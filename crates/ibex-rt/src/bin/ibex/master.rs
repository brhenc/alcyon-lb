// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The master process of `-W -S <socket>` (T200), HAProxy's master CLI.
//!
//! The master runs no proxy. It holds the `-S` socket, starts the binary again as a worker
//! process, and on every reload starts another worker, which takes the listening sockets
//! over from the serving one (`-x <dir>/<pid>.sock`) and soft-stops it (`-sf`). A worker
//! whose configuration does not load exits; the serving worker is never told anything, so
//! it goes on serving. See `tasks/T200-master-cli.md`.
//!
//! The link with a worker:
//! - env `IBEX_MASTER_DIR=<dir>`: the worker binds an admin CLI socket `<dir>/<pid>.sock`,
//!   which `@1 <cmd>` is forwarded to and the next worker's `-x` takes the listeners from;
//! - its stderr is a pipe the master reads: copied to the master's stderr, and kept as the
//!   startup logs until the worker writes [`READY_MARK`], its "loaded" signal (on the same
//!   pipe, so its own startup lines are always ahead of the master's "Loading success.").

use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{self, Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::process::{kill_process, Pid, Signal};

/// The line a worker started by a master writes on stderr once every thread listens.
pub const READY_MARK: &str = "\u{1}ibex-worker-ready";
/// The environment variable that makes a process a master's worker.
pub const MASTER_DIR_ENV: &str = "IBEX_MASTER_DIR";

const VERSION: &str = env!("CARGO_PKG_VERSION");
const STARTUP_LOG_CAP: usize = 256 * 1024;

const HELP: &[(&str, &str)] = &[
    ("@!<pid>", "send a command to the <pid> process"),
    ("@<relative pid>", "send a command to the <relative pid> process"),
    ("@master", "send a command to the master process"),
    ("echo <text>", "print text to the output"),
    ("hard-reload", "achieve a hard-reload (-st) of haproxy"),
    ("operator", "lower the level of the current CLI session to operator"),
    ("reload", "achieve a soft-reload (-sf) of haproxy"),
    ("show cli level", "display the level of the current CLI session"),
    ("show cli sockets", "dump list of cli sockets"),
    ("show env [var]", "dump environment variables known to the process"),
    ("show proc", "show processes status"),
    ("show startup-logs", "report logs emitted during HAProxy startup"),
    ("show version", "show version of the current process"),
    ("user", "lower the level of the current CLI session to user"),
    ("help [<command>]", "list matching or all commands"),
    ("prompt [help | n | i | p | timed ]*", "toggle interactive mode with prompt"),
    ("quit", "disconnect"),
];

/// `-S <path>[,<option>[,<value>]]...`.
#[derive(Debug, Clone)]
pub struct MasterSocket {
    pub path: PathBuf,
    pub mode: Option<u32>,
}

/// Parses `-S`'s argument. An option Ibex would not apply is an error, as HAProxy's own
/// unknown keywords are, rather than something dropped.
pub fn parse_socket(raw: &str) -> Result<MasterSocket, String> {
    let mut parts = raw.split(',');
    let addr = parts.next().unwrap_or_default();
    let path = addr.strip_prefix("unix@").unwrap_or(addr);
    if path.is_empty() || (path.contains('@') || (path.contains(':') && !path.contains('/'))) {
        return Err(format!("'{addr}' : the master CLI socket must be a unix socket path in Ibex."));
    }
    let mut sock = MasterSocket { path: PathBuf::from(path), mode: None };
    while let Some(kw) = parts.next() {
        match kw {
            "mode" => {
                let v = parts.next().unwrap_or_default();
                sock.mode = Some(
                    u32::from_str_radix(v, 8)
                        .map_err(|_| format!("'{path} mode' : '{v}' is not an octal mode."))?,
                );
            }
            "level" | "user" | "group" | "uid" | "gid" | "expose-fd" | "maxconn" | "name" | "process"
            | "accept-netscaler-cip" | "accept-proxy" | "backlog" | "id" | "nice" | "severity-output" => {
                return Err(format!("'{path} {kw}' : '{kw}' is not supported on the master CLI by Ibex."));
            }
            _ => return Err(format!("'{path} {kw}' : unknown keyword '{kw}'.")),
        }
    }
    Ok(sock)
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn uptime(since: u64) -> String {
    let up = now_secs().saturating_sub(since);
    format!("{}d{:02}h{:02}m{:02}s", up / 86400, (up % 86400) / 3600, (up % 3600) / 60, up % 60)
}

fn signal(pid: u32, sig: Signal) {
    if let Some(p) = i32::try_from(pid).ok().and_then(Pid::from_raw) {
        let _ = kill_process(p, sig);
    }
}

/// `exited with code <n> (<why>)`, as HAProxy's master words it.
fn exit_text(st: process::ExitStatus) -> (i32, String) {
    use std::os::unix::process::ExitStatusExt;
    // strsignal(3) for the signals a worker dies of in practice.
    const NAMES: [(i32, &str); 6] =
        [(1, "Hangup"), (2, "Interrupt"), (6, "Aborted"), (9, "Killed"), (11, "Segmentation fault"), (15, "Terminated")];
    let s = st.signal().unwrap_or(0);
    let name = NAMES.iter().find(|(n, _)| *n == s).map_or_else(|| format!("Signal {s}"), |(_, t)| (*t).to_string());
    st.code().map_or((128 + s, name), |c| (c, "Exit".into()))
}

#[derive(Debug, Clone)]
struct WorkerInfo {
    pid: u32,
    reloads: u32,
    started: u64,
    leaving: bool,
}

#[derive(Default)]
struct State {
    reloads: u32,
    failed: u32,
    load_failed: bool,
    /// In start order.
    workers: Vec<WorkerInfo>,
    /// The worker that last loaded and is still alive: `@1`, and the next `-x`.
    serving: Option<u32>,
    /// The worker that is loading, and whether it wrote [`READY_MARK`].
    loading: Option<u32>,
    loaded: bool,
    /// A reload asked for on the CLI (`Some(hard)`), for the main loop.
    requested: Option<bool>,
    /// Bumped each time a load finishes; `reload` sessions wait for it.
    results: u64,
    last_ok: bool,
    startup_logs: Vec<u8>,
}

struct Shared {
    state: Mutex<State>,
    done: Condvar,
    pid: u32,
    started: u64,
    dir: PathBuf,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One of the master's own log lines: to its stderr and into the startup logs.
    fn log(&self, st: &mut State, sev: &str, msg: &str) {
        let pad = " ".repeat(9usize.saturating_sub(sev.len()));
        let line = format!("[{sev}]{pad}({}) : {msg}\n", self.pid);
        let _ = io::stderr().write_all(line.as_bytes());
        push_log(st, line.as_bytes());
    }

    fn link(&self, pid: u32) -> PathBuf {
        self.dir.join(format!("{pid}.sock"))
    }
}

fn push_log(st: &mut State, bytes: &[u8]) {
    if st.startup_logs.len() + bytes.len() <= STARTUP_LOG_CAP {
        st.startup_logs.extend_from_slice(bytes);
    }
}

/// The arguments of a worker: the master's, less what described the master's own start.
/// The first worker keeps `-x`, `-sf` and `-st`: they name what the service replaces.
fn worker_args(args: &[String], first: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "-S" | "-p" => i += 2,
            "-x" if !first => i += 2,
            "-sf" | "-st" if !first => {
                i += 1;
                while i < args.len() && !args[i].starts_with('-') {
                    i += 1;
                }
            }
            "-D" => i += 1,
            _ if a.starts_with("-p") && a.len() > 2 => i += 1,
            _ => {
                out.push(a.to_string());
                i += 1;
            }
        }
    }
    out
}

fn exe() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let text = exe.to_string_lossy();
    Ok(text.strip_suffix(" (deleted)").map_or(exe.clone(), PathBuf::from))
}

fn private_dir() -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let name = format!("ibex-master-{}", process::id());
    // `<dir>/<pid>.sock` must fit in sun_path (108 bytes).
    let base = Some(std::env::temp_dir()).filter(|t| t.as_os_str().len() <= 60).unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = base.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// Becomes the master. Never returns.
pub fn run(sock: &MasterSocket, args: &[String], start_dir: Option<PathBuf>, systemd: bool) -> ! {
    // Reads NOTIFY_SOCKET and takes it out of the environment the workers inherit.
    ibex_rt::systemd::init();
    let lifecycle = ibex_rt::lifecycle::Lifecycle::new();
    let setup = lifecycle
        .install_signal_handlers()
        .and_then(|()| lifecycle.install_term_handler())
        .and_then(|()| private_dir())
        .and_then(|dir| {
            let _ = std::fs::remove_file(&sock.path);
            let bound = UnixListener::bind(&sock.path);
            if bound.is_err() {
                let _ = std::fs::remove_dir_all(&dir);
            }
            bound.map(|l| (dir, l))
        });
    let (dir, listener) = setup.unwrap_or_else(|e| {
        let _ = writeln!(io::stderr(), "[ALERT]    ({}) : cannot bind '{}': {e}", process::id(), sock.path.display());
        let _ = writeln!(io::stderr(), "[ALERT]    ({}) : Can't create the master's CLI.", process::id());
        process::exit(1);
    });
    if let Some(mode) = sock.mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock.path, std::fs::Permissions::from_mode(mode));
    }
    let _ = listener.set_nonblocking(true);

    let shared = Arc::new(Shared {
        state: Mutex::new(State::default()),
        done: Condvar::new(),
        pid: process::id(),
        started: now_secs(),
        dir: dir.clone(),
    });
    let mut m = Master {
        shared: Arc::clone(&shared),
        children: HashMap::new(),
        readers: HashMap::new(),
        first_args: worker_args(args, true),
        base_args: worker_args(args, false),
        start_dir,
        systemd,
        stopping: false,
        exit_code: 0,
        first: true,
        sock_path: sock.path.clone(),
    };
    m.start_worker(false);

    loop {
        if lifecycle.term_requested() {
            m.terminate();
        }
        if lifecycle.soft_stop_requested() && !m.stopping {
            m.stopping = true;
            if systemd {
                ibex_rt::systemd::notify_stopping_once();
            }
            let mut st = shared.lock();
            shared.log(&mut st, "WARNING", "Exiting Master process...");
            drop(st);
            for pid in m.children.keys() {
                signal(*pid, Signal::Usr1);
            }
        }
        if lifecycle.take_reload_request() {
            let mut st = shared.lock();
            if st.requested.is_none() {
                st.requested = Some(false);
            }
        }
        let wanted = {
            let mut st = shared.lock();
            if st.loading.is_none() { st.requested.take() } else { None }
        };
        if let Some(hard) = wanted {
            if !m.stopping {
                m.start_worker(hard);
            }
        }
        m.check_loaded();
        m.reap();
        if m.stopping && m.children.is_empty() {
            let mut st = shared.lock();
            let code = m.exit_code;
            shared.log(&mut st, "WARNING", &format!("All workers exited. Exiting... ({code})"));
            drop(st);
            m.cleanup();
            process::exit(code);
        }
        while let Ok((stream, _)) = listener.accept() {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || session(&shared, stream));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct Master {
    shared: Arc<Shared>,
    children: HashMap<u32, Child>,
    readers: HashMap<u32, Option<std::thread::JoinHandle<()>>>,
    first_args: Vec<String>,
    base_args: Vec<String>,
    start_dir: Option<PathBuf>,
    systemd: bool,
    stopping: bool,
    exit_code: i32,
    first: bool,
    sock_path: PathBuf,
}

impl Master {
    fn start_worker(&mut self, hard: bool) {
        let shared = Arc::clone(&self.shared);
        let mut st = shared.lock();
        let mut args = if self.first { self.first_args.clone() } else { self.base_args.clone() };
        if !self.first {
            st.reloads += 1;
            for w in &mut st.workers {
                w.reloads += 1;
                w.leaving = true;
            }
            st.startup_logs.clear();
            if self.systemd {
                ibex_rt::systemd::notify_reloading();
            }
        }
        if let Some(s) = st.serving {
            args.push("-x".into());
            args.push(shared.link(s).display().to_string());
        }
        let old: Vec<String> = st.workers.iter().map(|w| w.pid.to_string()).collect();
        if !old.is_empty() {
            args.push(if hard { "-st" } else { "-sf" }.into());
            args.extend(old);
        }
        let spawned = exe().and_then(|exe| {
            let mut cmd = Command::new(exe);
            cmd.args(&args)
                .env(MASTER_DIR_ENV, &shared.dir)
                .env_remove("NOTIFY_SOCKET")
                .stdin(Stdio::null())
                .stderr(Stdio::piped());
            if let Some(ref d) = self.start_dir {
                cmd.current_dir(d);
            }
            cmd.spawn()
        });
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                // As a worker that failed to load (the binary is gone after an upgrade...).
                shared.log(&mut st, "ALERT", &format!("Cannot fork new worker: {e}"));
                return self.load_failed(st, None, 1);
            }
        };
        let pid = child.id();
        shared.log(&mut st, "NOTICE", &format!("Initializing new worker ({pid})"));
        st.workers.push(WorkerInfo { pid, reloads: 0, started: now_secs(), leaving: false });
        st.loading = Some(pid);
        st.loaded = false;
        drop(st);
        let shared = Arc::clone(&self.shared);
        let reader = child.stderr.take().map(|err| std::thread::spawn(move || read_worker_stderr(&shared, pid, err)));
        self.readers.insert(pid, reader);
        self.children.insert(pid, child);
    }

    /// The loading worker wrote its ready line.
    fn check_loaded(&mut self) {
        let shared = Arc::clone(&self.shared);
        let mut st = shared.lock();
        if st.loading.is_some() && st.loaded {
            let pid = st.loading.take().unwrap_or_default();
            st.serving = Some(pid);
            shared.log(&mut st, "NOTICE", "Loading success.");
            self.finish_load(&mut st, true);
            if self.systemd {
                let _ = ibex_rt::systemd::notify_ready();
            }
        }
    }

    /// The new worker did not load. The first one takes the master with it, with its code;
    /// after that, the serving worker goes on serving.
    fn load_failed(&mut self, mut st: std::sync::MutexGuard<'_, State>, pid: Option<u32>, code: i32) {
        let first = self.first;
        st.workers.retain(|w| Some(w.pid) != pid);
        self.finish_load(&mut st, false);
        drop(st);
        if first {
            self.cleanup();
            process::exit(code);
        }
        if self.systemd {
            let _ = ibex_rt::systemd::notify_reload_failed();
        }
    }

    fn finish_load(&mut self, st: &mut State, ok: bool) {
        st.loading = None;
        st.last_ok = ok;
        st.load_failed = !ok;
        if ok {
            st.failed = 0;
        } else if !self.first {
            st.failed += 1;
        }
        st.results += 1;
        self.first = false;
        self.shared.done.notify_all();
    }

    /// Workers that have exited.
    fn reap(&mut self) {
        let exited: Vec<(u32, process::ExitStatus)> = self
            .children
            .iter_mut()
            .filter_map(|(pid, c)| c.try_wait().ok().flatten().map(|s| (*pid, s)))
            .collect();
        for (pid, status) in exited {
            self.children.remove(&pid);
            // Everything it wrote is read before its exit is reported.
            if let Some(Some(h)) = self.readers.remove(&pid) {
                let _ = h.join();
            }
            let _ = std::fs::remove_file(self.shared.link(pid));
            let (code, why) = exit_text(status);
            let shared = Arc::clone(&self.shared);
            let mut st = shared.lock();
            let info = st.workers.iter().find(|w| w.pid == pid).cloned();
            st.workers.retain(|w| w.pid != pid);
            if st.serving == Some(pid) {
                st.serving = None;
            }
            // Loading still (its ready line, if any, not yet acted on): a failed load.
            if st.loading == Some(pid) {
                shared.log(&mut st, "WARNING", &format!("Failed to load worker ({pid}) exited with code {code} ({why})"));
                self.load_failed(st, Some(pid), code);
                continue;
            }
            let current = info.as_ref().is_some_and(|w| !w.leaving);
            if self.stopping {
                let which = if current { "Current" } else { "Former" };
                shared.log(&mut st, "WARNING", &format!("{which} worker ({pid}) exited with code {code} ({why})"));
                if current {
                    self.exit_code = code;
                }
            } else if current {
                // HAProxy's default, exit-on-failure.
                shared.log(&mut st, "ALERT", &format!("Current worker ({pid}) exited with code {code} ({why})"));
                shared.log(&mut st, "ALERT", "exit-on-failure: killing every processes with SIGTERM");
                drop(st);
                self.exit_code = code;
                self.stopping = true;
                for p in self.children.keys() {
                    signal(*p, Signal::Term);
                }
            } else {
                shared.log(&mut st, "WARNING", &format!("Former worker ({pid}) exited with code {code} ({why})"));
            }
        }
    }

    /// SIGTERM: every worker is stopped at once, and the master exits 0.
    fn terminate(&mut self) -> ! {
        if self.systemd {
            ibex_rt::systemd::notify_stopping_once();
        }
        for p in self.children.keys() {
            signal(*p, Signal::Term);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !self.children.is_empty() && std::time::Instant::now() < deadline {
            self.children.retain(|_, c| c.try_wait().ok().flatten().is_none());
            std::thread::sleep(Duration::from_millis(10));
        }
        self.cleanup();
        process::exit(0);
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.sock_path);
        let _ = std::fs::remove_dir_all(&self.shared.dir);
    }
}

fn read_worker_stderr(shared: &Shared, pid: u32, err: process::ChildStderr) {
    let mut r = io::BufReader::new(err);
    let mut line = Vec::new();
    let mut startup = true;
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if startup && line.strip_suffix(b"\n").unwrap_or(&line) == READY_MARK.as_bytes() {
            startup = false;
            let mut st = shared.lock();
            if st.loading == Some(pid) {
                st.loaded = true;
            }
            continue;
        }
        let _ = io::stderr().write_all(&line);
        let mut st = shared.lock();
        if startup && st.loading == Some(pid) {
            push_log(&mut st, &line);
        }
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum Level {
    User,
    Operator,
    Admin,
}

struct Session {
    level: Level,
    interactive: bool,
    done: bool,
}

fn session(shared: &Shared, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
    let Ok(mut out) = stream.try_clone() else { return };
    let mut reader = io::BufReader::new(stream);
    let mut s = Session { level: Level::Admin, interactive: false, done: false };
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let text = line.trim_end_matches(['\n', '\r']);
        let mut reply = String::new();
        // An empty command (an empty line, `a;;b`) answers an empty line, as HAProxy's.
        for cmd in text.split(';').map(str::trim) {
            reply.push_str(&if cmd.is_empty() { "\n".to_string() } else { command(shared, &mut s, cmd) });
            if s.done {
                break;
            }
        }
        if s.interactive && !s.done {
            reply.push_str(&prompt(shared));
        }
        if out.write_all(reply.as_bytes()).is_err() || s.done || !s.interactive {
            return;
        }
    }
}

fn prompt(shared: &Shared) -> String {
    if shared.lock().load_failed { "master[ReloadFailed]> ".into() } else { "master> ".into() }
}

fn help_line(cmd: &str, what: &str) -> String {
    format!("  {cmd:<39} : {what}\n")
}

/// The help list under `head`: every command, or those whose first words are `words`
/// (and help, prompt, quit, which HAProxy always lists).
fn help_list(head: &str, words: &[&str]) -> String {
    let wanted = |c: &str| words.is_empty() || c.split_whitespace().zip(words).all(|(a, b)| a == *b);
    let always = |c: &str| matches!(c, "help [<command>]" | "prompt [help | n | i | p | timed ]*" | "quit");
    let any = HELP.iter().any(|(c, _)| !always(c) && wanted(c));
    let mut h = format!("{head}\n");
    for (c, w) in HELP.iter().filter(|(c, _)| !any || always(c) || wanted(c)) {
        h.push_str(&help_line(c, w));
    }
    h.push('\n');
    h
}

fn command(shared: &Shared, s: &mut Session, cmd: &str) -> String {
    if let Some(rest) = cmd.strip_prefix('@') {
        let (target, sub) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        let sub = sub.trim();
        if target.is_empty() || target == "master" {
            return if sub.is_empty() { String::new() } else { command(shared, s, sub) };
        }
        let pid = {
            let st = shared.lock();
            if let Some(p) = target.strip_prefix('!') {
                p.parse::<u32>().ok().filter(|p| st.workers.iter().any(|w| w.pid == *p))
            } else if target == "1" {
                st.serving
            } else {
                None
            }
        };
        let Some(pid) = pid else {
            return format!("Can't find the target PID matching the prefix '@{target}'\n");
        };
        if sub.is_empty() {
            return String::new();
        }
        return forward(shared, pid, sub, s.level);
    }
    let words: Vec<&str> = cmd.split_whitespace().collect();
    match words.as_slice() {
        ["help", rest @ ..] => help_list("The following commands are valid at this level:", rest),
        ["prompt", ..] => {
            s.interactive = !s.interactive;
            String::new()
        }
        ["quit", ..] => {
            s.done = true;
            String::new()
        }
        ["echo", ..] => format!("{}\n\n", cmd["echo".len()..].trim_start()),
        ["user"] => {
            s.level = Level::User;
            String::new()
        }
        ["operator"] if s.level < Level::Operator => {
            // Measured: the rest of the line is not run.
            s.done = true;
            "Permission denied!\n".into()
        }
        ["operator"] => {
            s.level = Level::Operator;
            String::new()
        }
        ["show", "cli", "level"] => {
            let l = match s.level {
                Level::User => "user",
                Level::Operator => "operator",
                Level::Admin => "admin",
            };
            format!("{l}\n\n")
        }
        ["show", "cli", "sockets"] => "\n".into(),
        ["show", "version"] => format!("{VERSION}\n\n"),
        ["show", "env"] => std::env::vars().map(|(k, v)| format!("{k}={v}\n")).chain(["\n".into()]).collect(),
        ["show", "env", var] => match std::env::var(var) {
            Ok(v) => format!("{var}={v}\n\n"),
            Err(_) => "Variable not found\n\n".into(),
        },
        ["show", "proc"] | ["show", "proc", "debug"] => show_proc(shared),
        ["show", "proc", ..] => "'show proc' only supports 'debug' as argument\n\n".into(),
        ["show", "startup-logs"] => {
            let st = shared.lock();
            format!("{}\n", String::from_utf8_lossy(&st.startup_logs))
        }
        ["reload"] | ["hard-reload"] => {
            if s.level < Level::Operator {
                return "Permission denied\n\n".into();
            }
            s.done = true;
            reload(shared, words[0] == "hard-reload")
        }
        _ => help_list(
            &format!("Unknown command: '{}', but maybe one of the following ones is a better match:", words[0]),
            &words[..1],
        ),
    }
}

fn show_proc(shared: &Shared) -> String {
    let st = shared.lock();
    let mut o = format!("#{:<14} {:<15} {:<15} {:<15} {:<15}\n", "<PID>", "<type>", "<reloads>", "<uptime>", "<version>");
    let reloads = format!("{} [failed: {}]", st.reloads, st.failed);
    o.push_str(&format!("{:<15} {:<15} {:<15} {:<15} {:<15}\n", shared.pid, "master", reloads, uptime(shared.started), VERSION));
    let row = |w: &WorkerInfo| format!("{:<15} {:<15} {:<15} {:<15} {:<15}\n", w.pid, "worker", w.reloads, uptime(w.started), VERSION);
    o.push_str("# workers\n");
    for w in st.workers.iter().filter(|w| !w.leaving) {
        o.push_str(&row(w));
    }
    if st.workers.iter().any(|w| w.leaving) {
        o.push_str("# old workers\n");
        // Newest first, as HAProxy lists them.
        for w in st.workers.iter().rev().filter(|w| w.leaving) {
            o.push_str(&row(w));
        }
    }
    o.push('\n');
    o
}

fn reload(shared: &Shared, hard: bool) -> String {
    let mut st = shared.lock();
    if st.loading.is_some() || st.requested.is_some() {
        return "Success=0\n--\nAnother reload is still in progress.\n".into();
    }
    st.requested = Some(hard);
    let seen = st.results;
    while st.results == seen {
        st = shared.done.wait(st).unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    let mut o = format!("Success={}\n", u8::from(st.last_ok));
    if !st.startup_logs.is_empty() {
        o.push_str("--\n");
        o.push_str(&String::from_utf8_lossy(&st.startup_logs));
    }
    o.push('\n');
    o
}

/// `@<target> <cmd>`: the command on that worker's own CLI, at this session's level.
fn forward(shared: &Shared, pid: u32, cmd: &str, level: Level) -> String {
    let prefix = match level {
        Level::Admin => "",
        Level::Operator => "operator;",
        Level::User => "user;",
    };
    let answer = UnixStream::connect(shared.link(pid)).and_then(|mut s| {
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        s.write_all(format!("{prefix}{cmd}\n").as_bytes())?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).map(|_| out)
    });
    let out = answer.unwrap_or_else(|_| format!("Can't connect to the target CLI ({pid})!\n").into_bytes());
    let text = String::from_utf8_lossy(&out);
    // The worker's answer to the level command itself is an empty line HAProxy does not send.
    if prefix.is_empty() { text.into_owned() } else { text.strip_prefix('\n').unwrap_or(&text).to_string() }
}
