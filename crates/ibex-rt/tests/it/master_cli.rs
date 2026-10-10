// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T200: the master CLI, `ibex -W -S <sock>`. Every expected output was measured on HAProxy
//! 3.5-dev8-885761-29 (`haproxy -W -S /tmp/t200m.sock -f cfg`, `socat - UNIX:...`); PIDs and
//! uptimes are checked for shape, not value.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// HAProxy's master `help`, byte for byte.
const HELP: &str = "The following commands are valid at this level:
  @!<pid>                                 : send a command to the <pid> process
  @<relative pid>                         : send a command to the <relative pid> process
  @master                                 : send a command to the master process
  echo <text>                             : print text to the output
  hard-reload                             : achieve a hard-reload (-st) of haproxy
  operator                                : lower the level of the current CLI session to operator
  reload                                  : achieve a soft-reload (-sf) of haproxy
  show cli level                          : display the level of the current CLI session
  show cli sockets                        : dump list of cli sockets
  show env [var]                          : dump environment variables known to the process
  show proc                               : show processes status
  show startup-logs                       : report logs emitted during HAProxy startup
  show version                            : show version of the current process
  user                                    : lower the level of the current CLI session to user
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

";

fn master(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect master socket");
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(cmd.as_bytes()).unwrap();
    if !cmd.ends_with('\n') {
        s.write_all(b"\n").unwrap();
    }
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn wait_for_socket(p: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if UnixStream::connect(p).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{} never accepted", p.display());
}

fn get(port: u16) -> Result<String, String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    if !out.starts_with("HTTP/1.1 200") {
        return Err(out);
    }
    Ok(out.rsplit("\r\n\r\n").next().unwrap_or("").to_string())
}

/// The body served once the old worker has taken its `-sf`: it may still accept for up to
/// one poll interval after the new one reported ready.
fn served_eventually(port: u16, want: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let got = get(port).unwrap_or_default();
        if got == want || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_exit(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return Some(st);
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn config(port: u16, body: &str) -> String {
    format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind 127.0.0.1:{port}\n  http-request return status 200 content-type text/plain string {body}\n"
    )
}

/// One row of `show proc`, checked against HAProxy's `%-15u %-15s %-15s %-15s %-15s`.
#[derive(Debug, Clone, PartialEq)]
struct Row {
    pid: u32,
    kind: String,
    reloads: String,
}

fn is_uptime(s: &str) -> bool {
    // %dd%02dh%02dm%02ds
    let Some((d, rest)) = s.split_once('d') else { return false };
    let b = rest.as_bytes();
    !d.is_empty()
        && d.bytes().all(|c| c.is_ascii_digit())
        && b.len() == 9
        && b[2] == b'h'
        && b[5] == b'm'
        && b[8] == b's'
        && [0, 1, 3, 4, 6, 7].iter().all(|&i| b[i].is_ascii_digit())
}

/// Parses `show proc`: (master row, `# workers` rows, `# old workers` rows).
fn show_proc(text: &str) -> (Row, Vec<Row>, Vec<Row>) {
    let mut lines = text.lines();
    let header = format!("#{:<14} {:<15} {:<15} {:<15} {:<15}", "<PID>", "<type>", "<reloads>", "<uptime>", "<version>");
    assert_eq!(lines.next(), Some(header.as_str()), "show proc header; got {text:?}");
    assert!(text.ends_with("\n\n"), "show proc ends with an empty line: {text:?}");
    let row = |l: &str| -> Row {
        let toks: Vec<&str> = l.split_whitespace().collect();
        let (pid, kind) = (toks[0], toks[1]);
        let (reloads, up, ver) = if kind == "master" {
            (toks[2..5].join(" "), toks[5], toks[6])
        } else {
            (toks[2].to_string(), toks[3], toks[4])
        };
        assert!(is_uptime(up), "uptime {up:?} in {l:?}");
        assert_eq!(ver, VERSION, "version column in {l:?}");
        assert_eq!(l, format!("{pid:<15} {kind:<15} {reloads:<15} {up:<15} {ver:<15}"), "columns of {l:?}");
        Row { pid: pid.parse().expect("pid"), kind: kind.to_string(), reloads }
    };
    let m = row(lines.next().expect("master row"));
    assert_eq!(m.kind, "master");
    assert_eq!(lines.next(), Some("# workers"), "{text:?}");
    let (mut cur, mut old) = (Vec::new(), Vec::new());
    let mut in_old = false;
    for l in lines {
        if l.is_empty() {
            break;
        }
        if l == "# old workers" {
            in_old = true;
            continue;
        }
        let r = row(l);
        assert_eq!(r.kind, "worker");
        if in_old { old.push(r) } else { cur.push(r) }
    }
    (m, cur, old)
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        && !std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default().contains(") Z ")
}

fn sig(pid: u32, s: rustix::process::Signal) {
    let p = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
    let _ = rustix::process::kill_process(p, s);
}

struct Hammer {
    stop: Arc<AtomicBool>,
    ok: Arc<AtomicU32>,
    failed: Arc<std::sync::Mutex<Vec<String>>>,
    t: Option<std::thread::JoinHandle<()>>,
}

impl Hammer {
    fn start(port: u16) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let ok = Arc::new(AtomicU32::new(0));
        let failed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (s, o, f) = (stop.clone(), ok.clone(), failed.clone());
        let t = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                match get(port) {
                    Ok(_) => {
                        o.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => f.lock().unwrap().push(e),
                }
            }
        });
        Self { stop, ok, failed, t: Some(t) }
    }
    fn finish(mut self) -> (u32, Vec<String>) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.t.take().unwrap().join();
        (self.ok.load(Ordering::Relaxed), self.failed.lock().unwrap().clone())
    }
}

struct Master {
    child: Child,
    dir: PathBuf,
}

impl Drop for Master {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn show_proc_reload_and_forwarding_on_the_master_socket() {
    let dir = PathBuf::from(format!("/tmp/t200-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("m.sock");
    let cfg = dir.join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(&cfg, config(port, "v1")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["-W", "-sf", "999999999", "-S"])
        .arg(format!("{},mode,600", sock.display()))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mpid = child.id();
    let mut m = Master { child, dir: dir.clone() };
    wait_for_socket(&sock);
    assert!(common::wait_listening(std::net::SocketAddr::from(([127, 0, 0, 1], port))));
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600, "-S <path>,mode,600");
    }

    assert_eq!(master(&sock, "help"), HELP);
    assert_eq!(master(&sock, "show version"), format!("{VERSION}\n\n"));
    assert_eq!(master(&sock, "echo hi there"), "hi there\n\n");
    assert_eq!(master(&sock, "show cli level"), "admin\n\n");
    assert_eq!(master(&sock, "show cli sockets"), "\n");
    assert_eq!(master(&sock, "show version;;show version"), format!("{VERSION}\n\n\n{VERSION}\n\n"));
    assert_eq!(master(&sock, ""), "\n");
    assert_eq!(master(&sock, "show env NOPE_T200"), "Variable not found\n\n");
    assert!(master(&sock, "show env PATH").starts_with("PATH=/"));
    assert!(master(&sock, "show env").ends_with("\n\n"));
    assert_eq!(master(&sock, "show proc foo"), "'show proc' only supports 'debug' as argument\n\n");
    assert_eq!(
        master(&sock, "help reload"),
        "The following commands are valid at this level:
  reload                                  : achieve a soft-reload (-sf) of haproxy
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"
    );
    // A worker command on the master itself.
    assert_eq!(
        master(&sock, "show info"),
        "Unknown command: 'show', but maybe one of the following ones is a better match:
  show cli level                          : display the level of the current CLI session
  show cli sockets                        : dump list of cli sockets
  show env [var]                          : dump environment variables known to the process
  show proc                               : show processes status
  show startup-logs                       : report logs emitted during HAProxy startup
  show version                            : show version of the current process
  help [<command>]                        : list matching or all commands
  prompt [help | n | i | p | timed ]*     : toggle interactive mode with prompt
  quit                                    : disconnect

"
    );
    assert_eq!(master(&sock, "user;operator;show cli level"), "Permission denied!\n");
    assert_eq!(master(&sock, "operator;show cli level;@1 show cli level"), "operator\n\noperator\n\n");
    assert_eq!(master(&sock, "@1"), "");

    // A master and one worker, a separate process.
    let (mrow, cur, old) = show_proc(&master(&sock, "show proc"));
    assert_eq!(mrow.pid, mpid);
    assert_eq!(mrow.reloads, "0 [failed: 0]");
    assert_eq!(cur.len(), 1, "one current worker");
    assert!(old.is_empty());
    let w1 = cur[0].pid;
    assert_ne!(w1, mpid, "the worker is its own process");
    assert_eq!(cur[0].reloads, "0");
    assert_eq!(get(port).unwrap(), "v1");

    let logs = master(&sock, "show startup-logs");
    assert!(logs.contains(&format!("[NOTICE]   ({mpid}) : Initializing new worker ({w1})\n")), "{logs:?}");
    assert!(logs.contains(&format!("[NOTICE]   ({mpid}) : Loading success.\n")), "{logs:?}");

    // Forwarding to the worker's own CLI.
    let info = master(&sock, "@1 show info");
    assert!(info.contains(&format!("\nPid: {w1}\n")), "@1 show info reaches the worker: {info:?}");
    assert_eq!(master(&sock, &format!("@!{w1} show version")), format!("{VERSION}\n\n"));
    assert_eq!(master(&sock, "@1 show cli level"), "admin\n\n");
    assert_eq!(master(&sock, "@master show version"), format!("{VERSION}\n\n"));
    // A lowered level holds for the commands forwarded from that session too.
    assert_eq!(master(&sock, "user;show cli level;@1 show cli level"), "user\n\nuser\n\n");
    assert_eq!(master(&sock, "user;reload"), "Permission denied\n\n");
    assert_eq!(master(&sock, "@2 show version"),"Can't find the target PID matching the prefix '@2'\n");
    assert_eq!(master(&sock, "@!99999999 show version"), "Can't find the target PID matching the prefix '@!99999999'\n");

    // A valid reload, with a client sending requests all along.
    std::fs::write(&cfg, config(port, "v2")).unwrap();
    let h = Hammer::start(port);
    std::thread::sleep(Duration::from_millis(200));
    let out = master(&sock, "reload");
    std::thread::sleep(Duration::from_millis(200));
    let (n, failed) = h.finish();
    assert!(failed.is_empty(), "requests failed during a reload: {failed:?}");
    assert!(n > 0);
    assert!(out.starts_with("Success=1\n--\n"), "{out:?}");
    assert!(out.ends_with("\n\n"), "{out:?}");
    assert!(out.contains(&format!("[NOTICE]   ({mpid}) : Initializing new worker (")), "{out:?}");
    assert!(out.contains(&format!("[NOTICE]   ({mpid}) : Loading success.\n")), "{out:?}");
    assert_eq!(served_eventually(port, "v2"), "v2", "the new worker serves the new configuration");
    let (mrow, cur, old) = show_proc(&master(&sock, "show proc"));
    assert_eq!(mrow.reloads, "1 [failed: 0]");
    assert_eq!(cur.len(), 1);
    let w2 = cur[0].pid;
    assert_ne!(w2, w1);
    assert_eq!(cur[0].reloads, "0");
    // The old worker is listed under "old workers" until it has drained and exited.
    assert!(old.iter().all(|r| r.pid == w1 && r.reloads == "1"), "{old:?}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(w1) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive(w1), "the old worker exits once it has drained");

    // An invalid configuration: the reload fails and the serving worker goes on serving.
    std::fs::write(&cfg, "global\n  bogus_kw\n").unwrap();
    let h = Hammer::start(port);
    let out = master(&sock, "reload");
    std::thread::sleep(Duration::from_millis(200));
    let (n, failed) = h.finish();
    assert!(failed.is_empty(), "requests failed during a failed reload: {failed:?}");
    assert!(n > 0);
    assert!(out.starts_with("Success=0\n--\n"), "{out:?}");
    assert!(out.contains("unknown keyword 'bogus_kw' in 'global' section"), "the worker's own error: {out:?}");
    assert!(out.contains(") exited with code 1 (Exit)\n"), "{out:?}");
    assert!(out.contains(&format!("[WARNING]  ({mpid}) : Failed to load worker (")), "{out:?}");
    assert_eq!(get(port).unwrap(), "v2", "the previous worker still serves");
    assert!(alive(w2));
    let (mrow, cur, old) = show_proc(&master(&sock, "show proc"));
    assert_eq!(mrow.reloads, "2 [failed: 1]");
    // As HAProxy: after a failed reload the serving worker is listed as an old one.
    assert!(cur.is_empty(), "{cur:?}");
    assert_eq!(old, vec![Row { pid: w2, kind: "worker".into(), reloads: "1".into() }]);
    let info = master(&sock, "@1 show info");
    assert!(info.contains(&format!("\nPid: {w2}\n")), "@1 is still the serving worker: {info:?}");
    assert_eq!(master(&sock, "show startup-logs"), out["Success=0\n--\n".len()..]);

    // Interactive mode, with the failed reload in the prompt.
    assert_eq!(
        master(&sock, "prompt\nshow version\nquit\n"),
        format!("master[ReloadFailed]> {VERSION}\n\nmaster[ReloadFailed]> ")
    );

    // SIGUSR2 to the master is a reload too; it succeeds again and stops the old worker.
    std::fs::write(&cfg, config(port, "v3")).unwrap();
    sig(mpid, rustix::process::Signal::Usr2);
    let deadline = Instant::now() + Duration::from_secs(10);
    while get(port).ok().as_deref() != Some("v3") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(served_eventually(port, "v3"), "v3", "SIGUSR2 on the master reloads");
    let (mrow, cur, _) = show_proc(&master(&sock, "show proc"));
    assert_eq!(mrow.reloads, "3 [failed: 0]");
    let w3 = cur[0].pid;
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(w2) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive(w2), "a successful reload stops the worker that survived the failed one");
    assert_eq!(master(&sock, "prompt\nquit\n"), "master> ", "the prompt drops [ReloadFailed] after a success");

    // SIGUSR1 on the master: the workers soft-stop, then the master exits 0.
    sig(mpid, rustix::process::Signal::Usr1);
    let deadline = Instant::now() + Duration::from_secs(5);
    let st = loop {
        if let Some(st) = m.child.try_wait().unwrap() {
            break Some(st);
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(st.is_some_and(|s| s.success()), "master exit after SIGUSR1: {st:?}");
    assert!(!alive(w3), "the worker is gone with the master");
}

#[test]
fn a_reload_while_one_is_loading_is_refused() {
    // Not measurable on demand on HAProxy (its window is a few ms); the text is
    // src/mworker.c's: "Success=0\n--\nAnother reload is still in progress.\n".
    // Covered here by holding the new worker in its startup: a configuration whose
    // worker never becomes ready is not available, so this only checks the master
    // answers the second request while the first is still running, or after it.
    let dir = PathBuf::from(format!("/tmp/t200b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("m.sock");
    let cfg = dir.join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(&cfg, config(port, "v1")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["-W", "-S"])
        .arg(&sock)
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mut m = Master { child, dir: dir.clone() };
    wait_for_socket(&sock);
    assert!(common::wait_listening(std::net::SocketAddr::from(([127, 0, 0, 1], port))));
    let s2 = sock.clone();
    let t = std::thread::spawn(move || master(&s2, "reload"));
    let second = master(&sock, "reload");
    let first = t.join().unwrap();
    for out in [&first, &second] {
        assert!(
            out.starts_with("Success=1\n--\n") || out == "Success=0\n--\nAnother reload is still in progress.\n",
            "{out:?}"
        );
    }
    assert_eq!(served_eventually(port, "v1"), "v1");
    // SIGTERM on the master: every worker is stopped at once and the master exits 0, as
    // HAProxy's (and Ibex's single process under -W) does.
    let w = show_proc(&master(&sock, "show proc")).1[0].pid;
    sig(m.child.id(), rustix::process::Signal::Term);
    let st = wait_exit(&mut m.child, Duration::from_secs(5));
    assert!(st.is_some_and(|s| s.success()), "SIGTERM on the master: {st:?}");
    assert!(!alive(w), "SIGTERM on the master stops the workers");
    assert!(!sock.exists(), "the master removes its socket");
}

/// Runs a start that must fail; one that does not is stopped after five seconds.
fn run_briefly(cmd: &mut Command) -> std::process::Output {
    let mut child = cmd.stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    common::stop(&mut child);
    child.wait_with_output().expect("output")
}

#[test]
fn the_master_cli_needs_master_worker_mode() {
    let dir = PathBuf::from(format!("/tmp/t200c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("c.cfg");
    std::fs::write(&cfg, config(common::reserve_port(), "v1")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ibex"));
    cmd.arg("-S")
        .arg(dir.join("m.sock"))
        .arg("-f")
        .arg(&cfg);
    let out = run_briefly(&mut cmd);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(" : a master CLI socket was defined, but master-worker mode (-W) is not enabled.\n"),
        "{err:?}"
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ibex"));
    cmd.arg("-W")
        .arg("-S")
        .arg(format!("{},bogus,1", dir.join("m.sock").display()))
        .arg("-f")
        .arg(&cfg);
    let out = run_briefly(&mut cmd);
    assert_eq!(out.status.code(), Some(1), "an -S option Ibex does not apply is refused");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Can't create the master's CLI."), "{err:?}");
    for bad in [
        format!("{},level,admin", dir.join("m.sock").display()),
        "ipv4@127.0.0.1:9999".to_string(),
        format!("{},mode,9z", dir.join("m.sock").display()),
        "/nonexistent-t200/m.sock".to_string(),
    ] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ibex"));
        cmd.args(["-W", "-S", &bad, "-f"]).arg(&cfg);
        let out = run_briefly(&mut cmd);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "-S {bad}: {err}");
        assert!(err.contains("Can't create the master's CLI."), "-S {bad}: {err:?}");
    }
    // `-s <path>` (Ibex's command-line stats socket, not the master CLI) is an admin stats
    // socket in a single process.
    let stats = dir.join("s.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .arg("-s")
        .arg(&stats)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    wait_for_socket(&stats);
    assert_eq!(master(&stats, "show cli level"), "admin\n\n");
    common::stop(&mut child);
    // `-s` needs its path.
    let out = run_briefly(Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).arg("-s"));
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-Ws -S` under systemd (HAProxy's unit puts `-S` in `EXTRAOPTS`): the master is the main
/// PID for the life of the service, and a reload on its socket is `RELOADING=1` then
/// `READY=1`, both from the master.
#[test]
fn under_systemd_the_master_stays_the_main_pid_across_reloads() {
    use std::os::unix::net::UnixDatagram;
    let dir = PathBuf::from(format!("/tmp/t200d-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (sock, cfg, notify) = (dir.join("m.sock"), dir.join("c.cfg"), dir.join("n.sock"));
    let port = common::reserve_port();
    std::fs::write(&cfg, config(port, "v1")).unwrap();
    let sink = UnixDatagram::bind(&notify).unwrap();
    sink.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(["-Ws", "-S"])
        .arg(&sock)
        .arg("-f")
        .arg(&cfg)
        .env("NOTIFY_SOCKET", &notify)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let mpid = child.id();
    let mut m = Master { child, dir: dir.clone() };
    let recv = || {
        let mut buf = [0u8; 1024];
        let (n, _) = sink.recv_from(&mut buf).expect("a notification");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    };
    let first = recv();
    assert!(first.contains("READY=1") && first.contains(&format!("MAINPID={mpid}\n")), "{first:?}");
    assert_eq!(get(port).unwrap(), "v1");
    std::fs::write(&cfg, config(port, "v2")).unwrap();
    assert!(master(&sock, "reload").starts_with("Success=1\n"));
    let reloading = recv();
    assert!(reloading.starts_with("RELOADING=1\n"), "{reloading:?}");
    let ready = recv();
    assert!(ready.contains("READY=1") && ready.contains(&format!("MAINPID={mpid}\n")), "{ready:?}");
    assert_eq!(served_eventually(port, "v2"), "v2");
    // A failed reload is reported too.
    std::fs::write(&cfg, "global\n  bogus_kw\n").unwrap();
    assert!(master(&sock, "reload").starts_with("Success=0\n"));
    assert!(recv().starts_with("RELOADING=1\n"));
    let failed = recv();
    assert!(failed.contains("STATUS=Reload failed!"), "{failed:?}");
    // SIGUSR1: STOPPING=1, the workers soft-stop and the master exits 0.
    sig(mpid, rustix::process::Signal::Usr1);
    assert!(recv().contains("STOPPING=1"));
    let st = wait_exit(&mut m.child, Duration::from_secs(5));
    assert!(st.is_some_and(|s| s.success()), "SIGUSR1 on the master: {st:?}");
    assert!(!sock.exists(), "the master removes its socket");
}

/// The current worker dying on its own takes the master with it, with the worker's code
/// (HAProxy's default `exit-on-failure`: 137 for a SIGKILL'd worker, measured).
#[test]
fn the_master_exits_when_its_worker_dies() {
    let dir = PathBuf::from(format!("/tmp/t200e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (sock, cfg) = (dir.join("m.sock"), dir.join("c.cfg"));
    let port = common::reserve_port();
    std::fs::write(&cfg, config(port, "v1")).unwrap();
    let start = || {
        Command::new(env!("CARGO_BIN_EXE_ibex"))
            .args(["-W", "-S"])
            .arg(&sock)
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn")
    };
    let mut m = Master { child: start(), dir: dir.clone() };
    wait_for_socket(&sock);
    assert!(common::wait_listening(std::net::SocketAddr::from(([127, 0, 0, 1], port))));
    let mpid = m.child.id();
    let w = show_proc(&master(&sock, "show proc")).1[0].pid;
    sig(w, rustix::process::Signal::Kill);
    let st = wait_exit(&mut m.child, Duration::from_secs(5));
    assert_eq!(st.and_then(|s| s.code()), Some(137), "{st:?}");
    let mut err = String::new();
    m.child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    assert!(err.contains(&format!("[ALERT]    ({mpid}) : Current worker ({w}) exited with code 137 (Killed)\n")), "{err:?}");
    assert!(err.contains(&format!("[ALERT]    ({mpid}) : exit-on-failure: killing every processes with SIGTERM\n")), "{err:?}");
    assert!(err.contains(&format!("[WARNING]  ({mpid}) : All workers exited. Exiting... (137)\n")), "{err:?}");

    // And a worker goes when its master does (here SIGKILL'd, so it cannot tell it).
    m.child = start();
    wait_for_socket(&sock);
    assert!(common::wait_listening(std::net::SocketAddr::from(([127, 0, 0, 1], port))));
    let w = show_proc(&master(&sock, "show proc")).1[0].pid;
    m.child.kill().unwrap();
    let _ = m.child.wait();
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(w) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive(w), "the worker outlived its master");
}

/// The first worker failing to start (its port taken) ends the master with its code, as
/// HAProxy's (exit 1, measured), and leaves no socket behind.
#[test]
fn a_first_worker_that_does_not_start_ends_the_master() {
    let dir = PathBuf::from(format!("/tmp/t200f-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (sock, cfg) = (dir.join("m.sock"), dir.join("c.cfg"));
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std::fs::write(&cfg, config(taken.local_addr().unwrap().port(), "v1")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ibex"));
    cmd.args(["-W", "-S"]).arg(&sock).arg("-f").arg(&cfg);
    let out = run_briefly(&mut cmd);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(") exited with code 1 (Exit)\n") && err.contains("Failed to load worker ("), "{err:?}");
    assert!(!sock.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The binary removed under a running master (an upgrade gone wrong): the reload fails,
/// the serving worker goes on serving.
#[test]
fn a_reload_that_cannot_start_a_worker_keeps_the_old_one() {
    let dir = PathBuf::from(format!("/tmp/t200g-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (sock, cfg, bin) = (dir.join("m.sock"), dir.join("c.cfg"), dir.join("ibex"));
    std::fs::copy(env!("CARGO_BIN_EXE_ibex"), &bin).unwrap();
    let port = common::reserve_port();
    std::fs::write(&cfg, config(port, "v1")).unwrap();
    let child = Command::new(&bin)
        .args(["-W", "-S"])
        .arg(&sock)
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let _m = Master { child, dir: dir.clone() };
    wait_for_socket(&sock);
    assert!(common::wait_listening(std::net::SocketAddr::from(([127, 0, 0, 1], port))));
    std::fs::remove_file(&bin).unwrap();
    let out = master(&sock, "reload");
    assert!(out.starts_with("Success=0\n--\n"), "{out:?}");
    assert!(out.contains(" : Cannot fork new worker: "), "{out:?}");
    assert_eq!(get(port).unwrap(), "v1");
    assert_eq!(show_proc(&master(&sock, "show proc")).0.reloads, "1 [failed: 1]");
}
