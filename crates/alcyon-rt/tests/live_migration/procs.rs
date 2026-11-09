// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Spawning Alcyon, reloading it, and asking its stats socket who owns what.

use super::iface::{self, Reload};
use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// How long any process start, reload or exit may take before the test fails instead of
/// hanging.
pub const START_WITHIN: Duration = Duration::from_secs(10);
/// How long the old process may take to exit after a reload. Every configuration here sets
/// `hard-stop-after 2s` (see `GLOBAL`), so a healthy old process is gone well before this.
pub const EXIT_WITHIN: Duration = Duration::from_secs(10);

/// The binary under test: `ALCYON_BIN` when set (to run this harness against another
/// build), otherwise the one cargo built for this test.
#[must_use]
pub fn alcyon_bin() -> PathBuf {
    std::env::var_os("ALCYON_BIN").map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_alcyon")), PathBuf::from)
}

/// A unique, short path under `/tmp`. Unix socket paths are limited to 107 bytes and
/// `HAProxy` rejects more than 97, which a tempdir path easily exceeds.
#[must_use]
pub fn short_path(tag: &str, ext: &str) -> PathBuf {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let p = PathBuf::from(format!("/tmp/t96-{}-{n}-{tag}.{ext}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// A file removed when dropped.
pub struct TempPath(pub PathBuf);

impl TempPath {
    #[must_use]
    pub fn new(tag: &str, ext: &str) -> Self {
        Self(short_path(tag, ext))
    }
    pub fn write(&self, text: &str) {
        std::fs::write(&self.0, text).expect("write temp file");
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn pid_of(pid: u32) -> Option<Pid> {
    Pid::from_raw(i32::try_from(pid).ok()?)
}

pub fn send_signal(pid: u32, sig: Signal) {
    if let Some(p) = pid_of(pid) {
        let _ = kill_process(p, sig);
    }
}

/// Whether `pid` exists and is not a zombie.
#[must_use]
pub fn alive(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { return false };
    // The state follows the parenthesised command name, which may itself contain spaces.
    let state = stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().next());
    !matches!(state, Some("Z" | "X") | None)
}

/// A spawned Alcyon. Its stderr goes to a file, so a failure can show what it said.
pub struct Alcyon {
    child: Child,
    pid: u32,
    stderr: TempPath,
    status: Option<ExitStatus>,
}

impl Alcyon {
    /// Spawns `alcyon -f <cfg> <args>`.
    ///
    /// # Panics
    /// When the binary cannot be spawned at all.
    #[must_use]
    pub fn spawn(cfg: &Path, args: &[String]) -> Self {
        let stderr = TempPath::new("err", "log");
        let file = std::fs::File::create(stderr.path()).expect("create stderr log");
        let child = Command::new(alcyon_bin())
            .arg("-f")
            .arg(cfg)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(file)
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", alcyon_bin().display()));
        let pid = child.id();
        Self { child, pid, stderr, status: None }
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// What the process has written to stderr so far.
    #[must_use]
    pub fn stderr(&self) -> String {
        std::fs::read_to_string(self.stderr.path()).unwrap_or_default()
    }

    /// The exit status, if it has exited.
    pub fn exited(&mut self) -> Option<ExitStatus> {
        if self.status.is_none() {
            self.status = self.child.try_wait().ok().flatten();
        }
        self.status
    }

    /// Waits up to `within` for the process to exit.
    pub fn wait_exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(st) = self.exited() {
                return Some(st);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn signal(&self, sig: Signal) {
        if self.status.is_none() {
            send_signal(self.pid, sig);
        }
    }
}

impl Drop for Alcyon {
    /// Soft stop, then `SIGKILL`: a killed process writes no coverage profile (see
    /// `common::stop`).
    fn drop(&mut self) {
        if self.exited().is_some() {
            return;
        }
        self.signal(Signal::Usr1);
        if self.wait_exit(Duration::from_secs(5)).is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// A process this test did not spawn directly: one a `-W` master started on reload.
/// Stopped when dropped, so a failing test does not leak it.
pub struct Foreign(pub u32);

impl Drop for Foreign {
    fn drop(&mut self) {
        send_signal(self.0, Signal::Usr1);
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(self.0) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if alive(self.0) {
            send_signal(self.0, Signal::Kill);
        }
    }
}

/// Sends `cmd` to the stats socket and returns the whole answer.
#[must_use]
pub fn cli(sock: &Path, cmd: &str) -> Option<String> {
    let mut s = UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(format!("{cmd}\n").as_bytes()).ok()?;
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    Some(out)
}

/// The PID the process behind `sock` reports in `show info`.
#[must_use]
pub fn cli_pid(sock: &Path) -> Option<u32> {
    let info = cli(sock, "show info")?;
    info.lines().find_map(|l| l.strip_prefix("Pid: ")).and_then(|p| p.trim().parse().ok())
}

/// `CurrConns` from `show info`: the client connections the process holds, idle ones
/// included.
#[must_use]
pub fn curr_conns(sock: &Path) -> Option<u64> {
    let info = cli(sock, "show info")?;
    info.lines().find_map(|l| l.strip_prefix("CurrConns: ")).and_then(|p| p.trim().parse().ok())
}

/// Waits until the process with `pid` answers on `sock`, panicking with its stderr if it
/// exits first. `exited` reports whether it has exited, and with what.
fn wait_cli_pid(sock: &Path, pid: u32, who: &str, mut exited: impl FnMut() -> Option<String>) {
    let deadline = Instant::now() + START_WITHIN;
    loop {
        if cli_pid(sock) == Some(pid) {
            return;
        }
        if let Some(why) = exited() {
            panic!("{who} (pid {pid}) exited before serving its stats socket: {why}");
        }
        assert!(Instant::now() < deadline, "{who} (pid {pid}) never answered on {}", sock.display());
        thread::sleep(Duration::from_millis(20));
    }
}

/// Starts the first process of a scenario and waits until it serves `fe` and its stats
/// socket.
///
/// # Panics
/// When it does not start; the message carries its stderr, so a configuration it refuses
/// is named as such.
#[must_use]
pub fn start(cfg: &Path, args: &[String], sock: &Path, fe: SocketAddr) -> Alcyon {
    let mut p = Alcyon::spawn(cfg, args);
    let pid = p.pid();
    let mut probe = || p.exited().map(|st| format!("{st}; stderr: {}", p.stderr()));
    wait_cli_pid(sock, pid, "the first alcyon process", &mut probe);
    assert!(crate::common::wait_listening(fe), "alcyon never listened on {fe}");
    p
}

/// Reloads: starts the process that replaces `old` (`-x <sock> [--migrate-conns] -sf
/// <old>`) on `cfg`, and waits until it answers on the stats socket.
///
/// # Panics
/// When the new process exits instead; the message carries its stderr (an unknown
/// command-line flag shows up here).
#[must_use]
pub fn reload(old: &Alcyon, cfg: &Path, sock: &Path, how: Reload) -> Alcyon {
    let mut new = Alcyon::spawn(cfg, &iface::reload_args(sock, old.pid(), how));
    let pid = new.pid();
    let mut probe = || new.exited().map(|st| format!("{st}; stderr: {}", new.stderr()));
    wait_cli_pid(sock, pid, "the new process of the reload", &mut probe);
    new
}

/// Waits for the old process to exit, panicking if it does not.
///
/// Every check that a connection "survived" is made *after* this returns: until the old
/// process is gone, a working connection proves nothing, because it may still be the old
/// process serving it.
pub fn wait_gone(old: &mut Alcyon) -> ExitStatus {
    old.wait_exit(EXIT_WITHIN).unwrap_or_else(|| {
        panic!(
            "the old process (pid {}) did not exit within {EXIT_WITHIN:?} of the reload; stderr: {}",
            old.pid(),
            old.stderr()
        )
    })
}

/// The new process holds at least `n` client connections (`show info` `CurrConns`). Called
/// only once the old process has exited, so the count cannot include anything the old
/// process holds.
pub fn assert_holds_at_least(sock: &Path, n: u64, what: &str) {
    let got = curr_conns(sock);
    assert!(
        got.is_some_and(|c| c >= n),
        "{what}: after the old process exited, the new one must hold the {n} migrated \
         connection(s); its `show info` reports CurrConns {got:?}"
    );
}

/// The new process's `show sess` lists a stream whose client is `client` (the test's
/// local address), the way `HAProxy` prints one: `src=127.0.0.1:<port> fe=<fe>`.
///
/// `HAProxy` lists streams, not connections, so this applies to a connection with a
/// transaction or a TCP stream in progress; an idle HTTP/1 keep-alive connection is not
/// listed by `HAProxy` either, and is checked with [`assert_holds_at_least`] instead.
///
/// `ALCYON_T96_NO_SHOW_SESS=1` skips this check, loudly, for running the harness against a
/// build that has no `show sess` (agy's). It is never set by default.
///
/// It first checks `CurrConns`, which exists today, so that a connection that was simply
/// lost is reported as lost rather than as a missing CLI command.
pub fn assert_show_sess_lists(sock: &Path, client: SocketAddr, fe: &str) {
    assert_holds_at_least(sock, 1, &format!("the stream from {client}"));
    if std::env::var_os("ALCYON_T96_NO_SHOW_SESS").is_some() {
        eprintln!("ALCYON_T96_NO_SHOW_SESS is set: NOT checking `show sess` for {client}");
        return;
    }
    let out = cli(sock, "show sess").unwrap_or_default();
    let needle = format!("src={client} ");
    let listed = out.lines().any(|l| l.contains(&needle) && l.contains(&format!("fe={fe} ")));
    assert!(
        listed,
        "after the old process exited, the new process's `show sess` must list the migrated \
         stream from {client} on frontend {fe}; it answered:\n{out}"
    );
}
