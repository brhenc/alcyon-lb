// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Reloads, driven through the real binary the way an operator or systemd drives them.
//!
//! A reload is two processes overlapping: the new one starts on the same config, then tells
//! the old one to soft-stop with `-sf <pid>`. Everything that can go wrong is in the
//! overlap, so these tests start two processes and look at what survives.

use crate::common;

use rustix::process::{kill_process, Pid, Signal};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;


/// A short socket path: `HAProxy` rejects anything over 97 bytes, and a tempdir path is
/// easily longer than that.
fn short_sock(tag: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/ibex-rl-{}-{tag}.sock", std::process::id()))
}

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn config(fe: SocketAddr, be: SocketAddr, sock: &Path, extra_global: &str) -> String {
    format!(
        "global\n  stats socket {} mode 600 level admin{extra_global}\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe}\n  default_backend be\n\
         backend be\n  server s1 {be}\n",
        sock.display()
    )
}

struct Proc {
    child: Child,
}

impl Proc {
    fn start(cfg: &Path, extra: &[String]) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(cfg)
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex");
        Self { child }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn wait_exit(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(st) = self.child.try_wait().expect("try_wait") {
                return Some(st);
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }

    fn signal(&self, sig: Signal) {
        let pid = Pid::from_raw(i32::try_from(self.pid()).expect("pid")).expect("pid");
        let _ = kill_process(pid, sig);
    }

    /// Soft-stops the process and waits for it. Tests end this way rather than with
    /// SIGKILL: a killed process never writes its coverage profile, so everything it ran
    /// -- including the socket adoption only the *new* process performs -- would count
    /// as untested.
    fn stop(&mut self) {
        self.signal(Signal::Usr1);
        let _ = self.wait_exit(Duration::from_secs(5));
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "nothing listening on {addr}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn cli(sock: &Path, cmd: &str) -> Option<String> {
    let mut s = UnixStream::connect(sock).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(format!("{cmd}\n").as_bytes()).ok()?;
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    Some(out)
}

fn write_cfg(text: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write");
    f
}

/// `new -sf <old>`, the reload `HAProxy` has always supported, done once.
///
/// Two things have to survive it. The port, obviously. And the stats socket: both
/// processes are configured with the same path, the new one binds it first, and the old
/// one then exits. The old engine's `Drop` unlinked that path unconditionally, which
/// removed the *new* process's socket file -- after any reload the CLI was simply gone.
#[test]
fn a_graceful_reload_keeps_the_port_and_the_stats_socket() {
    let be = backend();
    let fe = common::reserve_addr();
    let sock = short_sock("graceful");
    let cfg = write_cfg(&config(fe, be, &sock, ""));

    let mut old = Proc::start(cfg.path(), &[]);
    wait_listening(fe);
    let old_info = cli(&sock, "show info").expect("old CLI answers");
    assert!(old_info.contains(&format!("Pid: {}", old.pid())), "{old_info}");

    let mut new = Proc::start(cfg.path(), &["-sf".into(), old.pid().to_string()]);
    let st = old.wait_exit(Duration::from_secs(5));
    assert!(
        st.is_some_and(|s| s.success()),
        "the old process must soft-stop and exit cleanly on -sf; got {st:?}"
    );

    wait_listening(fe);
    let info = cli(&sock, "show info");
    assert!(
        info.as_deref().is_some_and(|i| i.contains(&format!("Pid: {}", new.pid()))),
        "after the old process exits, the stats socket must still be the new process's; \
         got {info:?}"
    );
    let _ = std::fs::remove_file(&sock);
    new.stop();
}

/// A backend that holds `/hold` until `release` is set (at most 120 s), counting in `arrived` the
/// `/hold` requests it has received, and answers everything else at once.
fn holding_backend() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let arrived = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(AtomicBool::new(false));
    let (a, r) = (Arc::clone(&arrived), Arc::clone(&release));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let (a, r) = (Arc::clone(&a), Arc::clone(&r));
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                if String::from_utf8_lossy(&buf[..n]).contains("GET /hold") {
                    a.fetch_add(1, Ordering::SeqCst);
                    let end = Instant::now() + Duration::from_secs(120);
                    while !r.load(Ordering::SeqCst) && Instant::now() < end {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
    (addr, arrived, release)
}

fn read_all(s: &mut TcpStream, within: Duration) -> String {
    s.set_read_timeout(Some(within)).expect("timeout");
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What makes a reload *hitless* rather than graceful.
///
/// Connections the kernel has completed but the old process has not yet accepted sit in
/// the accept queue of the old process's socket. Every worker binds its own
/// `SO_REUSEPORT` socket, so a new process that binds fresh gets a queue of its own, and
/// the old queue is reset when the old process closes its socket -- however gracefully.
/// Only taking over the same socket (`-x`, served by `expose-fd listeners`) keeps it.
///
/// The scenario is made deterministic with `maxconn 1`: one held request fills the old
/// process, so it stops accepting, and the next connections are left queued on its socket.
#[test]
fn a_reload_with_x_keeps_the_connections_queued_on_the_old_socket() {
    const QUEUED: usize = 5;
    let (be, arrived, release) = holding_backend();
    let fe = common::reserve_addr();
    let sock = short_sock("hitless");
    let text = format!(
        "global\n  stats socket {} mode 600 level admin expose-fd listeners\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe}\n  maxconn 1\n  default_backend be\n\
         backend be\n  server s1 {be}\n",
        sock.display()
    );
    let cfg = write_cfg(&text);

    let mut old = Proc::start(cfg.path(), &[]);
    wait_listening(fe);
    let mut held = TcpStream::connect(fe).expect("connect held");
    held.write_all(b"GET /hold HTTP/1.1\r\nHost: x\r\n\r\n").expect("send held");
    // The backend has the held request: the old process accepted that connection, so its
    // `maxconn 1` is full (the probe of `wait_listening` only delays this, it cannot prevent it).
    let end = Instant::now() + Duration::from_secs(60);
    while arrived.load(Ordering::SeqCst) == 0 && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(arrived.load(Ordering::SeqCst), 1, "the held request never reached the backend");

    let mut queued: Vec<TcpStream> = (0..QUEUED)
        .map(|i| {
            let mut c = TcpStream::connect(fe).expect("connect queued");
            c.write_all(format!("GET /q{i} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
                .expect("send queued");
            c
        })
        .collect();

    // Sanity: they really are queued, not being served.
    let mut probe = [0u8; 1];
    queued[0].set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
    assert!(
        matches!(queued[0].read(&mut probe), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut),
        "the setup is wrong: the old process is serving connections it should be too full to accept"
    );

    let mut new = Proc::start(
        cfg.path(),
        &["-x".into(), sock.display().to_string(), "-sf".into(), old.pid().to_string()],
    );

    for (i, c) in queued.iter_mut().enumerate() {
        let resp = read_all(c, Duration::from_secs(5));
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "queued connection {i} was lost across the reload -- the old socket and its \
             accept queue did not survive; got {resp:?}"
        );
    }

    release.store(true, Ordering::SeqCst);
    let held_resp = read_all(&mut held, Duration::from_secs(5));
    assert!(held_resp.starts_with("HTTP/1.1 200"), "held request: {held_resp:?}");
    let st = old.wait_exit(Duration::from_secs(5));
    assert!(st.is_some_and(|s| s.success()), "old process: {st:?}");

    let _ = std::fs::remove_file(&sock);
    new.stop();
}

/// When the sockets cannot be taken over, the new process must refuse to start rather
/// than fall back to binding fresh ones -- `HAProxy`'s behaviour (`src/haproxy.c:2069`). It
/// is the safe failure: `-sf` is only sent once the new process is listening, so the old
/// one is never told to stop and keeps serving as if no reload had been attempted.
#[test]
fn x_against_a_process_that_does_not_expose_its_sockets_leaves_it_serving() {
    let be = backend();
    let fe = common::reserve_addr();
    let sock = short_sock("noexpose");
    let cfg = write_cfg(&config(fe, be, &sock, ""));

    let mut old = Proc::start(cfg.path(), &[]);
    wait_listening(fe);

    let mut new = Proc::start(
        cfg.path(),
        &["-x".into(), sock.display().to_string(), "-sf".into(), old.pid().to_string()],
    );
    let st = new.wait_exit(Duration::from_secs(5));
    assert!(
        st.is_some_and(|s| !s.success()),
        "without `expose-fd listeners` on the old socket, -x must fail and the new process \
         must not start; got {st:?}"
    );

    assert!(old.wait_exit(Duration::from_millis(500)).is_none(), "the old process was stopped");
    let mut c = TcpStream::connect(fe).expect("old still accepting");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let resp = read_all(&mut c, Duration::from_secs(3));
    assert!(resp.starts_with("HTTP/1.1 200"), "old process must still serve: {resp:?}");
    let _ = std::fs::remove_file(&sock);
    old.stop();
}

/// Collects `sd_notify` datagrams the way systemd would receive them.
struct NotifySink {
    sock: std::os::unix::net::UnixDatagram,
    path: PathBuf,
    seen: Vec<String>,
}

impl NotifySink {
    fn new(tag: &str) -> Self {
        let path = PathBuf::from(format!("/tmp/ibex-rl-{}-{tag}.ntf", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sock = std::os::unix::net::UnixDatagram::bind(&path).expect("bind notify");
        sock.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
        Self { sock, path, seen: Vec::new() }
    }

    /// Waits for a datagram containing `needle`; returns it.
    fn wait_for(&mut self, needle: &str, within: Duration) -> Option<String> {
        self.wait_until(|m| m.contains(needle), within)
    }

    /// Waits for a datagram satisfying `pred`; returns it.
    fn wait_until(&mut self, pred: impl Fn(&str) -> bool, within: Duration) -> Option<String> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(m) = self.seen.iter().find(|m| pred(m)) {
                return Some(m.clone());
            }
            if Instant::now() >= deadline {
                return None;
            }
            let mut buf = [0u8; 4096];
            if let Ok(n) = self.sock.recv(&mut buf) {
                self.seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
        }
    }
}

impl Drop for NotifySink {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn read_pidfile(p: &Path) -> Option<u32> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

fn alive(pid: u32) -> bool {
    Pid::from_raw(i32::try_from(pid).unwrap_or(0))
        .is_some_and(|p| rustix::process::test_kill_process(p).is_ok())
}

fn wait_gone(pid: u32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while alive(pid) {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
    true
}

fn send_signal(pid: u32, sig: Signal) {
    if let Some(p) = Pid::from_raw(i32::try_from(pid).unwrap_or(0)) {
        let _ = kill_process(p, sig);
    }
}

fn mainpid(msg: &str) -> Option<u32> {
    msg.lines().find_map(|l| l.strip_prefix("MAINPID=")).and_then(|p| p.parse().ok())
}

/// Soft-stops a process this test did not spawn (the one a reload started), and waits for
/// it to go. See `Proc::stop` for why not SIGKILL.
fn stop_pid(pid: u32) {
    let Some(p) = Pid::from_raw(i32::try_from(pid).unwrap_or(0)) else { return };
    let _ = kill_process(p, Signal::Usr1);
    let deadline = Instant::now() + Duration::from_secs(5);
    while rustix::process::test_kill_process(p).is_ok() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let _ = kill_process(p, Signal::Kill);
}

fn start_notified(cfg: &Path, sink: &NotifySink, pidfile: &Path) -> Proc {
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-Ws")
        .arg("-f")
        .arg(cfg)
        .arg("-p")
        .arg(pidfile)
        .env("NOTIFY_SOCKET", &sink.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    Proc { child }
}

/// `systemctl reload` with `HAProxy`'s own unit file is `kill -USR2 $MAINPID`
/// (`admin/systemd/haproxy.service.in`). `SIGUSR2` had no handler, so the default action
/// terminated the service: a reload was a crash, and `Restart=always` brought it back cold.
///
/// Ibex has no separate master process to keep the PID stable, so the serving PID changes
/// on reload. The old process -- still systemd's main PID, so this works under the default
/// `NotifyAccess=main` -- announces the new one with `MAINPID=` before it starts to stop.
#[test]
fn sigusr2_reloads_and_hands_the_main_pid_to_the_new_process() {
    let be = backend();
    let fe = common::reserve_addr();
    let sock = short_sock("usr2");
    let cfg = write_cfg(&config(fe, be, &sock, ""));
    let mut sink = NotifySink::new("usr2");
    let pidfile = short_sock("usr2").with_extension("pid");

    let mut old = start_notified(cfg.path(), &sink, &pidfile);
    let ready = sink.wait_for("READY=1", Duration::from_secs(5)).expect("initial READY=1");
    assert_eq!(mainpid(&ready), Some(old.pid()), "{ready:?}");
    wait_listening(fe);

    old.signal(Signal::Usr2);

    assert!(
        sink.wait_for("RELOADING=1", Duration::from_secs(3)).is_some(),
        "a reload must announce RELOADING=1; got {:?}",
        sink.seen
    );
    let old_pid = old.pid();
    let handed = sink.wait_until(
        |m| m.contains("READY=1") && mainpid(m).is_some_and(|p| p != old_pid),
        Duration::from_secs(5),
    );
    let new_pid = handed
        .as_deref()
        .and_then(mainpid)
        .unwrap_or_else(|| panic!("no MAINPID handover to a new process; saw {:?}", sink.seen));

    let st = old.wait_exit(Duration::from_secs(5));
    assert!(
        st.is_some_and(|s| s.success()),
        "the old process must hand over, drain and exit cleanly; got {st:?}"
    );
    // Drain anything still in flight, then check the old process never said STOPPING=1.
    // It is systemd's main PID when it begins to drain, so systemd would read that as the
    // service going down in the middle of the reload.
    let _ = sink.wait_for("never-sent", Duration::from_millis(300));
    assert!(
        !sink.seen.iter().any(|m| m.contains("STOPPING=1")),
        "a reload must not announce STOPPING=1; saw {:?}",
        sink.seen
    );

    wait_listening(fe);
    let info = cli(&sock, "show info");
    assert!(
        info.as_deref().is_some_and(|i| i.contains(&format!("Pid: {new_pid}"))),
        "the process named in MAINPID must be the one serving; got {info:?}"
    );
    assert_eq!(
        read_pidfile(&pidfile),
        Some(new_pid),
        "after a reload the pidfile must name the process now serving"
    );

    // Again, from the process the first reload started. It was itself started with
    // `-x <socket> -sf <pid>`; those must be replaced, not passed on, or the second reload
    // would try to take sockets from a process that no longer exists.
    send_signal(new_pid, Signal::Usr2);
    let third = sink
        .wait_until(
            |m| m.contains("READY=1") && mainpid(m).is_some_and(|p| p != old_pid && p != new_pid),
            Duration::from_secs(5),
        )
        .as_deref()
        .and_then(mainpid)
        .unwrap_or_else(|| panic!("second reload: no handover; saw {:?}", sink.seen));
    assert!(wait_gone(new_pid, Duration::from_secs(5)), "second reload: {new_pid} did not exit");
    // The arguments a reload passes on must describe *this* reload only. Inheriting the
    // previous `-sf` still works -- the option parser accumulates `-sf` -- but it signals
    // the previous PID again, which by now may belong to an unrelated process.
    let argv = std::fs::read(format!("/proc/{third}/cmdline")).unwrap_or_default();
    let argv: Vec<String> =
        argv.split(|&b| b == 0).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    assert_eq!(argv.iter().filter(|a| *a == "-x").count(), 1, "one -x: {argv:?}");
    assert_eq!(argv.iter().filter(|a| *a == "-sf").count(), 1, "one -sf: {argv:?}");
    let sf = argv.iter().position(|a| a == "-sf").map(|i| argv[i + 1].clone());
    assert_eq!(sf, Some(new_pid.to_string()), "-sf must name only the process being replaced: {argv:?}");
    wait_listening(fe);
    let info = cli(&sock, "show info");
    assert!(
        info.as_deref().is_some_and(|i| i.contains(&format!("Pid: {third}"))),
        "second reload: the process named in MAINPID must be serving; got {info:?}"
    );
    assert_eq!(read_pidfile(&pidfile), Some(third), "second reload: pidfile");

    stop_pid(third);
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pidfile);
}

/// `HAProxy`'s property that makes reloads safe to automate: a new configuration that does
/// not load leaves the running one serving (`doc/internals/mworker.md`, V3). systemd is
/// told the reload failed, and nothing else changes.
#[test]
fn a_reload_with_a_broken_config_leaves_the_old_process_serving() {
    let be = backend();
    let fe = common::reserve_addr();
    let sock = short_sock("usr2bad");
    let cfg = write_cfg(&config(fe, be, &sock, ""));
    let mut sink = NotifySink::new("usr2bad");
    let pidfile = short_sock("usr2bad").with_extension("pid");

    let mut old = start_notified(cfg.path(), &sink, &pidfile);
    sink.wait_for("READY=1", Duration::from_secs(5)).expect("initial READY=1");
    wait_listening(fe);

    std::fs::write(cfg.path(), "frontend fe\n  this-is-not-a-keyword\n").expect("break cfg");

    old.signal(Signal::Usr2);
    assert!(
        sink.wait_for("Reload failed", Duration::from_secs(5)).is_some(),
        "systemd must be told the reload failed; saw {:?}",
        sink.seen
    );
    assert!(
        old.wait_exit(Duration::from_millis(500)).is_none(),
        "a failed reload must not stop the running process"
    );
    assert_eq!(
        read_pidfile(&pidfile),
        Some(old.pid()),
        "a failed reload must leave the pidfile naming the process still serving"
    );
    let mut c = TcpStream::connect(fe).expect("still accepting");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let resp = read_all(&mut c, Duration::from_secs(3));
    assert!(resp.starts_with("HTTP/1.1 200"), "old process must still serve: {resp:?}");
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pidfile);
    old.stop();
}

/// A reload can also fail *after* the new configuration has loaded -- here, a bind to an
/// address this host does not have. By then a process that wrote its pidfile at startup
/// would have replaced the running process's PID with its own, and then exited. The
/// pidfile must go on naming the process that is actually serving.
#[test]
fn a_reload_that_fails_after_loading_its_config_leaves_the_pidfile_alone() {
    let be = backend();
    let fe = common::reserve_addr();
    let sock = short_sock("latefail");
    let cfg = write_cfg(&config(fe, be, &sock, ""));
    let mut sink = NotifySink::new("latefail");
    let pidfile = short_sock("latefail").with_extension("pid");

    let mut old = start_notified(cfg.path(), &sink, &pidfile);
    sink.wait_for("READY=1", Duration::from_secs(5)).expect("initial READY=1");
    wait_listening(fe);
    assert_eq!(read_pidfile(&pidfile), Some(old.pid()));

    // Parses; cannot bind. 192.0.2.1 is TEST-NET-1 (RFC 5737), never a local address.
    // Not `set_len(0)` then `write_all`: truncating leaves the write offset where it was,
    // so the new text lands after a run of NUL bytes, the config fails to *parse*, and the
    // process never gets as far as the pidfile -- the path this test exists for. An earlier
    // version did exactly that and passed with the pidfile deferral removed.
    let unbindable = config(fe, be, &sock, "").replace(&format!("bind {fe}"), "bind 192.0.2.1:80");
    std::fs::write(cfg.path(), unbindable).expect("rewrite cfg");

    old.signal(Signal::Usr2);
    assert!(
        sink.wait_for("Reload failed", Duration::from_secs(5)).is_some(),
        "the reload must be reported as failed; saw {:?}",
        sink.seen
    );
    assert_eq!(
        read_pidfile(&pidfile),
        Some(old.pid()),
        "a reload that failed after loading its config must leave the pidfile naming the \
         process still serving"
    );
    assert!(old.wait_exit(Duration::from_millis(300)).is_none(), "old process stopped");
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pidfile);
    old.stop();
}

/// Without `-W` / `-Ws`, `SIGUSR2` is ignored, as in `HAProxy`'s standalone mode
/// (`src/haproxy.c:2606`). Before the handler existed it was the default action: the
/// process died.
#[test]
fn sigusr2_without_w_is_ignored_not_fatal() {
    let be = backend();
    let fe = common::reserve_addr();
    let sock = short_sock("nousr2");
    let cfg = write_cfg(&config(fe, be, &sock, ""));
    let mut p = Proc::start(cfg.path(), &[]);
    wait_listening(fe);
    p.signal(Signal::Usr2);
    assert!(p.wait_exit(Duration::from_millis(500)).is_none(), "SIGUSR2 stopped the process");
    let mut c = TcpStream::connect(fe).expect("still accepting");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    assert!(read_all(&mut c, Duration::from_secs(3)).starts_with("HTTP/1.1 200"));
    let _ = std::fs::remove_file(&sock);
    p.stop();
}

/// A reload onto a configuration that no longer binds an address must close that
/// address's socket. The old process hands every listener over; one the new process has
/// no bind for would otherwise stay open in it -- listening, queueing connections, and
/// never accepting them. `HAProxy` drops these (`sock_drop_unused_old_sockets`).
#[test]
fn a_reload_that_drops_a_bind_closes_its_socket() {
    let be = backend();
    let fe1 = common::reserve_addr();
    let fe2 = common::reserve_addr();
    let sock = short_sock("dropbind");
    let mut sink = NotifySink::new("dropbind");
    let pidfile = short_sock("dropbind").with_extension("pid");
    let two = config(fe1, be, &sock, "").replace(
        &format!("  bind {fe1}\n"),
        &format!("  bind {fe1}\n  bind {fe2}\n"),
    );
    let cfg = write_cfg(&two);

    let mut old = start_notified(cfg.path(), &sink, &pidfile);
    sink.wait_for("READY=1", Duration::from_secs(5)).expect("initial READY=1");
    wait_listening(fe1);
    wait_listening(fe2);

    std::fs::write(cfg.path(), config(fe1, be, &sock, "")).expect("drop the second bind");
    let old_pid = old.pid();
    old.signal(Signal::Usr2);
    let new_pid = sink
        .wait_until(
            |m| m.contains("READY=1") && mainpid(m).is_some_and(|p| p != old_pid),
            Duration::from_secs(5),
        )
        .as_deref()
        .and_then(mainpid)
        .unwrap_or_else(|| panic!("no handover; saw {:?}", sink.seen));
    // `old` is this test's own child: once it exits it is a zombie until reaped, and
    // `kill(pid, 0)` goes on succeeding for a zombie, so `wait_gone` would wait forever.
    let st = old.wait_exit(Duration::from_secs(5));
    assert!(st.is_some_and(|s| s.success()), "old process did not exit cleanly: {st:?}");

    wait_listening(fe1);
    assert!(
        TcpStream::connect(fe2).is_err(),
        "{fe2} was dropped from the configuration but its socket is still listening"
    );
    stop_pid(new_pid);
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&pidfile);
}

/// The listening inodes of `port` in `/proc/net/<table>` (`udp`, `udp6` or `tcp`; for tcp
/// only the sockets in LISTEN).
fn socket_inodes(table: &str, port: u16) -> Vec<String> {
    let text = std::fs::read_to_string(format!("/proc/net/{table}")).expect("proc net");
    let mut out: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let local_port = f.get(1)?.rsplit(':').next()?;
            let listening = table.starts_with("udp") || f.get(3) == Some(&"0A");
            (u16::from_str_radix(local_port, 16).ok() == Some(port) && listening).then(|| f[9].to_string())
        })
        .collect();
    out.sort();
    out
}

/// A `log-forward` section's `dgram-bind` and `bind` sockets are taken over by `-x` like a
/// proxy's: measured on HAProxy 3.5-dev8 (`expose-fd listeners`, then `-x <sock> -sf
/// <old>`), the sockets on those ports have the same inodes after the reload.
#[test]
fn a_reload_with_x_takes_over_the_log_forward_sockets() {
    let fe = common::reserve_addr();
    let udp = common::reserve_port();
    let tcp = common::reserve_port();
    std::net::UdpSocket::bind("[::1]:0").expect("an ipv6 loopback");
    let udp6 = common::reserve_port();
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("sink");
    let sock = short_sock("logfwd");
    let text = format!(
        "global\n  stats socket {} mode 600 level admin expose-fd listeners\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe}\n  http-request return status 200\n\
         log-forward lf\n  dgram-bind 127.0.0.1:{udp}\n  dgram-bind [::1]:{udp6}\n  bind 127.0.0.1:{tcp}\n  log {} format raw local0\n",
        sock.display(),
        sink.local_addr().expect("sink addr")
    );
    let cfg = write_cfg(&text);
    let mut old = Proc::start(cfg.path(), &[]);
    wait_listening(fe);
    wait_listening(SocketAddr::from(([127, 0, 0, 1], tcp)));
    let before = (socket_inodes("udp", udp), socket_inodes("tcp", tcp), socket_inodes("udp6", udp6));
    assert_eq!((before.0.len(), before.1.len(), before.2.len()), (1, 1, 1), "{before:?}");

    let mut new = Proc::start(cfg.path(), &["-x".into(), sock.display().to_string(), "-sf".into(), old.pid().to_string()]);
    let st = old.wait_exit(Duration::from_secs(5));
    assert!(st.is_some_and(|s| s.success()), "old process: {st:?}");
    wait_listening(fe);
    let after = (socket_inodes("udp", udp), socket_inodes("tcp", tcp), socket_inodes("udp6", udp6));
    let _ = std::fs::remove_file(&sock);
    new.stop();
    assert_eq!(after, before, "the new process bound sockets of its own instead of taking the old ones over");
}
