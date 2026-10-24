// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T456: SIGTTOU (pause), SIGTTIN (resume) and SIGUSR1 (soft stop) with several threads,
//! standalone and under `-W`, against `HAProxy` 3.5-dev8-885761-29 (`nbthread 4`):
//!
//! - SIGTTOU pauses every listener: a TCP connect to a frontend is refused until SIGTTIN
//!   (`tcp_suspend_receiver`: `connect(AF_UNSPEC)` takes the socket out of the listening
//!   state, `tcp_resume_receiver` `listen()`s again). A socket-file stats socket goes on
//!   answering (`uxst_suspend_receiver` only stops polling it).
//! - The log says it once per process, per proxy with a listener, in configuration order,
//!   `GLOBAL` last when there is a stats socket: `Paused frontend fe.`, `Paused proxy li.`
//!   (a `listen`), ..., `Paused frontend GLOBAL.`, the same with `Resumed` on SIGTTIN. A
//!   second SIGTTOU while paused, or SIGTTIN while running, logs nothing.
//!
//! These spawn ibex and signal the child, not the test process: they share the `it` binary.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Run {
    ibex: common::Ibex,
    dir: std::path::PathBuf,
    sock: String,
    addrs: Vec<SocketAddr>,
    err: Arc<Mutex<String>>,
}

impl Drop for Run {
    fn drop(&mut self) {
        common::stop(&mut self.ibex);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Run {
    fn signal(&self, sig: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_raw(i32::try_from(self.ibex.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, sig).unwrap();
    }

    /// The stderr lines seen so far that contain `what`.
    fn lines(&self, what: &str) -> Vec<String> {
        self.err.lock().unwrap().lines().filter(|l| l.contains(what)).map(|l| l[l.find(" : ").map_or(0, |i| i + 3)..].to_string()).collect()
    }
}

/// `frontend fe`, `listen li`, a `backend`, `frontend fe2` with two binds; a stats socket file.
const RET: &str = "  http-request return status 200 content-type text/plain string ok\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 30s\n  timeout server 30s\n";

fn start(tag: &str, nbthread: usize, args: &[&str]) -> Run {
    start_cfg(tag, 4, args, |sock, a| {
        format!(
            "global\n  stats socket {sock} level admin\n  nbthread {nbthread}\n{DEFAULTS}\
             frontend fe\n  bind {}\n{RET}\
             listen li\n  bind {}\n{RET}\
             backend be\n  server s 127.0.0.1:1\n\
             frontend fe2\n  bind {}\n  bind {}\n{RET}",
            a[0], a[1], a[2], a[3]
        )
    })
}

/// Starts ibex on the configuration `cfg` makes from the stats socket file and `n` addresses.
fn start_cfg(tag: &str, n: usize, args: &[&str], cfg: impl Fn(&str, &[SocketAddr]) -> String) -> Run {
    let addrs: Vec<SocketAddr> = (0..n).map(|_| common::reserve_addr()).collect();
    let dir = std::env::temp_dir().join(format!("t456-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = cfg(&sock, &addrs);
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .args(args)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let err = Arc::new(Mutex::new(String::new()));
    let pipe = child.stderr.take().unwrap();
    let sink = Arc::clone(&err);
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            let mut s = sink.lock().unwrap();
            s.push_str(&line);
            s.push('\n');
        }
    });
    let run = Run { ibex: common::Ibex(child), dir, sock, addrs, err };
    for a in &run.addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&run.sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    run
}

/// `Some(true)` answered 200, `Some(false)` refused, `None` anything else.
fn get(addr: SocketAddr) -> Option<bool> {
    let mut s = match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Some(false),
        Err(_) => return None,
    };
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").ok()?;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out.starts_with(b"HTTP/1.1 200").then_some(true)
}

/// Waits up to 2 s for every listener to answer (`true`) or to refuse (`false`). Each
/// connect is a new SYN the kernel hashes to one of the threads' sockets, so several
/// rounds reach every thread.
fn all(run: &Run, want: bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let got: Vec<Option<bool>> = (0..8).flat_map(|_| run.addrs.iter().map(|a| get(*a))).collect();
        if got.iter().all(|g| *g == Some(want)) {
            return;
        }
        assert!(Instant::now() < deadline, "want every listener {}: {got:?}", if want { "serving" } else { "refusing" });
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn pause_and_resume(tag: &str, args: &[&str]) {
    use rustix::process::Signal;
    let run = start(tag, 4, args);
    all(&run, true);
    run.signal(Signal::Ttou);
    all(&run, false);
    assert!(cli(&run.sock, "show info").contains("Name: "), "the stats socket file answers while paused");
    run.signal(Signal::Ttin);
    all(&run, true);
    // Again: a second cycle works as the first.
    run.signal(Signal::Ttou);
    all(&run, false);
    run.signal(Signal::Ttin);
    all(&run, true);
}

#[test]
fn sigttou_refuses_tcp_connections_until_sigttin() {
    pause_and_resume("plain", &[]);
}

#[test]
fn sigttou_refuses_tcp_connections_until_sigttin_under_w() {
    pause_and_resume("w", &["-W"]);
}

#[test]
fn pause_and_resume_are_logged_once_per_process() {
    use rustix::process::Signal;
    let run = start("log", 4, &[]);
    run.signal(Signal::Ttou);
    std::thread::sleep(Duration::from_millis(300));
    // A second SIGTTOU while paused logs nothing more.
    run.signal(Signal::Ttou);
    std::thread::sleep(Duration::from_millis(300));
    run.signal(Signal::Ttin);
    std::thread::sleep(Duration::from_millis(300));
    run.signal(Signal::Ttin);
    std::thread::sleep(Duration::from_millis(300));
    let want = [
        "Paused frontend fe.",
        "Paused proxy li.",
        "Paused frontend fe2.",
        "Paused frontend GLOBAL.",
        "Resumed frontend fe.",
        "Resumed proxy li.",
        "Resumed frontend fe2.",
        "Resumed frontend GLOBAL.",
    ];
    let mut got = run.lines("Paused ");
    got.extend(run.lines("Resumed "));
    assert_eq!(got, want, "stderr:\n{}", run.err.lock().unwrap());
}

/// Row 4: a soft stop (SIGUSR1) with an interactive CLI session open and nothing else. On
/// `HAProxy` (nbthread 4, plain and `-W`) the session goes on answering for as long as it
/// stays open (3 s measured), and the process exits once it is closed. Ibex's worker 0,
/// which serves the CLI, stopped as soon as it had no client session, and the CLI session
/// went with it (a broken pipe on the next command).
fn soft_stop_keeps_the_cli_session(tag: &str, args: &[&str]) {
    let mut run = start(tag, 4, args);
    let mut s = UnixStream::connect(&run.sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let cmd = |s: &mut UnixStream, c: &str| -> String {
        if s.write_all(format!("{c}\n").as_bytes()).is_err() {
            return "<write failed>".into();
        }
        let mut out = Vec::new();
        let mut b = [0u8; 8192];
        while !out.ends_with(b"\n> ") {
            match s.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&b[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    cmd(&mut s, "prompt");
    run.signal(rustix::process::Signal::Usr1);
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(500));
        assert!(run.ibex.try_wait().unwrap().is_none(), "ibex exited with a CLI session open");
        let info = cmd(&mut s, "show info");
        assert!(info.contains("Name: "), "the CLI session during the soft stop: {info:?}");
    }
    drop(s);
    let deadline = Instant::now() + Duration::from_secs(5);
    while run.ibex.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "ibex did not exit once the CLI session closed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_soft_stop_keeps_an_open_cli_session() {
    soft_stop_keeps_the_cli_session("usr1", &[]);
}

#[test]
fn a_soft_stop_keeps_an_open_cli_session_under_w() {
    soft_stop_keeps_the_cli_session("usr1w", &["-W"]);
}

/// Row 3: under `-W -S` the master runs the worker as a process of its own, and relays
/// SIGTTOU and SIGTTIN to it as `HAProxy`'s does (measured: TTOU to the master refuses
/// connections, TTIN serves them again; the worker logs it).
#[test]
fn the_master_relays_sigttou_and_sigttin_to_the_workers() {
    let master_sock = std::env::temp_dir().join(format!("t456-master-{}.sock", std::process::id()));
    let ms = master_sock.display().to_string();
    pause_and_resume("master", &["-W", "-S", &ms]);
    let _ = std::fs::remove_file(&master_sock);
}

/// One request on `s`, its answer awaited `wait`: the first bytes, or `TIMEOUT` / `RESET`.
fn answer(s: &mut TcpStream, wait: Duration) -> String {
    s.set_read_timeout(Some(wait)).unwrap();
    let mut b = [0u8; 12];
    match s.read(&mut b) {
        Ok(n) => String::from_utf8_lossy(&b[..n]).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => "RESET".into(),
        Err(_) => "TIMEOUT".into(),
    }
}

/// SIGTTIN while a `maxconn` holds the listener full: it stays stopped until the limit has
/// room. `HAProxy` 3.5-dev8-885761-29 (nbthread 1, `maxconn 1` in `global` with `maxconn 10`
/// in the frontend, or `maxconn 1` in the frontend; one connection held with half a request, a second one queued, SIGTTOU, SIGTTIN):
/// the queued one is reset by the pause, a third one opened after SIGTTIN is not answered
/// while the first is held (0.7 s) and is answered 200 once it closes.
fn sigttin_leaves_a_full_listener_to_its_limit(tag: &str, global: &str, frontend: &str) {
    let run = start_cfg(tag, 1, &[], |sock, a| {
        format!("global\n  stats socket {sock} level admin\n  nbthread 1\n{global}{DEFAULTS}frontend fe\n  bind {}\n{frontend}{RET}", a[0])
    });
    let req = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    let connect = || TcpStream::connect_timeout(&run.addrs[0], Duration::from_secs(1)).expect("connect");
    let mut held = connect();
    held.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let mut queued = connect();
    queued.write_all(req).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    run.signal(rustix::process::Signal::Ttou);
    std::thread::sleep(Duration::from_millis(400));
    run.signal(rustix::process::Signal::Ttin);
    std::thread::sleep(Duration::from_millis(400));
    let mut third = connect();
    third.write_all(req).unwrap();
    assert_eq!(answer(&mut third, Duration::from_millis(700)), "TIMEOUT", "answered while the limit is reached");
    drop(held);
    assert_eq!(answer(&mut third, Duration::from_secs(2)), "HTTP/1.1 200", "once the held connection closed");
    assert_eq!(answer(&mut queued, Duration::from_secs(1)), "RESET", "the connection queued before SIGTTOU");
}

#[test]
fn sigttin_leaves_a_listener_full_at_global_maxconn_stopped() {
    // The frontend's own limit above the global one: unset, it is the global one, and
    // the listener would be full by its frontend's limit instead.
    sigttin_leaves_a_full_listener_to_its_limit("gmax", "  maxconn 1\n", "  maxconn 10\n");
}

#[test]
fn sigttin_leaves_a_listener_full_at_frontend_maxconn_stopped() {
    sigttin_leaves_a_full_listener_to_its_limit("fmax", "", "  maxconn 1\n");
}

/// An abstract stats socket whose name something else holds at SIGTTIN, and still holds at
/// the next one. `HAProxy` 3.5-dev8-885761-29 (nbthread 4; SIGTTOU, the name bound from
/// outside, SIGTTIN, SIGTTIN, the name freed, SIGTTIN) logs the frontend resumed first, then
/// the refusal at each SIGTTIN the name is held, then `GLOBAL` resumed. It also prints
/// `Resuming listener: protocol abns_stream: receiving socket not bound for [abns@NAME].`
/// after each `cannot bind` line; Ibex does not (T370), and this test leaves it out.
#[test]
fn an_abns_name_held_at_two_sigttins_is_refused_twice_then_resumed() {
    use rustix::process::Signal;
    use std::os::linux::net::SocketAddrExt;
    let name = format!("t456-held-{}", std::process::id());
    let run = start_cfg("abns2", 1, &[], |sock, a| {
        format!("global\n  stats socket {sock} level admin\n  stats socket abns@{name} level admin\n  nbthread 4\n{DEFAULTS}frontend fe\n  bind {}\n{RET}", a[0])
    });
    let mut bytes = name.as_bytes().to_vec();
    bytes.resize(107, 0);
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(&bytes).unwrap();
    run.signal(Signal::Ttou);
    let deadline = Instant::now() + Duration::from_secs(2);
    let hold = loop {
        if let Ok(h) = std::os::unix::net::UnixListener::bind_addr(&addr) {
            break h;
        }
        assert!(Instant::now() < deadline, "the name was not released");
        std::thread::sleep(Duration::from_millis(20));
    };
    let refused = || run.lines("refused to resume").len();
    for n in 1..=2 {
        run.signal(Signal::Ttin);
        let deadline = Instant::now() + Duration::from_secs(2);
        while refused() < n {
            assert!(Instant::now() < deadline, "SIGTTIN {n}: no refusal:\n{}", run.err.lock().unwrap());
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    drop(hold);
    run.signal(Signal::Ttin);
    all(&run, true);
    let deadline = Instant::now() + Duration::from_secs(2);
    while run.lines("Resumed frontend GLOBAL.").is_empty() {
        assert!(Instant::now() < deadline, "GLOBAL not resumed:\n{}", run.err.lock().unwrap());
        std::thread::sleep(Duration::from_millis(20));
    }
    let cannot = format!("Resuming listener: protocol abns_stream: cannot bind UNIX socket (already in use) [abns@{name}].");
    let warn = "Some proxies refused to resume, probably due to a conflict on a listening port. You may want to try again after the conflicting application is stopped, otherwise a restart might be needed to resume safe operations.";
    let got: Vec<String> = run.lines("").into_iter().filter(|l| l.contains("Paused") || l.contains("Resum") || l.contains("refused")).collect();
    let want = [
        "Paused frontend fe.",
        "Paused frontend GLOBAL.",
        "Resumed frontend fe.",
        &cannot,
        warn,
        &cannot,
        warn,
        "Resumed frontend GLOBAL.",
    ];
    assert_eq!(got, want);
}
