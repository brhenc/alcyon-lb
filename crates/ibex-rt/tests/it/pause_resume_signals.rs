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
fn start(tag: &str, nbthread: usize, args: &[&str]) -> Run {
    let addrs: Vec<SocketAddr> = (0..4).map(|_| common::reserve_addr()).collect();
    let dir = std::env::temp_dir().join(format!("t456-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let ret = "  http-request return status 200 content-type text/plain string ok\n";
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n  nbthread {nbthread}\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 30s\n  timeout server 30s\n\
         frontend fe\n  bind {}\n{ret}\
         listen li\n  bind {}\n{ret}\
         backend be\n  server s 127.0.0.1:1\n\
         frontend fe2\n  bind {}\n  bind {}\n{ret}",
        addrs[0], addrs[1], addrs[2], addrs[3]
    );
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
