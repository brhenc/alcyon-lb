// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The logging actions `do-log`, `set-log-level` and `set-nice` of `http-request`,
//! `http-response` and `http-after-response`, as the reference `HAProxy`
//! (3.5-dev11) behaves for them, measured 2026-11-20 with a UDP syslog collector on
//! `log-format "uri=%HU st=%ST ts=%ts"`:
//!
//! `http-request`:
//! ```text
//! /normal  <134> ... uri=/normal st=200 ts=--
//! /dolog   <134> ... uri=/dolog st=-1 ts=--     (the do-log line, before the status exists)
//! /dolog   <134> ... uri=/dolog st=200 ts=--     (the stream's own close line follows)
//! /err     <131> ... uri=/err st=200 ts=--       (set-log-level err: local0.err, 128 + 3)
//! /silent  (no line at all)                      (set-log-level silent)
//! /normal  set-nice 5: accepted, the line is unchanged
//! ```
//! `http-response do-log` and `http-after-response do-log` each add one more line per
//! request (the stream's close line still goes out after them); `set-log-level err`
//! under `http-response` or `http-after-response` raises the close line to `<131>`;
//! `http-response set-nice 5` is accepted; `http-after-response set-nice 5` is refused
//! at load (`'http-after-response' expects 'set-log-level', ... but got 'set-nice'`),
//! as is `set-log-level` with a level name outside the eight syslog levels or `silent`.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev11-ce79f339c. Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// A backend answering 200 to every request, then closing.
fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut c = c;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => break,
                    }
                }
                let _ = c.write_all(RESPONSE);
            });
        }
    });
    addr
}

struct Case {
    child: Child,
    fe: SocketAddr,
    collector: UdpSocket,
    _cfg: NamedTempFile,
}

/// Starts the proxy (the oracle when `T281_ORACLE` is set) with `actions` in the
/// frontend; the syslog collector is already bound on its destination.
fn start(actions: &str) -> Case {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = backend();
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let log_addr = collector.local_addr().expect("addr");
    let mut cfg = NamedTempFile::new().expect("tmp");
    std::io::Write::write_all(
        &mut cfg,
        format!(
            "global\n  maxconn 128\n\
             defaults\n  mode http\n  log global\n  timeout connect 5s\n  timeout client 5s\n  \
             timeout server 5s\n\
             frontend fe\n  bind {fe}\n  log {log_addr} local0\n  \
             log-format \"uri=%HU st=%ST ts=%ts\"\n{actions}  default_backend be\n\
             frontend s\n  bind {sentinel}\n  http-request return status 200\n\
             backend be\n  server s1 {be}\n"
        )
        .as_bytes(),
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(common::wait_listening(sentinel), "never listened");
    Case { child, fe, collector, _cfg: cfg }
}

impl Drop for Case {
    fn drop(&mut self) {
        // End the proxy through `stop` (SIGUSR1), not `kill` (`SIGKILL`): the instrumented
        // binary writes its coverage profile only on a normal exit, so a killed child runs
        // its code and counts for nothing to the covercheck. `SIGUSR1` stops the oracle
        // (HAProxy) just as it stops Alcyon.
        common::stop(&mut self.child);
    }
}

/// Sends `path` on its own connection and reads the answer until the close.
fn request(fe: SocketAddr, path: &str) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n").as_bytes())
        .expect("send");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
}

/// The collected syslog lines: `(priority, body)` after the `tag[pid]: ` header.
fn collect(case: &Case, expected: usize, quiet: Duration) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(15);
    while out.len() < expected && Instant::now() < deadline {
        match case.collector.recv(&mut buf) {
            Ok(n) => {
                let l = String::from_utf8_lossy(&buf[..n]).into_owned();
                let pri = l.get(..5).unwrap_or("").to_string();
                let body = l.split_once("]: ").map_or("", |(_, b)| b).trim_end().to_string();
                out.push((pri, body));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => panic!("collector: {e}"),
        }
    }
    // Nothing more may follow: a silenced request must not appear late.
    let end = Instant::now() + quiet;
    while Instant::now() < end {
        match case.collector.recv(&mut buf) {
            Ok(n) => {
                let l = String::from_utf8_lossy(&buf[..n]).into_owned();
                let pri = l.get(..5).unwrap_or("").to_string();
                let body = l.split_once("]: ").map_or("", |(_, b)| b).trim_end().to_string();
                out.push((pri, body));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => panic!("collector: {e}"),
        }
    }
    out
}

#[test]
fn http_request_do_log_set_log_level_set_nice() {
    let case = start(
        "  http-request set-nice 5\n\
         http-request set-log-level err    if { path /err }\n\
         http-request set-log-level silent if { path /silent }\n\
         http-request do-log               if { path /dolog }\n",
    );
    for p in ["/normal", "/dolog", "/err", "/silent"] {
        request(case.fe, p);
    }
    let lines = collect(&case, 4, Duration::from_secs(2));
    assert_eq!(
        lines,
        vec![
            ("<134>".into(), "uri=/normal st=200 ts=--".into()),
            ("<134>".into(), "uri=/dolog st=-1 ts=--".into()),
            ("<134>".into(), "uri=/dolog st=200 ts=--".into()),
            ("<131>".into(), "uri=/err st=200 ts=--".into()),
        ],
        "the /silent request logs nothing, /dolog logs the do-log line then its close line, /err at local0.err"
    );
}

#[test]
fn http_response_do_log_and_set_nice() {
    let case = start("  http-response do-log\n  http-response set-nice 5\n");
    for p in ["/a", "/b"] {
        request(case.fe, p);
    }
    let lines = collect(&case, 4, Duration::from_secs(2));
    assert_eq!(
        lines,
        vec![
            ("<134>".into(), "uri=/a st=200 ts=--".into()),
            ("<134>".into(), "uri=/a st=200 ts=--".into()),
            ("<134>".into(), "uri=/b st=200 ts=--".into()),
            ("<134>".into(), "uri=/b st=200 ts=--".into()),
        ],
    );
}

#[test]
fn http_response_set_log_level() {
    let case = start("  http-response set-log-level err\n");
    for p in ["/a", "/b"] {
        request(case.fe, p);
    }
    let lines = collect(&case, 2, Duration::from_secs(2));
    assert_eq!(
        lines,
        vec![
            ("<131>".into(), "uri=/a st=200 ts=--".into()),
            ("<131>".into(), "uri=/b st=200 ts=--".into()),
        ],
    );
}

#[test]
fn http_after_response_do_log() {
    let case = start("  http-after-response do-log\n");
    for p in ["/a", "/b"] {
        request(case.fe, p);
    }
    let lines = collect(&case, 4, Duration::from_secs(2));
    assert_eq!(
        lines,
        vec![
            ("<134>".into(), "uri=/a st=200 ts=--".into()),
            ("<134>".into(), "uri=/a st=200 ts=--".into()),
            ("<134>".into(), "uri=/b st=200 ts=--".into()),
            ("<134>".into(), "uri=/b st=200 ts=--".into()),
        ],
    );
}

#[test]
fn http_after_response_set_log_level() {
    let case = start("  http-after-response set-log-level err\n");
    for p in ["/a", "/b"] {
        request(case.fe, p);
    }
    let lines = collect(&case, 2, Duration::from_secs(2));
    assert_eq!(
        lines,
        vec![
            ("<131>".into(), "uri=/a st=200 ts=--".into()),
            ("<131>".into(), "uri=/b st=200 ts=--".into()),
        ],
    );
}

/// Spawns the binary with a config that must be refused at load and returns its output.
fn refused_at_load(actions: &str) -> String {
    let mut cfg = NamedTempFile::new().expect("tmp");
    std::io::Write::write_all(
        &mut cfg,
        format!(
            "defaults\n  mode http\n  log global\n\
             frontend fe\n  log-format \"x\"\n{actions}\n"
        )
        .as_bytes(),
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(output)) => {
            let mut out = String::new();
            out.push_str(&String::from_utf8_lossy(&output.stdout));
            out.push_str(&String::from_utf8_lossy(&output.stderr));
            out
        }
        Ok(Err(e)) => panic!("wait: {e}"),
        Err(_) => panic!("accepted a config that must be refused"),
    }
}

#[test]
fn http_after_response_set_nice_is_refused() {
    let out = refused_at_load("  http-after-response set-nice 5\n");
    assert!(out.contains("set-nice"), "the refusal must name the action: {out}");
}

/// Every one of the eight syslog levels: `set-log-level <lvl>` sets the close line's
/// severity to that level. The priority of `local0.<lvl>` is `128 + n` with `n` the
/// syslog number (`emerg` 0 .. `debug` 7); each row was measured on `HAProxy`.
#[test]
fn http_request_set_log_level_sweep() {
    let levels = [
        ("emerg", "/emerg", "<128>"),
        ("alert", "/alert", "<129>"),
        ("crit", "/crit", "<130>"),
        ("err", "/err", "<131>"),
        ("warning", "/warning", "<132>"),
        ("notice", "/notice", "<133>"),
        ("info", "/info", "<134>"),
        ("debug", "/debug", "<135>"),
    ];
    let mut actions = String::new();
    for (lvl, path, _) in levels {
        actions.push_str(&format!("  http-request set-log-level {lvl} if {{ path {path} }}\n"));
    }
    let case = start(&actions);
    for (_, path, _) in levels {
        request(case.fe, path);
    }
    let lines = collect(&case, 8, Duration::from_secs(2));
    for ((_, path, pri), (got_pri, body)) in levels.iter().zip(lines) {
        assert_eq!(got_pri, *pri, "the {path} line must carry that level's priority");
        assert_eq!(body, format!("uri={path} st=200 ts=--"), "the {path} body");
    }
}

#[test]
fn set_log_level_with_unknown_level_is_refused() {
    let out = refused_at_load("  http-request set-log-level bogus\n");
    assert!(out.contains("set-log-level"), "the refusal must name the action: {out}");
}
