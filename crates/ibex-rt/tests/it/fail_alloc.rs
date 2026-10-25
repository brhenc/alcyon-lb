// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `-dMfail` with `tune.fail-alloc`, and `tune.buffers.limit` (memory slice S5): allocations
//! refused at random fail their stream, never the process.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`-dMfail`, `tune.fail-alloc 5`, `nbthread 1`, 400
//! connections each with one `GET`, proxied to a local server): 131 `200`, 183 `500`, 86 closed
//! with nothing; the `500`s log `IR--` (`<BADREQ>`) or `IC--`; the process serves on. Without
//! `-dMfail`, `tune.fail-alloc` changes nothing (200 of 200 answered `200`). `S5_ORACLE=<haproxy>`
//! runs these against it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::common;

fn binary() -> String {
    std::env::var("S5_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string())
}

/// A server answering every head `200` with `ok`, then closing.
fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            });
        }
    });
    port
}

struct Proxy {
    child: Child,
    port: u16,
    log: Arc<Mutex<String>>,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

impl Proxy {
    /// The log lines so far.
    fn log(&self) -> String {
        self.log.lock().expect("log").clone()
    }
}

/// The proxy with `global` lines and these command-line `args`, logging to stderr.
fn start(global: &str, args: &[&str]) -> Proxy {
    let be = backend();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n{global}\
             defaults\n\tmode http\n\tlog stderr format raw local0\n\toption httplog\n\
             \ttimeout connect 3s\n\ttimeout client 5s\n\ttimeout server 5s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{be}\n"
        ),
    )
    .expect("write config");
    let mut child = Command::new(binary()).args(args).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("spawn");
    let log = Arc::new(Mutex::new(String::new()));
    let (mut err, sink) = (child.stderr.take().expect("stderr"), Arc::clone(&log));
    thread::spawn(move || {
        let mut tmp = [0u8; 4096];
        while let Ok(n) = err.read(&mut tmp) {
            if n == 0 {
                break;
            }
            sink.lock().expect("log").push_str(&String::from_utf8_lossy(&tmp[..n]));
        }
    });
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "the proxy never listened on {port}");
    Proxy { child, port, log, _dir: dir }
}

/// One `GET` on a new connection: the status, or 0 when the connection closed with nothing.
fn get(port: u16) -> u16 {
    let Ok(mut c) = TcpStream::connect(("127.0.0.1", port)) else { return 0 };
    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
    if c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").is_err() {
        return 0;
    }
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let line = String::from_utf8_lossy(&got);
    line.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// `-dMfail` and `tune.fail-alloc 5`: every answer is a `200`, a `500` or a closed connection;
/// there are failures; the process is alive throughout and after; every failed stream that is
/// logged ends with an internal error (`%ts` starting with `I`: `IR--` for the request's buffer,
/// as on `HAProxy`; `IH--` for the response's, where `HAProxy`'s refusals at that point are of its
/// server connection, `IC--`).
#[test]
fn under_fail_alloc_only_the_failed_streams_fail() {
    let mut p = start("\ttune.fail-alloc 5\n", &["-dMfail"]);
    let mut counts = std::collections::BTreeMap::new();
    for _ in 0..300 {
        *counts.entry(get(p.port)).or_insert(0) += 1;
    }
    assert!(p.child.try_wait().expect("try_wait").is_none(), "the process died: {}", p.log());
    assert!(counts.keys().all(|s| [0, 200, 500].contains(s)), "{counts:?}");
    assert!(counts.get(&200).copied().unwrap_or(0) > 0, "nothing served: {counts:?}");
    assert!(counts.iter().any(|(&s, &n)| s != 200 && n > 0), "nothing failed at 5 %: {counts:?}");
    thread::sleep(Duration::from_millis(200));
    let log = p.log();
    // `wait_listening`'s probe connects and closes without a request: `400 CR--`, not a failure.
    for line in log.lines().filter(|l| l.contains(" fe ") && !l.contains(" 200 ") && !l.contains(" 400 0 - - CR-- ")) {
        let ts = line.split_whitespace().nth(9).unwrap_or("");
        assert!(ts.starts_with('I'), "a failed stream not logged as internal: {line}");
    }
}

/// `tune.fail-alloc` without `-dMfail` refuses nothing, as on `HAProxy`.
#[test]
fn fail_alloc_without_dmfail_refuses_nothing() {
    let mut p = start("\ttune.fail-alloc 50\n", &[]);
    for i in 0..50 {
        assert_eq!(get(p.port), 200, "request {i}");
    }
    assert!(p.child.try_wait().expect("try_wait").is_none());
}

/// `-dMfail` alone refuses 1 % (`HAProxy` presets `mem_fail_rate` to 1); `-dMno-fail` after it
/// turns it off again: here, all served.
#[test]
fn dmno_fail_turns_dmfail_off() {
    let mut p = start("", &["-dMfail,no-fail"]);
    for i in 0..50 {
        assert_eq!(get(p.port), 200, "request {i}");
    }
    assert!(p.child.try_wait().expect("try_wait").is_none());
}

/// The other `-dM` features are refused, not ignored (Ibex only: `HAProxy` has them all).
#[test]
fn other_pool_debugging_features_are_refused() {
    if std::env::var("S5_ORACLE").is_ok() {
        return;
    }
    let out = Command::new(binary()).args(["-dMpoison", "-c", "-f", "/dev/null"]).output().expect("run");
    assert!(!out.status.success(), "{out:?}");
}

/// `tune.buffers.limit 3` (Ibex: no wait queue yet, S6): with three connections each holding a
/// buffer for a partial request, a fourth gets nothing and is closed; once one of the three is
/// gone, the next request is served. `HAProxy` makes the fourth wait instead.
#[test]
fn past_tune_buffers_limit_a_stream_fails_and_the_next_one_is_served() {
    if std::env::var("S5_ORACLE").is_ok() {
        return;
    }
    let mut p = start("\ttune.buffers.limit 3\n", &[]);
    let held: Vec<TcpStream> = (0..3)
        .map(|_| {
            let mut c = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").expect("partial head");
            c
        })
        .collect();
    thread::sleep(Duration::from_millis(200));
    assert_eq!(get(p.port), 0, "a fourth buffer past the limit");
    drop(held);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(get(p.port), 200, "a buffer is free again");
    assert!(p.child.try_wait().expect("try_wait").is_none());
}

/// A header name over the HTX's 255 bytes is a bad request (`400`), not a failed allocation:
/// the parser's "no room in the HTX" is not a refused allocation (diff-fuzz 7f9a994e3567d3fa,
/// `oversized_header_name_300b`; `HAProxy` 3.5-dev8 answers `400`).
#[test]
fn a_header_name_too_long_for_the_htx_is_400_not_500() {
    let p = start("", &[]);
    let mut c = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let req = format!("GET /long-hdr HTTP/1.1\r\nHost: example.com\r\nX-{}: test\r\n\r\n", "a".repeat(300));
    c.write_all(req.as_bytes()).expect("write");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let got = String::from_utf8_lossy(&got);
    assert!(got.starts_with("HTTP/1.1 400"), "{}", &got[..got.len().min(80)]);
}
