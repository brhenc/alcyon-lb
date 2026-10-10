// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T100: a client could crash a worker through the scheduler's tasklet lists.
//!
//! A stream that ended in a pass still had its timer queued, after the pass, on the
//! task the scheduler had just freed. The freed slot went into the wait queue, was later
//! woken into the run queue, and then handed to the next connection with its old
//! membership forgotten; the next pass linked it into two lists at once, and
//! `pop_tasklet` underflowed a list length (`attempt to subtract with overflow` in a
//! debug build, corrupt lists in a release one).
//!
//! The two sequences below are the ones T100 reports. Each must leave the worker alive
//! and serving; `HAProxy` 3.5-dev8 answers them 504 (server timeout) and 408 (client
//! timeout), and then serves the next request.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const CFG: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 500ms\n  timeout server 500ms\n\
frontend fe\n  bind {fe}\n  default_backend be\n\
backend be\n  server s {srv}\n";

struct Ibex {
    child: Child,
    stderr: NamedTempFile,
    _cfg: NamedTempFile,
}

impl Ibex {
    fn stderr(&self) -> String {
        std::fs::read_to_string(self.stderr.path()).unwrap_or_default()
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(srv: SocketAddr) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let text = CFG.replace("{fe}", &fe.to_string()).replace("{srv}", &srv.to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let stderr = NamedTempFile::new().expect("tmp");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(stderr.reopen().expect("reopen stderr file"))
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, stderr, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    (ibex, fe)
}

/// A server that reads each request head and answers `/ok` with a 200, and anything
/// else not at all (the connection stays open, so `timeout server` fires).
fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        buf.drain(..end + 4);
                        if head.starts_with("GET /ok ")
                            && c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err()
                        {
                            return;
                        }
                    }
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
            });
        }
    });
    addr
}

/// Sends `req` on a new connection and returns what came back until the peer closed, or
/// three seconds passed.
fn send(fe: SocketAddr, req: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    c.write_all(req.as_bytes()).expect("send");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// The worker is alive and still serving: a request after the sequence is answered, the
/// process is still running, and nothing panicked.
fn assert_still_serving(ibex: &mut Ibex, fe: SocketAddr) {
    // The panic, when there is one, comes on the scheduler pass after the timeout.
    thread::sleep(Duration::from_millis(300));
    let after = send(fe, "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let stderr = ibex.stderr();
    assert!(!stderr.contains("panicked"), "a worker panicked:\n{stderr}");
    assert!(
        matches!(ibex.child.try_wait(), Ok(None)),
        "ibex exited; stderr:\n{stderr}"
    );
    assert!(after.starts_with("HTTP/1.1 200"), "the request after the sequence got {after:?}; stderr:\n{stderr}");
}

/// T100 trigger 1: an aborted half request, then a request the server never answers.
#[test]
fn half_request_then_server_timeout_leaves_the_worker_serving() {
    let (mut ibex, fe) = start(server());

    let mut half = TcpStream::connect(fe).expect("connect");
    half.write_all(b"GET /half HTTP/1.1\r\nHost: x\r\n").expect("send");
    thread::sleep(Duration::from_millis(200));
    drop(half);

    let hang = send(fe, "GET /hang HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(hang.starts_with("HTTP/1.1 504"), "GET /hang got {hang:?}");

    assert_still_serving(&mut ibex, fe);
}

/// T100 trigger 2: an answered request, an idle connection that times out, then a
/// request the server never answers.
#[test]
fn answered_idle_and_server_timeout_leave_the_worker_serving() {
    let (mut ibex, fe) = start(server());

    let ok = send(fe, "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(ok.starts_with("HTTP/1.1 200"), "GET /ok got {ok:?}");

    let idle = send(fe, "");
    assert!(idle.starts_with("HTTP/1.1 408"), "the idle connection got {idle:?}");

    let hang = send(fe, "GET /hang HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(hang.starts_with("HTTP/1.1 504"), "GET /hang got {hang:?}");

    assert_still_serving(&mut ibex, fe);
}
