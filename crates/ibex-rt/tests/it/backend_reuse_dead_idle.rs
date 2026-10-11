// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A server connection the server has closed while it sat idle is no longer one of the
//! server's idle connections (T301).
//!
//! `reg-tests/http-messaging/h1_to_h1.vtc` failed 2 runs in 20 (T295): its server closes the
//! connection it kept after a `Connection: close` request; the next client's first
//! response then released its fresh connection into the server's lists, which weighed the
//! dead one as still idle, refused the fresh one (`srv_add_to_idle_list`: the safe list is
//! not empty, or the idle list is not and the connection is not safe) and closed it. The
//! client's second request went out on a new connection the test's server never read: a
//! 504. `HAProxy` watches its idle connections for reads and drops one at the peer's close,
//! before any release can weigh it.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`nbthread 1`, the backend below): the dead
//! connection was safe (two requests) or idle (one); either way the next client's two
//! requests both go out on one new backend connection, which stays open.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// What the backend reports: a connection closed by the proxy (its number), or one it
/// closed itself after answering `/bye`.
enum Event {
    PeerClosed(usize),
    ClosedBye,
}

/// A backend that numbers its connections in `X-Conn`, closes a connection 20 ms after
/// answering a request for `/bye`, and reports both kinds of close.
fn backend(events: mpsc::Sender<Event>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let id = count.fetch_add(1, Ordering::SeqCst) + 1;
            let events = events.clone();
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = match s.read(&mut chunk) {
                        Ok(0) | Err(_) => {
                            let _ = events.send(Event::PeerClosed(id));
                            return;
                        }
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..end + 4).collect();
                        let bye = head.windows(5).any(|w| w == b" /bye");
                        let rsp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Conn: {id}\r\n\r\n");
                        if s.write_all(rsp.as_bytes()).is_err() {
                            return;
                        }
                        if bye {
                            // Long enough for the proxy to have pooled it, well inside the
                            // pool's 50 ms sweep.
                            thread::sleep(Duration::from_millis(20));
                            drop(s);
                            let _ = events.send(Event::ClosedBye);
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// The proxy, and its configuration file, kept until it stops.
struct Ibex(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(be: SocketAddr, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 2s\n\
         listen fe\n  bind {fe}\n  server s1 {be}\n"
    );
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

/// Sends `req` on `c` and returns the response's status and `X-Conn`.
fn exchange(c: &mut TcpStream, req: &str) -> (u16, usize) {
    c.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
    let status = resp.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("no answer to {req:?}: {resp:?}"));
    let id = resp.split("x-conn: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|n| n.trim().parse().ok()).unwrap_or(0);
    (status, id)
}

/// One client sends `first` requests, the last `/bye` with `Connection: close`; once the
/// backend has closed that connection, a second client sends two POSTs. Returns the second
/// client's (status, backend connection) pairs and the connections the proxy closed by then.
fn run(first: usize) -> (Vec<(u16, usize)>, Vec<usize>) {
    let (tx, rx) = mpsc::channel();
    let be = backend(tx);
    let fe = common::reserve_addr();
    let _ibex = start(be, fe);

    let mut a = TcpStream::connect(fe).expect("connect");
    a.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    for i in 1..first {
        exchange(&mut a, &format!("GET /a{i} HTTP/1.1\r\nHost: x\r\n\r\n"));
    }
    exchange(&mut a, "GET /bye HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    drop(a);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Event::ClosedBye) => break,
            Ok(Event::PeerClosed(_)) => {}
            Err(e) => panic!("the backend never closed the /bye connection: {e}"),
        }
    }

    let mut b = TcpStream::connect(fe).expect("connect");
    b.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let seq = vec![
        exchange(&mut b, "POST /p1 HTTP/1.1\r\nHost: x\r\n\r\n"),
        exchange(&mut b, "POST /p2 HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
    ];
    let closed = rx.try_iter().filter_map(|e| if let Event::PeerClosed(n) = e { Some(n) } else { None }).collect();
    (seq, closed)
}

#[test]
fn a_dead_safe_connection_does_not_crowd_out_the_next_clients() {
    let (seq, closed) = run(2);
    assert_eq!(seq, vec![(200, 2), (200, 2)], "both requests on one new connection (proxy closed: {closed:?})");
    assert!(!closed.contains(&2), "the proxy closed the connection between two requests");
}

#[test]
fn a_dead_idle_connection_does_not_crowd_out_the_next_clients() {
    let (seq, closed) = run(1);
    assert_eq!(seq, vec![(200, 2), (200, 2)], "both requests on one new connection (proxy closed: {closed:?})");
    assert!(!closed.contains(&2), "the proxy closed the connection between two requests");
}
