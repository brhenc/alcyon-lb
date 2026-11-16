// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A request body that is abandoned by its client under `option http-buffer-request`, as the
//! reference `HAProxy` (3.5-dev8) logged it, measured 2026-11-16 with the same setup as
//! `http-messaging/http_request_buffer.vtc` (a UDP collector, `option httplog`, a frontend with
//! `option http-buffer-request` and a `use_backend`):
//!
//! ```text
//!   POST /buf-eoflast HTTP/1.1 ... 1\r\n1\r\n1 [delay] \r\n1\r\n0\r\n  then the client FINs
//!   fe be/<NOSRV> 0/-1/-1/-1/0 400 0 - - CR-- 1/1/0/0/0 0/0 "POST /buf-eoflast HTTP/1.1"
//!   <no response at all: HAProxy writes nothing back to a client that stopped writing>
//! ```
//!
//! The fields that matter to an operator debugging bad clients are the termination state (`CR--`:
//! a client-side error, during the request), `<NOSRV>` (rejected before a server was chosen) and
//! the fact that the *backend* is named: `HAProxy` stops waiting for the body once the client is
//! gone, so the request reaches backend selection and is logged against it, with `Tq` set to the
//! time spent reading the request rather than `-1`.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

use crate::common;

/// A server answering 200 to anything; unused for the scenarios here but required for the
/// frontend to have a backend.
fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut d = Vec::new();
                let mut buf = [0u8; 4096];
                while !d.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(n) if n > 0 => d.extend_from_slice(&buf[..n]),
                        _ => return,
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz");
            });
        }
    });
    addr
}

/// Runs `client` against a fresh engine whose frontend has `option http-buffer-request`, and
/// returns the log line it produced and everything the client read back.
fn scenario(buffered: bool, client: impl FnOnce(&mut TcpStream) -> Vec<u8> + Send + 'static) -> (Option<String>, Vec<u8>) {
    let srv = server();
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 300ms\n  timeout server 1s\n\
         frontend fe\n  bind {fe}\n  log {} local0\n  option httplog\n{}\n  use_backend be\n\
         backend be\n  server s {srv}\n",
        collector.local_addr().expect("addr"),
        if buffered { "  option http-buffer-request" } else { "" }
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let (tx, rx) = mpsc::channel();
    let c = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let out = client(&mut s);
        let _ = tx.send(out);
    });
    let mut line: Option<String> = None;
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(5);
    while line.is_none() && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            line = Some(String::from_utf8_lossy(&buf[..n]).split_once("]: ").map_or(String::new(), |(_, b)| b.trim_end().to_string()));
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = c.join();
    (line, rx.try_iter().next().unwrap_or_default())
}

/// The fields of an httplog line: `<src> <date> <fe> <be>/<srv> <timers> <status> <bytes> - - <term> ...`.
fn fields(line: &str) -> Vec<&str> {
    line.split(' ').collect()
}

/// A chunked body abandoned by the client: the last chunk is promised but its data never comes.
/// `HAProxy` answers nothing and logs the request against the backend, with `Tq` set.
#[test]
fn an_abandoned_chunked_body_is_logged_against_the_backend() {
    let (line, resp) = scenario(true, |s| {
        s.write_all(b"POST /chunked-abort HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\na")
            .expect("send");
        s.shutdown(Shutdown::Write).expect("half-close");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    });
    let line = line.expect("the abandoned request is logged");
    let f = fields(&line);
    // HAProxy: fe be/<NOSRV> 0/-1/-1/-1/0 400 0 - - CR-- 1/1/0/0/0 0/0 "POST /chunked-abort HTTP/1.1"
    assert_eq!(f.get(3).copied(), Some("be/<NOSRV>"), "{line}");
    let timers = f.get(4).copied().unwrap_or_default();
    let t: Vec<&str> = timers.split('/').collect();
    assert_eq!(t.len(), 5, "{line}");
    assert_ne!(t[0], "-1", "HAProxy logs the time spent reading the request, not -1: {line}");
    assert_eq!(&t[1..4], ["-1", "-1", "-1"], "{line}");
    assert_eq!(f.get(5).copied(), Some("400"), "{line}");
    assert_eq!(f.get(6).copied(), Some("0"), "{line}");
    assert_eq!(f.get(9).copied(), Some("CR--"), "{line}");
    assert!(line.ends_with("\"POST /chunked-abort HTTP/1.1\""), "{line}");
    // HAProxy writes no response at all to a client that has already stopped writing.
    assert!(resp.is_empty(), "HAProxy answers nothing, got {resp:?}");
}

/// The same abandonment of a `Content-Length` body: `HAProxy` logged
/// `fe be/<NOSRV> 0/-1/-1/-1/0 400 0 - - CR-- 1/1/0/0/0 0/0 "POST /cl-abort HTTP/1.1"` and,
/// again, wrote nothing back.
#[test]
fn an_abandoned_content_length_body_is_logged_the_same_way() {
    let (line, resp) = scenario(true, |s| {
        s.write_all(b"POST /cl-abort HTTP/1.1\r\nHost: h\r\nContent-Length: 40\r\n\r\nabcdef")
            .expect("send");
        s.shutdown(Shutdown::Write).expect("half-close");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    });
    let line = line.expect("the abandoned request is logged");
    let f = fields(&line);
    assert_eq!(f.get(3).copied(), Some("be/<NOSRV>"), "{line}");
    let timers = f.get(4).copied().unwrap_or_default();
    let t: Vec<&str> = timers.split('/').collect();
    assert_ne!(t.first().copied().unwrap_or("-1"), "-1", "HAProxy logs the read time, not -1: {line}");
    assert_eq!(&t[1..4], ["-1", "-1", "-1"], "{line}");
    assert_eq!(f.get(5).copied(), Some("400"), "{line}");
    assert_eq!(f.get(9).copied(), Some("CR--"), "{line}");
    assert!(line.ends_with("\"POST /cl-abort HTTP/1.1\""), "{line}");
    assert!(resp.is_empty(), "HAProxy answers nothing, got {resp:?}");
}

/// The same abandonment without `option http-buffer-request`, where `HAProxy` answers nothing
/// and logs `be/s 0/0/0/-1/0 400 0 - - CH--`: the head was forwarded, so a server is named and
/// the phase is the server's head, not the request. (Alcyon agrees on the routing and on the
/// missing answer; the status and the termination state of that case are left as they are.)
#[test]
fn an_abandoned_body_without_buffering_reaches_no_client() {
    let (line, resp) = scenario(false, |s| {
        s.write_all(b"POST /chunked-abort-raw HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3\r\na")
            .expect("send");
        s.shutdown(Shutdown::Write).expect("half-close");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        out
    });
    let line = line.expect("the abandoned request is logged");
    let f = fields(&line);
    assert_eq!(f.get(3).copied(), Some("be/s"), "{line}");
    assert!(line.ends_with("\"POST /chunked-abort-raw HTTP/1.1\""), "{line}");
    assert!(resp.is_empty(), "HAProxy answers nothing, got {resp:?}");
}
