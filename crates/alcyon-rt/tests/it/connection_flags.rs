// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The client's `Connection` tokens are handled as flags (T575, K1): an HTTP/1.0 keep-alive
//! request (`ab -k`) reaches the server without its head being written out of the HTX again
//! ([`alcyon_sample::work::Op::ReqRebuild`]), and what the server reads is what `HAProxy` sends.
//!
//! `CASES` are the heads a server read from `$ALCYON_REFERENCE/haproxy/haproxy`
//! (3.5-dev8-885761-29) for the request in the first column, in the five modes of `MODES`,
//! captured with a backend that records the request it got.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::engine::Engine;
use alcyon_sample::work::Op;

/// (frontend lines, backend lines) of the five columns of `CASES`.
const MODES: [(&str, &str); 5] = [
    ("", ""),
    ("", "  option http-server-close\n"),
    ("", "  option httpclose\n"),
    ("  option httpclose\n", ""),
    ("  option http-server-close\n", ""),
];

const CASES: &[(&str, [&str; 5])] = &[
    ("GET /1 HTTP/1.0\r\nHost: a\r\nConnection: Keep-Alive\r\n\r\n", ["GET /1 HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n", "GET /1 HTTP/1.0\r\nhost: a\r\n\r\n", "GET /1 HTTP/1.0\r\nhost: a\r\n\r\n", "GET /1 HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n", "GET /1 HTTP/1.0\r\nhost: a\r\n\r\n"]),
    ("GET /2 HTTP/1.0\r\nHost: a\r\n\r\n", ["GET /2 HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n", "GET /2 HTTP/1.0\r\nhost: a\r\n\r\n", "GET /2 HTTP/1.0\r\nhost: a\r\n\r\n", "GET /2 HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n", "GET /2 HTTP/1.0\r\nhost: a\r\n\r\n"]),
    ("GET /3 HTTP/1.0\r\nHost: a\r\nConnection: close\r\n\r\n", ["GET /3 HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n", "GET /3 HTTP/1.0\r\nhost: a\r\n\r\n", "GET /3 HTTP/1.0\r\nhost: a\r\n\r\n", "GET /3 HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n", "GET /3 HTTP/1.0\r\nhost: a\r\n\r\n"]),
    ("GET /4 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", ["GET /4 HTTP/1.1\r\nhost: a\r\n\r\n", "GET /4 HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n", "GET /4 HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n", "GET /4 HTTP/1.1\r\nhost: a\r\n\r\n", "GET /4 HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n"]),
    ("GET /5 HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, foo\r\nX: y\r\n\r\n", ["GET /5 HTTP/1.1\r\nhost: a\r\nconnection: foo\r\nx: y\r\n\r\n", "GET /5 HTTP/1.1\r\nhost: a\r\nconnection: foo\r\nx: y\r\nconnection: close\r\n\r\n", "GET /5 HTTP/1.1\r\nhost: a\r\nconnection: foo\r\nx: y\r\nconnection: close\r\n\r\n", "GET /5 HTTP/1.1\r\nhost: a\r\nconnection: foo\r\nx: y\r\n\r\n", "GET /5 HTTP/1.1\r\nhost: a\r\nconnection: foo\r\nx: y\r\nconnection: close\r\n\r\n"]),
    ("GET /6 HTTP/1.1\r\nHost: a\r\n\r\n", ["GET /6 HTTP/1.1\r\nhost: a\r\n\r\n", "GET /6 HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n", "GET /6 HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n", "GET /6 HTTP/1.1\r\nhost: a\r\n\r\n", "GET /6 HTTP/1.1\r\nhost: a\r\nconnection: close\r\n\r\n"]),
    ("GET /7 HTTP/1.0\r\nHost: a\r\nConnection: Keep-Alive, foo\r\n\r\n", ["GET /7 HTTP/1.0\r\nhost: a\r\nconnection: foo\r\nconnection: keep-alive\r\n\r\n", "GET /7 HTTP/1.0\r\nhost: a\r\nconnection: foo\r\n\r\n", "GET /7 HTTP/1.0\r\nhost: a\r\nconnection: foo\r\n\r\n", "GET /7 HTTP/1.0\r\nhost: a\r\nconnection: foo\r\nconnection: keep-alive\r\n\r\n", "GET /7 HTTP/1.0\r\nhost: a\r\nconnection: foo\r\n\r\n"]),
    ("GET /8 HTTP/1.0\r\nHost: a\r\nX-A: 1\r\nconnection:   keep-alive  \r\nX-B: 2\r\n\r\n", ["GET /8 HTTP/1.0\r\nhost: a\r\nx-a: 1\r\nx-b: 2\r\nconnection: keep-alive\r\n\r\n", "GET /8 HTTP/1.0\r\nhost: a\r\nx-a: 1\r\nx-b: 2\r\n\r\n", "GET /8 HTTP/1.0\r\nhost: a\r\nx-a: 1\r\nx-b: 2\r\n\r\n", "GET /8 HTTP/1.0\r\nhost: a\r\nx-a: 1\r\nx-b: 2\r\nconnection: keep-alive\r\n\r\n", "GET /8 HTTP/1.0\r\nhost: a\r\nx-a: 1\r\nx-b: 2\r\n\r\n"]),
    ("GET /9 HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: foo\r\n\r\n", ["GET /9 HTTP/1.1\r\nhost: a\r\nconnection: Upgrade\r\nupgrade: foo\r\n\r\n", "GET /9 HTTP/1.1\r\nhost: a\r\nconnection: Upgrade\r\nupgrade: foo\r\n\r\n", "GET /9 HTTP/1.1\r\nhost: a\r\nconnection: Upgrade\r\nupgrade: foo\r\n\r\n", "GET /9 HTTP/1.1\r\nhost: a\r\nconnection: Upgrade\r\nupgrade: foo\r\n\r\n", "GET /9 HTTP/1.1\r\nhost: a\r\nconnection: Upgrade\r\nupgrade: foo\r\n\r\n"]),
    ("POST /10 HTTP/1.0\r\nHost: a\r\nConnection: Keep-Alive\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", ["POST /10 HTTP/1.0\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", "POST /10 HTTP/1.0\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", "POST /10 HTTP/1.0\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", "POST /10 HTTP/1.0\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n", "POST /10 HTTP/1.0\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"]),
];

const RSP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

type Heads = Arc<Mutex<Vec<Vec<u8>>>>;

/// A server that records each request head it reads and answers it; one thread a connection.
fn backend(listener: TcpListener, running: Arc<AtomicBool>, heads: Heads) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = listener.accept() else {
                thread::sleep(Duration::from_micros(200));
                continue;
            };
            let (running, heads) = (Arc::clone(&running), Arc::clone(&heads));
            thread::spawn(move || {
                s.set_nonblocking(false).expect("blocking");
                s.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
                let (mut pending, mut buf) = (Vec::new(), [0u8; 4096]);
                while running.load(Ordering::Relaxed) {
                    match s.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                        Err(_) => return,
                    }
                    while let Some(p) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = pending.drain(..p + 4).collect();
                        // A chunked request's body ("0\r\n\r\n") follows its head.
                        if head.windows(8).any(|w| w.eq_ignore_ascii_case(b"chunked\r")) {
                            let t = Instant::now();
                            while !pending.ends_with(b"0\r\n\r\n") && t.elapsed() < Duration::from_millis(300) {
                                if let Ok(n) = s.read(&mut buf) {
                                    pending.extend_from_slice(&buf[..n]);
                                }
                            }
                            pending.clear();
                        }
                        heads.lock().expect("heads").push(head);
                        if s.write_all(RSP).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    })
}

struct Rig {
    engine: Engine,
    fe: std::net::SocketAddr,
    running: Arc<AtomicBool>,
    heads: Heads,
    be: Option<thread::JoinHandle<()>>,
}

impl Rig {
    fn new(fe_lines: &str, be_lines: &str) -> Self {
        let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
        let srv_addr = srv.local_addr().expect("addr");
        let fe = common::reserve_addr();
        let running = Arc::new(AtomicBool::new(true));
        let heads: Heads = Arc::default();
        let be = Some(backend(srv, Arc::clone(&running), Arc::clone(&heads)));
        let cfg = format!(
            "global\n  tune.alcyon.h1-lowercase-headers on\ndefaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
             frontend fe\n  bind {fe}\n{fe_lines}  default_backend be\nbackend be\n{be_lines}  server s1 {srv_addr}\n"
        );
        let engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        Self { engine, fe, running, heads, be }
    }

    /// `req` on `client`, the engine run until the head reached the server and the answer is back
    /// (or the client's connection closed); the answer.
    fn send(&mut self, client: &mut TcpStream, req: &str) -> Vec<u8> {
        let seen = self.heads.lock().expect("heads").len();
        client.write_all(req.as_bytes()).expect("write");
        let (start, mut rsp, mut buf) = (Instant::now(), Vec::new(), [0u8; 1024]);
        while start.elapsed() < Duration::from_secs(2) && !rsp.ends_with(b"\r\n\r\nok") {
            let _ = self.engine.run_once();
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => rsp.extend_from_slice(&buf[..n]),
                Err(_) => {}
            }
        }
        assert!(self.heads.lock().expect("heads").len() > seen, "the server read no head for {req:?}: {rsp:?}");
        rsp
    }

    fn client(&self) -> TcpStream {
        let c = TcpStream::connect(self.fe).expect("connect");
        c.set_nonblocking(true).expect("nonblocking");
        c
    }

    fn last_head(&self) -> String {
        String::from_utf8_lossy(self.heads.lock().expect("heads").last().expect("a head")).into_owned()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        for _ in 0..5 {
            let _ = self.engine.run_once();
        }
        if let Some(b) = self.be.take() {
            let _ = b.join();
        }
    }
}

/// An HTTP/1.0 keep-alive request (what `ab -k` sends) is not written out of its HTX again,
/// and the server reads what `HAProxy` sends it.
#[test]
fn an_http10_keep_alive_request_is_forwarded_without_a_head_rebuild() {
    const N: u64 = 20;
    let mut rig = Rig::new("", "");
    let mut c = rig.client();
    let req = "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: Keep-Alive\r\n\r\n";
    let _ = rig.send(&mut c, req);
    let before = alcyon_sample::work::on_this_thread();
    for _ in 0..N {
        let rsp = rig.send(&mut c, req);
        assert!(rsp.starts_with(b"HTTP/1.1 200"), "{rsp:?}");
    }
    let after = alcyon_sample::work::on_this_thread();
    assert_eq!(rig.last_head(), "GET / HTTP/1.0\r\nhost: localhost\r\nconnection: keep-alive\r\n\r\n");
    assert_eq!(after[Op::ReqRebuild as usize] - before[Op::ReqRebuild as usize], 0, "request head rebuilds in {N} requests");
}

/// Every case of `CASES` in every mode: the head the server reads is `HAProxy`'s.
#[test]
fn the_server_reads_the_head_haproxy_sends() {
    for (m, (fe_lines, be_lines)) in MODES.iter().enumerate() {
        let mut rig = Rig::new(fe_lines, be_lines);
        for (req, expected) in CASES {
            let mut c = rig.client();
            let _ = rig.send(&mut c, req);
            // The head only: the capture of a chunked request holds its body too.
            let want = expected[m].split_inclusive("\r\n\r\n").next().unwrap_or_default();
            assert_eq!(rig.last_head(), want, "mode {m} ({fe_lines:?} {be_lines:?}), request {req:?}");
        }
    }
}

/// The parse of an ASCII request validates no UTF-8 (T575 part 2): HAProxy keeps request data as
/// bytes. A head with non-ASCII bytes in a value still reaches the server as it came.
#[test]
fn the_parse_of_an_ascii_keep_alive_request_reads_no_utf8() {
    const N: usize = 20;
    let mut rig = Rig::new("", "");
    let mut c = rig.client();
    let req = "GET /index.html HTTP/1.0\r\nHost: localhost\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";
    let _ = rig.send(&mut c, req);
    let before = alcyon_proto::utf8_parse_calls_on_this_thread();
    for _ in 0..N {
        let _ = rig.send(&mut c, req);
    }
    let reads = alcyon_proto::utf8_parse_calls_on_this_thread() - before;
    assert_eq!(reads, 0, "UTF-8 reads in {N} requests");
}

/// A head with bare-LF line ends cannot take the token in place: it is written out of the HTX, as
/// `HAProxy` writes it (CRLF, `connection: keep-alive` last; measured on 3.5-dev8).
#[test]
fn a_bare_lf_http10_keep_alive_head_is_written_out_with_the_token() {
    let mut rig = Rig::new("", "");
    let mut c = rig.client();
    let _ = rig.send(&mut c, "GET /lf HTTP/1.0\nHost: a\nConnection: Keep-Alive\n\n");
    assert_eq!(rig.last_head(), "GET /lf HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n");
}

/// A request a rule edited goes out with the token too, `HAProxy`'s wire: the HTX is written out
/// (the rule's copy of the headers, `req_headers`, is why the token is not put in place).
#[test]
fn an_http10_keep_alive_request_edited_by_a_rule_gets_the_token_last() {
    let mut rig = Rig::new("  http-request set-header X-A 1\n", "");
    let mut c = rig.client();
    let _ = rig.send(&mut c, "GET /r HTTP/1.0\r\nHost: a\r\nConnection: Keep-Alive\r\n\r\n");
    assert_eq!(rig.last_head(), "GET /r HTTP/1.0\r\nhost: a\r\nx-a: 1\r\nconnection: keep-alive\r\n\r\n");
}

/// T581 / X3: the server's response head is read as bytes too: its `Content-Length`, its
/// `Connection` and its status are not read as UTF-8 (`HAProxy` keeps the message as bytes).
#[test]
fn the_parse_of_an_ascii_response_reads_no_utf8() {
    const N: usize = 20;
    let mut rig = Rig::new("", "");
    let mut c = rig.client();
    let req = "GET /r HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let _ = rig.send(&mut c, req);
    let before = alcyon_proto::utf8_parse_calls_on_this_thread();
    for _ in 0..N {
        let rsp = rig.send(&mut c, req);
        assert!(rsp.starts_with(b"HTTP/1.1 200 OK\r\n"), "{rsp:?}");
    }
    let reads = alcyon_proto::utf8_parse_calls_on_this_thread() - before;
    if cfg!(debug_assertions) {
        assert_eq!(reads, 0, "UTF-8 reads in {N} responses");
    }
}
