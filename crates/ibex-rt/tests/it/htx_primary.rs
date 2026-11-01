// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! X2 (`docs/design/htx-engine-2026-11-01.md` §3): the request head is HTX-primary. The rules
//! edit the HTX and nothing else; the head goes to the server as the bytes that arrived when
//! nothing edited it, and is written out of its HTX once, at the server send, when something
//! did. Counted on the engine's thread ([`ibex_sample::work::Op::ReqRebuild`]: the head written
//! out of its HTX into the request buffer).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::engine::Engine;
use ibex_sample::work::Op;

/// `tools/measure/scenarios/rules.body`'s request rules.
const RULES: &str = "  acl api path_reg ^/(api|v[0-9]+)/\n  acl hosty hdr(host) -m sub local\n  \
    http-request set-header X-Forwarded-Proto http\n  http-request del-header X-Junk\n  \
    http-request add-header X-Id %[rand]\n  http-request set-var(txn.p) path\n  \
    http-request deny if api !hosty\n";

const RSP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A keep-alive server answering each whole request head; the heads it saw, in order.
fn backend(listener: TcpListener, running: Arc<AtomicBool>, seen: Arc<Mutex<Vec<Vec<u8>>>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<(TcpStream, Vec<u8>)> = Vec::new();
        let mut buf = vec![0u8; 65536];
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push((s, Vec::new()));
            }
            conns.retain_mut(|(s, acc)| match s.read(&mut buf) {
                Ok(0) => false,
                Ok(n) => {
                    acc.extend_from_slice(&buf[..n]);
                    while let Some(at) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = acc.drain(..at + 4).collect();
                        seen.lock().expect("seen").push(head);
                        let _ = s.write_all(RSP);
                    }
                    true
                }
                Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
            });
            thread::sleep(Duration::from_micros(200));
        }
    })
}

/// The proxy in this process, its frontend's `rules`, and a backend that records heads.
struct Rig {
    engine: Engine,
    fe: std::net::SocketAddr,
    running: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    be: Option<thread::JoinHandle<()>>,
}

impl Rig {
    fn new(global: &str, rules: &str) -> Self {
        let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
        let srv_addr = srv.local_addr().expect("addr");
        let fe = common::reserve_addr();
        let running = Arc::new(AtomicBool::new(true));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let be = backend(srv, Arc::clone(&running), Arc::clone(&seen));
        let cfg = format!(
            "global\n{global}defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
             frontend fe\n  bind {fe}\n{rules}  default_backend be\nbackend be\n  server s1 {srv_addr}\n"
        );
        let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        Self { engine, fe, running, seen, be: Some(be) }
    }

    fn connect(&self) -> TcpStream {
        let c = TcpStream::connect(self.fe).expect("connect");
        c.set_nonblocking(true).expect("nonblocking");
        c
    }

    /// `req` on `client`, the engine run until a whole response is back; the response.
    fn request(&mut self, client: &mut TcpStream, req: &[u8]) -> String {
        let mut off = 0;
        let start = Instant::now();
        let mut rsp = vec![0u8; 4096];
        let mut len = 0;
        while start.elapsed() < Duration::from_secs(5) && !(off == req.len() && rsp[..len].ends_with(b"\r\n\r\nok")) {
            if off < req.len() {
                if let Ok(n) = client.write(&req[off..]) {
                    off += n;
                }
            }
            let _ = self.engine.run_once();
            if let Ok(n) = client.read(&mut rsp[len..]) {
                len += n;
            }
        }
        String::from_utf8_lossy(&rsp[..len]).into_owned()
    }

    /// The last head the server saw.
    fn last_seen(&self) -> Vec<u8> {
        self.seen.lock().expect("seen").last().cloned().unwrap_or_default()
    }

    /// The `ReqRebuild` count of `rounds` requests on one keep-alive connection, after one to
    /// warm it; the last response.
    fn rebuilds(&mut self, req: &[u8], rounds: u64) -> (u64, String) {
        let mut c = self.connect();
        let mut last = self.request(&mut c, req);
        let before = ibex_sample::work::on_this_thread()[Op::ReqRebuild as usize];
        for _ in 0..rounds {
            last = self.request(&mut c, req);
        }
        (ibex_sample::work::on_this_thread()[Op::ReqRebuild as usize] - before, last)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        for _ in 0..5 {
            let _ = self.engine.run_once();
        }
        self.running.store(false, Ordering::Relaxed);
        if let Some(be) = self.be.take() {
            let _ = be.join();
        }
    }
}

/// `ab -k`'s request: HTTP/1.0 with `Connection: Keep-Alive`.
const AB_GET: &[u8] = b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";

/// The head is written out of its HTX at most once per request: never for a keep-alive GET
/// nothing edits, once for the rules scenario's head however many edits it takes, the
/// `option forwardfor` header after the rules included.
#[test]
fn a_request_head_is_written_at_most_once() {
    const N: u64 = 20;
    let mut plain = Rig::new("", "");
    let (n, rsp) = plain.rebuilds(AB_GET, N);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    assert_eq!(n, 0, "head writes for {N} keep-alive GETs nothing edits");

    let mut rules = Rig::new("", &format!("{RULES}  option forwardfor\n"));
    let req = b"GET /api/test HTTP/1.1\r\nHost: localhost\r\nX-Junk: 1\r\n\r\n";
    let (n, rsp) = rules.rebuilds(req, N);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    let seen = String::from_utf8_lossy(&rules.last_seen()).to_ascii_lowercase();
    assert!(
        seen.contains("x-forwarded-proto: http\r\n") && seen.contains("x-id: ") && seen.contains("x-forwarded-for: 127.0.0.1\r\n") && !seen.contains("x-junk"),
        "request the server saw: {seen:?}"
    );
    assert_eq!(n, N, "head writes for {N} requests of the rules scenario with forwardfor: one each");
}

/// The HTTP/1 request head is indexed where it is ([`ibex_proto::h1::H1Parser::index_head_in_place`]):
/// its fields are descriptors over the received bytes, not copied into the HTX one by one.
#[test]
fn a_request_head_is_indexed_not_copied() {
    const N: u64 = 10;
    let mut rig = Rig::new("", RULES);
    let mut c = rig.connect();
    let req = b"GET /api/x HTTP/1.1\r\nHost: localhost\r\nX-Junk: 1\r\nAccept: */*\r\n\r\n";
    let _ = rig.request(&mut c, req);
    let (parses, copies) = (ibex_proto::h1::request_parses(), ibex_proto::h1::copied_request_parses());
    for _ in 0..N {
        let rsp = rig.request(&mut c, req);
        assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    }
    assert_eq!(ibex_proto::h1::request_parses() - parses, N, "request heads parsed");
    assert_eq!(ibex_proto::h1::copied_request_parses() - copies, 0, "request heads parsed by copying their fields");
    let seen = String::from_utf8_lossy(&rig.last_seen()).to_ascii_lowercase();
    assert!(seen.contains("x-forwarded-proto: http\r\n") && !seen.contains("x-junk"), "request the server saw: {seen:?}");
}

/// D-E, default `off`: a head no rule edited reaches the server as the bytes that arrived,
/// names in the case they came in; `on` lowercases them, as `HAProxy`.
#[test]
fn an_unmodified_head_is_the_bytes_that_arrived() {
    let req = b"GET /a?b=C HTTP/1.1\r\nHost: localhost\r\nX-MiXeD-Case: Some Value\r\nAccept: */*\r\n\r\n";
    let mut off = Rig::new("", "");
    let mut c = off.connect();
    let rsp = off.request(&mut c, req);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    assert_eq!(String::from_utf8_lossy(&off.last_seen()), String::from_utf8_lossy(req), "off: the bytes that arrived");

    let mut on = Rig::new("  tune.ibex.h1-lowercase-headers on\n", "");
    let mut c = on.connect();
    let rsp = on.request(&mut c, req);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    assert_eq!(
        String::from_utf8_lossy(&on.last_seen()),
        "GET /a?b=C HTTP/1.1\r\nhost: localhost\r\nx-mixed-case: Some Value\r\naccept: */*\r\n\r\n",
        "on: names in lower case"
    );
}

/// A head that leaves little of the buffer, then five 200-byte `set-header`s: the rules'
/// room is `tune.maxrewrite` (1 KiB) and the head still fits what `HAProxy` holds, so the
/// request goes with all five.
#[test]
fn rules_with_a_full_reserve_still_forward() {
    let mut rules = String::new();
    for i in 0..5 {
        rules.push_str(&format!("  http-request set-header X-Big-{i} {}\n", "v".repeat(200)));
    }
    let mut rig = Rig::new("  tune.maxrewrite 1024\n", &rules);
    let mut req = b"GET /big HTTP/1.1\r\nHost: localhost\r\nX-Pad: ".to_vec();
    req.extend(std::iter::repeat_n(b'p', 13_000));
    req.extend_from_slice(b"\r\n\r\n");
    let mut c = rig.connect();
    let rsp = rig.request(&mut c, &req);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    let seen = String::from_utf8_lossy(&rig.last_seen()).into_owned();
    for i in 0..5 {
        assert!(seen.contains(&format!("X-Big-{i}: {}\r\n", "v".repeat(200))), "header {i} missing from the request the server saw ({} bytes)", seen.len());
    }
    assert!(seen.contains(&"p".repeat(13_000)), "the client's header went");
}
