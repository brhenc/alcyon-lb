// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! X3 (`docs/design/htx-engine-2026-11-01.md` section 3): the response head on the rules path is
//! read once and written at most once. The rules are `tools/measure/scenarios/rules.body`'s two
//! response rules (`set-header X-Served ibex`, `del-header Server`) on a keep-alive connection
//! to a keep-alive server.
//!
//! What is pinned, per response, on the thread that runs the engine (debug builds):
//! - the response's header list is never copied for the fetches to read
//!   ([`ibex_rt::reuse::pair_list_copies`]): the rules edit the list the fetches read. Before X3
//!   it was copied twice before the rules and once after each rule that edited it (4 a response
//!   with the scenario's two rules);
//! - the head is written once with rules and not at all without
//!   ([`ibex_rt::engine::response_head_writes`]).
//! (Module of the `it` binary: shares the process, counts its own thread only.)

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::engine::Engine;

const RULES: &str = "  http-response set-header X-Served ibex\n  http-response del-header Server\n";

const RSP: &[u8] = b"HTTP/1.1 200 OK\r\nServer: be\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";

fn backend(listener: TcpListener, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<TcpStream> = Vec::new();
        let mut buf = [0u8; 4096];
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push(s);
            }
            conns.retain_mut(|s| match s.read(&mut buf) {
                Ok(0) => false,
                Ok(n) => {
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
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

fn request(client: &mut TcpStream, engine: &mut Engine) -> String {
    client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write");
    let start = Instant::now();
    let mut rsp = [0u8; 1024];
    let mut len = 0;
    while start.elapsed() < Duration::from_secs(3) && !rsp[..len].ends_with(b"\r\n\r\nok") {
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut rsp[len..]) {
            len += n;
        }
    }
    String::from_utf8_lossy(&rsp[..len]).into_owned()
}

/// `n` responses through a frontend with `rules`: the header-list copies and head writes they
/// cost, and the last response.
fn responses(rules: &str, n: u64) -> (u64, u64, String) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv, Arc::clone(&running));
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n{rules}  default_backend be\nbackend be\n  server s1 {srv_addr}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let mut last = request(&mut c, &mut engine);
    let (c0, w0) = (ibex_rt::reuse::pair_list_copies(), ibex_rt::engine::response_head_writes());
    for _ in 0..n {
        last = request(&mut c, &mut engine);
    }
    let (copies, writes) = (ibex_rt::reuse::pair_list_copies() - c0, ibex_rt::engine::response_head_writes() - w0);
    drop(c);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
    (copies, writes, last)
}

/// With the scenario's two response rules: no copy of the header list, one write of the head.
#[test]
fn a_response_head_is_walked_once_and_written_at_most_once() {
    const N: u64 = 20;
    let (copies, writes, last) = responses(RULES, N);
    assert!(last.starts_with("HTTP/1.1 200 OK\r\n") && last.contains("X-Served: ibex\r\n") && !last.contains("Server: be"), "{last:?}");
    println!("[X3] {N} responses with two rules: {copies} header-list copies, {writes} head writes");
    if cfg!(debug_assertions) {
        assert_eq!(copies, 0, "header-list copies in {N} responses");
        assert_eq!(writes, N, "head writes in {N} responses");
    }
}

/// Without response rules the head goes as it came: never written again.
#[test]
fn a_response_head_without_rules_is_not_written_again() {
    const N: u64 = 20;
    let (copies, writes, last) = responses("", N);
    assert!(last.starts_with("HTTP/1.1 200 OK\r\nServer: be\r\n"), "{last:?}");
    if cfg!(debug_assertions) {
        assert_eq!((copies, writes), (0, 0), "header-list copies and head writes in {N} responses");
    }
}
