// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The operations a request costs on the rules path, pinned (S7,
//! `docs/design/memory-2026-10-24.md` §1.3 and §6). The rules are `tools/measure/scenarios/rules.body`'s
//! (T437's: two ACLs, set/del/add-header with `%[rand]`, `set-var`, a `deny if` that does not
//! fire, two response header rules), on keep-alive connections to a keep-alive server.
//!
//! Instructions per request are what the slice is measured by (`tools/measure/insreq.sh`), and
//! they move with the poller's passes; what this pins is the work behind them, counted on the
//! thread that runs the engine ([`ibex_sample::work`]): how often the request head is written out
//! of its HTX again, how often a sample context is copied, how often an expression is looked up by
//! its text, and how many idle server connections are looked at to find one to reuse.
//!
//! Before S7 (main fcab8c91), per request: 4 rebuilds (set-header is a delete and an add, then
//! the del-header and the add-header), 3 context copies, 2 expression lookups (`rand`, `path`).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::engine::Engine;
use ibex_sample::work::Op;

const RULES: &str = "  acl api path_reg ^/(api|v[0-9]+)/\n  acl hosty hdr(host) -m sub local\n  \
    http-request set-header X-Forwarded-Proto http\n  http-request del-header X-Junk\n  \
    http-request add-header X-Id %[rand]\n  http-request set-var(txn.p) path\n  \
    http-request deny if api !hosty\n  http-response set-header X-Served ibex\n  \
    http-response del-header Server\n";

/// `measure-bench backend`'s answer: a `Server` header for the response rule to remove.
const RSP: &[u8] = b"HTTP/1.1 200 OK\r\nServer: be\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";

/// A keep-alive server: one answer per request head, on every connection it accepted.
fn backend(listener: TcpListener, running: Arc<AtomicBool>) -> thread::JoinHandle<Vec<Vec<u8>>> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<TcpStream> = Vec::new();
        let mut last = Vec::new();
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
                        last = buf[..n].to_vec();
                        let _ = s.write_all(RSP);
                    }
                    true
                }
                Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
            });
            thread::sleep(Duration::from_micros(200));
        }
        vec![last]
    })
}

/// One request on `client`, the engine run until its whole response is back; the response.
fn request(client: &mut TcpStream, engine: &mut Engine) -> String {
    client.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\nX-Junk: 1\r\n\r\n").expect("write");
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

/// The counts of `rounds` requests on each of `clients` keep-alive connections (in turn), after
/// a warm-up request on each; the last response, and the last request head the server saw.
fn work(clients: usize, rounds: usize) -> ([u64; 4], String, String) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv, Arc::clone(&running));
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n{RULES}  default_backend be\nbackend be\n  server s1 {srv_addr}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut conns: Vec<TcpStream> = (0..clients)
        .map(|_| {
            let c = TcpStream::connect(fe).expect("connect");
            c.set_nonblocking(true).expect("nonblocking");
            c
        })
        .collect();
    let mut last = String::new();
    for c in &mut conns {
        last = request(c, &mut engine);
    }
    let before = ibex_sample::work::on_this_thread();
    for _ in 0..rounds {
        for c in &mut conns {
            last = request(c, &mut engine);
        }
    }
    let after = ibex_sample::work::on_this_thread();
    drop(conns);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let seen = be.join().expect("backend").pop().unwrap_or_default();
    (std::array::from_fn(|i| after[i] - before[i]), last, String::from_utf8_lossy(&seen).into_owned())
}

/// Per request on one keep-alive connection: what the rules cost, and what they still do.
#[test]
fn the_rules_scenario_costs_what_is_pinned() {
    const N: u64 = 50;
    let (counts, rsp, seen) = work(1, N as usize);
    let per = counts.map(|c| c as f64 / N as f64);
    println!("[MEASUREMENT S7] per request: rebuilds {}, context copies {}, expression lookups {}, idle scanned {}", per[Op::ReqRebuild as usize], per[Op::CtxClone as usize], per[Op::ExprLookup as usize], per[Op::IdleScanned as usize]);
    // The rules did what they say.
    assert!(rsp.starts_with("HTTP/1.1 200") && rsp.contains("x-served: ibex") && !rsp.to_ascii_lowercase().contains("server: be"), "response: {rsp:?}");
    let seen_lc = seen.to_ascii_lowercase();
    assert!(seen_lc.contains("x-forwarded-proto: http\r\n") && seen_lc.contains("x-id: ") && !seen_lc.contains("x-junk"), "request the server saw: {seen:?}");
    assert_eq!(counts[Op::ReqRebuild as usize], N, "request head rebuilds: one per rule pass");
    assert_eq!(counts[Op::CtxClone as usize], 0, "sample context copies");
    assert_eq!(counts[Op::ExprLookup as usize], 2 * N, "expressions looked up by text");
}

/// Idle server connections looked at per request, with eight clients taking turns: each request
/// takes one of the server's idle connections.
#[test]
fn reusing_an_idle_connection_looks_at_few() {
    const CLIENTS: usize = 8;
    const ROUNDS: usize = 10;
    let (counts, rsp, _) = work(CLIENTS, ROUNDS);
    let scanned = counts[Op::IdleScanned as usize];
    println!("[MEASUREMENT S7] idle connections looked at: {scanned} for {} requests", CLIENTS * ROUNDS);
    assert!(rsp.starts_with("HTTP/1.1 200"), "response: {rsp:?}");
    assert!(scanned <= (CLIENTS * ROUNDS * CLIENTS) as u64, "{scanned} idle connections looked at");
}
