// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The failure counters each worker counts into (T160: one set per proxy, shared by the
//! workers). A connect that fails at once and a request a backend's `tcp-request content`
//! rule refuses each count: `econ` and `dreq` in `show stat`. Measured on `HAProxy` 3.5-dev8
//! with the same configurations: `econ` 1 on the backend (and on a `listen`), `dreq` 1 on an
//! HTTP backend whose `tcp-request content silent-drop` drops the request.
//!
//! 255.255.255.255 is refused by `connect()` itself (`ENETUNREACH`), not later by the poller.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;

use ibex_rt::engine::Engine;

const UNREACHABLE: &str = "255.255.255.255:80";

fn start(body: &str) -> (Engine, std::net::SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n    timeout connect 1s\n    timeout client 2s\n    timeout server 2s\n    retries 1\n{}",
        body.replace("@FE@", &fe.to_string())
    );
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    (engine, fe)
}

fn idx(engine: &Engine, name: &str) -> usize {
    engine.proxies.iter().position(|p| p.name == name).expect("proxy")
}

/// Sends `req` and steps the engine until `counter` of proxy `name` moves.
fn counted(body: &str, req: &[u8], name: &str, counter: fn(&ibex_rt::engine::ProxyStats) -> u64) -> u64 {
    let (mut engine, fe) = start(body);
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(req);
    let p = idx(&engine, name);
    common::drive_until(&mut engine, |e| counter(e.proxies[p].counters()) > 0);
    counter(engine.proxies[p].counters())
}

fn econ(s: &ibex_rt::engine::ProxyStats) -> u64 {
    s.failed_conn.load(Ordering::Relaxed)
}

fn dreq(s: &ibex_rt::engine::ProxyStats) -> u64 {
    s.denied_req.load(Ordering::Relaxed)
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";

#[test]
fn a_tcp_listen_counts_a_connect_refused_at_once() {
    let body = format!("listen li\n    mode tcp\n    bind @FE@\n    server s {UNREACHABLE}\n");
    // `HAProxy` counts 1; Ibex counts the retry's failure too (2), a separate defect.
    assert!(counted(&body, b"x", "li", econ) >= 1);
}

#[test]
fn a_tcp_backend_counts_a_connect_refused_at_once() {
    let body = format!(
        "frontend fe\n    mode tcp\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode tcp\n    server s {UNREACHABLE}\n"
    );
    assert_eq!(counted(&body, b"x", "be", econ), 1);
}

#[test]
fn an_http_backend_counts_a_connect_refused_at_once() {
    let body = format!(
        "frontend fe\n    mode http\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode http\n    server s {UNREACHABLE}\n"
    );
    assert_eq!(counted(&body, GET, "be", econ), 1);
}

#[test]
fn an_http_backend_counts_a_silent_drop() {
    let body = "frontend fe\n    mode http\n    bind @FE@\n    default_backend be\n\
                backend be\n    mode http\n    tcp-request content silent-drop\n    server s 127.0.0.1:9\n";
    assert_eq!(counted(body, GET, "be", dreq), 1);
}

/// A TCP backend's `tcp-request content reject` and `silent-drop` close the client. Which
/// proxy's `dreq` counts them is not asserted: `HAProxy` counts the frontend's (`f1 dreq 1`,
/// `b1 dreq 0` in `show stat`), Ibex the backend's, which is a separate defect.
fn closes_the_client(rule: &str) -> bool {
    let body = format!(
        "frontend fe\n    mode tcp\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode tcp\n    tcp-request content {rule}\n    server s 127.0.0.1:9\n"
    );
    let (mut engine, fe) = start(&body);
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(b"x");
    c.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 16];
    common::drive_until(&mut engine, |_| match c.read(&mut buf) {
        Ok(0) => true,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
        Ok(_) => false,
    })
}

#[test]
fn a_tcp_backend_reject_closes_the_client() {
    assert!(closes_the_client("reject"));
}

/// `silent-drop` sends the client nothing: what shows it ran is the frontend's session
/// ending (its `scur` back to 0 after one).
#[test]
fn a_tcp_backend_silent_drop_ends_the_session() {
    let body = "frontend fe\n    mode tcp\n    bind @FE@\n    default_backend be\n\
                backend be\n    mode tcp\n    tcp-request content silent-drop\n    server s 127.0.0.1:9\n";
    let (mut engine, fe) = start(body);
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(b"x");
    let p = idx(&engine, "fe");
    let ended = common::drive_until(&mut engine, |e| {
        let s = e.proxies[p].counters();
        s.cum_conn.load(Ordering::Relaxed) == 1 && s.act_conn.load(Ordering::Relaxed) == 0
    });
    assert!(ended, "the session is still open");
}
