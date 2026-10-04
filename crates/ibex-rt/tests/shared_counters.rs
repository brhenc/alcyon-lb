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
    // `HAProxy` counts 1, once the retries are spent (see the `retries 2` cases below).
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

/// A retry whose own connect is refused at once ends the request: `HAProxy` answers 503 at
/// once and shows `wretr 1`, `econ 1` on the backend (measured with `retries 1` against
/// 255.255.255.255:80).
#[test]
fn an_http_backend_retry_refused_at_once_ends_the_request() {
    let body = format!(
        "frontend fe\n    mode http\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode http\n    server s {UNREACHABLE}\n"
    );
    let (mut engine, fe) = start(&body);
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(GET);
    c.set_nonblocking(true).expect("nonblocking");
    let p = idx(&engine, "be");
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline && !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let _ = engine.run_once();
        let mut buf = [0u8; 4096];
        if let Ok(n) = std::io::Read::read(&mut c, &mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(got.starts_with(b"HTTP/1.1 503"), "{}", String::from_utf8_lossy(&got));
    let s = engine.proxies[p].counters();
    assert_eq!(s.retries_count.load(Ordering::Relaxed), 1, "wretr");
    assert_eq!(econ(s), 1, "econ");
}

/// Sends a GET and steps the engine until a whole response head is back (or 5 s pass).
/// Returns what came back and how long it took.
fn answer(engine: &mut Engine, fe: std::net::SocketAddr) -> (Vec<u8>, std::time::Duration) {
    let started = std::time::Instant::now();
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(GET);
    c.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    while started.elapsed() < std::time::Duration::from_secs(5) && !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let _ = engine.run_once();
        let mut buf = [0u8; 4096];
        if let Ok(n) = c.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    (got, started.elapsed())
}

/// Field `field` of the `show stat` row `px`/`sv`.
fn stat(engine: &Engine, px: &str, sv: &str, field: &str) -> String {
    let csv = ibex_rt::stats::format_show_stat(&engine.proxies, &engine.checks, 1);
    let mut lines = csv.lines();
    let head: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let col = head.iter().position(|h| *h == field).expect("field");
    let row = lines
        .map(|l| l.split(',').collect::<Vec<_>>())
        .find(|r| r.first() == Some(&px) && r.get(1) == Some(&sv))
        .expect("row");
    row[col].to_string()
}

/// `retries 0`: the one connect refused at once is the end, a 503 at once (`HAProxy`:
/// < 1 ms, `econ` 1 and `wretr` 0 on the backend and the server).
#[test]
fn an_http_backend_without_retries_refused_at_once_answers_503_at_once() {
    let body = format!(
        "frontend fe\n    mode http\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode http\n    retries 0\n    server s {UNREACHABLE}\n"
    );
    let (mut engine, fe) = start(&body);
    let (got, took) = answer(&mut engine, fe);
    assert!(got.starts_with(b"HTTP/1.1 503"), "{}", String::from_utf8_lossy(&got));
    assert!(took < std::time::Duration::from_millis(500), "503 after {took:?}");
    for sv in ["BACKEND", "s"] {
        assert_eq!(stat(&engine, "be", sv, "econ"), "1", "{sv} econ");
        assert_eq!(stat(&engine, "be", sv, "wretr"), "0", "{sv} wretr");
    }
}

/// `retries 2` against a server refused at once: both retries run at once, without the
/// turnaround, and the last failure alone counts in `econ` (`HAProxy`: 503 in < 1 ms,
/// `wretr` 2, `econ` 1 on the backend and the server).
#[test]
fn an_http_backend_two_retries_refused_at_once_answer_503_at_once() {
    let body = format!(
        "frontend fe\n    mode http\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode http\n    retries 2\n    server s {UNREACHABLE}\n"
    );
    let (mut engine, fe) = start(&body);
    let (got, took) = answer(&mut engine, fe);
    assert!(got.starts_with(b"HTTP/1.1 503"), "{}", String::from_utf8_lossy(&got));
    assert!(took < std::time::Duration::from_millis(500), "503 after {took:?}");
    for sv in ["BACKEND", "s"] {
        assert_eq!(stat(&engine, "be", sv, "econ"), "1", "{sv} econ");
        assert_eq!(stat(&engine, "be", sv, "wretr"), "2", "{sv} wretr");
        assert_eq!(stat(&engine, "be", sv, "wredis"), "0", "{sv} wredis");
    }
}

/// `mode tcp`, `retries 2`: the client is closed once the retries are spent (`HAProxy`:
/// `wretr` 2, `econ` 1 on the backend and the server).
#[test]
fn a_tcp_backend_two_retries_refused_at_once_close_the_client() {
    let body = format!("listen li\n    mode tcp\n    bind @FE@\n    retries 2\n    server s {UNREACHABLE}\n");
    let (mut engine, fe) = start(&body);
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(b"x");
    c.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 16];
    let closed = common::drive_until(&mut engine, |_| match c.read(&mut buf) {
        Ok(0) => true,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
        Ok(_) => false,
    });
    assert!(closed, "the client is still open");
    for sv in ["BACKEND", "s"] {
        assert_eq!(stat(&engine, "li", sv, "econ"), "1", "{sv} econ");
        assert_eq!(stat(&engine, "li", sv, "wretr"), "2", "{sv} wretr");
    }
}

/// `mode tcp`, `retries 0`: the connect made at accept, refused at once, is the end
/// (`HAProxy`: the client closed at once; `econ` 1, `wretr` 0 on the backend and the server).
#[test]
fn a_tcp_backend_without_retries_refused_at_once_closes_the_client() {
    let body = format!("listen li\n    mode tcp\n    bind @FE@\n    retries 0\n    server s {UNREACHABLE}\n");
    assert!(closes_the_client_of(&body));
}

/// A retry that finds no server left -- the one server went down while its connect was
/// under way, and `option redispatch` asks the balancer again -- ends the stream (the
/// client is closed) rather than leaving it waiting.
#[test]
fn a_tcp_backend_retry_with_no_server_left_ends_the_stream() {
    let dead = common::reserve_addr();
    let body = format!(
        "listen li\n    mode tcp\n    bind @FE@\n    option redispatch\n    server s {dead}\n"
    );
    let (mut engine, fe) = start(&body);
    let p = idx(&engine, "li");
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(b"x");
    c.set_nonblocking(true).expect("nonblocking");
    // The stream is accepted, its connect under way; the server goes down before the
    // refusal comes back.
    let accepted = common::drive_until(&mut engine, |e| e.proxies[p].counters().cum_conn.load(Ordering::Relaxed) == 1);
    assert!(accepted, "not accepted");
    engine.proxies[p].server_statuses[0].store(ibex_rt::check::ServerStatus::Down as u8, Ordering::Relaxed);
    let mut buf = [0u8; 16];
    let closed = common::drive_until(&mut engine, |_| match c.read(&mut buf) {
        Ok(0) => true,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
        Ok(_) => false,
    });
    assert!(closed, "the client is still open");
}

/// Whether the client of a `mode tcp` proxy is closed, and the backend and server rows
/// then show `econ` 1, `wretr` 0.
fn closes_the_client_of(body: &str) -> bool {
    let (mut engine, fe) = start(body);
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(b"x");
    c.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 16];
    let closed = common::drive_until(&mut engine, |_| match c.read(&mut buf) {
        Ok(0) => true,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
        Ok(_) => false,
    });
    for sv in ["BACKEND", "s"] {
        assert_eq!(stat(&engine, "li", sv, "econ"), "1", "{sv} econ");
        assert_eq!(stat(&engine, "li", sv, "wretr"), "0", "{sv} wretr");
    }
    closed
}

/// `option redispatch`, two servers both refused at once, `retries 2`: every retry is a
/// redispatch to the other server, and only the server tried last counts the failure
/// (`HAProxy`: 503 in < 1 ms; backend `wredis` 2, `wretr` 0, `econ` 1; each server
/// `wredis` 1; `econ` 1 on the one tried last, 0 on the other).
#[test]
fn an_http_backend_redispatch_refused_at_once_answers_503_at_once() {
    let body = format!(
        "frontend fe\n    mode http\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode http\n    retries 2\n    option redispatch\n    balance roundrobin\n\
         \x20   server s {UNREACHABLE}\n    server s2 255.255.255.255:81\n"
    );
    let (mut engine, fe) = start(&body);
    let (got, took) = answer(&mut engine, fe);
    assert!(got.starts_with(b"HTTP/1.1 503"), "{}", String::from_utf8_lossy(&got));
    assert!(took < std::time::Duration::from_millis(500), "503 after {took:?}");
    assert_eq!(stat(&engine, "be", "BACKEND", "econ"), "1", "backend econ");
    assert_eq!(stat(&engine, "be", "BACKEND", "wredis"), "2", "backend wredis");
    assert_eq!(stat(&engine, "be", "BACKEND", "wretr"), "0", "backend wretr");
    for sv in ["s", "s2"] {
        assert_eq!(stat(&engine, "be", sv, "wredis"), "1", "{sv} wredis");
        assert_eq!(stat(&engine, "be", sv, "wretr"), "0", "{sv} wretr");
    }
    let mut econ: Vec<String> = ["s", "s2"].iter().map(|sv| stat(&engine, "be", sv, "econ")).collect();
    econ.sort();
    assert_eq!(econ, ["0", "1"], "server econ");
}

/// `mode tcp`, a connect refused later by the poller (an asynchronous error, a closed port
/// on 127.0.0.1): the retry to the same server waits out the turnaround, `MIN(1s, timeout
/// connect)` (`HAProxy`, `retries 1`: the client is closed after 1.0 s; `wretr` 1, `econ` 1).
#[test]
fn a_tcp_backend_retry_after_a_refused_connect_waits_the_turnaround() {
    let dead = common::reserve_addr();
    let body = format!("listen li\n    mode tcp\n    bind @FE@\n    server s {dead}\n");
    let (mut engine, fe) = start(&body);
    let started = std::time::Instant::now();
    let mut c = TcpStream::connect(fe).expect("connect");
    let _ = c.write_all(b"x");
    c.set_nonblocking(true).expect("nonblocking");
    let mut buf = [0u8; 16];
    let closed = common::drive_until(&mut engine, |_| match c.read(&mut buf) {
        Ok(0) => true,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
        Ok(_) => false,
    });
    assert!(closed, "the client is still open");
    let took = started.elapsed();
    assert!(took >= std::time::Duration::from_millis(900), "closed after {took:?}");
    assert_eq!(stat(&engine, "li", "BACKEND", "wretr"), "1", "wretr");
    assert_eq!(stat(&engine, "li", "BACKEND", "econ"), "1", "econ");
}

const BLACKHOLE: &str = "10.255.255.1:80";

/// A server that never answers: each connect ends at `timeout connect`, with no turnaround
/// between attempts (`HAProxy` 3.5-dev8, `timeout connect` 300 ms: `retries 0` 503 after
/// 0.31 s, `retries 1` after 0.65 s, `retries 2` after 0.92 s; `econ` 1 on the backend and
/// the server whatever the retries, `wretr` = retries, server `stot` = retries + 1; with
/// 100 ms and `retries 2`, 0.31 s).
fn blackhole(retries: u32) -> (Engine, Vec<u8>, std::time::Duration) {
    let body = format!(
        "frontend fe\n    mode http\n    bind @FE@\n    default_backend be\n\
         backend be\n    mode http\n    timeout connect 200ms\n    retries {retries}\n    server s {BLACKHOLE}\n"
    );
    let (mut engine, fe) = start(&body);
    let (got, took) = answer(&mut engine, fe);
    (engine, got, took)
}

#[test]
fn a_connect_timeout_without_retries_answers_503_and_counts_econ() {
    let (engine, got, took) = blackhole(0);
    assert!(got.starts_with(b"HTTP/1.1 503"), "{}", String::from_utf8_lossy(&got));
    assert!(took >= std::time::Duration::from_millis(190), "503 after {took:?}");
    for sv in ["BACKEND", "s"] {
        assert_eq!(stat(&engine, "be", sv, "econ"), "1", "{sv} econ");
        assert_eq!(stat(&engine, "be", sv, "wretr"), "0", "{sv} wretr");
    }
    assert_eq!(stat(&engine, "be", "s", "stot"), "1");
}

#[test]
fn a_connect_timeout_is_retried_without_a_turnaround() {
    let (engine, got, took) = blackhole(2);
    assert!(got.starts_with(b"HTTP/1.1 503"), "{}", String::from_utf8_lossy(&got));
    assert!(took >= std::time::Duration::from_millis(590), "503 after {took:?}");
    assert!(took < std::time::Duration::from_millis(900), "503 after {took:?}");
    for sv in ["BACKEND", "s"] {
        assert_eq!(stat(&engine, "be", sv, "econ"), "1", "{sv} econ");
        assert_eq!(stat(&engine, "be", sv, "wretr"), "2", "{sv} wretr");
    }
    assert_eq!(stat(&engine, "be", "s", "stot"), "3");
}
