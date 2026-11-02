// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! O2: the backend side finds a server and its idle connections by index. A request that
//! takes an idle server connection reads no `RwLock` and hashes no `(backend, server)`
//! (`work::Op::IdleLock`, `work::Op::IdleHash`).
//!
//! O1a: the per-request state is a `Stream` the HTTP/1 session keeps and resets in
//! place between its requests (`docs/design/engine-architecture-2026-11-01.md` §4.3): no
//! `Stream` taken and no `StreamLog` built per keep-alive request, and nothing a request set
//! (a variable, a capture, a priority, a timeout) left for the next one to log.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use ibex_rt::engine::Engine;
use ibex_sample::work::{on_this_thread, Op};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

fn backend(listener: TcpListener, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<(TcpStream, Vec<u8>)> = Vec::new();
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push((s, Vec::new()));
            }
            let mut buf = [0u8; 4096];
            conns.retain_mut(|(s, pending)| {
                match s.read(&mut buf) {
                    Ok(0) => return false,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                    Err(_) => {}
                }
                while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                    pending.drain(..end + 4);
                    let _ = s.write_all(RESPONSE);
                }
                true
            });
            thread::sleep(Duration::from_micros(200));
        }
    })
}

fn one_request(engine: &mut Engine, addr: SocketAddr) {
    let mut client = TcpStream::connect(addr).expect("connect");
    client.set_nonblocking(true).expect("nonblocking");
    client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    while got.len() < RESPONSE.len() {
        assert!(Instant::now() < deadline, "no response: {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut buf) {
            assert!(n > 0, "closed");
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert!(got.starts_with(b"HTTP/1.1 200"));
    // Let the engine see the close and put the server connection back in the lists.
    drop(client);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
}

#[test]
fn taking_an_idle_connection_takes_no_lock_and_hashes_nothing() {
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv_listener.local_addr().expect("addr");
    let fe_addr = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv_listener, Arc::clone(&running));
    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            default_backend: Some("be".into()),
            clitimeout: Some(Duration::from_secs(5)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            http_reuse: Some(ibex_config::HttpReuse::Always),
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    for _ in 0..3 {
        one_request(&mut engine, fe_addr);
    }
    let before = on_this_thread();
    const N: u64 = 20;
    for _ in 0..N {
        one_request(&mut engine, fe_addr);
    }
    let after = on_this_thread();
    let (locks, hashes) = (after[Op::IdleLock as usize] - before[Op::IdleLock as usize], after[Op::IdleHash as usize] - before[Op::IdleHash as usize]);
    println!("{N} requests: {locks} lock reads, {hashes} hashes");
    assert_eq!((locks, hashes), (0, 0), "the idle lists are found by server index");
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

#[test]
fn a_request_without_track_rules_builds_no_context_for_them() {
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv_listener.local_addr().expect("addr");
    let fe_addr = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let be = backend(srv_listener, Arc::clone(&running));
    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe".into(),
            bind: Some(fe_addr),
            mode: Mode::Http,
            default_backend: Some("be".into()),
            clitimeout: Some(Duration::from_secs(5)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", srv_addr)],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    for _ in 0..3 {
        one_request(&mut engine, fe_addr);
    }
    let before = on_this_thread()[Op::TrackCtx as usize];
    const N: u64 = 20;
    for _ in 0..N {
        one_request(&mut engine, fe_addr);
    }
    let built = on_this_thread()[Op::TrackCtx as usize] - before;
    println!("{N} requests: {built} track contexts built");
    assert_eq!(built, 0, "no track-sc rule, no context built for one");
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}

#[test]
fn a_round_robin_pick_syncs_with_the_servers_only_when_one_changed() {
    let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
    let config = Config {
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            servers: vec![Server::new("s1", a), Server::new("s2", b)],
            ..Default::default()
        }],
        ..Default::default()
    };
    let engine = Engine::new(&config, 8).expect("Engine::new");
    let px = &engine.proxies[0];
    assert!(px.select_server().is_some());
    let before = on_this_thread()[Op::LbSync as usize];
    let picks: Vec<_> = (0..100).map(|_| px.select_server()).collect();
    assert_eq!(on_this_thread()[Op::LbSync as usize] - before, 0, "100 picks, nothing changed");
    assert_eq!(picks.iter().filter(|p| **p == Some(a)).count(), 50);
    px.set_weight(1, 0);
    assert!(px.select_server_idx().is_some_and(|(i, _)| i == Some(0)), "a weight change is seen by the next pick");
    assert_eq!(on_this_thread()[Op::LbSync as usize] - before, 1);
}

#[test]
fn balance_source_and_the_other_algorithms_pick_by_index_without_a_list() {
    use ibex_config::BalanceAlgorithm;
    let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
    let engine = |balance| {
        let config = Config {
            backends: vec![BackendSection {
                name: "be".into(),
                mode: Mode::Http,
                balance,
                servers: vec![Server::new("s1", a), Server::new("s2", b)],
                ..Default::default()
            }],
            ..Default::default()
        };
        Engine::new(&config, 8).expect("Engine::new")
    };
    let e = engine(BalanceAlgorithm::Source);
    let px = &e.proxies[0];
    let v4 = Some(std::net::IpAddr::from([10, 0, 0, 3]));
    let v6 = Some(std::net::IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 5]));
    assert_eq!(px.select_server_with_key_idx(v4, None).map(|p| p.0), Some(Some(1)));
    assert_eq!(px.select_server_with_key_idx(v6, None).map(|p| p.0), Some(Some(1)));
    let no_ip: Vec<_> = (0..4).map(|_| px.select_server_with_key_idx(None, None).and_then(|p| p.0)).collect();
    assert_eq!(no_ip.iter().filter(|i| **i == Some(0)).count(), 2, "{no_ip:?}");
    for algo in [BalanceAlgorithm::Leastconn, BalanceAlgorithm::StaticRr, BalanceAlgorithm::First] {
        let e = engine(algo);
        assert!(e.proxies[0].select_server_idx().is_some_and(|(i, _)| i.is_some()));
    }
}

#[test]
fn a_backend_without_servers_picks_its_dispatch_address() {
    let d: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let config = Config {
        backends: vec![BackendSection { name: "be".into(), mode: Mode::Http, dispatch: Some(d), ..Default::default() }],
        ..Default::default()
    };
    let engine = Engine::new(&config, 8).expect("Engine::new");
    assert_eq!(engine.proxies[0].select_server_idx(), Some((None, d)));
}

/// A keep-alive server answering each request head; `X-R: r1` on a request for `/one`.
fn keepalive_backend(listener: TcpListener, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<(TcpStream, Vec<u8>)> = Vec::new();
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push((s, Vec::new()));
            }
            let mut buf = [0u8; 4096];
            conns.retain_mut(|(s, pending)| {
                match s.read(&mut buf) {
                    Ok(0) => return false,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                    Err(_) => {}
                }
                while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                    let one = pending.starts_with(b"GET /one ");
                    pending.drain(..end + 4);
                    let extra: &[u8] = if one { b"X-R: r1\r\n" } else { b"" };
                    let _ = s.write_all(&[&b"HTTP/1.1 200 OK\r\n"[..], extra, b"Content-Length: 2\r\n\r\nok"].concat());
                }
                true
            });
            thread::sleep(Duration::from_micros(100));
        }
    })
}

/// One request on the kept-alive `client`, the engine run until its response is in.
fn keepalive_request(engine: &mut Engine, client: &mut TcpStream, req: &[u8]) {
    client.write_all(req).expect("write");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    while !got.ends_with(b"ok") {
        assert!(Instant::now() < deadline, "no response: {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        match client.read(&mut buf) {
            Ok(0) => panic!("the proxy closed the connection"),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
    assert!(got.starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&got));
}

fn keepalive_engine(extra_fe: &str, extra_be: &str, defaults: &str) -> (Engine, SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv.local_addr().expect("addr");
    let running = Arc::new(AtomicBool::new(true));
    let be = keepalive_backend(srv, Arc::clone(&running));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n{defaults}\
         frontend fe\n  bind {fe}\n{extra_fe}  default_backend be\n\
         backend be\n{extra_be}  server s {srv_addr}\n"
    );
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    (engine, fe, running, be)
}

/// A keep-alive request after the first makes no `Stream` and builds no `StreamLog`: the
/// session's stream is reset in place at the transaction's end (O1a; on
/// ibex-rc5 `end_txn` rebuilt the log, `StreamLog::start` once a request).
#[test]
fn a_keepalive_request_resets_its_stream_in_place() {
    const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const N: u64 = 20;
    let (mut engine, fe, running, be) = keepalive_engine(
        "  capture request header Host len 16\n  http-request set-var(txn.x) str(a)\n",
        "",
        "",
    );
    let mut client = TcpStream::connect(fe).expect("connect");
    client.set_nonblocking(true).expect("nonblocking");
    client.set_nodelay(true).expect("nodelay");
    for _ in 0..4 {
        keepalive_request(&mut engine, &mut client, REQ);
    }
    let (t0, l0) = (ibex_rt::probe::stream_takes(), ibex_rt::probe::stream_log_starts());
    for _ in 0..N {
        keepalive_request(&mut engine, &mut client, REQ);
    }
    let (takes, logs) = (ibex_rt::probe::stream_takes() - t0, ibex_rt::probe::stream_log_starts() - l0);
    println!("{N} keep-alive requests: {takes} Streams made, {logs} StreamLog constructions");
    assert_eq!((takes, logs), (0, 0), "the session's Stream is reset in place, not rebuilt");
    running.store(false, Ordering::Relaxed);
    drop(client);
    let _ = be.join();
}

/// What the first request of a connection set (a `txn.` variable, header captures of both
/// kinds, the priority class, a stream timeout) is gone for the second: each line as
/// `HAProxy` 3.5-dev8-885761-29 logged it for the same two requests, measured 2026-11-02:
///   "GET /one HTTP/1.1" 200 one - s1 {c1|d1} {r1} 5 1000 56
///   "GET /two HTTP/1.1" 200 - - - {|} {} 0 5000 51
#[test]
fn a_field_set_in_request_one_is_absent_in_request_two() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let defaults = format!(
        "  log {} local0\n  log-format \"%{{+Q}}r %ST %[var(txn.x)] %[var(req.r)] %[var(res.s)] %hr %hs %[prio_class] %[cur_server_timeout] %B\"\n",
        collector.local_addr().expect("addr")
    );
    let (mut engine, fe, running, be) = keepalive_engine(
        "  capture request header X-Cap len 10\n  capture response header X-R len 10\n  http-request capture req.hdr(x-c2) len 10\n\
           http-request set-var(txn.x) str(one) if { path /one }\n  http-request set-var(req.r) str(r1) if { path /one }\n\
           http-request set-priority-class int(5) if { path /one }\n  http-response set-var(res.s) str(s1) if { var(txn.x) -m found }\n",
        "  http-request set-timeout server 1s if { path /one }\n",
        &defaults,
    );
    let mut client = TcpStream::connect(fe).expect("connect");
    client.set_nonblocking(true).expect("nonblocking");
    keepalive_request(&mut engine, &mut client, b"GET /one HTTP/1.1\r\nHost: h\r\nX-Cap: c1\r\nX-C2: d1\r\n\r\n");
    keepalive_request(&mut engine, &mut client, b"GET /two HTTP/1.1\r\nHost: h\r\n\r\n");
    let mut lines = Vec::new();
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(2);
    while lines.len() < 2 && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            lines.push(l.split_once("]: ").map_or(l.clone(), |(_, b)| b.trim_end().to_string()));
        }
    }
    assert_eq!(
        lines,
        ["\"GET /one HTTP/1.1\" 200 one - s1 {c1|d1} {r1} 5 1000 56", "\"GET /two HTTP/1.1\" 200 - - - {|} {} 0 5000 51"]
    );
    running.store(false, Ordering::Relaxed);
    drop(client);
    let _ = be.join();
}

/// The stream is at most 1 KiB (O1a; plan §4.3): what grows it past that is boxed, or belongs
/// to the connection.
#[test]
fn stream_is_at_most_1_kib() {
    let n = std::mem::size_of::<ibex_rt::stream::Stream>();
    println!("Stream: {n} bytes");
    assert!(n <= 1024, "Stream grew to {n} bytes (bound 1024)");
}

/// R4: `set-var(txn.p) path` keeps the path as bytes in the variable's slot: no spare string
/// is taken for the sample (on ibex-rc5 and until R4 the sample was made a text `String`, the
/// slot copied it and gave it back).
#[test]
fn set_var_takes_no_spare() {
    const REQ: &[u8] = b"GET /api/x HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const N: u64 = 20;
    let (mut engine, fe, running, be) = keepalive_engine("  http-request set-var(txn.p) path\n", "", "");
    let mut client = TcpStream::connect(fe).expect("connect");
    client.set_nonblocking(true).expect("nonblocking");
    client.set_nodelay(true).expect("nodelay");
    for _ in 0..4 {
        keepalive_request(&mut engine, &mut client, REQ);
    }
    let t0 = ibex_sample::spare::strings_taken_on_this_thread();
    for _ in 0..N {
        keepalive_request(&mut engine, &mut client, REQ);
    }
    let takes = ibex_sample::spare::strings_taken_on_this_thread() - t0;
    println!("{N} keep-alive requests with set-var(txn.p) path: {takes} spare strings taken");
    assert_eq!(takes, 0, "set-var of a path takes a spare string");
    running.store(false, Ordering::Relaxed);
    drop(client);
    let _ = be.join();
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("len").to_be_bytes();
    let mut f = vec![len[1], len[2], len[3], kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Whether `rx` holds a frame with `END_STREAM` on stream `id` (HEADERS or DATA).
fn h2_ended(rx: &[u8], id: u32) -> bool {
    let mut at = 0;
    while rx.len() >= at + 9 {
        let len = (usize::from(rx[at]) << 16) | (usize::from(rx[at + 1]) << 8) | usize::from(rx[at + 2]);
        let (kind, flags) = (rx[at + 3], rx[at + 4]);
        let sid = u32::from_be_bytes([rx[at + 5], rx[at + 6], rx[at + 7], rx[at + 8]]) & 0x7fff_ffff;
        if sid == id && (kind == 0 || kind == 1) && flags & 1 != 0 {
            return true;
        }
        at += 9 + len;
    }
    false
}

/// One GET on stream `id` of the h2c connection `client`, the engine run until its end.
fn h2_get(engine: &mut Engine, client: &mut TcpStream, rx: &mut Vec<u8>, id: u32) {
    let mut block = vec![0x82, 0x86, 0x84, 0x01, 9];
    block.extend_from_slice(b"localhost");
    h2_send(engine, client, rx, id, &block);
}

/// `:path` `path`, `:authority` `h`, and `extra` (literal fields), as an HPACK block.
fn h2_block(path: &[u8], extra: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short")];
    b.extend_from_slice(path);
    b.extend_from_slice(&[0x01, 1, b'h']);
    for (n, v) in extra {
        b.push(0);
        b.push(u8::try_from(n.len()).expect("short"));
        b.extend_from_slice(n);
        b.push(u8::try_from(v.len()).expect("short"));
        b.extend_from_slice(v);
    }
    b
}

/// HEADERS `block` with `END_STREAM` on stream `id`, the engine run until the response ends.
fn h2_send(engine: &mut Engine, client: &mut TcpStream, rx: &mut Vec<u8>, id: u32, block: &[u8]) {
    client.write_all(&h2_frame(0x1, 0x5, id, block)).expect("HEADERS");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 4096];
    while !h2_ended(rx, id) {
        assert!(Instant::now() < deadline, "no response on stream {id}");
        let _ = engine.run_once();
        match client.read(&mut buf) {
            Ok(0) => panic!("the proxy closed the connection"),
            Ok(n) => rx.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
}

/// O1b: an HTTP/2 stream is a `Stream` its connection holds, not a session of its own: a
/// request on a connection that served one before builds no `TcpSession` (on 2c69433e, one
/// per stream: `h2_child_of` -> `new_with_mode`, 2.0k ins a request).
#[test]
fn an_h2_stream_is_not_a_session() {
    const N: u64 = 20;
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv.local_addr().expect("addr");
    let running = Arc::new(AtomicBool::new(true));
    let be = keepalive_backend(srv, Arc::clone(&running));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe} proto h2\n  http-request set-var(txn.x) str(a)\n  default_backend be\n\
         backend be\n  server s {srv_addr}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut client = TcpStream::connect(fe).expect("connect");
    client.set_nonblocking(true).expect("nonblocking");
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(h2_frame(0x4, 0, 0, &[]));
    client.write_all(&hello).expect("preface");
    let mut rx = Vec::new();
    let mut id = 1;
    for _ in 0..4 {
        h2_get(&mut engine, &mut client, &mut rx, id);
        id += 2;
    }
    let s0 = ibex_rt::probe::session_news();
    for _ in 0..N {
        h2_get(&mut engine, &mut client, &mut rx, id);
        id += 2;
    }
    let made = ibex_rt::probe::session_news() - s0;
    println!("{N} h2 requests on one connection: {made} TcpSession constructions");
    assert_eq!(made, 0, "an h2 stream is reset in place, not built as a session");
    running.store(false, Ordering::Relaxed);
    drop(client);
    let _ = be.join();
}

/// What the first stream of an HTTP/2 connection set (a `txn.` variable, header captures of
/// both kinds, the priority class, a stream timeout) is gone for the second, served by the
/// same session reset in place (O1b): each line as `HAProxy` 3.5-dev8-885761-29 logged it
/// for the same two streams on one h2c connection, measured 2026-11-02:
/// `"GET http://h/one HTTP/2.0" 200 one - s1 {c1|d1} {r1} 5 1000 56` and
/// `"GET http://h/two HTTP/2.0" 200 - - - {|} {} 0 5000 51`.
#[test]
fn a_field_set_in_stream_one_is_absent_in_stream_two() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv.local_addr().expect("addr");
    let running = Arc::new(AtomicBool::new(true));
    let be = keepalive_backend(srv, Arc::clone(&running));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n  log {} local0\n\
           log-format \"%{{+Q}}r %ST %[var(txn.x)] %[var(req.r)] %[var(res.s)] %hr %hs %[prio_class] %[cur_server_timeout] %B\"\n\
         frontend fe\n  bind {fe} proto h2\n  capture request header X-Cap len 10\n  capture response header X-R len 10\n\
           http-request capture req.hdr(x-c2) len 10\n  http-request set-var(txn.x) str(one) if {{ path /one }}\n\
           http-request set-var(req.r) str(r1) if {{ path /one }}\n  http-request set-priority-class int(5) if {{ path /one }}\n\
           http-response set-var(res.s) str(s1) if {{ var(txn.x) -m found }}\n  default_backend be\n\
         backend be\n  http-request set-timeout server 1s if {{ path /one }}\n  server s {srv_addr}\n",
        collector.local_addr().expect("addr")
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut client = TcpStream::connect(fe).expect("connect");
    client.set_nonblocking(true).expect("nonblocking");
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(h2_frame(0x4, 0, 0, &[]));
    client.write_all(&hello).expect("preface");
    let mut rx = Vec::new();
    let s0 = ibex_rt::probe::session_news();
    h2_send(&mut engine, &mut client, &mut rx, 1, &h2_block(b"/one", &[(b"x-cap", b"c1"), (b"x-c2", b"d1")]));
    h2_send(&mut engine, &mut client, &mut rx, 3, &h2_block(b"/two", &[]));
    assert_eq!(ibex_rt::probe::session_news() - s0, 2, "the connection's session and its first stream's, which serves the second");
    let mut lines = Vec::new();
    let mut buf = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(2);
    while lines.len() < 2 && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(n) = collector.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            lines.push(l.split_once("]: ").map_or(l.clone(), |(_, b)| b.trim_end().to_string()));
        }
    }
    assert_eq!(
        lines,
        [
            "\"GET http://h/one HTTP/2.0\" 200 one - s1 {c1|d1} {r1} 5 1000 56",
            "\"GET http://h/two HTTP/2.0\" 200 - - - {|} {} 0 5000 51"
        ]
    );
    running.store(false, Ordering::Relaxed);
    drop(client);
    let _ = be.join();
}
