// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! O2: the backend side finds a server and its idle connections by index. A request that
//! takes an idle server connection reads no `RwLock` and hashes no `(backend, server)`
//! (`work::Op::IdleLock`, `work::Op::IdleHash`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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
