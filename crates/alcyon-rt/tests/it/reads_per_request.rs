// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Read syscalls per keep-alive request, counted in-process (`raw::read_counters`).
//!
//! `HAProxy` reads a socket only when the poller says it is readable: a read shorter than
//! the buffer means the socket is drained, and so does `EAGAIN`, and either way the fd is
//! not read again until epoll reports it (`fd_cant_recv`, `src/raw_sock.c`). Measured
//! 2026-10-02 with `strace -c`, one keep-alive connection: `HAProxy` 3.5 made 2.00
//! receives per request (one each side) and Alcyon 10.99, 9 of them `EAGAIN`
//! (`performance.md`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use alcyon_rt::engine::Engine;
use alcyon_rt::raw::read_counters;

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A keep-alive backend: answers every request head on a connection.
fn backend(listener: TcpListener, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            s.set_nonblocking(false).expect("blocking");
            s.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
            let mut pending = Vec::new();
            let mut buf = [0u8; 4096];
            while running.load(Ordering::Relaxed) {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                    Err(_) => continue,
                }
                while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                    pending.drain(..end + 4);
                    if s.write_all(RESPONSE).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Sends one request on `client` and steps the engine until its response is back.
fn one_request(engine: &mut Engine, client: &mut TcpStream) {
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write request");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    while got.len() < RESPONSE.len() {
        assert!(Instant::now() < deadline, "no response: {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        if let Ok(n) = client.read(&mut buf) {
            assert!(n > 0, "the proxy closed the connection");
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert!(got.starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&got));
}

#[test]
fn a_keep_alive_request_reads_each_socket_once() {
    let srv_listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let srv_addr: SocketAddr = srv_listener.local_addr().expect("addr");
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

    let mut client = TcpStream::connect(fe_addr).expect("connect");
    client.set_nonblocking(true).expect("nonblocking");
    // The first request connects to the server; the ones after reuse both connections.
    for _ in 0..5 {
        one_request(&mut engine, &mut client);
    }

    const N: u64 = 200;
    let (reads0, blocked0) = read_counters();
    for _ in 0..N {
        one_request(&mut engine, &mut client);
    }
    let (reads1, blocked1) = read_counters();
    let (reads, blocked) = (reads1 - reads0, blocked1 - blocked0);
    println!("{N} requests: {reads} reads, {blocked} EAGAIN");

    // One read of the request, one of the response. A little slack for the rare
    // readiness event that arrives with nothing left to read.
    assert!(
        blocked * 10 <= N && reads * 10 <= N * 22,
        "{reads} reads ({blocked} EAGAIN) for {N} requests: a socket is read when the \
         poller has not said it is readable"
    );

    drop(client);
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
}
