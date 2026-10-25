// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary: its #[global_allocator] refuses an allocation of a given size on demand, and the
// test needs the process's buffer pool untouched by other tests (`tune.buffers.limit` counts
// every buffer the process made); `buffer_alloc_failure.rs` leaves it in another state.

//! The buffer wait queue that cannot grow (S6, `buf_wait::enter`): the stream fails as in S5.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::{refusals_left, refuse_allocs_here, refuse_allocs_of, CountingAllocator};
use ibex_rt::engine::Engine;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

const BUFSIZE: usize = 16384;
const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

fn engine_with(global: &str, lines: &str) -> (Engine, SocketAddr) {
    let addr = common::reserve_addr();
    let cfg = format!("{global}{DEFAULTS}frontend f\n  bind {addr}\n{lines}");
    let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    ibex_alloc::drain_local_pools();
    (engine, addr)
}

/// Sends `req` on a new connection and runs the engine until the connection is closed (it must
/// be, within 2 s); what came back.
fn send(engine: &mut Engine, addr: SocketAddr, req: &[u8]) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let mut sent = 0;
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(2), "not closed; got {:?}", String::from_utf8_lossy(&got));
        if sent < req.len() {
            match c.write(&req[sent..]) {
                Ok(n) => sent += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => sent = req.len(),
            }
        }
        let _ = engine.run_once();
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// A stream past `tune.buffers.limit` waits in a queue; when the queue cannot grow to take it
/// (S6, `buf_wait::enter`), that stream fails as in S5 (closed), and the next stream is served
/// once the holders are gone. The client queue is filled to its capacity (2048 waiters of 8
/// bytes) with waiters whose sessions do not exist, so that its next growth, to 32768 bytes, is
/// an allocation nothing else makes and can be refused alone; the engine drops those waiters
/// when buffers come back (a woken waiter whose session is gone).
#[test]
fn a_stream_whose_wait_queue_cannot_grow_fails_as_without_a_buffer() {
    use ibex_rt::buf_wait::{enter, Class};
    let (mut engine, addr) = engine_with("global\n  tune.buffers.limit 3\n", "  http-request return status 200 content-type text/plain string ok\n");
    // Three connections each holding a buffer for a partial head: the limit.
    let mut held: Vec<TcpStream> = (0..3)
        .map(|_| {
            let mut c = TcpStream::connect(addr).expect("connect");
            c.write_all(b"GET /held HTTP/1.1\r\nHost: x\r\n").expect("partial head");
            c
        })
        .collect();
    for _ in 0..8 {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(2));
    }
    let waiter = std::mem::size_of::<(ibex_sched::TaskRef, u32)>();
    for i in 0..2048 {
        assert!(enter(ibex_sched::TaskRef(4_000_000 + i), u32::MAX - 1, Class::MuxRx, false));
    }
    refuse_allocs_here(4096 * waiter, 0, 1);
    let mut c4 = TcpStream::connect(addr).expect("connect");
    c4.write_all(GET).expect("write");
    c4.set_nonblocking(true).expect("nonblocking");
    let start = Instant::now();
    while refusals_left() != 0 && start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once();
    }
    assert_eq!(refusals_left(), 0, "the queue's growth was asked for and refused");
    refuse_allocs_of(BUFSIZE, 0, 0);
    // That stream failed (S5) and its error answer waits for a buffer like any: it comes when
    // the holders are gone, and is a 500, not the 200 the stream would have had.
    held.clear();
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(8), "not closed: {:?}", String::from_utf8_lossy(&got));
        let _ = engine.run_once();
        match c4.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
    }
    let got = String::from_utf8_lossy(&got);
    assert!(got.starts_with("HTTP/1.1 500") || got.is_empty(), "the stream that could not wait: {got:?}");
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200") && after.ends_with("ok"), "after: {after:?}");
}
