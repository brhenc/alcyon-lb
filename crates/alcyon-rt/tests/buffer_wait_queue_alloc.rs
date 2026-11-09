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

use alcyon_alloc::{refusals_left, refuse_allocs_here, refuse_allocs_of, CountingAllocator};
use alcyon_rt::engine::Engine;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

const BUFSIZE: usize = 16384;
const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

fn engine_with(global: &str, lines: &str) -> (Engine, SocketAddr) {
    engine_sized(global, lines, 64)
}

/// [`engine_with`] presized for `capacity` sessions (and so many buffer wait queue slots).
fn engine_sized(global: &str, lines: &str, capacity: usize) -> (Engine, SocketAddr) {
    let addr = common::reserve_addr();
    let cfg = format!("{global}{DEFAULTS}frontend f\n  bind {addr}\n{lines}");
    let engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), capacity).expect("Engine::new");
    alcyon_alloc::drain_local_pools();
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
/// (S6, `buf_wait::enter`), that stream fails as in S5, and the next stream is served once the
/// holders are gone. Since S6b the queues are lists through arrays indexed by session slot,
/// reserved for the engine's sessions at start: only a slot past them makes them grow. The
/// engine is presized for three sessions: the holders take slots 0-2 and the stream slot 3,
/// whose entry grows the first array from 3 to 4 `u32`s (16 bytes), refused. The stream's
/// failure answer (500) itself waits for a buffer as any local reply (S6b) and comes once the
/// holders are gone: it used to wait for `timeout client`, nothing waking it (T473).
#[test]
fn a_stream_whose_wait_queue_cannot_grow_fails_as_without_a_buffer() {
    let (mut engine, addr) = engine_sized("global\n  tune.buffers.limit 3\n  tune.buffers.reserve 0\n", "  http-request return status 200 content-type text/plain string ok\n", 3);
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
    refuse_allocs_here(4 * std::mem::size_of::<u32>(), 0, 1);
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
    assert!(got.starts_with("HTTP/1.1 500"), "the stream that could not wait: {got:?}");
    assert!(start.elapsed() < Duration::from_secs(2), "the 500 waited {:?} (timeout client 5s)", start.elapsed());
    let after = send(&mut engine, addr, GET);
    assert!(after.starts_with("HTTP/1.1 200") && after.ends_with("ok"), "after: {after:?}");
}
