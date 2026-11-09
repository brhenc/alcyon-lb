// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T468): counts the test process's buffer-sized allocations (#[global_allocator])

//! T468: with `tune.memory.prealloc on`, a burst of connections that each hold their buffers
//! takes every standard buffer from what the start made: none of the burst's 16 KiB buffers
//! comes from the allocator. Without it the same burst allocates its buffers as it goes (grow
//! and keep, design Q1), which the first half shows, so the second half measures something.
//! A new connection still allocates outside the pools (sockets, the h1 state, the log line):
//! "no allocation" here is no buffer allocation.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use alcyon_alloc::CountingAllocator;
use alcyon_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

const BUFSIZE: usize = 16384;

/// Answers every connection with a body larger than the buffers on the way, written until the
/// socket is full: a client that does not read holds its stream's buffers.
fn flood() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        while let Ok((mut c, _)) = l.accept() {
            thread::spawn(move || {
                let mut req = [0u8; 4096];
                let _ = c.read(&mut req);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n");
                let chunk = [b'x'; 16384];
                while c.write_all(&chunk).is_ok() {}
            });
        }
    });
    addr
}

const MAXCONN: usize = 200;
const BURST: usize = 150;

/// Bytes the engine's thread allocates while `BURST` clients each hold a response they do not
/// read; on a thread of its own, so that its pool caches start empty.
fn burst(prealloc: &'static str) -> usize {
    thread::spawn(move || burst_here(prealloc)).join().expect("burst thread")
}

fn burst_here(prealloc: &str) -> usize {
    let be = flood();
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n    maxconn {MAXCONN}\n    tune.memory.prealloc {prealloc}\ndefaults\n    mode http\n    timeout client 30s\n    timeout server 30s\n    timeout connect 5s\n\
         frontend f\n    bind {fe}\n    default_backend b\nbackend b\n    server s {be}\n"
    );
    let config = alcyon_config::parse_str(&cfg).expect("config");
    let mut engine = Engine::new(&config, MAXCONN).expect("Engine::new");
    for _ in 0..10 {
        let _ = engine.run_once();
    }
    let before = alcyon_alloc::thread_alloc_counters().bytes_allocated;
    let mut clients = Vec::new();
    for _ in 0..BURST {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        clients.push(c);
        let _ = engine.run_once();
    }
    let end = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < end {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let n = alcyon_alloc::thread_alloc_counters().bytes_allocated - before;
    drop(clients);
    drop(engine);
    n
}

#[test]
fn a_burst_takes_no_buffer_from_the_allocator_with_prealloc() {
    let grown = burst("off");
    let presized = burst("on");
    println!("[T468] bytes allocated by the engine thread for {BURST} held connections: prealloc off {grown}, on {presized}");
    assert!(grown >= BURST * BUFSIZE, "without prealloc the burst allocated {grown} bytes: it does not load the pool");
    // Every buffer the burst took without prealloc is missing with it; what is left is the
    // connections' other allocations, the same in both runs.
    assert!(presized + BURST * BUFSIZE <= grown, "with prealloc the burst allocated {presized} bytes, without {grown}");
}
