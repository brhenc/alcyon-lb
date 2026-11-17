// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T637): its #[global_allocator] refuses the growth of the task arena on demand.

//! A connection whose session can be had but whose task cannot is closed, and the server slot
//! it was picked with goes back: the next connection to a `maxconn 1` server is served.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use alcyon_alloc::{refusals_left, refuse_allocs_here, refuse_allocs_of, CountingAllocator};
use alcyon_rt::engine::Engine;
use alcyon_sched::{Kind, Task, WorkKind, TASK_POOL};

/// Refuses the task arena's growth on demand ([`refuse_allocs_here`]).
#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

/// A server that sends `hi` to each connection and closes it.
fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let _ = s.write_all(b"hi");
        }
    });
    addr
}

/// Connects, runs the engine until the connection is closed (within 3 s); what came back.
fn fetch(engine: &mut Engine, addr: SocketAddr) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(3), "not closed; got {:?}", String::from_utf8_lossy(&got));
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

/// The task arena is full, so the first connection's task cannot be had (the session's slot
/// can): the connection is closed with nothing, the server's slot it was picked with is given
/// back (`maxconn 1`: otherwise the next connection would wait in the queue for ever), and the
/// next one is answered.
#[test]
fn a_connection_whose_task_cannot_be_had_gives_back_the_server_slot_it_was_picked_with() {
    let srv = backend();
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode tcp\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n  timeout queue 1s\n\
         listen l\n  bind {addr}\n  server s1 {srv} maxconn 1\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut n = 0;
    while engine.scheduler.tasks.live() < engine.scheduler.tasks.capacity() {
        engine.scheduler.create(WorkKind::new(Kind::Synthetic, n)).expect("task");
        n += 1;
    }
    let failures = TASK_POOL.failures();
    // The arena grows from its capacity to twice that: the refused allocation.
    refuse_allocs_here(2 * engine.scheduler.tasks.capacity() * std::mem::size_of::<Task>(), 0, 1);
    let first = fetch(&mut engine, addr);
    let refused = refusals_left() == 0;
    refuse_allocs_of(0, 0, 0);
    assert!(refused, "the task arena was asked to grow");
    assert_eq!(TASK_POOL.failures(), failures + 1, "the refusal is counted");
    assert_eq!(first, "", "the connection whose task could not be had is closed");
    let second = fetch(&mut engine, addr);
    assert_eq!(second, "hi", "the server's slot was given back");
}
