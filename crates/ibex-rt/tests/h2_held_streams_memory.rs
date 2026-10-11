// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T312): counts the test process's allocations (#[global_allocator])

//! A held HTTP/2 stream (HEADERS of a POST, body never sent) costs a few KB (T312, MY-7).
//!
//! The red team measured ~33 KB of RSS per such stream on Ibex against ~10 KB on `HAProxy`
//! (3.5-dev8; ~5-6 KB with small headers, `show pools`: 26 16-KB buffers for 2000 held
//! streams). Two pooled buffers per stream were the cause: the HTX buffer kept for the
//! stream's life, and the request buffer holding the head until a server connection takes
//! it. Here the engine runs in-process under the counting allocator: `CONNS` h2c
//! connections each hold 100 streams, and the heap still live afterwards divided by the
//! streams is the cost. Two shapes: every stream connected to a server that never answers,
//! and every stream queued behind a server that takes one connection (`maxconn 1`).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

static TEST_MUTEX: Mutex<()> = Mutex::new(());

const CONNS: usize = 5;
const PER_CONN: u32 = 100;
const STREAMS: usize = CONNS * PER_CONN as usize;
/// `HAProxy` holds ~5-6 KB for such a stream; twice that is headroom.
const BUDGET: usize = 10 * 1024;

/// A backend that accepts connections, reads what comes and never answers.
fn silent_backend(accepted: Arc<AtomicUsize>, running: Arc<AtomicBool>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    l.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = l.accept() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            let running = Arc::clone(&running);
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
                let mut buf = [0u8; 4096];
                while running.load(Ordering::Relaxed) {
                    if matches!(s.read(&mut buf), Ok(0)) {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("len");
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// HEADERS (END_HEADERS only): POST http://localhost/ announcing a 10-byte body.
fn post_head(stream: u32) -> Vec<u8> {
    let mut block = vec![0x83, 0x86, 0x84, 0x01, 9];
    block.extend_from_slice(b"localhost");
    block.extend_from_slice(&[0x0f, 0x0d, 2, b'1', b'0']);
    frame(0x1, 0x4, stream, &block)
}

fn pass(engine: &mut Engine, socks: &mut [TcpStream]) {
    let _ = engine.run_once();
    let mut buf = [0u8; 4096];
    for s in socks.iter_mut() {
        let _ = s.read(&mut buf);
    }
}

/// Heap bytes live per held stream, with `server_opts` on the only server.
fn per_held_stream(server_opts: &str, want_connected: usize) -> usize {
    let accepted = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(AtomicBool::new(true));
    let srv = silent_backend(Arc::clone(&accepted), Arc::clone(&running));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 20s\n  timeout client 60s\n  timeout server 60s\n  timeout queue 60s\n\
         frontend fe\n  bind {fe} proto h2\n  default_backend be\n\
         backend be\n  server s1 {srv} {server_opts}\n"
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 4096).expect("Engine::new");
    let mut socks = Vec::new();
    for _ in 0..CONNS {
        let mut sock = TcpStream::connect(fe).expect("connect");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        hello.extend(frame(0x4, 0, 0, &[]));
        sock.write_all(&hello).expect("preface");
        socks.push(sock);
    }
    for _ in 0..50 {
        pass(&mut engine, &mut socks);
    }
    let before = ibex_alloc::alloc_counters().bytes_live();
    for sock in &mut socks {
        let mut batch = Vec::new();
        for i in 0..PER_CONN {
            batch.extend(post_head(1 + 2 * i));
        }
        sock.write_all(&batch).expect("heads");
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while accepted.load(Ordering::Relaxed) < want_connected {
        assert!(Instant::now() < deadline, "{} of {want_connected} server connections", accepted.load(Ordering::Relaxed));
        pass(&mut engine, &mut socks);
    }
    // Settled: the rest of the heads parsed, and the engine has nothing more to do.
    let mut idle = 0;
    for _ in 0..2000 {
        idle = if engine.run_once().unwrap_or(1) == 0 { idle + 1 } else { 0 };
        if idle == 3 {
            break;
        }
        let mut buf = [0u8; 4096];
        for s in &mut socks {
            let _ = s.read(&mut buf);
        }
    }
    let after = ibex_alloc::alloc_counters().bytes_live();
    let per = after.saturating_sub(before) / STREAMS;
    println!("{STREAMS} held streams ({server_opts:?}, {} server connections): {per} B each", accepted.load(Ordering::Relaxed));
    running.store(false, Ordering::Relaxed);
    drop(socks);
    for _ in 0..20 {
        let _ = engine.run_once();
    }
    per
}

/// Every held stream has its server connection (the head went out, nothing came back).
#[test]
fn a_held_h2_stream_connected_to_a_server_costs_a_few_kb() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let per = per_held_stream("", STREAMS);
    assert!(per < BUDGET, "{per} B of heap per held h2 stream, budget {BUDGET}");
}

/// The server takes one connection at a time: the other streams wait in the queue.
#[test]
fn a_held_h2_stream_waiting_for_a_server_costs_a_few_kb() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let per = per_held_stream("maxconn 1", 1);
    assert!(per < BUDGET, "{per} B of heap per held h2 stream, budget {BUDGET}");
}
