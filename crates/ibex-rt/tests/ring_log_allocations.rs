// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A log line written to a `ring` allocates no more than one written to a UDP collector: the
//! header is built in a per-thread buffer and the event is copied into storage reserved when
//! the ring was made. Measured the way `capture_rule_allocations.rs` measures a request: one
//! warm-up, then the allocations of the second.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

fn drive(fe: SocketAddr, e: &mut Engine) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    c.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write");
    let st = Instant::now();
    let mut r = Vec::new();
    let mut b = [0u8; 512];
    while st.elapsed() < Duration::from_secs(2) {
        let _ = e.run_once();
        if let Ok(n) = c.read(&mut b) {
            if n > 0 {
                r.extend_from_slice(&b[..n]);
                if r.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    for _ in 0..5 {
        let _ = e.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let text = String::from_utf8_lossy(&r);
    assert!(text.starts_with("HTTP/1.1 200"), "the request must succeed to be measured, got {text:?}");
}

/// The allocations of one request through a frontend configured with `extra` (a ring section
/// and `log` lines).
fn allocations_of_one_request(log: &str, ring: &str) -> usize {
    let sl = TcpListener::bind("127.0.0.1:0").expect("bind");
    let sa = sl.local_addr().expect("addr");
    let fl = TcpListener::bind("127.0.0.1:0").expect("bind");
    let fa = fl.local_addr().expect("addr");
    drop(fl);
    let run = Arc::new(AtomicBool::new(true));
    let run2 = Arc::clone(&run);
    sl.set_nonblocking(true).expect("nonblocking");
    let be = thread::spawn(move || {
        while run2.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = sl.accept() {
                s.set_nonblocking(false).ok();
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
            thread::sleep(Duration::from_millis(1));
        }
    });
    let cfg = ibex_config::parse_str(&format!(
        "{ring}frontend fe\n  mode http\n  option httplog\n  bind {fa}\n  timeout client 5s\n{log}  default_backend be\n\
         backend be\n  mode http\n  timeout connect 5s\n  timeout server 5s\n  server s1 {sa}\n"
    ))
    .expect("parses");
    ibex_rt::logfwd::start(&cfg).expect("starts");
    let mut e = Engine::new(&cfg, 64).expect("Engine::new");
    drive(fa, &mut e);
    let before = ibex_alloc::alloc_counters();
    drive(fa, &mut e);
    let n = before.diff(&ibex_alloc::alloc_counters()).alloc_count;
    run.store(false, Ordering::Relaxed);
    let _ = be.join();
    n
}

#[test]
fn a_log_line_to_a_ring_allocates_no_more_than_one_to_a_collector() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let target = collector.local_addr().expect("addr");
    let none = allocations_of_one_request("", "");
    let udp = allocations_of_one_request(&format!("  log {target} local0\n"), "");
    let ring = allocations_of_one_request("  log ring@alloc_ring local0\n", "ring alloc_ring\n  size 65536\n");
    println!("allocations per request: no log {none}, udp {udp}, ring {ring}");
    assert!(
        ring <= udp,
        "a request logged to a ring allocated {ring} times, against {udp} logged to a UDP \
         collector and {none} with no log at all"
    );
}
