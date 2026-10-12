// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): counts the test process's allocations (#[global_allocator]) and RSS
//! Heap held per idle client connection (T183).
//!
//! HAProxy holds no buffer for an idle connection: its muxes release `ibuf`/`obuf` once
//! they are empty and allocate them again when the socket has something
//! (`h1_release_buf`, `b_alloc`), and the server connection goes back to the server's lists
//! with the response (T187). Measured by T180: 1 062 B of RSS per idle keep-alive client
//! (10k clients, `nbthread 1`), against 26 989 B for Ibex.
//!
//! Here the engine runs in-process under the counting allocator: `N` clients connect (and
//! send one request, or nothing), stay idle, and the heap still allocated afterwards is
//! divided by `N`. A first batch fills the buffer caches so the measured batch sees only
//! what each connection keeps.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use ibex_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// A keep-alive backend answering `ok` to every request.
fn backend(running: Arc<AtomicBool>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    l.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = l.accept() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            s.set_nonblocking(false).expect("blocking");
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    while let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        got.drain(..end + 4);
                        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

fn engine(srv: SocketAddr, fe: SocketAddr) -> Engine {
    let config = Config {
        frontends: vec![FrontendSection {
            name: "fe".into(),
            bind: Some(fe),
            mode: Mode::Http,
            default_backend: Some("be".into()),
            clitimeout: Some(Duration::from_secs(30)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(30)),
            servers: vec![Server::new("s1", srv)],
            ..Default::default()
        }],
        ..Default::default()
    };
    Engine::new(&config, 1024).expect("Engine::new")
}

/// `n` clients, each sending one request (`request`) or nothing, all left open.
fn open_idle(engine: &mut Engine, fe: SocketAddr, n: usize, request: bool, keep: &mut Vec<TcpStream>) {
    for _ in 0..n {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_nonblocking(true).expect("nonblocking");
        let _ = engine.run_once();
        if request {
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
            let start = Instant::now();
            let mut got = Vec::new();
            let mut buf = [0u8; 512];
            while !got.ends_with(b"ok") {
                assert!(start.elapsed() < Duration::from_secs(5), "no answer: {:?}", String::from_utf8_lossy(&got));
                let _ = engine.run_once();
                if let Ok(k) = c.read(&mut buf) {
                    got.extend_from_slice(&buf[..k]);
                }
            }
        }
        keep.push(c);
    }
    // Settled: two passes in a row that ran no task, each having waited out the poller's
    // timeout with nothing to do. Fifty passes of that wait were 5 s per batch (T259).
    let mut idle = 0;
    for _ in 0..50 {
        idle = if engine.run_once().unwrap_or(1) == 0 { idle + 1 } else { 0 };
        if idle == 2 {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// Heap bytes each of 200 idle clients leaves allocated.
fn per_idle_conn(request: bool) -> usize {
    let running = Arc::new(AtomicBool::new(true));
    let srv = backend(Arc::clone(&running));
    let fe = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let mut engine = engine(srv, fe);
    let mut keep = Vec::new();
    open_idle(&mut engine, fe, 100, request, &mut keep);
    let before = ibex_alloc::alloc_counters();
    open_idle(&mut engine, fe, 200, request, &mut keep);
    let after = ibex_alloc::alloc_counters();
    running.store(false, Ordering::Relaxed);
    let per = usize::try_from(before.diff(&after).net_bytes().max(0)).unwrap_or(0) / 200;
    drop(keep);
    for _ in 0..20 {
        let _ = engine.run_once();
    }
    per
}

/// A backend answering every request with a body it never finishes (1 GB announced),
/// written for as long as the connection takes it.
fn endless_backend(running: Arc<AtomicBool>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    l.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            let Ok((mut s, _)) = l.accept() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            s.set_nonblocking(false).expect("blocking");
            thread::spawn(move || {
                let chunk = vec![b'x'; 65536];
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1073741824\r\n\r\n").is_err() {
                    return;
                }
                while s.write_all(&chunk).is_ok() {}
            });
        }
    });
    addr
}

/// A client whose receive buffer is 4 KB, as `m1_active_conn_rss.py`'s.
fn slow_client(fe: SocketAddr) -> TcpStream {
    use rustix::net::{AddressFamily, SocketType};
    let fd = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None).expect("socket");
    rustix::net::sockopt::set_socket_recv_buffer_size(&fd, 4096).expect("SO_RCVBUF");
    let SocketAddr::V4(v4) = fe else { panic!("v4") };
    rustix::net::connect_v4(&fd, &v4).expect("connect");
    TcpStream::from(fd)
}

/// T184: clients that ask for a large answer and never read it. HAProxy holds about one
/// buffer per direction that has data in transit and none for one that is empty (4.5 KB
/// of RSS per such client with a 1 MB answer, T180). Here, once every answer is stuck
/// behind its client: the request, forwarded long ago, holds no buffer; the response
/// holds one (full), the request's HTX one (kept for the transaction's rules and log):
/// two per client, where each held three.
#[test]
fn a_slow_client_holds_no_buffer_for_a_forwarded_request() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    const N: usize = 10;
    let running = Arc::new(AtomicBool::new(true));
    let srv = endless_backend(Arc::clone(&running));
    let fe = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let mut engine = engine(srv, fe);
    let used = || ibex_rt::buf::buffer_pool_stats().map_or(0, |p| p.used);
    for _ in 0..10 {
        let _ = engine.run_once();
    }
    let base = used();
    let mut clients = Vec::new();
    for _ in 0..N {
        let mut c = slow_client(fe);
        c.write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        clients.push(c);
        let _ = engine.run_once();
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        let _ = engine.run_once();
    }
    let held = used().saturating_sub(base);
    println!("standard buffers in use for {N} slow clients: {held}");
    assert!(held <= 2 * N, "{N} slow clients hold {held} buffers");
    running.store(false, Ordering::Relaxed);
    drop(clients);
    for _ in 0..20 {
        let _ = engine.run_once();
    }
}

/// T318: a burst of slow clients makes the heap hold hundreds of buffers at once; they go
/// back to the pool or the allocator, but the allocator keeps the pages. Once the engine has
/// been quiet for a while it must give them back (`buf::trim_idle`, `malloc_trim`), as
/// HAProxy's pool garbage collector does; otherwise RSS stays at the burst's peak.
#[test]
fn the_engine_gives_the_heap_back_after_a_burst_of_slow_clients() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    const N: usize = 200;
    let running = Arc::new(AtomicBool::new(true));
    let srv = endless_backend(Arc::clone(&running));
    let fe = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
    let mut engine = engine(srv, fe);
    let before = ibex_rt::buf::heap_trims();
    let mut clients = Vec::new();
    for _ in 0..N {
        let mut c = slow_client(fe);
        c.write_all(b"GET /big HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        clients.push(c);
        let _ = engine.run_once();
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once();
    }
    let trims = ibex_rt::buf::heap_trims() - before;
    println!("heap trims after a burst of {N} slow clients: {trims}");
    assert!(trims >= 1, "the heap was never given back");
    running.store(false, Ordering::Relaxed);
    drop(clients);
    for _ in 0..20 {
        let _ = engine.run_once();
    }
}

/// `trim_idle` itself: buffers allocated and freed in a burst leave their pages resident
/// until the idle hook runs.
#[test]
fn trim_idle_returns_the_pages_of_freed_buffers() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let rss = || -> usize {
        let s = std::fs::read_to_string("/proc/self/statm").expect("statm");
        s.split_whitespace().nth(1).and_then(|v| v.parse::<usize>().ok()).expect("rss") * 4096
    };
    // a live neighbour per buffer keeps the freed chunks from being the top of the heap
    let mut keep = Vec::new();
    let mut bufs = Vec::new();
    let base = rss();
    for _ in 0..1500 {
        let mut b = ibex_rt::buf::Buf::standard();
        b.writable().fill(1);
        bufs.push(b);
        keep.push(vec![1u8; 64]);
    }
    let peak = rss();
    drop(bufs);
    let t0 = Instant::now();
    ibex_rt::buf::trim_idle(t0);
    ibex_rt::buf::trim_idle(t0 + Duration::from_secs(2));
    let after = rss();
    println!("rss: base {base} peak {peak} after {after}");
    assert!(peak - base > 10_000_000, "the burst did not grow the heap");
    // Without the trim nothing comes back (T318: peak 59.4 MB, after 59.4 MB). Run alone, the
    // trim leaves 25-35% resident (base 8.0, peak 36.8, after 17.0 MB): the pool's cached
    // buffers, the neighbours and glibc's top pad.
    assert!(after - base < (peak - base) / 2, "freed buffers still resident");
    drop(keep);
}

/// HAProxy keeps ~1 KB of RSS per idle client, request or not; T183's target is at most
/// twice that. The session itself (its arena slot is preallocated here) is not counted:
/// what is held is what the connection allocated -- its buffers above all.
#[test]
fn an_idle_client_connection_holds_no_buffer() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let fresh = per_idle_conn(false);
    let after_one = per_idle_conn(true);
    println!("heap per idle client: no request {fresh} B, after one request {after_one} B; SessionEntry {} B, TcpSession {} B", std::mem::size_of::<ibex_rt::engine::SessionEntry>(), std::mem::size_of::<ibex_rt::proxy::TcpSession>());
    assert!(fresh <= 2048, "an idle client that sent nothing holds {fresh} B of heap");
    assert!(after_one <= 2048, "an idle keep-alive client holds {after_one} B of heap after its request");
}
