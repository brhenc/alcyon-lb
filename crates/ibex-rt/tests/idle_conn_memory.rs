// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
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
    for _ in 0..50 {
        let _ = engine.run_once();
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
