// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
use alcyon_rt::engine::Engine;

thread_local! {
    static IN_ALLOC: Cell<bool> = const { Cell::new(false) };
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

struct Attributing;
unsafe impl GlobalAlloc for Attributing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        let armed = ARMED.try_with(|a| a.get()).unwrap_or(false);
        let busy = IN_ALLOC.try_with(|b| b.get()).unwrap_or(true);
        if armed && !busy {
            let _ = IN_ALLOC.try_with(|b| b.set(true));
            let _ = ALLOCS.try_with(|a| a.set(a.get() + 1));
            let _ = BYTES.try_with(|b| b.set(b.get() + layout.size()));
            let _ = IN_ALLOC.try_with(|b| b.set(false));
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { System.dealloc(ptr, layout) }
}
#[global_allocator]
static A: Attributing = Attributing;

fn loopback0() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:8095").unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

fn backend(l: TcpListener, run: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    l.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        while run.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = l.accept() {
                s.set_nonblocking(false).ok(); s.set_nodelay(true).ok();
                s.set_read_timeout(Some(Duration::from_millis(100))).ok();
                let r = run.clone();
                thread::spawn(move || {
                    let mut b = [0u8; 4096];
                    while r.load(Ordering::Relaxed) {
                        match s.read(&mut b) {
                            Ok(n) if n > 0 => {
                                let reqs = b[..n].windows(4).filter(|w| *w == b"\r\n\r\n").count();
                                for _ in 0..reqs.max(1) {
                                    if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                                        return;
                                    }
                                }
                            }
                            Ok(_) => return,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                            Err(_) => return,
                        }
                    }
                });
            } else {
                thread::sleep(Duration::from_millis(1));
            }
        }
    })
}

fn main() {
    let target = std::env::var("HAPROXY_TARGET").unwrap_or_default();
    
    let (sl, sa) = loopback0();
    let fa;
    let mut e = None;
    let run_be = Arc::new(AtomicBool::new(true));
    let h_be = backend(sl, Arc::clone(&run_be));

    if target.is_empty() {
        let (fl, local_fa) = loopback0(); drop(fl);
        fa = local_fa;
        let cfg = Config {
            frontends: vec![FrontendSection { name: "fe".into(), bind: Some(fa), mode: Mode::Http,
                default_backend: Some("be".into()), clitimeout: Some(Duration::from_secs(5)),
                ..Default::default() }],
            backends: vec![BackendSection { name: "be".into(), mode: Mode::Http,
                contimeout: Some(Duration::from_secs(5)), srvtimeout: Some(Duration::from_secs(5)),
                servers: vec![Server::new("s1", sa)], ..Default::default() }],
            ..Default::default() };
        e = Some(Engine::new(&cfg, 1024).unwrap());
    } else {
        fa = target.parse().unwrap();
        println!("Testing against target: {}", fa);
    }
    
    if let Some(e) = e.as_mut() {
        // warm-up allocs
        for _ in 0..10 {
            let mut c_alloc = TcpStream::connect(fa).unwrap();
            c_alloc.set_nonblocking(true).unwrap();
            c_alloc.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut b = [0u8; 1024];
            let mut r = Vec::new();
            while r.len() < 10 {
                let _ = e.run_once();
                if let Ok(n) = c_alloc.read(&mut b) {
                    if n > 0 {
                        r.extend_from_slice(&b[..n]);
                        if r.windows(4).any(|w| w == b"\r\n\r\n") { break; }
                    } else { break; }
                }
            }
        }
        
        ALLOCS.with(|a| a.set(0)); BYTES.with(|b| b.set(0));
        ARMED.with(|a| a.set(true));
        for _ in 0..100 {
            let mut c_alloc = TcpStream::connect(fa).unwrap();
            c_alloc.set_nonblocking(true).unwrap();
            c_alloc.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut b = [0u8; 1024];
            let mut r = Vec::new();
            while r.len() < 10 {
                let _ = e.run_once();
                if let Ok(n) = c_alloc.read(&mut b) {
                    if n > 0 {
                        r.extend_from_slice(&b[..n]);
                        if r.windows(4).any(|w| w == b"\r\n\r\n") { break; }
                    } else { break; }
                }
            }
        }
        ARMED.with(|a| a.set(false));
        let all = ALLOCS.with(|a| a.get()) as f64 / 100.0;
        let byt = BYTES.with(|b| b.get()) as f64 / 100.0;
        println!("allocs: {:.1}", all);
        println!("bytes: {:.1}", byt);
    }
    
    // Throughput func
    let mut measure_rps = |conns: usize| -> usize {
        let run = Arc::new(AtomicBool::new(true));
        let count = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..conns {
            let r = run.clone(); let c = count.clone();
            threads.push(thread::spawn(move || {
                let mut sock = TcpStream::connect(fa).unwrap();
                sock.set_nonblocking(false).unwrap(); sock.set_nodelay(true).unwrap();
                sock.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                let mut b = [0u8; 4096];
                while r.load(Ordering::Relaxed) {
                    if sock.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n").is_err() {
                        if let Ok(new_sock) = TcpStream::connect(fa) {
                            sock = new_sock;
                            sock.set_nonblocking(false).unwrap(); sock.set_nodelay(true).unwrap();
                            sock.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                        }
                        continue;
                    }
                    let mut resp = 0;
                    while r.load(Ordering::Relaxed) {
                        match sock.read(&mut b) {
                            Ok(n) if n > 0 => {
                                resp += n;
                                if b[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                                    c.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                            }
                            Ok(_) => {
                                if let Ok(new_sock) = TcpStream::connect(fa) {
                                    sock = new_sock;
                                    sock.set_nonblocking(false).unwrap(); sock.set_nodelay(true).unwrap();
                                    sock.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                                }
                                break;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => continue,
                            Err(_) => {
                                if let Ok(new_sock) = TcpStream::connect(fa) {
                                    sock = new_sock;
                                    sock.set_nonblocking(false).unwrap(); sock.set_nodelay(true).unwrap();
                                    sock.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                                }
                                break;
                            }
                        }
                    }
                }
            }));
        }
        let start = Instant::now();
        let mut warmup_done = false;
        if let Some(e) = e.as_mut() {
            while start.elapsed() < Duration::from_secs(4) {
                let _ = e.run_once();
                if !warmup_done && start.elapsed() > Duration::from_secs(1) {
                    count.store(0, Ordering::Relaxed);
                    warmup_done = true;
                }
            }
        } else {
            thread::sleep(Duration::from_secs(1));
            count.store(0, Ordering::Relaxed);
            thread::sleep(Duration::from_secs(3));
        }
        run.store(false, Ordering::Relaxed);
        for t in threads { let _ = t.join(); }
        count.load(Ordering::Relaxed) / 3 // 3 seconds measurement
    };
    
    let rps_1 = measure_rps(1);
    let rps_50 = 0;
    
    run_be.store(false, Ordering::Relaxed);
    let _ = h_be.join();
    
    println!("rps_1: {}", rps_1);
    println!("rps_50: {}", rps_50);
}
