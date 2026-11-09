// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_config::ast::{BackendSection, Config, FrontendSection, HttpReqAction, HttpReqRule, Mode, Server};
use alcyon_rt::engine::Engine;

thread_local! {
    static IN_ALLOC: Cell<bool> = const { Cell::new(false) };
    static ARMED: Cell<bool> = const { Cell::new(false) };
    // `ALLOCPROFILE_DEPTH`: how many alcyon frames name a site (default 1).
    static DEPTH: Cell<usize> = Cell::new(
        std::env::var("ALLOCPROFILE_DEPTH").ok().and_then(|v| v.parse().ok()).unwrap_or(1));
    static SITES: RefCell<HashMap<String, (usize, usize)>> = RefCell::new(HashMap::new());
}

struct Attributing;
unsafe impl GlobalAlloc for Attributing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        let armed = ARMED.try_with(|a| a.get()).unwrap_or(false);
        let busy = IN_ALLOC.try_with(|b| b.get()).unwrap_or(true);
        if armed && !busy {
            let _ = IN_ALLOC.try_with(|b| b.set(true));
            let bt = format!("{}", std::backtrace::Backtrace::force_capture());
            let mut site = String::from("<no alcyon frame>");
            let depth = DEPTH.try_with(|d| d.get()).unwrap_or(1);
            let mut found = Vec::new();
            for line in bt.lines() {
                let l = line.trim();
                if (l.contains("alcyon_rt::") || l.contains("alcyon_sample::")
                    || l.contains("alcyon_config::") || l.contains("alcyon_proto::"))
                    && !l.contains("Attributing")
                {
                    found.push(l.split_whitespace().skip(1).collect::<Vec<_>>().join(" "));
                    if found.len() == depth { break; }
                }
            }
            if !found.is_empty() { site = found.join(" <- "); }
            // `ALLOCPROFILE_RAW`: an allocation with no alcyon frame is named by its whole backtrace.
            else if std::env::var_os("ALLOCPROFILE_RAW").is_some() { site = format!("<no alcyon frame>\n{bt}"); }
            let _ = SITES.try_with(|s| {
                let mut m = s.borrow_mut();
                let e = m.entry(site).or_insert((0, 0));
                e.0 += 1; e.1 += layout.size();
            });
            let _ = IN_ALLOC.try_with(|b| b.set(false));
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { System.dealloc(ptr, layout) }
}
#[global_allocator]
static A: Attributing = Attributing;

fn loopback0() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}
fn backend(l: TcpListener, run: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    l.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        while run.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = l.accept() {
                s.set_nonblocking(false).ok();
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
            thread::sleep(Duration::from_millis(2));
        }
    })
}
/// Drives one request and **asserts it succeeded**. A profiler that silently measures a
/// request the daemon failed to serve reports a wonderful number for the wrong reason;
/// this is the control that stops that.
fn drive(fe: SocketAddr, e: &mut Engine) {
    let mut c = TcpStream::connect(fe).unwrap();
    c.set_nonblocking(true).unwrap();
    c.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    // The response goes into a stack buffer: a `Vec` here was the one allocation per request
    // with no alcyon frame (59 B, the client's own), counted as if Alcyon made it.
    let st = Instant::now(); let mut r = [0u8; 2048]; let mut len = 0;
    while st.elapsed() < Duration::from_secs(2) && len < r.len() {
        let _ = e.run_once();
        if let Ok(n) = c.read(&mut r[len..]) { if n > 0 { len += n;
            if r[..len].windows(4).any(|w| w == b"\r\n\r\n") { break; } } }
        thread::sleep(Duration::from_millis(1));
    }
    for _ in 0..5 { let _ = e.run_once(); thread::sleep(Duration::from_millis(1)); }
    let text = String::from_utf8_lossy(&r[..len]);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "the profiled request did not succeed, so the allocation count below is \
         meaningless. Got: {text:?}"
    );
}

/// `ALLOCPROFILE_BACKENDS=N`: attribute the bytes `build_shared_state` allocates for N
/// backends of one server each (T175), ranked by bytes. Frees are not subtracted, so a
/// temporary shows up too; compare with `tests/backend_memory.rs`, which counts live bytes.
fn startup(n: usize) {
    let mut text = String::from(
        "global\n    maxconn 1000\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    timeout server 5s\n\
         frontend fe\n    bind 127.0.0.1:0\n    default_backend b0\n",
    );
    for i in 0..n {
        text.push_str(&format!("backend b{i}\n    server s{i} 127.0.0.1:{}\n", 20_000 + i % 1_000));
    }
    let cfg = alcyon_config::parse_str(&text).unwrap();
    ARMED.with(|a| a.set(true));
    let p = Engine::build_shared_state(&cfg).unwrap();
    ARMED.with(|a| a.set(false));
    SITES.with(|s| {
        let m = s.borrow();
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by(|a, b| b.1.1.cmp(&a.1.1));
        let tb: usize = m.values().map(|x| x.1).sum();
        println!("\n===== {n} backends: {} bytes per backend, ranked by call site =====", tb / n);
        for (site, (c, bytes)) in v.iter().take(40) {
            println!("{:8}B/be {:6}/be  {site}", bytes / n, c / n);
        }
    });
    drop(p);
}

/// A keep-alive server: answers every head on every connection with a 2-byte body.
fn keepalive_backend(l: TcpListener, run: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    l.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let mut conns: Vec<TcpStream> = Vec::new();
        let mut b = [0u8; 4096];
        while run.load(Ordering::Relaxed) {
            if let Ok((s, _)) = l.accept() {
                s.set_nonblocking(true).unwrap();
                conns.push(s);
            }
            for s in &mut conns {
                if let Ok(n) = s.read(&mut b) {
                    if n > 0 && b[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    }
                }
            }
            thread::sleep(Duration::from_micros(200));
        }
    })
}

/// One keep-alive request on `c`, the engine run until a full head and `tail` are back.
fn drive_ka(c: &mut TcpStream, e: &mut Engine, tail: &[u8]) {
    c.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let st = Instant::now();
    let mut r = [0u8; 1024];
    let mut len = 0;
    while st.elapsed() < Duration::from_secs(2) && !r[..len].ends_with(tail) {
        let _ = e.run_once();
        if let Ok(n) = c.read(&mut r[len..]) { len += n; }
    }
    assert!(r[..len].ends_with(tail), "the profiled request did not succeed: {:?}", String::from_utf8_lossy(&r[..len]));
}

/// `ALLOCPROFILE_FE=<file>`: the file's lines go into the frontend (indented), and the
/// profiled request is the fourth on one keep-alive connection to a keep-alive server, so
/// only per-request allocations show. `ALLOCPROFILE_TAIL` is the end of the expected
/// response (default `ok`).
fn keepalive_profile(fe_file: &str) {
    let lines = std::fs::read_to_string(fe_file).unwrap();
    let tail = std::env::var("ALLOCPROFILE_TAIL").unwrap_or_else(|_| "ok".into());
    let (sl, sa) = loopback0();
    let (fl, fa) = loopback0(); drop(fl);
    let run = Arc::new(AtomicBool::new(true));
    let h = keepalive_backend(sl, Arc::clone(&run));
    let fe: String = lines.lines().map(|l| format!("  {}\n", l.trim())).collect();
    let text = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fa}\n{fe}  default_backend be\nbackend be\n  server s1 {sa}\n"
    );
    let cfg = alcyon_config::parse_str(&text).unwrap();
    let mut e = Engine::new(&cfg, 64).unwrap();
    let mut c = TcpStream::connect(fa).unwrap();
    c.set_nonblocking(true).unwrap();
    for _ in 0..3 { drive_ka(&mut c, &mut e, tail.as_bytes()); }
    SITES.with(|s| s.borrow_mut().clear());
    ARMED.with(|a| a.set(true));
    drive_ka(&mut c, &mut e, tail.as_bytes());
    ARMED.with(|a| a.set(false));
    print_sites();
    run.store(false, Ordering::Relaxed); let _ = h.join();
}

fn print_sites() {
    SITES.with(|s| {
        let m = s.borrow();
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by(|a, b| b.1.0.cmp(&a.1.0));
        let tot: usize = m.values().map(|x| x.0).sum();
        let tb: usize = m.values().map(|x| x.1).sum();
        println!("\n===== {tot} allocations, {tb} bytes, ranked by call site =====");
        for (site, (n, bytes)) in v.iter().take(40) {
            println!("{n:4}  {bytes:8}B  {site}");
        }
    });
}

fn main() {
    if let Some(n) = std::env::var("ALLOCPROFILE_BACKENDS").ok().and_then(|v| v.parse().ok()) {
        return startup(n);
    }
    if let Ok(f) = std::env::var("ALLOCPROFILE_FE") {
        return keepalive_profile(&f);
    }
    let (sl, sa) = loopback0();
    let (fl, fa) = loopback0(); drop(fl);
    let run = Arc::new(AtomicBool::new(true));
    let h = backend(sl, Arc::clone(&run));
    // `ALLOCPROFILE_CAPTURE=1` adds `http-request capture req.hdr(host) len 20`, to profile
    // that rule's per-request cost (T105).
    let mut http_req_rules = Vec::new();
    if std::env::var_os("ALLOCPROFILE_CAPTURE").is_some() {
        http_req_rules.push(HttpReqRule {
            action: HttpReqAction::Capture { expr: "req.hdr(host)".into(), len: Some(20), id: None },
            cond: None,
            line: 0,
        });
    }
    let cfg = Config {
        frontends: vec![FrontendSection { name: "fe".into(), bind: Some(fa), mode: Mode::Http,
            http_req_rules,
            default_backend: Some("be".into()), clitimeout: Some(Duration::from_secs(5)),
            ..Default::default() }],
        backends: vec![BackendSection { name: "be".into(), mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)), srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", sa)], ..Default::default() }],
        ..Default::default() };
    // `ALLOCPROFILE_LOG=ring` (or `udp`) profiles the request with an access log written to a
    // `ring` section (or a UDP collector), to show where the log line's allocations are.
    let cfg = match std::env::var("ALLOCPROFILE_LOG").ok().as_deref() {
        Some(kind) => {
            let collector = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let (ring, log) = if kind == "ring" {
                ("ring r\n  size 65536\n".to_string(), "  log ring@r local0\n".to_string())
            } else {
                (String::new(), format!("  log {} local0\n", collector.local_addr().unwrap()))
            };
            let text = format!(
                "{ring}frontend fe\n  mode http\n  option httplog\n  bind {fa}\n  timeout client 5s\n{log}  default_backend be\n\
                 backend be\n  mode http\n  timeout connect 5s\n  timeout server 5s\n  server s1 {sa}\n"
            );
            let cfg = alcyon_config::parse_str(&text).unwrap();
            alcyon_rt::logfwd::start(&cfg).unwrap();
            std::mem::forget(collector);
            cfg
        }
        None => cfg,
    };
    let mut e = Engine::new(&cfg, 64).unwrap();
    drive(fa, &mut e);
    SITES.with(|s| s.borrow_mut().clear());
    ARMED.with(|a| a.set(true));
    drive(fa, &mut e);
    ARMED.with(|a| a.set(false));
    print_sites();
    run.store(false, Ordering::Relaxed); let _ = h.join();
}
