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

use ibex_config::ast::{BackendSection, Config, FrontendSection, HttpReqAction, HttpReqRule, Mode, Server};
use ibex_rt::engine::Engine;

thread_local! {
    static IN_ALLOC: Cell<bool> = const { Cell::new(false) };
    static ARMED: Cell<bool> = const { Cell::new(false) };
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
            let mut site = String::from("<no ibex frame>");
            for line in bt.lines() {
                let l = line.trim();
                if (l.contains("ibex_rt::") || l.contains("ibex_sample::")
                    || l.contains("ibex_config::") || l.contains("ibex_proto::"))
                    && !l.contains("Attributing")
                {
                    site = l.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
                    break;
                }
            }
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
    let st = Instant::now(); let mut r = Vec::new(); let mut b = [0u8; 512];
    while st.elapsed() < Duration::from_secs(2) {
        let _ = e.run_once();
        if let Ok(n) = c.read(&mut b) { if n > 0 { r.extend_from_slice(&b[..n]);
            if r.windows(4).any(|w| w == b"\r\n\r\n") { break; } } }
        thread::sleep(Duration::from_millis(1));
    }
    for _ in 0..5 { let _ = e.run_once(); thread::sleep(Duration::from_millis(1)); }
    let text = String::from_utf8_lossy(&r);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "the profiled request did not succeed, so the allocation count below is \
         meaningless. Got: {text:?}"
    );
}

fn main() {
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
    let mut e = Engine::new(&cfg, 64).unwrap();
    drive(fa, &mut e);
    SITES.with(|s| s.borrow_mut().clear());
    ARMED.with(|a| a.set(true));
    drive(fa, &mut e);
    ARMED.with(|a| a.set(false));
    SITES.with(|s| {
        let m = s.borrow();
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by(|a, b| b.1.0.cmp(&a.1.0));
        let tot: usize = m.values().map(|x| x.0).sum();
        let tb: usize = m.values().map(|x| x.1).sum();
        println!("\n===== {tot} allocations, {tb} bytes, ranked by call site =====");
        for (site, (n, bytes)) in v.iter().take(20) {
            println!("{n:4}  {bytes:8}B  {site}");
        }
    });
    run.store(false, Ordering::Relaxed); let _ = h.join();
}
