// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request capture <expr>` compiles its expression when the proxy is built, not on
//! every request (T105). Measured with `tools/allocprofile` (`ALLOCPROFILE_CAPTURE=1`),
//! a steady-state request allocated 5 times without the rule and 18 with it, four of them
//! in `ibex_sample::expr::parse_call` / `split_call_chain`: the expression was parsed per
//! request.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_config::ast::{BackendSection, Config, FrontendSection, HttpReqAction, HttpReqRule, Mode, Server};
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

fn allocations_of_one_request(rules: Vec<HttpReqRule>) -> usize {
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
    let cfg = Config {
        frontends: vec![FrontendSection {
            name: "fe".into(),
            bind: Some(fa),
            mode: Mode::Http,
            http_req_rules: rules,
            default_backend: Some("be".into()),
            clitimeout: Some(Duration::from_secs(5)),
            ..Default::default()
        }],
        backends: vec![BackendSection {
            name: "be".into(),
            mode: Mode::Http,
            contimeout: Some(Duration::from_secs(5)),
            srvtimeout: Some(Duration::from_secs(5)),
            servers: vec![Server::new("s1", sa)],
            ..Default::default()
        }],
        ..Default::default()
    };
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
fn a_capture_rule_does_not_parse_its_expression_per_request() {
    let capture = |expr: &str| HttpReqRule {
        action: HttpReqAction::Capture { expr: expr.into(), len: Some(20), id: None },
        cond: None,
    };
    let without = allocations_of_one_request(Vec::new());
    let with = allocations_of_one_request(vec![capture("req.hdr(host)")]);
    // What evaluating the sample and storing the capture costs is a few allocations
    // (the header list, the sample, the stored string); parsing `req.hdr(host)` was
    // four more (measured 18 vs 5 before the change).
    assert!(
        with <= without + 10,
        "a request with `http-request capture req.hdr(host)` allocated {with} times against \
         {without} without the rule; the expression is being parsed on every request"
    );
}
