// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T617 (CP4b P6): the response rules clone the response captures only when there are any.
//! A frontend with no response capture slot (the common case) costs no clone per response; one
//! with slots still reads them as they were when the response came in.
//! ([`alcyon_rt::engine::res_caps_clones`], debug builds; counts this thread only.)

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::engine::Engine;

/// One GET through an in-process engine with `rules` in the frontend: the clones it cost and
/// the raw response.
fn get(rules: &str, slow_body: bool) -> (u64, String) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let run2 = Arc::clone(&running);
    let be = thread::spawn(move || {
        srv.set_nonblocking(true).expect("nonblocking");
        while run2.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = srv.accept() {
                let mut b = [0u8; 2048];
                let _ = s.read(&mut b);
                if slow_body {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n");
                    thread::sleep(Duration::from_millis(150));
                    let _ = s.write_all(b"okok");
                } else {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                }
            }
            thread::sleep(Duration::from_micros(200));
        }
    });
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n{rules}  default_backend be\nbackend be\n  server s1 {srv_addr}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let c0 = alcyon_rt::engine::res_caps_clones();
    c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").expect("write");
    let start = Instant::now();
    let mut rsp = [0u8; 1024];
    let mut len = 0;
    while start.elapsed() < Duration::from_secs(3) && !rsp[..len].ends_with(b"ok") {
        let _ = engine.run_once();
        if let Ok(n) = c.read(&mut rsp[len..]) {
            len += n;
        }
    }
    let clones = alcyon_rt::engine::res_caps_clones() - c0;
    drop(c);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
    (clones, String::from_utf8_lossy(&rsp[..len]).into_owned())
}

/// No `declare capture response`: the response rules run (a `set-header`) and clone nothing.
#[test]
fn a_frontend_without_response_slots_clones_no_captures() {
    let (clones, rsp) = get("  http-response set-header x-out y\n", false);
    assert!(rsp.contains("x-out: y\r\n"), "the response rule ran: {rsp:?}");
    println!("[T617] no response slot: {clones} capture clones");
    if cfg!(debug_assertions) {
        assert_eq!(clones, 0, "response capture clones");
    }
}

/// A response slot filled when the request came in (`capture-res` in a request rule): a
/// response rule before the capture reads it as it was when the response came in, one after
/// the capture reads the new value, and the clones happen.
#[test]
fn a_frontend_with_response_slots_clones_them_and_the_rules_read_them() {
    let (clones, rsp) = get(
        "  declare capture response len 8\n  http-request set-var(txn.c) str(abcdefgh),capture-res(0)\n  \
         http-response set-header x-pre \"[%[capture.res.hdr(0)]]\"\n  http-response capture str(later) id 0\n  http-response set-header x-out \"[%[capture.res.hdr(0)]]\"\n",
        false,
    );
    println!("[T617] one response slot: {clones} capture clones\n{rsp}");
    assert!(rsp.contains("x-pre: [abcdefgh]\r\n"), "{rsp:?}");
    assert!(rsp.contains("x-out: [later]\r\n"), "{rsp:?}");
    if cfg!(debug_assertions) {
        assert!(clones > 0, "response capture clones");
    }
}

/// The same slot with the response held for its body (`http-response wait-for-body`): the head
/// goes back into the buffer, the captures are written back, and the rules go on from the
/// wait with the slot as the first pass left it.
#[test]
fn a_response_held_for_its_body_keeps_its_captures() {
    let (clones, rsp) = get(
        "  declare capture response len 8\n  http-response capture str(held) id 0\n  \
         http-response wait-for-body time 5s at-least 4\n  http-response set-header x-out \"[%[capture.res.hdr(0)]]\"\n",
        true,
    );
    println!("[T617] held for the body: {clones} capture clones\n{rsp}");
    assert!(rsp.contains("x-out: [held]\r\n"), "{rsp:?}");
    assert!(rsp.ends_with("okok"), "{rsp:?}");
    if cfg!(debug_assertions) {
        assert!(clones > 0, "response capture clones");
    }
}
