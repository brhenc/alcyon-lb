// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! X6 (`docs/design/htx-engine-2026-11-01.md` section 3): the request body a `wait-for-body` /
//! `option http-buffer-request` holds is read where it arrived, in the request buffer. A
//! `Content-Length` body is a view into it (no copy, no allocation per pass while it is
//! incomplete); `req.body_len` / `req.body` read that view.
//! ([`alcyon_rt::engine::request_body_copies`], debug builds; the module shares the process and
//! counts its own thread only.)

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::engine::Engine;

/// A backend that records every request it receives and answers `200` once the body is there.
fn backend(listener: TcpListener, running: Arc<AtomicBool>, seen: Arc<Mutex<Vec<u8>>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut conns: Vec<TcpStream> = Vec::new();
        let mut buf = [0u8; 16384];
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = listener.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push(s);
            }
            conns.retain_mut(|s| match s.read(&mut buf) {
                Ok(0) => false,
                Ok(n) => {
                    let mut seen = seen.lock().expect("lock");
                    seen.extend_from_slice(&buf[..n]);
                    let done = seen.windows(4).position(|w| w == b"\r\n\r\n").is_some_and(|h| seen.len() >= h + 4 + 4096 || !seen.starts_with(b"POST"));
                    if done {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    }
                    true
                }
                Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
            });
            thread::sleep(Duration::from_micros(200));
        }
    })
}

/// One POST of `body` (as `Content-Length`, sent in two pieces so the wait is passed more
/// than once, or `chunked`): the copies it cost and what the server saw.
fn post(chunked: bool) -> (u64, Vec<u8>, String) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv_addr = srv.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let running = Arc::new(AtomicBool::new(true));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let be = backend(srv, Arc::clone(&running), Arc::clone(&seen));
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  option http-buffer-request\n  http-request set-header X-Body-Len %[req.body_len]\n  default_backend be\nbackend be\n  server s1 {srv_addr}\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    let body = vec![b'x'; 4096];
    let (head, first, second): (&[u8], Vec<u8>, Vec<u8>) = if chunked {
        let mut wire = b"1000\r\n".to_vec();
        wire.extend_from_slice(&body);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        (b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n", wire[..2000].to_vec(), wire[2000..].to_vec())
    } else {
        (b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\n", body[..2000].to_vec(), body[2000..].to_vec())
    };
    let c0 = alcyon_rt::engine::request_body_copies();
    c.write_all(head).expect("write");
    c.write_all(&first).expect("write");
    let pump = |engine: &mut Engine, ms: u64| {
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(ms) {
            let _ = engine.run_once();
        }
    };
    pump(&mut engine, 100);
    c.write_all(&second).expect("write");
    let start = Instant::now();
    let mut rsp = [0u8; 1024];
    let mut len = 0;
    while start.elapsed() < Duration::from_secs(3) && !rsp[..len].ends_with(b"ok") {
        let _ = engine.run_once();
        if let Ok(n) = c.read(&mut rsp[len..]) {
            len += n;
        }
    }
    let copies = alcyon_rt::engine::request_body_copies() - c0;
    drop(c);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
    let seen = seen.lock().expect("lock").clone();
    (copies, seen, String::from_utf8_lossy(&rsp[..len]).into_owned())
}

/// A 4 KiB `Content-Length` POST with `option http-buffer-request`: the body is read in place.
#[test]
fn req_body_is_a_view_into_the_request_buffer() {
    let (copies, seen, rsp) = post(false);
    assert!(rsp.starts_with("HTTP/1.1 200 OK"), "{rsp:?}");
    let text = String::from_utf8_lossy(&seen);
    assert!(text.contains("X-Body-Len: 4096\r\n"), "req.body_len should see the whole body: {text:.300}");
    assert!(seen.ends_with(&[b'x'; 4096]), "the server sees the body");
    println!("[X6] 4 KiB POST, buffered request: {copies} body copies");
    if cfg!(debug_assertions) {
        assert_eq!(copies, 0, "body copies");
    }
}

/// A chunked body has to be un-framed, which is a copy; it must still arrive and be counted.
#[test]
fn a_chunked_body_is_unframed_and_still_forwarded() {
    let (copies, seen, rsp) = post(true);
    assert!(rsp.starts_with("HTTP/1.1 200 OK"), "{rsp:?}");
    let text = String::from_utf8_lossy(&seen);
    assert!(text.contains("X-Body-Len: 4096\r\n"), "{text:.300}");
    if cfg!(debug_assertions) {
        assert!(copies > 0, "a chunked body is decoded out of place");
    }
}
