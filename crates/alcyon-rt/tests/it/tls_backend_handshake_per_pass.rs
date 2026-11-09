// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A burst of backend TLS handshakes does not hold up the other connections of a thread
//! (T295 item 1; the frontend side is T283).
//!
//! `HAProxy` marks a connection's tasklet `TASK_HEAVY` while its handshake is in progress
//! (`ssl_sock_init`, for a server connection as for a client one; cleared in
//! `ssl_sock_io_cb` once it is done) and runs at most one heavy tasklet per scheduler pass
//! (`src/task.c`: `[TL_HEAVY] = 1`). Alcyon did this for the client side only: a server
//! reconnect burst (`server ... ssl` after a server restart, `http-reuse never`) ran every
//! ready handshake in the pass that found it, ahead of the plain requests of the thread.
//!
//! In-process, one engine pass at a time: eight clients have each sent a request whose
//! backend is `ssl`, and a plaintext client has sent a request that a second frontend
//! answers itself. The backend is a listener that only watches for `ClientHello`s. At most
//! one `ClientHello` may be sent per pass, and the plaintext request must not wait for all
//! eight.
//!
//! The check is on the scheduling (a deterministic count per pass), not on a wall-clock
//! p99: the machine is shared.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use alcyon_rt::engine::Engine;

/// Whether `s` has bytes to read (or is closed), without consuming them.
fn has_bytes(s: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    !matches!(s.peek(&mut b), Err(e) if e.kind() == ErrorKind::WouldBlock)
}

#[test]
fn at_most_one_backend_handshake_runs_per_pass_and_plain_requests_go_between() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fe_addr = common::reserve_addr();
    let plain_addr = common::reserve_addr();
    let be_addr = common::reserve_addr();
    let backend = TcpListener::bind(be_addr).unwrap();
    backend.set_nonblocking(true).unwrap();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe_addr}\n  default_backend b\n\
         frontend p\n  bind {plain_addr}\n\
         \x20 http-request return status 200 content-type text/plain string ok\n\
         backend b\n  http-reuse never\n  server s1 {be_addr} ssl verify none\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");

    let mut clients: Vec<TcpStream> = Vec::new();
    for _ in 0..8 {
        let mut s = TcpStream::connect(fe_addr).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        s.set_nonblocking(true).unwrap();
        clients.push(s);
    }
    let mut plain = TcpStream::connect(plain_addr).unwrap();
    plain.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    plain.set_nonblocking(true).unwrap();
    // Everything is in the kernel before the first pass looks.
    std::thread::sleep(Duration::from_millis(50));

    // The server connections, and whether each has sent its ClientHello.
    let mut srv: Vec<(TcpStream, bool)> = Vec::new();
    let mut most_in_one_pass = 0;
    let mut plain_answered_with = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while srv.iter().filter(|(_, hello)| *hello).count() < clients.len() && Instant::now() < deadline {
        let _ = engine.run_once();
        // The loopback delivers what the pass wrote before the pass returns.
        while let Ok((s, _)) = backend.accept() {
            s.set_nonblocking(true).unwrap();
            srv.push((s, false));
        }
        let mut new = 0;
        for (s, hello) in &mut srv {
            if !*hello && has_bytes(s) {
                *hello = true;
                new += 1;
            }
        }
        most_in_one_pass = most_in_one_pass.max(new);
        if plain_answered_with.is_none() && has_bytes(&plain) {
            plain_answered_with = Some(srv.iter().filter(|(_, hello)| *hello).count());
        }
    }
    let hellos = srv.iter().filter(|(_, hello)| *hello).count();
    assert_eq!(hellos, clients.len(), "not every server connection sent a ClientHello");
    assert!(
        most_in_one_pass <= 1,
        "{most_in_one_pass} backend handshakes ran in a single pass; HAProxy runs at most one (TL_HEAVY)"
    );
    let before = plain_answered_with.expect("the plaintext request was answered");
    assert!(before < clients.len(), "the plaintext request waited for all {before} backend handshakes");
    let mut buf = [0u8; 256];
    let n = plain.read(&mut buf).unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&buf[..n]));
}
