// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A flood of TLS handshakes does not hold up the other connections of a thread
//! (T283, MY-2).
//!
//! `HAProxy` marks a connection's tasklet `TASK_HEAVY` while its handshake is in progress
//! (`ssl_sock_init`, cleared in `ssl_sock_io_cb` once it is done) and runs at most one
//! heavy tasklet per scheduler pass (`src/task.c`: `[TL_HEAVY] = 1`), so the requests of
//! established connections are served between two handshakes. Alcyon woke every connection
//! as urgent and ran every ready handshake in the pass that found it: under 4000
//! handshakes/s, a legitimate h2 user's p99 was 56-108 ms against `HAProxy`'s 2 ms.
//!
//! In-process, one engine pass at a time: eight clients have each sent a `ClientHello` and
//! a plaintext client has sent a request. At most one `ClientHello` may be answered per
//! pass, and the plaintext request must not wait for all eight.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alcyon_rt::engine::Engine;
use tempfile::TempDir;

/// Whether `s` has bytes to read (or is closed), without consuming them.
fn has_bytes(s: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    !matches!(s.peek(&mut b), Err(e) if e.kind() == ErrorKind::WouldBlock)
}

#[test]
fn at_most_one_handshake_runs_per_pass_and_plain_requests_go_between() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = TempDir::new().unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).unwrap();
    let tls_addr = common::reserve_addr();
    let plain_addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {tls_addr} ssl crt {}\n  bind {plain_addr}\n\
         \x20 http-request return status 200 content-type text/plain string ok\n",
        pem.display()
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let client_cfg = Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
    let mut tls: Vec<TcpStream> = Vec::new();
    for _ in 0..8 {
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut c = rustls::ClientConnection::new(Arc::clone(&client_cfg), name).unwrap();
        let mut hello = Vec::new();
        c.write_tls(&mut hello).unwrap();
        let mut s = TcpStream::connect(tls_addr).unwrap();
        s.write_all(&hello).unwrap();
        s.set_nonblocking(true).unwrap();
        tls.push(s);
    }
    let mut plain = TcpStream::connect(plain_addr).unwrap();
    plain.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    plain.set_nonblocking(true).unwrap();
    // Everything is in the kernel before the first pass looks.
    std::thread::sleep(Duration::from_millis(50));

    let mut answered = vec![false; tls.len()];
    let mut most_in_one_pass = 0;
    let mut plain_answered_with = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while answered.iter().any(|a| !a) && Instant::now() < deadline {
        let _ = engine.run_once();
        let mut new = 0;
        for (i, s) in tls.iter().enumerate() {
            if !answered[i] && has_bytes(s) {
                answered[i] = true;
                new += 1;
            }
        }
        most_in_one_pass = most_in_one_pass.max(new);
        if plain_answered_with.is_none() && has_bytes(&plain) {
            plain_answered_with = Some(answered.iter().filter(|a| **a).count());
        }
    }
    assert!(answered.iter().all(|a| *a), "not every ClientHello was answered: {answered:?}");
    assert!(
        most_in_one_pass <= 1,
        "{most_in_one_pass} handshakes ran in a single pass; HAProxy runs at most one (TL_HEAVY)"
    );
    let before = plain_answered_with.expect("the plaintext request was answered");
    assert!(before < tls.len(), "the plaintext request waited for all {before} handshakes");
    let mut buf = [0u8; 256];
    let n = plain.read(&mut buf).unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", String::from_utf8_lossy(&buf[..n]));
}
