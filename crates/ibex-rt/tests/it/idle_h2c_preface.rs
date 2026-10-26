// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A connection on a `proto h2` bind that has sent nothing (T501, VV-5). Measured on
//! `HAProxy 3.5-dev8-885761-29`, `timeout client 2s`: no byte at 2 s, a close at 4 s (not an
//! HTTP/1 `408` at 2 s; `timeout http-request` changes nothing). A client that sent HTTP/1
//! text instead of the preface is cut off without a page.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bytes received and seconds until the close, for a client that sends `hello`.
fn run(hello: &[u8]) -> (Vec<u8>, f64) {
    let port = common::reserve_port();
    let dir = std::env::temp_dir().join(format!("ibex_t501h2_{}_{port}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let cfgf = dir.join("c.cfg");
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 500ms\n  timeout http-request 200ms\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{port} proto h2\n  default_backend b\nbackend b\n  http-request return status 200\n"
    );
    std::fs::write(&cfgf, cfg).expect("write config");
    let mut child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
        .arg("-f")
        .arg(&cfgf)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Ibex)
        .expect("spawn");
    assert!(common::wait_listening(format!("127.0.0.1:{port}").parse().unwrap()), "never listened");
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let t = Instant::now();
    if !hello.is_empty() {
        s.write_all(hello).expect("write");
    }
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    let took = t.elapsed().as_secs_f64();
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    (got, took)
}

#[test]
fn silent_client_gets_no_page_and_two_timeouts() {
    let (got, took) = run(b"");
    assert!(got.is_empty(), "got {:?}", String::from_utf8_lossy(&got));
    assert!((0.9..1.5).contains(&took), "closed after {took}s");
}

#[test]
fn http1_text_on_an_h2_bind_gets_no_page() {
    let (got, took) = run(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(got.is_empty(), "got {:?}", String::from_utf8_lossy(&got));
    assert!(took < 0.5, "closed after {took}s");
}
