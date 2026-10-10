// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `timeout http-request` after `tcp-request content switch-mode http` (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29: a `mode tcp` frontend with `timeout http-request
//! 700ms`, `timeout client 4s` and `tcp-request content switch-mode http`; a client that
//! sends `GET / HTT` and stops gets the 408 after 0.7 s, not after the client timeout.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

#[test]
fn the_first_request_after_switch_mode_has_the_http_request_timeout() {
    let fe = common::reserve_addr();
    let be = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  timeout client 4s\n  timeout connect 1s\n  timeout server 5s\n  timeout http-request 700ms\n\
         frontend f\n  mode tcp\n  bind {fe}\n  tcp-request inspect-delay 1s\n  tcp-request content switch-mode http\n  default_backend b\n\
         backend b\n  mode http\n  server s1 {be}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(6))).expect("timeout");
    let start = Instant::now();
    c.write_all(b"GET / HTT").expect("send");
    let mut buf = [0u8; 256];
    let n = c.read(&mut buf).unwrap_or(0);
    let took = start.elapsed();
    common::stop(&mut child);
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(text.starts_with("HTTP/1.1 408"), "{text:?}");
    assert!(took < Duration::from_millis(2500), "the 408 came after {took:?}, not at timeout http-request");
}
