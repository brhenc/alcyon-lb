// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `option forwardfor` on a request with no room left for the header (T241 item 6).
//! `HAProxy` fails the request with a 500 (`http_process_request`, `http_add_header` failing);
//! Ibex went on without the header. Measured on `HAProxy 3.5-dev8-885761-29`, 2026-10-10,
//! the default `tune.bufsize`, `tune.maxrewrite 0`: `GET /` with `Host: x` and an `X-a`
//! header of `n` bytes is answered up to `n` = 16211, gets a 500 from 16240 and a 431 from
//! 16272. (`http-request return` in the backend answers before the header is added: measured
//! 200 there up to 16183 -- the server is a real one here.)
//!
//! `option originalto` and `option forwarded` (backend) the same way, measured on the same
//! binary the same day: `X-Original-To` gets a 500 from 16250 (200 at 16240). `Forwarded`
//! gets a 500 at 16240 with no `Forwarded` header in the request and with one (200 at 16180),
//! and at 16170 with three (200 at 16140).

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

/// A server answering every request with `200`: the headers are added on the way to it, which
/// an `http-request return` in the backend would never reach.
fn server() -> std::net::SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut b = [0u8; 65536];
                let _ = c.read(&mut b);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
    addr
}

fn status(extra: &str, n: usize) -> String {
    status_with(extra, "", 0, n)
}

/// `fe_extra` and `be_extra` go in the frontend and the backend; the request carries
/// `forwarded` `Forwarded` headers before the `X-a` header of `n` bytes.
fn status_with(fe_extra: &str, be_extra: &str, forwarded: usize, n: usize) -> String {
    let fe = common::reserve_addr();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    write!(
        f,
        "global\n  tune.maxrewrite 0\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  {fe_extra}\n  default_backend be\nbackend be\n  {be_extra}\n  server s {}\n",
        server()
    )
    .expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe));
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    let fwd: String = (0..forwarded).map(|i| format!("Forwarded: for=10.0.0.{i}\r\n")).collect();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\n{fwd}X-a: {}\r\n\r\n", "a".repeat(n)).expect("send");
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while !out.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk) {
            Ok(n) if n > 0 => out.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    common::stop(&mut child);
    String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_string()
}

#[test]
fn forwardfor_that_does_not_fit_fails_the_request() {
    assert_eq!(status("option forwardfor", 16150), "HTTP/1.1 200 OK");
    assert_eq!(status("option forwardfor", 16240), "HTTP/1.1 500 Internal Server Error");
}

#[test]
fn without_the_option_the_same_request_is_served() {
    assert_eq!(status("", 16240), "HTTP/1.1 200 OK");
}

#[test]
fn originalto_that_does_not_fit_fails_the_request() {
    assert_eq!(status("option originalto", 16240), "HTTP/1.1 200 OK");
    assert_eq!(status("option originalto", 16250), "HTTP/1.1 500 Internal Server Error");
}

/// The element is appended to the last `Forwarded` header, so each shape of the request takes
/// its own path: no header (one is added), one header, several.
#[test]
fn forwarded_that_does_not_fit_fails_the_request() {
    for (headers, fits, fails) in [(0, 16180, 16240), (1, 16180, 16240), (3, 16140, 16170)] {
        assert_eq!(status_with("", "option forwarded", headers, fits), "HTTP/1.1 200 OK", "{headers} headers, {fits} bytes");
        assert_eq!(
            status_with("", "option forwarded", headers, fails),
            "HTTP/1.1 500 Internal Server Error",
            "{headers} headers, {fails} bytes"
        );
    }
}
