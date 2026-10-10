// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The largest request head that fits `tune.bufsize` is the same with repeated headers as
//! `HAProxy`'s (T265 item 1). Ibex lays its HTX out with 16-byte block descriptors where
//! `HAProxy`'s are 8, so a head close to the limit with several headers had no room in the
//! parser's buffer and drew a 400 (and the limit fell by 8 bytes per header) where `HAProxy`
//! answers it.
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, 2026-10-10, `tune.maxrewrite 0`, `GET /` with
//! `Host: x`, `n` repeated headers and an `X-a` header of `m` bytes, bisecting `m`:
//! `Forwarded: for=10.0.0.<i>` repeated: 0 -> 16271 is the largest answered, 1 -> 16242,
//! 2 -> 16213, 3 -> 16184, 6 -> 16097, and one byte more is a 431 each time.
//! `X-b: for=10.0.0.<i>` repeated: 2 -> 16225, 3 -> 16202.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

fn status(name: &str, repeated: usize, n: usize) -> String {
    let fe = common::reserve_addr();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    write!(
        f,
        "global\n  tune.maxrewrite 0\ndefaults\n  mode http\n  timeout client 5s\n\
         frontend f\n  bind {fe}\n  http-request return status 200 content-type text/plain string ok\n"
    )
    .expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe));
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    let rep: String = (0..repeated).map(|i| format!("{name}: for=10.0.0.{i}\r\n")).collect();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\n{rep}X-a: {}\r\n\r\n", "a".repeat(n)).expect("send");
    let mut out = [0u8; 64];
    let got = s.read(&mut out).unwrap_or(0);
    common::stop(&mut child);
    String::from_utf8_lossy(&out[..got]).lines().next().unwrap_or("").to_string()
}

#[test]
fn repeated_headers_leave_the_same_room_as_haproxy() {
    for (name, repeated, largest) in [
        ("Forwarded", 0, 16271),
        ("Forwarded", 1, 16242),
        ("Forwarded", 2, 16213),
        ("Forwarded", 3, 16184),
        ("Forwarded", 6, 16097),
        ("X-b", 2, 16225),
        ("X-b", 3, 16202),
    ] {
        assert_eq!(status(name, repeated, largest), "HTTP/1.1 200 OK", "{repeated} x {name}, {largest} bytes");
        assert_eq!(
            status(name, repeated, largest + 1),
            "HTTP/1.1 431 Request Header Fields Too Large",
            "{repeated} x {name}, {} bytes",
            largest + 1
        );
    }
}

/// A server answering with `repeated` `name` headers and an `X-a` header of `n` bytes.
fn response_status(name: &'static str, repeated: usize, n: usize) -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut b = [0u8; 4096];
            let _ = c.read(&mut b);
            let rep: String = (0..repeated).map(|i| format!("{name}: for=10.0.0.{i}\r\n")).collect();
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{rep}X-a: {}\r\n\r\nok", "a".repeat(n));
        }
    });
    let fe = common::reserve_addr();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    write!(
        f,
        "global\n  tune.maxrewrite 0\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  server s {srv}\n"
    )
    .expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe));
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut out = [0u8; 64];
    let got = s.read(&mut out).unwrap_or(0);
    common::stop(&mut child);
    String::from_utf8_lossy(&out[..got]).lines().next().unwrap_or("").to_string()
}

/// The response head: measured the same way on the same binary (the server's head carries
/// `Content-Length: 2`, then the repeated headers, then `X-a`), one byte more is a 502.
#[test]
fn response_head_limit_is_haproxys() {
    for (name, repeated, largest) in [
        ("Forwarded", 0, 16260),
        ("Forwarded", 1, 16231),
        ("Forwarded", 2, 16202),
        ("Forwarded", 3, 16173),
        ("Forwarded", 6, 16086),
        ("X-b", 2, 16214),
        ("X-b", 3, 16191),
    ] {
        assert_eq!(response_status(name, repeated, largest), "HTTP/1.1 200 OK", "{repeated} x {name}, {largest} bytes");
        assert_eq!(
            response_status(name, repeated, largest + 1),
            "HTTP/1.1 502 Bad Gateway",
            "{repeated} x {name}, {} bytes",
            largest + 1
        );
    }
}
