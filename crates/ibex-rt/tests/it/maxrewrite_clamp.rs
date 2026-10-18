// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `tune.maxrewrite` is held to half of `tune.bufsize` (T430 row 25). `HAProxy` does
//! `if (maxrewrite >= bufsize / 2) maxrewrite = bufsize / 2` after the configuration is read
//! (`src/haproxy.c`), silently. Ibex took the default 1024 as it was, so `tune.bufsize 1024`
//! left no room for any head and every request got a 431.
//!
//! Measured on `HAProxy 3.5-dev8`, 2026-10-18, `GET /0` with `Host: a` and `X: <n bytes>`,
//! the largest `n` served (the next size up is a 431):
//! bufsize 1024: 400 with no maxrewrite, with 1024 and with 2048; 912 with maxrewrite 0.
//! bufsize 2048: 912 with no maxrewrite, with 2048 and with 4096; 1936 with maxrewrite 0.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

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

/// The status line of the answer to a request carrying an `X` header of `n` bytes, with the
/// global section `global`.
fn status(global: &str, n: usize) -> String {
    status_with(global, "", n)
}

/// [`status`] with `extra` header lines in the request.
fn status_with(global: &str, extra: &str, n: usize) -> String {
    let fe = common::reserve_addr();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    write!(
        f,
        "global\n{global}defaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend be\nbackend be\n  server s {}\n",
        server()
    )
    .expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe));
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    write!(s, "GET /0 HTTP/1.1\r\nHost: a\r\n{extra}X: {}\r\n\r\n", "a".repeat(n)).expect("send");
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

const OK: &str = "HTTP/1.1 200 OK";
const TOO_BIG: &str = "HTTP/1.1 431 Request Header Fields Too Large";

#[test]
fn small_bufsize_default_maxrewrite_serves_requests() {
    let g = "  tune.bufsize 1024\n";
    assert_eq!(status(g, 300), OK);
    assert_eq!(status(g, 420), TOO_BIG);
}

#[test]
fn maxrewrite_at_or_above_half_the_buffer_is_half_the_buffer() {
    for m in [1024, 2048] {
        let g = format!("  tune.bufsize 1024\n  tune.maxrewrite {m}\n");
        assert_eq!(status(&g, 390), OK, "maxrewrite {m}");
        assert_eq!(status(&g, 420), TOO_BIG, "maxrewrite {m}");
    }
    let g = "  tune.bufsize 2048\n  tune.maxrewrite 4096\n";
    assert_eq!(status(g, 900), OK);
    assert_eq!(status(g, 930), TOO_BIG);
}

#[test]
fn maxrewrite_below_half_is_taken_as_set() {
    assert_eq!(status("  tune.bufsize 1024\n  tune.maxrewrite 0\n", 900), OK);
    assert_eq!(status("  tune.bufsize 1024\n  tune.maxrewrite 0\n", 930), TOO_BIG);
}

/// A `Connection: close` header is not an HTX block (HAProxy drops its tokens and the header
/// with them), so it costs the head nothing: measured, the largest `X` served at
/// `tune.bufsize 2048` is 912 with the header and without it; Ibex counted its 8-byte block.
#[test]
fn connection_close_takes_no_room_in_the_head() {
    let g = "  tune.bufsize 2048\n";
    assert_eq!(status_with(g, "Connection: close\r\n", 910), OK);
    assert_eq!(status_with(g, "Connection: close\r\n", 914), TOO_BIG);
}
