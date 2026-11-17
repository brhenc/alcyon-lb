// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The built-in error pages, byte for byte, as they reach the client socket.
//!
//! `HAProxy` keeps the built-in pages (`http_err_msgs`) in two wire forms. Before the
//! request is an HTX message -- a refused head, the `timeout client` of a head that never
//! completes -- the raw page text goes out (its `connection: close` between
//! `cache-control` and `content-type`, header names lower-cased on the wire). Once the head
//! is parsed and the request is an HTX message -- the `timeout client` of a body that does
//! not come in time under `option http-buffer-request`, a `deny`, a `503` with no server --
//! `HAProxy` builds the reply itself: `content-length`, `cache-control`, `content-type`, and
//! for the 400 and 408 the `connection: close` it adds last, after `content-type`.
//!
//! Every expected value below is the exact byte sequence measured on `HAProxy`
//! 3.5-dev8-885761-29 on the client socket, for the five answers this file covers. Set
//! `ERRWIRE_ORACLE=/path/to/haproxy` to run the same tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// The proxy under test: `ERRWIRE_ORACLE` (a `HAProxy` binary) when set, the `alcyon` this
/// build made otherwise.
fn bin() -> String {
    std::env::var("ERRWIRE_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct Proxy {
    child: Child,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Spawns the proxy on `cfg` (already holding the addresses) and waits for `fe`.
fn start(cfg: &str, fe: SocketAddr) -> Proxy {
    let mut c = NamedTempFile::new().expect("tmp");
    write!(c, "{cfg}").expect("write");
    let mut child = Command::new(bin())
        .arg("-f")
        .arg(c.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    if !common::wait_listening(fe) {
        child.kill().ok();
        let out = child.wait_with_output();
        eprintln!("proxy died; stderr: {}", String::from_utf8_lossy(&out.as_ref().map_or(&[] as &[u8], |o| o.stderr.as_slice())));
        panic!("never listened on {fe}");
    }
    Proxy { child, fe, _cfg: c }
}

/// Connects, sends `send`, goes quiet for `quiet`, then reads until the proxy closes: the
/// exact bytes the client socket received, in the order they arrived.
fn exchange(fe: SocketAddr, send: &[u8], quiet: Duration) -> Vec<u8> {
    let mut c = std::net::TcpStream::connect(fe).expect("connect");
    c.write_all(send).expect("write");
    if quiet != Duration::ZERO {
        thread::sleep(quiet);
    }
    c.set_read_timeout(Some(Duration::from_millis(200))).expect("read timeout");
    let started = Instant::now();
    let mut got = Vec::new();
    let mut idle_since = None;
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) => break,
            Ok(n) => {
                got.extend_from_slice(&b[..n]);
                idle_since = None;
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => match idle_since {
                // Nothing yet: the `timeout client` has not run out (bounded, so a proxy
                // that sends nothing at all fails with an empty `got`, not a hang).
                None if got.is_empty() && started.elapsed() < Duration::from_secs(10) => continue,
                // Bytes arrived: a short idle gap is TCP, a sustained one means the reply
                // is whole and the connection is closing behind it.
                None => idle_since = Some(Instant::now()),
                Some(t) if t.elapsed() < Duration::from_millis(500) => continue,
                _ => break,
            },
            Err(_) => break,
        }
    }
    got
}

/// The head of a response, from its start to the blank line.
fn head_of(got: &[u8]) -> String {
    let end = got.windows(4).position(|w| w == b"\r\n\r\n").map_or(got.len(), |i| i + 4);
    String::from_utf8_lossy(&got[..end]).to_string()
}

/// What the `assert_eq!` failure prints: both heads, then the whole reply escaped.
fn diff(got: &[u8], want: &[u8]) -> String {
    let esc = |b: &[u8]| {
        let s = b.escape_ascii().to_string();
        if s.len() > 400 {
            format!("{}... ({} bytes)", &s[..400], b.len())
        } else {
            s
        }
    };
    format!(
        "got {} byte(s)\nhead: {g}\nbytes: {gb}\n--- want {w} byte(s)\nhead: {wh}\nbytes: {wb}",
        got.len(),
        g = head_of(got),
        gb = esc(got),
        w = want.len(),
        wh = head_of(want),
        wb = esc(want),
    )
}

#[test]
fn a_408_of_a_body_that_does_not_come_in_time() {
    // The head is accepted (the request is an HTX message) and then only part of the body
    // comes: the frontend's `option http-buffer-request` holds the request for its body, and
    // `timeout client` (1s in the config) runs out in the wait. The proxy answers 408 and
    // closes. Measured on 3.5-dev8: `content-type` before `connection`.
    let fe = common::reserve_addr();
    let be = common::reserve_addr();
    let cfg = format!(
        "global\n  maxconn 128\n\
         defaults\n  mode http\n  timeout client 1s\n  timeout connect 5s\n  timeout server 5s\n  timeout http-request 5s\n  timeout http-keep-alive 5s\n\
         frontend f\n  bind {fe}\n  option http-buffer-request\n  default_backend b\n\
         backend b\n  server s {be}\n"
    );
    let p = start(&cfg, fe);
    let got = exchange(p.fe, b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nhello", Duration::from_millis(1500));
    let want = b"HTTP/1.1 408 Request Time-out\r\ncontent-length: 110\r\ncache-control: no-cache\r\ncontent-type: text/html\r\nconnection: close\r\n\r\n<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n";
    assert_eq!(got, want, "408 of a body that does not come in time: {}", diff(&got, want));
}

#[test]
fn a_408_of_a_head_that_never_completes() {
    // No `option http-buffer-request` here (the default, the config sets it for nothing):
    // the client sends part of a request head and no more. The head never completes, the
    // request is not an HTX message, and `timeout client` (1s) running out sends the raw
    // built-in 408 page: `connection` before `content-type`.
    let fe = common::reserve_addr();
    let be = common::reserve_addr();
    let cfg = format!(
        "global\n  maxconn 128\n\
         defaults\n  mode http\n  timeout client 1s\n  timeout connect 5s\n  timeout server 5s\n  timeout http-request 5s\n  timeout http-keep-alive 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  server s {be}\n"
    );
    let p = start(&cfg, fe);
    let got = exchange(p.fe, b"POST /b HTTP/1.1\r\nHost: x\r\nCont", Duration::from_millis(1500));
    let want = b"HTTP/1.1 408 Request Time-out\r\ncontent-length: 110\r\ncache-control: no-cache\r\nconnection: close\r\ncontent-type: text/html\r\n\r\n<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n";
    assert_eq!(got, want, "408 of a head that never completes: {}", diff(&got, want));
}

#[test]
fn a_400_of_a_malformed_request_head() {
    // A head that is a head on the wire but refuses to parse: the header line `NoColon` has
    // no colon. The refusal is instant (no waiting), the request is not an HTX message, and
    // the raw built-in 400 page goes out: `connection` before `content-type`.
    let fe = common::reserve_addr();
    let be = common::reserve_addr();
    let cfg = format!(
        "global\n  maxconn 128\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n  timeout http-request 5s\n  timeout http-keep-alive 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  server s {be}\n"
    );
    let p = start(&cfg, fe);
    let got = exchange(p.fe, b"GET / HTTP/1.1\r\nNoColon\r\n\r\n", Duration::ZERO);
    let want = b"HTTP/1.1 400 Bad request\r\ncontent-length: 90\r\ncache-control: no-cache\r\nconnection: close\r\ncontent-type: text/html\r\n\r\n<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n";
    assert_eq!(got, want, "400 of a malformed head: {}", diff(&got, want));
}

#[test]
fn a_403_of_an_http_request_deny() {
    // A complete request the frontend's `http-request deny` refuses: the built-in 403 page,
    // with no `connection` header at all.
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  maxconn 128\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n  timeout http-request 5s\n  timeout http-keep-alive 5s\n\
         frontend f\n  bind {fe}\n  http-request deny\n"
    );
    let p = start(&cfg, fe);
    let got = exchange(p.fe, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Duration::ZERO);
    let want = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 93\r\ncache-control: no-cache\r\ncontent-type: text/html\r\n\r\n<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n";
    assert_eq!(got, want, "403 of http-request deny: {}", diff(&got, want));
}

#[test]
fn a_503_of_a_backend_with_no_server() {
    // A complete request routed to a backend that has no `server` line: the built-in 503
    // page, with no `connection` header at all.
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  maxconn 128\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n  timeout http-request 5s\n  timeout http-keep-alive 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n"
    );
    let p = start(&cfg, fe);
    let got = exchange(p.fe, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Duration::ZERO);
    let want = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 107\r\ncache-control: no-cache\r\ncontent-type: text/html\r\n\r\n<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n";
    assert_eq!(got, want, "503 of a backend with no server: {}", diff(&got, want));
}
