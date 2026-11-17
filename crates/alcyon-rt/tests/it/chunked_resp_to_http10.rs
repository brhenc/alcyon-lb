// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A chunked response to an HTTP/1.0 client must not stay chunked.
//!
//! HTTP/1.0 has no chunked transfer coding (RFC 9112 section 6.1): when the server
//! answers `Transfer-Encoding: chunked` and the client spoke HTTP/1.0, `HAProxy`
//! removes the header, sends the body unframed until the close, answers
//! `Connection: close` and closes the client connection behind the body. A bodyless
//! response (a `HEAD`) loses the header alone and keeps the connection's mode.
//! Responses to HTTP/1.1 clients stay chunked, and a `Content-Length` response to a
//! 1.0 client is unchanged.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev11. Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.
//! The reg-test is `http-messaging/h1_chunked_resp_to_http10.vtc`.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

const CHUNKED_RSP: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n7\r\n world!\r\n0\r\n\r\n";
const HEAD_RSP: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
const CLEN_RSP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!";

struct Proxy {
    child: Child,
    logs: mpsc::Receiver<String>,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The scripted server: `GET /chunk` answers with a chunked body, `HEAD` with a chunked
/// head and no body, `GET /cl` with a `Content-Length` body. It holds each connection
/// open after answering, so that every close the client sees is the proxy's decision.
fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            thread::spawn(move || {
                let mut req = Vec::new();
                let mut b = [0u8; 8192];
                loop {
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        let line = req.split(|&c| c == b'\n').next().unwrap_or_default();
                        let line = std::str::from_utf8(line).unwrap_or_default();
                        let mut w = line.split_whitespace();
                        let (meth, path) = (
                            w.next().unwrap_or_default().to_ascii_uppercase(),
                            w.next().unwrap_or_default(),
                        );
                        let rsp = if meth == "HEAD" {
                            HEAD_RSP
                        } else if path == "/chunk" {
                            CHUNKED_RSP
                        } else if path == "/cl" {
                            CLEN_RSP
                        } else {
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                        };
                        if s.write_all(rsp).is_err() {
                            return;
                        }
                        // Hold the connection: a close from here would be the server's,
                        // not the proxy's, and hide what the proxy decided.
                        thread::sleep(Duration::from_secs(10));
                        return;
                    }
                    match s.read(&mut b) {
                        Ok(0) => return,
                        Err(_) => break,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
            });
        }
    });
    addr
}

fn start(fe_opts: &str) -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  \
         timeout client 10s\n  timeout server 10s\n  timeout http-request 5s\n\
         frontend f\n  bind {fe}\n{fe_opts}  default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, logs, fe, _cfg: cfg }
}

/// Sends `req` and reads: what came back, and whether the proxy closed the connection
/// (a quiet of 1.5 s with no close means it kept it).
fn exchange(p: &Proxy, req: &[u8]) -> (Vec<u8>, bool) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
    c.write_all(req).expect("write");
    let mut got = Vec::new();
    let mut b = [0u8; 65536];
    loop {
        match c.read(&mut b) {
            Ok(0) => return (got, true),
            Ok(n) => got.extend_from_slice(&b[..n]),
            Err(_) => return (got, false),
        }
    }
}

/// The head (up to and including the blank line) and the rest.
fn split_head(got: &[u8]) -> (&[u8], &[u8]) {
    let pos = got.windows(4).position(|w| w == b"\r\n\r\n").expect("a head in the reply");
    (&got[..pos + 4], &got[pos + 4..])
}

/// A header value of the head, by case-insensitive name, trimmed and lower-cased.
fn header(head: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(head).expect("ascii head");
    text.lines()
        .skip(1)
        .filter_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_ascii_lowercase())
        })
        .next()
}

/// Decodes a chunked body: what it carries, or `None` if the framing does not hold.
fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(&rest[..eol])
            .ok()?
            .trim()
            .split(';')
            .next()?;
        let size = usize::from_str_radix(size, 16).ok()?;
        rest = &rest[eol + 2..];
        if rest.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
        if size == 0 {
            return Some(out);
        }
    }
}

#[test]
fn http10_get_chunked_goes_unframed_and_closes() {
    let p = start("");
    let (got, closed) = exchange(
        &p,
        b"GET /chunk HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    );
    let (head, body) = split_head(&got);
    assert!(std::str::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"), "status: {head:?}");
    assert!(header(head, "transfer-encoding").is_none(), "the chunked coding goes: {head:?}");
    assert_eq!(header(head, "connection").as_deref(), Some("close"), "the client connection closes: {head:?}");
    assert_eq!(body, b"hello world!", "the body goes unframed: {got:?}");
    assert!(closed, "the proxy closed the client connection");
}

#[test]
fn http11_get_chunked_stays_chunked() {
    let p = start("");
    let (got, closed) = exchange(&p, b"GET /chunk HTTP/1.1\r\nHost: x\r\n\r\n");
    let (head, body) = split_head(&got);
    assert!(std::str::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"), "status: {head:?}");
    assert_eq!(header(head, "transfer-encoding").as_deref(), Some("chunked"), "an HTTP/1.1 client keeps the coding: {head:?}");
    assert_eq!(dechunk(body), Some(b"hello world!".to_vec()), "the body stays chunked: {got:?}");
    assert!(!closed, "a complete chunked reply to a 1.1 client keeps the connection");
}

#[test]
fn http10_head_chunked_loses_the_header_and_keeps_the_connection() {
    let p = start("");
    let (got, closed) = exchange(
        &p,
        b"HEAD /chunk HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    );
    let (head, body) = split_head(&got);
    assert!(std::str::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"), "status: {head:?}");
    assert!(header(head, "transfer-encoding").is_none(), "the bodyless reply loses the coding: {head:?}");
    assert_eq!(header(head, "connection").as_deref(), Some("keep-alive"), "a reply without a body keeps the mode: {head:?}");
    assert_eq!(body, b"", "no body after the head: {got:?}");
    assert!(!closed, "the proxy kept the client connection");
}

#[test]
fn http10_get_chunked_with_a_response_rule_goes_unframed_and_closes() {
    // With `http-response` rules the head goes through the HTX path; the sub-1.1 rule is
    // `HAProxy`'s last word on it, after the rules (`h1_make_stline`).
    let p = start("  http-response add-header X-R: 1\n");
    let (got, closed) = exchange(
        &p,
        b"GET /chunk HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    );
    let (head, body) = split_head(&got);
    assert!(std::str::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"), "status: {head:?}");
    assert!(header(head, "transfer-encoding").is_none(), "the chunked coding goes, rules or no: {head:?}");
    assert_eq!(header(head, "connection").as_deref(), Some("close"), "the client connection closes: {head:?}");
    assert_eq!(body, b"hello world!", "the body goes unframed: {got:?}");
    assert!(closed, "the proxy closed the client connection");
}

#[test]
fn http10_content_length_unchanged() {
    let p = start("");
    let (got, closed) = exchange(
        &p,
        b"GET /cl HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    );
    let (head, body) = split_head(&got);
    assert!(std::str::from_utf8(head).unwrap().starts_with("HTTP/1.1 200"), "status: {head:?}");
    assert_eq!(header(head, "content-length").as_deref(), Some("12"), "the length stays: {head:?}");
    assert!(header(head, "transfer-encoding").is_none(), "{head:?}");
    assert_eq!(header(head, "connection").as_deref(), Some("keep-alive"), "{head:?}");
    assert_eq!(body, b"hello world!", "{got:?}");
    assert!(!closed, "a complete length-delimited reply to a 1.0 keep-alive client keeps the connection");
}
