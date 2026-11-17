// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A method the `http-request` rules leave behind changes who expects a body.
//!
//! `http-request set-method HEAD` turns a client's GET into a HEAD at the server, whose
//! answer is the head alone (a `Content-Length` with no body, or a `Transfer-Encoding:
//! chunked` with no chunks). The client asked for a GET, so it waits for a body the
//! proxy will never deliver: `HAProxy` 3.5-dev11 closes the connection behind the head
//! and says so (`Connection: close`) when the head promises a `Content-Length` body, and
//! completes an empty chunked body (`0\r\n\r\n` behind the head) when it promises a
//! chunked one, keeping the connection. A request no rule changed is untouched: a HEAD
//! keeps its keep-alive, and a HEAD turned into a GET gets its head alone, its body
//! dropped, its connection kept.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev11. Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.
//! The reg-test is `http-messaging/h1_set_method_head_resp.vtc`.

use crate::common;

use std::io::{Read, Seek, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Proxy {
    child: Child,
    fe: SocketAddr,
    _cfg: NamedTempFile,
    _err: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The scripted server: a `HEAD` answers with `Content-Length: 1234` and no body, or
/// (for `/chunked`) `Transfer-Encoding: chunked` and no body; a `GET` answers with the
/// length and a 1234-byte body. It holds each connection open, so every close the client
/// sees is the proxy's decision.
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
                            w.next().unwrap_or_default(),
                            w.next().unwrap_or_default(),
                        );
                        let rsp: &[u8] = if meth.eq_ignore_ascii_case("HEAD") {
                            if path.contains("chunked") {
                                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                            } else if path.contains("bare") {
                                b"HTTP/1.1 200 OK\r\nServer: probe\r\n\r\n"
                            } else if path.contains("zero") {
                                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                            } else {
                                b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"
                            }
                        } else {
                            let mut out = Vec::with_capacity(1234 + 64);
                            out.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n");
                            out.extend_from_slice(&[b'x'; 1234]);
                            s.write_all(&out).ok();
                            thread::sleep(Duration::from_secs(10));
                            return;
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

fn start(rule: &str) -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  \
         timeout client 30s\n  timeout server 30s\n  timeout http-request 5s\n\
         frontend f\n  bind {fe}\n  {rule}\n  default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut err = NamedTempFile::new().expect("tmp2");
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(err.as_file().try_clone().unwrap()).spawn().expect("spawn");
    let ok = common::wait_listening(sentinel);
    if !ok {
        let cfg_t = std::fs::read_to_string(cfg.path()).unwrap_or_default();
        let mut t = String::new();
        let _ = err.as_file_mut().seek(std::io::SeekFrom::Start(0));
        let _ = std::io::Read::read_to_string(&mut err, &mut t);
        panic!("never listened\nconfig:\n{}\nstderr:\n{}", cfg_t, t);
    }
    Proxy { child, fe, _cfg: cfg, _err: err }
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

/// The status of the first line.
fn status_of(head: &[u8]) -> u16 {
    let text = std::str::from_utf8(head).expect("ascii head");
    text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status")
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

#[test]
fn get_to_head_cl_closes() {
    // The reg-test case: the client's GET is turned into a HEAD; the server's head-only
    // answer promises 1234 bytes the client will never get: `Connection: close`, and the
    // connection goes behind the head.
    let p = start("http-request set-method HEAD");
    let (got, closed) = exchange(&p, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "content-length").as_deref(), Some("1234"));
    assert_eq!(header(head, "connection").as_deref(), Some("close"));
    assert!(rest.is_empty(), "nothing after the head, got {:?}", rest);
    assert!(closed, "the proxy closes behind the head");
}

#[test]
fn head_alone_keeps_conn() {
    // No rule changes the method: the client's HEAD gets its head alone, its connection
    // unchanged (no `Connection`, no close).
    let p = start("http-request set-header x-noop foo if { path /never }");
    let (got, closed) = exchange(&p, b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "content-length").as_deref(), Some("1234"));
    assert_eq!(header(head, "connection"), None);
    assert!(rest.is_empty(), "nothing after the head, got {:?}", rest);
    assert!(!closed, "the connection is kept");
}

#[test]
fn head_to_get_drops_body_and_keeps_conn() {
    // The client's HEAD is turned into a GET: the server's answer carries a body the
    // client never asked for; the client gets its head alone, the body is dropped, and
    // the connection is kept (no `Connection`).
    let p = start("http-request set-method GET");
    let (got, closed) = exchange(&p, b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "content-length").as_deref(), Some("1234"));
    assert_eq!(header(head, "connection"), None);
    assert!(rest.is_empty(), "the body is not relayed, got {:?}", rest);
    assert!(!closed, "the connection is kept");
}

#[test]
fn get_to_head_chunked_terminates_and_keeps_conn() {
    // The client's GET is turned into a HEAD and the server's answer is chunked: the
    // empty chunked body the client expects is completed with the last chunk, and the
    // connection is kept.
    let p = start("http-request set-method HEAD");
    let (got, closed) = exchange(&p, b"GET /chunked HTTP/1.1\r\nHost: a\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "transfer-encoding").as_deref(), Some("chunked"));
    assert_eq!(header(head, "connection"), None);
    assert_eq!(rest, b"0\r\n\r\n", "the last chunk completes the body");
    assert!(!closed, "the connection is kept");
}

#[test]
fn get_to_head_bare_gains_chunked_and_keeps_conn() {
    // The server's answer carries no framing at all (`200`, a server line, the blank line):
    // the client's body would last until the close; the head is given the empty chunked
    // body that completes it, and the connection is kept.
    let p = start("http-request set-method HEAD");
    let (got, closed) = exchange(&p, b"GET /bare HTTP/1.1\r\nHost: a\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "transfer-encoding").as_deref(), Some("chunked"));
    assert_eq!(header(head, "connection"), None);
    assert_eq!(rest, b"0\r\n\r\n", "the last chunk completes the body");
    assert!(!closed, "the connection is kept");
}

#[test]
fn get_to_head_zero_length_keeps_conn() {
    // The server's head promises `Content-Length: 0`: the client's body is already exactly
    // what comes (nothing), and the connection is kept, without a `Connection`.
    let p = start("http-request set-method HEAD");
    let (got, closed) = exchange(&p, b"GET /zero HTTP/1.1\r\nHost: a\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "content-length").as_deref(), Some("0"));
    assert_eq!(header(head, "connection"), None);
    assert!(rest.is_empty(), "nothing after the head, got {:?}", rest);
    assert!(!closed, "the connection is kept");
}

#[test]
fn client_close_keeps_chunked_completion_and_closes() {
    // The client already asked for the close with its own `Connection: close`: the empty
    // chunked body is still completed behind the head, and the connection is closed
    // behind it, all the same.
    let p = start("http-request set-method HEAD");
    let (got, closed) =
        exchange(&p, b"GET /chunked HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "transfer-encoding").as_deref(), Some("chunked"));
    assert_eq!(header(head, "connection").as_deref(), Some("close"));
    assert_eq!(rest, b"0\r\n\r\n", "the last chunk completes the body");
    assert!(closed, "the client's close is kept");
}

#[test]
fn keep_alive_client_still_closes() {
    // The client's `Connection: keep-alive` does not stand against a body it will never
    // get: the answer is closed all the same, and says so.
    let p = start("http-request set-method HEAD");
    let (got, closed) = exchange(&p, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n");
    let (head, rest) = split_head(&got);
    assert_eq!(status_of(head), 200);
    assert_eq!(header(head, "content-length").as_deref(), Some("1234"));
    assert_eq!(header(head, "connection").as_deref(), Some("close"));
    assert!(rest.is_empty(), "nothing after the head, got {:?}", rest);
    assert!(closed, "the proxy closes behind the head");
}
