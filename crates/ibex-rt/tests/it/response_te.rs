// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What a response with `Transfer-Encoding` becomes on the client side, and whether the
//! client connection stays open after it (T296): `chunked` next to `Content-Length`, a
//! coding other than `chunked`, several `Transfer-Encoding` lines, an HTTP/1.0 response, a
//! `HEAD` request, a body-less status. A response `HAProxy` refuses is a 502 for a `HEAD`
//! as it is for a `GET`.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29 with a raw backend.
//! Set `T296_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Proxy {
    child: Child,
    fe: SocketAddr,
    resp: Arc<Mutex<Vec<u8>>>,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers every request with the bytes in `resp`, then holds the connection
/// open for a few seconds.
fn start() -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let be = l.local_addr().unwrap();
    let resp: Arc<Mutex<Vec<u8>>> = Arc::default();
    let server_resp = Arc::clone(&resp);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let resp = Arc::clone(&server_resp);
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
                        _ => return,
                    }
                }
                let out = resp.lock().unwrap().clone();
                let _ = s.write_all(&out);
                thread::sleep(Duration::from_secs(3));
            });
        }
    });
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  tune.ibex.h1-lowercase-headers on\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T296_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().expect("spawn");
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, fe, resp, _cfg: cfg }
}

/// What the client gets for `req` when the server answers `resp`, and whether the proxy
/// closed the connection (rather than leaving it open) by the time the read gave up.
fn exchange(p: &Proxy, resp: &[u8], req: &[u8]) -> (Vec<u8>, bool) {
    *p.resp.lock().unwrap() = resp.to_vec();
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
    c.write_all(req).unwrap();
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        match c.read(&mut b) {
            Ok(0) => return (got, true),
            Ok(n) => got.extend_from_slice(&b[..n]),
            Err(_) => return (got, false),
        }
    }
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
const HEAD: &[u8] = b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n";
const BAD: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 107\r\ncache-control: no-cache\r\ncontent-type: text/html\r\n\r\n\
<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n";
const BAD_HEAD: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 107\r\ncache-control: no-cache\r\ncontent-type: text/html\r\n\r\n";
const BODY: &[u8] = b"5\r\nhello\r\n0\r\n\r\n";

/// A case: what it is, the server's answer, the request, what the client gets, and whether
/// the proxy closes the connection.
type Case<'a> = (&'a str, &'a [u8], &'a [u8], Vec<u8>, bool);

fn check(name: &str, cases: &[Case<'_>]) {
    let p = start();
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(what, resp, req, want, want_closed)| {
            let (got, closed) = exchange(&p, resp, req);
            (got != *want || closed != *want_closed).then(|| {
                format!("{what}: got {} closed={closed}, want {} closed={want_closed}", got.escape_ascii(), want.escape_ascii())
            })
        })
        .collect();
    assert!(wrong.is_empty(), "{name}: differ from HAProxy:\n{}", wrong.join("\n"));
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `chunked` and `Content-Length` together: the length goes, the response stays chunked and
/// the client connection stays open. A coding that is not `chunked`, a repeated or empty
/// one, is a 502 for a `GET` and for a `HEAD`.
#[test]
fn transfer_encoding_on_an_http11_response() {
    let ok = cat(&[b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n", BODY]);
    check(
        "http/1.1",
        &[
            ("chunked + content-length", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", BODY]), GET, ok.clone(), false),
            ("content-length, chunked", &cat(&[b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", BODY]), GET, ok.clone(), false),
            ("upper case", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n", BODY]), GET, ok.clone(), false),
            ("blanks around", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding:   chunked  \r\n\r\n", BODY]), GET, ok, false),
            ("gzip, chunked", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", BODY]), GET, BAD.to_vec(), false),
            ("gzip", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nhello", GET, BAD.to_vec(), false),
            ("chunked, gzip", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", BODY]), GET, BAD.to_vec(), false),
            ("two lines", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n", BODY]), GET, BAD.to_vec(), false),
            ("chunked twice", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", BODY]), GET, BAD.to_vec(), false),
            ("empty", b"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n\r\nhello", GET, BAD.to_vec(), false),
            ("trailing comma", &cat(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\n\r\n", BODY]), GET, BAD.to_vec(), false),
            // The same answers to a HEAD: the head of the 502, no body, the connection open.
            ("HEAD gzip", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nhello", HEAD, BAD_HEAD.to_vec(), false),
            ("HEAD chunked twice", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", HEAD, BAD_HEAD.to_vec(), false),
        ],
    );
}

/// `Transfer-Encoding` in an HTTP/1.0 response: forwarded as it came, but it ends the
/// client connection too, and an announced `Connection: keep-alive` is not kept.
#[test]
fn transfer_encoding_on_an_http10_response() {
    let ok = cat(&[b"HTTP/1.0 200 OK\r\ntransfer-encoding: chunked\r\n\r\n", BODY]);
    let head = b"HTTP/1.0 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
    check(
        "http/1.0",
        &[
            ("chunked", &cat(&[b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", BODY]), GET, ok.clone(), true),
            ("chunked + content-length", &cat(&[b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n", BODY]), GET, ok.clone(), true),
            ("chunked, keep-alive", &cat(&[b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n", BODY]), GET, ok, true),
            ("HEAD", &cat(&[b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"]), HEAD, head, true),
            // Not the same: no `Transfer-Encoding`, the connection is kept for a 1.1 client.
            (
                "content-length, keep-alive",
                b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
                GET,
                b"HTTP/1.0 200 OK\r\ncontent-length: 5\r\nconnection: keep-alive\r\n\r\nhello".to_vec(),
                false,
            ),
        ],
    );
}

/// A status that has no body does not carry the coding; the other statuses keep it.
#[test]
fn transfer_encoding_on_a_response_without_a_body() {
    check(
        "no body",
        &[
            ("204", b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n", GET, b"HTTP/1.1 204 No Content\r\n\r\n".to_vec(), false),
            (
                "304",
                b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
                GET,
                b"HTTP/1.1 304 Not Modified\r\ntransfer-encoding: chunked\r\n\r\n".to_vec(),
                false,
            ),
            (
                "103 then 200",
                b"HTTP/1.1 103 Early\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                GET,
                b"HTTP/1.1 103 Early\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
                false,
            ),
        ],
    );
}
