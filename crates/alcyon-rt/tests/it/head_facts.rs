// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T436: the proxy reads what it needs of a head (its HTX size, its `Connection` tokens, its
//! body framing, its `Connection` lines) in one pass, `txn::HeadFacts`, and the parser notes
//! which of `Content-Length`, `Transfer-Encoding`, `Connection` and `Upgrade` a head has as it
//! parses it. Each case here is a head whose handling hangs on one of those facts, alone or
//! with a rule that edits the header after the facts were read. Every expected value was
//! measured on `HAProxy 3.5-dev8-885761-29` (2026-10-19) with a raw-socket client and server
//! (`nbthread 1`, `timeout client 5s`): what the server got, what the client got, and whether
//! the client connection was closed after it.
//!
//! `T436_ORACLE=/path/to/haproxy` runs the same assertions on the reference binary.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Proc {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers every head it reads with `resp`, and records each head (without its
/// blank line) and, after a `content-length: 2` head, the two bytes of its body.
fn server(resp: &'static [u8]) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    let got = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&got);
    thread::spawn(move || {
        for c in l.incoming().flatten() {
            let seen = Arc::clone(&seen);
            thread::spawn(move || {
                let mut c = c;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while let Ok(n) = c.read(&mut chunk) {
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..at]).into_owned();
                        let mut used = at + 4;
                        let body = head.to_ascii_lowercase().contains("content-length: 2") && buf.len() >= used + 2;
                        seen.lock().unwrap().push(head);
                        if body {
                            seen.lock().unwrap().push(String::from_utf8_lossy(&buf[used..used + 2]).into_owned());
                            used += 2;
                        }
                        buf.drain(..used);
                        if c.write_all(resp).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    (addr, got)
}

/// Sends `req` through a proxy running `rules` in its frontend to a server answering `resp`:
/// what the server got, what the client got, and whether the proxy closed the client side.
fn exchange(rules: &str, req: &[u8], resp: &'static [u8]) -> (Vec<String>, String, bool) {
    let (srv, got) = server(resp);
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  tune.alcyon.h1-lowercase-headers on\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n{rules}  default_backend b\nbackend b\n  server s1 {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let bin = std::env::var("T436_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let _proc = Proc { child, _cfg: f };
    assert!(common::wait_listening(fe), "never listened with:\n{text}");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(500))).ok();
    c.write_all(req).expect("send");
    let (mut out, mut closed) = (Vec::new(), false);
    let mut chunk = [0u8; 4096];
    loop {
        match c.read(&mut chunk) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let seen = got.lock().unwrap().clone();
    (seen, String::from_utf8_lossy(&out).into_owned(), closed)
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";

fn check(name: &str, rules: &str, req: &[u8], resp: &'static [u8], srv: &[&str], client: &str, closed: bool) {
    let (s, c, cl) = exchange(rules, req, resp);
    assert_eq!((s.iter().map(String::as_str).collect::<Vec<_>>(), c.as_str(), cl), (srv.to_vec(), client, closed), "{name}");
}

/// The facts of the response head without rules: its `Connection` tokens go, the ones the
/// client connection calls for come in, and its framing is relayed.
#[test]
fn a_response_is_relayed_by_its_facts() {
    let host = "GET / HTTP/1.1\r\nhost: a";
    check(
        "Connection: close from the server",
        "",
        GET,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        &[host],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        false,
    );
    check(
        "keep-alive and another token",
        "",
        GET,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive, te\r\n\r\nok",
        &[host],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: te\r\n\r\nok",
        false,
    );
    check(
        "chunked to an HTTP/1.0 keep-alive client",
        "",
        b"GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        &["GET / HTTP/1.0\r\nhost: a\r\nconnection: keep-alive"],
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: keep-alive\r\n\r\n2\r\nok\r\n0\r\n\r\n",
        false,
    );
}

/// The facts of the request head: HTTP/1.0 without `keep-alive` closes, `Content-Length`
/// frames the body, `close` closes and its other tokens go on.
#[test]
fn a_request_is_handled_by_its_facts() {
    check(
        "HTTP/1.0",
        "",
        b"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
        OK,
        &["GET / HTTP/1.0\r\nhost: a\r\nconnection: keep-alive"],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    );
    check(
        "a body by its length",
        "",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi",
        OK,
        &["POST / HTTP/1.1\r\nhost: a\r\ncontent-length: 2", "hi"],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        false,
    );
    check(
        "close and another token",
        "",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close, foo\r\n\r\n",
        OK,
        &["GET / HTTP/1.1\r\nhost: a\r\nconnection: foo"],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    );
}

/// A rule that edits a header the facts were read from: the client side keeps what the head
/// said when it was parsed, as `HAProxy` keeps `h1m->flags`, and the header goes on as the
/// rule left it.
#[test]
fn a_rule_editing_a_header_after_its_facts() {
    let host = "GET / HTTP/1.1\r\nhost: a";
    check(
        "the client's Connection: close deleted",
        "  http-request del-header connection\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
        OK,
        &[host],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    );
    check(
        "keep-alive set on an HTTP/1.0 request",
        "  http-request set-header connection keep-alive\n",
        b"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
        OK,
        &["GET / HTTP/1.0\r\nhost: a\r\nconnection: keep-alive"],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
        true,
    );
    check("Host set", "  http-request set-header host b\n", GET, OK, &["GET / HTTP/1.1\r\nhost: b"], "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok", false);
    check(
        "the server's Connection: close deleted",
        "  http-response del-header connection\n",
        GET,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        &[host],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        false,
    );
}

/// T436 C: a header value with obs-text (Latin-1 bytes, not UTF-8) is a header like any other
/// for every reader of the request: it is found, counted and fetched as its bytes, and a `Host`
/// after it is still found. (Measured on 3.5-dev8 alongside the cases above.)
#[test]
fn an_obs_text_header_value_is_read_as_its_bytes() {
    let ret = "  http-request return status 200 content-type text/plain lf-string ";
    let obs = b"GET / HTTP/1.1\r\nHost: a\r\nX-Foo: \xe9t\xe9\r\n\r\n";
    let reply = |body: &str| format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n\r\n{body}", body.len());
    check(
        "forwardfor if-none",
        "  option forwardfor if-none\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: 1.2.3.\xe9\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nbe",
        &["GET / HTTP/1.1\r\nhost: a\r\nx-forwarded-for: 1.2.3.\u{fffd}"],
        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nbe",
        false,
    );
    check("found", &format!("{ret}found if {{ req.hdr(x-foo) -m found }}\n"), obs, OK, &[], &reply("found"), false);
    check("hdr_cnt", &format!("{ret}n=%[req.hdr_cnt(x-foo)]\n"), obs, OK, &[], &reply("n=1"), false);
    check("hdr", &format!("{ret}v=%[req.hdr(x-foo),hex]\n"), obs, OK, &[], &reply("v=E974E9"), false);
    check("fhdr", &format!("{ret}v=%[req.fhdr(x-foo),hex]\n"), obs, OK, &[], &reply("v=E974E9"), false);
    check("hdrs", &format!("{ret}l=%[req.hdrs,length]\n"), obs, OK, &[], &reply("l=23"), false);
    check(
        "Host after it",
        &format!("{ret}h=%[req.hdr(host)]\n"),
        b"GET / HTTP/1.1\r\nX-Foo: \xe9t\xe9\r\nHost: a\r\n\r\n",
        OK,
        &[],
        &reply("h=a"),
        false,
    );
    check("forwarded", "", obs, OK, &["GET / HTTP/1.1\r\nhost: a\r\nx-foo: \u{fffd}t\u{fffd}"], "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok", false);
}

/// More `Transfer-Encoding` lines than the scan keeps (four), and a response head with a byte
/// that is not ASCII, are heads the facts are not read from: they take the general reading, and
/// relay as it always did.
#[test]
fn heads_the_facts_are_not_read_from() {
    check(
        "five Transfer-Encoding lines",
        "",
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        OK,
        &[],
        "HTTP/1.1 422 Unprocessable Content\r\ncontent-length: 116\r\ncache-control: no-cache\r\ncontent-type: text/html\r\n\r\n<html><body><h1>422 Unprocessable Content</h1>\nThe server cannot process the contained instructions.\n</body></html>\n",
        true,
    );
    check(
        "a response with obs-text",
        "",
        GET,
        b"HTTP/1.1 200 OK\r\nX-Foo: \xe9\r\nContent-Length: 2\r\n\r\nok",
        &["GET / HTTP/1.1\r\nhost: a"],
        "HTTP/1.1 200 OK\r\nx-foo: \u{fffd}\r\ncontent-length: 2\r\n\r\nok",
        false,
    );
}
