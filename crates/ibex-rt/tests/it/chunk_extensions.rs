// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Chunk extensions and chunk-size lines as `HAProxy` forwards them (tasks/T302 item 5,
//! left open by T291).
//!
//! `HAProxy` parses a chunked body into HTX and writes it out again: every chunk extension
//! is dropped (`5;a=b` goes out as `5`), and the size is written in upper-case hex without
//! leading zeros (`0005` and `a` go out as `5` and `A`), in both directions. A proxy that
//! relays the size line as received hands the next hop bytes it may read otherwise -- the
//! request-smuggling class. A control character, a bare CR or a bare LF in the line is a
//! 400 (a 502 from a server) and nothing is forwarded.
//!
//! Each case sends a whole message in one write and compares the body bytes the other side
//! receives. The expected values were measured on `HAProxy` 3.5-dev8; set
//! `T302_ORACLE=/path/to/haproxy` to run the same cases against it. (`HAProxy` also merges
//! the chunks it has in its buffer at once into one, `A` and `3` into `D`: that depends on
//! how the bytes arrive, Ibex keeps the chunks as received, and no case here has two.)

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

type Recorded = Arc<Mutex<Vec<Vec<u8>>>>;

/// A server that records each connection's bytes until it has been quiet for 300 ms, and
/// writes `answer` (a `200` with `Connection: close` when it is empty) for each message it
/// has whole (a `GET` head, or a chunked body's end), or once when it falls quiet with
/// none.
fn backend(answer: Arc<Mutex<Vec<u8>>>) -> (SocketAddr, Recorded) {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let conns: Recorded = Arc::default();
    let c2 = Arc::clone(&conns);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let (c3, answer) = (Arc::clone(&c2), Arc::clone(&answer));
            thread::spawn(move || {
                let mut answer = answer.lock().unwrap().clone();
                if answer.is_empty() {
                    answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
                }
                let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
                let (mut rec, mut buf, mut answered) = (Vec::new(), vec![0u8; 65536], 0);
                while let Ok(n @ 1..) = s.read(&mut buf) {
                    rec.extend_from_slice(&buf[..n]);
                    let whole = rec.windows(4).filter(|w| *w == b"GET ").count() + rec.windows(7).filter(|w| *w == b"\r\n0\r\n\r\n").count();
                    for _ in answered..whole {
                        let _ = s.write_all(&answer);
                    }
                    answered = whole;
                }
                if answered == 0 {
                    let _ = s.write_all(&answer);
                }
                c3.lock().unwrap().push(rec);
            });
        }
    });
    (addr, conns)
}

struct Proxy {
    child: Child,
    addr: SocketAddr,
    conns: Recorded,
    answer: Arc<Mutex<Vec<u8>>>,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn proxy() -> Proxy {
    let answer = Arc::default();
    let (be, conns) = backend(Arc::clone(&answer));
    let addr = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 3s\n    timeout server 3s\n    \
         timeout connect 1s\nfrontend f\n    bind {addr}\n    default_backend b\nbackend b\n    server s {be}\n"
    )
    .expect("write cfg");
    let bin = std::env::var("T302_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn proxy");
    assert!(common::wait_listening(addr), "proxy never listened");
    Proxy { child, addr, conns, answer, _cfg: cfg }
}

/// What follows the first blank line of `b`.
fn body(b: &[u8]) -> Vec<u8> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map_or_else(Vec::new, |p| b[p + 4..].to_vec())
}

/// Sends `raw`; returns what came back (read until the proxy closes or has been quiet for
/// 800 ms) and the bytes of each server connection it opened.
fn exchange(p: &Proxy, raw: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let before = p.conns.lock().unwrap().len();
    let mut c = TcpStream::connect(p.addr).expect("connect");
    c.write_all(raw).expect("send");
    let _ = c.set_read_timeout(Some(Duration::from_millis(800)));
    let (mut out, mut buf) = (Vec::new(), [0u8; 16384]);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => break,
        }
    }
    drop(c);
    thread::sleep(Duration::from_millis(100));
    let fwd = p.conns.lock().unwrap()[before..].to_vec();
    (out, fwd)
}

const POST: &[u8] = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";

/// Request bodies: the body sent, the status answered, the body the server gets (`None`:
/// no server connection).
#[test]
fn request_chunk_lines_are_rewritten_as_haproxy_does() {
    let p = proxy();
    let cases: &[(&[u8], &[u8], Option<&[u8]>)] = &[
        (b"5;a=b\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5;a=\"q v;x\"\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5;a=b;c;d=e\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5\r\nhello\r\n0;last=1\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5;\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5 ;a=b\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5\t;a=b\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5; a = b\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5 \r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"5;a=\xff\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"0005\r\nhello\r\n0\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\n\r\n")),
        (b"a;x\r\n0123456789\r\n0\r\n\r\n", b"200", Some(b"A\r\n0123456789\r\n0\r\n\r\n")),
        (b"00\r\n\r\n", b"200", Some(b"0\r\n\r\n")),
        (b"0000;x=y\r\n\r\n", b"200", Some(b"0\r\n\r\n")),
        // With a trailer section: the last-chunk line rewritten, the section kept (its
        // field names lower-cased by HAProxy, which Ibex does not do yet: none here).
        (b"5;a=b\r\nhello\r\n00;z\r\nx-t: 1\r\n\r\n", b"200", Some(b"5\r\nhello\r\n0\r\nx-t: 1\r\n\r\n")),
        // A control character, a bare LF or a bare CR in the line: 400, nothing forwarded.
        (b"5;a\x01\r\nhello\r\n0\r\n\r\n", b"400", None),
        (b"5;a\nb\r\nhello\r\n0\r\n\r\n", b"400", None),
        (b"5;a\rb\r\nhello\r\n0\r\n\r\n", b"400", None),
        (b"5;a=b\nhello\r\n0\r\n\r\n", b"400", None),
    ];
    let mut bad = Vec::new();
    for &(sent, status, want) in cases {
        let (out, fwd) = exchange(&p, &[POST, sent].concat());
        let got_status = out.get(9..12).unwrap_or_default();
        let got: Option<Vec<u8>> = fwd.first().map(|f| body(f));
        if got_status != status || got.as_deref() != want || fwd.len() > 1 {
            bad.push(format!(
                "{:?}: answered {:?}, server got {:?}, want {:?} and {:?}",
                String::from_utf8_lossy(sent),
                String::from_utf8_lossy(got_status),
                fwd.iter().map(|f| String::from_utf8_lossy(&body(f)).into_owned()).collect::<Vec<_>>(),
                String::from_utf8_lossy(status),
                want.map(String::from_utf8_lossy),
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ from HAProxy:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

/// The same rewrite of a two-request pipeline: the second request's chunk lines too, and
/// nothing of the second leaks into the first.
#[test]
fn a_pipelined_request_has_its_chunk_lines_rewritten_too() {
    let p = proxy();
    *p.answer.lock().unwrap() = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
    let one = [POST, b"5;a=b\r\nhello\r\n0;e\r\n\r\n"].concat();
    let (out, fwd) = exchange(&p, &[one.as_slice(), one.as_slice()].concat());
    assert!(out.starts_with(b"HTTP/1.1 200"), "answered {:?}", String::from_utf8_lossy(&out));
    let all = fwd.concat().to_ascii_lowercase();
    let want = [POST, b"5\r\nhello\r\n0\r\n\r\n"].concat().to_ascii_lowercase();
    assert_eq!(all.windows(want.len()).filter(|w| *w == want.as_slice()).count(), 2, "server got {:?}", String::from_utf8_lossy(&all));
    assert_eq!(all.len(), 2 * want.len(), "server got {:?}", String::from_utf8_lossy(&all));
}

/// Response bodies: the server's body, and what the client gets after the head, with the
/// server closing after its response and with it keeping the connection.
#[test]
fn response_chunk_lines_are_rewritten_as_haproxy_does() {
    let p = proxy();
    let cases: &[(&[u8], &[u8])] = &[
        (b"5;a=b\r\nhello\r\n0;z=1\r\n\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
        (b"0005;x\r\nhello\r\n0\r\n\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
        (b"a ; x=\"y\"\r\n0123456789\r\n0\r\n\r\n", b"A\r\n0123456789\r\n0\r\n\r\n"),
        (b"5;\r\nhello\r\n0\r\n\r\n", b"5\r\nhello\r\n0\r\n\r\n"),
    ];
    let mut bad = Vec::new();
    for close in ["Connection: close\r\n", ""] {
        for &(sent, want) in cases {
            *p.answer.lock().unwrap() = [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n", close.as_bytes(), b"\r\n", sent].concat();
            let (out, _) = exchange(&p, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
            if body(&out) != want {
                bad.push(format!("{close:?} {:?}: client got {:?}", String::from_utf8_lossy(sent), String::from_utf8_lossy(&out)));
            }
        }
    }
    assert!(bad.is_empty(), "{} cases differ from HAProxy:\n{}", bad.len(), bad.join("\n"));
}

/// A size line with a control character in it from the server: 502, as `HAProxy` answers,
/// and none of the body.
#[test]
fn a_response_chunk_line_with_a_control_character_is_a_502() {
    let p = proxy();
    *p.answer.lock().unwrap() = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;a\x01\r\nhello\r\n0\r\n\r\n".to_vec();
    let (out, _) = exchange(&p, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(out.starts_with(b"HTTP/1.1 502"), "client got {:?}", String::from_utf8_lossy(&out));
    assert!(!out.windows(5).any(|w| w == b"hello"), "client got {:?}", String::from_utf8_lossy(&out));
}
