// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The request line as `HAProxy`'s H1 parser reads it (`h1_headers_to_hdr_list`,
//! `h1_process_req_vsn`), and a head ended by a bare LF (tasks/T291, from the differential
//! fuzzer's `fuzz/known_diffs.json`).
//!
//! A method is a token, then spaces or tabs, a target of the bytes 0x21 to 0x7e, spaces or
//! tabs, and `HTTP/<digit>.<digit>` right before the line's end. Any other byte is a 400 and
//! nothing reaches the server -- a proxy that forwards what its neighbour refuses is the
//! request-smuggling class. A line `HAProxy` accepts goes to the server rewritten: one space
//! between the parts, and `HTTP/1.1` for any version from 1.1 up.
//!
//! Each case sends raw bytes on one connection and checks every status line answered and
//! the bytes each server connection received (the server answers with `Connection: close`,
//! so a second request comes on a new one). The expected values were measured on `HAProxy`
//! 3.5-dev8; set `T291_ORACLE=/path/to/haproxy` to run the same cases against it.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

type Recorded = Arc<Mutex<Vec<Arc<Mutex<Vec<u8>>>>>>;

/// A server that records each connection's bytes, answers `200` with `Connection: close`
/// once it has a whole head, and closes when the client has been quiet for 150 ms.
fn backend() -> (SocketAddr, Recorded) {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let conns: Recorded = Arc::default();
    let c2 = Arc::clone(&conns);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let rec = Arc::new(Mutex::new(Vec::new()));
            c2.lock().unwrap().push(Arc::clone(&rec));
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
                let (mut buf, mut answered) = (vec![0u8; 65536], false);
                loop {
                    match s.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            let mut r = rec.lock().unwrap();
                            r.extend_from_slice(&buf[..n]);
                            let eoh = r.windows(4).any(|w| w == b"\r\n\r\n") || r.windows(2).any(|w| w == b"\n\n");
                            if !answered && eoh {
                                answered = true;
                                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                                let _ = s.set_read_timeout(Some(Duration::from_millis(150)));
                            }
                        }
                        _ => return,
                    }
                }
            });
        }
    });
    (addr, conns)
}

struct Proxy {
    child: Child,
    addr: SocketAddr,
    conns: Recorded,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn proxy() -> Proxy {
    let (be, conns) = backend();
    let addr = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n  tune.alcyon.h1-lowercase-headers on\n    nbthread 1\n    tune.bufsize 32768\ndefaults\n    mode http\n    timeout client 3s\n    \
         timeout server 3s\n    timeout connect 1s\n    timeout http-request 3s\nfrontend f\n    bind {addr}\n    \
         default_backend b\nbackend b\n    server s {be}\n"
    )
    .expect("write cfg");
    let bin = std::env::var("T291_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn proxy");
    assert!(common::wait_listening(addr), "proxy never listened");
    Proxy { child, addr, conns, _cfg: cfg }
}

/// Sends `raw` and returns the statuses answered (read until the proxy closes or has been
/// quiet for 600 ms) and the bytes of each server connection it opened.
fn exchange(p: &Proxy, raw: &[u8]) -> (Vec<u16>, Vec<Vec<u8>>) {
    let before = p.conns.lock().unwrap().len();
    let mut c = TcpStream::connect(p.addr).expect("connect");
    c.write_all(raw).expect("send");
    let _ = c.set_read_timeout(Some(Duration::from_millis(600)));
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
    thread::sleep(Duration::from_millis(300));
    let statuses = out
        .windows(12)
        .filter(|w| w.starts_with(b"HTTP/1.1 ") || w.starts_with(b"HTTP/1.0 "))
        .filter_map(|w| std::str::from_utf8(&w[9..12]).ok()?.parse().ok())
        .collect();
    let fwd = p.conns.lock().unwrap()[before..].iter().map(|r| r.lock().unwrap().clone()).collect();
    (statuses, fwd)
}

/// One case: the bytes sent, the statuses `HAProxy` answers, what each server connection gets.
type Case<'a> = (&'a [u8], &'a [u16], &'a [&'a [u8]]);

fn check(p: &Proxy, cases: &[Case<'_>]) {
    let mut bad = Vec::new();
    for &(raw, want_st, want_fwd) in cases {
        let (st, fwd) = exchange(p, raw);
        let want_fwd: Vec<Vec<u8>> = want_fwd.iter().map(|f| f.to_vec()).collect();
        if st != want_st || fwd != want_fwd {
            bad.push(format!(
                "{:?}\n   answered {st:?}, want {want_st:?}\n   forwarded {:?}\n   want      {:?}",
                String::from_utf8_lossy(raw),
                fwd.iter().map(|f| String::from_utf8_lossy(f).into_owned()).collect::<Vec<_>>(),
                want_fwd.iter().map(|f| String::from_utf8_lossy(f).into_owned()).collect::<Vec<_>>(),
            ));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ from HAProxy:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

const NOTHING: &[&[u8]] = &[];

/// Bytes `HAProxy` refuses in a request line: 400 and nothing forwarded (`known_diffs`
/// 003e1754, aacc58d3, b37e99b4, afb64d2a, be877190, 0e5159c6, daaf9617, ...).
#[test]
fn a_request_line_with_a_forbidden_byte_is_refused() {
    let p = proxy();
    check(
        &p,
        &[
            (b"HEAD /\0bad HTTP/1.1\nHost: example.com\r\n\r\n", &[400], NOTHING),
            (b"GET /ind\0x.html HTTP/1.1\r\nHost: example.com\r\n\r\n", &[400], NOTHING),
            (b"G\0T / HTTP/1.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET / HTTP\x001.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"G:T /mixed HTTP/1.1\r\nHost: example.com\nX-Header: value\n\n", &[400], NOTHING),
            (b"PO:T /smuggle HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\nabcdef", &[400], NOTHING),
            (b"GET /a b HTTP/1.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET / TTP/1.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET / HTTP:1.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET / HTTP/\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET /x\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET  /\x01\tHTTP/1.1\r\nHost: example.com\n\nPOST /c HTTP/1.1\r\nHost: e\r\nContent-Length: 0\r\n\r\n", &[400], NOTHING),
            (b"GET\x0b/\x01\x0cHTTP/1.2\nHost: example.com\r\n\n", &[400], NOTHING),
            (b"get\x0b/a b HTTP/1.1\nHost: example.com\n\r\n", &[400], NOTHING),
            (b"GET / HTTP/1.1 \n\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET /\x7f HTTP/1.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"GET /\xc3\xa9 HTTP/1.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
            (b"\r\r\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n", &[400], NOTHING),
        ],
    );
}

/// A refused request behind an accepted one: the first is answered and forwarded, the
/// second is a 400 and goes nowhere (`known_diffs` 44dcef8f, 832db3eb, c6af6b29).
#[test]
fn a_pipelined_request_with_a_forbidden_byte_is_refused() {
    let p = proxy();
    check(
        &p,
        &[
            (
                b"GET /first HTTP/1.1\r\nHost: a.com\r\n\r\nGET /sec\0nd HTTP/1.1\r\nHost: b.com\r\n\r\n",
                &[200, 400],
                &[b"GET /first HTTP/1.1\r\nhost: a.com\r\n\r\n"],
            ),
            (
                b"POST /p1 HTTP/1.1\r\nHost: a.com\r\nContent-Length: 4\r\n\r\n1234E:TRA_BYTESGET /p2 HTTP/1.1\r\nHost: b.com\r\n\r\n",
                &[200, 400],
                &[b"POST /p1 HTTP/1.1\r\nhost: a.com\r\ncontent-length: 4\r\n\r\n1234"],
            ),
        ],
    );
}

/// A head whose last line ends with a bare LF and whose blank line is CRLF ends there: the
/// request behind it is the next one (T291 item 1, soak case 1025; `known_diffs` 8170daad,
/// a0eba82b).
#[test]
fn a_bare_lf_then_crlf_ends_the_head() {
    let p = proxy();
    check(
        &p,
        &[
            (
                b"GET /first HTTP/1.1\r\nHost: a.com\n\r\nGET /second HTTP/1.1\r\nHost: b.com\r\n\r\n",
                &[200, 200],
                &[b"GET /first HTTP/1.1\r\nhost: a.com\r\n\r\n", b"GET /second HTTP/1.1\r\nhost: b.com\r\n\r\n"],
            ),
            (
                b"GET /first HTTP/1.1\r\nHost: a.com \n\r\nGET /second HTTP/1.1\r\nHost: b.com\r\n\r\n",
                &[200, 200],
                &[b"GET /first HTTP/1.1\r\nhost: a.com\r\n\r\n", b"GET /second HTTP/1.1\r\nhost: b.com\r\n\r\n"],
            ),
            (b"get\x0bhttp://h/x\nHost: example.com\n\r\n", &[400], NOTHING),
        ],
    );
}

/// What `HAProxy` forwards of a request line it accepts: single spaces, and `HTTP/1.1` for a
/// version from 1.1 up, without the `Connection: keep-alive` of a 1.0 request (`known_diffs`
/// 054dac49, 56ac0269, 19cb05b3, ...).
#[test]
fn an_accepted_request_line_is_forwarded_normalised() {
    let p = proxy();
    check(
        &p,
        &[
            (
                b"OPTIONS /api/v1/resource HTTP/2.0\r\nHost: example.com\r\n\r\n",
                &[200],
                &[b"OPTIONS /api/v1/resource HTTP/1.1\r\nhost: example.com\r\n\r\n"],
            ),
            (b"get  / HTTP/1.2\r\nHost: example.com\r\n\n", &[200], &[b"get / HTTP/1.1\r\nhost: example.com\r\n\r\n"]),
            (b"POST /index.html HTTP/9.9\r\nHost: example.com\r\n\r\n", &[200], &[b"POST /index.html HTTP/1.1\r\nhost: example.com\r\n\r\n"]),
            (b"GET\t/x\tHTTP/1.1\r\nHost: a\r\n\r\n", &[200], &[b"GET /x HTTP/1.1\r\nhost: a\r\n\r\n"]),
            (b"GET /x  HTTP/1.1\r\nHost: a\r\n\r\n", &[200], &[b"GET /x HTTP/1.1\r\nhost: a\r\n\r\n"]),
            (b"GET /x HTTP/1.0\r\nHost: a\r\n\r\n", &[200], &[b"GET /x HTTP/1.0\r\nhost: a\r\nconnection: keep-alive\r\n\r\n"]),
            (b"GET /x HTTP/0.9\r\nHost: a\r\n\r\n", &[200], &[b"GET /x HTTP/0.9\r\nhost: a\r\nconnection: keep-alive\r\n\r\n"]),
            (b"\r\n\nGET /x HTTP/1.1\r\nHost: a\r\n\r\n", &[200], &[b"GET /x HTTP/1.1\r\nhost: a\r\n\r\n"]),
        ],
    );
}

/// A head not yet whole that already holds a byte `HAProxy` refuses is a 400 at once, not a
/// 408 when `timeout http-request` strikes: a folded first header line, a NUL in a name, a
/// CR not followed by LF (`known_diffs` 0fa04ea1, 2ae8c610, 9e961c3d, da30321d, f7da18fc).
#[test]
fn a_partial_head_with_a_forbidden_byte_is_refused_at_once() {
    let p = proxy();
    check(
        &p,
        &[
            (b"GET /obs-first HTTP/1.1\r\n folded-without-header: value\r\nHost: example.com\r\n\0\n", &[400], NOTHING),
            (b"GET /nul-in-name HTTP/1.1\r\nHost: example.com\r\nX-Foo\0Bar: value\r\n \n", &[400], NOTHING),
            (b"POST /signed-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: +5\r\xff\r\nhello", &[400], NOTHING),
            (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\xff", &[400], NOTHING),
            (b"GET /nul-in-name HTTP/1.1\r\nHost: example.com\r\nX-Foo\0Bar: value\r\n\r\0", &[400], NOTHING),
            (b"GET / HTTP/1.1\r\nHost: a\r\nX-A: b\0c\r\n", &[400], NOTHING),
            (b"GET / HTTP/1.1\r\nHost: a\r\nX A: b\r\n", &[400], NOTHING),
            (b"GET / HTTP/1.1\r\nHost: a\r\n: b\r\n", &[400], NOTHING),
        ],
    );
}
