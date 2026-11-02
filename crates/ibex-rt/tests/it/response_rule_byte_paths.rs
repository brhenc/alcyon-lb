// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The response rules on HTX blocks (X3b-1), the paths a plain response does not take: a status
//! line that is not UTF-8, a head the rules leave larger than the free room with a Latin-1 value
//! in it, and `del-header` with a pattern.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29; `X3B1_ORACLE=<haproxy>`
//! runs these against it.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

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

/// A server that picks its answer by the request's path.
fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
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
                let rsp: Vec<u8> = if got.starts_with(b"GET /reason ") {
                    b"HTTP/1.1 200 Caf\xe9\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
                } else if got.starts_with(b"GET /big ") {
                    let mut v = b"HTTP/1.1 200 OK\r\nX-R: caf\xe9".to_vec();
                    v.extend(std::iter::repeat_n(b'p', 1500));
                    v.extend_from_slice(b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                    v
                } else {
                    b"HTTP/1.1 200 OK\r\nX-Drop-1: a\r\nX-Keep: b\r\nx-drop-2: c\r\nX-Other-Drop: d\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
                };
                let _ = s.write_all(&rsp);
            });
        }
    });
    addr
}

fn start() -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n\
         \x20 http-response set-header x-m \"%[res.hdr(x-r)]\"\n\
         \x20 http-response set-header x-n1 \"%[res.hdr(x-r)]\"\n  http-response set-header x-n2 \"%[res.hdr(x-r)]\"\n\
         \x20 http-response set-header x-n3 \"%[res.hdr(x-r)]\"\n  http-response set-header x-n4 \"%[res.hdr(x-r)]\"\n\
         \x20 http-response set-header x-n5 \"%[res.hdr(x-r)]\"\n  http-response set-header x-n6 \"%[res.hdr(x-r)]\"\n\
         \x20 http-response set-header x-n7 \"%[res.hdr(x-r)]\"\n  http-response set-header x-n8 \"%[res.hdr(x-r)]\"\n\
         \x20 http-response del-header x-drop -m beg\n\
         \x20 default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("X3B1_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().expect("spawn");
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, fe, _cfg: cfg }
}

fn get(p: &Proxy, path: &str) -> Vec<u8> {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    got
}

fn has(got: &[u8], want: &[u8]) -> bool {
    got.windows(want.len()).any(|w| w == want)
}

/// A reason phrase that is Latin-1 reaches the client as the server sent it, with the rules
/// applied to the head.
#[test]
fn a_latin1_reason_phrase_survives_the_rules() {
    let p = start();
    let got = get(&p, "/reason");
    assert!(got.starts_with(b"HTTP/1.1 200 Caf\xe9\r\n"), "got {}", got.escape_ascii());
    assert!(has(&got, b"x-m: \r\n"), "the rules did not run: {}", got.escape_ascii());
    assert!(got.ends_with(b"ok"), "got {}", got.escape_ascii());
}

/// A head the rules leave larger than the buffer's free room (ten copies of a 1.5 KB value) is
/// written whole, a Latin-1 value as the bytes it was.
#[test]
fn a_latin1_value_in_a_head_larger_than_the_free_room_keeps_its_bytes() {
    let p = start();
    let got = get(&p, "/big");
    assert!(got.len() > 14_000, "response of {} bytes", got.len());
    // Names keep the server's case here (`tune.ibex.h1-lowercase-headers` is off), so compare in lower case.
    let low = got.to_ascii_lowercase();
    let mut value = b"caf\xe9".to_vec();
    value.extend(std::iter::repeat_n(b'p', 1500));
    value.extend_from_slice(b"\r\n");
    for name in ["x-r", "x-m", "x-n1", "x-n5", "x-n8"] {
        let mut want = format!("{name}: ").into_bytes();
        want.extend_from_slice(&value);
        assert!(has(&low, &want), "{name} lost its bytes");
    }
    assert!(!has(&low, b"\xc3\xa9"), "a Latin-1 byte became UTF-8");
}

/// `del-header <prefix> -m beg` removes every header whose name begins so, in any case, and keeps
/// the others (`X-Other-Drop` does not begin with it).
#[test]
fn del_header_with_a_pattern_removes_the_matching_headers() {
    let p = start();
    let got = get(&p, "/del");
    assert!(got.starts_with(b"HTTP/1.1 200 OK\r\n"), "got {}", got.escape_ascii());
    let low = got.to_ascii_lowercase();
    assert!(!has(&low, b"x-drop-1") && !has(&low, b"x-drop-2"), "not removed: {}", got.escape_ascii());
    assert!(has(&low, b"x-keep: b\r\n") && has(&low, b"x-other-drop: d\r\n"), "others lost: {}", got.escape_ascii());
}
