// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A response sent before the request body ended (T314).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` (`T314_ORACLE=haproxy` runs these against it):
//! `http-request return status 503` on an h2c frontend, `POST` HEADERS without END_STREAM
//! on streams 1, 3, 5 (bodies never sent), then a `GET` (END_STREAM) on stream 7:
//!
//! ```text
//!   HEADERS(1) DATA(1,ES) RST_STREAM(1,NO_ERROR) HEADERS(3) DATA(3,ES) RST_STREAM(3,NO_ERROR) ...
//!   HEADERS(7) DATA(7,ES)
//! ```
//!
//! With 100 such streams (the default limit) the stream 201 sent at once is either refused
//! (`RST_STREAM(REFUSED_STREAM)`, seen when it arrives before the resets are processed) or
//! answered; sent after the 100 resets it is answered. Ibex sent no RST_STREAM and left the
//! 101st stream without any frame.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proxy {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start() -> Proxy {
    start_with("\thttp-request return status 503 content-type text/plain string no\n", "")
}

/// A server that answers every request head at once with a 413 and then holds the
/// connection open, the request body never ending.
fn early_server() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let (mut got, mut b) = (Vec::new(), [0u8; 4096]);
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 413 X\r\nContent-Length: 2\r\n\r\nno");
                c.set_read_timeout(Some(Duration::from_secs(20))).ok();
                while c.read(&mut b).is_ok_and(|n| n > 0) {}
            });
        }
    });
    port
}

fn start_with(fe_rules: &str, be: &str) -> Proxy {
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout client 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n{fe_rules}{be}"
        ),
    )
    .expect("write config");
    let bin = std::env::var("T314_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let t = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(t.elapsed() < Duration::from_secs(10), "the proxy never listened on {port}");
        std::thread::sleep(Duration::from_millis(50));
    }
    Proxy { child, port, _dir: dir }
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0, u8::try_from(name.len()).unwrap()];
    v.extend_from_slice(name.as_bytes());
    v.push(u8::try_from(value.len()).unwrap());
    v.extend_from_slice(value.as_bytes());
    v
}

fn request(method: &str) -> Vec<u8> {
    [literal(":method", method), literal(":scheme", "http"), literal(":path", "/x"), literal(":authority", "a")].concat()
}

/// (type, flags, stream, payload)
type Frame = (u8, u8, u32, Vec<u8>);

fn client(p: &Proxy) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    s
}

/// Reads frames until `done(frames)` or `limit`.
fn read_until(s: &mut TcpStream, limit: Duration, done: impl Fn(&[Frame]) -> bool) -> Vec<Frame> {
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let t0 = Instant::now();
    let (mut buf, mut tmp, mut out) = (Vec::new(), [0u8; 16384], Vec::new());
    while t0.elapsed() < limit && !done(&out) {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let sid = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            out.push((buf[3], buf[4], sid, buf[9..9 + len].to_vec()));
            buf.drain(..9 + len);
        }
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => {}
        }
    }
    out
}

/// The frames of `sid` as short names, ignoring the connection's own.
fn of(frames: &[Frame], sid: u32) -> Vec<String> {
    frames
        .iter()
        .filter(|f| f.2 == sid && f.0 != 0x08)
        .map(|f| match f.0 {
            0x00 => format!("DATA{}", if f.1 & 1 != 0 { "+ES" } else { "" }),
            0x01 => "HEADERS".to_string(),
            0x03 => format!("RST({})", u32::from_be_bytes(f.3[..4].try_into().unwrap())),
            t => format!("type{t}"),
        })
        .collect()
}

fn post_streams(s: &mut TcpStream, n: u32) {
    let mut burst = Vec::new();
    for i in 0..n {
        burst.extend_from_slice(&frame(0x01, 0x04, 1 + 2 * i, &request("POST")));
    }
    s.write_all(&burst).expect("headers");
}

/// An early response is followed by `RST_STREAM(NO_ERROR)` on its stream (measured), and a
/// further stream is answered as usual.
#[test]
fn an_early_response_is_followed_by_rst_stream_no_error() {
    let p = start();
    let mut s = client(&p);
    post_streams(&mut s, 3);
    s.write_all(&frame(0x01, 0x05, 7, &request("GET"))).expect("get");
    let seen = read_until(&mut s, Duration::from_secs(5), |f| of(f, 7).len() >= 2 && (1..=5).step_by(2).all(|i| of(f, i).len() >= 3));
    for sid in [1, 3, 5] {
        assert_eq!(of(&seen, sid), ["HEADERS", "DATA+ES", "RST(0)"], "stream {sid}: {seen:?}");
    }
    assert_eq!(of(&seen, 7), ["HEADERS", "DATA+ES"], "the GET: {seen:?}");
}

/// A request that ended before the response gets no RST_STREAM.
#[test]
fn a_complete_request_gets_no_rst_stream() {
    let p = start();
    let mut s = client(&p);
    s.write_all(&frame(0x01, 0x05, 1, &request("GET"))).expect("get");
    let seen = read_until(&mut s, Duration::from_millis(800), |_| false);
    assert_eq!(of(&seen, 1), ["HEADERS", "DATA+ES"], "{seen:?}");
}

/// With the default 100 streams all answered early, the 101st is never left without a frame:
/// sent at once it is refused or answered, sent after the resets it is answered.
#[test]
fn the_stream_past_the_limit_is_never_dropped_silently() {
    let p = start();
    let mut s = client(&p);
    post_streams(&mut s, 100);
    s.write_all(&frame(0x01, 0x05, 201, &request("GET"))).expect("get at once");
    let seen = read_until(&mut s, Duration::from_secs(5), |f| !of(f, 201).is_empty() && (0..100).all(|i| of(f, 1 + 2 * i).len() >= 3));
    let late = of(&seen, 201);
    assert!(!late.is_empty(), "stream 201 got no frame at all: {} frames", seen.len());
    assert!(late == ["HEADERS", "DATA+ES"] || late == ["RST(7)"], "stream 201: {late:?}");
    for i in 0..100 {
        assert_eq!(of(&seen, 1 + 2 * i), ["HEADERS", "DATA+ES", "RST(0)"], "stream {}", 1 + 2 * i);
    }
    // Once the resets are in, the slots are free again.
    s.write_all(&frame(0x01, 0x05, 203, &request("GET"))).expect("get after");
    let seen = read_until(&mut s, Duration::from_secs(5), |f| of(f, 203).len() >= 2);
    assert_eq!(of(&seen, 203), ["HEADERS", "DATA+ES"], "stream 203: {seen:?}");
}

/// A server's early answer (not a reply the proxy made): measured, `HAProxy` sends no
/// RST_STREAM and keeps the stream open, so with 100 of them the 101st is refused
/// (`RST_STREAM(REFUSED_STREAM)`), not left waiting for a slot that never frees.
#[test]
fn the_stream_past_the_limit_of_server_answered_streams_is_refused() {
    let srv = early_server();
    let p = start_with("\tdefault_backend be\n", &format!("backend be\n\tserver s 127.0.0.1:{srv}\n"));
    let mut s = client(&p);
    post_streams(&mut s, 100);
    let seen = read_until(&mut s, Duration::from_secs(5), |f| (0..100).all(|i| of(f, 1 + 2 * i).len() >= 2));
    for i in 0..100 {
        assert_eq!(of(&seen, 1 + 2 * i), ["HEADERS", "DATA+ES"], "stream {}", 1 + 2 * i);
    }
    s.write_all(&frame(0x01, 0x05, 201, &request("GET"))).expect("get");
    let seen = read_until(&mut s, Duration::from_secs(3), |f| !of(f, 201).is_empty());
    assert_eq!(of(&seen, 201), ["RST(7)"], "stream 201: {seen:?}");
}
