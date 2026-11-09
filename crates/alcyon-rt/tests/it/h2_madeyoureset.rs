// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A stream that the same read pass resets does not reach the backend (T309, MY-6).
//!
//! The MadeYouReset shape (`clients.py attack h2_madeyoureset` of the red team): one h2c
//! connection, 200 requests each followed at once by a frame that makes the proxy reset the
//! stream, all in one write. Since T280 every stream is a session of its own and a parsed
//! head was dispatched before the rest of the read, the trigger included, was processed:
//! about 7 % of the reset streams connected to the backend (1618 connections in 60 s of the
//! attack, against 7 for `HAProxy`). `HAProxy` demuxes the whole buffer first.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=/path/to/haproxy` runs this on it).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// The most backend connections one case may cost: `HAProxy` 0-7 per 10000 requests, so
/// for the 200 of a case a handful at most.
const BOUND: usize = 5;

fn binary() -> String {
    std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct Proxy(Child);
impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
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

/// `GET /` on `localhost`, `END_STREAM | END_HEADERS`.
fn request(sid: u32) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, 1, b'/', 0x01, 9];
    v.extend_from_slice(b"localhost");
    frame(0x01, 0x05, sid, &v)
}

/// The five triggers of the red team's client, by index.
const TRIGGERS: [&str; 5] = ["window_update_0", "priority_on_self", "data_after_end_stream", "window_update_overflow", "headers_after_end_stream"];

fn trigger(sid: u32, k: usize) -> Vec<u8> {
    match k {
        0 => frame(0x08, 0, sid, &0u32.to_be_bytes()),
        1 => frame(0x02, 0, sid, &[sid.to_be_bytes().as_slice(), &[16]].concat()),
        2 => frame(0x00, 0, sid, b"x"),
        3 => frame(0x08, 0, sid, &0x7fff_ffffu32.to_be_bytes()),
        _ => request(sid),
    }
}

/// A backend that answers every request and counts the connections it accepts.
fn counting_backend() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    let n = Arc::new(AtomicUsize::new(0));
    let count = n.clone();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            count.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let (mut req, mut tmp) = (Vec::new(), [0u8; 2048]);
                loop {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(k) => req.extend_from_slice(&tmp[..k]),
                    }
                    while let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        req.drain(..i + 4);
                        if c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    (port, n)
}

/// Backend connections one connection costs that sends 200 x (request, trigger `k`) in one
/// write.
fn backend_conns(k: usize) -> usize {
    let (backend, n) = counting_backend();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n"
        ),
    )
    .expect("write config");
    let _p = Proxy(Command::new(binary()).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut buf = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    buf.extend_from_slice(&frame(0x04, 0, 0, &[]));
    for i in 0..200u32 {
        let sid = 1 + 2 * i;
        buf.extend_from_slice(&request(sid));
        buf.extend_from_slice(&trigger(sid, k));
    }
    s.write_all(&buf).expect("write");
    // Drain the replies for a moment, so that the proxy is never blocked writing to us.
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let t0 = Instant::now();
    let mut tmp = [0u8; 65536];
    while t0.elapsed() < Duration::from_millis(1500) {
        if let Ok(0) = s.read(&mut tmp) {
            break;
        }
    }
    thread::sleep(Duration::from_millis(300));
    n.load(Ordering::SeqCst)
}

#[test]
fn a_stream_reset_in_the_pass_that_read_it_never_reaches_the_backend() {
    let got: Vec<(&str, usize)> = TRIGGERS.iter().enumerate().map(|(k, &name)| (name, backend_conns(k))).collect();
    eprintln!("backend connections per trigger: {got:?}");
    for (name, n) in &got {
        assert!(*n <= BOUND, "trigger {name}: {n} backend connections for 200 reset streams (HAProxy: 0-7 per 10000); all: {got:?}");
    }
}

/// What the client is told: a PRIORITY that makes stream 3 depend on itself, after the
/// request on stream 1, is a connection error. Measured on `HAProxy` 3.5-dev8-885761-29:
/// `GOAWAY` (last stream 1, `PROTOCOL_ERROR`), the same for a stream that is idle or open.
#[test]
fn a_priority_on_itself_is_a_connection_error() {
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    let (backend, _n) = counting_backend();
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n"
        ),
    )
    .expect("write config");
    let _p = Proxy(Command::new(binary()).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut buf = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    buf.extend_from_slice(&frame(0x04, 0, 0, &[]));
    buf.extend_from_slice(&request(1));
    buf.extend_from_slice(&trigger(3, 1));
    s.write_all(&buf).expect("write");
    s.set_read_timeout(Some(Duration::from_millis(100))).ok();
    let (mut got, mut tmp) = (Vec::new(), [0u8; 4096]);
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(1) {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(k) => got.extend_from_slice(&tmp[..k]),
            Err(_) => {}
        }
    }
    let mut goaway = None;
    let mut i = 0;
    while i + 9 <= got.len() {
        let len = (usize::from(got[i]) << 16) | (usize::from(got[i + 1]) << 8) | usize::from(got[i + 2]);
        if got[i + 3] == 0x07 && got.len() >= i + 9 + 8 {
            let p = &got[i + 9..i + 17];
            goaway = Some((u32::from_be_bytes([p[0], p[1], p[2], p[3]]), u32::from_be_bytes([p[4], p[5], p[6], p[7]])));
        }
        i += 9 + len;
    }
    assert_eq!(goaway, Some((1, 1)), "GOAWAY (last stream, error code); frames: {got:?}");
}
