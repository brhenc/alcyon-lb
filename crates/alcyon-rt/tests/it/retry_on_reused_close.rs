// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T517: a server that answers one request on a connection and closes it a moment later,
//! one client connection sending its requests one after the other. Each second request
//! takes the server connection kept from the first (`http-reuse safe`), which the server
//! then closes with no answer.
//!
//! Measured on 2026-10-31 (`nbthread 1`, a backend closing 50 ms after its answer, 40
//! requests, clients that do not retry: a raw socket for h1, `h2load -c1 -m1` for h2,
//! aioquic for h3; scripts in `tasks/T517-progress.md`):
//!
//! | config | `HAProxy` 3.0.30, 3.5-dev8 (h1, h2), 3.5-dev7 QUIC (h1, h2, h3) |
//! |---|---|
//! | default (`retry-on conn-failure`) | 20 x 200, 20 reset: h1 connection closed unanswered, h2 `RST_STREAM`, h3 stream reset 0x10c |
//! | `retry-on empty-response conn-failure` | 40 x 200 |
//!
//! No 502 anywhere: a request lost on a reused connection is `abort_keep_alive`'s. The
//! HTTP/3 rows (relay and mux) are in `h3_mux_edges.rs`, which has the QUIC client.
//! `T517_ORACLE=/usr/bin/haproxy cargo test -p alcyon-rt --test it retry_on_reused_close::`
//! runs these against `HAProxy`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

/// How long the backend waits after its answer before it closes the connection: long
/// enough that the client's next request always comes first, also on a loaded machine.
const CLOSE_AFTER: Duration = Duration::from_millis(200);

/// Requests per run: half of them land on a reused connection.
const N: usize = 10;

/// An HTTP/1.1 backend that answers the first request of each connection `200 ok`, then
/// closes the connection `CLOSE_AFTER` later without reading on.
pub fn closing_backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let (mut got, mut buf) = (Vec::new(), [0u8; 4096]);
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
                thread::sleep(CLOSE_AFTER);
            });
        }
    });
    addr
}

/// The proxy, frontend `bind_opts` on a fresh address, backend `backend_line` to `be`.
fn proxy(be: SocketAddr, bind_opts: &str, backend_line: &str) -> (common::Alcyon, NamedTempFile, SocketAddr) {
    let fe = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend fe\n  bind {fe}{bind_opts}\n  default_backend be\nbackend be\n  {backend_line}\n  server s1 {be}\n"
    )
    .expect("write cfg");
    let bin = std::env::var("T517_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn proxy");
    let child = common::Alcyon(child);
    assert!(common::wait_listening(fe), "proxy never listened");
    (child, cfg, fe)
}

/// What the client saw for each request, in order: the status, or `reset`.
pub fn alternating() -> Vec<String> {
    (0..N).map(|i| if i % 2 == 0 { "200".to_string() } else { "reset".to_string() }).collect()
}

pub fn all_served() -> Vec<String> {
    vec!["200".to_string(); N]
}

/// `N` requests over HTTP/1.1, one at a time, on one connection while it lasts; a request
/// whose connection ends before its answer is `reset`, and the next goes on a new one.
fn h1_run(fe: SocketAddr) -> Vec<String> {
    let mut out = Vec::new();
    let mut conn: Option<TcpStream> = None;
    for i in 0..N {
        let s = conn.get_or_insert_with(|| {
            let s = TcpStream::connect(fe).expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
            s
        });
        let _ = s.write_all(format!("GET /{i} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes());
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        let answered = loop {
            if let Some(h) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                if got.len() >= h + 4 + 2 {
                    break Some(String::from_utf8_lossy(&got[9..12]).into_owned());
                }
            }
            match s.read(&mut b) {
                Ok(0) | Err(_) => break None,
                Ok(n) => got.extend_from_slice(&b[..n]),
            }
        };
        match answered {
            Some(status) => out.push(status),
            None => {
                out.push("reset".to_string());
                conn = None;
            }
        }
    }
    out
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame fits");
    let mut v = len.to_be_bytes()[1..].to_vec();
    v.extend_from_slice(&[ftype, flags]);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn read_frame(s: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut h = [0u8; 9];
    s.read_exact(&mut h).ok()?;
    let len = usize::from(h[0]) << 16 | usize::from(h[1]) << 8 | usize::from(h[2]);
    let mut p = vec![0u8; len];
    s.read_exact(&mut p).ok()?;
    Some((h[3], h[4], u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]), p))
}

/// `N` requests over HTTP/2 prior knowledge, one stream at a time on one connection
/// (`h2load -c1 -m1`): each stream is its `:status` (static-table index byte), or `reset`.
fn h2_run(fe: SocketAddr) -> Vec<String> {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(frame(4, 0, 0, &[]));
    s.write_all(&hello).expect("preface");
    let mut out = Vec::new();
    for i in 0..N {
        let id = u32::try_from(2 * i + 1).expect("id");
        // GET, http, path "/", authority "localhost".
        let mut hb = vec![0x82, 0x86, 0x84, 0x01, 9];
        hb.extend_from_slice(b"localhost");
        s.write_all(&frame(1, 0x05, id, &hb)).expect("headers");
        let seen = loop {
            let Some((t, flags, sid, p)) = read_frame(&mut s) else { break "lost".to_string() };
            match t {
                4 if flags & 1 == 0 => s.write_all(&frame(4, 1, 0, &[])).expect("settings ack"),
                // `:status 200` is static index 8 (0x88), the first field alcyon and HAProxy send.
                1 if sid == id => {
                    let status = if p.first() == Some(&0x88) { "200".to_string() } else { format!("head {:02x?}", &p[..p.len().min(4)]) };
                    if flags & 1 != 0 {
                        break status;
                    }
                    out.push(status);
                }
                0 if sid == id && flags & 1 != 0 => break out.pop().expect("a head before the body's end"),
                3 if sid == id => break "reset".to_string(),
                7 => break "goaway".to_string(),
                _ => {}
            }
        };
        out.push(seen);
    }
    out
}

#[test]
fn h1_a_request_lost_on_a_reused_connection_is_reset_by_default() {
    let be = closing_backend();
    let (_p, _cfg, fe) = proxy(be, "", "");
    assert_eq!(h1_run(fe), alternating());
}

#[test]
fn h1_retry_on_empty_response_serves_every_request() {
    let be = closing_backend();
    let (_p, _cfg, fe) = proxy(be, "", "retry-on empty-response conn-failure");
    assert_eq!(h1_run(fe), all_served());
}

#[test]
fn h2_a_request_lost_on_a_reused_connection_is_reset_by_default() {
    let be = closing_backend();
    let (_p, _cfg, fe) = proxy(be, " proto h2", "");
    assert_eq!(h2_run(fe), alternating());
}

#[test]
fn h2_retry_on_empty_response_serves_every_request() {
    let be = closing_backend();
    let (_p, _cfg, fe) = proxy(be, " proto h2", "retry-on empty-response conn-failure");
    assert_eq!(h2_run(fe), all_served());
}
