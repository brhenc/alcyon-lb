// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Which timeout ends an idle HTTP/2 connection (T349, `h2c_update_timeout`, `src/mux_h2.c`).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-17 with a raw-socket client and
//! `proto h2`: with no stream attached the connection's deadline is `idle_start` plus
//! `timeout http-keep-alive` once a stream has been seen and nothing of the next request is
//! buffered, else `idle_start` plus `timeout http-request`, and only if the chosen one is
//! unset `timeout client` (from now). The deadline sends a GOAWAY (`NO_ERROR`); the same
//! `timeout client` after it the connection is closed (with a second GOAWAY if the socket
//! takes it). `idle_start` is the end of the last stream, not the last byte: PINGs do not
//! postpone it. A stream still open keeps the connection alive. Seconds there, tens of
//! milliseconds here (c = `timeout client`, hr = `http-request`, ka = `http-keep-alive`):
//!
//! | case                          | GOAWAY at | close at |
//! |-------------------------------|-----------|----------|
//! | one GET, c6 hr4 ka2           | 2.0       | 8.0      |
//! | one GET, c6 hr4               | 4.0       | 10.0     |
//! | one GET, c6 ka2               | 2.0       | 8.0      |
//! | no request, c6 hr2            | 2.0       | 8.0      |
//! | no request, c6 ka2            | 6.0       | 12.0     |
//! | one GET + PING / 0.5 s, ka2   | 2.0       | 8.0      |
//! | one GET, 5 s response, ka2    | 7.0       | 13.0     |

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A backend that answers after `delay`.
fn backend(delay: Duration) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut c = c;
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                std::thread::sleep(delay);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
    addr
}

fn frame(t: u8, fl: u8, sid: u32, p: &[u8]) -> Vec<u8> {
    let n = p.len();
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, t, fl];
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(p);
    v
}

/// `(GOAWAY, close)` instants, the first GOAWAY seen and the end of the connection.
/// `timeouts` are config lines (`client 1500ms`), `request` whether to send a GET,
/// `ping_every` a PING cadence, `delay` how long the backend takes.
fn run(timeouts: &[&str], request: bool, ping_every: Option<Duration>, delay: Duration) -> (Option<Duration>, Duration) {
    let be = backend(delay);
    let fe = common::reserve_addr();
    let mut text = format!("defaults\n  mode http\n  timeout connect 5s\n  timeout server 10s\n");
    for t in timeouts {
        text.push_str(&format!("  timeout {t}\n"));
    }
    text.push_str(&format!("frontend f\n  bind {fe} proto h2\n  default_backend b\nbackend b\n  server s {be}\n"));
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened");

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(20))).ok();
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend_from_slice(&frame(4, 0, 0, &[]));
    if request {
        hello.extend_from_slice(&frame(1, 5, 1, &[0x82, 0x86, 0x84, 0x01, 0x01, b'x']));
    }
    let t0 = Instant::now();
    c.write_all(&hello).expect("send");
    let mut buf: Vec<u8> = Vec::new();
    let mut goaway = None;
    let mut next_ping = Duration::ZERO;
    let mut chunk = [0u8; 4096];
    while t0.elapsed() < Duration::from_secs(10) {
        if let Some(p) = ping_every {
            if t0.elapsed() >= next_ping {
                next_ping += p;
                let _ = c.write_all(&frame(6, 0, 0, b"12345678"));
            }
        }
        match c.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            if buf[3] == 7 && goaway.is_none() {
                goaway = Some(t0.elapsed());
            }
            buf.drain(..9 + len);
        }
    }
    (goaway, t0.elapsed())
}

fn near(what: &str, got: Duration, want_ms: u64) {
    let ms = u64::try_from(got.as_millis()).unwrap_or(u64::MAX);
    assert!(ms + 120 >= want_ms && ms < want_ms + 350, "{what}: at {ms} ms, HAProxy's {want_ms} ms");
}

fn check(timeouts: &[&str], request: bool, ping: Option<Duration>, delay: Duration, goaway_ms: u64, close_ms: u64) {
    let (g, close) = run(timeouts, request, ping, delay);
    near("first GOAWAY", g.expect("a GOAWAY"), goaway_ms);
    near("close", close, close_ms);
}

const NO: Duration = Duration::ZERO;

#[test]
fn keep_alive_ends_a_connection_that_served_a_request() {
    check(&["client 1500ms", "http-request 1000ms", "http-keep-alive 400ms"], true, None, NO, 400, 1900);
}

#[test]
fn http_request_ends_it_when_there_is_no_keep_alive() {
    check(&["client 1500ms", "http-request 600ms"], true, None, NO, 600, 2100);
}

#[test]
fn keep_alive_alone_is_enough() {
    check(&["client 1500ms", "http-keep-alive 400ms"], true, None, NO, 400, 1900);
}

#[test]
fn a_connection_with_no_request_waits_http_request() {
    check(&["client 1500ms", "http-request 500ms"], false, None, NO, 500, 2000);
}

#[test]
fn a_connection_with_no_request_does_not_use_keep_alive() {
    check(&["client 1000ms", "http-keep-alive 300ms"], false, None, NO, 1000, 2000);
}

#[test]
fn pings_do_not_postpone_the_deadline() {
    check(&["client 1500ms", "http-request 1000ms", "http-keep-alive 400ms"], true, Some(Duration::from_millis(100)), NO, 400, 1900);
}

#[test]
fn a_stream_still_open_is_not_cut_and_the_wait_starts_when_it_ends() {
    // The response comes at 1.2 s; keep-alive 400 ms runs from there.
    check(&["client 1500ms", "http-request 1000ms", "http-keep-alive 400ms"], true, None, Duration::from_millis(1200), 1600, 3100);
}
