// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The streams of one HTTP/2 connection are served concurrently (T280).
//!
//! The red team's probe (`tools/battery/repro/h2concurrency.py`, branch `myth/battery-spam`):
//! ten GETs on one h2c connection to a backend that sends its response head at once and then
//! drips the body. Measured 2026-10-11 against `haproxy` 3.5-dev8 and Ibex (b11c30f), same
//! config (`bind ... proto h2`, one server):
//!
//! ```text
//!   haproxy: HEADERS within 3 s: 10 -- streams 1..19 at 0.002..0.004 s
//!   ibex:    HEADERS within 3 s:  1 -- stream 1 at 0.002 s; the others wait for it to end
//! ```
//!
//! `HAProxy` runs a stream (its own transaction and server connection) per HTTP/2 stream;
//! Ibex serves one at a time per connection, so a slow response holds up every other one on
//! the connection: a browser's page stalls behind one slow image.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long the dripping backend takes to finish one response: well past `BOUND`, so that a
/// proxy serving the streams one after the other cannot pass.
const BODY_BYTES: usize = 10;
const DRIP: Duration = Duration::from_millis(300);
/// Every stream's HEADERS must have come within this (`HAProxy`: 4 ms on loopback).
const BOUND: Duration = Duration::from_millis(1500);

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn wait_for_port(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

/// A backend that answers every request on its own connection: the head at once, then one
/// byte of body per `DRIP` -- unless the path is `/fast`, which gets the whole body at once.
fn spawn_drip_backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let mut req = Vec::new();
                let mut tmp = [0u8; 2048];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&tmp[..n]),
                    }
                }
                let fast = req.starts_with(b"GET /fast ");
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {BODY_BYTES}\r\ncontent-type: text/plain\r\n\r\n");
                if c.write_all(head.as_bytes()).is_err() {
                    return;
                }
                if fast {
                    let _ = c.write_all(&[b'f'; BODY_BYTES]);
                } else {
                    for _ in 0..BODY_BYTES {
                        thread::sleep(DRIP);
                        if c.write_all(b"x").is_err() {
                            return;
                        }
                    }
                }
                // Hold the connection open a little: the proxy may reuse or close it.
                thread::sleep(Duration::from_millis(200));
            });
        }
    });
    port
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

/// `GET <path>` on `localhost`, static-table indices and literals only (no Huffman).
fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short path")];
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

/// Starts ibex with an h2c frontend in front of the dripping backend; returns the daemon and
/// a client connection that has sent its preface and SETTINGS.
fn start() -> (Daemon, TcpStream, std::path::PathBuf) {
    let backend = spawn_drip_backend();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2conc_{}_{port}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n"
        ),
    )
    .expect("write config");
    let d = Daemon(
        Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    (d, s, cfg)
}

/// Reads frames for `window`, returning for each stream when its HEADERS came and whether
/// it ended (`END_STREAM` on HEADERS or DATA), with the time of the end.
/// (stream id, when) for each frame of a kind seen.
type Seen = Vec<(u32, Duration)>;

fn collect(s: &mut TcpStream, window: Duration) -> (Seen, Seen) {
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let t0 = Instant::now();
    let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
    let (mut heads, mut ends) = (Vec::new(), Vec::new());
    while t0.elapsed() < window {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => {}
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (ty, flags) = (buf[3], buf[4]);
            let sid = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            if ty == 0x01 {
                heads.push((sid, t0.elapsed()));
            }
            if (ty == 0x00 || ty == 0x01) && flags & 0x01 != 0 {
                ends.push((sid, t0.elapsed()));
            }
            buf.drain(..9 + len);
        }
    }
    (heads, ends)
}

/// The probe as a test: ten streams to the dripping backend, all ten HEADERS within `BOUND`.
#[test]
#[ignore = "T280: red until stage 3b (streams served concurrently); run with --ignored"]
fn ten_streams_to_a_dripping_backend_all_get_their_headers() {
    let (_d, mut s, cfg) = start();
    let ids: Vec<u32> = (0..10).map(|k| 1 + 2 * k).collect();
    let mut burst = Vec::new();
    for &sid in &ids {
        burst.extend_from_slice(&frame(0x01, 0x05, sid, &hpack_get("/drip")));
    }
    s.write_all(&burst).expect("headers");
    let (heads, _) = collect(&mut s, BOUND);
    let _ = std::fs::remove_file(&cfg);
    let mut got: Vec<u32> = heads.iter().map(|&(sid, _)| sid).collect();
    got.sort_unstable();
    got.dedup();
    assert_eq!(
        got, ids,
        "every stream's response head must come within {BOUND:?} while the backend drips its \
         bodies (HAProxy: all ten in 4 ms); got HEADERS (stream, at) {heads:?} -- the streams \
         of one connection are being served one at a time"
    );
}

/// The browser case: a fast response is not held behind a slow one opened before it on the
/// same connection.
#[test]
#[ignore = "T280: red until stage 3b (streams served concurrently); run with --ignored"]
fn a_fast_stream_is_not_held_behind_a_slow_one() {
    let (_d, mut s, cfg) = start();
    let mut burst = frame(0x01, 0x05, 1, &hpack_get("/drip"));
    burst.extend_from_slice(&frame(0x01, 0x05, 3, &hpack_get("/fast")));
    s.write_all(&burst).expect("headers");
    let (_, ends) = collect(&mut s, BOUND);
    let _ = std::fs::remove_file(&cfg);
    assert!(
        ends.iter().any(|&(sid, _)| sid == 3),
        "stream 3 (/fast, whole body at once) must end within {BOUND:?} although stream 1 \
         (/drip, {BODY_BYTES} bytes at one per {DRIP:?}) is still running; streams ended: {ends:?}"
    );
}
