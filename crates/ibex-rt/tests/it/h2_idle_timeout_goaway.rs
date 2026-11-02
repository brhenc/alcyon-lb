// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! An HTTP/2 connection that sits idle for `timeout client` (T146 item 8).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04 with a raw-socket client, `proto
//! h2` and `timeout client` of 1 s and 2 s: nothing happens to the connection but a GOAWAY
//! (`NO_ERROR`, last stream = the highest one the client opened, 0 when it opened none) at
//! the end of the first timeout, a second identical GOAWAY at the end of the next one, and
//! the close right after it. Without a GOAWAY a client cannot tell a timeout from a crash.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
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

const TIMEOUT_MS: u64 = 400;

/// The frames after the server's SETTINGS exchange: `(type, flags, stream, payload)`, and
/// the instant each one was complete.
fn run(send_request: bool) -> Vec<(u8, u8, u32, Vec<u8>, Duration)> {
    let fe = common::reserve_addr();
    let text = format!(
        "defaults\n  mode http\n  timeout client {TIMEOUT_MS}ms\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe} proto h2\n  default_backend b\nbackend b\n  http-request return status 200\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened");

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    if send_request {
        // HEADERS, END_STREAM|END_HEADERS, stream 1: GET http h:/ .
        let blk = [0x82, 0x86, 0x84, 0x41, 0x01, 0x68];
        hello.extend_from_slice(&[0, 0, blk.len() as u8, 1, 5, 0, 0, 0, 1]);
        hello.extend_from_slice(&blk);
    }
    let t0 = Instant::now();
    c.write_all(&hello).expect("send");
    let mut buf: Vec<u8> = Vec::new();
    let mut frames = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match c.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let sid = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            frames.push((buf[3], buf[4], sid, buf[9..9 + len].to_vec(), t0.elapsed()));
            buf.drain(..9 + len);
        }
    }
    frames.push((255, 0, 0, Vec::new(), t0.elapsed())); // the close
    frames
}

fn goaway(last: u32) -> Vec<u8> {
    let mut p = last.to_be_bytes().to_vec();
    p.extend_from_slice(&0u32.to_be_bytes());
    p
}

fn check(send_request: bool, last: u32) {
    let frames = run(send_request);
    let types: Vec<u8> = frames.iter().map(|f| f.0).collect();
    let tail: Vec<&(u8, u8, u32, Vec<u8>, Duration)> = frames.iter().filter(|f| f.0 == 7 || f.0 == 255).collect();
    assert_eq!(
        tail.iter().map(|f| (f.0, f.1, f.2, f.3.clone())).collect::<Vec<_>>(),
        vec![(7, 0, 0, goaway(last)), (7, 0, 0, goaway(last)), (255, 0, 0, Vec::new())],
        "frames: {types:?}"
    );
    let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    // Not sooner than the timer; the first one a loaded host may deliver late, so the second is
    // judged by its distance from the first (one more `timeout client`), which a late wake-up
    // of this thread barely stretches.
    let (first, second) = (ms(tail[0].4), ms(tail[1].4));
    assert!(first >= TIMEOUT_MS - 50 && first < TIMEOUT_MS + 1500, "first GOAWAY at {:?}", tail[0].4);
    assert!(second >= first + TIMEOUT_MS - 50 && second < first + TIMEOUT_MS + 750, "second GOAWAY at {:?} (first at {:?})", tail[1].4, tail[0].4);
}

#[test]
fn an_idle_h2_connection_gets_two_goaways_then_closes() {
    check(false, 0);
}

#[test]
fn the_goaway_names_the_last_stream_the_client_opened() {
    check(true, 1);
}
