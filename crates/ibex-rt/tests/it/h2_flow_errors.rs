// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! h2 flow-control and priority errors over h2c (VV-4, T274 F). Expected replies measured on
//! `HAProxy 3.5-dev8-885761-29` (`bind proto h2`, `http-request return status 200`); stream 1
//! "open" means HEADERS without END_STREAM, "complete" HEADERS with it:
//!
//! ```text
//! WINDOW_UPDATE(1, 0), stream 1 open or complete, unanswered   RST_STREAM 1 PROTOCOL_ERROR (1);
//!                                                              connection kept, stream 3 answered
//! WINDOW_UPDATE(1, 0) or (1, 2^31-1) after stream 1 is closed  ignored, stream 3 answered
//! WINDOW_UPDATE(0, 0), after request 1                         GOAWAY last 1 PROTOCOL_ERROR (1)
//! WINDOW_UPDATE(0, 0), nothing before                          GOAWAY last 0 PROTOCOL_ERROR (1)
//! WINDOW_UPDATE(5, 0) or (5, 2^31-1) on an idle stream 5       GOAWAY last 0 PROTOCOL_ERROR (1)
//! PRIORITY 1 -> 1 (after request 1, or idle stream 3 -> 3)    GOAWAY last 1 / 0 PROTOCOL_ERROR (1)
//! HEADERS 1 with a priority block 1 -> 1 (open or complete)    GOAWAY last 1 PROTOCOL_ERROR (1)
//! SETTINGS INITIAL_WINDOW_SIZE raised, no overflow             streams keep working
//! ```
//!
//! Not an oracle value: SETTINGS INITIAL_WINDOW_SIZE raised so that an open stream's window
//! passes 2^31-1. HAProxy keeps the stream window as `sws + miw` in an `int32_t`: it wraps
//! negative, no error is sent and the stream's DATA stalls. Ibex follows RFC 9113 section
//! 6.9.2 instead (connection error FLOW_CONTROL_ERROR), which a conforming peer never
//! triggers.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const MAX: u32 = (1 << 31) - 1;
const END_STREAM: u8 = 1;
const END_HEADERS: u8 = 4;
const PRIORITY_FLAG: u8 = 0x20;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start() -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n\
         frontend fe\n  bind {fe} proto h2\n  http-request return status 200 content-type text/plain string ok\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened:\n{cfg}");
    (Ibex { child, _cfg: f }, fe)
}

fn lit(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

fn head() -> Vec<u8> {
    [(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", "/")]
        .iter()
        .flat_map(|(n, v)| lit(n, v))
        .collect()
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn request(sid: u32) -> Vec<u8> {
    frame(1, END_STREAM | END_HEADERS, sid, &head())
}

fn open_request(sid: u32) -> Vec<u8> {
    frame(1, END_HEADERS, sid, &head())
}

/// HEADERS carrying a priority block that makes `sid` depend on `dep`.
fn request_with_priority(sid: u32, dep: u32, end: bool) -> Vec<u8> {
    let mut p = dep.to_be_bytes().to_vec();
    p.push(0);
    p.extend(head());
    frame(1, END_HEADERS | PRIORITY_FLAG | if end { END_STREAM } else { 0 }, sid, &p)
}

fn priority(sid: u32, dep: u32) -> Vec<u8> {
    let mut p = dep.to_be_bytes().to_vec();
    p.push(0);
    frame(2, 0, sid, &p)
}

fn window_update(sid: u32, inc: u32) -> Vec<u8> {
    frame(8, 0, sid, &inc.to_be_bytes())
}

fn initial_window(val: u32) -> Vec<u8> {
    let mut p = 4u16.to_be_bytes().to_vec();
    p.extend_from_slice(&val.to_be_bytes());
    frame(4, 0, 0, &p)
}

struct Reply {
    frames: Vec<(u8, u8, u32, Vec<u8>)>,
    closed: bool,
}

impl Reply {
    fn answered(&self, sid: u32) -> bool {
        self.frames.iter().any(|f| f.0 == 1 && f.2 == sid && f.3.first() == Some(&0x88))
    }
    fn goaway(&self) -> Option<(u32, u32)> {
        self.frames.iter().find(|f| f.0 == 7).map(|f| {
            (
                u32::from_be_bytes([f.3[0] & 0x7f, f.3[1], f.3[2], f.3[3]]),
                u32::from_be_bytes([f.3[4], f.3[5], f.3[6], f.3[7]]),
            )
        })
    }
    fn rst(&self, sid: u32) -> Option<u32> {
        self.frames
            .iter()
            .find(|f| f.0 == 3 && f.2 == sid)
            .map(|f| u32::from_be_bytes([f.3[0], f.3[1], f.3[2], f.3[3]]))
    }
}

/// Sends the preface, SETTINGS, its ACK and `first`; after 400 ms, `second`; reads until
/// close or for 1.5 s.
fn exchange(fe: SocketAddr, first: &[Vec<u8>], second: &[Vec<u8>]) -> Reply {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(200))).ok();
    s.set_write_timeout(Some(Duration::from_millis(1500))).ok();
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(4, 0, 0, &[]));
    out.extend(frame(4, 1, 0, &[]));
    first.iter().for_each(|f| out.extend_from_slice(f));
    let _ = s.write_all(&out);
    let mut buf = Vec::new();
    let mut closed = false;
    let mut tmp = [0u8; 16384];
    let mut read_until = |s: &mut TcpStream, buf: &mut Vec<u8>, ms: u64| {
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            match s.read(&mut tmp) {
                Ok(0) => return true,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => return true,
            }
        }
        false
    };
    if !second.is_empty() {
        closed = read_until(&mut s, &mut buf, 400);
        if !closed {
            let out: Vec<u8> = second.concat();
            let _ = s.write_all(&out);
        }
    }
    if !closed {
        closed = read_until(&mut s, &mut buf, 1200);
    }
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 9 <= buf.len() {
        let len = (usize::from(buf[i]) << 16) | (usize::from(buf[i + 1]) << 8) | usize::from(buf[i + 2]);
        if buf.len() < i + 9 + len {
            break;
        }
        let sid = u32::from_be_bytes([buf[i + 5] & 0x7f, buf[i + 6], buf[i + 7], buf[i + 8]]);
        frames.push((buf[i + 3], buf[i + 4], sid, buf[i + 9..i + 9 + len].to_vec()));
        i += 9 + len;
    }
    Reply { frames, closed }
}

#[test]
fn zero_increment_on_a_stream_is_a_stream_error() {
    let (_ibex, fe) = start();
    // Stream 1 open, and stream 1 complete but not yet answered when the frame is read.
    for first in [[open_request(1), window_update(1, 0), request(3)], [request(1), window_update(1, 0), request(3)]] {
        let r = exchange(fe, &first, &[]);
        assert_eq!(r.rst(1), Some(1), "{:?}", r.frames);
        assert_eq!(r.goaway(), None, "{:?}", r.frames);
        assert!(!r.closed, "connection closed");
        assert!(r.answered(3), "stream 3 not answered: {:?}", r.frames);
    }
}

#[test]
fn zero_increment_on_the_connection_is_a_connection_error_naming_the_last_stream() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &[request(1), window_update(0, 0)], &[]);
    assert_eq!(r.goaway(), Some((1, 1)), "{:?}", r.frames);
    assert!(r.closed);
    let r = exchange(fe, &[window_update(0, 0)], &[]);
    assert_eq!(r.goaway(), Some((0, 1)), "{:?}", r.frames);
    assert!(r.closed);
}

#[test]
fn window_update_on_an_idle_stream_is_a_connection_error() {
    let (_ibex, fe) = start();
    for inc in [0, 1, MAX] {
        let r = exchange(fe, &[window_update(5, inc), request(1)], &[]);
        assert_eq!(r.goaway(), Some((0, 1)), "{inc}: {:?}", r.frames);
        assert!(r.closed, "{inc}");
        assert!(!r.answered(1), "{inc}: {:?}", r.frames);
    }
}

#[test]
fn window_update_on_a_closed_stream_is_ignored() {
    let (_ibex, fe) = start();
    for inc in [0, 1, MAX] {
        let r = exchange(fe, &[request(1)], &[window_update(1, inc), request(3)]);
        assert_eq!(r.goaway(), None, "{inc}: {:?}", r.frames);
        assert_eq!(r.rst(1), None, "{inc}: {:?}", r.frames);
        assert!(r.answered(1) && r.answered(3), "{inc}: {:?}", r.frames);
    }
}

#[test]
fn a_stream_depending_on_itself_is_a_connection_error() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &[request(1), priority(1, 1), request(3)], &[]);
    assert_eq!(r.goaway(), Some((1, 1)), "PRIORITY after request: {:?}", r.frames);
    let r = exchange(fe, &[priority(3, 3), request(1)], &[]);
    assert_eq!(r.goaway(), Some((0, 1)), "PRIORITY on an idle stream: {:?}", r.frames);
    for end in [true, false] {
        let r = exchange(fe, &[request_with_priority(1, 1, end), request(3)], &[]);
        assert_eq!(r.goaway(), Some((1, 1)), "HEADERS priority block, end={end}: {:?}", r.frames);
        assert!(r.closed, "end={end}");
        assert!(!r.answered(3), "end={end}: {:?}", r.frames);
    }
    // A priority block on another stream is fine.
    let r = exchange(fe, &[request_with_priority(1, 3, true)], &[]);
    assert_eq!(r.goaway(), None, "{:?}", r.frames);
    assert!(r.answered(1), "{:?}", r.frames);
}

#[test]
fn raising_the_initial_window_without_overflow_keeps_streams_working() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &[open_request(1), initial_window(MAX), request(3)], &[]);
    assert_eq!(r.goaway(), None, "{:?}", r.frames);
    assert!(r.answered(1) && r.answered(3), "{:?}", r.frames);
}

#[test]
fn raising_the_initial_window_past_2_pow_31_minus_1_on_an_open_stream_is_flow_control_error() {
    let (_ibex, fe) = start();
    // Stream 1's window is raised to exactly 2^31-1 (legal), then the setting raises it by 1.
    let r = exchange(fe, &[open_request(1), window_update(1, MAX - 65_535), initial_window(65_536), request(3)], &[]);
    assert_eq!(r.goaway(), Some((1, 3)), "{:?}", r.frames);
    assert!(r.closed);
    // The same setting with no stream beyond the limit is fine.
    let r = exchange(fe, &[open_request(1), window_update(1, MAX - 65_536), initial_window(65_536), request(3)], &[]);
    assert_eq!(r.goaway(), None, "{:?}", r.frames);
    assert!(r.answered(3), "{:?}", r.frames);
}
