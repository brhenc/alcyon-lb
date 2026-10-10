// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Peer SETTINGS values, frame lengths and header counts an HTTP/2 client can abuse (T234,
//! RFC 9113 sections 4.2, 6.5.2; RFC 7541).
//!
//! Before T234 a SETTINGS_MAX_FRAME_SIZE of 0 made the send loop spin forever on empty DATA
//! frames (the worker wedged and ran out of memory), and a HEADERS frame of 16 MiB was
//! buffered and HPACK-decoded into 16M header fields. Expected replies measured on
//! `HAProxy 3.5-dev8-885761-29` with the same frames (cleartext `proto h2` bind,
//! `http-request return status 200`); every GOAWAY below is followed by a close:
//!
//! ```text
//! SETTINGS MAX_FRAME_SIZE 0 / 16383 / 2^24          GOAWAY last 0 PROTOCOL_ERROR (1), no ACK
//! SETTINGS MAX_FRAME_SIZE 2^24-1                    200
//! SETTINGS INITIAL_WINDOW_SIZE 2^31                 GOAWAY last 0 FLOW_CONTROL_ERROR (3)
//! SETTINGS INITIAL_WINDOW_SIZE 2^31-1               200
//! SETTINGS ENABLE_PUSH 2                            GOAWAY last 0 PROTOCOL_ERROR (1)
//! request 1, then SETTINGS MAX_FRAME_SIZE 0         GOAWAY last 1 PROTOCOL_ERROR (1)
//! HEADERS of 16385 bytes                            GOAWAY last 0 FRAME_SIZE_ERROR (6)
//! frame header claiming 16 MiB, 100 bytes sent      GOAWAY last 0 FRAME_SIZE_ERROR (6)
//! PING / unknown type of 16385 bytes                GOAWAY last 0 FRAME_SIZE_ERROR (6)
//! DATA of 16385 bytes on open stream 1              GOAWAY last 1 FRAME_SIZE_ERROR (6)
//! 4 pseudo-headers + 99 headers                     200   (host + 99 = 100 = tune.http.maxhdr - 1)
//! 4 pseudo-headers + 100 .. 197 headers             RST_STREAM PROTOCOL_ERROR (1), connection kept
//! 4 pseudo-headers + 198 headers (202 fields)       GOAWAY last 1 COMPRESSION_ERROR (9)
//! 2000 headers over HEADERS + CONTINUATION          GOAWAY last 1 COMPRESSION_ERROR (9)
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        // SIGUSR1, then SIGKILL only after common::stop's 5 s: a process killed while it writes
        // its coverage profile leaves a corrupt .profraw.
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

/// The request head followed by `n` headers `x: y`.
fn head_with(n: usize) -> Vec<u8> {
    let mut h = head();
    for _ in 0..n {
        h.extend(lit("x", "y"));
    }
    h
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn setting(id: u16, val: u32) -> Vec<u8> {
    let mut v = id.to_be_bytes().to_vec();
    v.extend_from_slice(&val.to_be_bytes());
    v
}

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

fn request(sid: u32) -> Vec<u8> {
    frame(1, END_STREAM | END_HEADERS, sid, &head())
}

/// What came back: the frames `(type, flags, stream, payload)` and whether the peer closed.
struct Reply {
    frames: Vec<(u8, u8, u32, Vec<u8>)>,
    closed: bool,
}

impl Reply {
    fn got_200(&self) -> bool {
        self.frames.iter().any(|f| f.0 == 1 && f.2 == 1 && f.3.first() == Some(&0x88))
    }
    /// The GOAWAY's (last-stream-id, error code).
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
    fn settings_acked(&self) -> bool {
        self.frames.iter().any(|f| f.0 == 4 && f.1 & 1 != 0)
    }
}

/// Sends the preface, a SETTINGS frame carrying `settings`, the ACK of the server's, and
/// `frames`; reads until close or for 1.5 s. Never blocks longer: a wedged server is a
/// failed assertion, not a hung test.
fn exchange(fe: SocketAddr, settings: &[u8], frames: &[Vec<u8>]) -> Reply {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(200))).ok();
    s.set_write_timeout(Some(Duration::from_millis(1500))).ok();
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(4, 0, 0, settings));
    out.extend(frame(4, 1, 0, &[]));
    for f in frames {
        out.extend_from_slice(f);
    }
    // The server may close before reading everything: a write error is not the verdict.
    let _ = s.write_all(&out);
    let (mut buf, mut closed) = (Vec::new(), false);
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut tmp = [0u8; 16384];
    while Instant::now() < deadline {
        match s.read(&mut tmp) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                if buf.windows(9).any(|w| w[3] == 0 && w[4] & 1 != 0) {
                    break;
                }
            }
            Err(_) => {
                closed = true;
                break;
            }
        }
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

const MAX_FRAME_SIZE: u16 = 5;
const INITIAL_WINDOW_SIZE: u16 = 4;
const ENABLE_PUSH: u16 = 2;

#[test]
fn max_frame_size_zero_is_protocol_error_and_does_not_wedge_the_worker() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &setting(MAX_FRAME_SIZE, 0), &[request(1)]);
    assert_eq!(r.goaway(), Some((0, 1)), "{:?}", r.frames);
    assert!(!r.settings_acked(), "invalid SETTINGS acknowledged: {:?}", r.frames);
    assert!(!r.got_200());
    assert!(r.closed, "not closed after GOAWAY");
    // The worker still answers.
    let r = exchange(fe, &[], &[request(1)]);
    assert!(r.got_200(), "worker wedged: {:?}", r.frames);
}

#[test]
fn max_frame_size_outside_its_range_is_protocol_error() {
    let (_ibex, fe) = start();
    for val in [16_383, 1 << 24, u32::MAX] {
        let r = exchange(fe, &setting(MAX_FRAME_SIZE, val), &[request(1)]);
        assert_eq!(r.goaway(), Some((0, 1)), "{val}: {:?}", r.frames);
        assert!(r.closed, "{val}: not closed");
    }
    for val in [16_384, (1 << 24) - 1] {
        let r = exchange(fe, &setting(MAX_FRAME_SIZE, val), &[request(1)]);
        assert!(r.got_200(), "{val}: {:?}", r.frames);
    }
}

#[test]
fn initial_window_size_above_2_pow_31_minus_1_is_flow_control_error() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &setting(INITIAL_WINDOW_SIZE, 1 << 31), &[request(1)]);
    assert_eq!(r.goaway(), Some((0, 3)), "{:?}", r.frames);
    assert!(r.closed);
    let r = exchange(fe, &setting(INITIAL_WINDOW_SIZE, (1 << 31) - 1), &[request(1)]);
    assert!(r.got_200(), "{:?}", r.frames);
}

#[test]
fn enable_push_above_1_is_protocol_error() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &setting(ENABLE_PUSH, 2), &[request(1)]);
    assert_eq!(r.goaway(), Some((0, 1)), "{:?}", r.frames);
    assert!(r.closed);
}

#[test]
fn invalid_settings_after_a_request_name_that_stream_as_last() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &[], &[request(1), frame(4, 0, 0, &setting(MAX_FRAME_SIZE, 0)), request(3)]);
    assert_eq!(r.goaway(), Some((1, 1)), "{:?}", r.frames);
    assert!(r.closed);
    let r = exchange(fe, &[], &[request(1), frame(4, 0, 0, &setting(INITIAL_WINDOW_SIZE, 1 << 31)), request(3)]);
    assert_eq!(r.goaway(), Some((1, 3)), "{:?}", r.frames);
}

#[test]
fn frames_longer_than_16384_are_frame_size_errors() {
    let (_ibex, fe) = start();
    let mut h = head();
    h.resize(16_385, 0x82);
    let r = exchange(fe, &[], &[frame(1, END_STREAM | END_HEADERS, 1, &h)]);
    assert_eq!(r.goaway(), Some((0, 6)), "headers: {:?}", r.frames);
    assert!(r.closed, "headers: not closed");
    let r = exchange(fe, &[], &[frame(6, 0, 0, &[0; 16_385])]);
    assert_eq!(r.goaway(), Some((0, 6)), "ping: {:?}", r.frames);
    let r = exchange(fe, &[], &[frame(0x20, 0, 0, &[0; 16_385])]);
    assert_eq!(r.goaway(), Some((0, 6)), "unknown type: {:?}", r.frames);
    let r = exchange(fe, &[], &[frame(1, END_HEADERS, 1, &head()), frame(0, END_STREAM, 1, &[b'a'; 16_385])]);
    assert_eq!(r.goaway(), Some((1, 6)), "data: {:?}", r.frames);
    // 16384 is the limit itself.
    let r = exchange(fe, &[], &[frame(0x20, 0, 0, &[0; 16_384]), request(1)]);
    assert!(r.got_200(), "16384: {:?}", r.frames);
}

#[test]
fn an_oversized_frame_is_refused_on_its_header_not_buffered() {
    let (_ibex, fe) = start();
    // Claims 16 MiB and sends 100 bytes: the answer must not wait for the rest.
    let mut f = vec![0xff, 0xff, 0xff, 1, END_STREAM | END_HEADERS, 0, 0, 0, 1];
    f.extend([0x82; 100]);
    let r = exchange(fe, &[], &[f]);
    assert_eq!(r.goaway(), Some((0, 6)), "{:?}", r.frames);
    assert!(r.closed);
}

#[test]
fn header_count_is_bounded_like_haproxy() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &[], &[frame(1, END_STREAM | END_HEADERS, 1, &head_with(99))]);
    assert!(r.got_200(), "99: {:?}", r.frames);
    for n in [100, 197] {
        let r = exchange(fe, &[], &[frame(1, END_STREAM | END_HEADERS, 1, &head_with(n))]);
        assert_eq!(r.rst(1), Some(1), "{n}: {:?}", r.frames);
        assert_eq!(r.goaway(), None, "{n}: {:?}", r.frames);
        assert!(!r.got_200(), "{n}");
    }
    let r = exchange(fe, &[], &[frame(1, END_STREAM | END_HEADERS, 1, &head_with(198))]);
    assert_eq!(r.goaway(), Some((1, 9)), "198: {:?}", r.frames);
    assert!(r.closed, "198: not closed");
}

#[test]
fn many_headers_over_continuation_are_a_compression_error() {
    let (_ibex, fe) = start();
    let block = head_with(2000);
    let chunks: Vec<&[u8]> = block.chunks(8000).collect();
    let mut frames = vec![frame(1, END_STREAM, 1, chunks[0])];
    for (i, c) in chunks.iter().enumerate().skip(1) {
        frames.push(frame(9, if i == chunks.len() - 1 { END_HEADERS } else { 0 }, 1, c));
    }
    let r = exchange(fe, &[], &frames);
    assert_eq!(r.goaway(), Some((1, 9)), "{:?}", r.frames);
    assert!(r.closed);
}
