// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The PRIORITY and PADDED flags of HEADERS and DATA frames (T213, RFC 9113 sections 6.1, 6.2).
//!
//! Chrome sets PRIORITY on every request HEADERS (`END_STREAM|END_HEADERS|PRIORITY`, 5 bytes
//! `80 00 00 00 ff` before the HPACK block). Expected values measured on
//! `HAProxy 3.5-dev8-885761-29` with the same frames (cleartext `proto h2` bind,
//! `http-request return status 200`):
//!
//! ```text
//! PRIORITY | PADDED | both | PRIORITY then CONTINUATION | PADDED then CONTINUATION   200
//! padded DATA (4 + 3 + 4 pad)    200, WINDOW_UPDATE counts the 8 bytes of the frame
//! HEADERS pad length >= payload  GOAWAY PROTOCOL_ERROR (1)
//! DATA    pad length >= payload  GOAWAY PROTOCOL_ERROR (1)
//! HEADERS stream depends on itself   GOAWAY PROTOCOL_ERROR (1), with or without END_STREAM
//! HEADERS PADDED, empty payload / PRIORITY, 2 bytes   GOAWAY FRAME_SIZE_ERROR (6)
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

fn head(method: &str) -> Vec<u8> {
    [(":method", method), (":scheme", "http"), (":authority", "x"), (":path", "/")]
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

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// What came back: the frames `(type, flags, stream, payload)` and whether the peer closed.
struct Reply {
    frames: Vec<(u8, u8, u32, Vec<u8>)>,
    closed: bool,
}

impl Reply {
    fn got_200(&self) -> bool {
        self.frames.iter().any(|f| f.0 == 1 && f.2 == 1 && f.3.first() == Some(&0x88))
    }
    fn goaway(&self) -> Option<u32> {
        self.frames.iter().find(|f| f.0 == 7).map(|f| u32::from_be_bytes([f.3[4], f.3[5], f.3[6], f.3[7]]))
    }
}

/// Sends the preface, empty SETTINGS and `frames`; reads until close or 1.5 s of the answer.
fn exchange(fe: SocketAddr, frames: &[Vec<u8>]) -> Reply {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(4, 0, 0, &[]));
    out.extend(frame(4, 1, 0, &[]));
    for f in frames {
        out.extend_from_slice(f);
    }
    s.write_all(&out).expect("send");
    let (mut buf, mut closed) = (Vec::new(), false);
    let deadline = Instant::now() + Duration::from_millis(1500);
    let mut tmp = [0u8; 4096];
    while Instant::now() < deadline {
        match s.read(&mut tmp) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => {
                // Stop early once a response or a GOAWAY is in.
                if buf.windows(9).any(|w| w[3] == 7 || (w[3] == 1 && w[4] & 1 != 0) || (w[3] == 0 && w[4] & 1 != 0)) {
                    break;
                }
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

#[test]
fn chrome_headers_with_priority_flag_get_a_response() {
    let (_ibex, fe) = start();
    let mut p = vec![0x80, 0, 0, 0, 0xff];
    p.extend(head("GET"));
    let r = exchange(fe, &[frame(1, END_STREAM | END_HEADERS | PRIORITY, 1, &p)]);
    assert!(r.got_200(), "{:?}", r.frames);
    assert_eq!(r.goaway(), None);
}

#[test]
fn padded_headers_get_a_response() {
    let (_ibex, fe) = start();
    let mut p = vec![3];
    p.extend(head("GET"));
    p.extend([0, 0, 0]);
    let r = exchange(fe, &[frame(1, END_STREAM | END_HEADERS | PADDED, 1, &p)]);
    assert!(r.got_200(), "{:?}", r.frames);
}

#[test]
fn padded_headers_with_priority_get_a_response() {
    let (_ibex, fe) = start();
    let mut p = vec![2, 0, 0, 0, 0, 0x10];
    p.extend(head("GET"));
    p.extend([0, 0]);
    let r = exchange(fe, &[frame(1, END_STREAM | END_HEADERS | PADDED | PRIORITY, 1, &p)]);
    assert!(r.got_200(), "{:?}", r.frames);
}

#[test]
fn continuation_after_priority_or_padded_headers() {
    let (_ibex, fe) = start();
    let h = head("GET");
    let mut p = vec![0, 0, 0, 0, 0x10];
    p.extend(&h[..5]);
    let r = exchange(fe, &[frame(1, END_STREAM | PRIORITY, 1, &p), frame(9, END_HEADERS, 1, &h[5..])]);
    assert!(r.got_200(), "priority: {:?}", r.frames);
    let mut p = vec![2];
    p.extend(&h[..5]);
    p.extend([0, 0]);
    let r = exchange(fe, &[frame(1, END_STREAM | PADDED, 1, &p), frame(9, END_HEADERS, 1, &h[5..])]);
    assert!(r.got_200(), "padded: {:?}", r.frames);
}

#[test]
fn padded_data_counts_its_padding_toward_flow_control() {
    let (_ibex, fe) = start();
    let mut frames = vec![frame(1, END_HEADERS, 1, &head("POST"))];
    // 130 frames of pad length 255 and no data: 33280 bytes of window, below the 32768 left of
    // 65535 only if the padding is counted. The connection window is then given back.
    for _ in 0..130 {
        let mut p = vec![255];
        p.extend([0u8; 255]);
        frames.push(frame(0, PADDED, 1, &p));
    }
    frames.push(frame(0, END_STREAM, 1, &[]));
    let r = exchange(fe, &frames);
    assert!(r.got_200(), "{:?}", r.frames);
    assert!(
        r.frames.iter().any(|f| f.0 == 8 && f.2 == 0),
        "no connection WINDOW_UPDATE for 33280 bytes of padding: {:?}",
        r.frames
    );
}

#[test]
fn pad_length_not_below_payload_is_protocol_error() {
    let (_ibex, fe) = start();
    let h = head("GET");
    let mut p = vec![(h.len() + 1) as u8];
    p.extend(&h);
    let r = exchange(fe, &[frame(1, END_STREAM | END_HEADERS | PADDED, 1, &p)]);
    assert_eq!(r.goaway(), Some(1), "headers: {:?}", r.frames);
    let r = exchange(fe, &[frame(1, END_HEADERS, 1, &head("POST")), frame(0, PADDED, 1, &[9, b'a', b'b', b'c'])]);
    assert_eq!(r.goaway(), Some(1), "data: {:?}", r.frames);
}

#[test]
fn stream_depending_on_itself_is_protocol_error() {
    let (_ibex, fe) = start();
    let mut p = vec![0, 0, 0, 1, 0x10];
    p.extend(head("GET"));
    for flags in [END_STREAM | END_HEADERS | PRIORITY, END_HEADERS | PRIORITY] {
        let r = exchange(fe, &[frame(1, flags, 1, &p)]);
        assert_eq!(r.goaway(), Some(1), "flags {flags:#x}: {:?}", r.frames);
        assert!(!r.got_200());
    }
}

#[test]
fn truncated_padded_or_priority_headers_are_frame_size_errors() {
    let (_ibex, fe) = start();
    let r = exchange(fe, &[frame(1, END_HEADERS | PADDED, 1, &[])]);
    assert_eq!(r.goaway(), Some(6), "padded: {:?} closed={}", r.frames, r.closed);
    let r = exchange(fe, &[frame(1, END_HEADERS | PRIORITY, 1, &[0, 0])]);
    assert_eq!(r.goaway(), Some(6), "priority: {:?}", r.frames);
}
