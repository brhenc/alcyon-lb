// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T520: interim (1xx) responses of an HTTP/1 server reach an HTTP/2 client as HEADERS
//! frames without END_STREAM, before the final response. Measured on `HAProxy` 3.5-dev8
//! (curl 8.18 `--http2-prior-knowledge`, the backend of `h3_mux_trailers`):
//!
//! | case | `HAProxy` |
//! |---|---|
//! | server: `103` then (300 ms later) `200` | `HTTP/2 103` + `link`, then `200`, `ok`; `B=119` (the `103` head counts; Alcyon logs `B=51`, not asserted: docs/differences.md) |
//! | server: `103` and `200` in one segment | the same (the h2 mux does not crash) |
//! | `expect: 100-continue` POST, the server sends `100` | `HTTP/2 100`, then the `200`; the `200` carries its own length |

use crate::common;
use crate::h3_mux_trailers::backend;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn alcyon(be: SocketAddr) -> Alcyon {
    let fe = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe} proto h2\n  default_backend b\n\
         backend b\n  http-reuse never\n  server s {be}\n"
    )
    .expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened");
    Alcyon { child, fe, _cfg: cfg }
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn block(list: &[(&str, &str)]) -> Vec<u8> {
    list.iter()
        .flat_map(|(n, v)| {
            let mut f = vec![0, n.len() as u8];
            f.extend_from_slice(n.as_bytes());
            f.push(v.len() as u8);
            f.extend_from_slice(v.as_bytes());
            f
        })
        .collect()
}

type Frame = (u8, u8, u32, Vec<u8>);

/// The frames of stream 1 up to its END_STREAM (or 5 s).
fn read_stream_1(s: &mut TcpStream) -> Vec<Frame> {
    let (mut out, mut buf, mut tmp) = (Vec::new(), Vec::new(), [0u8; 4096]);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            let f = (buf[3], buf[4], id, buf[9..9 + len].to_vec());
            buf.drain(..9 + len);
            let end = f.2 == 1 && matches!(f.0, 0 | 1) && f.1 & 1 != 0;
            out.push(f);
            if end {
                return out;
            }
        }
        match s.read(&mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => {}
        }
    }
    out
}

fn connect(fe: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(200))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(4, 0, 0, &[])).expect("settings");
    s.write_all(&frame(4, 1, 0, &[])).expect("ack");
    s
}

/// The stream's HEADERS and DATA frames as `H end=<0|1> name: value, ..` and `D end=<0|1> <text>`
/// lines (one decoder for the connection: the response's blocks share its table).
fn shape(frames: &[Frame]) -> Vec<String> {
    let mut dec = alcyon_proto::hpack::HpackDecoder::new();
    frames
        .iter()
        .filter(|f| f.2 == 1 && matches!(f.0, 0 | 1))
        .map(|f| {
            let end = f.1 & 1;
            if f.0 == 1 {
                let fields = dec.decode(&f.3).expect("a header block");
                format!("H end={end} {}", fields.iter().map(|h| format!("{}: {}", h.name, h.value)).collect::<Vec<_>>().join(", "))
            } else {
                format!("D end={end} {}", String::from_utf8_lossy(&f.3))
            }
        })
        .collect()
}

fn get(path: &str, extra: &[(&str, &str)], end: bool) -> Vec<u8> {
    let mut l = vec![(":method", "GET"), (":scheme", "http"), (":authority", "x"), (":path", path)];
    l.extend_from_slice(extra);
    frame(1, if end { 5 } else { 4 }, 1, &block(&l))
}

/// The response frames for `/early2` and `/early1`.
fn early(path: &str) {
    let (be, _seen) = backend();
    let alcyon = alcyon(be);
    let mut s = connect(alcyon.fe);
    s.write_all(&get(path, &[], true)).expect("request");
    let f = read_stream_1(&mut s);
    let sh = shape(&f);
    assert_eq!(sh, ["H end=0 :status: 103, link: </s.css>; rel=preload", "H end=0 :status: 200, content-length: 2", "D end=1 ok"]);
}

#[test]
fn an_early_hint_is_an_interim_headers_before_the_final_response() {
    early("/early2");
}

/// The oracle's h2 mux forwards both; so does Alcyon.
#[test]
fn an_early_hint_and_the_final_response_in_one_segment_are_both_forwarded() {
    early("/early1");
}

#[test]
fn a_100_continue_is_an_interim_headers() {
    let (be, _seen) = backend();
    let alcyon = alcyon(be);
    let mut s = connect(alcyon.fe);
    let mut l = vec![(":method", "POST"), (":scheme", "http"), (":authority", "x"), (":path", "/cont")];
    l.extend_from_slice(&[("expect", "100-continue"), ("content-length", "3")]);
    s.write_all(&frame(1, 4, 1, &block(&l))).expect("head");
    std::thread::sleep(Duration::from_millis(300));
    s.write_all(&frame(0, 1, 1, b"abc")).expect("body");
    let f = read_stream_1(&mut s);
    let sh = shape(&f);
    assert_eq!(sh[..2], ["H end=0 :status: 100", "H end=0 :status: 200, content-length: 2"], "{sh:?}");
}
