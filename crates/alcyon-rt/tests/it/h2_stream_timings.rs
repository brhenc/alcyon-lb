// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The timings of an HTTP/2 stream that follows a reset stream, or an idle gap (T529).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` with a raw h2 client: `GET /slow` on stream 1,
//! `RST_STREAM(CANCEL)` 500 ms later, `GET /plain` on stream 3 500 ms after that:
//!
//! ```text
//! stream 1  TR=0 Tw=0 Tc=0 Tr=-1 Ta=500 Th=0 Ti=0   Tt=500  400 CD
//! stream 3  TR=0 Tw=0 Tc=0 Tr=1  Ta=1   Th=0 Ti=500 Tt=501  200
//! ```
//!
//! and with no reset, `/plain` on 1 then on 3 500 ms later: stream 3 `TR=0 Ta=0 Ti=499`.
//! Alcyon agrees (the HTTP/3 mux did not, `h3_mux_drain.rs`); these keep it so.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    port: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// An HTTP/1 backend: `/slow` answers after 2 s, anything else at once.
fn backend() -> SocketAddr {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                if got.starts_with(b"GET /slow") {
                    thread::sleep(Duration::from_secs(2));
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
            });
        }
    });
    addr
}

fn alcyon(be: SocketAddr, collector: &UdpSocket) -> Alcyon {
    let port = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 5s\n    timeout server 10s\n    timeout connect 1s\n    \
         log {} local0\nfrontend f\n    bind {port} proto h2\n    \
         log-format \"TR=%TR Tw=%Tw Tc=%Tc Tr=%Tr Ta=%Ta Th=%Th Ti=%Ti Tt=%Tt %ST %{{+Q}}r\"\n    default_backend b\nbackend b\n    server s {be}\n",
        collector.local_addr().expect("addr")
    )
    .expect("write cfg");
    let child = common::alcyon_command(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon");
    assert!(common::wait_listening(port), "alcyon never listened");
    Alcyon { child, port, _cfg: cfg }
}

fn lit(n: &[u8], v: &[u8]) -> Vec<u8> {
    let mut o = vec![0, u8::try_from(n.len()).expect("name")];
    o.extend_from_slice(n);
    o.push(u8::try_from(v.len()).expect("value"));
    o.extend_from_slice(v);
    o
}

fn frame(ty: u8, flags: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut o = u32::try_from(payload.len()).expect("len").to_be_bytes()[1..].to_vec();
    o.extend_from_slice(&[ty, flags]);
    o.extend_from_slice(&id.to_be_bytes());
    o.extend_from_slice(payload);
    o
}

fn get(id: u32, path: &[u8]) -> Vec<u8> {
    let mut h = lit(b":method", b"GET");
    h.extend(lit(b":scheme", b"http"));
    h.extend(lit(b":path", path));
    h.extend(lit(b":authority", b"localhost"));
    frame(1, 5, id, &h)
}

fn client(alcyon: &Alcyon) -> TcpStream {
    let mut s = TcpStream::connect(alcyon.port).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(4, 0, 0, b"")).expect("settings");
    s
}

fn timings(collector: &UdpSocket, what: &str) -> std::collections::HashMap<String, i64> {
    collector.set_read_timeout(Some(Duration::from_secs(6))).expect("timeout");
    let mut buf = [0u8; 2048];
    loop {
        let n = collector.recv(&mut buf).unwrap_or_else(|_| panic!("no log line with {what}"));
        let l = String::from_utf8_lossy(&buf[..n]).into_owned();
        if l.contains(what) {
            return l.split_whitespace().filter_map(|w| w.split_once('=')).filter_map(|(k, v)| Some((k.to_owned(), v.parse().ok()?))).collect();
        }
    }
}

#[test]
fn the_stream_after_a_reset_stream_is_timed_from_its_own_start() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    let alcyon = alcyon(backend(), &collector);
    let mut s = client(&alcyon);
    s.write_all(&get(1, b"/slow")).expect("get");
    thread::sleep(Duration::from_millis(500));
    s.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst");
    thread::sleep(Duration::from_millis(500));
    s.write_all(&get(3, b"/after")).expect("get");
    let t = timings(&collector, "/after");
    assert!(t["TR"] <= 50 && t["Ta"] <= 100 && t["Tr"] <= 50, "{t:?}");
    assert!((400..=700).contains(&t["Ti"]) && t["Tt"] >= t["Ti"], "{t:?}");
}

#[test]
fn the_stream_after_an_idle_gap_is_timed_from_its_own_start() {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    let alcyon = alcyon(backend(), &collector);
    let mut s = client(&alcyon);
    s.write_all(&get(1, b"/first")).expect("get");
    let first = timings(&collector, "/first");
    assert!(first["Ti"] >= 0 && first["Ti"] <= 50 && first["TR"] <= 50, "{first:?}");
    thread::sleep(Duration::from_millis(500));
    s.write_all(&get(3, b"/second")).expect("get");
    let t = timings(&collector, "/second");
    assert!(t["TR"] <= 50 && t["Ta"] <= 100, "{t:?}");
    assert!((400..=700).contains(&t["Ti"]) && t["Tt"] >= t["Ti"], "{t:?}");
}
