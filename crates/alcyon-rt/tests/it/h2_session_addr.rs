// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Every stream of an HTTP/2 connection reads the session's source and destination: a
//! `tcp-request session set-src`/`set-dst` made once for the connection is what `src`/`dst`
//! answer in each of its streams, not the connection's own addresses (`sess_get_src`: a new
//! stream starts from the session's value). Set `T281_ORACLE=/path/to/haproxy` to run it
//! against `HAProxy`, where it passes (3.5-dev11).
//!
//! Each stream's response status says whether its rules saw the rewritten pair: 200 when
//! `src` and `dst` are the session's, 403 otherwise. `:status 200` is HPACK static index 8, so
//! the response's header block of a 200 starts with `0x88` on both implementations.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn bin() -> String {
    std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

#[test]
fn every_h2_stream_reads_the_session_addresses() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe} proto h2\n\
         \x20 tcp-request session set-src ipv4(10.9.9.1)\n\
         \x20 tcp-request session set-dst ipv4(10.9.9.2)\n\
         \x20 http-request return status 200 if {{ src 10.9.9.1 }} {{ dst 10.9.9.2 }}\n\
         \x20 http-request return status 403\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(bin())
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(fe), "never listened");

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(50))).ok();
    // GET / on streams 1 and 3 of the same connection: :method GET, :scheme http, :path /,
    // :authority "x" (a literal without indexing, name index 1).
    let req = [0x82, 0x86, 0x84, 0x01, 0x01, b'x'];
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend_from_slice(&frame(4, 0, 0, &[]));
    hello.extend_from_slice(&frame(1, 5, 1, &req));
    hello.extend_from_slice(&frame(1, 5, 3, &req));
    c.write_all(&hello).expect("send");

    // The first byte of each stream's response header block.
    let mut first: Vec<(u32, u8)> = Vec::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let t0 = Instant::now();
    while first.len() < 2 && t0.elapsed() < Duration::from_secs(5) {
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
            let stream = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            if buf[3] == 1 && len > 0 {
                // A PADDED or PRIORITY HEADERS frame would move the block; neither side sends one.
                assert_eq!(buf[4] & 0x28, 0, "HEADERS with padding/priority: {:02x?}", &buf[..9 + len]);
                first.push((stream, buf[9]));
            }
            buf.drain(..9 + len);
        }
    }
    common::stop(&mut child);

    first.sort_unstable();
    assert_eq!(first, vec![(1, 0x88), (3, 0x88)], "(stream, first header-block byte): 0x88 = :status 200");
}
