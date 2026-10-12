// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A bad `Content-Length` line is refused as soon as the line is complete and a byte of
//! the next one is in, not when the head ends (tasks/T315, from the differential fuzzer's
//! `fuzz/known_diffs.json`). `HAProxy` 3.5-dev8 checks each header line as it completes
//! (`h1_headers_to_hdr_list`, `h1_parse_cont_len_header`):
//!
//! - a value that is not digits (`+5`, `-5`, `5 5`, empty, a trailing comma, too large), or
//!   a list of different values in the first line: 400 at once;
//! - a value that differs from an earlier `Content-Length` line's: the connection closes
//!   with nothing written (logged as a 400).
//!
//! Equal values (`5, 5`, `5` and `05`) are fine and the head is awaited. Each case sends
//! the bytes of a head that never ends and reads for up to 1.5 s: a refusal arrives within
//! that, a head being awaited does not. Set `T315_ORACLE=/path/to/haproxy` to run the same
//! cases against it.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// What a client saw of a head that never ended: the bytes it was answered, and whether
/// the proxy closed the connection within the time allowed.
fn exchange(addr: std::net::SocketAddr, tail: &[u8]) -> (Vec<u8>, bool) {
    let mut c = TcpStream::connect(addr).expect("connect");
    // One write: `HAProxy` fails fast only when the line completes in the pass that reads it,
    // so a head arriving in pieces is judged at its end (a quirk Ibex does not copy).
    let mut raw = b"POST /x HTTP/1.1\r\nHost: example.com\r\n".to_vec();
    raw.extend_from_slice(tail);
    c.write_all(&raw).expect("send");
    let _ = c.set_read_timeout(Some(Duration::from_millis(1500)));
    let (mut out, mut buf, t0) = (Vec::new(), [0u8; 4096], Instant::now());
    while t0.elapsed() < Duration::from_millis(1500) {
        match c.read(&mut buf) {
            Ok(0) => return (out, true),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return (out, true),
        }
    }
    (out, false)
}

fn run(cases: &[(&[u8], Option<&str>)]) {
    let srv = common::reserve_addr();
    let addr = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 10s\n    timeout server 10s\n    \
         timeout connect 1s\n    timeout http-request 10s\nfrontend f\n    bind {addr}\n    default_backend b\n\
         backend b\n    server s {srv}\n"
    )
    .expect("write cfg");
    let bin = std::env::var("T315_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(addr), "proxy never listened");
    let mut bad = Vec::new();
    for &(tail, want) in cases {
        let (out, closed) = exchange(addr, tail);
        // want: Some("400") = answered 400 and closed; Some("") = closed, nothing written;
        // None = still waiting for the head.
        let got = match (closed, out.is_empty()) {
            (false, _) => None,
            (true, true) => Some(String::new()),
            (true, false) => Some(String::from_utf8_lossy(&out[9..out.len().min(12)]).into_owned()),
        };
        if got.as_deref() != want {
            bad.push(format!("{:?}: got {got:?}, want {want:?}", String::from_utf8_lossy(tail)));
        }
    }
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} of {} cases differ from HAProxy:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

/// The four inputs of the fuzzer's report (575c9712, a9ac40bd, b05bd55d, cd65f480) and the
/// shapes around them that are refused at once.
#[test]
fn a_bad_content_length_line_is_refused_before_the_head_ends() {
    run(&[
        (b"Content-Length: +5\r\n \nhello", Some("400")),
        (b"Content-Length: -5\r\n \nhello", Some("400")),
        (b"Content-Length: 5 5\r\n \nhello", Some("400")),
        (b"Content-Length: 5, 6\r\n \nhello", Some("400")),
        (b"Content-Length: +5\r\nX: y\r\n", Some("400")),
        (b"Content-Length: \r\nX: y\r\n", Some("400")),
        (b"Content-Length: 5,\r\nX: y\r\n", Some("400")),
        (b"Content-Length: 99999999999999999999999\r\nX: y\r\n", Some("400")),
        // different values in two lines: closed, nothing written
        (b"Content-Length: 5\r\nContent-Length: 10\r\n \nhelloworld", Some("")),
        (b"Content-Length: 5\r\nContent-Length: 10\r\nX: y", Some("")),
        (b"Content-Length: 5\r\nContent-Length: 5, 6\r\nX: y\r\n", Some("")),
    ]);
}

/// What is not refused: the head is awaited.
#[test]
fn a_good_content_length_line_waits_for_the_head() {
    run(&[
        (b"Content-Length: 5, 5\r\n \nhello", None),
        (b"Content-Length: 5\r\n \nhello", None),
        (b"Content-Length: 5\r\nContent-Length: 05\r\nX: y\r\n", None),
        (b"Content-Length: 5\r\nContent-Length: 5, 5\r\nX: y\r\n", None),
        // the line is not complete, or no byte follows it (it could be folded)
        (b"Content-Length: +5", None),
        (b"Content-Length: +5\r\n", None),
        (b"Content-Length: 5\r\nContent-Length: 10\r\n", None),
    ]);
}
