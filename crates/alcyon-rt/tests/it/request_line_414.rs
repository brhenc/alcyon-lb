// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A request line that cannot fit the buffer is a 414, not a 431 (T282, VV-6).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, 2026-10-11 (`tune.bufsize 4096` and the default
//! 16384, default `tune.maxrewrite`), `GET /` + `n` x `a` + ` HTTP/1.1` and `Host: h`:
//! * the start-line block (40 bytes of HTX, 20 of block, the method, target and version) that
//!   does not fit the buffer is a 414: `n` = 4025 on 4096 (4024 is a 431: the head is too big
//!   for `bufsize - maxrewrite`), 16313 on 16384 (16312 is a 431), whether the rest of the head
//!   follows or not (the request line and its line feed alone are enough);
//! * a request line with no line feed yet is waited for (a 408 from `timeout client`) until
//!   the buffer holds `bufsize - 56` bytes, then it is a 414: 4040 bytes on 4096 (4035 is
//!   waited for); a complete request line with a partial head is still a 431.
//! The log line of a 414 is `414 0 ... PR-- ... "<BADREQ>"`, that of a 431 the same with 431.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};

/// The first line of the answer to `data` on a daemon with `tune.bufsize` `bufsize`.
fn answer(bufsize: usize, data: &[u8]) -> String {
    let fe = common::reserve_addr();
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    write!(
        f,
        "global\n  tune.bufsize {bufsize}\ndefaults\n  mode http\n  timeout client 1s\n\
         frontend f\n  bind {fe}\n  http-request return status 200 content-type text/plain string ok\n"
    )
    .expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe));
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    s.write_all(data).expect("send");
    let mut out = [0u8; 64];
    let got = s.read(&mut out).unwrap_or(0);
    common::stop(&mut child);
    String::from_utf8_lossy(&out[..got]).lines().next().unwrap_or("").to_string()
}

fn full(n: usize) -> Vec<u8> {
    format!("GET /{} HTTP/1.1\r\nHost: h\r\n\r\n", "a".repeat(n)).into_bytes()
}

const E414: &str = "HTTP/1.1 414 URI Too Long";
const E431: &str = "HTTP/1.1 431 Request Header Fields Too Large";
const E408: &str = "HTTP/1.1 408 Request Time-out";

#[test]
fn a_start_line_that_does_not_fit_is_a_414() {
    assert_eq!(answer(4096, &full(4024)), E431);
    assert_eq!(answer(4096, &full(4025)), E414);
    assert_eq!(answer(4096, &full(20000)), E414);
    // The request line and its line feed are enough, the headers need not follow.
    assert_eq!(answer(4096, format!("GET /{} HTTP/1.1\r\n", "a".repeat(4024)).as_bytes()), E431);
    assert_eq!(answer(4096, format!("GET /{} HTTP/1.1\r\n", "a".repeat(4025)).as_bytes()), E414);
}

#[test]
fn the_default_buffer_has_the_same_step() {
    assert_eq!(answer(16384, &full(16312)), E431);
    assert_eq!(answer(16384, &full(16313)), E414);
    assert_eq!(answer(16384, &full(20000)), E414);
}

#[test]
fn a_request_line_still_open_is_waited_for_then_a_414() {
    let open = |n: usize| format!("GET /{}", "a".repeat(n)).into_bytes();
    assert_eq!(answer(4096, &open(4030)), E408);
    assert_eq!(answer(4096, &open(4035)), E414);
    assert_eq!(answer(4096, &open(4050)), E414);
    // A complete request line with a partial head stays a 431.
    let partial = format!("GET / HTTP/1.1\r\nHost: h\r\nX: {}", "a".repeat(4050)).into_bytes();
    assert_eq!(answer(4096, &partial), E431);
}
