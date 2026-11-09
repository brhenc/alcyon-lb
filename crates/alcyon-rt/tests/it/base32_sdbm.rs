// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `base32` and `base32+src` hash with SDBM, as `HAProxy` does, not djb2.
//!
//! `HAProxy`'s `smp_fetch_base32` (`src/http_fetch.c`) runs
//! `hash = c + (hash << 6) + (hash << 16) - hash` from 0 over the Host header's value (when
//! there is one), then over the path up to `?` (when it starts with `/`), then `full_hash`.
//! The Host header, not an absolute URI's authority: with no Host header only the path is
//! hashed. `base32+src` is that hash big-endian followed by the source address.
//!
//! Every column measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-17 with
//! `lf-string "[%[base32]][%[base32+src,hex]]"`, raw client from 127.0.0.1.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

const CASES: &[(&str, &str)] = &[
    ("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", "[877786378][3451F50A7F000001]"),
    ("GET /p?q=1 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", "[1690518478][64C343CE7F000001]"),
    // No Host header: the path alone.
    ("GET /p?q=1 HTTP/1.0\r\n\r\n", "[543366309][20631CA57F000001]"),
    // Absolute URI with its Host: Host then the path, the query left out.
    (
        "GET http://b.example/x/y?z HTTP/1.1\r\nHost: b.example\r\nConnection: close\r\n\r\n",
        "[1034438397][3DA846FD7F000001]",
    ),
    // Absolute URI with no path: the path is `/`.
    (
        "GET http://b.example HTTP/1.1\r\nHost: b.example\r\nConnection: close\r\n\r\n",
        "[1925871626][72CA780A7F000001]",
    ),
    // Absolute URI and no Host header: the authority is not hashed, the path alone.
    ("GET http://c.example/q?x HTTP/1.0\r\n\r\n", "[2868956757][AB00CE557F000001]"),
    (
        "GET /Some/Long/Path.html HTTP/1.1\r\nHost: www.Example.com:8080\r\nConnection: close\r\n\r\n",
        "[153990313][092DB4A97F000001]",
    ),
];

#[test]
fn base32_is_sdbm_over_host_and_path() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  \
         http-request return status 200 content-type text/plain lf-string \"[%[base32]][%[base32+src,hex]]\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened");

    let mut wrong = Vec::new();
    for (req, want) in CASES {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).ok();
        c.write_all(req.as_bytes()).expect("send");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        let body = got.windows(4).position(|w| w == b"\r\n\r\n").map_or(&got[..0], |p| &got[p + 4..]);
        let body = String::from_utf8_lossy(body);
        if body != *want {
            wrong.push(format!("{:?}: got {body:?}, HAProxy {want:?}", req.lines().next().unwrap_or("")));
        }
    }
    common::stop(&mut child);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
