// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! How the stats page is framed and whether its connection stays open (T566). Measured on
//! HAProxy 3.5-dev8-885761-29: to an HTTP/1.1 client the page (HTML and `;csv`) is
//! `transfer-encoding: chunked` with no `content-length`, and the connection stays open unless
//! the client asked for `close` (then `connection: close`); to an HTTP/1.0 client it has no
//! length at all, says `connection: close` (even after `Connection: Keep-Alive`) and is
//! closed after the body.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// Read until the peer closes or `quiet` passes without data; the bytes, and whether it closed.
fn drain(c: &mut TcpStream, quiet: Duration) -> (Vec<u8>, bool) {
    c.set_read_timeout(Some(quiet)).expect("timeout");
    let (mut got, mut tmp) = (Vec::new(), [0u8; 8192]);
    loop {
        match c.read(&mut tmp) {
            Ok(0) => return (got, true),
            Ok(k) => got.extend_from_slice(&tmp[..k]),
            Err(_) => return (got, false),
        }
    }
}

fn split(resp: &[u8]) -> (Vec<String>, &[u8]) {
    let at = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("head end");
    let head = String::from_utf8_lossy(&resp[..at]).to_ascii_lowercase();
    (head.split("\r\n").skip(1).map(str::to_string).collect(), &resp[at + 4..])
}

fn ends_chunked(body: &[u8]) -> bool {
    body.ends_with(b"\r\n0\r\n\r\n")
}

#[test]
fn stats_page_is_chunked_or_unframed_as_haproxy() {
    let fe = common::reserve_addr();
    let cfg = format!("global\n\nfrontend f\n    mode http\n    bind {fe}\n    timeout client 5s\n    stats enable\n    stats uri /s\n");
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    let mut bad = Vec::new();
    // (version, Connection token, chunked, connection header, still open)
    let rows: &[(&str, Option<&str>, bool, Option<&str>, bool)] = &[
        ("1.1", None, true, None, true),
        ("1.1", Some("close"), true, Some("connection: close"), false),
        ("1.0", None, false, Some("connection: close"), false),
        ("1.0", Some("Keep-Alive"), false, Some("connection: close"), false),
    ];
    for uri in ["/s", "/s;csv"] {
        for &(ver, tok, chunked, conn, open) in rows {
            let mut c = TcpStream::connect(fe).expect("connect");
            let host = if ver == "1.1" { "Host: x\r\n" } else { "" };
            let t = tok.map_or(String::new(), |t| format!("Connection: {t}\r\n"));
            write!(c, "GET {uri} HTTP/{ver}\r\n{host}{t}\r\n").expect("send");
            let (resp, closed) = drain(&mut c, Duration::from_millis(700));
            let (hdrs, body) = split(&resp);
            let has = |p: &str| hdrs.iter().any(|h| h.starts_with(p));
            let ok = has("transfer-encoding: chunked") == chunked
                && !has("content-length")
                && hdrs.iter().filter(|h| h.starts_with("connection:")).map(String::as_str).eq(conn)
                && (closed != open)
                && (!chunked || ends_chunked(body));
            if !ok {
                bad.push(format!("{uri} HTTP/{ver} {tok:?}: headers {hdrs:?} closed {closed} chunk-terminated {}", ends_chunked(body)));
            }
        }
    }
    // A second request on the same HTTP/1.1 connection is answered.
    let mut c = TcpStream::connect(fe).expect("connect");
    for n in 0..2 {
        write!(c, "GET /s;csv HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        let (resp, closed) = drain(&mut c, Duration::from_millis(700));
        if closed || !resp.starts_with(b"HTTP/1.1 200") || !ends_chunked(&resp) {
            bad.push(format!("keep-alive request {n}: closed {closed}, {} bytes", resp.len()));
            break;
        }
    }
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} cases differ from HAProxy:\n{}", bad.len(), bad.join("\n"));
}
