// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! VV-13: a client that leaves while Ibex is still connecting (retrying) to the server it
//! already chose is logged with that server, not `<NOSRV>`.
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (2026-10-18), `option httplog`, `server s` on a
//! closed port, `timeout connect 1s`, default retries, one GET, the client closes after:
//!
//! ```text
//! 0.1 s   f b/s 0/0/-1/-1/100  -1 0 - - CC-- 1/1/0/0/1 0/0 "GET /x HTTP/1.1"
//! 0.3 s   f b/s 0/0/-1/-1/300  -1 0 - - CC-- 1/1/0/0/1 0/0 "GET /x HTTP/1.1"
//! 1.5 s   f b/s 0/0/-1/-1/1501 -1 0 - - CC-- 1/1/0/0/2 0/0 "GET /x HTTP/1.1"
//! 2.5 s   f b/s 0/0/-1/-1/2502 -1 0 - - CC-- 1/1/0/0/3 0/0 "GET /x HTTP/1.1"
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// The log line (after the client address and accept date) of one request whose client
/// closes `after` it was sent.
fn line_after(after: Duration) -> String {
    let log = UdpSocket::bind("127.0.0.1:0").expect("bind log");
    log.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    let log_addr = log.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let dead = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  log {log_addr} format raw local0\n  option httplog\n  default_backend b\n\
         backend b\n  server s {dead}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(after)).expect("timeout");
    c.write_all(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let _ = c.read(&mut [0u8; 200]);
    drop(c);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 4096];
    let mut got = None;
    while got.is_none() && Instant::now() < deadline {
        if let Ok(n) = log.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            // The probe of `wait_listening` is logged too (a 400); it has no GET.
            if let Some(i) = l.find("] ").filter(|_| l.contains("GET /x")) {
                got = Some(l[i + 2..].trim().to_string());
            }
        }
    }
    common::stop(&mut child);
    got.expect("no log line for the request")
}

/// `f b/s 0/0/-1/-1/<Ta> -1 0 - - CC-- 1/1/0/0/<retries> 0/0 "GET /x HTTP/1.1"`: the
/// fields but the total time.
fn check(after_ms: u64, retries: u32) {
    let line = line_after(Duration::from_millis(after_ms));
    let (_frontend, rest) = line.split_once(' ').expect("frontend");
    let (bs, after_bs) = rest.split_once(' ').expect("server field");
    assert_eq!(bs, "b/s", "client left after {after_ms} ms: {line}");
    let (t, fields) = after_bs.split_once(' ').expect("fields");
    let ta: u64 = t.rsplit('/').next().and_then(|v| v.parse().ok()).expect("Ta");
    assert!(t.starts_with("0/0/-1/-1/"), "timers: {line}");
    assert!(ta >= after_ms - 50 && ta <= after_ms + 300, "Ta {ta} for {after_ms} ms: {line}");
    assert_eq!(
        fields,
        format!("-1 0 - - CC-- 1/1/0/0/{retries} 0/0 \"GET /x HTTP/1.1\""),
        "client left after {after_ms} ms: {line}"
    );
}

#[test]
fn client_leaving_during_the_first_connect_is_logged_with_its_server() {
    check(300, 1);
}

#[test]
fn client_leaving_during_the_retries_is_logged_with_its_server() {
    check(1500, 2);
}
