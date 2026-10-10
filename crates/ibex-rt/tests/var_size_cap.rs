// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A variable cannot grow past the buffer size (T251 item 4). A session variable fed back
//! into itself with `concat` on every keep-alive request reached 24 MB in Ibex.
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` (default `tune.bufsize` 16384), with
//! `set-var(sess.x) var(sess.x),concat(<1000 A>)` on each request of one connection: the
//! length goes 1001, 2001, ... 16001 and stays at 16001 (the next `concat` is larger than
//! the trash and is no sample, so the variable keeps its value); `set-var-fmt(txn.f)
//! "%[var(txn.a)]%[var(txn.a)]"` with a 16000-byte `txn.a` stores 16383 bytes.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn a_variable_stops_growing_at_the_buffer_size() {
    let fe = common::reserve_addr();
    let cfg = std::env::temp_dir().join(format!("ibex_t251_var_{}.cfg", std::process::id()));
    let (thousand, sixteen_k) = ("A".repeat(1000), "A".repeat(16000));
    let text = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n\
         \x20 http-request set-var(sess.x) str(B) if !{{ var(sess.x) -m found }}\n\
         \x20 http-request set-var(sess.x) var(sess.x),concat({thousand})\n\
         \x20 http-request set-var(txn.a) str({sixteen_k})\n\
         \x20 http-request set-var-fmt(txn.f) \"%[var(txn.a)]%[var(txn.a)]\"\n\
         \x20 http-request return status 200 hdr x-len %[var(sess.x),length] hdr x-fmt %[var(txn.f),length]\n"
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut r = BufReader::new(c.try_clone().expect("clone"));
    let mut seen = Vec::new();
    for _ in 0..20 {
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        let (mut len, mut fmt, mut body) = (String::new(), String::new(), 0usize);
        loop {
            let mut l = String::new();
            if r.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
                break;
            }
            let lower = l.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("x-len: ") {
                len = v.trim().to_string();
            } else if let Some(v) = lower.strip_prefix("x-fmt: ") {
                fmt = v.trim().to_string();
            } else if let Some(v) = lower.strip_prefix("content-length: ") {
                body = v.trim().parse().unwrap_or(0);
            }
        }
        let mut skip = vec![0u8; body];
        r.read_exact(&mut skip).expect("body");
        assert_eq!(fmt, "16383", "set-var-fmt is cut at bufsize - 1");
        seen.push(len);
    }
    common::stop(&mut child);
    let _ = std::fs::remove_file(&cfg);
    let want: Vec<String> = (1..=20).map(|i: usize| (i.min(16) * 1000 + 1).to_string()).collect();
    assert_eq!(seen, want);
}
