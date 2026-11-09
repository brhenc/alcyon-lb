// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request return ... hdr <name> <fmt>` keeps the spaces of the value, leading, trailing and
//! inner, and those a log-format evaluates to (HAProxy 3.5-dev8-885761-29, measured 2026-10-18).
//! Pin only: this passed on its first run, the reported trimming did not reproduce on HTTP/1 or h2.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

const CFG: &str = "defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind @FE@
  http-request set-var(txn.sp) str(\"  \")
  http-request return status 200 hdr x-both \" a b \" hdr x-lead \" a\" hdr x-trail \"a \" hdr x-sp \"%[var(txn.sp)]\" hdr x-mid \"a  b\" hdr x-lf \" %[var(txn.sp)]z %[var(txn.sp)]\" hdr x-onlysp \" \"
";

#[test]
fn return_header_values_keep_their_spaces() {
    let fe = common::reserve_addr();
    let config = alcyon_config::parse_str(&CFG.replace("@FE@", &fe.to_string())).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let out = client.join().expect("client");
    let got: Vec<&str> = out.lines().filter(|l| l.starts_with("x-")).collect();
    assert_eq!(
        got,
        ["x-both:  a b ", "x-lead:  a", "x-trail: a ", "x-sp:   ", "x-mid: a  b", "x-lf:    z   ", "x-onlysp:  "]
    );
}
