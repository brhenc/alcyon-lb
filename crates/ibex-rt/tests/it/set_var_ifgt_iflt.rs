// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T364 S3: `set-var(<name>,ifgt)` and `,iflt)` compare the stored and the new value only when
//! both are `sint` (`var_set`, src/vars.c); with any other pair of types the condition is
//! ignored and the variable is set. Expected values measured on `HAProxy` 3.5-dev8 (probe e2.py).

use crate::common;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

const RULES: &str = "\
  http-request set-var(txn.a) int(5)
  http-request set-var(txn.a,ifgt) int(3)
  http-request set-var(txn.b) int(5)
  http-request set-var(txn.b,ifgt) int(9)
  http-request set-var(txn.c) int(5)
  http-request set-var(txn.c,iflt) int(9)
  http-request set-var(txn.d) int(5)
  http-request set-var(txn.d,iflt) int(3)
  http-request set-var(txn.e) str(5)
  http-request set-var(txn.e,ifgt) int(9)
  http-request set-var(txn.f) int(5)
  http-request set-var(txn.f,ifgt) str(1)
  http-request set-var(txn.g,ifgt) int(1)
  http-request set-var(txn.h) int(5)
  http-request set-var(txn.h,ifgt,ifexists) int(2)
  http-request set-var(txn.i) bool(1)
  http-request set-var(txn.i,iflt) bool(0)
  http-request set-var(txn.j) int(5)
  http-request set-var(txn.k) int(3),set-var(txn.j,ifgt)
  http-request set-var(sess.s) int(5)
  http-request set-var(sess.s,ifgt) int(2)
  http-request set-var(proc.p) int(5)
  http-request set-var(proc.p,iflt) int(8)
  http-request return status 200 content-type text/plain lf-string \"a=%[var(txn.a)] b=%[var(txn.b)] c=%[var(txn.c)] d=%[var(txn.d)] e=%[var(txn.e)] f=%[var(txn.f)] g=%[var(txn.g)] h=%[var(txn.h)] i=%[var(txn.i)] j=%[var(txn.j)] s=%[var(sess.s)] p=%[var(proc.p)]\"
";

#[test]
fn ifgt_and_iflt_compare_only_two_sints() {
    let addr = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\nfrontend f\n  bind {addr}\n{RULES}"
    );
    let path = std::env::temp_dir().join(format!("ibex-t364-ifgt-{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let mut ibex = common::Ibex(
        Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-db").arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex"),
    );
    assert!(common::wait_listening(addr), "ibex did not load/listen");
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").expect("send");
    let mut d = Vec::new();
    let _ = s.read_to_end(&mut d);
    common::stop(&mut ibex);
    let _ = std::fs::remove_file(&path);
    let d = String::from_utf8_lossy(&d).into_owned();
    let body = d.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    // j: the converter form; proc.p: iflt keeps the maximum, 8.
    assert_eq!(body, "a=3 b=5 c=9 d=5 e=9 f=1 g=1 h=2 i=0 j=3 s=2 p=8");
}
