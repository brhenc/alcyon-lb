// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An ACL on a multi-value fetch stops at the first occurrence a converter gives no sample for
//! (`acl_exec_cond` in `src/acl.c`: `continue` to the next expression), T362. Expected values
//! measured on HAProxy 3.5-dev8-885761-29 with the same configuration, 2026-10-18.

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
  acl a1 req.hdr(a),field(2,:) -m found
  acl a2 req.hdr(a),field(2,:) -m str q
  acl a3 req.hdr(a),field(2,:) -m beg q
  acl a4 req.hdr(a),field(2,:) -m str zz
  acl a5 req.cook(c),field(2,:) -m found
  http-request set-var(txn.m1) str(1) if a1
  http-request set-var(txn.m2) str(2) unless a2
  http-request set-var(txn.m3) str(3) if !a3
  http-request set-var(txn.m4) str(4) unless a4
  http-request set-var(txn.m5) str(5) if a5
  http-request return status 200 hdr x-m \"[%[var(txn.m1)]%[var(txn.m2)]%[var(txn.m3)]%[var(txn.m4)]%[var(txn.m5)]]\"
";

#[test]
fn a_converter_failure_ends_the_acl_expression() {
    let fe = common::reserve_addr();
    let config = alcyon_config::parse_str(&CFG.replace("@FE@", &fe.to_string())).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    // (extra header lines, expected x-m): `p` has no `:` so field(2,:) gives no sample for it.
    let cases: [(&str, &str); 8] = [
        ("a: p:q\r\na: p:q\r\n", "[14]"),
        ("a: p\r\na: p:q\r\na: p:q\r\n", "[234]"),
        ("a: p:q\r\na: p\r\na: p:q\r\n", "[14]"),
        ("a: p:q\r\na: p:q\r\na: p\r\n", "[14]"),
        ("a: p\r\na: p:q\r\n", "[234]"),
        ("Cookie: c=p:q; c=p:q\r\n", "[2345]"),
        ("Cookie: c=p; c=p:q\r\n", "[234]"),
        ("Cookie: c=p:q; c=p\r\n", "[2345]"),
    ];
    let client = thread::spawn(move || {
        cases
            .iter()
            .map(|(h, _)| {
                let mut s = TcpStream::connect(fe).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                write!(s, "GET / HTTP/1.1\r\nHost: x\r\n{h}Connection: close\r\n\r\n").expect("send");
                let mut out = String::new();
                let _ = s.read_to_string(&mut out);
                out.lines().find_map(|l| l.strip_prefix("x-m: ")).unwrap_or("-").to_string()
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    assert_eq!(got, ["[14]", "[234]", "[14]", "[14]", "[234]", "[2345]", "[234]", "[2345]"]);
}

/// Outside an ACL the last occurrence gives the value: an earlier one a converter fails on
/// does not matter, a failure on the last leaves the value empty (`set-header`-style `hdr`, same configuration on HAProxy
/// 3.5-dev8-885761-29, 2026-10-18).
#[test]
fn outside_an_acl_a_converter_failure_does_not_stop_the_later_occurrences() {
    let fe = common::reserve_addr();
    let cfg = "defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind @FE@
  http-request return status 200 hdr y \"[%[req.hdr(x),ipmask(24)]]\"
";
    let config = alcyon_config::parse_str(&cfg.replace("@FE@", &fe.to_string())).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let cases: [(&str, &str); 4] = [
        ("X: abc\r\nX: 1.2.3.4\r\nX: 5.6.7.8\r\n", "[5.6.7.0]"),
        ("X: 1.2.3.4\r\nX: abc\r\n", "[]"),
        ("X: 1.2.3.4\r\nX: 5.6.7.8\r\nX: zz\r\nX: 9.9.9.9\r\n", "[9.9.9.0]"),
        ("X: abc\r\n", "[]"),
    ];
    let client = thread::spawn(move || {
        cases
            .iter()
            .map(|(h, _)| {
                let mut s = TcpStream::connect(fe).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                write!(s, "GET / HTTP/1.1\r\nHost: x\r\n{h}Connection: close\r\n\r\n").expect("send");
                let mut out = String::new();
                let _ = s.read_to_string(&mut out);
                out.lines().find_map(|l| l.strip_prefix("y: ")).unwrap_or("-").to_string()
            })
            .collect::<Vec<_>>()
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !client.is_finished() && Instant::now() < deadline {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    let got = client.join().expect("client");
    assert_eq!(got, ["[5.6.7.0]", "[]", "[9.9.9.0]", "[]"]);
}
