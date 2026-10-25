// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T471: the options of a rule's format. A format compiled with `LOG_OPT_HTTP` (the value of
//! `set-header`, `add-header`, `replace-header`, `redirect`, ...) ignores `+json`/`+cbor` and does
//! not quote a sample (`+Q`); one compiled without it (`set-var-fmt`, `return lf-string`) keeps
//! them. Every expected value was measured on `HAProxy` 3.5-dev8-885761-29 on 2026-10-25 with the
//! same configuration.

use crate::common;

use ibex_config::parse_str;
use ibex_rt::Engine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const CFG: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
frontend fe\n  bind ADDR\n\
  http-request set-header x-q \"%{+Q}[str(a)]\"\n\
  http-request set-header x-j \"%{+json}o %[str(a)] %[str(b)]\"\n\
  http-request set-header x-l \"%{+json}o lit\"\n\
  http-request set-header x-c \"%{+cbor}o %[str(a)]\"\n\
  http-request set-header x-n \"%{+json}[str(a)] %{+Q,+X}[str(z)]\"\n\
  http-request set-header x-a \"%{+Q}f|%{+json}f|%{+Q,+X}ci\"\n\
  http-request set-header x-v1 abc\n\
  http-request replace-header x-v1 ^(.*)$ \"\\1-%{+Q}[str(q)]\"\n\
  http-request set-var-fmt(txn.q) \"%{+Q}[str(a)]\"\n\
  http-request set-var-fmt(txn.j) \"%{+json}o %[str(a)]\"\n\
  http-request redirect location \"/%{+Q}[str(a)]-%{+json}o\" if { path /r }\n\
  http-request return status 200 content-type text/plain hdr x-q \"%[req.fhdr(x-q)]\" hdr x-j \"%[req.fhdr(x-j)]\" hdr x-l \"%[req.fhdr(x-l)]\" hdr x-c \"%[req.fhdr(x-c)]\" hdr x-n \"%[req.fhdr(x-n)]\" hdr x-a \"%[req.fhdr(x-a)]\" hdr x-v1 \"%[req.fhdr(x-v1)]\" hdr x-vq \"%[var(txn.q)]\" hdr x-vj \"%[var(txn.j)]\" lf-string \"%{+Q}[str(r)] %{+Q}f\"\n";

fn get(path: &str) -> String {
    let addr = common::reserve_addr();
    let cfg = parse_str(&CFG.replace("ADDR", &addr.to_string())).expect("parse");
    let mut engine = Engine::new(&cfg, 64).expect("engine");
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).unwrap();
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("step");
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let out = String::from_utf8_lossy(&out).into_owned();
    out
}

fn header<'a>(r: &'a str, name: &str) -> &'a str {
    let key = format!("\r\n{name}: ");
    let i = r.find(&key).unwrap_or_else(|| panic!("no {name} in {r}")) + key.len();
    r[i..].split("\r\n").next().unwrap_or("")
}

#[test]
fn a_header_value_ignores_quote_and_encoding_options() {
    let r = get("/");
    assert_eq!(header(&r, "x-q"), "a", "{r}");
    assert_eq!(header(&r, "x-j"), "a b", "{r}");
    assert_eq!(header(&r, "x-l"), "lit", "{r}");
    assert_eq!(header(&r, "x-c"), "a", "{r}");
    assert_eq!(header(&r, "x-n"), "a z", "{r}");
    assert_eq!(header(&r, "x-v1"), "abc-q", "{r}");
}

#[test]
fn a_header_value_alias_keeps_quote_but_not_json() {
    let r = get("/");
    assert_eq!(header(&r, "x-a"), "\"fe\"|fe|7F000001", "{r}");
}

#[test]
fn a_variable_or_payload_format_keeps_its_options() {
    let r = get("/");
    assert_eq!(header(&r, "x-vq"), "\"a\"", "{r}");
    assert_eq!(header(&r, "x-vj"), "{}", "{r}");
    assert!(r.ends_with("\"r\" \"fe\""), "{r}");
}

#[test]
fn a_redirect_location_ignores_encoding_options() {
    let r = get("/r");
    assert_eq!(header(&r, "location"), "/a-", "{r}");
}
