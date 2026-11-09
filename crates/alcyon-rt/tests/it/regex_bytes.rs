// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A regex reads a header value as bytes, as PCRE does without UTF mode (T296): `.` is one
//! byte, so the UTF-8 `é` (C3 A9) is two of them, in `-m reg`, `replace-header` and
//! `regsub`.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29.
//! Set `T296_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

struct Proxy {
    child: Child,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start() -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 2s\n\
         frontend f\n  bind {fe}\n\
         \x20 acl one req.hdr(x) -m reg ^.$\n\
         \x20 acl two req.hdr(x) -m reg ^..$\n\
         \x20 acl three req.hdr(x) -m reg ^...$\n\
         \x20 acl nota req.hdr(x) -m reg ^[^a]$\n\
         \x20 acl notaa req.hdr(x) -m reg ^[^a][^a]$\n\
         \x20 acl wide req.hdr(x) -m reg ^\\W\\W$\n\
         \x20 acl lit req.hdr(x) -m reg ^\u{e9}$\n\
         \x20 acl lit2 req.hdr(x) -m reg ^\u{e9}+$\n\
         \x20 acl cls req.hdr(x) -m reg ^[\u{e9}]$\n\
         \x20 acl cls2 req.hdr(x) -m reg ^[\u{e9}][\u{e9}]$\n\
         \x20 acl nocase req.hdr(x) -m reg -i ^\u{c9}$\n\
         \x20 acl high req.hdr(x) -m reg ^[\\x80-\\xff]+$\n\
         \x20 http-request set-var(txn.a) str(),concat(,txn.a)\n\
         \x20 http-request set-header y1 A if one\n\
         \x20 http-request set-header y2 B if two\n\
         \x20 http-request set-header y3 C if three\n\
         \x20 http-request set-header y4 D if nota\n\
         \x20 http-request set-header y5 E if notaa\n\
         \x20 http-request set-header y6 F if wide\n\
         \x20 http-request set-header y7 G if lit\n\
         \x20 http-request set-header y8 H if lit2\n\
         \x20 http-request set-header y9 I if cls\n\
         \x20 http-request set-header y10 J if cls2\n\
         \x20 http-request set-header y11 K if nocase\n\
         \x20 http-request set-header y12 L if high\n\
         \x20 http-request replace-header x-r ^(.)(.)$ \"<\\2\\1>\"\n\
         \x20 http-request set-header x-sub \"%[req.hdr(x-s),regsub(^.,-)]\"\n\
         \x20 http-request set-header x-suball \"%[req.hdr(x-s),regsub(.,-,g)]\"\n\
         \x20 http-request return status 200 hdr x-y \"%[req.hdr(y1)]%[req.hdr(y2)]%[req.hdr(y3)]%[req.hdr(y4)]%[req.hdr(y5)]%[req.hdr(y6)]%[req.hdr(y7)]%[req.hdr(y8)]%[req.hdr(y9)]%[req.hdr(y10)]%[req.hdr(y11)]%[req.hdr(y12)]\" hdr x-r \"%[req.hdr(x-r)]\" hdr x-sub \"%[req.hdr(x-sub)]\" hdr x-suball \"%[req.hdr(x-suball)]\"\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n"
    )
    .expect("write");
    let bin = std::env::var("T296_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().expect("spawn");
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, fe, _cfg: cfg }
}

fn get(p: &Proxy, hdrs: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n".to_vec();
    req.extend_from_slice(hdrs);
    req.extend_from_slice(b"\r\n");
    c.write_all(&req).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    got
}

/// The value of response header `name` (lower case, as `HAProxy` writes it).
fn header(got: &[u8], name: &str) -> Vec<u8> {
    let key = format!("\r\n{name}: ").into_bytes();
    let at = got.windows(key.len()).position(|w| w == key).unwrap_or_else(|| panic!("no {name} in {}", got.escape_ascii())) + key.len();
    let end = got[at..].windows(2).position(|w| w == b"\r\n").expect("end of line");
    got[at..at + end].to_vec()
}

/// What a request with `value` in `x`, `x-r` and `x-s` comes back as: the letters of the ACLs
/// that matched (`A` is `^.$`, `B` is `^..$`, and so on), `x-r` rewritten, `x-s` through
/// `regsub` once and globally.
fn probe(p: &Proxy, value: &[u8]) -> (String, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut h = Vec::new();
    for name in ["x", "x-r", "x-s"] {
        h.extend_from_slice(name.as_bytes());
        h.extend_from_slice(b": ");
        h.extend_from_slice(value);
        h.extend_from_slice(b"\r\n");
    }
    let got = get(p, &h);
    (String::from_utf8(header(&got, "x-y")).unwrap(), header(&got, "x-r"), header(&got, "x-sub"), header(&got, "x-suball"))
}

#[test]
fn a_utf8_value_is_matched_byte_by_byte() {
    let p = start();
    let mut wrong = Vec::new();
    for (value, want) in EXPECTED {
        let got = probe(&p, value);
        let got = (got.0.as_str(), got.1.as_slice(), got.2.as_slice(), got.3.as_slice());
        if got != *want {
            wrong.push(format!("{}: got {got:?}, want {want:?}", value.escape_ascii()));
        }
    }
    assert!(wrong.is_empty(), "differ from HAProxy:\n{}", wrong.join("\n"));
}

type Row = (&'static [u8], (&'static str, &'static [u8], &'static [u8], &'static [u8]));
const EXPECTED: &[Row] = &[
    // E-acute in UTF-8 is two bytes: `^..$`, `^[^a][^a]$`, `^\W\W$`, the literal and its
    // repeat, a class of its two bytes twice, a high byte run; swapped by `replace-header`.
    (b"\xc3\xa9", ("BEFGHJL", b"<\xa9\xc3>", b"-\xa9", b"--")),
    // E-acute in Latin-1 is one.
    (b"\xe9", ("ADL", b"\xe9", b"-", b"-")),
    (b"\xe2\x82\xac", ("CL", b"\xe2\x82\xac", b"-\x82\xac", b"---")),
    (b"a", ("A", b"a", b"-", b"-")),
];
