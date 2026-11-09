// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! R4: what `set-var` and `set-var-fmt` keep, and what a rule's format renders, when the
//! value is a path or a header: ASCII (copied as bytes into the variable's slot), a byte
//! 0x80-0xFF, a request line longer than the format's inline scratch.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29. Set `R4_ORACLE=/path/to/haproxy`
//! to run these tests against `HAProxy`.

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
    let (fe, be) = (common::reserve_addr(), common::reserve_addr());
    let mut cfg = NamedTempFile::new().expect("tmp");
    let text = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n\
         \x20 http-request set-var(txn.p) path\n\
         \x20 http-request set-var(txn.f) str(old)\n\
         \x20 http-request set-var-fmt(txn.f) \"[%[req.hdr(x)]|%HM|%[path]]\"\n\
         \x20 http-request set-var(txn.s) req.hdr(x),lower\n\
         \x20 http-request set-header x-line \"%r\"\n\
         \x20 http-request set-header x-types \"%[int(5)]|%[bool(1)]|%[bool(0)]|%[src]|%[ipv6(::1)]|%[method]|%[req.hdr(x),base64,b64dec]|%[req.hdr(x)]\"\n\
         \x20 http-response set-header x-p \"%[var(txn.p)]\"\n\
         \x20 http-response set-header x-f \"%[var(txn.f)]\"\n\
         \x20 http-response set-header x-s \"%[var(txn.s)]\"\n\
         \x20 default_backend b\n\
         backend b\n  server s {be}\n\
         frontend s\n  bind {be}\n  http-request return status 200 hdr x-seen \"%[req.hdr(x-line)]\" hdr x-types \"%[req.hdr(x-types)]\"\n"
    );
    cfg.write_all(text.as_bytes()).expect("write");
    let bin = std::env::var("R4_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().expect("spawn");
    let mut p = Proxy { child, fe, _cfg: cfg };
    assert!(common::wait_listening(p.fe) && common::wait_listening(be), "never listened");
    let _ = &mut p;
    p
}

/// The status line and the response headers to `GET <path>` with `X: <x>`, names in lower case.
fn probe(p: &Proxy, path: &[u8], x: &[u8]) -> (String, Vec<(String, Vec<u8>)>) {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = b"GET ".to_vec();
    req.extend_from_slice(path);
    req.extend_from_slice(b" HTTP/1.1\r\nHost: h\r\nConnection: close\r\nX: ");
    req.extend_from_slice(x);
    req.extend_from_slice(b"\r\n\r\n");
    c.write_all(&req).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let end = got.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(got.len());
    let mut lines = got[..end].split(|&b| b == b'\n');
    let status = String::from_utf8_lossy(lines.next().unwrap_or_default()).trim_end().to_string();
    let hdrs = lines
        .filter_map(|l| {
            let l = l.strip_suffix(b"\r").unwrap_or(l);
            let at = l.iter().position(|&b| b == b':')?;
            let v = &l[at + 1..];
            let v = &v[v.iter().position(|&b| b != b' ').unwrap_or(v.len())..];
            Some((String::from_utf8_lossy(&l[..at]).to_ascii_lowercase(), v.to_vec()))
        })
        .collect();
    (status, hdrs)
}

/// `(x-p, x-f, x-s, x-seen)` of one request, escaped as `escape_ascii` prints them.
fn row(p: &Proxy, path: &[u8], x: &[u8]) -> String {
    let (status, hdrs) = probe(p, path, x);
    let h = |n: &str| hdrs.iter().find(|(k, _)| k == n).map(|(_, v)| v.escape_ascii().to_string()).unwrap_or_default();
    format!("{status} | p={} f={} s={} seen={} types={}", h("x-p"), h("x-f"), h("x-s"), h("x-seen"), h("x-types"))
}

#[test]
fn a_path_and_a_format_kept_in_variables_are_what_haproxy_keeps() {
    let p = start();
    let long = format!("/{}", "a".repeat(300));
    let mut got = vec![
        row(&p, b"/api/x", b"Abc"),
        row(&p, b"/api/x?q=1", b"caf\xe9"),
        row(&p, long.as_bytes(), b"V"),
    ];
    // The same variables set again on the next request of a connection: the ASCII path once
    // more after a non-ASCII one (the slot's buffer is reused).
    got.push(row(&p, b"/z", b"Q"));
    for g in &got {
        println!("{g}");
    }
    let long_want = LONG.replace("{A}", &"a".repeat(300));
    let want: Vec<String> = WANT_SHORT.iter().map(ToString::to_string).chain([long_want, LAST.to_string()]).collect();
    assert_eq!(got, want);
}

const WANT_SHORT: &[&str] = &[
    "HTTP/1.1 200 OK | p=/api/x f=[Abc|GET|/api/x] s=abc seen=GET /api/x HTTP/1.1 types=5|1|0|127.0.0.1|::1|GET|Abc|Abc",
    "HTTP/1.1 200 OK | p=/api/x f=[caf\\xe9|GET|/api/x] s=caf\\xe9 seen=GET /api/x?q=1 HTTP/1.1 types=5|1|0|127.0.0.1|::1|GET|caf\\xe9|caf\\xe9",
];
const LONG: &str = "HTTP/1.1 200 OK | p=/{A} f=[V|GET|/{A}] s=v seen=GET /{A} HTTP/1.1 types=5|1|0|127.0.0.1|::1|GET|V|V";
const LAST: &str = "HTTP/1.1 200 OK | p=/z f=[Q|GET|/z] s=q seen=GET /z HTTP/1.1 types=5|1|0|127.0.0.1|::1|GET|Q|Q";
