// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T340: the delimiter of `req.hdr_names`, `res.hdr_names`, `req.cook_names` and `res.cook_names`
//! is the first byte of the argument (`,` without argument, NUL for an empty one), as HAProxy
//! reads `args[0].data.str.area[0]`. Names that are not UTF-8 keep their bytes. The expected
//! values were measured on HAProxy 3.5-dev8.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

/// A server that reads each request head, answers `resp` and closes the connection.
fn backend(resp: &'static [u8]) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let _ = c.write_all(resp);
        }
    });
    addr
}

/// The four lists the header `x-d<n>` holds as `|`-separated hex strings, decoded.
fn parts(addr: SocketAddr, req: &[u8], n: usize) -> Vec<Vec<u8>> {
    let raw = get(addr, req);
    let name = format!("x-d{n}:");
    let head = raw.split(|b| *b == b'\n').find(|l| l.len() > name.len() && l[..name.len()].eq_ignore_ascii_case(name.as_bytes())).unwrap_or_else(|| panic!("no {name} in {:?}", String::from_utf8_lossy(&raw)));
    let hex = String::from_utf8_lossy(&head[name.len()..]).trim().to_string();
    hex.split('|').map(|h| (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2).unwrap_or("zz"), 16).unwrap_or(0xff)).collect()).collect()
}

/// `names` joined by the byte `d`.
fn join(names: &[&[u8]], d: u8) -> Vec<u8> {
    names.join(&d)
}

/// The four lists for the delimiter byte `d`: request headers, response headers, request cookies, response cookies.
fn want(d: u8, req_h: &[&[u8]], res_h: &[&[u8]], req_c: &[&[u8]], res_c: &[&[u8]]) -> Vec<Vec<u8>> {
    vec![join(req_h, d), join(res_h, d), join(req_c, d), join(res_c, d)]
}

#[test]
fn names_delimiter() {
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nSet-Cookie: sa=1\r\nx-c: 2\r\nSet-Cookie: sb=2; Path=/\r\nX-B: 3\r\n\r\nok";
    const BARE: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nok";
    let res_h: &[&[u8]] = &[b"content-length", b"x-b", b"set-cookie", b"x-c", b"set-cookie", b"x-b"];
    let res_c: &[&[u8]] = &[b"sa", b"sb"];

    let (be, bare) = (backend(RESP), backend(BARE));
    let a = common::reserve_addr();
    // The delimiter forms, in the order of the `x-d<n>` headers: none, a 4-byte character
    // (first byte 0xF0), a 2-byte character (first byte 0xC3), an empty string and empty parentheses (NUL, both).
    let forms = ["", "(🙂)", "(ñ)", "(\"\")", "()"];
    let mut cfg = format!("global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  use_backend bare if {{ path /bare }}\n  default_backend b\n");
    for (n, f) in forms.iter().enumerate() {
        for (v, fetch) in [("h", "req.hdr_names"), ("c", "req.cook_names")] {
            cfg += &format!("  http-request set-var(txn.{v}{n}) {fetch}{f},hex\n");
        }
        for (v, fetch) in [("r", "res.hdr_names"), ("s", "res.cook_names")] {
            cfg += &format!("  http-response set-var(txn.{v}{n}) {fetch}{f},hex\n");
        }
    }
    // The headers come after every variable, or `res.hdr_names` would list them.
    for n in 0..forms.len() {
        cfg += &format!("  http-response set-header x-d{n} \"%[var(txn.h{n})]|%[var(txn.r{n})]|%[var(txn.c{n})]|%[var(txn.s{n})]\"\n");
    }
    cfg += &format!("backend b\n  server s {be}\nbackend bare\n  server s {bare}\n");
    let dir = std::env::temp_dir().join(format!("names-delim-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = common::Ibex(child);
    assert!(common::wait_listening(a), "ibex did not listen on {a}");
    let delims = [b',', 0xF0, 0xC3, 0, 0];

    // several headers and cookies
    let many = b"GET / HTTP/1.1\r\nHost: a\r\nX-A: 1\r\nCookie: ca=1; cb=2\r\nX-A: 2\r\nCookie: cc=3\r\nConnection: close\r\n\r\n";
    for (n, d) in delims.iter().enumerate() {
        let req_h: &[&[u8]] = &[b"host", b"x-a", b"cookie", b"x-a", b"cookie"];
        assert_eq!(parts(a, many, n), want(*d, req_h, res_h, &[b"ca", b"cb", b"cc"], res_c), "many, form {n}");
    }
    // one header, no cookie
    let one = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    for (n, d) in delims.iter().enumerate() {
        assert_eq!(parts(a, one, n), want(*d, &[b"host"], res_h, &[], res_c), "one, form {n}");
    }
    // bytes that are not UTF-8: in a cookie name, a cookie value and a header value
    let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX-V: v\xc3\r\nCookie: \xc3%=1; a=\xc3x\r\nConnection: close\r\n\r\n";
    for (n, d) in delims.iter().enumerate() {
        let req_h: &[&[u8]] = &[b"host", b"x-v", b"cookie"];
        assert_eq!(parts(a, raw, n), want(*d, req_h, res_h, &[b"\xc3%", b"a"], res_c), "raw, form {n}");
    }
    // no header at all, in either direction
    let nothing = b"GET /bare HTTP/1.0\r\n\r\n";
    for n in 0..delims.len() {
        assert_eq!(parts(a, nothing, n), vec![Vec::<u8>::new(); 4], "bare, form {n}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
