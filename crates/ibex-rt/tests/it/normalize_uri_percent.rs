// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request normalize-uri percent-decode-unreserved` and `percent-to-uppercase` on a `%`
//! followed by something that is not two hex digits (T358 #1).
//!
//! Ibex sliced the request `str` at `i + 1..i + 3`, off a character boundary when a multibyte
//! character followed the `%`: the panic aborts the process, and a client sends it with one
//! request (over h2 by default, over h1 with `option accept-unsafe-violations-in-http-request`).
//! Both normalizers also set only `req_uri`, never the HTX message, so the request that was
//! forwarded (and `path`) was left as received.
//!
//! The expected answers were measured on `HAProxy` 3.5-dev8-885761-29 with the same
//! configuration (`return` of `[%[path]]` after the rule), over h1 and over h2: the two
//! agree on every input here.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// (request path, path after `percent-decode-unreserved`, path after `percent-to-uppercase`),
/// measured on the oracle.
const CASES: &[(&[u8], &[u8], &[u8])] = &[
    (b"/%41", b"/A", b"/%41"),
    (b"/%4", b"/%4", b"/%4"),
    (b"/%", b"/%", b"/%"),
    (b"/%G1", b"/%G1", b"/%G1"),
    (b"/%\xc3\xa9", b"/%\xc3\xa9", b"/%\xc3\xa9"),
    (b"/%4\xc3\xa9", b"/%4\xc3\xa9", b"/%4\xc3\xa9"),
    (b"/%a\xc3\xa9", b"/%a\xc3\xa9", b"/%a\xc3\xa9"),
    (b"/%7e%2d%2f%20x", b"/~-%2f%20x", b"/%7E%2D%2F%20x"),
    (b"/\xc3\xa9", b"/\xc3\xa9", b"/\xc3\xa9"),
    (b"/%zz", b"/%zz", b"/%zz"),
    (b"/%41%", b"/A%", b"/%41%"),
];

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = u32::try_from(payload.len()).unwrap().to_be_bytes()[1..].to_vec();
    f.extend_from_slice(&[kind, flags]);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Everything the peer sends until it closes or goes quiet.
fn read_all(s: &mut TcpStream) -> Vec<u8> {
    let mut d = Vec::new();
    let mut b = [0u8; 4096];
    while let Ok(n) = s.read(&mut b) {
        if n == 0 {
            break;
        }
        d.extend_from_slice(&b[..n]);
    }
    d
}

/// The text between the last `[` and `]` of `d`, or the beginning of `d` if there is none.
fn bracketed(d: &[u8]) -> Vec<u8> {
    match (d.iter().position(|&c| c == b'['), d.iter().rposition(|&c| c == b']')) {
        (Some(i), Some(j)) if i < j => d[i..=j].to_vec(),
        _ => format!("no answer: {:?}", String::from_utf8_lossy(&d[..d.len().min(60)])).into_bytes(),
    }
}

fn over_h2(addr: SocketAddr, path: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).expect("connect h2");
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut hdrs = vec![0x82, 0x86, 0x44, u8::try_from(path.len()).unwrap()];
    hdrs.extend_from_slice(path);
    hdrs.extend_from_slice(&[0x41, 1, b'a']);
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(4, 0, 0, b""));
    out.extend(frame(1, 5, 1, &hdrs));
    s.write_all(&out).unwrap();
    bracketed(&read_all(&mut s))
}

fn over_h1(addr: SocketAddr, path: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).expect("connect h1");
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut req = b"GET ".to_vec();
    req.extend_from_slice(path);
    req.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    s.write_all(&req).unwrap();
    bracketed(&read_all(&mut s))
}

fn check(normalizer: &str, col: usize) {
    let (h2, h1) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "global\n  expose-experimental-directives\n\
         defaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         listen f\n  bind {h2} proto h2\n  bind {h1}\n  option accept-unsafe-violations-in-http-request\n\
         \x20 http-request normalize-uri {normalizer}\n\
         \x20 http-request return status 200 content-type text/plain lf-string \"[%[path]]\"\n"
    );
    let path = std::env::temp_dir().join(format!("ibex-nup-{}-{}.cfg", std::process::id(), h1.port()));
    std::fs::write(&path, cfg).unwrap();
    let mut ibex = common::Ibex(
        Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-db")
            .arg("-f")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(common::wait_listening(h1) && common::wait_listening(h2));
    for case in CASES {
        let want = {
            let mut w = b"[".to_vec();
            w.extend_from_slice(if col == 1 { case.1 } else { case.2 });
            w.push(b']');
            w
        };
        for (proto, addr) in [("h2", h2), ("h1", h1)] {
            let got = if proto == "h2" { over_h2(addr, case.0) } else { over_h1(addr, case.0) };
            assert_eq!(
                String::from_utf8_lossy(&got),
                String::from_utf8_lossy(&want),
                "{normalizer} {proto} {:?}",
                String::from_utf8_lossy(case.0)
            );
            assert!(ibex.try_wait().unwrap().is_none(), "ibex died on {:?} over {proto}", String::from_utf8_lossy(case.0));
        }
    }
    common::stop(&mut ibex);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn percent_decode_unreserved_survives_and_matches_haproxy() {
    check("percent-decode-unreserved", 1);
}

#[test]
fn percent_to_uppercase_matches_haproxy() {
    check("percent-to-uppercase", 2);
}
