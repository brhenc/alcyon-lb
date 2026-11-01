// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T363f: a chunked message's trailers as `HAProxy` writes them (`http_transfer_encoding.vtc`,
//! c12), and which trailer sections it refuses. Every expected value below was measured on
//! `HAProxy` 3.5-dev8; `T363F_ORACLE=/path/to/haproxy` runs the same cases against it.
//!
//! Where `HAProxy` adds a byte the input has not got (`x-a:v` is written `x-a: v`) Ibex
//! writes the field as it is, in place, without a new buffer; those cases are not here.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct Proxy(Child, std::path::PathBuf);

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> Proxy {
    let dir = std::env::temp_dir().join(format!("t363f-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let bin = std::env::var("T363F_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let p = Proxy(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "no listener on {a}");
    }
    p
}

/// Sends `req`, returns the raw answer up to the close or a pause.
fn exchange(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

const CHUNKED_HEAD: &[u8] = b"POST /t HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n";

/// (trailer section as sent, trailer section as `HAProxy` writes it), each ending with the blank line.
const REWRITTEN: &[(&[u8], &[u8])] = &[
    (b"x-tlr1: value1\r\nX-Tlr2: \tvalue2\t \r\n\r\n", b"x-tlr1: value1\r\nx-tlr2: value2\r\n\r\n"),
    (b"x-a:   v w \t\r\n\r\n", b"x-a: v w\r\n\r\n"),
    (b"x-a: v \r\n\r\n", b"x-a: v\r\n\r\n"),
    (b"x-a: a\r\n\tb\r\n\r\n", b"x-a: a  \tb\r\n\r\n"),
    (b"x-a: a\r\n b\r\n  c\r\n\r\n", b"x-a: a   b    c\r\n\r\n"),
    (b"x-a:\r\n b\r\n\r\n", b"x-a: b\r\n\r\n"),
    (b"x-a: a \r\n  \r\n\r\n", b"x-a: a\r\n\r\n"),
    (b"X-A: a \t b\r\nX-B:  c \r\n\r\n", b"x-a: a \t b\r\nx-b: c\r\n\r\n"),
    (b"X-A: 1\r\nx-a: 2\r\n\r\n", b"x-a: 1\r\nx-a: 2\r\n\r\n"),
    (b"x-a: \t \r\n\r\n", b"x-a: \r\n\r\n"),
    (b"\r\n", b"\r\n"),
];

/// Trailer sections `HAProxy` answers 400 (c14 to c19, and the fields that frame or route).
const REFUSED: &[&[u8]] = &[
    b"x tlr: value\r\n\r\n",
    b"x-tlr value\r\n\r\n",
    b":method: GET\r\n\r\n",
    b": value\r\n\r\n",
    b"x-tlr: val\rue\r\n\r\n",
    b"X-Tlr: value\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nTE: trailers\r\nHost: foo\r\nConnection: close\r\n\r\n",
    b"Content-Length: 5\r\n\r\n",
    b"Transfer-Encoding: chunked\r\n\r\n",
    b"Host: foo\r\n\r\n",
    b"Connection: close\r\n\r\n",
    b"TE: trailers\r\n\r\n",
    b"x-a: a\x00b\r\n\r\n",
    b"x-a : 1\r\n\r\n",
    b" x-a: 1\r\n\r\n",
];

/// Trailer sections `HAProxy` accepts as they are.
const ACCEPTED: &[&[u8]] = &[b"x-a: a\x01b\r\n\r\n", b"x-a: \r\n\r\n", b"x-tlr: value\r\n\r\n"];

#[test]
fn request_trailers_are_forwarded_as_haproxy_writes_them() {
    let be = TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = be.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        for stream in be.incoming() {
            let Ok(mut stream) = stream else { return };
            stream.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            while !buf.ends_with(b"\r\n\r\n") || !buf.windows(7).any(|w| w == b"hello\r\n") || !buf.windows(3).any(|w| w == b"0\r\n") {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let _ = tx.send(buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  tune.ibex.h1-lowercase-headers on\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nlisten fe\n  bind {fe}\n  server s {be_addr}\n"
    );
    let _p = start("req", &cfg, &[fe]);
    for (sent, want) in REWRITTEN {
        let req = [CHUNKED_HEAD, sent].concat();
        let answer = exchange(fe, &req);
        assert!(answer.starts_with(b"HTTP/1.1 200"), "{:?}: {}", String::from_utf8_lossy(sent), String::from_utf8_lossy(&answer));
        let got = rx.recv_timeout(Duration::from_secs(3)).expect("the server saw the request");
        let want = [b"5\r\nhello\r\n0\r\n".as_slice(), want].concat();
        assert!(
            got.ends_with(&want),
            "sent {:?}: the server got {:?}, HAProxy writes {:?}",
            String::from_utf8_lossy(sent),
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want)
        );
    }
}

#[test]
fn response_trailers_are_forwarded_as_haproxy_writes_them() {
    let be = TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = be.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<&'static [u8]>();
    std::thread::spawn(move || {
        for stream in be.incoming() {
            let Ok(mut stream) = stream else { return };
            stream.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
            let mut tmp = [0u8; 4096];
            let mut buf = Vec::new();
            while !buf.ends_with(b"\r\n\r\n") {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let Ok(trailers) = rx.recv_timeout(Duration::from_secs(3)) else { return };
            let _ = stream.write_all([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nworld\r\n0\r\n".as_slice(), trailers].concat().as_slice());
        }
    });
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  tune.ibex.h1-lowercase-headers on\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nlisten fe\n  bind {fe}\n  server s {be_addr}\n"
    );
    let _p = start("rsp", &cfg, &[fe]);
    for (sent, want) in REWRITTEN {
        tx.send(sent).unwrap();
        let answer = exchange(fe, b"GET /t HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        let want = [b"5\r\nworld\r\n0\r\n".as_slice(), want].concat();
        assert!(
            answer.ends_with(&want),
            "sent {:?}: the client got {:?}, HAProxy writes {:?}",
            String::from_utf8_lossy(sent),
            String::from_utf8_lossy(&answer),
            String::from_utf8_lossy(&want)
        );
    }
}

#[test]
fn request_trailer_sections_are_accepted_or_refused_as_haproxy_does() {
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  tune.ibex.h1-lowercase-headers on\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nlisten fe\n  bind {fe}\n  option http-buffer-request\n  http-request return status 200\n"
    );
    let _p = start("acc", &cfg, &[fe]);
    for sent in REFUSED {
        let answer = exchange(fe, &[CHUNKED_HEAD, sent].concat());
        assert!(answer.starts_with(b"HTTP/1.1 400"), "{:?} must be refused: {}", String::from_utf8_lossy(sent), String::from_utf8_lossy(&answer));
    }
    for sent in ACCEPTED.iter().chain(REWRITTEN.iter().map(|(s, _)| s)) {
        let answer = exchange(fe, &[CHUNKED_HEAD, sent].concat());
        assert!(answer.starts_with(b"HTTP/1.1 200"), "{:?} must be accepted: {}", String::from_utf8_lossy(sent), String::from_utf8_lossy(&answer));
    }
}

/// c1 to c10 of `http_transfer_encoding.vtc`, and the combinations around them: the status
/// `HAProxy` answers, and whether the request reaches the server (and with which framing).
#[test]
fn transfer_encoding_and_content_length_are_judged_as_haproxy_does() {
    let be = TcpListener::bind("127.0.0.1:0").unwrap();
    let be_addr = be.local_addr().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        for stream in be.incoming() {
            let Ok(mut stream) = stream else { return };
            stream.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let mut tmp = [0u8; 4096];
            let mut buf = Vec::new();
            while let Ok(n) = stream.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let _ = tx.send(buf);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  tune.ibex.h1-lowercase-headers on\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nlisten fe\n  bind {fe}\n  server s {be_addr}\n"
    );
    let _p = start("te", &cfg, &[fe]);
    // (name, request, status, what the server is sent up to its blank line, lines separated by '|')
    let cases: &[(&str, &[u8], &str, Option<&str>)] = &[
        // c1: the smuggled request is not parsed, the connection closes, the length goes.
        ("c1", b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 31\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n", "200", Some("POST / HTTP/1.1|transfer-encoding: chunked")),
        ("c1-host", b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 31\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n", "200", Some("POST / HTTP/1.1|host: x|transfer-encoding: chunked")),
        ("c2", b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "200", None),
        ("get-te-cl", b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n", "200", Some("GET / HTTP/1.1|host: x|transfer-encoding: chunked")),
        ("te-case", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: ChUnKeD\r\n\r\n0\r\n\r\n", "200", Some("POST / HTTP/1.1|host: x|transfer-encoding: chunked")),
        ("c5", b"POST /1 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTE: trailers, gzip\r\n\r\n0\r\n\r\n", "200", Some("POST /1 HTTP/1.1|host: x|transfer-encoding: chunked|te: trailers")),
        ("c6", b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n0\r\n\r\n", "400", None),
        ("c7", b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip, chunked\r\n\r\n0\r\n\r\n", "400", None),
        ("c8", b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n", "400", None),
        ("c9", b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n", "400", None),
        ("c10", b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", "422", None),
        ("c10-two-lines", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "422", None),
        ("empty", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: \r\n\r\n", "400", None),
        ("trailing-comma", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked,\r\n\r\n0\r\n\r\n", "400", None),
        ("twice", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "400", None),
        ("space-before-colon", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n", "400", None),
        ("xchunked", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n", "400", None),
        ("bad-cl", b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: abc\r\n\r\n0\r\n\r\n", "400", None),
        ("http10-get", b"GET / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "413", None),
    ];
    for (name, req, status, fwd) in cases {
        while rx.try_recv().is_ok() {}
        let answer = String::from_utf8_lossy(&exchange(fe, req)).into_owned();
        assert!(answer.starts_with(&format!("HTTP/1.1 {status}")), "{name}: {answer}");
        match fwd {
            Some(want) => {
                let got = rx.recv_timeout(Duration::from_secs(3)).unwrap_or_else(|_| panic!("{name}: the server saw nothing"));
                let head = String::from_utf8_lossy(&got).split("\r\n\r\n").next().unwrap_or("").replace("\r\n", "|");
                assert_eq!(&head, want, "{name}");
                // Nothing after the first request reaches the server (c1, "GET /smuggled").
                assert!(!String::from_utf8_lossy(&got).contains("/smuggled"), "{name}: smuggled request forwarded: {got:?}");
            }
            None if *status != "200" => {
                assert!(rx.recv_timeout(Duration::from_millis(700)).is_err(), "{name}: refused but forwarded");
            }
            None => {}
        }
    }
}
