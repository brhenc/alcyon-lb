// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T449: an HTTP/2 request field with a byte the HTTP/1 head cannot carry is malformed
//! (RFC 9113 section 8.2.1) and never reaches the server. A CR LF in a value written into
//! the HTTP/1 head adds a header, or a whole request, the server trusts: request smuggling.
//!
//! Every expected answer was measured on `HAProxy` 3.5-dev8 (the supervisor's
//! probe, grown to every case): `RST_STREAM` `PROTOCOL_ERROR` and the server never
//! sees the request, for NUL / CR / LF in a value, a name or any pseudo-header, in trailers,
//! and split by CONTINUATION; and for a name with an uppercase letter or a byte that is not
//! a token, a `:path` with a control byte, space or `#`, an `:authority` or `host` that
//! `http_authority_has_forbidden_char` refuses, a connection-specific header, `te` other
//! than `trailers`, a forbidden trailer name. A method that is not a token, and a URI with
//! a blank or DEL, are a 400 (`HTX_FL_PARSING_ERROR`), the server not contacted either.

use crate::common;

use ibex_proto::hpack::HpackDecoder;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("short");
    let mut v = Vec::new();
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A literal field without indexing, new name, no Huffman.
fn lit(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, u8::try_from(name.len()).expect("short")];
    v.extend_from_slice(name);
    v.push(u8::try_from(value.len()).expect("short"));
    v.extend_from_slice(value);
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    /// `RST_STREAM` `PROTOCOL_ERROR`, the request never forwarded.
    Rst,
    /// A 400 answered by the proxy, the request never forwarded.
    BadRequest,
    /// Forwarded, answered 200 by the server.
    Pass,
    /// A trailer refused: `RST_STREAM` `PROTOCOL_ERROR`, the head and body forwarded but the
    /// message never ended (the server sees no last chunk).
    RstTrailer,
}

struct Case {
    id: String,
    frames: Vec<u8>,
    want: Want,
}

/// The request's HEADERS block: the four pseudo-headers, the marker `x-case: <id>` the
/// server is searched for, then `extra`.
fn block(id: &str, method: &[u8], scheme: &[u8], path: &[u8], auth: &[u8], extra: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut b = lit(b":method", method);
    b.extend(lit(b":scheme", scheme));
    b.extend(lit(b":path", path));
    b.extend(lit(b":authority", auth));
    b.extend(lit(b"x-case", id.as_bytes()));
    for (n, v) in extra {
        b.extend(lit(n, v));
    }
    b
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut add = |id: String, frames: Vec<u8>, want| out.push(Case { id, frames, want });
    let one = |id: &str, m: &[u8], s: &[u8], p: &[u8], a: &[u8], x: &[(&[u8], &[u8])]| frame(1, 5, 1, &block(id, m, s, p, a, x));
    // The supervisor's four rows, the byte each in a value, a name, every pseudo-header.
    for (k, bad) in [("crlf", &b"\r\nx-injected: 1"[..]), ("lf", b"\nx-injected: 2"), ("cr", b"\r"), ("nul", b"\0")] {
        let v = [&b"b"[..], bad, b"e"].concat();
        let id = format!("val-{k}");
        add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"x-a", &v)]), Want::Rst);
        let id = format!("name-{k}");
        add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(&[&b"x-a"[..], bad].concat(), b"1")]), Want::Rst);
        let id = format!("path-{k}");
        add(id.clone(), one(&id, b"GET", b"http", &[&b"/"[..], &v].concat(), b"x", &[]), Want::Rst);
        let id = format!("auth-{k}");
        add(id.clone(), one(&id, b"GET", b"http", b"/", &[&b"x"[..], &v].concat(), &[]), Want::Rst);
        let id = format!("meth-{k}");
        add(id.clone(), one(&id, &[&b"GET"[..], &v].concat(), b"http", b"/", b"x", &[]), Want::Rst);
        let id = format!("schm-{k}");
        add(id.clone(), one(&id, b"GET", &[&b"http"[..], &v].concat(), b"/", b"x", &[]), Want::Rst);
        // In a trailer: HEADERS, DATA, HEADERS with END_STREAM.
        let id = format!("trl-{k}");
        let mut f = frame(1, 4, 1, &block(&id, b"GET", b"http", b"/", b"x", &[]));
        f.extend(frame(0, 0, 1, id.as_bytes()));
        f.extend(frame(1, 5, 1, &lit(b"x-t", &v)));
        add(id, f, Want::RstTrailer);
        // Split by CONTINUATION at the bad byte, which starts the second fragment.
        let id = format!("cont-{k}");
        let blk = block(&id, b"GET", b"http", b"/", b"x", &[(b"x-a", &v)]);
        let cut = blk.len() - v.len() + 1;
        let mut f = frame(1, 1, 1, &blk[..cut]);
        f.extend(frame(9, 4, 1, &blk[cut..]));
        add(id, f, Want::Rst);
    }
    let names: [(&str, &[u8]); 5] = [("upper", b"X-a"), ("space", b"x a"), ("colon", b"x:a"), ("del", b"x\x7fa"), ("empty-pseudo", b":x")];
    for (k, n) in names {
        let id = format!("name-{k}");
        add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(n, b"1")]), Want::Rst);
    }
    for (k, p, want) in [
        ("space", &b"/a b"[..], Want::Rst),
        ("hash", b"/a#b", Want::Rst),
        ("tab", b"/a\tb", Want::Rst),
        ("rel", b"a", Want::Rst),
        ("del", b"/a\x7fb", Want::BadRequest),
    ] {
        let id = format!("path-{k}");
        add(id.clone(), one(&id, b"GET", b"http", p, b"x", &[]), want);
    }
    for (k, a) in [("space", &b"x y"[..]), ("at", b"u@x"), ("slash", b"x/y")] {
        let id = format!("auth-{k}");
        add(id.clone(), one(&id, b"GET", b"http", b"/", a, &[]), Want::Rst);
    }
    for (k, m) in [("space", &b"GE T"[..]), ("tab", b"GE\tT"), ("del", b"GE\x7fT")] {
        let id = format!("meth-{k}");
        add(id.clone(), one(&id, m, b"http", b"/", b"x", &[]), Want::BadRequest);
    }
    let id = "schm-space".to_string();
    add(id.clone(), one(&id, b"GET", b"ht tp", b"/", b"x", &[]), Want::BadRequest);
    let id = "host-crlf".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"host", b"x\r\ny")]), Want::Rst);
    for (k, n, v) in [
        ("conn", &b"connection"[..], &b"close"[..]),
        ("pconn", b"proxy-connection", b"close"),
        ("ka", b"keep-alive", b"1"),
        ("upgrade", b"upgrade", b"h2c"),
        ("te-enc", b"transfer-encoding", b"chunked"),
        ("te", b"te", b"gzip"),
    ] {
        let id = format!("hdr-{k}");
        add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(n, v)]), Want::Rst);
    }
    for (k, n) in [("host", &b"host"[..]), ("cl", b"content-length"), ("te", b"te"), ("te-enc", b"transfer-encoding"), ("upper", b"X-t")] {
        let id = format!("trl-{k}");
        let mut f = frame(1, 4, 1, &block(&id, b"GET", b"http", b"/", b"x", &[]));
        f.extend(frame(0, 0, 1, id.as_bytes()));
        f.extend(frame(1, 5, 1, &lit(n, b"1")));
        add(id, f, Want::RstTrailer);
    }
    // What stays allowed: a tab, another control byte, DEL in a value; `te: trailers`; a
    // trailer of a valid name.
    for (k, v) in [("tab", &b"a\tb"[..]), ("ctl", b"a\x01b"), ("del", b"a\x7fb")] {
        let id = format!("ok-{k}");
        add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"x-a", v)]), Want::Pass);
    }
    let id = "ok-te".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"te", b"trailers")]), Want::Pass);
    let id = "ok-trl".to_string();
    let mut f = frame(1, 4, 1, &block(&id, b"GET", b"http", b"/", b"x", &[]));
    f.extend(frame(0, 0, 1, id.as_bytes()));
    f.extend(frame(1, 5, 1, &lit(b"x-t", b"1")));
    add(id, f, Want::Pass);
    out
}

/// What came back for stream 1: `RST_STREAM` with its code, a response status, a GOAWAY
/// code, or nothing within the deadline.
#[derive(Debug, PartialEq, Eq)]
enum Got {
    Rst(u32),
    Status(String),
    Goaway(u32),
    Nothing,
}

fn exchange(port: u16, frames: &[u8]) -> Got {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    conn.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    conn.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    conn.write_all(&frame(4, 0, 0, &[])).unwrap();
    conn.write_all(frames).unwrap();
    let mut buf = Vec::new();
    let mut dec = HpackDecoder::new();
    let end = Instant::now() + Duration::from_secs(4);
    let mut chunk = [0u8; 16384];
    while Instant::now() < end {
        match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => {}
        }
        let mut i = 0;
        while i + 9 <= buf.len() {
            let len = usize::from(buf[i]) << 16 | usize::from(buf[i + 1]) << 8 | usize::from(buf[i + 2]);
            if i + 9 + len > buf.len() {
                break;
            }
            let (ftype, p) = (buf[i + 3], &buf[i + 9..i + 9 + len]);
            let code = || u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
            match ftype {
                3 => return Got::Rst(code()),
                7 => return Got::Goaway(u32::from_be_bytes([p[4], p[5], p[6], p[7]])),
                1 => {
                    let fields = dec.decode(p).expect("hpack");
                    let st = fields.iter().find(|f| f.name == ":status").map(|f| f.value.clone()).unwrap_or_default();
                    return Got::Status(st);
                }
                _ => {}
            }
            i += 9 + len;
        }
    }
    Got::Nothing
}

#[test]
fn an_h2_field_the_http1_head_cannot_carry_is_refused_before_the_server() {
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let be = l.local_addr().unwrap();
    let sink = Arc::clone(&seen);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let sink = Arc::clone(&sink);
            thread::spawn(move || {
                // All the connection carries until it goes quiet, trailers included.
                let _ = s.set_read_timeout(Some(Duration::from_millis(800)));
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                while let Ok(n) = s.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&b[..n]);
                }
                sink.lock().unwrap().push(got);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            });
        }
    });
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2field_{}_{port}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 20s\n\ttimeout server 20s\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\
             backend be\n\tserver s1 {be}\n"
        ),
    )
    .expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "never listened");
    let all = cases();
    let answers: Vec<Got> = all
        .iter()
        .map(|c| {
            let f = c.frames.clone();
            thread::spawn(move || exchange(port, &f))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().expect("client"))
        .collect();
    thread::sleep(Duration::from_millis(1500));
    common::stop(&mut child);
    let _ = std::fs::remove_file(&cfg);
    let seen = seen.lock().unwrap();
    let mut wrong = Vec::new();
    for (c, got) in all.iter().zip(answers) {
        let marker = format!("x-case: {}\r\n", c.id);
        let fwd: Vec<&Vec<u8>> = seen.iter().filter(|h| h.windows(marker.len()).any(|w| w == marker.as_bytes())).collect();
        // The last chunk after the case's body: the message was ended for the server.
        let ended = format!("{}\r\n0\r\n", c.id);
        let completed = fwd.iter().any(|h| h.windows(ended.len()).any(|w| w == ended.as_bytes()));
        let ok = match c.want {
            Want::Rst => got == Got::Rst(1) && fwd.is_empty(),
            Want::BadRequest => got == Got::Status("400".into()) && fwd.is_empty(),
            Want::Pass => got == Got::Status("200".into()) && !fwd.is_empty(),
            Want::RstTrailer => got == Got::Rst(1) && !completed && !fwd.iter().any(|h| h.windows(10).any(|w| w == b"x-injected")),
        };
        if !ok {
            let shown: Vec<String> = fwd.iter().map(|h| h.escape_ascii().to_string()).collect();
            wrong.push(format!("{}: want {:?}, got {got:?}, server saw {shown:?}", c.id, c.want));
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ from HAProxy:\n{}", wrong.len(), all.len(), wrong.join("\n"));
}
