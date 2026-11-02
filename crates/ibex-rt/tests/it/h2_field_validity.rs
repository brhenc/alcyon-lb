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
    /// Forwarded, answered 200, and the server saw these bytes in the request.
    Forwards(&'static [u8]),
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
    out.extend(normalisation_cases());
    out
}

/// T451: what `HAProxy` normalises, and a name that is not UTF-8.
fn normalisation_cases() -> Vec<Case> {
    let mut out = Vec::new();
    let mut add = |id: String, frames: Vec<u8>, want| out.push(Case { id, frames, want });
    let one = |id: &str, m: &[u8], s: &[u8], p: &[u8], a: &[u8], x: &[(&[u8], &[u8])]| frame(1, 5, 1, &block(id, m, s, p, a, x));
    // T451 row 1: a value's leading and trailing blanks (space, tab) are trimmed, as
    // `h2_make_htx_request` trims them; a cookie's are not (`http_cookie_merge`).
    let id = "trim-sp".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"x-a", b"   ok  ")]), Want::Forwards(b"\r\nx-a: ok\r\n"));
    let id = "trim-tab".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"x-a", b"\t ok \t")]), Want::Forwards(b"\r\nx-a: ok\r\n"));
    let id = "trim-cookie".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"cookie", b"  a=1  ")]), Want::Forwards(b"\r\ncookie:   a=1  \r\n"));
    // T451 row 2: `:path *` with an `:authority` is the absolute form without a path,
    // which goes as `/`, except for OPTIONS; without `:authority` it stays `*`.
    let id = "star-get".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"*", b"x", &[]), Want::Forwards(b"GET / HTTP/1.1\r\n"));
    let id = "star-options".to_string();
    add(id.clone(), one(&id, b"OPTIONS", b"http", b"*", b"x", &[]), Want::Forwards(b"OPTIONS * HTTP/1.1\r\n"));
    let id = "star-host".to_string();
    let mut b = lit(b":method", b"GET");
    b.extend(lit(b":scheme", b"http"));
    b.extend(lit(b":path", b"*"));
    b.extend(lit(b"host", b"x"));
    b.extend(lit(b"x-case", id.as_bytes()));
    add(id.clone(), frame(1, 5, 1, &b), Want::Forwards(b"GET * HTTP/1.1\r\n"));
    // T451 row 3: a name with a byte that is not UTF-8, plain or Huffman-coded, is a name
    // that is not a token: the stream is reset, the connection stays.
    let id = "name-e9".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"x-\xe9", b"1")]), Want::Rst);
    let id = "name-e9-huff".to_string();
    let mut b = block(&id, b"GET", b"http", b"/", b"x", &[]);
    let mut h = Vec::new();
    ibex_proto::hpack::encode_huffman(b"x-\xe9", &mut h);
    b.extend([0x00, 0x80 | u8::try_from(h.len()).expect("short")]);
    b.extend(&h);
    b.extend([0x01, b'1']);
    add(id.clone(), frame(1, 5, 1, &b), Want::Rst);
    // The same byte in a value: HAProxy forwards it as it came, in a cookie too, the
    // crumbs joined (measured on 3.5-dev8, E1: `x-a: caf\xe9`, `x-a: \xff\xfe`,
    // `cookie: a=\xe9;  b=2 `). Ibex carries the fields as bytes into the HTX since E1.
    let id = "val-e9".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"x-a", b"caf\xe9")]), Want::Forwards(b"\r\nx-a: caf\xe9\r\n"));
    let id = "val-ff".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"x-a", b"\xff\xfe")]), Want::Forwards(b"\r\nx-a: \xff\xfe\r\n"));
    let id = "cookie-e9".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/", b"x", &[(b"cookie", b"a=\xe9"), (b"cookie", b" b=2 ")]), Want::Forwards(b"\r\ncookie: a=\xe9;  b=2 \r\n"));
    // E1: a `content-length` that is no length, or two that differ, is RST_STREAM
    // PROTOCOL_ERROR (`h2_parse_cont_len_header`; measured on 3.5-dev8: `abc`, `5\xe9`, `5`
    // then `6`), with the body that follows; Ibex forwarded `abc` and the two lengths.
    for (k, lens) in [("cl-abc", &[&b"abc"[..]][..]), ("cl-e9", &[b"5\xe9"]), ("cl-56", &[b"5", b"6"])] {
        let id = k.to_string();
        let extra: Vec<(&[u8], &[u8])> = lens.iter().map(|v| (&b"content-length"[..], *v)).collect();
        let mut f = frame(1, 4, 1, &block(&id, b"POST", b"http", b"/", b"x", &extra));
        f.extend(frame(0, 1, 1, b"hello"));
        add(id, f, Want::Rst);
    }
    // A `:path` that is UTF-8 but not ASCII: the HTTP/1 parser refuses it, so the head
    // has no HTX and goes as text (`h2_bridge::text_wire`); without a length, chunked.
    // Measured on 3.5-dev8: `POST /caf\xc3\xa9` forwarded with `transfer-encoding: chunked`.
    let id = "path-utf8-chunked".to_string();
    let mut f = frame(1, 4, 1, &block(&id, b"POST", b"http", "/caf\u{e9}".as_bytes(), b"x", &[]));
    f.extend(frame(0, 1, 1, b"hello"));
    add(id, f, Want::Forwards(b"POST /caf\xc3\xa9 HTTP/1.1\r\nhost: x\r\nx-case: path-utf8-chunked\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"));
    // The same head with a length not written in its digits (`005`, `5` twice): one
    // `content-length: 5` in the first one's place (measured on 3.5-dev8, `%U` 76 both).
    for (k, lens) in [("path-utf8-cl005", &[&b"005"[..]][..]), ("path-utf8-cl55", &[b"5", b"5"])] {
        let id = k.to_string();
        let extra: Vec<(&[u8], &[u8])> = lens.iter().map(|v| (&b"content-length"[..], *v)).collect();
        let mut f = frame(1, 4, 1, &block(&id, b"POST", b"http", "/caf\u{e9}".as_bytes(), b"x", &extra));
        f.extend(frame(0, 1, 1, b"hello"));
        let want: &'static [u8] = Box::leak(format!("POST /caf\u{e9} HTTP/1.1\r\nhost: x\r\nx-case: {id}\r\ncontent-length: 5\r\n\r\nhello").into_bytes().into_boxed_slice());
        add(id, f, Want::Forwards(want));
    }
    // In `:path` HAProxy forwards it too, measured on 3.5-dev8 (X7): `GET /a\xe9b HTTP/1.1`, the
    // log line `GET http://x/a#E9b HTTP/2.0 U=49`.
    let id = "path-e9".to_string();
    add(id.clone(), one(&id, b"GET", b"http", b"/a\xe9b", b"x", &[]), Want::Forwards(b"GET /a\xe9b HTTP/1.1\r\nhost: x\r\nx-case: path-e9\r\n\r\n"));
    // Two `:path`: a malformed request (X7: the path is read as bytes in the loop).
    let mut two = lit(b":method", b"GET");
    two.extend(lit(b":scheme", b"http"));
    two.extend(lit(b":path", b"/a"));
    two.extend(lit(b":path", b"/b"));
    two.extend(lit(b":authority", b"x"));
    add("path-twice".to_string(), frame(1, 5, 1, &two), Want::Rst);
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

/// A server that answers 200 to anything, and what each of its connections carried.
fn server() -> (std::net::SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
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
    (be, seen)
}

/// An ibex with an h2 frontend (`fe_extra` added to it) in front of `be`, and its port.
fn proxy(be: std::net::SocketAddr, fe_extra: &str) -> (std::process::Child, u16, std::path::PathBuf) {
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2field_{}_{port}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 20s\n\ttimeout server 20s\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n{fe_extra}\tdefault_backend be\n\
             backend be\n\tserver s1 {be}\n"
        ),
    )
    .expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "never listened");
    (child, port, cfg)
}

/// Each case on a connection of its own; the cases that differ from what they want.
fn run(fe_extra: &str, all: &[Case]) -> Vec<String> {
    let (be, seen) = server();
    let (mut child, port, cfg) = proxy(be, fe_extra);
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
            Want::Forwards(b) => got == Got::Status("200".into()) && fwd.iter().any(|h| h.windows(b.len()).any(|w| w == b)),
        };
        if !ok {
            let shown: Vec<String> = fwd.iter().map(|h| h.escape_ascii().to_string()).collect();
            wrong.push(format!("{}: want {:?}, got {got:?}, server saw {shown:?}", c.id, c.want));
        }
    }
    wrong
}

#[test]
fn an_h2_field_the_http1_head_cannot_carry_is_refused_before_the_server() {
    let all = cases();
    let wrong = run("", &all);
    assert!(wrong.is_empty(), "{} of {} cases differ from HAProxy:\n{}", wrong.len(), all.len(), wrong.join("\n"));
}

/// T451 row 4: `option accept-unsafe-violations-in-http-request` relaxes the `:path` check
/// as `h2_make_htx_request(.., relaxed)` does (measured on 3.5-dev8): a `#` is forwarded, a
/// space, tab or control byte is a 400; a relative or empty `:path` is still refused.
#[test]
fn accept_unsafe_violations_relaxes_the_h2_path_check() {
    let one = |id: &str, p: &[u8]| frame(1, 5, 1, &block(id, b"GET", b"http", p, b"x", &[]));
    let all: Vec<Case> = [
        ("u-hash", &b"/a#b"[..], Want::Forwards(b"GET /a#b HTTP/1.1\r\n")),
        ("u-space", b"/a b", Want::BadRequest),
        ("u-tab", b"/a\tb", Want::BadRequest),
        ("u-ctl", b"/a\x01b", Want::BadRequest),
        ("u-del", b"/a\x7fb", Want::BadRequest),
        ("u-rel", b"a", Want::Rst),
        ("u-empty", b"", Want::Rst),
        ("u-nul", b"/a\0b", Want::Rst),
    ]
    .into_iter()
    .map(|(id, p, want)| Case { id: id.to_string(), frames: one(id, p), want })
    .collect();
    let wrong = run("\toption accept-unsafe-violations-in-http-request\n", &all);
    assert!(wrong.is_empty(), "{} of {} cases differ from HAProxy:\n{}", wrong.len(), all.len(), wrong.join("\n"));
}

/// What each stream of one connection got: the first `RST_STREAM` code or response
/// status per stream id, and a GOAWAY code under id 0.
fn exchange_streams(port: u16, frames: &[u8], want: usize) -> std::collections::BTreeMap<u32, Got> {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    conn.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    conn.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    conn.write_all(&frame(4, 0, 0, &[])).unwrap();
    conn.write_all(frames).unwrap();
    let (mut buf, mut out) = (Vec::new(), std::collections::BTreeMap::new());
    let mut dec = HpackDecoder::new();
    let end = Instant::now() + Duration::from_secs(4);
    let mut chunk = [0u8; 16384];
    while Instant::now() < end && out.len() < want && !out.contains_key(&0) {
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
            let (ftype, sid, p) = (buf[i + 3], u32::from_be_bytes([buf[i + 5], buf[i + 6], buf[i + 7], buf[i + 8]]) & 0x7fff_ffff, &buf[i + 9..i + 9 + len]);
            match ftype {
                3 => {
                    out.entry(sid).or_insert(Got::Rst(u32::from_be_bytes([p[0], p[1], p[2], p[3]])));
                }
                7 => {
                    out.insert(0, Got::Goaway(u32::from_be_bytes([p[4], p[5], p[6], p[7]])));
                }
                1 => {
                    let fields = dec.decode(p).expect("hpack");
                    let st = fields.iter().find(|f| f.name == ":status").map(|f| f.value.clone()).unwrap_or_default();
                    out.entry(sid).or_insert(Got::Status(st));
                }
                _ => {}
            }
            i += 9 + len;
        }
        buf.drain(..i);
    }
    out
}

/// T451 row 3: a name that is not UTF-8 resets its stream alone, and the block is decoded
/// whole first, so the HPACK table stays the client's. Measured on 3.5-dev8: stream 1 adds
/// `x-\xe9z: 1` to the table and is reset, stream 3 adds `x-b: 2` and is answered, stream
/// 5 sends only index 62 (now `x-b: 2`) and the server sees `x-b: 2`. A stream that names
/// the bad entry by its index is reset too.
#[test]
fn a_name_that_is_not_utf8_resets_its_stream_and_keeps_the_connection() {
    let (be, seen) = server();
    let (mut child, port, cfg) = proxy(be, "");
    let lit_indexed = |n: &[u8], v: &[u8]| {
        let mut b = vec![0x40, u8::try_from(n.len()).expect("short")];
        b.extend_from_slice(n);
        b.push(u8::try_from(v.len()).expect("short"));
        b.extend_from_slice(v);
        b
    };
    let base = |id: &str| block(id, b"GET", b"http", b"/", b"x", &[]);
    let mut f = frame(1, 5, 1, &[base("sync-1"), lit_indexed(b"x-\xe9z", b"1")].concat());
    f.extend(frame(1, 5, 3, &[base("sync-3"), lit_indexed(b"x-b", b"2")].concat()));
    f.extend(frame(1, 5, 5, &[base("sync-5"), vec![0xbe] /* index 62 */].concat()));
    // Index 63 is the bad name now.
    f.extend(frame(1, 5, 7, &[base("sync-7"), vec![0xbf] /* index 63 */].concat()));
    let got = exchange_streams(port, &f, 4);
    thread::sleep(Duration::from_millis(1200));
    common::stop(&mut child);
    let _ = std::fs::remove_file(&cfg);
    let want: std::collections::BTreeMap<u32, Got> =
        [(1, Got::Rst(1)), (3, Got::Status("200".into())), (5, Got::Status("200".into())), (7, Got::Rst(1))].into_iter().collect();
    assert_eq!(got, want);
    let seen = seen.lock().unwrap();
    let has = |id: &str, b: &[u8]| {
        let m = format!("x-case: {id}\r\n");
        seen.iter().any(|h| h.windows(m.len()).any(|w| w == m.as_bytes()) && (b.is_empty() || h.windows(b.len()).any(|w| w == b)))
    };
    assert!(has("sync-3", b"\r\nx-b: 2\r\n") && has("sync-5", b"\r\nx-b: 2\r\n"), "server saw {seen:?}");
    assert!(!has("sync-1", b"") && !has("sync-7", b""), "a reset stream reached the server: {seen:?}");
}
