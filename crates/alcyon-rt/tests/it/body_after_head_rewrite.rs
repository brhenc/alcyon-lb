// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A message body that arrives in the same read as its head must reach the peer intact
//! whatever a rule did to the head (T107). The client sends head and body in one write, the
//! body a position-dependent byte pattern; the server checks every byte and the length.
//! The same is checked for a response body behind an `http-response` rewrite.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(rules: &str, srv: SocketAddr) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let text = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f\n  bind {fe}\n{rules}  default_backend b\nbackend b\n  server s {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon { child, _cfg: f };
    assert!(common::wait_listening(fe), "alcyon never listened with:\n{text}");
    (alcyon, fe)
}

/// Byte `i` of the test pattern: depends on the position, in a way a shifted copy cannot match.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + i / 251) % 251) as u8).collect()
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn header_of(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// Reads one message body framed by `head` (`Content-Length` or chunked) from `c`, starting
/// with `got`, the bytes already read after the head.
fn read_body(c: &mut TcpStream, head: &str, mut got: Vec<u8>) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = vec![0u8; 65536];
    let mut more = |got: &mut Vec<u8>, c: &mut TcpStream| -> bool {
        if Instant::now() > deadline {
            return false;
        }
        match c.read(&mut buf) {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                true
            }
        }
    };
    if let Some(l) = header_of(head, "content-length") {
        let l: usize = l.parse().expect("content-length");
        while got.len() < l && more(&mut got, c) {}
        got.truncate(l);
        return got;
    }
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let eol = loop {
            if let Some(p) = find(&got[pos..], b"\r\n") {
                break pos + p;
            }
            if !more(&mut got, c) {
                return out;
            }
        };
        let size = usize::from_str_radix(std::str::from_utf8(&got[pos..eol]).unwrap_or("x").trim(), 16).unwrap_or(usize::MAX);
        if size == usize::MAX {
            return out;
        }
        pos = eol + 2;
        if size == 0 {
            return out;
        }
        while got.len() < pos + size + 2 {
            if !more(&mut got, c) {
                return out;
            }
        }
        out.extend_from_slice(&got[pos..pos + size]);
        pos += size + 2;
    }
}

fn read_head(c: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut got = Vec::new();
    let mut buf = vec![0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(e) = find(&got, b"\r\n\r\n") {
            let rest = got.split_off(e + 4);
            got.truncate(e);
            return Some((String::from_utf8_lossy(&got).into_owned(), rest));
        }
        if Instant::now() > deadline {
            return None;
        }
        match c.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
}

/// A server that reads one request, checks its body against `pattern(n)`, and answers
/// `200` with a body describing what it saw (`ok` or the first mismatch and the length)
/// followed by the request head it received.
fn checking_server(n: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
                let Some((head, rest)) = read_head(&mut c) else { return };
                let body = read_body(&mut c, &head, rest);
                let want = pattern(n);
                let verdict = if body == want {
                    "ok".to_string()
                } else {
                    let first = body.iter().zip(&want).position(|(a, b)| a != b);
                    format!("BAD len={} want={} first_mismatch={first:?}", body.len(), n)
                };
                let msg = format!("{verdict}\n{head}");
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}", msg.len()).as_bytes());
            });
        }
    });
    addr
}

fn chunked(body: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for c in body.chunks(size) {
        out.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        out.extend_from_slice(c);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// Sends head and body of a POST in a single write through alcyon running `rules`, and returns
/// the server's verdict body.
fn post(rules: &str, n: usize, chunk: Option<usize>) -> String {
    let srv = checking_server(n);
    let (_alcyon, fe) = start(rules, srv);
    let body = pattern(n);
    let (framing, payload) = match chunk {
        None => (format!("Content-Length: {n}\r\n"), body),
        Some(sz) => ("Transfer-Encoding: chunked\r\n".to_string(), chunked(&body, sz)),
    };
    let mut req = format!("POST /a/b?q=1 HTTP/1.1\r\nHost: x\r\nX-Del: gone\r\nX-Rep: aaa-bbb\r\n{framing}\r\n").into_bytes();
    req.extend_from_slice(&payload);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    c.write_all(&req).expect("send");
    let (h, rest) = read_head(&mut c).expect("response head");
    assert!(h.starts_with("HTTP/1.1 200"), "response: {h}");
    String::from_utf8_lossy(&read_body(&mut c, &h, rest)).into_owned()
}

const RULES: &[(&str, &str)] = &[
    ("no-rule", ""),
    ("set-header","  http-request set-header X-Gen 1\n"),
    ("set-header-long", "  http-request set-header X-Gen 0123456789012345678901234567890123456789012345678901234567890123456789\n"),
    ("add-header", "  http-request add-header X-Gen 1\n"),
    ("del-header", "  http-request del-header X-Del\n"),
    ("replace-header", "  http-request replace-header X-Rep aaa-bbb ccccccccccccccccccccccccc\n"),
    ("replace-header-shrink", "  http-request replace-header X-Rep aaa-bbb z\n"),
    ("set-path", "  http-request set-path /a/much/longer/path/than/before\n"),
    ("set-uri", "  http-request set-uri /x\n"),
    ("set-header+del", "  http-request set-header X-Gen 1\n  http-request del-header X-Del\n"),
];

fn run_all(n: usize, chunk: Option<usize>) {
    let mut bad = Vec::new();
    for (name, rules) in RULES {
        let v = post(rules, n, chunk);
        if !v.starts_with("ok\n") {
            bad.push(format!("{name}: {}", v.lines().next().unwrap_or("")));
        }
    }
    assert!(bad.is_empty(), "n={n} chunk={chunk:?}: {bad:#?}");
}

#[test]
fn request_body_content_length_200k() {
    run_all(200_000, None);
}

#[test]
fn request_body_chunked_200k() {
    run_all(200_000, Some(7000));
}

#[test]
fn request_body_content_length_small() {
    run_all(700, None);
}

#[test]
fn request_body_chunked_small() {
    run_all(700, Some(100));
}

#[test]
fn request_body_content_length_around_buffer_size() {
    for n in [16_000, 16_384, 16_400, 32_768, 65_536, 1_000_000] {
        run_all(n, None);
    }
}

#[test]
fn rule_really_applied_with_body() {
    let v = post("  http-request set-header X-Gen 1\n", 5000, None);
    assert!(v.starts_with("ok\n"), "{v}");
    assert_eq!(header_of(&v, "x-gen").as_deref(), Some("1"), "{v}");
}

/// A server answering with a head and a body of `n` bytes in one write.
fn big_response_server(n: usize) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                if read_head(&mut c).is_none() {
                    return;
                }
                let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nX-Del: gone\r\nConnection: close\r\n\r\n").into_bytes();
                r.extend_from_slice(&pattern(n));
                let _ = c.write_all(&r);
            });
        }
    });
    addr
}

#[test]
fn response_body_after_rewrite() {
    let rules: &[&str] = &[
        "  http-response set-header X-Gen 1\n",
        "  http-response add-header X-Gen 1\n",
        "  http-response del-header X-Del\n",
    ];
    let mut bad = Vec::new();
    for n in [700, 200_000] {
        for r in rules {
            let srv = big_response_server(n);
            let (_alcyon, fe) = start(r, srv);
            let mut c = TcpStream::connect(fe).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
            let (h, rest) = read_head(&mut c).expect("head");
            let body = read_body(&mut c, &h, rest);
            if body != pattern(n) {
                bad.push(format!("{r:?} n={n}: got {} bytes", body.len()));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}
