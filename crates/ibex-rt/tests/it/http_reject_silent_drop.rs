// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request reject`, `http-request silent-drop` and `http-response silent-drop`
//! (tasks/T305 item 1), as `HAProxy` 3.5-dev8 does them. Before this, a configuration using
//! one failed to load.
//!
//! Measured on `HAProxy`, h1 over loopback:
//! * `reject`: the client gets a FIN and no byte; the log line has status `-1`, flags `PR--`;
//!   the frontend's `dreq` goes up (not the backend's); the server is never contacted.
//! * `silent-drop`: no response either, and on loopback the client sees a reset (TTL 1 does
//!   not stop a reset on the local host); same log line and counter.
//! * `http-response silent-drop`: the server was contacted, the response never reaches the
//!   client (a reset); the log line has the server's status and `PR--`; `dreq` goes up on
//!   both the frontend and the backend.
//!
//! Set `T305_ORACLE=/path/to/haproxy` to run the same cases against it.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Proxy {
    child: Child,
    addr: SocketAddr,
    stats: SocketAddr,
    hits: Arc<AtomicUsize>,
    log: UdpSocket,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn proxy(rules: &str, mode: &str) -> Proxy {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let be = ls.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let h2 = Arc::clone(&hits);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let h3 = Arc::clone(&h2);
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = s.read(&mut buf) {
                    h3.fetch_add(1, Ordering::SeqCst);
                    let _ = n;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    let log = UdpSocket::bind("127.0.0.1:0").expect("bind log");
    log.set_read_timeout(Some(Duration::from_millis(1500))).expect("timeout");
    let (addr, stats) = (common::reserve_addr(), common::reserve_addr());
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 3s\n    timeout server 3s\n    \
         timeout connect 1s\nfrontend f\n    bind {addr} {mode}\n    log {} local0\n    option httplog\n{rules}    \
         default_backend b\nbackend b\n    server s {be}\nfrontend st\n    bind {stats}\n    stats enable\n    stats uri /st\n",
        log.local_addr().expect("log addr")
    )
    .expect("write cfg");
    let bin = std::env::var("T305_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn proxy");
    assert!(common::wait_listening(addr), "proxy never listened");
    Proxy { child, addr, stats, hits, log, _cfg: cfg }
}

/// The value of CSV column `col` on the FRONTEND or BACKEND row of proxy `f` / `b`.
fn stat(p: &Proxy, row: &str, col: &str) -> u64 {
    let mut c = TcpStream::connect(p.stats).expect("stats connect");
    c.write_all(b"GET /st;csv HTTP/1.0\r\n\r\n").expect("stats send");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("stats read");
    let csv = out.split("\r\n\r\n").nth(1).unwrap_or_default();
    let mut lines = csv.lines();
    let head: Vec<&str> = lines.next().unwrap_or_default().trim_start_matches("# ").split(',').collect();
    let idx = head.iter().position(|h| *h == col).expect("column");
    let want = if row == "f" { ("f", "FRONTEND") } else { ("b", "BACKEND") };
    lines
        .map(|l| l.split(',').collect::<Vec<_>>())
        .find(|f| f.first() == Some(&want.0) && f.get(1) == Some(&want.1))
        .and_then(|f| f.get(idx).and_then(|v| v.parse().ok()))
        .expect("stat row")
}

/// What an h1 client sees of `GET path`: the bytes, and how it ended (`None` for a FIN).
fn get(p: &Proxy, path: &str) -> (Vec<u8>, Option<ErrorKind>) {
    let mut c = TcpStream::connect(p.addr).expect("connect");
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_millis(800))).expect("timeout");
    let (mut out, mut buf) = (Vec::new(), [0u8; 4096]);
    let end = Instant::now() + Duration::from_secs(4);
    while Instant::now() < end {
        match c.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Some(e.kind())),
        }
    }
    (out, Some(ErrorKind::TimedOut))
}

/// The next log line that is not the `<BADREQ>` of the connect probe.
fn log_line(p: &Proxy) -> String {
    let mut b = [0u8; 2048];
    loop {
        let n = p.log.recv(&mut b).expect("a log line");
        let line = String::from_utf8_lossy(&b[..n]).into_owned();
        if !line.contains("<BADREQ>") {
            return line;
        }
    }
}

const REQ_RULES: &str = "    http-request reject if { path /rej }\n    http-request silent-drop unless { path -m beg /rej /ok }\n";

#[test]
fn http_request_reject_closes_without_a_response() {
    let p = proxy(REQ_RULES, "");
    let (out, end) = get(&p, "/rej");
    assert_eq!((out.as_slice(), end), (&b""[..], None), "a FIN and nothing else");
    let line = log_line(&p);
    assert!(line.contains(" -1 0 - - PR-- "), "log line: {line}");
    assert!(line.contains("\"GET /rej HTTP/1.1\""), "log line: {line}");
    assert_eq!(stat(&p, "f", "dreq"), 1);
    assert_eq!(stat(&p, "b", "dreq"), 0);
    assert_eq!(p.hits.load(Ordering::SeqCst), 0, "the server was not contacted");
    // The condition decides: a request it does not match goes through.
    let (out, end) = get(&p, "/ok");
    assert!(out.starts_with(b"HTTP/1.1 200"), "answered {:?}", String::from_utf8_lossy(&out));
    assert_eq!(end, Some(ErrorKind::WouldBlock), "kept alive");
    assert_eq!(p.hits.load(Ordering::SeqCst), 1);
}

#[test]
fn http_request_silent_drop_sends_nothing() {
    let p = proxy(REQ_RULES, "");
    let (out, end) = get(&p, "/other");
    assert!(out.is_empty(), "got {:?}", String::from_utf8_lossy(&out));
    assert_eq!(end, Some(ErrorKind::ConnectionReset), "loopback sees the reset");
    let line = log_line(&p);
    assert!(line.contains(" -1 0 - - PR-- "), "log line: {line}");
    assert_eq!(stat(&p, "f", "dreq"), 1);
    assert_eq!(p.hits.load(Ordering::SeqCst), 0, "the server was not contacted");
}

#[test]
fn http_response_silent_drop_loses_the_response() {
    let rules = "    http-request set-var(txn.sd) int(1) if { path /sd }\n    \
                 http-response silent-drop if { var(txn.sd) -m found }\n";
    let p = proxy(rules, "");
    let (out, end) = get(&p, "/sd");
    assert!(out.is_empty(), "got {:?}", String::from_utf8_lossy(&out));
    assert_eq!(end, Some(ErrorKind::ConnectionReset));
    let line = log_line(&p);
    // `%B` is the server's response as it was received, head and body (T305 item 8).
    assert!(line.contains(" 200 51 - - PR-- "), "log line: {line}");
    assert_eq!(stat(&p, "f", "dreq"), 1);
    assert_eq!(stat(&p, "b", "dreq"), 1);
    assert_eq!(p.hits.load(Ordering::SeqCst), 1, "the server was asked");
    let (out, _) = get(&p, "/ok");
    assert!(out.starts_with(b"HTTP/1.1 200"), "answered {:?}", String::from_utf8_lossy(&out));
}

fn frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("small");
    let mut v = len.to_be_bytes()[1..].to_vec();
    v.extend_from_slice(&[ftype, flags]);
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short")];
    v.extend_from_slice(path.as_bytes());
    v.extend_from_slice(&[0x01, 9]);
    v.extend_from_slice(b"localhost");
    v
}

/// The (type, stream, payload) of every frame the proxy sends for `GET`s on streams 1, 3
/// (`paths`) before the connection ends or 1.5 s pass.
fn h2_exchange(p: &Proxy, paths: &[&str]) -> Vec<(u8, u32, Vec<u8>)> {
    let mut c = TcpStream::connect(p.addr).expect("connect");
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(4, 0, 0, &[]));
    for (i, path) in paths.iter().enumerate() {
        out.extend(frame(1, 5, u32::try_from(2 * i + 1).expect("small"), &hpack_get(path)));
    }
    c.write_all(&out).expect("send");
    c.set_read_timeout(Some(Duration::from_millis(1500))).expect("timeout");
    let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
    loop {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let (mut frames, mut i) = (Vec::new(), 0);
    while i + 9 <= buf.len() {
        let len = (usize::from(buf[i]) << 16) | (usize::from(buf[i + 1]) << 8) | usize::from(buf[i + 2]);
        if i + 9 + len > buf.len() {
            break;
        }
        let sid = u32::from_be_bytes([buf[i + 5] & 0x7f, buf[i + 6], buf[i + 7], buf[i + 8]]);
        frames.push((buf[i + 3], sid, buf[i + 9..i + 9 + len].to_vec()));
        i += 9 + len;
    }
    frames
}

#[test]
fn http_request_reject_on_an_h2_stream() {
    let p = proxy(REQ_RULES, "proto h2");
    let frames = h2_exchange(&p, &["/rej"]);
    eprintln!("{frames:?}");
    // The stream is reset, with ENHANCE_YOUR_CALM, and so is the connection (GOAWAY).
    assert!(frames.iter().any(|(t, s, pl)| *t == 3 && *s == 1 && pl == &[0, 0, 0, 0xb]), "{frames:?}");
    assert!(frames.iter().any(|(t, _, pl)| *t == 7 && pl.get(4..8) == Some(&[0, 0, 0, 0xb])), "{frames:?}");
    assert!(!frames.iter().any(|(t, ..)| *t == 1), "no response: {frames:?}");
    assert_eq!(p.hits.load(Ordering::SeqCst), 0);
    assert_eq!(stat(&p, "f", "dreq"), 1);
}

#[test]
fn http_request_silent_drop_on_an_h2_stream() {
    let p = proxy(REQ_RULES, "proto h2");
    let frames = h2_exchange(&p, &["/other"]);
    eprintln!("{frames:?}");
    assert!(!frames.iter().any(|(t, ..)| *t == 1), "no response: {frames:?}");
    assert_eq!(p.hits.load(Ordering::SeqCst), 0);
    assert_eq!(stat(&p, "f", "dreq"), 1);
}

/// The other streams of the connection survive a silent-drop: stream 1 is answered, stream
/// 3 is reset with `REFUSED_STREAM` and nothing else, and the connection stays open.
#[test]
fn an_h2_silent_drop_leaves_the_other_streams_alone() {
    let p = proxy(REQ_RULES, "proto h2");
    let frames = h2_exchange(&p, &["/ok", "/other"]);
    assert!(frames.iter().any(|(t, s, _)| *t == 1 && *s == 1), "stream 1 answered: {frames:?}");
    assert!(frames.iter().any(|(t, s, pl)| *t == 3 && *s == 3 && pl == &[0, 0, 0, 7]), "stream 3 refused: {frames:?}");
    assert!(!frames.iter().any(|(t, s, _)| (*t == 1 || *t == 0) && *s == 3), "nothing else on stream 3: {frames:?}");
    assert!(!frames.iter().any(|(t, ..)| *t == 7), "no GOAWAY: {frames:?}");
}

#[test]
fn an_h2_response_silent_drop_resets_the_stream() {
    let rules = "    http-request set-var(txn.sd) int(1) if { path /sd }\n    \
                 http-response silent-drop if { var(txn.sd) -m found }\n";
    let p = proxy(rules, "proto h2");
    let frames = h2_exchange(&p, &["/sd"]);
    assert!(frames.iter().any(|(t, s, pl)| *t == 3 && *s == 1 && pl == &[0, 0, 0, 7]), "{frames:?}");
    assert!(!frames.iter().any(|(t, ..)| *t == 1 || *t == 0), "no response: {frames:?}");
    assert_eq!(stat(&p, "f", "dreq"), 1);
}

#[test]
fn http_response_redirect_is_a_local_answer_in_the_log() {
    // HAProxy 3.5-dev8 (2026-10-11): the redirect a response rule sends is logged `LH--`
    // (a local answer while the response head was processed, not an error), and `%B` is
    // still the server's response (51: the HTX message of `200`, `content-length: 2`, `ok`).
    let p = proxy("    http-response redirect location /x\n", "");
    let (out, _) = get(&p, "/r");
    assert!(out.starts_with(b"HTTP/1.1 302"), "answered {:?}", String::from_utf8_lossy(&out));
    let line = log_line(&p);
    assert!(line.contains(" 302 51 - - LH-- "), "log line: {line}");
}
