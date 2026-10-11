// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The websocket / `Upgrade` handshake, on both sides (tasks/T281 item 3, T274 I1-I2).
//!
//! Request: a request is a websocket handshake when one of its `Connection` lines carries
//! `upgrade` and one of its `Upgrade` lines carries `websocket` (each header read as a list,
//! all lines counted). It must then carry a `Sec-WebSocket-Key` of exactly 24 characters,
//! or it is refused with 400 (`h1_search_websocket_key` in mux_h1.c), unless the frontend
//! has `option accept-unsafe-violations-in-http-request`: then it goes on, and with no key
//! at all the proxy writes a random one. An `Upgrade` without `Connection: upgrade` is
//! dropped, `h2c` and `h2` are taken out of it, and a `Connection: upgrade` without an
//! `Upgrade` loses its token (`h1_postparse_req_hdrs`).
//!
//! Response: a `101` is refused with 502 unless both the request and the response carry
//! `Connection: upgrade` (`http_wait_for_response`), the option or not. A websocket `101`
//! without `Sec-WebSocket-Accept` is refused with 502, but with
//! `option accept-unsafe-violations-in-http-response` it is relayed with the accept the
//! client's key calls for (24 NULs when it sent none that counts), as is any response with
//! `Connection: upgrade` and `Upgrade: websocket` but no accept. When the proxy wrote the
//! key, the server's accept must match it.
//!
//! The expected values were measured on `HAProxy` 3.5-dev8. Set
//! `T281C_ORACLE=/path/to/haproxy` to run the same cases against it.

use crate::common;

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
// The accept for `KEY` is `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=` (RFC 6455 section 1.3); for a key
// of 24 NUL bytes, what `HAProxy` computes when it has no client key, `X7sdFi1aZDLMcFz+yURsFmFjwvU=`.
const U_REQ: &str = "option accept-unsafe-violations-in-http-request";
const U_RSP: &str = "option accept-unsafe-violations-in-http-response";

#[derive(Clone, Copy, Debug)]
enum Check {
    /// This header line, compared without case.
    Has(&'static str),
    /// No header line starting with this, compared without case.
    Lacks(&'static str),
    /// A `sec-websocket-key` of 24 characters that is not [`KEY`]: written by the proxy.
    KeyWritten,
}
use Check::{Has, KeyWritten, Lacks};

struct Case {
    name: &'static str,
    /// `(frontend option, backend option)`.
    opts: (&'static str, &'static str),
    req: Vec<&'static str>,
    /// The request line, `GET` and HTTP/1.1 when `None`.
    line: Option<&'static str>,
    rsp: String,
    status: u16,
    /// `None`: the backend never sees the request.
    backend: Option<Vec<Check>>,
    client: Vec<Check>,
}

const CU: &str = "Connection: Upgrade";
const UW: &str = "Upgrade: websocket";

fn key() -> &'static str {
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="
}

fn ok200() -> String {
    "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".into()
}

fn r101(h: &[&str]) -> String {
    let mut s = String::from("HTTP/1.1 101 Switching Protocols\r\n");
    for l in h {
        s.push_str(l);
        s.push_str("\r\n");
    }
    s.push_str("\r\n");
    s
}

fn ws101() -> String {
    r101(&[UW, CU, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="])
}

fn c(name: &'static str, req: Vec<&'static str>, rsp: String, status: u16, backend: Option<Vec<Check>>, client: Vec<Check>) -> Case {
    Case { name, opts: ("", ""), req, line: None, rsp, status, backend, client }
}

#[allow(clippy::too_many_lines)]
fn cases() -> Vec<Case> {
    let fwd_ws = || Some(vec![Has("upgrade: websocket"), Has("sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==")]);
    let mut v = vec![
        // ---- request side ----
        c("valid handshake", vec![CU, UW, key()], ok200(), 200, fwd_ws(), vec![]),
        c("no key", vec![CU, UW], ok200(), 400, None, vec![]),
        c("key of 10 characters", vec![CU, UW, "Sec-WebSocket-Key: abcdefghij"], ok200(), 400, None, vec![]),
        c("key of 25 characters", vec![CU, UW, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==x"], ok200(), 400, None, vec![]),
        c("Upgrade twice, with a key", vec![CU, UW, UW, key()], ok200(), 200, fwd_ws(), vec![]),
        c("Upgrade twice, no key", vec![CU, UW, UW], ok200(), 400, None, vec![]),
        c("websocket on a second Upgrade line, no key", vec![CU, "Upgrade: foo", UW], ok200(), 400, None, vec![]),
        c("upgrade on a second Connection line, no key", vec!["Connection: keep-alive", "Connection: upgrade", UW], ok200(), 400, None, vec![]),
        c(
            "upgrade on a second Connection line, with a key",
            vec!["Connection: keep-alive", "Connection: upgrade", UW, key()],
            ok200(),
            200,
            Some(vec![Has("connection: upgrade"), Has("upgrade: websocket"), Has("sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==")]),
            vec![],
        ),
        c("list values, no key", vec!["Connection: keep-alive, Upgrade", "Upgrade: foo, WebSocket"], ok200(), 400, None, vec![]),
        c("Upgrade without Connection: upgrade is dropped", vec![UW], ok200(), 200, Some(vec![Lacks("upgrade"), Lacks("connection")]), vec![]),
        c("Connection: upgrade without Upgrade loses it", vec![CU], ok200(), 200, Some(vec![Lacks("upgrade"), Lacks("connection")]), vec![]),
        c("Upgrade: h2c goes, and the upgrade with it", vec![CU, "Upgrade: h2c"], ok200(), 200, Some(vec![Lacks("upgrade"), Lacks("connection")]), vec![]),
        c("h2c taken out of an Upgrade list", vec![CU, "Upgrade: h2c, websocket", key()], ok200(), 200, Some(vec![Has("upgrade: websocket"), Has("connection: upgrade")]), vec![]),
        c(
            "a short key, then a good one",
            vec![CU, UW, "Sec-WebSocket-Key: short", key()],
            ok200(),
            200,
            Some(vec![Has("sec-websocket-key: short"), Has("sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==")]),
            vec![],
        ),
        c("another protocol needs no key", vec![CU, "Upgrade: foo"], ok200(), 200, Some(vec![Has("upgrade: foo"), Has("connection: upgrade")]), vec![]),
        // ---- response side ----
        c("101 with its accept", vec![CU, UW, key()], ws101(), 101, fwd_ws(), vec![Has("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")]),
        c("websocket 101 without accept", vec![CU, UW, key()], r101(&[UW, CU]), 502, fwd_ws(), vec![]),
        c("an accept that does not match the client's key is relayed", vec![CU, UW, key()], r101(&[UW, CU, "Sec-WebSocket-Accept: nope"]), 101, fwd_ws(), vec![Has("sec-websocket-accept: nope")]),
        c("101 to a request that asked for nothing", vec![], ws101(), 502, Some(vec![Lacks("upgrade")]), vec![]),
        c("101 without Connection: upgrade", vec![CU, UW, key()], r101(&[UW, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="]), 502, fwd_ws(), vec![]),
        c("101 without an Upgrade header", vec![CU, UW, key()], r101(&[CU, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="]), 101, fwd_ws(), vec![Has("connection: upgrade"), Lacks("upgrade:")]),
        c("101 to an Upgrade without Connection: upgrade", vec![UW, key()], ws101(), 502, Some(vec![Lacks("upgrade")]), vec![]),
        c("101 to a Connection: upgrade without Upgrade", vec![CU], ws101(), 502, Some(vec![Lacks("upgrade")]), vec![]),
        c("101 with upgrade on a second Connection line, no accept", vec![CU, UW, key()], r101(&["Connection: keep-alive", "Connection: upgrade", UW]), 502, fwd_ws(), vec![]),
        c("101 with Upgrade twice, no accept", vec![CU, UW, key()], r101(&[CU, UW, UW]), 502, fwd_ws(), vec![]),
        c("101 to another protocol", vec![CU, "Upgrade: foo"], r101(&[CU, "Upgrade: foo"]), 101, Some(vec![Has("upgrade: foo")]), vec![Has("upgrade: foo")]),
        c(
            "200 with the websocket headers gets an accept",
            vec![CU, UW, key()],
            "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: websocket\r\ncontent-length: 2\r\n\r\nok".into(),
            200,
            fwd_ws(),
            vec![Has("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")],
        ),
        c(
            "200 with the websocket headers to a plain request",
            vec![],
            "HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: websocket\r\ncontent-length: 2\r\n\r\nok".into(),
            200,
            Some(vec![Lacks("upgrade")]),
            vec![Has("sec-websocket-accept: X7sdFi1aZDLMcFz+yURsFmFjwvU=")],
        ),
        c(
            "101 with Upgrade: h2c only",
            vec![CU, UW, key()],
            r101(&[CU, "Upgrade: h2c", "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="]),
            101,
            fwd_ws(),
            vec![Lacks("upgrade:")],
        ),
    ];
    let mut http10 = c("HTTP/1.0, no key", vec![CU, UW], ok200(), 400, None, vec![]);
    http10.line = Some("GET /c HTTP/1.0");
    v.push(http10);
    let mut post = c("POST with a body length, no key", vec![CU, UW, "content-length: 0"], ok200(), 400, None, vec![]);
    post.line = Some("POST /c HTTP/1.1");
    v.push(post);
    // ---- under the options ----
    let opt = |mut k: Case, fe: &'static str, be: &'static str| {
        k.opts = (fe, be);
        k
    };
    v.push(opt(c("no key, unsafe request: a key is written", vec![CU, UW], ok200(), 200, Some(vec![KeyWritten]), vec![]), U_REQ, ""));
    v.push(opt(
        c("short key, unsafe request: forwarded as it is", vec![CU, UW, "Sec-WebSocket-Key: short"], ok200(), 200, Some(vec![Has("sec-websocket-key: short")]), vec![]),
        U_REQ,
        "",
    ));
    v.push(opt(
        c("101 without accept, unsafe response: the accept is added", vec![CU, UW, key()], r101(&[UW, CU]), 101, fwd_ws(), vec![Has("sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")]),
        "",
        U_RSP,
    ));
    v.push(opt(c("101 to a request that asked for nothing, unsafe response", vec![], ws101(), 502, Some(vec![Lacks("upgrade")]), vec![]), "", U_RSP));
    v.push(opt(c("written key, the server's accept does not match it", vec![CU, UW], ws101(), 502, Some(vec![KeyWritten]), vec![]), U_REQ, ""));
    v.push(opt(
        c("written key, 101 without accept, both options", vec![CU, UW], r101(&[UW, CU]), 101, Some(vec![KeyWritten]), vec![Has("sec-websocket-accept: X7sdFi1aZDLMcFz+yURsFmFjwvU=")]),
        U_REQ,
        U_RSP,
    ));
    v.push(opt(
        c("short key, 101 without accept, both options", vec![CU, UW, "Sec-WebSocket-Key: short"], r101(&[UW, CU]), 101, Some(vec![Has("sec-websocket-key: short")]), vec![Has("sec-websocket-accept: X7sdFi1aZDLMcFz+yURsFmFjwvU=")]),
        U_REQ,
        U_RSP,
    ));
    v
}

/// The head each connection's request came with, by the path of its request line.
type Seen = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// A backend that answers each request with the response of the case its path names.
fn backend(rsps: HashMap<String, String>) -> (SocketAddr, Seen) {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = ls.local_addr().expect("addr");
    let seen: Seen = Arc::default();
    let s2 = Arc::clone(&seen);
    let rsps = Arc::new(rsps);
    thread::spawn(move || {
        for s in ls.incoming() {
            let Ok(mut s) = s else { continue };
            let (seen, rsps) = (Arc::clone(&s2), Arc::clone(&rsps));
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                let mut got = Vec::new();
                let mut buf = [0u8; 16384];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string();
                let path = line.split(' ').nth(1).unwrap_or("").to_string();
                let rsp = rsps.get(&path).cloned().unwrap_or_else(ok200);
                seen.lock().unwrap().insert(path, got);
                let _ = s.write_all(rsp.as_bytes());
                thread::sleep(Duration::from_millis(200));
            });
        }
    });
    (addr, seen)
}

struct Proxy {
    child: Child,
    addr: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn proxy(be: SocketAddr, fe_extra: &str, be_extra: &str) -> Proxy {
    let addr = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 3s\n    timeout server 3s\n    \
         timeout connect 1s\n    timeout http-request 3s\nfrontend f\n    bind {addr}\n    {fe_extra}\n    \
         default_backend b\nbackend b\n    {be_extra}\n    http-reuse never\n    server s {be}\n"
    )
    .expect("write cfg");
    let bin = std::env::var("T281C_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn proxy");
    assert!(common::wait_listening(addr), "proxy never listened");
    Proxy { child, addr, _cfg: cfg }
}

/// Sends `req` and reads the response head (and a `content-length` body).
fn send(addr: SocketAddr, req: &[u8]) -> (Option<u16>, String) {
    let mut c = TcpStream::connect(addr).expect("connect");
    let _ = c.write_all(req);
    let _ = c.set_read_timeout(Some(Duration::from_millis(200)));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    while Instant::now() < deadline {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        if out.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let status = out.starts_with(b"HTTP/1.").then(|| String::from_utf8_lossy(&out[9..12.min(out.len())]).parse().ok()).flatten();
    let head = out.windows(4).position(|w| w == b"\r\n\r\n").map_or(&out[..], |h| &out[..h]);
    (status, String::from_utf8_lossy(head).into_owned())
}

/// What is wrong with `head` (the request or status line left out) against `checks`.
fn check(head: &str, checks: &[Check]) -> Result<(), String> {
    let lines: Vec<String> = head.split("\r\n").skip(1).map(str::to_ascii_lowercase).collect();
    for ck in checks {
        let ok = match ck {
            Has(l) => lines.iter().any(|x| x == &l.to_ascii_lowercase()),
            Lacks(p) => !lines.iter().any(|x| x.starts_with(&p.to_ascii_lowercase())),
            KeyWritten => lines.iter().any(|x| {
                x.strip_prefix("sec-websocket-key: ").is_some_and(|v| v.len() == 24 && v != KEY.to_ascii_lowercase())
            }),
        };
        if !ok {
            return Err(format!("{ck:?} fails on {head:?}"));
        }
    }
    Ok(())
}

#[test]
fn websocket_handshake_rules_match_haproxy() {
    let cases = cases();
    let mut groups: Vec<(&str, &str)> = cases.iter().map(|k| k.opts).collect();
    groups.sort_unstable();
    groups.dedup();
    let mut failures = Vec::new();
    for (fe, be) in groups {
        let mine: Vec<(usize, &Case)> = cases.iter().enumerate().filter(|(_, k)| k.opts == (fe, be)).collect();
        let rsps = mine.iter().map(|(i, k)| (format!("/c{i}"), k.rsp.clone())).collect();
        let (be_addr, seen) = backend(rsps);
        let p = proxy(be_addr, fe, be);
        for (i, k) in mine {
            let path = format!("/c{i}");
            let line = k.line.map_or_else(|| format!("GET {path} HTTP/1.1"), |l| l.replace("/c", &path));
            let mut req = format!("{line}\r\nHost: h\r\n");
            for h in &k.req {
                req.push_str(h);
                req.push_str("\r\n");
            }
            req.push_str("\r\n");
            let (status, head) = send(p.addr, req.as_bytes());
            thread::sleep(Duration::from_millis(50));
            let got = seen.lock().unwrap().get(&path).cloned();
            let mut why = Vec::new();
            if status != Some(k.status) {
                why.push(format!("status {status:?}, want {}", k.status));
            }
            if let Err(e) = check(&head, &k.client) {
                why.push(format!("client: {e}"));
            }
            match (&k.backend, got) {
                (None, Some(g)) => why.push(format!("reached the backend: {:?}", String::from_utf8_lossy(&g))),
                (Some(_), None) => why.push("never reached the backend".into()),
                (Some(checks), Some(g)) => {
                    let s = String::from_utf8_lossy(&g);
                    let h = s.split("\r\n\r\n").next().unwrap_or("");
                    if let Err(e) = check(h, checks) {
                        why.push(format!("backend: {e}"));
                    }
                }
                (None, None) => {}
            }
            if !why.is_empty() {
                failures.push(format!("{}: {}", k.name, why.join("; ")));
            }
        }
    }
    assert!(failures.is_empty(), "{} case(s) differ:\n{}", failures.len(), failures.join("\n"));
}
