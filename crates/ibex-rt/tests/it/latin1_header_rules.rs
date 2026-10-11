// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Rules, ACLs, converters, captures and log-formats read a Latin-1 header value (bytes
//! 0x80-0xFF that are not UTF-8) as the bytes the client sent, as `HAProxy` does (T286):
//! `req.hdr(x) -m str "caf\xe9"` matches `caf\xe9`; an ACL that does not is a bypass.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29.
//! Set `T286_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Proxy {
    child: Child,
    logs: Arc<Mutex<Vec<Vec<u8>>>>,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers every request `200` with `X-R: caf\xe9` and a two-byte body.
fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b) {
                        Ok(n) if n > 0 => got.extend_from_slice(&b[..n]),
                        _ => return,
                    }
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nX-R: caf\xe9\r\n\r\nok");
            });
        }
    });
    addr
}

fn start() -> Proxy {
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    let be = server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  \
         timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  capture request header x-cap len 20\n\
         \x20 http-request deny deny_status 403 if {{ req.hdr(x-a) -m str \"caf\\xe9\" }}\n\
         \x20 http-request deny deny_status 404 if {{ req.hdr(x-b) -m reg \"^caf\\xe9\\$\" }}\n\
         \x20 http-request deny deny_status 405 if {{ req.hdr(x-c),length -m int 4 }}\n\
         \x20 http-request deny deny_status 407 if {{ req.hdr(x-d) -m sub \"\\xe9\" }}\n\
         \x20 http-request deny deny_status 408 if {{ req.hdr(x-e) -m beg \"caf\\xe9\" }}\n\
         \x20 http-request deny deny_status 410 if {{ req.hdr(x-f) -m end \"\\xe9\" }}\n\
         \x20 http-request deny deny_status 413 if {{ req.hdr(x-g) -m reg \"^caf.\\$\" }}\n\
         \x20 http-request deny deny_status 425 if {{ req.hdr(x-h),hex -m str 636166E9 }}\n\
         \x20 http-request deny deny_status 429 if {{ req.hdr(x-i) -m reg \"^caf[\\xe0-\\xef]\\$\" }}\n\
         \x20 http-request deny deny_status 500 if {{ req.hdr(x-j) -m str \"caf\\xc3\\xa9\" }}\n\
         \x20 http-request set-var(txn.l) req.hdr(x-l)\n\
         \x20 http-request return status 200 hdr x-ret \"%[req.hdr(x-l)]\" hdr x-ret-u \"%[req.hdr(x-l),upper]\" if {{ path /ret }}\n\
         \x20 http-response set-header x-echo \"%[var(txn.l)]\"\n\
         \x20 http-response set-header x-m1 y if {{ res.hdr(x-r) -m str \"caf\\xe9\" }}\n\
         \x20 http-response set-header x-m2 y if {{ res.hdr(x-r) -m sub \"caf\" }}\n\
         \x20 http-response set-header x-m3 y if {{ res.hdr(x-r) -m reg \"^caf.\\$\" }}\n\
         \x20 http-response set-header x-m4 y if {{ res.hdr(x-r) -m end \"\\xe9\" }}\n\
         \x20 http-response set-header x-m5 y if {{ res.hdr(x-r),length -m int 4 }}\n\
         \x20 http-response set-header x-m6 \"%[res.hdr(x-r)]\"\n\
         \x20 default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n"
    )
    .expect("write");
    let bin = std::env::var("T286_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let logs: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let sink = Arc::clone(&logs);
    thread::spawn(move || {
        let mut r = BufReader::new(out);
        let mut line = Vec::new();
        while r.read_until(b'\n', &mut line).map_or(0, |n| n) > 0 {
            sink.lock().unwrap().push(std::mem::take(&mut line));
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, logs, fe, _cfg: cfg }
}

/// The client's whole answer to `GET path` with the extra header lines `hdrs`.
fn get(p: &Proxy, path: &str, hdrs: &[u8]) -> Vec<u8> {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n").into_bytes();
    req.extend_from_slice(hdrs);
    req.extend_from_slice(b"\r\n");
    c.write_all(&req).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    got
}

fn status(got: &[u8]) -> u16 {
    std::str::from_utf8(got.get(9..12).unwrap_or_default()).ok().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// Each request and the status it should get.
#[test]
fn acls_on_a_latin1_value_match_its_bytes() {
    let p = start();
    let cases: &[(&str, &[u8], u16)] = &[
        ("/a", b"X-A: caf\xe9\r\n", 403),
        ("/b", b"X-B: caf\xe9\r\n", 404),
        ("/c", b"X-C: caf\xe9\r\n", 405),
        ("/d", b"X-D: ab\xe9cd\r\n", 407),
        ("/e", b"X-E: caf\xe9 au lait\r\n", 408),
        ("/f", b"X-F: caf\xe9\r\n", 410),
        ("/g", b"X-G: caf\xe9\r\n", 413),
        ("/h", b"X-H: caf\xe9\r\n", 425),
        ("/i", b"X-I: caf\xe9\r\n", 429),
        // The UTF-8 bytes of the same letter are other bytes: no match on the Latin-1 pattern.
        ("/a-utf8", b"X-A: caf\xc3\xa9\r\n", 200),
        ("/j-utf8", b"X-J: caf\xc3\xa9\r\n", 500),
        ("/j-latin1", b"X-J: caf\xe9\r\n", 200),
    ];
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(path, h, want)| {
            let got = status(&get(&p, path, h));
            (got != *want).then(|| format!("{path}: sent {} got {got} want {want}", h.escape_ascii()))
        })
        .collect();
    assert!(wrong.is_empty(), "differ from HAProxy:\n{}", wrong.join("\n"));
}

#[test]
fn a_response_header_acl_matches_the_bytes_the_server_sent() {
    let p = start();
    let got = get(&p, "/res", b"");
    assert_eq!(status(&got), 200);
    // The response is forwarded with the bytes the server sent.
    assert!(got.windows(11).any(|w| w == b"x-r: caf\xe9\r\n"), "got {}", got.escape_ascii());
    for want in [&b"x-m1: y\r\n"[..], b"x-m2: y\r\n", b"x-m3: y\r\n", b"x-m4: y\r\n", b"x-m5: y\r\n", b"x-m6: caf\xe9\r\n"] {
        assert!(got.windows(want.len()).any(|w| w == want), "no {} in {}", want.escape_ascii(), got.escape_ascii());
    }
}

#[test]
fn a_log_format_echoes_the_bytes_the_client_sent() {
    let p = start();
    let got = get(&p, "/echo", b"X-L: caf\xe9\r\n");
    assert_eq!(status(&got), 200);
    let want: &[u8] = b"x-echo: caf\xe9\r\n";
    assert!(got.windows(want.len()).any(|w| w == want), "got {}", got.escape_ascii());
    let got = get(&p, "/ret", b"X-L: caf\xe9\r\n");
    for want in [&b"x-ret: caf\xe9\r\n"[..], b"x-ret-u: CAF\xe9\r\n"] {
        assert!(got.windows(want.len()).any(|w| w == want), "got {}", got.escape_ascii());
    }
}

#[test]
fn a_captured_latin1_value_reaches_the_log() {
    let p = start();
    let got = get(&p, "/cap", b"X-Cap: caf\xe9\r\n");
    assert_eq!(status(&got), 200);
    thread::sleep(Duration::from_millis(500));
    let logs = p.logs.lock().unwrap();
    let line = logs.iter().find(|l| l.windows(4).any(|w| w == b"/cap")).expect("no log line");
    // HAProxy logs a byte over 0x7e as "#E9".
    assert!(line.windows(7).any(|w| w == b"{caf#E9}"[..7].as_ref()) || line.windows(8).any(|w| w == b"{caf#E9}"), "log: {}", line.escape_ascii());
}
