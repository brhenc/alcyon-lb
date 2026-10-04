// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-response redirect`, and the `last_rule_file` / `last_rule_line` fetches: the file
//! and line of the last rule that ended a rule set (accept, allow, reject, deny, redirect)
//! for the stream's current request, `-` where none did.
//!
//! Every expected value below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-04, with the same configurations (the
//! `data/last_rule.cfg` one included, run with `log stdout`) and a raw-socket client and
//! server.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers every request on a connection with `200 ok`, keeping it open.
fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut chunk) {
                            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                            _ => return,
                        }
                    }
                    buf.clear();
                    if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start(cfg: &str) -> (Ibex, SocketAddr, UdpSocket) {
    let fe = common::reserve_addr();
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let text = cfg
        .replace("{fe}", &fe.to_string())
        .replace("{srv}", &server().to_string())
        .replace("{log}", &logs.local_addr().expect("addr").to_string());
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe, logs)
}

/// What came back to one request: the bytes until the head's end and what followed it
/// within a moment.
fn exchange(c: &mut TcpStream, path: &str) -> String {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut chunk) {
            Ok(n) if n > 0 => got.extend_from_slice(&chunk[..n]),
            _ => return String::from_utf8_lossy(&got).into_owned(),
        }
    }
    c.set_read_timeout(Some(Duration::from_millis(150))).ok();
    while let Ok(n) = c.read(&mut chunk) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// Drops the log lines there are, such as the one the harness's probe connection leaves.
fn drain(logs: &UdpSocket) {
    logs.set_nonblocking(true).ok();
    let mut buf = [0u8; 2048];
    while logs.recv(&mut buf).is_ok() {}
    logs.set_nonblocking(false).ok();
}

/// The `lr=` of the log line of the request for `path` (the format starts with `p=%HP`).
fn lr(logs: &UdpSocket, path: &str) -> String {
    let mut buf = [0u8; 2048];
    loop {
        let n = logs.recv(&mut buf).unwrap_or_else(|e| panic!("no log line for {path}: {e}"));
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        if let Some(at) = line.find(&format!("p={path} lr=")) {
            return line[at + 2 + path.len() + 4..].trim_end().to_string();
        }
    }
}

const LAST_RULE: &str = include_str!("data/last_rule.cfg");

fn line_of(marker: &str) -> usize {
    let at = LAST_RULE.lines().position(|l| l.contains(marker)).unwrap_or_else(|| panic!("{marker}"));
    at + 1
}

#[test]
fn the_last_rule_is_the_one_that_ended_the_rules_of_the_request() {
    // (path, a marker of the rule HAProxy names, whether the client gets an answer)
    let table = [
        ("/trqacc1", Some("-m beg /trqacc1"), "HTTP/1.1 200"),
        ("/trqrej1", Some("-m beg /trqrej1"), ""),
        ("/trqrej2", Some("-m beg /trqrej2"), ""),
        ("/trsacc1", Some("-m beg /trsacc1"), "HTTP/1.1 200"),
        ("/trsrej1", Some("-m beg /trsrej1"), ""),
        ("/trsrej2", Some("-m beg /trsrej2"), ""),
        // `set-var` is not a final rule.
        ("/hrqvar", None, "HTTP/1.1 200"),
        ("/hrqacc1", Some("-m beg /hrqacc1"), "HTTP/1.1 200"),
        ("/hrqred1", Some("-m beg /hrqred1"), "HTTP/1.1 302"),
        // Accepted by `tcp-request content`, then denied: the later rule is the last.
        ("/hrqrej1", Some("-m beg /hrqrej1"), "HTTP/1.1 403"),
        ("/hrqrej2", Some("-m beg /hrqrej2"), "HTTP/1.1 403"),
        // The response rules run after the request's `allow`, whose line they replace.
        ("/hrsacc1", Some("-m beg /hrsacc1"), "HTTP/1.1 200"),
        ("/hrsred1", Some("-m beg /hrsred1"), "HTTP/1.1 302"),
        ("/hrsrej1", Some("-m beg /hrsrej1"), "HTTP/1.1 502"),
        ("/hrsrej2", Some("-m beg /hrsrej2"), "HTTP/1.1 502"),
        ("/hrsrej3", Some("-m beg /hrsrej3"), "HTTP/1.1 502"),
        ("/nothing", None, "HTTP/1.1 200"),
    ];
    let (ibex, fe, logs) = start(LAST_RULE);
    for (path, marker, status) in table {
        drain(&logs);
        let mut c = TcpStream::connect(fe).expect("connect");
        let got = exchange(&mut c, path);
        assert!(got.starts_with(status), "{path}: {got:?}");
        let want = marker.map_or_else(|| "-:-".to_string(), |m| format!("{}:{}", ibex.cfg.path().display(), line_of(m)));
        assert_eq!(lr(&logs, path), want, "{path}");
    }
}

#[test]
fn the_last_rule_does_not_outlive_its_request_on_a_kept_alive_connection() {
    // HAProxy: lr=<line of the redirect>, then lr=-:- for the next request.
    let (ibex, fe, logs) = start(LAST_RULE);
    drain(&logs);
    let mut c = TcpStream::connect(fe).expect("connect");
    assert!(exchange(&mut c, "/hrqred1").starts_with("HTTP/1.1 302"));
    assert_eq!(lr(&logs, "/hrqred1"), format!("{}:{}", ibex.cfg.path().display(), line_of("-m beg /hrqred1")));
    assert!(exchange(&mut c, "/nothing").starts_with("HTTP/1.1 200"));
    assert_eq!(lr(&logs, "/nothing"), "-:-");
    assert!(exchange(&mut c, "/hrsred1").starts_with("HTTP/1.1 302"));
    assert_eq!(lr(&logs, "/hrsred1"), format!("{}:{}", ibex.cfg.path().display(), line_of("-m beg /hrsred1")));
}

const REDIRECTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n  http-request set-var(txn.p) path\n  default_backend be\n\
backend be\n\
  http-response redirect location /z code 301 if { var(txn.p) -m beg /e }\n\
  http-response redirect location /303 code 303 if { var(txn.p) -m beg /303 }\n\
  http-response redirect location /307 code 307 if { var(txn.p) -m beg /307 }\n\
  http-response redirect location /308 code 308 if { var(txn.p) -m beg /308 }\n\
  http-response redirect location /k keep-query drop-query if { var(txn.p) -m beg /k }\n\
  http-response redirect location /l%[var(txn.p)] if { var(txn.p) -m beg /l }\n\
  http-response redirect location /ck1 set-cookie ck if { var(txn.p) -m beg /ck1 }\n\
  http-response redirect location /ck2 set-cookie ck=v=w if { var(txn.p) -m beg /ck2 }\n\
  http-response redirect location /ck3 set-cookie a=1 clear-cookie b if { var(txn.p) -m beg /ck3 }\n\
  http-response redirect location /unl unless { var(txn.p) -m beg /zzz /b }\n\
  server s {srv}\n";

#[test]
fn the_redirect_is_the_response_whatever_the_server_said() {
    let (_i, fe, _logs) = start(REDIRECTS);
    let head = |status: &str, rest: &str| format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\n{rest}\r\n");
    let nc = "cache-control: no-cache\r\n";
    for (path, want) in [
        ("/e", head("301 Moved Permanently", "location: /z\r\n")),
        ("/303", head("303 See Other", &format!("location: /303\r\n{nc}"))),
        ("/307", head("307 Temporary Redirect", &format!("location: /307\r\n{nc}"))),
        ("/308", head("308 Permanent Redirect", "location: /308\r\n")),
        ("/k?q=1", head("302 Found", &format!("location: /k\r\n{nc}"))),
        ("/lx", head("302 Found", &format!("location: /l/lx\r\n{nc}"))),
        ("/ck1", head("302 Found", &format!("location: /ck1\r\n{nc}set-cookie: ck; path=/;\r\n"))),
        ("/ck2", head("302 Found", &format!("location: /ck2\r\n{nc}set-cookie: ck=v=w; path=/;\r\n"))),
        ("/ck3", head("302 Found", &format!("location: /ck3\r\n{nc}set-cookie: b; path=/; Max-Age=0;\r\n"))),
        ("/unl", head("302 Found", &format!("location: /unl\r\n{nc}"))),
    ] {
        let mut c = TcpStream::connect(fe).expect("connect");
        // Nothing follows the head: the server's `ok` is dropped with its response.
        assert_eq!(exchange(&mut c, path), want, "{path}");
    }
}

#[test]
fn the_connection_serves_the_next_request_after_a_response_redirect() {
    // HAProxy: /e -> 301, then /b on the same connection -> 200 `ok`, then /e again.
    let (_i, fe, _logs) = start(REDIRECTS);
    let mut c = TcpStream::connect(fe).expect("connect");
    assert!(exchange(&mut c, "/e").starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
    let second = exchange(&mut c, "/b");
    assert!(second.starts_with("HTTP/1.1 200 OK\r\n") && second.ends_with("\r\n\r\nok"), "{second:?}");
    assert!(exchange(&mut c, "/e").starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
}

#[test]
fn wait_end_holds_a_tcp_request_content_rule_until_the_inspect_delay_is_over() {
    // HAProxy (TCP mode): `tcp-request inspect-delay 300ms` with `tcp-request content accept
    // if WAIT_END` -- the server hears the client's bytes at +0.30 s, not before.
    let heard = Arc::new(Mutex::new(None::<Instant>));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    let at = heard.clone();
    thread::spawn(move || {
        if let Ok((mut c, _)) = listener.accept() {
            let mut b = [0u8; 16];
            if c.read(&mut b).is_ok_and(|n| n > 0) {
                *at.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
                c.write_all(b"pong").ok();
            }
        }
    });
    let cfg = "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
        frontend fe\n  bind {fe}\n  tcp-request inspect-delay 300ms\n  tcp-request content accept if WAIT_END\n  default_backend be\n\
        backend be\n  server s {srv}\n";
    let fe = common::reserve_addr();
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.replace("{fe}", &fe.to_string()).replace("{srv}", &srv.to_string()).as_bytes()).expect("write");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let _ibex = Ibex { child, cfg: f };
    assert!(common::wait_listening(fe));
    let mut c = TcpStream::connect(fe).expect("connect");
    // The harness's own probe connection took the server's one accept: a second server
    // is not needed because it closes without sending, and `accept` above is the client's.
    let sent = Instant::now();
    c.write_all(b"ping").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let mut got = [0u8; 8];
    let n = c.read(&mut got).expect("an answer");
    assert_eq!(&got[..n], b"pong");
    let at = heard.lock().unwrap_or_else(std::sync::PoisonError::into_inner).expect("the server heard");
    let waited = at.duration_since(sent);
    assert!(waited >= Duration::from_millis(250), "the server heard the client after {waited:?}");
}

#[test]
fn wait_end_holds_a_tcp_response_content_rule_until_the_inspect_delay_is_over() {
    // HAProxy (TCP mode): `tcp-response inspect-delay 300ms` with `tcp-response content
    // accept if WAIT_END` -- the server answers at once, the client has it at +0.30 s.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let srv = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for (mut c, _) in listener.incoming().flatten().map(|c| (c, ())) {
            let mut b = [0u8; 16];
            if c.read(&mut b).is_ok_and(|n| n > 0) {
                c.write_all(b"pong").ok();
                thread::sleep(Duration::from_millis(600));
            }
        }
    });
    let cfg = "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
        frontend fe\n  bind {fe}\n  default_backend be\n\
        backend be\n  tcp-response inspect-delay 300ms\n  tcp-response content accept if WAIT_END\n  server s {srv}\n";
    let fe = common::reserve_addr();
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.replace("{fe}", &fe.to_string()).replace("{srv}", &srv.to_string()).as_bytes()).expect("write");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let _ibex = Ibex { child, cfg: f };
    assert!(common::wait_listening(fe));
    let mut c = TcpStream::connect(fe).expect("connect");
    let sent = Instant::now();
    c.write_all(b"ping").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let mut got = [0u8; 8];
    let n = c.read(&mut got).expect("an answer");
    assert_eq!(&got[..n], b"pong");
    assert!(sent.elapsed() >= Duration::from_millis(250), "the client had the answer after {:?}", sent.elapsed());
}

#[test]
fn a_tarpit_is_the_last_rule_of_its_request() {
    // HAProxy: `lr=<file>:<line of the tarpit>` for both forms, `deny_status` or not;
    // a request no rule matches is unaffected.
    let cfg = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n  timeout tarpit 200ms\n\
frontend fe\n  bind {fe}\n  log {log} local0\n  log-format \"p=%HP lr=%[last_rule_file]:%[last_rule_line]\"\n  default_backend be\n\
backend be\n\
  http-request tarpit deny_status 429 if { path_beg /tq }\n\
  http-request tarpit if { path_beg /tp }\n\
  http-request deny if { path_beg /dn }\n\
  server s {srv}\n";
    let (ibex, fe, logs) = start(cfg);
    let file = ibex.cfg.path().display().to_string();
    for (path, status, line) in [("/tq", "HTTP/1.1 429", Some(13)), ("/tp", "HTTP/1.1 500", Some(14)), ("/dn", "HTTP/1.1 403", Some(15)), ("/none", "HTTP/1.1 200", None)] {
        drain(&logs);
        let mut c = TcpStream::connect(fe).expect("connect");
        let got = exchange(&mut c, path);
        assert!(got.starts_with(status), "{path}: {got:?}");
        let want = line.map_or_else(|| "-:-".to_string(), |l| format!("{file}:{l}"));
        assert_eq!(lr(&logs, path), want, "{path}");
    }
}
