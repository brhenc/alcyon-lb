// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `option http-server-close` against the real binary (T149).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`, a backend that numbers the
//! connections it accepts and echoes the request's `Connection` header; one client
//! connection sending three requests): with the option in `defaults`, the frontend, the
//! backend or a `listen`, every request goes on a new server connection and carries
//! `connection: close`, while the client connection stays open and its responses do not
//! say `close`. Without the option, or after `option http-keep-alive`, the three requests
//! share server connection 1 and the server is not asked to close.
//!
//! A server that closes a connection without announcing it is the case that matters: a
//! connection kept for the next request is dead by then, and the client gets a 502.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// Answers with `x-conn` (its connection number) and `x-saw-close` (whether the request
/// said `Connection: close`). Closes the connection `close_after` after answering, whatever
/// the request said, when given.
fn backend(close_after: Option<Duration>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let id = count.fetch_add(1, Ordering::SeqCst) + 1;
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                    let close = req.contains("connection: close");
                    let rsp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Conn: {id}\r\nX-Saw-Close: {}\r\n\r\n", u8::from(close));
                    if s.write_all(rsp.as_bytes()).is_err() {
                        break;
                    }
                    if let Some(d) = close_after {
                        thread::sleep(d);
                        break;
                    }
                    if close {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

/// One answer: the head, lowercased.
fn request(c: &mut TcpStream) -> String {
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&resp).to_ascii_lowercase()
}

fn header(resp: &str, name: &str) -> Option<String> {
    resp.split(&format!("{name}: ")).nth(1).and_then(|r| r.split("\r\n").next()).map(|v| v.trim().to_string())
}

/// Three requests on one client connection, 100 ms apart: each answer's server connection
/// number and whether the server was told to close; and that the client was not.
fn run(cfg: &dyn Fn(SocketAddr, SocketAddr) -> String, close_after: Option<Duration>) -> Vec<(String, String)> {
    let be = backend(close_after);
    let fe = common::reserve_addr();
    let _ibex = start(&cfg(fe, be), fe);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut out = Vec::new();
    for _ in 0..3 {
        let resp = request(&mut c);
        assert!(resp.starts_with("http/1.1 200"), "not served: {resp:?}");
        assert!(header(&resp, "connection").is_none(), "the client is told to close: {resp:?}");
        out.push((header(&resp, "x-conn").expect("x-conn"), header(&resp, "x-saw-close").expect("x-saw-close")));
        thread::sleep(Duration::from_millis(100));
    }
    out
}

const GLOBAL: &str = "global\n  nbthread 1\n";
const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n";

fn closing(seq: &[(String, String)]) -> bool {
    let want: Vec<(String, String)> = (1..=3).map(|i| (i.to_string(), "1".to_string())).collect();
    seq == want
}

fn keeping(seq: &[(String, String)]) -> bool {
    let want: Vec<(String, String)> = (0..3).map(|_| ("1".to_string(), "0".to_string())).collect();
    seq == want
}

#[test]
fn without_the_option_the_server_connection_is_kept() {
    let seq = run(&|fe, be| format!("{GLOBAL}{DEFAULTS}listen l\n  bind {fe}\n  server s {be}\n"), None);
    assert!(keeping(&seq), "{seq:?}");
}

#[test]
fn in_a_listen_each_request_has_its_own_server_connection() {
    let seq = run(&|fe, be| format!("{GLOBAL}{DEFAULTS}listen l\n  bind {fe}\n  option http-server-close\n  server s {be}\n"), None);
    assert!(closing(&seq), "{seq:?}");
}

#[test]
fn in_a_frontend_alone() {
    let seq = run(
        &|fe, be| format!("{GLOBAL}{DEFAULTS}frontend f\n  bind {fe}\n  option http-server-close\n  default_backend b\nbackend b\n  server s {be}\n"),
        None,
    );
    assert!(closing(&seq), "{seq:?}");
}

#[test]
fn in_a_backend_alone() {
    let seq = run(
        &|fe, be| format!("{GLOBAL}{DEFAULTS}frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  option http-server-close\n  server s {be}\n"),
        None,
    );
    assert!(closing(&seq), "{seq:?}");
}

#[test]
fn from_defaults() {
    let seq = run(
        &|fe, be| format!("{GLOBAL}{DEFAULTS}  option http-server-close\nlisten l\n  bind {fe}\n  server s {be}\n"),
        None,
    );
    assert!(closing(&seq), "{seq:?}");
}

#[test]
fn no_option_and_http_keep_alive_turn_it_off() {
    let seq = run(
        &|fe, be| format!("{GLOBAL}{DEFAULTS}  option http-server-close\nlisten l\n  bind {fe}\n  no option http-server-close\n  server s {be}\n"),
        None,
    );
    assert!(keeping(&seq), "no option: {seq:?}");
    let seq = run(
        &|fe, be| format!("{GLOBAL}{DEFAULTS}  option http-server-close\nlisten l\n  bind {fe}\n  option http-keep-alive\n  server s {be}\n"),
        None,
    );
    assert!(keeping(&seq), "http-keep-alive: {seq:?}");
}

/// A server that closes after each answer without saying so: kept, its connection would be
/// found dead by the next request (a 502); asked to close, a new one is opened.
#[test]
fn a_server_that_closes_after_each_answer_is_never_reused() {
    let seq = run(
        &|fe, be| format!("{GLOBAL}{DEFAULTS}listen l\n  bind {fe}\n  option http-server-close\n  server s {be}\n"),
        Some(Duration::from_millis(10)),
    );
    assert!(closing(&seq), "{seq:?}");
}
