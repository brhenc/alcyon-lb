// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `option httpclose` against the real binary (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`, a backend that numbers its
//! connections and echoes whether the request said `Connection: close`; one client
//! connection, three requests). The last of `http-keep-alive`, `http-server-close` and
//! `httpclose` wins within a section (defaults are the starting point):
//!   - frontend `httpclose`: the response says `connection: close` and the client
//!     connection is closed after it; the server is not asked to close (unless the backend's
//!     mode says so);
//!   - backend `httpclose` (or `http-server-close`): the server is asked to close and each
//!     request has a new server connection; the client connection stays;
//!   - frontend `http-server-close`: the same as the backend's;
//!   - the last option wins, in either order;
//!   - `no option httpclose` undoes a `httpclose` the section inherited.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn backend() -> SocketAddr {
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
                    if s.write_all(rsp.as_bytes()).is_err() || close {
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

fn header(resp: &str, name: &str) -> Option<String> {
    resp.split(&format!("{name}: ")).nth(1).and_then(|r| r.split("\r\n").next()).map(|v| v.trim().to_string())
}

type Seen = Option<(String, String, bool)>;

/// What each of three requests on one client connection saw: `(x-conn, x-saw-close,
/// client told to close)`, or `None` when the connection was closed before the answer.
fn run(cfg: &dyn Fn(SocketAddr, SocketAddr) -> String) -> Vec<Seen> {
    let be = backend();
    let fe = common::reserve_addr();
    let _ibex = start(&cfg(fe, be), fe);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut out = Vec::new();
    for _ in 0..3 {
        let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
            }
        }
        let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
        if resp.is_empty() {
            out.push(None);
            continue;
        }
        out.push(Some((
            header(&resp, "x-conn").expect("x-conn"),
            header(&resp, "x-saw-close").expect("x-saw-close"),
            header(&resp, "connection").as_deref() == Some("close"),
        )));
        thread::sleep(Duration::from_millis(100));
    }
    out
}

const HEAD: &str = "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n";

fn split(defaults: &str, fe: &str, be: &str) -> impl Fn(SocketAddr, SocketAddr) -> String {
    let (d, f, b) = (defaults.to_string(), fe.to_string(), be.to_string());
    move |bind, srv| format!("{HEAD}{d}frontend f\n  bind {bind}\n  default_backend b\n{f}backend b\n{b}  server s {srv}\n")
}

fn s(a: &str, b: &str, c: bool) -> Seen {
    Some((a.to_string(), b.to_string(), c))
}

#[test]
fn frontend_httpclose_closes_the_client_and_leaves_the_server_alone() {
    let seq = run(&split("", "  option httpclose\n", ""));
    assert_eq!(seq, vec![s("1", "0", true), None, None]);
}

#[test]
fn frontend_httpclose_with_a_server_closing_backend() {
    let seq = run(&split("", "  option httpclose\n", "  option http-server-close\n"));
    assert_eq!(seq, vec![s("1", "1", true), None, None]);
}

#[test]
fn backend_httpclose_asks_the_server_to_close_and_the_client_stays() {
    let seq = run(&split("", "", "  option httpclose\n"));
    assert_eq!(seq, vec![s("1", "1", false), s("2", "1", false), s("3", "1", false)]);
}

#[test]
fn the_last_option_wins() {
    let seq = run(&split("", "", "  option httpclose\n  option http-keep-alive\n"));
    assert_eq!(seq, vec![s("1", "0", false), s("1", "0", false), s("1", "0", false)]);
    let seq = run(&split("", "", "  option http-keep-alive\n  option httpclose\n"));
    assert_eq!(seq, vec![s("1", "1", false), s("2", "1", false), s("3", "1", false)]);
    let seq = run(&split("  option httpclose\n  option http-server-close\n", "", ""));
    assert_eq!(seq, vec![s("1", "1", false), s("2", "1", false), s("3", "1", false)]);
}

#[test]
fn a_section_overrides_the_defaults_mode() {
    let seq = run(&split("  option httpclose\n", "  option http-keep-alive\n", "  option http-keep-alive\n"));
    assert_eq!(seq, vec![s("1", "0", false), s("1", "0", false), s("1", "0", false)]);
    let seq = run(&split("  option httpclose\n", "", "  no option httpclose\n"));
    assert_eq!(seq, vec![s("1", "0", true), None, None]);
}
