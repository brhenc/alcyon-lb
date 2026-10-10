// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Server-connection reuse for chunked replies (T202). Two requests on one client
//! connection must travel on one backend connection, whatever the framing of the reply
//! and whichever keep-alive headers the server sends. Measured on HAProxy
//! 3.5-dev8-885761-29: one backend connection in every case below. Set `IBEX_TEST_BIN`
//! to run the same cases against another binary (e.g. haproxy).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const CHUNKED: &str = "HTTP/1.1 200 OK\r\nX-Conn: {id}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
const LENGTH: &str = "HTTP/1.1 200 OK\r\nX-Conn: {id}\r\nContent-Length: 5\r\n\r\nhello";
const HTTPD_CHUNKED: &str = "HTTP/1.1 200 OK\r\nX-Conn: {id}\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
const HTTPD_LENGTH: &str = "HTTP/1.1 200 OK\r\nX-Conn: {id}\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Length: 5\r\n\r\nhello";

const HTTPD_SPLIT: &str = "HTTP/1.1 200 OK\r\nX-Conn: {id}\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nTransfer-Encoding: chunked\r\n\r\n|5\r\nhello\r\n|0\r\n\r\n";

/// A raw backend answering every request with `reply`, sent in pieces split at `|`, 30 ms
/// apart; returns its address and accept count.
fn backend(reply: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&count);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let id = c.fetch_add(1, Ordering::SeqCst) + 1;
            let reply = reply.replace("{id}", &id.to_string());
            thread::spawn(move || {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    while let Some(p) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        req.drain(..p + 4);
                        for (i, part) in reply.split('|').enumerate() {
                            if i > 0 {
                                thread::sleep(Duration::from_millis(30));
                            }
                            if s.write_all(part.as_bytes()).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, count)
}

struct Proxy(Child, NamedTempFile);

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Proxy {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let bin = std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn proxy");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "proxy never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Proxy(child, f)
}

/// `clients` client connections one after the other, two requests each; the backend
/// connection that carried each request.
fn sequences(reply: &'static str, options: &str, req: &str, clients: usize) -> Vec<Vec<usize>> {
    let (be, count) = backend(reply);
    let fe = common::reserve_addr();
    let _p = start(
        &format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n{options}\
             listen l\n  bind {fe}\n  server srv {be}\n"
        ),
        fe,
    );
    let mut out = Vec::new();
    for _ in 0..clients {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut seq = Vec::new();
        for _ in 0..2 {
            c.write_all(req.as_bytes()).unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while !got.ends_with(b"hello") && !got.ends_with(b"0\r\n\r\n") {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => panic!("no complete answer: {:?}", String::from_utf8_lossy(&got)),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            let text = String::from_utf8_lossy(&got).to_ascii_lowercase();
            let id = text.split("x-conn: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|n| n.parse().ok());
            seq.push(id.unwrap_or_else(|| panic!("no X-Conn: {text:?}")));
        }
        drop(c);
        thread::sleep(Duration::from_millis(100));
        out.push(seq);
    }
    out
}

const GET: &str = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
const POST: &str = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nab";
/// Every variant, at `nbthread 1` (a pool per thread: the thread count decides what a
/// second client connection finds): the first client's two requests share one server
/// connection; each later client opens its own for its first request (`http-reuse safe`)
/// and its second request takes the connection the first one left (`[n, 1]`, the safe one).
/// Measured on HAProxy 3.5-dev8-885761-29 with `IBEX_TEST_BIN`; with `nbthread 4` HAProxy
/// gives `[n, n]` because it places each new client on another thread, which has its own
/// pool, and `ibex` does not (the kernel spreads `SO_REUSEPORT` sockets by hash).
const WANT: [[usize; 2]; 4] = [[1, 1], [2, 1], [3, 1], [4, 1]];

fn variants() -> [(&'static str, &'static str, &'static str, &'static str); 7] {
    [
        ("chunked", CHUNKED, "", GET),
        ("length", LENGTH, "", GET),
        ("httpd-chunked", HTTPD_CHUNKED, "", GET),
        ("httpd-length", HTTPD_LENGTH, "", GET),
        ("chunked+http-keep-alive", CHUNKED, "  option http-keep-alive\n", GET),
        ("chunked post", CHUNKED, "", POST),
        ("httpd-chunked in three segments", HTTPD_SPLIT, "", GET),
    ]
}

#[test]
fn reply_framing_and_keep_alive_headers_do_not_change_server_reuse() {
    for (name, reply, opt, req) in variants() {
        let got = sequences(reply, opt, req, 4);
        assert_eq!(got, WANT.map(Vec::from), "{name}");
    }
}

#[test]
fn first_client_two_requests_one_server_connection() {
    for (name, reply, opt, req) in variants() {
        assert_eq!(sequences(reply, opt, req, 1), vec![vec![1, 1]], "{name}");
    }
}
