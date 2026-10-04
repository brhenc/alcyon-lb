// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `%B` and `%U` of an HTTP transaction are not what crossed the wire: `HAProxy` counts the
//! HTX message it parsed, as it was received -- before any rule rewrote it. Every expected
//! value below was measured on `HAProxy 3.5-dev8-885761-29` (2026-10-04) with a raw-socket
//! client and server and `log-format "B=%B U=%U ST=%ST"`.
//!
//! What a message counts: the 20 bytes of the start-line block, the three strings of the
//! start line (method, target and version; or version, status and reason), the name and
//! value of each header (the value without its blanks; no `: `, no CRLF), 1 byte for the
//! end of the headers, then the payload bytes (no chunk framing) and, for a chunked body,
//! 1 byte for its end. A `Connection` header loses its `close`, `keep-alive` and `upgrade`
//! tokens (the others stay, joined by `,`), and goes altogether when none is left.
//!
//! ```text
//! GET / HTTP/1.1, Host: a                              U=38     (27 on the wire)
//! 200 OK, content-length: 2, body ok                   B=51     (40 on the wire)
//! ```

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers a request with the response registered for its path, then holds
/// the connection open for a moment.
fn server(responses: HashMap<&'static str, &'static str>) -> SocketAddr {
    let responses = Arc::new(responses);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let responses = Arc::clone(&responses);
            thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                let line = String::from_utf8_lossy(&buf);
                let path = line.split(' ').nth(1).unwrap_or("/").split('?').next().unwrap_or("/").to_string();
                let resp = responses.get(path.as_str()).copied().unwrap_or("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = c.write_all(resp.as_bytes());
                thread::sleep(Duration::from_millis(500));
            });
        }
    });
    addr
}

fn start(rules: &str, responses: HashMap<&'static str, &'static str>) -> (Ibex, SocketAddr, UdpSocket) {
    let fe = common::reserve_addr();
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let text = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n  log {} local0\n  log-format \"B=%B U=%U ST=%ST\"\n  default_backend be\n\
         backend be\n{rules}  server s {}\n",
        logs.local_addr().expect("addr"),
        server(responses)
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    (ibex, fe, logs)
}

/// Sends `req` on a connection of its own, reads what comes back until the server's hold
/// is over, and returns the log line of the request.
fn log_of(fe: SocketAddr, logs: &UdpSocket, req: &str) -> String {
    logs.set_nonblocking(true).ok();
    let mut junk = [0u8; 2048];
    while logs.recv(&mut junk).is_ok() {}
    logs.set_nonblocking(false).ok();
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(1500))).ok();
    c.write_all(req.as_bytes()).expect("send");
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match c.read(&mut chunk) {
            Ok(n) if n > 0 => got.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    assert!(!got.is_empty(), "no answer to {req:?}");
    let mut buf = [0u8; 2048];
    loop {
        let n = logs.recv(&mut buf).unwrap_or_else(|e| panic!("no log line for {req:?}: {e}"));
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        let line = line[line.find("B=").expect("a B= in the log line")..].trim_end().to_string();
        // The line of the harness's probe connection, which sent nothing.
        if line != "B=0 U=0 ST=400" {
            return line;
        }
    }
}

fn responses() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("/two", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        ("/nf", "HTTP/1.1 404 Not Found\r\nX-A: bb\r\nContent-Length: 0\r\n\r\n"),
        ("/chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
        ("/head", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"),
        ("/cfoo", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: foo\r\n\r\nok"),
        ("/cclose", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
        ("/cka", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"),
        ("/noreason", "HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok"),
    ])
}

#[test]
fn b_counts_the_htx_message_the_server_sent() {
    let (_ibex, fe, logs) = start("", responses());
    // The request line is `GET <path> HTTP/1.1`, and `Host: a` is 5 bytes: U is
    // 20 + 3 + path + 8 + 5 + 1.
    let get = |p: &str| format!("GET {p} HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(log_of(fe, &logs, &get("/two")), "B=51 U=41 ST=200");
    assert_eq!(log_of(fe, &logs, &get("/nf")), "B=61 U=40 ST=404");
    // The chunk framing does not count; the end of the chunked body does (1 byte).
    assert_eq!(log_of(fe, &logs, &get("/chunked")), "B=62 U=45 ST=200");
    // A response to a HEAD has no body: 20 + 13 + 15 + 1.
    assert_eq!(log_of(fe, &logs, "HEAD /head HTTP/1.1\r\nHost: a\r\n\r\n"), "B=49 U=43 ST=200");
    // Connection: close and keep-alive are not kept by the parser; other tokens are.
    assert_eq!(log_of(fe, &logs, &get("/cfoo")), "B=64 U=42 ST=200");
    assert_eq!(log_of(fe, &logs, &get("/cclose")), "B=51 U=44 ST=200");
    assert_eq!(log_of(fe, &logs, &get("/cka")), "B=51 U=41 ST=200");
    // The reason is counted as the server wrote it: none here.
    assert_eq!(log_of(fe, &logs, &get("/noreason")), "B=49 U=46 ST=200");
}

#[test]
fn u_counts_the_htx_message_the_client_sent() {
    let (_ibex, fe, logs) = start("", responses());
    let with = |extra: &str| format!("GET / HTTP/1.1\r\nHost: a\r\n{extra}\r\n");
    assert_eq!(log_of(fe, &logs, &with("")), "B=51 U=38 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Connection: close\r\n")), "B=51 U=38 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Connection: keep-alive\r\n")), "B=51 U=38 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Connection: foo\r\n")), "B=51 U=51 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Connection: close, foo\r\n")), "B=51 U=51 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Connection: foo, close, bar\r\n")), "B=51 U=55 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Connection: foo\r\nConnection: close\r\nConnection: bar\r\n")), "B=51 U=64 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Proxy-Connection: close\r\n")), "B=51 U=59 ST=200");
    assert_eq!(log_of(fe, &logs, &with("Keep-Alive: timeout=5\r\n")), "B=51 U=57 ST=200");
    // The value is counted without its blanks.
    assert_eq!(log_of(fe, &logs, &with("X-A:   padded   \r\n")), "B=51 U=47 ST=200");
}

#[test]
fn u_counts_the_request_body_without_its_framing() {
    let (_ibex, fe, logs) = start("", responses());
    let post = "POST /x?y=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nabcd";
    assert_eq!(log_of(fe, &logs, post), "B=51 U=63 ST=200");
    let chunked = "POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    assert_eq!(log_of(fe, &logs, chunked), "B=51 U=68 ST=200");
    let two = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
    assert_eq!(log_of(fe, &logs, two), "B=51 U=69 ST=200");
}

#[test]
fn rules_that_rewrite_the_messages_do_not_change_what_was_counted() {
    // HAProxy: the same B and U as without the rules (`GET /two`: 41, 51).
    let rules = "  http-request add-header X-Foo barbar\n  http-response add-header X-Bar zzz\n  http-response del-header content-length\n";
    let (_ibex, fe, logs) = start(rules, responses());
    assert_eq!(log_of(fe, &logs, "GET /two HTTP/1.1\r\nHost: a\r\n\r\n"), "B=51 U=41 ST=200");
}
