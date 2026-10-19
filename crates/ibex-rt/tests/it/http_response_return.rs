// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-response return` (T339): the server's response is dropped and the client gets the
//! reply `http-request return` would build, e.g. a maintenance page in place of a 503.
//!
//! Every expected value was measured on `HAProxy 3.5-dev8-885761-29` with the same
//! configurations, a raw-socket client, a raw server and a UDP log socket, on 2026-10-18:
//!
//! ```text
//! 503 -> return status 404 content-type text/plain string "nope" hdr x-r r1
//!   HTTP/1.1 404 Not Found / x-r: r1 / content-length: 4 / content-type: text/plain / nope
//!   log: 404 84 - - LH--     (84: the server's 503 response, 83 bytes, plus one)
//!   the client connection stays open; the server one is reused (small body)
//!   a server body larger than the buffer: the server connection is closed, the next
//!   request opens another
//! body sources (client sends `Connection: close`; each adds `connection: close`):
//!   default-errorfiles status 503 / errorfile F  : the file as it is (its own status line)
//!   file F (content-type text/plain)             : 200, content-length 11, HELLO FILE
//!   lf-string "S=%[status] A=%[res.hdr(x-a)] P=%[var(txn.p)]" : "S= A= P=/lfs" -- the
//!       server's response is already gone when the string is built, so its fetches are empty
//!   no body                                      : 200 / content-length: 0 (204: no content-length-less)
//!   hdr whose value formats to nothing           : the header is left out
//!   over h2 (curl --http2-prior-knowledge)       : HTTP/2 404, x-r: r1, content-length: 5, maint
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    _dir: TempDir,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server: `/…503…` answers 503, `/…404…` 404, anything else 200; the body is 4 bytes,
/// 3000 for `big`, 200000 for `huge`. Returns its address and its accept counter.
fn server() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            count.fetch_add(1, Ordering::SeqCst);
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
                    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    buf.drain(..end);
                    let path = head.split(' ').nth(1).unwrap_or("");
                    let body = vec![b'x'; if path.contains("huge") { 200_000 } else if path.contains("big") { 3000 } else { 4 }];
                    let st = if path.contains("503") {
                        "503 Service Unavailable"
                    } else if path.contains("404") {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    };
                    let mut out = format!("HTTP/1.1 {st}\r\nX-A: fromsrv\r\nX-B: b\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                    out.extend_from_slice(&body);
                    if c.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, accepted)
}

const HEAD: &str = "global\n  log {log} local0\ndefaults\n  mode http\n  log global\n  option httplog\n  \
    timeout client 5s\n  timeout server 5s\n  timeout connect 2s\n";

/// `rules` are the lines of a backend that follows the standard frontend.
fn start(proto: &str, rules: &str) -> (Ibex, SocketAddr, UdpSocket, Arc<AtomicUsize>) {
    let fe = common::reserve_addr();
    let (srv, accepted) = server();
    let logs = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    logs.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("body.txt"), "HELLO FILE\n").expect("body");
    std::fs::write(dir.path().join("err.http"), "HTTP/1.1 599 X\r\nContent-Type: text/plain\r\n\r\nERRFILE\n").expect("err");
    std::fs::write(dir.path().join("lf.txt"), "LF st=%[status] h=%[res.hdr(x-a)]\n").expect("lf");
    let text = format!(
        "{HEAD}frontend f\n  bind {fe}{proto}\n  http-request set-var(txn.p) path\n  default_backend b\nbackend b\n  server s {srv}\n{rules}\n"
    )
    .replace("{dir}", &dir.path().display().to_string())
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
    let ibex = Ibex { child, _cfg: f, _dir: dir };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    // The probe connection of `wait_listening` leaves a line of its own: wait for it (on a
    // loaded host it comes late) rather than for a fixed time, so it cannot be taken for the
    // line of the first request.
    logs.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut sink = [0u8; 2048];
    let _ = logs.recv(&mut sink);
    logs.set_read_timeout(Some(Duration::from_secs(3))).ok();
    logs.set_nonblocking(true).ok();
    while logs.recv(&mut sink).is_ok() {}
    logs.set_nonblocking(false).ok();
    (ibex, fe, logs, accepted)
}

/// Sends `req` and returns what came back until the connection closed or went quiet.
fn talk(c: &mut TcpStream, req: &str, quiet_ms: u64) -> String {
    c.write_all(req.as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_millis(quiet_ms))).ok();
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = c.read(&mut chunk) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

fn log_line(logs: &UdpSocket) -> String {
    let mut buf = [0u8; 2048];
    let n = logs.recv(&mut buf).expect("a log line");
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// `status bytes - - flags` of an `option httplog` line.
fn log_tail(line: &str) -> String {
    let words: Vec<&str> = line.split(' ').collect();
    let i = words.iter().position(|w| w.contains('/') && w.matches('/').count() == 4).expect("timers");
    words[i + 1..i + 6].join(" ")
}

#[test]
fn a_backend_503_is_replaced_by_the_maintenance_page_and_the_connections_live_on() {
    let (_i, fe, logs, accepted) = start(
        "",
        "  http-response return status 404 content-type text/plain string \"nope\" hdr x-r r1 if { status 503 }",
    );
    let mut c = TcpStream::connect(fe).expect("connect");
    let got = talk(&mut c, "GET /503 HTTP/1.1\r\nHost: x\r\n\r\n", 400);
    assert_eq!(
        got,
        "HTTP/1.1 404 Not Found\r\nx-r: r1\r\ncontent-length: 4\r\ncontent-type: text/plain\r\n\r\nnope"
    );
    assert_eq!(log_tail(&log_line(&logs)), "404 84 - - LH--");
    // The client connection is still there and the server one was reused.
    let got = talk(&mut c, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 400);
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n") && got.ends_with("\r\n\r\nxxxx"), "{got:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "the server connection was not reused");
    assert_eq!(log_tail(&log_line(&logs)).split(' ').next(), Some("200"));
}

#[test]
fn a_rule_whose_condition_is_false_leaves_the_response_alone() {
    let (_i, fe, _logs, _) = start("", "  http-response return status 404 content-type text/plain string \"gone\" if { status 404 }");
    let mut c = TcpStream::connect(fe).expect("connect");
    let got = talk(&mut c, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 400);
    assert!(got.starts_with("HTTP/1.1 200 OK\r\nx-a: fromsrv\r\n"), "{got:?}");
}

#[test]
fn a_server_body_larger_than_the_buffer_closes_the_server_connection() {
    let (_i, fe, logs, accepted) = start(
        "",
        "  http-response return status 404 content-type text/plain string \"nope\" if { status 503 }",
    );
    let mut c = TcpStream::connect(fe).expect("connect");
    let got = talk(&mut c, "GET /503huge HTTP/1.1\r\nHost: x\r\n\r\n", 400);
    assert_eq!(got, "HTTP/1.1 404 Not Found\r\ncontent-length: 4\r\ncontent-type: text/plain\r\n\r\nnope");
    assert!(log_tail(&log_line(&logs)).ends_with("LH--"));
    let got = talk(&mut c, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n", 400);
    assert!(got.starts_with("HTTP/1.1 200 OK\r\n"), "{got:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "the rest of the server body must not be read into the next response");
}

#[test]
fn every_body_source_builds_the_reply_http_request_return_builds() {
    let rules = "  errorfile 503 {dir}/err.http\n  \
        http-response return status 503 default-errorfiles if { var(txn.p) -m str /de }\n  \
        http-response return status 503 errorfile {dir}/err.http if { var(txn.p) -m str /ef }\n  \
        http-response return status 200 content-type text/plain file {dir}/body.txt if { var(txn.p) -m str /file }\n  \
        http-response return status 200 content-type text/x-a file {dir}/body.txt if { var(txn.p) -m str /filect }\n  \
        http-response return status 201 lf-file {dir}/lf.txt content-type text/plain if { var(txn.p) -m str /lff }\n  \
        http-response return status 202 content-type text/plain lf-string \"S=%[status] A=%[res.hdr(x-a)] P=%[var(txn.p)]\" if { var(txn.p) -m str /lfs }\n  \
        http-response return status 204 if { var(txn.p) -m str /empty }\n  \
        http-response return if { var(txn.p) -m str /def }\n  \
        http-response return status 418 content-type text/plain string \"t\" hdr x-a mine hdr x-e \"%[var(txn.q)]\" if { var(txn.p) -m str /hdr }";
    let (_i, fe, logs, _) = start("", rules);
    let close = "Connection: close\r\n";
    let echo = "connection: close\r\n";
    let err = "HTTP/1.1 599 X\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nERRFILE\n";
    let table = [
        ("/de", err.to_string()),
        ("/ef", err.to_string()),
        ("/file", format!("HTTP/1.1 200 OK\r\ncontent-length: 11\r\ncontent-type: text/plain\r\n{echo}\r\nHELLO FILE\n")),
        ("/filect", format!("HTTP/1.1 200 OK\r\ncontent-length: 11\r\ncontent-type: text/x-a\r\n{echo}\r\nHELLO FILE\n")),
        ("/lff", format!("HTTP/1.1 201 Created\r\ncontent-length: 10\r\ncontent-type: text/plain\r\n{echo}\r\nLF st= h=\n")),
        ("/lfs", format!("HTTP/1.1 202 Accepted\r\ncontent-length: 12\r\ncontent-type: text/plain\r\n{echo}\r\nS= A= P=/lfs")),
        ("/empty", format!("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n{echo}\r\n")),
        ("/def", format!("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n{echo}\r\n")),
        ("/hdr", format!("HTTP/1.1 418 I'm a teapot\r\nx-a: mine\r\ncontent-length: 1\r\ncontent-type: text/plain\r\n{echo}\r\nt")),
    ];
    let mut bad = Vec::new();
    for (path, want) in table {
        let mut c = TcpStream::connect(fe).expect("connect");
        let got = talk(&mut c, &format!("GET {path} HTTP/1.1\r\nHost: x\r\n{echo}\r\n"), 1500);
        if got != want {
            bad.push(format!("{path}: got {got:?}, want {want:?}"));
        }
        let tail = log_line(&logs);
        if !log_tail(&tail).ends_with(" - - LH--") {
            bad.push(format!("{path}: log {tail}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn the_reply_reaches_an_h2_client_as_headers_and_data() {
    let (_i, fe, _logs, _) = start(
        " proto h2",
        "  http-response return status 404 content-type text/plain string \"maint\" hdr x-r r1 if { status 503 }",
    );
    let out = Command::new("curl")
        .args(["-s", "-i", "--http2-prior-knowledge", "-w", "\n%{http_version} %{http_code}\n", &format!("http://{fe}/503")])
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
    assert_eq!(
        text,
        "HTTP/2 404 \nx-r: r1\ncontent-length: 5\ncontent-type: text/plain\n\nmaint\n2 404\n"
    );
}
