// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Waits and timeouts of the stream: `WAIT_END` in HTTP-mode `tcp-response content`, the
//! inspect delay of a backend's `tcp-request content`, `timeout http-request`, and the
//! precision of a deadline. Expected values measured on `HAProxy 3.5-dev8-885761-29`,
//! 2026-10-04, with the same configurations and a raw-socket client and server.
//!
//! The machine is shared and loaded: lower bounds are tight, upper bounds loose.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
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

/// A server that answers every request with `200 ok` at once, keeping the connection open.
/// It records the instant each request head arrived.
fn server() -> (SocketAddr, std::sync::mpsc::Receiver<Instant>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let tx = tx.clone();
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
                    tx.send(Instant::now()).ok();
                    buf.clear();
                    if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, rx)
}

/// Starts Ibex on `cfg`, `{fe}` and `{srv}` replaced.
fn start(cfg: &str, srv: SocketAddr) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.replace("{fe}", &fe.to_string()).replace("{srv}", &srv.to_string()).as_bytes()).expect("write");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe));
    (Ibex { child, _cfg: f }, fe)
}

/// Sends `req`, and returns how long the first bytes of the answer took, and them.
fn timed(fe: SocketAddr, req: &str) -> (Duration, String) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).ok();
    let sent = Instant::now();
    c.write_all(req.as_bytes()).expect("send");
    let mut got = [0u8; 512];
    let n = c.read(&mut got).unwrap_or(0);
    (sent.elapsed(), String::from_utf8_lossy(&got[..n]).into_owned())
}

const GET: &str = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

#[test]
fn wait_end_holds_a_tcp_mode_backend_rule_until_the_inspect_delay_is_over() {
    // HAProxy (TCP mode), the same configuration with `mode tcp`: the client has the
    // answer at +0.502 s, and the server hears the request no sooner.
    let (srv, heard) = server();
    let cfg = "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
        frontend fe\n  bind {fe}\n  default_backend be\n\
        backend be\n  tcp-request inspect-delay 500ms\n  tcp-request content accept if WAIT_END\n  server s {srv}\n";
    let (_ibex, fe) = start(cfg, srv);
    let sent = Instant::now();
    let (took, resp) = timed(fe, GET);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp:?}");
    let at = heard.recv_timeout(Duration::from_secs(3)).expect("the server heard the request");
    assert!(at.duration_since(sent) >= Duration::from_millis(480), "the server heard it after {:?}", at.duration_since(sent));
    assert!(took < Duration::from_millis(3000), "the client had the response after {took:?}");
}

#[test]
fn wait_end_holds_a_backend_tcp_request_content_rule_until_the_inspect_delay_is_over() {
    // HAProxy (HTTP mode): the backend's `tcp-request inspect-delay 500ms` with
    // `tcp-request content accept if WAIT_END` -- the request reaches the server, and the
    // client has the response, at +0.502 s.
    let (srv, heard) = server();
    let cfg = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
        frontend fe\n  bind {fe}\n  default_backend be\n\
        backend be\n  tcp-request inspect-delay 500ms\n  tcp-request content accept if WAIT_END\n  server s {srv}\n";
    let (_ibex, fe) = start(cfg, srv);
    let sent = Instant::now();
    let (took, resp) = timed(fe, GET);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp:?}");
    let at = heard.recv_timeout(Duration::from_secs(3)).expect("the server heard the request");
    assert!(at.duration_since(sent) >= Duration::from_millis(480), "the server heard it after {:?}", at.duration_since(sent));
    assert!(took >= Duration::from_millis(480), "the client had the response after {took:?}");
    assert!(took < Duration::from_millis(3000), "the client had the response after {took:?}");
}

#[test]
fn wait_end_holds_an_http_response_until_the_inspect_delay_is_over() {
    // HAProxy (HTTP mode): `tcp-response inspect-delay 500ms` and `tcp-response content
    // accept if WAIT_END` -- the server answers at once, the client has the response at
    // +0.501 s.
    let (srv, _rx) = server();
    let cfg = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
        frontend fe\n  bind {fe}\n  default_backend be\n\
        backend be\n  tcp-response inspect-delay 500ms\n  tcp-response content accept if WAIT_END\n  server s {srv}\n";
    let (_ibex, fe) = start(cfg, srv);
    let (took, resp) = timed(fe, GET);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp:?}");
    assert!(took >= Duration::from_millis(480), "the client had the response after {took:?}");
    assert!(took < Duration::from_millis(3000), "the client had the response after {took:?}");
}
