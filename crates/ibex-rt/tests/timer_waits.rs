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

/// A server that answers one request per connection and closes.
fn closing_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                if c.read(&mut buf).is_ok_and(|n| n > 0) {
                    c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").ok();
                }
            });
        }
    });
    addr
}

#[test]
fn a_server_that_closed_behind_its_response_does_not_cut_the_wait_short() {
    // HAProxy: `tcp-response inspect-delay 300ms`, the server closing right after its
    // response: `accept if WAIT_END` -- the client has the response at +0.30 s;
    // `reject if WAIT_END` -- the client gets a close, no data, at +0.30 s (a 502 is not
    // sent behind a rejected response).
    for (action, rejected) in [("accept", false), ("reject", true)] {
        let srv = closing_server();
        let cfg = format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {{fe}}\n  default_backend be\n\
             backend be\n  tcp-response inspect-delay 300ms\n  tcp-response content {action} if WAIT_END\n  server s {{srv}}\n"
        );
        let (_ibex, fe) = start(&cfg, srv);
        let (took, resp) = timed(fe, GET);
        if rejected {
            assert_eq!(resp, "", "{action}: {resp:?}");
        } else {
            assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{action}: {resp:?}");
        }
        assert!(took >= Duration::from_millis(280), "{action}: answered after {took:?}");
        assert!(took < Duration::from_millis(3000), "{action}: answered after {took:?}");
    }
}

/// `timeout http-request 500ms` over `timeout client 5s`.
fn http_request_cfg() -> &'static str {
    "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n  timeout http-request 500ms\n\
     frontend fe\n  bind {fe}\n  default_backend be\n\
     backend be\n  server s {srv}\n"
}

/// Reads until `needle` shows or the connection ends, for at most `within`.
fn read_until(c: &mut TcpStream, needle: &str, within: Duration) -> String {
    let end = Instant::now() + within;
    let mut all = Vec::new();
    let mut buf = [0u8; 1024];
    while Instant::now() < end && !String::from_utf8_lossy(&all).contains(needle) {
        c.set_read_timeout(Some(Duration::from_millis(50))).ok();
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&all).into_owned()
}

#[test]
fn timeout_http_request_answers_408_to_a_head_that_does_not_complete() {
    // HAProxy: `timeout http-request 1s`, `timeout client 5s`, a partial head: `408` at
    // +1.001 s (`cR` in the log); nothing sent at all: the same; a byte every 0.3 s: the
    // same, at +1.2 s -- the client's trickle does not move it.
    let (srv, _rx) = server();
    let (_ibex, fe) = start(http_request_cfg(), srv);
    let (took, resp) = timed(fe, "GET / HTTP/1.1\r\nHost: x\r\n");
    assert!(resp.starts_with("HTTP/1.1 408 "), "{resp:?}");
    assert!(took >= Duration::from_millis(480), "408 after {took:?}");
    assert!(took < Duration::from_millis(3000), "408 after {took:?}");
    let (took, resp) = timed(fe, "");
    assert!(resp.starts_with("HTTP/1.1 408 "), "{resp:?}");
    assert!(took >= Duration::from_millis(480), "408 after {took:?}");
    assert!(took < Duration::from_millis(3000), "408 after {took:?}");

    let mut c = TcpStream::connect(fe).expect("connect");
    let t0 = Instant::now();
    let mut got = String::new();
    for b in b"GET / HTTP/1.1\r\nHost: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n" {
        if c.write_all(&[*b]).is_err() {
            break;
        }
        got = read_until(&mut c, "408", Duration::from_millis(150));
        if got.contains("408") {
            break;
        }
    }
    assert!(got.starts_with("HTTP/1.1 408 "), "{got:?}");
    assert!(t0.elapsed() >= Duration::from_millis(480), "408 after {:?}", t0.elapsed());
    assert!(t0.elapsed() < Duration::from_millis(3000), "408 after {:?}", t0.elapsed());
}

#[test]
fn timeout_http_request_runs_from_the_first_byte_of_each_request_and_ends_with_the_head() {
    // HAProxy: after a first request answered, a second whose head stops half way gets
    // its `408` 1.0 s after its first byte, not after the first response; and a head that
    // is complete in time is not cut short by a body that comes later than the timeout.
    let (srv, _rx) = server();
    let (_ibex, fe) = start(http_request_cfg(), srv);
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(GET.as_bytes()).expect("send");
    assert!(read_until(&mut c, "ok", Duration::from_secs(3)).ends_with("ok"));
    thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").expect("send");
    let got = read_until(&mut c, "Time-out", Duration::from_secs(4));
    assert!(got.starts_with("HTTP/1.1 408 "), "{got:?}");
    assert!(t0.elapsed() >= Duration::from_millis(480), "408 after {:?}", t0.elapsed());
    assert!(t0.elapsed() < Duration::from_millis(3000), "408 after {:?}", t0.elapsed());

    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n").expect("send");
    thread::sleep(Duration::from_millis(900));
    c.write_all(b"abcd").expect("send");
    let got = read_until(&mut c, "ok", Duration::from_secs(3));
    assert!(got.starts_with("HTTP/1.1 200 "), "{got:?}");
}

#[test]
fn a_timeout_is_not_early_by_the_time_the_engine_was_idle() {
    // HAProxy: `timeout client 1s`, a head that stops half way, connections made at
    // different phases of an idle engine -- the `408` always comes at +1.001 s (10 trials:
    // 1.001 to 1.002). Timers armed from the tick taken before the poller wait came up to
    // 100 ms early (0.906 to 0.993 on Ibex).
    let (srv, _rx) = server();
    let cfg = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 5s\n\
        frontend fe\n  bind {fe}\n  default_backend be\n\
        backend be\n  server s {srv}\n";
    let (_ibex, fe) = start(cfg, srv);
    let trials: Vec<_> = (0..8u64)
        .map(|i| {
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(60 + 37 * i));
                timed(fe, "GET / HTTP/1.1\r\nHost: x\r\n")
            })
        })
        .collect();
    for t in trials {
        let (took, resp) = t.join().expect("trial");
        assert!(resp.starts_with("HTTP/1.1 408 "), "{resp:?}");
        assert!(took >= Duration::from_millis(990), "408 after {took:?}");
        assert!(took < Duration::from_millis(4000), "408 after {took:?}");
    }
}

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
        backend be\n  tcp-response inspect-delay 500ms\n  tcp-response content reject if !WAIT_END\n  tcp-response content accept if WAIT_END\n  server s {srv}\n";
    let (_ibex, fe) = start(cfg, srv);
    let (took, resp) = timed(fe, GET);
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp:?}");
    assert!(took >= Duration::from_millis(480), "the client had the response after {took:?}");
    assert!(took < Duration::from_millis(3000), "the client had the response after {took:?}");
}
