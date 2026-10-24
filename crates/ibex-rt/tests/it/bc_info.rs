// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: the backend connection's fetches, `bc_err`, `bc_err_str`, `bc_reused`, `bc_dst`
//! and `bc_dst_port`. Every expected value was measured on `HAProxy` 3.5-dev8-885761-29 with
//! the same configuration.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> Ibex {
    let dir = std::env::temp_dir().join(format!("bc-info-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    let full = format!("defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{cfg}");
    std::fs::write(&path, full).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    ibex
}

/// A keep-alive server on `bind`: answers every request of every connection with a 2-byte 200.
fn backend(bind: &str) -> SocketAddr {
    let l = TcpListener::bind(bind).unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let (mut pending, mut b) = (Vec::new(), [0u8; 4096]);
                loop {
                    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        pending.drain(..end + 4);
                        if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                    match c.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pending.extend_from_slice(&b[..n]),
                    }
                }
            });
        }
    });
    addr
}

/// A port nothing listens on: reserved and never bound, so a connect to it is refused. A
/// port taken by binding `:0` and dropping the listener is in the ephemeral range, where the
/// kernel can hand it to another test's outgoing connection.
fn closed_port() -> SocketAddr {
    common::reserve_addr()
}

/// Sends one keep-alive request on `c` and returns the `x-out` header of its 2-byte answer.
fn xout(c: &mut TcpStream) -> String {
    c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
    let (mut got, mut b) = (Vec::new(), [0u8; 4096]);
    let head = loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            if got.len() >= end + 4 + 2 {
                break String::from_utf8_lossy(&got[..end]).into_owned();
            }
        }
        let n = c.read(&mut b).unwrap_or(0);
        assert!(n > 0, "the answer stopped short: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&b[..n]);
    };
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {head:?}"))
}

fn connect(a: SocketAddr) -> TcpStream {
    let c = TcpStream::connect_timeout(&a, Duration::from_secs(2)).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c
}

const XOUT: &str = "http-response set-header x-out \"%[bc_err]|[%[bc_err_str]]|%[bc_reused]|%[bc_dst]|%[bc_dst_port]|%[dst]\"";

/// `http-reuse always`, three requests on one client connection: the second and third run
/// on the server connection the first opened (oracle: 0, then 1, then 1).
#[test]
fn bc_reused_is_set_on_a_reused_server_connection() {
    let be = backend("127.0.0.1:0");
    let a = common::reserve_addr();
    let cfg = format!("frontend fe\n  bind {a}\n  default_backend b\n  {XOUT}\nbackend b\n  http-reuse always\n  server s {be}\n");
    let _ibex = start("reuse", &cfg, &[a]);
    let mut c = connect(a);
    let p = be.port();
    assert_eq!(xout(&mut c), format!("0|[Success]|0|127.0.0.1|{p}|127.0.0.1"));
    assert_eq!(xout(&mut c), format!("0|[Success]|1|127.0.0.1|{p}|127.0.0.1"));
    assert_eq!(xout(&mut c), format!("0|[Success]|1|127.0.0.1|{p}|127.0.0.1"));
}

/// A server on `::1` behind a frontend on 127.0.0.1: `bc_dst` is the server's address, an
/// IPv6 one, and `dst` the frontend's (oracle: `0|[Success]|0|::1|<port>|127.0.0.1`).
#[test]
fn bc_dst_is_the_server_address_not_the_frontend_one() {
    let be = backend("[::1]:0");
    let a = common::reserve_addr();
    let cfg = format!("frontend fe\n  bind {a}\n  default_backend b\n  {XOUT}\nbackend b\n  http-reuse never\n  server s {be}\n");
    let _ibex = start("v6", &cfg, &[a]);
    let mut c = connect(a);
    assert_eq!(xout(&mut c), format!("0|[Success]|0|::1|{}|127.0.0.1", be.port()));
}

/// The log line of a connect the server refused (`retries 0`) carries `CO_ER_EREFUSED`; one
/// with no server to connect to has no backend connection, so no `bc_err` nor `bc_dst`, and
/// `bc_reused` 0 (oracle, in this order: 200 ok, 503 refused, 503 no server).
#[test]
fn bc_err_logs_the_server_connect_error() {
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (be, dead) = (backend("127.0.0.1:0"), closed_port());
    let (ok, refused, none) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    // The readiness probes send nothing: `dontlognull` keeps them out of the log.
    let fmt = "LOG %ST %[bc_err]|[%[bc_err_str]]|%[bc_reused]|%[bc_dst]|%[bc_dst_port]";
    let log = collector.local_addr().unwrap();
    let cfg = format!(
        "frontend f1\n  bind {ok}\n  log {log} local0\n  option dontlognull\n  log-format \"{fmt}\"\n  default_backend good\n\
         frontend f2\n  bind {refused}\n  log {log} local0\n  option dontlognull\n  log-format \"{fmt}\"\n  default_backend refused\n\
         frontend f3\n  bind {none}\n  log {log} local0\n  option dontlognull\n  log-format \"{fmt}\"\n  default_backend none\n\
         backend good\n  server s {be}\n\
         backend refused\n  retries 0\n  server s {dead}\n\
         backend none\n"
    );
    let _ibex = start("err", &cfg, &[ok, refused, none]);
    let mut lines = Vec::new();
    for a in [ok, refused, none] {
        let mut c = connect(a);
        c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
        let _ = c.read_to_end(&mut Vec::new());
        let mut buf = [0u8; 2048];
        let n = collector.recv(&mut buf).expect("a log line");
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        lines.push(line[line.find("LOG ").expect("the log-format line")..].trim_end().to_string());
    }
    assert_eq!(
        lines,
        [
            format!("LOG 200 0|[Success]|0|127.0.0.1|{}", be.port()),
            format!("LOG 503 47|[ECONNREFUSED returned by OS]|0|127.0.0.1|{}", dead.port()),
            "LOG 503 -|[-]|0|-|-".to_string(),
        ]
    );
}

/// A server written without a port connects to the destination port, which
/// `set-dst-port` sets per request: `bc_dst_port` is the port each request's server
/// connection went to, on one client connection, the second request to another port than
/// the first (oracle, `http-reuse always`: `127.0.0.1|<p1>|<p1>`, then `<p2>`, `<p2>`, `<p1>`).
/// `bc_dst` is derived from the stream's server and destination (not stored): this pins
/// that the derivation follows each new connection.
#[test]
fn bc_dst_port_follows_the_destination_a_portless_server_maps() {
    let (be1, be2) = (backend("127.0.0.1:0"), backend("127.0.0.1:0"));
    let a = common::reserve_addr();
    let cfg = format!(
        "frontend fe\n  bind {a}\n  http-request set-dst-port req.hdr(x-port)\n  default_backend b\n  \
         http-response set-header x-out \"%[bc_dst]|%[bc_dst_port]|%[dst_port]\"\n\
         backend b\n  http-reuse always\n  server s 127.0.0.1\n"
    );
    let _ibex = start("mapports", &cfg, &[a]);
    let mut c = connect(a);
    for p in [be1.port(), be2.port(), be2.port(), be1.port()] {
        c.write_all(format!("GET / HTTP/1.1\r\nHost: a\r\nx-port: {p}\r\n\r\n").as_bytes()).unwrap();
        let (mut got, mut b) = (Vec::new(), [0u8; 4096]);
        let head = loop {
            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                if got.len() >= end + 4 + 2 {
                    break String::from_utf8_lossy(&got[..end]).into_owned();
                }
            }
            let n = c.read(&mut b).unwrap_or(0);
            assert!(n > 0, "the answer stopped short: {:?}", String::from_utf8_lossy(&got));
            got.extend_from_slice(&b[..n]);
        };
        let out = head.lines().find_map(|l| l.strip_prefix("x-out: ")).unwrap_or_else(|| panic!("no x-out: {head:?}"));
        assert_eq!(out, format!("127.0.0.1|{p}|{p}"));
    }
}
