// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The HTTP rule keywords of T124 (`replace-uri`, `errorloc`, `http-err-codes`, ...).
//!
//! Every expected value below was measured on the reference binary, `HAProxy
//! 3.5-dev8-885761-29`, on 2026-10-04, with the same configurations and a raw-socket
//! client and server (the server answers with the request head it received as the body).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
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

/// A server answering every request with `200` and the request head it got as the body.
fn echo_server() -> SocketAddr {
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
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", buf.len());
                    let mut out = resp.into_bytes();
                    out.extend_from_slice(&buf);
                    buf.clear();
                    if c.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start(cfg: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let text = cfg.replace("{fe}", &fe.to_string()).replace("{srv}", &echo_server().to_string());
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
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe)
}

/// Sends `raw`, returns everything until the peer closes or goes quiet.
fn send(fe: SocketAddr, raw: &str) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(raw.as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_millis(800))).ok();
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

/// The request line the server saw for `GET <target>` through `fe`.
fn seen_target(fe: SocketAddr, target: &str, host: &str) -> String {
    let got = send(fe, &format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"));
    let body = got.split("\r\n\r\n").nth(1).unwrap_or("");
    let line = body.lines().next().unwrap_or("").to_string();
    assert!(got.starts_with("HTTP/1.1 200"), "{target}: {got:?}");
    line
}

const REPLACE_URI: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n\
  http-request replace-uri ([^/:]*://[^/]*)?(.*) \\1/pfx\\2 if { url_param(t) -m str prefix }\n\
  http-request replace-uri ^http://(.*) https://\\1 if { url_param(t) -m str scheme }\n\
  http-request replace-uri ^/nosuchprefix/(.*) /other/\\1 if { url_param(t) -m str nomatch }\n\
  default_backend be\n\
backend be\n  server s {srv}\n";

#[test]
fn replace_uri_rewrites_the_whole_target_scheme_and_authority_included() {
    let (_i, fe) = start(REPLACE_URI);
    assert_eq!(seen_target(fe, "/bar?t=prefix", "a"), "GET /pfx/bar?t=prefix HTTP/1.1");
    assert_eq!(
        seen_target(fe, "http://www.example.com/bar?t=prefix", "www.example.com"),
        "GET http://www.example.com/pfx/bar?t=prefix HTTP/1.1"
    );
    assert_eq!(
        seen_target(fe, "http://www.example.com/bar?t=scheme", "www.example.com"),
        "GET https://www.example.com/bar?t=scheme HTTP/1.1"
    );
    assert_eq!(seen_target(fe, "/bar?t=nomatch", "a"), "GET /bar?t=nomatch HTTP/1.1");
}

const ERRORLOC: &str = "defaults\n  mode http\n  retries 0\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe1\n  bind {fe}\n  errorloc 503 http://www.example.com/oops503\n\
  http-request deny deny_status 403 if { path /denied }\n  default_backend dead\n\
backend dead\n  server s1 {dead}\n";

fn start_dead(cfg: &str) -> (Ibex, SocketAddr) {
    let dead = common::reserve_addr();
    start(&cfg.replace("{dead}", &dead.to_string()))
}

fn get_close(fe: SocketAddr, path: &str) -> String {
    send(fe, &format!("GET {path} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"))
}

#[test]
fn errorloc_answers_with_the_redirect_haproxy_builds() {
    let (_i, fe) = start_dead(ERRORLOC);
    assert_eq!(
        // Header names are case-insensitive: Ibex writes `Connection: close` capitalised.
        get_close(fe, "/gone").replace("Connection: close", "connection: close"),
        "HTTP/1.1 302 Found\r\ncache-control: no-cache\r\ncontent-length: 0\r\nlocation: http://www.example.com/oops503\r\nconnection: close\r\n\r\n"
    );
    // No errorloc for 403: the default page.
    let got = get_close(fe, "/denied");
    assert!(got.starts_with("HTTP/1.1 403 Forbidden\r\n") && !got.contains("location"), "{got:?}");
}

#[test]
fn errorloc303_and_a_relative_location() {
    let cfg = ERRORLOC.replace(
        "errorloc 503 http://www.example.com/oops503",
        "errorloc303 503 /l503\n  errorloc302 403 /l403",
    );
    let (_i, fe) = start_dead(&cfg);
    let got = get_close(fe, "/gone");
    assert!(got.starts_with("HTTP/1.1 303 See Other\r\n") && got.contains("location: /l503\r\n"), "{got:?}");
    let got = get_close(fe, "/denied");
    assert!(got.starts_with("HTTP/1.1 302 Found\r\n") && got.contains("location: /l403\r\n"), "{got:?}");
}
