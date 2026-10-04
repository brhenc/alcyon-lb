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

/// A server answering `GET /<status>` with that status, an empty body, and `Connection: close`.
fn status_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let status: u16 = head.split(' ').nth(1).and_then(|p| p.trim_matches('/').parse().ok()).unwrap_or(200);
                let _ = c.write_all(format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes());
            });
        }
    });
    addr
}

fn start(cfg: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let text = cfg
        .replace("{fe}", &fe.to_string())
        .replace("{srv}", &echo_server().to_string())
        .replace("{status}", &status_server().to_string());
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

const FORWARDFOR: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n  {ffopt}\n  use_backend be1 if { path /req1 }\n  use_backend be2 if { path /req2 }\n  use_backend be3 if { path /req3 }\n\
backend be1\n  option forwardfor\n  server s {srv}\n\
backend be2\n  option forwardfor if-none\n  server s {srv}\n\
backend be3\n  server s {srv}\n";

/// How many `x-forwarded-for` header lines the server got for `path`, the client having
/// sent one of its own when `own`.
fn xff_count(fe: SocketAddr, path: &str, own: bool) -> usize {
    let hdr = if own { "x-forwarded-for: 127.0.0.9\r\n" } else { "" };
    let got = send(fe, &format!("GET {path} HTTP/1.1\r\nHost: a\r\n{hdr}Connection: close\r\n\r\n"));
    let body = got.split("\r\n\r\n").nth(1).unwrap_or("");
    body.lines().filter(|l| l.to_ascii_lowercase().starts_with("x-forwarded-for:")).count()
}

#[test]
fn forwardfor_if_none_adds_only_where_no_proxy_asks_for_it_always() {
    // Measured on HAProxy 3.5-dev8-885761-29 (reg-tests/http-rules/ifnone-forwardfor.vtc,
    // with the same frontend and backend options): the header is added always as soon as the
    // frontend or the backend asks for it without `if-none`; and it is added, not replaced.
    let (_i, fe) = start(&FORWARDFOR.replace("{ffopt}", "option forwardfor if-none"));
    assert_eq!(xff_count(fe, "/req1", true), 2);
    assert_eq!(xff_count(fe, "/req2", true), 1);
    assert_eq!(xff_count(fe, "/req2", false), 1);
    assert_eq!(xff_count(fe, "/req3", true), 1);
    assert_eq!(xff_count(fe, "/req3", false), 1);
    let (_i, fe) = start(&FORWARDFOR.replace("{ffopt}", "option forwardfor"));
    assert_eq!(xff_count(fe, "/req1", true), 2);
    assert_eq!(xff_count(fe, "/req2", true), 2);
    assert_eq!(xff_count(fe, "/req3", true), 2);
}

const ERR_FAIL: &str = "{global}defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
frontend fe\n  bind {fe}\n  http-request track-sc0 path\n\
  http-after-response add-header x-table err=%[sc0_http_err_cnt],fail=%[sc0_http_fail_cnt]\n\
  stick-table type string size 100 store http_err_cnt,http_fail_cnt\n\
  http-request deny if { path /deny }\n  http-request return status 404 if { path /ret404 }\n\
  http-request return status 500 if { path /ret500 }\n  default_backend be\n\
backend be\n  server s {status}\n";

/// The `x-table` header `HAProxy` answered for `GET /<code>` (the counters as the response
/// leaves, so counting the response itself).
fn x_table(fe: SocketAddr, code: &str) -> String {
    let got = get_close(fe, &format!("/{code}"));
    got.lines()
        .find_map(|l| l.strip_prefix("x-table: ").or_else(|| l.strip_prefix("X-Table: ")))
        .unwrap_or_else(|| panic!("/{code}: no x-table in {got:?}"))
        .to_string()
}

#[test]
fn the_default_error_and_failure_codes_count_what_haproxy_counts() {
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", ""));
    // (path, "err=..,fail=..") measured on HAProxy 3.5-dev8-885761-29 with the same config.
    for (code, want) in [
        ("200", "err=0,fail=0"),
        ("301", "err=0,fail=0"),
        ("399", "err=0,fail=0"),
        ("400", "err=1,fail=0"),
        ("401", "err=1,fail=0"),
        ("404", "err=1,fail=0"),
        ("407", "err=1,fail=0"),
        ("499", "err=1,fail=0"),
        ("500", "err=0,fail=1"),
        ("501", "err=0,fail=0"),
        ("502", "err=0,fail=1"),
        ("505", "err=0,fail=0"),
        ("599", "err=0,fail=1"),
        ("600", "err=0,fail=0"),
    ] {
        assert_eq!(x_table(fe, code), want, "status {code}");
    }
}

#[test]
fn deny_counts_an_error_and_return_does_not() {
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", ""));
    assert_eq!(x_table(fe, "deny"), "err=1,fail=0");
    assert_eq!(x_table(fe, "deny"), "err=2,fail=0");
    assert_eq!(x_table(fe, "ret404"), "err=0,fail=0");
    assert_eq!(x_table(fe, "ret500"), "err=0,fail=0");
}

#[test]
fn http_err_codes_and_http_fail_codes_redefine_the_sets() {
    // The vtc's lines: `220 +300-499 -300-399` leaves 220 and 400-499; the fail codes lose
    // 550-580 and gain 555, 599, 556-566.
    let g = "global\n  http-err-codes 220 +300-499 -300-399\n  http-fail-codes -550-580 +555,599,556-566\n";
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", g));
    for (code, want) in [
        ("220", "err=1,fail=0"),
        ("300", "err=0,fail=0"),
        ("400", "err=1,fail=0"),
        ("555", "err=0,fail=1"),
        ("550", "err=0,fail=0"),
        ("556", "err=0,fail=1"),
        ("500", "err=0,fail=1"),
        ("301", "err=0,fail=0"),
    ] {
        assert_eq!(x_table(fe, code), want, "status {code}");
    }
    // A sign sticks along a comma list; an unsigned element clears the set first.
    let g = "global\n  http-err-codes +300,310 -400,401\n";
    let (_i, fe) = start(&ERR_FAIL.replace("{global}", g));
    for (code, want) in
        [("300", "err=1"), ("310", "err=1"), ("400", "err=0"), ("401", "err=0"), ("402", "err=1")]
    {
        assert!(x_table(fe, code).starts_with(want), "status {code}");
    }
}
