// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/1 request authority against `Host`: what is refused, and what the server receives
//! (tasks/T93, `reg-tests/http-messaging/h1_host_normalization.vtc`).
//!
//! `HAProxy` checks the authority of an absolute-form or CONNECT request-target against the
//! `Host` header while parsing the head (`src/h1.c`: `h1_parse_msg_hdrs`,
//! `h1_validate_connect_authority`, `h1_validate_mismatch_authority`), and then normalises
//! an absolute-form target by its scheme (`src/http_htx.c`, `http_scheme_based_normalize`,
//! RFC 3986 section 6.3.2): a default or empty port is dropped from the authority and every
//! `Host` is rewritten to match, and an empty path becomes `/`.
//!
//! Every expected value below was measured, not derived: `HAProxy` 3.5-dev8-885761-29
//! (2026/10/02, `/home/bhenc/reference/haproxy/haproxy`), on 2026-10-03, with
//! `defaults mode http` / `frontend fe` / `default_backend be` / `backend be` / `server s1`,
//! sending each request on its own connection and recording the status the client got and
//! the request line and `Host` lines the server received. The `c*` names are the clients
//! of the vtc; the `x*` cases are extra probes measured the same way. `HAProxy` sends the
//! header name as `host`; the names are compared without case here, the values exactly.

mod common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A server that records the head of every request it is sent and answers 200.
fn backend() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let log = Arc::clone(&log);
            thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                log.lock().unwrap().push(String::from_utf8_lossy(&head).into_owned());
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            });
        }
    });
    (addr, seen)
}

struct Ibex(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(be: SocketAddr) -> (Ibex, SocketAddr) {
    start_with(be, "")
}

/// `fe_lines` are extra lines (each ending in a newline) in the frontend.
fn start_with(be: SocketAddr, fe_lines: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe}\n{fe_lines}  default_backend be\n\
         backend be\n  server s1 {be}\n"
    );
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
    (Ibex(child, f), fe)
}

/// One request: the method, the target and the `Host` values sent; then the status the
/// client must get, and -- for a forwarded request -- the request line and `Host` values
/// the server must receive.
struct Case {
    name: &'static str,
    method: &'static str,
    target: &'static str,
    hosts: &'static [&'static str],
    status: u16,
    line: &'static str,
    server_hosts: &'static [&'static str],
}

const fn ok(
    name: &'static str,
    method: &'static str,
    target: &'static str,
    hosts: &'static [&'static str],
    line: &'static str,
    server_hosts: &'static [&'static str],
) -> Case {
    Case { name, method, target, hosts, status: 200, line, server_hosts }
}

const fn bad(name: &'static str, method: &'static str, target: &'static str, hosts: &'static [&'static str]) -> Case {
    Case { name, method, target, hosts, status: 400, line: "", server_hosts: &[] }
}

/// Sends every case through one ibex and returns a description of each that differs from
/// `HAProxy`, so a failure lists all of them at once.
fn run(cases: &[Case]) -> Vec<String> {
    run_with(cases, "")
}

fn run_with(cases: &[Case], fe_lines: &str) -> Vec<String> {
    let (be, seen) = backend();
    let (_ibex, fe) = start_with(be, fe_lines);
    let mut wrong = Vec::new();
    for c in cases {
        seen.lock().unwrap().clear();
        let mut req = format!("{} {} HTTP/1.1\r\n", c.method, c.target);
        for h in c.hosts {
            let _ = write!(req, "host: {h}\r\n");
        }
        req.push_str("\r\n");
        let mut s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        while !resp.windows(2).any(|w| w == b"\r\n") {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
            }
        }
        drop(s);
        let resp = String::from_utf8_lossy(&resp).into_owned();
        let status: u16 = resp.split(' ').nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        let heads = seen.lock().unwrap().clone();
        let got = heads.first().map(|head| {
            let mut lines = head.split("\r\n");
            let line = lines.next().unwrap_or("").to_string();
            let hosts: Vec<String> = lines
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim().to_string())
                .collect();
            (line, hosts)
        });
        let sent = format!("{} {} host={:?}", c.method, c.target, c.hosts);
        if status != c.status {
            wrong.push(format!(
                "{}: `{sent}` got status {status}, HAProxy {}; the server received {got:?}",
                c.name, c.status
            ));
            continue;
        }
        if c.status != 200 {
            if let Some(g) = got {
                wrong.push(format!("{}: `{sent}` was refused but the server still received {g:?}", c.name));
            }
            continue;
        }
        let want = (c.line.to_string(), c.server_hosts.iter().map(|h| (*h).to_string()).collect::<Vec<_>>());
        match got {
            Some(g) if g == want => {}
            g => wrong.push(format!(
                "{}: `{sent}` reached the server as {g:?}; HAProxy sends {want:?}",
                c.name
            )),
        }
    }
    wrong
}

fn check(cases: &[Case], what: &str) {
    let wrong = run(cases);
    assert!(wrong.is_empty(), "{what}: {} of {} differ from HAProxy 3.5:\n  {}", wrong.len(), cases.len(), wrong.join("\n  "));
}

/// An authority and a `Host` that do not name the same thing are refused with 400 and
/// never reach the server: vtc c8-c19, plus a non-http(s) scheme with a port (x6, where
/// no port is a default), a port of `080`, compared as text (x9), and an IPv4 CONNECT
/// target with another address in `Host` (x17).
#[test]
fn an_authority_that_disagrees_with_host_is_refused() {
    check(
        &[
            bad("c8", "GET", "http://hostname1/", &["hostname2"]),
            bad("c9", "GET", "http://hostname:80/", &["hostname:81"]),
            bad("c10", "GET", "http://hostname:8080/", &["hostname"]),
            bad("c11", "GET", "http://hostname/", &["hostname:81"]),
            bad("c12", "GET", "http://hostname1/", &["hostname1", "hostname2"]),
            bad("c13", "GET", "http://hostname1/", &["hostname1:80", "hostname1"]),
            bad("c14", "CONNECT", "hostname", &["hostname"]),
            bad("c15", "CONNECT", "hostname1:80", &["hostname2:80"]),
            bad("c16", "CONNECT", "hostname:80", &["hostname:443"]),
            bad("c17", "CONNECT", "hostname:8080", &["hostname"]),
            bad("c18", "CONNECT", "/", &["hostname"]),
            bad("c19", "CONNECT", "hostname:", &["hostname"]),
            bad("x6", "GET", "ftp://hostname:80/x6", &["hostname"]),
            bad("x9", "GET", "http://hostname:080/x9", &["hostname"]),
            bad("x12", "GET", "http://hostname/x12", &["hostname", "hostname:80"]),
            bad("x17", "CONNECT", "127.0.0.1:443", &["127.0.0.2"]),
        ],
        "mismatched authority",
    );
}

/// A default port (80 for `http://`, 443 for `https://`) or an empty port is dropped from
/// an absolute-form target, every `Host` is rewritten to the authority's host, and an
/// empty path becomes `/`. Userinfo stays in the target (c1). The scheme is matched
/// without case (x7); the host keeps the target's case (x4).
#[test]
fn an_absolute_target_is_normalised_by_its_scheme() {
    check(
        &[
            ok("c1", "GET", "http://toto:poue@hostname:80/c1", &["hostname:80"], "GET http://toto:poue@hostname/c1 HTTP/1.1", &["hostname"]),
            ok("c3", "GET", "https://hostname:443/c3", &["hostname:443"], "GET https://hostname/c3 HTTP/1.1", &["hostname"]),
            ok("c20", "GET", "http://hostname:80/c20", &["hostname"], "GET http://hostname/c20 HTTP/1.1", &["hostname"]),
            ok("c21", "GET", "https://hostname:443/c21", &["hostname"], "GET https://hostname/c21 HTTP/1.1", &["hostname"]),
            ok("c24", "GET", "http://hostname:/c24", &["hostname"], "GET http://hostname/c24 HTTP/1.1", &["hostname"]),
            ok("c25", "GET", "https://hostname:/c25", &["hostname"], "GET https://hostname/c25 HTTP/1.1", &["hostname"]),
            ok("c28", "GET", "http://hostname:80/c28", &["hostname:"], "GET http://hostname/c28 HTTP/1.1", &["hostname"]),
            ok("c29", "GET", "http://hostname:/c29", &["hostname:80"], "GET http://hostname/c29 HTTP/1.1", &["hostname"]),
            ok("c30", "GET", "https://hostname:443/c30", &["hostname:"], "GET https://hostname/c30 HTTP/1.1", &["hostname"]),
            ok("c31", "GET", "https://hostname:/c31", &["hostname:443"], "GET https://hostname/c31 HTTP/1.1", &["hostname"]),
            ok("c32", "GET", "http://:", &[":80"], "GET http:/// HTTP/1.1", &[""]),
            ok("c33", "GET", "https://:", &[":443"], "GET https:/// HTTP/1.1", &[""]),
            ok("c34", "GET", "http://:", &[":"], "GET http:/// HTTP/1.1", &[""]),
            ok("c35", "GET", "https://:", &[":"], "GET https:/// HTTP/1.1", &[""]),
            ok("c36", "GET", "http://hostname", &["hostname"], "GET http://hostname/ HTTP/1.1", &["hostname"]),
            ok("c37", "GET", "http://hostname:80", &["hostname"], "GET http://hostname/ HTTP/1.1", &["hostname"]),
            ok("c38", "GET", "http://hostname:", &["hostname"], "GET http://hostname/ HTTP/1.1", &["hostname"]),
            ok("c39", "GET", "https://hostname", &["hostname"], "GET https://hostname/ HTTP/1.1", &["hostname"]),
            ok("c40", "GET", "https://hostname:443", &["hostname"], "GET https://hostname/ HTTP/1.1", &["hostname"]),
            ok("c41", "GET", "https://hostname:", &["hostname"], "GET https://hostname/ HTTP/1.1", &["hostname"]),
            ok("c42", "GET", "http://hostname:81", &["hostname:81"], "GET http://hostname:81/ HTTP/1.1", &["hostname:81"]),
            ok("c43", "GET", "https://hostname:444", &["hostname:444"], "GET https://hostname:444/ HTTP/1.1", &["hostname:444"]),
            ok("c45", "GET", "http://hostname:80?c=d", &["hostname:80"], "GET http://hostname?c=d HTTP/1.1", &["hostname"]),
            ok("x1", "GET", "http://hostname:80/x1", &[], "GET http://hostname/x1 HTTP/1.1", &[]),
            ok("x4", "GET", "http://HostName:80/x4", &["hostname"], "GET http://HostName/x4 HTTP/1.1", &["HostName"]),
            ok("x5", "OPTIONS", "http://hostname:80", &["hostname"], "OPTIONS http://hostname HTTP/1.1", &["hostname"]),
            ok("x7", "GET", "HTTP://hostname:80/x7", &["hostname"], "GET HTTP://hostname/x7 HTTP/1.1", &["hostname"]),
            ok("x16", "GET", "http://[::1]:80/x16", &["[::1]"], "GET http://[::1]/x16 HTTP/1.1", &["[::1]"]),
        ],
        "scheme-based normalisation",
    );
}

/// The controls: a non-default port for the scheme, a port only on `Host`, a path that is
/// already there, a query with no path, and origin-form, all reach the server as sent.
/// Without these the normalisation could strip every port and still pass the test above.
#[test]
fn a_target_without_a_default_port_reaches_the_server_as_sent() {
    check(
        &[
            ok("c2", "GET", "http://hostname:8080/c2", &["hostname:8080"], "GET http://hostname:8080/c2 HTTP/1.1", &["hostname:8080"]),
            ok("c4", "GET", "https://hostname:80/c4", &["hostname:80"], "GET https://hostname:80/c4 HTTP/1.1", &["hostname:80"]),
            ok("c22", "GET", "http://hostname/c22", &["hostname:80"], "GET http://hostname/c22 HTTP/1.1", &["hostname:80"]),
            ok("c23", "GET", "https://hostname/c23", &["hostname:443"], "GET https://hostname/c23 HTTP/1.1", &["hostname:443"]),
            ok("c26", "GET", "http://hostname/c26", &["hostname:"], "GET http://hostname/c26 HTTP/1.1", &["hostname:"]),
            ok("c27", "GET", "https://hostname/c27", &["hostname:"], "GET https://hostname/c27 HTTP/1.1", &["hostname:"]),
            ok("c44", "GET", "http://hostname?a=b", &["hostname"], "GET http://hostname?a=b HTTP/1.1", &["hostname"]),
            ok("x3", "GET", "/x3", &["hostname:80"], "GET /x3 HTTP/1.1", &["hostname:80"]),
        ],
        "targets left alone",
    );
}

/// CONNECT keeps its authority as sent; a `Host` carrying a default port (80 or 443, either
/// one, since CONNECT has no scheme) loses it, and `Host: name:` with an empty port is
/// left alone. A non-default port is kept on both. An IPv4 or IPv6 target, which starts
/// with no letter, is an authority like any other (x14, x15).
#[test]
fn connect_keeps_its_authority_and_normalises_host() {
    check(
        &[
            ok("c5a", "CONNECT", "hostname:80", &["hostname:80"], "CONNECT hostname:80 HTTP/1.1", &["hostname"]),
            ok("c5b", "CONNECT", "hostname:80", &["hostname"], "CONNECT hostname:80 HTTP/1.1", &["hostname"]),
            ok("c5c", "CONNECT", "hostname:80", &["hostname:"], "CONNECT hostname:80 HTTP/1.1", &["hostname:"]),
            ok("c6a", "CONNECT", "hostname:443", &["hostname:443"], "CONNECT hostname:443 HTTP/1.1", &["hostname"]),
            ok("c6b", "CONNECT", "hostname:443", &["hostname"], "CONNECT hostname:443 HTTP/1.1", &["hostname"]),
            ok("c6c", "CONNECT", "hostname:443", &["hostname:"], "CONNECT hostname:443 HTTP/1.1", &["hostname:"]),
            ok("c7", "CONNECT", "hostname:8443", &["hostname:8443"], "CONNECT hostname:8443 HTTP/1.1", &["hostname:8443"]),
            ok("x10", "CONNECT", "hostname:80", &[], "CONNECT hostname:80 HTTP/1.1", &[]),
            ok("x14", "CONNECT", "127.0.0.1:443", &["127.0.0.1:443"], "CONNECT 127.0.0.1:443 HTTP/1.1", &["127.0.0.1"]),
            ok("x15", "CONNECT", "[::1]:443", &["[::1]:443"], "CONNECT [::1]:443 HTTP/1.1", &["[::1]"]),
        ],
        "CONNECT authority",
    );
}

/// A repeated `Host` with the same value (compared without case) is forwarded once; with
/// a different value it is refused (c12, c13 and x12 above).
#[test]
fn a_repeated_identical_host_is_forwarded_once() {
    check(
        &[
            ok("x2", "GET", "http://hostname:80/x2", &["hostname:80", "HOSTNAME:80"], "GET http://hostname/x2 HTTP/1.1", &["hostname"]),
            ok("x11", "GET", "http://hostname:80/x11", &["hostname", "hostname"], "GET http://hostname/x11 HTTP/1.1", &["hostname"]),
            ok("x13", "CONNECT", "hostname:80", &["hostname:80", "hostname:80"], "CONNECT hostname:80 HTTP/1.1", &["hostname"]),
        ],
        "repeated Host",
    );
}

/// A `#` anywhere in the request-target is refused (`src/h1.c`, `http_msg_rquri2`: the
/// request line is invalid unless `accept-unsafe-violations-in-http-request` is set), in
/// every form of target and whatever the authority is (T101 item 1).
#[test]
fn a_fragment_in_the_target_is_refused() {
    check(
        &[
            bad("f1", "GET", "http://hostname:80#frag", &["hostname"]),
            bad("f2", "GET", "/a#b", &["h"]),
            bad("f3", "GET", "http://hostname/a#b", &["hostname"]),
            bad("f4", "GET", "/a?b#c", &["h"]),
        ],
        "fragment in the target",
    );
}

/// `http_authority_has_forbidden_char`: the first `Host` of every request, and the
/// authority of an absolute-form or CONNECT target, may hold no byte outside `!`..`~`,
/// none of `, # / ? @ \`, and `[` or `]` only as the brackets of an IP literal (`[` first,
/// `]` last or before a colon). A later `Host` is only compared with the first (T101
/// item 3).
#[test]
fn forbidden_characters_in_the_authority_or_host_are_refused() {
    check(
        &[
            bad("h1", "GET", "/x", &["a/b"]),
            bad("h2", "GET", "/x", &["a,b"]),
            bad("h3", "GET", "/x", &["[::1"]),
            bad("h4", "GET", "/x", &["a?b"]),
            bad("h5", "GET", "/x", &["u@a"]),
            bad("h6", "GET", "/x", &["a\\b"]),
            bad("h7", "GET", "/x", &["a b"]),
            bad("h8", "GET", "/x", &["a]"]),
            bad("h9", "GET", "/x", &["ok", "a/b"]),
            bad("a1", "GET", "http://a,b/x", &["a,b"]),
            bad("a2", "GET", "http://a\\b/x", &["a\\b"]),
            bad("a3", "GET", "http://a,b/x", &[]),
            bad("a4", "CONNECT", "a,b:80", &["a,b:80"]),
            bad("a5", "CONNECT", "a,b:80", &[]),
            ok("o1", "GET", "/x", &["[::1]:80"], "GET /x HTTP/1.1", &["[::1]:80"]),
            ok("o2", "GET", "http://[::1]/x", &["[::1]"], "GET http://[::1]/x HTTP/1.1", &["[::1]"]),
            ok("o3", "GET", "http://u@a/x", &["a"], "GET http://u@a/x HTTP/1.1", &["a"]),
            ok("o4", "GET", "/x", &[""], "GET /x HTTP/1.1", &[""]),
        ],
        "forbidden characters",
    );
}

/// Sends `req` and returns the head the server received and the client's status.
fn one(req: &str) -> (String, u16) {
    let (be, seen) = backend();
    let (_ibex, fe) = start(be);
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.windows(2).any(|w| w == b"\r\n") {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    let resp = String::from_utf8_lossy(&resp).into_owned();
    let status = resp.split(' ').nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    let head = seen.lock().unwrap().first().cloned().unwrap_or_default();
    (head, status)
}

/// A head bigger than the 8 KiB the rebuild once had is normalised like any other
/// (T101 item 2): the authority, the `Host`, and the `Content-Length` beside
/// `Transfer-Encoding` of T89.
#[test]
fn a_head_over_8_kib_is_normalised_too() {
    let pad = "a".repeat(9000);
    let (head, status) = one(&format!(
        "GET http://hostname:80/big HTTP/1.1\r\nhost: hostname:80\r\nx-pad: {pad}\r\n\r\n"
    ));
    assert_eq!(status, 200, "head: {head:.200}");
    assert!(head.starts_with("GET http://hostname/big HTTP/1.1\r\n"), "request line: {:.80}", head);
    assert!(head.contains("\r\nhost: hostname\r\n"), "Host not normalised");
    assert!(head.contains(&pad), "padding lost");

    let (head, status) = one(&format!(
        "POST /big HTTP/1.1\r\nhost: h\r\ncontent-length: 5\r\ntransfer-encoding: chunked\r\nx-pad: {pad}\r\n\r\n0\r\n\r\n"
    ));
    assert_eq!(status, 200, "head: {head:.200}");
    assert!(!head.to_ascii_lowercase().contains("content-length"), "Content-Length kept beside Transfer-Encoding");
}

/// `option accept-unsafe-violations-in-http-request` lets a `#` through in the target
/// (`h1m->err_pos == -1`: captured, not refused); the authority stops at it, so a default
/// port before it is still dropped. A forbidden character in `Host` stays refused, as does
/// one in the authority when `Host` is sent (reg-tests `h1_authority_fragment_char.vtc`).
/// `no option` in the same frontend turns it off again.
#[test]
fn accept_unsafe_violations_lets_a_fragment_through() {
    let opt = "  option accept-unsafe-violations-in-http-request\n";
    let cases = [
        ok("u1", "GET", "http://hostname#frag", &["hostname"], "GET http://hostname#frag HTTP/1.1", &["hostname"]),
        ok("u2", "GET", "http://hostname:80#frag", &["hostname"], "GET http://hostname#frag HTTP/1.1", &["hostname"]),
        ok("u3", "GET", "/a#b", &["h"], "GET /a#b HTTP/1.1", &["h"]),
        ok("u4", "GET", "http://hostname/abc#frag", &["hostname"], "GET http://hostname/abc#frag HTTP/1.1", &["hostname"]),
        ok("u5", "GET", "http://a,b/x", &[], "GET http://a,b/x HTTP/1.1", &[]),
        bad("u6", "GET", "/x", &["a/b"]),
        bad("u7", "GET", "http://a,b/x", &["a,b"]),
    ];
    let wrong = run_with(&cases, opt);
    assert!(wrong.is_empty(), "with the option:\n  {}", wrong.join("\n  "));
    let off = format!("{opt}  no option accept-unsafe-violations-in-http-request\n");
    let wrong = run_with(&[bad("u8", "GET", "/a#b", &["h"])], &off);
    assert!(wrong.is_empty(), "with the option turned off:\n  {}", wrong.join("\n  "));
}

/// `%r` is the request line after the authority was normalised, not as received
/// (`h1_host_normalization.vtc` expects `uri: GET http://toto:poue@hostname/c1 HTTP/1.1`
/// for a target sent with `:80`; T101 item 4).
#[test]
fn the_logged_request_line_is_the_normalised_one() {
    let collector = std::net::UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (be, _seen) = backend();
    let lines = format!("  log {} local0\n  log-format \"uri: %r; host: %hr\"\n  http-request capture req.hdr(host) len 512\n", collector.local_addr().unwrap());
    let (_ibex, fe) = start_with(be, &lines);
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(b"GET http://hostname:80/log HTTP/1.1\r\nhost: hostname:80\r\nconnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let mut buf = [0u8; 2048];
    // The connection `start` made to see ibex listening logs as `<BADREQ>` first.
    let mut seen = Vec::new();
    while let Ok(n) = collector.recv(&mut buf) {
        let line = String::from_utf8_lossy(&buf[..n]).into_owned();
        if !line.contains("<BADREQ>") {
            seen.push(line);
            break;
        }
    }
    assert!(
        seen.first().is_some_and(|l| l.trim_end_matches('\n').ends_with("uri: GET http://hostname/log HTTP/1.1; host: {hostname}")),
        "logged: {seen:?}"
    );
}
