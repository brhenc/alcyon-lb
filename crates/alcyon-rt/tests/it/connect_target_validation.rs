// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The target of an H1 CONNECT request must be in authority-form: `host:port`, and
//! nothing else. RFC 9112 section 3.2.3: the target is forwarded as-is, so a userinfo
//! (`user:pass@host:port`), a path (`host:port/x`) or a query (`host:port?x`) in it makes
//! the proxy and the next hop disagree on the destination. HAProxy 3.5-dev11 answers 400
//! to every such target, with or without a `Host` header
//! (`reg-tests/http-messaging/h1_connect_target_validation.vtc`); Alcyon used to accept
//! the userinfo form.
//!
//! Every expected status below was measured on `HAProxy` 3.5-dev11, sent as raw bytes to
//! a frontend with `http-request return status 200` (a raw probe, so no `Host` is added
//! unless the test sends one; the reg-test's own runner adds `Host: 127.0.0.1`, which is
//! the mismatch the reg-test's c5 exercises). Set
//! `T281_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

struct Proxy {
    child: Child,
    fe: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start() -> Proxy {
    let fe = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  http-request return status 200\n"
    )
    .expect("write");
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(common::wait_listening(fe), "never listened");
    Proxy { child, fe, _cfg: cfg }
}

/// Sends `CONNECT {target} HTTP/1.1` with the given `Host` header (or none) and returns
/// the status of the response: the first line is all either form of answer carries.
fn connect_status(p: &Proxy, target: &str, host: Option<&str>) -> u16 {
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut req = format!("CONNECT {target} HTTP/1.1\r\n");
    if let Some(h) = host {
        req.push_str(&format!("Host: {h}\r\n"));
    }
    req.push_str("\r\n");
    c.write_all(req.as_bytes()).expect("write");
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        if got.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    let text = String::from_utf8_lossy(&got);
    let first = text.lines().next().unwrap_or("");
    first.split_whitespace().nth(1).and_then(|s| s.parse().ok()).expect("a status line")
}

/// The reg-test's c1: a plain authority-form target, with a matching `Host`: accepted.
#[test]
fn authority_form_is_accepted() {
    let p = start();
    assert_eq!(connect_status(&p, "allowed.com:443", Some("allowed.com:443")), 200);
}

/// The reg-test's c2: userinfo before the host, with a `Host` that matches the host the
/// target names: refused, because the target is forwarded as-is.
#[test]
fn userinfo_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, "internal:22@allowed.com:443", Some("allowed.com:443")), 400);
}

/// The reg-test's c3: a path after the authority: refused.
#[test]
fn path_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, "allowed.com:443/x", Some("allowed.com:443")), 400);
}

/// The reg-test's c4: a query after the authority: refused.
#[test]
fn query_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, "allowed.com:443?x", Some("allowed.com:443")), 400);
}

/// The reg-test's c5: userinfo, and a `Host` that matches nothing in the target (the
/// reg-test's client adds `Host: 127.0.0.1`): refused.
#[test]
fn userinfo_with_mismatching_host_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, "internal:22@allowed.com:443", Some("127.0.0.1")), 400);
}

/// Measured: two `@` in the target: refused, whatever the `Host`.
#[test]
fn double_userinfo_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, "a@b@allowed.com:443", Some("allowed.com:443")), 400);
}

/// Measured: an empty host (`:443`): refused.
#[test]
fn empty_host_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, ":443", Some(":443")), 400);
}

/// Measured: no port at all: refused.
#[test]
fn missing_port_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, "allowed.com", Some("allowed.com")), 400);
}

/// Measured: a non-numeric port: refused.
#[test]
fn non_numeric_port_is_refused() {
    let p = start();
    assert_eq!(connect_status(&p, "allowed.com:abc", Some("allowed.com:abc")), 400);
}

/// Measured: a bracketed IPv6 literal with a port: accepted.
#[test]
fn bracketed_ipv6_is_accepted() {
    let p = start();
    assert_eq!(connect_status(&p, "[::1]:443", Some("[::1]:443")), 200);
}

/// Measured: a port above 65535 is accepted (the proxy does not range-check the digits):
/// the target is only forwarded, so no error here.
#[test]
fn port_above_65535_is_accepted() {
    let p = start();
    assert_eq!(connect_status(&p, "allowed.com:65536", Some("allowed.com:65536")), 200);
}

/// Measured: a target without any `Host` header: accepted (the proxy derives the `Host`
/// from the target).
#[test]
fn missing_host_is_accepted() {
    let p = start();
    assert_eq!(connect_status(&p, "allowed.com:443", None), 200);
}
