// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `accept-proxy` is an option of one `bind`, not of the frontend (T194): a plain bind next
//! to an `accept-proxy` bind serves without a PROXY header, the other one reads it.
//! Also `http-request return ... string` is literal; only `lf-string` is a log-format.
//! Expected values measured on HAProxy 3.5-dev8-885761-29.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

fn exchange(addr: SocketAddr, preamble: &str) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let req = format!("{preamble}GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn body(resp: &str) -> &str {
    resp.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn run(cfg: &str, first: SocketAddr) -> (NamedTempFile, common::Alcyon) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(first));
    (f, child)
}

const DEFS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

#[test]
fn accept_proxy_applies_to_its_own_bind_only() {
    let (plain, pp) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "{DEFS}frontend fe\n  bind {plain}\n  bind {pp} accept-proxy\n\
         \x20 http-request return status 200 content-type text/plain lf-string \"src=%[src]\"\n"
    );
    let (_f, mut child) = run(&cfg, plain);
    assert!(common::wait_listening(pp));
    let a = exchange(plain, "");
    let b = exchange(pp, &format!("PROXY TCP4 10.9.8.7 127.0.0.1 54321 {}\r\n", pp.port()));
    common::stop(&mut child);
    assert_eq!(body(&a), "src=127.0.0.1", "{a}");
    assert_eq!(body(&b), "src=10.9.8.7", "{b}");
}

#[test]
fn accept_proxy_bind_first_and_listen_section() {
    let (pp, plain) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "{DEFS}listen li\n  bind {pp} accept-proxy\n  bind {plain}\n\
         \x20 http-request return status 200 content-type text/plain lf-string \"src=%[src]\"\n"
    );
    let (_f, mut child) = run(&cfg, plain);
    assert!(common::wait_listening(pp));
    let a = exchange(plain, "");
    let b = exchange(pp, &format!("PROXY TCP4 10.9.8.7 127.0.0.1 54321 {}\r\n", pp.port()));
    common::stop(&mut child);
    assert_eq!(body(&a), "src=127.0.0.1", "{a}");
    assert_eq!(body(&b), "src=10.9.8.7", "{b}");
}

#[test]
fn return_string_is_literal_lf_string_is_expanded() {
    let (a, b) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "{DEFS}frontend fe\n  bind {a}\n\
         \x20 http-request return status 200 content-type text/plain string \"lit=%[src]\"\n\
         frontend fe2\n  bind {b}\n\
         \x20 http-request return status 200 content-type text/plain lf-string \"lf=%[src]\"\n"
    );
    let (_f, mut child) = run(&cfg, a);
    assert!(common::wait_listening(b));
    let (ra, rb) = (exchange(a, ""), exchange(b, ""));
    common::stop(&mut child);
    assert_eq!(body(&ra), "lit=%[src]", "{ra}");
    assert_eq!(body(&rb), "lf=127.0.0.1", "{rb}");
}
