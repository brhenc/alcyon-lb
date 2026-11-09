// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `tcp-request content capture`, and the capture slots of a `listen` section that another
//! frontend uses as its backend: the slots of a stream are its frontend's, so the rule of
//! the `listen` must neither take slot 0 of the frontend nor write past it.
//!
//! Expected values measured on the reference binary (HAProxy 3.5-dev8) with the same
//! configuration (`reg-tests/http-rules/capture_len_listen_as_backend.vtc`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// Starts `cfg`, in which `{a}`..`{e}` are replaced by reserved addresses.
fn start(cfg: &str) -> (Alcyon, Vec<SocketAddr>) {
    let addrs: Vec<SocketAddr> = (0..5).map(|_| common::reserve_addr()).collect();
    let mut text = cfg.to_string();
    for (n, a) in ["{a}", "{b}", "{c}", "{d}", "{e}"].iter().zip(&addrs) {
        text = text.replace(n, &a.to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon { child, _cfg: f };
    for a in &addrs[..3] {
        assert!(common::wait_listening(*a), "alcyon never listened on {a} with:\n{text}");
    }
    (alcyon, addrs)
}

/// The `cap0` header of the answer to a request with the `extra` header lines.
fn cap0(addr: SocketAddr, extra: &str) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let req = format!("GET / HTTP/1.1\r\nHost: h\r\n{extra}Connection: close\r\n\r\n");
    c.write_all(req.as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    text.split("\r\n")
        .find_map(|l| l.strip_prefix("cap0: "))
        // An empty value sets no header: the vtc calls that `<undef>`.
        .map_or_else(|| if text.starts_with("HTTP/1.1 200") { "<undef>".to_string() } else { format!("no answer in {text:?}") }, str::to_string)
}

fn config(rule: &str) -> String {
    format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend fe_nocap\n  bind {{a}}\n  use_backend lst\n\
         frontend fe_cap\n  bind {{b}}\n  capture request header x-a len 1\n  use_backend lst\n\
         listen lst\n  bind {{c}}\n  tcp-request inspect-delay 1s\n  {rule}\n  \
         http-request return status 200 hdr cap0 \"%[capture.req.hdr(0)]\"\n"
    )
}

fn check_all(rule: &str) {
    let (_alcyon, a) = start(&config(rule));
    let direct = cap0(a[2], "x-b: hello\r\n");
    assert_eq!(direct, "hello", "the listen reached directly captures");
    let nocap = cap0(a[0], "x-b: hello\r\n");
    assert_eq!(nocap, "<undef>", "a frontend without a slot: the rule is ignored");
    let withcap = cap0(a[1], "x-a: A\r\nx-b: hello\r\n");
    assert_eq!(withcap, "A", "slot 0 stays the frontend's header capture");
}

#[test]
fn an_http_request_capture_of_a_listen_used_as_backend_leaves_the_frontend_slot() {
    check_all("http-request capture req.hdr(x-b) len 40");
}

#[test]
fn a_tcp_request_content_capture_fills_a_slot_and_leaves_the_frontend_slot() {
    check_all("tcp-request content capture req.hdr(x-b) len 40");
}

/// `alcyon -c -f` on `cfg`: whether it was accepted, and what it said.
fn check(cfg: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("run alcyon -c");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// The forms of `tcp-request content capture` `HAProxy` refuses (measured with `haproxy -c`),
/// by the text of its message.
#[test]
fn the_tcp_request_content_capture_forms_haproxy_refuses_are_refused() {
    let d = "defaults\n  mode http\n";
    for (body, msg) in [
        ("frontend f\n  bind 127.0.0.1:1\n  tcp-request content capture req.hdr(x)\n", "a positive 'len' argument is mandatory"),
        ("frontend f\n  bind 127.0.0.1:1\n  tcp-request content capture req.hdr(x) len 0\n", "length must be > 0"),
        ("frontend f\n  bind 127.0.0.1:1\n  tcp-request content capture req.hdr(x) len\n", "length must be > 0"),
        ("frontend f\n  bind 127.0.0.1:1\n  tcp-request content capture req.hdr(x) id 0\n", "a positive 'len' argument is mandatory"),
        ("frontend f\n  bind 127.0.0.1:1\n  tcp-request content capture\n", "missing fetch method"),
        ("frontend f\n  bind 127.0.0.1:1\n  tcp-request content capture req.hdr(x) len 5 foo\n", "only accepts 'if' or 'unless'"),
        ("backend b\n  tcp-request content capture req.hdr(x) len 5\n", "proxy 'b' has no frontend capability"),
    ] {
        let (ok, out) = check(&format!("{d}{body}"));
        assert!(!ok && out.contains(msg), "{body:?} must be refused with {msg:?}, got ok={ok}: {out}");
    }
    let (ok, out) = check(&format!("{d}frontend f\n  bind 127.0.0.1:1\n  tcp-request content capture req.hdr(x) len 5 if TRUE\n"));
    assert!(ok, "a valid rule is accepted: {out}");
}
