// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `set-src`/`set-dst` at connection, session and content level, and `fc_src` versus
//! `src` (reg-test connection/cli_src_dst.vtc, run on `HAProxy` 3.5-dev11 where it
//! passes).
//!
//! In `HAProxy` `fc_src`/`fc_dst` are the client *connection's* addresses and
//! `src`/`dst` are the *stream's*: `set-src`/`set-dst` change whichever level the rule
//! that runs them owns (connection, session, or stream), and a stream inherits the
//! session value, which inherits the connection value. So a `tcp-request connection
//! set-src ipv4(10.0.0.1)` shows up in every level's `src` until a session or stream
//! rule sets its own, while `fc_src` only moves with the connection-level rule. A
//! `PROXY` header received on an `accept-proxy` bind becomes the stream's value,
//! under the connection-level one.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

/// One plain request on a fresh connection.
fn get(addr: SocketAddr, extra: &[(&str, &str)]) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut req = format!("GET / HTTP/1.1\r\nHost: x\r\n");
    for (n, v) in extra {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let _ = s.write_all(req.as_bytes());
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out.to_ascii_lowercase()
}

/// One request on a connection that is kept: `extra` is empty, plus the optional
/// last-request marker. Reads exactly one response (the body is empty, so the
/// headers end at the first blank line).
fn keep_get(s: &mut TcpStream, extra: &[(&str, &str)], close: bool) -> String {
    let mut req = format!("GET / HTTP/1.1\r\nHost: x\r\n");
    for (n, v) in extra {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    if close {
        req.push_str("Connection: close\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).expect("write");
    let mut out = String::new();
    let mut buf = [0u8; 4096];
    while !out.contains("\r\n\r\n") {
        let n = s.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        out.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    out.to_ascii_lowercase()
}

#[test]
fn multi_level_set_src_dst_fc_vs_src() {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let addrs: Vec<SocketAddr> = (0..6).map(|_| common::reserve_addr()).collect();
    let (fe1, fe2, fe3, fe4, li1, li3) = (addrs[0], addrs[1], addrs[2], addrs[3], addrs[4], addrs[5]);
    // The eight headers each frontend echoes: session-level values first (captured by
    // `tcp-request session` rules, before any stream exists), then the stream-level
    // ones (captured by the `tcp-request content` rules after `inspect-delay`).
    let echo = "\x20 http-after-response set-header sess-fc-src \"%[var(sess.sess_fc_src)]\"\n\
                \x20 http-after-response set-header sess-src \"%[var(sess.sess_src)]\"\n\
                \x20 http-after-response set-header sess-fc-dst \"%[var(sess.sess_fc_dst)]\"\n\
                \x20 http-after-response set-header sess-dst \"%[var(sess.sess_dst)]\"\n\
                \x20 http-after-response set-header strm-fc-src \"%[var(txn.strm_fc_src)]\"\n\
                \x20 http-after-response set-header strm-src \"%[var(txn.strm_src)]\"\n\
                \x20 http-after-response set-header strm-fc-dst \"%[var(txn.strm_fc_dst)]\"\n\
                \x20 http-after-response set-header strm-dst \"%[var(txn.strm_dst)]\"\n";
    let sess_capture = "\x20 tcp-request session set-var(sess.sess_fc_src) fc_src\n\
                        \x20 tcp-request session set-var(sess.sess_fc_dst) fc_dst\n\
                        \x20 tcp-request session set-var(sess.sess_src) src\n\
                        \x20 tcp-request session set-var(sess.sess_dst) dst\n";
    let content_capture = "\x20 tcp-request inspect-delay 100ms\n\
                           \x20 tcp-request content set-var(txn.strm_fc_src) fc_src\n\
                           \x20 tcp-request content set-var(txn.strm_fc_dst) fc_dst\n\
                           \x20 tcp-request content set-var(txn.strm_src) src\n\
                           \x20 tcp-request content set-var(txn.strm_dst) dst\n";
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe1\n  bind {fe1}\n  tcp-request connection set-src ipv4(10.0.0.1)\n\
         \x20 tcp-request connection set-dst ipv4(10.0.0.2)\n{sess_capture}{content_capture}{echo}\
         \x20 default_backend be\n\
         frontend fe2\n  bind {fe2}\n  tcp-request connection set-src ipv4(10.0.0.1)\n\
         \x20 tcp-request connection set-dst ipv4(10.0.0.2)\n\
         \x20 tcp-request session set-src ipv4(10.1.0.1)\n\
         \x20 tcp-request session set-dst ipv4(10.1.0.2)\n{sess_capture}{content_capture}{echo}\
         \x20 default_backend be\n\
         frontend fe3\n  bind {fe3}\n  tcp-request connection set-src ipv4(10.0.0.1)\n\
         \x20 tcp-request connection set-dst ipv4(10.0.0.2)\n\
         \x20 tcp-request session set-src ipv4(10.1.0.1)\n\
         \x20 tcp-request session set-dst ipv4(10.1.0.2)\n{sess_capture}\n\
         \x20 tcp-request inspect-delay 100ms\n\
         \x20 tcp-request content set-src ipv4(10.2.0.1)\n\
         \x20 tcp-request content set-dst ipv4(10.2.0.2)\n\
         \x20 tcp-request content set-var(txn.strm_fc_src) fc_src\n\
         \x20 tcp-request content set-var(txn.strm_fc_dst) fc_dst\n\
         \x20 tcp-request content set-var(txn.strm_src) src\n\
         \x20 tcp-request content set-var(txn.strm_dst) dst\n{echo}\
         \x20 default_backend be\n\
         frontend fe4\n  bind {fe4}\n  tcp-request connection set-src ipv4(10.0.0.1)\n\
         \x20 tcp-request connection set-dst ipv4(10.0.0.2)\n{sess_capture}\n\
         \x20 http-request set-src hdr(x-forwarded-for)\n\
         \x20 http-request set-dst hdr(x-original-to)\n\
         \x20 http-request set-var(txn.strm_fc_src) fc_src\n\
         \x20 http-request set-var(txn.strm_fc_dst) fc_dst\n\
         \x20 http-request set-var(txn.strm_src) src\n\
         \x20 http-request set-var(txn.strm_dst) dst\n{echo}\
         \x20 default_backend be\n\
         backend be\n  http-request return status 200\n\
         listen li1\n  bind {li1}\n  tcp-request connection set-src ipv4(10.0.0.1)\n\
         \x20 tcp-request connection set-dst ipv4(10.0.0.2)\n\
         \x20 http-request set-src ipv4(192.168.0.1)\n\
         \x20 http-request set-dst ipv4(192.168.0.2)\n\
         \x20 http-after-response set-header li1-fc-src \"%[fc_src]\"\n\
         \x20 http-after-response set-header li1-src \"%[src]\"\n\
         \x20 http-after-response set-header li1-fc-dst \"%[fc_dst]\"\n\
         \x20 http-after-response set-header li1-dst \"%[dst]\"\n\
         \x20 server srv {li3} send-proxy\n\
         listen li3\n  bind {li3} accept-proxy\n  tcp-request connection set-src ipv4(10.1.0.1)\n\
         \x20 tcp-request connection set-dst ipv4(10.1.0.2)\n\
         \x20 http-after-response set-header li3-fc-src \"%[fc_src]\"\n\
         \x20 http-after-response set-header li3-src \"%[src]\"\n\
         \x20 http-after-response set-header li3-fc-dst \"%[fc_dst]\"\n\
         \x20 http-after-response set-header li3-dst \"%[dst]\"\n\
         \x20 http-request return status 200\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(&bin)
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    for a in &addrs {
        assert!(common::wait_listening(*a), "not listening on {a}");
    }

    // fe1: only a connection-level set; the stream inherits it, so every read of
    // `src`/`dst` at any level is the set value, as is `fc_src`/`fc_dst`.
    let r1 = get(fe1, &[]);
    for h in ["sess-fc-src: 10.0.0.1", "sess-src: 10.0.0.1", "strm-fc-src: 10.0.0.1", "strm-src: 10.0.0.1",
              "sess-fc-dst: 10.0.0.2", "sess-dst: 10.0.0.2", "strm-fc-dst: 10.0.0.2", "strm-dst: 10.0.0.2"] {
        assert!(r1.contains(&format!("{h}\r\n")), "fe1 missing {h}:\n{r1}");
    }

    // fe2: a session-level set moves the stream's value at every level, `fc_*` stays.
    let r2 = get(fe2, &[]);
    for h in ["sess-fc-src: 10.0.0.1", "sess-src: 10.1.0.1", "strm-fc-src: 10.0.0.1", "strm-src: 10.1.0.1",
              "sess-fc-dst: 10.0.0.2", "sess-dst: 10.1.0.2", "strm-fc-dst: 10.0.0.2", "strm-dst: 10.1.0.2"] {
        assert!(r2.contains(&format!("{h}\r\n")), "fe2 missing {h}:\n{r2}");
    }

    // fe3: a stream-level set moves the stream's value only.
    let r3 = get(fe3, &[]);
    for h in ["sess-fc-src: 10.0.0.1", "sess-src: 10.1.0.1", "strm-fc-src: 10.0.0.1", "strm-src: 10.2.0.1",
              "sess-fc-dst: 10.0.0.2", "sess-dst: 10.1.0.2", "strm-fc-dst: 10.0.0.2", "strm-dst: 10.2.0.2"] {
        assert!(r3.contains(&format!("{h}\r\n")), "fe3 missing {h}:\n{r3}");
    }

    // fe4: `http-request set-src` is a stream-level set; on a kept connection each
    // request re-reads the lower levels, and a set whose sample is missing is a no-op.
    let mut k = TcpStream::connect(fe4).expect("connect");
    k.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let k1 = keep_get(&mut k, &[("x-forwarded-for", "192.168.0.1"), ("x-original-to", "192.168.0.2")], false);
    let k2 = keep_get(&mut k, &[("x-forwarded-for", "192.168.1.1"), ("x-original-to", "192.168.1.2")], false);
    let k3 = keep_get(&mut k, &[], true);
    drop(k);
    for (r, src, dst, why) in [
        (&k1, "192.168.0.1", "192.168.0.2", "fe4 req1"),
        (&k2, "192.168.1.1", "192.168.1.2", "fe4 req2"),
        (&k3, "10.0.0.1", "10.0.0.2", "fe4 req3 (no header, set is a no-op)"),
    ] {
        for h in ["sess-fc-src: 10.0.0.1", "sess-src: 10.0.0.1", "strm-fc-src: 10.0.0.1",
                  "sess-fc-dst: 10.0.0.2", "sess-dst: 10.0.0.2", "strm-fc-dst: 10.0.0.2"] {
            assert!(r.contains(&format!("{h}\r\n")), "{why} missing {h}:\n{r}");
        }
        assert!(r.contains(&format!("strm-src: {src}\r\n")), "{why} strm-src:\n{r}");
        assert!(r.contains(&format!("strm-dst: {dst}\r\n")), "{why} strm-dst:\n{r}");
    }

    // li1 rewrites the stream's addresses and sends them in the PROXY header; li3,
    // with `accept-proxy`, takes them as the stream's, under its own connection-level set.
    let r5 = get(li1, &[]);
    for h in ["li1-fc-src: 10.0.0.1", "li1-src: 192.168.0.1", "li1-fc-dst: 10.0.0.2", "li1-dst: 192.168.0.2",
              "li3-fc-src: 10.1.0.1", "li3-src: 192.168.0.1", "li3-fc-dst: 10.1.0.2", "li3-dst: 192.168.0.2"] {
        assert!(r5.contains(&format!("{h}\r\n")), "proxy chain missing {h}:\n{r5}");
    }

    common::stop(&mut child);
}
