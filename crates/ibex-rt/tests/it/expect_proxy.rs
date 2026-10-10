// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tcp-request connection expect-proxy layer4 [if|unless cond]` (T125). Measured against
//! HAProxy 3.5-dev8-885761-29 (reg-test connection/expect_proxy, and `haproxy -c`):
//!
//! * the header is expected only on connections whose rule matches; there it replaces
//!   `src`/`dst` and not `fc_src`; a missing or malformed header closes the connection;
//! * `expect-proxy` with no argument, or `layer7`: "'tcp-request connection expect-proxy'
//!   only supports 'layer4'" (`'layer7'`);
//! * `tcp-request session expect-proxy layer4`: "'expect-proxy layer4' is not allowed in
//!   'tcp-request session' rules".

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

fn talk(addr: SocketAddr, pre: &[u8], req: bool) -> String {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = pre.to_vec();
    if req {
        out.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    }
    let _ = s.write_all(&out);
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf
}

#[test]
fn expect_proxy_is_per_connection() {
    let (a, b) = (common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe1\n  bind {a}\n  tcp-request connection expect-proxy layer4 if {{ src 127.0.0.0/8 }}\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n\
         \x20 http-after-response set-header x-dst \"%[dst]:%[dst_port]\"\n\
         \x20 http-after-response set-header x-fcsrc \"%[fc_src]\"\n\
         frontend fe2\n  bind {b}\n  tcp-request connection expect-proxy layer4 if {{ src 10.0.0.0/8 }}\n\
         \x20 http-request return status 200\n\
         \x20 http-after-response set-header x-src \"%[src]:%[src_port]\"\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn");
    assert!(common::wait_listening(a));
    let r1 = talk(a, b"PROXY TCP4 192.168.0.1 10.0.0.2 1234 81\r\n", true).to_ascii_lowercase();
    let r2 = talk(a, b"", true);
    let r3 = talk(a, b"PROXY TCP4 not an address at all\r\n", false);
    let r4 = talk(b, b"", true).to_ascii_lowercase();
    common::stop(&mut child);
    assert!(r1.starts_with("http/1.1 200"), "{r1}");
    assert!(r1.contains("x-src: 192.168.0.1:1234\r\n"), "{r1}");
    assert!(r1.contains("x-dst: 10.0.0.2:81\r\n"), "{r1}");
    assert!(r1.contains("x-fcsrc: 127.0.0.1\r\n"), "{r1}");
    assert!(r2.is_empty(), "no header: closed, got {r2}");
    assert!(r3.is_empty(), "malformed header: closed, got {r3}");
    assert!(r4.starts_with("http/1.1 200"), "{r4}");
    assert!(r4.contains("x-src: 127.0.0.1:"), "{r4}");
}

fn check(rule: &str) -> (Option<i32>, String) {
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind 127.0.0.1:18081\n  {rule}\n  default_backend be\nbackend be\n  server s1 127.0.0.1:1\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("ibex -c");
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn expect_proxy_arguments_are_checked_at_load() {
    let (c, o) = check("tcp-request connection expect-proxy");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("'tcp-request connection expect-proxy' only supports 'layer4'"), "{o}");
    let (c, o) = check("tcp-request connection expect-proxy layer7");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("only supports 'layer4'"), "{o}");
    let (c, o) = check("tcp-request session expect-proxy layer4");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("'expect-proxy layer4' is not allowed in 'tcp-request session' rules"), "{o}");
    // HAProxy: "only accepts 'if' or 'unless'" (got 'foo').
    let (c, o) = check("tcp-request connection expect-proxy layer4 foo");
    assert_ne!(c, Some(0), "{o}");
    assert!(o.contains("only accepts 'if' or 'unless'"), "{o}");
    let (c, o) = check("tcp-request connection expect-proxy layer4 if { src 10.0.0.0/8 }");
    assert_eq!(c, Some(0), "{o}");
}
