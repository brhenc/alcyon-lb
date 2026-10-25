// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Plain `silent-drop` is silent when the process may use `TCP_REPAIR` (T500, MY-5).
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, plain `http-request silent-drop`:
//! * unprivileged (`TCP_REPAIR` refused): h1 gets a reset at once (TTL 1); on h2c the client gets
//!   SETTINGS, its ACK and a RST_STREAM, the connection stays open;
//! * with `CAP_NET_ADMIN`: h1 gets nothing and the socket stays open; on h2c only SETTINGS and
//!   the ACK, no RST_STREAM;
//! * `silent-drop rst-ttl 7`, either way: the unprivileged behaviour.
//!
//! The privileged cases run the same test binary inside `unshare -Urn` (a user and network
//! namespace in which the process is root and owns the loopback it brings up); they are skipped,
//! saying so, where unprivileged user namespaces are not allowed.
//! `T500_ORACLE=/path/to/haproxy` runs the cases on it.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

const INNER: &str = "T500_INNER_NAMESPACE";

struct Proxy {
    child: Child,
    h1: std::net::SocketAddr,
    h2: std::net::SocketAddr,
    _cfg: NamedTempFile,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn proxy(rule: &str) -> Proxy {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let be = ls.local_addr().expect("addr");
    thread::spawn(move || {
        for s in ls.incoming().flatten() {
            drop(s);
        }
    });
    let (h1, h2) = (common::reserve_addr(), common::reserve_addr());
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\ndefaults\n    mode http\n    timeout client 5s\n    timeout server 5s\n    \
         timeout connect 1s\nfrontend f\n    bind {h1}\n    bind {h2} proto h2\n    {rule}\n    default_backend b\n\
         backend b\n    server s {be}\n"
    )
    .expect("write cfg");
    let bin = std::env::var("T500_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(h1), "proxy never listened");
    Proxy { child, h1, h2, _cfg: cfg }
}

/// Reads until the end of the stream, an error or 1.2 s of silence: the bytes and the end
/// (`None` for a FIN, `WouldBlock`/`TimedOut` for a socket left open).
fn read_all(c: &mut TcpStream) -> (Vec<u8>, Option<ErrorKind>) {
    c.set_read_timeout(Some(Duration::from_millis(1200))).expect("timeout");
    let (mut out, mut buf) = (Vec::new(), [0u8; 4096]);
    loop {
        match c.read(&mut buf) {
            Ok(0) => return (out, None),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => return (out, Some(e.kind())),
        }
    }
}

fn h1_end(p: &Proxy) -> (Vec<u8>, Option<ErrorKind>) {
    let mut c = TcpStream::connect(p.h1).expect("connect");
    c.write_all(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n").expect("send");
    read_all(&mut c)
}

/// The frame types an h2c client receives for one `GET /x`, and how the read ended.
fn h2_frames(p: &Proxy) -> (Vec<u8>, Option<ErrorKind>) {
    let mut c = TcpStream::connect(p.h2).expect("connect");
    let mut req = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    req.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    // HEADERS, END_STREAM|END_HEADERS: :method GET, :scheme http, :path /x, :authority a.
    let hb = [0x82, 0x86, 0x84, 0x41, 1, b'a'];
    req.extend_from_slice(&[0, 0, 6, 1, 5, 0, 0, 0, 1]);
    req.extend_from_slice(&hb);
    c.write_all(&req).expect("send");
    let (raw, end) = read_all(&mut c);
    let (mut types, mut i) = (Vec::new(), 0);
    while i + 9 <= raw.len() {
        types.push(raw[i + 3]);
        i += 9 + ((usize::from(raw[i]) << 16) | (usize::from(raw[i + 1]) << 8) | usize::from(raw[i + 2]));
    }
    (types, end)
}

const RST_STREAM: u8 = 3;

/// Runs `name` of this module inside `unshare -Urn`, with the loopback up. `false` when the
/// namespace cannot be made.
fn in_namespace(name: &str) -> bool {
    if !Command::new("unshare").args(["-Urn", "ip", "link", "set", "lo", "up"]).stderr(Stdio::null()).status().is_ok_and(|s| s.success()) {
        eprintln!("skipped: no unprivileged user namespace (or no unshare/ip) here");
        return false;
    }
    let exe = std::env::current_exe().expect("exe");
    let out = Command::new("unshare")
        .args(["-Urn", "sh", "-c", "ip link set lo up && exec \"$0\" --exact \"$1\" --nocapture", exe.to_str().expect("utf8"), name])
        .env(INNER, "1")
        .output()
        .expect("unshare");
    assert!(out.status.success(), "{name} in the namespace:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    true
}

fn inside() -> bool {
    std::env::var_os(INNER).is_some()
}

#[test]
fn unprivileged_plain_silent_drop_resets_h1_and_resets_the_h2_stream() {
    if inside() {
        return;
    }
    let p = proxy("http-request silent-drop");
    assert_eq!(h1_end(&p), (vec![], Some(ErrorKind::ConnectionReset)));
    let (types, end) = h2_frames(&p);
    assert_eq!((types, end.is_some_and(|e| e != ErrorKind::ConnectionReset)), (vec![4, 4, RST_STREAM], true));
}

#[test]
fn plain_silent_drop_with_tcp_repair_sends_nothing() {
    if !inside() {
        in_namespace("silent_drop_repair::plain_silent_drop_with_tcp_repair_sends_nothing");
        return;
    }
    let p = proxy("http-request silent-drop");
    let (out, end) = h1_end(&p);
    assert_eq!((out, end.is_some_and(|e| matches!(e, ErrorKind::WouldBlock | ErrorKind::TimedOut))), (vec![], true), "h1: no byte, socket left open");
    let (types, end) = h2_frames(&p);
    assert!(!types.contains(&RST_STREAM), "h2 frames {types:?}");
    assert!(end.is_some_and(|e| matches!(e, ErrorKind::WouldBlock | ErrorKind::TimedOut)), "h2 end {end:?}");
}

#[test]
fn silent_drop_rst_ttl_still_resets_with_tcp_repair_available() {
    if !inside() {
        in_namespace("silent_drop_repair::silent_drop_rst_ttl_still_resets_with_tcp_repair_available");
        return;
    }
    let p = proxy("http-request silent-drop rst-ttl 7");
    assert_eq!(h1_end(&p), (vec![], Some(ErrorKind::ConnectionReset)));
    let (types, _) = h2_frames(&p);
    assert!(types.contains(&RST_STREAM), "h2 frames {types:?}");
}
