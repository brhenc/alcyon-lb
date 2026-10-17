// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T331: `fc_rcvd_proxy` is true only on a connection that carried a PROXY header
//! (`CO_FL_RCVD_PROXY`, connection.c), whatever its kind: v1, v1 UNKNOWN, v2 LOCAL.
//! Every expected body below was measured on `HAProxy` 3.5-dev8 with this configuration.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// `{A}` binds with `accept-proxy`, `{B}` without. `/e` goes to a backend with no server,
/// so the 503 comes from `proxy_error_response` and its `http-error` lf-string.
const CFG: &str = "global
  nbthread 1
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind {A} accept-proxy
  bind {B}
  http-request return status 200 content-type text/plain lf-string \"%[fc_rcvd_proxy]|%[src]|%[fc_rcvd_proxy,not]\" if !{ path /e }
  use_backend nosrv
backend nosrv
  http-error status 503 content-type text/plain lf-string \"e%[fc_rcvd_proxy]\"
";

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
const GET_E: &[u8] = b"GET /e HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
const V1: &[u8] = b"PROXY TCP4 192.0.2.1 192.0.2.2 1111 80\r\n";
/// A PROXY v2 header: signature, version 2 + LOCAL, family UNSPEC, no address block.
const V2_LOCAL: &[u8] = b"\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00";

/// The body of the answer to `pre` followed by `req` on a new connection.
fn body(addr: SocketAddr, pre: &[u8], req: &[u8]) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(&[pre, req].concat()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let s = String::from_utf8_lossy(&out).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

#[test]
fn fc_rcvd_proxy_fetch() {
    let (a, b) = (common::reserve_addr(), common::reserve_addr());
    let dir = std::env::temp_dir().join(format!("fc-rcvd-proxy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(&path, CFG.replace("{A}", &a.to_string()).replace("{B}", &b.to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = common::Ibex(child);
    assert!(common::wait_listening(a) && common::wait_listening(b), "ibex did not listen");

    let rows = [
        ("v1 TCP4", a, V1, GET, "1|192.0.2.1|0"),
        ("v1 UNKNOWN", a, &b"PROXY UNKNOWN\r\n"[..], GET, "1|127.0.0.1|0"),
        ("v2 LOCAL", a, V2_LOCAL, GET, "1|127.0.0.1|0"),
        ("bind without accept-proxy", b, &b""[..], GET, "0|127.0.0.1|1"),
        ("http-error lf-string after a PROXY header", a, V1, GET_E, "e1"),
        ("http-error lf-string without one", b, &b""[..], GET_E, "e0"),
    ];
    let got: Vec<_> = rows.iter().map(|(n, addr, pre, req, _)| (*n, body(*addr, pre, req))).collect();
    let want: Vec<_> = rows.iter().map(|(n, .., w)| (*n, (*w).to_string())).collect();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(got, want);
}
