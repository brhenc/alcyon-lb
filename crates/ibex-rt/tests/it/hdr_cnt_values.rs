// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T327: `req.hdr_cnt` counts values, `req.fhdr_cnt` lines, on the headers as the H1 parser
//! leaves them.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts ibex on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Ibex, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (ibex, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map_or_else(|| panic!("no answer: {s:?}"), |(_, b)| b.to_string())
}

#[test]
fn hdr_cnt_values() {
    const CFG: &str = r#"
global
  stats socket {sock} level admin
defaults
  mode http
  timeout connect 1s
  timeout client 5s
  timeout server 5s
frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "[%[req.hdr_cnt(x-foo)]|%[hdr_cnt(x-foo)]|%[req.fhdr_cnt(x-foo)]|%[req.hdr_cnt(x-l)]|%[req.hdr_cnt]|%[req.fhdr_cnt]|%[req.hdr_cnt(connection)]|%[req.fhdr_cnt(connection)]|%[req.hdr_cnt(upgrade)]]"
"#;

    let a = common::reserve_addr();
    let (_ibex, _sock) = start("hdr_cnt_values", &CFG.replace("{A}", &a.to_string()), &[a]);

    // Each row: the request, and the answer HAProxy 3.5-dev8 gives for it.
    let rows: &[(&[u8], &str)] = &[
        // 9 = Host 1 + X-Foo 1+2 + Cookie 1+1 + X-L 2 + User-Agent 1, on 7 lines: the H1
        // parser removes `Connection: close` (h1_parse_connection_header).
        (
            b"GET /a/b.html?x=1&y=%41b&x=2 HTTP/1.1\r\nHost: a\r\nX-Foo: 1\r\nX-Foo: 2, 3\r\nCookie: a=1; b=2\r\nCookie: a=3\r\nX-L: a, b\r\nUser-Agent: Mozilla/5.0 (X11)\r\nConnection: close\r\n\r\n",
            "[3|3|2|2|9|7|0|0|0]",
        ),
        // Host and Content-Length.
        (b"POST http://Example.com:8080/p;m?q HTTP/1.0\r\nHost: example.com:8080\r\nContent-Length: 3\r\n\r\nabc", "[0|0|0|0|2|2|0|0|0]"),
        // A comma inside a quoted string does not separate values (http_find_hdr_value_end).
        (b"GET / HTTP/1.1\r\nHost: a\r\nX-Foo: \"a,b\", c\r\nConnection: close\r\n\r\n", "[2|2|1|0|3|2|0|0|0]"),
        // Nor does one after a backslash-escaped quote inside the quoted string.
        (b"GET / HTTP/1.1\r\nHost: a\r\nX-Foo: \"a\\\",b\" , c\r\nConnection: close\r\n\r\n", "[2|2|1|0|3|2|0|0|0]"),
        // WebSocket: `Connection: Upgrade` stays and counts.
        (
            b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            "[0|0|0|0|5|5|1|1|1]",
        ),
        // Only `close` is removed from the Connection line; `x-foo` stays.
        (b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close, x-foo\r\nX-Foo: 1\r\n\r\n", "[1|1|1|0|3|3|1|1|0]"),
        // Two Connection lines left empty are both removed.
        (b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n", "[0|0|0|0|1|1|0|0|0]"),
        // h2c is dropped from Upgrade, which leaves it empty; then `upgrade` is dropped from
        // Connection because no Upgrade header is left.
        (
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
            "[0|0|0|0|3|3|1|1|0]",
        ),
        // Upgrade without `Connection: upgrade` is removed.
        (b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n", "[0|0|0|0|1|1|0|0|0]"),
        // Empty values count; after `close` is cut out, the rewrite keeps the empty ones too
        // (Connection "x,,y, close,,z" becomes "x,,y,,z": 5 values).
        (b"GET / HTTP/1.1\r\nHost: a\r\nConnection: x,,y, close,,z\r\nX-Foo: a,,b,\r\nX-Foo:\r\n\r\n", "[5|5|2|0|11|4|5|1|0]"),
    ];
    let mut bad = Vec::new();
    for (i, (req, want)) in rows.iter().enumerate() {
        let got = body(a, req);
        if got != *want {
            bad.push(format!("row {i}: got {got}, want {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
