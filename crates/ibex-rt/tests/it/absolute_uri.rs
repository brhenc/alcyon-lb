// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T327: `base`, `baseq`, `capture.req.uri`, `path` and `pathq` on absolute-form and other
//! request targets, as the oracle's `http_parse_path` and `smp_fetch_base` give them.

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
fn test_absolute_uri_fetches() {
    // No backend: `http-request return` answers every request.
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
  http-request return status 200 content-type text/plain lf-string "[%[base]|%[baseq]|%[capture.req.uri]|%[path]|%[url]|%[pathq]]"
"#;
    let a = common::reserve_addr();
    let (_ibex, _sock) = start("t327-absolute-uri", &CFG.replace("{A}", &a.to_string()), &[a]);

    // Each row: the request, and the answer HAProxy 3.5-dev8 gives for it.
    let rows: &[(&[u8], &str)] = &[
        // An absolute path.
        (
            b"GET /a/b.html?x=1&y=%41b&x=2 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
            "[a/a/b.html|a/a/b.html?x=1&y=%41b&x=2|/a/b.html?x=1&y=%41b&x=2|/a/b.html|/a/b.html?x=1&y=%41b&x=2|/a/b.html?x=1&y=%41b&x=2]",
        ),
        // Absolute form: the host comes from the Host header, not the authority.
        (
            b"POST http://Example.com:8080/p;m?q HTTP/1.0\r\nHost: example.com:8080\r\nContent-Length: 3\r\n\r\nabc",
            "[example.com:8080/p;m|example.com:8080/p;m?q|/p;m?q|/p;m|http://Example.com:8080/p;m?q|/p;m?q]",
        ),
        (b"GET http://h.example/ HTTP/1.1\r\nHost: H.example\r\nConnection: close\r\n\r\n", "[H.example/|H.example/|/|/|http://h.example/|/]"),
        // `*` has no path: no capture.req.uri, and base is the host alone.
        (b"OPTIONS * HTTP/1.1\r\nHost: h.example\r\nConnection: close\r\n\r\n", "[h.example|h.example|||*|]"),
        // Any scheme, in any case.
        (b"GET HTTP://h.example/x?y HTTP/1.1\r\nHost: h.example\r\nConnection: close\r\n\r\n", "[h.example/x|h.example/x?y|/x?y|/x|HTTP://h.example/x?y|/x?y]"),
        (b"GET ftp://h.example/x?y HTTP/1.1\r\nHost: h.example\r\nConnection: close\r\n\r\n", "[h.example/x|h.example/x?y|/x?y|/x|ftp://h.example/x?y|/x?y]"),
        // The path of an absolute URI with only a query is `?q=1`: base appends nothing.
        (b"GET http://h.example?q=1 HTTP/1.1\r\nHost: h.example\r\nConnection: close\r\n\r\n", "[h.example|h.example|?q=1||http://h.example?q=1|?q=1]"),
        // No Host header, or an empty one: base is what path gives, baseq what pathq gives.
        (b"GET /x?y HTTP/1.0\r\n\r\n", "[/x|/x?y|/x?y|/x|/x?y|/x?y]"),
        (b"GET /x?y HTTP/1.0\r\nHost:\r\n\r\n", "[/x|/x?y|/x?y|/x|/x?y|/x?y]"),
        (b"GET http://h.example?q=1 HTTP/1.0\r\n\r\n", "[|?q=1|?q=1||http://h.example?q=1|?q=1]"),
        // The H1 parser gives an absolute URI without a path the path `/`.
        (b"GET http://h.example HTTP/1.1\r\nHost: h.example\r\nConnection: close\r\n\r\n", "[h.example/|h.example/|/|/|http://h.example/|/]"),
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
