// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T326: url32 fetches

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
fn url32_fetches() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"[%[url32]][%[url32+src,hex]]\""
    );
    let (_ibex, _sock) = start("url32", &cfg, &[a]);
    // Test cases from the issue
    let req1 = b"GET /p?q=1 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    let req2 = b"GET http://example.com/x?y HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let req3 = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, req1), "[526637239][1F63D8B77F000001]");
    assert_eq!(body(a, req2), "[255589819][0F3BFDBB7F000001]");
    assert_eq!(body(a, req3), "[877786378][3451F50A7F000001]");
    // Review F1/F2 (values measured on HAProxy 3.5-dev8): the raw path tail is hashed as sent,
    // trailing '?' included, after any RFC 3986 scheme and the authority (which ends at '/', '?'
    // or '#'); a tail that does not start with '/' is not hashed; an empty path is "/" except
    // for OPTIONS (http_scheme_based_normalize).
    let cases: &[(&str, &str, &str)] = &[
        ("GET /p? HTTP/1.1", "a", "[4174073112][F8CB4D187F000001]"),
        ("GET http://a/p? HTTP/1.1", "a", "[4174073112][F8CB4D187F000001]"),
        ("GET http://a/? HTTP/1.1", "a", "[1034210362][3DA4CC3A7F000001]"),
        ("GET http://a?x HTTP/1.1", "a", "[1830748055][6D1EFF977F000001]"),
        ("GET https://a HTTP/1.1", "a", "[877786378][3451F50A7F000001]"),
        ("OPTIONS https://a HTTP/1.1", "a", "[1830748055][6D1EFF977F000001]"),
        ("OPTIONS https://a?q HTTP/1.1", "a", "[1830748055][6D1EFF977F000001]"),
        ("OPTIONS * HTTP/1.1", "a", "[1830748055][6D1EFF977F000001]"),
        ("GET HTTP://example.com/x?y HTTP/1.1", "example.com", "[255589819][0F3BFDBB7F000001]"),
        ("GET ftp://example.com/x?y HTTP/1.1", "example.com", "[255589819][0F3BFDBB7F000001]"),
        ("GET a1+.b://a/y HTTP/1.1", "a", "[2193154996][82B8E3B47F000001]"),
        ("GET /x://y HTTP/1.1", "a", "[2182710902][821986767F000001]"),
    ];
    for (line, host, want) in cases {
        let req = format!("{line}\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        assert_eq!(body(a, req.as_bytes()), *want, "{line}");
    }
    assert_eq!(body(a, b"GET /x HTTP/1.0\r\n\r\n"), "[2340802059][8B85CE0B7F000001]", "no Host");
}
