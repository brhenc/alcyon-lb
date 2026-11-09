// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T327: urlp raw value

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Alcyon, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "alcyon did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (alcyon, sock)
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
fn urlp_raw() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"[%[urlp(y)]|%[url_param(y)]|%[urlp(y),url_dec]|%[urlp(z)]]\""
    );
    let (_alcyon, _sock) = start("urlp_raw", &cfg, &[a]);
    // Row 1
    let req1 = b"GET /a/b.html?x=1&y=%41b&x=2 HTTP/1.1\r\nHost: a\r\nX-Foo: 1\r\nX-Foo: 2, 3\r\nCookie: a=1; b=2\r\nCookie: a=3\r\nX-L: a, b\r\nUser-Agent: Mozilla/5.0 (X11)\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, req1), "[%41b|%41b|Ab|]");
    // Row 2
    let req2 = b"GET /?z=a%20b+c&y=%2F HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, req2), "[%2F|%2F|/|a%20b+c]");
    // Row 3
    let req3 = b"GET /?y=%zz HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, req3), "[%zz|%zz||]");
}

/// Review U1: `urlp_val` is `strl2ic` over the raw value (no percent-decoding, stops at the
/// first non-digit, wraps as a C int), and a parameter matches only as `name=`, so a bare
/// `n` is not found. Values measured on `HAProxy` 3.5-dev8.
#[test]
fn urlp_val_raw() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"found:%[urlp(n)]:%[urlp_val(n)]\" if {{ urlp(n) -m found }}\n  http-request return status 200 content-type text/plain lf-string \"none\"\n"
    );
    let (_alcyon, _sock) = start("urlp_val_raw", &cfg, &[a]);
    for (q, want) in [
        ("n=%31", "found:%31:0"),
        ("n=%2D5", "found:%2D5:0"),
        ("n=%2B3", "found:%2B3:0"),
        ("n=12abc", "found:12abc:12"),
        ("n=", "found::0"),
        ("n=99999999999", "found:99999999999:1215752191"),
        ("n=-99999999999", "found:-99999999999:-1215752191"),
        ("n=-12", "found:-12:-12"),
        ("n=+3", "found:+3:0"),
        ("n=-", "found:-:0"),
        ("n", "none"),
        ("n&n=5", "found:5:5"),
        ("nn=3&n=4", "found:4:4"),
    ] {
        let req = format!("GET /?{q} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        assert_eq!(body(a, req.as_bytes()), want, "?{q}");
    }
}
