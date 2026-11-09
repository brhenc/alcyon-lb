// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T326: the `req.cook_names` fetch

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
fn req_cook_names_fetch() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"[%[req.cook_names]][%[req.cook_names(;)]]\""
    );
    let (_alcyon, _sock) = start("req_cook_names", &cfg, &[a]);
    let req1 = b"GET / HTTP/1.1\r\nHost: a\r\nCookie: a=1; b=2\r\nConnection: close\r\n\r\n";
    let req2 = b"GET / HTTP/1.1\r\nHost: a\r\nCookie: a=1\r\nCookie: c=3; d\r\nConnection: close\r\n\r\n";
    let req3 = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, req1), "[a,b][a;b]");
    assert_eq!(body(a, req2), "[a,c][a;c]");
    assert_eq!(body(a, req3), "[][]");
    // The names as `http_extract_next_cookie_name` finds them: a Cookie value is split on
    // `,` too, `$` attributes and pairs without `=` are skipped, quotes are honoured, and a
    // delimiter goes in only behind a non-empty output, so a leading empty name vanishes
    // while a later one keeps its slot (measured on HAProxy 3.5-dev8).
    for (cookie, want) in [
        ("$Version=1; a=1; $Path=/; b=2", "[a,b][a;b]"),
        ("a=1, b=2", "[a,b][a;b]"),
        ("=1; b=2; c=", "[b,c][b;c]"),
        ("a=1; =2; b=3", "[a,,b][a;;b]"),
        ("a=\"x;y\"; b=2", "[a,b][a;b]"),
        ("a=\"1,2\", b=3", "[a,b][a;b]"),
        ("a=1; nov; b=2", "[a,b][a;b]"),
        ("  a = 1 ;  b  =2", "[a,b][a;b]"),
        ("a=1;b", "[a][a]"),
        ("a b=1", "[a b][a b]"),
        ("x", "[][]"),
    ] {
        let req = format!("GET / HTTP/1.1\r\nHost: a\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n");
        assert_eq!(body(a, req.as_bytes()), want, "for Cookie: {cookie}");
    }
}
