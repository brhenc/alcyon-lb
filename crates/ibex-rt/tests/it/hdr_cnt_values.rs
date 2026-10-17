// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T327: hdr_cnt counts values

use crate::common;

use std::collections::HashMap;
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

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
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

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

/// A server on a free port that reads each request head, answers `resp` and closes the connection.
fn backend(resp: &'static [u8]) -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut b) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&b[..n]),
                }
            }
            let _ = c.write_all(resp);
        }
    });
    addr
}

/// The body of the answer to `req` (what follows the first empty line).
fn body(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    s.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_else(|| panic!("no answer: {s:?}"))
}

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
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
  http-request return status 200 content-type text/plain lf-string "[%[req.hdr_cnt(x-foo)]|%[hdr_cnt(x-foo)]|%[req.fhdr_cnt(x-foo)]|%[req.hdr_cnt(x-l)]|%[req.hdr_cnt]|%[req.fhdr_cnt]]"
"#;

    let a = common::reserve_addr();
    let (ibex, _sock) = start("hdr_cnt_values", &CFG.replace("{A}", &a.to_string()), &[a]);
    let addr = a;

    // Test case 1: Multiple headers with comma-separated values
    let req1 = b"GET /a/b.html?x=1&y=%41b&x=2 HTTP/1.1\r\nHost: a\r\nX-Foo: 1\r\nX-Foo: 2, 3\r\nCookie: a=1; b=2\r\nCookie: a=3\r\nX-L: a, b\r\nUser-Agent: Mozilla/5.0 (X11)\r\nConnection: close\r\n\r\n";
    let body1 = body(addr, req1);
    // Expected: [3|3|2|2|9|7]
    // req.hdr_cnt(x-foo)=3 (1 from "1", 2 from "2, 3")
    // hdr_cnt(x-foo)=3 (same)
    // req.fhdr_cnt(x-foo)=2 (two header lines)
    // req.hdr_cnt(x-l)=2 (a, b from "a, b")
    // req.hdr_cnt=9 (X-Foo:1, X-Foo:2, X-Foo:3, Cookie:a=1; b=2, Cookie:a=3, X-L:a, X-L:b, User-Agent:Mozilla/5.0 (X11), Connection:close)
    // Wait, let me count: X-Foo has 3 values, Cookie has 2 values, X-L has 2 values, User-Agent has 1, Connection has 1 = 9
    // fhdr_cnt=7 (X-Foo:1, X-Foo:2,3, Cookie:a=1;b=2, Cookie:a=3, X-L:a,b, User-Agent:..., Connection:close)
    assert_eq!(body1, "[3|3|2|2|9|7]", "body={body1:?}");

    // Test case 2: Simple request with no custom headers
    let req2 = b"POST http://Example.com:8080/p;m?q HTTP/1.0\r\nHost: example.com:8080\r\nContent-Length: 3\r\n\r\nabc";
    let body2 = body(addr, req2);
    // Expected: [0|0|0|0|2|2]
    // req.hdr_cnt(x-foo)=0, hdr_cnt(x-foo)=0, req.fhdr_cnt(x-foo)=0, req.hdr_cnt(x-l)=0
    // req.hdr_cnt=2 (Host, Content-Length - Connection not counted)
    // req.fhdr_cnt=2
    assert_eq!(body2, "[0|0|0|0|2|2]", "body={body2:?}");
}
