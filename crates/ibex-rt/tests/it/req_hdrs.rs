// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T302: req.hdrs fetch

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

#[test]
fn test_req_hdrs() {
    let a = common::reserve_addr();
    let (ibex, sock) = start("req-hdrs", &http_cfg("", &format!(
        "frontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"[%[req.hdrs]]\"\n"
    )), &[a]);
    let _ = &ibex;

    // Test 1: Host: a, X-Foo: Bar, Connection: close → [host: a\r\nx-foo: Bar\r\n\r\n]
    let resp = get(a, b"GET / HTTP/1.1\r\nHost: a\r\nX-Foo: Bar\r\nConnection: close\r\n\r\n");
    let body = std::str::from_utf8(&resp).unwrap();
    let body = body.splitn(2, "\r\n\r\n").nth(1).unwrap();
    assert_eq!(body, "[host: a\r\nx-foo: Bar\r\n\r\n]", "test 1 body mismatch");

    // Test 2: repeated headers + Connection
    let resp = get(a, b"GET / HTTP/1.1\r\nHost: a\r\nX-A: 1\r\nx-a: 2\r\nUser-Agent: T/1\r\nConnection: keep-alive, close\r\n\r\n");
    let body = std::str::from_utf8(&resp).unwrap();
    let body = body.splitn(2, "\r\n\r\n").nth(1).unwrap();
    assert_eq!(body, "[host: a\r\nx-a: 1\r\nx-a: 2\r\nuser-agent: T/1\r\n\r\n]", "test 2 body mismatch");

    // Test 3: empty and padded values
    let resp = get(a, b"GET / HTTP/1.1\r\nX-Empty:\r\nX-Sp:   padded  \r\n\r\n");
    let body = std::str::from_utf8(&resp).unwrap();
    let body = body.splitn(2, "\r\n\r\n").nth(1).unwrap();
    assert_eq!(body, "[x-empty: \r\nx-sp: padded\r\n\r\n]", "test 3 body mismatch");
}
