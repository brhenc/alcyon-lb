// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T326: the `req.hdr_names` fetch

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
fn req_hdr_names() {
    let a = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {{sock}} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\nfrontend fe\n  bind {a}\n  http-request return status 200 content-type text/plain lf-string \"[%[req.hdr_names]][%[req.hdr_names(;)]]\""
    );
    let (_alcyon, _sock) = start("req_hdr_names", &cfg, &[a]);
    let req1 = b"GET / HTTP/1.1\r\nHost: a\r\nX-Foo: 1\r\nx-foo: 2\r\nUser-Agent: T\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, req1), "[host,x-foo,x-foo,user-agent][host;x-foo;x-foo;user-agent]");
    let req2 = b"GET / HTTP/1.0\r\n\r\n";
    assert_eq!(body(a, req2), "[][]");
    let req3 = b"GET / HTTP/1.1\r\nHost: a\r\nA-B: c, d\r\nConnection: close\r\n\r\n";
    assert_eq!(body(a, req3), "[host,a-b][host;a-b]");
    // The H1 parser takes `close` and `keep-alive` out of a Connection value and drops the
    // header when nothing is left; `h2c`/`h2` out of Upgrade; and, in a request, an Upgrade
    // without `Connection: upgrade` and an `upgrade` token without an Upgrade header
    // (measured on HAProxy 3.5-dev8; the trailing `Connection: close` goes too).
    for (hdrs, want) in [
        ("Connection: upgrade\r\nUpgrade: foo", "[host,connection,upgrade]"),
        ("Connection: close, x-y\r\nX-Y: 1", "[host,connection,x-y]"),
        ("Connection: x-y, upgrade\r\nX-Y: 1", "[host,connection,x-y]"),
        ("Connection: upgrade\r\nUpgrade: h2c", "[host]"),
        ("Connection: upgrade\r\nUpgrade: h2c, foo", "[host,connection,upgrade]"),
        ("Upgrade: websocket", "[host]"),
        ("Connection: upgrade", "[host]"),
        ("Connection: Keep-Alive, Close", "[host]"),
        ("Connection: ,  , close", "[host,connection]"),
    ] {
        let req = format!("GET / HTTP/1.1\r\nHost: a\r\n{hdrs}\r\nConnection: close\r\n\r\n");
        let got = body(a, req.as_bytes());
        assert_eq!(got.split(']').next().map(|s| format!("{s}]")), Some(want.to_string()), "for {hdrs:?}: {got}");
    }
}
