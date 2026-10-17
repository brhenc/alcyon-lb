// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T329: req.hdrs_bin fetch

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

#[test]
fn req_hdrs_bin_basic() {
    let addr = common::reserve_addr();
    let be = backend(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let cfg = http_cfg(
        "",
        &format!(
            r#"frontend fe
  bind {A}
  http-request return status 200 content-type text/plain lf-string "[%[req.hdrs_bin,hex]]"
  default_backend be
backend be
  server s1 {be}"#,
            A = addr,
        ),
    );
    let (_ibex, _sock) = start("req_hdrs_bin_basic", &cfg, &[addr]);
    let a = addr;

    // Test 1: single header Host: a
    assert_eq!(
        body(a, b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"),
        "[04686F737401610000]"
    );

    // Test 2: multiple headers including duplicates
    assert_eq!(
        body(a, b"GET / HTTP/1.1\r\nHost: a\r\nX-A: 1\r\nx-a: 2\r\nConnection: close\r\n\r\n"),
        "[04686F7374016103782D61013103782D6101320000]"
    );

    // Test 3: long header value
    let long_val = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu";
    assert_eq!(
        body(a, format!("GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n", long_val).as_bytes()),
        format!("[04686F737401610A757365722D6167656E7482{}0000]", hex_encode(long_val.as_bytes()))
    );
}

fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        use std::fmt::Write;
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Lengths of 240 and more take `HAProxy`'s varint (`include/haproxy/intops.h`), and the
/// `Connection` / `Upgrade` headers are what `HAProxy`'s H1 parser leaves of them
/// (`h1_parse_connection_header`, `h1_parse_upgrade_header`, `h1_postparse_req_hdrs`).
/// Every expected value was measured on `HAProxy` 3.5-dev8.
#[test]
fn req_hdrs_bin_matches_haproxy() {
    const HOST: &str = "04686F73740161";
    let addr = common::reserve_addr();
    let cfg = http_cfg(
        "",
        &format!(
            r#"frontend fe
  bind {addr}
  http-request return status 200 content-type text/plain lf-string "[%[req.hdrs_bin,hex]]""#
        ),
    );
    let (_ibex, _sock) = start("req_hdrs_bin_oracle", &cfg, &[addr]);

    // Varint boundaries: (value length, its varint as HAProxy writes it).
    for (n, varint) in [(239, "EF"), (240, "F000"), (300, "FC03"), (2287, "FF7F"), (2288, "F08000"), (5000, "F8A901")] {
        let v = "v".repeat(n);
        let req = format!("GET / HTTP/1.1\r\nHost: a\r\nX-L: {v}\r\nConnection: close\r\n\r\n");
        assert_eq!(body(addr, req.as_bytes()), format!("[{HOST}03782D6C{varint}{}0000]", hex_encode(v.as_bytes())), "X-L of {n} bytes");
    }

    // (headers after `Host: a`, the whole sample as HAProxy encodes it).
    let cases = [
        ("connection: close\r\n", "04686F737401610000"),
        ("Connection: close, foo\r\n", "04686F737401610A636F6E6E656374696F6E03666F6F0000"),
        ("Connection: foo , close\r\n", "04686F737401610A636F6E6E656374696F6E04666F6F200000"),
        ("Connection: close, Foo,  bar\r\n", "04686F737401610A636F6E6E656374696F6E07466F6F2C6261720000"),
        ("Connection: upgrade, foo\r\n", "04686F737401610A636F6E6E656374696F6E03666F6F0000"),
        ("Connection: upgrade\r\nUpgrade: h2c\r\n", "04686F737401610000"),
        ("Connection: upgrade, close\r\nUpgrade: x\r\n", "04686F737401610A636F6E6E656374696F6E0775706772616465077570677261646501780000"),
        ("Connection: Upgrade\r\nUpgrade: h2c, Foo\r\n", "04686F737401610A636F6E6E656374696F6E0755706772616465077570677261646503466F6F0000"),
        ("Upgrade: x\r\nKeep-Alive: 5\r\nConnection: close\r\n", "04686F737401610A6B6565702D616C69766501350000"),
        ("Proxy-Connection: x\r\nConnection: close\r\n", "04686F737401611070726F78792D636F6E6E656374696F6E01780000"),
        ("X-A: 1\r\n", "04686F7374016103782D6101310000"),
    ];
    for (hdrs, want) in cases {
        let req = format!("GET / HTTP/1.1\r\nHost: a\r\n{hdrs}\r\n");
        assert_eq!(body(addr, req.as_bytes()), format!("[{want}]"), "headers {hdrs:?}");
    }
    let te = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n";
    assert_eq!(body(addr, te), "[04686F73740161117472616E736665722D656E636F64696E67076368756E6B65640000]");
}
