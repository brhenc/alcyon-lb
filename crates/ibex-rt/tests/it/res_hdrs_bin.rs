// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T329: `res.hdrs_bin` fetch

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

/// The value of the `x-out` header in the answer to `req`.
fn xout(addr: SocketAddr, req: &[u8]) -> String {
    let s = String::from_utf8_lossy(&get(addr, req)).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("x-out")).map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| panic!("no x-out header in the answer: {s:?}"))
}

#[test]
fn res_hdrs_bin() {
    // Backend response: exactly these bytes
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nX-B: 2, 3\r\nSet-Cookie: s=abc\r\n\r\nok";

    let be = backend(RESP);
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "",
        &format!(
            r#"frontend fe
  bind {A}
  default_backend b
  http-response set-header x-out "[%[res.hdrs_bin,hex]]"
backend b
  server s {BE}"#,
            A = a,
            BE = be,
        ),
    );
    let (ibex, _sock) = start("res-hdrs-bin", &cfg, &[a]);
    let _ = ibex; // keep it alive

    // Expected binary encoding of headers:
    // content-length: 2  -> 0E 636F6E74656E742D6C656E677468 01 32
    // x-b: 1             -> 03 782D62 01 31
    // x-b: 2, 3          -> 03 782D62 04 322C2033
    // set-cookie: s=abc  -> 0A 7365742D636F6F6B6965 05 733D616263
    // end marker         -> 00 00
    let expected = "0E636F6E74656E742D6C656E677468013203782D62013103782D6204322C20330A7365742D636F6F6B696505733D6162630000";
    assert_eq!(xout(a, GET), format!("[{expected}]"));
}

/// Lengths of 240 and more take `HAProxy`'s varint (a value of 4096 bytes or more panicked
/// the candidate's), and `Connection` / `Upgrade` are what `HAProxy`'s H1 parser leaves of
/// them in a response (no `h1_postparse_req_hdrs` pairing there). Every expected value was
/// measured on `HAProxy` 3.5-dev8.
#[test]
fn res_hdrs_bin_matches_haproxy() {
    use std::fmt::Write;
    const CL: &str = "0E636F6E74656E742D6C656E6774680132"; // content-length: 2
    const CONN: &str = "0A636F6E6E656374696F6E"; // "connection"
    let mut cases: Vec<(String, String)> = Vec::new();
    for (n, varint) in [(239, "EF"), (240, "F000"), (300, "FC03"), (4095, "FFF000"), (4096, "F0F100"), (5000, "F8A901")] {
        let v = "v".repeat(n);
        let mut hex = String::new();
        for b in v.bytes() {
            let _ = write!(hex, "{b:02X}");
        }
        cases.push((format!("X-L: {v}\r\n"), format!("{CL}03782D6C{varint}{hex}")));
    }
    for (hdrs, want) in [
        ("Connection: keep-alive\r\nKeep-Alive: timeout=5\r\n", format!("{CL}0A6B6565702D616C6976650974696D656F75743D35")),
        ("Connection: close, foo\r\n", format!("{CL}{CONN}03666F6F")),
        ("Connection: foo, keep-alive\r\n", format!("{CL}{CONN}03666F6F")),
        ("Upgrade: x\r\n", format!("{CL}07757067726164650178")),
        ("Connection: upgrade\r\n", format!("{CL}{CONN}0775706772616465")),
        ("Connection: upgrade\r\nUpgrade: h2c\r\n", format!("{CL}{CONN}0775706772616465")),
    ] {
        cases.push((hdrs.to_string(), want));
    }
    let mut routes = String::new();
    let mut backends = String::new();
    for (i, (hdrs, _)) in cases.iter().enumerate() {
        let resp: &'static [u8] = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n{hdrs}\r\nok").into_bytes().leak();
        let be = backend(resp);
        let _ = writeln!(routes, "  use_backend b{i} if {{ path /{i} }}");
        let _ = writeln!(backends, "backend b{i}\n  server s {be}");
    }
    let a = common::reserve_addr();
    let cfg = http_cfg(
        "",
        &format!("frontend fe\n  bind {a}\n{routes}  http-response set-header x-out \"[%[res.hdrs_bin,hex]]\"\n{backends}"),
    );
    let (_ibex, _sock) = start("res-hdrs-bin-oracle", &cfg, &[a]);
    for (i, (hdrs, want)) in cases.iter().enumerate() {
        let req = format!("GET /{i} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        let got = xout(a, req.as_bytes());
        assert!(got == format!("[{want}0000]"), "response headers {hdrs:?}: got {got:.120}");
    }
}
