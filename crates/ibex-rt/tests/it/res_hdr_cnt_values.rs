// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T327: `res.hdr_cnt` counts values, `res.fhdr_cnt` lines, on the headers as the H1 parser
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

/// A server on a free port that reads each request head and answers `GET /<i>` with
/// `resps[i]`, then closes the connection.
fn backend(resps: &'static [&'static [u8]]) -> SocketAddr {
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
            let head = String::from_utf8_lossy(&head);
            let i: usize = head.split(' ').nth(1).and_then(|p| p.trim_start_matches('/').parse().ok()).unwrap_or(0);
            let _ = c.write_all(resps[i]);
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
fn res_hdr_cnt_values() {
    // Each row: the backend's response, and the x-out HAProxy 3.5-dev8 gives for it.
    const ROWS: &[(&[u8], &str)] = &[
        // The task's row: X-B "1" + "2, 3" is 3 values on 2 lines; 6 values on 5 lines in all.
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nX-B: 2, 3\r\nSet-Cookie: s=abc; Path=/\r\nSet-Cookie: n=7\r\n\r\nok",
            "[3|2|6|5|2|0|0|0|0]",
        ),
        // A comma inside quotes does not split ("3,4" is one value); the Expires comma does,
        // as on the oracle; `Connection: close` is removed by the H1 parser.
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nX-B: 2, \"3,4\"\r\nX-E:\r\nSet-Cookie: s=abc; Expires=Thu, 01 Jan 2030 00:00:00 GMT\r\nSet-Cookie: n=7\r\nConnection: close\r\n\r\nok",
            "[3|2|8|6|3|0|0|0|0]",
        ),
        // Only `close` is cut out of Connection; `Upgrade` stays.
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close, Upgrade\r\n\r\nok", "[0|0|2|2|0|1|1|0|0]"),
        // `Connection: keep-alive` is removed; an escaped quote inside quotes does not end them.
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\nX-C: \"a,b,c\"\r\nX-B: \"a\\\",b\", c\r\n\r\nok",
            "[2|1|4|3|0|0|0|1|0]",
        ),
        // `Upgrade: h2c` is removed; `Keep-Alive` is cut out of Connection, `foo` stays.
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nUpgrade: h2c\r\nX-B: 1\r\nConnection: Keep-Alive, foo\r\n\r\nok", "[1|1|3|3|0|1|1|0|0]"),
    ];
    const RESPS: &[&[u8]] = &[ROWS[0].0, ROWS[1].0, ROWS[2].0, ROWS[3].0, ROWS[4].0];
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
  default_backend b
  http-response set-header x-out "[%[res.hdr_cnt(x-b)]|%[res.fhdr_cnt(x-b)]|%[res.hdr_cnt]|%[res.fhdr_cnt]|%[res.hdr_cnt(set-cookie)]|%[res.hdr_cnt(connection)]|%[res.fhdr_cnt(connection)]|%[res.hdr_cnt(x-c)]|%[res.hdr_cnt(upgrade)]]"
backend b
  server s {BE}
"#;

    let a = common::reserve_addr();
    let be = backend(RESPS);
    let cfg = CFG.replace("{A}", &a.to_string()).replace("{BE}", &be.to_string());
    let (_ibex, _sock) = start("t327-res-hdr-cnt", &cfg, &[a]);

    let mut bad = Vec::new();
    for (i, (_, want)) in ROWS.iter().enumerate() {
        let got = xout(a, format!("GET /{i} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes());
        if got != *want {
            bad.push(format!("row {i}: got {got}, want {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn shdr_cnt_is_res_hdr_cnt() {
    // `shdr_cnt` is `smp_fetch_hdr_cnt` like `res.hdr_cnt`: it counts values, with or without a
    // name. x-out as HAProxy 3.5-dev8-885761-29 gives it (measured at the batch/1011 merge of
    // t326e and t327b). The oracle refuses `shdr_cnt` in a frontend `log-format` ("needs 'HTTP
    // response headers' which is not available here"), so set-header is where it is checked.
    const ROWS: &[(&[u8], &str)] = &[
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nX-B: 2, 3\r\nSet-Cookie: s=abc; Path=/\r\nSet-Cookie: n=7\r\n\r\nok", "[3|6|2|0|3|6]"),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nX-B: 2, \"3,4\"\r\nX-E:\r\nSet-Cookie: s=abc; Expires=Thu, 01 Jan 2030 00:00:00 GMT\r\nSet-Cookie: n=7\r\nConnection: close\r\n\r\nok",
            "[3|8|3|0|3|8]",
        ),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close, Upgrade\r\n\r\nok", "[0|2|0|1|0|2]"),
    ];
    const RESPS: &[&[u8]] = &[ROWS[0].0, ROWS[1].0, ROWS[2].0];
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
  default_backend b
  http-response set-header x-out "[%[shdr_cnt(x-b)]|%[shdr_cnt]|%[shdr_cnt(set-cookie)]|%[shdr_cnt(connection)]|%[res.hdr_cnt(x-b)]|%[res.hdr_cnt]]"
backend b
  server s {BE}
"#;

    let a = common::reserve_addr();
    let be = backend(RESPS);
    let cfg = CFG.replace("{A}", &a.to_string()).replace("{BE}", &be.to_string());
    let (_ibex, _sock) = start("t326e-shdr-cnt", &cfg, &[a]);

    let mut bad = Vec::new();
    for (i, (_, want)) in ROWS.iter().enumerate() {
        let got = xout(a, format!("GET /{i} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes());
        if got != *want {
            bad.push(format!("row {i}: got {got}, want {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
