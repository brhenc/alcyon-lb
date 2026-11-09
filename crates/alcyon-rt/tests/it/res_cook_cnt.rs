// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T327: `res.cook_cnt` counts one cookie per Set-Cookie value, as the oracle's
//! `smp_fetch_cookie_cnt` does.

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
fn res_cook_cnt_attributes() {
    // Each row: the backend's response, and the x-out HAProxy 3.5-dev8 gives for it. The oracle
    // walks Set-Cookie with http_find_header(full=0), so a header is first split at commas
    // outside quotes (the Expires date too: `Path=/` after it becomes a cookie of its own),
    // and each piece has one cookie: its first attribute with `=` not starting with `$`.
    const ROWS: &[(&[u8], &str)] = &[
        // The task's row.
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-B: 1\r\nX-B: 2, 3\r\nSet-Cookie: s=abc; Path=/\r\nSet-Cookie: n=7\r\n\r\nok",
            "[2|1|0|0|0|0|0|0]",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: s=abc; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Path=/\r\nSet-Cookie: t=1; Expires=Thu, 01 Jan 2030 00:00:00 GMT; HttpOnly\r\n\r\nok",
            "[3|1|1|0|1|0|0|0]",
        ),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: a=1, b=2\r\n\r\nok", "[2|0|0|0|0|1|1|0]"),
        // A comma inside quotes does not split.
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: q=\"x,y\"; Path=/\r\n\r\nok", "[1|0|0|0|0|0|0|1]"),
        // `s=` has an empty value and is not `s` for cook_cnt(s); `$v` is skipped.
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: s=\r\nSet-Cookie: $v=1; s=2\r\n\r\nok", "[2|1|0|0|0|0|0|0]"),
        // An attribute with no `=` is skipped; an empty name is a cookie; blanks around `=`.
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: flag; s=3\r\nSet-Cookie: =v; s=4\r\nSet-Cookie: s = 5 ; Path=/\r\n\r\nok",
            "[3|2|0|0|0|0|0|0]",
        ),
        // No `=` at all, an empty header, and empty pieces around a cookie.
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: s\r\nSet-Cookie:\r\nSet-Cookie: ,s=6,\r\n\r\nok", "[1|1|0|0|0|0|0|0]"),
    ];
    const RESPS: &[&[u8]] = &[ROWS[0].0, ROWS[1].0, ROWS[2].0, ROWS[3].0, ROWS[4].0, ROWS[5].0, ROWS[6].0];
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
  http-response set-header x-out "[%[res.cook_cnt]|%[res.cook_cnt(s)]|%[res.cook_cnt(Path)]|%[res.cook_cnt(Expires)]|%[res.cook_cnt(t)]|%[res.cook_cnt(a)]|%[res.cook_cnt(b)]|%[res.cook_cnt(q)]]"
backend b
  server s {BE}
"#;

    let a = common::reserve_addr();
    let be = backend(RESPS);
    let cfg = CFG.replace("{A}", &a.to_string()).replace("{BE}", &be.to_string());
    let (_alcyon, _sock) = start("t327-res-cook-cnt", &cfg, &[a]);

    let mut bad = Vec::new();
    for (i, (_, want)) in ROWS.iter().enumerate() {
        let got = xout(a, format!("GET /{i} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes());
        if got != *want {
            bad.push(format!("row {i}: got {got}, want {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
