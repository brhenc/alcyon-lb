// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A section may carry any number of `log` lines (tasks/T302 item 7). Measured with
//! `haproxy -c` on 3.5-dev8: global, defaults, frontend and backend all load 3, 4, 10, 50
//! and 500 lines, there is no limit and no error. Each target must receive the line.
//! Set `T306C_ORACLE=/path/to/haproxy` to run the same cases against it.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn collectors(n: usize) -> Vec<UdpSocket> {
    (0..n)
        .map(|_| {
            let s = UdpSocket::bind("127.0.0.1:0").expect("collector");
            s.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
            s
        })
        .collect()
}

fn lines(cs: &[UdpSocket]) -> String {
    cs.iter().map(|c| format!("  log {} local0\n", c.local_addr().expect("addr"))).collect()
}

fn server() -> SocketAddr {
    let ls = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = ls.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in ls.incoming().flatten() {
            let mut b = [0u8; 4096];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    addr
}

/// Runs `cfg` (with `{fe}` and `{be}` filled in), sends one request, and returns for each
/// collector whether it received a line with the marker `MARK`.
fn run(build: impl Fn(&str) -> String, cs: &[UdpSocket]) -> Vec<bool> {
    let (fe, be) = (common::reserve_addr(), server());
    let cfg = build(&format!("{fe}")).replace("{be}", &be.to_string());
    let mut f = NamedTempFile::new().expect("cfg");
    f.write_all(cfg.as_bytes()).expect("write");
    let bin = std::env::var("T306C_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = common::Alcyon(Command::new(bin).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn"));
    assert!(common::wait_listening(fe), "never listened:\n{cfg}");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(b"GET /MARK HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    let mut got = vec![false; cs.len()];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && got.iter().any(|g| !g) {
        for (i, s) in cs.iter().enumerate() {
            if let Ok(n) = s.recv(&mut buf) {
                got[i] |= String::from_utf8_lossy(&buf[..n]).contains("/MARK");
            }
        }
    }
    common::stop(&mut child);
    got
}

const TAIL: &str = "  mode http\n  timeout client 3s\n  timeout server 3s\n  timeout connect 1s\n  option httplog\n";

#[test]
fn five_log_lines_in_a_frontend_all_receive_the_line() {
    let cs = collectors(5);
    let l = lines(&cs);
    let got = run(|fe| format!("frontend f\n{TAIL}  bind {fe}\n{l}  default_backend b\nbackend b\n  mode http\n  server s {{be}}\n"), &cs);
    assert_eq!(got, vec![true; 5]);
}

#[test]
fn three_global_lines_and_log_global_all_receive_the_line() {
    let cs = collectors(3);
    let l = lines(&cs);
    let got = run(|fe| format!("global\n{l}defaults\n{TAIL}frontend f\n  bind {fe}\n  log global\n  default_backend b\nbackend b\n  mode http\n  server s {{be}}\n"), &cs);
    assert_eq!(got, vec![true; 3]);
}

#[test]
fn four_defaults_lines_reach_the_frontend_that_inherits_them() {
    let cs = collectors(4);
    let l = lines(&cs);
    let got = run(|fe| format!("defaults\n{TAIL}{l}frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  mode http\n  server s {{be}}\n"), &cs);
    assert_eq!(got, vec![true; 4]);
}

#[test]
fn a_backend_with_ten_lines_loads() {
    let cs = collectors(10);
    let l = lines(&cs);
    let cfg = format!("frontend f\n{TAIL}  bind 127.0.0.1:1\n  default_backend b\nbackend b\n{TAIL}{l}  server s 127.0.0.1:1\n");
    alcyon_config::parse_str(&cfg).expect("ten log lines in a backend load");
}
