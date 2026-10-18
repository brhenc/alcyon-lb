// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `monitor fail if|unless <cond>` against the real binary: the monitor URI answers 200
//! until a condition holds, then 503 through the proxy's error replacement (`errorloc302`
//! gives a 302). Expected bytes measured on HAProxy 3.5-dev8.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

const OK: &str = "HTTP/1.1 200 OK\r\ncontent-length: 58\r\n\
cache-control: no-cache\r\ncontent-type: text/html\r\n\r\n\
<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n";
const UNAVAILABLE: &str = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 107\r\n\
cache-control: no-cache\r\ncontent-type: text/html\r\n\r\n\
<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n";
const FOUND: &str = "HTTP/1.1 302 Found\r\ncache-control: no-cache\r\ncontent-length: 0\r\n\
location: http://www.example.com/down\r\n\r\n";

/// Sends each request on one connection, in order, and returns what came back for each.
fn ask(fe: SocketAddr, requests: &[(&str, &str)], answers: &[&str]) -> Vec<String> {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut got = Vec::new();
    for ((uri, hdr), want) in requests.iter().zip(answers) {
        write!(c, "GET {uri} HTTP/1.1\r\nHost: x\r\n{hdr}\r\n").unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while out.len() < want.len() {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        got.push(String::from_utf8_lossy(&out).into_owned());
    }
    got
}

#[test]
fn monitor_fail_switches_the_monitor_answer_from_200_to_503() {
    let (fe1, fe2, fe3) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let mut cfg = tempfile::NamedTempFile::new().unwrap();
    write!(
        cfg,
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
         frontend fe1\n  bind {fe1}\n  monitor-uri /health\n  monitor fail if {{ req.hdr(x-down) -m found }}\n\
         frontend fe2\n  bind {fe2}\n  monitor-uri /health\n  monitor fail unless {{ req.hdr(x-up) -m found }}\n\
         frontend fe3\n  bind {fe3}\n  errorloc302 503 http://www.example.com/down\n  monitor-uri /health\n  \
         monitor fail if {{ req.hdr(x-down) -m found }}\n"
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Ibex)
        .expect("spawn ibex");
    for a in [fe1, fe2, fe3] {
        assert!(common::wait_listening(a), "ibex never started listening");
    }
    let down = "x-down: 1\r\n";
    let up = "x-up: 1\r\n";
    // The connection stays open after each answer, as HAProxy's does.
    let one = ask(fe1, &[("/health", ""), ("/health", down), ("/health", "")], &[OK, UNAVAILABLE, OK]);
    let two = ask(fe2, &[("/health", ""), ("/health", up)], &[UNAVAILABLE, OK]);
    let three = ask(fe3, &[("/health", down)], &[FOUND]);
    common::stop(&mut child);
    assert_eq!(one, [OK, UNAVAILABLE, OK]);
    assert_eq!(two, [UNAVAILABLE, OK]);
    assert_eq!(three, [FOUND]);
}
