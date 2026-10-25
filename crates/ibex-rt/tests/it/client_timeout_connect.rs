// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `timeout client` while the stream is still connecting to the server (T496, VV-22, VV-23).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` (`tools/battery/repro/vv-timeouts/vv22.py`), the
//! server 10.9.9.9 unreachable, one `GET /`:
//!
//! | client | connect | retries | HAProxy                               |
//! |--------|---------|---------|---------------------------------------|
//! | 2s     | 1s      | 3       | 503 `sC--` at 4.0 s (client timer idle) |
//! | 1s     | 3s      | 3       | 503 `sC--` at 12 s                    |
//! | 2s     | 1s      | 0       | 503 `sC--` at 1.0 s                   |
//!
//! A complete request with no body owes the client timer nothing until the server answers,
//! and a connect timeout is a server-side timeout (`s`), logged `sC`.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// One `GET /` against a proxy whose server is unreachable: status line, seconds taken and
/// the termination state of the log line.
fn run(client_ms: u32, connect_ms: u32, retries: u32) -> (String, f64, String) {
    let port = common::reserve_port();
    let dir = std::env::temp_dir().join(format!("ibex_t496_{}_{client_ms}_{connect_ms}_{retries}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let (cfgf, logf) = (dir.join("c.cfg"), dir.join("out.log"));
    let cfg = format!(
        "global\n  log stdout format raw local0\ndefaults\n  mode http\n  log global\n  option httplog\n  retries {retries}\n  \
         timeout connect {connect_ms}ms\n  timeout client {client_ms}ms\n  timeout server 5s\n\
         listen l\n  bind 127.0.0.1:{port}\n  server s1 10.9.9.9:80\n"
    );
    std::fs::write(&cfgf, cfg).expect("write config");
    let out = std::fs::File::create(&logf).expect("log");
    let mut child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
        .arg("-f")
        .arg(&cfgf)
        .stdout(out)
        .stderr(Stdio::null())
        .spawn()
        .map(common::Ibex)
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "never listened");
        thread::sleep(Duration::from_millis(25));
    }
    let t = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(15))).ok();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let took = t.elapsed().as_secs_f64();
    thread::sleep(Duration::from_millis(200));
    common::stop(&mut child);
    let status = String::from_utf8_lossy(&buf).lines().next().unwrap_or("").to_string();
    let log = std::fs::read_to_string(&logf).unwrap_or_default();
    let line = log.lines().find(|l| l.contains("\"GET")).unwrap_or("").to_string();
    let flags = line.split_whitespace().find(|w| w.len() == 4 && w.chars().all(|c| "-cCsSIPRDLHQTKpP".contains(c)) && w.contains(['-', 'c', 's', 'S', 'C', 'I'])).unwrap_or("").to_string();
    let _ = std::fs::remove_dir_all(&dir);
    (status, took, flags)
}

#[test]
fn client_timer_idle_while_connect_retries_run() {
    // 3 attempts of 600 ms against a 1 s client timeout.
    let (status, took, flags) = run(1000, 600, 2);
    assert_eq!(status, "HTTP/1.1 503 Service Unavailable", "{took}s {flags}");
    assert!(took >= 1.7, "answered after {took}s, before the connect attempts ended");
    assert_eq!(flags, "sC--");
}

#[test]
fn connect_timeout_longer_than_client_timeout() {
    let (status, took, flags) = run(500, 1500, 0);
    assert_eq!(status, "HTTP/1.1 503 Service Unavailable", "{took}s {flags}");
    assert!(took >= 1.4, "answered after {took}s");
    assert_eq!(flags, "sC--");
}

#[test]
fn no_overlap_controls() {
    let (status, took, flags) = run(3000, 400, 0);
    assert_eq!(status, "HTTP/1.1 503 Service Unavailable");
    assert!((0.3..1.5).contains(&took), "{took}");
    assert_eq!(flags, "sC--");
}
