// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A POST with a body while the stream connects to the server (T501, T496's open question).
//! Measured on `HAProxy 3.5-dev8-885761-29`, server 10.9.9.9 unreachable, `timeout client 1s`,
//! `timeout connect 3s`, no retry:
//!
//! | request                              | HAProxy                                     |
//! |--------------------------------------|---------------------------------------------|
//! | Content-Length 100, 10 bytes sent    | 400 `cC--` at 1 s, closed at 2 s            |
//! | Content-Length 5, all 5 sent         | 503 `sC--` at 3 s (the body is complete)    |
//! | chunked, first chunk sent, no end    | 400 `cC--` at 1 s, closed at 2 s            |

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Status line, seconds until the answer, seconds until the close, and the log line.
fn run(req: &[u8]) -> (String, f64, f64, String) {
    let port = common::reserve_port();
    let dir = std::env::temp_dir().join(format!("ibex_t501p_{}_{port}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let (cfgf, logf) = (dir.join("c.cfg"), dir.join("out.log"));
    let cfg = format!(
        "global\n  log stdout format raw local0\ndefaults\n  mode http\n  log global\n  option httplog\n  retries 0\n  \
         timeout connect 1500ms\n  timeout client 500ms\n  timeout server 5s\n\
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
    assert!(common::wait_listening(format!("127.0.0.1:{port}").parse().unwrap()), "never listened");
    let t = Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(6))).ok();
    s.write_all(req).expect("write");
    let (mut first, mut got, mut buf) = (None, Vec::new(), [0u8; 4096]);
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                first.get_or_insert(t.elapsed().as_secs_f64());
            }
        }
    }
    let closed = t.elapsed().as_secs_f64();
    thread::sleep(Duration::from_millis(200));
    common::stop(&mut child);
    let log = std::fs::read_to_string(&logf).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let status = String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string();
    (status, first.unwrap_or(-1.0), closed, log)
}

#[test]
fn partial_content_length_body() {
    let (status, first, closed, log) = run(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n0123456789");
    assert_eq!(status, "HTTP/1.1 400 Bad request", "{log}");
    assert!((0.4..0.9).contains(&first), "400 at {first}");
    assert!((0.9..1.5).contains(&closed), "closed at {closed}");
    assert!(log.contains("cC--"), "{log}");
}

#[test]
fn partial_chunked_body() {
    let (status, first, _, log) = run(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n01234\r\n");
    assert_eq!(status, "HTTP/1.1 400 Bad request", "{log}");
    assert!((0.4..0.9).contains(&first), "400 at {first}");
    assert!(log.contains("cC--"), "{log}");
}

#[test]
fn complete_content_length_body_owes_the_client_timer_nothing() {
    let (status, first, _, log) = run(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n01234");
    assert_eq!(status, "HTTP/1.1 503 Service Unavailable", "{log}");
    assert!(first >= 1.4, "503 at {first}");
    assert!(log.contains("sC--"), "{log}");
}
