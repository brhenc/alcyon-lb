// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `%rc` carries a `+` when the request was redispatched (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 with `log-format "RC=%rc SRV=%s ST=%ST"`, a
//! backend with `server s1` (nothing listens) and `server s2` (answers), six requests:
//!
//! * `retries 2` and `option redispatch`: every request is answered by s2; the ones balanced
//!   to s1 first are retried on s2 and log `RC=+1`, the others `RC=0`;
//! * `retries 2` alone: s1's requests are retried on s1 and fail with 503 (`RC=2 SRV=s1`),
//!   the others log `RC=0`; no `+` anywhere.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// The log lines of six requests under `backend_opts`.
fn run(backend_opts: &str) -> Vec<String> {
    let log = UdpSocket::bind("127.0.0.1:0").expect("bind log");
    log.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    let log_addr = log.local_addr().expect("addr");
    let fe = common::reserve_addr();
    let dead = common::reserve_addr();
    let live = server();
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 1s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  log {log_addr} format raw local0\n  log-format \"RC=%rc SRV=%s ST=%ST\"\n  default_backend b\n\
         backend b\n{backend_opts}  server s1 {dead}\n  server s2 {live}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn alcyon");
    assert!(common::wait_listening(fe), "alcyon never listened");
    for _ in 0..6 {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
    }
    let mut lines = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 4096];
    while lines.len() < 6 && Instant::now() < deadline {
        if let Ok(n) = log.recv(&mut buf) {
            let l = String::from_utf8_lossy(&buf[..n]).into_owned();
            // A syslog header, if the format adds one, is not part of the line.
            let line = l.find("RC=").map_or(l.clone(), |i| l[i..].trim().to_string());
            // The probe `wait_listening` opens carries nothing: logged as a 400, not a request.
            if !line.ends_with("ST=400") {
                lines.push(line);
            }
        }
    }
    common::stop(&mut child);
    lines
}

#[test]
fn a_redispatched_request_logs_a_plus() {
    let lines = run("  retries 2\n  option redispatch\n");
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert!(lines.iter().all(|l| l == "RC=0 SRV=s2 ST=200" || l == "RC=+1 SRV=s2 ST=200"), "{lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("RC=+1")), "no request was redispatched: {lines:?}");
}

#[test]
fn retries_alone_never_log_a_plus() {
    let lines = run("  retries 2\n");
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert!(lines.iter().all(|l| l == "RC=0 SRV=s2 ST=200" || l == "RC=2 SRV=s1 ST=503"), "{lines:?}");
}
