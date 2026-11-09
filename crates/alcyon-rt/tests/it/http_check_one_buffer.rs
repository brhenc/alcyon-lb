// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An HTTP check reads one buffer of the response and judges on that (T238).
//!
//! Alcyon used to read the whole response, however large, re-parsing it on every readable
//! event while `expect string` waited: a 17 MB body took the process from 17 MB to 222 MB
//! RSS in one check. `HAProxy` reads at most one `tune.bufsize` buffer and, once it is full,
//! judges on what it holds. Measured on 3.5-dev8-885761-29 (2026-10-10), `option httpchk`,
//! `http-check expect string NEEDLE`, the server keeping the connection open:
//!
//! ```text
//! NEEDLE at body offset 0, 17 MB body      succeeded, Layer7 check passed, code: 200
//! no NEEDLE, 17 MB body                    failed, Layer7 invalid response,
//!                                            info: "HTTP content check did not match"
//! NEEDLE at body offset 20000              failed, Layer7 invalid response,
//!                                            info: "HTTP content check did not match"
//! a 20000-byte header, expect status       failed, reason: Socket error
//! ```
//!
//! The last body offset at which `HAProxy` still finds NEEDLE is 16244 (with a 41-byte
//! header block): its buffer holds HTX blocks, whose metadata take ~90 bytes of the 16384.
//! Alcyon's holds the response bytes, so it finds NEEDLE up to ~16330: the same buffer, the
//! window ~90 bytes larger.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Alcyon(Child);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A server that answers every request with `reply` and keeps the connection open, so that
/// only a full buffer can end the read.
fn fake(reply: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let reply = std::sync::Arc::new(reply);
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            let reply = std::sync::Arc::clone(&reply);
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(1))).ok();
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b);
                let _ = s.write_all(&reply);
                thread::sleep(Duration::from_secs(3));
            });
        }
    });
    addr
}

fn response(headers: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}

fn needle_at(offset: usize, len: usize) -> Vec<u8> {
    let mut body = vec![b'x'; len];
    body[offset..offset + 6].copy_from_slice(b"NEEDLE");
    body
}

/// The first health-check log line, and alcyon's peak RSS (kB) once it is logged.
fn check_line(check_lines: &str, reply: Vec<u8>) -> (String, u64) {
    let server = fake(reply);
    let dir = tempfile::TempDir::new().expect("tmp");
    let syslog = UdpSocket::bind("127.0.0.1:0").expect("udp");
    syslog.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let front = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  log 127.0.0.1:{} local0\n  option log-health-checks\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 2s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n{check_lines}\n  server s {server} check inter 300ms fall 1 rise 1\n",
        syslog.local_addr().unwrap().port()
    );
    let path = dir.path().join("alcyon.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon(child);
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        if let Ok((n, _)) = syslog.recv_from(&mut buf) {
            let line = String::from_utf8_lossy(&buf[..n]).into_owned();
            if line.contains("Health check for server b/s") {
                let status = std::fs::read_to_string(format!("/proc/{}/status", alcyon.0.id())).unwrap_or_default();
                let hwm = status
                    .lines()
                    .find_map(|l| l.strip_prefix("VmHWM:"))
                    .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
                    .unwrap_or(0);
                return (line, hwm);
            }
        }
    }
    panic!("no health-check log line within 8s for:\n{cfg}");
}

const EXPECT_NEEDLE: &str = "  option httpchk GET /\n  http-check expect string NEEDLE";

#[test]
fn a_string_past_the_first_buffer_is_not_found() {
    let (line, _) = check_line(EXPECT_NEEDLE, response("", &needle_at(20000, 21000)));
    assert!(
        line.contains("failed, reason: Layer7 invalid response, info: \"HTTP content check did not match\""),
        "{line}"
    );
}

#[test]
fn a_string_inside_the_first_buffer_is_found() {
    let (line, _) = check_line(EXPECT_NEEDLE, response("", &needle_at(16200, 21000)));
    assert!(line.contains("succeeded, reason: Layer7 check passed, code: 200"), "{line}");
}

#[test]
fn headers_larger_than_the_buffer_are_a_socket_error() {
    let big = format!("X-Big: {}\r\n", "a".repeat(20000));
    let (line, _) = check_line("  option httpchk GET /", response(&big, b"ok"));
    assert!(line.contains("failed, reason: Socket error"), "{line}");
}

/// A 17 MB body without the string is not held while the check waits for the rest of it:
/// the check fails on the first buffer, and the process stays far below the body's size.
#[test]
fn a_large_body_is_not_read_whole() {
    let (line, hwm) = check_line(EXPECT_NEEDLE, response("", &vec![b'x'; 17 * 1024 * 1024]));
    assert!(
        line.contains("failed, reason: Layer7 invalid response, info: \"HTTP content check did not match\""),
        "{line}"
    );
    // A debug alcyon peaks at ~22 MB here; reading the whole body took it past 200 MB.
    assert!(hwm < 64 * 1024, "peak RSS {hwm} kB for one check of a 17 MB body");
}
