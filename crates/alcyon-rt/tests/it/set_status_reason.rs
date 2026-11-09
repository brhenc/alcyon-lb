// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-response set-status <code> [reason <text>]` and the same on `http-after-response`:
//! the reason reaches the status line. Measured on HAProxy 3.5-dev8-885761-29 (2026-10-05),
//! one frontend per rule, a server answering `HTTP/1.1 200 OK` with `Content-Length: 2`:
//!
//! ```text
//! http-response set-status 201                          HTTP/1.x 201 Created
//! http-response set-status 201 reason Foo-Bar           HTTP/1.x 201 Foo-Bar
//! http-response set-status 299 reason "Hello World"     HTTP/1.x 299 Hello World
//! http-response set-status 299                          HTTP/1.x 299 Success
//! http-after-response set-status 202 reason After      HTTP/1.x 202 After
//! http-response set-status 201 reason "R-%[str(abc)]"   HTTP/1.x 201 R-%[str(abc)]   (literal)
//! ```

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

fn server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                while c.read(&mut b).is_ok_and(|n| n > 0) {
                    if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// The status line of the answer a frontend with `rule` gives.
fn status_line(rule: &str) -> String {
    let srv = server();
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         listen l\n  bind {fe}\n  {rule}\n  server s {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Alcyon)
        .expect("spawn");
    assert!(common::wait_listening(fe), "never listened with:\n{cfg}");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    common::stop(&mut child);
    String::from_utf8_lossy(&got).split("\r\n").next().unwrap_or("").to_string()
}

#[test]
fn set_status_reason_reaches_the_status_line() {
    let cases: &[(&str, &str)] = &[
        ("http-response set-status 201", "HTTP/1.1 201 Created"),
        ("http-response set-status 201 reason Foo-Bar", "HTTP/1.1 201 Foo-Bar"),
        ("http-response set-status 299 reason \"Hello World\"", "HTTP/1.1 299 Hello World"),
        ("http-response set-status 299", "HTTP/1.1 299 Success"),
        ("http-after-response set-status 202 reason After", "HTTP/1.1 202 After"),
        ("http-response set-status 201 reason \"R-%[str(abc)]\"", "HTTP/1.1 201 R-%[str(abc)]"),
        ("http-response set-status 203 reason X if { status 200 }", "HTTP/1.1 203 X"),
        ("http-after-response set-status 203 reason Y unless { status 404 }", "HTTP/1.1 203 Y"),
    ];
    for (rule, want) in cases {
        assert_eq!(&status_line(rule), want, "{rule}");
    }
}

/// HAProxy refuses what follows the status when it is neither `reason <text>` nor a
/// condition (measured: "expects either 'if' or 'unless' followed by a condition but found
/// 'reason'" for a bare `reason`, and for `set-status 201 foo`). So does Alcyon, rather than
/// dropping the words.
#[test]
fn set_status_refuses_stray_words() {
    for rule in [
        "http-response set-status 201 reason",
        "http-response set-status 201 foo",
        "http-response set-status 201 reason if",
        "http-after-response set-status 201 reason",
        "http-after-response set-status 201 reason A B",
    ] {
        let cfg = format!("defaults\n  mode http\n  timeout client 1s\n  timeout connect 1s\n  timeout server 1s\nlisten l\n  bind 127.0.0.1:0\n  {rule}\n  server s 127.0.0.1:1\n");
        let mut f = NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
        assert!(!out.status.success(), "{rule} was accepted");
    }
}
