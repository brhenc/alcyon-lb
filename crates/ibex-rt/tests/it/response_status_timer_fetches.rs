// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T385: `server_status`, `res.comp`, `res.comp_algo`, `res.timer.hdr` in an `http-response` rule.
//! The expected line was measured on HAProxy 3.5-dev8: with `set-status 202` ahead of the fetches and
//! a server that answers 201 after 300 ms, `[201|202|0||300]`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn backend() -> SocketAddr {
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
            std::thread::sleep(Duration::from_millis(300));
            let _ = c.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    addr
}

#[test]
fn server_status_comp_and_header_timer() {
    let a = common::reserve_addr();
    let be = backend();
    let dir = std::env::temp_dir().join(format!("t385-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  default_backend b\n  http-response set-status 202\n  \
             http-response set-header x-out \"[%[server_status]|%[status]|%[res.comp]|%[res.comp_algo]|%[res.timer.hdr]]\"\n\
             backend b\n  server s {be}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    assert!(common::wait_listening(a), "ibex did not listen");
    let mut s = TcpStream::connect(a).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    let line = out.lines().find(|l| l.starts_with("x-out:")).unwrap_or_else(|| panic!("no x-out in {out:?}")).trim_start_matches("x-out:").trim();
    let inner = line.trim_start_matches('[').trim_end_matches(']');
    let f: Vec<&str> = inner.split('|').collect();
    assert_eq!(&f[..4], ["201", "202", "0", ""], "line {line}");
    let tr: i64 = f[4].parse().unwrap_or_else(|_| panic!("Tr {:?}", f[4]));
    assert!((290..400).contains(&tr), "Tr {tr}");
}
