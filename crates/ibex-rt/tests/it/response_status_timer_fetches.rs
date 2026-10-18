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

/// A reply Ibex builds itself after a proxied 201 on the same worker: HAProxy (3.5-dev8) gives
/// `[0|403|-1]` for `/deny` and `/ret`, and `[201|201|<ms>]` again for a proxied one.
#[test]
fn local_reply_does_not_inherit_previous_response() {
    let a = common::reserve_addr();
    let be = backend();
    let dir = std::env::temp_dir().join(format!("t385b-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("c.cfg");
    std::fs::write(
        &path,
        format!(
            "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}\n  http-request deny if {{ path /deny }}\n  http-request return status 403 if {{ path /ret }}\n  \
             default_backend b\n  http-after-response set-header x-out \"[%[server_status]|%[status]|%[res.timer.hdr]]\"\n\
             backend b\n  server s {be}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    assert!(common::wait_listening(a), "ibex did not listen");
    let mut got = Vec::new();
    for p in ["/", "/deny", "/ret", "/"] {
        let mut s = TcpStream::connect(a).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(format!("GET {p} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        let l = out.lines().find(|l| l.starts_with("x-out:")).unwrap_or_else(|| panic!("no x-out for {p}: {out:?}")).trim_start_matches("x-out:").trim().to_string();
        got.push(l);
    }
    common::stop(&mut child);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(got[0].starts_with("[201|201|") && got[3].starts_with("[201|201|"), "{got:?}");
    assert_eq!(got[1], "[0|403|-1]", "{got:?}");
    assert_eq!(got[2], "[0|403|-1]", "{got:?}");
}
