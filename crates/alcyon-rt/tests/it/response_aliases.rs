// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T329e: `resp_ver`, `HAProxy`'s alias of `res.ver`. Expectations measured on
//! 3.5-dev8-885761-29 on 2026-10-17.
//!
//! `server_status` is not registered: `HAProxy` answers the status the server sent, which
//! `http-response set-status` does not change (`txn->server_status`; measured `[404|201]` for
//! `[%[status]|%[server_status]]` after `set-status 404` on a 201), and Alcyon keeps no such
//! value yet. Answering the current status instead would be wrong exactly where the fetch is
//! used, so the parser refuses it until it is plumbed (AGENTS.md section 5).
//! `fc_http_major`, `bc_http_major` and `req_proto_http` belong to T326g.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

/// A server that reads each request head, answers `resp` and closes the connection.
fn backend(resp: &'static [u8]) -> SocketAddr {
    let addr = common::reserve_addr();
    let listener = TcpListener::bind(addr).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
            let (mut head, mut buf) = (Vec::new(), [0u8; 4096]);
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(got) => head.extend_from_slice(&buf[..got]),
                }
            }
            let _ = conn.write_all(resp);
        }
    });
    addr
}

/// The value of the `x-out` header in the answer to `GET path`.
fn xout(addr: SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let s = String::from_utf8_lossy(&out).into_owned();
    let head = s.split("\r\n\r\n").next().unwrap_or("");
    head.lines().find_map(|l| l.strip_prefix("x-out: ")).map_or_else(|| panic!("no x-out header in the answer: {s:?}"), str::to_string)
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n";

/// `alcyon -c` on `cfg`: whether it loads, and what it said.
fn check(tag: &str, cfg: &str) -> (bool, String) {
    let path = std::env::temp_dir().join(format!("response-aliases-{tag}-{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout))
}

#[test]
fn resp_ver_is_res_ver() {
    let b0 = backend(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok");
    let b1 = backend(b"HTTP/1.0 201 Created\r\nContent-Length: 2\r\n\r\nok");
    let a = common::reserve_addr();
    let path = std::env::temp_dir().join(format!("response-aliases-{}.cfg", std::process::id()));
    std::fs::write(
        &path,
        format!(
            "{DEFAULTS}frontend fe\n  bind {a}\n  use_backend b1 if {{ path /1 }}\n  default_backend b0\n\
             backend b0\n  http-response set-header x-out \"[%[resp_ver]|%[res.ver]]\"\n  server s {b0}\n\
             backend b1\n  http-response set-header x-out \"[%[resp_ver]|%[res.ver]]\"\n  server s {b1}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _alcyon = common::Alcyon(child);
    assert!(common::wait_listening(a), "alcyon did not listen on {a}");
    assert_eq!(xout(a, "/0"), "[1.1|1.1]");
    assert_eq!(xout(a, "/1"), "[1.0|1.0]");
    let _ = std::fs::remove_file(&path);

    // Like res.ver, it needs the response.
    let (ok, said) = check("req", &format!("{DEFAULTS}frontend fe\n  bind 127.0.0.1:0\n  http-request set-header x \"%[resp_ver]\"\n"));
    assert!(!ok && said.contains("sample fetch <resp_ver> may not be reliably used here because it needs 'HTTP response' which is not available here."), "{said}");
}

#[test]
fn server_status_loads_now_that_it_is_plumbed() {
    // Refused until T385 gave it the server's own status; response_status_timer_fetches.rs
    // checks the value it answers.
    let (ok, said) = check("srv", &format!("{DEFAULTS}backend b\n  http-response set-header x \"%[server_status]\"\n  server s 127.0.0.1:1\n"));
    assert!(ok, "server_status is refused: {said}");
}
