// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `tune.ibex.h1-lowercase-headers on|off` (X5, decision D-E of
//! docs/design/htx-engine-2026-11-01.md): with `on`, the names of a forwarded HTTP/1 head go
//! in lower case both ways, as `HAProxy` 3.5-dev8 writes them (measured: the server got
//! `host: a`, `x-mixed-case: v`; the client `content-length: 2`, `x-srv-case: A`); with `off`,
//! the default, in the case they came in. `h1-case-adjust` applies on top of either.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

const RSP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv-Case: A\r\n\r\nok";
const REQ: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nX-Mixed-Case: v\r\n\r\n";

/// The head the server got and the head the client got, through ibex on `global` + a
/// proxy section of `proxy_extra`.
fn through(global: &str, proxy_extra: &str) -> (String, String) {
    let srv = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let srv_addr = srv.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut c, _) = srv.accept().expect("accept");
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        c.write_all(RSP).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        String::from_utf8_lossy(&got).into_owned()
    });
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n{global}defaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         listen l\n  bind {fe}\n{proxy_extra}  server s1 {srv_addr}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(REQ).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.ends_with(b"ok") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    let got = server.join().expect("server");
    common::stop(&mut child);
    let head = |t: &str| t.split("\r\n\r\n").next().unwrap_or("").to_string();
    (head(&got), head(&String::from_utf8_lossy(&resp)))
}

#[test]
fn on_writes_every_forwarded_name_in_lower_case_as_haproxy() {
    let (srv, cli) = through("  tune.ibex.h1-lowercase-headers on\n", "");
    assert_eq!(srv, "GET / HTTP/1.1\r\nhost: a\r\nx-mixed-case: v");
    assert_eq!(cli, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-srv-case: A");
}

#[test]
fn off_and_unset_keep_the_case_the_names_came_in() {
    for global in ["", "  tune.ibex.h1-lowercase-headers off\n"] {
        let (srv, cli) = through(global, "");
        assert_eq!(srv, "GET / HTTP/1.1\r\nHost: a\r\nX-Mixed-Case: v", "{global:?}");
        assert_eq!(cli, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Srv-Case: A", "{global:?}");
    }
}

/// `h1-case-adjust` still names what its table holds, the other names as the setting says.
#[test]
fn the_case_adjust_table_applies_on_top_of_either() {
    let adjust = "  h1-case-adjust x-mixed-case X-MIXED-case\n  h1-case-adjust x-srv-case X-SRV-case\n";
    let opts = "  option h1-case-adjust-bogus-server\n  option h1-case-adjust-bogus-client\n";
    let (srv, cli) = through(&format!("{adjust}  tune.ibex.h1-lowercase-headers on\n"), opts);
    assert_eq!(srv, "GET / HTTP/1.1\r\nhost: a\r\nX-MIXED-case: v");
    assert_eq!(cli, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nX-SRV-case: A");
    let (srv, cli) = through(adjust, opts);
    assert_eq!(srv, "GET / HTTP/1.1\r\nHost: a\r\nX-MIXED-case: v");
    assert_eq!(cli, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-SRV-case: A");
}

#[test]
fn the_setting_takes_only_on_or_off() {
    for bad in ["  tune.ibex.h1-lowercase-headers\n", "  tune.ibex.h1-lowercase-headers yes\n", "  tune.ibex.h1-lowercase-headers on off\n"] {
        let mut f = NamedTempFile::new().expect("tmp");
        write!(f, "global\n{bad}defaults\n  mode http\nlisten l\n  bind 127.0.0.1:1\n").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
        assert!(!out.status.success(), "{bad:?} was accepted");
    }
}
