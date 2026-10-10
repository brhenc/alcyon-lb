// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The request head as the server receives it. `HAProxy` 3.5-dev8 writes the header names in
//! lower case (they went through HTX), whatever case the client used, `Connection` added
//! by `option http-server-close` included; values and the request line are untouched.
//! (`h1-case-adjust` is not supported: the parser refuses it.)

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

/// Sends `req` through ibex configured with `extra` in the backend, returns what the server saw.
fn seen_by_server(extra: &str, req: &[u8]) -> String {
    let fe = common::reserve_addr();
    let be = common::reserve_addr();
    let listener = TcpListener::bind(be).expect("bind backend");
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("accept");
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = s.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
            if n == 0 || got.windows(4).any(|w| w == b"\r\n\r\n") && (got.ends_with(b"hi") || !got.starts_with(b"POST")) {
                break;
            }
        }
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        String::from_utf8_lossy(&got).into_owned()
    });
    let cfg = format!(
        "global\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n{extra}  server s {be}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(req).unwrap();
    let mut buf = [0u8; 4096];
    let _ = c.read(&mut buf);
    common::stop(&mut child);
    server.join().expect("server thread")
}

/// Oracle: `host: x`, `x-my-header: A`, `user-agent: u`, the values as sent.
#[test]
fn the_server_sees_lower_case_header_names() {
    let got = seen_by_server(
        "",
        b"GET /Path?Q=1 HTTP/1.1\r\nHost: x\r\nX-My-Header: A\r\nUser-Agent: U\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(got, "GET /Path?Q=1 HTTP/1.1\r\nhost: x\r\nx-my-header: A\r\nuser-agent: U\r\n\r\n");
}

/// Oracle: the `Connection` header `http-server-close` adds is lower case too.
#[test]
fn the_connection_header_added_for_the_server_is_lower_case() {
    let got = seen_by_server(
        "  option http-server-close\n",
        b"POST / HTTP/1.1\r\nHost: x\r\nX-My-Header: A\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nhi",
    );
    assert_eq!(got, "POST / HTTP/1.1\r\nhost: x\r\nx-my-header: A\r\ncontent-length: 2\r\nconnection: close\r\n\r\nhi");
}
