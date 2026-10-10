// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Connection-level fetches against the real binary, with the values `HAProxy` 3.5 gives for
//! the same configuration.
//!
//! `tcp-request connection set-src` rewrites the front connection's own source address, so
//! `fc_src` reads the rewritten one, not the peer's (HAProxy: `x-fc: 10.1.2.3`). Ibex kept
//! the peer's. `http_first_req` did not exist.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0
                        || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

fn header(resp: &str, name: &str) -> Option<String> {
    resp.split("\r\n").find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

#[test]
fn fc_src_follows_set_src_and_http_first_req_is_true_on_the_first_request() {
    let be = backend();
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!(
            "defaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {fe}\n  tcp-request connection set-src ipv4(10.1.2.3)\n\
             \x20 http-response set-header X-First %[http_first_req]\n\
             \x20 http-response set-header X-Fc %[fc_src]\n\
             \x20 default_backend be\n\
             backend be\n  server s1 {be}\n"
        ),
        fe,
    );

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.ends_with(b"ok") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.starts_with("HTTP/1.1 200"), "no response: {resp:?}");
    assert_eq!(header(&resp, "X-Fc").as_deref(), Some("10.1.2.3"), "{resp}");
    assert_eq!(header(&resp, "X-First").as_deref(), Some("1"), "{resp}");
}
