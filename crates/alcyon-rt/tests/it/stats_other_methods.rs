// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T430 row 35: only GET, HEAD and POST reach the stats applet (`stats_check_uri` returns 0
//! for any other method). A PUT, DELETE or OPTIONS to the stats URI is an ordinary request:
//! it goes to the backend (measured on 3.5-dev8: with a dead server the 503 comes after the
//! connection retries, ~3 s; with no backend at all, at once), never the stats page.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};

struct Fixture {
    addr: SocketAddr,
    child: Child,
}

impl Fixture {
    fn start(backend: &str) -> Fixture {
        let addr = common::reserve_addr();
        let dir = std::path::PathBuf::from(format!("/tmp/t430-35-{}-{}", std::process::id(), addr.port()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("c.cfg");
        std::fs::write(
            &cfg,
            format!(
                "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n\
                 frontend f\n  bind {addr}\n  stats enable\n  stats uri /st\n  default_backend app\n\
                 backend app\n  {backend}\n"
            ),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        assert!(common::wait_listening(addr));
        Fixture { addr, child }
    }

    fn send(&self, req: &str) -> String {
        let mut c = TcpStream::connect(self.addr).expect("connect");
        c.set_read_timeout(Some(std::time::Duration::from_secs(8))).unwrap();
        c.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A backend that answers every request with the body `BACKEND`.
fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nBACKEND");
        }
    });
    a
}

#[test]
fn put_delete_options_to_the_stats_uri_go_to_the_backend() {
    let be = backend();
    let f = Fixture::start(&format!("server s {be}"));
    for m in ["PUT", "DELETE", "OPTIONS", "PATCH"] {
        let r = f.send(&format!("{m} /st HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        assert!(r.ends_with("BACKEND"), "{m} must reach the backend, got {r:?}");
        assert!(!r.contains("<html"), "{m} must not get the stats page: {r:?}");
    }
    let r = f.send("GET /st HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(r.contains("<!DOCTYPE html>"), "GET still gets the page: {r:?}");
}

#[test]
fn put_to_the_stats_uri_without_a_backend_server_is_503() {
    let f = Fixture::start("");
    let r = f.send("PUT /st HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    assert!(r.starts_with("HTTP/1.1 503"), "got {r:?}");
}
