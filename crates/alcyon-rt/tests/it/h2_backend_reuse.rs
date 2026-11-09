// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A backend connection is reused across h2 client connections (T313 item 1, VV-10).
//!
//! Every stream of an HTTP/2 frontend is "not the first request" for `http-reuse safe`
//! (`mux_h2.c` sets `SE_FL_NOT_FIRST` on each `h2s`, `backend.c` `be_reuse_connection`), so
//! the second client connection takes the idle connection the first one left. Backend
//! connections opened for 10 h2c connections in a row, one GET each, default `http-reuse`,
//! measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=` runs this on it): 1.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn binary() -> String {
    std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short path")];
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

/// A keep-alive backend answering every request with 5 bytes; counts the connections it
/// accepts.
fn spawn_counting_backend() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    let count = Arc::new(AtomicUsize::new(0));
    let c2 = count.clone();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            c2.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || {
                let (mut req, mut tmp) = (Vec::new(), [0u8; 2048]);
                loop {
                    while let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        req.drain(..i + 4);
                        if c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello").is_err() {
                            return;
                        }
                    }
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&tmp[..n]),
                    }
                }
            });
        }
    });
    (port, count)
}

struct Proxy(Child, tempfile::TempDir);
impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(backend: u16, port: u16) -> Proxy {
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\ndefaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend}\n"
        ),
    )
    .expect("write config");
    let child = Command::new(binary()).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    Proxy(child, dir)
}

/// One h2c connection: `gets` GETs one after the other, each read to its END_STREAM.
fn client_session(port: u16, gets: u32) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    for k in 0..gets {
        let sid = 1 + 2 * k;
        s.write_all(&frame(0x01, 0x05, sid, &hpack_get("/"))).expect("headers");
        'resp: loop {
            while buf.len() >= 9 {
                let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
                if buf.len() < 9 + len {
                    break;
                }
                let (ty, flags) = (buf[3], buf[4]);
                let id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
                buf.drain(..9 + len);
                if id == sid && (ty == 0x00 || ty == 0x01) && flags & 1 != 0 {
                    break 'resp;
                }
            }
            let n = s.read(&mut tmp).expect("response");
            assert!(n > 0, "closed before the response ended");
            buf.extend_from_slice(&tmp[..n]);
        }
    }
}

#[test]
fn sequential_h2_connections_share_one_backend_connection() {
    let (backend, count) = spawn_counting_backend();
    let port = common::reserve_port();
    let _p = start(backend, port);
    for _ in 0..10 {
        client_session(port, 1);
        thread::sleep(Duration::from_millis(60));
    }
    assert_eq!(count.load(Ordering::SeqCst), 1, "backend connections for 10 h2 connections of one GET (HAProxy: 1)");
}

#[test]
fn sequential_gets_on_h2_connections_share_one_backend_connection() {
    let (backend, count) = spawn_counting_backend();
    let port = common::reserve_port();
    let _p = start(backend, port);
    for _ in 0..4 {
        client_session(port, 3);
        thread::sleep(Duration::from_millis(60));
    }
    assert_eq!(count.load(Ordering::SeqCst), 1, "backend connections for 4 h2 connections of 3 GETs (HAProxy: 1)");
}
