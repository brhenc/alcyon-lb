// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T491: a request the proxy answers itself (`deny`, `redirect`, `auth`, `return`) between two
//! forwarded requests of one keep-alive client connection leaves the server connection alone:
//! `HAProxy` serves the third request on the same one (same local port, one `connect` on the
//! server). `T491_BIN` replaces the binary under test (to run the same cases on `HAProxy`).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn backend(accepted: Arc<AtomicUsize>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            accepted.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let peer = c.peer_addr().unwrap();
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let (mut pending, mut b) = (Vec::new(), [0u8; 4096]);
                loop {
                    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        pending.drain(..end + 4);
                        let r = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nx-peer: {}\r\n\r\nok", peer.port());
                        if c.write_all(r.as_bytes()).is_err() {
                            return;
                        }
                    }
                    match c.read(&mut b) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pending.extend_from_slice(&b[..n]),
                    }
                }
            });
        }
    });
    addr
}

fn get(c: &mut TcpStream, path: &str) -> (String, String) {
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes()).unwrap();
    let (mut got, mut b) = (Vec::new(), [0u8; 4096]);
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..end]).into_owned();
            let want: usize = head.to_ascii_lowercase().lines().find_map(|l| l.strip_prefix("content-length: ").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
            if got.len() >= end + 4 + want {
                return (head.lines().next().unwrap().to_string(), head);
            }
        }
        let n = c.read(&mut b).unwrap_or(0);
        assert!(n > 0, "the answer stopped short: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&b[..n]);
    }
}

fn peer(head: &str) -> String {
    head.lines().find_map(|l| l.strip_prefix("x-peer: ")).expect("x-peer").to_string()
}

fn run(tag: &str, rule: &str, path: &str, status: &str) {
    run_proto(tag, rule, path, status, false);
}

fn run_proto(tag: &str, rule: &str, path: &str, status: &str, h2: bool) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let be = backend(accepted.clone());
    let a = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("t491-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let proto = if h2 { " proto h2" } else { "" };
    let cfg = dir.join("c.cfg");
    std::fs::write(
        &cfg,
        format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
             frontend fe\n  bind {a}{proto}\n  acl lr path {path}\n  {rule}\n  default_backend b\nbackend b\n  server s {be}\n"
        ),
    )
    .unwrap();
    let bin = std::env::var("T491_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _g = Ibex(child, dir);
    assert!(common::wait_listening(a));
    let mut c = TcpStream::connect(a).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    if h2 {
        for (k, p) in ["/", path, "/"].iter().enumerate() {
            h2_get(&mut c, p, u32::try_from(k).unwrap());
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "{tag}: connects to the server");
        return;
    }
    let (_, h1) = get(&mut c, "/");
    let (st, _) = get(&mut c, path);
    assert!(st.contains(status), "{st}");
    let (_, h3) = get(&mut c, "/");
    assert_eq!(peer(&h1), peer(&h3), "{tag}: the third request is on another server connection");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "{tag}: connects to the server");
}

#[test]
fn deny() {
    run("deny", "http-request deny if lr", "/x", "403");
}

#[test]
fn redirect() {
    run("redir", "http-request redirect location /y if lr", "/x", "302");
}

#[test]
fn auth() {
    run("auth", "http-request auth realm r if lr", "/x", "401");
}

#[test]
fn local_return() {
    run("ret", "http-request return status 200 content-type text/plain string hi if lr", "/x", "200");
}

fn frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap();
    let mut v = len.to_be_bytes()[1..].to_vec();
    v.extend_from_slice(&[ftype, flags]);
    v.extend_from_slice(&sid.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Sends the k-th GET of an h2c connection (the first sends the preface) and reads its
/// answer to `END_STREAM`.
fn h2_get(c: &mut TcpStream, path: &str, k: u32) {
    if k == 0 {
        c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        c.write_all(&frame(4, 0, 0, &[])).unwrap();
    }
    let sid = 1 + 2 * k;
    let mut blk = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).unwrap()];
    blk.extend_from_slice(path.as_bytes());
    blk.extend_from_slice(&[0x01, 9]);
    blk.extend_from_slice(b"localhost");
    c.write_all(&frame(1, 5, sid, &blk)).unwrap();
    let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
    loop {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (ty, flags) = (buf[3], buf[4]);
            let id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            buf.drain(..9 + len);
            if id == sid && (ty == 0 || ty == 1) && flags & 1 != 0 {
                return;
            }
        }
        let n = c.read(&mut tmp).unwrap_or(0);
        assert!(n > 0, "closed before the response ended");
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[test]
fn h2_deny() {
    run_proto("h2deny", "http-request deny if lr", "/x", "", true);
}
