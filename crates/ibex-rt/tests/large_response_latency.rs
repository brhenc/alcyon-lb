// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// T185: a 64 KB / 256 KB response (or request body) on a kept-alive connection must not wait
// on Nagle / delayed ACK. HAProxy answers in well under a millisecond here; Ibex took ~41 ms.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Origin: keep-alive, answers every request with `size` bytes, reading any request body.
fn origin(size: usize) -> SocketAddr {
    let addr = common::reserve_addr();
    let listener = TcpListener::bind(addr).expect("bind origin");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 65536];
                loop {
                    let head_end = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        match s.read(&mut tmp) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                    let clen = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    while buf.len() < head_end + clen {
                        match s.read(&mut tmp) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    buf.drain(..head_end + clen);
                    let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").into_bytes();
                    resp.extend(std::iter::repeat(b'x').take(size));
                    if s.write_all(&resp).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn spawn_ibex(tag: &str, be: SocketAddr) -> (common::Ibex, SocketAddr, std::path::PathBuf) {
    let fe = common::reserve_addr();
    let path = std::env::temp_dir().join(format!("ibex_lrl_{tag}_{}.cfg", std::process::id()));
    let cfg = format!(
        "defaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\nfrontend fe\n    bind {fe}\n    default_backend be\nbackend be\n    server s1 {be}\n"
    );
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex did not listen");
    (child, fe, path)
}

/// Sends `req` and reads one complete response; returns the elapsed time.
fn round_trip(c: &mut TcpStream, req: &[u8], body_len: usize) -> Duration {
    let t = Instant::now();
    c.write_all(req).expect("write");
    let mut got = Vec::new();
    let mut tmp = [0u8; 65536];
    let head_end = loop {
        if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = c.read(&mut tmp).expect("read head");
        assert!(n > 0, "eof in head");
        got.extend_from_slice(&tmp[..n]);
    };
    while got.len() < head_end + body_len {
        let n = c.read(&mut tmp).expect("read body");
        assert!(n > 0, "eof in body");
        got.extend_from_slice(&tmp[..n]);
    }
    t.elapsed()
}

fn median_of_five(fe: SocketAddr, req: &[u8], body_len: usize) -> Duration {
    let mut times = Vec::new();
    for _ in 0..5 {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_nodelay(true).expect("nodelay");
        c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        // the first request opens the backend connection; the two after it are on a warm pair
        round_trip(&mut c, req, body_len);
        let a = round_trip(&mut c, req, body_len);
        let b = round_trip(&mut c, req, body_len);
        times.push(a.max(b));
    }
    times.sort();
    times[2]
}

fn check(size: usize, req: &[u8]) {
    let be = origin(size);
    let (mut child, fe, path) = spawn_ibex(&format!("{size}_{}", req.len()), be);
    let med = median_of_five(fe, req, size);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    assert!(med < Duration::from_millis(15), "{size}-byte exchange on a kept-alive connection took {med:?} (median of 5)");
}

#[test]
fn response_64k_keepalive_is_not_delayed() {
    check(65536, b"GET /64k HTTP/1.1\r\nHost: x\r\n\r\n");
}

#[test]
fn response_256k_keepalive_is_not_delayed() {
    check(262144, b"GET /256k HTTP/1.1\r\nHost: x\r\n\r\n");
}

#[test]
fn request_body_64k_keepalive_is_not_delayed() {
    let mut req = b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n".to_vec();
    req.extend(std::iter::repeat(b'y').take(65536));
    check(16, &req);
}
