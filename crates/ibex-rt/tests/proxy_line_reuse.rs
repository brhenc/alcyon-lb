// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A server connection opened with a PROXY header carries the next request only if that
//! request would send the same header. `HAProxy` hashes the PROXY line into the connection's
//! reuse key (`be_reuse_connection` / `conn_hash_prehash`, `src/backend.c`, step 5), so a
//! `proxy-v2-options unique-id` header that differs per request opens a new connection.
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, 2026-10-03: one client connection, two
//! keep-alive requests, `unique-id-format ID-%[req.hdr(in)]`, a server decoding the PROXY v2
//! header of each connection it accepts and counting the requests on it:
//!
//! ```text
//! send-proxy-v2 proxy-v2-options unique-id, in: foo then bar   [(TLV 0x05 "ID-foo", 1 request), (TLV 0x05 "ID-bar", 1 request)]
//! send-proxy-v2 proxy-v2-options unique-id, in: foo then foo   [(TLV 0x05 "ID-foo", 2 requests)]
//! send-proxy-v2, in: foo then bar                              [(no TLV, 2 requests)]
//! ```
//!
//! This is what `reg-tests/connection/proxy_protocol_send_unique_id.vtc` checks on its
//! second request.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

/// Per accepted connection: the PROXY v2 TLVs it opened with, and how many requests it
/// carried.
type Seen = Vec<(Vec<(u8, Vec<u8>)>, usize)>;
type Conns = Arc<Mutex<Seen>>;

fn server() -> (SocketAddr, Conns) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let conns: Conns = Arc::default();
    let seen = Arc::clone(&conns);
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let seen = Arc::clone(&seen);
            thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(3)));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let mut slot = None;
                loop {
                    if slot.is_none() && buf.len() >= 16 {
                        let end = 16 + usize::from(u16::from_be_bytes([buf[14], buf[15]]));
                        if buf.len() >= end {
                            // IPv4 addresses and ports, then the TLVs.
                            let mut t = &buf[28.min(end)..end];
                            let mut tlvs = Vec::new();
                            while t.len() >= 3 {
                                let l = usize::from(u16::from_be_bytes([t[1], t[2]]));
                                tlvs.push((t[0], t[3..(3 + l).min(t.len())].to_vec()));
                                t = &t[(3 + l).min(t.len())..];
                            }
                            let mut all = seen.lock().expect("lock");
                            all.push((tlvs, 0));
                            slot = Some(all.len() - 1);
                            drop(all);
                            buf.drain(..end);
                            continue;
                        }
                    }
                    if let Some(i) = slot {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            buf.drain(..p + 4);
                            seen.lock().expect("lock")[i].1 += 1;
                            if c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").is_err() {
                                return;
                            }
                            continue;
                        }
                    }
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
            });
        }
    });
    (addr, conns)
}

/// Two requests on one client connection, with `in: first` and `in: second`; what the
/// server saw.
fn run(options: &str, first: &str, second: &str) -> Seen {
    let (srv, conns) = server();
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         listen l\n  bind {fe}\n  unique-id-format ID-%[req.hdr(in)]\n  \
         server s {srv} send-proxy-v2 {options}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    for v in [first, second] {
        c.write_all(format!("GET / HTTP/1.1\r\nhost: a\r\nin: {v}\r\n\r\n").as_bytes()).expect("send");
        let mut resp = Vec::new();
        let mut buf = [0u8; 1024];
        while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
            match c.read(&mut buf) {
                Ok(n) if n > 0 => resp.extend_from_slice(&buf[..n]),
                _ => break,
            }
        }
        assert!(resp.starts_with(b"HTTP/1.1 200"), "in: {v}: {:?}", String::from_utf8_lossy(&resp));
    }
    thread::sleep(Duration::from_millis(200));
    common::stop(&mut child);
    let seen = conns.lock().expect("lock").clone();
    seen
}

#[test]
fn a_request_whose_proxy_header_differs_gets_its_own_connection() {
    assert_eq!(
        run("proxy-v2-options unique-id", "foo", "bar"),
        [(vec![(5, b"ID-foo".to_vec())], 1), (vec![(5, b"ID-bar".to_vec())], 1)],
        "the second request went out on the connection opened with the first one's PROXY \
         header, so the server took it for ID-foo"
    );
}

/// The controls: the same header, and a header with nothing per request, keep the
/// connection.
#[test]
fn a_request_with_the_same_proxy_header_keeps_the_connection() {
    assert_eq!(run("proxy-v2-options unique-id", "foo", "foo"), [(vec![(5, b"ID-foo".to_vec())], 2)]);
    assert_eq!(run("", "foo", "bar"), [(vec![], 2)]);
}
