// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `send-proxy-v2 proxy-v2-options unique-id`: the TLVs a server receives, as the reference
//! `HAProxy` (3.5-dev8-885761-29) sent them for this configuration, measured 2026-10-03 with
//! a listener decoding the PROXY v2 header:
//!
//! ```text
//! http, unique-id-format ID-%[req.hdr(in)]-%ci, `in: foo`   tlvs [(0x05, "ID-foo-127.0.0.1")]
//! tcp,  unique-id-format T-%ci                              tlvs [(0x05, "T-127.0.0.1")]
//! tcp,  no unique-id-format                                 tlvs [(0x05, "")]
//! ```
//!
//! and nothing else: no other TLV, the request or the TCP payload right after the header.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

/// One accepted connection: its PROXY v2 TLVs as (type, value), and the bytes after them.
type Seen = (Vec<(u8, Vec<u8>)>, Vec<u8>);

fn decode(d: &[u8]) -> Option<Seen> {
    let len = usize::from(u16::from_be_bytes([*d.get(14)?, *d.get(15)?]));
    let end = 16 + len;
    let addrs = match d.get(13)? & 0xf0 {
        0x10 => 12,
        0x20 => 36,
        _ => 0,
    };
    let mut tlvs = Vec::new();
    let mut t = d.get(16 + addrs..end)?;
    while t.len() >= 3 {
        let l = usize::from(u16::from_be_bytes([t[1], t[2]]));
        tlvs.push((t[0], t.get(3..3 + l)?.to_vec()));
        t = &t[3 + l..];
    }
    Some((tlvs, d[end..].to_vec()))
}

fn server(n: usize) -> (SocketAddr, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for mut c in listener.incoming().take(n).flatten() {
            let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
            let mut d = Vec::new();
            let mut buf = [0u8; 4096];
            // The header, then whatever the first read after it brings.
            while let Ok(k) = c.read(&mut buf) {
                if k == 0 {
                    break;
                }
                d.extend_from_slice(&buf[..k]);
                if d.len() >= 16 && d.len() > 16 + usize::from(u16::from_be_bytes([d[14], d[15]])) {
                    break;
                }
            }
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            if let Some(seen) = decode(&d) {
                let _ = tx.send(seen);
            }
        }
    });
    (addr, rx)
}

#[test]
fn the_unique_id_travels_in_tlv_0x05_as_haproxy_sends_it() {
    let (srv, seen) = server(3);
    let (h, t, n) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "defaults\n  timeout client 2s\n  timeout server 2s\n  timeout connect 2s\n\
         listen h\n  mode http\n  bind {h}\n  unique-id-format ID-%[req.hdr(in)]-%ci\n  \
         server s {srv} send-proxy-v2 proxy-v2-options unique-id\n\
         listen t\n  mode tcp\n  bind {t}\n  unique-id-format T-%ci\n  \
         server s {srv} send-proxy-v2 proxy-v2-options unique-id\n\
         listen n\n  mode tcp\n  bind {n}\n  server s {srv} send-proxy-v2 proxy-v2-options unique-id\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let client = thread::spawn(move || {
        for (addr, data) in [
            (h, &b"GET /x HTTP/1.1\r\nhost: a\r\nin: foo\r\nconnection: close\r\n\r\n"[..]),
            (t, b"tcpdata"),
            (n, b"z"),
        ] {
            let mut c = TcpStream::connect(addr).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
            c.write_all(data).expect("send");
            let mut out = [0u8; 256];
            let _ = c.read(&mut out);
        }
    });
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while got.len() < 3 && Instant::now() < deadline {
        let _ = engine.run_once();
        if let Ok(s) = seen.try_recv() {
            got.push(s);
        }
        thread::sleep(Duration::from_millis(1));
    }
    client.join().expect("client");
    assert_eq!(got.len(), 3, "three connections reached the server: {got:?}");
    assert_eq!(got[0].0, [(5, b"ID-foo-127.0.0.1".to_vec())]);
    assert!(got[0].1.starts_with(b"GET /x HTTP/1.1\r\n"), "{:?}", String::from_utf8_lossy(&got[0].1));
    assert_eq!(got[1], (vec![(5, b"T-127.0.0.1".to_vec())], b"tcpdata".to_vec()));
    assert_eq!(got[2], (vec![(5, Vec::new())], b"z".to_vec()));
}
