// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `balance roundrobin` honours the server weights (T146 item 1).
//!
//! Every sequence below was measured on `HAProxy 3.5-dev8-885761-29` (`nbthread 1`, so a
//! single thread group, one new connection per request) on 2026-10-04. HAProxy's order is
//! that of `fwrr_get_next_server` (`src/lb_fwrr.c`), not the nginx smooth round-robin: each
//! server owns positions in a window of `sum(weights)` slots. A sequence repeats with the
//! period of the sum of the weights, and a weight of 0 takes no traffic.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server answering every request with `X-Server: <name>`.
fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..end + 4);
                        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Server: {name}\r\n\r\nok");
                        if c.write_all(resp.as_bytes()).is_err() {
                            return;
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
    addr
}

fn start(cfg: &str) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let mut text = cfg.replace("{fe}", &fe.to_string());
    for name in ["s1", "s2", "s3"] {
        text = text.replace(&format!("{{{name}}}"), &server(name).to_string());
    }
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon { child, _cfg: f };
    assert!(common::wait_listening(fe), "alcyon never listened on {fe} with:\n{text}");
    (alcyon, fe)
}

fn get(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(std::time::Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let text = String::from_utf8_lossy(&got).into_owned();
    text.split("\r\n")
        // Header names are case-insensitive; HAProxy emits them lowercase (T244).
        .find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case("X-Server")).map(|(_, v)| v))
        .map_or_else(|| text.lines().next().unwrap_or("<nothing>").to_string(), str::to_string)
}

/// The servers that answer `n` requests on a backend with these weights, as one string.
fn sequence(weights: [u32; 3], n: usize) -> String {
    let cfg = format!(
        "global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  timeout server 2s\n\
         frontend f\n  bind {{fe}}\n  default_backend b\nbackend b\n  balance roundrobin\n\
         \x20 server s1 {{s1}} weight {}\n  server s2 {{s2}} weight {}\n  server s3 {{s3}} weight {}\n",
        weights[0], weights[1], weights[2]
    );
    let (_alcyon, fe) = start(&cfg);
    (0..n).map(|_| get(fe)).collect::<Vec<_>>().join(" ")
}

const MEASURED: &[([u32; 3], &str)] = &[
    ([1, 3, 2], "s2 s3 s2 s1 s2 s3 s2 s3 s2 s1 s2 s3 s2 s3 s2 s1 s2 s3 s2 s3 s2 s1 s2 s3"),
    ([5, 1, 1], "s1 s1 s1 s2 s1 s1 s3 s1 s1 s1 s2 s1 s1 s3 s1 s1 s1 s2 s1 s1 s3 s1 s1 s1"),
    (
        [7, 3, 10],
        "s3 s1 s3 s1 s3 s2 s3 s1 s3 s1 s3 s2 s3 s1 s3 s1 s3 s3 s1 s2 s3 s1 s3 s1 s3 s2 s3 s1 s3 s1 s3 s2 s3 s1 s3 s1 s3 s3 s1 s2",
    ),
    ([1, 1, 1], "s1 s2 s3 s1 s2 s3 s1 s2 s3 s1 s2 s3"),
    ([100, 1, 50], "s1 s1 s3 s1 s1 s3 s1 s1 s3 s1 s1 s3 s1 s1 s3 s1 s1 s3"),
    ([2, 0, 3], "s3 s3 s1 s3 s1 s3 s3 s1 s3 s1 s3 s3 s1 s3 s1 s3 s3 s1"),
];

#[test]
fn the_order_is_the_one_haproxy_gives() {
    for (weights, expected) in MEASURED {
        let n = expected.split(' ').count();
        assert_eq!(&sequence(*weights, n), expected, "weights {weights:?}");
    }
}
