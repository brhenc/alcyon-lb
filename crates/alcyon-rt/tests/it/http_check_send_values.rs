// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-check send`: what a `hdr` value writes for an alias, an empty or absent sample,
//! quoted and not; and `send-state` for a backend with no usable server.
//!
//! In a file of its own: the engine keeps the resolved check configuration in a
//! process-wide map keyed by proxy and server index (`alcyon_config::ast::checks`), so two
//! engines with checks in one test binary run each other's checks.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use alcyon_rt::Engine;

type Seen = Arc<Mutex<Vec<String>>>;

/// A server that records every complete request it receives and answers with `status`.
fn capture(status: &'static str) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen: Seen = Arc::default();
    let rec = Arc::clone(&seen);
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let _ = c.set_read_timeout(Some(Duration::from_millis(300)));
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = c.read(&mut buf) {
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&data);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if body.len() >= len {
                        break;
                    }
                }
            }
            if !data.is_empty() {
                rec.lock().expect("lock").push(String::from_utf8_lossy(&data).into_owned());
            }
            let _ = c.write_all(format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").as_bytes());
        }
    });
    (addr, seen)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").expect("hostname").trim().to_string()
}

/// The last request in `seen` containing `marker`.
fn last_with(seen: &Seen, marker: &str) -> Option<String> {
    seen.lock().expect("lock").iter().rev().find(|r| r.contains(marker)).cloned()
}

/// What a `hdr` value writes for each kind of node, and `send-state` when no server is
/// usable.
///
/// Measured on 2026-10-03 against `HAProxy` 3.5-dev8-885761-29 with this configuration
/// (capture servers; the last request each received):
///
/// ```text
/// be1/s1  GET / HTTP/1.1 | x-alias: be1/s1 | x-binq: "" | x-noneq: "" | x-strq: "" |
///         x-lit: lit | connection: close
/// be4/z1  (answers 503, so DOWN; weight 5) GET / HTTP/1.1 | x-haproxy-server-state: DOWN;
///         address=127.0.0.1; port=<z1>; name=be4/z1; node=<hostname>; weight=5/0;
///         scur=0/0; qcur=0 | connection: close
/// ```
///
/// So: an alias (`%b/%s`) writes the backend and server names; an empty binary sample
/// (`bin(61),bytes(1)`) and a sample that does not exist (`var(proc.nope)`) write nothing,
/// and so no header, unless quoted (`%{+Q}`), when they write `""`. With its only server
/// DOWN the backend's total weight is 0.
#[test]
fn http_check_send_hdr_writes_aliases_empty_and_absent_samples_as_haproxy_does() {
    let (p1, seen1) = capture("200 OK");
    let (p4, seen4) = capture("503 Service Unavailable");
    let fe = common::reserve_addr();
    let ck = "check inter 100 rise 1 fall 1";
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind {fe}\n  default_backend be1\n\
         backend be1\n  option httpchk\n  \
         http-check send meth GET uri / ver HTTP/1.1 hdr x-alias %b/%s hdr x-bin %[bin(61),bytes(1)] \
         hdr x-binq %{{+Q}}[bin(61),bytes(1)] hdr x-none %[var(proc.nope)] hdr x-noneq %{{+Q}}[var(proc.nope)] \
         hdr x-strq %{{+Q}}[str()] hdr x-lit lit\n  \
         server s1 {p1} {ck}\n\
         backend be4\n  option httpchk\n  http-check send-state\n  http-check send meth GET uri / ver HTTP/1.1\n  \
         server z1 {p4} {ck} weight 5\n"
    );
    let mut engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    let until = Instant::now() + Duration::from_millis(1200);
    while Instant::now() < until {
        let _ = engine.run_once();
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        last_with(&seen1, "x-alias").as_deref(),
        Some("GET / HTTP/1.1\r\nx-alias: be1/s1\r\nx-binq: \"\"\r\nx-noneq: \"\"\r\nx-strq: \"\"\r\nx-lit: lit\r\nconnection: close\r\n\r\n"),
        "an alias, an empty binary sample and an absent sample in `hdr` values, quoted and not"
    );
    let (node, a4) = (hostname(), p4.port());
    assert_eq!(
        last_with(&seen4, "DOWN").as_deref(),
        Some(format!(
            "GET / HTTP/1.1\r\nx-haproxy-server-state: DOWN; address=127.0.0.1; port={a4}; name=be4/z1; node={node}; \
             weight=5/0; scur=0/0; qcur=0\r\nconnection: close\r\n\r\n"
        ).as_str()),
        "send-state when the backend has no usable server: its total weight is 0"
    );
}
