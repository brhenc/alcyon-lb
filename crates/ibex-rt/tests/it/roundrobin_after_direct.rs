// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The round robin's order around requests a persistence cookie sent directly (T233).
//!
//! `HAProxy`'s weighted round robin (`lb_fwrr.c`) moves a server only when
//! `fwrr_get_next_server` picks it (`fwrr_update_position`), or on a weight or state change.
//! A request a cookie sends straight to a server (`SF_DIRECT`) never enters the balancer, so
//! it leaves the order where it was. Measured on `HAProxy 3.5-dev8-885761-29` (2026-10-10)
//! with `thread-groups 1`, `Connection: close` requests, `*` marking a cookie request:
//!
//! - weights 1/1, `*s1 x5` then 4: `s1 s2 s1 s2`.
//! - weights 1/1: `- *s2 - *s2 - *s1 - - *s1 -` gives `s1 s2 s1 s2 s1 s2`.
//! - weights 3/1, `*s2 x3` then 8: `s1 s1 s1 s2 s1 s1 s1 s2`.
//! - weights 2/3: `*s1 - - *s2 - - - *s1 *s1 - - - -` gives `s2 s2 s1 s2 s1 s2 s2 s1 s2`.
//!
//! Without `thread-groups 1` the oracle on a 64-CPU host runs 8 thread groups, each with its
//! own tree, and the order depends on which group accepted each connection: that is where
//! T225's "all 4 cookieless requests went to s2" came from, not from the direct requests.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A server that answers every request with its name as the body.
fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("server");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                    while let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        got.drain(..i + 4);
                        let r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{name}", name.len());
                        if s.write_all(r.as_bytes()).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Sends `seq` (`-` without a cookie, else the cookie value), one `Connection: close`
/// request each, to an Ibex with weights `w1`/`w2`; returns the server that answered each
/// request without a cookie.
fn balanced(w1: u32, w2: u32, seq: &[&str]) -> Vec<String> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let (s1, s2) = (server("s1"), server("s2"));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 2s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  balance roundrobin\n  cookie SRV insert indirect nocache\n\
         \x20 server s1 {s1} cookie s1 weight {w1}\n  server s2 {s2} cookie s2 weight {w2}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex-rrd-{}-{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _ibex = Ibex(child);
    assert!(common::wait_listening(fe), "ibex never listened");
    let _ = std::fs::remove_file(&path);

    let mut out = Vec::new();
    for t in seq {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
        let ck = if *t == "-" { String::new() } else { format!("Cookie: SRV={t}\r\n") };
        c.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\n{ck}Connection: close\r\n\r\n").as_bytes()).expect("send");
        let mut got = Vec::new();
        let _ = c.read_to_end(&mut got);
        let got = String::from_utf8_lossy(&got).into_owned();
        let body = got.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        if *t == "-" {
            out.push(body);
        } else {
            assert_eq!(&body, t, "the cookie request went to its server");
        }
    }
    out
}

#[test]
fn direct_requests_leave_the_order_of_equal_weights_alone() {
    let mut seq = vec!["s1"; 5];
    seq.extend(["-"; 4]);
    assert_eq!(balanced(1, 1, &seq), ["s1", "s2", "s1", "s2"]);
    assert_eq!(balanced(1, 1, &["-", "s2", "-", "s2", "-", "s1", "-", "-", "s1", "-"]), ["s1", "s2", "s1", "s2", "s1", "s2"]);
}

#[test]
fn direct_requests_leave_the_weighted_order_alone() {
    let mut seq = vec!["s2"; 3];
    seq.extend(["-"; 8]);
    assert_eq!(balanced(3, 1, &seq), ["s1", "s1", "s1", "s2", "s1", "s1", "s1", "s2"]);
    let seq = ["s1", "-", "-", "s2", "-", "-", "-", "s1", "s1", "-", "-", "-", "-"];
    assert_eq!(balanced(2, 3, &seq), ["s2", "s2", "s1", "s2", "s1", "s2", "s2", "s1", "s2"]);
}
