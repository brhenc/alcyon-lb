// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `stats show-desc` / `stats show-node` reach the stats page: HAProxy 3.5-dev8 prints
//! "Statistics Report for pid N[ on <node>][: <desc>]" (desc unescaped) and puts " on <node>"
//! in the page title. Only the proxy serving the page counts.

mod common;

use ibex_config::parse_str;
use ibex_rt::Engine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn page(extra: &str) -> String {
    let addr = common::reserve_addr();
    let cfg = parse_str(&format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         listen l\n  bind {addr}\n  stats enable\n  stats uri /\n{extra}\
         listen other\n  bind 127.0.0.1:0\n  stats enable\n  stats show-node other-node\n"
    ))
    .expect("parse");
    let mut engine = Engine::new(&cfg, 64).expect("engine");
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_nonblocking(true).unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(3) {
        let _ = engine.run_once().expect("step");
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn node_and_desc_are_in_the_heading_and_title() {
    let h = page("  stats show-desc primary  load <b>balancer\n  stats show-node lb1\n");
    assert!(h.contains(" on lb1</title>"), "title");
    assert!(h.contains(" on lb1: primary load <b>balancer</h2>"), "heading");
    assert!(!h.contains("other-node"));
}

#[test]
fn desc_alone_and_neither() {
    let h = page("  stats show-desc only desc\n");
    assert!(h.contains(">Statistics Report for pid ") && h.contains(": only desc</h2>"));
    assert!(!h.contains(" on "), "no node");
    let h = page("");
    assert!(h.contains("</h2>") && !h.contains(": </h2>"));
}

#[test]
fn node_without_a_name_is_the_host_name() {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    let h = page("  stats show-node\n");
    assert!(h.contains(&format!(" on {}</h2>", host.trim())));
}
