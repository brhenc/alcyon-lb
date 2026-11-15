// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `balance uri` with the default `hash-type` (map-based), BALURI. Measured on the reference
//! `HAProxy` 3.5-dev8 (`/var/tmp/qwen-next-eval/oracle/haproxy`, 2026-11-15): for each server
//! layout, the answering server's number for the URIs `/p0` .. `/p31`, then `/q?a=1`, `/q?a=2`
//! and `/q` (the query string is not hashed, so the last three land together).
//!
//! `get_server_uh` (`src/backend.c`) hashes the path with `sdbm`, and `map_get_server_hash`
//! (`src/lb_map.c`) takes it modulo `tot_weight` into the interleaved weighted map. Reaches
//! the data path in `lb::balance_uri`, called from `Proxy` server selection (`engine.rs`).

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn backend(id: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            c.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{id}");
        }
    });
    port
}

fn get(port: u16, uri: &str) -> char {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {uri} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

/// The answering server's number for each URI, behind `balance uri` and servers with
/// `weights`; with `s2_down` the second server is `disabled`.
fn answers(weights: &[u32], s2_down: bool) -> String {
    let mut servers = String::new();
    for (i, w) in weights.iter().enumerate() {
        let down = if s2_down && i == 1 { " disabled" } else { "" };
        servers.push_str(&format!("  server s{} 127.0.0.1:{} weight {w}{down}\n", i + 1, backend(i + 1)));
    }
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  balance uri\n{servers}"
    );
    let path = std::env::temp_dir().join(format!("alcyon_baluri_{}_{}_{s2_down}", std::process::id(), weights.len()));
    std::fs::write(&path, cfg).expect("write config");
    let _child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(common::Alcyon)
        .expect("spawn alcyon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let uris = (0..32).map(|i| format!("/p{i}")).chain(["/q?a=1", "/q?a=2", "/q"].map(String::from));
    uris.map(|u| get(port, &u)).collect()
}

#[test]
fn equal_weights_follow_haproxys_map() {
    assert_eq!(answers(&[1, 1, 1, 1], false), "41234123411234123412412341234134333", "four servers");
    assert_eq!(answers(&[1, 1, 1], false), "23123123123123123123123123123123222", "three servers");
    assert_eq!(answers(&[1, 1, 1, 1, 1], false), "23451234515123451234451234512334222", "five servers");
}

#[test]
fn unequal_weights_interleave_like_haproxys_map() {
    assert_eq!(answers(&[1, 2, 3], false), "32323132322323132323323132323123222", "weights 1 2 3");
    assert_eq!(answers(&[10, 20, 5], false), "31221223122122312212223122122331222", "weights 10 20 5");
}

#[test]
fn a_server_down_is_left_out_of_the_map() {
    assert_eq!(answers(&[1, 1, 1, 1], true), "34134134134134134134134134134134333");
}
