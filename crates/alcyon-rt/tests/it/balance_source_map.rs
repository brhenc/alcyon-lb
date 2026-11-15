// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `balance source` with the default `hash-type` (map-based), T634 item 2. Measured on the
//! reference `HAProxy` 3.5-dev8-885761-29 (`/home/bhenc/ibex-worktrees/agy-eval/oracle/haproxy`,
//! 2026-11-15): for each server layout, the answering server's number for 32 clients bound to
//! `127.0.0.1` .. `127.0.0.32`, and for IPv6 client addresses over `accept-proxy`.
//!
//! `get_server_sh` (`src/backend.c`) XORs the address's 32-bit big-endian words (`ntohl`, no
//! avalanche in `map-based` mode) and `map_get_server_hash` (`src/lb_map.c`) indexes the
//! interleaved [`lb::WeightMap`] modulo `tot_weight`. Reaches the data path in
//! `lb::balance_source`, called from `Proxy::select_server_with_key_idx` (`engine.rs`).

use crate::common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static RUN: AtomicUsize = AtomicUsize::new(0);

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

fn from(src: &str, port: u16) -> char {
    let fd = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .expect("socket");
    rustix::net::bind(&fd, &format!("{src}:0").parse::<SocketAddr>().expect("addr")).expect("bind source");
    rustix::net::connect(&fd, &format!("127.0.0.1:{port}").parse::<SocketAddr>().expect("addr")).expect("connect");
    let mut s = TcpStream::from(fd);
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

fn from_v6_proxy(v6_src: &str, port: u16) -> char {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(
        s,
        "PROXY TCP6 {v6_src} ::1 50000 80\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

/// The answering server's number for `127.0.0.1` .. `127.0.0.32` behind `balance source` and
/// servers with `weights`; with `s2_down` the second server is `disabled`.
fn answers(weights: &[u32], s2_down: bool) -> String {
    let mut servers = String::new();
    for (i, w) in weights.iter().enumerate() {
        let down = if s2_down && i == 1 { " disabled" } else { "" };
        let _ = writeln!(servers, "  server s{} 127.0.0.1:{} weight {w}{down}", i + 1, backend(i + 1));
    }
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  default_backend be\n\
         backend be\n  balance source\n{servers}"
    );
    let path = std::env::temp_dir().join(format!(
        "alcyon_balsrc_map_{}_{}",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
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
    let got: String = (1..=32).map(|n| from(&format!("127.0.0.{n}"), port)).collect();
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    got
}

/// The answering server's number for each IPv6 source in `v6_srcs` behind `balance source` and
/// servers with `weights`.
fn answers_v6(weights: &[u32], v6_srcs: &[&str]) -> String {
    let mut servers = String::new();
    for (i, w) in weights.iter().enumerate() {
        let _ = writeln!(servers, "  server s{} 127.0.0.1:{} weight {w}", i + 1, backend(i + 1));
    }
    let port = common::reserve_port();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind 127.0.0.1:{port} accept-proxy\n  default_backend be\n\
         backend be\n  balance source\n{servers}"
    );
    let path = std::env::temp_dir().join(format!(
        "alcyon_balsrc_map_v6_{}_{}",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
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
    let got: String = v6_srcs.iter().map(|s| from_v6_proxy(s, port)).collect();
    common::stop(&mut child);
    let _ = std::fs::remove_file(&path);
    got
}

#[test]
fn source_follows_haproxys_weighted_map() {
    assert_eq!(answers(&[1, 1, 1, 1], false), "23412341234123412341234123412341", "four equal servers");
    assert_eq!(answers(&[1, 1, 1], false), "31231231231231231231231231231231", "three equal servers");
    assert_eq!(answers(&[1, 1, 1, 1, 1], false), "45123451234512345123451234512345", "five equal servers");
    assert_eq!(answers(&[1, 2, 3], false), "31323231323231323231323231323231", "weights 1 2 3");
    assert_eq!(answers(&[10, 20, 5], false), "21223122122312212231221223122122", "weights 10 20 5");
}

#[test]
fn a_server_down_is_left_out_of_the_weighted_map() {
    assert_eq!(answers(&[1, 1, 1, 1], true), "41341341341341341341341341341341", "weights 1 1 1 1, s2 down");
    assert_eq!(answers(&[1, 2, 3], true), "33313331333133313331333133313331", "weights 1 2 3, s2 down");
    assert_eq!(answers(&[1, 2, 3, 4], true), "43434341434343414343434143434341", "weights 1 2 3 4, s2 down");
}

#[test]
fn ipv6_sources_xor_words_into_the_weighted_map() {
    let srcs = [
        "::1",
        "::2",
        "::1:0",
        "::2:0",
        "2001:db8::1",
        "2001:db8:1::1",
        "fe80::1:2:3:4",
        "fd00:1234:5678:9abc:def0:1234:5678:9abc",
    ];
    assert_eq!(answers_v6(&[1, 1, 1, 1], &srcs), "23112231", "four equal servers, IPv6");
    assert_eq!(answers_v6(&[1, 2, 3], &srcs), "32223312", "weights 1 2 3, IPv6");
}
