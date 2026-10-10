// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `balance source` with `hash-type consistent` (T131). Measured on the reference
//! `HAProxy` 3.5-dev8-885761-29: three servers `s1 s2 s3` (weight 1), 32 clients from
//! 127.0.0.1 .. 127.0.0.32, the answering server's number for each:
//! `21312131132333111311122111131121`.
//!
//! `get_server_sh` (`src/backend.c`): the key is the XOR of the address' 32-bit words in
//! host order, avalanched by `full_hash`, and the server is the one owning the nearest
//! point of the same ring `balance uri` uses. Reaches the data path in
//! `Proxy::select_server_with_key` (`proxy.rs`), the call of every connect and retry.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn backend(id: u8) -> u16 {
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
    let fd = rustix::net::socket(rustix::net::AddressFamily::INET, rustix::net::SocketType::STREAM, None).expect("socket");
    rustix::net::bind(&fd, &format!("{src}:0").parse::<SocketAddr>().expect("addr")).expect("bind source");
    rustix::net::connect(&fd, &format!("127.0.0.1:{port}").parse::<SocketAddr>().expect("addr")).expect("connect");
    let mut s = TcpStream::from(fd);
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

/// The answering server's number for 127.0.0.1 .. 127.0.0.32, or `x` for a failure.
fn answers(extra: &str, s1_dead: bool) -> String {
    answers_from(extra, s1_dead, false)
}

/// [`answers`], or with `v6` the one client `::1` on a `[::1]` listener.
fn answers_from(extra: &str, s1_dead: bool, v6: bool) -> String {
    let mut b: Vec<u16> = (1..=3).map(backend).collect();
    if s1_dead {
        b[0] = common::reserve_port();
    }
    let port = common::reserve_port();
    let host = if v6 { "[::1]" } else { "127.0.0.1" };
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {host}:{port}\n  default_backend be\n\
         backend be\n  balance source\n  hash-type consistent\n{extra}  server s1 127.0.0.1:{}\n  server s2 127.0.0.1:{}\n  server s3 127.0.0.1:{}\n",
        b[0], b[1], b[2]
    );
    let path = std::env::temp_dir().join(format!("ibex_t131_src_{}_{s1_dead}_{v6}", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect((if v6 { "::1" } else { "127.0.0.1" }, port)).is_err() {
        assert!(Instant::now() < deadline, "the daemon never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    let got: String = if v6 {
        let mut s = TcpStream::connect(("::1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out.chars().last().into_iter().collect()
    } else {
        (1..=32).map(|n| from(&format!("127.0.0.{n}"), port)).collect()
    };
    common::stop(&mut child);
    let _ = std::fs::remove_file(path);
    got
}

#[test]
fn source_follows_the_consistent_hash_ring() {
    assert_eq!(answers("", false), "21312131132333111311122111131121");
}

/// `option redispatch`, `retries 1`, `s1` closed (same clients, measured on the reference):
/// the retry asks the ring for a server other than the one that failed (`avoid` in
/// `chash_get_server_hash`), so every client whose key falls on `s1` is answered by
/// the next one along the ring and nobody sees a 503.
#[test]
fn a_redispatch_walks_the_ring_past_the_failed_server() {
    assert_eq!(
        answers("  option redispatch\n  retries 1\n", true),
        "23322233332333323333322222232323"
    );
}

/// One IPv6 client, `::1` (the only address the loopback has): the words of the address
/// are XORed the same way. Measured on the reference: server 3.
#[test]
fn an_ipv6_source_hashes_like_an_ipv4_one() {
    assert_eq!(answers_from("", false, true), "3");
}
