// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: `show info` `Listeners` and `MaxconnReached`.

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts alcyon on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Alcyon, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let alcyon = Alcyon(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "alcyon did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (alcyon, sock)
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn info(sock: &str) -> HashMap<String, String> {
    cli(sock, "show info").lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn num(i: &HashMap<String, String>, k: &str) -> u64 {
    i.get(k).unwrap_or_else(|| panic!("show info has no {k}")).parse().unwrap_or_else(|_| panic!("{k} is not a number: {:?}", i[k]))
}

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

#[test]
fn show_info_listeners() {
    let (a, b, c) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = http_cfg("  nbthread 4\n  maxconn 8\n", &format!("frontend fe\n  bind {a}\n  bind {b}\n  http-request return status 200\nfrontend fe2\n  bind {c}\n  http-request return status 200\n"));
    let (_alcyon, sock) = start("lst", &cfg, &[a, b, c]);
    // 3 bind lines + 1 stats socket, as the oracle gives with `nbthread 4` (one thread group).
    assert_eq!(num(&info(&sock), "Listeners"), 4);
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).expect("connect");
    std::thread::sleep(Duration::from_millis(50));
    s
}

/// `MaxconnReached` counts every accept, refused ones and stats-socket ones included, made
/// while `actconn + 1 >= maxconn` (listener.c): the last two slots. Every number below was
/// measured on the oracle (3.5-dev8) with this exact sequence; each `show info` is itself a
/// counted accept once 7 or more connections are held.
#[test]
fn show_info_maxconn_reached() {
    let (a, r) = (common::reserve_addr(), common::reserve_addr());
    let cfg = http_cfg(
        "  nbthread 1\n  maxconn 8\n",
        &format!("frontend fe\n  bind {a}\n  http-request return status 200\nfrontend rej\n  bind {r}\n  tcp-request connection reject\n"),
    );
    let (_alcyon, sock) = start("mcr", &cfg, &[a, r]);
    let reached = || num(&info(&sock), "MaxconnReached");
    assert_eq!(reached(), 0, "at start");

    let mut held: Vec<TcpStream> = (0..6).map(|_| connect(a)).collect();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached(), 0, "6 held of 8: 6 + 1 < 8");

    for _ in 0..3 {
        let mut s = connect(r);
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let _ = s.read(&mut [0u8; 16]);
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached(), 3, "3 connections refused by tcp-request connection reject at 6 held");

    held.push(connect(a));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached(), 5, "7th connection + this show info");
    assert_eq!(reached(), 6, "one more show info at 7 held");
    held.push(connect(a));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(reached(), 8, "8th connection + this show info");

    drop(held);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(reached(), 8, "not counted once the connections closed");
    cli(&sock, "clear counters all");
    assert_eq!(reached(), 8, "clear counters all does not reset it");
}
