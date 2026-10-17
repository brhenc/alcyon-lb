// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: show info Listeners, MaxconnReached

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts ibex on `cfg` (`{sock}` is replaced by the stats socket path), waits for `addrs` and the
/// socket, then lets the readiness probes slide out of the one-second windows and clears the maxima.
fn start(tag: &str, cfg: &str, addrs: &[SocketAddr]) -> (Ibex, String) {
    let dir = std::env::temp_dir().join(format!("qh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg.replace("{sock}", &sock).replace("{dir}", &dir.display().to_string())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, dir);
    for a in addrs {
        assert!(common::wait_listening(*a), "ibex did not listen on {a}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(2200));
    cli(&sock, "clear counters");
    (ibex, sock)
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

/// One request on a new connection; the whole raw answer.
fn get(addr: SocketAddr, req: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

fn http_cfg(global: &str, body: &str) -> String {
    format!(
        "global\n  stats socket {{sock}} level admin\n{global}\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n{body}"
    )
}

#[test]
fn show_info_listeners_maxconn_reached() {
    let a: SocketAddr = "127.0.0.1:18001".parse().unwrap();
    let b: SocketAddr = "127.0.0.1:18002".parse().unwrap();
    let c: SocketAddr = "127.0.0.1:18003".parse().unwrap();
    let cfg = http_cfg("  nbthread 4\n  maxconn 8\n", &format!("frontend fe\n  bind {a}\n  bind {b}\n  http-request return status 200\nfrontend fe2\n  bind {c}\n  http-request return status 200\n"));
    let (_ibex, sock) = start("lmc", &cfg, &[a, b, c]);

    let info_map = info(&sock);

    // Listeners: 2 frontends with 3 bind lines total + 1 stats socket = 4
    assert_eq!(num(&info_map, "Listeners"), 4, "Listeners should be 4 (3 binds + 1 stats socket)");

    // MaxconnReached should be 0 at start
    assert_eq!(num(&info_map, "MaxconnReached"), 0, "MaxconnReached should be 0 at start");

    // Open 8 connections (maxconn 8) and keep them open
    let mut streams: Vec<TcpStream> = Vec::with_capacity(8);
    for _ in 0..8 {
        let s = TcpStream::connect(a).expect("connect");
        streams.push(s);
    }

    std::thread::sleep(Duration::from_millis(300));

    let info_map = info(&sock);
    let reached = num(&info_map, "MaxconnReached");
    assert!(reached >= 1, "MaxconnReached should be >= 1 after 8 connections with maxconn 8, got {reached}");
    assert!(reached <= 8, "MaxconnReached should be <= 8, got {reached}");

    // Drop the connections
    drop(streams);

    // clear counters all should NOT reset MaxconnReached
    cli(&sock, "clear counters all");
    let info_map = info(&sock);
    let reached = num(&info_map, "MaxconnReached");
    assert!(reached >= 1, "MaxconnReached should still be >= 1 after clear counters all, got {reached}");
}
