// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `wretr` and `wredis` columns of `show stat` (T131), measured on the reference
//! `HAProxy` 3.5-dev8-885761-29 with `retries 1`, `timeout connect 300ms`:
//!
//! * a backend with one closed port, one request (503): server `wretr=1 wredis=0`, backend
//!   `wretr=1 wredis=0`;
//! * `option redispatch`, `balance roundrobin`, a closed port then a live one, two requests
//!   (200, 200) each of which first picked the closed port: the closed server shows
//!   `wredis=2` (a redispatch is counted on the server that failed), the live one `0`, the
//!   backend `wredis=2 wretr=0`;
//! * the frontend row has both columns empty.
//!
//! Reaches the data path in `retry_server_connect` (`engine.rs`), which counts on the
//! backend's `ProxyStats` and on the failed server's own counters; `stats.rs` prints them.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
    }
}

fn live_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            c.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

fn get_status(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split(' ').nth(1).unwrap_or("").to_string()
}

/// `(proxy, server) -> (wretr, wredis)` from `show stat`.
fn columns(sock: &std::path::Path) -> Vec<(String, String, String, String)> {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(b"show stat\n").expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    let mut lines = out.lines();
    let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let at = |n: &str| header.iter().position(|h| *h == n).expect("column");
    let (wretr, wredis) = (at("wretr"), at("wredis"));
    lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (f[0].to_string(), f[1].to_string(), f[wretr].to_string(), f[wredis].to_string())
        })
        .collect()
}

#[test]
fn wretr_and_wredis_are_counted_per_server_and_backend() {
    let live = live_backend();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let dir = std::env::temp_dir();
    let sock = dir.join(format!("ibex_t131_stat_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  stats socket {}\n\
         defaults\n  mode http\n  timeout connect 300ms\n  timeout client 10s\n  timeout server 10s\n  retries 1\n\
         frontend f\n  bind 127.0.0.1:{port}\n  use_backend redis if {{ path /r }}\n  default_backend plain\n\
         backend plain\n  server dead 127.0.0.1:{dead}\n\
         backend redis\n  option redispatch\n  balance roundrobin\n  server dead 127.0.0.1:{dead}\n  server live 127.0.0.1:{live}\n",
        sock.display()
    );
    let path = dir.join(format!("ibex_t131_stat_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() || !sock.exists() {
        assert!(Instant::now() < deadline, "the daemon never listened");
        thread::sleep(Duration::from_millis(25));
    }

    assert_eq!(get_status(port, "/p"), "503");
    assert_eq!(get_status(port, "/r"), "200");
    assert_eq!(get_status(port, "/r"), "200");

    let rows = columns(&sock);
    let row = |px: &str, sv: &str| {
        let r = rows.iter().find(|r| r.0 == px && r.1 == sv).unwrap_or_else(|| panic!("no row {px}/{sv}"));
        (r.2.clone(), r.3.clone())
    };
    let s = |a: &str, b: &str| (a.to_string(), b.to_string());
    assert_eq!(row("f", "FRONTEND"), s("", ""));
    assert_eq!(row("plain", "dead"), s("1", "0"));
    assert_eq!(row("plain", "BACKEND"), s("1", "0"));
    // Which server the first request picked depends on the round-robin position, so the
    // two redispatches may be counted on the dead server only when it was picked twice:
    // two requests, each retried once away from the dead server, as measured.
    let (dead_r, dead_d) = row("redis", "dead");
    let (live_r, live_d) = row("redis", "live");
    let (be_r, be_d) = row("redis", "BACKEND");
    assert_eq!((dead_r.as_str(), live_r.as_str(), be_r.as_str()), ("0", "0", "0"));
    assert_eq!(be_d, "2");
    assert_eq!(dead_d, "2", "a redispatch is counted on the server that failed");
    assert_eq!(live_d, "0");
}
