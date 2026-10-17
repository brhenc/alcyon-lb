// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T320: `show info` ConnRate, SessRate, MaxConnRate, MaxSessRate.
//!
//! Measured on HAProxy with two HTTP frontends and a stats socket:
//!
//! | moment                                         | ConnRate | MaxConnRate | SessRate | MaxSessRate |
//! |------------------------------------------------|----------|-------------|----------|-------------|
//! | start (nothing yet)                            | 0        | 0           | 0        | 0           |
//! | right after 50 client connections (both frontends together) | 50 | 50   | 50       | 50          |
//! | right after the CLI command `clear counters`   | 50       | 0           | 50       | 0           |
//! | 2.2 s later, no traffic                        | 0        | 0           | 0        | 0           |
//! | right after 5 more connections                 | 5        | 5           | 5        | 5           |
//! | right after `clear counters all`               | 5        | 0           | 5        | 0           |

use crate::common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child, std::path::PathBuf, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
        let _ = std::fs::remove_file(&self.2);
    }
}

fn get_status(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::<u8>::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split(' ').nth(1).unwrap_or("").to_string()
}

fn cli(sock: &std::path::Path, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    out
}

fn show_info(sock: &std::path::Path) -> String {
    cli(sock, "show info")
}

fn get_rate(info: &str, name: &str) -> u64 {
    info.lines()
        .find(|l| l.starts_with(name))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

#[test]
fn show_info_rates_track_connections_and_clear_counters_resets_maxima() {
    let addr1 = common::reserve_addr();
    let addr2 = common::reserve_addr();
    let dir = std::env::temp_dir();
    let sock = dir.join(format!("ibex_t320_rates_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  nbthread 4\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f1\n  bind {addr1}\n  http-request return status 200\n\
         frontend f2\n  bind {addr2}\n  http-request return status 200\n",
        sock.display()
    );
    let path = dir.join(format!("ibex_t320_rates_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path, sock.clone());

    // Wait for ibex to be ready. The readiness loop opens client connections,
    // which are counted by the rate counters, exactly as HAProxy counts them.
    common::wait_listening(addr1);
    common::wait_listening(addr2);
    assert!(sock.exists(), "stats socket should exist");

    // Sleep 2.2s so the readiness-loop connections age out of the 1s window,
    // then send `clear counters` to zero the maxima. Now we should see all 0s.
    thread::sleep(Duration::from_secs(2));
    thread::sleep(Duration::from_millis(200));
    assert_eq!(cli(&sock, "clear counters"), "\n");
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 0, "ConnRate at start");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate at start");
    assert_eq!(get_rate(&info, "SessRate"), 0, "SessRate at start");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate at start");

    // 2. Send 50 connections across both frontends.
    for _ in 0..25 {
        assert_eq!(get_status(addr1.port(), "/"), "200");
        assert_eq!(get_status(addr2.port(), "/"), "200");
    }

    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 50, "ConnRate after 50 connections");
    assert_eq!(get_rate(&info, "MaxConnRate"), 50, "MaxConnRate after 50 connections");
    assert_eq!(get_rate(&info, "SessRate"), 50, "SessRate after 50 connections");
    assert_eq!(get_rate(&info, "MaxSessRate"), 50, "MaxSessRate after 50 connections");

    // 3. `clear counters` resets maxima to 0, leaves rates.
    assert_eq!(cli(&sock, "clear counters"), "\n");
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 50, "ConnRate after clear counters");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate after clear counters");
    assert_eq!(get_rate(&info, "SessRate"), 50, "SessRate after clear counters");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate after clear counters");

    // 4. Wait 2.2s, no traffic: everything goes to 0.
    thread::sleep(Duration::from_secs(2));
    thread::sleep(Duration::from_millis(200));
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 0, "ConnRate after 2.2s idle");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate after 2.2s idle");
    assert_eq!(get_rate(&info, "SessRate"), 0, "SessRate after 2.2s idle");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate after 2.2s idle");

    // 5. Send 5 more connections.
    for _ in 0..5 {
        assert_eq!(get_status(addr1.port(), "/"), "200");
    }

    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 5, "ConnRate after 5 connections");
    assert_eq!(get_rate(&info, "MaxConnRate"), 5, "MaxConnRate after 5 connections");
    assert_eq!(get_rate(&info, "SessRate"), 5, "SessRate after 5 connections");
    assert_eq!(get_rate(&info, "MaxSessRate"), 5, "MaxSessRate after 5 connections");

    // 6. `clear counters all` resets maxima to 0, leaves rates.
    assert_eq!(cli(&sock, "clear counters all"), "\n");
    let info = show_info(&sock);
    assert_eq!(get_rate(&info, "ConnRate"), 5, "ConnRate after clear counters all");
    assert_eq!(get_rate(&info, "MaxConnRate"), 0, "MaxConnRate after clear counters all");
    assert_eq!(get_rate(&info, "SessRate"), 5, "SessRate after clear counters all");
    assert_eq!(get_rate(&info, "MaxSessRate"), 0, "MaxSessRate after clear counters all");
}
