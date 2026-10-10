// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The check columns of `show stat` and `show servers state` (T273 A). Expected values were
//! measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-10):
//!
//! ```text
//! tcp-check connect only    check_status L4OK   check_code ""   last_chk "(tcp-check)"  state 6
//! smtp pass (221 by)        check_status L7OK   check_code 221  last_chk "by"           state 15 result 3
//! redis -ERR, closed        check_status L7STS  check_code 0    last_chk "-ERR"         state 17 result 2
//! pgsql E reply             check_status L7RSP  check_code ""   last_chk "EVE"          state 13
//! httpchk 503 Bad Gateway X check_status L7STS  check_code 503  last_chk "Bad Gateway X"
//! httpchk 200               check_status L7OK   check_code 200  last_chk ""             state 15 result 3
//! first check still running check_status "* INI" (a star while a check is in progress)
//! ```
//!
//! Only statuses from L57DATA on carry a `check_code`; `last_chk` is the check's info text.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// Answers each connection: optional greeting, read, reply, read, second reply, then close
/// (`close`) or hold.
fn fake(greet: &'static [u8], reply: &'static [u8], second: &'static [u8], close: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let _ = s.write_all(greet);
                let _ = s.read(&mut b);
                let _ = s.write_all(reply);
                if !second.is_empty() {
                    let _ = s.read(&mut b);
                    let _ = s.write_all(second);
                }
                if !close {
                    thread::sleep(Duration::from_secs(8));
                }
            });
        }
    });
    addr
}

fn query(sock: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect stats");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    out
}

/// (check_status, check_code, last_chk, servers-state check_status, servers-state result)
fn columns(check_line: &str, server: SocketAddr, wait: Duration) -> (String, String, String, String, String) {
    let dir = tempfile::TempDir::new().expect("tmp");
    let sock = dir.path().join("stats.sock");
    let front = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {} level admin\ndefaults\n  mode tcp\n  timeout connect 1s\n  timeout client 2s\n  \
         timeout server 2s\n  timeout check 5s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n{check_line}\n  server s {server} check inter 30s fall 1 rise 1\n",
        sock.display()
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _ibex = Ibex(child);
    let start = Instant::now();
    while !sock.exists() && start.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(wait);
    let stat = query(&sock, "show stat");
    let mut lines = stat.lines();
    let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let row: Vec<&str> = lines.find(|l| l.split(',').nth(1) == Some("s")).expect("server row").split(',').collect();
    let col = |n: &str| row[header.iter().position(|h| *h == n).expect(n)].to_string();
    let state = query(&sock, "show servers state b");
    let f: Vec<&str> = state.lines().nth(2).expect("state line").split_whitespace().collect();
    (col("check_status"), col("check_code"), col("last_chk"), f[10].to_string(), f[11].to_string())
}

fn t(s: &(String, String, String, String, String)) -> (&str, &str, &str, &str, &str) {
    (&s.0, &s.1, &s.2, &s.3, &s.4)
}

const SETTLE: Duration = Duration::from_millis(800);

#[test]
fn l4ok_has_no_code_and_the_tcp_check_info() {
    let c = columns("  option tcp-check\n  tcp-check connect", fake(b"", b"", b"", false), SETTLE);
    assert_eq!(t(&c), ("L4OK", "", "(tcp-check)", "6", "3"));
}

#[test]
fn smtp_pass_shows_221_and_its_info() {
    let c = columns("  option smtpchk", fake(b"220 ok\r\n", b"250 hi\r\n", b"221 by\r\n", false), SETTLE);
    assert_eq!(t(&c), ("L7OK", "221", "by", "15", "3"));
}

#[test]
fn l7sts_and_l7rsp_columns() {
    let c = columns("  option redis-check", fake(b"", b"-ERR\r\n", b"", true), SETTLE);
    assert_eq!(t(&c), ("L7STS", "0", "-ERR", "17", "2"));
    let c = columns("  option pgsql-check user x", fake(b"", b"E\0\0\0\x0bSEVE", b"", false), SETTLE);
    assert_eq!(t(&c), ("L7RSP", "", "EVE", "13", "2"));
}

#[test]
fn http_check_columns() {
    let ok = columns(
        "  option httpchk GET /",
        fake(b"", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", b"", false),
        SETTLE,
    );
    assert_eq!(t(&ok), ("L7OK", "200", "", "15", "3"));
    let bad = columns(
        "  option httpchk GET /",
        fake(b"", b"HTTP/1.1 503 Bad Gateway X\r\nContent-Length: 0\r\n\r\n", b"", false),
        SETTLE,
    );
    assert_eq!(t(&bad), ("L7STS", "503", "Bad Gateway X", "17", "2"));
}

#[test]
fn a_check_in_progress_has_a_star() {
    let c = columns("  option redis-check", fake(b"", b"", b"", false), Duration::from_millis(500));
    assert_eq!((c.0.as_str(), c.1.as_str(), c.2.as_str()), ("* INI", "", ""));
}
