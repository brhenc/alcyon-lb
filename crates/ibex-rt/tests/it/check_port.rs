// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `check port <n>` (and `port` on `default-server`) sends the plain TCP check and the
//! protocol checks to that port, not to the traffic port (T495). Measured on `HAProxy`
//! 3.5-dev8-885761-29 (2026-10-25), traffic port live / check port dead, and the reverse:
//!
//! ```text
//! check port <dead>                    DOWN L4CON      check port <live> (traffic dead)  UP L4OK
//! default-server port <dead>           DOWN L4CON      default-server port <live>        UP L4OK
//! redis/smtp/ldap/mysql/pgsql/ssl-hello with check port <dead>      DOWN L4CON
//! ```
//!
//! `addr`, `agent-*` and `check-send-proxy` are refused by the parser (not part of this file).

use crate::common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Ibex(std::process::Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// A listener that accepts and holds connections; returns its port.
fn live() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming() {
            let Ok(s) = s else { break };
            held.push(s);
        }
    });
    port
}

fn dead() -> u16 {
    common::reserve_addr().port()
}

/// `(status, check_status)` of server `s` once its first check has finished.
fn verdict(backend_lines: &dyn Fn(u16, u16) -> String) -> (String, String) {
    let (live, dead) = (live(), dead());
    let dir = tempfile::TempDir::new().expect("tmp");
    let sock = dir.path().join("stats.sock");
    let front = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {}\ndefaults\n  mode tcp\n  timeout connect 1s\n  timeout client 2s\n  \
         timeout server 2s\n  timeout check 2s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n{}\n",
        sock.display(),
        backend_lines(live, dead)
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
    thread::sleep(Duration::from_millis(900));
    let mut s = UnixStream::connect(&sock).expect("connect stats");
    s.write_all(b"show stat\n").expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    let mut lines = out.lines();
    let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let row: Vec<&str> = lines.find(|l| l.split(',').nth(1) == Some("s")).expect("server row").split(',').collect();
    let col = |n: &str| row[header.iter().position(|h| *h == n).expect(n)].to_string();
    (col("status").split(' ').next().unwrap_or("").to_string(), col("check_status"))
}

fn is(v: &(String, String), status: &str, check: &str) {
    assert_eq!((v.0.as_str(), v.1.as_str()), (status, check));
}

#[test]
fn tcp_check_goes_to_the_check_port() {
    is(&verdict(&|l, d| format!("  server s 127.0.0.1:{l} check port {d} inter 30s")), "DOWN", "L4CON");
    let v = verdict(&|l, d| format!("  server s 127.0.0.1:{d} check port {l} inter 30s"));
    assert_eq!((v.0.as_str(), v.1.as_str()), ("UP", "L4OK"), "{v:?}");
}

#[test]
fn default_server_port_reaches_the_tcp_check() {
    is(&verdict(&|l, d| format!("  default-server port {d}\n  server s 127.0.0.1:{l} check inter 30s")), "DOWN", "L4CON");
    let v = verdict(&|l, d| format!("  default-server port {l}\n  server s 127.0.0.1:{d} check inter 30s"));
    assert_eq!((v.0.as_str(), v.1.as_str()), ("UP", "L4OK"), "{v:?}");
}

#[test]
fn protocol_checks_go_to_the_check_port() {
    for opt in [
        "option redis-check",
        "option smtpchk",
        "option ldap-check",
        "option mysql-check user x",
        "option pgsql-check user x",
        "option ssl-hello-chk",
    ] {
        let v = verdict(&|l, d| format!("  {opt}\n  server s 127.0.0.1:{l} check port {d} inter 30s"));
        assert_eq!((v.0.as_str(), v.1.as_str()), ("DOWN", "L4CON"), "{opt}: {v:?}");
    }
}
