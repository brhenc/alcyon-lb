// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `status` column of `show stat` across a checked server's life (T274 D1). Expected
//! sequences were measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-10), `option httpchk`:
//!
//! ```text
//! rise 3 fall 2, first check running      UP -2/2       (health starts at 0, state running)
//! rise 1 fall 1, first check running      UP 0/1
//! rise 3 fall 2, healthy                  UP -2/2 UP -1/2 UP 0/2 UP
//! rise 3 fall 2, 1 success then failure   UP -1/2 DOWN         (health 1 -> 0 at once)
//! rise 3 fall 2, full health then failures UP 1/2 DOWN
//! rise 3 fall 2, down then successes      DOWN 1/3 DOWN 2/3 UP
//! set server state drain / maint / ready  DRAIN / MAINT (check columns empty) / UP 1/2
//! ```
//!
//! `NOLB` needs the stopping state, which Ibex does not have (`set server health stopping`
//! is refused).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const OK: u8 = 0;
const FAIL: u8 = 1;
const SLOW: u8 = 2;

struct Ibex(Child);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// An HTTP server whose answer to a check follows `mode`: 200, 503, or 200 after 1.5 s.
fn backend(mode: Arc<AtomicU8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            let mode = mode.clone();
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                let _ = s.read(&mut b);
                let m = mode.load(Ordering::Relaxed);
                if m == SLOW {
                    thread::sleep(Duration::from_millis(1500));
                }
                let status = if m == FAIL { "503 X" } else { "200 OK" };
                let _ = s.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes());
                thread::sleep(Duration::from_millis(300));
            });
        }
    });
    addr
}

struct Rig {
    sock: std::path::PathBuf,
    mode: Arc<AtomicU8>,
    _ibex: Ibex,
    _dir: tempfile::TempDir,
}

fn query(sock: &std::path::Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect stats");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    out
}

fn rig(initial: u8, server_opts: &str) -> Rig {
    let mode = Arc::new(AtomicU8::new(initial));
    let be = backend(mode.clone());
    let dir = tempfile::TempDir::new().expect("tmp");
    let sock = dir.path().join("stats.sock");
    let front = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {} level admin\ndefaults\n  mode http\n  timeout connect 1s\n  timeout client 2s\n  \
         timeout server 2s\n  timeout check 5s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n  option httpchk GET /\n  server s {be} check {server_opts}\n",
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
    let ibex = Ibex(child);
    let start = Instant::now();
    while !sock.exists() && start.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(5));
    }
    Rig { sock, mode, _ibex: ibex, _dir: dir }
}

impl Rig {
    /// (status, check_status) of server `s`.
    fn row(&self) -> (String, String) {
        let stat = query(&self.sock, "show stat");
        let mut lines = stat.lines();
        let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
        let row: Vec<&str> = lines.find(|l| l.split(',').nth(1) == Some("s")).expect("server row").split(',').collect();
        let col = |n: &str| row[header.iter().position(|h| *h == n).expect(n)].to_string();
        (col("status"), col("check_status"))
    }

    fn status(&self) -> String {
        self.row().0
    }

    /// The distinct consecutive statuses seen until `stop` returns true or 6 s pass.
    fn watch(&self, stop: impl Fn(&str) -> bool) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(6) {
            let s = self.status();
            if seen.last() != Some(&s) {
                seen.push(s.clone());
            }
            if stop(&s) {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
        seen
    }

    fn wait_for(&self, want: &str) {
        let seen = self.watch(|s| s == want);
        assert_eq!(seen.last().map(String::as_str), Some(want), "never reached {want}: {seen:?}");
    }
}

#[test]
fn the_first_check_running_shows_up_0_over_1() {
    let r = rig(SLOW, "inter 5s rise 1 fall 1");
    thread::sleep(Duration::from_millis(400));
    assert_eq!(r.row(), ("UP 0/1".to_string(), "* INI".to_string()));
    r.wait_for("UP");
}

#[test]
fn a_new_server_climbs_through_up_n_over_fall() {
    let r = rig(OK, "inter 400ms rise 3 fall 2");
    let seen = r.watch(|s| s == "UP");
    assert_eq!(seen, ["UP -2/2", "UP -1/2", "UP 0/2", "UP"]);
}

#[test]
fn one_success_then_a_failure_is_down() {
    let r = rig(OK, "inter 400ms rise 3 fall 2");
    r.wait_for("UP -1/2");
    r.mode.store(FAIL, Ordering::Relaxed);
    let seen = r.watch(|s| s == "DOWN");
    assert_eq!(seen, ["UP -1/2", "DOWN"]);
}

#[test]
fn full_health_falls_through_up_1_over_2() {
    let r = rig(OK, "inter 300ms rise 3 fall 2");
    r.wait_for("UP");
    r.mode.store(FAIL, Ordering::Relaxed);
    let seen = r.watch(|s| s == "DOWN");
    assert_eq!(seen, ["UP", "UP 1/2", "DOWN"]);
}

#[test]
fn down_climbs_through_down_n_over_rise() {
    let r = rig(FAIL, "inter 300ms rise 3 fall 2");
    r.wait_for("DOWN");
    r.mode.store(OK, Ordering::Relaxed);
    let seen = r.watch(|s| s == "UP");
    assert_eq!(seen, ["DOWN", "DOWN 1/3", "DOWN 2/3", "UP"]);
}

#[test]
fn drain_maint_and_ready() {
    let r = rig(OK, "inter 300ms rise 3 fall 2");
    r.wait_for("UP");
    query(&r.sock, "set server b/s state drain");
    assert_eq!(r.status(), "DRAIN");
    query(&r.sock, "set server b/s state maint");
    // A server in maintenance has its checks paused: the check columns are empty.
    assert_eq!(r.row(), ("MAINT".to_string(), String::new()));
    query(&r.sock, "set server b/s state ready");
    assert_eq!(r.status(), "UP 1/2");
}
