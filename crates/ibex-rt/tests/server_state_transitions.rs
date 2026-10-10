// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The operator's admin state (`ready`, `drain`, `maint`) and the checks' operational state
//! (running, stopped) are two states, as `srv->cur_admin` and `srv->cur_state` are in
//! `HAProxy` (T274 E). Measured on `HAProxy` 3.5-dev8-885761-29 (2026-10-10), `inter 300
//! rise 2 fall 2`, `show stat` status / `show servers state` op and admin / a request:
//!
//! ```text
//! down by checks                     DOWN       op 0 adm 0  503
//! set server state ready             DOWN       op 0 adm 0  503   (E1: Ibex said UP)
//! set server state drain             DOWN       op 0 adm 8  503
//! checks pass again                  DRAIN      op 2 adm 8  503
//! checks fail                        DOWN       op 0 adm 8  503   (E2: Ibex stayed DRAIN)
//! set server state ready             DOWN       op 0 adm 0  503
//! drain + set server health down     DOWN       op 0 adm 8
//! drain + set server health up       DRAIN      op 2 adm 8
//! maint + set server health up       MAINT      op 0 adm 1  health 3
//! enable server / state ready        UP 1/2     op 2 adm 0  health 2 (rise)
//! ```
//!
//! E3 is not a defect: `HAProxy` does not check at once after `enable server`. Its paused
//! check task keeps its `inter` cadence (`process_chk_conn` reschedules it), so the first
//! check came 0.85 s, 1.88 s and 1.77 s after `enable` at `inter 3s`; Ibex's, at most 1 s.
//!
//! Set `T274E_BIN` to a `haproxy` binary to run these against the oracle.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const OK: u8 = 0;
const FAIL: u8 = 1;
const SLOW: u8 = 2;

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// An HTTP server that answers its checks (`GET /chk`) 200 or 503 as `mode` says, and every
/// other request 200 `served` (`SLOW`: 200 after 1.5 s): a client that gets `served` was sent to the server.
fn backend(mode: Arc<AtomicU8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { break };
            let mode = mode.clone();
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                let n = s.read(&mut b).unwrap_or(0);
                let check = b[..n].starts_with(b"GET /chk ");
                if check && mode.load(Ordering::Relaxed) == SLOW {
                    thread::sleep(Duration::from_millis(1500));
                }
                let resp = if check && mode.load(Ordering::Relaxed) == FAIL {
                    "HTTP/1.1 503 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else if check {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nserved"
                };
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    addr
}

struct Rig {
    sock: std::path::PathBuf,
    front: SocketAddr,
    mode: Arc<AtomicU8>,
    _proc: Proc,
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
         timeout server 2s\n  timeout check 2s\nfrontend f\n  bind {front}\n  default_backend b\n\
         backend b\n  option httpchk GET /chk\n  server s {be} check {server_opts}\n",
        sock.display()
    );
    let path = dir.path().join("ibex.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let bin = std::env::var("T274E_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin)
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let proc = Proc(child);
    let start = Instant::now();
    while !sock.exists() && start.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(common::wait_listening(front), "front never listened");
    Rig { sock, front, mode, _proc: proc, _dir: dir }
}

impl Rig {
    fn cli(&self, cmd: &str) {
        let out = query(&self.sock, cmd);
        assert_eq!(out.trim(), "", "{cmd}: {out}");
    }

    fn stat_col(&self, name: &str) -> String {
        let stat = query(&self.sock, "show stat");
        let mut lines = stat.lines();
        let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
        let row: Vec<&str> = lines.find(|l| l.split(',').nth(1) == Some("s")).expect("server row").split(',').collect();
        row[header.iter().position(|h| *h == name).expect(name)].to_string()
    }

    fn status(&self) -> String {
        self.stat_col("status")
    }

    /// `srv_op_state` and `srv_admin_state` of `show servers state`.
    fn op_admin(&self) -> (String, String) {
        let out = query(&self.sock, "show servers state b");
        let row: Vec<&str> =
            out.lines().find(|l| l.split(' ').nth(3) == Some("s")).expect("server row").split(' ').collect();
        (row[5].to_string(), row[6].to_string())
    }

    /// What a client gets: `served` by the server, or the proxy's status code.
    fn request(&self) -> String {
        let mut s = TcpStream::connect(self.front).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(4))).expect("timeout");
        s.write_all(b"GET /data HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        if out.ends_with("served") {
            "served".to_string()
        } else {
            out.split(' ').nth(1).unwrap_or("none").to_string()
        }
    }

    /// The distinct consecutive statuses seen until `want` or 6 s pass.
    fn watch(&self, want: &str) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(6) {
            let s = self.status();
            if seen.last() != Some(&s) {
                seen.push(s.clone());
            }
            if s == want {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
        seen
    }

    fn wait_for(&self, want: &str) {
        let seen = self.watch(want);
        assert_eq!(seen.last().map(String::as_str), Some(want), "never reached {want}: {seen:?}");
    }
}

fn s(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

/// E1: `ready` is an admin state; it does not make a server the checks found dead alive.
/// `downinter 10s`: no check runs for the rest of the test, so only the command can move it.
#[test]
fn ready_leaves_a_server_down_by_checks_down() {
    let r = rig(FAIL, "inter 200ms downinter 10s rise 2 fall 2");
    r.wait_for("DOWN");
    r.cli("set server b/s state ready");
    assert_eq!(r.status(), "DOWN");
    assert_eq!(r.op_admin(), s("0", "0"));
    assert_eq!(r.request(), "503");
    r.cli("set server b/s state drain");
    assert_eq!(r.status(), "DOWN");
    assert_eq!(r.op_admin(), s("0", "8"));
    r.cli("set server b/s state ready");
    assert_eq!(r.status(), "DOWN");
    assert_eq!(r.request(), "503");
}

/// E2: a draining server whose checks fail goes down, and comes back draining.
#[test]
fn a_draining_server_goes_down_when_its_checks_fail() {
    let r = rig(OK, "inter 300ms rise 2 fall 2");
    r.wait_for("UP");
    r.cli("set server b/s state drain");
    assert_eq!(r.op_admin(), s("2", "8"));
    r.mode.store(FAIL, Ordering::Relaxed);
    assert_eq!(r.watch("DOWN"), ["DRAIN", "DRAIN 1/2", "DOWN"]);
    assert_eq!(r.op_admin(), s("0", "8"));
    r.mode.store(OK, Ordering::Relaxed);
    assert_eq!(r.watch("DRAIN"), ["DOWN", "DOWN 1/2", "DRAIN"]);
    assert_eq!(r.op_admin(), s("2", "8"));
    r.cli("set server b/s state ready");
    assert_eq!(r.status(), "UP");
    assert_eq!(r.request(), "served");
}

/// A draining server that the checks took down stays down when the drain ends.
#[test]
fn ready_after_drain_on_a_dead_server_stays_down() {
    let r = rig(OK, "inter 200ms downinter 10s rise 2 fall 2");
    r.wait_for("UP");
    r.cli("set server b/s state drain");
    r.mode.store(FAIL, Ordering::Relaxed);
    r.wait_for("DOWN");
    r.cli("set server b/s state ready");
    assert_eq!(r.status(), "DOWN");
    assert_eq!(r.op_admin(), s("0", "0"));
    assert_eq!(r.request(), "503");
}

/// `set server health` moves the operational state under a drain, and only the counter
/// under maintenance.
#[test]
fn health_under_drain_and_maint() {
    let r = rig(OK, "inter 10s fastinter 100ms rise 2 fall 2");
    r.wait_for("UP");
    r.cli("set server b/s state drain");
    r.cli("set server b/s health down");
    assert_eq!(r.status(), "DOWN");
    assert_eq!(r.op_admin(), s("0", "8"));
    r.cli("set server b/s health up");
    assert_eq!(r.status(), "DRAIN");
    assert_eq!(r.op_admin(), s("2", "8"));
    r.cli("set server b/s state maint");
    r.cli("set server b/s health up");
    assert_eq!(r.status(), "MAINT");
    assert_eq!(r.op_admin(), s("0", "1"));
    r.cli("set server b/s state ready");
    assert_eq!(r.status(), "UP 1/2");
    assert_eq!(r.op_admin(), s("2", "0"));
}

/// E4: `check_duration` is printed from the first completed check on (`HCHK_STATUS_CHECKED`),
/// not while the status is still `INI`.
#[test]
fn no_check_duration_before_the_first_check() {
    let r = rig(SLOW, "inter 10s rise 2 fall 2");
    thread::sleep(Duration::from_millis(400));
    assert_eq!(r.stat_col("check_status"), "* INI");
    assert_eq!(r.stat_col("check_duration"), "");
    r.mode.store(OK, Ordering::Relaxed);
    let start = Instant::now();
    while r.stat_col("check_status") == "* INI" && start.elapsed() < Duration::from_secs(4) {
        thread::sleep(Duration::from_millis(20));
    }
    assert_ne!(r.stat_col("check_duration"), "");
}
