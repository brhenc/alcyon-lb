// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `set server <b>/<s> health up|down` (T149b).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 with `server s1 ... check inter 100s fall 3 rise 2`,
//! `server s2 ...` (no check), `server s3 ... track b/s1`:
//!
//! * `health` with nothing, or with anything but `up`, `stopping` or `down` (case matters)
//!   answers `'set server <srv> health' expects 'up', 'stopping', or 'down'.`;
//! * `health up` and `health down` work on a server without a check too, and answer an empty
//!   line; `down` makes the operational state 0 (stopped) and, on a server with a check, the
//!   health counter 0; `up` makes it 2 (running) and the counter `rise + fall - 1` (4 here);
//! * a server that tracks another answers `cannot change health on a tracking server.`, and
//!   follows the one it tracks when that one changes;
//! * `stopping` (`NOLB`) is accepted by HAProxy; Ibex has no such state and refuses it.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// A server that accepts and answers every request.
fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn start() -> Ibex {
    let fe = common::reserve_addr();
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!("ibex_t149b_h_{}_{n}.sock", std::process::id()));
    let be = server();
    let text = format!(
        "global\n  nbthread 1\n  stats socket {sock} mode 600 level admin\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  server s1 {be} check inter 100s fall 3 rise 2\n  server s2 {be}\n  server s3 {be} track b/s1\n",
        sock = sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f, sock };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    ibex
}

fn cli(ibex: &Ibex, cmd: &str) -> String {
    let mut s = UnixStream::connect(&ibex.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `(srv_op_state, srv_check_health)` of server `name` in `show servers state b`.
fn state(ibex: &Ibex, name: &str) -> (String, String) {
    let out = cli(ibex, "show servers state b");
    let line = out.lines().find(|l| l.split(' ').nth(3) == Some(name)).unwrap_or_else(|| panic!("no {name} in {out}"));
    let f: Vec<&str> = line.split(' ').collect();
    (f[5].to_string(), f[12].to_string())
}

#[test]
fn an_unknown_health_is_refused_with_haproxys_words() {
    let ibex = start();
    for cmd in ["set server b/s1 health", "set server b/s1 health bogus", "set server b/s1 health UP"] {
        assert_eq!(cli(&ibex, cmd), "'set server <srv> health' expects 'up', 'stopping', or 'down'.\n\n", "{cmd}");
    }
}

#[test]
fn health_down_and_up_set_the_state_and_the_counter() {
    let ibex = start();
    assert_eq!(cli(&ibex, "set server b/s1 health up"), "\n");
    assert_eq!(state(&ibex, "s1"), ("2".to_string(), "4".to_string()));
    assert_eq!(cli(&ibex, "set server b/s1 health down"), "\n");
    assert_eq!(state(&ibex, "s1"), ("0".to_string(), "0".to_string()));
    assert_eq!(cli(&ibex, "set server b/s1 health up"), "\n");
    assert_eq!(state(&ibex, "s1").0, "2");
}

#[test]
fn a_server_without_a_check_takes_it_too() {
    let ibex = start();
    assert_eq!(cli(&ibex, "set server b/s2 health down"), "\n");
    assert_eq!(state(&ibex, "s2").0, "0");
    assert_eq!(cli(&ibex, "set server b/s2 health up"), "\n");
    assert_eq!(state(&ibex, "s2").0, "2");
}

#[test]
fn a_tracking_server_refuses_it_and_follows_its_target() {
    let ibex = start();
    assert_eq!(cli(&ibex, "set server b/s3 health up"), "cannot change health on a tracking server.\n\n");
    cli(&ibex, "set server b/s1 health down");
    assert_eq!(state(&ibex, "s3").0, "0");
    cli(&ibex, "set server b/s1 health up");
    assert_eq!(state(&ibex, "s3").0, "2");
}

#[test]
fn stopping_is_refused_not_ignored() {
    let ibex = start();
    let out = cli(&ibex, "set server b/s2 health stopping");
    assert!(out.contains("not supported"), "{out}");
    assert_eq!(state(&ibex, "s2").0, "2");
}
