// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `balance roundrobin` across a weight or state change (T149b).
//!
//! `HAProxy` does not start the order over when a server's weight or state changes: it moves
//! that server in the trees of `fwrr` (`fwrr_update_server_weight`,
//! `fwrr_set_server_status_up` and `_down`, `src/lb_fwrr.c`) and the window goes on. Every
//! sequence below was measured on 3.5-dev8-885761-29 (`nbthread 1`, `server s1 weight 3`,
//! `s2 weight 2`, `s3 weight 1`, one new connection per request, commands on the stats
//! socket between the groups of requests).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
    sock: PathBuf,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn server(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = c.read(&mut buf) {
                    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Server: {name}\r\n\r\n");
                    if n == 0 || c.write_all(resp.as_bytes()).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn start() -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sock = std::env::temp_dir().join(format!("alcyon_t149b_rr_{}_{n}.sock", std::process::id()));
    let (s1, s2, s3) = (server("s1"), server("s2"), server("s3"));
    let text = format!(
        "global\n  nbthread 1\n  stats socket {sock} mode 600 level admin\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  balance roundrobin\n  server s1 {s1} weight 3\n  server s2 {s2} weight 2\n  server s3 {s3} weight 1\n",
        sock = sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon");
    let alcyon = Alcyon { child, _cfg: f, sock };
    assert!(common::wait_listening(fe), "alcyon never listened on {fe} with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !alcyon.sock.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    (alcyon, fe)
}

fn cli(alcyon: &Alcyon, cmd: &str) {
    let mut s = UnixStream::connect(&alcyon.sock).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    assert_eq!(out, "\n", "{cmd}");
}

fn get(fe: SocketAddr) -> String {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    // Header names are case-insensitive; HAProxy emits them lowercase (T244).
    String::from_utf8_lossy(&got).split("\r\n").find_map(|l| l.split_once(": ").filter(|(n, _)| n.eq_ignore_ascii_case("X-Server")).map(|(_, v)| v)).unwrap_or("?").to_string()
}

enum Step {
    Cmd(&'static str),
    Seq(&'static str),
}

fn run(steps: &[Step]) {
    let (alcyon, fe) = start();
    for (i, step) in steps.iter().enumerate() {
        match step {
            Step::Cmd(c) => cli(&alcyon, c),
            Step::Seq(want) => {
                let n = want.split(' ').count();
                let got: Vec<String> = (0..n).map(|_| get(fe)).collect();
                assert_eq!(got.join(" "), *want, "step {i}");
            }
        }
    }
}

#[test]
fn a_lower_weight_then_maint_then_ready() {
    run(&[
        Step::Seq("s1 s2 s1 s3 s1 s2 s1 s2 s1 s3 s1 s2"),
        Step::Cmd("set server b/s1 weight 1"),
        Step::Seq("s2 s2 s3 s1 s2 s2 s3 s1 s2 s2 s3 s1"),
        Step::Cmd("set server b/s2 state maint"),
        Step::Seq("s3 s1 s3 s1 s3 s1 s3 s1 s3 s1 s3 s1"),
        Step::Cmd("set server b/s2 state ready"),
        Step::Seq("s3 s2 s1 s2 s3 s2 s1 s2 s3 s2 s1 s2"),
    ]);
}

#[test]
fn a_change_in_the_middle_of_a_window() {
    run(&[
        Step::Seq("s1 s2 s1 s3 s1"),
        Step::Cmd("set server b/s2 weight 4"),
        Step::Seq("s2 s1 s2 s1 s3 s2 s1 s2 s2 s1"),
        Step::Cmd("set server b/s3 weight 0"),
        Step::Seq("s2 s1 s2 s1 s2 s2 s1 s2"),
        Step::Cmd("set server b/s3 weight 2"),
        Step::Seq("s1 s2 s3 s1 s2 s2 s1 s3"),
    ]);
}

/// Weight changes at other points of the window, from the thirty sequences measured on
/// HAProxy (a seeded random walk over `set server b/sN weight W` and runs of requests).
#[test]
fn measured_sequences_with_weight_changes() {
    run(&[
        Step::Seq("s1 s2 s1"),
        Step::Cmd("set server b/s2 weight 5"),
        Step::Seq("s3"),
        Step::Cmd("set server b/s1 weight 6"),
        Step::Seq("s2 s1 s2 s1 s2 s1 s1 s2 s3"),
        Step::Cmd("set server b/s1 weight 2"),
        Step::Seq("s2 s2 s1 s2 s2 s2 s1 s2 s2 s1"),
    ]);
    run(&[
        Step::Seq("s1"),
        Step::Cmd("set server b/s3 weight 1"),
        Step::Seq("s2"),
        Step::Cmd("set server b/s1 weight 3"),
        Step::Seq("s1 s3 s1 s2 s1 s2 s1"),
        Step::Cmd("set server b/s1 weight 1"),
        Step::Seq("s3 s2"),
        Step::Cmd("set server b/s3 weight 3"),
        Step::Seq("s3 s2 s1 s3 s2 s3 s3 s2 s1 s3"),
    ]);
    run(&[
        Step::Seq("s1"),
        Step::Cmd("set server b/s1 weight 0"),
        Step::Seq("s2 s2 s3 s2 s2 s3 s2 s2 s3"),
        Step::Cmd("set server b/s1 weight 2"),
        Step::Seq("s2 s1 s3 s2 s1 s2 s1"),
        Step::Cmd("set server b/s1 weight 4"),
        Step::Seq("s3 s2 s1 s1 s2 s1 s1 s3 s2 s1"),
    ]);
    run(&[
        Step::Seq("s1 s2 s1 s3"),
        Step::Cmd("set server b/s2 weight 0"),
        Step::Seq("s1 s1 s1 s1 s1 s3 s1 s1 s1"),
        Step::Cmd("set server b/s3 weight 0"),
        Step::Seq("s1"),
        Step::Cmd("set server b/s3 weight 1"),
        Step::Seq("s1 s1 s3 s1 s1 s1 s3 s1"),
        Step::Cmd("set server b/s3 weight 4"),
        Step::Seq("s3 s1 s3 s1 s3 s3 s1 s3 s1 s3"),
    ]);
    run(&[
        Step::Seq("s1 s2 s1 s3 s1 s2"),
        Step::Cmd("set server b/s2 weight 4"),
        Step::Seq("s1 s2 s1 s2 s3 s2 s1 s2"),
        Step::Cmd("set server b/s2 weight 2"),
        Step::Seq("s1 s1 s2 s3"),
        Step::Cmd("set server b/s1 weight 5"),
        Step::Seq("s1 s2 s1 s1 s2 s3 s1 s1 s1 s2"),
    ]);
    run(&[
        Step::Seq("s1 s2 s1 s3 s1 s2 s1 s2"),
        Step::Cmd("set server b/s2 weight 4"),
        Step::Seq("s1 s2"),
        Step::Cmd("set server b/s1 weight 4"),
        Step::Seq("s3 s2 s1 s2 s1 s2 s1"),
        Step::Cmd("set server b/s1 weight 6"),
        Step::Seq("s2 s1 s3 s1 s2 s1"),
        Step::Cmd("set server b/s1 weight 3"),
        Step::Seq("s2 s2 s1 s2 s1 s2 s3 s2 s1 s2"),
    ]);
}
