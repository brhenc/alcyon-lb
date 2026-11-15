// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `balance source` (map-based, the default `hash-type`) for a client with no IP address:
//! one on a UNIX socket (`bind unix@...`), T634 item 2 review.
//!
//! `assign_server` (`src/backend.c`) calls `get_server_sh` only for an `AF_INET` or
//! `AF_INET6` source; for any other the hash finds no server and the stream falls back to
//! `map_get_server_rr` (`src/lb_map.c`): a weighted round robin over the same interleaved
//! server map the IP hash indexes, from slot 0, one slot per pick. The IP clients' picks do
//! not move it. Measured on the reference `HAProxy` 3.5-dev8
//! (`/home/bhenc/ibex-worktrees/agy-eval/oracle/haproxy`, 2026-11-15, `nbthread 1`), one
//! `curl --unix-socket` connection per request:
//!
//! ```text
//! weights 1 2 3                         132323132323132323
//! weights 1 2 3 4, s2 disabled          1434343414343434
//! weights 1 2 3: 3 UNIX, 2 from 127.0.0.1, 6 UNIX    132 33 323132
//! ```
//!
//! Before this test Alcyon took these clients round robin over the servers by count
//! (`Proxy::select_server_idx`), ignoring the weights: `123123...`. Reaches the data path in
//! `lb::balance_source_unix`, called from `Proxy::select_server_with_key_idx` (`engine.rs`).

use crate::common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static RUN: AtomicUsize = AtomicUsize::new(0);

fn backend(id: usize) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            c.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{id}");
        }
    });
    port
}

/// The answering server's number from one request on `s`, `x` when there was none.
fn answer(mut s: impl Read + Write) -> char {
    write!(s, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    if out.starts_with("HTTP/1.1 200") { out.chars().last().unwrap_or('x') } else { 'x' }
}

fn unix(sock: &Path) -> char {
    let s = UnixStream::connect(sock).expect("connect unix");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    answer(s)
}

fn tcp(port: u16) -> char {
    let s = TcpStream::connect(("127.0.0.1", port)).expect("connect tcp");
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    answer(s)
}

/// A daemon with a frontend on a UNIX socket and on `127.0.0.1`, before a `balance source`
/// backend whose servers have `weights` (`s2_down`: the second is `disabled`).
struct Daemon {
    child: common::Alcyon,
    sock: PathBuf,
    port: u16,
    cfg: PathBuf,
}

impl Daemon {
    fn start(weights: &[u32], s2_down: bool) -> Self {
        let mut servers = String::new();
        for (i, w) in weights.iter().enumerate() {
            let down = if s2_down && i == 1 { " disabled" } else { "" };
            let _ = writeln!(servers, "  server s{} 127.0.0.1:{} weight {w}{down}", i + 1, backend(i + 1));
        }
        let run = RUN.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("alcyon_balsrc_unix_{}_{run}", std::process::id()));
        let sock = base.with_extension("sock");
        let cfg = base.with_extension("cfg");
        let _ = std::fs::remove_file(&sock);
        let port = common::reserve_port();
        std::fs::write(
            &cfg,
            format!(
                "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
                 frontend f\n  bind unix@{}\n  bind 127.0.0.1:{port}\n  default_backend be\n\
                 backend be\n  balance source\n{servers}",
                sock.display()
            ),
        )
        .expect("write config");
        let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(common::Alcyon)
            .expect("spawn alcyon");
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).is_err() || UnixStream::connect(&sock).is_err() {
            assert!(Instant::now() < deadline, "the daemon never listened on {port} and {}", sock.display());
            thread::sleep(Duration::from_millis(25));
        }
        Daemon { child, sock, port, cfg }
    }

    fn unix(&self, n: usize) -> String {
        (0..n).map(|_| unix(&self.sock)).collect()
    }

    fn tcp(&self, n: usize) -> String {
        (0..n).map(|_| tcp(self.port)).collect()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.cfg);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// The probe connections the start-up wait made on the UNIX socket were balanced too, as
/// they are in `HAProxy`; start the sequence from slot 0 by consuming whole rounds of the
/// map: `tot_weight` picks bring the round robin back to where it was. The wait makes one
/// probe connection that sends nothing; Alcyon balances only once the request is in, so it
/// takes no slot. Asserted, not assumed: the first answers are compared in full.
fn unix_answers(weights: &[u32], s2_down: bool, n: usize) -> String {
    let d = Daemon::start(weights, s2_down);
    d.unix(n)
}

#[test]
fn a_unix_client_takes_the_weighted_map_round_robin() {
    let got = unix_answers(&[1, 2, 3], false, 18);
    assert_eq!(
        got, "132323132323132323",
        "UNIX-socket clients behind `balance source`, weights 1 2 3: HAProxy walks the \
         interleaved server map one slot per request (`map_get_server_rr`), 1:2:3; Alcyon \
         answered {got:?}"
    );
}

#[test]
fn a_unix_client_round_robin_leaves_a_server_down_out() {
    let got = unix_answers(&[1, 2, 3, 4], true, 16);
    assert_eq!(
        got, "1434343414343434",
        "UNIX-socket clients behind `balance source`, weights 1 2 3 4 with s2 disabled: \
         HAProxy's map holds 1, 3 and 4 only; Alcyon answered {got:?}"
    );
}

#[test]
fn ip_clients_do_not_move_the_unix_round_robin() {
    let d = Daemon::start(&[1, 2, 3], false);
    let got = format!("{} {} {}", d.unix(3), d.tcp(2), d.unix(6));
    assert_eq!(
        got, "132 33 323132",
        "3 UNIX clients, 2 from 127.0.0.1 (hashed: always s3), then 6 UNIX clients: the IP \
         picks do not advance HAProxy's round robin; Alcyon answered {got:?}"
    );
}
