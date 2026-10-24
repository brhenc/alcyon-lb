// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A server connection that failed (refused, or `timeout connect`) leaves the poller and
//! the fd table before its socket closes (T443).
//!
//! It used to be dropped by `server_failed` with its fd-table entry and its epoll
//! registration in place. Closing a descriptor takes it out of the epoll set only when it
//! was the last reference to the socket; any other (a `fork` between `clone` and `exec`
//! in another thread, which a loaded host makes long) keeps it there, reporting the
//! socket's error on every poll under the old number. The entry left behind still named
//! the stream's task, and once the stream ended, the poller woke the freed slot:
//! `tasklet_wakeup on freed task` in a debug build, a wakeup of whatever task took the
//! slot next in a release one. `HAProxy` takes the connection out of the poller
//! (`fd_delete` from `conn_full_close`, through `sc_conn_shut` in `back_handle_st_cer`)
//! before it closes it.
//!
//! The tests take a reference of their own on every server socket the engine opens
//! (`pidfd_getfd` on this process), the deterministic form of that `fork`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::OwnedFd;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::fdtab::FdState;
use ibex_rt::Engine;

const MAX_FD: i32 = 4096;

/// Runs one request through an engine on `cfg` (`@FE@` its frontend), holding a duplicate
/// of every server socket it opens, then a few more passes once the client is answered.
/// Returns the engine and the response's status line.
fn run(cfg: &str) -> (Engine, String) {
    let fe = common::reserve_addr();
    let config = ibex_config::parse_str(&cfg.replace("@FE@", &fe.to_string())).expect("parse");
    let mut engine = Engine::new(&config, 64).expect("Engine::new");
    let pidfd = rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty())
        .expect("pidfd_open");
    let mut held: Vec<OwnedFd> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let client = thread::spawn(move || {
        let mut s = TcpStream::connect(fe).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).lines().next().unwrap_or("").to_string()
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut after = 0;
    while after < 50 && Instant::now() < deadline {
        let _ = engine.run_once();
        for fd in 0..MAX_FD {
            if let FdState::Conn { conn: 1, .. } = engine.fdtab.state(fd) {
                // One duplicate per socket: a number given to the next attempt is a new one.
                let Ok(dup) = rustix::process::pidfd_getfd(&pidfd, fd, rustix::process::PidfdGetfdFlags::empty()) else {
                    continue;
                };
                let id = rustix::fs::fstat(&dup).map_or(0, |st| st.st_ino);
                if seen.insert(id) {
                    held.push(dup);
                }
            }
        }
        if client.is_finished() {
            after += 1;
        }
        thread::sleep(Duration::from_millis(1));
    }
    let status = client.join().expect("client");
    assert!(!held.is_empty(), "no server socket was ever opened");
    (engine, status)
}

/// Every fd-table entry that names a task names a live one.
fn assert_no_stale_entry(engine: &Engine) {
    for fd in 0..MAX_FD {
        if let FdState::Conn { task, conn } = engine.fdtab.state(fd) {
            assert!(engine.scheduler.is_live(task), "fd {fd} (conn {conn}) names freed task {task:?}");
        }
    }
}

const DEFAULTS: &str = "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n";

#[test]
fn a_refused_connect_leaves_the_poller_before_it_closes() {
    let dead: SocketAddr = common::reserve_addr();
    let cfg = format!("{DEFAULTS}  timeout connect 1s\nlisten l\n  bind @FE@\n  retries 2\n  server s {dead}\n");
    let (engine, status) = run(&cfg);
    assert!(status.starts_with("HTTP/1.1 503"), "{status}");
    assert_no_stale_entry(&engine);
}

#[test]
fn a_connect_timed_out_leaves_the_poller_before_it_closes() {
    // A listener whose accept queue is full drops the SYNs that follow: the connect neither
    // succeeds nor fails before `timeout connect`.
    let sock = rustix::net::socket(rustix::net::AddressFamily::INET, rustix::net::SocketType::STREAM, None).expect("socket");
    rustix::net::bind_v4(&sock, &std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind");
    rustix::net::listen(&sock, 0).expect("listen");
    let Some(rustix::net::SocketAddrAny::V4(addr)) = rustix::net::getsockname(&sock).ok() else {
        panic!("getsockname");
    };
    let full: Vec<TcpStream> = (0..4)
        .filter_map(|_| TcpStream::connect_timeout(&SocketAddr::V4(addr), Duration::from_millis(100)).ok())
        .collect();
    assert!(!full.is_empty(), "the queue took no connection");
    let cfg = format!("{DEFAULTS}  timeout connect 50ms\nlisten l\n  bind @FE@\n  retries 1\n  server s {addr}\n");
    let (engine, status) = run(&cfg);
    assert!(status.starts_with("HTTP/1.1 503"), "{status}");
    assert_no_stale_entry(&engine);
    drop(full);
}
