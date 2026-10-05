// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A client that leaves while its request is at a server that has not answered (T226).
//!
//! On devtest7, vegeta's 30 s timeout closed ~2000 clients whose requests sat at a slow
//! backend, and every worker then ran at 100% CPU until `timeout server` freed the server
//! connections. With nothing left to read and nothing to send, the process must sleep.

mod common;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::NamedTempFile;

const CLIENTS: usize = 20;

/// User + system CPU of `pid`, in clock ticks (100 per second).
fn cpu_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    // Fields after the parenthesised command name; utime and stime are fields 14 and 15.
    let rest = &stat[stat.rfind(')').expect("comm") + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

/// Ticks Ibex spends in the second after `CLIENTS` clients sent a request to a server that
/// never answers and then left, each with `leave`.
fn ticks_after_clients_leave(leave: fn(TcpStream)) -> u64 {
    let fe = common::reserve_addr();
    let be = TcpListener::bind("127.0.0.1:0").expect("backend");
    let be_addr = be.local_addr().unwrap();
    // Accepts and holds every connection, answers nothing.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in be.incoming().flatten() {
            held.push(s);
        }
    });
    let cfg = format!(
        "global\n  nbthread 2\ndefaults\n  mode http\n  timeout client 50s\n  timeout connect 5s\n  timeout server 50s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  server s1 {be_addr}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    for _ in 0..CLIENTS {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(b"GET /items/42 HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        // Let the request reach the server before the client goes.
        std::thread::sleep(Duration::from_millis(20));
        leave(c);
    }
    std::thread::sleep(Duration::from_millis(300));
    let before = cpu_ticks(child.id());
    std::thread::sleep(Duration::from_secs(1));
    let spent = cpu_ticks(child.id()) - before;
    common::stop(&mut child);
    spent
}

#[test]
fn clients_that_close_while_the_server_is_silent_leave_ibex_idle() {
    let spent = ticks_after_clients_leave(drop);
    assert!(spent < 10, "Ibex used {spent} ticks (100 = one core) in 1 s with nothing to do");
}

#[test]
fn clients_that_reset_while_the_server_is_silent_leave_ibex_idle() {
    let spent = ticks_after_clients_leave(|c| {
        rustix::net::sockopt::set_socket_linger(&c, Some(Duration::ZERO)).expect("linger");
        drop(c);
    });
    assert!(spent < 10, "Ibex used {spent} ticks (100 = one core) in 1 s with nothing to do");
}
