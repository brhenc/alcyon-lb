// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What bounds the stats socket (T239). Measured on `HAProxy 3.5-dev8-885761-29`,
//! 2026-10-10, `tune.bufsize` 16384:
//! - a command line of 16383 bytes plus its line feed is read (and answered "Unknown command");
//!   one with no line feed in the first 16384 bytes is answered
//!   "The command line is too big for the buffer size. Please change 'tune.bufsize' in the
//!   configuration to use a bigger command.\n" and the connection is closed. 100,000 bytes
//!   without a line feed get the same answer.
//! - 10 concurrent CLI connections are served (`stats maxconn` default); the 11th is accepted
//!   by the kernel and gets nothing until one of the ten closes, then it is served.
//!   `stats maxconn <n>` moves the limit.

mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

struct Ibex {
    child: Child,
    sock: PathBuf,
    cfg: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start(global_extra: &str) -> Ibex {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let sock = PathBuf::from(format!("/tmp/ibex-cli-limits-{}-{n}.sock", std::process::id()));
    let cfg = std::env::temp_dir().join(format!("ibex-cli-limits-{}-{n}.cfg", std::process::id()));
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {} level admin\n{global_extra}\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n",
        sock.display()
    );
    std::fs::write(&cfg, text).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened");
    Ibex { child, sock, cfg }
}

fn rss_kb(pid: u32) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    let l = s.lines().find(|l| l.starts_with("VmRSS:")).expect("VmRSS");
    l.split_whitespace().nth(1).expect("value").parse().expect("number")
}

fn connect(i: &Ibex) -> UnixStream {
    let c = UnixStream::connect(&i.sock).expect("connect cli");
    c.set_read_timeout(Some(Duration::from_millis(700))).expect("timeout");
    c
}

fn read_some(c: &mut UnixStream) -> Option<Vec<u8>> {
    let mut b = [0u8; 256];
    match c.read(&mut b) {
        Ok(n) => Some(b[..n].to_vec()),
        Err(_) => None,
    }
}

const TOO_BIG: &str = "The command line is too big for the buffer size.";

#[test]
fn a_command_line_longer_than_the_buffer_is_refused_and_not_stored() {
    let ibex = start("");
    let pid = ibex.child.id();
    let before = rss_kb(pid);
    let mut c = connect(&ibex);
    // 8 MiB with no line feed: the connection is answered and closed long before.
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..128 {
        if c.write_all(&chunk).is_err() {
            break;
        }
    }
    let got = read_some(&mut c).unwrap_or_default();
    assert!(String::from_utf8_lossy(&got).starts_with(TOO_BIG), "answer: {:?}", String::from_utf8_lossy(&got));
    assert_eq!(read_some(&mut c), Some(Vec::new()), "the connection stays open");
    let grew = rss_kb(pid).saturating_sub(before);
    assert!(grew < 4096, "RSS grew by {grew} kB");
}

#[test]
fn a_line_that_fits_the_buffer_is_still_read() {
    let ibex = start("");
    let mut c = connect(&ibex);
    let mut line = vec![b'x'; 16_383];
    line.push(b'\n');
    c.write_all(&line).expect("send");
    let got = read_some(&mut c).unwrap_or_default();
    assert!(String::from_utf8_lossy(&got).starts_with("Unknown command"), "answer: {:?}", String::from_utf8_lossy(&got));
}

/// Opens `n` prompt-mode connections and checks each is served, then the next one is not.
fn held_after(ibex: &Ibex, n: usize) {
    let mut open = Vec::new();
    for i in 0..n {
        let mut c = connect(ibex);
        c.write_all(b"prompt\n").expect("send");
        assert!(read_some(&mut c).is_some_and(|b| !b.is_empty()), "connection {i} was not served");
        open.push(c);
    }
    let mut extra = connect(ibex);
    extra.write_all(b"show info\n").expect("send");
    assert_eq!(read_some(&mut extra), None, "connection {} was served past the limit", n + 1);
    drop(open.remove(0));
    extra.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let got = read_some(&mut extra).unwrap_or_default();
    assert!(String::from_utf8_lossy(&got).contains("Name:"), "not served after a slot freed: {:?}", String::from_utf8_lossy(&got));
}

#[test]
fn the_eleventh_cli_connection_waits_for_one_of_ten_to_close() {
    held_after(&start(""), 10);
}

#[test]
fn stats_maxconn_moves_the_cli_connection_limit() {
    held_after(&start("  stats maxconn 2\n"), 2);
}
