// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T236: `log stdout` / `log stderr` never block a worker.
//!
//! HAProxy makes the descriptor O_NONBLOCK (unless it is a tty), and a line it cannot write
//! is dropped and counted (`DroppedLogs` in `show info`). Measured on 3.5-dev8-885761-29:
//! with stdout a pipe nobody reads, `log stdout format raw local0` and 3000 requests, every
//! request is answered and `DroppedLogs` is non-zero.
//!
//! Each test gives ibex a pipe for the stream under test and never reads it, sends far more
//! log lines than a pipe holds (64 KiB), and gives every request a read timeout so a blocked
//! worker fails the test rather than hanging it.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        // Close our end of the pipes first: a worker stuck in a log write is then released
        // (EPIPE) and can handle SIGUSR1; stop() falls back to SIGKILL after five seconds.
        drop(self.0.stdout.take());
        drop(self.0.stderr.take());
        common::stop(&mut self.0);
    }
}

fn config(addr: SocketAddr, sock: &str, target: &str) -> String {
    format!(
        "global\n  nbthread 1\n  log {target} format raw local0\n  stats socket {sock}\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 1s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {addr}\n  http-request return status 200 content-type text/plain string ok\n"
    )
}

fn get(addr: SocketAddr) -> Result<(), String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"GET /a-path-long-enough-to-make-the-log-line-big HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("write: {e}"))?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| format!("read: {e}"))?;
    if out.starts_with("HTTP/1.1 200") { Ok(()) } else { Err(format!("bad answer {out:?}")) }
}

fn show_info(sock: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s.write_all(b"show info\n").unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// Starts ibex (optionally under `-W`) with `which` ("stdout"/"stderr") a pipe nobody reads
/// and the other one discarded, then sends 3000 requests.
fn run(tag: &str, target: &str, master: bool) -> (Guard, String) {
    let dir = std::path::PathBuf::from(format!("/tmp/t236-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let addr = common::reserve_addr();
    let cfg = dir.join("c.cfg");
    std::fs::write(&cfg, config(addr, &sock, target)).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ibex"));
    if master {
        cmd.arg("-W");
    }
    cmd.arg("-f").arg(&cfg);
    if target == "stdout" {
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    } else {
        cmd.stderr(Stdio::piped()).stdout(Stdio::null());
    }
    let g = Guard(cmd.spawn().expect("spawn"));
    assert!(common::wait_listening(addr), "ibex did not start");
    for i in 0..3000 {
        if let Err(e) = get(addr) {
            panic!("request {i} was not answered: {e} (a worker is blocked on a log write)");
        }
    }
    (g, sock)
}

#[test]
fn stdout_pipe_nobody_reads_does_not_block_requests() {
    let (_g, sock) = run("out", "stdout", false);
    let info = show_info(&sock);
    let dropped: u64 = info.lines().find_map(|l| l.strip_prefix("DroppedLogs: ")).and_then(|v| v.trim().parse().ok()).expect("DroppedLogs");
    assert!(dropped > 0, "lines that could not be written are counted: {info}");
}

#[test]
fn stderr_pipe_nobody_reads_does_not_block_requests() {
    let (_g, _sock) = run("err", "stderr", false);
}

#[test]
fn master_mode_stdout_pipe_nobody_reads_does_not_block_requests() {
    let (_g, _sock) = run("mout", "stdout", true);
}

#[test]
fn master_mode_stderr_pipe_nobody_reads_does_not_block_requests() {
    // The worker's stderr goes through the master, which writes it to its own stderr.
    let (_g, _sock) = run("merr", "stderr", true);
}
