// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T468: `tune.memory.prealloc on` (Ibex extension; `HAProxy` 3.5-dev8 has no such keyword and
//! nothing that pre-fills a pool) sizes the pools from `maxconn` at start: 2 standard buffers
//! and one session slot per connection, per worker thread `ceil(maxconn / nbthread)`. The load
//! refuses it without an explicit `maxconn` or `-m`, and when `maxconn` needs more than `-m`.
//! After start the buffer pool does not grow: a burst of `maxconn` connections leaves `show
//! pools`' `allocated` where it was.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Ibex(Child, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("t468-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const DEFAULTS: &str = "defaults\n    mode http\n    timeout client 60s\n    timeout server 60s\n    timeout connect 5s\n";

/// `ibex -c` on `global` plus a frontend; returns (exit code, stderr).
fn check(tag: &str, global: &str, args: &[&str]) -> (i32, String) {
    let d = dir(tag);
    let path = d.join("c.cfg");
    std::fs::write(&path, format!("global\n{global}{DEFAULTS}frontend f\n    bind 127.0.0.1:{}\n", common::reserve_port())).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").args(args).arg("-f").arg(&path).output().unwrap();
    let _ = std::fs::remove_dir_all(&d);
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn prealloc_needs_maxconn_or_m_and_fits_m() {
    let (code, err) = check("nomaxconn", "    tune.memory.prealloc on\n", &[]);
    assert_eq!(code, 1, "accepted without maxconn: {err}");
    assert!(err.contains("'tune.memory.prealloc' needs an explicit global 'maxconn' or '-m' to size the pools."), "{err}");
    assert_eq!(check("maxconn", "    maxconn 100\n    tune.memory.prealloc on\n", &[]).0, 0);
    assert_eq!(check("m", "    tune.memory.prealloc on\n", &["-m", "100"]).0, 0);
    // 100 connections at 2 x 16 KiB and a session slot are ~3.3 MB: within `-m 100`.
    let (code, err) = check("fits", "    maxconn 100\n    tune.memory.prealloc on\n", &["-m", "100"]);
    assert_eq!(code, 0, "refused within -m: {err}");
    assert_eq!(check("off", "    tune.memory.prealloc off\n", &[]).0, 0);
    // 10000 connections at 2 x 16 KiB are 312 MiB and more, past `-m 64`.
    let (code, err) = check("toobig", "    maxconn 10000\n    tune.memory.prealloc on\n", &["-m", "64"]);
    assert_eq!(code, 1, "accepted past -m: {err}");
    assert!(err.contains("'tune.memory.prealloc': maxconn 10000 needs"), "{err}");
    assert!(err.contains("more than the 64 MB of '-m'"), "{err}");
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `allocated` and `failures` of the `show pools` line of pool `name`.
fn pool(sock: &str, name: &str) -> (usize, usize) {
    let out = cli(sock, "show pools");
    let line = out.lines().find(|l| l.trim_start().starts_with(&format!("- Pool {name} ("))).unwrap_or_else(|| panic!("no {name} pool line in {out:?}"));
    let allocated = line.split(" : ").nth(1).and_then(|r| r.split_whitespace().next()).and_then(|n| n.parse().ok()).expect("allocated");
    let failures = line.split(", ").find(|f| f.ends_with(" failures")).and_then(|f| f.split_whitespace().next()).and_then(|n| n.parse().ok()).expect("failures");
    (allocated, failures)
}

/// `used` less `cached` of pool `name`: what streams hold.
fn in_use(sock: &str, name: &str) -> usize {
    let out = cli(sock, "show pools");
    let line = out.lines().find(|l| l.trim_start().starts_with(&format!("- Pool {name} ("))).unwrap_or_else(|| panic!("no {name} pool line in {out:?}"));
    let rest = line.split(" bytes), ").nth(1).expect("pool line layout");
    let used: usize = rest.split_whitespace().next().and_then(|n| n.parse().ok()).expect("used");
    let cached: usize = rest.split("(~").nth(1).and_then(|c| c.split_whitespace().next()).and_then(|c| c.parse().ok()).expect("cached");
    used - cached
}

/// A backend that answers every connection with a body larger than the buffers on the way,
/// written until the socket is full: a client that does not read holds its stream's buffers.
fn flood() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        while let Ok((mut c, _)) = l.accept() {
            std::thread::spawn(move || {
                let mut req = [0u8; 4096];
                let _ = c.read(&mut req);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n");
                let chunk = [b'x'; 16384];
                while c.write_all(&chunk).is_ok() {}
            });
        }
    });
    addr
}

/// A worker that cannot make what `maxconn` implies does not start: `maxconn 10000` needs ~330 MB
/// of buffers, `RLIMIT_DATA` is 150 MB (`prlimit`, so the check against `-m` does not refuse it
/// first). The process exits 1 and says what it could not allocate.
#[test]
fn a_worker_that_cannot_presize_refuses_to_start() {
    let d = dir("oom");
    let path = d.join("c.cfg");
    std::fs::write(&path, format!("global\n    nbthread 1\n    maxconn 10000\n    tune.memory.prealloc on\n{DEFAULTS}frontend f\n    bind 127.0.0.1:{}\n", common::reserve_port())).unwrap();
    let out = Command::new("prlimit")
        .arg(format!("--data={}", 150 * 1_048_576))
        .arg("--")
        .arg(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&d);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("Failed to initialize Ibex engine (worker 0): tune.memory.prealloc: cannot allocate 20000 buffers and 10000 session slots"), "{err}");
}

/// `ibex -f` on `global` and a frontend; waits for the stats socket and the first publication.
fn start(tag: &str, global: &str) -> (Ibex, String) {
    let fe = common::reserve_addr();
    let d = dir(tag);
    let sock = d.join("cli.sock").display().to_string();
    let path = d.join("c.cfg");
    std::fs::write(&path, format!("global\n{global}    stats socket {sock} level admin\n{DEFAULTS}frontend f\n    bind {fe}\n")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let ibex = Ibex(child, d);
    assert!(common::wait_listening(fe), "ibex did not listen");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));
    (ibex, sock)
}

/// A `tune.buffers.limit` below `2 * maxconn` is the pool's size: 10 buffers, not 100.
#[test]
fn a_smaller_buffers_limit_sizes_the_buffer_pool() {
    let (_ibex, sock) = start("limit", "    nbthread 1\n    maxconn 50\n    tune.buffers.limit 10\n    tune.memory.prealloc on\n");
    assert_eq!(pool(&sock, "buffer"), (10, 0));
    assert_eq!(pool(&sock, "session").0, 50);
}

const MAXCONN: usize = 50;

#[test]
fn show_pools_shows_the_presize_at_start_and_after_a_burst_of_maxconn() {
    let be = flood();
    let fe = common::reserve_addr();
    let d = dir("burst");
    let sock = d.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n    nbthread 1\n    maxconn {MAXCONN}\n    tune.memory.prealloc on\n    stats socket {sock} level admin\n{DEFAULTS}\
         frontend f\n    bind {fe}\n    default_backend b\nbackend b\n    server s {be}\n"
    );
    let path = d.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = Ibex(child, d);
    assert!(common::wait_listening(fe), "ibex did not listen");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    // The counters are published once per loop pass, at most every 10 ms.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(pool(&sock, "buffer"), (2 * MAXCONN, 0), "standard buffers right after start");
    assert_eq!(pool(&sock, "session").0, MAXCONN, "session slots right after start");

    // Every connection holds a response it does not read. One connection is left for the CLI's.
    let mut clients = Vec::new();
    for _ in 0..MAXCONN - 1 {
        let mut c = TcpStream::connect(fe).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        clients.push(c);
    }
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(pool(&sock, "buffer"), (2 * MAXCONN, 0), "standard buffers during the burst");
    let held = in_use(&sock, "buffer");
    assert!(held >= MAXCONN - 1, "the burst holds {held} buffers: it does not load the pool");
    assert_eq!(pool(&sock, "session").0, MAXCONN, "session slots during the burst");
    drop(clients);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(pool(&sock, "buffer"), (2 * MAXCONN, 0), "standard buffers after the burst");
    assert_eq!(pool(&sock, "session").0, MAXCONN, "session slots after the burst");
}

/// T475: `nbthread 2`, `maxconn 100`: the limit is 200 buffers, each thread's cache is filled
/// with 100. All connections land on thread 1 (`bind ... thread 1`): 80 held connections need
/// 160 buffers, more than thread 1's 100, while thread 2 holds 100 idle ones. None of the 80 may
/// be refused (the process is at 80 of 100 connections) and the pool does not grow past 200.
#[test]
#[ignore = "T475: a thread out of its share cannot use the buffers another thread holds yet (design in tasks/T475-progress.md)"]
fn a_thread_out_of_its_share_uses_the_buffers_other_threads_hold() {
    const HELD: usize = 80;
    let be = flood();
    let fe = common::reserve_addr();
    let d = dir("shared");
    let sock = d.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n    nbthread 2\n    maxconn 100\n    tune.memory.prealloc on\n    stats socket {sock} level admin\n{DEFAULTS}\
         frontend f\n    bind {fe} thread 1\n    default_backend b\nbackend b\n    server s {be}\n"
    );
    let path = d.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _ibex = Ibex(child, d);
    assert!(common::wait_listening(fe), "ibex did not listen");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(pool(&sock, "buffer"), (200, 0), "standard buffers right after start");

    let mut clients = Vec::new();
    for _ in 0..HELD {
        let mut c = TcpStream::connect(fe).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        clients.push(c);
    }
    std::thread::sleep(Duration::from_millis(1000));
    let held = in_use(&sock, "buffer");
    assert_eq!(pool(&sock, "buffer"), (200, 0), "standard buffers during the burst ({held} held)");
    assert!(held >= 2 * HELD, "the {HELD} connections hold {held} buffers: some were refused or wait");
    drop(clients);
}
