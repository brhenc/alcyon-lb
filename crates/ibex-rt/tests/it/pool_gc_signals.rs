// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T445: the signals on which `HAProxy` runs `pool_gc` (SIGQUIT, SIGTTOU, SIGUSR1) empty
//! Ibex's pool caches.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (nbthread 4, 500 connections opened at once,
//! each with a request head half sent, then completed and closed):
//!
//! | after            | `buffer` pool                                   | RSS       |
//! |------------------|-------------------------------------------------|-----------|
//! | the burst        | 112 allocated, 112 used (~93 by thread caches)  | 93.7 MB   |
//! | SIGQUIT          | the same; still serving                         | 91.1 MB   |
//! | SIGTTOU          | the same; listeners paused (connection refused) | 91.1 MB   |
//! | SIGUSR1          | the same; a half-sent request holds it open     | 91.2 MB   |
//!
//! `pool_gc` frees each pool's shared free list down to `minavail` and trims the heap; its
//! per-thread caches are not touched, which is why the counts stay. Ibex has only per-thread
//! caches (64 buffers a thread, where `HAProxy`'s cache is 512 kB a thread), so its collector
//! empties them: after each signal no buffer is cached. A CLI session opened before the
//! signal answers after it on both (`HAProxy` pauses and stops its stats listener).
//!
//! These spawn ibex and signal the child, not the test process: they share the `it` binary.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Run {
    ibex: common::Ibex,
    dir: std::path::PathBuf,
    sock: String,
    addr: SocketAddr,
}

impl Drop for Run {
    fn drop(&mut self) {
        common::stop(&mut self.ibex);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start(tag: &str, nbthread: usize) -> Run {
    start_with(tag, nbthread, "")
}

fn start_with(tag: &str, nbthread: usize, fe_extra: &str) -> Run {
    let addr = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("pgc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n  nbthread {nbthread}\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 30s\n  timeout server 30s\n\
         frontend fe\n  bind {addr}\n{fe_extra}  http-request return status 200 content-type text/plain string 0123456789\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let run = Run { ibex: common::Ibex(child), dir, sock, addr };
    assert!(common::wait_listening(addr), "ibex did not listen on {addr}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&run.sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    run
}

/// An interactive CLI session (`prompt`), opened before a signal and used after it.
struct Cli(UnixStream);

impl Cli {
    fn open(sock: &str) -> Self {
        let mut s = UnixStream::connect(sock).expect("cli");
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(b"prompt\n").unwrap();
        let mut c = Cli(s);
        c.read();
        c
    }

    fn read(&mut self) -> String {
        let mut out = Vec::new();
        let mut b = [0u8; 8192];
        while !out.ends_with(b"\n> ") {
            match self.0.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&b[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn cmd(&mut self, c: &str) -> String {
        self.0.write_all(format!("{c}\n").as_bytes()).expect("cli write");
        self.read()
    }
}

/// `(allocated, cached)` of the `buffer` pool in a `show pools` dump.
fn buffers(dump: &str) -> (usize, usize) {
    let line = dump.lines().find(|l| l.contains("Pool buffer ")).unwrap_or_else(|| panic!("no buffer pool in {dump:?}"));
    let num = |after: &str, before: &str| -> usize {
        let rest = &line[line.find(after).unwrap() + after.len()..];
        rest[..rest.find(before).unwrap()].trim().parse().unwrap()
    };
    (num(" : ", " allocated"), num("(~", " by thread caches"))
}

/// 500 connections at once, each holding a buffer with half a request head, then each
/// request completed and its answer read.
fn burst(addr: SocketAddr) {
    let mut conns: Vec<TcpStream> = (0..500)
        .map(|_| {
            let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
            s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    for s in &mut conns {
        s.write_all(b"Connection: close\r\n\r\n").unwrap();
    }
    for mut s in conns {
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        assert!(out.starts_with(b"HTTP/1.1 200"), "burst answer {:?}", String::from_utf8_lossy(&out));
    }
}

/// Cached buffers after the burst, then the signal, then the cache seen empty within 2 s.
fn caches_empty_after(cli: &mut Cli, ibex: &common::Ibex, sig: rustix::process::Signal) -> String {
    let (alloc, cached) = buffers(&cli.cmd("show pools"));
    assert!(cached > 0 && alloc >= cached, "the burst left no cached buffer: {alloc} allocated, {cached} cached");
    let pid = rustix::process::Pid::from_raw(i32::try_from(ibex.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, sig).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let dump = cli.cmd("show pools");
        let (a, c) = buffers(&dump);
        if c == 0 {
            assert!(a < alloc, "the cache is empty but nothing was freed: {a} allocated, was {alloc}");
            return dump;
        }
        assert!(Instant::now() < deadline, "{sig:?}: {c} buffers still cached ({a} allocated), was {cached}:\n{dump}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn get(addr: SocketAddr) -> Vec<u8> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    out
}

#[test]
fn sigquit_flushes_the_caches_and_keeps_serving() {
    let mut run = start("quit", 2);
    burst(run.addr);
    let mut cli = Cli::open(&run.sock);
    caches_empty_after(&mut cli, &run.ibex, rustix::process::Signal::Quit);
    assert!(run.ibex.try_wait().unwrap().is_none(), "SIGQUIT ended ibex");
    assert!(get(run.addr).starts_with(b"HTTP/1.1 200"), "not serving after SIGQUIT");
    // `show info` follows `show pools`: nothing cached is counted in either.
    let info = cli.cmd("show info");
    assert!(info.contains("PoolAlloc_MB: 0"), "show info after SIGQUIT: {info}");
}

#[test]
fn sigttou_flushes_the_caches() {
    let run = start("ttou", 2);
    burst(run.addr);
    let mut cli = Cli::open(&run.sock);
    caches_empty_after(&mut cli, &run.ibex, rustix::process::Signal::Ttou);
    let pid = rustix::process::Pid::from_raw(i32::try_from(run.ibex.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::Ttin).unwrap();
}

#[test]
fn sigusr1_flushes_the_caches_while_a_connection_holds_the_stop() {
    // One thread: the CLI session and the held connection live on the same worker, which
    // a stopping worker without sessions would otherwise leave.
    let mut run = start("usr1", 1);
    burst(run.addr);
    let mut held = TcpStream::connect_timeout(&run.addr, Duration::from_secs(2)).expect("connect");
    held.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
    let mut cli = Cli::open(&run.sock);
    std::thread::sleep(Duration::from_millis(100));
    caches_empty_after(&mut cli, &run.ibex, rustix::process::Signal::Usr1);
    assert!(run.ibex.try_wait().unwrap().is_none(), "the held connection did not keep the soft stop open");
    drop(held);
}

/// The stop path (`src/proxy.c:3715`): while stopping, a stick-table purge that freed
/// entries runs `pool_gc` again. The soft stop's own collection empties the cache; a request
/// finished afterwards caches its buffers again, and only the purge of the expired entry
/// empties it a second time.
#[test]
fn a_purge_while_stopping_flushes_the_caches_again() {
    let mut run = start_with(
        "purge",
        1,
        "  stick-table type ip size 10 expire 500ms\n  http-request track-sc0 src\n",
    );
    let mut held = TcpStream::connect_timeout(&run.addr, Duration::from_secs(2)).expect("connect");
    held.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
    let mut late = TcpStream::connect_timeout(&run.addr, Duration::from_secs(2)).expect("connect");
    late.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap();
    burst(run.addr);
    let mut cli = Cli::open(&run.sock);
    std::thread::sleep(Duration::from_millis(100));
    caches_empty_after(&mut cli, &run.ibex, rustix::process::Signal::Usr1);
    // Finished now, its entry refreshed: its buffers go back to the cache.
    late.write_all(b"Connection: close\r\n\r\n").unwrap();
    late.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut out = Vec::new();
    let _ = late.read_to_end(&mut out);
    assert!(out.starts_with(b"HTTP/1.1 200"), "late answer {:?}", String::from_utf8_lossy(&out));
    let (_, cached) = buffers(&cli.cmd("show pools"));
    assert!(cached > 0, "the late request cached no buffer");
    // The entry expires after 500 ms and is purged within 250 ms more.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let dump = cli.cmd("show pools");
        if buffers(&dump).1 == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "the purge while stopping did not flush the cache:\n{dump}");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(run.ibex.try_wait().unwrap().is_none(), "the held connection did not keep the soft stop open");
    drop(held);
}
