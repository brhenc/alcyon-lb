// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! One idle connection pool per server, shared by the worker threads (T159 part B,
//! `tune.idle-pool.shared`), against the real binary.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29: `nbthread 4`, one `listen` with `http-reuse
//! always` and one server, a backend that numbers the connections it accepts; each client
//! connection carries one request, so where it lands among the threads is up to the
//! listener (the load across threads is uneven by construction). Three runs each:
//!
//! | `tune.idle-pool.shared` | 40 clients one after the other | 3 x (8 at once, 20 one after the other) |
//! |---|---|---|
//! | `on` (default) | 1 backend connection (39 reused) | 8 (76 reused) |
//! | `off`          | 4 (one per thread)               | 8 to 10 |
//!
//! `conn_backend_get`: a thread whose own lists hold nothing for the server tries the other
//! threads' lists (`HA_SPIN_TRYLOCK`, a busy list is skipped) and takes the connection over;
//! with `tune.idle-pool.shared off` it opens a new one.

use crate::common;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// A backend whose answers say which of its accepted connections carried the request;
/// `/slow` is answered after 50 ms.
fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let id = count.fetch_add(1, Ordering::SeqCst) + 1;
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut pending = Vec::new();
                'conn: loop {
                    let n = match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    pending.extend_from_slice(&buf[..n]);
                    while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = pending.drain(..end + 4).collect();
                        if head.starts_with(b"GET /slow") {
                            thread::sleep(Duration::from_millis(50));
                        }
                        let rsp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Conn: {id}\r\n\r\n");
                        if s.write_all(rsp.as_bytes()).is_err() {
                            break 'conn;
                        }
                    }
                }
            });
        }
    });
    addr
}

struct Alcyon(Child, #[allow(dead_code)] NamedTempFile);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(shared: Option<&str>, be: SocketAddr) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let tune = shared.map_or(String::new(), |s| format!("  tune.idle-pool.shared {s}\n"));
    let cfg = format!(
        "global\n  nbthread 4\n{tune}defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         listen l\n  bind {fe}\n  http-reuse always\n  server s {be}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !common::wait_listening(fe) {
        assert!(Instant::now() < deadline, "alcyon never started listening on {fe}");
    }
    // Every worker binds its own socket: give the others time to.
    thread::sleep(Duration::from_millis(300));
    (Alcyon(child, f), fe)
}

/// One request of `path` on a client connection of its own: the backend connection that
/// carried it.
fn request(fe: SocketAddr, path: &str) -> usize {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
        }
    }
    let resp = String::from_utf8_lossy(&resp).to_ascii_lowercase();
    resp.split("x-conn: ")
        .nth(1)
        .and_then(|r| r.split("\r\n").next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("no answer: {resp:?}"))
}

/// 40 client connections one after the other: the backend connections they used.
fn sequential(shared: Option<&str>) -> usize {
    let be = backend();
    let (_alcyon, fe) = start(shared, be);
    let used: HashSet<usize> = (0..40)
        .map(|_| {
            let c = request(fe, "/");
            thread::sleep(Duration::from_millis(20));
            c
        })
        .collect();
    used.len()
}

#[test]
fn shared_by_default_one_connection_serves_clients_on_every_thread() {
    assert_eq!(sequential(None), 1);
}

#[test]
fn shared_on_one_connection_serves_clients_on_every_thread() {
    assert_eq!(sequential(Some("on")), 1);
}

/// Each thread keeps its own: as many connections as threads the clients landed on.
#[test]
fn shared_off_each_thread_opens_its_own() {
    assert_eq!(sequential(Some("off")), 4);
}

/// Bursts of 8 concurrent requests between sequential ones: the 8 connections a burst
/// opened, wherever they went idle, carry every later request (`HAProxy`: 8).
#[test]
fn bursts_reuse_the_connections_idle_on_other_threads() {
    let be = backend();
    let (_alcyon, fe) = start(None, be);
    let mut used = HashSet::new();
    for _ in 0..3 {
        let burst: Vec<_> = (0..8).map(|_| thread::spawn(move || request(fe, "/slow"))).collect();
        used.extend(burst.into_iter().map(|t| t.join().unwrap()));
        // A client can read its answer before its worker has put the server connection
        // back: on a loaded machine the next request would then open a ninth, on HAProxy
        // as here. Let the workers catch up between phases.
        thread::sleep(Duration::from_millis(100));
        for _ in 0..20 {
            used.insert(request(fe, "/"));
            thread::sleep(Duration::from_millis(10));
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(used.len(), 8, "backend connections: {used:?}");
}

/// `tune.idle-pool.shared` takes `full`, `on` or `off` only, as `HAProxy`'s parser. Alcyon has
/// one thread group, so `full` (every thread) is `on` (the threads of the group).
#[test]
fn tune_idle_pool_shared_takes_on_or_off() {
    for (arg, ok) in [("full", true), ("on", true), ("off", true), ("maybe", false)] {
        let fe = common::reserve_addr();
        let mut f = NamedTempFile::new().expect("tmp");
        write!(f, "global\n  tune.idle-pool.shared {arg}\ndefaults\n  mode http\nlisten l\n  bind {fe}\n  server s 127.0.0.1:1\n").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("alcyon -c");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.success(), ok, "{arg}: {err}");
        assert!(!err.contains("ignored"), "{arg}: {err}");
    }
}
