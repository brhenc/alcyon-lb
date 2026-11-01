// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A server's `maxconn` holds across workers (T590).
//!
//! `maxconn` on a server is a hard limit: `HAProxy` admits a stream to it only while
//! `srv->served < srv_dynamic_maxconn(srv)`, taken under the server's lock (`assign_server`,
//! `pendconn_dequeue`, `process_srv_queue` in src/queue.c), so no two threads take its last
//! slot. Ibex's workers checked the server's count and raised it later, apart: two workers
//! that both saw `0 < 1` both connected, and a server with `maxconn 1` held two connections
//! (`cli_changes_all_workers::set_maxconn_server_reaches_every_worker`, 2 of 30 runs).
//!
//! Here eight workers send 48 concurrent requests to a slow server with `maxconn 1`; the
//! server counts the connections it holds at once (released before it answers, so that the
//! next connection, which Ibex opens only after the answer, never overlaps it here). The
//! peak must be 1, and so must `smax` in `show stat`.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const CLIENTS: usize = 48;

struct Backend {
    addr: SocketAddr,
    peak: Arc<AtomicUsize>,
}

fn backend(delay: Duration) -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    let cur = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let (c2, p2) = (cur.clone(), peak.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let (cur, peak) = (c2.clone(), p2.clone());
            std::thread::spawn(move || {
                let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                std::thread::sleep(delay);
                cur.fetch_sub(1, Ordering::SeqCst);
                let _ = conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
            });
        }
    });
    Backend { addr, peak }
}

struct Ibex {
    child: Child,
    sock: PathBuf,
    cfg: PathBuf,
    fe: SocketAddr,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start(servers: &str) -> Ibex {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tag = format!("ibex_t590_{}_{n}", std::process::id());
    let tmp = std::env::temp_dir();
    let (sock, cfg) = (tmp.join(format!("{tag}.sock")), tmp.join(format!("{tag}.cfg")));
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  stats socket {sock} mode 600 level admin\n  nbthread 8\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 30s\n  timeout server 30s\n  timeout queue 30s\n\
         frontend f\n  bind {fe}\n  maxconn 200\n  default_backend be\n\
         backend be\n  balance roundrobin\n{servers}",
        sock = sock.display(),
    );
    std::fs::write(&cfg, &text).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, sock, cfg, fe };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.sock.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
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

/// `smax` of `be,<sv>` in `show stat`.
fn smax(ibex: &Ibex, sv: &str) -> String {
    let text = cli(ibex, "show stat");
    text.lines()
        .find(|l| l.starts_with(&format!("be,{sv},")))
        .and_then(|l| l.split(',').nth(5))
        .map_or_else(|| format!("<no be,{sv} in {text:?}>"), str::to_string)
}

/// `CLIENTS` requests at once; every one is answered.
fn burst(fe: SocketAddr) {
    let threads: Vec<_> = (0..CLIENTS)
        .map(|_| {
            std::thread::spawn(move || {
                let mut c = TcpStream::connect(fe).expect("connect");
                c.set_read_timeout(Some(Duration::from_secs(30))).expect("timeout");
                c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
                let mut got = Vec::new();
                let _ = c.read_to_end(&mut got);
                String::from_utf8_lossy(&got).into_owned()
            })
        })
        .collect();
    for t in threads {
        let text = t.join().expect("client");
        assert!(text.starts_with("HTTP/1.1 200"), "{text:?}");
    }
}

#[test]
fn server_maxconn_one_holds_across_workers() {
    let a = backend(Duration::from_millis(20));
    let ibex = start(&format!("  server a {} maxconn 1\n", a.addr));
    burst(ibex.fe);
    assert_eq!(a.peak.load(Ordering::SeqCst), 1, "server a held more than its maxconn 1");
    assert_eq!(smax(&ibex, "a"), "1");
}

#[test]
fn set_maxconn_server_holds_across_workers() {
    let a = backend(Duration::from_millis(20));
    let b = backend(Duration::from_millis(20));
    let ibex = start(&format!("  server a {}\n  server b {}\n", a.addr, b.addr));
    assert_eq!(cli(&ibex, "set maxconn server be/a 1"), "\n");
    assert_eq!(cli(&ibex, "set maxconn server be/b 1"), "\n");
    burst(ibex.fe);
    assert_eq!((a.peak.load(Ordering::SeqCst), b.peak.load(Ordering::SeqCst)), (1, 1), "a server held more than its maxconn 1");
}
