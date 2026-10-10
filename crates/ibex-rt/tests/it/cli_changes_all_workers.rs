// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Runtime changes from the CLI and the stats page reach every worker (T177).
//!
//! The CLI lives on one worker; the proxies are shared by all of them. A write must change
//! the shared state, not a copy for the worker that served the command. Each test issues a
//! command once, then makes 40 fresh connections, which spread over the four threads.
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-05, `nbthread 4`, `balance
//! roundrobin` over `a` and `b`, 40 connections each:
//!
//! * before any change: 20 to `a`, 20 to `b`;
//! * `set weight be/a 0`, `set server be/a weight 0`, `disable server be/a`, `set server
//!   be/a state maint`, and the stats page's `action=maint` form: 40 to `b`;
//! * `set server be/a addr 127.0.0.1 port <c>` answers `port changed from '<a>' to '<c>' by
//!   'stats socket command'`, then 20 to `b` and 20 to `c`;
//! * `set maxconn server be/b 7` and `set maxconn frontend f 9`: `slim` of `be,b` is 7 and
//!   of `f,FRONTEND` 9 in `show stat` and on the stats page;
//! * `set maxconn frontend f 1` with 12 idle connections held: a 13th connection's request
//!   gets no answer (it waits in the backlog).

use crate::common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A backend server answering `x-s: <name>`, after `delay`, counting how many connections
/// it holds at once.
struct Backend {
    addr: SocketAddr,
    peak: Arc<AtomicUsize>,
}

fn backend(name: &'static str, delay: Duration) -> Backend {
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
                let _ = conn.set_read_timeout(Some(Duration::from_secs(3)));
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                std::thread::sleep(delay);
                let _ = conn.write_all(
                    format!("HTTP/1.1 200 OK\r\nx-s: {name}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").as_bytes(),
                );
                cur.fetch_sub(1, Ordering::SeqCst);
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
    stats: SocketAddr,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start(a: SocketAddr, b: SocketAddr) -> Ibex {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir();
    let tag = format!("ibex_t177_{}_{n}", std::process::id());
    let (sock, cfg) = (tmp.join(format!("{tag}.sock")), tmp.join(format!("{tag}.cfg")));
    let (fe, stats) = (common::reserve_addr(), common::reserve_addr());
    let text = format!(
        "global\n  stats socket {sock} mode 600 level admin\n  nbthread 4\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 3s\n  timeout server 3s\n  timeout queue 3s\n\
         frontend f\n  bind {fe}\n  maxconn 50\n  default_backend be\n\
         backend be\n  balance roundrobin\n  server a {a}\n  server b {b}\n\
         listen st\n  bind {stats}\n  stats enable\n  stats uri /\n  stats admin if TRUE\n",
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
    let ibex = Ibex { child, sock, cfg, fe, stats };
    assert!(common::wait_listening(fe), "ibex never listened with:\n{text}");
    assert!(common::wait_listening(stats), "stats never listened");
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

fn http(addr: SocketAddr, req: &str) -> String {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(req.as_bytes()).expect("send");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    String::from_utf8_lossy(&got).into_owned()
}

/// Which server answered one fresh connection.
fn hit(ibex: &Ibex) -> String {
    let text = http(ibex.fe, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    text.split("\r\n")
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("x-s: ").map(str::to_string))
        .unwrap_or_else(|| format!("<none in {text:?}>"))
}

/// How 40 fresh connections spread over the servers.
fn spread(ibex: &Ibex) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for _ in 0..40 {
        *m.entry(hit(ibex)).or_insert(0) += 1;
    }
    m
}

/// `slim` of `<px>,<sv>` on the stats page, over 40 fresh connections (every worker).
fn page_slims(ibex: &Ibex, px: &str, sv: &str) -> Vec<String> {
    let mut seen: Vec<String> = (0..40)
        .map(|_| {
            let text = http(ibex.stats, "GET /;csv HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            text.lines()
                .find(|l| l.starts_with(&format!("{px},{sv},")))
                .and_then(|l| l.split(',').nth(6))
                .map_or_else(|| format!("<no {px},{sv} in {text:?}>"), str::to_string)
        })
        .collect();
    seen.sort();
    seen.dedup();
    seen
}

fn only_b() -> BTreeMap<String, usize> {
    BTreeMap::from([("b".to_string(), 40)])
}

fn two_servers() -> (Backend, Backend, Ibex) {
    let (a, b) = (backend("a", Duration::ZERO), backend("b", Duration::ZERO));
    let ibex = start(a.addr, b.addr);
    (a, b, ibex)
}

#[test]
fn set_weight_reaches_every_worker() {
    let (_a, _b, ibex) = two_servers();
    assert_eq!(spread(&ibex), BTreeMap::from([("a".to_string(), 20), ("b".to_string(), 20)]));
    assert_eq!(cli(&ibex, "set weight be/a 0"), "\n");
    assert_eq!(spread(&ibex), only_b());
    assert_eq!(cli(&ibex, "get weight be/a"), "0 (initial 1)\n\n");
    assert_eq!(cli(&ibex, "set weight be/a 1"), "\n");
    assert_eq!(cli(&ibex, "set server be/a weight 0"), "\n");
    assert_eq!(spread(&ibex), only_b());
}

#[test]
fn disable_server_and_state_reach_every_worker() {
    let (_a, _b, ibex) = two_servers();
    assert_eq!(cli(&ibex, "disable server be/a"), "\n");
    assert_eq!(spread(&ibex), only_b());
    assert_eq!(cli(&ibex, "enable server be/a"), "\n");
    assert_eq!(cli(&ibex, "set server be/a state maint"), "\n");
    assert_eq!(spread(&ibex), only_b());
    // The errors end with an empty line too (measured).
    for verb in ["disable", "enable"] {
        assert_eq!(cli(&ibex, &format!("{verb} server zz/a")), "No such backend.\n\n");
        assert_eq!(cli(&ibex, &format!("{verb} server be/zz")), "No such server.\n\n");
        assert_eq!(cli(&ibex, &format!("{verb} server bea")), "Require 'backend/server'.\n\n");
    }
}

#[test]
fn set_server_addr_reaches_every_worker() {
    let (a, _b, ibex) = two_servers();
    let c = backend("c", Duration::ZERO);
    assert_eq!(
        cli(&ibex, &format!("set server be/a addr 127.0.0.1 port {}", c.addr.port())),
        format!("port changed from '{}' to '{}' by 'stats socket command'\n\n", a.addr.port(), c.addr.port())
    );
    let got = spread(&ibex);
    assert!(!got.contains_key("a"), "a connection still went to the old address: {got:?}");
    assert_eq!(got.values().sum::<usize>(), 40, "{got:?}");
    assert_eq!(got.keys().cloned().collect::<Vec<_>>(), ["b", "c"], "{got:?}");
}

#[test]
fn set_maxconn_server_reaches_every_worker() {
    let a = backend("a", Duration::from_millis(100));
    let b = backend("b", Duration::ZERO);
    let ibex = start(a.addr, b.addr);
    assert_eq!(cli(&ibex, "set maxconn server be/a 1"), "\n");
    assert_eq!(page_slims(&ibex, "be", "a"), ["1"]);
    // Sixteen at once: eight for `a`, which takes one at a time and queues the rest.
    let fe = ibex.fe;
    let threads: Vec<_> = (0..16)
        .map(|_| std::thread::spawn(move || http(fe, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")))
        .collect();
    for t in threads {
        let text = t.join().expect("client");
        assert!(text.starts_with("HTTP/1.1 200"), "{text:?}");
    }
    assert_eq!(a.peak.load(Ordering::SeqCst), 1, "server a held more than its maxconn");
}

#[test]
fn set_maxconn_frontend_reaches_every_worker() {
    let (_a, _b, ibex) = two_servers();
    assert_eq!(cli(&ibex, "set maxconn frontend f 9"), "\n");
    assert_eq!(page_slims(&ibex, "f", "FRONTEND"), ["9"]);
    assert_eq!(cli(&ibex, "set maxconn frontend f 1"), "\n");
    // Twelve idle connections fill every worker's share of the frontend; a thirteenth
    // waits in the backlog and is not answered.
    let held: Vec<TcpStream> = (0..12).map(|_| TcpStream::connect(ibex.fe).expect("connect")).collect();
    std::thread::sleep(Duration::from_millis(200));
    let mut c = TcpStream::connect(ibex.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(800))).expect("timeout");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    let mut buf = [0u8; 64];
    let got = c.read(&mut buf);
    assert!(got.is_err(), "answered past maxconn 1: {:?}", got.map(|n| String::from_utf8_lossy(&buf[..n]).into_owned()));
    drop(held);
}

#[test]
fn stats_page_form_reaches_every_worker() {
    let (_a, _b, ibex) = two_servers();
    let post = |body: &str| {
        http(
            ibex.stats,
            &format!(
                "POST / HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        )
    };
    let text = post("b=be&s=a&weight=0");
    assert!(text.starts_with("HTTP/1.1 303") || text.starts_with("HTTP/1.1 200"), "{text:?}");
    assert_eq!(spread(&ibex), only_b());
    assert_eq!(cli(&ibex, "get weight be/a"), "0 (initial 1)\n\n");
    let _ = post("b=be&s=a&weight=1");
    let _ = post("b=be&s=b&maxconn=3");
    assert_eq!(page_slims(&ibex, "be", "b"), ["3"]);
    // With an action, the form's `maxconn` goes with it.
    let _ = post("b=be&s=b&action=ready&maxconn=4");
    assert_eq!(page_slims(&ibex, "be", "b"), ["4"]);
    let _ = post("b=be&s=a&action=maint");
    assert_eq!(spread(&ibex), only_b());
}
