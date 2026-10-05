// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Connection limits: frontend `maxconn` default, `defaults maxconn`, `global maxconn` (T182).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (see `tasks/T182-frontend-maxconn-default.md`):
//! a frontend without `maxconn` has `slim` = the global maxconn; `defaults maxconn` sets it;
//! frontend `maxconn N` is a total over all threads (`nbthread 4` still accepts exactly N);
//! connections over the limit wait in the kernel backlog (no reset) and are served as slots
//! free; `global maxconn` caps all frontends together.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Ibex {
    child: Child,
    sock: PathBuf,
    dir: PathBuf,
    fes: Vec<SocketAddr>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn backend() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            thread::spawn(move || {
                let mut b = [0u8; 4096];
                while let Ok(n) = c.read(&mut b) {
                    if n == 0 || c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// `global`/`defaults` are extra lines; `fes` is each frontend's `maxconn` line (or empty).
fn start(global: &str, defaults: &str, fes: &[&str], nbthread: u32) -> Ibex {
    start_with(&[], global, defaults, fes, nbthread)
}

fn start_with(args: &[&str], global: &str, defaults: &str, fes: &[&str], nbthread: u32) -> Ibex {
    let addrs: Vec<SocketAddr> = fes.iter().map(|_| common::reserve_addr()).collect();
    let dir = std::env::temp_dir().join(format!("ibex_t182_{}_{}", std::process::id(), addrs[0].port()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("s.sock");
    let mut cfg = format!(
        "global\n  nbthread {nbthread}\n  stats socket {} level admin\n{global}\n\
         defaults\n  mode http\n  timeout client 30s\n  timeout connect 1s\n  timeout server 30s\n{defaults}\n",
        sock.display()
    );
    for (i, (fe, a)) in fes.iter().zip(&addrs).enumerate() {
        cfg += &format!("frontend f{i}\n  bind {a}\n  {fe}\n  default_backend be\n");
    }
    cfg += &format!("backend be\n  server s {}\n", backend());
    std::fs::write(dir.join("cfg"), cfg).expect("cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).args(args).arg("-f").arg(dir.join("cfg")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let ibex = Ibex { child, sock, dir, fes: addrs.clone() };
    for a in addrs {
        assert!(common::wait_listening(a));
    }
    let end = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&ibex.sock).is_err() {
        assert!(Instant::now() < end, "the stats socket never came up");
        thread::sleep(Duration::from_millis(25));
    }
    ibex
}

fn cli(sock: &Path, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `slim` of every frontend, in `show stat`.
fn slims(sock: &Path) -> Vec<String> {
    let st = cli(sock, "show stat");
    let hdr: Vec<&str> = st.lines().next().expect("header").trim_start_matches("# ").split(',').collect();
    let col = hdr.iter().position(|c| *c == "slim").expect("slim column");
    st.lines().skip(1).map(|l| l.split(',').collect::<Vec<_>>()).filter(|f| f.get(1) == Some(&"FRONTEND")).map(|f| f[col].to_string()).collect()
}

fn info(sock: &Path, key: &str) -> String {
    cli(sock, "show info").lines().find_map(|l| l.strip_prefix(&format!("{key}: ")).map(str::to_string)).unwrap_or_default()
}

/// Opens `n` connections round-robin over the frontends, each sending one request.
fn open(addrs: &[SocketAddr], n: usize) -> Vec<TcpStream> {
    (0..n)
        .map(|i| {
            let mut s = TcpStream::connect(addrs[i % addrs.len()]).expect("connect");
            s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
            s
        })
        .collect()
}

/// Which of the connections were answered, waiting up to `wait` for each.
fn answered(conns: &mut [TcpStream], wait: Duration) -> Vec<bool> {
    let end = Instant::now() + wait;
    conns
        .iter_mut()
        .map(|s| {
            let left = end.saturating_duration_since(Instant::now()).max(Duration::from_millis(20));
            s.set_read_timeout(Some(left)).expect("timeout");
            let mut b = [0u8; 64];
            matches!(s.read(&mut b), Ok(n) if n > 0)
        })
        .collect()
}

/// `limit` connections are served at once and the rest, still open, only once those close.
fn assert_limit(ibex: &Ibex, total: usize, limit: usize) {
    let mut conns = open(&ibex.fes, total);
    let ok = answered(&mut conns, Duration::from_secs(4));
    assert_eq!(ok.iter().filter(|&&k| k).count(), limit, "served at once");
    // Closing the served ones frees slots; the others, queued in the backlog, are served.
    let mut waiting = Vec::new();
    for (s, k) in conns.into_iter().zip(ok) {
        if !k {
            waiting.push(s);
        }
    }
    let first_batch = total - waiting.len();
    assert_eq!(first_batch, limit);
    // The served connections were dropped above only when not in `waiting`: they are gone.
    let ok2 = answered(&mut waiting, Duration::from_secs(5));
    assert_eq!(ok2.iter().filter(|&&k| k).count(), waiting.len(), "queued connections served as slots free");
}

#[test]
fn a_frontend_without_maxconn_takes_the_global_one() {
    let ibex = start("maxconn 50", "", &[""], 1);
    assert_eq!(slims(&ibex.sock), ["50"]);
    let ibex2 = start("", "", &[""], 1);
    assert_eq!(slims(&ibex2.sock), [info(&ibex2.sock, "Maxconn")]);
}

#[test]
fn the_n_option_caps_the_frontend_limit() {
    let ibex = start_with(&["-n", "8"], "maxconn 50", "", &["maxconn 20", ""], 1);
    assert_eq!(slims(&ibex.sock), ["8", "8"]);
    let mut conns = open(&ibex.fes[..1], 12);
    let ok = answered(&mut conns, Duration::from_secs(4));
    assert_eq!(ok.iter().filter(|&&k| k).count(), 8, "served at once");
}

#[test]
fn defaults_maxconn_is_the_frontend_limit() {
    let ibex = start("maxconn 50", "maxconn 30", &[""], 1);
    assert_eq!(slims(&ibex.sock), ["30"]);
}

#[test]
fn frontend_maxconn_is_a_total_over_all_threads() {
    let ibex = start("maxconn 50", "", &["maxconn 20"], 4);
    assert_eq!(slims(&ibex.sock), ["20"]);
    assert_limit(&ibex, 40, 20);
}

#[test]
fn global_maxconn_caps_all_frontends_together() {
    let ibex = start("maxconn 50", "", &["", ""], 4);
    assert_limit(&ibex, 70, 50);
}

#[test]
fn raising_frontend_maxconn_rearms_a_full_listener() {
    let ibex = start("maxconn 50", "", &["maxconn 5"], 4);
    let mut conns = open(&ibex.fes, 10);
    let ok = answered(&mut conns, Duration::from_secs(4));
    assert_eq!(ok.iter().filter(|&&k| k).count(), 5, "served at once");
    assert_eq!(cli(&ibex.sock, "set maxconn frontend f0 20"), "\n");
    let mut rest: Vec<TcpStream> = conns.into_iter().zip(ok).filter(|(_, k)| !k).map(|(s, _)| s).collect();
    let ok2 = answered(&mut rest, Duration::from_secs(5));
    assert!(ok2.iter().all(|&k| k), "the connections in the backlog are served without a close: {ok2:?}");
}

#[test]
fn the_default_frontend_limit_lets_in_more_than_2000_idle_connections() {
    let l = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    if let Some(max) = l.maximum {
        let _ = rustix::process::setrlimit(rustix::process::Resource::Nofile, rustix::process::Rlimit { current: Some(max.min(65536)), maximum: Some(max) });
    }
    // The idle connections must outlive the test: a client timeout would free slots.
    let ibex = start("", "timeout client 300s", &[""], 1);
    let idle: Vec<TcpStream> = (0..2500)
        .map(|i| TcpStream::connect_timeout(&ibex.fes[0], Duration::from_secs(3)).unwrap_or_else(|e| panic!("connection {i} not accepted into the backlog: {e}")))
        .collect();
    // A request on a new connection is still answered.
    let mut probe = open(&ibex.fes, 1);
    assert_eq!(answered(&mut probe, Duration::from_secs(3)), [true], "a new request with 2500 idle connections open");
    drop(idle);
}
