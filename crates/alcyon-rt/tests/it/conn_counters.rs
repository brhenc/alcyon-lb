// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The `connect` and `reuse` columns of `show stat` and the log's connection counts (T225).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` (2026-10-10):
//!
//! - `connect` and `reuse` count each attempt to reach the server, on the server and the
//!   backend (`connect_server`): `reuse` when the stream uses a connection that already
//!   exists (its client connection's, or one from the idle lists), `connect` when it makes a
//!   new one, failed attempts included. 2 client connections with 4 keep-alive requests each:
//!   `connect=2 reuse=6`; then 3 `Connection: close` requests: `connect=5 reuse=6`. One
//!   request to a refused port with `retries 2`: `connect=3`.
//! - `%ac` is the process's client connections, `%fc` the frontend's (this stream's included,
//!   idle keep-alive ones too), `%bc` the backend's other streams, `%sc` the server's other
//!   streams (the stream has let go of both when the line is made; the stats socket's
//!   connections are not counted). `%rc` carries a `+` only when the server changed.

use crate::common;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct Alcyon {
    child: Child,
    sock: PathBuf,
    fa: SocketAddr,
    fb: SocketAddr,
    fw: SocketAddr,
    logs: Arc<Mutex<Vec<String>>>,
    released: Arc<Mutex<HashSet<String>>>,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// A server that answers every request; `/hold/N` waits until `N` is released.
fn server(released: Arc<Mutex<HashSet<String>>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("server");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let released = released.clone();
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                    while let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&got[..i]).to_string();
                        got.drain(..i + 4);
                        let path = head.split(' ').nth(1).unwrap_or("").to_string();
                        if path.starts_with("/hold/") {
                            let end = Instant::now() + Duration::from_secs(15);
                            while !released.lock().unwrap().contains(&path) && Instant::now() < end {
                                thread::sleep(Duration::from_millis(5));
                            }
                        }
                        if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

fn start() -> Alcyon {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let sock = PathBuf::from(format!("/tmp/alcyon-cc-{}-{n}.sock", std::process::id()));
    let released = Arc::new(Mutex::new(HashSet::new()));
    let srv = server(released.clone());
    // A reserved port nothing listens on; an ephemeral one released by `bind(0)` can be handed
    // to another test's socket (or to Alcyon's own outgoing connection) under load.
    let dead = common::reserve_addr();
    let udp = UdpSocket::bind("127.0.0.1:0").expect("log socket");
    let log_addr = udp.local_addr().unwrap();
    let logs = Arc::new(Mutex::new(Vec::new()));
    let sink = logs.clone();
    thread::spawn(move || {
        let mut b = [0u8; 4096];
        while let Ok(n) = udp.recv(&mut b) {
            let l = String::from_utf8_lossy(&b[..n]).to_string();
            // The last two words: the counts and the path.
            let w: Vec<&str> = l.trim_end().rsplitn(3, ' ').collect();
            sink.lock().unwrap().push(format!("{} {}", w[1], w[0]));
        }
    });
    let (fa, fb, fw) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let cfg = format!(
        "global\n  stats socket {sock} level admin\n  log {log_addr} local0\n\
         defaults\n  mode http\n  log global\n  option dontlognull\n  log-format \"%ac/%fc/%bc/%sc/%rc %HP\"\n  timeout client 15s\n  timeout connect 2s\n  timeout server 15s\n  retries 2\n\
         frontend fa\n  bind {fa}\n  default_backend x\n\
         frontend fb\n  bind {fb}\n  default_backend y\n\
         frontend fw\n  bind {fw}\n  default_backend w\n\
         backend x\n  server s1 {srv}\n\
         backend y\n  server s2 {srv}\n\
         backend w\n  server d3 {dead}\n",
        sock = sock.display()
    );
    let path = std::env::temp_dir().join(format!("alcyon-cc-{}-{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(std::env::var("CC_BIN").unwrap_or(env!("CARGO_BIN_EXE_alcyon").into())).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon");
    let alcyon = Alcyon { child, sock, fa, fb, fw, logs, released };
    assert!(common::wait_listening(fa), "alcyon never listened");
    let _ = std::fs::remove_file(&path);
    alcyon
}

/// Connects, retrying while the listener is not up yet: `start` waits for the first
/// frontend only, and a probe connection to the others would be counted by the tests.
fn connect(addr: SocketAddr) -> TcpStream {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(addr) {
            Ok(c) => return c,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused && Instant::now() < end => thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("connect {addr}: {e}"),
        }
    }
}

fn send(c: &mut TcpStream, path: &str, close: bool) {
    let cl = if close { "Connection: close\r\n" } else { "" };
    c.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n{cl}\r\n").as_bytes()).expect("send");
}

fn answer(c: &mut TcpStream) -> String {
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut got = Vec::new();
    let mut b = [0u8; 1024];
    while !got.ends_with(b"ok") && !got.windows(4).any(|w| w == b"\r\n\r\n" && !got.starts_with(b"HTTP/1.1 200")) {
        match c.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    String::from_utf8_lossy(&got).to_string()
}

/// Waits for `n` log lines in all and returns them.
fn log_lines(alcyon: &Alcyon, n: usize) -> Vec<String> {
    let end = Instant::now() + Duration::from_secs(20);
    while alcyon.logs.lock().unwrap().len() < n && Instant::now() < end {
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(50));
    alcyon.logs.lock().unwrap().clone()
}

type Stats = HashMap<(String, String), HashMap<String, String>>;

fn stats(sock: &PathBuf) -> Stats {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(b"show stat\n").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let mut lines = out.lines();
    let head: Vec<String> = lines.next().unwrap_or("").trim_start_matches("# ").split(',').map(str::to_string).collect();
    let mut all = HashMap::new();
    for l in lines {
        let v: Vec<&str> = l.split(',').collect();
        if v.len() < 2 {
            continue;
        }
        all.insert((v[0].to_string(), v[1].to_string()), head.iter().cloned().zip(v.iter().map(|s| (*s).to_string())).collect());
    }
    all
}

fn col(st: &Stats, px: &str, sv: &str, name: &str) -> String {
    st.get(&(px.to_string(), sv.to_string())).and_then(|r| r.get(name)).cloned().unwrap_or_default()
}

#[test]
fn connect_and_reuse_count_each_attempt_on_server_and_backend() {
    let alcyon = start();
    let mut cs: Vec<TcpStream> = (0..2).map(|_| connect(alcyon.fa)).collect();
    for round in 0..4 {
        for c in &mut cs {
            send(c, &format!("/k{round}"), false);
            answer(c);
        }
    }
    drop(cs);
    thread::sleep(Duration::from_millis(200));
    let st = stats(&alcyon.sock);
    for sv in ["s1", "BACKEND"] {
        assert_eq!(col(&st, "x", sv, "connect"), "2", "{sv} connect after 2 connections");
        assert_eq!(col(&st, "x", sv, "reuse"), "6", "{sv} reuse after 2 connections");
    }
    for _ in 0..3 {
        let mut c = connect(alcyon.fa);
        send(&mut c, "/c", true);
        answer(&mut c);
    }
    thread::sleep(Duration::from_millis(200));
    let st = stats(&alcyon.sock);
    for sv in ["s1", "BACKEND"] {
        assert_eq!(col(&st, "x", sv, "connect"), "5", "{sv} connect after 3 close requests");
        assert_eq!(col(&st, "x", sv, "reuse"), "6", "{sv} reuse after 3 close requests");
    }
    // A frontend has neither column filled.
    assert_eq!(col(&st, "fa", "FRONTEND", "connect"), "");
}

#[test]
fn failed_attempts_count_as_connects() {
    let alcyon = start();
    let mut c = connect(alcyon.fw);
    send(&mut c, "/w", true);
    assert!(answer(&mut c).starts_with("HTTP/1.1 503"));
    // The retries finish after the 503 is out: wait for the counters, do not guess a delay.
    let end = Instant::now() + Duration::from_secs(20);
    let mut st = stats(&alcyon.sock);
    while col(&st, "w", "d3", "connect") != "3" && Instant::now() < end {
        thread::sleep(Duration::from_millis(20));
        st = stats(&alcyon.sock);
    }
    for sv in ["d3", "BACKEND"] {
        assert_eq!(col(&st, "w", sv, "connect"), "3", "{sv} connect: 1 + retries 2");
        assert_eq!(col(&st, "w", sv, "reuse"), "0", "{sv} reuse");
    }
    // Same server throughout: no `+` in `%rc`.
    assert_eq!(log_lines(&alcyon, 1), ["1/1/0/0/2 /w"]);
}

#[test]
fn log_counts_are_the_processs_the_frontends_and_the_other_streams() {
    let alcyon = start();
    let hold = |addr: SocketAddr, n: usize| {
        let mut c = connect(addr);
        send(&mut c, &format!("/hold/{n}"), false);
        c
    };
    // Three held on x (fa), two held on y (fb), one idle keep-alive connection on fa.
    let mut held: Vec<TcpStream> = vec![hold(alcyon.fa, 0), hold(alcyon.fa, 1), hold(alcyon.fa, 2), hold(alcyon.fb, 3), hold(alcyon.fb, 4)];
    thread::sleep(Duration::from_millis(300)); // all five are on their servers
    let mut idle = connect(alcyon.fa);
    send(&mut idle, "/idle", false);
    answer(&mut idle);
    thread::sleep(Duration::from_millis(300));
    let mut q = connect(alcyon.fa);
    send(&mut q, "/q", true);
    answer(&mut q);
    drop(q);
    thread::sleep(Duration::from_millis(100));
    let mut q2 = connect(alcyon.fb);
    send(&mut q2, "/q2", true);
    answer(&mut q2);
    drop(q2);
    let got = log_lines(&alcyon, 3);
    // /idle finished before the others held: the held ones were already on their servers.
    assert_eq!(got, ["6/4/3/3/0 /idle", "7/5/3/3/0 /q", "7/3/2/2/0 /q2"]);
    // Release one at a time, each client closing after its answer.
    let expect = ["6/4/2/2/0 /hold/0", "5/3/1/1/0 /hold/1", "4/2/0/0/0 /hold/2", "3/2/1/1/0 /hold/3", "2/1/0/0/0 /hold/4"];
    let mut seen = got.len();
    for (i, c) in held.iter_mut().enumerate() {
        alcyon.released.lock().unwrap().insert(format!("/hold/{i}"));
        answer(c);
        let all = log_lines(&alcyon, seen + 1);
        seen = all.len();
        assert_eq!(all[seen - 1], expect[i], "release {i}");
        c.shutdown(std::net::Shutdown::Both).unwrap();
        thread::sleep(Duration::from_millis(200));
    }
}
