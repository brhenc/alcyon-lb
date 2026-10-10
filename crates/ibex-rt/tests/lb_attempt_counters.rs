// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Where `show stat` counts a stream's connection attempts and server choices (T225).
//!
//! `HAProxy` counts a server's `stot` at each connect attempt made on it
//! (`srv_inc_sess_ctr` in `back_handle_st_req`/`connect_server`), and `lbtot` on the backend
//! and the server each time the load balancer picks a server other than the last one
//! (`assign_server`); a server chosen by a persistence cookie, `use-server` or `stick match`
//! (`SF_DIRECT`) is not a pick. Measured on `HAProxy 3.5-dev8-885761-29` (2026-10-10):
//!
//! - two servers, s2's port closed, `retries 3`, `option redispatch 1`, `balance
//!   roundrobin`, 6 `Connection: close` requests then 4 keep-alive ones: s1 `stot=10
//!   lbtot=10`, s2 `stot=8 lbtot=8 wredis=8`, BACKEND `stot=10 lbtot=18 wredis=8`. Ibex
//!   counted every attempt on the server that answered (s1 `stot=19`), and s2 none.
//! - `cookie SRV insert indirect nocache`, 5 requests with `SRV=s1`, then 4 without: s1
//!   `stot=5` and no `lbtot`, s2 `stot=4 lbtot=4`, BACKEND `lbtot=4`. Ibex counted all 9 in
//!   `lbtot`.
//! - one server down, `retries 2`, 3 requests: s1 `stot=9 lbtot=3 wretr=6 econ=3`. Ibex
//!   already matched.
//!
//! The round robin's order is not checked here: only where each attempt and pick is counted.

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

struct Ibex {
    child: Child,
    sock: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

type Stats = HashMap<String, HashMap<String, u64>>;

/// A server that answers every request.
fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("server");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&b[..n]),
                    }
                    while let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        got.drain(..i + 4);
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

/// An address nothing listens on: a connect to it is refused.
fn refused() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().unwrap()
}

/// `b`'s BACKEND and server lines of `show stat`, by `svname`, numeric fields only.
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
        if v.len() < 2 || v[0] != "b" {
            continue;
        }
        let row = head.iter().cloned().zip(v.iter().map(|s| s.parse().unwrap_or(0))).collect();
        all.insert(v[1].to_string(), row);
    }
    all
}

fn get(st: &Stats, sv: &str, name: &str) -> u64 {
    st.get(sv).and_then(|r| r.get(name)).copied().unwrap_or(0)
}

/// Ibex with `backend` as `b`'s body; `requests` is a list of (cookie, connection close).
fn run(backend: &str, requests: &[(Option<&str>, bool)]) -> Stats {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let sock = PathBuf::from(format!("/tmp/ibex-lbc-{}-{n}.sock", std::process::id()));
    let fe = common::reserve_addr();
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 2s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n{backend}",
        sock.display()
    );
    let path = std::env::temp_dir().join(format!("ibex-lbc-{}-{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = Ibex { child, sock };
    assert!(common::wait_listening(fe), "ibex never listened");
    let _ = std::fs::remove_file(&path);

    let mut kept: Option<TcpStream> = None;
    for (cookie, close) in requests {
        let mut c = match kept.take() {
            Some(c) if !close => c,
            _ => TcpStream::connect(fe).expect("connect"),
        };
        c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
        let ck = cookie.map_or(String::new(), |v| format!("Cookie: SRV={v}\r\n"));
        let conn = if *close { "Connection: close\r\n" } else { "" };
        c.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\n{ck}{conn}\r\n").as_bytes()).expect("send");
        let mut got = Vec::new();
        let mut b = [0u8; 1024];
        while !(got.windows(4).any(|w| w == b"\r\n\r\n") && (got.ends_with(b"ok") || got.ends_with(b"</html>\n"))) {
            match c.read(&mut b) {
                Ok(0) | Err(_) => break,
                Ok(r) => got.extend_from_slice(&b[..r]),
            }
        }
        assert!(got.starts_with(b"HTTP/1.1 "), "no response: {:?}", String::from_utf8_lossy(&got));
        if !close {
            kept = Some(c);
        }
    }
    thread::sleep(Duration::from_millis(200));
    stats(&ibex.sock)
}

/// Every attempt on the dead server is counted there, where it was made, and so is the
/// pick that sent the request to it; the server that answered counts its own attempts.
#[test]
fn each_attempt_and_pick_is_counted_on_the_server_it_was_made_on() {
    let (s1, s2) = (server(), refused());
    let mut reqs = vec![(None, true); 6];
    reqs.extend([(None, false); 4]);
    let st = run(&format!("  balance roundrobin\n  retries 3\n  option redispatch 1\n  server s1 {s1}\n  server s2 {s2}\n"), &reqs);
    let s2_tries = get(&st, "s2", "wredis");
    assert!(s2_tries > 0, "no request went to s2 first");
    assert_eq!(get(&st, "s1", "stot"), 10, "s1 stot: one attempt per request, all answered");
    assert_eq!(get(&st, "s1", "lbtot"), 10, "s1 lbtot");
    assert_eq!(get(&st, "s2", "stot"), s2_tries, "s2 stot: one per attempt (HAProxy 8, wredis 8)");
    assert_eq!(get(&st, "s2", "lbtot"), s2_tries, "s2 lbtot: one per pick");
    assert_eq!(get(&st, "BACKEND", "stot"), 10, "BACKEND stot");
    assert_eq!(get(&st, "BACKEND", "lbtot"), 10 + s2_tries, "BACKEND lbtot: every pick");
}

/// A server a persistence cookie chose is not a load-balancing pick.
#[test]
fn a_server_the_cookie_chose_is_not_counted_as_balanced() {
    let (s1, s2) = (server(), server());
    let mut reqs = vec![(Some("s1"), true); 5];
    reqs.extend([(None, true); 4]);
    let st = run(&format!("  balance roundrobin\n  cookie SRV insert indirect nocache\n  server s1 {s1} cookie s1\n  server s2 {s2} cookie s2\n"), &reqs);
    let balanced = get(&st, "s1", "lbtot") + get(&st, "s2", "lbtot");
    assert_eq!(get(&st, "s1", "stot") + get(&st, "s2", "stot"), 9, "stot of s1 and s2");
    assert_eq!(balanced, 4, "only the 4 requests without the cookie were balanced (HAProxy: s1 0, s2 4)");
    assert_eq!(get(&st, "BACKEND", "lbtot"), 4, "BACKEND lbtot");
}

/// Retries on one server: every attempt counted there, one pick per request (already so).
#[test]
fn retries_on_one_server_count_every_attempt_there() {
    let st = run(&format!("  retries 2\n  server s1 {}\n", refused()), &[(None, true); 3]);
    assert_eq!((get(&st, "s1", "stot"), get(&st, "s1", "lbtot"), get(&st, "s1", "wretr"), get(&st, "s1", "econ")), (9, 3, 6, 3));
}
