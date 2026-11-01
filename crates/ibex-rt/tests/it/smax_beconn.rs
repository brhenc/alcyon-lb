// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The backend's `scur`/`smax` follow `beconn`, the streams it holds (T583), and come back to
//! zero on every way a stream leaves it.
//!
//! Measured on HAProxy 3.5-dev8-885761-29 with this config and 6 requests held at 3 servers
//! (`balance roundrobin`): BACKEND scur 6 smax 6; each server scur = smax = the requests it took; after
//! the answers: scur 0, smax kept. Set `IBEX_SMAX_BIN` to run the same test on another binary.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Proc {
    child: Child,
    sock: PathBuf,
}

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn start(tag: &str, servers: &str, fe: std::net::SocketAddr) -> Proc {
    let sock = PathBuf::from(format!("/tmp/ibex-smax-{}-{tag}.sock", std::process::id()));
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 5s\n  timeout connect 2s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\n\
         backend b\n  balance roundrobin\n{servers}",
        sock.display()
    );
    let path = std::env::temp_dir().join(format!("ibex-smax-{}-{tag}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("cfg");
    let bin = std::env::var("IBEX_SMAX_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    assert!(common::wait_listening(fe), "never listened");
    let _ = std::fs::remove_file(&path);
    Proc { child, sock }
}

/// `(scur, smax)` of the rows named `b` / `BACKEND`, `b` / `s0`..`s2`.
fn rows(sock: &PathBuf) -> Vec<(String, u64, u64)> {
    let mut c = UnixStream::connect(sock).expect("cli");
    c.write_all(b"show stat\n").unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let mut lines = out.lines();
    let head: Vec<&str> = lines.next().unwrap().trim_start_matches("# ").split(',').collect();
    let (sc, sm) = (head.iter().position(|h| *h == "scur").unwrap(), head.iter().position(|h| *h == "smax").unwrap());
    lines
        .filter_map(|l| {
            let v: Vec<&str> = l.split(',').collect();
            (v.len() > sm && v[0] == "b").then(|| (v[1].to_string(), v[sc].parse().unwrap_or(0), v[sm].parse().unwrap_or(0)))
        })
        .collect()
}

fn get(rows: &[(String, u64, u64)], name: &str) -> (u64, u64) {
    rows.iter().find(|r| r.0 == name).map(|r| (r.1, r.2)).unwrap_or_else(|| panic!("no row {name}"))
}

fn settle(sock: &PathBuf, want: impl Fn(&[(String, u64, u64)]) -> bool) -> Vec<(String, u64, u64)> {
    for _ in 0..50 {
        let r = rows(sock);
        if want(&r) {
            return r;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    rows(sock)
}

#[test]
fn backend_scur_and_smax_count_held_streams_and_return_to_zero() {
    let ls: Vec<TcpListener> = (0..3).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
    let servers: String = ls.iter().enumerate().map(|(i, l)| format!("  server s{i} {}\n", l.local_addr().unwrap())).collect();
    let fe = common::reserve_addr();
    let p = start("hold", &servers, fe);

    let mut clients = Vec::new();
    for _ in 0..6 {
        let mut c = TcpStream::connect(fe).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        clients.push(c);
    }
    // Which server took which request is the balancer's business (HAProxy's roundrobin gave
    // 3/2/1 here, Ibex 2/2/2): the rows must agree with what each server accepted.
    let mut held: Vec<(usize, TcpStream)> = Vec::new();
    for l in &ls {
        l.set_nonblocking(true).unwrap();
    }
    let t0 = std::time::Instant::now();
    while held.len() < 6 && t0.elapsed() < Duration::from_secs(5) {
        for (i, l) in ls.iter().enumerate() {
            if let Ok((mut s, _)) = l.accept() {
                s.set_nonblocking(false).unwrap();
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).unwrap();
                held.push((i, s));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(held.len(), 6);
    let counts: Vec<u64> = (0..3).map(|i| held.iter().filter(|h| h.0 == i).count() as u64).collect();
    let per = |i: usize| counts[i];
    let r = settle(&p.sock, |r| get(r, "BACKEND").0 == 6);
    assert_eq!(get(&r, "BACKEND"), (6, 6));
    for i in 0..3 {
        assert_eq!(get(&r, &format!("s{i}")), (per(i), per(i)), "s{i}");
    }
    for (_, s) in &mut held {
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
    }
    for c in &mut clients {
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = Vec::new();
        let mut b = [0u8; 256];
        while !got.ends_with(b"ok") {
            let n = c.read(&mut b).unwrap();
            assert!(n > 0);
            got.extend_from_slice(&b[..n]);
        }
    }
    drop(clients);
    let r = settle(&p.sock, |r| get(r, "BACKEND").0 == 0);
    assert_eq!(get(&r, "BACKEND"), (0, 6));
    for i in 0..3 {
        assert_eq!(get(&r, &format!("s{i}")), (0, per(i)), "s{i}");
    }
}

/// An error page (connect refused: a 503) and a client that leaves while the server holds the
/// request both release the backend: `scur` returns to 0 and `smax` stays at what was held.
#[test]
fn backend_scur_returns_to_zero_after_an_error_page_and_an_abort() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let fe = common::reserve_addr();
    let p = start("err", &format!("  server s0 {dead}\n"), fe);
    let mut c = TcpStream::connect(fe).unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert!(got.starts_with(b"HTTP/1.1 503"), "{:?}", String::from_utf8_lossy(&got));
    let r = settle(&p.sock, |r| get(r, "BACKEND").0 == 0);
    assert_eq!(get(&r, "BACKEND").0, 0);
    drop(p);

    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let fe = common::reserve_addr();
    let p = start("abort", &format!("  server s0 {}\n", l.local_addr().unwrap()), fe);
    let mut c = TcpStream::connect(fe).unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let (mut s, _) = l.accept().unwrap();
    let mut b = [0u8; 512];
    let _ = s.read(&mut b).unwrap();
    let r = settle(&p.sock, |r| get(r, "BACKEND").0 == 1);
    assert_eq!(get(&r, "BACKEND"), (1, 1));
    drop(c);
    let r = settle(&p.sock, |r| get(r, "BACKEND").0 == 0);
    assert_eq!(get(&r, "BACKEND"), (0, 1));
}
