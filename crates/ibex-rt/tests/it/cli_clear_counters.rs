// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `clear counters` on the CLI (T146 items 19 and 20), measured on the reference `HAProxy`
//! 3.5-dev8-885761-29 with a frontend, two backends and a few requests:
//!
//! * `clear counters` resets only the maxima (`smax` goes to 0, `scur` being 0) of every
//!   proxy; `stot`, `bin`, `bout`, `econ`, `wretr` and the rest stay;
//! * any other word after it (`clear counters bl`, `clear counters nosuch`) is ignored and
//!   it does the same: there is no per-proxy form, and no "No such backend" for it;
//! * `clear counters all` resets all of them, in every proxy (an argument after `all` is
//!   ignored too), the per-server `econ` and `wretr` included;
//! * `clear counters server <be>/<sv>` resets that server's counters and nothing else.
//!
//! The reply of each of these, when nothing is wrong, is the empty line.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child, std::path::PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.1);
    }
}

fn live_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            c.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf);
            thread::sleep(Duration::from_millis(30));
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

fn get_status(port: u16, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(8))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).split(' ').nth(1).unwrap_or("").to_string()
}

fn cli(sock: &std::path::Path, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read");
    out
}

/// One column of `show stat` by `(proxy, server)`.
fn column(sock: &std::path::Path, name: &str) -> Vec<(String, String, String)> {
    let out = cli(sock, "show stat");
    let mut lines = out.lines();
    let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let col = header.iter().position(|h| *h == name).unwrap_or_else(|| panic!("a {name} column"));
    lines
        .filter(|l| !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (f[0].to_string(), f[1].to_string(), f[col].to_string())
        })
        .collect()
}

fn value(sock: &std::path::Path, name: &str, px: &str, sv: &str) -> String {
    column(sock, name).into_iter().find(|r| r.0 == px && r.1 == sv).unwrap_or_else(|| panic!("no row {px}/{sv}")).2
}

#[test]
fn clear_counters_resets_the_maxima_all_resets_everything_and_the_rest_is_ignored() {
    let live = live_backend();
    let dead = common::reserve_port();
    let port = common::reserve_port();
    let dir = std::env::temp_dir();
    let sock = dir.join(format!("ibex_t146_clear_{}.sock", std::process::id()));
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f\n  bind 127.0.0.1:{port}\n  use_backend bd if {{ path /d }}\n  default_backend bl\n\
         backend bl\n  server l 127.0.0.1:{live}\n\
         backend bd\n  retries 0\n  server d 127.0.0.1:{dead}\n",
        sock.display()
    );
    let path = dir.join(format!("ibex_t146_clear_{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let _d = Daemon(child, path);
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() || !sock.exists() {
        assert!(Instant::now() < deadline, "the daemon never listened");
        thread::sleep(Duration::from_millis(25));
    }

    let traffic = || {
        assert_eq!(get_status(port, "/l"), "200");
        assert_eq!(get_status(port, "/l"), "200");
        assert_eq!(get_status(port, "/d"), "503");
    };
    traffic();
    let smax = |px: &str, sv: &str| value(&sock, "smax", px, sv);
    let stot = |px: &str, sv: &str| value(&sock, "stot", px, sv);
    assert_ne!(smax("f", "FRONTEND"), "0");
    assert_ne!(stot("f", "FRONTEND"), "0");
    assert_eq!(value(&sock, "econ", "bd", "BACKEND"), "1");

    // Plain, and with a word it ignores: the maxima only, in every proxy.
    for cmd in ["clear counters", "clear counters bl", "clear counters nosuch"] {
        traffic();
        // The last request's session is taken off `scur` a moment after its client saw the
        // answer; a clear before that would find it current. Wait for the proxy to be idle.
        let idle_by = Instant::now() + Duration::from_secs(10);
        while Instant::now() < idle_by && (value(&sock, "scur", "f", "FRONTEND") != "0" || value(&sock, "scur", "bl", "BACKEND") != "0") {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(cli(&sock, cmd), "\n", "{cmd}");
        assert_eq!(smax("f", "FRONTEND"), "0", "{cmd}: smax of the frontend");
        assert_eq!(smax("bl", "BACKEND"), "0", "{cmd}: smax of the other backend, too");
        assert_ne!(stot("f", "FRONTEND"), "0", "{cmd} must leave the totals");
        assert_ne!(value(&sock, "econ", "bd", "BACKEND"), "0", "{cmd} must leave econ");
    }

    // `clear counters server` resets that server's counters and no other.
    assert_eq!(cli(&sock, "clear counters server bd/d"), "Server counters cleared.\n\n");
    assert_eq!(value(&sock, "econ", "bd", "d"), "0");
    assert_ne!(value(&sock, "econ", "bd", "BACKEND"), "0", "the backend keeps its own");
    // The wrong forms, as HAProxy answers them (measured on 3.5-dev8-885761-29): a bare
    // server name is not enough, and each miss is a message and a blank line.
    assert_eq!(cli(&sock, "clear counters server d"), "Require 'backend/server'.\n\n");
    assert_eq!(cli(&sock, "clear counters server nobe/d"), "No such backend.\n\n");
    assert_eq!(cli(&sock, "clear counters server bd/nosuch"), "No such server.\n\n");

    // `all`, with or without something after it: everything, in every proxy.
    traffic();
    assert_eq!(cli(&sock, "clear counters all bl"), "\n");
    for (px, sv) in [("f", "FRONTEND"), ("bl", "BACKEND"), ("bl", "l"), ("bd", "BACKEND"), ("bd", "d")] {
        assert_eq!(stot(px, sv), "0", "{px}/{sv} after clear counters all");
    }
    assert_eq!(value(&sock, "econ", "bd", "BACKEND"), "0");
}
