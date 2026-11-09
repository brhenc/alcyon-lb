// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T597 item 1: the check columns of `show stat` are the same whichever worker answers.
//! The checks run on worker 0 (T593); a `show stat` served by another worker has to read
//! them from published state. Oracle (HAProxy 3.5-dev8-885761-29, `nbthread 4`, a
//! `tcp-check connect` server that is UP): every answer has `check_status` L4OK,
//! `last_chk` "(tcp-check)", `chkfail` 0 and `check_duration` set.

use crate::common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// The stats page in CSV (`/s;csv`) over a fresh connection: any worker may answer.
fn http_csv(addr: &str) -> String {
    let mut s = std::net::TcpStream::connect(addr).expect("connect st");
    s.write_all(b"GET /s;csv HTTP/1.0\r\n\r\n").expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    out.split_once("\r\n\r\n").map_or(String::new(), |x| x.1.to_string())
}

#[test]
fn check_columns_are_the_same_on_every_worker() {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for s in l.incoming() {
            if let Ok(s) = s {
                thread::spawn(move || {
                    let _s = s;
                    thread::sleep(Duration::from_secs(5));
                });
            }
        }
    });
    let dir = tempfile::TempDir::new().expect("tmp");
    let sock = dir.path().join("stats.sock");
    let front = common::reserve_addr();
    let st = common::reserve_addr();
    let cfg = format!(
        "global\n  nbthread 4\n  stats socket {} level admin\ndefaults\n  mode tcp\n  timeout connect 1s\n  \
         timeout client 2s\n  timeout server 2s\n  timeout check 5s\nfrontend f\n  bind {front}\n  default_backend b\n\
         frontend st\n  mode http\n  bind {st}\n  stats enable\n  stats uri /s\nbackend b\n  option tcp-check\n  tcp-check connect\n  server s {addr} check inter 30s fall 1 rise 1\n",
        sock.display()
    );
    let path = dir.path().join("alcyon.cfg");
    std::fs::write(&path, &cfg).expect("write cfg");
    let mut child = common::Alcyon(Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon"));
    let start = Instant::now();
    while !sock.exists() && start.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(800));
    let mut bad = Vec::new();
    for i in 0..40 {
        let stat = http_csv(&st.to_string());
        let mut lines = stat.lines();
        let header: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
        let row: Vec<&str> = lines.find(|l| l.split(',').nth(1) == Some("s")).expect("server row").split(',').collect();
        let col = |n: &str| row[header.iter().position(|h| *h == n).expect(n)];
        let got = (col("check_status"), col("last_chk"), col("chkfail"));
        if got != ("L4OK", "(tcp-check)", "0") || col("check_duration").is_empty() {
            bad.push((i, got.0.to_string(), got.1.to_string(), got.2.to_string()));
        }
    }
    common::stop(&mut child);
    assert!(bad.is_empty(), "{} of 40 answers had other check columns: {:?}", bad.len(), &bad[..bad.len().min(3)]);
}
