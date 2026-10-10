// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `replace-path`, `replace-pathq` and `replace-uri` on the request targets that have no
//! (ordinary) path, and what each replaces. Every row is the request line the server saw
//! from the reference `HAProxy` (3.5-dev8-885761-29), measured 2026-10-05.
//!
//! * A match replaces the whole component (path, path and query, or URI) with the format,
//!   not just the matched part, and only once.
//! * `OPTIONS *` has no path: both path rules leave it alone; `replace-uri` sees `*`.
//! * `http://h?q=1` has an empty path: `replace-path` does not match (not even `^$`),
//!   `replace-pathq` matches `?q=1`. `http://h` is `http://h/`.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tempfile::NamedTempFile;

const REQS: [&str; 5] =
    ["OPTIONS *", "GET http://h?q=1", "GET http://h", "GET http://h/", "GET /aab?q=1"];

fn backend(tx: mpsc::Sender<String>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = c.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = tx.send(text.lines().next().unwrap_or("").to_string());
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    addr
}

fn run(rule: &str) -> Vec<String> {
    let (tx, rx) = mpsc::channel();
    let srv = backend(tx);
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 3s\n  timeout connect 3s\n  timeout server 3s\n\
         frontend f\n  bind {fe}\n  http-request {rule}\n  default_backend b\nbackend b\n  server s {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write");
    let mut child: common::Ibex = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn");
    assert!(common::wait_listening(fe), "ibex never listened");
    let mut seen = Vec::new();
    for r in REQS {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        c.write_all(format!("{r} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes()).expect("send");
        // The request line the server saw is the result; the client connection is kept
        // alive, so reading it to its end would wait out the 3 s read timeout (T259).
        seen.push(rx.recv_timeout(Duration::from_secs(3)).unwrap_or_else(|_| "<none>".into()));
    }
    common::stop(&mut child);
    seen
}

fn check(rule: &str, want: [&str; 5]) {
    let want: Vec<String> = want.iter().map(|w| format!("{w} HTTP/1.1")).collect();
    assert_eq!(run(rule), want, "rule: {rule}");
}

#[test]
fn replace_path_leaves_targets_without_a_path_alone() {
    check(
        "replace-path (.*) /pre\\1",
        ["OPTIONS *", "GET http://h?q=1", "GET http://h/pre/", "GET http://h/pre/", "GET /pre/aab?q=1"],
    );
    check(
        "replace-path ^ /pre",
        ["OPTIONS *", "GET http://h?q=1", "GET http://h/pre", "GET http://h/pre", "GET /pre?q=1"],
    );
    check(
        "replace-path ^$ /empty",
        ["OPTIONS *", "GET http://h?q=1", "GET http://h/", "GET http://h/", "GET /aab?q=1"],
    );
}

#[test]
fn replace_path_replaces_the_whole_path_once() {
    check("replace-path ^/a /b", ["OPTIONS *", "GET http://h?q=1", "GET http://h/", "GET http://h/", "GET /b?q=1"]);
    check("replace-path a X", ["OPTIONS *", "GET http://h?q=1", "GET http://h/", "GET http://h/", "GET X?q=1"]);
}

#[test]
fn replace_pathq_sees_the_query_of_an_empty_path_and_replaces_everything() {
    check(
        "replace-pathq (.*) /pre\\1",
        ["OPTIONS *", "GET http://h/pre?q=1", "GET http://h/pre/", "GET http://h/pre/", "GET /pre/aab?q=1"],
    );
    check("replace-pathq a X", ["OPTIONS *", "GET http://h?q=1", "GET http://h/", "GET http://h/", "GET X"]);
}

#[test]
fn replace_uri_takes_the_whole_target_and_replaces_all_of_it() {
    check(
        "replace-uri (.*) /pre\\1",
        ["OPTIONS /pre*", "GET /prehttp://h?q=1", "GET /prehttp://h/", "GET /prehttp://h/", "GET /pre/aab?q=1"],
    );
    check("replace-uri ^http://h /Z", ["OPTIONS *", "GET /Z", "GET /Z", "GET /Z", "GET /aab?q=1"]);
    check("replace-uri a X", ["OPTIONS *", "GET http://h?q=1", "GET http://h/", "GET http://h/", "GET X"]);
}
