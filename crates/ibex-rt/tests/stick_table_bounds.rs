// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T250: a stick-table key is at most `len` bytes (32 by default) and an expired entry
//! leaves the table without waiting for it to be full.
//!
//! Measured on HAProxy 3.5-dev8-885761-29: a table `type string len 4` tracking
//! `req.hdr(x-k)` holds `key=abcd` for `abcdefgh` and `key=ab` for `ab`; with `expire 3s`
//! `show table` says `used:2` after the two requests and `used:0` once the time has passed.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

struct Ibex(Child, NamedTempFile, std::path::PathBuf);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_file(&self.2);
    }
}

fn start(table: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let sock = std::env::temp_dir().join(format!("ibex_t250_{}_{}.sock", std::process::id(), fe.port()));
    let text = format!(
        "global\n  nbthread 1\n  stats socket {sock} mode 600 level admin\ndefaults\n  mode http\n  timeout client 5s\n  timeout connect 2s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  http-request track-sc0 req.hdr(x-k) table t\n  http-request return status 200\nbackend t\n  {table}\n",
        sock = sock.display()
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = Ibex(child, f, sock);
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ibex.2.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    (ibex, fe)
}

fn request(fe: SocketAddr, key: &str) {
    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    write!(c, "GET / HTTP/1.1\r\nHost: x\r\nx-k: {key}\r\nConnection: close\r\n\r\n").expect("send");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
}

fn show_table(ibex: &Ibex) -> String {
    let mut s = UnixStream::connect(&ibex.2).expect("connect to the stats socket");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(b"show table t\n").expect("send");
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

#[test]
fn a_string_key_is_cut_at_len() {
    let (ibex, fe) = start("stick-table type string len 4 size 100 expire 3s");
    request(fe, "abcdefgh");
    request(fe, "ab");
    thread::sleep(Duration::from_millis(100));
    let out = show_table(&ibex);
    assert!(out.contains("used:2"), "{out}");
    assert!(out.contains("key=abcd "), "{out}");
    assert!(out.contains("key=ab "), "{out}");
    assert!(!out.contains("abcde"), "{out}");
}

#[test]
fn a_string_key_is_cut_at_32_by_default() {
    let (ibex, fe) = start("stick-table type string size 100 expire 3s");
    let long = "k".repeat(40);
    request(fe, &long);
    thread::sleep(Duration::from_millis(100));
    let out = show_table(&ibex);
    assert!(out.contains(&format!("key={} ", "k".repeat(32))), "{out}");
    assert!(!out.contains(&"k".repeat(33)), "{out}");
}

#[test]
fn an_expired_entry_leaves_the_table() {
    let (ibex, fe) = start("stick-table type string size 100 expire 1s");
    request(fe, "a");
    request(fe, "b");
    thread::sleep(Duration::from_millis(100));
    assert!(show_table(&ibex).contains("used:2"));
    thread::sleep(Duration::from_millis(2500));
    let out = show_table(&ibex);
    assert!(out.contains("used:0"), "{out}");
}
