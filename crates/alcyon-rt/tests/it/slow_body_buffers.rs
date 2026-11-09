// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T371: a request whose head is on the wire to the server holds no buffer while its body
//! trickles in. HAProxy empties the channel buffer once the head is forwarded; on 3.5-dev8,
//! 200 slow-body connections behind `nbthread 2` leave 20 to 27 buffers "used" in `show pools`,
//! of which 9 to 16 sit in thread caches: 11 in use, which is what is there at start, for a CL body, a chunked body and
//! a frontend that captures a request header and rewrites the response from it.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const N: usize = 200;

struct Alcyon(Child, std::path::PathBuf);

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

fn cli(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("cli");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(format!("{cmd}\n").as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

/// `used` of the 16 KiB buffer pool, less those the thread caches hold: `used` counts a
/// cached buffer as in use (HAProxy's does too), and a cache keeps what a burst freed.
fn buffers_used(sock: &str) -> usize {
    let out = cli(sock, "show pools");
    let line = out.lines().find(|l| l.trim_start().starts_with("- Pool buffer (")).unwrap_or_else(|| panic!("no buffer pool line in {out:?}"));
    let rest = line.split(" bytes), ").nth(1).expect("pool line layout");
    let used: usize = rest.split_whitespace().next().unwrap().parse().expect("used count");
    let cached: usize = rest.split("(~").nth(1).and_then(|c| c.split_whitespace().next()).and_then(|c| c.parse().ok()).expect("cached count");
    used - cached
}

/// A backend that reads everything and never answers.
fn sink() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    l.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let mut conns: Vec<TcpStream> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            while let Ok((c, _)) = l.accept() {
                c.set_nonblocking(true).unwrap();
                conns.push(c);
            }
            for c in &mut conns {
                let _ = c.read(&mut buf);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    addr
}

/// `head` and one body byte from `N` clients; returns the buffers used once every head has
/// reached the sink and a second body byte went on.
fn run(tag: &str, frontend_extra: &str, backend_extra: &str, head: &[u8], first: &[u8], second: &[u8]) -> usize {
    let be = sink();
    let fe = common::reserve_addr();
    let dir = std::env::temp_dir().join(format!("t371-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("cli.sock").display().to_string();
    let cfg = format!(
        "global\n    nbthread 2\n    stats socket {sock} level admin\ndefaults\n    mode http\n    timeout client 60s\n    timeout server 60s\n    timeout connect 5s\n\
         frontend f\n    bind {fe}\n{frontend_extra}    default_backend b\nbackend b\n{backend_extra}    server s {be}\n"
    );
    let path = dir.join("c.cfg");
    std::fs::write(&path, cfg).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let _alcyon = Alcyon(child, dir);
    assert!(common::wait_listening(fe), "alcyon did not listen");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !std::path::Path::new(&sock).exists() {
        assert!(Instant::now() < deadline, "no stats socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut clients = Vec::new();
    for _ in 0..N {
        let mut c = TcpStream::connect(fe).unwrap();
        c.write_all(head).unwrap();
        c.write_all(first).unwrap();
        clients.push(c);
    }
    std::thread::sleep(Duration::from_millis(1500));
    for c in &mut clients {
        c.write_all(second).unwrap();
    }
    std::thread::sleep(Duration::from_millis(1000));
    buffers_used(&sock)
}

/// HAProxy: 11 in use for 200 connections (20..27 used, less its thread caches).
const BOUND: usize = N / 10;

#[test]
fn a_content_length_body_in_flight_holds_no_head_buffer() {
    let used = run("cl", "", "", b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\n", b"x", b"y");
    assert!(used <= BOUND, "{used} buffers used for {N} slow bodies, HAProxy holds 11");
}

#[test]
fn a_chunked_body_in_flight_holds_no_head_buffer() {
    let used = run("chunk", "", "", b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", b"1\r\nx\r\n", b"1\r\ny\r\n");
    assert!(used <= BOUND, "{used} buffers used for {N} slow bodies, HAProxy holds 11");
}

#[test]
fn a_capture_and_a_response_rule_do_not_keep_the_head_buffer() {
    let used = run(
        "rule",
        "    capture request header x-foo len 10\n",
        "    http-response set-header X-Seen %[capture.req.hdr(0)]\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nX-Foo: bar\r\nContent-Length: 1000\r\n\r\n",
        b"x",
        b"y",
    );
    assert!(used <= BOUND, "{used} buffers used for {N} slow bodies, HAProxy holds 11");
}
