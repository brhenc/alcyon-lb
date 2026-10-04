// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `timeout http-keep-alive` against the real binary (T149).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`nbthread 1`, `timeout client 5s` unless
//! noted, a client that sends one request, reads the answer, then waits):
//!
//! | timeouts                         | idle after the answer   | first byte of the next, then a stall |
//! |----------------------------------|-------------------------|---------------------------------------|
//! | keep-alive 300 ms                | closed, silently, 300 ms | nothing before `timeout client`        |
//! | keep-alive 300 ms, request 1 s   | closed, silently, 300 ms | 408 after 1 s (from that byte)        |
//! | request 300 ms                   | closed, silently, 300 ms | 408 after 300 ms                      |
//! | keep-alive 1 s, request 300 ms   | closed, silently, 1 s    | 408 after 300 ms                      |
//!
//! So an idle connection waits `timeout http-keep-alive`, else `timeout http-request`, else
//! `timeout client`; the first request of a connection never waits on the keep-alive
//! timeout; and once the first byte of a request is here `timeout http-request` takes over
//! (none: the client timeout).

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

fn backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

struct Ibex(Child, NamedTempFile);

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn start(cfg: &str, fe: SocketAddr) -> Ibex {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(fe).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening on {fe}");
        thread::sleep(Duration::from_millis(20));
    }
    Ibex(child, f)
}

#[derive(Clone, Copy)]
enum Wait {
    /// A new connection that sends nothing.
    First,
    /// After one answered request, nothing.
    Idle,
    /// After one answered request, the first bytes of the next, then nothing.
    Partial,
}

/// What the client sees, and when, counted from the last thing it sent (or the answer).
fn observe(timeouts: &str, wait: Wait, give_up: Duration) -> (String, Duration) {
    let be = backend();
    let fe = common::reserve_addr();
    let _ibex = start(
        &format!("global\n  nbthread 1\ndefaults\n  mode http\n  timeout connect 2s\n  timeout server 5s\n  {timeouts}\nlisten l\n  bind {fe}\n  server s {be}\n"),
        fe,
    );
    let mut c = TcpStream::connect(fe).expect("connect");
    let mut buf = [0u8; 4096];
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    if !matches!(wait, Wait::First) {
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert!(c.read(&mut buf).unwrap() > 0, "no answer");
    }
    if matches!(wait, Wait::Partial) {
        thread::sleep(Duration::from_millis(100));
        c.write_all(b"GET / HT").unwrap();
    }
    let t0 = Instant::now();
    c.set_read_timeout(Some(give_up)).unwrap();
    let seen = match c.read(&mut buf) {
        Ok(0) => "closed".to_string(),
        Ok(n) => String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string(),
        Err(_) => "open".to_string(),
    };
    (seen, t0.elapsed())
}

fn within(d: Duration, ms: u64) -> bool {
    let want = Duration::from_millis(ms);
    d >= want.saturating_sub(Duration::from_millis(60)) && d <= want + Duration::from_millis(250)
}

const GIVE_UP: Duration = Duration::from_millis(2500);

#[test]
fn keep_alive_alone_closes_an_idle_connection_and_only_that() {
    let t = "timeout client 5s\n  timeout http-keep-alive 300ms";
    let (seen, d) = observe(t, Wait::Idle, GIVE_UP);
    assert!(seen == "closed" && within(d, 300), "idle: {seen} after {d:?}");
    let (seen, d) = observe(t, Wait::First, Duration::from_millis(900));
    assert_eq!(seen, "open", "first request: {seen} after {d:?}");
    let (seen, d) = observe(t, Wait::Partial, Duration::from_millis(900));
    assert_eq!(seen, "open", "partial request: {seen} after {d:?}");
}

#[test]
fn keep_alive_with_a_longer_request_timeout() {
    let t = "timeout client 5s\n  timeout http-keep-alive 300ms\n  timeout http-request 1s";
    let (seen, d) = observe(t, Wait::Idle, GIVE_UP);
    assert!(seen == "closed" && within(d, 300), "idle: {seen} after {d:?}");
    let (seen, d) = observe(t, Wait::Partial, GIVE_UP);
    assert!(seen.contains("408") && within(d, 1000), "partial: {seen} after {d:?}");
}

#[test]
fn the_request_timeout_is_the_idle_timeout_without_keep_alive() {
    let t = "timeout client 5s\n  timeout http-request 300ms";
    let (seen, d) = observe(t, Wait::Idle, GIVE_UP);
    assert!(seen == "closed" && within(d, 300), "idle: {seen} after {d:?}");
}

#[test]
fn a_keep_alive_longer_than_the_request_timeout() {
    let t = "timeout client 5s\n  timeout http-keep-alive 1s\n  timeout http-request 300ms";
    let (seen, d) = observe(t, Wait::Idle, GIVE_UP);
    assert!(seen == "closed" && within(d, 1000), "idle: {seen} after {d:?}");
    let (seen, d) = observe(t, Wait::Partial, GIVE_UP);
    assert!(seen.contains("408") && within(d, 300), "partial: {seen} after {d:?}");
}
