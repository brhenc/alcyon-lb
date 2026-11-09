// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A reused backend connection that dies before any response byte ends only the stream
//! whose request went out on it, never the client's HTTP/2 connection (T324, VV-12).
//!
//! `http_wait_for_response`'s `abort_keep_alive`: a keep-alive request lost to a network
//! error on a reused server connection is closed unanswered, unlogged (`logwait = 0`), so
//! the client retries. On HTTP/1 that closes the client connection; on HTTP/2 the mux sees
//! a stream ended before its response head and resets it `REFUSED_STREAM`, which tells the
//! client it may retry, and the connection and its other streams go on.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`nbthread 1`, `http-reuse always`, the
//! backends below; `T324_ORACLE=/path/to/haproxy` runs this on it):
//!
//! | shape                                                          | stream            | log line |
//! |----------------------------------------------------------------|-------------------|----------|
//! | request sent on a reused connection, server closes, no answer  | `RST_STREAM` 7    | none     |
//! | the same with `retries 0` or `retry-on none`                   | `RST_STREAM` 7    | none     |
//! | the same with `retry-on empty-response` (or all-retryable-errors) | 200 (retried once) | 200, retries 1 |
//! | idle pooled connection the server closed, then a request       | 200 on a new one  | 200      |
//!
//! Every row: no `GOAWAY`, the sibling stream to a healthy backend completes 200, and the
//! connection serves the next stream. Alcyon closed the client connection with no frame for
//! any stream in flight and logged none of them.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short path")];
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

/// A keep-alive HTTP/1.1 backend. `/k`: the first request of a connection is answered,
/// a later one is read and the connection closed 50 ms later with no answer (an
/// application server killed while it works on the request). Anything else is answered
/// after `delay`.
fn backend(delay: Duration) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                let (mut req, mut tmp, mut nreq) = (Vec::new(), [0u8; 2048], 0u32);
                loop {
                    while let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&req[..i]).into_owned();
                        req.drain(..i + 4);
                        nreq += 1;
                        let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                        if path == "/k" && nreq >= 2 {
                            thread::sleep(Duration::from_millis(50));
                            return;
                        }
                        thread::sleep(delay);
                        if c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                    }
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&tmp[..n]),
                    }
                }
            });
        }
    });
    port
}

struct Proxy {
    child: Child,
    logs: mpsc::Receiver<String>,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(be1_extra: &str) -> Proxy {
    let (be1, be2) = (backend(Duration::ZERO), backend(Duration::from_millis(300)));
    let port = common::reserve_port();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\tlog stdout format raw local0\n\n\
             defaults\n\tmode http\n\tlog global\n\toption httplog\n\ttimeout connect 2s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port} proto h2\n\tuse_backend be2 if {{ path_beg /be2 }}\n\tdefault_backend be1\n\n\
             backend be1\n\thttp-reuse always\n{be1_extra}\tserver s1 127.0.0.1:{be1}\n\n\
             backend be2\n\thttp-reuse always\n\tserver s2 127.0.0.1:{be2}\n"
        ),
    )
    .expect("write config");
    let bin = std::env::var("T324_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    let mut child = Command::new(bin).arg("-f").arg(&cfg).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened on {port}");
        thread::sleep(Duration::from_millis(25));
    }
    Proxy { child, logs, port, _dir: dir }
}

/// What the client saw on its connection.
#[derive(Default, Debug)]
struct Seen {
    /// `(stream, first byte of its response HEADERS block)`: 0x88 is `:status 200`.
    heads: Vec<(u32, u8)>,
    /// Streams whose response ended (`END_STREAM`).
    ended: Vec<u32>,
    /// `(stream, error code)` of each `RST_STREAM`.
    rsts: Vec<(u32, u32)>,
    goaway: bool,
    eof: bool,
}

struct Client {
    s: TcpStream,
    buf: Vec<u8>,
    seen: Seen,
}

impl Client {
    fn new(port: u16) -> Self {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(100))).ok();
        s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
        s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
        Client { s, buf: Vec::new(), seen: Seen::default() }
    }

    fn get(&mut self, sid: u32, path: &str) {
        self.s.write_all(&frame(0x01, 0x05, sid, &hpack_get(path))).expect("headers");
    }

    /// Reads frames until `done` holds, the connection ends, or `limit` passes.
    fn pump(&mut self, limit: Duration, done: impl Fn(&Seen) -> bool) {
        let deadline = Instant::now() + limit;
        let mut tmp = [0u8; 4096];
        while !done(&self.seen) && !self.seen.eof && Instant::now() < deadline {
            match self.s.read(&mut tmp) {
                Ok(0) => self.seen.eof = true,
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(_) => self.seen.eof = true,
            }
            while self.buf.len() >= 9 {
                let len = (usize::from(self.buf[0]) << 16) | (usize::from(self.buf[1]) << 8) | usize::from(self.buf[2]);
                if self.buf.len() < 9 + len {
                    break;
                }
                let (ty, flags) = (self.buf[3], self.buf[4]);
                let id = u32::from_be_bytes([self.buf[5] & 0x7f, self.buf[6], self.buf[7], self.buf[8]]);
                let p = self.buf[9..9 + len].to_vec();
                self.buf.drain(..9 + len);
                match ty {
                    0x01 => self.seen.heads.push((id, p.first().copied().unwrap_or(0))),
                    0x03 => self.seen.rsts.push((id, u32::from_be_bytes([p[0], p[1], p[2], p[3]]))),
                    0x07 => self.seen.goaway = true,
                    _ => {}
                }
                if (ty == 0x00 || ty == 0x01) && flags & 1 != 0 {
                    self.seen.ended.push(id);
                }
            }
        }
    }
}

/// The log lines that came within `wait`.
fn lines(p: &Proxy, wait: Duration) -> Vec<String> {
    let deadline = Instant::now() + wait;
    let mut v = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match p.logs.recv_timeout(left) {
            Ok(l) if l.contains("HTTP/2.0\"") => v.push(l),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    v
}

/// Stream 1 takes a backend connection, which then waits idle; stream 3 goes out on it as
/// the server dies, and stream 5 goes to a healthy backend at the same time.
fn killed_on_reused_connection(be1_extra: &str) -> (Seen, Vec<String>) {
    let p = start(be1_extra);
    let mut c = Client::new(p.port);
    c.get(1, "/k");
    c.pump(Duration::from_secs(3), |s| s.ended.contains(&1));
    assert!(c.seen.ended.contains(&1), "stream 1 was not answered: {:?}", c.seen);
    thread::sleep(Duration::from_millis(200));
    c.get(3, "/k");
    c.get(5, "/be2/x");
    c.pump(Duration::from_secs(3), |s| s.ended.contains(&5) && (s.ended.contains(&3) || s.rsts.iter().any(|r| r.0 == 3)));
    if !c.seen.eof {
        c.get(7, "/ok");
        c.pump(Duration::from_secs(3), |s| s.ended.contains(&7));
    }
    (std::mem::take(&mut c.seen), lines(&p, Duration::from_millis(500)))
}

fn assert_connection_kept(seen: &Seen) {
    assert!(!seen.eof, "the client connection was closed: {seen:?}");
    assert!(!seen.goaway, "a GOAWAY was sent (HAProxy sends none): {seen:?}");
    assert!(seen.heads.contains(&(5, 0x88)) && seen.ended.contains(&5), "the sibling stream 5 did not complete 200: {seen:?}");
    assert!(seen.heads.contains(&(7, 0x88)) && seen.ended.contains(&7), "the next stream 7 was not answered 200: {seen:?}");
}

#[test]
fn a_reused_connection_dying_unanswered_refuses_only_its_stream() {
    let (seen, logs) = killed_on_reused_connection("");
    assert_connection_kept(&seen);
    assert_eq!(seen.rsts, vec![(3, 7)], "stream 3 is reset REFUSED_STREAM, as on HAProxy: {seen:?}");
    assert!(!seen.heads.iter().any(|h| h.0 == 3), "stream 3 got a response: {seen:?}");
    // `abort_keep_alive` logs nothing for the refused stream: the client's retry is the
    // request that gets logged. Streams 1, 5 and 7 are logged.
    assert_eq!(logs.iter().filter(|l| l.contains("GET http://localhost/k ")).count(), 1, "log lines: {logs:#?}");
    assert_eq!(logs.iter().filter(|l| l.contains(" 200 ")).count(), 3, "log lines: {logs:#?}");
    assert_eq!(logs.len(), 3, "log lines: {logs:#?}");
}

#[test]
fn a_reused_connection_dying_unanswered_is_refused_without_retries() {
    for extra in ["\tretries 0\n", "\tretry-on none\n"] {
        let (seen, logs) = killed_on_reused_connection(extra);
        assert_connection_kept(&seen);
        assert_eq!(seen.rsts, vec![(3, 7)], "{extra}: stream 3 is reset REFUSED_STREAM: {seen:?}");
        assert_eq!(logs.len(), 3, "{extra}: log lines: {logs:#?}");
    }
}

#[test]
fn a_reused_connection_dying_unanswered_is_retried_under_retry_on_empty_response() {
    let (seen, logs) = killed_on_reused_connection("\tretry-on empty-response\n");
    assert_connection_kept(&seen);
    assert!(seen.rsts.is_empty(), "no stream is reset: {seen:?}");
    assert!(seen.heads.contains(&(3, 0x88)) && seen.ended.contains(&3), "stream 3 is answered 200 after a retry: {seen:?}");
    assert_eq!(logs.len(), 4, "log lines: {logs:#?}");
    // `%rc` (the fifth of `actconn/feconn/beconn/srv_conn/retries`) is 1 for the retried stream.
    assert_eq!(logs.iter().filter(|l| l.contains("GET http://localhost/k ") && l.contains("/1 0/0 ")).count(), 1, "log lines: {logs:#?}");
}
