// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `set-timeout` changes the timeouts of its own stream, and only of it (T156).
//!
//! The `cur_*_timeout` fetches read a per-thread map that every stream on the thread
//! wrote in turn, and `set-timeout` wrote only that map: the response of a stream that had
//! waited for its server showed the timeout another stream had set, and the timeouts the
//! stream ran on never changed. Measured on HAProxy 3.5-dev8-885761-29, `nbthread 1`:
//!
//! ```text
//!                                                   HAProxy            Alcyon 8392fff
//! 40 x 12 keep-alive requests, set-timeout server
//!   from x-n, x-id: %[cur_server_timeout]           480/480 own value  1/480
//! set-timeout server 500ms, server answers at 1.5s  504 after 0.53 s   200 after 1.5 s
//! set-timeout connect 300ms, unreachable server     503 after 0.31 s   503 after 10 s
//! set-timeout client 300ms, body never sent         400 after 0.35 s   the server's 200 at 3 s
//! ```

use crate::common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const CLIENTS: usize = 40;
const REQUESTS: usize = 12;

struct Alcyon {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers every request on a connection with a 200, after `delay(n)` ms
/// for the `n`th request it sees on any connection.
fn server(delay: fn(usize) -> u64) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for (n, c) in listener.incoming().flatten().enumerate() {
            thread::spawn(move || {
                let mut c = c;
                let mut buf = Vec::new();
                let mut chunk = [0u8; 16384];
                let mut i = n;
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match c.read(&mut chunk) {
                            Ok(k) if k > 0 => buf.extend_from_slice(&chunk[..k]),
                            _ => return,
                        }
                    }
                    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
                    buf.drain(..end);
                    i = i.wrapping_mul(31).wrapping_add(7);
                    thread::sleep(Duration::from_millis(delay(i)));
                    if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start(body: &str) -> (Alcyon, SocketAddr) {
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  retries 0\n  timeout connect 10s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f\n  bind {fe}\n{body}"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let alcyon = Alcyon { child, _cfg: f };
    assert!(common::wait_listening(fe), "alcyon never listened on {fe} with:\n{text}");
    (alcyon, fe)
}

/// Reads one response off `r`: its status and its headers.
fn response(r: &mut impl BufRead) -> Option<(u16, HashMap<String, String>)> {
    let mut line = String::new();
    if r.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let status = line.split(' ').nth(1)?.parse().ok()?;
    let mut hdrs = HashMap::new();
    loop {
        line.clear();
        if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            hdrs.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len = hdrs.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    Some((status, hdrs))
}

/// Sends `req` on a new connection and returns the status of the answer, and how long it
/// took to come.
fn exchange(fe: SocketAddr, req: &str) -> (Option<u16>, Duration) {
    let s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(15))).expect("timeout");
    let t0 = Instant::now();
    (&s).write_all(req.as_bytes()).expect("send");
    let st = response(&mut BufReader::new(&s)).map(|(st, _)| st);
    (st, t0.elapsed())
}

/// The server timeout client `c` asks for in its request `q`: distinct for every request.
fn timeout_of(c: usize, q: usize) -> usize {
    5000 + c * REQUESTS + q
}

#[test]
fn every_response_sees_the_timeout_its_own_request_set() {
    let srv = server(|i| (i % 11) as u64);
    let (_alcyon, fe) = start(&format!(
        "  http-response set-header x-id %[cur_server_timeout]\n  default_backend b\n\
         backend b\n  http-request set-timeout server req.hdr(x-n)\n  server s {srv}\n"
    ));
    let clients: Vec<_> = (0..CLIENTS)
        .map(|c| {
            thread::spawn(move || {
                let s = TcpStream::connect(fe).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
                let mut w = s.try_clone().expect("clone");
                let mut r = BufReader::new(s);
                (0..REQUESTS)
                    .map(|q| {
                        let n = timeout_of(c, q).to_string();
                        w.write_all(format!("GET / HTTP/1.1\r\nHost: x\r\nx-n: {n}\r\n\r\n").as_bytes()).expect("send");
                        let got = response(&mut r).and_then(|(_, mut h)| h.remove("x-id"));
                        (n, got)
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let seen: Vec<(String, Option<String>)> = clients.into_iter().flat_map(|h| h.join().expect("client")).collect();
    let wrong: Vec<_> = seen.iter().filter(|(n, got)| got.as_deref() != Some(n.as_str())).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} responses did not show the server timeout their own request set; first: {:?}",
        wrong.len(),
        seen.len(),
        &wrong[..wrong.len().min(5)]
    );
}

#[test]
fn set_timeout_server_is_the_timeout_the_stream_waits_for_its_server() {
    let srv = server(|_| 1500);
    let (_alcyon, fe) = start(&format!(
        "  default_backend b\nbackend b\n  http-request set-timeout server 500ms if {{ path /short }}\n  server s {srv}\n"
    ));
    let (st, took) = exchange(fe, "GET /short HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(st, Some(504), "set-timeout server 500ms against a server answering after 1.5 s (took {took:?})");
    assert!(took < Duration::from_millis(1200), "the 504 came after {took:?}, not after the 500 ms set");
    // The next stream runs on the backend's own timeout again.
    let (st, _) = exchange(fe, "GET /long HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(st, Some(200));
}

#[test]
fn set_timeout_connect_is_the_timeout_of_the_connect() {
    // A non-routable address: the SYN goes unanswered.
    let (_alcyon, fe) = start("  default_backend b\nbackend b\n  http-request set-timeout connect 300ms\n  server s 10.255.255.1:80\n");
    let (st, took) = exchange(fe, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(st, Some(503), "took {took:?}");
    assert!(took < Duration::from_secs(3), "the 503 came after {took:?}, not after the 300 ms set");
}

#[test]
fn set_timeout_client_is_the_timeout_of_the_client_side() {
    let srv = server(|_| 3000);
    let (_alcyon, fe) =
        start(&format!("  http-request set-timeout client 300ms\n  default_backend b\nbackend b\n  server s {srv}\n"));
    // The body announced is never sent.
    // HAProxy answers it with a 400; Alcyon closes the connection without one on any client
    // timeout during a body, `set-timeout` or not (listed in tasks/T156): what this checks is
    // that the stream ends on the timeout set, not on the server's answer.
    let (st, took) = exchange(fe, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n");
    assert_ne!(st, Some(200), "a client silent past its 300 ms got the server's answer (took {took:?})");
    assert!(took < Duration::from_millis(2500), "the stream ended after {took:?}, not after the 300 ms set");
}
