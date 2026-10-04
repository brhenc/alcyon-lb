// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A transaction's variables are its own while other streams run beside it (T152).
//!
//! The rules read variables through a per-thread map. It was filled for one stream at the
//! start of its request rules and read by whatever ran next on the thread: the response
//! rules and the log line of a stream that had waited for its server read the variables of
//! the stream that ran last. With 40 keep-alive clients of 12 requests each, `nbthread 1`,
//! a server answering after 0 to 10 ms:
//!
//! ```text
//! HAProxy 3.5-dev8-885761-29   480/480 responses carry their own x-id, every log line its own
//! Ibex c5dc274                   2/480; the log lines 0/221 (all showed another client's id)
//! ```
//!
//! The same load, `log-format "%HP st=%[status]"` and no `http-response` rule: HAProxy logs
//! every transaction's own status; Ibex logged `-`, the status being read from the thread's
//! last response rather than from the stream.

mod common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;

const CLIENTS: usize = 40;
const REQUESTS: usize = 12;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that answers every request on a connection with the status its `x-st` header
/// asks for, after a short delay that differs from one request to the next, so the
/// streams' responses come back out of order.
fn server() -> SocketAddr {
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
                    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                    buf.drain(..end);
                    let status = head
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("x-st: "))
                        .and_then(|v| v.trim().parse::<u16>().ok())
                        .unwrap_or(200);
                    i = i.wrapping_mul(31).wrapping_add(7);
                    thread::sleep(Duration::from_millis((i % 11) as u64));
                    let rsp = format!("HTTP/1.1 {status} OK\r\nContent-Length: 2\r\n\r\nok");
                    if c.write_all(rsp.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

fn start(srv: SocketAddr, log: SocketAddr, log_format: &str, rules: &str) -> (Ibex, SocketAddr) {
    let fe = common::reserve_addr();
    let text = format!(
        "global\n  nbthread 1\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
         frontend f\n  bind {fe}\n  log {log} local0\n  log-format \"{log_format}\"\n{rules}\
         \x20 default_backend b\n\
         backend b\n  server s {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(text.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened on {fe} with:\n{text}");
    (ibex, fe)
}

/// The id of request `q` of client `c`, and the status the server is asked to answer it with.
fn request(c: usize, q: usize) -> (String, u16) {
    (format!("c{c}r{q}"), 200 + u16::try_from((c + q) % 4).unwrap_or(0))
}

/// The status [`request`] gives the request whose id is `id`.
fn status_of(id: &str) -> Option<u16> {
    let (c, q) = id.strip_prefix('c')?.split_once('r')?;
    Some(request(c.parse().ok()?, q.parse().ok()?).1)
}

/// One keep-alive client: `REQUESTS` requests, each with its own id in the path and in
/// `x-id`; returns (id sent, `x-id` received) for every response.
fn client(fe: SocketAddr, c: usize) -> Vec<(String, Option<String>)> {
    let s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let mut w = s.try_clone().expect("clone");
    let mut r = BufReader::new(s);
    let mut seen = Vec::new();
    for q in 0..REQUESTS {
        let (id, st) = request(c, q);
        w.write_all(format!("GET /{id} HTTP/1.1\r\nHost: x\r\nx-id: {id}\r\nx-st: {st}\r\n\r\n").as_bytes()).expect("send");
        let mut hdrs = HashMap::new();
        let mut line = String::new();
        r.read_line(&mut line).expect("status line");
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
        r.read_exact(&mut body).expect("body");
        seen.push((id, hdrs.remove("x-id")));
    }
    seen
}

/// Runs every client at once through ibex on `log_format` and `rules`; returns what each
/// response carried and the log lines (`<path> <rest>`, the syslog header cut off), the
/// line of the listener probe left out: it sent nothing, and is a `<BADREQ>`.
fn run(log_format: &str, rules: &str) -> (Vec<(String, Option<String>)>, Vec<String>) {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(500))).expect("timeout");
    let log_addr = collector.local_addr().expect("addr");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut idle = 0;
        while idle < 6 {
            match collector.recv(&mut buf) {
                Ok(n) => {
                    idle = 0;
                    sink.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
                }
                Err(_) => idle += 1,
            }
        }
    });

    let (_ibex, fe) = start(server(), log_addr, log_format, rules);
    let clients: Vec<_> = (0..CLIENTS).map(|c| thread::spawn(move || client(fe, c))).collect();
    let seen = clients.into_iter().flat_map(|h| h.join().expect("client")).collect();
    reader.join().expect("log reader");
    let lines = lines
        .lock()
        .unwrap()
        .iter()
        .filter(|l| !l.contains("<BADREQ>"))
        .map(|l| l.rsplit_once("]: ").map_or(l.as_str(), |(_, b)| b).trim_end().to_string())
        .collect();
    (seen, lines)
}

#[test]
fn every_response_and_log_line_sees_its_own_transaction_variables() {
    let (seen, lines) = run(
        "%HP id=%[var(txn.id)]",
        "  http-request set-var(txn.id) req.hdr(x-id)\n  http-response set-header x-id %[var(txn.id)]\n",
    );
    let wrong: Vec<_> = seen.iter().filter(|(id, got)| got.as_deref() != Some(id.as_str())).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} responses did not carry their own request's txn.id; first: {:?}",
        wrong.len(),
        seen.len(),
        &wrong[..wrong.len().min(5)]
    );
    assert!(!lines.is_empty(), "no log line arrived");
    let bad: Vec<&String> = lines
        .iter()
        .filter(|l| l.split_once(" id=").is_none_or(|(path, id)| path.strip_prefix('/') != Some(id)))
        .collect();
    assert!(bad.is_empty(), "{} of {} log lines show another transaction's txn.id; first: {:?}", bad.len(), lines.len(), &bad[..bad.len().min(3)]);
}

#[test]
fn every_log_line_shows_its_own_status() {
    let (_, lines) = run("%HP st=%[status]", "");
    assert!(!lines.is_empty(), "no log line arrived");
    let bad: Vec<&String> = lines
        .iter()
        .filter(|l| {
            l.split_once(" st=").is_none_or(|(path, st)| {
                path.strip_prefix('/').and_then(status_of).map(|s| s.to_string()).as_deref() != Some(st)
            })
        })
        .collect();
    assert!(bad.is_empty(), "{} of {} log lines do not show their own status; first: {:?}", bad.len(), lines.len(), &bad[..bad.len().min(3)]);
}
