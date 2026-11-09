// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A keep-alive request lost on a kept server connection (`abort_keep_alive`, T229).
//!
//! The server answers the first request on its connection and closes (FIN) or resets it on
//! the second. Both proxies close the client connection unanswered, so that the client
//! retries. `HAProxy` sets the transaction's status to 0 there and drops its log: measured
//! on `HAProxy 3.5-dev8-885761-29` on 2026-10-10, FIN and RST alike:
//!
//! | counter (added)      | FRONTEND | BACKEND | server |
//! |----------------------|----------|---------|--------|
//! | `req_tot`            | 2        | 1       | 1      |
//! | `hrsp_2xx`           | 1        | 1       | 1      |
//! | `hrsp_other`         | 0        | 0       | 0      |
//! | `eresp`              | 0        | 1       | 1      |
//! | `srv_abrt`           | 0        | 1       | 1      |
//!
//! and one log line, the first request's. Found on devtest7 when a server was killed under
//! load: Alcyon logged every such request as `-1 ... SH--` (or `----`) and counted it as a
//! response of no class (`hrsp_other`), a backend request and two response errors.

use crate::common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

struct Alcyon {
    child: Child,
    sock: PathBuf,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn read_head(s: &mut TcpStream) -> bool {
    let mut got = Vec::new();
    let mut b = [0u8; 1024];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(0) | Err(_) => return false,
            Ok(n) => got.extend_from_slice(&b[..n]),
        }
    }
    true
}

/// A server that answers the first request on each connection and, on the second, closes
/// the connection (or resets it, with `reset`) without a byte.
fn second_request_dropping_server(reset: bool) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("server");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                if read_head(&mut s) {
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    if read_head(&mut s) {
                        if reset {
                            let _ = rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO));
                        } else {
                            let _ = s.shutdown(Shutdown::Write);
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Non-empty `show stat` fields of `f`'s FRONTEND, and `b`'s BACKEND and server `s`, by
/// `svname`.
fn stats(sock: &PathBuf) -> HashMap<String, HashMap<String, String>> {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(b"show stat\n").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let mut lines = out.lines();
    let head: Vec<String> = lines.next().unwrap_or("").trim_start_matches("# ").split(',').map(str::to_string).collect();
    let mut all = HashMap::new();
    for l in lines {
        let v: Vec<&str> = l.split(',').collect();
        if v.len() < 2 || !matches!(v[0], "f" | "b") {
            continue;
        }
        let row = head.iter().cloned().zip(v.iter().map(|s| (*s).to_string())).collect();
        all.insert(v[1].to_string(), row);
    }
    all
}

type Stats = HashMap<String, HashMap<String, String>>;

/// Two requests on one client connection; the second is lost at the server. Returns the
/// log lines that arrived, and the counters before the requests (after the connection
/// `wait_listening` made) and after them.
fn run(reset: bool) -> (Vec<String>, Stats, Stats) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let sock = PathBuf::from(format!("/tmp/alcyon-kaa-{}-{n}.sock", std::process::id()));
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
    let fe = common::reserve_addr();
    let srv = second_request_dropping_server(reset);
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 2s\n  timeout connect 2s\n  timeout server 2s\n\
         frontend f\n  bind {fe}\n  log {} local0\n  log-format \"%HU ST=%ST ts=%ts\"\n  default_backend b\n\
         backend b\n  server s {srv}\n",
        sock.display(),
        collector.local_addr().unwrap()
    );
    let path = std::env::temp_dir().join(format!("alcyon-kaa-{}-{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn alcyon");
    let alcyon = Alcyon { child, sock };
    assert!(common::wait_listening(fe), "alcyon never listened");
    let _ = std::fs::remove_file(&path);
    // The probe is counted when the proxy has dealt with it, which it logs: wait for that line
    // (on a loaded host it takes far longer than 100 ms) before the first snapshot.
    let mut probe_line = [0u8; 2048];
    collector.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let _ = collector.recv(&mut probe_line);
    collector.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
    let before = stats(&alcyon.sock);

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    c.write_all(b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let mut b = [0u8; 1024];
    while !got.ends_with(b"ok") {
        let n = c.read(&mut b).expect("the first response");
        assert!(n > 0, "closed before the first response");
        got.extend_from_slice(&b[..n]);
    }
    c.write_all(b"GET /2 HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut rest = Vec::new();
    let _ = c.read_to_end(&mut rest);
    assert!(rest.is_empty(), "the second request was answered: {:?}", String::from_utf8_lossy(&rest));

    let mut logs = Vec::new();
    let end = Instant::now() + Duration::from_millis(500);
    while Instant::now() < end {
        if let Ok(n) = collector.recv(&mut b) {
            let line = String::from_utf8_lossy(&b[..n]).into_owned();
            // `<BADREQ>`: the connection `wait_listening` opened and closed.
            if let Some(i) = line.find(" ST=").filter(|_| !line.contains("<BADREQ>")) {
                let start = line[..i].rfind(' ').map_or(0, |s| s + 1);
                logs.push(line[start..].trim_end().to_string());
            }
        }
    }
    (logs, before, stats(&alcyon.sock))
}

/// How much `name` of `sv` grew between the two snapshots.
fn grew(before: &Stats, after: &Stats, sv: &str, name: &str) -> String {
    let get = |st: &Stats| st.get(sv).and_then(|r| r.get(name)).and_then(|v| v.parse::<i64>().ok());
    match (get(before), get(after)) {
        (Some(b), Some(a)) => (a - b).to_string(),
        _ => "<missing>".to_string(),
    }
}

fn check(reset: bool) {
    let (logs, before, after) = run(reset);
    assert_eq!(logs, vec!["/1 ST=200 ts=--".to_string()], "only the answered request is logged");
    let want = [
        ("FRONTEND", [("req_tot", "2"), ("hrsp_2xx", "1"), ("hrsp_other", "0")].as_slice()),
        ("BACKEND", [("req_tot", "1"), ("hrsp_2xx", "1"), ("hrsp_other", "0"), ("eresp", "1"), ("srv_abrt", "1")].as_slice()),
        ("s", [("req_tot", "1"), ("hrsp_2xx", "1"), ("hrsp_other", "0"), ("eresp", "1"), ("srv_abrt", "1")].as_slice()),
    ];
    let mut wrong = Vec::new();
    for (sv, fields) in want {
        for (name, v) in fields {
            let got = grew(&before, &after, sv, name);
            if got != *v {
                wrong.push(format!("{sv}.{name}={got} (HAProxy {v})"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join(", "));
}

#[test]
fn a_kept_server_connection_closed_on_the_next_request_is_neither_logged_nor_counted_as_a_response() {
    check(false);
}

#[test]
fn a_kept_server_connection_reset_on_the_next_request_is_neither_logged_nor_counted_as_a_response() {
    check(true);
}
