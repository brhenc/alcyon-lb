// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What a failed TLS handshake logs, sends and counts (T262).
//!
//! Measured on HAProxy 3.5-dev8-885761-29 (`bind ... ssl crt`, `log <udp> local0`, `option
//! httplog`), for the three clients of `tls_handshake_close.rs`:
//! - A client that leaves before a byte, or after part of a ClientHello, logs
//!   `<src>:<port> [<date>] <fe>/<listener>: Connection closed during SSL handshake`; plaintext
//!   HTTP logs `...: SSL handshake failure (error:0A00009C:SSL routines::http request)`. Never a
//!   request line, whatever the `log-format`.
//! - Level `info` (6), `err` (3) with `option log-separate-errors`.
//! - `option dontlognull` drops the first two, not the third.
//! - A plaintext client is sent nothing (Ibex sent a 7-byte TLS alert).
//! - `show stat`: the frontend counts `conn_tot` and `ssl_failed_handshake`, and no `ereq`,
//!   `hrsp_4xx` or `req_tot`.

// Set `T262_ORACLE=/path/to/haproxy` to run these tests against HAProxy: it passes all five.
mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const HELLO_PART: &[u8] = b"\x16\x03\x01\x00\xff\x01";
const PLAIN: &[u8] = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n";

struct Run {
    /// The datagrams the three probes produced, in order.
    logs: Vec<String>,
    /// What the plaintext client was sent.
    plain_reply: Vec<u8>,
    /// `show stat`'s frontend row, by column.
    stat: Stat,
    /// The same, before the probes.
    before: Stat,
}

type Stat = std::collections::HashMap<String, String>;

fn show_stat(sock: &str) -> Stat {
    let mut s = UnixStream::connect(sock).expect("stats socket");
    s.write_all(b"show stat\n").expect("write");
    let mut csv = String::new();
    s.read_to_string(&mut csv).expect("read");
    let mut lines = csv.lines();
    let head: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let row = lines.find(|l| l.starts_with("t,FRONTEND,")).expect("frontend row");
    head.iter().zip(row.split(',')).map(|(k, v)| ((*k).to_string(), v.to_string())).collect()
}

/// Runs the three probes against `bind ssl` with `extra` lines in the frontend.
fn run(extra: &str) -> Run {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(300))).expect("timeout");
    let fe = common::reserve_addr();
    let cert = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem");
    let sock = format!("/tmp/t262-{}-{}.sock", std::process::id(), fe.port());
    let mut f = NamedTempFile::new().expect("tmp");
    write!(
        f,
        "global\n  stats socket {sock}\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend t\n  bind {fe} ssl crt {cert}\n  log {} local0\n  option httplog\n  {extra}\n  \
         http-request return status 200\n",
        collector.local_addr().expect("addr")
    )
    .expect("write");
    let mut child = Command::new(std::env::var("T262_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(common::wait_listening(fe), "ibex never listened");
    let probe = |send: &[u8], half_close: bool| -> Vec<u8> {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(send).expect("send");
        if half_close {
            c.shutdown(Shutdown::Write).expect("shutdown");
        }
        c.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(3) {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        got
    };
    // `wait_listening`'s own connection is one more failed handshake: count and log from here.
    std::thread::sleep(Duration::from_millis(300));
    let mut buf = [0u8; 2048];
    while collector.recv(&mut buf).is_ok() {}
    let before = show_stat(&sock);
    probe(b"", true);
    probe(HELLO_PART, true);
    let plain_reply = probe(PLAIN, false);
    let mut logs = Vec::new();
    while let Ok(n) = collector.recv(&mut buf) {
        logs.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    let stat = show_stat(&sock);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&sock);
    Run { logs, plain_reply, stat, before }
}

/// The part after the syslog header.
fn body(l: &str) -> &str {
    l.split_once("]: ").map_or(l, |(_, b)| b).trim_end()
}

/// `<src>:<port> [<date>] t/<listener>: <message>`.
fn is_conn_error(l: &str, message: &str) -> bool {
    let b = body(l);
    let ok = b.starts_with("127.0.0.1:") && b.contains(" [") && b.contains("] t/");
    ok && b.split_once("] t/").and_then(|(_, r)| r.split_once(": ")).is_some_and(|(id, m)| id.bytes().all(|c| c.is_ascii_digit()) && m == message)
}

const EMPTY: &str = "Connection closed during SSL handshake";
const FAILURE: &str = "SSL handshake failure (error:0A00009C:SSL routines::http request)";

#[test]
fn each_failed_handshake_logs_the_connection_error_not_a_request() {
    let r = run("");
    assert_eq!(r.logs.len(), 3, "{:#?}", r.logs);
    assert!(is_conn_error(&r.logs[0], EMPTY), "{:#?}", r.logs);
    assert!(is_conn_error(&r.logs[1], EMPTY), "{:#?}", r.logs);
    assert!(is_conn_error(&r.logs[2], FAILURE), "{:#?}", r.logs);
    assert!(r.logs.iter().all(|l| l.starts_with("<134>") && !l.contains("BADREQ")), "{:#?}", r.logs);
}

#[test]
fn log_separate_errors_sends_them_at_err() {
    let r = run("option log-separate-errors");
    assert_eq!(r.logs.len(), 3, "{:#?}", r.logs);
    assert!(r.logs.iter().all(|l| l.starts_with("<131>")), "{:#?}", r.logs);
    assert!(is_conn_error(&r.logs[2], FAILURE), "{:#?}", r.logs);
}

#[test]
fn dontlognull_drops_the_empty_and_the_aborted_not_the_failure() {
    let r = run("option dontlognull");
    assert_eq!(r.logs.len(), 1, "{:#?}", r.logs);
    assert!(is_conn_error(&r.logs[0], FAILURE), "{:#?}", r.logs);
}

#[test]
fn a_plaintext_client_is_sent_nothing() {
    let r = run("");
    assert_eq!(r.plain_reply, Vec::<u8>::new());
}

#[test]
fn a_failed_handshake_counts_as_such_and_not_as_a_bad_request() {
    let r = run("");
    let get = |k: &str| r.stat.get(k).map_or("", String::as_str).to_string();
    let grew = |k: &str| get(k).parse::<u64>().unwrap_or(0) - r.before.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    assert_eq!(grew("conn_tot"), 3);
    assert_eq!(grew("ssl_failed_handshake"), 3);
    for k in ["ereq", "hrsp_4xx", "req_tot"] {
        assert!(matches!(get(k).as_str(), "" | "0"), "{k} = {:?}", get(k));
    }
}
