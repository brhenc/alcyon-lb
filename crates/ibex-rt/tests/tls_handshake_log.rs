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

// ---- T268: what T262 left ----

/// One probe: what it sent, and what came back and was logged.
struct Probed {
    reply: Vec<u8>,
    log: Vec<String>,
}

struct Session {
    probes: Vec<Probed>,
    stat: Stat,
    stderr: String,
}

/// Starts `bind ssl` in `mode` with `extra` in the frontend, sends each input on its own
/// connection (half-closing after it when asked) and reads the reply and the log line of each.
fn session(mode: &str, extra: &str, inputs: &[(&[u8], bool)]) -> Session {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(400))).expect("timeout");
    let fe = common::reserve_addr();
    let cert = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem");
    let sock = format!("/tmp/t268-{}-{}.sock", std::process::id(), fe.port());
    let mut f = NamedTempFile::new().expect("tmp");
    let (log_opt, tail) = if mode == "http" { ("httplog", "http-request return status 200") } else { ("tcplog", "default_backend b") };
    write!(
        f,
        "global\n  stats socket {sock}\n\
         defaults\n  mode {mode}\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend t\n  bind {fe} ssl crt {cert}\n  log {} local0\n  option {log_opt}\n  {extra}\n  {tail}\n\
         backend b\n  server s 127.0.0.1:1\n",
        collector.local_addr().expect("addr")
    )
    .expect("write");
    let mut child = Command::new(std::env::var("T262_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    if !common::wait_listening(fe) {
        common::stop(&mut child);
        let mut stderr = String::new();
        let _ = child.stderr.take().map(|mut e| e.read_to_string(&mut stderr));
        return Session { probes: Vec::new(), stat: Stat::new(), stderr };
    }
    std::thread::sleep(Duration::from_millis(300));
    let mut buf = [0u8; 2048];
    while collector.recv(&mut buf).is_ok() {}
    let mut probes = Vec::new();
    for (send, half_close) in inputs {
        let mut c = TcpStream::connect(fe).expect("connect");
        c.write_all(send).expect("send");
        if *half_close {
            c.shutdown(Shutdown::Write).expect("shutdown");
        }
        c.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
        let mut reply = Vec::new();
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(2) {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => reply.extend_from_slice(&buf[..n]),
            }
        }
        drop(c);
        let mut log = Vec::new();
        while let Ok(n) = collector.recv(&mut buf) {
            log.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        probes.push(Probed { reply, log });
    }
    let stat = show_stat(&sock);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&sock);
    Session { probes, stat, stderr: String::new() }
}

/// A TLS record.
fn record(kind: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut r = vec![kind];
    r.extend_from_slice(&version.to_be_bytes());
    r.extend_from_slice(&u16::try_from(body.len()).expect("len").to_be_bytes());
    r.extend_from_slice(body);
    r
}

/// A ClientHello (TLS 1.3 capable) offering `ciphers`, in a record with `record_version`.
fn client_hello(ciphers: &[u8], record_version: u16) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(b"\x00\x2b\x00\x03\x02\x03\x04"); // supported_versions: 1.3
    ext.extend_from_slice(b"\x00\x0a\x00\x04\x00\x02\x00\x1d"); // supported_groups: x25519
    ext.extend_from_slice(b"\x00\x0d\x00\x04\x00\x02\x08\x04"); // signature_algorithms
    ext.extend_from_slice(b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20");
    ext.extend_from_slice(&[1u8; 32]); // key_share
    let mut b = vec![0x03, 0x03];
    b.extend_from_slice(&[2u8; 32]);
    b.push(0);
    b.extend_from_slice(&u16::try_from(ciphers.len()).expect("len").to_be_bytes());
    b.extend_from_slice(ciphers);
    b.extend_from_slice(&[1, 0]);
    b.extend_from_slice(&u16::try_from(ext.len()).expect("len").to_be_bytes());
    b.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&u32::try_from(b.len()).expect("len").to_be_bytes()[1..]);
    hs.extend_from_slice(&b);
    record(0x16, record_version, &hs)
}

fn num(stat: &Stat, k: &str) -> u64 {
    stat.get(k).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// A frontend counts a session once its handshake is done; `conn_tot` counts the connection.
#[test]
fn a_failed_handshake_is_a_connection_not_a_session() {
    for mode in ["http", "tcp"] {
        let s = session(mode, "", &[(b"", true), (HELLO_PART, true), (PLAIN, false)]);
        assert_eq!(num(&s.stat, "conn_tot"), 4, "{mode}: {:?}", s.stat); // the probes and `wait_listening`
        assert_eq!(num(&s.stat, "stot"), 0, "{mode}: stot");
        assert_eq!(num(&s.stat, "rate"), 0, "{mode}: rate");
        assert!(num(&s.stat, "conn_rate") >= 1, "{mode}: conn_rate");
    }
}

/// Measured on HAProxy: the log text and the alert (none when the record header is wrong).
#[test]
fn tls_looking_failures_log_openssl_text_and_send_openssl_alerts() {
    let no_cipher = client_hello(b"\x00\xff", 0x0301);
    let app_data = record(0x17, 0x0303, &[b'x'; 20]);
    let garbage = record(0x16, 0x0301, &[0xff; 40]);
    let early_alert = record(0x15, 0x0303, b"\x02\x28");
    let bad_version = client_hello(b"\x13\x01", 0x0100);
    let s = session("http", "", &[(&no_cipher, false), (&app_data, false), (&garbage, false), (&early_alert, false), (&bad_version, false)]);
    assert_eq!(s.probes.len(), 5, "{}", s.stderr);
    let msg = |i: usize| s.probes[i].log.first().map(|l| body(l).split_once("] t/").and_then(|(_, r)| r.split_once(": ")).map_or("", |(_, m)| m).to_string());
    let no_shared = "SSL handshake failure (error:0A0000C1:SSL routines::no shared cipher)";
    let unexpected = "SSL handshake failure (error:0A0000F4:SSL routines::unexpected message)";
    let wrong_version = "SSL handshake failure (error:0A00010B:SSL routines::wrong version number)";
    assert_eq!(msg(0).as_deref(), Some(no_shared));
    assert_eq!(s.probes[0].reply, b"\x15\x03\x03\x00\x02\x02\x28", "handshake_failure");
    for i in 1..=3 {
        assert_eq!(msg(i).as_deref(), Some(unexpected), "probe {i}");
        assert_eq!(s.probes[i].reply, b"\x15\x03\x03\x00\x02\x02\x0a", "unexpected_message, probe {i}");
    }
    // A record header that is not TLS's at all: logged as such, answered with nothing.
    let junk_header = client_hello(b"\x13\x01", 0x0501);
    let s2 = session("http", "", &[(&junk_header, false)]);
    let m2 = s2.probes[0].log.first().map(|l| body(l).split_once("] t/").and_then(|(_, r)| r.split_once(": ")).map_or("", |(_, m)| m).to_string());
    assert_eq!(m2.as_deref(), Some(wrong_version));
    assert_eq!(s2.probes[0].reply, Vec::<u8>::new());
}

/// HAProxy has `error-log-format` and applies it to this line (measured). Ibex does not
/// read the keyword, so the parser must refuse it rather than drop it (AGENTS.md section 5).
#[test]
fn error_log_format_is_refused_or_applied() {
    let s = session("http", "error-log-format \"ELF %ci:%cp %ft\"", &[(b"", true)]);
    if s.probes.is_empty() {
        assert!(s.stderr.contains("error-log-format"), "{}", s.stderr);
    } else {
        assert!(s.probes[0].log.first().is_some_and(|l| body(l).starts_with("ELF 127.0.0.1:")), "{:#?}", s.probes[0].log);
    }
}

/// A TCP frontend takes the same path: the same line, level and counters (measured).
#[test]
fn a_tcp_frontend_logs_the_connection_error_too() {
    let s = session("tcp", "option log-separate-errors", &[(b"", true), (PLAIN, false)]);
    assert_eq!(s.probes[0].log.len(), 1, "{:#?}", s.probes[0].log);
    assert!(is_conn_error(&s.probes[0].log[0], EMPTY), "{:#?}", s.probes[0].log);
    assert!(is_conn_error(&s.probes[1].log[0], FAILURE), "{:#?}", s.probes[1].log);
    assert!(s.probes.iter().all(|p| p.log[0].starts_with("<131>")), "{:#?}", s.probes[0].log);
    assert_eq!(s.probes[1].reply, Vec::<u8>::new());
    assert_eq!(num(&s.stat, "ssl_failed_handshake"), 3);
}
