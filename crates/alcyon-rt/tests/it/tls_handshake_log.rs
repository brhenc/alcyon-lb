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
//! - A plaintext client is sent nothing (Alcyon sent a 7-byte TLS alert).
//! - `show stat`: the frontend counts `conn_tot` and `ssl_failed_handshake`, and no `ereq`,
//!   `hrsp_4xx` or `req_tot`.

// Set `T262_ORACLE=/path/to/haproxy` to run these tests against HAProxy: it passes all five.
use crate::common;

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

fn admin(sock: &str, cmd: &str) -> String {
    let mut s = UnixStream::connect(sock).expect("stats socket");
    s.write_all(format!("{cmd}\n").as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    out
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
        "global\n  stats socket {sock} level admin\n\
         defaults\n  mode http\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend t\n  bind {fe} ssl crt {cert}\n  log {} local0\n  option httplog\n  {extra}\n  \
         http-request return status 200\n",
        collector.local_addr().expect("addr")
    )
    .expect("write");
    let mut child = Command::new(std::env::var("T262_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string()))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    assert!(common::wait_listening(fe), "alcyon never listened");
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
    /// The output of each admin command given to `session_with`, after the probes.
    cmd_out: Vec<String>,
}

/// Starts `bind ssl` in `mode` with `extra` in the frontend, sends each input on its own
/// connection (half-closing after it when asked) and reads the reply and the log line of each.
fn session(mode: &str, extra: &str, inputs: &[(&[u8], bool)]) -> Session {
    session_with(mode, extra, inputs, &[])
}

/// `session`, then each of `cmds` on the stats socket, before the final `show stat`.
fn session_with(mode: &str, extra: &str, inputs: &[(&[u8], bool)], cmds: &[&str]) -> Session {
    session_full(mode, "", extra, inputs, cmds)
}

/// `session_with`, with `bind_opts` on the `bind` line.
fn session_full(mode: &str, bind_opts: &str, extra: &str, inputs: &[(&[u8], bool)], cmds: &[&str]) -> Session {
    session_quiet(mode, bind_opts, extra, inputs, cmds, 400)
}

/// `session_full`, a probe's log read until `quiet_ms` pass without a line. Longer waits make the
/// session slower, which the rate counters (`conn_rate`, per second) the other tests read do not take.
fn session_quiet(mode: &str, bind_opts: &str, extra: &str, inputs: &[(&[u8], bool)], cmds: &[&str], quiet_ms: u64) -> Session {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(quiet_ms))).expect("timeout");
    let fe = common::reserve_addr();
    let cert = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/localhost.pem");
    let sock = format!("/tmp/t268-{}-{}.sock", std::process::id(), fe.port());
    let mut f = NamedTempFile::new().expect("tmp");
    let (log_opt, tail) = if mode == "http" { ("httplog", "http-request return status 200") } else { ("tcplog", "default_backend b") };
    write!(
        f,
        "global\n  stats socket {sock} level admin\n\
         defaults\n  mode {mode}\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend t\n  bind {fe} ssl crt {cert} {bind_opts}\n  log {} local0\n  option {log_opt}\n  {extra}\n  {tail}\n\
         backend b\n  server s 127.0.0.1:1\n",
        collector.local_addr().expect("addr")
    )
    .expect("write");
    let mut child = Command::new(std::env::var("T262_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string()))
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
        return Session { probes: Vec::new(), stat: Stat::new(), stderr, cmd_out: Vec::new() };
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
    let cmd_out = cmds.iter().map(|c| admin(&sock, c)).collect();
    let stat = show_stat(&sock);
    common::stop(&mut child);
    let _ = std::fs::remove_file(&sock);
    Session { probes, stat, stderr: String::new(), cmd_out }
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

/// HAProxy has `error-log-format` and applies it to this line (measured). Alcyon does not
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

// ---- T272B: TLS handshake details (measured on HAProxy 3.5-dev8-885761-29) ----

/// A ClientHello whose body claims `legacy_version`.
fn hello_legacy(legacy_version: u16) -> Vec<u8> {
    let mut h = client_hello(b"\x13\x01", 0x0301);
    h[9..11].copy_from_slice(&legacy_version.to_be_bytes());
    h
}

/// The message of the one line a probe logged.
fn message(p: &Probed) -> String {
    assert_eq!(p.log.len(), 1, "{:#?}", p.log);
    body(&p.log[0]).split_once("] t/").and_then(|(_, r)| r.split_once(": ")).map_or(String::new(), |(_, m)| m.to_string())
}

/// OpenSSL refuses a ClientHello whose `legacy_version` is below TLS 1.0 (`bad legacy
/// version`), and answers with a fatal alert in a record of that very version:
/// `protocol_version` below SSL 3.0, `handshake_failure` for SSL 3.0. Rustls accepts them.
#[test]
fn a_clienthello_with_an_old_legacy_version_is_refused_like_openssl() {
    let bad = "SSL handshake failure (error:0A000124:SSL routines::bad legacy version)";
    let hellos: Vec<Vec<u8>> = [0x0000, 0x0100, 0x0200, 0x0300, 0x0302].iter().map(|v| hello_legacy(*v)).collect();
    let inputs: Vec<(&[u8], bool)> = hellos.iter().map(|h| (h.as_slice(), false)).collect();
    let s = session("http", "", &inputs);
    assert_eq!(s.probes.len(), 5, "{}", s.stderr);
    for (i, (v, alert)) in [(0x0000u16, 70u8), (0x0100, 70), (0x0200, 70), (0x0300, 40)].into_iter().enumerate() {
        let [hi, lo] = v.to_be_bytes();
        assert_eq!(s.probes[i].reply, [0x15, hi, lo, 0, 2, 2, alert], "legacy_version {v:04x}");
        assert_eq!(message(&s.probes[i]), bad, "legacy_version {v:04x}");
    }
    // TLS 1.1 and 1.2 in `legacy_version` are fine: the server answers with its flight.
    assert_eq!(s.probes[4].reply.first(), Some(&0x16), "legacy_version 0302");
}

/// A client that sends part of its handshake and goes: "Connection closed during SSL
/// handshake" when OpenSSL has not yet read a whole handshake message header, or the FIN came
/// with the bytes; a bare "SSL handshake failure" when a record carrying the start of a
/// handshake message had been read and the FIN arrives alone, later.
#[test]
fn a_client_that_leaves_after_a_whole_record_is_a_bare_failure() {
    let full = client_hello(b"\x13\x01", 0x0301);
    let cut = |n: usize| record(0x16, 0x0301, &full[5..5 + n]);
    let (r3, r20, r40) = (cut(3), cut(20), cut(40));
    // A line the loaded host delivers late must still be read: 1.5 s of quiet ends a probe's log.
    let s = session_quiet(
        "http",
        "",
        "",
        &[(&r20, false), (&r40, false), (&full, false), (&r20, true), (&full, true), (&r3, false), (&full[..30], false), (&full[..30], true), (&r3, true)],
        &[],
        1500,
    );
    assert_eq!(s.probes.len(), 9, "{}", s.stderr);
    let msgs: Vec<String> = s.probes.iter().map(message).collect();
    let bare = "SSL handshake failure";
    assert_eq!(&msgs[..3], [bare, bare, bare], "FIN alone, after a whole record");
    assert!(msgs[3..].iter().all(|m| m == EMPTY), "{msgs:?}");
    assert_eq!(num(&s.stat, "ssl_failed_handshake"), 10, "9 probes and `wait_listening`");
}

/// `strict-sni` is HAProxy's refusal of a ClientHello with no SNI or an unknown one: alert
/// `unrecognized_name` (112), `callback failed`; a matching SNI is served. Alcyon does not
/// implement it and must refuse the keyword (AGENTS.md section 5), not serve without it.
#[test]
fn strict_sni_is_applied_or_refused() {
    let hellos = [hello_sni("other.example"), hello_sni("localhost"), client_hello(b"\x13\x01", 0x0301)];
    let inputs: Vec<(&[u8], bool)> = hellos.iter().map(|h| (h.as_slice(), false)).collect();
    let s = session_full("http", "strict-sni", "", &inputs, &[]);
    if s.probes.is_empty() {
        assert!(s.stderr.contains("strict-sni"), "{}", s.stderr);
        return;
    }
    let cb = "SSL handshake failure (error:0A0000EA:SSL routines::callback failed)";
    for i in [0, 2] {
        assert_eq!(s.probes[i].reply, b"\x15\x03\x03\x00\x02\x02\x70", "probe {i}");
        assert_eq!(message(&s.probes[i]), cb, "probe {i}");
    }
    assert_eq!(s.probes[1].reply.first(), Some(&0x16));
}

fn hello_sni(name: &str) -> Vec<u8> {
    let full = client_hello(b"\x13\x01", 0x0301);
    let n = name.as_bytes();
    let mut e = vec![0, 0];
    e.extend_from_slice(&u16::try_from(n.len() + 5).expect("len").to_be_bytes());
    e.extend_from_slice(&u16::try_from(n.len() + 3).expect("len").to_be_bytes());
    e.push(0);
    e.extend_from_slice(&u16::try_from(n.len()).expect("len").to_be_bytes());
    e.extend_from_slice(n);
    let mut hs = full[5..].to_vec();
    let ext_len_off = 4 + 2 + 32 + 1 + 2 + 2 + 2; // after the cipher list and compression methods
    let old = usize::from(u16::from_be_bytes([hs[ext_len_off], hs[ext_len_off + 1]]));
    hs[ext_len_off..ext_len_off + 2].copy_from_slice(&u16::try_from(old + e.len()).expect("len").to_be_bytes());
    hs.extend_from_slice(&e);
    let l = u32::try_from(hs.len() - 4).expect("len").to_be_bytes();
    hs[1..4].copy_from_slice(&l[1..]);
    record(0x16, 0x0301, &hs)
}

fn stat_row(csv: &str) -> Stat {
    let mut lines = csv.lines();
    let head: Vec<&str> = lines.next().expect("header").trim_start_matches("# ").split(',').collect();
    let row = lines.find(|l| l.starts_with("t,FRONTEND,")).expect("frontend row");
    head.iter().zip(row.split(',')).map(|(k, v)| ((*k).to_string(), v.to_string())).collect()
}

/// `clear counters` zeroes `ssl_failed_handshake` along with the maxima but leaves `conn_tot`;
/// `clear counters all` zeroes both (measured).
#[test]
fn clear_counters_resets_the_failed_handshake_count() {
    let bad = client_hello(b"\x00\xff", 0x0301);
    let ins: [(&[u8], bool); 3] = [(b"", true), (&bad, false), (&bad, false)];
    let s = session_with("http", "", &ins, &["show stat", "clear counters", "show stat", "clear counters all", "show stat"]);
    let (before, plain, all) = (stat_row(&s.cmd_out[0]), stat_row(&s.cmd_out[2]), stat_row(&s.cmd_out[4]));
    assert_eq!((num(&before, "ssl_failed_handshake"), num(&before, "conn_tot")), (4, 4));
    assert_eq!((num(&plain, "ssl_failed_handshake"), num(&plain, "conn_tot")), (0, 4), "clear counters");
    assert_eq!((num(&all, "ssl_failed_handshake"), num(&all, "conn_tot")), (0, 0), "clear counters all");
}

/// A connection whose handshake failed was never a session: `rate_max` stays 0, while
/// `conn_rate_max` follows the connections (measured: 2 or more for connections 0.4 s apart).
#[test]
fn failed_handshakes_raise_conn_rate_max_and_not_rate_max() {
    let ins: [(&[u8], bool); 4] = [(b"", true), (b"", true), (b"", true), (b"", true)];
    let s = session("http", "", &ins);
    assert_eq!(num(&s.stat, "rate_max"), 0, "{:?}", s.stat);
    assert!(num(&s.stat, "conn_rate_max") >= 2, "{:?}", s.stat);
}

/// `option dontlognull` drops the clients that left, not the bare failure (a handshake
/// message was under way): measured.
#[test]
fn dontlognull_keeps_the_bare_failure() {
    let full = client_hello(b"\x13\x01", 0x0301);
    let r20 = record(0x16, 0x0301, &full[5..25]);
    let s = session("http", "option dontlognull", &[(&r20, false), (&r20, true)]);
    assert_eq!(s.probes.len(), 2, "{}", s.stderr);
    assert_eq!(message(&s.probes[0]), "SSL handshake failure");
    assert!(s.probes[1].log.is_empty(), "{:#?}", s.probes[1].log);
}
