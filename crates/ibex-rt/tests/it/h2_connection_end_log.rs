// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What a client connection that ends before any request logs, sends and counts: HTTP/2
//! with no stream, and HTTP/1 under `option http-ignore-probes` (T272).
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`bind ... ssl crt ... alpn h2,http/1.1` and a
//! cleartext bind, `option httplog`), 10 runs each:
//!
//! | client (TLS: ALPN `h2`)                               | log                    |
//! |-------------------------------------------------------|------------------------|
//! | preface (+ SETTINGS), then FIN, reset or a bad record | none                   |
//! | preface + SETTINGS, then `timeout client`             | none (a GOAWAY)        |
//! | nothing or part of the preface, then FIN or reset     | `0 ... PR-- <BADREQ>`  |
//! | the same under `dontlognull` / `http-ignore-probes`   | none for nothing, `0 PR--` for part |
//! | nothing or part of the preface, then a bad record     | none                   |
//! | nothing, then `timeout client`                        | none, nothing sent     |
//! | an HTTP/1 request (a bad preface)                     | `0 PR--`               |
//! | preface, SETTINGS of 5 bytes; HEADERS on stream 2     | `0 PR--`               |
//!
//! None of these opens a stream: `show stat` counts no request and no 4xx. Ibex logged
//! every one `400 CR--` (or `408 cR--`, with an HTTP/1 408 page written into the TLS h2
//! connection) and counted a request and a 4xx for each. A browser that opens an h2
//! connection and closes it unused made a fake 400.
//!
//! HTTP/1 (`h1_process`, `h1_handle_req_tout`): under `option http-ignore-probes` a
//! connection that sent nothing and closes or times out is sent nothing and not logged;
//! under `option dontlognull` the 408 is sent and not logged; part of a request is a
//! `408 cR--` either way.
//!
//! Set `T272_ORACLE=/path/to/haproxy` to run these tests against `HAProxy`: it passes all.

use crate::common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS: &[u8] = b"\0\0\0\x04\0\0\0\0\0";
/// A SETTINGS frame of 5 bytes: not a multiple of 6, `FRAME_SIZE_ERROR`.
const SETTINGS_5: &[u8] = b"\0\0\x05\x04\0\0\0\0\0\0\0\0\0\0";
/// HEADERS (`:method GET`, `END_HEADERS|END_STREAM`) on stream 2: an even id from a client.
const HEADERS_ON_2: &[u8] = b"\0\0\x01\x01\x05\0\0\0\x02\x82";

/// A TLS 1.3 application-data record that does not decrypt.
const BAD_RECORD: [u8; 37] = {
    let mut r = [0u8; 37];
    (r[0], r[1], r[2], r[4]) = (0x17, 3, 3, 32);
    r
};

struct Proxy {
    child: Child,
    logs: mpsc::Receiver<String>,
    stats: std::path::PathBuf,
    tls: SocketAddr,
    clear: SocketAddr,
    sentinel: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    _cfg: NamedTempFile,
    _dir: TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// A server that accepts and never answers (nothing here reaches it).
fn silent_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming() {
            held.push(s);
        }
    });
    addr
}

fn start(options: &str, timeout_client: &str) -> Proxy {
    let dir = TempDir::new().expect("dir");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("pem");
    let stats = dir.path().join("stats.sock");
    let (tls, clear, sentinel) = (common::reserve_addr(), common::reserve_addr(), common::reserve_addr());
    let be = silent_server();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n  stats socket {}\n\
         defaults\n  mode http\n  log global\n  option httplog\n  {options}\n  timeout connect 2s\n  \
         timeout client {timeout_client}\n  timeout server 30s\n\
         frontend t\n  bind {tls} ssl crt {} alpn h2,http/1.1\n  bind {clear}\n  default_backend b\n\
         frontend s\n  bind {sentinel}\n  http-request return status 200\n\
         backend b\n  server s {be}\n",
        stats.display(),
        pem.display()
    )
    .expect("write");
    let bin = std::env::var("T272_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let mut child = Command::new(bin).arg("-f").arg(cfg.path()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proxy { child, logs, stats, tls, clear, sentinel, cert: ck.cert.der().clone(), _cfg: cfg, _dir: dir }
}

#[derive(Clone, Copy)]
enum End {
    /// A FIN, then read to EOF.
    Fin,
    /// A reset.
    Rst,
    /// A TLS record that does not decrypt, then read to EOF.
    BadRecord,
    /// Nothing: read to EOF (`timeout client`, or the proxy closing on an error).
    Wait,
}

/// What a client got.
struct Ended {
    port: u16,
    /// The plaintext it was sent (decrypted on TLS).
    got: Vec<u8>,
    /// How long it waited for EOF after its last action (`None`: a reset, or no EOF in 5 s).
    eof: Option<Duration>,
}

fn read_to_eof(tcp: &mut TcpStream, mut tls: Option<&mut rustls::ClientConnection>) -> (Vec<u8>, Option<Duration>) {
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let t0 = Instant::now();
    let mut got = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match tcp.read(&mut buf) {
            Ok(0) => return (got, Some(t0.elapsed())),
            Ok(n) => match tls.as_deref_mut() {
                Some(c) => {
                    let mut rd = &buf[..n];
                    while !rd.is_empty() && c.read_tls(&mut rd).is_ok() {}
                    if c.process_new_packets().is_ok() {
                        let _ = c.reader().read_to_end(&mut got);
                    }
                }
                None => got.extend_from_slice(&buf[..n]),
            },
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return (got, Some(t0.elapsed())),
            Err(_) => return (got, None),
        }
    }
}

/// Connects (over TLS with ALPN `h2` when `tls`), sends `send`, then ends as `end` says.
fn client(p: &Proxy, tls: bool, send: &[u8], end: End) -> Ended {
    let mut tcp = TcpStream::connect(if tls { p.tls } else { p.clear }).expect("connect");
    let port = tcp.local_addr().unwrap().port();
    let mut conn = None;
    if tls {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(p.cert.clone()).expect("root");
        let mut cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut c = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
        while c.is_handshaking() {
            c.complete_io(&mut tcp).expect("handshake");
        }
        while c.wants_write() {
            c.write_tls(&mut tcp).expect("write_tls");
        }
        thread::sleep(Duration::from_millis(100));
        if !send.is_empty() {
            c.writer().write_all(send).expect("write");
            while c.wants_write() {
                c.write_tls(&mut tcp).expect("write_tls");
            }
        }
        conn = Some(c);
    } else if !send.is_empty() {
        tcp.write_all(send).expect("write");
    }
    thread::sleep(Duration::from_millis(300));
    let (got, eof) = match end {
        End::Rst => {
            rustix::net::sockopt::set_socket_linger(&tcp, Some(Duration::ZERO)).expect("linger");
            drop(tcp);
            thread::sleep(Duration::from_millis(300));
            (Vec::new(), None)
        }
        End::Fin => {
            tcp.shutdown(Shutdown::Write).expect("shutdown");
            read_to_eof(&mut tcp, conn.as_mut())
        }
        End::BadRecord => {
            tcp.write_all(&BAD_RECORD).expect("bad record");
            read_to_eof(&mut tcp, None)
        }
        End::Wait => read_to_eof(&mut tcp, conn.as_mut()),
    };
    Ended { port, got, eof }
}

/// The log lines of the connection from `port`: everything logged before a request to the
/// sentinel frontend, which every proxy logs, is logged.
fn logs_of(p: &Proxy, port: u16) -> Vec<String> {
    let mut s = TcpStream::connect(p.sentinel).expect("sentinel");
    s.write_all(b"GET /sentinel HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").unwrap();
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
    let from = format!("127.0.0.1:{port} ");
    let mut lines = Vec::new();
    loop {
        let line = p.logs.recv_timeout(Duration::from_secs(5)).expect("no sentinel log line");
        if line.contains("GET /sentinel ") {
            return lines;
        }
        if line.starts_with(&from) {
            lines.push(line);
        }
    }
}

/// `show stat`'s frontend `t` columns.
fn stat(p: &Proxy, col: &str) -> String {
    let mut s = UnixStream::connect(&p.stats).expect("stats socket");
    s.write_all(b"show stat\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let head: Vec<&str> = out.lines().next().unwrap().trim_start_matches("# ").split(',').collect();
    let i = head.iter().position(|h| *h == col).expect("column");
    let row = out.lines().find(|l| l.starts_with("t,FRONTEND,")).expect("row");
    row.split(',').nth(i).unwrap().to_string()
}

fn assert_no_log(p: &Proxy, e: &Ended) {
    let l = logs_of(p, e.port);
    assert!(l.is_empty(), "logged: {l:?}");
}

/// `HAProxy`'s line for an HTTP/2 connection error with no stream (`h2_sess_log_conn`).
fn assert_pr(p: &Proxy, e: &Ended) {
    let l = logs_of(p, e.port);
    assert_eq!(l.len(), 1, "{l:?}");
    assert!(l[0].contains(" t/<NOSRV> ") && l[0].contains(" 0 0 - - PR-- ") && l[0].ends_with("\"<BADREQ>\""), "{l:?}");
}

fn full() -> Vec<u8> {
    [PREFACE, SETTINGS].concat()
}

// ---- HTTP/2 after the preface: no stream, nothing to log --------------------------------

#[test]
fn h2_preface_and_settings_then_fin_is_not_logged() {
    let p = start("", "30s");
    let e = client(&p, true, &full(), End::Fin);
    assert!(e.eof.is_some(), "no EOF");
    assert_no_log(&p, &e);
    // No stream: no request, no 4xx.
    assert_eq!((stat(&p, "req_tot"), stat(&p, "hrsp_4xx"), stat(&p, "ereq")), ("0".into(), "0".into(), "0".into()));
}

#[test]
fn h2_preface_then_reset_is_not_logged() {
    let p = start("", "30s");
    let e = client(&p, true, PREFACE, End::Rst);
    assert_no_log(&p, &e);
}

#[test]
fn h2_preface_and_settings_then_a_bad_record_is_not_logged() {
    let p = start("", "30s");
    let e = client(&p, true, &full(), End::BadRecord);
    assert!(e.eof.is_some_and(|d| d < Duration::from_secs(3)), "not closed at once: {:?}", e.eof);
    assert_no_log(&p, &e);
}

#[test]
fn cleartext_h2_preface_and_settings_then_fin_is_not_logged() {
    let p = start("", "30s");
    let e = client(&p, false, &full(), End::Fin);
    assert_no_log(&p, &e);
}

#[test]
fn h2_idle_after_settings_times_out_unlogged() {
    let p = start("", "500ms");
    let e = client(&p, true, &full(), End::Wait);
    assert!(e.eof.is_some(), "never closed");
    assert_no_log(&p, &e);
}

// ---- HTTP/2 negotiated, the preface never complete --------------------------------------

#[test]
fn alpn_h2_nothing_then_fin_logs_pr() {
    let p = start("", "30s");
    let e = client(&p, true, b"", End::Fin);
    assert_pr(&p, &e);
    assert_eq!((stat(&p, "req_tot"), stat(&p, "hrsp_4xx")), ("0".into(), "0".into()));
}

#[test]
fn alpn_h2_part_of_the_preface_then_reset_logs_pr() {
    let p = start("", "30s");
    let e = client(&p, true, &PREFACE[..10], End::Rst);
    assert_pr(&p, &e);
}

#[test]
fn alpn_h2_nothing_then_fin_under_dontlognull_is_not_logged() {
    let p = start("option dontlognull", "30s");
    let e = client(&p, true, b"", End::Fin);
    assert_no_log(&p, &e);
}

#[test]
fn alpn_h2_part_of_the_preface_under_dontlognull_logs_pr() {
    let p = start("option dontlognull", "30s");
    let e = client(&p, true, &PREFACE[..10], End::Fin);
    assert_pr(&p, &e);
}

#[test]
fn alpn_h2_nothing_then_fin_under_http_ignore_probes_is_not_logged() {
    let p = start("option http-ignore-probes", "30s");
    let e = client(&p, true, b"", End::Rst);
    assert_no_log(&p, &e);
}

#[test]
fn alpn_h2_part_of_the_preface_under_http_ignore_probes_logs_pr() {
    let p = start("option http-ignore-probes", "30s");
    let e = client(&p, true, &PREFACE[..10], End::Fin);
    assert_pr(&p, &e);
}

#[test]
fn alpn_h2_nothing_then_a_bad_record_is_not_logged() {
    let p = start("", "30s");
    let e = client(&p, true, b"", End::BadRecord);
    assert!(e.eof.is_some_and(|d| d < Duration::from_secs(3)), "not closed at once: {:?}", e.eof);
    assert_no_log(&p, &e);
}

#[test]
fn alpn_h2_nothing_then_timeout_sends_nothing_and_is_not_logged() {
    let p = start("", "500ms");
    let e = client(&p, true, b"", End::Wait);
    assert!(e.eof.is_some(), "never closed");
    assert!(e.got.is_empty(), "sent {:?}", String::from_utf8_lossy(&e.got));
    assert_no_log(&p, &e);
}

// ---- HTTP/2 protocol errors with no stream: logged (`h2_sess_log_conn`) -----------------

#[test]
fn alpn_h2_http1_request_is_a_bad_preface_logged_pr() {
    let p = start("", "30s");
    let e = client(&p, true, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", End::Wait);
    assert!(e.eof.is_some_and(|d| d < Duration::from_secs(3)), "not closed at once: {:?}", e.eof);
    assert_pr(&p, &e);
}

#[test]
fn h2_a_bad_settings_frame_is_logged_pr() {
    let p = start("", "30s");
    let e = client(&p, true, &[PREFACE, SETTINGS_5].concat(), End::Wait);
    assert!(e.eof.is_some_and(|d| d < Duration::from_secs(3)), "not closed at once: {:?}", e.eof);
    assert_pr(&p, &e);
}

#[test]
fn cleartext_h2_headers_on_an_even_stream_is_logged_pr() {
    let p = start("option dontlognull", "30s");
    let e = client(&p, false, &[PREFACE, SETTINGS, HEADERS_ON_2].concat(), End::Wait);
    assert!(e.eof.is_some_and(|d| d < Duration::from_secs(3)), "not closed at once: {:?}", e.eof);
    assert_pr(&p, &e);
    assert_eq!((stat(&p, "req_tot"), stat(&p, "hrsp_4xx")), ("0".into(), "0".into()));
}

// ---- HTTP/1: `option http-ignore-probes` -------------------------------------------------

#[test]
fn h1_nothing_then_fin_under_http_ignore_probes_sends_nothing_and_is_not_logged() {
    let p = start("option http-ignore-probes", "30s");
    let e = client(&p, false, b"", End::Fin);
    assert!(e.got.is_empty(), "sent {:?}", String::from_utf8_lossy(&e.got));
    assert_no_log(&p, &e);
    assert_eq!((stat(&p, "req_tot"), stat(&p, "hrsp_4xx"), stat(&p, "ereq")), ("0".into(), "0".into(), "0".into()));
}

#[test]
fn h1_nothing_then_reset_under_http_ignore_probes_is_not_logged() {
    let p = start("option http-ignore-probes", "30s");
    let e = client(&p, false, b"", End::Rst);
    assert_no_log(&p, &e);
    assert_eq!((stat(&p, "req_tot"), stat(&p, "hrsp_4xx")), ("0".into(), "0".into()));
}

#[test]
fn h1_nothing_then_timeout_under_http_ignore_probes_sends_no_408() {
    let p = start("option http-ignore-probes", "500ms");
    let e = client(&p, false, b"", End::Wait);
    assert!(e.eof.is_some(), "never closed");
    assert!(e.got.is_empty(), "sent {:?}", String::from_utf8_lossy(&e.got));
    assert_no_log(&p, &e);
    assert_eq!((stat(&p, "req_tot"), stat(&p, "hrsp_4xx")), ("0".into(), "0".into()));
}

#[test]
fn h1_part_of_a_request_then_timeout_under_http_ignore_probes_is_a_408() {
    let p = start("option http-ignore-probes", "500ms");
    let e = client(&p, false, b"GET / HTTP/1.1\r\n", End::Wait);
    assert!(e.got.starts_with(b"HTTP/1.1 408"), "sent {:?}", String::from_utf8_lossy(&e.got));
    let l = logs_of(&p, e.port);
    assert!(l.len() == 1 && l[0].contains(" 408 ") && l[0].contains(" cR-- "), "{l:?}");
}

#[test]
fn h1_nothing_then_timeout_under_dontlognull_sends_the_408_unlogged() {
    let p = start("option dontlognull", "500ms");
    let e = client(&p, false, b"", End::Wait);
    assert!(e.got.starts_with(b"HTTP/1.1 408"), "sent {:?}", String::from_utf8_lossy(&e.got));
    assert_no_log(&p, &e);
}

#[test]
fn h1_nothing_then_timeout_is_a_logged_408() {
    let p = start("", "500ms");
    let e = client(&p, false, b"", End::Wait);
    assert!(e.got.starts_with(b"HTTP/1.1 408"), "sent {:?}", String::from_utf8_lossy(&e.got));
    let l = logs_of(&p, e.port);
    assert!(l.len() == 1 && l[0].contains(" 408 ") && l[0].contains(" cR-- "), "{l:?}");
}
