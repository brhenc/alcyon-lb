// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! An error a session's processing returns ends that session at once (T261).
//!
//! The engine called `Session::process` at four places and dropped what it returned, so an
//! error closed nothing: the connection was held until a timeout. The error a client can
//! cause at will is a TLS record that does not decrypt, sent after the handshake.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`bind ... ssl crt ... alpn h2,http/1.1`,
//! `timeout client 30s`, `timeout server 30s`, a server that accepts and never answers),
//! a client that completes the handshake and then sends `17 03 03 00 20` and 32 zero bytes:
//!
//! | before the bad record        | client EOF | log                                  |
//! |------------------------------|-----------:|--------------------------------------|
//! | nothing (HTTP/1.1)           | 0.0 s      | `400 ... CR-- ... "<BADREQ>"`        |
//! | a request, server silent     | 0.0 s      | `b/s ... 400 ... CD-- ... "GET / ..."` |
//! | the HTTP/2 preface, SETTINGS | 0.0 s      | `0 ... PR-- ... "<BADREQ>"`          |
//!
//! Ibex held all three for the 30 s of a timeout (`408 cR--`, `504 sH--`, `408 cR--`). Now
//! it closes them at once, with `HAProxy`'s log for the first two; the HTTP/2 one is logged
//! `400 CR--`, as `HAProxy` logs an HTTP/2 client's reset at that point.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

/// How long the client waits for EOF; every timeout in the configuration is 30 s.
const PROMPT: Duration = Duration::from_secs(3);

/// A TLS 1.3 application-data record that does not decrypt.
const BAD_RECORD: [u8; 37] = {
    let mut r = [0u8; 37];
    (r[0], r[1], r[2], r[4]) = (0x17, 3, 3, 32);
    r
};

struct Ibex {
    child: Child,
    logs: mpsc::Receiver<String>,
    stats: std::path::PathBuf,
    fe: SocketAddr,
    _cfg: NamedTempFile,
    _dir: TempDir,
    cert: rustls::pki_types::CertificateDer<'static>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(be: SocketAddr) -> Ibex {
    let dir = TempDir::new().expect("dir");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("pem");
    let stats = dir.path().join("stats.sock");
    let fe = common::reserve_addr();
    let mut cfg = NamedTempFile::new().expect("tmp");
    write!(
        cfg,
        "global\n  log stdout format raw local0\n  stats socket {}\n\
         defaults\n  mode http\n  log global\n  option httplog\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
         frontend t\n  bind {fe} ssl crt {} alpn h2,http/1.1\n  default_backend b\n\
         backend b\n  server s {be}\n",
        stats.display(),
        pem.display()
    )
    .expect("write");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(fe), "ibex never listened");
    Ibex { child, logs, stats, fe, _cfg: cfg, _dir: dir, cert: ck.cert.der().clone() }
}

/// A server that accepts and never answers; sends each connection's lifetime once it ends.
fn silent_server() -> (SocketAddr, mpsc::Receiver<Duration>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let tx = tx.clone();
            thread::spawn(move || {
                let t0 = Instant::now();
                let mut buf = [0u8; 4096];
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
                let _ = tx.send(t0.elapsed());
            });
        }
    });
    (addr, rx)
}

/// Completes a TLS handshake (offering `alpn`), sends `first` under TLS, then the bad
/// record in clear. How long the client waited for EOF (`None`: none came), and its port.
fn bad_record_after(ibex: &Ibex, alpn: &[u8], first: &[u8]) -> (Option<Duration>, u16) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ibex.cert.clone()).expect("root");
    let mut cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).expect("client");
    let mut tcp = TcpStream::connect(ibex.fe).expect("connect");
    let port = tcp.local_addr().unwrap().port();
    tcp.set_read_timeout(Some(PROMPT + Duration::from_secs(1))).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).expect("handshake");
    }
    // The client's `Finished` may still be queued. The bad record comes after the server has
    // taken it: one read with both fails the handshake, which T259 covers.
    while conn.wants_write() {
        conn.write_tls(&mut tcp).expect("write_tls");
    }
    thread::sleep(Duration::from_millis(100));
    if !first.is_empty() {
        conn.writer().write_all(first).expect("write");
        while conn.wants_write() {
            conn.write_tls(&mut tcp).expect("write_tls");
        }
        thread::sleep(Duration::from_millis(300));
    }
    tcp.write_all(&BAD_RECORD).expect("bad record");
    let t0 = Instant::now();
    let mut buf = [0u8; 4096];
    loop {
        match tcp.read(&mut buf) {
            Ok(0) => return (Some(t0.elapsed()), port),
            Ok(_) => {}
            // A reset is the connection closed too.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return (Some(t0.elapsed()), port),
            Err(_) => return (None, port),
        }
    }
}

/// The log line of the connection from `port` (`wait_listening`'s probe has one too).
fn log_of(ibex: &Ibex, port: u16) -> String {
    let from = format!("127.0.0.1:{port} ");
    loop {
        let line = ibex.logs.recv_timeout(PROMPT).expect("no log line");
        if line.starts_with(&from) {
            return line;
        }
    }
}

/// The `scur` column of `show stat` for `proxy`/`name`.
fn scur(ibex: &Ibex, proxy: &str, name: &str) -> String {
    let mut s = UnixStream::connect(&ibex.stats).expect("stats socket");
    s.write_all(b"show stat\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let head: Vec<&str> = out.lines().next().unwrap().trim_start_matches("# ").split(',').collect();
    let col = head.iter().position(|h| *h == "scur").expect("scur column");
    let row = out.lines().find(|l| l.starts_with(&format!("{proxy},{name},"))).expect("row");
    row.split(',').nth(col).unwrap().to_string()
}

fn assert_prompt((waited, port): (Option<Duration>, u16)) -> u16 {
    assert!(waited.is_some_and(|d| d < PROMPT), "no EOF within {PROMPT:?}: {waited:?}");
    port
}

#[test]
fn a_bad_record_before_any_request_closes_the_connection() {
    let (be, _) = silent_server();
    let ibex = start(be);
    let port = assert_prompt(bad_record_after(&ibex, b"http/1.1", b""));
    let log = log_of(&ibex, port);
    assert!(log.contains(" 400 0 - - CR-- ") && log.ends_with("\"<BADREQ>\""), "{log}");
    assert_eq!(scur(&ibex, "t", "FRONTEND"), "0");
}

#[test]
fn a_bad_record_while_the_server_is_silent_closes_both_connections() {
    let (be, server_ended) = silent_server();
    let ibex = start(be);
    let port = assert_prompt(bad_record_after(&ibex, b"http/1.1", b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"));
    let held = server_ended.recv_timeout(PROMPT).expect("the server connection was kept open");
    assert!(held < PROMPT, "server connection held {held:?}");
    let log = log_of(&ibex, port);
    assert!(log.contains(" b/s ") && log.contains(" CD-- ") && log.ends_with("\"GET / HTTP/1.1\""), "{log}");
    assert_eq!(scur(&ibex, "t", "FRONTEND"), "0");
    assert_eq!(scur(&ibex, "b", "s"), "0");
    assert_eq!(scur(&ibex, "b", "BACKEND"), "0");
}

#[test]
fn a_bad_record_on_an_http2_connection_closes_it() {
    let (be, _) = silent_server();
    let ibex = start(be);
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0";
    let port = assert_prompt(bad_record_after(&ibex, b"h2", preface));
    // Logged once. HAProxy logs it `0 ... PR--`; Ibex logs `400 ... CR--`, which is what
    // HAProxy logs for an HTTP/2 client that resets or half-closes at this point: the
    // flags are not this test's subject (see the report of T261).
    let log = log_of(&ibex, port);
    assert!(log.ends_with("\"<BADREQ>\""), "{log}");
    assert_eq!(scur(&ibex, "t", "FRONTEND"), "0");
}

/// A socket error the transport does not map (here `ECONNREFUSED`, as an ICMP error leaves on
/// a connection) on the server side ends that side as a server abort. It used to be returned
/// and dropped, leaving the server side established until `timeout server`. Not measured on
/// `HAProxy`, which cannot be made to see an ICMP error on an established TCP connection from
/// here; it closes on any socket error (`CO_FL_ERROR`) at once.
#[test]
fn an_unmapped_server_socket_error_ends_the_server_side() {
    use ibex_proto::endpoint::ScState;
    use ibex_rt::proxy::{Ending, TcpSession, Timeouts};
    use ibex_sched::Tick;
    use std::net::UdpSocket;
    use std::os::fd::OwnedFd;

    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let _client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (cli, _) = l.accept().unwrap();
    cli.set_nonblocking(true).unwrap();
    // A port nothing listens on: the datagram draws ICMP port unreachable, which the next
    // read on the socket returns as `ECONNREFUSED`.
    let closed = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
    srv.connect(closed.local_addr().unwrap()).unwrap();
    drop(closed);
    srv.send(b"x").unwrap();
    thread::sleep(Duration::from_millis(50));
    srv.set_nonblocking(true).unwrap();

    let t = Timeouts { client: 30_000, server: 30_000, connect: 2_000 };
    let mut sess = TcpSession::new(OwnedFd::from(cli), t, 0, Tick(1));
    sess.attach_server(OwnedFd::from(srv), Tick(1));
    sess.server_connected(Tick(1));
    let _ = sess.process(Tick(2));
    assert_eq!(sess.srv_state, ScState::Closed);
    assert_eq!(sess.ending, Some(Ending::ServerAbort));
}
