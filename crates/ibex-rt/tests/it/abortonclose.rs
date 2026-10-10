// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `option abortonclose`: a client that leaves before its response (T227).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-05, `mode http`, a request `GET /`
//! and then the client leaving (the T227 scratch `oracle.py`, `body.py`):
//!
//! | request is ...         | client   | abortonclose (the default) | `no option abortonclose` |
//! |------------------------|----------|----------------------------|--------------------------|
//! | at the server          | FIN      | server RST at once; `CH` 400; a half-closed client is sent the 400; `cli_abrt` +1 | the server keeps it, nothing logged |
//! | at the server          | RST      | server RST; `CD` 400; `cli_abrt` +2 | the same            |
//! | answered in part       | FIN      | server RST, the rest of the body is not sent; `CD` 200 | the rest is sent |
//! | queued (`maxconn`)     | FIN      | dropped: `CQ` -1           | still queued             |
//! | connecting             | FIN      | dropped: `CC` -1           | still connecting         |
//!
//! `option abortonclose` in the backend overrides `no option abortonclose` in `defaults`,
//! and `no option abortonclose` in the backend overrides the default.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Where the request is when the client leaves.
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    /// At a server that has read it and does not answer.
    Server,
    /// At a server that has sent the head and part of the body.
    Body,
    /// Queued behind the one connection `maxconn 1` allows.
    Queue,
    /// Connecting to a server whose accept queue is full.
    Connect,
}

/// How the client leaves.
#[derive(Clone, Copy, PartialEq)]
enum Leave {
    /// `close()`: a FIN, and nothing more read.
    Close,
    /// `shutdown(SHUT_WR)`: a FIN, and the client reads what comes.
    HalfClose,
    /// `close()` with `SO_LINGER` 0: a reset.
    Reset,
}

/// What the server saw on its connection after the client left.
#[derive(Debug, PartialEq)]
enum Saw {
    Reset,
    Fin,
    Nothing,
    /// The phase has no server connection to look at.
    NotConnected,
}

struct Outcome {
    server: Saw,
    /// What a half-closed client read after it left.
    client: Vec<u8>,
    /// The stream's log line, `%HU ts=%ts ST=%ST`, if it ended within the second.
    log: Option<String>,
    /// `cli_abrt` of the backend and of its server.
    cli_abrt: (u64, u64),
}

struct Ibex {
    child: Child,
    sock: PathBuf,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn cli(sock: &PathBuf, cmd: &str) -> String {
    let mut c = UnixStream::connect(sock).expect("connect cli");
    c.write_all(format!("{cmd}\n").as_bytes()).expect("send");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    out
}

/// `cli_abrt` of `b`'s BACKEND line and of its server `s`.
fn cli_abrt(sock: &PathBuf) -> (u64, u64) {
    let stat = cli(sock, "show stat");
    let mut lines = stat.lines();
    let head: Vec<&str> = lines.next().unwrap_or("").trim_start_matches("# ").split(',').collect();
    let col = head.iter().position(|h| *h == "cli_abrt").expect("cli_abrt column");
    let mut be = 0;
    let mut srv = 0;
    for l in lines {
        let v: Vec<&str> = l.split(',').collect();
        if v.len() > col && v[0] == "b" {
            let n = v[col].parse().unwrap_or(0);
            match v[1] {
                "BACKEND" => be = n,
                "s" => srv = n,
                _ => {}
            }
        }
    }
    (be, srv)
}

/// A listener whose accept queue is full: a connect to it neither completes nor fails.
fn full_listener() -> (rustix::fd::OwnedFd, SocketAddr, TcpStream) {
    use rustix::net::{bind, listen, socket, AddressFamily, SocketType};
    let fd = socket(AddressFamily::INET, SocketType::STREAM, None).expect("socket");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    bind(&fd, &any).expect("bind");
    listen(&fd, 0).expect("listen");
    let addr = match rustix::net::getsockname(&fd).expect("getsockname") {
        rustix::net::SocketAddrAny::V4(a) => SocketAddr::V4(a),
        other => panic!("{other:?}"),
    };
    // A backlog of 0 takes one connection; the next ones wait for a SYN-ACK.
    let filler = TcpStream::connect(addr).expect("fill the accept queue");
    (fd, addr, filler)
}

/// What a server connection shows within `wait`: a reset, a FIN, or nothing.
fn watch(s: &mut TcpStream, wait: Duration) -> Saw {
    s.set_read_timeout(Some(wait)).expect("timeout");
    let mut buf = [0u8; 256];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return Saw::Fin,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return Saw::Reset,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Saw::Nothing,
            Err(e) => panic!("server read: {e}"),
        }
    }
}

fn read_head(s: &mut TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    let mut d = Vec::new();
    let mut b = [0u8; 1024];
    while !d.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut b).expect("server reads the request");
        assert!(n > 0, "Ibex closed before sending the request");
        d.extend_from_slice(&b[..n]);
    }
}

fn leave(mut c: TcpStream, how: Leave) -> Vec<u8> {
    match how {
        Leave::Close => Vec::new(),
        Leave::Reset => {
            rustix::net::sockopt::set_socket_linger(&c, Some(Duration::ZERO)).expect("linger");
            Vec::new()
        }
        Leave::HalfClose => {
            c.shutdown(Shutdown::Write).expect("shutdown");
            c.set_read_timeout(Some(Duration::from_millis(1500))).expect("timeout");
            let mut out = Vec::new();
            let _ = c.read_to_end(&mut out);
            out
        }
    }
}

/// Ibex with `defaults_extra` and `backend_extra`, a client that sends `GET /` and leaves
/// with `how` once the request is at `phase`.
fn run(defaults_extra: &str, backend_extra: &str, phase: Phase, how: Leave) -> Outcome {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let sock = PathBuf::from(format!("/tmp/ibex-aoc-{}-{n}.sock", std::process::id()));
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
    let fe = common::reserve_addr();

    let listener = TcpListener::bind("127.0.0.1:0").expect("server");
    let mut _full = None;
    let srv_addr = if phase == Phase::Connect {
        let (fd, addr, filler) = full_listener();
        _full = Some((fd, filler));
        addr
    } else {
        listener.local_addr().unwrap()
    };
    let maxconn = if phase == Phase::Queue { " maxconn 1" } else { "" };
    let cfg = format!(
        "global\n  stats socket {} level admin\n\
         defaults\n  mode http\n  timeout client 2s\n  timeout connect 2s\n  timeout server 2s\n  timeout queue 2s\n{defaults_extra}\
         frontend f\n  bind {fe}\n  log {} local0\n  log-format \"%HU ts=%ts ST=%ST\"\n  default_backend b\n\
         backend b\n{backend_extra}  server s {srv_addr}{maxconn}\n",
        sock.display(),
        collector.local_addr().unwrap()
    );
    let path = std::env::temp_dir().join(format!("ibex-aoc-{}-{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let ibex = Ibex { child, sock };
    assert!(common::wait_listening(fe), "ibex never listened");
    let _ = std::fs::remove_file(&path);

    // The request that holds the server's one slot.
    let mut holder = None;
    if phase == Phase::Queue {
        let mut h = TcpStream::connect(fe).expect("connect");
        h.write_all(b"GET /hold HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        let (mut s, _) = listener.accept().expect("accept the holder");
        read_head(&mut s);
        holder = Some((h, s));
    }

    let mut c = TcpStream::connect(fe).expect("connect");
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut srv = None;
    match phase {
        Phase::Server | Phase::Body => {
            let (mut s, _) = listener.accept().expect("accept");
            read_head(&mut s);
            if phase == Phase::Body {
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n0123456789").expect("answer");
                let mut b = [0u8; 256];
                c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
                let mut got = Vec::new();
                while !got.ends_with(b"0123456789") {
                    let n = c.read(&mut b).expect("the response head and half the body");
                    assert!(n > 0, "closed before the first half of the body");
                    got.extend_from_slice(&b[..n]);
                }
            }
            srv = Some(s);
        }
        // Long enough to be queued, or for the connect to be under way.
        Phase::Queue | Phase::Connect => thread::sleep(Duration::from_millis(300)),
    }

    // A half-closed client reads while the server is watched.
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || tx.send(leave(c, how)));
    let server = match srv.as_mut() {
        Some(s) if phase == Phase::Body => {
            thread::sleep(Duration::from_millis(300));
            // The second half: refused by a reset connection, forwarded by a kept one. The
            // write reports the reset when it comes first, and the read after it sees an EOF.
            match s.write_all(b"abcdefghij") {
                Err(e) if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::BrokenPipe) => Saw::Reset,
                _ => watch(s, Duration::from_millis(1000)),
            }
        }
        Some(s) => watch(s, Duration::from_millis(1000)),
        None => Saw::NotConnected,
    };
    let client = rx.recv_timeout(Duration::from_secs(5)).expect("the client finished");

    let mut log = None;
    let end = Instant::now() + Duration::from_millis(1000);
    let mut buf = [0u8; 2048];
    while log.is_none() && Instant::now() < end {
        if let Ok(n) = collector.recv(&mut buf) {
            let line = String::from_utf8_lossy(&buf[..n]).into_owned();
            // `/hold` is the queue phase's other request.
            if let Some(i) = line.find("/ ts=").filter(|_| !line.contains("/hold")) {
                let start = line[..i].rfind(' ').map_or(0, |s| s + 1);
                log = Some(line[start..].trim_end().to_string());
            }
        }
    }
    let cli_abrt = cli_abrt(&ibex.sock);
    // The timeouts are short so that a stream still waiting (without abortonclose) has ended
    // by the soft stop's deadline: a binary killed after it writes no coverage profile.
    drop(holder);
    Outcome { server, client, log, cli_abrt }
}

fn status_line(client: &[u8]) -> String {
    String::from_utf8_lossy(client).lines().next().unwrap_or("").to_string()
}

#[test]
fn by_default_a_client_that_closes_resets_the_server_connection() {
    let o = run("", "", Phase::Server, Leave::Close);
    assert_eq!(o.server, Saw::Reset, "HAProxy resets the server connection at once");
    assert_eq!(o.log.as_deref(), Some("/ ts=CH ST=400"));
    assert_eq!(o.cli_abrt, (1, 1));
}

#[test]
fn a_half_closed_client_is_sent_a_400() {
    let o = run("", "", Phase::Server, Leave::HalfClose);
    assert_eq!(o.server, Saw::Reset);
    assert_eq!(status_line(&o.client), "HTTP/1.1 400 Bad request", "{:?}", String::from_utf8_lossy(&o.client));
    assert_eq!(o.log.as_deref(), Some("/ ts=CH ST=400"));
}

#[test]
fn option_abortonclose_in_the_backend_overrides_defaults() {
    let o = run("  no option abortonclose\n", "  option abortonclose\n", Phase::Server, Leave::Close);
    assert_eq!(o.server, Saw::Reset);
    assert_eq!(o.log.as_deref(), Some("/ ts=CH ST=400"));
}

#[test]
fn without_abortonclose_the_server_keeps_the_request() {
    for (defaults, backend) in [("  no option abortonclose\n", ""), ("", "  no option abortonclose\n")] {
        for how in [Leave::Close, Leave::HalfClose] {
            let o = run(defaults, backend, Phase::Server, how);
            assert_eq!(o.server, Saw::Nothing, "defaults {defaults:?} backend {backend:?}");
            // Still waiting for the server, or, read late enough, ended by `timeout server`.
            assert!(matches!(o.log.as_deref(), None | Some("/ ts=sH ST=504")), "{:?}", o.log);
            assert_eq!(o.client, b"", "nothing is sent to a half-closed client");
        }
    }
}

#[test]
fn a_client_reset_aborts_with_or_without_the_option() {
    for defaults in ["", "  no option abortonclose\n"] {
        let o = run(defaults, "", Phase::Server, Leave::Reset);
        assert_eq!(o.server, Saw::Reset, "defaults {defaults:?}");
        assert_eq!(o.log.as_deref(), Some("/ ts=CD ST=400"), "defaults {defaults:?}");
        assert_eq!(o.cli_abrt, (2, 2), "HAProxy counts a reset client twice (defaults {defaults:?})");
    }
}

#[test]
fn a_client_that_half_closes_during_the_body_cuts_the_response() {
    let o = run("", "", Phase::Body, Leave::HalfClose);
    assert_eq!(o.server, Saw::Reset);
    assert!(!o.client.ends_with(b"abcdefghij"), "the rest of the body was forwarded");
    assert_eq!(o.log.as_deref(), Some("/ ts=CD ST=200"));

    let o = run("  no option abortonclose\n", "", Phase::Body, Leave::HalfClose);
    assert_eq!(o.server, Saw::Nothing);
    assert!(o.client.ends_with(b"abcdefghij"), "{:?}", String::from_utf8_lossy(&o.client));
}

#[test]
fn a_queued_request_is_dropped_only_with_abortonclose() {
    let o = run("", "", Phase::Queue, Leave::Close);
    assert_eq!(o.log.as_deref(), Some("/ ts=CQ ST=-1"));
    assert_eq!(o.cli_abrt, (0, 0));
    let o = run("  no option abortonclose\n", "", Phase::Queue, Leave::Close);
    assert_eq!(o.log, None, "still queued");
}

#[test]
fn a_connecting_request_is_dropped_only_with_abortonclose() {
    let o = run("", "", Phase::Connect, Leave::Close);
    assert_eq!(o.log.as_deref(), Some("/ ts=CC ST=-1"));
    assert_eq!(o.cli_abrt, (0, 0));
    let o = run("  no option abortonclose\n", "", Phase::Connect, Leave::Close);
    assert_eq!(o.log, None, "still connecting");
}

/// On devtest7 (vegeta keeps its connections alive), streams whose client left stayed at the
/// server until `timeout server`: an earlier request on the same connection had ended in a
/// 503 (its connect refused), and what ended that one was still taken for how this one ended.
#[test]
fn a_request_after_a_503_on_the_same_connection_is_still_aborted() {
    // Nothing listens on the server's port for the first request: refused, a 503.
    let port = common::reserve_port();
    let srv_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  retries 0\n  timeout client 5s\n  timeout connect 2s\n  timeout server 5s\n\
         frontend f\n  bind {fe}\n  default_backend b\nbackend b\n  server s {srv_addr}\n"
    );
    let path = std::env::temp_dir().join(format!("ibex-aoc-503-{}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&path).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn ibex");
    let _ibex = Ibex { child, sock: PathBuf::from("/nonexistent") };
    assert!(common::wait_listening(fe), "ibex never listened");
    let _ = std::fs::remove_file(&path);

    let mut c = TcpStream::connect(fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(5))).expect("timeout");
    c.write_all(b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let mut got = Vec::new();
    let mut b = [0u8; 4096];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = c.read(&mut b).expect("the first answer");
        assert!(n > 0, "closed instead of answering");
        got.extend_from_slice(&b[..n]);
    }
    assert!(got.starts_with(b"HTTP/1.1 503"), "{:?}", String::from_utf8_lossy(&got));
    // HAProxy keeps the connection after this 503 too (measured): the next request on it.
    let listener = TcpListener::bind(srv_addr).expect("the server comes up");
    c.write_all(b"GET /2 HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let (mut s, _) = listener.accept().expect("the second request reaches the server");
    read_head(&mut s);
    drop(c);
    assert_eq!(watch(&mut s, Duration::from_millis(1000)), Saw::Reset, "the client left; abortonclose resets the server");
}
