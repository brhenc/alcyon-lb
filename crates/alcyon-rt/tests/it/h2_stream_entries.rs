// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Each stream of an HTTP/2 connection is served by a session entry of its own, beside the
//! entry that holds the connection (T280 stage 3a): `HAProxy`'s `h2c` and, per stream, an
//! `h2s` with its `struct stream`.
//!
//! The split must not show: the connection counts once in `act_conn` (`feconn`), each
//! stream once in `be_streams` (`beconn`) while it is served, a finished stream's entry
//! is freed and the connection's is not, a connection that closes ends its stream, and the
//! next stream takes back the server connection the last one kept (as the session kept it
//! between requests). `show sess` lists one stream per stream being served (measured on
//! `HAProxy` 3.5-dev8-885761-29: an `h2c` with one stream at a silent server lists one
//! stream, `fe=fe be=be srv=s1`, with the connection's fd; an idle `h2c` lists none, where
//! Alcyon still lists the connection: left for T280 stage 4). The log line of each stream is
//! the one the connection logged for it before, as `HAProxy` logs it (measured below; run
//! the binary tests against it with `T280_ORACLE=/path/to/haproxy`). These two passed
//! before the split too; the three in-process ones failed (one entry, not two).
//!
//! In process: the entries and counters are read from the engine.

use crate::common;

use alcyon_rt::engine::Engine;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

/// A keep-alive backend that answers each request head once `go` is set (at once when it
/// is set from the start), and counts the connections it accepted.
fn backend(go: Arc<AtomicBool>, conns: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            conns.fetch_add(1, Ordering::SeqCst);
            let go = Arc::clone(&go);
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    while let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        got.drain(..at + 4);
                        while !go.load(Ordering::SeqCst) {
                            thread::sleep(Duration::from_millis(2));
                        }
                        if s.write_all(RESPONSE).is_err() {
                            return;
                        }
                    }
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
            });
        }
    });
    addr
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("len");
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// HEADERS, `END_STREAM` and `END_HEADERS`: `GET http://localhost/`, the authority a literal without
/// indexing.
fn request(stream: u32) -> Vec<u8> {
    let mut block = vec![0x82, 0x86, 0x84, 0x01, 9];
    block.extend_from_slice(b"localhost");
    frame(0x1, 0x5, stream, &block)
}

fn preface() -> Vec<u8> {
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(frame(0x4, 0, 0, &[]));
    hello
}

struct Setup {
    engine: Engine,
    fe: SocketAddr,
    go: Arc<AtomicBool>,
    conns: Arc<AtomicUsize>,
}

fn setup(answer_at_once: bool) -> Setup {
    let go = Arc::new(AtomicBool::new(answer_at_once));
    let conns = Arc::new(AtomicUsize::new(0));
    let srv = backend(Arc::clone(&go), Arc::clone(&conns));
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 5s\n  timeout client 5s\n  timeout server 5s\n\
         frontend fe\n  bind {fe} proto h2\n  default_backend be\n\
         backend be\n  server s1 {srv}\n"
    );
    let engine = Engine::new(&alcyon_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
    Setup { engine, fe, go, conns }
}

fn counter(e: &Engine, name: &str, f: impl Fn(&alcyon_rt::engine::ProxyStats) -> u32) -> u32 {
    e.proxies.iter().find(|p| p.name == name).map_or(u32::MAX, |p| f(p.counters()))
}

fn act_conn(e: &Engine) -> u32 {
    counter(e, "fe", |c| c.act_conn.load(Ordering::Relaxed))
}

fn be_streams(e: &Engine) -> u32 {
    counter(e, "be", |c| c.be_streams.load(Ordering::Relaxed))
}

/// The entries with a transaction, and those without.
fn entries(e: &Engine) -> (usize, usize) {
    let with = e.sessions.iter().filter(|(_, s)| s.sess.strm.txn.is_some()).count();
    (with, e.sessions.live() - with)
}

/// Runs the engine, reading what the proxy sends, until `done` holds of it or 3 s pass.
fn drive(s: &mut Setup, c: &mut TcpStream, rx: &mut Vec<u8>, mut done: impl FnMut(&Engine, &[u8]) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        let _ = s.engine.run_once();
        if let Ok(n) = c.read(&mut buf) {
            rx.extend_from_slice(&buf[..n]);
        }
        if done(&s.engine, rx) {
            return true;
        }
    }
    false
}

/// Whether `rx` holds a frame with `END_STREAM` on stream `id` (HEADERS or DATA).
fn ended(rx: &[u8], id: u32) -> bool {
    let mut at = 0;
    while rx.len() >= at + 9 {
        let len = (usize::from(rx[at]) << 16) | (usize::from(rx[at + 1]) << 8) | usize::from(rx[at + 2]);
        let (kind, flags) = (rx[at + 3], rx[at + 4]);
        let sid = u32::from_be_bytes([rx[at + 5], rx[at + 6], rx[at + 7], rx[at + 8]]) & 0x7fff_ffff;
        if sid == id && (kind == 0 || kind == 1) && flags & 1 != 0 {
            return true;
        }
        at += 9 + len;
    }
    false
}

fn connect(s: &Setup) -> TcpStream {
    let mut c = TcpStream::connect(s.fe).expect("connect");
    c.set_nonblocking(true).expect("nonblocking");
    c.write_all(&preface()).expect("preface");
    c
}

#[test]
fn a_stream_is_served_by_an_entry_of_its_own_and_freed_with_its_end() {
    let mut s = setup(false);
    let mut c = connect(&s);
    let mut rx = Vec::new();
    c.write_all(&request(1)).expect("request");
    // The request at the server: the connection's entry and the stream's.
    assert!(drive(&mut s, &mut c, &mut rx, |e, _| entries(e).0 == 1 && be_streams(e) == 1), "the stream never reached its backend");
    assert_eq!(entries(&s.engine), (1, 1), "one entry with the stream's transaction, one for the connection");
    assert_eq!(act_conn(&s.engine), 1, "the connection counts once in act_conn, its stream not");
    assert_eq!(be_streams(&s.engine), 1, "the stream counts once in be_streams");
    s.go.store(true, Ordering::SeqCst);
    assert!(drive(&mut s, &mut c, &mut rx, |e, rx| ended(rx, 1) && e.sessions.live() == 1), "the response came and the stream's entry went: {} live", s.engine.sessions.live());
    assert_eq!(entries(&s.engine), (0, 1), "the connection's entry stays");
    assert_eq!((act_conn(&s.engine), be_streams(&s.engine)), (1, 0), "act_conn, be_streams after the stream");
    // A second stream: the same again, on the server connection the first one kept.
    s.go.store(false, Ordering::SeqCst);
    c.write_all(&request(3)).expect("request");
    assert!(drive(&mut s, &mut c, &mut rx, |e, _| entries(e).0 == 1 && be_streams(e) == 1), "the second stream never reached its backend");
    assert_eq!(entries(&s.engine), (1, 1));
    s.go.store(true, Ordering::SeqCst);
    assert!(drive(&mut s, &mut c, &mut rx, |e, rx| ended(rx, 3) && e.sessions.live() == 1), "the second response, and its entry freed");
    assert_eq!(s.conns.load(Ordering::SeqCst), 1, "the second stream took the server connection the first one kept");
    drop(c);
    assert!(drive_closed(&mut s), "the connection's entry went with the client: {} live", s.engine.sessions.live());
    assert_eq!((act_conn(&s.engine), be_streams(&s.engine)), (0, 0), "act_conn, be_streams after the connection");
}

fn drive_closed(s: &mut Setup) -> bool {
    common::drive_until(&mut s.engine, |e| e.sessions.live() == 0)
}

#[test]
fn a_connection_that_closes_ends_its_stream() {
    let mut s = setup(false);
    let mut c = connect(&s);
    let mut rx = Vec::new();
    c.write_all(&request(1)).expect("request");
    assert!(drive(&mut s, &mut c, &mut rx, |e, _| entries(e).0 == 1 && be_streams(e) == 1), "the stream never reached its backend");
    assert_eq!(entries(&s.engine), (1, 1), "one entry with the stream's transaction, one for the connection");
    c.shutdown(std::net::Shutdown::Write).expect("FIN");
    assert!(drive_closed(&mut s), "the stream and its connection did not end: {:?} entries", entries(&s.engine));
    assert_eq!((act_conn(&s.engine), be_streams(&s.engine)), (0, 0), "each counted out once");
    s.go.store(true, Ordering::SeqCst);
}

#[test]
fn a_reset_stream_frees_its_entry_and_the_connection_serves_the_next() {
    let mut s = setup(false);
    let mut c = connect(&s);
    let mut rx = Vec::new();
    c.write_all(&request(1)).expect("request");
    assert!(drive(&mut s, &mut c, &mut rx, |e, _| entries(e).0 == 1 && be_streams(e) == 1), "the stream never reached its backend");
    assert_eq!(entries(&s.engine), (1, 1), "one entry with the stream's transaction, one for the connection");
    c.write_all(&frame(0x3, 0, 1, &8u32.to_be_bytes())).expect("RST_STREAM CANCEL");
    assert!(drive(&mut s, &mut c, &mut rx, |e, _| e.sessions.live() == 1), "the reset stream's entry stayed: {:?}", entries(&s.engine));
    assert_eq!((act_conn(&s.engine), be_streams(&s.engine)), (1, 0));
    s.go.store(true, Ordering::SeqCst);
    c.write_all(&request(3)).expect("request");
    assert!(drive(&mut s, &mut c, &mut rx, |e, rx| ended(rx, 3) && e.sessions.live() == 1), "the next stream was not served");
}

/// The binary under test, or the oracle with `T280_ORACLE=/path/to/haproxy`.
fn binary() -> String {
    std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

struct Proc {
    child: std::process::Child,
    logs: mpsc::Receiver<String>,
    fe: SocketAddr,
    sentinel: SocketAddr,
    stats: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Drop for Proc {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn start(srv: SocketAddr) -> Proc {
    let dir = tempfile::TempDir::new().expect("dir");
    let stats = dir.path().join("s.sock");
    let cfg = dir.path().join("c.cfg");
    let (fe, sentinel) = (common::reserve_addr(), common::reserve_addr());
    std::fs::write(
        &cfg,
        format!(
            "global\n  log stdout format raw local0\n  stats socket {}\n\
             defaults\n  mode http\n  log global\n  timeout connect 2s\n  timeout client 30s\n  timeout server 30s\n\
             frontend fe\n  bind {fe} proto h2\n  log-format \"%ci %ft %b/%s %ST %B %U %ac/%fc/%bc/%sc/%rc %sq/%bq %tsc %{{+Q}}r\"\n  default_backend be\n\
             frontend s\n  bind {sentinel}\n  option httplog\n  http-request return status 200\n\
             backend be\n  server s1 {srv}\n",
            stats.display()
        ),
    )
    .expect("cfg");
    let mut child = Command::new(binary()).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("spawn");
    let out = child.stdout.take().expect("stdout");
    let (tx, logs) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    assert!(common::wait_listening(sentinel), "never listened");
    Proc { child, logs, fe, sentinel, stats, _dir: dir }
}

/// The lines logged for the frontend `fe`, up to the sentinel's.
fn fe_logs(p: &Proc) -> Vec<String> {
    let mut s = TcpStream::connect(p.sentinel).expect("sentinel");
    s.write_all(b"GET /sentinel HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").unwrap();
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
    let mut lines = Vec::new();
    loop {
        let line = p.logs.recv_timeout(Duration::from_secs(5)).expect("no sentinel log line");
        if line.contains("/sentinel") {
            return lines;
        }
        if line.contains(" fe ") {
            lines.push(line);
        }
    }
}

fn show_sess(p: &Proc) -> String {
    let mut u = std::os::unix::net::UnixStream::connect(&p.stats).expect("stats socket");
    u.write_all(b"show sess\n").unwrap();
    let mut out = String::new();
    let _ = u.read_to_string(&mut out);
    out
}

/// A blocking client: the preface, then reads frames until `END_STREAM` on `id`.
fn blocking_get(c: &mut TcpStream, rx: &mut Vec<u8>, id: u32) {
    c.write_all(&request(id)).expect("request");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 4096];
    while !ended(rx, id) {
        assert!(Instant::now() < deadline, "no response on stream {id}");
        match c.read(&mut buf) {
            Ok(0) => panic!("closed"),
            Ok(n) => rx.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
}

/// `show sess` lists the stream being served once, not the connection beside it.
#[test]
fn show_sess_lists_a_served_stream_once() {
    let go = Arc::new(AtomicBool::new(false));
    let srv = backend(Arc::clone(&go), Arc::new(AtomicUsize::new(0)));
    let p = start(srv);
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    c.write_all(&preface()).unwrap();
    c.write_all(&request(1)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let streams = loop {
        let out = show_sess(&p);
        let streams: Vec<String> = out.lines().filter(|l| l.contains("fe=fe ")).map(str::to_string).collect();
        if streams.iter().any(|l| l.contains("srv=s1")) || Instant::now() > deadline {
            break streams;
        }
        thread::sleep(Duration::from_millis(20));
    };
    go.store(true, Ordering::SeqCst);
    assert_eq!(streams.len(), 1, "one stream at the server, listed once: {streams:#?}");
    assert!(streams[0].contains("be=be srv=s1"), "{}", streams[0]);
}

/// Two streams on one connection log a line each, with the counters as they were when the
/// connection's entry served them itself. Measured on `HAProxy` 3.5-dev8-885761-29:
/// `127.0.0.1 fe be/s1 200 51 62 1/1/0/0/0 0/0 ---- "GET http://localhost/ HTTP/2.0"`,
/// twice (`%bc`, `%sc` count the stream out before its line).
#[test]
fn each_stream_logs_its_line_with_the_connection_counted_once() {
    let go = Arc::new(AtomicBool::new(true));
    let srv = backend(Arc::clone(&go), Arc::new(AtomicUsize::new(0)));
    let p = start(srv);
    let mut c = TcpStream::connect(p.fe).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    c.write_all(&preface()).unwrap();
    let mut rx = Vec::new();
    blocking_get(&mut c, &mut rx, 1);
    blocking_get(&mut c, &mut rx, 3);
    drop(c);
    thread::sleep(Duration::from_millis(100));
    let lines = fe_logs(&p);
    assert_eq!(lines.len(), 2, "{lines:#?}");
    for l in &lines {
        let f: Vec<&str> = l.split(' ').collect();
        assert_eq!(f[..9], ["127.0.0.1", "fe", "be/s1", "200", "51", "62", "1/1/0/0/0", "0/0", "----"], "{lines:#?}");
        assert!(l.ends_with("\"GET http://localhost/ HTTP/2.0\""), "{l}");
    }
}
