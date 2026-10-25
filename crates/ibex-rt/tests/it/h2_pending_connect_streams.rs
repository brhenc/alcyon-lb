// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An HTTP/2 connection whose streams wait for a backend connect holds a bounded number of
//! them, not one pending connect per stream (T322, red team MY-10).
//!
//! The shape (`tools/battery/repro/h2rxbudget.py`): per connection one POST of 88 x 16 KB
//! DATA, then 99 POSTs of one 16 KB frame each, the client obeying the windows, to a backend
//! whose accept queue is full so every connect hangs. `HAProxy` stores DATA in the
//! connection's shared receive buffers (`h2s_get_rxbuf`, one per allowed stream plus one);
//! a stream that cannot get one blocks the demux (`H2_CF_DEM_RXBUF`) and the connection is
//! no longer read, so the HEADERS behind it -- and their connects -- wait in the socket.
//! Measured on 3.5-dev8-885761-29 (`nbthread` 1 and 2, `/proc/<pid>/fd`, `show sess`):
//!
//! | client connections | streams on the backend | proxy fds over idle | new h1 client |
//! |--------------------|------------------------|---------------------|---------------|
//! | 1                  | 7                      | +8                  | 200           |
//! | 3 (`maxconn 60`)   | 21                     | +24                 | 200           |
//! | 10                 | 70                     | +80                 | 200           |
//!
//! Ibex demuxed every HEADERS and every stream's first DATA frame whatever the connection
//! held: 100 streams and 100 pending connects per connection (+101 fds for one, +1010 for
//! ten); with `maxconn 60` three such clients took it to its fd ceiling, so streams were
//! reset, a client connection closed and a new client was refused. Once the backend
//! accepts, every held stream is served on both.
//!
//! `T322_ORACLE=/path/to/haproxy` runs this on `HAProxy`.

use crate::common;

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FRAME: usize = 16384;
const FRAME_W: i64 = 16384;
const BIG_FRAMES: usize = 88;
const SMALL_STREAMS: u32 = 99;
const CONNS: usize = 3;

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// `POST /slow` on `localhost` with a `content-length` (literal, not indexed).
fn hpack_post(len: usize) -> Vec<u8> {
    let mut v = vec![0x83, 0x86, 0x04, 5];
    v.extend_from_slice(b"/slow");
    v.extend_from_slice(&[0x01, 9]);
    v.extend_from_slice(b"localhost");
    let cl = len.to_string();
    v.push(0x0f); // literal without indexing, indexed name 28 (content-length): 15 + 13
    v.push(13);
    v.push(u8::try_from(cl.len()).expect("short"));
    v.extend_from_slice(cl.as_bytes());
    v
}

/// A listener whose accept queue is full: a connect to it neither completes nor fails.
fn full_listener() -> (rustix::fd::OwnedFd, SocketAddr, TcpStream) {
    use rustix::net::{bind, listen, socket_with, AddressFamily, SocketFlags, SocketType};
    // CLOEXEC: every ibex another test spawns would inherit a listener that stays open for the
    // whole run, and its highest descriptor number moves `maxsock_limit`'s ceiling (T355).
    let fd = socket_with(AddressFamily::INET, SocketType::STREAM, SocketFlags::CLOEXEC, None).expect("socket");
    // A reserved port may still have connections of an earlier run in TIME_WAIT.
    rustix::net::sockopt::set_socket_reuseaddr(&fd, true).expect("SO_REUSEADDR");
    bind(&fd, &common::reserve_addr()).expect("bind");
    listen(&fd, 0).expect("listen");
    let addr = match rustix::net::getsockname(&fd).expect("getsockname") {
        rustix::net::SocketAddrAny::V4(a) => SocketAddr::V4(a),
        other => panic!("{other:?}"),
    };
    let filler = TcpStream::connect(addr).expect("fill the accept queue");
    (fd, addr, filler)
}

/// Reads a request head and its `content-length` body, answers 200 and closes.
fn serve_one(mut c: TcpStream) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
    let mut got = Vec::new();
    let mut tmp = vec![0u8; 65536];
    let (head_end, cl) = loop {
        if let Some(p) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..p]).to_ascii_lowercase();
            let cl = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (p + 4, cl);
        }
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => got.extend_from_slice(&tmp[..n]),
        }
    };
    let mut body = got.len() - head_end;
    while body < cl {
        match c.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => body += n,
        }
    }
    let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
}

/// The default backend: answers every request 200.
fn ok_backend() -> u16 {
    let addr = common::reserve_addr();
    let l = TcpListener::bind(addr).expect("bind ok backend");
    thread::spawn(move || {
        for c in l.incoming().map_while(Result::ok) {
            thread::spawn(move || serve_one(c));
        }
    });
    addr.port()
}

/// One attacker connection: the streams in order, each sent as the windows allow; a stream
/// the windows stall for half a second is left for later, as the red team's client does.
struct Client {
    s: TcpStream,
    out: Vec<u8>,
    inb: Vec<u8>,
    conn_win: i64,
    init_win: i64,
    win: HashMap<u32, i64>,
    /// (stream, frames in its body, frames sent, HEADERS sent)
    plan: Vec<(u32, usize, usize, bool)>,
    next: usize,
    stalled_since: Option<Instant>,
    answered: HashMap<u32, u8>,
    reset: HashMap<u32, u32>,
    closed: bool,
}

impl Client {
    fn new(port: u16) -> Self {
        let s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_nonblocking(true).expect("nonblocking");
        let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        out.extend(frame(4, 0, 0, &[0, 4, 1, 0, 0, 0])); // INITIAL_WINDOW_SIZE 16 MB
        let mut plan = vec![(1, BIG_FRAMES, 0, false)];
        plan.extend((0..SMALL_STREAMS).map(|k| (3 + 2 * k, 1, 0, false)));
        Self {
            s,
            out,
            inb: Vec::new(),
            conn_win: 65535,
            init_win: 65535,
            win: HashMap::new(),
            plan,
            next: 0,
            stalled_since: None,
            answered: HashMap::new(),
            reset: HashMap::new(),
            closed: false,
        }
    }

    fn io(&mut self) {
        while !self.out.is_empty() && !self.closed {
            match self.s.write(&self.out) {
                Ok(n) => {
                    self.out.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => self.closed = true,
            }
        }
        let mut tmp = vec![0u8; 65536];
        while !self.closed {
            match self.s.read(&mut tmp) {
                Ok(0) => self.closed = true,
                Ok(n) => self.inb.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => self.closed = true,
            }
        }
        while self.inb.len() >= 9 {
            let len = (usize::from(self.inb[0]) << 16) | (usize::from(self.inb[1]) << 8) | usize::from(self.inb[2]);
            if self.inb.len() < 9 + len {
                break;
            }
            let (t, fl) = (self.inb[3], self.inb[4]);
            let sid = u32::from_be_bytes([self.inb[5], self.inb[6], self.inb[7], self.inb[8]]) & 0x7fff_ffff;
            let p: Vec<u8> = self.inb[9..9 + len].to_vec();
            self.inb.drain(..9 + len);
            match t {
                4 if fl & 1 == 0 => {
                    for kv in p.chunks_exact(6) {
                        if u16::from_be_bytes([kv[0], kv[1]]) == 4 {
                            self.init_win = i64::from(u32::from_be_bytes([kv[2], kv[3], kv[4], kv[5]]));
                        }
                    }
                    self.out.extend(frame(4, 1, 0, &[]));
                }
                8 if p.len() >= 4 => {
                    let inc = i64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
                    if sid == 0 {
                        self.conn_win += inc;
                    } else {
                        *self.win.entry(sid).or_insert(self.init_win) += inc;
                    }
                }
                1 => {
                    // The first byte of the block: 0x88 is `:status 200` from the static table.
                    self.answered.entry(sid).or_insert(p.first().copied().unwrap_or(0));
                }
                3 if p.len() >= 4 => {
                    self.reset.insert(sid, u32::from_be_bytes([p[0], p[1], p[2], p[3]]));
                }
                6 if fl & 1 == 0 => self.out.extend(frame(6, 1, 0, &p)),
                7 => self.closed = true,
                _ => {}
            }
        }
    }

    /// Queues what the windows allow, while the socket takes it (TCP backpressure holds the rest).
    fn send_some(&mut self, wait: Duration) {
        let mut idx = self.next;
        let mut looked = 0;
        while looked < self.plan.len() && self.out.len() < 4 * FRAME && !self.closed {
            if idx >= self.plan.len() {
                idx = 0;
            }
            let (sid, total, sent, hdrs) = self.plan[idx];
            if sent == total {
                idx += 1;
                looked += 1;
                continue;
            }
            if self.reset.contains_key(&sid) {
                self.plan[idx].2 = total;
                continue;
            }
            if !hdrs {
                self.out.extend(frame(1, 0x4, sid, &hpack_post(total * FRAME)));
                self.plan[idx].3 = true;
            }
            let w = *self.win.entry(sid).or_insert(self.init_win);
            if self.conn_win >= FRAME_W && w >= FRAME_W {
                let last = sent + 1 == total;
                self.out.extend(frame(0, u8::from(last), sid, &vec![b'x'; FRAME]));
                self.conn_win -= FRAME_W;
                *self.win.get_mut(&sid).expect("window") -= FRAME_W;
                self.plan[idx].2 += 1;
                self.stalled_since = None;
                continue;
            }
            // Stalled by a window: wait `wait` before going on to the next stream.
            let since = *self.stalled_since.get_or_insert_with(Instant::now);
            if since.elapsed() < wait {
                break;
            }
            self.stalled_since = None;
            idx += 1;
            looked += 1;
        }
        self.next = idx;
    }

    fn done(&self) -> bool {
        self.closed || self.plan.iter().all(|&(sid, ..)| self.answered.contains_key(&sid) || self.reset.contains_key(&sid))
    }
}

fn fds(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, Iterator::count)
}

/// A new HTTP/1.1 client: the status line it is answered with within 20 s (a loaded host
/// takes seconds to serve a client while 100 streams per connection are held), or what happened.
fn new_client(port: u16) -> String {
    let Ok(mut c) = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(10)) else {
        return "connect failed".into();
    };
    let _ = c.set_read_timeout(Some(Duration::from_secs(20)));
    if c.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n").is_err() {
        return "write failed".into();
    }
    let mut got = Vec::new();
    let mut tmp = [0u8; 4096];
    while !got.windows(2).any(|w| w == b"\r\n") {
        match c.read(&mut tmp) {
            Ok(0) => return format!("closed after {} bytes", got.len()),
            Ok(n) => got.extend_from_slice(&tmp[..n]),
            Err(e) => return format!("{:?}", e.kind()),
        }
    }
    String::from_utf8_lossy(&got).lines().next().unwrap_or("").to_string()
}

struct Proxy {
    child: Child,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// The proxy, with the h2 bind, the h1 bind, `/slow` to `hung` and the rest to a backend
/// that answers.
fn start(hung: SocketAddr, defaults_extra: &str) -> (Proxy, u32, u16, u16) {
    let ok = ok_backend();
    let (h2, h1) = (common::reserve_port(), common::reserve_port());
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\tmaxconn 60\n\n\
             defaults\n\tmode http\n\ttimeout client 60s\n\ttimeout server 60s\n\t{defaults_extra}\n\n\
             frontend fe\n\tbind 127.0.0.1:{h2} proto h2\n\tbind 127.0.0.1:{h1}\n\
             \tuse_backend slow if {{ path_beg /slow }}\n\tdefault_backend ok\n\n\
             backend slow\n\tserver s1 {hung}\n\n\
             backend ok\n\tserver s2 127.0.0.1:{ok}\n"
        ),
    )
    .expect("write config");
    let bin = std::env::var("T322_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let pid = child.id();
    let proxy = Proxy { child, _dir: dir };
    assert!(common::wait_listening(SocketAddr::from(([127, 0, 0, 1], h1))), "the proxy never listened");
    thread::sleep(Duration::from_millis(200));
    (proxy, pid, h2, h1)
}

#[test]
fn streams_waiting_for_a_connect_hold_the_demux_not_an_fd_each() {
    let (hung, hung_addr, filler) = full_listener();
    let (proxy, pid, h2, h1) = start(hung_addr, "timeout connect 30s");
    let _proxy = proxy;
    let idle = fds(pid);

    // Build: the clients send all they can for four seconds while every connect hangs.
    let mut clients: Vec<Client> = (0..CONNS).map(|_| Client::new(h2)).collect();
    let end = Instant::now() + Duration::from_secs(4);
    while Instant::now() < end {
        for c in &mut clients {
            c.io();
            c.send_some(Duration::from_millis(500));
            c.io();
        }
        thread::sleep(Duration::from_millis(2));
    }
    let held = fds(pid).saturating_sub(idle);
    let reset: usize = clients.iter().map(|c| c.reset.len()).sum();
    let closed = clients.iter().filter(|c| c.closed).count();
    let fresh = new_client(h1);
    eprintln!("held: +{held} fds over idle {idle}; streams reset {reset}; client connections closed {closed}; new client: {fresh}");

    // Release: the backend accepts and answers every request; every held stream completes.
    drop(filler);
    rustix::net::listen(&hung, 1024).expect("relisten");
    let l = TcpListener::from(hung);
    thread::spawn(move || {
        for c in l.incoming().map_while(Result::ok) {
            thread::spawn(move || serve_one(c));
        }
    });
    let end = Instant::now() + Duration::from_secs(120);
    while Instant::now() < end && !clients.iter().all(Client::done) {
        for c in &mut clients {
            c.io();
            c.send_some(Duration::ZERO);
            c.io();
        }
        thread::sleep(Duration::from_millis(2));
    }
    let answered: usize = clients.iter().map(|c| c.answered.values().filter(|&&b| b == 0x88).count()).sum();
    let reset_after: usize = clients.iter().map(|c| c.reset.len()).sum();
    eprintln!("released: {answered} of {} streams answered 200, {reset_after} reset", CONNS * 100);
    let mut statuses = std::collections::BTreeMap::new();
    for b in clients.iter().flat_map(|c| c.answered.values()) {
        *statuses.entry(*b).or_insert(0usize) += 1;
    }
    let unfinished = clients.iter().filter(|c| !c.done()).count();
    eprintln!("released: first header bytes {statuses:x?}; connections not done {unfinished}");

    // HAProxy: +24 (one client fd and seven server fds per connection).
    assert!(held <= CONNS * 16, "+{held} fds for {CONNS} connections: a pending connect per stream");
    assert_eq!((reset, closed), (0, 0), "no stream is reset and no client connection closed while held");
    assert!(fresh.starts_with("HTTP/1.1 200"), "a new client is served while the streams are held: {fresh}");
    assert_eq!(answered, CONNS * 100, "every held stream is answered once the backend accepts");
}

/// The streams held behind those whose connect fails go on: each failed stream ends and
/// gives its receive buffers back, and the demux takes the next ones, so all 100 end and the
/// connection stays up. `HAProxy` (`timeout connect 300ms`, `retries 0`) resets all 100
/// (`RST_STREAM` 5 and 7, the body not fully received); Ibex answers them 503. That
/// difference is not this test's subject.
#[test]
fn streams_whose_connect_fails_give_their_buffers_back() {
    let (_hung, hung_addr, _filler) = full_listener();
    let (proxy, _pid, h2, _) = start(hung_addr, "timeout connect 300ms\n\tretries 0");
    let _proxy = proxy;
    let mut c = Client::new(h2);
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end && !c.done() {
        c.io();
        c.send_some(Duration::from_millis(500));
        c.io();
        thread::sleep(Duration::from_millis(2));
    }
    let mut codes: Vec<u32> = c.reset.values().copied().collect();
    codes.sort_unstable();
    codes.dedup();
    eprintln!("answered {:?}, reset {} {codes:?}, closed {}", c.answered.values().collect::<std::collections::BTreeSet<_>>(), c.reset.len(), c.closed);
    assert!(!c.closed, "the connection stays up");
    assert_eq!(c.answered.len() + c.reset.len(), 100, "every stream ends, answered or reset");
}

/// The fds and resets of `CONNS` attacker connections held `secs` seconds over a backend that
/// never accepts, after `extra` lines of `defaults`: (peak fds over idle, streams reset,
/// connections closed).
fn hold(extra: &str, secs: u64) -> (usize, usize, usize) {
    let (_hung, hung_addr, _filler) = full_listener();
    let (proxy, pid, h2, _) = start(hung_addr, extra);
    let _proxy = proxy;
    let idle = fds(pid);
    let mut clients: Vec<Client> = (0..CONNS).map(|_| Client::new(h2)).collect();
    let end = Instant::now() + Duration::from_secs(secs);
    let mut peak = 0;
    while Instant::now() < end {
        for c in &mut clients {
            c.io();
            c.send_some(Duration::from_millis(500));
            c.io();
        }
        peak = peak.max(fds(pid).saturating_sub(idle));
        thread::sleep(Duration::from_millis(2));
    }
    let reset: usize = clients.iter().map(|c| c.reset.len()).sum();
    let closed = clients.iter().filter(|c| c.closed).count();
    eprintln!("peak +{peak} fds over idle {idle}; streams reset {reset}; connections closed {closed}");
    (peak, reset, closed)
}

/// `timeout connect` expiring on a stream that waits for its connect is a retry, as
/// `back_handle_st_cer` does it (`retries` 3 by default: four attempts of `timeout connect`,
/// then 503 `sC`), so the held streams keep the demux and the fds stay flat until the last
/// attempt is spent (T379). Measured on HAProxy 3.5-dev8 (`timeout connect 2s`, 7 s): +24.
#[test]
fn a_connect_timeout_retries_and_does_not_free_the_demux() {
    let (peak, reset, closed) = hold("timeout connect 2s", 7);
    assert!(peak <= CONNS * 16, "+{peak} fds for {CONNS} connections: connects keep opening after timeout connect");
    assert_eq!((reset, closed), (0, 0));
}

/// A stream whose request data fills its buffer and waits for the server (here: for the connect)
/// owes the client nothing: `sc_rcv_may_expire` is false while the channel has no room
/// (`SC_FL_NEED_ROOM`), so `timeout client` does not end it, the demux stays held, and the
/// connects stay at HAProxy's seven a connection (T379, VV-16: Ibex timed the streams out at
/// `timeout client`, the demux went on and each connection opened ~50 connects). Measured on
/// HAProxy 3.5-dev8 (`timeout client 3s`, `timeout connect 60s`, 8 s): +24 fds, nothing reset.
#[test]
fn a_full_request_buffer_waiting_for_the_server_does_not_time_out_at_timeout_client() {
    let (peak, reset, closed) = hold("timeout connect 60s\n\ttimeout client 3s", 8);
    assert!(peak <= CONNS * 16, "+{peak} fds for {CONNS} connections: held streams timed out at timeout client");
    assert_eq!((reset, closed), (0, 0), "no stream is reset and no connection closed");
}
