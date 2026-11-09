// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A client that leaves while nothing can move costs no CPU, and what it held is let go
//! when it leaves, not two `timeout client` later (T269, from the battery's `h2_window0`).
//!
//! * An HTTP/2 client that never opens its window and then sends its FIN: `HAProxy`
//!   3.5-dev8 ends the stream at once (`CD--`, measured with `SETTINGS_INITIAL_WINDOW_SIZE`
//!   0 and a 10 MB body: `Tt` 803 ms for a FIN 800 ms in), freeing the server connection.
//!   Alcyon kept the stream until `timeout client`, then sent a GOAWAY and waited a second
//!   `timeout client`, a core spinning all the while.
//! * A client that half-closed (`no option abortonclose`: the request goes on) and is then
//!   reset while the server thinks: nothing is polled on its socket, and `HAProxy` spends
//!   nothing (0 ticks in 2 s, measured). Alcyon was woken by the reset's level-triggered
//!   `EPOLLHUP` on every poll, a core for as long as the server took.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The process, and its configuration file, kept until the process is stopped.
struct Proxy(Child, #[allow(dead_code)] tempfile::NamedTempFile);

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

impl Proxy {
    /// CPU time (user + system, clock ticks) the proxy has used so far.
    fn cpu_ticks(&self) -> u64 {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.0.id())).expect("read /proc stat");
        let rest = &stat[stat.rfind(')').expect("comm") + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        f[11].parse::<u64>().expect("utime") + f[12].parse::<u64>().expect("stime")
    }
}

/// Starts alcyon, one thread, `timeout client 10s`, one frontend (`fe_extra` lines added)
/// in front of `backend`.
fn start(bind_extra: &str, fe_extra: &str, backend: SocketAddr) -> (Proxy, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(
        cfg.path(),
        format!(
            "global\n\tnbthread 1\n\
             defaults\n\tmode http\n\ttimeout connect 2s\n\ttimeout client 10s\n\ttimeout server 30s\n\n\
             frontend fe\n\tbind {fe}{bind_extra}\n{fe_extra}\tdefault_backend be\n\n\
             backend be\n{fe_extra}\tserver s1 {backend}\n"
        ),
    )
    .expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon"))
        .arg("-f")
        .arg(cfg.path())
        .arg("-db")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    let p = Proxy(child, cfg);
    assert!(common::wait_listening(fe), "alcyon never listened on {fe}");
    (p, fe)
}

/// A server that reads one request head, hands the connection to `respond`, and reports
/// on `done` when `respond` returns.
fn backend(respond: fn(&mut TcpStream)) -> (SocketAddr, mpsc::Receiver<Instant>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(30))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                respond(&mut c);
                let _ = tx.send(Instant::now());
            });
        }
    });
    (addr, rx)
}

/// A 64 MB body, written until the proxy stops taking it and then until the proxy lets
/// the connection go (the write fails).
fn big_body(c: &mut TcpStream) {
    c.set_write_timeout(Some(Duration::from_secs(30))).ok();
    if c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 67108864\r\n\r\n").is_err() {
        return;
    }
    let chunk = vec![b'y'; 65536];
    for _ in 0..1024 {
        if c.write_all(&chunk).is_err() {
            return;
        }
    }
}

/// Never answers; returns when the proxy closes the connection.
fn no_answer(c: &mut TcpStream) {
    let mut tmp = [0u8; 64];
    while matches!(c.read(&mut tmp), Ok(n) if n > 0) {}
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame fits");
    let mut v = len.to_be_bytes()[1..].to_vec();
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Reads until `:status 200` HEADERS on stream 1 came, or `wait` passed.
fn saw_status_200(s: &mut TcpStream, wait: Duration) -> bool {
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut tmp = vec![0u8; 65536];
    while start.elapsed() < wait {
        s.set_read_timeout(Some(Duration::from_millis(20))).ok();
        match s.read(&mut tmp) {
            Ok(0) => return false,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => return false,
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (t, sid) = (buf[3], u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff);
            if sid == 1 && t == 0x01 && buf.get(9) == Some(&0x88) {
                return true;
            }
            buf.drain(..9 + len);
        }
    }
    false
}

/// Reads until EOF or an error; how long that took, or `None` past `limit`.
fn closed_within(s: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut tmp = vec![0u8; 65536];
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    while start.elapsed() < limit {
        match s.read(&mut tmp) {
            Ok(0) => return Some(start.elapsed()),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => return Some(start.elapsed()),
        }
    }
    None
}

/// The battery's `h2_window0` attacker, one stream of it: window 0, a large body
/// waiting at the server, and then the client's FIN.
#[test]
fn an_h2_client_that_leaves_with_its_window_at_0_is_let_go_at_once() {
    let (be, released) = backend(big_body);
    let (px, fe) = start(" proto h2", "", be);
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    // SETTINGS_INITIAL_WINDOW_SIZE 0
    s.write_all(&frame(0x04, 0, 0, &[0, 4, 0, 0, 0, 0])).expect("settings");
    // GET / on localhost, END_STREAM | END_HEADERS, static-table HPACK only.
    let mut get = vec![0x82, 0x86, 0x84, 0x01, 9];
    get.extend_from_slice(b"localhost");
    s.write_all(&frame(0x01, 0x05, 1, &get)).expect("headers");
    assert!(saw_status_200(&mut s, Duration::from_secs(2)), "no :status 200 before the stall");
    // Let the server fill what the proxy buffers.
    std::thread::sleep(Duration::from_millis(300));

    s.shutdown(std::net::Shutdown::Write).expect("FIN");
    let fin = Instant::now();
    let before = px.cpu_ticks();
    let closed = closed_within(&mut s, Duration::from_secs(3));
    let ticks = px.cpu_ticks() - before;
    // HAProxy ends the stream as the FIN arrives (`CD--`, `Tt` = the FIN's time); Alcyon
    // waited 2 x `timeout client` (20 s here) before it closed anything.
    assert!(closed.is_some(), "the client connection was still open 3 s after its FIN");
    let srv = released.recv_timeout(Duration::from_secs(1)).expect("the server connection was never let go");
    assert!(srv.duration_since(fin) < Duration::from_secs(2), "the server connection was let go {:?} after the FIN", srv.duration_since(fin));
    assert!(ticks < 40, "alcyon used {ticks} ticks after the client's FIN");
}

/// A client that half-closed after its request, under `no option abortonclose` (the
/// request goes on), then reset while the server has not answered: nothing is to be
/// read or written on its socket, and so nothing done until the server answers.
#[test]
fn a_client_reset_while_its_socket_is_not_polled_costs_no_cpu() {
    let (be, _done) = backend(no_answer);
    let (px, fe) = start("", "\tno option abortonclose\n", be);
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    std::thread::sleep(Duration::from_millis(300));
    s.shutdown(std::net::Shutdown::Write).expect("FIN");
    std::thread::sleep(Duration::from_millis(300));
    // SO_LINGER 0: the close is a reset.
    rustix::net::sockopt::set_socket_linger(&s, Some(Duration::ZERO)).expect("linger");
    drop(s);
    std::thread::sleep(Duration::from_millis(100));
    let before = px.cpu_ticks();
    std::thread::sleep(Duration::from_secs(2));
    let ticks = px.cpu_ticks() - before;
    // HAProxy 3.5-dev8: 0 ticks in 2 s. Alcyon was at ~200 (a whole core).
    assert!(ticks < 40, "alcyon used {ticks} ticks in 2 s with nothing to read or write");
}
