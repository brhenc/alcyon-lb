// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Memory an HTTP/2 client can make the proxy hold (T235).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29`, cleartext `proto h2` bind, `nbthread 1`, one
//! HTTP/1 server that accepts and never reads (SO_RCVBUF 4096):
//!
//! ```text
//! POST, then DATA far past the stream window   HAProxy takes 3.7 MB (kernel buffers on
//!   (32 MiB offered within 6 s)                 both sides), RSS +1.7 MB, then stops reading
//!                                               the socket: no error, the client is held
//!                                               by TCP. HAProxy does not police the receive
//!                                               window (mux_h2.c); its stream buffer
//!                                               filling stops the demux (H2_CF_DEM_SFULL).
//!                                               Ibex before T235: all 32 MiB, RSS +31.6 MB.
//! ```
//!
//! A client that does not read is held the same way on the send side: HAProxy stops the
//! demux while its output buffers are full (H2_CF_DEM_MROOM), so the control frames a
//! flood would make it queue are never made. 100 requests held by that server, then
//! HEADERS on new ids over the limit, never reading: HAProxy takes 3 MB, RSS +0.2 MB;
//! Ibex before T235 RST each, RSS +4.4 MB for 6 MB in 4 s (debug build), growing.
//!
//! Not reproduced (no change): a client that raises its windows to 2^31-1 and reads
//! nothing, or reads slowly, of a 200 MB response -- Ibex RSS +0.4 MB, flat.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
    _held: std::sync::Arc<std::sync::Mutex<Vec<TcpStream>>>,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        // The server lets go of its connections, so the sessions end and the soft stop
        // is not held by them for its five seconds.
        if let Ok(mut held) = self._held.lock() {
            held.clear();
        }
        common::stop(&mut self.child);
    }
}

/// A server that accepts and never reads, with a small receive buffer.
fn stalled_server() -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<TcpStream>>>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    rustix::net::sockopt::set_socket_recv_buffer_size(&l, 4096).expect("SO_RCVBUF");
    let addr = l.local_addr().expect("addr");
    let held = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let h = held.clone();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            h.lock().expect("lock").push(c);
        }
    });
    (addr, held)
}

fn start() -> (Ibex, SocketAddr) {
    let (srv, held) = stalled_server();
    let fe = common::reserve_addr();
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 10s\n  timeout server 10s\n  timeout connect 2s\n\
         frontend fe\n  bind {fe} proto h2\n  default_backend be\n\
         backend be\n  server s1 {srv}\n"
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(f.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(fe), "ibex never listened:\n{cfg}");
    (Ibex { child, _cfg: f, _held: held }, fe)
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn lit(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

fn head(method: &str) -> Vec<u8> {
    [(":method", method), (":scheme", "http"), (":authority", "x"), (":path", "/")]
        .iter()
        .flat_map(|(n, v)| lit(n, v))
        .collect()
}

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

fn connect(fe: SocketAddr) -> TcpStream {
    let mut c = TcpStream::connect(fe).expect("connect");
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(frame(4, 0, 0, &[]));
    hello.extend(frame(4, 1, 0, &[]));
    c.write_all(&hello).expect("preface");
    c.set_nonblocking(true).expect("nonblocking");
    c
}

/// Writes `unit` over and over for up to `secs`, until `cap` bytes are taken or the
/// socket stays full for a second, reading and dropping what comes back if `read`.
/// Returns how many bytes the proxy took.
fn offer(c: &mut TcpStream, unit: &[u8], cap: usize, secs: u64, read: bool) -> usize {
    let end = Instant::now() + Duration::from_secs(secs);
    let (mut taken, mut off, mut stuck_since) = (0, 0, None::<Instant>);
    let mut sink = vec![0u8; 65536];
    while taken < cap && Instant::now() < end {
        if read {
            while matches!(c.read(&mut sink), Ok(n) if n > 0) {}
        }
        match c.write(&unit[off..]) {
            Ok(n) => {
                taken += n;
                off = (off + n) % unit.len();
                stuck_since = None;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                let since = *stuck_since.get_or_insert_with(Instant::now);
                if since.elapsed() > Duration::from_secs(1) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    taken
}

/// A client that sends DATA past the window to a server that does not read is held by TCP
/// once the stream's buffer is full, as HAProxy holds it: before T235 Ibex took the 24 MiB.
#[test]
fn data_past_the_window_to_a_stalled_server_is_not_buffered() {
    let (_ibex, fe) = start();
    let mut c = connect(fe);
    c.set_nonblocking(false).expect("blocking");
    c.write_all(&frame(1, END_HEADERS, 1, &head("POST"))).expect("headers");
    c.set_nonblocking(true).expect("nonblocking");
    let data = frame(0, 0, 1, &[b'a'; 16384]);
    let taken = offer(&mut c, &data, 24 << 20, 2, true);
    assert!(taken < 12 << 20, "the proxy took {taken} bytes of DATA for a server that reads nothing");
}

/// Reads frames for up to `secs`: `(type, stream, payload)` and whether the peer closed.
fn frames(c: &mut TcpStream, secs: u64) -> (Vec<(u8, u32, Vec<u8>)>, bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    let (mut raw, mut buf, mut closed) = (Vec::new(), vec![0u8; 65536], false);
    while Instant::now() < end {
        match c.read(&mut buf) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    let (mut out, mut at) = (Vec::new(), 0);
    while raw.len() >= at + 9 {
        let len = (usize::from(raw[at]) << 16) | (usize::from(raw[at + 1]) << 8) | usize::from(raw[at + 2]);
        if raw.len() < at + 9 + len {
            break;
        }
        let sid = u32::from_be_bytes([raw[at + 5] & 0x7f, raw[at + 6], raw[at + 7], raw[at + 8]]);
        out.push((raw[at + 3], sid, raw[at + 9..at + 9 + len].to_vec()));
        at += 9 + len;
    }
    (out, closed)
}

fn goaway(f: &[(u8, u32, Vec<u8>)]) -> Option<(u32, u32)> {
    f.iter().find(|f| f.0 == 7).map(|f| {
        (u32::from_be_bytes([f.2[0] & 0x7f, f.2[1], f.2[2], f.2[3]]), u32::from_be_bytes([f.2[4], f.2[5], f.2[6], f.2[7]]))
    })
}

/// HEADERS on a stream id at or below the highest one seen -- a closed stream, or one never
/// opened -- is a connection error STREAM_CLOSED (RFC 9113 section 5.1.1). HAProxy measured:
/// stream 1 answered then HEADERS on 1 again -> GOAWAY last 1 STREAM_CLOSED (5) and close;
/// HEADERS on 3 then on 1 -> GOAWAY last 3 STREAM_CLOSED. Before T235 Ibex sent a 13-byte
/// RST_STREAM for each and read on: a flood of them was queued for a client that reads none.
#[test]
fn headers_on_a_closed_stream_id_is_goaway_stream_closed() {
    let (_ibex, fe) = start();
    let mut c = connect(fe);
    c.set_nonblocking(false).expect("blocking");
    c.write_all(&frame(1, END_HEADERS | END_STREAM, 3, &head("GET"))).expect("headers 3");
    c.write_all(&frame(1, END_HEADERS | END_STREAM, 1, &head("GET"))).expect("headers 1");
    c.set_nonblocking(true).expect("nonblocking");
    let (f, closed) = frames(&mut c, 1);
    assert_eq!((goaway(&f), closed), (Some((3, 5)), true), "{f:?}");
}

/// A client that reads nothing and makes the proxy answer every frame (here HEADERS over
/// the stream limit, each refused with an RST_STREAM) is held by TCP once the output
/// waiting for it is full, as HAProxy holds it (`H2_CF_DEM_MROOM`): before T235 Ibex took
/// the 24 MiB and queued an RST for each.
#[test]
fn a_client_that_reads_nothing_is_not_queued_replies_without_bound() {
    let (_ibex, fe) = start();
    let mut c = connect(fe);
    // 100 requests the stalled server holds: the stream limit.
    let mut wire = Vec::new();
    for i in 0..100 {
        wire.extend(frame(1, END_HEADERS | END_STREAM, 2 * i + 1, &head("GET")));
    }
    c.set_nonblocking(false).expect("blocking");
    c.write_all(&wire).expect("100 requests");
    rustix::net::sockopt::set_socket_recv_buffer_size(&c, 4096).expect("SO_RCVBUF");
    c.set_nonblocking(true).expect("nonblocking");
    std::thread::sleep(Duration::from_millis(200));
    // Then HEADERS on new ids, all over the limit; an indexed-only block (GET, http, /).
    let mut flood = Vec::new();
    for i in 0..1_000_000u32 {
        flood.extend(frame(1, END_HEADERS | END_STREAM, 1001 + 2 * i, &[0x82, 0x86, 0x84]));
    }
    let before = rss_kib(&_ibex);
    let taken = offer(&mut c, &flood, flood.len(), 3, false);
    // What the kernel holds for the proxy is read and answered meanwhile, or not at all.
    std::thread::sleep(Duration::from_secs(1));
    let grown = rss_kib(&_ibex) - before;
    assert!(grown < 1024, "the proxy grew by {grown} KiB queueing RST_STREAM for a client that reads nothing ({taken} bytes taken)");
}

fn rss_kib(i: &Ibex) -> i64 {
    let status = std::fs::read_to_string(format!("/proc/{}/status", i.child.id())).expect("status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .expect("VmRSS")
}
