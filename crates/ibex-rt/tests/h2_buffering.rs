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
//! flood would make it queue are never made.

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
