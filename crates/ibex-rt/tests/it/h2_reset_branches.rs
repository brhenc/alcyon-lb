// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The endings of an HTTP/2 stream that `h2_no_frames_after_rst.rs` does not reach: a
//! stream reset while it waits in the server's queue, one reset while the proxy is
//! sending a reply of its own, and a client that closes its connection with nothing in
//! flight. Expected values measured on `HAProxy 3.5-dev8-885761-29` (set
//! `H2RST_BIN=/path/to/haproxy` to run this file against it).

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

/// How the `/stall` connection ended at the server: 1 closed, 2 reset, 3 other, 0 not yet.
static STALL_END: AtomicU8 = AtomicU8::new(0);

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// An HTTP/1 server: `/a` is answered 500 ms after its head, anything else at once.
fn server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(8))).ok();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                if got.starts_with(b"GET /stall ") {
                    // The head and 2 of 10 body bytes, then silence until the connection ends.
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab");
                    let end = match c.read(&mut buf) {
                        Ok(_) => 1,
                        Err(e) if e.kind() == ErrorKind::ConnectionReset => 2,
                        Err(_) => 3,
                    };
                    STALL_END.store(end, Ordering::SeqCst);
                    return;
                }
                if got.starts_with(b"GET /a ") {
                    thread::sleep(Duration::from_millis(500));
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = c.read(&mut buf);
            });
        }
    });
    addr
}

fn start(extra_fe: &str, extra_srv: &str) -> (Ibex, SocketAddr, UdpSocket) {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_secs(4))).ok();
    let (fe, srv) = (common::reserve_addr(), server());
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 6s\n  timeout server 4s\n  timeout queue 4s\n\
         frontend fe\n  bind {fe} proto h2\n  log {} local0\n  option httplog\n{extra_fe}  default_backend be\n\
         backend be\n  server s {srv} {extra_srv}\n",
        collector.local_addr().expect("addr")
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let bin = std::env::var("H2RST_BIN").ok().filter(|b| !b.is_empty()).unwrap_or_else(|| env!("CARGO_BIN_EXE_ibex").to_string());
    let child =
        Command::new(bin).arg("-f").arg(f.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("spawn");
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "never listened:\n{cfg}");
    // The probe connection is logged as a request that never came.
    let _ = log_line(&collector);
    (ibex, fe, collector)
}

fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

fn head(method: &str, path: &str) -> Vec<u8> {
    [(":method", method), (":scheme", "http"), (":authority", "x"), (":path", path)]
        .iter()
        .flat_map(|(n, v)| literal(n, v))
        .collect()
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn connect(fe: SocketAddr, settings: &[u8]) -> TcpStream {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(4, 0, 0, settings)).expect("settings");
    s.write_all(&frame(4, 1, 0, &[])).expect("ack");
    s
}

fn log_line(c: &UdpSocket) -> String {
    let mut buf = [0u8; 2048];
    let n = c.recv(&mut buf).expect("a log line");
    let l = String::from_utf8_lossy(&buf[..n]).into_owned();
    l.split_once("]: ").map_or(l.clone(), |(_, b)| b.trim_end().to_string())
}

/// Reads for `wait`, returning the (type, stream) of the frames seen.
fn frames_for(s: &mut TcpStream, wait: Duration) -> Vec<(u8, u32)> {
    let (mut out, mut buf, mut tmp) = (Vec::new(), Vec::new(), [0u8; 4096]);
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            out.push((buf[3], u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]])));
            buf.drain(..9 + len);
        }
    }
    out
}

#[test]
fn reset_stream_leaves_the_queue() {
    let (_ibex, fe, log) = start("", "maxconn 1");
    let mut a = connect(fe, &[]);
    a.write_all(&frame(1, 5, 1, &head("GET", "/a"))).expect("stream 1, holds the server");
    thread::sleep(Duration::from_millis(100));
    let mut b = connect(fe, &[]);
    b.write_all(&frame(1, 5, 1, &head("GET", "/b"))).expect("queued");
    thread::sleep(Duration::from_millis(100));
    b.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst_stream cancel");
    // HAProxy: the queued request is logged at once, `-1 0 - - CQ--`, Tw 100 ms.
    let line = log_line(&log);
    assert!(line.contains("be/<NOSRV> 0/1") && line.contains("/-1/-1/1") && line.contains(" -1 0 - - CQ-- "), "{line}");
    // The request in front of it is answered all the same.
    let frames = frames_for(&mut a, Duration::from_millis(800));
    assert!(frames.contains(&(1, 1)) && frames.contains(&(0, 1)), "stream 1 of the first connection: {frames:?}");
    let line = log_line(&log);
    assert!(line.contains(" 200 51 - - ---- ") && line.contains("/a HTTP/2.0"), "{line}");
}

#[test]
fn reset_stream_during_a_reply_of_the_proxy() {
    let mut body = NamedTempFile::new().expect("tmp");
    body.write_all(&[b'x'; 10_000]).expect("write body");
    let path = body.path().display().to_string();
    let (_ibex, fe, log) =
        start(&format!("  http-request return status 200 content-type text/plain file {path}\n"), "");
    // A window of 0 for the streams: the reply cannot go out.
    let mut s = connect(fe, &[0, 4, 0, 0, 0, 0]);
    s.write_all(&frame(1, 5, 1, &head("GET", "/b"))).expect("stream 1");
    thread::sleep(Duration::from_millis(200));
    s.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst_stream cancel");
    // The reply cannot go out (window 0), so the reset ends it: nothing is sent on the stream.
    let frames = frames_for(&mut s, Duration::from_millis(500));
    assert!(!frames.iter().any(|f| f.0 == 0 && f.1 == 1), "no body on the reset stream: {frames:?}");
    // HAProxy: the reply keeps its own status and ending (`LR--`).
    let line = log_line(&log);
    assert!(line.contains(" 200 0 - - LR-- ") && line.contains("fe/<NOSRV>"), "{line}");
}

#[test]
fn client_fin_with_nothing_in_flight() {
    let (_ibex, fe, log) = start("", "");
    let mut s = connect(fe, &[]);
    s.write_all(&frame(1, 5, 1, &head("GET", "/b"))).expect("stream 1");
    let frames = frames_for(&mut s, Duration::from_millis(300));
    assert!(frames.contains(&(0, 1)), "the response arrived: {frames:?}");
    s.shutdown(Shutdown::Write).expect("fin");
    // Nothing is in flight: the FIN changes nothing, and the transaction was logged once.
    let frames = frames_for(&mut s, Duration::from_millis(500));
    assert!(!frames.iter().any(|f| f.1 == 1), "nothing more on stream 1: {frames:?}");
    let line = log_line(&log);
    assert!(line.contains(" 200 51 - - ---- ") && line.contains("/b HTTP/2.0"), "{line}");
}

#[test]
fn client_fin_while_the_request_is_still_coming() {
    let (_ibex, fe, log) = start("", "");
    let mut s = connect(fe, &[]);
    s.write_all(&frame(1, 4, 1, &head("POST", "/b"))).expect("head without end of stream");
    thread::sleep(Duration::from_millis(200));
    s.shutdown(Shutdown::Write).expect("fin");
    // HAProxy (3.5-dev8) answers it all the same, a WINDOW_UPDATE first and `CL--` in the log;
    // Ibex logs `----` for it (not asserted here).
    let frames = frames_for(&mut s, Duration::from_millis(800));
    assert!(frames.contains(&(1, 1)) && frames.contains(&(0, 1)), "stream 1 is answered: {frames:?}");
    let line = log_line(&log);
    assert!(line.contains(" 200 51 - - ") && line.contains("POST http://x/b"), "{line}");
}

#[test]
fn reset_stream_during_the_response_body() {
    let (_ibex, fe, log) = start("", "");
    let mut s = connect(fe, &[]);
    s.write_all(&frame(1, 5, 1, &head("GET", "/stall"))).expect("stream 1");
    // The head and 2 bytes arrive, the server then stalls: the response is under way.
    let frames = frames_for(&mut s, Duration::from_millis(400));
    assert!(frames.contains(&(1, 1)) && frames.contains(&(0, 1)), "head and part of the body: {frames:?}");
    s.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst_stream cancel");
    // HAProxy: `200 52 - - CD--`; the server connection is reset at once.
    let line = log_line(&log);
    assert!(line.contains(" 200 52 - - CD-- ") && line.contains("/stall HTTP/2.0"), "{line}");
    let deadline = Instant::now() + Duration::from_secs(2);
    while STALL_END.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert_ne!(STALL_END.load(Ordering::SeqCst), 0, "the server connection was let go");
    // The next stream of the connection is answered at once.
    s.write_all(&frame(1, 5, 3, &head("GET", "/b"))).expect("stream 3");
    let frames = frames_for(&mut s, Duration::from_millis(500));
    assert!(frames.contains(&(0, 3)), "stream 3 answered: {frames:?}");
}
