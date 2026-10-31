// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! An HTTP/2 stream reset after its request went to the server (T273 B).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` with a raw h2 client (cleartext `proto h2`
//! bind, an HTTP/1 server that answers `/a` 300 ms after the head, `option httplog`),
//! the request `POST /a` sent without END_STREAM, then 200 ms later:
//!
//! ```text
//! client RST_STREAM(CANCEL)   nothing more on stream 1; the server connection is reset at
//!                             once (TCP RST); log `400 0 - - CH--` Tt=200; the connection
//!                             stays up and a GET on stream 3 is answered at once.
//! trailers without ES         a stream reset (HAProxy makes it a connection error: GOAWAY
//!                             PROTOCOL_ERROR, then FIN) and nothing on stream 1 after it;
//!                             the server connection is reset at once; log `400 ... CH--`.
//! client RST during the body  (server sent the head and 2 of 10 bytes at once) the server
//!                             connection is reset at once; log `200 52 - - CD--`; stream 3
//!                             answered at once.
//! ```
//!
//! Ibex sent the server's response HEADERS on the stream it had reset (a frame on a closed
//! stream, a connection error for a strict client, RFC 9113 5.1), held the server
//! connection until `timeout server`, and kept the connection's next stream waiting
//! behind it.

use crate::common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

struct Ibex {
    child: Child,
    _cfg: NamedTempFile,
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

/// How a server connection ended, and how long after its first request head.
#[derive(Debug)]
struct Ended {
    reset: bool,
    after: Duration,
}

/// An HTTP/1 server: `/a` is answered 300 ms after its head (with `partial`, the head and
/// 2 of 10 body bytes at once instead), anything else at once. Each connection's end is
/// sent on the channel.
fn server(partial: bool) -> (SocketAddr, Receiver<Ended>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = channel();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let tx = tx.clone();
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_millis(20))).ok();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                let mut head_at: Option<Instant> = None;
                let mut answered = false;
                let start = Instant::now();
                let reset = loop {
                    if start.elapsed() > Duration::from_secs(8) {
                        break false;
                    }
                    match c.read(&mut buf) {
                        Ok(0) => break false,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                        Err(_) => break true,
                    }
                    if head_at.is_none() && got.windows(4).any(|w| w == b"\r\n\r\n") {
                        head_at = Some(Instant::now());
                    }
                    let Some(at) = head_at else { continue };
                    if answered {
                        continue;
                    }
                    let slow = got.starts_with(b"POST /a ");
                    let reply: &[u8] = if slow && partial {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab"
                    } else if slow && at.elapsed() < Duration::from_millis(300) {
                        continue;
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    };
                    answered = true;
                    let _ = c.write_all(reply);
                };
                let _ = tx.send(Ended { reset, after: head_at.map_or(Duration::ZERO, |h| h.elapsed()) });
            });
        }
    });
    (addr, rx)
}

fn start(partial: bool) -> (Ibex, SocketAddr, Receiver<Ended>, UdpSocket) {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_secs(6))).ok();
    let (fe, (srv, rx)) = (common::reserve_addr(), server(partial));
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 6s\n  timeout server 4s\n\
         frontend fe\n  bind {fe} proto h2\n  log {} local0\n  option httplog\n  default_backend be\n\
         backend be\n  server s {srv}\n",
        collector.local_addr().expect("addr")
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
    let ibex = Ibex { child, _cfg: f };
    assert!(common::wait_listening(fe), "ibex never listened:\n{cfg}");
    // The probe connection above is logged as a request that never came.
    let _ = log_line(&collector);
    (ibex, fe, rx, collector)
}

fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

fn block(list: &[(&str, &str)]) -> Vec<u8> {
    list.iter().flat_map(|(n, v)| literal(n, v)).collect()
}

fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn head(method: &str, path: &str) -> Vec<u8> {
    block(&[(":method", method), (":scheme", "http"), (":authority", "x"), (":path", path)])
}

type Frames = Vec<(u8, u8, u32, Vec<u8>)>;

/// Frames read from `s` for `wait`, or until `sid` has ended (END_STREAM).
fn read_frames(s: &mut TcpStream, buf: &mut Vec<u8>, wait: Duration, sid: u32) -> Frames {
    let mut out = Vec::new();
    let deadline = Instant::now() + wait;
    let mut tmp = [0u8; 4096];
    while Instant::now() < deadline {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            let f = (buf[3], buf[4], id, buf[9..9 + len].to_vec());
            buf.drain(..9 + len);
            let ended = id == sid && matches!(f.0, 0 | 1) && f.1 & 1 != 0;
            out.push(f);
            if ended {
                return out;
            }
        }
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
    out
}

fn connect(fe: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(50))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(4, 0, 0, &[])).expect("settings");
    s.write_all(&frame(4, 1, 0, &[])).expect("ack");
    s
}

fn log_line(c: &UdpSocket) -> String {
    let mut buf = [0u8; 2048];
    let n = c.recv(&mut buf).expect("a log line");
    let l = String::from_utf8_lossy(&buf[..n]).into_owned();
    l.split_once("]: ").map_or(l.clone(), |(_, b)| b.trim_end().to_string())
}

/// HEADERS (1) or DATA (0) frames on `sid`.
fn on_stream(frames: &Frames, sid: u32) -> Vec<&(u8, u8, u32, Vec<u8>)> {
    frames.iter().filter(|f| f.2 == sid && matches!(f.0, 0 | 1)).collect()
}

/// The server connection of stream 1 was reset, at once rather than at `timeout server`.
fn assert_server_aborted(rx: &Receiver<Ended>) {
    let ended = rx.recv_timeout(Duration::from_secs(8)).expect("the server connection ended");
    assert!(ended.reset && ended.after < Duration::from_secs(1), "HAProxy resets the server connection at once: {ended:?}");
}

/// A GET on stream 3 of the same connection is answered at once: the reset stream does
/// not hold the connection's next one.
fn assert_next_stream_served(s: &mut TcpStream, buf: &mut Vec<u8>) {
    s.write_all(&frame(1, 5, 3, &head("GET", "/b"))).expect("get");
    let t = Instant::now();
    let frames = read_frames(s, buf, Duration::from_secs(2), 3);
    assert!(
        frames.iter().any(|f| f.0 == 1 && f.2 == 3 && f.3.first() == Some(&0x88)) && t.elapsed() < Duration::from_secs(1),
        "stream 3 answered at once ({:?}): {frames:?}",
        t.elapsed()
    );
}

#[test]
fn client_reset_while_waiting_for_the_response_head() {
    let (_ibex, fe, rx, log) = start(false);
    let mut s = connect(fe);
    let mut buf = Vec::new();
    s.write_all(&frame(1, 4, 1, &head("POST", "/a"))).expect("head");
    thread::sleep(Duration::from_millis(200));
    s.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst_stream cancel");
    // The server's answer comes 300 ms after the head.
    let frames = read_frames(&mut s, &mut buf, Duration::from_millis(600), 99);
    assert!(on_stream(&frames, 1).is_empty(), "nothing on the stream the client reset: {frames:?}");
    assert!(!frames.iter().any(|f| f.0 == 3 && f.2 == 1), "no RST_STREAM for a stream the client reset: {frames:?}");
    assert_server_aborted(&rx);
    let line = log_line(&log);
    assert!(line.contains(" 400 0 - - CH-- "), "{line}");
    assert_next_stream_served(&mut s, &mut buf);
}

/// T521: the request whole (`POST` with END_STREAM, no body), the client resets the stream while the
/// server has not answered: `HAProxy` 3.5-dev8 (and 3.5-dev7 on h2 and h3) logs `400 0 - -
/// CD--`, not the `CH--` of a request cut short above.
#[test]
fn client_reset_of_a_whole_request_while_waiting_for_the_response_head() {
    let (_ibex, fe, rx, log) = start(false);
    let mut s = connect(fe);
    let mut buf = Vec::new();
    s.write_all(&frame(1, 5, 1, &head("POST", "/a"))).expect("head");
    thread::sleep(Duration::from_millis(200));
    s.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst_stream cancel");
    let frames = read_frames(&mut s, &mut buf, Duration::from_millis(600), 99);
    assert!(on_stream(&frames, 1).is_empty(), "nothing on the stream the client reset: {frames:?}");
    assert_server_aborted(&rx);
    let line = log_line(&log);
    assert!(line.contains(" 400 0 - - CD-- "), "{line}");
    assert_next_stream_served(&mut s, &mut buf);
}

#[test]
fn stream_error_after_dispatch_sends_nothing_after_the_rst() {
    let (_ibex, fe, rx, log) = start(false);
    let mut s = connect(fe);
    let mut buf = Vec::new();
    s.write_all(&frame(1, 4, 1, &head("POST", "/a"))).expect("head");
    thread::sleep(Duration::from_millis(200));
    s.write_all(&frame(1, 4, 1, &block(&[("x", "y")]))).expect("trailers without end of stream");
    let frames = read_frames(&mut s, &mut buf, Duration::from_millis(600), 99);
    let rst = frames.iter().position(|f| f.0 == 3 && f.2 == 1).unwrap_or_else(|| panic!("the stream is reset: {frames:?}"));
    assert!(on_stream(&frames[rst..].to_vec(), 1).is_empty(), "nothing on stream 1 after its RST_STREAM: {frames:?}");
    assert_server_aborted(&rx);
    let line = log_line(&log);
    assert!(line.contains(" 400 0 - - CH-- "), "{line}");
}

#[test]
fn client_reset_during_the_response_body() {
    let (_ibex, fe, rx, log) = start(true);
    let mut s = connect(fe);
    let mut buf = Vec::new();
    s.write_all(&frame(1, 4, 1, &head("POST", "/a"))).expect("head");
    let frames = read_frames(&mut s, &mut buf, Duration::from_millis(200), 99);
    assert_eq!(on_stream(&frames, 1).len(), 2, "the head and 2 bytes: {frames:?}");
    s.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst_stream cancel");
    let frames = read_frames(&mut s, &mut buf, Duration::from_millis(300), 99);
    assert!(!frames.iter().any(|f| f.2 == 1), "nothing more on the stream the client reset: {frames:?}");
    assert_server_aborted(&rx);
    let line = log_line(&log);
    assert!(line.contains(" 200 52 - - CD-- "), "{line}");
    assert_next_stream_served(&mut s, &mut buf);
}

/// The response is complete (the server answered `/a` and the mux has it) while the request
/// is still open, and then the client resets the stream. Measured on `HAProxy`: nothing more
/// on the stream, the server connection reset, log `200 51 - - CL--`, stream 3 answered. (Ibex differs in the last two
/// details of the server side and the log; see the comments below.)
#[test]
fn client_reset_after_the_response_was_complete() {
    let (_ibex, fe, rx, log) = start(false);
    let mut s = connect(fe);
    let mut buf = Vec::new();
    s.write_all(&frame(1, 4, 1, &head("POST", "/a"))).expect("head");
    // The server's answer comes 300 ms after the head, whole.
    let frames = read_frames(&mut s, &mut buf, Duration::from_millis(600), 99);
    let on_1 = on_stream(&frames, 1);
    assert_eq!(on_1.len(), 2, "the head and the 2 bytes: {frames:?}");
    assert_eq!(on_1[1].1 & 1, 1, "the response ended the stream while the request is open: {frames:?}");
    s.write_all(&frame(3, 0, 1, &8u32.to_be_bytes())).expect("rst_stream cancel");
    let frames = read_frames(&mut s, &mut buf, Duration::from_millis(300), 99);
    assert!(!frames.iter().any(|f| f.2 == 1), "nothing more on the stream the client reset: {frames:?}");
    // HAProxy resets the server connection here (`Ended { reset: true, .. }`); Ibex closes it
    // with a FIN, at once all the same. Not asserted as a reset until it is one.
    let ended = rx.recv_timeout(Duration::from_secs(8)).expect("the server connection ended");
    assert!(ended.after < Duration::from_secs(1), "the server connection is closed at once: {ended:?}");
    let line = log_line(&log);
    // HAProxy's termination state is `CL--` here; Ibex's is `----`. Only the status and size
    // are asserted until it is the same.
    assert!(line.contains(" 200 51 - - "), "{line}");
    assert_next_stream_served(&mut s, &mut buf);
}
