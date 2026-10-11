// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What an HTTP/2 client's request becomes on its way through (T179).
//!
//! Expected values measured on `HAProxy 3.5-dev8-885761-29` with a hand-built h2 client
//! (cleartext `proto h2` bind, an HTTP/1 server that records the bytes it gets):
//!
//! ```text
//! Expect: 100-continue   no 100 on the stream (curl waits its 1 s and sends); the header is
//!                        forwarded to the server unchanged. Same with TLS+ALPN h2, with or
//!                        without a content-length.
//! trailers               HEADERS+END_STREAM after the DATA reach an h1 server as
//!                        `0\r\nname: value\r\n...\r\n`; `req.hdr` does not see them, with or
//!                        without `option http-buffer-request`.
//! no content-length      the server gets `transfer-encoding: chunked`; `req.hdr(transfer-encoding)`
//!                        in the rules is empty (the header is added on output).
//! %B/%U                  the HTX message: GET x /g -> U=47; POST /n, 3 bytes, no length -> 51;
//!                        PUT /x with expect + content-length 6 + 6 bytes -> 86; POST /t with
//!                        te + content-type, 3 bytes and two trailers (21) -> 111 (the trailers
//!                        and the one byte of their end); %B=51 for the 2-byte reply.
//!                        %r is `GET http://x/g HTTP/2.0`.
//! ```

use crate::common;

use std::io::{Read, Write};
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

/// An HTTP/1 server that sends each request it gets, as bytes, on the channel and answers
/// `200` with `ok`.
fn server() -> (SocketAddr, Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = channel();
    thread::spawn(move || {
        for mut c in listener.incoming().flatten() {
            let tx = tx.clone();
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(3))).ok();
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(n) = c.read(&mut buf) else { break };
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    if complete(&got) {
                        break;
                    }
                }
                let _ = tx.send(got);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            });
        }
    });
    (addr, rx)
}

fn complete(got: &[u8]) -> bool {
    let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
    let body = &got[at + 4..];
    if head.contains("transfer-encoding: chunked") {
        let text = String::from_utf8_lossy(body);
        return text.ends_with("\r\n\r\n") && (text.starts_with("0\r\n") || text.contains("\r\n0\r\n"));
    }
    let len = head.split("content-length: ").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
    body.len() >= len
}

fn start(extra_fe: &str) -> (Ibex, SocketAddr, Receiver<Vec<u8>>, UdpSocket) {
    let collector = UdpSocket::bind("127.0.0.1:0").expect("collector");
    collector.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let (fe, (srv, rx)) = (common::reserve_addr(), server());
    let cfg = format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 3s\n\
         frontend fe\n  bind {fe} proto h2\n  log {} local0\n\
         \x20 log-format \"B=%B U=%U te=%[var(txn.te)] tr=%[var(txn.tr)] r=%r\"\n\
         \x20 http-request set-var(txn.te) req.hdr(transfer-encoding)\n\
         \x20 http-request set-var(txn.tr) req.hdr(x-trail)\n{extra_fe}\
         \x20 default_backend be\n\
         backend be\n  server s {srv}\n",
        collector.local_addr().expect("addr")
    );
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(cfg.as_bytes()).expect("write cfg");
    // `T306A_ORACLE=/path/to/haproxy` runs the same assertions on the reference binary.
    let bin = std::env::var("T306A_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string());
    let child = Command::new(bin)
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

fn head(method: &str, path: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut l = vec![(":method", method), (":scheme", "http"), (":authority", "x"), (":path", path)];
    l.extend_from_slice(extra);
    block(&l)
}

type Frame = (u8, u8, u32, Vec<u8>);

/// Frames read from `s` until the stream `sid` has ended (END_STREAM on a DATA or HEADERS).
fn read_until_end(s: &mut TcpStream, sid: u32) -> Vec<Frame> {
    read_frames(s, Duration::from_secs(5), |f| f.2 == sid && matches!(f.0, 0 | 1) && f.1 & 1 != 0)
}

/// Frames read from `s` until one is `last`, for up to 5 s: a proxy slow to answer under
/// load is waited for (a read that gave up at the socket's 200 ms timeout made the tests
/// that read a whole response fail under parallel load, T305 item 9).
fn read_until(s: &mut TcpStream, last: impl Fn(&Frame) -> bool) -> Vec<Frame> {
    read_frames(s, Duration::from_secs(5), last)
}

/// What `s` has to read now: frames until 200 ms pass with nothing.
fn read_quiet(s: &mut TcpStream) -> Vec<Frame> {
    read_frames(s, Duration::ZERO, |_| false)
}

/// Frames read from `s` until one is `last`; a read timeout (200 ms of quiet) ends the
/// reading once `patience` has passed.
fn read_frames(s: &mut TcpStream, patience: Duration, last: impl Fn(&Frame) -> bool) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let deadline = Instant::now() + patience;
    let mut tmp = [0u8; 4096];
    loop {
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            let f = (buf[3], buf[4], id, buf[9..9 + len].to_vec());
            buf.drain(..9 + len);
            let done = last(&f);
            out.push(f);
            if done {
                return out;
            }
        }
        match s.read(&mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) && Instant::now() < deadline => {}
            _ => return out,
        }
    }
}

fn connect(fe: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.set_read_timeout(Some(Duration::from_millis(200))).ok();
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

/// 0x08 in the first byte after the indexed `:status`: the reply is a 200 (`0x88`).
fn is_200(frames: &[(u8, u8, u32, Vec<u8>)]) -> bool {
    frames.iter().any(|f| f.0 == 1 && f.3.first() == Some(&0x88))
}

#[test]
fn expect_100_continue_gets_no_interim_and_reaches_the_server() {
    let (_ibex, fe, rx, _log) = start("");
    let mut s = connect(fe);
    s.write_all(&frame(1, 4, 1, &head("PUT", "/x", &[("expect", "100-continue"), ("content-length", "6")]))).expect("head");
    thread::sleep(Duration::from_millis(400));
    let early = read_quiet(&mut s);
    assert!(
        !early.iter().any(|f| f.0 == 1 && f.2 == 1),
        "HAProxy sends no HEADERS (no :status 100) before the body: {early:?}"
    );
    s.write_all(&frame(0, 1, 1, b"hello\n")).expect("body");
    let frames = read_until_end(&mut s, 1);
    assert!(is_200(&frames), "{frames:?}");
    let got = String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).expect("request")).into_owned();
    assert!(got.contains("expect: 100-continue\r\n") && got.contains("content-length: 6\r\n") && got.ends_with("hello\n"), "{got:?}");
}

#[test]
fn request_trailers_reach_an_h1_server_as_chunked_trailers() {
    for extra in ["", "  option http-buffer-request\n"] {
        let (_ibex, fe, rx, log) = start(extra);
        let mut s = connect(fe);
        s.write_all(&frame(1, 4, 1, &head("POST", "/t", &[("te", "trailers"), ("content-type", "application/grpc")]))).expect("head");
        s.write_all(&frame(0, 0, 1, b"abc")).expect("data");
        thread::sleep(Duration::from_millis(100));
        s.write_all(&frame(1, 5, 1, &block(&[("x-trail", "tv"), ("grpc-status", "0")]))).expect("trailers");
        let frames = read_until_end(&mut s, 1);
        assert!(is_200(&frames), "{extra:?}: {frames:?}");
        let got = String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).expect("request")).into_owned();
        assert_eq!(
            got,
            "POST /t HTTP/1.1\r\nhost: x\r\nte: trailers\r\ncontent-type: application/grpc\r\ntransfer-encoding: chunked\r\n\r\n\
             3\r\nabc\r\n0\r\nx-trail: tv\r\ngrpc-status: 0\r\n\r\n",
            "{extra:?}"
        );
        // The rules do not see the trailers (`tr=` empty), and the message counts them.
        let l = log_line(&log);
        assert!(l.contains(" tr=- ") && l.contains("U=111 "), "{extra:?}: {l}");
    }
}

#[test]
fn rules_do_not_see_the_transfer_encoding_added_on_output() {
    let (_ibex, fe, rx, log) = start("");
    let mut s = connect(fe);
    s.write_all(&frame(1, 4, 1, &head("POST", "/n", &[]))).expect("head");
    s.write_all(&frame(0, 1, 1, b"abc")).expect("data");
    let frames = read_until_end(&mut s, 1);
    assert!(is_200(&frames), "{frames:?}");
    let got = String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).expect("request")).into_owned();
    assert_eq!(got, "POST /n HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
    let l = log_line(&log);
    assert!(l.contains(" te=- "), "{l}");
}

#[test]
fn log_counts_of_an_h2_request_are_the_htx_message() {
    let (_ibex, fe, _rx, log) = start("");
    let mut s = connect(fe);
    s.write_all(&frame(1, 5, 1, &head("GET", "/g", &[]))).expect("get");
    assert!(is_200(&read_until_end(&mut s, 1)));
    assert_eq!(log_line(&log), "B=51 U=47 te=- tr=- r=GET http://x/g HTTP/2.0");
    s.write_all(&frame(1, 4, 3, &head("POST", "/n", &[]))).expect("head");
    s.write_all(&frame(0, 1, 3, b"abc")).expect("data");
    assert!(is_200(&read_until_end(&mut s, 3)));
    assert_eq!(log_line(&log), "B=51 U=51 te=- tr=- r=POST http://x/n HTTP/2.0");
    s.write_all(&frame(1, 4, 5, &head("PUT", "/x", &[("expect", "100-continue"), ("content-length", "6")]))).expect("head");
    s.write_all(&frame(0, 1, 5, b"hello\n")).expect("data");
    assert!(is_200(&read_until_end(&mut s, 5)));
    assert_eq!(log_line(&log), "B=51 U=86 te=- tr=- r=PUT http://x/x HTTP/2.0");
}

#[test]
fn trailers_after_a_content_length_body_are_counted_and_not_forwarded() {
    let (_ibex, fe, rx, log) = start("");
    let mut s = connect(fe);
    s.write_all(&frame(1, 4, 1, &head("POST", "/cl", &[("content-length", "3")]))).expect("head");
    s.write_all(&frame(0, 0, 1, b"abc")).expect("data");
    s.write_all(&frame(1, 5, 1, &block(&[("x-trail", "tv")]))).expect("trailers");
    assert!(is_200(&read_until_end(&mut s, 1)));
    let got = String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).expect("request")).into_owned();
    assert_eq!(got, "POST /cl HTTP/1.1\r\nhost: x\r\ncontent-length: 3\r\n\r\nabc");
    assert_eq!(log_line(&log), "B=51 U=77 te=- tr=- r=POST http://x/cl HTTP/2.0");
}

/// The same request with its trailers sent only once the whole response is back
/// (measured on `HAProxy` 3.5-dev8, 2026-10-11): the stream is not over until the client
/// ends it. Nothing more is sent on it -- no `RST_STREAM`, no `GOAWAY` for the trailers --
/// the line is logged then, with the trailers counted, and the connection goes on.
#[test]
fn trailers_after_the_response_are_counted_and_the_connection_goes_on() {
    let (_ibex, fe, rx, log) = start("");
    let mut s = connect(fe);
    s.write_all(&frame(1, 4, 1, &head("POST", "/cl", &[("content-length", "3")]))).expect("head");
    s.write_all(&frame(0, 0, 1, b"abc")).expect("data");
    assert!(is_200(&read_until_end(&mut s, 1)));
    let got = String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).expect("request")).into_owned();
    assert_eq!(got, "POST /cl HTTP/1.1\r\nhost: x\r\ncontent-length: 3\r\n\r\nabc");
    thread::sleep(Duration::from_millis(300));
    s.write_all(&frame(1, 5, 1, &block(&[("x-trail", "tv")]))).expect("trailers");
    assert_eq!(log_line(&log), "B=51 U=77 te=- tr=- r=POST http://x/cl HTTP/2.0");
    s.write_all(&frame(1, 5, 3, &head("GET", "/g", &[]))).expect("get");
    let frames = read_until_end(&mut s, 3);
    assert!(frames.iter().all(|f| !matches!(f.0, 3 | 7)), "a reset or a GOAWAY: {frames:?}");
    assert!(is_200(&frames), "{frames:?}");
}

#[test]
fn a_rule_that_edits_the_head_does_not_lose_the_chunked_framing() {
    let (_ibex, fe, rx, _log) = start("  http-request set-header x-added 1\n");
    let mut s = connect(fe);
    s.write_all(&frame(1, 4, 1, &head("POST", "/n", &[]))).expect("head");
    s.write_all(&frame(0, 1, 1, b"abc")).expect("data");
    assert!(is_200(&read_until_end(&mut s, 1)));
    let got = String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).expect("request")).into_owned();
    assert_eq!(got, "POST /n HTTP/1.1\r\nhost: x\r\nx-added: 1\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n");
}

/// Error codes seen on the wire for each way a second HEADERS can be wrong: trailers
/// without END_STREAM, with a pseudo-header (RST_STREAM), and after the stream has closed.
/// The last: HAProxy 3.5-dev8 answers HEADERS on a stream whose response has ended with
/// GOAWAY(STREAM_CLOSED), measured 2026-10-11; so the test reads stream 5's response to
/// its end before sending the HEADERS (sent at once, HAProxy's answer is GOAWAY(PROTOCOL_ERROR)).
#[test]
fn malformed_trailers_reset_the_stream() {
    let (_ibex, fe, _rx, _log) = start("");
    let rst = |s: &mut TcpStream, sid: u32| -> Option<u32> {
        let frames = read_until(s, |f| f.0 == 3 && f.2 == sid);
        frames.iter().find(|f| f.0 == 3 && f.2 == sid).map(|f| u32::from_be_bytes([f.3[0], f.3[1], f.3[2], f.3[3]]))
    };
    let mut s = connect(fe);
    s.write_all(&frame(1, 4, 1, &head("POST", "/a", &[]))).expect("head");
    s.write_all(&frame(1, 4, 1, &block(&[("x", "y")]))).expect("trailers without end of stream");
    assert_eq!(rst(&mut s, 1), Some(1), "PROTOCOL_ERROR");
    s.write_all(&frame(1, 4, 3, &head("POST", "/b", &[]))).expect("head");
    s.write_all(&frame(1, 5, 3, &block(&[(":path", "/z")]))).expect("trailers with a pseudo-header");
    assert_eq!(rst(&mut s, 3), Some(1), "PROTOCOL_ERROR");
    s.write_all(&frame(1, 5, 5, &head("GET", "/c", &[]))).expect("get");
    assert!(is_200(&read_until_end(&mut s, 5)), "stream 5 answered before its HEADERS come");
    s.write_all(&frame(1, 5, 5, &block(&[("x", "y")]))).expect("headers after the end");
    let goaway = read_until(&mut s, |f| f.0 == 7)
        .iter()
        .find(|f| f.0 == 7)
        .map(|f| u32::from_be_bytes([f.3[4], f.3[5], f.3[6], f.3[7]]));
    assert_eq!(goaway, Some(5), "GOAWAY(STREAM_CLOSED)");
}
