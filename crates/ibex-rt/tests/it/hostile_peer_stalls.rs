// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A peer that is slow or hostile in a way the protocol allows must cost neither a core
//! nor a stream that never ends (T248).
//!
//! * An HTTP/2 client whose flow-control window is 0 is not polled for writability while
//!   nothing can be sent to it; a `WINDOW_UPDATE` resumes the download.
//! * Interim (1xx) responses, any number of them in one read, are relayed at once, and the
//!   final response behind them follows without waiting for a timer.
//! * Chunk extensions and trailers from the server are bounded: past what fits in a
//!   buffer, the response is aborted instead of relayed for as long as the server talks.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8; each test says what it saw.

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Proxy(Child, tempfile::NamedTempFile);

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

impl Proxy {
    /// CPU time (user + system, clock ticks) the proxy has used so far.
    fn cpu_ticks(&self) -> u64 {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.0.id())).expect("read /proc stat");
        // The fields after the command name, which is in parentheses and may hold spaces.
        let rest = &stat[stat.rfind(')').expect("comm") + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        // utime and stime are fields 14 and 15 of the line, 12 and 13 after the name.
        f[11].parse::<u64>().expect("utime") + f[12].parse::<u64>().expect("stime")
    }
}

/// Starts ibex with one frontend (`bind_extra` after its address) in front of `backend`.
fn start(bind_extra: &str, backend: SocketAddr, timeout_server: &str) -> (Proxy, SocketAddr) {
    let fe = common::reserve_addr();
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(
        cfg.path(),
        format!(
            "global\n\tnbthread 1\n\
             defaults\n\tmode http\n\ttimeout connect 2s\n\ttimeout client 10s\n\ttimeout server {timeout_server}\n\n\
             frontend fe\n\tbind {fe}{bind_extra}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 {backend}\n"
        ),
    )
    .expect("write config");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(cfg.path())
        .arg("-db")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    let p = Proxy(child, cfg);
    assert!(common::wait_listening(fe), "ibex never listened on {fe}");
    (p, fe)
}

/// A server that reads one request head and then hands the connection to `respond`.
fn backend(respond: fn(&mut TcpStream)) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("addr");
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                respond(&mut c);
            });
        }
    });
    addr
}

/// What an HTTP/1 client saw of one `GET /`: every byte until `until` held, the
/// connection closed, or `limit` passed; and whether it was closed.
struct Seen {
    bytes: Vec<u8>,
    total: usize,
    closed: bool,
    elapsed: Duration,
}

fn get(fe: SocketAddr, limit: Duration, until: impl Fn(&[u8]) -> bool) -> Seen {
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let start = Instant::now();
    let mut bytes = Vec::new();
    let mut total = 0;
    let mut closed = false;
    let mut tmp = vec![0u8; 65536];
    while start.elapsed() < limit && !until(&bytes) {
        s.set_read_timeout(Some(Duration::from_millis(50))).ok();
        match s.read(&mut tmp) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(n) => {
                total += n;
                // Keep the start of a flood, not all of it.
                if bytes.len() < 1 << 20 {
                    bytes.extend_from_slice(&tmp[..n]);
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    Seen { bytes, total, closed, elapsed: start.elapsed() }
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

fn ends_with_ok(b: &[u8]) -> bool {
    b.windows(17).any(|w| w == b"HTTP/1.1 200 OK\r\n") && b.ends_with(b"\r\n\r\nok")
}

// --- 1. HTTP/2 client with a closed window -----------------------------------------------

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame fits");
    let mut v = len.to_be_bytes()[1..].to_vec();
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// `GET /` on `localhost`, static-table HPACK only.
fn hpack_get() -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x84, 0x01, 9];
    v.extend_from_slice(b"localhost");
    v
}

/// Reads frames for `wait`; the bytes of DATA on stream 1, and whether a `:status 200`
/// HEADERS came on it.
fn h2_read(s: &mut TcpStream, buf: &mut Vec<u8>, wait: Duration) -> (bool, usize) {
    let start = Instant::now();
    let mut tmp = vec![0u8; 65536];
    let (mut ok, mut data) = (false, 0);
    while start.elapsed() < wait {
        s.set_read_timeout(Some(Duration::from_millis(20))).ok();
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (t, sid) = (buf[3], u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff);
            if sid == 1 && t == 0x01 && buf.get(9) == Some(&0x88) {
                ok = true;
            }
            if sid == 1 && t == 0x00 {
                data += len;
            }
            buf.drain(..9 + len);
        }
    }
    (ok, data)
}

fn big_body(c: &mut TcpStream) {
    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4000000\r\n\r\n");
    let _ = c.write_all(&vec![b'y'; 4_000_000]);
    std::thread::sleep(Duration::from_secs(20));
}

/// Drives an h2c download that stalls on `stall`, then measures the proxy's CPU over two
/// seconds; returns the ticks and the stream after the stall.
fn stalled_h2_download(initial_window: u32) -> (u64, TcpStream, Vec<u8>, Proxy) {
    let be = backend(big_body);
    let (px, fe) = start(" proto h2", be, "30s");
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    // SETTINGS_INITIAL_WINDOW_SIZE
    let mut set = vec![0, 4];
    set.extend_from_slice(&initial_window.to_be_bytes());
    s.write_all(&frame(0x04, 0, 0, &set)).expect("settings");
    s.write_all(&frame(0x01, 0x05, 1, &hpack_get())).expect("headers");
    let mut buf = Vec::new();
    let (ok, data) = h2_read(&mut s, &mut buf, Duration::from_millis(800));
    assert!(ok, "no :status 200 before the stall");
    assert!(data <= 65535, "more DATA than the windows allow: {data}");
    let before = px.cpu_ticks();
    std::thread::sleep(Duration::from_secs(2));
    let ticks = px.cpu_ticks() - before;
    (ticks, s, buf, px)
}

/// The stream's window is 0 from the start (`SETTINGS_INITIAL_WINDOW_SIZE` 0), the
/// response body is waiting: nothing may be sent, and nothing should be done.
///
/// Before the fix ibex burned the whole core (~200 ticks in 2 s: level-triggered EPOLLOUT
/// with the response counted as pending output). `HAProxy` 3.5-dev8 on the same exchange
/// (`curl --http2-prior-knowledge --limit-rate 50k`, 20 MB body): 1 tick in 4 s.
/// A `WINDOW_UPDATE` on the stream then resumes the body.
#[test]
fn an_h2_client_with_a_zero_stream_window_costs_no_cpu_and_resumes_on_window_update() {
    let (ticks, mut s, mut buf, _px) = stalled_h2_download(0);
    assert!(ticks < 40, "ibex used {ticks} ticks in 2 s with nothing it could send");
    s.write_all(&frame(0x08, 0, 1, &60000u32.to_be_bytes())).expect("window update");
    let (_, data) = h2_read(&mut s, &mut buf, Duration::from_secs(2));
    assert!(data > 0, "no DATA after the WINDOW_UPDATE");
}

/// The connection window (65535, never raised) is used up by the first DATA; the stream
/// window is large. The same: no CPU while blocked, and a connection-level
/// `WINDOW_UPDATE` resumes the body.
#[test]
fn an_h2_client_with_a_spent_connection_window_costs_no_cpu_and_resumes_on_window_update() {
    let (ticks, mut s, mut buf, _px) = stalled_h2_download(1 << 30);
    assert!(ticks < 40, "ibex used {ticks} ticks in 2 s with nothing it could send");
    s.write_all(&frame(0x08, 0, 0, &60000u32.to_be_bytes())).expect("window update");
    let (_, data) = h2_read(&mut s, &mut buf, Duration::from_secs(2));
    assert!(data > 0, "no DATA after the connection WINDOW_UPDATE");
}

// --- 2. Interim responses -------------------------------------------------------------

fn interims_then_ok(c: &mut TcpStream, interim: &[u8], n: usize) {
    let mut v = interim.repeat(n);
    v.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let _ = c.write_all(&v);
    std::thread::sleep(Duration::from_secs(15));
}

const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
const EARLY_HINTS: &[u8] = b"HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\n";

/// `n` interim responses and the final one in one write reach the client at once.
///
/// `HAProxy` 3.5-dev8, 1, 4, 10 and 50 `100 Continue` (and 4, 10, 50 `103 Early Hints`)
/// then a 200, one write: every interim response and the 200 relayed within 1 ms. Ibex
/// relayed three per pass and left the rest, and the 200, for the next unrelated timer:
/// `timeout server` (here 10 s) for four, never for fifty.
fn interims_in_one_write(interim: &[u8], n: usize) {
    let be = match (interim == CONTINUE, n) {
        (true, 4) => backend(|c| interims_then_ok(c, CONTINUE, 4)),
        (true, 10) => backend(|c| interims_then_ok(c, CONTINUE, 10)),
        (true, _) => backend(|c| interims_then_ok(c, CONTINUE, 50)),
        (false, 4) => backend(|c| interims_then_ok(c, EARLY_HINTS, 4)),
        (false, _) => backend(|c| interims_then_ok(c, EARLY_HINTS, 50)),
    };
    let (_px, fe) = start("", be, "10s");
    let seen = get(fe, Duration::from_secs(5), ends_with_ok);
    assert!(ends_with_ok(&seen.bytes), "no 200 within 5 s ({:?}): {:?}", seen.elapsed, String::from_utf8_lossy(&seen.bytes));
    assert!(seen.elapsed < Duration::from_secs(2), "the 200 took {:?}", seen.elapsed);
    let status = if interim == CONTINUE { &b"HTTP/1.1 100 "[..] } else { &b"HTTP/1.1 103 "[..] };
    assert_eq!(count(&seen.bytes, status), n, "{:?}", String::from_utf8_lossy(&seen.bytes));
}

#[test]
fn four_100_continue_and_the_final_response_in_one_write() {
    interims_in_one_write(CONTINUE, 4);
}

#[test]
fn ten_100_continue_and_the_final_response_in_one_write() {
    interims_in_one_write(CONTINUE, 10);
}

#[test]
fn fifty_100_continue_and_the_final_response_in_one_write() {
    interims_in_one_write(CONTINUE, 50);
}

#[test]
fn four_103_early_hints_and_the_final_response_in_one_write() {
    interims_in_one_write(EARLY_HINTS, 4);
}

#[test]
fn fifty_103_early_hints_and_the_final_response_in_one_write() {
    interims_in_one_write(EARLY_HINTS, 50);
}

/// A server that sends `100 Continue` for ever. `HAProxy` 3.5-dev8 relays it as fast as
/// the client reads (1 GB in 12 s, `timeout server` 3 s never fires since the server is
/// not idle). Ibex relayed three per timer wake-up, 14 in 8 s.
#[test]
fn an_endless_stream_of_100_continue_is_relayed_as_it_comes() {
    let be = backend(|c| {
        let burst = CONTINUE.repeat(200);
        while c.write_all(&burst).is_ok() {}
    });
    let (_px, fe) = start("", be, "10s");
    let seen = get(fe, Duration::from_secs(2), |_| false);
    let n = count(&seen.bytes, b"HTTP/1.1 100 ");
    assert!(n >= 2000, "only {n} interim responses relayed in 2 s");
}

/// The same over HTTP/2: fifty `100 Continue` and the 200 in one write. `HAProxy` 3.5-dev8
/// sends the interim HEADERS and the 200 at once; ibex drops the interim responses (the
/// HTTP/2 1xx gap of design 010) and, before the fix, sent a 504 after `timeout server`.
#[test]
fn fifty_100_continue_then_the_final_response_reach_an_h2_client() {
    let be = backend(|c| interims_then_ok(c, CONTINUE, 50));
    let (_px, fe) = start(" proto h2", be, "10s");
    let mut s = TcpStream::connect(fe).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    s.write_all(&frame(0x01, 0x05, 1, &hpack_get())).expect("headers");
    let mut buf = Vec::new();
    let (ok, data) = h2_read(&mut s, &mut buf, Duration::from_secs(2));
    assert!(ok, "no :status 200 within 2 s");
    assert_eq!(data, 2);
}

// --- 3. Chunk extensions and trailers -------------------------------------------------

/// A chunk extension that never ends. `HAProxy` 3.5-dev8 does not relay extensions; it
/// accepts one up to about a buffer (16300 bytes passes, 16330 does not) and past that
/// relays nothing more of the response and closes the client connection (at `timeout
/// server` there; ibex at once). Ibex relayed it all: 893 MB in 6 s.
#[test]
fn an_endless_chunk_extension_is_not_relayed() {
    let be = backend(|c| {
        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;");
        let e = vec![b'e'; 16384];
        while c.write_all(&e).is_ok() {}
    });
    let (_px, fe) = start("", be, "3s");
    let seen = get(fe, Duration::from_secs(6), |_| false);
    assert!(seen.total < 64 * 1024, "{} bytes relayed", seen.total);
    assert!(seen.closed, "the client connection is still open after {:?}", seen.elapsed);
}

/// A chunk extension that fits a buffer still passes.
#[test]
fn a_long_chunk_extension_that_fits_passes() {
    let be = backend(|c| {
        let mut v = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;".to_vec();
        v.extend_from_slice(&[b'e'; 16000]);
        v.extend_from_slice(b"\r\nok\r\n0\r\n\r\n");
        let _ = c.write_all(&v);
        std::thread::sleep(Duration::from_secs(10));
    });
    let (_px, fe) = start("", be, "10s");
    let seen = get(fe, Duration::from_secs(3), |b| b.ends_with(b"0\r\n\r\n"));
    assert!(seen.bytes.ends_with(b"0\r\n\r\n") && !seen.closed, "{:?}", String::from_utf8_lossy(&seen.bytes[..seen.bytes.len().min(200)]));
}

/// Trailers that never end. `HAProxy` 3.5-dev8 relays the data, then closes the client
/// connection at once. Ibex relayed them all.
#[test]
fn endless_trailers_are_not_relayed() {
    let be = backend(|c| {
        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n");
        let mut t = b"T: ".to_vec();
        t.extend_from_slice(&[b'v'; 100]);
        t.extend_from_slice(b"\r\n");
        let burst = t.repeat(100);
        while c.write_all(&burst).is_ok() {}
    });
    let (_px, fe) = start("", be, "3s");
    let seen = get(fe, Duration::from_secs(6), |_| false);
    assert!(seen.total < 64 * 1024, "{} bytes relayed", seen.total);
    assert!(seen.closed, "the client connection is still open after {:?}", seen.elapsed);
    assert!(seen.elapsed < Duration::from_secs(2), "closed after {:?}", seen.elapsed);
}

fn trailer_lines(c: &mut TcpStream, n: usize) {
    let mut v = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n".to_vec();
    v.extend_from_slice(&b"T: v\r\n".repeat(n));
    v.extend_from_slice(b"\r\n");
    let _ = c.write_all(&v);
    std::thread::sleep(Duration::from_secs(10));
}

/// 100 trailer fields pass, 101 do not: `HAProxy` 3.5-dev8 relays 100 and answers 502 to
/// 101 (`tune.http.maxhdr`). Ibex has sent the head by then; the response is cut short
/// before the 101st field and the connection closed.
#[test]
fn a_hundred_trailer_fields_pass_and_a_hundred_and_one_do_not() {
    let be = backend(|c| trailer_lines(c, 100));
    let (px, fe) = start("", be, "10s");
    let seen = get(fe, Duration::from_secs(3), |b| b.ends_with(b"T: v\r\n\r\n"));
    assert!(seen.bytes.ends_with(b"T: v\r\n\r\n") && !seen.closed, "{:?}", String::from_utf8_lossy(&seen.bytes));
    assert_eq!(count(&seen.bytes, b"T: v\r\n"), 100);
    drop(px);

    let be = backend(|c| trailer_lines(c, 101));
    let (_px, fe) = start("", be, "10s");
    let seen = get(fe, Duration::from_secs(3), |_| false);
    assert!(seen.closed, "the client connection is still open after {:?}", seen.elapsed);
    assert!(count(&seen.bytes, b"T: v\r\n") <= 100, "{:?}", String::from_utf8_lossy(&seen.bytes));
    assert!(!seen.bytes.ends_with(b"\r\n\r\n"), "the response looks complete: {:?}", String::from_utf8_lossy(&seen.bytes));
}
