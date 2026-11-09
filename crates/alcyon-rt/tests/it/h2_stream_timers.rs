// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Each stream of an HTTP/2 connection has its own `timeout client` (T300). `HAProxy`'s
//! h2 connection has no timer while streams are attached (`h2c_may_expire`); each stream's
//! channels have theirs. A stream whose client stalls its upload times out alone, and the
//! connection's other streams go on.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29 (`T280_ORACLE=/path/to/haproxy` runs these
//! tests on it), `timeout client` 1 s or 2 s, `timeout server` 10 s:
//! - a POST whose body stops after the head gets, at `timeout client`, `HEADERS :status 400`,
//!   the 90-byte error page with `END_STREAM`, then `RST_STREAM NO_ERROR`; its log line
//!   reads `0/0/0/-1/<timeout client> 400 0 - - cH--`;
//! - a GET on the same connection whose server answers later than that is delivered
//!   (`200 54 - - ----`), and so is a response dripping past it;
//! - the connection is let go two `timeout client` after its last stream (GOAWAY, GOAWAY
//!   and close), as when it served one stream.
//!
//! - a stalled upload waits on its client even when `timeout server` is the shorter (no 504
//!   at `timeout server`), and an answer the server gave before the upload ended is logged
//!   `200 54 - - cL--` at `timeout client` (T305 item 2).
//!
//! Before, the connection's one timer ran for all its streams: the stalled upload held it
//! (no 400, the connection sent its GOAWAY at `timeout client` and closed at the next), and a
//! response dripping on another stream re-armed it, so the upload never timed out.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The binary under test, or the oracle with `T280_ORACLE=/path/to/haproxy`.
fn binary() -> String {
    std::env::var("T280_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string())
}

/// How long the server takes over `/slow`.
const SLOW: Duration = Duration::from_millis(2000);

/// A server: `/slow` answers `hello` after [`SLOW`]; `/drip` sends 30 x 100 bytes, one
/// every 100 ms; `POST /early` answers `hello` at once and reads the rest; another POST
/// waits for its body (or the close) and answers nothing.
fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = l.local_addr().expect("addr").port();
    thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(20))).ok();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                if buf.starts_with(b"GET /slow") {
                    thread::sleep(SLOW);
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
                } else if buf.starts_with(b"POST /early") {
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
                    while matches!(c.read(&mut tmp), Ok(n) if n > 0) {}
                    return;
                } else if buf.starts_with(b"GET /drip") {
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n");
                    for _ in 0..30 {
                        if c.write_all(&[b'y'; 100]).is_err() {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                } else {
                    let _ = c.read(&mut tmp);
                }
                thread::sleep(Duration::from_secs(1));
            });
        }
    });
    port
}

struct Proxy {
    child: Child,
    port: u16,
    log: Arc<Mutex<String>>,
    _dir: tempfile::TempDir,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

impl Proxy {
    /// The log lines so far.
    fn log(&self) -> String {
        self.log.lock().expect("log").clone()
    }
}

/// The proxy, `timeout client 1s`, `timeout server 10s`, logging to stderr; `bind_extra`
/// after the bind address (`proto h2` for cleartext HTTP/2).
fn start(bind_extra: &str) -> Proxy {
    start_with(bind_extra, "1s", "10s")
}

/// [`start`] with these `timeout client` and `timeout server`.
fn start_with(bind_extra: &str, client: &str, server: &str) -> Proxy {
    let be = backend();
    let dir = tempfile::TempDir::new().expect("dir");
    let cfg = dir.path().join("c.cfg");
    let port = common::reserve_port();
    std::fs::write(
        &cfg,
        format!(
            "global\n\tnbthread 1\n\
             defaults\n\tmode http\n\tlog stderr format raw local0\n\toption httplog\n\
             \ttimeout connect 3s\n\ttimeout client {client}\n\ttimeout server {server}\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}{bind_extra}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{be}\n"
        ),
    )
    .expect("write config");
    let mut child = Command::new(binary()).arg("-f").arg(&cfg).arg("-db").stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("spawn");
    let log = Arc::new(Mutex::new(String::new()));
    let (mut err, sink) = (child.stderr.take().expect("stderr"), Arc::clone(&log));
    thread::spawn(move || {
        let mut tmp = [0u8; 4096];
        while let Ok(n) = err.read(&mut tmp) {
            if n == 0 {
                break;
            }
            sink.lock().expect("log").push_str(&String::from_utf8_lossy(&tmp[..n]));
        }
    });
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "the proxy never listened on {port}");
    Proxy { child, port, log, _dir: dir }
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

/// A literal header field with incremental indexing, its name from the static table.
fn literal(name_idx: u8, value: &[u8]) -> Vec<u8> {
    let mut v = vec![0x40 | name_idx, u8::try_from(value.len()).expect("short")];
    v.extend_from_slice(value);
    v
}

/// `GET <path>`, `:authority x`.
fn get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86];
    v.extend(literal(4, path.as_bytes()));
    v.extend(literal(1, b"x"));
    v
}

/// `POST /up`, `content-length: 10`.
fn post() -> Vec<u8> {
    post_to("/up")
}

/// `POST <path>`, `content-length: 10`.
fn post_to(path: &str) -> Vec<u8> {
    let mut v = vec![0x83, 0x86];
    v.extend(literal(4, path.as_bytes()));
    v.extend(literal(1, b"x"));
    v.extend(literal(28, b"10"));
    v
}

/// The `:status` of a response header block: an indexed static entry or a literal one.
fn status(block: &[u8]) -> u16 {
    match block.first() {
        Some(&b) if (0x88..=0x8e).contains(&b) => [200, 204, 206, 304, 400, 404, 500][usize::from(b - 0x88)],
        Some(&b) if (b & 0xc0 == 0x40 && b & 0x3f == 8) || b == 0x08 || b == 0x18 => {
            let n = usize::from(block[1] & 0x7f);
            String::from_utf8_lossy(&block[2..2 + n]).parse().unwrap_or(0)
        }
        _ => 0,
    }
}

/// What came on a stream, and when (since the requests were sent).
#[derive(Debug, Default)]
struct Stream {
    status: u16,
    data: usize,
    end: Option<Duration>,
    rst: Option<(u32, Duration)>,
}

/// Opens a connection, sends `requests` after the preface and reads for `limit`: each
/// stream's frames, and when the connection ended.
fn exchange(p: &Proxy, requests: &[u8], limit: Duration) -> (std::collections::BTreeMap<u32, Stream>, Option<Duration>) {
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    hello.extend(frame(0x04, 0, 0, &[]));
    hello.extend_from_slice(requests);
    s.write_all(&hello).expect("send");
    let t0 = Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(20))).ok();
    let (mut buf, mut tmp) = (Vec::new(), [0u8; 16384]);
    let mut streams = std::collections::BTreeMap::<u32, Stream>::new();
    let mut closed = None;
    while t0.elapsed() < limit && closed.is_none() {
        match s.read(&mut tmp) {
            Ok(0) => closed = Some(t0.elapsed()),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => closed = Some(t0.elapsed()),
        }
        while buf.len() >= 9 {
            let len = (usize::from(buf[0]) << 16) | (usize::from(buf[1]) << 8) | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let (ty, flags) = (buf[3], buf[4]);
            let sid = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            let payload = buf[9..9 + len].to_vec();
            buf.drain(..9 + len);
            if ty == 0x04 && flags & 1 == 0 {
                let _ = s.write_all(&frame(0x04, 1, 0, &[]));
            }
            if sid == 0 {
                continue;
            }
            let st = streams.entry(sid).or_default();
            match ty {
                0x01 => st.status = status(&payload),
                0x00 => st.data += len,
                0x03 => st.rst = Some((u32::from_be_bytes(payload[..4].try_into().expect("rst")), t0.elapsed())),
                _ => {}
            }
            if matches!(ty, 0x00 | 0x01) && flags & 1 != 0 {
                st.end = Some(t0.elapsed());
            }
        }
    }
    (streams, closed)
}

/// The log line of the request `what`.
fn log_line(p: &Proxy, what: &str) -> String {
    let log = p.log();
    log.lines().find(|l| l.contains(what)).unwrap_or_else(|| panic!("no log line for {what}: {log}")).to_string()
}

/// A POST stalled after its head times out alone, at its own `timeout client`: 400, the
/// error page, `RST_STREAM NO_ERROR`, `cH--`. The GET beside it, whose response comes
/// later than that, is delivered.
#[test]
fn a_stalled_upload_times_out_alone_and_the_slow_response_beside_it_is_delivered() {
    let p = start(" proto h2");
    let mut req = frame(0x01, 0x05, 1, &get("/slow"));
    req.extend(frame(0x01, 0x04, 3, &post()));
    let (streams, closed) = exchange(&p, &req, Duration::from_secs(4));
    let (get, up) = (&streams[&1], &streams.get(&3).unwrap_or_else(|| panic!("nothing on stream 3: {streams:?}")));
    assert_eq!(up.status, 400, "{streams:?}");
    assert_eq!(up.data, 90, "the 400 page: {streams:?}");
    let (code, at) = up.rst.unwrap_or_else(|| panic!("no RST_STREAM on stream 3: {streams:?}"));
    assert_eq!(code, 0, "RST_STREAM NO_ERROR: {streams:?}");
    assert!(at > Duration::from_millis(800) && at < Duration::from_millis(1600), "stream 3 times out at timeout client: {streams:?}");
    assert_eq!((get.status, get.data), (200, 5), "{streams:?} closed {closed:?}");
    assert!(get.end.is_some_and(|t| t >= SLOW), "{streams:?}");
    assert!(closed.is_none_or(|t| t > SLOW + Duration::from_millis(1500)), "the connection outlives its last stream by two timeout client: {closed:?}");
    thread::sleep(Duration::from_millis(200));
    assert!(log_line(&p, "\"POST ").contains(" 400 0 - - cH-- "), "{}", p.log());
    assert!(log_line(&p, "\"GET ").contains(" 200 54 - - ---- "), "{}", p.log());
}

/// The other way round: a response dripping on stream 1 (each piece was progress on the
/// connection and re-armed its one timer) does not keep a stalled upload on stream 3 from
/// timing out.
#[test]
fn a_dripping_response_does_not_keep_a_stalled_upload_alive() {
    let p = start(" proto h2");
    let mut req = frame(0x01, 0x05, 1, &get("/drip"));
    req.extend(frame(0x01, 0x04, 3, &post()));
    let (streams, _) = exchange(&p, &req, Duration::from_secs(4));
    let up = streams.get(&3).unwrap_or_else(|| panic!("nothing on stream 3: {streams:?}"));
    assert_eq!((up.status, up.data), (400, 90), "{streams:?}");
    assert!(up.rst.is_some_and(|(c, t)| c == 0 && t < Duration::from_millis(1600)), "{streams:?}");
    assert_eq!((streams[&1].status, streams[&1].data), (200, 3000), "{streams:?}");
}

/// The same timeout on HTTP/1: `HAProxy` answers 400 and logs `cH--` (Alcyon closed
/// without a response and logged `-1`).
#[test]
fn a_stalled_http1_upload_gets_a_400_at_timeout_client() {
    let p = start("");
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
    s.write_all(b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc").expect("send");
    s.set_read_timeout(Some(Duration::from_secs(4))).ok();
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    assert!(got.starts_with(b"HTTP/1.1 400 "), "{}", String::from_utf8_lossy(&got));
    thread::sleep(Duration::from_millis(200));
    assert!(log_line(&p, "\"POST ").contains(" 400 0 - - cH-- "), "{}", p.log());
}

/// A response the stream's flow-control window holds (the client gave it 100 bytes) times
/// out alone at `timeout client` though its server still sends: `RST_STREAM CANCEL`, its
/// server connection reset, `200 152 - - cD--`. The stream beside it is delivered. (The
/// server's bytes re-armed the stream's timer, and the stream lived on with the
/// connection.)
#[test]
fn a_response_held_by_its_window_times_out_alone() {
    let p = start(" proto h2");
    // SETTINGS_INITIAL_WINDOW_SIZE 100.
    let mut req = frame(0x04, 0, 0, &[0, 4, 0, 0, 0, 100]);
    req.extend(frame(0x01, 0x05, 1, &get("/drip")));
    req.extend(frame(0x01, 0x05, 3, &get("/slow")));
    let (streams, _) = exchange(&p, &req, Duration::from_millis(2600));
    let held = &streams[&1];
    assert_eq!((held.status, held.data), (200, 100), "{streams:?}");
    let (code, at) = held.rst.unwrap_or_else(|| panic!("no RST_STREAM on stream 1: {streams:?}"));
    assert_eq!(code, 8, "RST_STREAM CANCEL: {streams:?}");
    assert!(at > Duration::from_millis(800) && at < Duration::from_millis(1600), "{streams:?}");
    assert_eq!((streams[&3].status, streams[&3].data), (200, 5), "{streams:?}");
    thread::sleep(Duration::from_millis(200));
    assert!(log_line(&p, "/drip").contains(" 200 152 - - cD-- "), "{}", p.log());
}

/// A stalled upload waits on its client, not its server, whichever timeout is shorter:
/// `HAProxy`'s server side does not time out a read while the request is still coming
/// (`SE_FL_EXP_NO_DATA`, set by the client's mux until the request's end, read by
/// `sc_rcv_may_expire`). With `timeout client 2s` and `timeout server 500ms`, it answers at
/// 2 s: 400, the error page, `RST_STREAM NO_ERROR`, `cH--` (Alcyon sent a 504 at 500 ms and
/// logged `sH--`, T305 item 2).
#[test]
fn a_stalled_upload_waits_for_timeout_client_not_timeout_server() {
    let p = start_with(" proto h2", "2s", "500ms");
    let mut req = frame(0x01, 0x04, 1, &post());
    req.extend(frame(0x00, 0, 1, b"abc"));
    let (streams, closed) = exchange(&p, &req, Duration::from_millis(2600));
    let up = streams.get(&1).unwrap_or_else(|| panic!("nothing on stream 1: {streams:?} closed {closed:?}"));
    assert_eq!((up.status, up.data), (400, 90), "{streams:?}");
    let (code, at) = up.rst.unwrap_or_else(|| panic!("no RST_STREAM on stream 1: {streams:?}"));
    assert_eq!(code, 0, "RST_STREAM NO_ERROR: {streams:?}");
    assert!(at > Duration::from_millis(1800) && at < Duration::from_millis(2500), "{streams:?}");
    assert!(closed.is_none(), "the connection outlives the stream: {closed:?}");
    thread::sleep(Duration::from_millis(200));
    assert!(log_line(&p, "\"POST ").contains(" 400 0 - - cH-- "), "{}", p.log());
}

/// The same on HTTP/1: 400 at `timeout client`, `cH--`.
#[test]
fn a_stalled_http1_upload_waits_for_timeout_client_not_timeout_server() {
    let p = start_with("", "2s", "500ms");
    let mut s = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
    s.write_all(b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc").expect("send");
    let t0 = Instant::now();
    s.set_read_timeout(Some(Duration::from_secs(4))).ok();
    let mut got = [0u8; 64];
    let n = s.read(&mut got).unwrap_or(0);
    let at = t0.elapsed();
    assert!(got[..n].starts_with(b"HTTP/1.1 400 "), "{} at {at:?}", String::from_utf8_lossy(&got[..n]));
    assert!(at > Duration::from_millis(1800) && at < Duration::from_millis(2500), "{at:?}");
    thread::sleep(Duration::from_millis(200));
    assert!(log_line(&p, "\"POST ").contains(" 400 0 - - cH-- "), "{}", p.log());
}

/// A server that answers before the upload ends: the response is delivered at once, and
/// the stalled upload ends at `timeout client` with `RST_STREAM NO_ERROR` (no `CANCEL`, its
/// server connection closed, not reset), logged `200 54 - - cL--`, whichever of `timeout
/// client` and `timeout server` is shorter. (Alcyon logged `sD--` with `timeout server` the
/// shorter, and reset the stream with `CANCEL`, `cD--`, with `timeout client` the shorter.)
#[test]
fn an_early_answer_to_a_stalled_upload_ends_at_timeout_client() {
    for (client, server) in [("1s", "300ms"), ("1s", "3s")] {
        let p = start_with(" proto h2", client, server);
        let mut req = frame(0x01, 0x04, 1, &post_to("/early"));
        req.extend(frame(0x00, 0, 1, b"abc"));
        let (streams, closed) = exchange(&p, &req, Duration::from_millis(1600));
        let up = streams.get(&1).unwrap_or_else(|| panic!("{client}/{server}: nothing on stream 1: {streams:?} closed {closed:?}"));
        assert_eq!((up.status, up.data), (200, 5), "{client}/{server}: {streams:?}");
        assert!(up.end.is_some_and(|t| t < Duration::from_millis(300)), "{client}/{server}: {streams:?}");
        let (code, at) = up.rst.unwrap_or_else(|| panic!("{client}/{server}: no RST_STREAM on stream 1: {streams:?}"));
        assert_eq!(code, 0, "{client}/{server}: RST_STREAM NO_ERROR: {streams:?}");
        assert!(at > Duration::from_millis(800) && at < Duration::from_millis(1400), "{client}/{server}: {streams:?}");
        thread::sleep(Duration::from_millis(200));
        assert!(log_line(&p, "\"POST ").contains(" 200 54 - - cL-- "), "{client}/{server}: {}", p.log());
    }
}

/// The same on HTTP/1: `200 54 - - cL--` at `timeout client`.
#[test]
fn an_early_http1_answer_to_a_stalled_upload_ends_at_timeout_client() {
    for (client, server) in [("1s", "300ms"), ("1s", "3s")] {
        let p = start_with("", client, server);
        let mut s = TcpStream::connect(("127.0.0.1", p.port)).expect("connect");
        s.write_all(b"POST /early HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc").expect("send");
        s.set_read_timeout(Some(Duration::from_millis(1500))).ok();
        let mut got = [0u8; 64];
        let n = s.read(&mut got).unwrap_or(0);
        assert!(got[..n].starts_with(b"HTTP/1.1 200 "), "{client}/{server}: {}", String::from_utf8_lossy(&got[..n]));
        thread::sleep(Duration::from_millis(1300));
        assert!(log_line(&p, "\"POST ").contains(" 200 54 - - cL-- "), "{client}/{server}: {}", p.log());
    }
}
