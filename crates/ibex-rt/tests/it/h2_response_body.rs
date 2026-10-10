// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 response bodies through an `h2` bind, against the real daemon (T106).
//!
//! A body larger than the response buffer (16 KB) or the initial flow-control window
//! (64 KB - 1) must arrive whole, byte for byte, with END_STREAM on the last DATA frame
//! and nowhere else; and the daemon must not send more DATA than the client's windows
//! allow. The client here is a raw frame reader so it sees what curl would only summarise.

use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

/// The byte at position `i` of a body whose pattern is `salt`: position-dependent, so a
/// dropped, repeated or reordered span shows.
fn pat(salt: u8, i: usize) -> u8 {
    u8::try_from((i.wrapping_mul(31) ^ (i >> 8) ^ usize::from(salt)) & 0xff).unwrap_or(0)
}

fn body(salt: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| pat(salt, i)).collect()
}

/// A backend serving `/<len>/<salt>/<cl|chunked>`.
fn spawn_backend() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    while let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..p + 4).collect();
                        let head = String::from_utf8_lossy(&head).into_owned();
                        let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                        let mut it = path.trim_start_matches('/').split('/');
                        let len: usize = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        let salt: u8 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        let mode = it.next().unwrap_or("cl");
                        let chunked = mode == "chunked" || mode == "badchunk";
                        let data = body(salt, len);
                        let mut out = Vec::new();
                        if chunked {
                            out.extend_from_slice(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                            for ch in data.chunks(5000) {
                                out.extend_from_slice(format!("{:x}\r\n", ch.len()).as_bytes());
                                out.extend_from_slice(ch);
                                out.extend_from_slice(b"\r\n");
                            }
                            out.extend_from_slice(if mode == "badchunk" { b"zz\r\n" } else { b"0\r\n\r\n" });
                        } else if mode == "close" {
                            // No length: the body ends when the server closes.
                            out.extend_from_slice(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
                            out.extend_from_slice(&data);
                        } else {
                            // `cut` promises twice the length it sends, then closes.
                            let promised = if mode == "cut" { len * 2 } else { len };
                            out.extend_from_slice(
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {promised}\r\n\r\n").as_bytes(),
                            );
                            out.extend_from_slice(&data);
                        }
                        if c.write_all(&out).is_err() || mode == "close" || mode == "cut" || mode == "badchunk" {
                            return;
                        }
                    }
                    match c.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
            });
        }
    });
    port
}

fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame fits");
    let mut v = Vec::with_capacity(9 + payload.len());
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// `GET <path>` with static-table indices and literal path/authority (no Huffman).
fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86, 0x04, u8::try_from(path.len()).expect("short path")];
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

fn start(backend_port: u16) -> (Daemon, u16, std::path::PathBuf) {
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2body_{}_{port}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 20s\n\t\
             timeout server 20s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");
    let d = Daemon(
        Command::new(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(common::wait_listening(([127, 0, 0, 1], port).into()), "daemon never listened");
    (d, port, cfg)
}

#[derive(Default, Debug)]
struct StreamSeen {
    headers: bool,
    headers_end_stream: bool,
    data: Vec<u8>,
    ended: bool,
    /// DATA frames (or HEADERS) arriving after END_STREAM.
    after_end: bool,
    reset: bool,
}

struct Client {
    s: TcpStream,
    buf: Vec<u8>,
    streams: std::collections::BTreeMap<u32, StreamSeen>,
    /// Send WINDOW_UPDATEs as DATA arrives.
    updates: bool,
}

impl Client {
    fn connect(port: u16, updates: bool) -> Self {
        let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(100))).ok();
        s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
        s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
        Client { s, buf: Vec::new(), streams: std::collections::BTreeMap::new(), updates }
    }

    fn get(&mut self, sid: u32, path: &str) {
        self.s.write_all(&frame(0x01, 0x05, sid, &hpack_get(path))).expect("headers");
    }

    fn window_update(&mut self, sid: u32, inc: u32) {
        self.s.write_all(&frame(0x08, 0, sid, &inc.to_be_bytes())).expect("window update");
    }

    /// Reads and processes frames for up to `dur`, or until every stream in `until` ended.
    fn pump(&mut self, dur: Duration, until: &[u32]) {
        let deadline = Instant::now() + dur;
        let mut tmp = vec![0u8; 65536];
        while Instant::now() < deadline {
            if !until.is_empty() && until.iter().all(|i| self.streams.get(i).is_some_and(|s| s.ended)) {
                return;
            }
            match self.s.read(&mut tmp) {
                Ok(0) => return,
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(_) => {}
            }
            self.drain();
        }
    }

    /// Reads until stream `sid` is reset or ended (or `dur` passes), then a further 300 ms
    /// for anything the daemon sends after that, which the caller's checks would see.
    fn pump_until_closed(&mut self, dur: Duration, sid: u32) {
        let deadline = Instant::now() + dur;
        while Instant::now() < deadline && !self.streams.get(&sid).is_some_and(|s| s.reset || s.ended) {
            self.pump(Duration::from_millis(50), &[]);
        }
        self.pump(Duration::from_millis(300), &[]);
    }

    fn drain(&mut self) {
        while self.buf.len() >= 9 {
            let len = (usize::from(self.buf[0]) << 16) | (usize::from(self.buf[1]) << 8) | usize::from(self.buf[2]);
            if self.buf.len() < 9 + len {
                break;
            }
            let ftype = self.buf[3];
            let flags = self.buf[4];
            let sid = u32::from_be_bytes([self.buf[5] & 0x7f, self.buf[6], self.buf[7], self.buf[8]]);
            let payload: Vec<u8> = self.buf[9..9 + len].to_vec();
            self.buf.drain(..9 + len);
            match ftype {
                0x04 if flags & 1 == 0 => {
                    self.s.write_all(&frame(0x04, 1, 0, &[])).ok();
                }
                0x01 => {
                    let st = self.streams.entry(sid).or_default();
                    st.after_end |= st.ended;
                    st.headers = true;
                    st.headers_end_stream = flags & 1 != 0;
                    st.ended |= flags & 1 != 0;
                }
                0x00 => {
                    let st = self.streams.entry(sid).or_default();
                    st.after_end |= st.ended;
                    st.data.extend_from_slice(&payload);
                    st.ended |= flags & 1 != 0;
                    if self.updates && len > 0 {
                        let inc = u32::try_from(len).expect("small");
                        self.window_update(0, inc);
                        self.window_update(sid, inc);
                    }
                }
                0x03 => self.streams.entry(sid).or_default().reset = true,
                _ => {}
            }
        }
    }
}

fn check(c: &Client, sid: u32, salt: u8, len: usize) {
    let st = c.streams.get(&sid).unwrap_or_else(|| panic!("stream {sid}: nothing received"));
    assert!(st.headers, "stream {sid}: no HEADERS");
    assert!(!st.reset, "stream {sid}: RST_STREAM received after {} bytes", st.data.len());
    assert!(!st.headers_end_stream, "stream {sid}: END_STREAM on HEADERS of a {len}-byte body");
    assert!(!st.after_end, "stream {sid}: frames after END_STREAM");
    assert!(
        st.ended && st.data.len() == len,
        "stream {sid}: got {} of {len} bytes, ended={}",
        st.data.len(),
        st.ended
    );
    let want = body(salt, len);
    if let Some(i) = st.data.iter().zip(&want).position(|(a, b)| a != b) {
        panic!("stream {sid}: first wrong byte at offset {i}");
    }
}

fn single(len: usize, mode: &str) {
    let backend = spawn_backend();
    let (_d, port, cfg) = start(backend);
    let mut c = Client::connect(port, true);
    c.get(1, &format!("/{len}/7/{mode}"));
    c.pump(Duration::from_secs(15), &[1]);
    let _ = std::fs::remove_file(&cfg);
    check(&c, 1, 7, len);
}

#[test]
fn h2_body_16k_plus_1_content_length() {
    single(16 * 1024 + 1, "cl");
}
#[test]
fn h2_body_16k_plus_1_chunked() {
    single(16 * 1024 + 1, "chunked");
}
#[test]
fn h2_body_64k_plus_1_content_length() {
    single(64 * 1024 + 1, "cl");
}
#[test]
fn h2_body_64k_plus_1_chunked() {
    single(64 * 1024 + 1, "chunked");
}
#[test]
fn h2_body_without_length_ends_with_the_server_close() {
    single(200_000, "close");
}

/// The server closes in the middle of a body: the client must be told by RST_STREAM, not
/// by an END_STREAM that says the truncated body is complete.
#[test]
fn h2_body_cut_short_is_reset_not_ended() {
    let backend = spawn_backend();
    let (_d, port, cfg) = start(backend);
    let mut c = Client::connect(port, true);
    c.get(1, "/50000/7/cut");
    c.pump_until_closed(Duration::from_secs(5), 1);
    let _ = std::fs::remove_file(&cfg);
    let st = c.streams.get(&1).expect("stream 1 answered");
    assert!(st.reset, "no RST_STREAM for a body cut short: {st:?}");
    assert!(!st.ended, "END_STREAM on a body cut short: {} bytes", st.data.len());
    assert_eq!(st.data, body(7, 50000)[..st.data.len()], "bytes before the reset are the body's");
}

#[test]
fn h2_body_1m_content_length() {
    single(1 << 20, "cl");
}
#[test]
fn h2_body_1m_chunked() {
    single(1 << 20, "chunked");
}

/// Two streams opened together, each with a large body: both arrive whole.
#[test]
fn h2_two_concurrent_large_bodies() {
    let backend = spawn_backend();
    let (_d, port, cfg) = start(backend);
    let mut c = Client::connect(port, true);
    let mut both = frame(0x01, 0x05, 1, &hpack_get("/300000/1/cl"));
    both.extend_from_slice(&frame(0x01, 0x05, 3, &hpack_get("/200000/2/chunked")));
    c.s.write_all(&both).expect("both requests");
    c.pump(Duration::from_secs(20), &[1, 3]);
    let _ = std::fs::remove_file(&cfg);
    check(&c, 1, 1, 300_000);
    check(&c, 3, 2, 200_000);
}

/// A client that never opens its window gets at most the initial window of DATA, then the
/// rest once it does.
#[test]
fn h2_body_respects_client_flow_control() {
    let backend = spawn_backend();
    let (_d, port, cfg) = start(backend);
    let mut c = Client::connect(port, false);
    c.get(1, "/1000000/9/cl");
    c.pump(Duration::from_secs(2), &[1]);
    let got = c.streams.get(&1).map_or(0, |s| s.data.len());
    let ended = c.streams.get(&1).is_some_and(|s| s.ended);
    assert!(got <= 65535, "sent {got} DATA bytes against a 65535-byte window");
    assert!(!ended, "END_STREAM before the client opened its window");
    assert!(got > 0, "nothing sent within the window");
    // Now open the windows, generously, and keep topping them up.
    c.updates = true;
    c.window_update(0, 1 << 20);
    c.window_update(1, 1 << 20);
    c.pump(Duration::from_secs(15), &[1]);
    let _ = std::fs::remove_file(&cfg);
    check(&c, 1, 9, 1_000_000);
}

/// A client with huge windows that does not read for a while: the daemon stops queueing
/// DATA once its socket is full instead of buffering the whole body, and everything still
/// arrives, in order, when the client reads.
#[test]
fn h2_body_to_a_client_that_stops_reading_arrives_whole() {
    let backend = spawn_backend();
    let (_d, port, cfg) = start(backend);
    let len = 8 << 20;
    let mut c = Client::connect(port, true);
    c.window_update(0, 1 << 30);
    c.get(1, &format!("/{len}/3/cl"));
    c.window_update(1, 1 << 30);
    thread::sleep(Duration::from_millis(2500));
    c.pump(Duration::from_secs(60), &[1]);
    let _ = std::fs::remove_file(&cfg);
    check(&c, 1, 3, len);
}

/// The server's chunked body is malformed: the stream is reset, never ended as if whole.
#[test]
fn h2_malformed_chunked_body_is_reset_not_ended() {
    let backend = spawn_backend();
    let (_d, port, cfg) = start(backend);
    let mut c = Client::connect(port, true);
    c.get(1, "/30000/7/badchunk");
    c.pump_until_closed(Duration::from_secs(5), 1);
    let _ = std::fs::remove_file(&cfg);
    let st = c.streams.get(&1).expect("stream 1 answered");
    assert!(st.reset, "no RST_STREAM for a malformed chunked body: {st:?}");
    assert!(!st.ended, "END_STREAM on a malformed chunked body");
}
