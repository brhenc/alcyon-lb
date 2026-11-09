// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! In-process servers that record what reached them, on which TCP connection, and when.
//!
//! The servers tell the test when something has happened (a request head arrived, half a
//! body arrived) so the test can migrate while that state is really held, rather than
//! guessing with a sleep.

use super::pattern::{self, Checker};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Bytes per write and pause between writes while a backend streams "steadily": about
/// 1 MB/s, so a stream is still flowing seconds later, while the migration happens.
pub const STEADY_CHUNK: usize = 4096;
pub const STEADY_PAUSE: Duration = Duration::from_millis(4);
/// The longest any backend waits for the test to release it. A test that forgets to
/// release fails on its own timeouts long before this.
const GATE_MAX: Duration = Duration::from_secs(60);

/// A one-way latch the test opens.
#[derive(Default)]
pub struct Gate {
    open: Mutex<bool>,
    cv: Condvar,
}

impl Gate {
    pub fn open(&self) {
        *self.open.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.cv.notify_all();
    }
    #[must_use]
    pub fn is_open(&self) -> bool {
        *self.open.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Waits until open, or `GATE_MAX`.
    pub fn wait(&self) {
        let g = self.open.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = self.cv.wait_timeout_while(g, GATE_MAX, |o| !*o);
    }
}

/// Something the HTTP backend observed.
#[derive(Clone, Debug)]
pub enum Event {
    /// A request head, complete, on backend connection `conn`.
    Head { conn: usize, path: String, head: String },
    /// `received` bytes of the request body for `path` have arrived on `conn`.
    Body { conn: usize, path: String, received: u64 },
}

/// What the HTTP backend wrote for one streamed response.
#[derive(Clone, Debug, Default)]
pub struct Streamed {
    /// Shown in failure messages (through `Debug`).
    #[allow(dead_code)]
    pub conn: usize,
    pub path: String,
    /// Body bytes written (payload only, without chunk framing).
    pub written: u64,
    /// Whether the whole body was written.
    pub finished: bool,
    pub error: Option<String>,
}

#[derive(Default)]
struct Shared {
    accepted: AtomicUsize,
    events: Mutex<Vec<Event>>,
    events_cv: Condvar,
    streams: Mutex<HashMap<(usize, String), Streamed>>,
    /// Released by [`HttpBackend::release_holds`]: `/hold` answers.
    holds: Gate,
    /// Released by [`HttpBackend::release_streams`]: streams stop pacing and finish.
    streams_go: Gate,
}

/// An HTTP/1.1 origin server. What it does depends on the request path:
///
/// * `/stream?len=N&seed=S[&fast=1]` -- a `Content-Length: N` body, bytes `0..N` of
///   stream `S`. Paced at about 1 MB/s until [`HttpBackend::release_streams`] (unless
///   `fast=1`), then at full speed.
/// * `/chunked?len=N&seed=S` -- the same body, chunked, in chunks of varying size.
/// * `/hold...` -- an echo, sent only after [`HttpBackend::release_holds`].
/// * anything else -- an echo.
///
/// An echo's body is the request head exactly as received. Its headers report the
/// backend connection (`X-Conn`), the `X-Gen` request header the proxy added (`X-Seen-Gen`),
/// every request header whose name starts `x-t` (`X-Echo-<name>`), and the request body
/// length and whether it was bytes `0..len` of stream `x-body-seed` (`X-Body: <len> ok|bad`).
#[derive(Clone)]
pub struct HttpBackend {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
}

impl HttpBackend {
    #[must_use]
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
        let addr = listener.local_addr().expect("addr");
        let shared = Arc::new(Shared::default());
        let sh = Arc::clone(&shared);
        thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(s) = s else { continue };
                let id = sh.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                let sh = Arc::clone(&sh);
                thread::spawn(move || serve_conn(&sh, s, id));
            }
        });
        Self { addr, shared }
    }

    /// TCP connections accepted so far.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    pub fn release_holds(&self) {
        self.shared.holds.open();
    }

    pub fn release_streams(&self) {
        self.shared.streams_go.open();
    }

    /// Waits up to `within` for an event matching `pred`.
    pub fn wait_event(&self, within: Duration, pred: impl Fn(&Event) -> bool) -> Option<Event> {
        let deadline = Instant::now() + within;
        let mut g = self.shared.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(e) = g.iter().find(|e| pred(e)) {
                return Some(e.clone());
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            g = self.shared.events_cv.wait_timeout(g, deadline - now).map_or_else(|e| e.into_inner().0, |r| r.0);
        }
    }

    /// The most request-body bytes reported so far for a path starting with `prefix`.
    #[must_use]
    pub fn body_received(&self, prefix: &str) -> u64 {
        let g = self.shared.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.iter()
            .filter_map(|e| match e {
                Event::Body { path, received, .. } if path.starts_with(prefix) => Some(*received),
                _ => None,
            })
            .max()
            .unwrap_or(0)
    }

    /// Waits for a complete request head for a path starting with `prefix`.
    ///
    /// # Panics
    /// When none arrives within `within`.
    pub fn wait_head(&self, prefix: &str, within: Duration) -> (usize, String) {
        match self.wait_event(within, |e| matches!(e, Event::Head { path, .. } if path.starts_with(prefix))) {
            Some(Event::Head { conn, head, .. }) => (conn, head),
            _ => panic!("the backend never received a request head for {prefix} within {within:?}"),
        }
    }

    /// The streamed response for `path` on any connection.
    #[must_use]
    pub fn streamed(&self, path_prefix: &str) -> Vec<Streamed> {
        let g = self.shared.streams.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.values().filter(|s| s.path.starts_with(path_prefix)).cloned().collect()
    }

    /// Waits until the stream for `path_prefix` is finished or has failed.
    pub fn wait_streamed(&self, path_prefix: &str, within: Duration) -> Vec<Streamed> {
        let deadline = Instant::now() + within;
        loop {
            let v = self.streamed(path_prefix);
            if !v.is_empty() && v.iter().all(|s| s.finished || s.error.is_some()) || Instant::now() >= deadline {
                return v;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn push(sh: &Shared, e: Event) {
    sh.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(e);
    sh.events_cv.notify_all();
}

/// Reads until `buf` holds a complete head; returns its length, or None at EOF.
fn read_head(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<usize> {
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(p + 4);
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

fn query(path: &str, key: &str) -> Option<u64> {
    let q = path.split_once('?')?.1;
    q.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('=')).and_then(|v| v.parse().ok())
}

fn serve_conn(sh: &Shared, mut s: TcpStream, id: usize) {
    let _ = s.set_read_timeout(Some(GATE_MAX));
    let mut buf = Vec::new();
    loop {
        let Some(hlen) = read_head(&mut s, &mut buf) else { return };
        let head_bytes: Vec<u8> = buf.drain(..hlen).collect();
        let head = String::from_utf8_lossy(&head_bytes).into_owned();
        let mut lines = head.split("\r\n");
        let reqline = lines.next().unwrap_or("");
        let path = reqline.split(' ').nth(1).unwrap_or("").to_string();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let hdr = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
        push(sh, Event::Head { conn: id, path: path.clone(), head: head.clone() });

        // The request body, checked against `x-body-seed` as it arrives.
        let seed = hdr("x-body-seed").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut checker = Checker::new(seed);
        let chunked = hdr("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
        let body_ok = if chunked {
            read_chunked_body(&mut s, &mut buf, &mut checker, sh, id, &path)
        } else {
            let len = hdr("content-length").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            read_cl_body(&mut s, &mut buf, len, &mut checker, sh, id, &path)
        };
        if !body_ok {
            return;
        }

        let r = if path.starts_with("/stream") || path.starts_with("/chunked") {
            stream_response(sh, &mut s, id, &path)
        } else {
            if path.starts_with("/hold") {
                sh.holds.wait();
            }
            let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Conn: {id}\r\n", head_bytes.len());
            if let Some(g) = hdr("x-gen") {
                let _ = write!(resp, "X-Seen-Gen: {g}\r\n");
            }
            for (n, v) in headers.iter().filter(|(n, _)| n.starts_with("x-t")) {
                let _ = write!(resp, "X-Echo-{n}: {v}\r\n");
            }
            let verdict = if checker.mismatch.is_none() { "ok" } else { "bad" };
            let _ = write!(resp, "X-Body: {} {verdict}\r\n\r\n", checker.pos());
            let mut out = resp.into_bytes();
            out.extend_from_slice(&head_bytes);
            s.write_all(&out)
        };
        if r.is_err() {
            return;
        }
    }
}

/// Reports body progress after every read, so a test waiting for an exact count sees it.
fn body_progress(sh: &Shared, id: usize, path: &str, checker: &Checker, last: &mut u64) {
    if checker.pos() > *last {
        *last = checker.pos();
        push(sh, Event::Body { conn: id, path: path.to_string(), received: checker.pos() });
    }
}

fn read_cl_body(
    s: &mut TcpStream,
    buf: &mut Vec<u8>,
    len: u64,
    checker: &mut Checker,
    sh: &Shared,
    id: usize,
    path: &str,
) -> bool {
    let mut last = 0;
    let mut tmp = [0u8; 16384];
    while checker.pos() < len {
        if buf.is_empty() {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return false,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        let take = usize::try_from((len - checker.pos()).min(buf.len() as u64)).unwrap_or(0);
        let part: Vec<u8> = buf.drain(..take).collect();
        checker.feed(&part);
        body_progress(sh, id, path, checker, &mut last);
    }
    if len > 0 {
        push(sh, Event::Body { conn: id, path: path.to_string(), received: checker.pos() });
    }
    true
}

fn read_line(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(p) = buf.windows(2).position(|w| w == b"\r\n") {
            let line: Vec<u8> = buf.drain(..p + 2).collect();
            return Some(String::from_utf8_lossy(&line[..p]).into_owned());
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

fn read_chunked_body(
    s: &mut TcpStream,
    buf: &mut Vec<u8>,
    checker: &mut Checker,
    sh: &Shared,
    id: usize,
    path: &str,
) -> bool {
    loop {
        let Some(line) = read_line(s, buf) else { return false };
        let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if size == 0 {
            // Trailers, then the empty line.
            loop {
                match read_line(s, buf) {
                    Some(l) if l.is_empty() => {
                        push(sh, Event::Body { conn: id, path: path.to_string(), received: checker.pos() });
                        return true;
                    }
                    Some(_) => {}
                    None => return false,
                }
            }
        }
        let end = checker.pos() + size;
        if !read_cl_body(s, buf, end, checker, sh, id, path) {
            return false;
        }
        if read_line(s, buf).is_none() {
            return false;
        }
    }
}

/// Chunk sizes for `/chunked`, cycled: odd, tiny and large, so the proxy's chunk parser is
/// caught in every state at some point.
const CHUNK_SIZES: [usize; 7] = [1, 7, 100, 4096, 333, 8000, 2];

fn stream_response(sh: &Shared, s: &mut TcpStream, id: usize, path: &str) -> std::io::Result<()> {
    let len = query(path, "len").unwrap_or(0);
    let seed = query(path, "seed").unwrap_or(0);
    let fast = query(path, "fast") == Some(1);
    let chunked = path.starts_with("/chunked");
    let key = (id, path.to_string());
    let update = |f: &dyn Fn(&mut Streamed)| {
        let mut g = sh.streams.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let e = g.entry(key.clone()).or_insert_with(|| Streamed { conn: id, path: path.to_string(), ..Streamed::default() });
        f(e);
    };
    update(&|_| {});
    let head = if chunked {
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Conn: {id}\r\n\r\n")
    } else {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nX-Conn: {id}\r\n\r\n")
    };
    if let Err(e) = s.write_all(head.as_bytes()) {
        update(&|st| st.error = Some(e.to_string()));
        return Err(e);
    }
    let mut pos = 0u64;
    let mut k = 0usize;
    let mut buf = vec![0u8; 16384];
    while pos < len {
        let paced = !fast && !sh.streams_go.is_open();
        let want = if chunked { CHUNK_SIZES[k % CHUNK_SIZES.len()] } else if paced { STEADY_CHUNK } else { 16384 };
        k += 1;
        let n = usize::try_from((len - pos).min(want as u64)).unwrap_or(0);
        pattern::fill(seed, pos, &mut buf[..n]);
        let r = if chunked {
            let mut out = format!("{n:x}\r\n").into_bytes();
            out.extend_from_slice(&buf[..n]);
            out.extend_from_slice(b"\r\n");
            s.write_all(&out)
        } else {
            s.write_all(&buf[..n])
        };
        if let Err(e) = r {
            update(&|st| st.error = Some(format!("write at body offset {pos}: {e}")));
            return Err(e);
        }
        pos += n as u64;
        update(&|st| st.written = pos);
        if paced && (!chunked || k.is_multiple_of(3)) {
            thread::sleep(STEADY_PAUSE);
        }
    }
    if chunked {
        if let Err(e) = s.write_all(b"0\r\n\r\n") {
            update(&|st| st.error = Some(e.to_string()));
            return Err(e);
        }
    }
    update(&|st| st.finished = true);
    Ok(())
}

/// What a TCP-mode backend connection saw.
#[derive(Clone, Debug, Default)]
pub struct TcpSeen {
    /// Bytes received from the client, all checked against the client's stream.
    pub received: u64,
    pub recv_error: Option<String>,
    /// Bytes sent to the client.
    pub sent: u64,
    pub send_error: Option<String>,
    /// The client's stream ended with a clean EOF.
    pub eof: bool,
}

/// A TCP server for `mode tcp`: on every connection it checks what arrives against stream
/// `up_seed` and, at the same time, sends stream `down_seed` at a steady rate until the
/// client half-closes, then half-closes too.
pub struct TcpBackend {
    pub addr: SocketAddr,
    conns: Arc<Mutex<Vec<Arc<Mutex<TcpSeen>>>>>,
}

impl TcpBackend {
    #[must_use]
    #[allow(clippy::many_single_char_names)]
    pub fn start(up_seed: u64, down_seed: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp backend");
        let addr = listener.local_addr().expect("addr");
        let conns: Arc<Mutex<Vec<Arc<Mutex<TcpSeen>>>>> = Arc::default();
        let cs = Arc::clone(&conns);
        thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(s) = s else { continue };
                let seen = Arc::new(Mutex::new(TcpSeen::default()));
                cs.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(Arc::clone(&seen));
                let done = Arc::new(AtomicBool::new(false));
                let mut r = s.try_clone().expect("clone");
                let (seen_r, done_r) = (Arc::clone(&seen), Arc::clone(&done));
                thread::spawn(move || {
                    let _ = r.set_read_timeout(Some(GATE_MAX));
                    let mut c = Checker::new(up_seed);
                    let mut buf = [0u8; 16384];
                    loop {
                        match r.read(&mut buf) {
                            Ok(0) => {
                                seen_r.lock().unwrap_or_else(std::sync::PoisonError::into_inner).eof = true;
                                break;
                            }
                            Ok(n) => {
                                c.feed(&buf[..n]);
                                let mut g = seen_r.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                g.received = c.pos();
                                if let Some(e) = c.error() {
                                    g.recv_error = Some(e);
                                    break;
                                }
                            }
                            Err(e) => {
                                seen_r.lock().unwrap_or_else(std::sync::PoisonError::into_inner).recv_error =
                                    Some(e.to_string());
                                break;
                            }
                        }
                    }
                    done_r.store(true, Ordering::SeqCst);
                });
                let mut w = s;
                thread::spawn(move || {
                    let mut pos = 0u64;
                    let mut buf = [0u8; STEADY_CHUNK];
                    while !done.load(Ordering::SeqCst) {
                        pattern::fill(down_seed, pos, &mut buf);
                        if let Err(e) = w.write_all(&buf) {
                            seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).send_error = Some(e.to_string());
                            return;
                        }
                        pos += buf.len() as u64;
                        seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).sent = pos;
                        thread::sleep(STEADY_PAUSE);
                    }
                    let _ = w.shutdown(Shutdown::Write);
                });
            }
        });
        Self { addr, conns }
    }

    /// What the connection carrying the client's stream saw: the one that received the
    /// most. Others are the proxy's connections for the probes that check it listens,
    /// which carry nothing.
    #[must_use]
    pub fn stream_conn(&self) -> Option<TcpSeen> {
        let g = self.conns.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.iter()
            .map(|c| c.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone())
            .max_by_key(|s| (s.received, s.sent))
    }

    /// How many server connections carried any client data. The client's stream must
    /// stay on exactly one.
    #[must_use]
    pub fn carrying(&self) -> usize {
        let g = self.conns.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.iter().filter(|c| c.lock().unwrap_or_else(std::sync::PoisonError::into_inner).received > 0).count()
    }
}

/// The client half of a TCP-mode stream: sends stream `up_seed` steadily and checks
/// stream `down_seed` as it arrives, each in its own thread.
pub struct TcpClient {
    pub local: SocketAddr,
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    writer: Option<thread::JoinHandle<Result<u64, String>>>,
    reader: Option<thread::JoinHandle<(u64, Result<(), String>)>>,
}

/// How a direction of a stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// A clean EOF.
    Eof,
    /// An error: a reset, or any other.
    Error(String),
    /// Nothing within the time allowed: the connection may still be open.
    Timeout,
}

impl TcpClient {
    #[must_use]
    #[allow(clippy::many_single_char_names)]
    pub fn connect(fe: SocketAddr, up_seed: u64, down_seed: u64) -> Self {
        let s = TcpStream::connect(fe).expect("connect to the TCP frontend");
        let local = s.local_addr().expect("local addr");
        let sent = Arc::new(AtomicU64::new(0));
        let received = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let mut w = s.try_clone().expect("clone");
        let (sent_w, stop_w) = (Arc::clone(&sent), Arc::clone(&stop));
        let writer = thread::spawn(move || {
            let mut pos = 0u64;
            let mut buf = [0u8; STEADY_CHUNK];
            let _ = w.set_write_timeout(Some(Duration::from_secs(20)));
            while !stop_w.load(Ordering::SeqCst) {
                pattern::fill(up_seed, pos, &mut buf);
                w.write_all(&buf).map_err(|e| format!("client write at {pos}: {e}"))?;
                pos += buf.len() as u64;
                sent_w.store(pos, Ordering::SeqCst);
                thread::sleep(STEADY_PAUSE);
            }
            w.shutdown(Shutdown::Write).map_err(|e| format!("client shutdown: {e}"))?;
            Ok(pos)
        });
        let mut r = s;
        let recv_r = Arc::clone(&received);
        let reader = thread::spawn(move || {
            let _ = r.set_read_timeout(Some(Duration::from_secs(20)));
            let mut c = Checker::new(down_seed);
            let mut buf = [0u8; 16384];
            loop {
                match r.read(&mut buf) {
                    Ok(0) => return (c.pos(), Ok(())),
                    Ok(n) => {
                        c.feed(&buf[..n]);
                        recv_r.store(c.pos(), Ordering::SeqCst);
                        if let Some(e) = c.error() {
                            return (c.pos(), Err(format!("client received a wrong byte: {e}")));
                        }
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                        return (c.pos(), Err(TIMED_OUT.to_string()));
                    }
                    Err(e) => return (c.pos(), Err(format!("client read: {e} ({:?})", e.kind()))),
                }
            }
        });
        Self { local, sent, received, stop, writer: Some(writer), reader: Some(reader) }
    }

    #[must_use]
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::SeqCst)
    }
    #[must_use]
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::SeqCst)
    }
    /// Whether the reading side has finished (EOF or error).
    #[must_use]
    pub fn reader_done(&self) -> bool {
        self.reader.as_ref().is_none_or(thread::JoinHandle::is_finished)
    }

    /// Waits until both directions have moved at least `more` bytes past `(sent, received)`,
    /// or the reader ends, or `within` passes. Returns whether they did.
    pub fn wait_progress(&self, from: (u64, u64), more: u64, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.sent() >= from.0 + more && self.received() >= from.1 + more {
                return true;
            }
            if self.reader_done() {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        false
    }

    /// Stops sending, half-closes, and waits for the reader: returns (bytes sent, writer
    /// result, bytes received, how reading ended).
    pub fn finish(&mut self, within: Duration) -> (Result<u64, String>, u64, End) {
        self.stop.store(true, Ordering::SeqCst);
        let w = self.writer.take().map_or_else(|| Err("no writer".into()), |h| h.join().unwrap_or_else(|_| Err("writer panicked".into())));
        let deadline = Instant::now() + within;
        while !self.reader_done() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !self.reader_done() {
            return (w, self.received(), End::Timeout);
        }
        let (n, r) = self.reader.take().map_or((0, Err("no reader".into())), |h| h.join().unwrap_or((0, Err("reader panicked".into()))));
        (w, n, to_end(r))
    }

    /// Waits up to `within` for the reading side to end, without stopping the writer.
    pub fn wait_end(&mut self, within: Duration) -> End {
        let deadline = Instant::now() + within;
        while !self.reader_done() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if !self.reader_done() {
            return End::Timeout;
        }
        self.stop.store(true, Ordering::SeqCst);
        let (_, r) = self.reader.take().map_or((0, Err("no reader".into())), |h| h.join().unwrap_or((0, Err("reader panicked".into()))));
        to_end(r)
    }
}

const TIMED_OUT: &str = "read timed out";

fn to_end(r: Result<(), String>) -> End {
    match r {
        Ok(()) => End::Eof,
        Err(e) if e == TIMED_OUT => End::Timeout,
        Err(e) => End::Error(e),
    }
}

impl Drop for TcpClient {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// The kind of an I/O error that means the peer is gone.
#[must_use]
pub fn is_gone(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe | ErrorKind::UnexpectedEof
    )
}
