// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The stats page and `show stat` are produced a buffer at a time (T572), as `HAProxy`'s stats
//! applet and CLI applet dump them: the page is never built whole, the memory a dump holds is
//! one buffer whatever the server count, and the other streams of the thread are served
//! between two chunks.
//!
//! Measured on `HAProxy` 3.5-dev8-885761-29, 10,000 servers (100 backends of 100), default
//! `tune.bufsize`: the HTML page is 20.8 MB in 1452 chunks of at most 16336 bytes, `;csv` 2.3 MB
//! in 188 chunks of at most 12737, the process grows by under 110 kB during either, and a
//! plain request on the same thread is answered within 6 ms while the page dumps. Alcyon before
//! T572 sent the page as one chunk of 32 MB, grew by 128 MB and held that request for 95 ms
//! (release build).

use crate::common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BACKENDS: usize = 100;
const PER: usize = 100;
/// `tune.bufsize`'s default: no chunk can be larger than the buffer it is written in.
const BUFSIZE: usize = 16384;
/// What a dump may add to the process while its client reads nothing: a few buffers, far
/// below the page (32 MB of HTML, 2.5 MB of CSV).
const GROWTH_KB: u64 = 2048;
/// What a plain request may wait while a dump runs: a few chunks. A page built whole held it
/// for 134 ms (debug build, 10,000 servers), `show stat` for 394 ms.
const LATENCY_MS: u64 = 60;

struct Setup {
    child: common::Alcyon,
    st: SocketAddr,
    ping: SocketAddr,
    sock: String,
    cfg: std::path::PathBuf,
    /// The stats frontend behind TLS (`alpn h2`), when asked for, and the directory of its
    /// certificate.
    tls: Option<(SocketAddr, tempfile::TempDir, Vec<u8>)>,
    /// The stats frontend's QUIC address (`alpn h3`), when asked for.
    quic: Option<SocketAddr>,
}

impl Drop for Setup {
    fn drop(&mut self) {
        common::stop(&mut self.child);
        let _ = std::fs::remove_file(&self.sock);
        let _ = std::fs::remove_file(&self.cfg);
    }
}

fn start(tag: &str) -> Setup {
    start_with(tag, "", BACKENDS, PER)
}

/// [`start`] with more `global` lines and `nb` backends of `per` servers.
fn start_with(tag: &str, global: &str, nb: usize, per: usize) -> Setup {
    start_full(tag, global, nb, per, false, false)
}

/// [`start_with`], and the stats frontend behind TLS too (`alpn h2,http/1.1`) when `tls`, on
/// QUIC (`alpn h3`) when `quic`.
fn start_full(tag: &str, global: &str, nb: usize, per: usize, tls: bool, quic: bool) -> Setup {
    let (st, ping) = (common::reserve_addr(), common::reserve_addr());
    let sock = format!("/tmp/alcyon-t572-{tag}-{}.sock", std::process::id());
    let cfg = std::env::temp_dir().join(format!("alcyon-t572-{tag}-{}.cfg", std::process::id()));
    let mut c = format!(
        "global\n  tune.alcyon.h1-lowercase-headers on\n    nbthread 1\n{global}    stats socket {sock} level admin\ndefaults\n    mode http\n    timeout client 30s\n    timeout server 30s\n    timeout connect 5s\n\
         frontend st\n    bind {st}\n    stats enable\n    stats uri /s\n\
         frontend ping\n    bind {ping}\n    http-request return status 200 content-type text/plain string ok\n"
    );
    let tls = tls.then(|| {
        let dir = tempfile::tempdir().expect("dir");
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let pem = dir.path().join("c.pem");
        std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("pem");
        let addr = common::reserve_addr();
        c.push_str(&format!("frontend sttls\n    bind {addr} ssl crt {} alpn h2,http/1.1\n    stats enable\n    stats uri /s\n", pem.display()));
        (addr, dir, ck.cert.der().to_vec())
    });
    let quic = quic.then(|| {
        let addr = common::reserve_addr();
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        c.push_str(&format!("frontend stquic\n    bind quic4@{addr} ssl crt {crt} alpn h3\n    stats enable\n    stats uri /s\n"));
        addr
    });
    for b in 0..nb {
        c.push_str(&format!("backend b{b}\n"));
        for s in 0..per {
            c.push_str(&format!("    server s{s} 127.0.0.{}:{}\n", 1 + s % 250, 1000 + b));
        }
    }
    std::fs::write(&cfg, c).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Alcyon).expect("spawn alcyon");
    let setup = Setup { child, st, ping, sock, cfg, tls, quic };
    let deadline = Instant::now() + Duration::from_secs(60);
    // Every TCP listener the tests connect to, not only `ping`: each is bound on its own, and the
    // TLS frontend could still refuse a connection after `ping` accepted one (2026-11-09, 1 in 3
    // runs of h2_tls_page_is_streamed_with_bounded_memory alone).
    let tls_addr = setup.tls.as_ref().map(|t| t.0);
    let up = |a: SocketAddr| TcpStream::connect(a).is_ok();
    while !up(ping) || !up(st) || !tls_addr.map_or(true, up) || UnixStream::connect(&setup.sock).is_err() {
        assert!(Instant::now() < deadline, "alcyon never started listening");
        std::thread::sleep(Duration::from_millis(20));
    }
    setup
}

fn status_kb(pid: u32, key: &str) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
    s.lines().find(|l| l.starts_with(key)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()).expect(key)
}

/// Resets the peak RSS to the current one; returns that.
fn reset_peak(pid: u32) -> u64 {
    std::fs::write(format!("/proc/{pid}/clear_refs"), "5").expect("clear_refs");
    status_kb(pid, "VmRSS")
}

/// One plain request on the other frontend; how long its answer took.
fn ping(addr: SocketAddr) -> Duration {
    let mut c = TcpStream::connect(addr).expect("connect ping");
    c.set_read_timeout(Some(Duration::from_secs(30))).expect("timeout");
    let t = Instant::now();
    c.write_all(b"GET /p HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send ping");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    assert!(got.starts_with(b"HTTP/1.1 200"), "ping: {:?}", String::from_utf8_lossy(&got));
    t.elapsed()
}

/// Reads a chunked response to its last chunk: the body and each chunk's size.
fn read_chunked(c: &mut TcpStream) -> (Vec<u8>, Vec<usize>) {
    c.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    let mut raw = Vec::new();
    let mut tmp = vec![0u8; 1 << 20];
    while !raw.ends_with(b"\r\n0\r\n\r\n") {
        let n = c.read(&mut tmp).expect("read page");
        assert!(n > 0, "closed before the last chunk, {} bytes", raw.len());
        raw.extend_from_slice(&tmp[..n]);
    }
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
    let head = String::from_utf8_lossy(&raw[..at]).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200") && head.contains("transfer-encoding: chunked"), "{head}");
    let (mut body, mut sizes, mut i) = (Vec::new(), Vec::new(), at);
    loop {
        let eol = i + raw[i..].windows(2).position(|w| w == b"\r\n").expect("chunk size line");
        let n = usize::from_str_radix(std::str::from_utf8(&raw[i..eol]).expect("hex"), 16).expect("chunk size");
        if n == 0 {
            break;
        }
        body.extend_from_slice(&raw[eol + 2..eol + 2 + n]);
        assert_eq!(&raw[eol + 2 + n..eol + 4 + n], b"\r\n", "chunk data ends with CRLF");
        sizes.push(n);
        i = eol + 4 + n;
    }
    (body, sizes)
}

/// Sends `req` on a connection that reads nothing yet; the plain request's latency meanwhile
/// and how much the process grew.
fn while_unread(s: &Setup, c: &mut impl Write, req: &[u8]) -> (Duration, u64) {
    let pid = s.child.id();
    let base = reset_peak(pid);
    c.write_all(req).expect("send");
    // The dump has started (or, built whole, is being built) when the plain request goes.
    std::thread::sleep(Duration::from_millis(20));
    let lat = ping(s.ping);
    // Long enough for a page built whole to be built, whatever the build type.
    std::thread::sleep(Duration::from_millis(1500));
    (lat, status_kb(pid, "VmHWM").saturating_sub(base))
}

#[test]
fn html_page_is_streamed_with_bounded_memory() {
    let s = start("html");
    let mut a = TcpStream::connect(s.st).expect("connect");
    let (lat, grew) = while_unread(&s, &mut a, b"GET /s HTTP/1.1\r\nHost: x\r\n\r\n");
    let (body, sizes) = read_chunked(&mut a);
    let body = String::from_utf8_lossy(&body);
    let mut bad = Vec::new();
    if grew > GROWTH_KB {
        bad.push(format!("the process grew by {grew} kB while the page waited for its client ({} kB of page)", body.len() / 1024));
    }
    if lat > Duration::from_millis(LATENCY_MS) {
        bad.push(format!("a plain request on the same thread waited {lat:?} while the page dumped"));
    }
    if sizes.len() < body.len() / BUFSIZE || sizes.iter().any(|&n| n > BUFSIZE) {
        bad.push(format!("{} chunks, the largest {} bytes, for {} bytes", sizes.len(), sizes.iter().max().unwrap_or(&0), body.len()));
    }
    if !body.starts_with("<!DOCTYPE html>") || !body.ends_with("</html>\n") || body.matches("<tr id=\"srv-row-").count() != BACKENDS * PER {
        bad.push(format!("the page is not whole: {} bytes, {} server rows", body.len(), body.matches("<tr id=\"srv-row-").count()));
    }
    // The same connection takes the next request.
    a.write_all(b"GET /s;csv HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
    let (csv, csv_sizes) = read_chunked(&mut a);
    if csv_sizes.len() < 2 || csv_sizes.iter().any(|&n| n > BUFSIZE) {
        bad.push(format!(";csv: {} chunks, the largest {}", csv_sizes.len(), csv_sizes.iter().max().unwrap_or(&0)));
    }
    // Its rows are those of `show stat`, in the same order.
    let rows = |t: &str| t.lines().map(|l| l.split(',').take(2).collect::<Vec<_>>().join(",")).collect::<Vec<_>>();
    let mut cli = UnixStream::connect(&s.sock).expect("cli");
    cli.write_all(b"show stat\n").expect("send");
    let mut out = String::new();
    let _ = cli.read_to_string(&mut out);
    let csv = String::from_utf8_lossy(&csv);
    if rows(&csv) != rows(out.trim_end_matches('\n')) || rows(&csv).len() != 3 + BACKENDS * (PER + 1) {
        bad.push(format!(";csv has {} rows, show stat {}", rows(&csv).len(), rows(&out).len()));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn http10_page_is_streamed_unframed_and_closed() {
    let s = start("h10");
    let mut a = TcpStream::connect(s.st).expect("connect");
    let (lat, grew) = while_unread(&s, &mut a, b"GET /s HTTP/1.0\r\n\r\n");
    a.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    let mut raw = Vec::new();
    a.read_to_end(&mut raw).expect("read to close");
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
    let head = String::from_utf8_lossy(&raw[..at]).to_ascii_lowercase();
    let body = String::from_utf8_lossy(&raw[at..]);
    let mut bad = Vec::new();
    if grew > GROWTH_KB {
        bad.push(format!("the process grew by {grew} kB while the page waited for its client"));
    }
    if lat > Duration::from_millis(LATENCY_MS) {
        bad.push(format!("a plain request waited {lat:?} while the page dumped"));
    }
    if head.contains("transfer-encoding") || head.contains("content-length") || !head.contains("connection: close") {
        bad.push(format!("head: {head}"));
    }
    if !body.ends_with("</html>\n") || body.matches("<tr id=\"srv-row-").count() != BACKENDS * PER {
        bad.push(format!("the page is not whole: {} bytes", body.len()));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn cli_show_stat_is_streamed_with_bounded_memory() {
    let s = start("cli");
    let mut c = UnixStream::connect(&s.sock).expect("cli");
    let (lat, grew) = while_unread(&s, &mut c, b"show stat\n");
    c.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read answer");
    let mut bad = Vec::new();
    if grew > GROWTH_KB {
        bad.push(format!("the process grew by {grew} kB while `show stat` waited for its client ({} kB answer)", out.len() / 1024));
    }
    if lat > Duration::from_millis(LATENCY_MS) {
        bad.push(format!("a plain request waited {lat:?} while `show stat` dumped"));
    }
    if !out.starts_with("# pxname,") || !out.ends_with(",\n\n") || out.lines().count() != 4 + BACKENDS * (PER + 1) {
        bad.push(format!("the answer is not whole: {} lines", out.lines().count()));
    }
    // `prompt` mode: the next command runs once the dump is out.
    let mut c = UnixStream::connect(&s.sock).expect("cli");
    c.write_all(b"prompt\nshow stat\nshow info\nquit\n").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    let mut out = String::new();
    c.read_to_string(&mut out).expect("read answer");
    if out.matches("\nb99,BACKEND,").count() != 1 || !out.contains("Name: ") {
        bad.push(format!("prompt mode: {} bytes, show info after it: {}", out.len(), out.contains("Name: ")));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Past `tune.buffers.limit` the head waits for a response buffer like any reply (S6b): the
/// page joins it, and it all goes once a buffer is free, chunked to the end.
#[test]
fn a_page_whose_head_waits_for_a_buffer_is_sent_whole() {
    let s = start_with("bufwait", "    tune.buffers.limit 3\n    tune.buffers.reserve 0\n", 3, 20);
    // Three partial heads hold the three buffers. The page's request waits for one, gets the
    // first given back, and its answer then waits for a second.
    let mut held: Vec<TcpStream> = (0..3)
        .map(|_| {
            let mut c = TcpStream::connect(s.st).expect("connect");
            c.write_all(b"GET /held HTTP/1.1\r\nHost: x\r\n").expect("partial head");
            c
        })
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    let mut a = TcpStream::connect(s.st).expect("connect");
    // The start of a next request keeps the request buffer from being given back.
    a.write_all(b"GET /s HTTP/1.1\r\nHost: x\r\n\r\nGET /next").expect("send");
    std::thread::sleep(Duration::from_millis(300));
    drop(held.remove(0));
    std::thread::sleep(Duration::from_millis(500));
    let mut early = [0u8; 1];
    a.set_nonblocking(true).expect("nonblocking");
    let waited = matches!(a.read(&mut early), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock);
    a.set_nonblocking(false).expect("blocking");
    assert!(waited, "the answer did not wait for a buffer");
    drop(held.remove(0));
    let (body, _) = read_chunked(&mut a);
    let body = String::from_utf8_lossy(&body);
    assert!(body.ends_with("</html>\n") && body.matches("<tr id=\"srv-row-").count() == 60, "{} bytes", body.len());
}

/// A HEAD gets the head of the page alone.
#[test]
fn a_head_request_gets_the_head_alone() {
    let s = start_with("head", "", 2, 3);
    let mut c = TcpStream::connect(s.st).expect("connect");
    c.write_all(b"HEAD /s;csv HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").expect("send");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let got = String::from_utf8_lossy(&got).to_ascii_lowercase();
    assert!(got.starts_with("http/1.1 200") && got.contains("transfer-encoding: chunked") && got.ends_with("\r\n\r\n"), "{got:?}");
}

/// HTTP/2 frame: length, type, flags, stream.
fn h2_frame(ftype: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = u32::try_from(payload.len()).expect("short").to_be_bytes()[1..].to_vec();
    v.extend_from_slice(&[ftype, flags]);
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// An HTTP/2 client gets the page as one message (DATA frames on its stream, then its end).
#[test]
fn an_h2_client_gets_the_whole_page() {
    let s = start_with("h2", "", 2, 3);
    let mut c = TcpStream::connect(s.st).expect("connect");
    c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    c.write_all(&h2_frame(0x04, 0, 0, &[])).expect("settings");
    // :method GET, :scheme http, :path /s;csv, :authority x -- no Huffman.
    let mut h = vec![0x82, 0x86, 0x04, 6];
    h.extend_from_slice(b"/s;csv");
    h.extend_from_slice(&[0x01, 1, b'x']);
    c.write_all(&h2_frame(0x01, 0x05, 1, &h)).expect("headers");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let (mut raw, mut data, mut ended) = (Vec::new(), Vec::new(), false);
    let mut tmp = [0u8; 65536];
    while !ended {
        let n = c.read(&mut tmp).expect("read");
        assert!(n > 0, "closed before the end of the stream");
        raw.extend_from_slice(&tmp[..n]);
        while raw.len() >= 9 {
            let len = usize::from(raw[0]) << 16 | usize::from(raw[1]) << 8 | usize::from(raw[2]);
            if raw.len() < 9 + len {
                break;
            }
            let (ty, fl, sid) = (raw[3], raw[4], u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) & 0x7fff_ffff);
            if ty == 0 && sid == 1 {
                data.extend_from_slice(&raw[9..9 + len]);
            }
            ended |= sid == 1 && fl & 1 != 0 && (ty == 0 || ty == 1);
            raw.drain(..9 + len);
        }
    }
    let data = String::from_utf8_lossy(&data);
    assert!(data.starts_with("# pxname,") && data.ends_with(",\n") && data.lines().count() == 3 + 2 * 4, "{data:?}");
}

// HTTP/2 (T580). HAProxy streams the applet's output to an h2 stream as it streams it to an
// HTTP/1.1 client: the stats applet fills the channel buffer and `h2_snd_buf` sends what is
// there as DATA frames, within the stream's and the connection's windows. Measured on
// 3.5-dev8 over h2c (client windows open), 10,000 servers: the HTML page, 20.8 MB, in 1453 DATA
// frames of at most 16336 bytes, the process grows by 200 kB, and a plain request on the same
// thread waits at most 0.3 ms meanwhile. Alcyon before T580 built the page whole (+127 MB, that
// request held 88 ms) and then sent its first buffer alone: 16315 bytes, and the stream reset
// at `timeout client` (release-perf, `/tmp/t580/measure_h2.py`).

/// The HEADERS frame of a request on stream `sid` (END_STREAM, END_HEADERS): `GET` (or `HEAD`)
/// `path`, `:scheme http`, `:authority x`, no Huffman.
fn h2_request(sid: u32, head: bool, path: &str) -> Vec<u8> {
    let mut h = if head { vec![0x02, 4, b'H', b'E', b'A', b'D'] } else { vec![0x82] };
    h.extend_from_slice(&[0x86, 0x04, u8::try_from(path.len()).expect("short path")]);
    h.extend_from_slice(path.as_bytes());
    h.extend_from_slice(&[0x01, 1, b'x']);
    h2_frame(0x01, 0x05, sid, &h)
}

/// A response read off an HTTP/2 stream.
struct H2Response {
    /// The first byte of its header block: 0x88 is `:status 200` from the static table.
    status_byte: u8,
    /// END_STREAM on its HEADERS: the head alone.
    head_ended: bool,
    body: Vec<u8>,
    /// The size of each DATA frame.
    sizes: Vec<usize>,
}

/// An HTTP/2 client over `S` (h2c with prior knowledge, or TLS with ALPN `h2`), enough for the
/// stats page: the windows it gives the server are the test's to give.
struct H2<S: Read + Write> {
    s: S,
    raw: Vec<u8>,
}

impl<S: Read + Write> H2<S> {
    /// The preface and SETTINGS, with `SETTINGS_INITIAL_WINDOW_SIZE` when `window` says.
    fn open(mut s: S, window: Option<u32>) -> Self {
        s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
        let settings = window.map_or_else(Vec::new, |w| [&[0u8, 4][..], &w.to_be_bytes()].concat());
        s.write_all(&h2_frame(0x04, 0, 0, &settings)).expect("settings");
        H2 { s, raw: Vec::new() }
    }

    /// The next frame (type, flags, stream, payload); the server's SETTINGS are acknowledged.
    /// `None` when nothing came within the socket's read timeout.
    fn frame(&mut self) -> Option<(u8, u8, u32, Vec<u8>)> {
        let mut tmp = vec![0u8; 65536];
        loop {
            if self.raw.len() >= 9 {
                let len = usize::from(self.raw[0]) << 16 | usize::from(self.raw[1]) << 8 | usize::from(self.raw[2]);
                if self.raw.len() >= 9 + len {
                    let f: Vec<u8> = self.raw.drain(..9 + len).collect();
                    let (ty, fl, sid) = (f[3], f[4], u32::from_be_bytes([f[5], f[6], f[7], f[8]]) & 0x7fff_ffff);
                    if ty == 0x04 && fl & 1 == 0 {
                        self.s.write_all(&h2_frame(0x04, 1, 0, &[])).expect("settings ack");
                    }
                    assert!(ty != 0x07, "GOAWAY: {:?}", &f[9..]);
                    return Some((ty, fl, sid, f[9..].to_vec()));
                }
            }
            match self.s.read(&mut tmp) {
                Ok(0) => panic!("the connection closed"),
                Ok(n) => self.raw.extend_from_slice(&tmp[..n]),
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return None,
                Err(e) => panic!("read: {e}"),
            }
        }
    }

    /// Opens `n` more bytes of the window of stream `sid` (0: the connection's).
    fn window(&mut self, sid: u32, n: u32) {
        self.s.write_all(&h2_frame(0x08, 0, sid, &n.to_be_bytes())).expect("window update");
    }

    /// Reads stream `sid` to its end, giving back the window of each DATA frame as it comes.
    fn read_stream(&mut self, sid: u32) -> H2Response {
        let mut r = H2Response { status_byte: 0, head_ended: false, body: Vec::new(), sizes: Vec::new() };
        loop {
            let (ty, fl, id, p) = self.frame().unwrap_or_else(|| panic!("stream {sid}: nothing more after {} bytes", r.body.len()));
            if id != sid {
                continue;
            }
            match ty {
                0x01 => {
                    r.status_byte = p[0];
                    if fl & 1 != 0 {
                        r.head_ended = true;
                        return r;
                    }
                }
                0x00 => {
                    if !p.is_empty() {
                        let n = u32::try_from(p.len()).expect("frame");
                        self.window(sid, n);
                        self.window(0, n);
                    }
                    r.sizes.push(p.len());
                    r.body.extend_from_slice(&p);
                    if fl & 1 != 0 {
                        return r;
                    }
                }
                0x03 => panic!("stream {sid} reset: {p:?} after {} bytes", r.body.len()),
                _ => {}
            }
        }
    }
}

/// A TLS connection to the stats frontend that negotiated `h2`.
fn tls_h2(s: &Setup) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (addr, _, der) = s.tls.as_ref().expect("a TLS frontend");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(der.clone())).expect("root");
    let mut conf = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    conf.alpn_protocols = vec![b"h2".to_vec()];
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(conf), rustls::pki_types::ServerName::try_from("localhost").expect("name")).expect("client");
    let sock = TcpStream::connect(addr).expect("connect tls");
    sock.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    let mut t = rustls::StreamOwned::new(conn, sock);
    while t.conn.is_handshaking() {
        t.conn.complete_io(&mut t.sock).expect("handshake");
    }
    assert_eq!(t.conn.alpn_protocol(), Some(&b"h2"[..]));
    t
}

/// The HTML page and `;csv` over HTTP/2: what the dump adds while the client reads nothing,
/// the plain request meanwhile, then the page read whole in DATA frames no larger than a
/// buffer, and `;csv` on the next stream of the same connection.
fn h2_page_streamed<S: Read + Write>(s: &Setup, h: &mut H2<S>, what: &str) -> Vec<String> {
    // The TLS frontend is one more row.
    let rows = 3 + BACKENDS * (PER + 1) + usize::from(s.tls.is_some());
    let (lat, grew) = while_unread(s, &mut h.s, &h2_request(1, false, "/s"));
    let r = h.read_stream(1);
    let body = String::from_utf8_lossy(&r.body);
    let mut bad = Vec::new();
    if grew > GROWTH_KB {
        bad.push(format!("{what}: the process grew by {grew} kB while the page waited for its client ({} kB of page)", body.len() / 1024));
    }
    if lat > Duration::from_millis(LATENCY_MS) {
        bad.push(format!("{what}: a plain request on the same thread waited {lat:?} while the page dumped"));
    }
    if r.sizes.len() < body.len() / BUFSIZE || r.sizes.iter().any(|&n| n > BUFSIZE) {
        bad.push(format!("{what}: {} DATA frames, the largest {} bytes, for {} bytes", r.sizes.len(), r.sizes.iter().max().unwrap_or(&0), body.len()));
    }
    if r.status_byte != 0x88 || !body.starts_with("<!DOCTYPE html>") || !body.ends_with("</html>\n") || body.matches("<tr id=\"srv-row-").count() != BACKENDS * PER {
        bad.push(format!("{what}: the page is not whole: status byte {:#x}, {} bytes, {} server rows", r.status_byte, body.len(), body.matches("<tr id=\"srv-row-").count()));
    }
    h.s.write_all(&h2_request(3, false, "/s;csv")).expect("send csv");
    let r = h.read_stream(3);
    let csv = String::from_utf8_lossy(&r.body);
    if !csv.starts_with("# pxname,") || csv.lines().count() != rows || r.sizes.iter().any(|&n| n > BUFSIZE) {
        bad.push(format!("{what} ;csv: {} lines in {} DATA frames, the largest {}", csv.lines().count(), r.sizes.len(), r.sizes.iter().max().unwrap_or(&0)));
    }
    bad
}

#[test]
fn h2c_page_is_streamed_with_bounded_memory() {
    let s = start("h2c");
    let c = TcpStream::connect(s.st).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    let mut h = H2::open(c, None);
    let bad = h2_page_streamed(&s, &mut h, "h2c");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn h2_tls_page_is_streamed_with_bounded_memory() {
    let s = start_full("h2tls", "", BACKENDS, PER, true, false);
    let mut h = H2::open(tls_h2(&s), None);
    // The preface and SETTINGS are out before the dump is timed.
    h.s.flush().expect("flush");
    let bad = h2_page_streamed(&s, &mut h, "h2 over TLS");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// A client whose window is closed (`SETTINGS_INITIAL_WINDOW_SIZE` 0) while it reads all that
/// comes: the page waits in no more than a buffer, another stream of the connection is
/// answered meanwhile, and the dump goes on as the window opens.
#[test]
fn an_h2_page_waits_for_a_closed_window_in_a_buffer() {
    let s = start("h2win");
    let c = TcpStream::connect(s.st).expect("connect");
    c.set_read_timeout(Some(Duration::from_millis(100))).expect("timeout");
    let mut h = H2::open(c, Some(0));
    while h.frame().is_some() {}
    let pid = s.child.id();
    let base = reset_peak(pid);
    let t = Instant::now();
    // The page, then a request the frontend answers itself (no backend: 503).
    h.s.write_all(&[h2_request(1, false, "/s"), h2_request(3, false, "/other")].concat()).expect("send");
    let (mut other, mut data_1, mut head_1) = (None, 0, false);
    let until = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < until {
        match h.frame() {
            Some((0x01, _, 3, _)) if other.is_none() => other = Some(t.elapsed()),
            Some((0x01, _, 1, _)) => head_1 = true,
            Some((0x00, _, 1, p)) => data_1 += p.len(),
            _ => {}
        }
    }
    let grew = status_kb(pid, "VmHWM").saturating_sub(base);
    let mut bad = Vec::new();
    if grew > GROWTH_KB {
        bad.push(format!("the process grew by {grew} kB while the page waited for a window"));
    }
    match other {
        Some(d) if d <= Duration::from_millis(LATENCY_MS) => {}
        d => bad.push(format!("the other stream's answer came after {d:?}")),
    }
    if !head_1 || data_1 != 0 {
        bad.push(format!("closed window: HEADERS {head_1}, {data_1} bytes of DATA"));
    }
    h.s.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    h.window(1, 65535);
    let r = h.read_stream(1);
    let body = String::from_utf8_lossy(&r.body);
    if !body.ends_with("</html>\n") || body.matches("<tr id=\"srv-row-").count() != BACKENDS * PER {
        bad.push(format!("after the window opened: {} bytes, {} server rows", body.len(), body.matches("<tr id=\"srv-row-").count()));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Each page over HTTP/2 is the page an HTTP/1.1 client gets, once the numbers that move
/// between two requests (counters, times) are set aside.
#[test]
fn the_h2_pages_are_the_h1_pages() {
    let s = start_with("h2eq", "", 3, 5);
    let norm = |b: &[u8]| {
        let t = String::from_utf8_lossy(b);
        let mut out = String::with_capacity(t.len());
        let mut digit = false;
        for ch in t.chars() {
            if !ch.is_ascii_digit() {
                out.push(ch);
            } else if !digit {
                out.push('0');
            }
            digit = ch.is_ascii_digit();
        }
        out
    };
    let c = TcpStream::connect(s.st).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let mut h = H2::open(c, None);
    let mut a = TcpStream::connect(s.st).expect("connect");
    let mut bad = Vec::new();
    for (sid, path) in [(1, "/s"), (3, "/s;csv"), (5, "/s;json"), (7, "/s;up"), (9, "/s;norefresh")] {
        a.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).expect("send h1");
        let (h1, _) = read_chunked(&mut a);
        h.s.write_all(&h2_request(sid, false, path)).expect("send h2");
        let h2 = h.read_stream(sid).body;
        if h1.len() < 100 || norm(&h1) != norm(&h2) {
            bad.push(format!("{path}: HTTP/1.1 {} bytes, HTTP/2 {} bytes", h1.len(), h2.len()));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// `show pools`' `scrape_box` line: (allocated, of them in thread caches).
fn scrape_boxes(sock: &str) -> (u64, u64) {
    let mut c = UnixStream::connect(sock).expect("cli");
    c.write_all(b"show pools\n").expect("send");
    let mut out = String::new();
    let _ = c.read_to_string(&mut out);
    let l = out.lines().find(|l| l.contains("Pool scrape_box ")).unwrap_or_else(|| panic!("no scrape_box in {out}"));
    let num = |after: &str| l.split(after).nth(1).and_then(|t| t.trim_start().split(|c: char| !c.is_ascii_digit()).next()).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("{l}"));
    (num(") : "), num("(~"))
}

/// A client that resets its stream while the page dumps ends the dump: the stream's box goes
/// back to its pool (a box taken from a pool is outside its accounting until it is given
/// back: dropped, it never shows), and the connection's next stream gets its page.
#[test]
fn an_h2_stream_reset_mid_dump_ends_the_dump() {
    let s = start("h2rst");
    let c = TcpStream::connect(s.st).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(60))).expect("timeout");
    let mut h = H2::open(c, None);
    h.s.write_all(&h2_request(1, false, "/s")).expect("send");
    loop {
        if let Some((0x00, _, 1, p)) = h.frame() {
            if !p.is_empty() {
                break;
            }
        }
    }
    // CANCEL.
    h.s.write_all(&h2_frame(0x03, 0, 1, &8u32.to_be_bytes())).expect("rst");
    // What stream 1 already sent spent the connection's window (65535 bytes, never credited
    // here: only `read_stream` gives window back). On a loaded host the proxy sends more of
    // the page before it sees the reset, up to the whole window, and stream 3 then waits for a
    // credit that never comes until `timeout client` cancels it (T614b: `rp` 16302 bytes
    // pending, 31 s). Credit the connection generously.
    h.window(0, 1 << 20);
    // The box is back in its pool once the proxy has handled the reset: wait for that (up to
    // 10 s), not a fixed 300 ms a loaded host can overrun.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut alloc, mut cached) = scrape_boxes(&s.sock);
    while !(alloc >= 1 && cached == alloc) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        (alloc, cached) = scrape_boxes(&s.sock);
    }
    h.s.write_all(&h2_request(3, false, "/s;csv")).expect("send csv");
    let r = h.read_stream(3);
    let csv = String::from_utf8_lossy(&r.body);
    assert!(csv.lines().count() == 3 + BACKENDS * (PER + 1) && alloc >= 1 && cached == alloc, "{} lines; scrape_box after the reset: {alloc} allocated, {cached} in caches", csv.lines().count());
}

/// A HEAD over HTTP/2 gets the head alone: HEADERS with the end of the stream.
#[test]
fn an_h2_head_gets_the_head_alone() {
    let s = start_with("h2head", "", 2, 3);
    let c = TcpStream::connect(s.st).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let mut h = H2::open(c, None);
    for (sid, path) in [(1, "/s"), (3, "/s;csv")] {
        h.s.write_all(&h2_request(sid, true, path)).expect("send");
        let r = h.read_stream(sid);
        assert!(r.status_byte == 0x88 && r.head_ended && r.body.is_empty(), "{path}: status byte {:#x}, ended {}, {} bytes", r.status_byte, r.head_ended, r.body.len());
    }
    // Any reply the proxy makes itself: HAProxy 3.5-dev8 sends `return`'s HEADERS with the end
    // of the stream and no DATA.
    let c = TcpStream::connect(s.ping).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10))).expect("timeout");
    let mut h = H2::open(c, None);
    h.s.write_all(&h2_request(1, true, "/p")).expect("send");
    let r = h.read_stream(1);
    assert!(r.status_byte == 0x88 && r.head_ended && r.body.is_empty(), "return: ended {}, {} bytes", r.head_ended, r.body.len());
    // A DATA frame after the end of the stream would come before the next stream's answer.
    h.s.write_all(&h2_request(3, false, "/p")).expect("send");
    let r = h.read_stream(3);
    assert!(r.body == b"ok", "the next stream: {:?}", r.body);
}

/// HTTP/3 streams the page as HTTP/2 does: its stream's response goes out of the same `rep`
/// as DATA frames (`h3_bridge_moves`). It already did before T580 (an HTTP/3 stream is not
/// `is_h2()`, so it took the HTTP/1.1 path, chunked in `rep`): this one guards it. curl reads as fast as it can: the process grows by the
/// QUIC send buffers, not by the page, and the plain request is answered meanwhile. Skipped
/// where curl has no HTTP/3.
#[test]
fn h3_page_is_streamed_with_bounded_memory() {
    let has_h3 = Command::new("curl").arg("-V").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"));
    if !has_h3 {
        eprintln!("curl on this host has no HTTP3 support; skipping");
        return;
    }
    let s = start_full("h3", "", BACKENDS, PER, false, true);
    let port = s.quic.expect("quic").port();
    let out = std::env::temp_dir().join(format!("alcyon-t580-h3-{}.html", std::process::id()));
    let pid = s.child.id();
    let base = reset_peak(pid);
    let curl = Command::new("curl")
        .args(["-sS", "--http3-only", "-k", "--max-time", "60", "--resolve", &format!("localhost:{port}:127.0.0.1"), &format!("https://localhost:{port}/s"), "-o"])
        .arg(&out)
        .args(["-w", "%{http_code} %{http_version}"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("run curl");
    std::thread::sleep(Duration::from_millis(50));
    let lat = ping(s.ping);
    let done = curl.wait_with_output().expect("curl");
    let grew = status_kb(pid, "VmHWM").saturating_sub(base);
    let body = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    let mut bad = Vec::new();
    if String::from_utf8_lossy(&done.stdout) != "200 3" || !body.ends_with("</html>\n") || body.matches("<tr id=\"srv-row-").count() != BACKENDS * PER {
        bad.push(format!("curl: {:?}, {} bytes, {} server rows", String::from_utf8_lossy(&done.stdout), body.len(), body.matches("<tr id=\"srv-row-").count()));
    }
    // The QUIC send buffers fill up to the window curl advertises while it reads slowly, so
    // the bound is a quarter of the page (31 MB), not a few buffers: 1.1-1.6 MB measured on a
    // quiet and on a loaded host, 4.6 MB in T603's gate (host loaded by builds); a page held
    // whole would be 31 MB (T614b: the cause of the 4.6 inferred, not reproduced).
    if grew > 8 * GROWTH_KB {
        bad.push(format!("the process grew by {grew} kB while the page went out over HTTP/3 ({} kB of page)", body.len() / 1024));
    }
    if lat > Duration::from_millis(LATENCY_MS) {
        bad.push(format!("a plain request on the same thread waited {lat:?} while the page went out over HTTP/3"));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
