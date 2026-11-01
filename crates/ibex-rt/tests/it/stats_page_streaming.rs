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
//! plain request on the same thread is answered within 6 ms while the page dumps. Ibex before
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
    child: common::Ibex,
    st: SocketAddr,
    ping: SocketAddr,
    sock: String,
    cfg: std::path::PathBuf,
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
    let (st, ping) = (common::reserve_addr(), common::reserve_addr());
    let sock = format!("/tmp/ibex-t572-{tag}-{}.sock", std::process::id());
    let cfg = std::env::temp_dir().join(format!("ibex-t572-{tag}-{}.cfg", std::process::id()));
    let mut c = format!(
        "global\n    nbthread 1\n{global}    stats socket {sock} level admin\ndefaults\n    mode http\n    timeout client 30s\n    timeout server 30s\n    timeout connect 5s\n\
         frontend st\n    bind {st}\n    stats enable\n    stats uri /s\n\
         frontend ping\n    bind {ping}\n    http-request return status 200 content-type text/plain string ok\n"
    );
    for b in 0..nb {
        c.push_str(&format!("backend b{b}\n"));
        for s in 0..per {
            c.push_str(&format!("    server s{s} 127.0.0.{}:{}\n", 1 + s % 250, 1000 + b));
        }
    }
    std::fs::write(&cfg, c).expect("write cfg");
    let child = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-f").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(common::Ibex).expect("spawn ibex");
    let setup = Setup { child, st, ping, sock, cfg };
    let deadline = Instant::now() + Duration::from_secs(60);
    while TcpStream::connect(ping).is_err() || UnixStream::connect(&setup.sock).is_err() {
        assert!(Instant::now() < deadline, "ibex never started listening");
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
