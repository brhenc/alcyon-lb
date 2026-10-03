// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 stream multiplexing, against the real daemon over cleartext h2c.
//!
//! `curl --http2` passing proves one request works. Multiplexing is the thing HTTP/2 is
//! *for*, and it is a separate claim: several concurrent streams on one connection, each
//! carrying its own request, each reaching the backend once and unchanged.
//!
//! Cleartext rather than TLS deliberately — the defect is in the mux, and putting a TLS
//! handshake in front of it only adds ways for the test to fail for unrelated reasons.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}


struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        common::stop(&mut self.0);
    }
}

fn wait_for_port(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

/// An HTTP/1 backend that records every request line it is given and keeps the
/// connection open, so backend-side reuse does not hide requests from the count.
fn spawn_backend() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    thread::spawn(move || {
        for conn in listener.incoming().take(8) {
            let Ok(mut c) = conn else { continue };
            let sink = Arc::clone(&sink);
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(3))).ok();
                let mut buf: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 4096];
                while let Ok(n) = c.read(&mut tmp) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    while let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..p + 4).collect();
                        let line = String::from_utf8_lossy(&head)
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_string();
                        sink.lock().expect("lock").push(line);
                        let _ = c.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                        );
                    }
                }
            });
        }
    });
    (port, seen)
}

/// One HTTP/2 frame: 24-bit length, type, flags, 31-bit stream id, payload.
fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("frame payload fits in 24 bits");
    let mut v = Vec::with_capacity(9 + payload.len());
    // 24-bit big-endian length: the top byte of the u32 is always zero here.
    v.extend_from_slice(&len.to_be_bytes()[1..]);
    v.push(ftype);
    v.push(flags);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A minimal HPACK block for `GET <path> HTTP/2` on `localhost`.
///
/// Static-table indices only, so there is no Huffman coding and no dynamic table to get
/// wrong: `:method: GET` is index 2, `:scheme: http` is index 6, and `:path` and
/// `:authority` are literals with an indexed name (indices 4 and 1).
fn hpack_get(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86];
    v.push(0x04);
    v.push(u8::try_from(path.len()).expect("short path"));
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

/// Each stream carries its own request, and each reaches the backend exactly once.
///
/// Measured against the daemon before this test was written, three streams with distinct
/// paths sent 250 ms apart over h2c:
///
/// ```text
///   client sent:    /s0  /s1  /s2
///   backend saw:    /s0  /s0  /s0
/// ```
///
/// The first stream's request is replayed for every stream that follows; `/s1` and `/s2`
/// never arrive. Sent as a burst instead, ten streams produced a single backend request.
///
/// That is per-stream state that is not per-stream. Two things follow, and the second is
/// why this is not merely a correctness bug: requests are **lost** without any error to
/// the client, and a request is **duplicated under another stream's identity**. On a
/// connection carrying more than one user's traffic — which is the normal case for a
/// proxy — serving one stream's request in place of another's is the same family as
/// response-queue poisoning.
///
/// `curl --http2` passes against this daemon because it sends one request.
#[test]
fn each_h2_stream_carries_its_own_request() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2mux_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let paths = ["/s0", "/s1", "/s2"];
    for (i, p) in paths.iter().enumerate() {
        // END_STREAM | END_HEADERS: a complete request, no body.
        let sid = 1 + 2 * u32::try_from(i).expect("small");
        s.write_all(&frame(0x01, 0x05, sid, &hpack_get(p)))
            .expect("headers");
        s.flush().ok();
        thread::sleep(Duration::from_millis(250));
    }
    thread::sleep(Duration::from_millis(500));

    let got = seen.lock().expect("lock").clone();
    let _ = std::fs::remove_file(&cfg);

    let mut wanted: Vec<String> = paths.iter().map(|p| format!("GET {p}")).collect();
    let mut normalised: Vec<String> = got
        .iter()
        .map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
        .collect();
    wanted.sort();
    normalised.sort();

    assert_eq!(
        normalised, wanted,
        "each stream must reach the backend once with its own path. client sent {paths:?}, \
         backend saw {got:?} -- a request replayed under another stream's identity is \
         response-queue poisoning, and a request dropped without an error is a hang."
    );

    let mut exact_wanted: Vec<String> = paths.iter().map(|p| format!("GET {p} HTTP/1.1")).collect();
    let mut exact_got = got;
    exact_wanted.sort();
    exact_got.sort();
    assert_eq!(
        exact_got, exact_wanted,
        "backend must see HTTP/1.1 request lines normalized from HTTP/2 client"
    );
}

/// Ten streams sent in an immediate burst over cleartext h2c without any inter-frame delay.
/// All ten streams must reach the backend as normalized HTTP/1.1 requests without loss or replay.
#[test]
fn ten_h2_streams_burst_reach_backend_without_loss() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2burst_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let mut burst_payload = Vec::new();
    let count = 10;
    let paths: Vec<String> = (0..count).map(|i| format!("/b{i}")).collect();
    for (i, p) in paths.iter().enumerate() {
        let sid = 1 + 2 * u32::try_from(i).expect("small");
        burst_payload.extend_from_slice(&frame(0x01, 0x05, sid, &hpack_get(p)));
    }
    s.write_all(&burst_payload).expect("send burst");
    s.flush().ok();

    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if seen.lock().expect("lock").len() >= count {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let got = seen.lock().expect("lock").clone();
    let _ = std::fs::remove_file(&cfg);

    let mut wanted: Vec<String> = paths.iter().map(|p| format!("GET {p} HTTP/1.1")).collect();
    let mut got_sorted = got.clone();
    wanted.sort();
    got_sorted.sort();

    assert_eq!(
        got_sorted, wanted,
        "all 10 burst streams must reach the backend as normalized HTTP/1.1 requests without loss. \
         client sent {paths:?}, backend saw {got:?}"
    );
}

/// Rapid Reset flood (CVE-2023-44487) triggers GOAWAY with `ENHANCE_YOUR_CALM` (0xb).
#[test]
fn rapid_reset_flood_triggers_goaway_enhance_your_calm() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, _) = spawn_backend();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2rstflood_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "global\n\ttune.h2.fe.glitches-threshold 100\n\ndefaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let mut flood = Vec::new();
    for i in 0..150u32 {
        let sid = 1 + 2 * i;
        flood.extend_from_slice(&frame(0x01, 0x05, sid, &hpack_get("/flood")));
        // RST_STREAM frame (type 0x03, cancel = error code 8)
        flood.extend_from_slice(&frame(0x03, 0, sid, &8u32.to_be_bytes()));
    }
    s.write_all(&flood).ok();
    s.flush().ok();

    let mut resp = Vec::new();
    let mut tmp = [0u8; 1024];
    while let Ok(n) = s.read(&mut tmp) {
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
    }
    let _ = std::fs::remove_file(&cfg);

    // Frame type 0x07 is GOAWAY. Verify GOAWAY was received in response frames.
    let has_goaway = resp.windows(9).any(|hdr| hdr[3] == 0x07);
    assert!(
        has_goaway,
        "Rapid reset flood must trigger a GOAWAY frame from the daemon"
    );
}

/// PING flood triggers GOAWAY with `ENHANCE_YOUR_CALM` (0xb).
#[test]
fn ping_flood_triggers_goaway_enhance_your_calm() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, _) = spawn_backend();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2pingflood_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let mut flood = Vec::new();
    for i in 0..150u64 {
        // PING frame (type 0x06, flags 0, stream 0, 8 bytes opaque data)
        flood.extend_from_slice(&frame(0x06, 0, 0, &i.to_be_bytes()));
    }
    s.write_all(&flood).ok();
    s.flush().ok();

    let mut resp = Vec::new();
    let mut tmp = [0u8; 1024];
    while let Ok(n) = s.read(&mut tmp) {
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
    }
    let _ = std::fs::remove_file(&cfg);

    let has_goaway = resp.windows(9).any(|hdr| hdr[3] == 0x07);
    assert!(
        has_goaway,
        "PING flood must trigger a GOAWAY frame from the daemon"
    );
}

/// SETTINGS flood triggers GOAWAY with `ENHANCE_YOUR_CALM` (0xb).
#[test]
fn settings_flood_triggers_goaway_enhance_your_calm() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, _) = spawn_backend();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2setflood_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let mut flood = Vec::new();
    for _ in 0..150 {
        // Empty SETTINGS frame (non-ACK)
        flood.extend_from_slice(&frame(0x04, 0, 0, &[]));
    }
    s.write_all(&flood).ok();
    s.flush().ok();

    let mut resp = Vec::new();
    let mut tmp = [0u8; 1024];
    while let Ok(n) = s.read(&mut tmp) {
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&tmp[..n]);
    }
    let _ = std::fs::remove_file(&cfg);

    let has_goaway = resp.windows(9).any(|hdr| hdr[3] == 0x07);
    assert!(
        has_goaway,
        "SETTINGS flood must trigger a GOAWAY frame from the daemon"
    );
}

/// An HTTP/1 backend that records every complete request header block it receives.
fn spawn_backend_full() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    thread::spawn(move || {
        for conn in listener.incoming().take(8) {
            let Ok(mut c) = conn else { continue };
            let sink = Arc::clone(&sink);
            thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(3))).ok();
                let mut buf: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 4096];
                while let Ok(n) = c.read(&mut tmp) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    while let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..p + 4).collect();
                        let header_text = String::from_utf8_lossy(&head).to_string();
                        sink.lock().expect("lock").push(header_text);
                        let _ = c.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                        );
                    }
                }
            });
        }
    });
    (port, seen)
}

fn hpack_get_with_authority_and_headers(
    path: &str,
    authority: &str,
    extra_headers: &[(&str, &str)],
) -> Vec<u8> {
    let mut v = vec![0x82, 0x86]; // :method: GET, :scheme: http
    v.push(0x04);
    v.push(u8::try_from(path.len()).expect("short path"));
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(u8::try_from(authority.len()).expect("short authority"));
    v.extend_from_slice(authority.as_bytes());
    for (name, val) in extra_headers {
        v.push(0x00);
        v.push(u8::try_from(name.len()).expect("short name"));
        v.extend_from_slice(name.as_bytes());
        v.push(u8::try_from(val.len()).expect("short val"));
        v.extend_from_slice(val.as_bytes());
    }
    v
}

fn hpack_get_with_unknown_pseudo(path: &str, pseudo_name: &str, pseudo_val: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x86];
    v.push(0x04);
    v.push(u8::try_from(path.len()).expect("short path"));
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v.push(0x00);
    v.push(u8::try_from(pseudo_name.len()).expect("short name"));
    v.extend_from_slice(pseudo_name.as_bytes());
    v.push(u8::try_from(pseudo_val.len()).expect("short val"));
    v.extend_from_slice(pseudo_val.as_bytes());
    v
}

fn hpack_get_pseudo_after_regular(path: &str) -> Vec<u8> {
    let mut v = vec![0x82]; // :method: GET
    // Regular header: x-custom: test
    v.push(0x00);
    v.push(8);
    v.extend_from_slice(b"x-custom");
    v.push(4);
    v.extend_from_slice(b"test");
    // Pseudo header after regular: :scheme: http (0x86)
    v.push(0x86);
    // :path
    v.push(0x04);
    v.push(u8::try_from(path.len()).expect("short path"));
    v.extend_from_slice(path.as_bytes());
    // :authority
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

fn hpack_get_duplicate_pseudo(path: &str) -> Vec<u8> {
    let mut v = vec![0x82, 0x82, 0x86]; // Duplicate :method GET
    v.push(0x04);
    v.push(u8::try_from(path.len()).expect("short path"));
    v.extend_from_slice(path.as_bytes());
    v.push(0x01);
    v.push(9);
    v.extend_from_slice(b"localhost");
    v
}

fn recv_h2_frames(s: &mut TcpStream, timeout: Duration) -> Vec<(u8, u8, u32, Vec<u8>)> {
    s.set_read_timeout(Some(timeout)).ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let start = Instant::now();
    while start.elapsed() < timeout {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let mut frames = Vec::new();
    let mut i = 0;
    while i + 9 <= buf.len() {
        let len = ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | (buf[i + 2] as usize);
        let ftype = buf[i + 3];
        let flags = buf[i + 4];
        let sid = u32::from_be_bytes([buf[i + 5] & 0x7f, buf[i + 6], buf[i + 7], buf[i + 8]]);
        if i + 9 + len > buf.len() {
            break;
        }
        let payload = buf[i + 9..i + 9 + len].to_vec();
        frames.push((ftype, flags, sid, payload));
        i += 9 + len;
    }
    frames
}

/// Exactly one Host header matching :authority reaches the HTTP/1.1 backend,
/// and zero pseudo-headers (starting with ':') reach the backend.
#[test]
fn exactly_one_host_matching_authority_and_no_colon_headers_reach_backend() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend_full();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2pseudo_norm_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let payload = hpack_get_with_authority_and_headers(
        "/probe",
        "example.com",
        &[("user-agent", "curl/8.18.0"), ("accept", "*/*")],
    );
    s.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s.flush().ok();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !seen.lock().expect("lock").is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let got = seen.lock().expect("lock").clone();
    let _ = std::fs::remove_file(&cfg);

    assert_eq!(
        got.len(),
        1,
        "backend must receive exactly 1 request, got {got:?}"
    );

    let raw_req = &got[0];
    let lines: Vec<&str> = raw_req.lines().collect();
    assert_eq!(lines[0], "GET /probe HTTP/1.1");

    let mut host_count = 0;
    let mut host_val = None;
    let mut colon_headers = Vec::new();

    for line in &lines[1..] {
        if line.is_empty() {
            continue;
        }
        if let Some((name, val)) = line.split_once(':') {
            let name_trimmed = name.trim();
            if name_trimmed.starts_with(':') {
                colon_headers.push(line.to_string());
            }
            if name_trimmed.eq_ignore_ascii_case("host") {
                host_count += 1;
                host_val = Some(val.trim().to_string());
            }
        }
    }

    assert_eq!(
        host_count, 1,
        "backend must receive exactly one Host header; received: {raw_req:?}"
    );
    assert_eq!(
        host_val,
        Some("example.com".to_string()),
        "Host header value must match :authority 'example.com'; received: {raw_req:?}"
    );
    assert!(
        colon_headers.is_empty(),
        "no headers starting with ':' may reach the backend; found: {colon_headers:?}"
    );
}

/// Agreeing Host and :authority is accepted and forwarded with a single Host header.
#[test]
fn agreeing_host_and_authority_is_accepted_and_forwarded_with_single_host() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend_full();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2agree_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let payload = hpack_get_with_authority_and_headers(
        "/agree",
        "example.com",
        &[("host", "example.com")],
    );
    s.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s.flush().ok();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !seen.lock().expect("lock").is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let got = seen.lock().expect("lock").clone();
    let _ = std::fs::remove_file(&cfg);

    assert_eq!(
        got.len(),
        1,
        "agreeing Host and :authority must be accepted; got {got:?}"
    );

    let raw_req = &got[0];
    let host_headers: Vec<&str> = raw_req
        .lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("host:"))
        .collect();
    assert_eq!(
        host_headers.len(),
        1,
        "backend must receive exactly 1 host header; received: {raw_req:?}"
    );
}

/// Disagreeing Host vs :authority is rejected with `RST_STREAM` (RFC 9113 §8.3.1).
#[test]
fn disagreeing_host_and_authority_is_rejected_with_rst_stream() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend_full();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2disagree_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let payload = hpack_get_with_authority_and_headers(
        "/disagree",
        "example.com",
        &[("host", "evil.com")],
    );
    s.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s.flush().ok();

    let frames = recv_h2_frames(&mut s, Duration::from_secs(1));
    let _ = std::fs::remove_file(&cfg);

    let has_rst = frames.iter().any(|(ftype, _, sid, pld)| {
        *ftype == 0x03 && *sid == 1 && pld.len() >= 4 && u32::from_be_bytes([pld[0], pld[1], pld[2], pld[3]]) == 1
    });

    assert!(
        has_rst,
        "disagreeing Host vs :authority must trigger RST_STREAM (PROTOCOL_ERROR=1) on stream 1; frames received: {frames:?}"
    );

    let got = seen.lock().expect("lock").clone();
    assert!(
        got.is_empty(),
        "disagreeing Host vs :authority must not reach backend; backend saw: {got:?}"
    );
}

/// Unknown pseudo-header (e.g. :custom) is rejected with `RST_STREAM` (RFC 9113 §8.3).
#[test]
fn unknown_pseudo_header_is_rejected_with_rst_stream() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend_full();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2unknown_pseudo_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let payload = hpack_get_with_unknown_pseudo("/unknown", ":custom", "value");
    s.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s.flush().ok();

    let frames = recv_h2_frames(&mut s, Duration::from_secs(1));
    let _ = std::fs::remove_file(&cfg);

    let has_rst = frames.iter().any(|(ftype, _, sid, pld)| {
        *ftype == 0x03 && *sid == 1 && pld.len() >= 4 && u32::from_be_bytes([pld[0], pld[1], pld[2], pld[3]]) == 1
    });

    assert!(
        has_rst,
        "unknown pseudo-header must trigger RST_STREAM (PROTOCOL_ERROR=1) on stream 1; frames received: {frames:?}"
    );

    let got = seen.lock().expect("lock").clone();
    assert!(
        got.is_empty(),
        "unknown pseudo-header must not reach backend; backend saw: {got:?}"
    );
}

/// Pseudo-header appearing after regular header is rejected with `RST_STREAM` (RFC 9113 §8.3).
#[test]
fn pseudo_header_after_regular_header_is_rejected_with_rst_stream() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend_full();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2pseudo_after_reg_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let payload = hpack_get_pseudo_after_regular("/after_reg");
    s.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s.flush().ok();

    let frames = recv_h2_frames(&mut s, Duration::from_secs(1));
    let _ = std::fs::remove_file(&cfg);

    let has_rst = frames.iter().any(|(ftype, _, sid, pld)| {
        *ftype == 0x03 && *sid == 1 && pld.len() >= 4 && u32::from_be_bytes([pld[0], pld[1], pld[2], pld[3]]) == 1
    });

    assert!(
        has_rst,
        "pseudo-header after regular header must trigger RST_STREAM (PROTOCOL_ERROR=1) on stream 1; frames received: {frames:?}"
    );

    let got = seen.lock().expect("lock").clone();
    assert!(
        got.is_empty(),
        "pseudo-header after regular header must not reach backend; backend saw: {got:?}"
    );
}

/// Duplicate pseudo-header (e.g. duplicate :method) is rejected with `RST_STREAM` (RFC 9113 §8.3).
#[test]
fn duplicate_pseudo_header_is_rejected_with_rst_stream() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (backend_port, seen) = spawn_backend_full();
    let port = common::reserve_port();
    let cfg = std::env::temp_dir().join(format!("ibex_h2dup_pseudo_{}.cfg", std::process::id()));
    std::fs::write(
        &cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");

    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");

    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let payload = hpack_get_duplicate_pseudo("/dup");
    s.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s.flush().ok();

    let frames = recv_h2_frames(&mut s, Duration::from_secs(1));
    let _ = std::fs::remove_file(&cfg);

    let has_rst = frames.iter().any(|(ftype, _, sid, pld)| {
        *ftype == 0x03 && *sid == 1 && pld.len() >= 4 && u32::from_be_bytes([pld[0], pld[1], pld[2], pld[3]]) == 1
    });

    assert!(
        has_rst,
        "duplicate pseudo-header must trigger RST_STREAM (PROTOCOL_ERROR=1) on stream 1; frames received: {frames:?}"
    );

    let got = seen.lock().expect("lock").clone();
    assert!(
        got.is_empty(),
        "duplicate pseudo-header must not reach backend; backend saw: {got:?}"
    );
}

/// Compares received backend headers between HAProxy oracle and Ibex for an identical HTTP/2 request.
#[test]
fn h2_backend_headers_match_haproxy_reference_oracle() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let oracle_bin = std::path::PathBuf::from("/home/bhenc/reference/haproxy-quic/haproxy");
    let haproxy_bin = if oracle_bin.exists() {
        oracle_bin
    } else {
        std::path::PathBuf::from("/home/bhenc/reference/haproxy/haproxy")
    };
    if !haproxy_bin.exists() {
        return;
    }

    // 1. Run HAProxy
    let (haproxy_be_port, haproxy_seen) = spawn_backend_full();
    let haproxy_port = common::reserve_port();
    let haproxy_cfg = std::env::temp_dir().join(format!("haproxy_diff_{}.cfg", std::process::id()));
    std::fs::write(
        &haproxy_cfg,
        format!(
            "global\n\ttune.h2.fe.glitches-threshold 100\n\ndefaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{haproxy_port} proto h2\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{haproxy_be_port}\n"
        ),
    )
    .expect("write haproxy cfg");

    let _d_haproxy = Daemon(
        Command::new(&haproxy_bin)
            .arg("-f")
            .arg(&haproxy_cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn haproxy"),
    );
    assert!(wait_for_port(haproxy_port), "haproxy never listened on {haproxy_port}");

    let mut s_haproxy = TcpStream::connect(("127.0.0.1", haproxy_port)).expect("connect haproxy");
    s_haproxy.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s_haproxy.write_all(&frame(0x04, 0, 0, &[])).expect("settings");

    let payload = hpack_get_with_authority_and_headers(
        "/probe",
        "example.com",
        &[("user-agent", "curl/8.18.0"), ("accept", "*/*")],
    );
    s_haproxy.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s_haproxy.flush().ok();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !haproxy_seen.lock().expect("lock").is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let haproxy_got = haproxy_seen.lock().expect("lock").clone();
    let _ = std::fs::remove_file(&haproxy_cfg);

    // 2. Run Ibex
    let (ibex_be_port, ibex_seen) = spawn_backend_full();
    let ibex_port = common::reserve_port();
    let ibex_cfg = std::env::temp_dir().join(format!("ibex_diff_{}.cfg", std::process::id()));
    std::fs::write(
        &ibex_cfg,
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\t\
             timeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{ibex_port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{ibex_be_port}\n"
        ),
    )
    .expect("write ibex cfg");

    let _d_ibex = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(&ibex_cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(ibex_port), "ibex never listened on {ibex_port}");

    let mut s_ibex = TcpStream::connect(("127.0.0.1", ibex_port)).expect("connect ibex");
    s_ibex.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s_ibex.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    s_ibex.write_all(&frame(0x01, 0x05, 1, &payload)).expect("headers");
    s_ibex.flush().ok();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !ibex_seen.lock().expect("lock").is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let ibex_got = ibex_seen.lock().expect("lock").clone();
    let _ = std::fs::remove_file(&ibex_cfg);

    assert_eq!(haproxy_got.len(), 1, "HAProxy must produce 1 request");
    assert_eq!(ibex_got.len(), 1, "Ibex must produce 1 request");

    let parse_hdrs = |raw: &str| -> (String, Vec<(String, String)>) {
        let lines: Vec<&str> = raw.lines().collect();
        let req_line = lines.first().copied().unwrap_or("").to_string();
        let mut hdrs = Vec::new();
        for line in &lines[1..] {
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                hdrs.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        hdrs.sort();
        (req_line, hdrs)
    };

    let (haproxy_req, haproxy_hdrs) = parse_hdrs(&haproxy_got[0]);
    let (ibex_req, ibex_hdrs) = parse_hdrs(&ibex_got[0]);

    assert_eq!(ibex_req, haproxy_req, "Request lines must match");
    assert_eq!(
        ibex_hdrs, haproxy_hdrs,
        "Forwarded HTTP/1.1 headers between Ibex and HAProxy oracle must match identically.\nIbex saw: {:?}\nHAProxy saw: {:?}",
        ibex_got[0], haproxy_got[0]
    );
}

// ---- responses the HTTP/1 server shapes oddly ---------------------------------------

/// A backend that answers every request with `raw`, then closes.
fn raw_backend(raw: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            c.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
            let _ = c.write_all(raw);
        }
    });
    port
}

/// One h2c GET for `/` through a daemon in front of `backend_port`; the frames that come
/// back within two seconds.
fn h2_get_through(backend_port: u16) -> Vec<(u8, u8, u32, Vec<u8>)> {
    let port = common::reserve_port();
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(
        cfg.path(),
        format!(
            "defaults\n\tmode http\n\ttimeout connect 3s\n\ttimeout client 10s\n\ttimeout server 10s\n\n\
             frontend fe\n\tbind 127.0.0.1:{port}\n\tdefault_backend be\n\n\
             backend be\n\tserver s1 127.0.0.1:{backend_port}\n"
        ),
    )
    .expect("write config");
    let _d = Daemon(
        Command::new(ibex_bin())
            .arg("-f")
            .arg(cfg.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex"),
    );
    assert!(wait_for_port(port), "the daemon never listened on {port}");
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").expect("preface");
    s.write_all(&frame(0x04, 0, 0, &[])).expect("settings");
    s.write_all(&frame(0x01, 0x05, 1, &hpack_get("/"))).expect("headers");
    recv_h2_frames(&mut s, Duration::from_secs(2))
}

/// Whether a `:status 200` HEADERS (HPACK static index 8, `0x88`) came on stream 1, and
/// the DATA bytes on it.
fn status_200_and_data(frames: &[(u8, u8, u32, Vec<u8>)]) -> (bool, Vec<u8>) {
    let ok = frames.iter().any(|(t, _, sid, p)| *t == 0x01 && *sid == 1 && p.first() == Some(&0x88));
    let data = frames
        .iter()
        .filter(|(t, _, sid, _)| *t == 0x00 && *sid == 1)
        .flat_map(|(_, _, _, p)| p.clone())
        .collect();
    (ok, data)
}

/// An unsolicited interim `100 Continue` from the HTTP/1 server ahead of the final
/// response, in one packet: the final response reaches the HTTP/2 client.
///
/// `HAProxy` 3.5-dev8 sends a `:status 100` HEADERS frame and then the 200. Ibex drops the
/// interim response (`h2_forward_response`), which is the HTTP/2 1xx gap design 010 step 5
/// closes; only the final response is asserted here. (3.5-dev7 aborted on this exchange,
/// `BUG_ON` at `src/htx.c:391`, fixed upstream by 76454cbbf.)
#[test]
fn an_interim_response_ahead_of_the_final_one_reaches_an_h2_client() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let be = raw_backend(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let frames = h2_get_through(be);
    let (ok, data) = status_200_and_data(&frames);
    assert!(ok, "no :status 200 HEADERS on stream 1: {frames:?}");
    assert_eq!(data, b"ok", "{frames:?}");
}

/// The HTTP/1 server closes in the middle of the body: what arrived reaches the HTTP/2
/// client. `HAProxy` 3.5: HEADERS (`content-length: 100`), DATA `hello`, then
/// `RST_STREAM CANCEL`.
///
/// Not asserted, because Ibex differs: it ends the stream with `END_STREAM` on the DATA
/// frame, telling the client a truncated body is complete. `H2MuxContext::send_response`
/// has no way to leave a stream open for a reset; that belongs with per-stream
/// transactions (design 010 step 5) and is reported, not fixed here.
#[test]
fn a_response_cut_short_delivers_what_arrived_to_an_h2_client() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let be = raw_backend(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello");
    let frames = h2_get_through(be);
    let (ok, data) = status_200_and_data(&frames);
    assert!(ok, "no :status 200 HEADERS on stream 1: {frames:?}");
    assert_eq!(data, b"hello", "{frames:?}");
}
