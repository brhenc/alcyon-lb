// SPDX-License-Identifier: GPL-2.0-or-later

//! HTTP/2 stream multiplexing, against the real daemon over cleartext h2c.
//!
//! `curl --http2` passing proves one request works. Multiplexing is the thing HTTP/2 is
//! *for*, and it is a separate claim: several concurrent streams on one connection, each
//! carrying its own request, each reaching the backend once and unchanged.
//!
//! Cleartext rather than TLS deliberately — the defect is in the mux, and putting a TLS
//! handshake in front of it only adds ways for the test to fail for unrelated reasons.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
    let len = payload.len();
    let mut v = Vec::with_capacity(9 + len);
    v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
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
    let (backend_port, seen) = spawn_backend();
    let port = free_port();
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
}
