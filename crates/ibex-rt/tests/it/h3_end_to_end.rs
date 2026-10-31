// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `curl --http3` against Ibex must return 200.
//!
//! Everything below this test existed separately and was never connected: the datagram path
//! (`dgram.rs` over `ibex-mmsg`), the QUIC transport (`ibex-quic` over `quinn-proto`), the
//! HTTP/3 frame parser (`h3.rs`) and the QPACK decoder (`qpack.rs`). A handshake completed
//! and then the connection hung, because no code path could produce a response. The QUIC
//! parity report was filled in with "Blocked on T25" for every Ibex conformance row.
//!
//! This is the end-to-end check that the chain is closed:
//!
//!   UDP datagram -> QUIC packet -> stream -> HTTP/3 HEADERS -> QPACK decode
//!     -> response -> QPACK encode -> HEADERS + DATA -> stream -> QUIC -> UDP datagram

use crate::common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Ibex started on a real configuration (T463): one frontend with a QUIC bind, one backend.
/// Every request goes through the stream engine, the path an operator's Ibex takes.
struct Ibex {
    child: Child,
    _cfg: tempfile::NamedTempFile,
    port: u16,
}

impl Ibex {
    fn start(backend: std::net::SocketAddr) -> Self {
        let tcp = common::reserve_addr();
        let quic = common::reserve_addr();
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let cfg = format!(
            "global\n  nbthread 1\n\
             defaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\n\
             frontend fe\n  bind {tcp}\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  default_backend be\n\
             backend be\n  server s1 {backend}\n"
        );
        let mut f = tempfile::NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("write cfg");
        let child = common::ibex_command(env!("CARGO_BIN_EXE_ibex"))
            .arg("-f")
            .arg(f.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ibex");
        assert!(common::wait_listening(tcp), "ibex never started listening on {tcp}");
        Self { child, _cfg: f, port: quic.port() }
    }
}

impl Drop for Ibex {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn curl_has_http3() -> bool {
    Command::new("curl")
        .arg("-V")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"))
}

/// A backend that echoes what it was asked, so the test can assert the request survived the
/// HTTP/3 -> HTTP/1.1 conversion rather than only that a response came back.
fn spawn_echo_backend(stop: Arc<AtomicBool>) -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let addr = l.local_addr().expect("backend addr");
    l.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match l.accept() {
                Ok((mut c, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = c.set_read_timeout(Some(Duration::from_millis(200)));
                    let n = c.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first = req.lines().next().unwrap_or("").to_string();
                    let host = req
                        .lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                        .unwrap_or("host: MISSING")
                        .to_string();
                    let body = format!("{first}|{host}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = c.write_all(resp.as_bytes());
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    addr
}

crate::h3_both_paths! {
/// Known to flake rarely under a loaded parallel suite: 1 failure in 30 full-suite runs
/// (2026-10-02), none in 48 runs alone. Cause not found; see `data/suite_baseline.json`
/// (`known_flaky`). One red run is that; a repeatable failure is not.
fn curl_http3_is_proxied_to_a_backend() {
    if !curl_has_http3() {
        eprintln!("curl on this host has no HTTP3 support; skipping");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let backend = spawn_echo_backend(Arc::clone(&stop));

    let ibex = Ibex::start(backend);
    let port = ibex.port;

    let out = Command::new("curl")
        .args([
            "-sS", "--http3-only", "-k", "--max-time", "15",
            "--resolve", &format!("localhost:{port}:127.0.0.1"),
            &format!("https://localhost:{port}/probe"),
            "-o", "-", "-w", "\n__STATUS__%{http_code}",
        ])
        .output()
        .expect("run curl");

    drop(ibex);
    stop.store(true, Ordering::Relaxed);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(stdout.contains("__STATUS__200"), "expected 200.\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("GET /probe HTTP/1.1"),
        "the backend must receive an HTTP/1.1 request line with the original path.\nstdout: {stdout}"
    );
    assert!(
        stdout.to_ascii_lowercase().contains("host: localhost"),
        "RFC 9112 requires Host; :authority must become it, as HAProxy does.\nstdout: {stdout}"
    );
    assert!(
        !stdout.contains(":authority") && !stdout.contains(":scheme"),
        "no pseudo-header may reach an HTTP/1 backend.\nstdout: {stdout}"
    );
}
}

crate::h3_both_paths! {
fn curl_http3_gets_a_response_from_ibex() {
    if !curl_has_http3() {
        eprintln!("curl on this host has no HTTP3 support; skipping");
        return;
    }

    // The body comes from a backend now: Ibex has no canned response of its own (T463).
    let stop = Arc::new(AtomicBool::new(false));
    let l = TcpListener::bind("127.0.0.1:0").expect("bind backend");
    let backend = l.local_addr().expect("addr");
    l.set_nonblocking(true).expect("nonblocking");
    let stop_be = Arc::clone(&stop);
    thread::spawn(move || {
        while !stop_be.load(Ordering::Relaxed) {
            match l.accept() {
                Ok((mut c, _)) => {
                    let mut buf = [0u8; 4096];
                    let _ = c.set_read_timeout(Some(Duration::from_millis(200)));
                    let _ = c.read(&mut buf);
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nhello-from-ibex-h3");
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });
    let ibex = Ibex::start(backend);
    let port = ibex.port;

    let out = Command::new("curl")
        .args([
            "-sS",
            "--http3-only",
            "-k",
            "--max-time",
            "15",
            "--resolve",
            &format!("localhost:{port}:127.0.0.1"),
            &format!("https://localhost:{port}/probe"),
            "-o",
            "-",
            "-w",
            "\n__STATUS__%{http_code} __VER__%{http_version}",
        ])
        .output()
        .expect("run curl");

    drop(ibex);
    stop.store(true, Ordering::Relaxed);

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stdout.contains("__STATUS__200"),
        "curl --http3 must get 200 from Ibex.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("__VER__3"),
        "the response must arrive over HTTP/3, not a fallback.\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("hello-from-ibex-h3"),
        "the response body must reach the client.\nstdout: {stdout}"
    );
}
}

const BACKEND_DELAY: Duration = Duration::from_millis(1000);

crate::h3_both_paths! {
/// A slow backend stalls only its own request, not the whole listener.
///
/// This is the property the non-blocking backend leg exists for, and the one the first
/// version did not have: it did `TcpStream::connect` plus blocking reads inside the pump
/// loop, so every QUIC connection on the listener waited for whichever backend request was
/// in flight. Two concurrent requests against a backend that takes ~1s each would have taken
/// ~2s serialised; overlapped they take ~1s.
fn a_slow_backend_does_not_stall_other_quic_connections() {
    if !curl_has_http3() {
        eprintln!("curl on this host has no HTTP3 support; skipping");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_be = Arc::clone(&stop);
    let l = TcpListener::bind("127.0.0.1:0").expect("bind slow backend");
    let backend = l.local_addr().expect("addr");
    l.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        while !stop_be.load(Ordering::Relaxed) {
            match l.accept() {
                Ok((mut c, _)) => {
                    // Each connection gets its own thread, so the backend itself is not the
                    // bottleneck -- any serialisation observed is the proxy's.
                    thread::spawn(move || {
                        let mut buf = [0u8; 4096];
                        let _ = c.set_read_timeout(Some(Duration::from_millis(500)));
                        let _ = c.read(&mut buf);
                        thread::sleep(BACKEND_DELAY);
                        let body = b"slow";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            String::from_utf8_lossy(body)
                        );
                        let _ = c.write_all(resp.as_bytes());
                    });
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
    });

    let ibex = Ibex::start(backend);
    let port = ibex.port;

    let started = Instant::now();
    let clients: Vec<_> = (0..2)
        .map(|i| {
            thread::spawn(move || {
                Command::new("curl")
                    .args([
                        "-sS", "--http3-only", "-k", "--max-time", "20",
                        "--resolve", &format!("localhost:{port}:127.0.0.1"),
                        &format!("https://localhost:{port}/slow{i}"),
                        "-o", "-", "-w", "|%{http_code}",
                    ])
                    .output()
                    .expect("run curl")
            })
        })
        .collect();

    let outs: Vec<String> = clients
        .into_iter()
        .map(|h| String::from_utf8_lossy(&h.join().expect("join").stdout).to_string())
        .collect();
    let elapsed = started.elapsed();

    drop(ibex);
    stop.store(true, Ordering::Relaxed);

    for (i, o) in outs.iter().enumerate() {
        assert!(o.contains("|200"), "request {i} did not get 200: {o}");
    }

    // Serialised would be >= 2 x BACKEND_DELAY. The margin is deliberately wide: this is a
    // timing assertion on a shared box, and the failure it guards against is a doubling,
    // not a few percent.
    let serialised = BACKEND_DELAY * 2;
    assert!(
        elapsed < serialised,
        "two requests against a {BACKEND_DELAY:?} backend took {elapsed:?}; \
         serialised would be >= {serialised:?}, so the backend leg is blocking the pump loop"
    );
}
}
