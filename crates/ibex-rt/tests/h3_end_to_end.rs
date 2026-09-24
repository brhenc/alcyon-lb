// SPDX-License-Identifier: GPL-2.0-or-later
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

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_rt::QuicListener;
use rustls::ServerConfig;

const CERT: &str = "../../examples/certs/localhost.pem";

fn server_config() -> Arc<ServerConfig> {
    ibex_tls::config::install_default_crypto_provider();
    let path = std::path::Path::new(CERT);
    let (certs, key) = ibex_tls::config::load_cert_file(path).expect("load test certificate");
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build server config");
    // Without this a client offering h3 gets no ALPN back and gives up before sending a
    // request, which looks exactly like a server that is not listening.
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(cfg)
}

fn curl_has_http3() -> bool {
    Command::new("curl")
        .arg("-V")
        .output()
        .ok()
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).contains("HTTP3"))
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

#[test]
fn curl_http3_is_proxied_to_a_backend() {
    if !curl_has_http3() {
        eprintln!("curl on this host has no HTTP3 support; skipping");
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let backend = spawn_echo_backend(Arc::clone(&stop));

    let tls = server_config();
    let addr = "127.0.0.1:0".parse().expect("addr");
    let mut listener = QuicListener::bind(addr, &tls, None).expect("bind QUIC listener");
    listener.set_backend(backend);
    let port = listener.addr().port();

    let stop_worker = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        while !stop_worker.load(Ordering::Relaxed) {
            let _ = listener.pump(Instant::now());
            thread::sleep(Duration::from_millis(2));
        }
    });

    let out = Command::new("curl")
        .args([
            "-sS", "--http3-only", "-k", "--max-time", "15",
            "--resolve", &format!("localhost:{port}:127.0.0.1"),
            &format!("https://localhost:{port}/probe"),
            "-o", "-", "-w", "\n__STATUS__%{http_code}",
        ])
        .output()
        .expect("run curl");

    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();
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

#[test]
fn curl_http3_gets_a_response_from_ibex() {
    if !curl_has_http3() {
        eprintln!("curl on this host has no HTTP3 support; skipping");
        return;
    }

    let tls = server_config();
    let addr = "127.0.0.1:0".parse().expect("addr");
    let mut listener = QuicListener::bind(addr, &tls, None).expect("bind QUIC listener");
    let port = listener.addr().port();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = Arc::clone(&stop);

    // The listener is not yet driven by the engine's poller, so the test drives it. A short
    // sleep between pumps keeps this from spinning a core while curl does its handshake.
    let worker = thread::spawn(move || {
        while !stop_worker.load(Ordering::Relaxed) {
            let _ = listener.pump(Instant::now());
            thread::sleep(Duration::from_millis(2));
        }
    });

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

    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();

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
