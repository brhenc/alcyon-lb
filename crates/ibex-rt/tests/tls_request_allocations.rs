// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary: counts the engine thread's allocations (#[global_allocator]).

//! T440: a steady-state keep-alive request over TLS allocates nothing on the engine's thread.
//!
//! The engine runs on the test thread; the TLS client (and the server, when the backend speaks
//! TLS too) run on threads of their own, so that only the proxy's allocations are counted
//! (`ibex_alloc::thread_alloc_counters`). The count for 1100 requests must equal the count for
//! 100: whatever is left is one-time (the handshake), not per request.
//!
//! Before (rustls 0.23.45, buffered connections): about 5 per request, 3 of them inside rustls
//! (`read_tls` into its own receive buffer, `take_received_plaintext`, one `PrefixedPayload`
//! per record sent). See `tradeoff.md` 6.20 and `tasks/T440-rustls-0.24-caller-owned-buffers.md`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ibex_alloc::CountingAllocator;
use ibex_rt::engine::Engine;

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn loopback0() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = l.local_addr().expect("local_addr");
    (l, addr)
}

/// A self-signed certificate for `localhost`: the PEM bundle a `crt` file holds, and its DER.
fn cert() -> (String, Vec<u8>, Vec<u8>) {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("generate cert");
    (format!("{}{}", c.cert.pem(), c.key_pair.serialize_pem()), c.cert.der().to_vec(), c.key_pair.serialize_der())
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config(ca_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(ca_der.to_vec())).expect("root");
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A keep-alive HTTP/1.1 server answering every head with a 2-byte body, in plaintext or, with
/// `tls`, over TLS (one thread per connection; its allocations are not the engine's).
fn start_backend(listener: TcpListener, tls: Option<Arc<rustls::ServerConfig>>, running: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        while running.load(Ordering::Relaxed) {
            let Ok((s, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            s.set_nonblocking(false).expect("blocking");
            s.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
            let tls = tls.clone();
            let running = Arc::clone(&running);
            thread::spawn(move || {
                let mut io: Box<dyn ReadWrite> = match tls {
                    Some(cfg) => Box::new(rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).expect("server conn"), s)),
                    None => Box::new(s),
                };
                let mut buf = [0u8; 4096];
                let mut have = Vec::new();
                while running.load(Ordering::Relaxed) {
                    match io.read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => have.extend_from_slice(&buf[..n]),
                        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                        Err(_) => return,
                    }
                    while let Some(p) = have.windows(4).position(|w| w == b"\r\n\r\n") {
                        have.drain(..p + 4);
                        if io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                            return;
                        }
                        let _ = io.flush();
                    }
                }
            });
        }
    })
}

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// The engine thread's allocations over `n` keep-alive requests on one TLS client connection,
/// after three warm-up requests (the handshake among them). `backend_tls`: the server line
/// speaks TLS too (`ssl verify none`).
fn tls_keepalive_allocations(n: usize, backend_tls: bool) -> usize {
    let (pem, der, key) = cert();
    let dir = tempfile::tempdir().expect("tempdir");
    let crt = dir.path().join("fe.pem");
    std::fs::write(&crt, pem).expect("write crt");

    let (srv, srv_addr) = loopback0();
    let (l, addr) = loopback0();
    drop(l);
    let running = Arc::new(AtomicBool::new(true));
    let be_tls = backend_tls.then(|| {
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key.clone().into());
        Arc::new(
            rustls::ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_no_client_auth()
                .with_single_cert(vec![der.clone().into()], key)
                .expect("server cert"),
        )
    });
    let be = start_backend(srv, be_tls, Arc::clone(&running));
    let ssl = if backend_tls { " ssl verify none" } else { "" };
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend f\n  bind {addr} ssl crt {}\n  default_backend b\nbackend b\n  server s1 {srv_addr}{ssl}\n",
        crt.display()
    );
    let mut engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");

    // 0: running; 1: warm-up done, waiting for the go; 2: measuring; 3: done.
    let phase = Arc::new(AtomicUsize::new(0));
    let client = {
        let phase = Arc::clone(&phase);
        let config = client_config(&der);
        thread::spawn(move || {
            let sock = TcpStream::connect(addr).expect("connect to frontend");
            let conn = rustls::ClientConnection::new(config, "localhost".try_into().expect("name")).expect("client conn");
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut one = |tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>| {
                tls.write_all(b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write req");
                let mut got = [0u8; 512];
                let mut len = 0;
                while !got[..len].ends_with(b"\r\n\r\nok") {
                    let r = tls.read(&mut got[len..]).expect("read response");
                    assert!(r > 0, "the proxy closed: {:?}", String::from_utf8_lossy(&got[..len]));
                    len += r;
                }
                assert!(got.starts_with(b"HTTP/1.1 200"), "response: {:?}", String::from_utf8_lossy(&got[..len]));
            };
            for _ in 0..3 {
                one(&mut tls);
            }
            phase.store(1, Ordering::SeqCst);
            while phase.load(Ordering::SeqCst) != 2 {
                thread::yield_now();
            }
            for _ in 0..n {
                one(&mut tls);
            }
            phase.store(3, Ordering::SeqCst);
            tls
        })
    };

    let deadline = Instant::now() + Duration::from_secs(120);
    while phase.load(Ordering::SeqCst) != 1 {
        assert!(Instant::now() < deadline, "the warm-up requests did not complete");
        let _ = engine.run_once();
    }
    let before = ibex_alloc::thread_alloc_counters();
    phase.store(2, Ordering::SeqCst);
    while phase.load(Ordering::SeqCst) != 3 {
        assert!(Instant::now() < deadline, "the measured requests did not complete");
        let _ = engine.run_once();
    }
    let diff = before.diff(&ibex_alloc::thread_alloc_counters());
    let tls = client.join().expect("client thread");
    drop(tls);
    for _ in 0..5 {
        let _ = engine.run_once();
    }
    running.store(false, Ordering::Relaxed);
    let _ = be.join();
    diff.alloc_count
}

/// A keep-alive request from a TLS client, proxied to a plaintext server.
#[test]
fn a_tls_keep_alive_request_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let few = tls_keepalive_allocations(100, false);
    let many = tls_keepalive_allocations(1100, false);
    println!("[MEASUREMENT T440] TLS keep-alive allocations: 100 requests {few}, 1100 requests {many}");
    assert_eq!(many, few, "1000 more TLS keep-alive requests made {} more allocations", many as i64 - few as i64);
}

/// The same with the server line speaking TLS as well: both the frontend and the backend
/// sessions, on the engine's thread.
#[test]
fn a_tls_to_tls_keep_alive_request_allocates_nothing() {
    let _lock = TEST_MUTEX.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let few = tls_keepalive_allocations(100, true);
    let many = tls_keepalive_allocations(1100, true);
    println!("[MEASUREMENT T440] TLS to TLS keep-alive allocations: 100 requests {few}, 1100 requests {many}");
    assert_eq!(many, few, "1000 more TLS-to-TLS keep-alive requests made {} more allocations", many as i64 - few as i64);
}
