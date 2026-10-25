// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T509): counts allocations through a #[global_allocator]

//! An HTTP/3 request through the h3 mux and the bridge (`tune.ibex.h3-path mux`, T509;
//! `docs/design/h3-engine-2026-10-26.md` sections 0 and 6) allocates nothing in steady state,
//! as the h2 path's `an_h2c_request_allocates_nothing` pins. The client is a `quinn-proto`
//! connection in this thread; only what the engine does (`Engine::run_once`) is counted,
//! with this thread's counters, so the client's own allocations are not.

mod common;

use ibex_alloc::CountingAllocator;
use ibex_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Dir, Endpoint, EndpointConfig, Event, StreamId,
};
use ibex_rt::engine::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

#[derive(Debug)]
struct Any;
impl ServerCertVerifier for Any {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default().map(|p| p.signature_verification_algorithms.supported_schemes()).unwrap_or_default()
    }
}

/// A keep-alive HTTP/1.1 server answering every head with `ok`.
fn backend(running: Arc<AtomicBool>) -> (SocketAddr, thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("addr");
    l.set_nonblocking(true).expect("nonblocking");
    let h = thread::spawn(move || {
        let mut conns: Vec<TcpStream> = Vec::new();
        let mut buf = [0u8; 4096];
        while running.load(Ordering::Relaxed) {
            if let Ok((s, _)) = l.accept() {
                s.set_nonblocking(true).expect("nonblocking");
                conns.push(s);
            }
            conns.retain_mut(|s| match s.read(&mut buf) {
                Ok(0) => false,
                Ok(n) => {
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    }
                    true
                }
                Err(e) => e.kind() == std::io::ErrorKind::WouldBlock,
            });
            thread::sleep(Duration::from_micros(200));
        }
    });
    (addr, h)
}

/// The client and the engine it talks to; what the engine allocated, counted.
struct Rig {
    engine: Engine,
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    buf: Vec<u8>,
    out: Vec<u8>,
    resp: Vec<u8>,
    engine_allocs: usize,
}

impl Rig {
    fn new(be: SocketAddr) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let quic = common::reserve_addr();
        let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
        let cfg = format!(
            "global\n  tune.ibex.h3-path mux\n\
             defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
             frontend f\n  bind quic4@{quic} ssl crt {crt} alpn h3\n  default_backend b\nbackend b\n  server s1 {be}\n"
        );
        let engine = Engine::new(&ibex_config::parse_str(&cfg).expect("parse"), 64).expect("Engine::new");
        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, quic, "localhost").expect("connect");
        let mut rig = Self { engine, sock, ep, handle, conn, buf: vec![0u8; 65536], out: Vec::with_capacity(2048), resp: Vec::with_capacity(4096), engine_allocs: 0 };
        let deadline = Instant::now() + Duration::from_secs(5);
        while rig.conn.is_handshaking() && Instant::now() < deadline {
            rig.step();
        }
        assert!(!rig.conn.is_handshaking(), "no handshake");
        rig
    }

    fn step(&mut self) {
        let now = Instant::now();
        while let Some(t) = self.conn.poll_transmit(now, 1, &mut self.out) {
            let _ = self.sock.send_to(&self.out[..t.size], t.destination);
            self.out.clear();
        }
        let before = ibex_alloc::thread_alloc_counters();
        let _ = self.engine.run_once();
        self.engine_allocs += before.diff(&ibex_alloc::thread_alloc_counters()).alloc_count;
        let now = Instant::now();
        while let Ok((n, from)) = self.sock.recv_from(&mut self.buf) {
            let mut resp = Vec::new();
            if let Some(ibex_quic::quinn_proto::DatagramEvent::ConnectionEvent(_, e)) = self.ep.handle(now, from, None, None, self.buf[..n].into(), &mut resp) {
                self.conn.handle_event(e);
            }
        }
        if self.conn.poll_timeout().is_some_and(|t| t <= now) {
            self.conn.handle_timeout(now);
        }
        while let Some(e) = self.conn.poll_endpoint_events() {
            if let Some(ce) = self.ep.handle_event(self.handle, e) {
                self.conn.handle_event(ce);
            }
        }
        while let Some(ev) = self.conn.poll() {
            assert!(!matches!(ev, Event::ConnectionLost { .. }), "connection lost: {ev:?}");
        }
    }

    /// One GET on a new stream, run until its response has ended.
    fn request(&mut self, req: &[u8]) {
        let id: StreamId = self.conn.streams().open(Dir::Bi).expect("open");
        let mut s = self.conn.send_stream(id);
        assert_eq!(s.write(req).expect("write"), req.len());
        s.finish().expect("finish");
        self.resp.clear();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut fin = false;
        while !fin && Instant::now() < deadline {
            self.step();
            let mut rs = self.conn.recv_stream(id);
            if let Ok(mut chunks) = rs.read(true) {
                loop {
                    match chunks.next(usize::MAX) {
                        Ok(Some(c)) => self.resp.extend_from_slice(&c.bytes),
                        Ok(None) => {
                            fin = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let _ = chunks.finalize();
            };
        }
        assert!(fin, "the response on {id} never ended: {:?}", self.resp);
        assert!(self.resp.ends_with(b"ok"), "not the server's body: {:?}", self.resp);
    }
}

/// The engine's allocations over `n` requests on one connection, after five warm-up ones.
fn h3_allocations(n: usize) -> usize {
    let running = Arc::new(AtomicBool::new(true));
    let (be, h) = backend(Arc::clone(&running));
    let mut rig = Rig::new(be);
    let f: Vec<(String, String)> =
        [(":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", "/")].iter().map(|(a, b)| ((*a).to_string(), (*b).to_string())).collect();
    let mut req = Vec::new();
    ibex_proto::mux_h3::encode_frame(&mut req, 0x01, &ibex_proto::mux_h3::encode_field_section(&f));
    for _ in 0..5 {
        rig.request(&req);
    }
    rig.engine_allocs = 0;
    for _ in 0..n {
        rig.request(&req);
    }
    let allocs = rig.engine_allocs;
    drop(rig);
    running.store(false, Ordering::Relaxed);
    let _ = h.join();
    allocs
}

/// T509 (design section 6): the target is a steady-state HTTP/3 request through the mux that
/// allocates nothing (the count for 220 requests the count for 20). Not met yet: measured
/// 2026-10-26, 483 for 20 and 5034 to 5075 for 220, about 23 a request (quinn-proto's stream
/// state and the `Bytes` of each STREAM frame in and out among them; not broken down yet,
/// `tasks/T509-progress.md`). Until it is, this pins the figure so that it does not grow:
/// at most 24 a request.
#[test]
fn an_h3_request_through_the_mux_allocates_at_most_the_pinned_count() {
    let few = h3_allocations(20);
    let many = h3_allocations(220);
    println!("[MEASUREMENT T509] h3 mux allocations: 20 requests {few}, 220 requests {many}");
    let per_request = many.saturating_sub(few) / 200;
    assert!(per_request <= 24, "{per_request} allocations a request ({few} for 20, {many} for 220); pinned at 24, target 0");
}
