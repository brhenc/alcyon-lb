// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T480: after a QUIC handshake step, the stack below the TLS session holds none of the TLS 1.3
//! traffic secrets (`ibex_alloc::scrub_stack` in `TlsSession::read_handshake`, under
//! `tune.ibex.ssl-zero-buffers`; T462 did the same for TCP's `TlsCtx::handshake`).
//!
//! The server endpoint is fed the client's datagrams one at a time. Around each call the probe
//! paints the stack below the caller and copies it out (`ibex_alloc::stack_probe`, test-only);
//! the secrets come from a `KeyLog` on the bind. With the scrub off on this thread, the copies
//! must hold a secret (so that the probe is shown to see them); on, none.
//!
//! Runs in a thread of its own with an 8 MiB stack, so that the probe's window is mapped stack.

#![cfg(target_arch = "x86_64")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ibex_alloc::stack_probe;
use ibex_quic::{load_pem_cert_and_key, QuicConfig, QuicEndpoint, QuicTransport, TransportEvent, ALPN_H3};
use ibex_tls::tcp::BindTls;

const WINDOW: usize = 1024 * 1024;
const PAINT: u8 = 0xa5;

#[derive(Debug, Default)]
struct Secrets(Mutex<Vec<(String, Vec<u8>)>>);

impl ibex_tls::tcp::rustls24::KeyLog for Secrets {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        self.0.lock().unwrap().push((label.to_string(), secret.to_vec()));
    }
}

/// One call into the server at a fixed depth: paints the window below, calls, copies it out.
#[inline(never)]
fn feed(server: &mut QuicEndpoint, now: Instant, addr: SocketAddr, data: &[u8], snap: &mut [u8]) {
    stack_probe::paint_below(snap.len(), PAINT);
    server.handle_datagram(now, addr, None, data).expect("server datagram");
    stack_probe::copy_below(snap);
}

/// Runs one handshake; returns the secrets logged and the (label, step) found in the copies.
fn handshake(scrub: bool) -> (usize, Vec<(String, usize)>) {
    stack_probe::set_thread_ssl_zero_buffers(scrub);
    let pem = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/certs/localhost.pem");
    let (certs, key) = load_pem_cert_and_key(&pem).expect("pem");
    let log = Arc::new(Secrets::default());
    let b = BindTls::single_tls13(certs, key, vec![ALPN_H3.to_vec()]).expect("bind");
    let mut cfg = (*b.config).clone();
    cfg.key_log = Arc::clone(&log) as Arc<dyn ibex_tls::tcp::rustls24::KeyLog>;
    let cfg = Arc::new(cfg);
    let b = Arc::new(BindTls::from_parts(Arc::clone(&cfg), cfg, Arc::clone(&b.resolver), b.provider));
    let server_config = QuicConfig::new().build_server_config(&b).expect("quic config");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).expect("client crypto");
    let config = quinn_proto::ClientConfig::new(Arc::new(crypto));
    let mut client = quinn_proto::Endpoint::new(Arc::new(quinn_proto::EndpointConfig::default()), None, false, None);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55611);
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let mut now = Instant::now();
    let (handle, mut conn) = client.connect(now, config, server_addr, "localhost").expect("connect");
    let (mut cbuf, mut sbuf) = (Vec::new(), vec![0u8; 65535]);
    let mut snap = vec![0u8; WINDOW];
    let mut snaps: Vec<Vec<u8>> = Vec::new();
    let mut up = false;
    for _ in 0..100 {
        now += Duration::from_millis(5);
        cbuf.clear();
        while let Some(tx) = conn.poll_transmit(now, 1, &mut cbuf) {
            feed(&mut server, now, client_addr, &cbuf[..tx.size], &mut snap);
            snaps.push(snap.clone());
            cbuf.clear();
        }
        while let Some(tx) = server.poll_transmit(now, &mut sbuf) {
            let mut resp = Vec::new();
            if let Some(quinn_proto::DatagramEvent::ConnectionEvent(_, ev)) =
                client.handle(now, server_addr, None, None, bytes::BytesMut::from(&sbuf[..tx.size]), &mut resp)
            {
                conn.handle_event(ev);
            }
        }
        while let Some(ev) = conn.poll_endpoint_events() {
            if let Some(ev) = client.handle_event(handle, ev) {
                conn.handle_event(ev);
            }
        }
        while server.poll_event().is_some_and(|ev| {
            up |= matches!(ev, TransportEvent::HandshakeComplete { .. });
            true
        }) {}
        if up {
            break;
        }
    }
    stack_probe::set_thread_ssl_zero_buffers(true);
    assert!(up, "the handshake did not complete");
    let secrets = log.0.lock().unwrap().clone();
    let mut found = Vec::new();
    for (label, secret) in &secrets {
        for (i, s) in snaps.iter().enumerate() {
            if s.windows(secret.len()).any(|w| w == secret.as_slice()) && !found.contains(&(label.clone(), i)) {
                found.push((label.clone(), i));
            }
        }
    }
    (secrets.len(), found)
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[test]
fn no_quic_handshake_secret_is_left_on_the_stack_below_the_tls_session() {
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(|| {
            let (n, off) = handshake(false);
            let (_, on) = handshake(true);
            assert!(n > 0, "the key log saw the secrets");
            assert!(!off.is_empty(), "the probe found no secret even without the scrub");
            assert!(on.is_empty(), "secrets left on the stack: {on:?}");
        })
        .expect("thread")
        .join()
        .expect("probe thread");
}
