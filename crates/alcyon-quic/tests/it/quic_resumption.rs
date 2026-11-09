// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T461: what QUIC's TLS did on rustls 0.23 it still does on rustls 0.24. A QUIC bind issues
//! session tickets (its `BindTls` has the ticket rotator and the session cache TCP binds have),
//! and a client coming back resumes: the server sends no certificate the second time, so the
//! client's verifier is called once for two connections. Seen failing with the bind's ticketer
//! and session storage both removed. 0-RTT is not enabled (`max_early_data_size` 0, as before),
//! nor is Retry by default; neither is tested here.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alcyon_quic::{QuicConfig, QuicEndpoint, QuicTransport, TransportEvent, ALPN_H3};

/// Accepts any certificate, and counts the certificates it was asked about (rustls 0.24,
/// T534: the client is Alcyon's).
#[derive(Debug)]
struct Counting(Arc<alcyon_tls::tcp::rustls24::crypto::CryptoProvider>, AtomicUsize);

impl alcyon_tls::tcp::rustls24::client::danger::ServerVerifier for Counting {
    fn verify_identity<'a>(
        &self,
        identity: &alcyon_tls::tcp::rustls24::client::danger::ServerIdentity<'a, '_>,
    ) -> Result<alcyon_tls::tcp::rustls24::crypto::VerifiedIdentity<'a>, alcyon_tls::tcp::rustls24::Error> {
        self.1.fetch_add(1, Ordering::Relaxed);
        Ok(alcyon_tls::tcp::rustls24::crypto::VerifiedIdentity::assertion(identity.identity.clone()))
    }

    fn verify_tls12_signature(
        &self,
        input: &alcyon_tls::tcp::rustls24::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<alcyon_tls::tcp::rustls24::client::danger::HandshakeSignatureValid, alcyon_tls::tcp::rustls24::Error> {
        alcyon_tls::tcp::rustls24::crypto::verify_tls12_signature(input, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        input: &alcyon_tls::tcp::rustls24::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<alcyon_tls::tcp::rustls24::client::danger::HandshakeSignatureValid, alcyon_tls::tcp::rustls24::Error> {
        alcyon_tls::tcp::rustls24::crypto::verify_tls13_signature(input, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<alcyon_tls::tcp::rustls24::crypto::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    fn hash_config(&self, h: &mut dyn std::hash::Hasher) {
        h.write(b"alcyon-test:counting");
    }
}

/// Runs one connection from `client` (on `client_addr`) to `server` for a while after both
/// sides are connected, so that the post-handshake ticket reaches the client.
fn connect_once(
    server: &mut QuicEndpoint,
    client: &mut quinn_proto::Endpoint,
    config: &quinn_proto::ClientConfig,
    client_addr: SocketAddr,
) -> bool {
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let mut now = Instant::now();
    let (handle, mut conn) = client.connect(now, config.clone(), server_addr, "localhost").expect("connect");
    let (mut cbuf, mut sbuf) = (Vec::new(), vec![0u8; 65535]);
    let (mut server_up, mut client_up, mut after) = (false, false, 0);
    for _ in 0..100 {
        now += Duration::from_millis(5);
        cbuf.clear();
        while let Some(tx) = conn.poll_transmit(now, 1, &mut cbuf) {
            server.handle_datagram(now, client_addr, None, &cbuf[..tx.size]).expect("server datagram");
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
        while let Some(ev) = conn.poll() {
            client_up |= matches!(ev, quinn_proto::Event::Connected);
        }
        while let Some(ev) = server.poll_event() {
            server_up |= matches!(ev, TransportEvent::HandshakeComplete { .. });
        }
        if server_up && client_up {
            after += 1;
            if after == 10 {
                break;
            }
        }
    }
    server_up && client_up
}

#[test]
fn a_client_coming_back_resumes_its_session() {
    let pem = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/certs/localhost.pem");
    let server_config = QuicConfig::new().load_server_config_from_pem(pem).expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let provider = alcyon_tls::provider::of(alcyon_config::TlsCryptoProvider::Ring, false, true);
    let verifier = Arc::new(Counting(Arc::clone(&provider), AtomicUsize::new(0)));
    let mut tls = alcyon_tls::tcp::rustls24::ClientConfig::builder(provider)
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&verifier) as Arc<dyn alcyon_tls::tcp::rustls24::client::danger::ServerVerifier>)
        .with_no_client_auth()
        .expect("client");
    tls.alpn_protocols = vec![ALPN_H3.to_vec().into()];
    let crypto = alcyon_quic::crypto::QuicClientConfig::new(Arc::new(tls), alcyon_config::TlsCryptoProvider::Ring).expect("client crypto");
    let config = quinn_proto::ClientConfig::new(Arc::new(crypto));
    let reset = Arc::new(alcyon_quic::crypto::ResetKey::new().expect("reset key"));
    let mut client = quinn_proto::Endpoint::new(Arc::new(quinn_proto::EndpointConfig::new(reset)), None, false, None);

    assert!(connect_once(&mut server, &mut client, &config, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55601)));
    assert_eq!(verifier.1.load(Ordering::Relaxed), 1, "the first handshake is a full one");
    assert!(connect_once(&mut server, &mut client, &config, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55602)));
    assert_eq!(verifier.1.load(Ordering::Relaxed), 1, "the second handshake verified a certificate: not resumed");
}
