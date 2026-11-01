// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A burst of new QUIC connections at `nbthread 1` is read while the handshakes are served
//! (T560, VV-31).
//!
//! `h2load --alpn-list=h3 -c 1000 -n 1000` left ~30% of the connections unanswered in 30 s on
//! Ibex at `nbthread 1`; `HAProxy` 3.5-dev10 served 1000/1000 in 1.6-3.4 s. Ibex read 32
//! datagrams, ran the 32 handshakes they started, and only then read the socket again: the
//! Initials that arrived meanwhile overflowed the socket's receive buffer, and the same
//! clients lost every retransmission wave. `HAProxy` reads up to `maxpollevents` datagrams a
//! wakeup into a 256 KiB ring per thread (`quic_lstnr_sock_fd_iocb` -> `quic_dgram_write`) and
//! serves them from there, so its socket keeps being emptied while handshakes run.
//!
//! Here 300 clients each send one Initial, 200 us apart, and never retransmit: every Initial
//! the listener did not read in time is lost for good. 300 is below what the receive buffer
//! and the listener's ring hold together, so the result does not depend on the host's speed.

use crate::common;

use ibex_quic::quinn_proto::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, EndpointConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::Write;
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

const CLIENTS: usize = 300;

#[test]
fn a_burst_of_initials_at_nbthread_1_is_answered() {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let mut cfg = tempfile::NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread 1\n    hard-stop-after 300ms\ndefaults\n    mode http\n    timeout client 10s\n    timeout server 3s\n    \
         timeout connect 1s\nfrontend f\n    bind {tcp}\n    bind quic4@{quic} ssl crt {crt} alpn h3\n    http-request return status 200\n"
    )
    .expect("write cfg");
    let mut child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(tcp), "ibex never listened");

    // Every client's first Initial, made before the burst so that the burst is only sends.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
    ctls.alpn_protocols = vec![b"h3".to_vec()];
    let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
    let mut clients = Vec::with_capacity(CLIENTS);
    for _ in 0..CLIENTS {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_nonblocking(true).expect("nonblocking");
        let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (_, mut conn) = ep.connect(Instant::now(), client_cfg.clone(), quic, "localhost").expect("connect");
        let mut out = Vec::new();
        let t = conn.poll_transmit(Instant::now(), 1, &mut out).expect("an Initial");
        out.truncate(t.size);
        // The endpoint and connection are kept: dropped, nothing changes on the wire, but
        // they hold the client's state for as long as the test looks at its socket.
        clients.push((sock, out, ep, conn));
    }

    let start = Instant::now();
    for (i, (sock, initial, _, _)) in clients.iter().enumerate() {
        let _ = sock.send_to(initial, quic);
        let at = Duration::from_micros(200 * (i as u64 + 1));
        while start.elapsed() < at {
            std::hint::spin_loop();
        }
    }

    // An Initial or a Retry back is an answer; none of the clients sends anything again.
    let mut answered = vec![false; CLIENTS];
    let mut buf = vec![0u8; 65536];
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && answered.iter().any(|a| !a) {
        for (i, (sock, _, _, _)) in clients.iter().enumerate() {
            while sock.recv(&mut buf).is_ok() {
                answered[i] = true;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    common::stop(&mut child);
    let n = answered.iter().filter(|a| **a).count();
    assert_eq!(n, CLIENTS, "{n} of {CLIENTS} Initials sent 200 us apart were answered");
}
