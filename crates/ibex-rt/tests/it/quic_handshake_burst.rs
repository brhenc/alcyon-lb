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

type Client = (UdpSocket, Vec<u8>, Endpoint, ibex_quic::quinn_proto::Connection);

/// Ibex at `nbthread 1`, and its QUIC address.
fn spawn() -> (std::process::Child, std::net::SocketAddr, tempfile::NamedTempFile) {
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
    let child = Command::new(std::env::var("IBEX_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_ibex").to_string()))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ibex");
    assert!(common::wait_listening(tcp), "ibex never listened");
    (child, quic, cfg)
}

/// `n` clients and each one's first Initial, made before the burst so that the burst is
/// only sends. The endpoint and connection are kept: they hold the client's state for as
/// long as the test looks at its socket.
fn clients(n: usize, quic: std::net::SocketAddr) -> Vec<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
    ctls.alpn_protocols = vec![b"h3".to_vec()];
    let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
    (0..n)
        .map(|_| {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
            sock.set_nonblocking(true).expect("nonblocking");
            let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
            let (_, mut conn) = ep.connect(Instant::now(), client_cfg.clone(), quic, "localhost").expect("connect");
            let mut out = Vec::new();
            let t = conn.poll_transmit(Instant::now(), 1, &mut out).expect("an Initial");
            out.truncate(t.size);
            (sock, out, ep, conn)
        })
        .collect()
}

/// When each client first got a datagram back (an Initial or a Retry), within `wait`.
fn answers(clients: &[Client], wait: Duration) -> Vec<Option<Instant>> {
    let mut answered = vec![None; clients.len()];
    let mut buf = vec![0u8; 65536];
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline && answered.iter().any(Option::is_none) {
        for (i, (sock, _, _, _)) in clients.iter().enumerate() {
            while sock.recv(&mut buf).is_ok() {
                answered[i].get_or_insert_with(Instant::now);
            }
        }
        std::thread::sleep(Duration::from_micros(200));
    }
    answered
}

#[test]
fn a_burst_of_initials_at_nbthread_1_is_answered() {
    let (mut child, quic, _cfg) = spawn();
    let clients = clients(CLIENTS, quic);
    let start = Instant::now();
    for (i, (sock, initial, _, _)) in clients.iter().enumerate() {
        let _ = sock.send_to(initial, quic);
        let at = Duration::from_micros(200 * (i as u64 + 1));
        while start.elapsed() < at {
            std::hint::spin_loop();
        }
    }
    // None of the clients sends anything again.
    let answered = answers(&clients, Duration::from_secs(20));
    common::stop(&mut child);
    let n = answered.iter().filter(|a| a.is_some()).count();
    assert_eq!(n, CLIENTS, "{n} of {CLIENTS} Initials sent 200 us apart were answered");
}

/// 33 Initials at once, under the Retry threshold: a pass accepts 32 new connections and
/// sends their answers as it ends, and the socket is empty by then. The 33rd is accepted in
/// the next pass, at once: the loop does not sleep while a new connection waits
/// (`has_backlog`). It waited for its 100 ms poll timeout. A pass of one handshake makes
/// the longest gap between two answers, so it is that handshake, not 32.
#[test]
fn new_connections_past_one_pass_are_accepted_without_waiting() {
    const N: usize = 33;
    let (mut child, quic, _cfg) = spawn();
    let clients = clients(N, quic);
    for (sock, initial, _, _) in &clients {
        let _ = sock.send_to(initial, quic);
    }
    let answered = answers(&clients, Duration::from_secs(10));
    common::stop(&mut child);
    let mut at: Vec<Instant> = answered.iter().flatten().copied().collect();
    assert_eq!(at.len(), N, "every Initial is answered");
    at.sort();
    let gap = at.windows(2).map(|w| w[1] - w[0]).max().unwrap_or_default();
    assert!(gap < Duration::from_millis(40), "the longest wait between two answers was {gap:?}");
}
