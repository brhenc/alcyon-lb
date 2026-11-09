// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `quic-force-retry` and `tune.quic.fe.sec.retry-threshold` reach the QUIC listener (T492).
//!
//! Measured on the QUIC oracle (`HAProxy` 3.5-dev7, aioquic 1.3.0 client, `nbthread 1`; the
//! half-open count is the frontend's at any `nbthread`, the last test, T523):
//! - `quic-force-retry`: the first Initial is answered by a Retry alone; the client that
//!   answers it connects.
//! - `tune.quic.fe.sec.retry-threshold 2` and two clients that sent one Initial and went
//!   quiet: the next client gets a Retry and connects. With one quiet client: no Retry.
//! - Neither keyword: no Retry.

use crate::common;

use alcyon_quic::quinn_proto::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, ConnectionHandle, Endpoint, EndpointConfig,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

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

struct Alcyon {
    child: Child,
    quic: SocketAddr,
    _cfg: NamedTempFile,
}

impl Drop for Alcyon {
    fn drop(&mut self) {
        common::stop(&mut self.child);
    }
}

fn alcyon(global: &str, bind_opts: &str) -> Alcyon {
    alcyon_threads(1, global, bind_opts)
}

fn alcyon_threads(nbthread: usize, global: &str, bind_opts: &str) -> Alcyon {
    let tcp = common::reserve_addr();
    let quic = common::reserve_addr();
    let crt = format!("{}/../../examples/certs/localhost.pem", env!("CARGO_MANIFEST_DIR"));
    let mut cfg = NamedTempFile::new().expect("cfg");
    write!(
        cfg,
        "global\n    nbthread {nbthread}\n    hard-stop-after 300ms\n{global}defaults\n    mode http\n    timeout client 10s\n    timeout server 3s\n    \
         timeout connect 1s\nfrontend f\n    bind {tcp}\n    bind quic4@{quic} ssl crt {crt} alpn h3{bind_opts}\n    \
         http-request return status 200\n"
    )
    .expect("write cfg");
    let child = Command::new(std::env::var("ALCYON_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string()))
        .arg("-f")
        .arg(cfg.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn alcyon");
    assert!(common::wait_listening(tcp), "alcyon never listened");
    Alcyon { child, quic, _cfg: cfg }
}

/// The long-header packet type of a datagram's first packet.
fn kind(d: &[u8]) -> &'static str {
    match d.first() {
        Some(b) if b & 0x80 == 0 => "short",
        Some(b) => ["Initial", "0-RTT", "Handshake", "Retry"][usize::from((b >> 4) & 3)],
        None => "empty",
    }
}

/// One QUIC client on its own UDP socket, driven by hand.
struct Client {
    sock: UdpSocket,
    ep: Endpoint,
    handle: ConnectionHandle,
    conn: Connection,
    server: SocketAddr,
}

impl Client {
    fn new(server: SocketAddr) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut ctls = rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(Any)).with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let client_cfg = ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).expect("client config")));
        let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
        sock.set_read_timeout(Some(Duration::from_millis(20))).expect("timeout");
        let mut ep = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
        let (handle, conn) = ep.connect(Instant::now(), client_cfg, server, "localhost").expect("connect");
        Self { sock, ep, handle, conn, server }
    }

    fn send(&mut self) {
        let mut out = Vec::new();
        while let Some(t) = self.conn.poll_transmit(Instant::now(), 1, &mut out) {
            let _ = self.sock.send_to(&out[..t.size], self.server);
            out.clear();
        }
    }

    /// The datagrams that arrive within `wait`, not yet handed to the connection.
    fn recv(&self, wait: Duration) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        let mut buf = vec![0u8; 65536];
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Ok(n) = self.sock.recv(&mut buf) {
                got.push(buf[..n].to_vec());
            }
        }
        got
    }

    fn feed(&mut self, dgrams: &[Vec<u8>]) {
        let now = Instant::now();
        for d in dgrams {
            let mut resp = Vec::new();
            if let Some(alcyon_quic::quinn_proto::DatagramEvent::ConnectionEvent(_, e)) =
                self.ep.handle(now, self.server, None, None, d[..].into(), &mut resp)
            {
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
        while self.conn.poll().is_some() {}
    }

    /// Sends the first Initial and returns the kinds of what came back.
    fn first_flight(&mut self) -> Vec<&'static str> {
        self.send();
        let got = self.recv(Duration::from_millis(300));
        let kinds = got.iter().map(|d| kind(d)).collect();
        self.feed(&got);
        kinds
    }

    fn handshake(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline && self.conn.is_handshaking() {
            self.send();
            let got = self.recv(Duration::from_millis(20));
            self.feed(&got);
        }
        !self.conn.is_handshaking() && !self.conn.is_closed()
    }
}

#[test]
fn quic_force_retry_answers_the_first_initial_with_a_retry() {
    let alcyon = alcyon("", " quic-force-retry");
    let mut c = Client::new(alcyon.quic);
    assert_eq!(c.first_flight(), ["Retry"]);
    assert!(c.handshake(), "the client that answered the Retry connects");
}

#[test]
fn past_the_retry_threshold_a_new_connection_gets_a_retry() {
    let alcyon = alcyon("    tune.quic.fe.sec.retry-threshold 2\n", "");
    let mut quiet = Vec::new();
    for _ in 0..2 {
        let mut q = Client::new(alcyon.quic);
        assert_eq!(q.first_flight().first(), Some(&"Initial"), "under the threshold, served");
        quiet.push(q);
    }
    let mut c = Client::new(alcyon.quic);
    assert_eq!(c.first_flight(), ["Retry"]);
    assert!(c.handshake(), "the client that answered the Retry connects");
}

#[test]
fn under_the_default_threshold_there_is_no_retry() {
    let alcyon = alcyon("", "");
    let _quiet = Client::new(alcyon.quic).first_flight();
    let mut c = Client::new(alcyon.quic);
    assert_eq!(c.first_flight().first(), Some(&"Initial"));
    assert!(c.handshake());
}

/// T492 oracle row `retry-threshold 2`, one quiet client: no Retry; with `1` the second
/// half-open client is the first one over the threshold. The value comes from the config
/// into the listener (engine.rs, `qc.retry_threshold`).
#[test]
fn retry_threshold_one_retries_the_second_half_open_client() {
    let alcyon = alcyon("    tune.quic.fe.sec.retry-threshold 1\n", "");
    let mut first = Client::new(alcyon.quic);
    assert_eq!(first.first_flight().first(), Some(&"Initial"), "under the threshold, served");
    let mut second = Client::new(alcyon.quic);
    assert_eq!(second.first_flight(), ["Retry"]);
    assert!(second.handshake(), "the client that answered the Retry connects");
}

/// The half-open count is the frontend's, not a worker's (T523). `HAProxy` keeps
/// `half_open_conn` in the frontend's QUIC counters, one set per thread group
/// (`EXTRA_COUNTERS_GET(prx->extra_counters_fe, ...)`, `qc_new_conn`), so at `nbthread 16`
/// the Retry threshold weighs every thread's half-open connections: measured on the QUIC
/// oracle with this test (`ALCYON_TEST_BIN`), the ninth client gets a Retry; in the burst of
/// 200 (`tools/battery/repro/h3_burst.sh`) 84 of 200 clients were retried, as at
/// `nbthread 1`. Counted per worker, eight quiet clients spread over 16 sockets of the
/// reuseport group left every worker under 8, and Alcyon sent no Retry at all at `nbthread 16`.
#[test]
fn the_retry_threshold_counts_the_half_open_connections_of_every_thread() {
    let alcyon = alcyon_threads(16, "    tune.quic.fe.sec.retry-threshold 8\n", "");
    let mut quiet = Vec::new();
    for _ in 0..8 {
        let mut q = Client::new(alcyon.quic);
        assert_eq!(q.first_flight().first(), Some(&"Initial"), "under the threshold, served");
        quiet.push(q);
    }
    let mut c = Client::new(alcyon.quic);
    assert_eq!(c.first_flight(), ["Retry"], "eight half-open connections over 16 threads reach a threshold of 8");
    assert!(c.handshake(), "the client that answered the Retry connects");
}
