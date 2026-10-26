// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC Retry and the half-open connection count (T492).
//!
//! Measured on the QUIC oracle (`HAProxy` 3.5-dev7, `nbthread 1`; the count is per thread
//! there, per worker endpoint here):
//! - `tune.quic.fe.sec.retry-threshold 2`, two clients that sent an Initial and went quiet:
//!   the third client's Initial is answered by a Retry, and that client then connects.
//!   One quiet client: no Retry. A connection stops being half-open once the peer's address
//!   is validated, and when it is released.
//! - `quic-force-retry`: the first Initial is answered by a Retry and nothing else; a client
//!   that does not answer gets nothing more.
//! - The Initial carrying the token, sent again 1 s later from the same port: handshake;
//!   from another port: dropped, nothing sent; 11 s later: dropped (`QUIC_RETRY_DURATION_SEC`
//!   10). A 40-byte garbage token, with or without Retry configured: dropped, nothing sent.
//!
//! `quinn-proto` answers a token it can decode but refuses with an `INVALID_TOKEN` close and
//! proceeds with one it cannot decode as if there were none; Ibex drops both, as the oracle.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ibex_quic::{QuicConfig, QuicEndpoint, QuicTransport, TransportEvent};

use super::quic_transport_tests::{cert_path, create_client_endpoint};

const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn server(cfg: QuicConfig) -> QuicEndpoint {
    let pem = cert_path();
    let (certs, key) = ibex_quic::config::load_pem_cert_and_key(pem.as_path()).expect("load cert");
    let tls = ibex_tls::tcp::BindTls::single_tls13(certs, key, Vec::new()).expect("bind tls");
    QuicEndpoint::new(&tls, Some(cfg)).expect("server endpoint")
}

/// The long-header packet type of a datagram's first packet.
fn kind(d: &[u8]) -> &'static str {
    match d.first() {
        Some(b) if b & 0x80 == 0 => "short",
        Some(b) => ["Initial", "0-RTT", "Handshake", "Retry"][usize::from((b >> 4) & 3)],
        None => "empty",
    }
}

/// A client token store handing out one fixed token: what a client returning a token it
/// got elsewhere, or a forged one, sends.
struct FixedToken(Bytes);

impl quinn_proto::TokenStore for FixedToken {
    fn insert(&self, _server_name: &str, _token: Bytes) {}
    fn take(&self, _server_name: &str) -> Option<Bytes> {
        Some(self.0.clone())
    }
}

struct Client {
    ep: quinn_proto::Endpoint,
    handle: quinn_proto::ConnectionHandle,
    conn: quinn_proto::Connection,
    addr: SocketAddr,
    connected: bool,
}

impl Client {
    fn new(now: Instant, port: u16, token: Option<&[u8]>) -> Self {
        let (mut ep, cfg) = create_client_endpoint();
        let mut cfg = (*cfg).clone();
        if let Some(t) = token {
            cfg.token_store(Arc::new(FixedToken(Bytes::copy_from_slice(t))));
        }
        let (handle, conn) = ep.connect(now, cfg, SERVER, "localhost").expect("connect");
        Self { ep, handle, conn, addr: addr(port), connected: false }
    }

    /// The datagrams the client has to send now.
    fn transmits(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = Vec::new();
        while let Some(tx) = self.conn.poll_transmit(now, 1, &mut buf) {
            out.push(buf[..tx.size].to_vec());
            buf.clear();
        }
        out
    }

    fn receive(&mut self, now: Instant, data: &[u8]) {
        let mut resp = Vec::new();
        if let Some(quinn_proto::DatagramEvent::ConnectionEvent(_, evt)) =
            self.ep.handle(now, SERVER, None, None, bytes::BytesMut::from(data), &mut resp)
        {
            self.conn.handle_event(evt);
        }
        while let Some(ep_evt) = self.conn.poll_endpoint_events() {
            if let Some(evt) = self.ep.handle_event(self.handle, ep_evt) {
                self.conn.handle_event(evt);
            }
        }
        while let Some(evt) = self.conn.poll() {
            if matches!(evt, quinn_proto::Event::Connected) {
                self.connected = true;
            }
        }
    }
}

/// Hands `dgrams` to the server as coming from `from`, and returns what the server then
/// sends to `from` (what it sends anyone else is lost, as for a client that went quiet).
fn exchange(server: &mut QuicEndpoint, now: Instant, from: SocketAddr, dgrams: &[Vec<u8>]) -> Vec<Vec<u8>> {
    for d in dgrams {
        server.handle_datagram(now, from, None, d).expect("handle datagram");
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65535];
    while let Some(tx) = server.poll_transmit(now, &mut buf) {
        if tx.destination == from {
            out.push(buf[..tx.size].to_vec());
        }
    }
    out
}

/// A client that sends its first Initial and never speaks again: a half-open connection.
/// Returns the kinds of what the server answered.
fn first_flight(server: &mut QuicEndpoint, now: Instant, port: u16) -> Vec<&'static str> {
    let mut c = Client::new(now, port, None);
    let dgrams = c.transmits(now);
    exchange(server, now, c.addr, &dgrams).iter().map(|d| kind(d)).collect()
}

/// Runs the client's handshake to the end, answering whatever the server sends, then two
/// more rounds so that the client's last flight (its Finished) reaches the server.
fn complete(server: &mut QuicEndpoint, c: &mut Client, now: &mut Instant) -> bool {
    let mut after = 0;
    for _ in 0..50 {
        *now += Duration::from_millis(5);
        let dgrams = c.transmits(*now);
        for d in exchange(server, *now, c.addr, &dgrams) {
            c.receive(*now, &d);
        }
        if c.connected {
            after += 1;
            if after > 2 {
                return true;
            }
        }
    }
    false
}

fn handshakes_completed(server: &mut QuicEndpoint) -> usize {
    let mut n = 0;
    while let Some(evt) = server.poll_event() {
        if matches!(evt, TransportEvent::HandshakeComplete { .. }) {
            n += 1;
        }
    }
    n
}

#[test]
fn the_101st_half_open_connection_gets_a_retry_and_then_connects() {
    let mut server = server(QuicConfig::new());
    let mut now = Instant::now();
    for i in 0..100 {
        let kinds = first_flight(&mut server, now, 20_000 + i);
        assert_eq!(kinds.first(), Some(&"Initial"), "half-open connection {i} is served: {kinds:?}");
    }
    assert_eq!(server.connection_count(), 100);

    let mut c = Client::new(now, 30_000, None);
    let dgrams = c.transmits(now);
    let answer = exchange(&mut server, now, c.addr, &dgrams);
    let kinds: Vec<_> = answer.iter().map(|d| kind(d)).collect();
    assert_eq!(kinds, ["Retry"], "the 101st Initial is answered by a Retry alone");
    assert_eq!(server.connection_count(), 100, "a Retry holds no connection");
    for d in &answer {
        c.receive(now, d);
    }
    assert!(complete(&mut server, &mut c, &mut now), "the client that answered the Retry connects");
    assert_eq!(server.connection_count(), 101);
    assert_eq!(handshakes_completed(&mut server), 1);

    // The validated connection is not half-open, and the other 100 still are.
    let kinds = first_flight(&mut server, now, 30_001);
    assert_eq!(kinds, ["Retry"]);
}

#[test]
fn completed_and_released_connections_leave_the_half_open_count() {
    let mut server = server(QuicConfig::new().with_retry_threshold(2));
    let mut now = Instant::now();
    for port in [21_000, 21_001] {
        let mut c = Client::new(now, port, None);
        assert!(complete(&mut server, &mut c, &mut now));
    }
    // Two completed handshakes are not half-open: two more quiet clients are served.
    assert_eq!(first_flight(&mut server, now, 21_002).first(), Some(&"Initial"));
    assert_eq!(first_flight(&mut server, now, 21_003).first(), Some(&"Initial"));
    // Two half-open now: the threshold is reached.
    assert_eq!(first_flight(&mut server, now, 21_004), ["Retry"]);

    // The quiet ones time out and are released; so are the two others, idle as long.
    for _ in 0..20 {
        now += Duration::from_secs(10);
        server.handle_timeout(now);
    }
    assert_eq!(server.connection_count(), 0);
    assert_eq!(first_flight(&mut server, now, 21_005).first(), Some(&"Initial"));
}

#[test]
fn quic_force_retry_retries_every_new_connection() {
    let cfg = QuicConfig { require_retry: true, ..QuicConfig::new() };
    let mut server = server(cfg);
    let mut now = Instant::now();

    // A client that does not answer the Retry costs the server nothing.
    assert_eq!(first_flight(&mut server, now, 22_000), ["Retry"]);
    assert_eq!(server.connection_count(), 0);

    let mut c = Client::new(now, 22_001, None);
    let dgrams = c.transmits(now);
    let answer = exchange(&mut server, now, c.addr, &dgrams);
    assert_eq!(answer.iter().map(|d| kind(d)).collect::<Vec<_>>(), ["Retry"]);
    for d in &answer {
        c.receive(now, d);
    }
    assert!(complete(&mut server, &mut c, &mut now));
    assert_eq!(handshakes_completed(&mut server), 1);
}

#[test]
fn a_retry_token_from_another_address_is_dropped() {
    let cfg = QuicConfig { require_retry: true, ..QuicConfig::new() };
    let mut server = server(cfg);
    let now = Instant::now();

    let mut c = Client::new(now, 23_000, None);
    let dgrams = c.transmits(now);
    for d in exchange(&mut server, now, c.addr, &dgrams) {
        assert_eq!(kind(&d), "Retry");
        c.receive(now, &d);
    }
    // The Initial that carries the token.
    let with_token = c.transmits(now);
    assert_eq!(with_token.len(), 1, "one Initial datagram");

    let elsewhere = exchange(&mut server, now, addr(23_999), &with_token);
    assert!(elsewhere.is_empty(), "nothing is sent for a token issued to another address: {:?}",
        elsewhere.iter().map(|d| kind(d)).collect::<Vec<_>>());
    assert_eq!(server.connection_count(), 0);

    let answer = exchange(&mut server, now, c.addr, &with_token);
    assert_eq!(answer.first().map(|d| kind(d)), Some("Initial"), "from its own address the token is good");
    assert_eq!(server.connection_count(), 1);
}

#[test]
fn an_initial_with_a_token_the_server_never_issued_is_dropped() {
    let mut server = server(QuicConfig::new());
    let now = Instant::now();
    let mut c = Client::new(now, 24_000, Some(&[0x5a; 40]));
    let dgrams = c.transmits(now);
    let answer = exchange(&mut server, now, c.addr, &dgrams);
    assert!(answer.is_empty(), "garbage token answered: {:?}", answer.iter().map(|d| kind(d)).collect::<Vec<_>>());
    assert_eq!(server.connection_count(), 0);
}
