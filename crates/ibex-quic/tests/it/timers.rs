// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T493 item 1: the cost of a datagram, of a sent packet and of a timer expiry does not grow
//! with the number of idle connections. The measure is `QuicEndpoint::timeout_polls`, the
//! number of per-connection timeout queries; before the fix `update_next_timeout` queried
//! every live connection, so 1000 idle connections cost 1000 queries per datagram.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ibex_quic::{QuicConfig, QuicEndpoint, QuicTransport};

use super::quic_transport_tests::{cert_path, create_client_endpoint};

const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

fn server() -> QuicEndpoint {
    let pem = cert_path();
    let (certs, key) = ibex_quic::config::load_pem_cert_and_key(pem.as_path()).expect("load cert");
    let tls = ibex_tls::tcp::BindTls::single_tls13(certs, key, Vec::new()).expect("bind tls");
    QuicEndpoint::new(&tls, Some(QuicConfig::default().with_retry_threshold(u64::MAX))).expect("server endpoint")
}

/// A new client's first flight, as it would come from `port`.
fn first_flight(now: Instant) -> Vec<Vec<u8>> {
    let (mut ep, cfg) = create_client_endpoint();
    let (_h, mut conn) = ep.connect(now, (*cfg).clone(), SERVER, "localhost").expect("connect");
    let mut out = Vec::new();
    let mut buf = Vec::new();
    while let Some(tx) = conn.poll_transmit(now, 1, &mut buf) {
        out.push(buf[..tx.size].to_vec());
        buf.clear();
    }
    out
}

fn from(i: usize) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_000 + u16::try_from(i).expect("port"))
}

/// Opens `n` idle connections, then returns the timeout queries one more datagram, the
/// packets it makes the server send, and one timer expiry cost.
fn costs(n: usize) -> (u64, u64, u64) {
    let mut s = server();
    let now = Instant::now();
    let mut buf = vec![0u8; 65535];
    for i in 0..n {
        for d in first_flight(now) {
            s.handle_datagram(now, from(i), None, &d).expect("datagram");
        }
        while s.poll_transmit(now, &mut buf).is_some() {}
    }
    assert_eq!(s.connection_count(), n);

    let flight = first_flight(now);
    let before = s.timeout_polls();
    for d in &flight {
        s.handle_datagram(now, from(n), None, d).expect("datagram");
    }
    let per_datagram = s.timeout_polls() - before;

    let before = s.timeout_polls();
    while s.poll_transmit(now, &mut buf).is_some() {}
    let per_sent = s.timeout_polls() - before;

    // The first loss-recovery timer of the idle ones fires: nothing else is queried.
    let before = s.timeout_polls();
    s.handle_timeout(now + Duration::from_millis(500));
    let per_expiry = s.timeout_polls() - before;
    (per_datagram, per_sent, per_expiry)
}

#[test]
fn timeout_cost_does_not_grow_with_idle_connections() {
    let (d10, s10, _) = costs(10);
    let (d1000, s1000, _) = costs(1000);
    assert!(d1000 <= d10 + 4, "per datagram {d10} -> {d1000}");
    assert!(s1000 <= s10 + 4, "per sent packet {s10} -> {s1000}");
}

/// Idle connections that never complete are timed out and removed, each costing a constant
/// number of timeout queries (not one pass over all of them per connection).
#[test]
fn expiry_visits_only_the_expired() {
    let mut s = server();
    let now = Instant::now();
    let mut buf = vec![0u8; 65535];
    let n = 200;
    for i in 0..n {
        for d in first_flight(now) {
            s.handle_datagram(now, from(i), None, &d).expect("datagram");
        }
        while s.poll_transmit(now, &mut buf).is_some() {}
    }
    assert_eq!(s.connection_count(), n);
    let before = s.timeout_polls();
    let mut t = now;
    for _ in 0..200 {
        let Some(next) = s.poll_timeout() else { break };
        t = next.max(t);
        s.handle_timeout(t);
        while s.poll_transmit(t, &mut buf).is_some() {}
    }
    assert_eq!(s.connection_count(), 0, "all idle connections time out");
    let polls = s.timeout_polls() - before;
    assert!(polls < 60 * u64::try_from(n).expect("n"), "{polls} queries for {n} connections");
}
