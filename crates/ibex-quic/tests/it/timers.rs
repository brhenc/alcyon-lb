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

/// One exchange at `now`: the client's datagrams to the server, the server's back, both sides'
/// timers and endpoint events.
fn exchange(now: Instant, s: &mut QuicEndpoint, ep: &mut quinn_proto::Endpoint, ch: quinn_proto::ConnectionHandle, c: &mut quinn_proto::Connection) {
    let mut out = Vec::new();
    while let Some(t) = c.poll_transmit(now, 1, &mut out) {
        s.handle_datagram(now, from(0), None, &out[..t.size]).expect("datagram");
        out.clear();
    }
    if s.poll_timeout().is_some_and(|t| t <= now) {
        s.handle_timeout(now);
    }
    let mut buf = vec![0u8; 65535];
    while let Some(t) = s.poll_transmit(now, &mut buf) {
        let mut resp = Vec::new();
        if let Some(quinn_proto::DatagramEvent::ConnectionEvent(_, e)) = ep.handle(now, SERVER, None, None, bytes::BytesMut::from(&buf[..t.size]), &mut resp) {
            c.handle_event(e);
        }
    }
    if c.poll_timeout().is_some_and(|t| t <= now) {
        c.handle_timeout(now);
    }
    while let Some(e) = c.poll_endpoint_events() {
        if let Some(ce) = ep.handle_event(ch, e) {
            c.handle_event(ce);
        }
    }
    while c.poll().is_some() {}
}

/// T543: the endpoint asks quinn for a packet only from a connection something happened to
/// since it last had nothing to send (a datagram, a timer, a stream call). Before, every
/// `poll_transmit` asked every connection: the h3 listener drains transmits ~8 times a
/// request, and quinn's empty `poll_transmit` re-checks every space, path and queue each time.
#[test]
fn a_quiet_connection_is_not_asked_for_a_packet() {
    let mut s = server();
    let (mut ep, cfg) = create_client_endpoint();
    let mut now = Instant::now();
    let (ch, mut c) = ep.connect(now, (*cfg).clone(), SERVER, "localhost").expect("connect");
    for _ in 0..50 {
        if !c.is_handshaking() {
            break;
        }
        exchange(now, &mut s, &mut ep, ch, &mut c);
        now += Duration::from_millis(1);
    }
    assert!(!c.is_handshaking(), "no handshake");
    for _ in 0..3 {
        exchange(now, &mut s, &mut ep, ch, &mut c);
        now += Duration::from_millis(1);
    }
    let mut buf = vec![0u8; 65535];
    while s.poll_transmit(now, &mut buf).is_some() {}
    let before = s.transmit_polls();
    for _ in 0..10 {
        assert!(s.poll_transmit(now, &mut buf).is_none(), "nothing to send");
    }
    assert_eq!(s.transmit_polls() - before, 0, "a quiet connection was asked for a packet");
    // A stream write makes it worth asking again, and the data goes out.
    let id = c.streams().open(quinn_proto::Dir::Bi).expect("open");
    c.send_stream(id).write(b"x").expect("write");
    exchange(now, &mut s, &mut ep, ch, &mut c);
    // The endpoint accepts the stream itself and reports it.
    let mut opened = None;
    while let Some(ev) = s.poll_event() {
        if let ibex_quic::transport::TransportEvent::StreamOpened { conn_id, stream_id, .. } = ev {
            opened = Some((conn_id, stream_id));
        }
    }
    let (conn_id, sid) = opened.expect("stream opened event");
    while s.poll_transmit(now, &mut buf).is_some() {}
    let before = s.transmit_polls();
    s.write_stream(conn_id, sid, b"y", false).expect("write");
    let t = s.poll_transmit(now, &mut buf);
    assert!(t.is_some(), "the write goes out");
    assert!(s.transmit_polls() - before >= 1);
}
