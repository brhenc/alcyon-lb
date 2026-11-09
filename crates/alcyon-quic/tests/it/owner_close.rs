// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T561: a connection this endpoint closes is reported ended, once, whoever closed it.
//! quinn raises no `ConnectionLost` for a local `close()`: its close timer drains the
//! connection silently. The listener releases the frontend's `act_conn`/`maxconn` slot on
//! `ConnectionClosed`, so an owner close without one leaks the slot.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use alcyon_quic::transport::TransportEvent;
use alcyon_quic::{QuicConfig, QuicEndpoint, QuicTransport};

use super::quic_transport_tests::{cert_path, create_client_endpoint};

const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

fn server() -> QuicEndpoint {
    let pem = cert_path();
    let (certs, key) = alcyon_quic::config::load_pem_cert_and_key(pem.as_path()).expect("load cert");
    let tls = alcyon_tls::tcp::BindTls::single_tls13(certs, key, Vec::new()).expect("bind tls");
    QuicEndpoint::new(&tls, Some(QuicConfig::default().with_retry_threshold(u64::MAX))).expect("server endpoint")
}

/// Counts the `ConnectionClosed` events of `conn` among what the endpoint has queued.
fn closed_events(s: &mut QuicEndpoint, conn: alcyon_quic::ConnHandle) -> usize {
    let mut n = 0;
    while let Some(ev) = s.poll_event() {
        if matches!(ev, TransportEvent::ConnectionClosed { conn: c, .. } if c == conn) {
            n += 1;
        }
    }
    n
}

#[test]
fn a_connection_closed_by_the_endpoint_is_reported_ended_once() {
    let mut s = server();
    let now = Instant::now();
    let (mut ep, cfg) = create_client_endpoint();
    let (_h, mut c) = ep.connect(now, (*cfg).clone(), SERVER, "localhost").expect("connect");
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10_000);
    let mut buf = Vec::new();
    while let Some(tx) = c.poll_transmit(now, 1, &mut buf) {
        s.handle_datagram(now, from, None, &buf[..tx.size]).expect("datagram");
        buf.clear();
    }
    let mut conn = None;
    while let Some(ev) = s.poll_event() {
        if let TransportEvent::NewConnection { conn: h, .. } = ev {
            conn = Some(h);
        }
    }
    let conn = conn.expect("new connection");
    // The client says nothing more: only the endpoint can end this connection.
    s.close_connection(conn, 0, b"");
    let mut out = vec![0u8; 65535];
    let mut t = now;
    let mut ended = closed_events(&mut s, conn);
    for _ in 0..200 {
        if s.connection_count() == 0 {
            break;
        }
        let Some(next) = s.poll_timeout() else { break };
        t = next.max(t);
        s.handle_timeout(t);
        while s.poll_transmit(t, &mut out).is_some() {}
        ended += closed_events(&mut s, conn);
    }
    let _ = s.poll_timeout();
    ended += closed_events(&mut s, conn);
    assert_eq!(s.connection_count(), 0, "still counted after {:?}", t - now);
    assert!(t - now < Duration::from_secs(60));
    assert_eq!(ended, 1, "a connection the endpoint closed was dropped without a ConnectionClosed (after {:?})", t - now);
}
