// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! P1 (`docs/design/quic-transport-2026-11-01.md` 2.2): the per-stream objects quinn-proto
//! allocates (`Send`, `Recv`, `Retransmits`) come from `ibex_alloc` pools, so that `show pools`
//! lists `quic_send`, `quic_recv` and `quic_retransmits`. The feature `ibex-pools` of the
//! vendored quinn-proto (turned on by this crate) puts them there.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ibex_quic::{QuicConfig, QuicEndpoint, QuicTransport, StreamDirection, TransportEvent};

use super::quic_transport_tests::{cert_path, create_client_endpoint};

fn head(name: &str) -> Option<ibex_alloc::PoolHead> {
    ibex_alloc::pool::publish_local();
    let mut found = None;
    ibex_alloc::for_each_pool(|p| {
        if p.name() == name {
            found = Some(p.head());
        }
    });
    found
}

/// A handshake, then a stream each way left open: the connection holds a `Send` and a `Recv`
/// on each side, and its handshake packets have used (and given back) `Retransmits`.
#[test]
fn quinn_streams_and_retransmits_are_pool_objects() {
    let server_config = QuicConfig::new().load_server_config_from_pem(cert_path()).expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");
    let (mut client_endpoint, client_config) = create_client_endpoint();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55444);
    let mut now = Instant::now();
    let (client_handle, mut client) = client_endpoint.connect(now, (*client_config).clone(), server_addr, "localhost").expect("connect");

    let mut conn_id = None;
    let mut client_connected = false;
    let mut sent = false;
    let mut cbuf = Vec::new();
    let mut sbuf = vec![0u8; 65535];
    for _ in 0..60 {
        now += Duration::from_millis(5);
        cbuf.clear();
        while let Some(tx) = client.poll_transmit(now, 1, &mut cbuf) {
            server.handle_datagram(now, client_addr, None, &cbuf[..tx.size]).expect("server datagram");
            cbuf.clear();
        }
        while let Some(tx) = server.poll_transmit(now, &mut sbuf) {
            let mut resp = Vec::new();
            if let Some(quinn_proto::DatagramEvent::ConnectionEvent(_, e)) =
                client_endpoint.handle(now, server_addr, None, None, bytes::BytesMut::from(&sbuf[..tx.size]), &mut resp)
            {
                client.handle_event(e);
            }
        }
        while let Some(e) = client.poll_endpoint_events() {
            if let Some(ev) = client_endpoint.handle_event(client_handle, e) {
                client.handle_event(ev);
            }
        }
        while let Some(e) = client.poll() {
            client_connected |= matches!(e, quinn_proto::Event::Connected);
        }
        while let Some(e) = server.poll_event() {
            if let TransportEvent::HandshakeComplete { conn_id: id, .. } = e {
                conn_id = Some(id);
            }
        }
        if client_connected && conn_id.is_some() && !sent {
            sent = true;
            let id = conn_id.clone().expect("conn");
            // server -> client: a bidirectional stream, one byte written, left open
            let sid = server.open_stream(id.clone(), StreamDirection::Bidirectional).expect("server stream");
            server.write_stream(id, sid, b"x", false).expect("server write");
            // client -> server: the same
            let cid = client.streams().open(quinn_proto::Dir::Bi).expect("client stream");
            client.send_stream(cid).write(b"y").expect("client write");
        }
    }
    assert!(sent, "the handshake completed");

    for name in ["quic_send", "quic_recv"] {
        let h = head(name).unwrap_or_else(|| panic!("show pools lists {name}"));
        assert!(h.used >= 1, "{name}: {} used", h.used);
    }
    let h = head("quic_retransmits").expect("show pools lists quic_retransmits");
    assert!(h.allocated >= 1, "quic_retransmits: {} allocated", h.allocated);
}
