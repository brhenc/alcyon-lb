// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ibex_quic::{
    DatagramOutcome, QuicConfig, QuicEndpoint, QuicListener, QuicTransport, TransportEvent,
    ALPN_H3,
};

pub(crate) fn cert_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../examples/certs/localhost.pem")
}

/// The test client: Ibex's own (T534, `crypto::client`, rustls 0.24), `verify none`, ALPN
/// `h3`, on an endpoint whose stateless reset key is Ibex's too: no rustls 0.23 in it.
pub(crate) fn create_client_endpoint() -> (quinn_proto::Endpoint, Arc<quinn_proto::ClientConfig>) {
    let crypto = ibex_quic::crypto::QuicClientConfig::without_verification(&[ALPN_H3], ibex_config::TlsCryptoProvider::Ring)
        .expect("client crypto");
    let mut client_config = quinn_proto::ClientConfig::new(Arc::new(crypto));
    let mut tc = quinn_proto::TransportConfig::default();
    tc.initial_rtt(Duration::from_millis(10));
    client_config.transport_config(Arc::new(tc));

    let reset = Arc::new(ibex_quic::crypto::ResetKey::new().expect("reset key"));
    let endpoint_config = Arc::new(quinn_proto::EndpointConfig::new(reset));
    let endpoint = quinn_proto::Endpoint::new(endpoint_config, None, false, None);

    (endpoint, Arc::new(client_config))
}

#[test]
fn test_endpoint_init_and_tls_config() {
    let config = QuicConfig::new();
    let server_config = config
        .load_server_config_from_pem(cert_path())
        .expect("load server config from pem");

    let mut endpoint = QuicEndpoint::with_server_config(server_config).expect("endpoint init");
    assert_eq!(endpoint.connection_count(), 0);
    assert!(endpoint.poll_timeout().is_none());
}

#[test]
fn test_quic_handshake_completion_alpn_h3() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let (mut client_endpoint, client_config) = create_client_endpoint();

    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55443);

    let now = Instant::now();
    let (client_handle, mut client_conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");


    let mut client_buf = Vec::new();
    let mut server_buf = vec![0u8; 65535];
    let mut sim_now = now;

    let mut server_connected = false;
    let mut client_connected = false;
    let mut negotiated_alpn = None;
    let mut negotiated_server_name = None;

    // Step datagram exchange
    for _ in 0..50 {
        sim_now += Duration::from_millis(5);

        // Drive client transmits -> server
        client_buf.clear();
        while let Some(tx) = client_conn.poll_transmit(sim_now, 1, &mut client_buf) {
            let data = &client_buf[..tx.size];
            let outcome = server
                .handle_datagram(sim_now, client_addr, None, data)
                .expect("server handle datagram");
            assert!(matches!(
                outcome,
                DatagramOutcome::Accepted | DatagramOutcome::Routed
            ));
            client_buf.clear();
        }

        // Drive server transmits -> client
        while let Some(tx) = server.poll_transmit(sim_now, &mut server_buf) {
            let data = &server_buf[..tx.size];
            let mut resp = Vec::new();
            if let Some(quinn_proto::DatagramEvent::ConnectionEvent(_, conn_evt)) =
                client_endpoint.handle(
                    sim_now,
                    server_addr,
                    None,
                    None,
                    bytes::BytesMut::from(data),
                    &mut resp,
                )
            {
                client_conn.handle_event(conn_evt);
            }
        }

        // Process client events
        while let Some(ep_evt) = client_conn.poll_endpoint_events() {
            if let Some(conn_evt) = client_endpoint.handle_event(client_handle, ep_evt) {
                client_conn.handle_event(conn_evt);
            }
        }
        while let Some(evt) = client_conn.poll() {
            if let quinn_proto::Event::Connected = evt {
                client_connected = true;
            }
        }

        // Process server events
        while let Some(evt) = server.poll_event() {
            if let TransportEvent::HandshakeComplete {
                conn,
                alpn,
                server_name,
            } = evt
            {
                // The transport answers the same from the connection's handshake data.
                assert_eq!(server.alpn(conn).as_deref(), alpn.as_deref());
                assert_eq!(server.server_name(conn), server_name);
                server_connected = true;
                negotiated_alpn = alpn;
                negotiated_server_name = server_name;
            }
        }

        if server_connected && client_connected {
            break;
        }
    }

    assert!(server_connected, "server QUIC handshake must complete");
    assert!(client_connected, "client QUIC handshake must complete");
    assert_eq!(
        negotiated_alpn.as_deref(),
        Some(ALPN_H3),
        "ALPN must negotiate h3"
    );
    assert_eq!(
        negotiated_server_name.as_deref(),
        Some("localhost"),
        "SNI must be localhost"
    );
}

#[test]
fn test_connection_table_dcid_lookup_and_migration() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let (mut client_endpoint, client_config) = create_client_endpoint();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let mut client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000);

    let now = Instant::now();
    let (client_handle, mut client_conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");

    let mut client_buf = Vec::new();
    let mut server_buf = vec![0u8; 65535];
    let mut sim_now = now;

    // Handshake
    for _ in 0..50 {
        sim_now += Duration::from_millis(5);
        client_buf.clear();
        while let Some(tx) = client_conn.poll_transmit(sim_now, 1, &mut client_buf) {
            let _ = server.handle_datagram(sim_now, client_addr, None, &client_buf[..tx.size]);
            client_buf.clear();
        }
        while let Some(tx) = server.poll_transmit(sim_now, &mut server_buf) {
            let mut resp = Vec::new();
            if let Some(quinn_proto::DatagramEvent::ConnectionEvent(_, conn_evt)) =
                client_endpoint.handle(
                    sim_now,
                    server_addr,
                    None,
                    None,
                    bytes::BytesMut::from(&server_buf[..tx.size]),
                    &mut resp,
                )
            {
                client_conn.handle_event(conn_evt);
            }
        }
        while let Some(ep_evt) = client_conn.poll_endpoint_events() {
            if let Some(conn_evt) = client_endpoint.handle_event(client_handle, ep_evt) {
                client_conn.handle_event(conn_evt);
            }
        }
    }


    assert_eq!(server.connection_count(), 1);

    // Client opens a stream
    let stream_id = client_conn.streams().open(quinn_proto::Dir::Uni).unwrap();
    client_conn.send_stream(stream_id).write(b"data-before-migration").unwrap();

    // Client migrates to a new IP / port
    client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 60000);

    // Send packet from the new client address
    let mut migrated_routed = false;
    client_buf.clear();
    while let Some(tx) = client_conn.poll_transmit(sim_now, 1, &mut client_buf) {
        let outcome = server
            .handle_datagram(sim_now, client_addr, None, &client_buf[..tx.size])
            .expect("server handle");
        if outcome == DatagramOutcome::Routed {
            migrated_routed = true;
        }
        client_buf.clear();
    }

    assert!(
        migrated_routed,
        "datagram from new 4-tuple with same DCID must be Routed to existing connection"
    );
    assert_eq!(
        server.connection_count(),
        1,
        "connection must survive migration without duplicating"
    );
}

#[test]
fn test_timeout_handling_and_loss_recovery() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let (mut client_endpoint, client_config) = create_client_endpoint();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51111);

    let now = Instant::now();
    let (_client_handle, mut client_conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");

    let mut client_buf = Vec::new();
    let mut server_buf = vec![0u8; 65535];
    let sim_now = now;

    // Send Initial packet from client to server
    if let Some(tx) = client_conn.poll_transmit(sim_now, 1, &mut client_buf) {
        let outcome = server
            .handle_datagram(sim_now, client_addr, None, &client_buf[..tx.size])
            .expect("handle initial");
        assert_eq!(outcome, DatagramOutcome::Accepted);
    }

    // Server emits initial handshake responses
    let mut server_packets = Vec::new();
    while let Some(tx) = server.poll_transmit(sim_now, &mut server_buf) {
        server_packets.push(server_buf[..tx.size].to_vec());
    }
    assert!(!server_packets.is_empty(), "server must produce Initial packets");

    // We intentionally DROP the server packets (simulating network loss)
    // Now poll server timeout deadline
    let timeout = server.poll_timeout();
    assert!(
        timeout.is_some(),
        "server must have a loss recovery timer active"
    );

    let deadline = timeout.unwrap();
    assert!(deadline > sim_now, "timer deadline must be in the future");

    // Advance clock past the loss recovery deadline and handle timeout
    server.handle_timeout(deadline + Duration::from_millis(1));

    // Server should now retransmit the lost packets via loss recovery timer
    let mut retransmits = Vec::new();
    while let Some(tx) = server.poll_transmit(deadline + Duration::from_millis(1), &mut server_buf) {
        retransmits.push(server_buf[..tx.size].to_vec());
    }

    assert!(
        !retransmits.is_empty(),
        "loss recovery timer expiry must trigger packet retransmission"
    );
}


#[test]
fn test_version_negotiation_packet() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 52222);
    let now = Instant::now();

    // Fabricate a QUIC Long Header packet with unsupported version 0x1a2a3a4a
    // Format: 1 (long header) | 0x00 (initial) | unused, Version (4 bytes: 0x1a2a3a4a), DCID len, DCID (8 bytes), SCID len, SCID (8 bytes)
    let mut fake_packet = Vec::new();
    fake_packet.push(0xc0); // Long header, Initial type
    fake_packet.extend_from_slice(&0x1a2a_3a4a_u32.to_be_bytes()); // Unsupported version
    fake_packet.push(0x08); // DCID len 8
    fake_packet.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // DCID
    fake_packet.push(0x08); // SCID len 8
    fake_packet.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]); // SCID
    fake_packet.extend_from_slice(&[0; 1200]); // Padding to meet 1200 byte minimum

    let outcome = server
        .handle_datagram(now, client_addr, None, &fake_packet)
        .expect("handle bad version");

    assert_eq!(
        outcome,
        DatagramOutcome::StatelessResponse,
        "unsupported version must trigger a stateless Version Negotiation response"
    );

    let mut out = vec![0u8; 1500];
    let tx = server
        .poll_transmit(now, &mut out)
        .expect("poll version negotiation packet");

    assert_eq!(tx.destination, client_addr);
    let response_data = &out[..tx.size];

    // Check Version Negotiation packet header (version field in response must be 0x00000000)
    assert!(response_data.len() >= 5);
    assert_eq!(
        &response_data[1..5],
        &[0, 0, 0, 0],
        "Version Negotiation packet must have version 0"
    );
}

#[test]
fn test_curl_http3_only_quic_handshake() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut listener = QuicListener::bind_with_server_config(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        server_config,
    )
    .expect("bind listener");


    let port = listener.addr().port();
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    let (handshake_tx, handshake_rx) = std::sync::mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut handshake_done = false;

        while running_clone.load(Ordering::Relaxed) {
            let now = Instant::now();
            let _ = listener.handle_read(now);
            let _ = listener.handle_write(now);

            if let Some(timeout) = listener.poll_timeout() {
                if timeout <= now {
                    listener.handle_timeout(now);
                }
            }

            while let Some(evt) = listener.poll_event() {
                if let TransportEvent::HandshakeComplete { alpn, .. } = evt {
                    handshake_done = true;
                    let _ = handshake_tx.send(alpn);
                }
            }

            let timeout_ms = match listener.poll_timeout() {
                Some(deadline) => {
                    let now = Instant::now();
                    if deadline <= now {
                        0
                    } else {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
                        let diff = (deadline - now).as_millis().min(50) as i32;
                        diff.max(1)
                    }
                }
                None => 50,
            };

            let mut poll_fds = [rustix::event::PollFd::from_borrowed_fd(
                listener.socket().as_fd(),
                rustix::event::PollFlags::IN,
            )];
            let _ = rustix::event::poll(&mut poll_fds, timeout_ms);
        }

        handshake_done
    });

    // Run curl --http3-only against the listener
    let output = Command::new("curl")
        .args([
            "-v",
            "-sk",
            "--http3-only",
            "--max-time",
            "2",
            "--resolve",
            &format!("localhost:{port}:127.0.0.1"),
            &format!("https://localhost:{port}/probe"),
        ])
        .output()
        .expect("execute curl");

    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("curl stderr:\n{stderr}");

    // Wait up to 3s for handshake notification
    let alpn_result = handshake_rx.recv_timeout(Duration::from_secs(3));

    running.store(false, Ordering::Relaxed);
    let _ = server_thread.join();

    assert!(
        alpn_result.is_ok(),
        "QUIC TLS handshake must complete within timeout: {alpn_result:?}"
    );
    let alpn = alpn_result.unwrap();
    assert_eq!(alpn.as_deref(), Some(ALPN_H3), "ALPN must negotiate h3");

    // Verify curl logged SSL handshake / HTTP/3 negotiation in stderr
    let handshake_confirmed = stderr.contains("SSL handshake")
        || stderr.contains("ALPN: server accepted h3")
        || stderr.contains("using HTTP/3")
        || stderr.contains("QUIC");

    assert!(
        handshake_confirmed,
        "curl stderr must confirm QUIC/TLS handshake completion and ALPN h3"
    );
}

/// RFC 9000 §8.1: a server must not send more than three times what it has received on an
/// unvalidated path.
///
/// Exceeding this makes the proxy usable as a `DDoS` reflector: an attacker spoofing a
/// victim's source address spends one datagram and causes several to be sent at the victim,
/// with no handshake to prevent it.
///
/// Measured live against both proxies before this test existed:
///
/// ```text
/// HAProxy 3.5-dev7   1200 B in -> 1490 B out   1.242x   PASS
/// Ibex               1200 B in -> 4167 B out   3.472x   FAIL
/// ```
///
/// The same violation appeared through a hand-rolled drive loop and through
/// `Engine::run_once`, so it is below the drive loop rather than an artefact of it.
#[test]
#[allow(clippy::cast_precision_loss)]
fn a_server_must_not_amplify_beyond_three_times_before_address_validation() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let (mut client_endpoint, client_config) = create_client_endpoint();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55443);

    let now = Instant::now();
    let (_h, mut client_conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");

    // Exactly one client datagram: the Initial. The client never replies after this, so the
    // address is never validated and the budget stays at 3x this one datagram forever.
    let mut client_buf = Vec::new();
    let tx = client_conn
        .poll_transmit(now, 1, &mut client_buf)
        .expect("client Initial");
    let received = tx.size;
    server
        .handle_datagram(now, client_addr, None, &client_buf[..tx.size])
        .expect("server handles Initial");

    // Drain everything the server will send, advancing time well past any PTO so that
    // retransmissions are included -- §8.1 counts them against the same budget.
    let mut sent = 0usize;
    let mut out = vec![0u8; 65535];
    let mut sim_now = now;
    for _ in 0..200 {
        while let Some(tx) = server.poll_transmit(sim_now, &mut out) {
            sent += tx.size;
        }
        sim_now += Duration::from_millis(25);
        server.handle_timeout(sim_now);
    }

    let limit = received * 3;
    assert!(
        sent <= limit,
        "RFC 9000 §8.1: server sent {sent} B for {received} B received ({:.3}x), \
         limit is {limit} B (3x). Exceeding it makes this a DDoS reflector.",
        sent as f64 / received as f64
    );
}

#[test]
fn test_runt_datagrams_discarded_zero_bytes_returned() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let (mut client_endpoint, client_config) = create_client_endpoint();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55444);

    let now = Instant::now();
    let (_h, mut client_conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");

    let mut client_buf = Vec::new();
    let tx = client_conn
        .poll_transmit(now, 1, &mut client_buf)
        .expect("client Initial");
    let full_initial = client_buf[..tx.size].to_vec();
    assert!(full_initial.len() >= 1200);

    // RFC 9000 §14.1: runt datagrams (< 1200 bytes) must be dropped with 0 bytes returned.
    for runt_len in [64, 500, 1199] {
        let runt_payload = &full_initial[..runt_len];
        let outcome = server
            .handle_datagram(now, client_addr, None, runt_payload)
            .expect("handle runt datagram");

        assert_eq!(
            outcome,
            DatagramOutcome::Ignored,
            "runt datagram of length {runt_len} B must be Ignored"
        );

        let mut out = vec![0u8; 65535];
        let transmitted = server.poll_transmit(now, &mut out);
        assert!(
            transmitted.is_none(),
            "server must return 0 bytes for runt datagram of length {runt_len} B"
        );
    }
}

#[test]
#[allow(clippy::cast_precision_loss)]
fn test_amplification_accounting_with_multiple_initial_datagrams() {
    let server_config = QuicConfig::new()
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let (mut client_endpoint, client_config) = create_client_endpoint();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55445);

    let now = Instant::now();
    let (_h, mut client_conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");

    let mut client_buf = Vec::new();
    let tx = client_conn
        .poll_transmit(now, 1, &mut client_buf)
        .expect("client Initial");
    let dgram1 = client_buf[..tx.size].to_vec();

    // Send first Initial (1200 B)
    server
        .handle_datagram(now, client_addr, None, &dgram1)
        .expect("server handles first Initial");

    let mut sent = 0usize;
    let mut out = vec![0u8; 65535];
    let mut sim_now = now;

    // Drain initial flight
    while let Some(tx) = server.poll_transmit(sim_now, &mut out) {
        sent += tx.size;
    }
    assert!(sent <= 1200 * 3, "initial flight must be <= 3600 B");

    // Client re-sends Initial (e.g. client timeout or second probe packet of 1200 B)
    sim_now += Duration::from_millis(50);
    server
        .handle_datagram(sim_now, client_addr, None, &dgram1)
        .expect("server handles second Initial");

    // Advance time and drain all transmits
    for _ in 0..100 {
        while let Some(tx) = server.poll_transmit(sim_now, &mut out) {
            sent += tx.size;
        }
        sim_now += Duration::from_millis(25);
        server.handle_timeout(sim_now);
    }

    let total_received = dgram1.len() * 2;
    let limit = total_received * 3;
    assert!(
        sent <= limit,
        "server sent {sent} B for {total_received} B received ({:.3}x), limit is {limit} B",
        sent as f64 / total_received as f64
    );
}

/// A configured factor is enforced, not just accepted.
///
/// This test was called `test_strict_anti_amplification_matches_haproxy_profile` and carried a
/// comment claiming the numbers were "verified against `HAProxy` baseline profile". It never
/// ran `HAProxy`. In a project whose first rule is that the reference binary is the oracle, a
/// test that names the oracle without consulting it is worse than one that does not mention
/// it, because the name is
/// what a reader trusts. The real differential lives in `tools/quic-differential/` and its
/// measured numbers are recorded in `data/quic_parity.md`.
///
/// What this test actually proves is worth keeping: with the factor set to 2, the endpoint
/// stays under 2x across 200 simulated timeouts. It would fail on the default factor of 3,
/// which measures 2.4x, so it is a real check that the setting reaches the accounting.
#[test]
#[allow(clippy::cast_precision_loss)]
fn a_configured_factor_of_two_is_enforced_across_retransmissions() {
    let pem_path = cert_path();
    let (_, key) = ibex_quic::config::load_pem_cert_and_key(pem_path.as_path()).expect("load key");
    let certs = {
        let file = std::fs::File::open(pem_path.as_path()).expect("open cert");
        let mut reader = std::io::BufReader::new(file);
        rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("read certs")
    };

    let rustls_config = ibex_tls::tcp::BindTls::single_tls13(certs, key, Vec::new()).expect("bind tls");

    // Configure strict anti-amplification factor of 2x (HAProxy baseline single flight profile)
    let quic_config = QuicConfig::new().with_anti_amplification_factor(2);
    let mut server = QuicEndpoint::new(&rustls_config, Some(quic_config)).expect("server endpoint");

    let (mut client_endpoint, client_config) = create_client_endpoint();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55446);

    let now = Instant::now();
    let (_h, mut client_conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");

    let mut client_buf = Vec::new();
    let tx = client_conn
        .poll_transmit(now, 1, &mut client_buf)
        .expect("client Initial");
    let received = tx.size;
    server
        .handle_datagram(now, client_addr, None, &client_buf[..tx.size])
        .expect("server handles Initial");

    let mut sent = 0usize;
    let mut out = vec![0u8; 65535];
    let mut sim_now = now;
    for _ in 0..200 {
        while let Some(tx) = server.poll_transmit(sim_now, &mut out) {
            sent += tx.size;
        }
        sim_now += Duration::from_millis(25);
        server.handle_timeout(sim_now);
    }

    let limit = received * 2;
    assert!(
        sent <= limit,
        "strict anti-amplification: server sent {sent} B for {received} B received ({:.3}x), \
         limit is {limit} B (2x)",
        sent as f64 / received as f64
    );
    assert!(
        sent > 0,
        "server must send the initial flight"
    );
}



/// A bind's TLS (rustls 0.24, no ALPN: the QUIC config's `h3`) for the tests that need to hand
/// one to `QuicListener::bind`.
fn rustls_server_config() -> Arc<ibex_tls::tcp::BindTls> {
    let pem_path = cert_path();
    let (certs, key) = ibex_quic::config::load_pem_cert_and_key(pem_path.as_path()).expect("load key");
    ibex_tls::tcp::BindTls::single_tls13(certs, key, Vec::new()).expect("bind tls")
}

/// Produces a genuine client Initial datagram aimed at `server_addr`.
fn client_initial(server_addr: SocketAddr) -> Vec<u8> {
    let (mut client_endpoint, client_config) = create_client_endpoint();
    let now = Instant::now();
    let (_h, mut conn) = client_endpoint
        .connect(now, (*client_config).clone(), server_addr, "localhost")
        .expect("connect");
    let mut buf = Vec::new();
    let tx = conn.poll_transmit(now, 1, &mut buf).expect("client Initial");
    buf[..tx.size].to_vec()
}

/// Drives `listener` for `window`, returning (bytes sent to it, bytes it sent back).
fn probe_listener(listener: &mut QuicListener, window: Duration) -> (usize, usize) {
    let server_addr = listener.addr();
    let initial = client_initial(server_addr);
    let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    sock.set_nonblocking(true).expect("nonblocking");
    sock.send_to(&initial, server_addr).expect("send Initial");

    let mut got = 0usize;
    let mut buf = vec![0u8; 65535];
    let start = Instant::now();
    while start.elapsed() < window {
        let now = Instant::now();
        let _ = listener.handle_read(now);
        let _ = listener.handle_write(now);
        listener.handle_timeout(now);
        while let Ok((n, _)) = sock.recv_from(&mut buf) {
            got += n;
        }
        thread::sleep(Duration::from_millis(2));
    }
    (initial.len(), got)
}

/// `QuicConfig::anti_amplification_factor` must reach the endpoint the listener builds.
///
/// `QuicListener::bind` took a `QuicConfig`, used it only to build the TLS `ServerConfig`, and
/// dropped the rest on the way to `bind_with_server_config`. The cap still applied, because
/// `QuicEndpoint::with_server_config` hardcodes 3 -- so the listener was compliant by accident
/// and an operator asking for a stricter factor got silence. This is the project's recurring
/// defect: a setting that parses and then does nothing.
#[test]
#[allow(clippy::cast_precision_loss)]
fn a_listener_honours_the_configured_anti_amplification_factor() {
    let tls = rustls_server_config();
    let cfg = QuicConfig::new().with_anti_amplification_factor(2);
    let mut listener = QuicListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &tls,
        Some(cfg),
    )
    .expect("bind listener");

    let (sent_to_server, got_back) = probe_listener(&mut listener, Duration::from_millis(700));

    assert!(got_back > 0, "the listener must answer the Initial at all");
    let limit = sent_to_server * 2;
    assert!(
        got_back <= limit,
        "listener was configured with factor 2 but sent {got_back} B for {sent_to_server} B \
         received ({:.3}x); limit is {limit} B. The configured factor never reached the endpoint.",
        got_back as f64 / sent_to_server as f64
    );
}

/// A packet refused by the budget must never have been generated.
///
/// Checking the budget after `poll_transmit` means quinn-proto has already assigned the packet
/// a number and armed loss recovery for it by the time it is discarded, so every refusal costs
/// a packet that must later be retransmitted. The budget is known before the call; the decision
/// belongs there.
#[test]
fn a_refused_packet_is_never_generated_in_the_first_place() {
    let tls = rustls_server_config();
    let cfg = QuicConfig::new().with_anti_amplification_factor(2);
    let mut listener = QuicListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &tls,
        Some(cfg),
    )
    .expect("bind listener");

    let (_sent, got_back) = probe_listener(&mut listener, Duration::from_millis(700));
    assert!(got_back > 0, "the listener must answer the Initial at all");

    assert_eq!(
        listener.transport().amplification_overshoots(),
        0,
        "packets were generated and then thrown away by the budget"
    );
}


/// The first retransmission must not come sooner than RFC 9002's initial RTT allows.
///
/// `QuicConfig` set `initial_rtt` to 100 ms. RFC 9002 §6.2.2 puts kInitialRtt at 333 ms and
/// `quinn-proto`'s own default is 333 ms, so this was an override to a third of the standard
/// value with nothing recording why. PTO is `smoothed_rtt + 4 * rttvar`, so 100 ms fires the
/// first probe at ~300 ms where the standard value fires at ~1000 ms -- measured, `HAProxy`
/// 3.5-dev7 retransmits at 1002 ms and Ibex retransmitted at 301 ms.
///
/// It costs twice. Any client further away than 100 ms -- which is most of the internet --
/// makes the server retransmit a handshake flight that was never lost. And on a path that is
/// still unvalidated it spends the anti-amplification budget three times faster, which is
/// throughput for anyone using the proxy as a reflector.
#[test]
fn a_handshake_is_not_retransmitted_sooner_than_the_initial_rtt() {
    let tls = rustls_server_config();
    let mut listener = QuicListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &tls,
        None,
    )
    .expect("bind listener");

    let server_addr = listener.addr();
    let initial = client_initial(server_addr);
    let sock = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    sock.set_nonblocking(true).expect("nonblocking");

    // The client sends one Initial and then goes silent, so everything after the first flight
    // is the server probing on its own timer.
    let start = Instant::now();
    sock.send_to(&initial, server_addr).expect("send Initial");

    let mut buf = vec![0u8; 65535];
    let mut first_flight_done: Option<Instant> = None;
    let mut retransmit_at: Option<Duration> = None;

    while start.elapsed() < Duration::from_millis(1500) && retransmit_at.is_none() {
        let now = Instant::now();
        let _ = listener.handle_read(now);
        let _ = listener.handle_write(now);
        listener.handle_timeout(now);
        while let Ok((_n, _)) = sock.recv_from(&mut buf) {
            let seen = Instant::now();
            match first_flight_done {
                // A gap of 50 ms after the first burst means the flight is over and this
                // packet is a probe rather than the rest of the flight.
                Some(last) if seen.duration_since(last) > Duration::from_millis(50) => {
                    retransmit_at = Some(seen.duration_since(start));
                }
                _ => first_flight_done = Some(seen),
            }
        }
        thread::sleep(Duration::from_millis(2));
    }

    let at = retransmit_at.expect("the server must probe at all within 1.5 s");
    assert!(
        at >= Duration::from_millis(500),
        "the server retransmitted after {at:?}. RFC 9002 §6.2.2 puts kInitialRtt at 333 ms, \
         which places the first PTO near 1000 ms; HAProxy measures 1002 ms. Anything near \
         300 ms means initial_rtt is set below the standard value."
    );
}

/// Q0 (docs/design/quic-transport-2026-11-01.md §3): the server asks an established client to
/// acknowledge less often (ACK_FREQUENCY, draft-ietf-quic-ack-frequency). The client here
/// advertises `min_ack_delay`, as every client that implements the extension does.
/// Runs a handshake and then 1 s of idle connection against a server built from `config`;
/// returns how many ACK_FREQUENCY frames the client received and whether it is established.
fn ack_frequency_frames_received(config: QuicConfig, stop_at_first: bool) -> (u64, bool) {
    let server_config = config
        .load_server_config_from_pem(cert_path())
        .expect("load cert");
    let mut server = QuicEndpoint::with_server_config(server_config).expect("server endpoint");

    let crypto = ibex_quic::crypto::QuicClientConfig::without_verification(&[ALPN_H3], ibex_config::TlsCryptoProvider::Ring)
        .expect("client crypto");
    let mut client_config = quinn_proto::ClientConfig::new(Arc::new(crypto));
    let mut tc = quinn_proto::TransportConfig::default();
    tc.initial_rtt(Duration::from_millis(10));
    tc.ack_frequency_config(Some(quinn_proto::AckFrequencyConfig::default()));
    client_config.transport_config(Arc::new(tc));
    let reset = Arc::new(ibex_quic::crypto::ResetKey::new().expect("reset key"));
    let mut client_endpoint = quinn_proto::Endpoint::new(Arc::new(quinn_proto::EndpointConfig::new(reset)), None, false, None);

    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 55444);
    let mut now = Instant::now();
    let (client_handle, mut client_conn) = client_endpoint
        .connect(now, client_config, server_addr, "localhost")
        .expect("connect");

    let mut client_buf = Vec::new();
    let mut server_buf = vec![0u8; 65535];
    for _ in 0..200 {
        now += Duration::from_millis(5);
        client_buf.clear();
        while let Some(tx) = client_conn.poll_transmit(now, 1, &mut client_buf) {
            server
                .handle_datagram(now, client_addr, None, &client_buf[..tx.size])
                .expect("server handle datagram");
            client_buf.clear();
        }
        server.handle_timeout(now);
        while let Some(tx) = server.poll_transmit(now, &mut server_buf) {
            let mut resp = Vec::new();
            if let Some(quinn_proto::DatagramEvent::ConnectionEvent(_, evt)) = client_endpoint.handle(
                now,
                server_addr,
                None,
                None,
                bytes::BytesMut::from(&server_buf[..tx.size]),
                &mut resp,
            ) {
                client_conn.handle_event(evt);
            }
        }
        client_conn.handle_timeout(now);
        while let Some(ep_evt) = client_conn.poll_endpoint_events() {
            if let Some(evt) = client_endpoint.handle_event(client_handle, ep_evt) {
                client_conn.handle_event(evt);
            }
        }
        while client_conn.poll().is_some() {}
        while server.poll_event().is_some() {}
        if stop_at_first && client_conn.stats().frame_rx.ack_frequency > 0 {
            break;
        }
    }
    (client_conn.stats().frame_rx.ack_frequency, !client_conn.is_handshaking())
}

#[test]
fn the_server_asks_the_client_for_fewer_acks_when_the_setting_is_on() {
    let mut config = QuicConfig::new();
    config.ack_frequency = Some((2, Duration::from_millis(25)));
    let (frames, established) = ack_frequency_frames_received(config, true);
    assert!(established);
    assert!(frames > 0, "the server never sent ACK_FREQUENCY");
}

/// The default: the setting is off, the server sends no ACK_FREQUENCY and the connection works.
#[test]
fn the_server_sends_no_ack_frequency_by_default() {
    assert_eq!(QuicConfig::new().ack_frequency, None);
    let (frames, established) = ack_frequency_frames_received(QuicConfig::new(), false);
    assert!(established, "the handshake did not complete");
    assert_eq!(frames, 0, "ACK_FREQUENCY sent with the setting off");
}
