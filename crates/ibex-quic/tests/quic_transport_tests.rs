use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

fn cert_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../examples/certs/localhost.pem")
}

#[derive(Debug)]
struct NoCertVerifier(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn create_client_endpoint() -> (quinn_proto::Endpoint, Arc<quinn_proto::ClientConfig>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut rustls_client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocols")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier(provider)))
        .with_no_client_auth();
    rustls_client_config.alpn_protocols = vec![ALPN_H3.to_vec()];

    let quic_client_crypto =
        quinn_proto::crypto::rustls::QuicClientConfig::try_from(Arc::new(rustls_client_config))
            .expect("client crypto");
    let mut client_config = quinn_proto::ClientConfig::new(Arc::new(quic_client_crypto));
    let mut tc = quinn_proto::TransportConfig::default();
    tc.initial_rtt(Duration::from_millis(10));
    client_config.transport_config(Arc::new(tc));

    let endpoint_config = Arc::new(quinn_proto::EndpointConfig::default());
    let endpoint = quinn_proto::Endpoint::new(endpoint_config, None, false, None);

    (endpoint, Arc::new(client_config))
}

#[test]
fn test_endpoint_init_and_tls_config() {
    let config = QuicConfig::new();
    let server_config = config
        .load_server_config_from_pem(cert_path())
        .expect("load server config from pem");

    let endpoint = QuicEndpoint::with_server_config(server_config).expect("endpoint init");
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
                conn_id: _,
                alpn,
                server_name,
            } = evt
            {
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
