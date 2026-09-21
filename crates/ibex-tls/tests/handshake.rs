// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! Integration tests verifying full TLS 1.3 handshake, bidirectional data exchange,
//! SNI dispatch, ALPN negotiation, and `TlsInfo` introspection over `RustlsTransport`.

mod common;

use common::{build_root_store, generate_test_cert};
use ibex_proto::transport::{TlsInfo, Transport, VerifyResult};
use ibex_tls::{IbexCertResolver, RustlsContext, RustlsTransport, TlsConfig};
use rustls::pki_types::ServerName;
use std::sync::Arc;

/// Pumps ciphertext bidirectionally between client and server until both complete the handshake.
fn pump_handshake(
    server_transport: &RustlsTransport,
    server_ctx: &mut RustlsContext,
    client_transport: &RustlsTransport,
    client_ctx: &mut RustlsContext,
) {
    let mut iterations = 0;
    while (!server_ctx.handshake_done || !client_ctx.handshake_done) && iterations < 50 {
        iterations += 1;

        // Drive client
        let _ = client_transport.handshake(client_ctx);
        let client_out = client_ctx.take_raw_output();
        if !client_out.is_empty() {
            server_ctx.feed_raw_input(&client_out);
        }

        // Drive server
        let _ = server_transport.handshake(server_ctx);
        let server_out = server_ctx.take_raw_output();
        if !server_out.is_empty() {
            client_ctx.feed_raw_input(&server_out);
        }
    }

    assert!(server_ctx.handshake_done, "Server handshake timed out");
    assert!(client_ctx.handshake_done, "Client handshake timed out");
}

/// Pumps encrypted application data from sender to receiver.
fn transfer_data(
    sender_transport: &RustlsTransport,
    sender_ctx: &mut RustlsContext,
    receiver_transport: &RustlsTransport,
    receiver_ctx: &mut RustlsContext,
    plaintext: &[u8],
) -> Vec<u8> {
    let sent = sender_transport
        .send(sender_ctx, plaintext)
        .expect("Send plaintext");
    assert_eq!(sent, plaintext.len());

    let raw_ciphertext = sender_ctx.take_raw_output();
    assert!(!raw_ciphertext.is_empty(), "Ciphertext generated");

    receiver_ctx.feed_raw_input(&raw_ciphertext);

    let mut rx_buf = vec![0u8; plaintext.len() + 128];
    let n = receiver_transport
        .recv(receiver_ctx, &mut rx_buf)
        .expect("Recv plaintext");
    rx_buf.truncate(n);
    rx_buf
}

#[test]
fn test_tls13_handshake_and_bidirectional_data() {
    let (cert, cert_der) = generate_test_cert(vec!["example.com".to_string()]);
    let mut resolver = IbexCertResolver::new();
    resolver.add_exact("example.com", cert);

    let server_tls_cfg = TlsConfig::new()
        .with_cert_resolver(Arc::new(resolver))
        .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let server_config = server_tls_cfg.build_server_config().unwrap();
    let server_transport = RustlsTransport::new_server(server_config);

    let root_store = build_root_store(&[cert_der]);
    let client_tls_cfg = TlsConfig::new().with_alpn(vec![b"h2".to_vec()]);
    let client_config = client_tls_cfg.build_client_config(root_store).unwrap();
    let server_name = ServerName::try_from("example.com").unwrap();
    let client_transport = RustlsTransport::new_client(client_config, server_name);

    let mut server_ctx = server_transport.init(1, true).unwrap();
    let mut client_ctx = client_transport.init(2, false).unwrap();

    // 1. Handshake
    pump_handshake(
        &server_transport,
        &mut server_ctx,
        &client_transport,
        &mut client_ctx,
    );

    assert!(server_transport.is_handshake_done(&server_ctx));
    assert!(client_transport.is_handshake_done(&client_ctx));

    // 2. Check TlsInfo on both ends
    let s_info = server_transport.tls_info(&server_ctx).unwrap();
    let c_info = client_transport.tls_info(&client_ctx).unwrap();

    assert_eq!(s_info.sni(), Some("example.com"));
    assert_eq!(c_info.sni(), Some("example.com"));

    assert_eq!(s_info.protocol_version(), Some("TLSv1.3"));
    assert_eq!(c_info.protocol_version(), Some("TLSv1.3"));

    // ALPN negotiated "h2"
    assert_eq!(s_info.alpn(), Some(&b"h2"[..]));
    assert_eq!(c_info.alpn(), Some(&b"h2"[..]));

    assert!(s_info.cipher().is_some());
    assert!(c_info.cipher().is_some());

    assert!(c_info.peer_has_cert());
    assert_eq!(c_info.peer_verify(), VerifyResult::Ok);

    // 3. Client -> Server data transfer
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let received_by_server = transfer_data(
        &client_transport,
        &mut client_ctx,
        &server_transport,
        &mut server_ctx,
        request,
    );
    assert_eq!(received_by_server, request);

    // 4. Server -> Client data transfer
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, Ibex!\n";
    let received_by_client = transfer_data(
        &server_transport,
        &mut server_ctx,
        &client_transport,
        &mut client_ctx,
        response,
    );
    assert_eq!(received_by_client, response);

    // 5. Shutdown write
    client_transport.shutdown_write(&mut client_ctx).unwrap();
    let shutdown_raw = client_ctx.take_raw_output();
    assert!(!shutdown_raw.is_empty());
}

#[test]
fn test_sni_multi_cert_dispatch() {
    let (exact_cert, exact_der) = generate_test_cert(vec!["site-a.com".to_string()]);
    let (wildcard_cert, wildcard_der) = generate_test_cert(vec!["*.wildcard.org".to_string()]);

    let mut resolver = IbexCertResolver::new();
    resolver.add_exact("site-a.com", exact_cert);
    resolver.add_wildcard("*.wildcard.org", wildcard_cert);

    let server_config = TlsConfig::new()
        .with_cert_resolver(Arc::new(resolver))
        .build_server_config()
        .unwrap();
    let server_transport = RustlsTransport::new_server(server_config);

    // Connect with SNI = "site-a.com"
    {
        let root_store = build_root_store(std::slice::from_ref(&exact_der));
        let client_config = TlsConfig::new().build_client_config(root_store).unwrap();
        let server_name = ServerName::try_from("site-a.com").unwrap();
        let client_transport = RustlsTransport::new_client(client_config, server_name);

        let mut server_ctx = server_transport.init(10, true).unwrap();
        let mut client_ctx = client_transport.init(11, false).unwrap();

        pump_handshake(
            &server_transport,
            &mut server_ctx,
            &client_transport,
            &mut client_ctx,
        );

        assert_eq!(server_ctx.tls_info.sni(), Some("site-a.com"));
        assert_eq!(client_ctx.tls_info.peer_verify(), VerifyResult::Ok);
    }

    // Connect with SNI = "api.wildcard.org" (matches *.wildcard.org)
    {
        let root_store = build_root_store(std::slice::from_ref(&wildcard_der));
        let client_config = TlsConfig::new().build_client_config(root_store).unwrap();
        let server_name = ServerName::try_from("api.wildcard.org").unwrap();
        let client_transport = RustlsTransport::new_client(client_config, server_name);

        let mut server_ctx = server_transport.init(20, true).unwrap();
        let mut client_ctx = client_transport.init(21, false).unwrap();

        pump_handshake(
            &server_transport,
            &mut server_ctx,
            &client_transport,
            &mut client_ctx,
        );

        assert_eq!(server_ctx.tls_info.sni(), Some("api.wildcard.org"));
        assert_eq!(client_ctx.tls_info.peer_verify(), VerifyResult::Ok);
    }
}

#[test]
fn test_alpn_negotiation_fallback() {
    let (cert, cert_der) = generate_test_cert(vec!["example.com".to_string()]);
    let mut resolver = IbexCertResolver::new();
    resolver.set_default_cert(cert);

    // Server supports [http/1.1]
    let server_config = TlsConfig::new()
        .with_cert_resolver(Arc::new(resolver))
        .with_alpn(vec![b"http/1.1".to_vec()])
        .build_server_config()
        .unwrap();
    let server_transport = RustlsTransport::new_server(server_config);

    // Client supports [h2, http/1.1]
    let root_store = build_root_store(&[cert_der]);
    let client_config = TlsConfig::new()
        .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .build_client_config(root_store)
        .unwrap();
    let server_name = ServerName::try_from("example.com").unwrap();
    let client_transport = RustlsTransport::new_client(client_config, server_name);

    let mut server_ctx = server_transport.init(1, true).unwrap();
    let mut client_ctx = client_transport.init(2, false).unwrap();

    pump_handshake(
        &server_transport,
        &mut server_ctx,
        &client_transport,
        &mut client_ctx,
    );

    // Should negotiate http/1.1
    let s_info = server_transport.tls_info(&server_ctx).unwrap();
    let c_info = client_transport.tls_info(&client_ctx).unwrap();
    assert_eq!(s_info.alpn(), Some(&b"http/1.1"[..]));
    assert_eq!(c_info.alpn(), Some(&b"http/1.1"[..]));
}
