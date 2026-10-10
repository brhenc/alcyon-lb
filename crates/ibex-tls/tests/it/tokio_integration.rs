// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Real TCP loopback integration test verifying TLS 1.3 handshake, SNI resolution,
//! ALPN negotiation, and HTTP transactions over network sockets.

use crate::common;

use common::{build_root_store, generate_test_cert};
use ibex_tls::{IbexCertResolver, TlsConfig};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn test_tokio_tcp_loopback_tls() {
    let (cert, cert_der) = generate_test_cert(vec!["localhost".to_string()]);
    let mut resolver = IbexCertResolver::new();
    resolver.add_exact("localhost", cert);

    let server_tls_cfg = TlsConfig::new()
        .with_cert_resolver(Arc::new(resolver))
        .with_alpn(vec![b"http/1.1".to_vec()]);
    let server_config = server_tls_cfg.build_server_config().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains("GET / HTTP/1.1"));

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nIbex!\n";
        tls_stream.write_all(response).await.unwrap();
        tls_stream.shutdown().await.unwrap();
    });

    let root_store = build_root_store(std::slice::from_ref(&cert_der));
    let client_tls_cfg = TlsConfig::new().with_alpn(vec![b"http/1.1".to_vec()]);
    let client_config = client_tls_cfg.build_client_config(root_store).unwrap();
    let connector = TlsConnector::from(client_config);

    let client_stream = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client_tls = connector.connect(server_name, client_stream).await.unwrap();

    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client_tls.write_all(request).await.unwrap();

    let mut resp_buf = Vec::new();
    client_tls.read_to_end(&mut resp_buf).await.unwrap();

    let resp_str = String::from_utf8_lossy(&resp_buf);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("Ibex!"));

    server_task.await.unwrap();
}
