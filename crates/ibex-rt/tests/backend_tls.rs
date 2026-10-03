// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Outbound backend TLS tests for Ibex.
//!
//! Asserts:
//! 1. Successful HTTPS proxying to TLS backend over `ServerXprt::Tls`.
//! 2. `verify required` refusing an untrusted / self-signed certificate.
//! 3. `verify none` accepting the self-signed certificate.
//! 4. SNI mismatch rejection under certificate validation.
//! 5. End-to-end `TcpSession` proxying through `ServerXprt::Tls`.

use ibex_rt::{Io, TcpSession, Timeouts};
use ibex_sched::Tick;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig, ServerConnection};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::sync::Arc;

use ibex_tls::{build_backend_client_config, BackendTlsOptions};

fn test_certs(san: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec![san.to_string()])
        .expect("generate test cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let pem = cert.cert.pem();
    (der, key, pem)
}

fn server_tls_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

fn backend_client_config_with_ca(ca_pem: &str) -> (Arc<ClientConfig>, tempfile::NamedTempFile) {
    let mut temp = tempfile::NamedTempFile::new().expect("create temp ca file");
    temp.write_all(ca_pem.as_bytes()).expect("write ca pem");
    let opts = BackendTlsOptions {
        verify_required: true,
        ca_file: Some(temp.path().to_path_buf()),
        client_crt: None,
        alpn: vec![b"http/1.1".to_vec()],
        sni: None,
    };
    let cfg = build_backend_client_config(&opts).expect("build backend config");
    (cfg, temp)
}

fn backend_client_config_system_ca() -> Arc<ClientConfig> {
    let opts = BackendTlsOptions {
        verify_required: true,
        ca_file: None,
        client_crt: None,
        alpn: vec![b"http/1.1".to_vec()],
        sni: None,
    };
    build_backend_client_config(&opts).expect("build backend config")
}

fn backend_client_config_verify_none() -> Arc<ClientConfig> {
    let opts = BackendTlsOptions {
        verify_required: false,
        ca_file: None,
        client_crt: None,
        alpn: vec![b"http/1.1".to_vec()],
        sni: None,
    };
    build_backend_client_config(&opts).expect("build backend config")
}

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nonblocking(true).expect("nonblocking client");
    server.set_nonblocking(true).expect("nonblocking server");
    client.set_nodelay(true).expect("nodelay client");
    server.set_nodelay(true).expect("nodelay server");
    (client, server)
}

/// Runs a server-side rustls connection to pump packets against a nonblocking socket.
fn pump_server(conn: &mut ServerConnection, sock: &mut TcpStream) {
    loop {
        let mut progress = false;
        while conn.wants_write() {
            match conn.write_tls(sock) {
                Ok(0) => break,
                Ok(_) => progress = true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("server write_tls: {e}"),
            }
        }
        if conn.wants_read() {
            match conn.read_tls(sock) {
                Ok(0) => {}
                Ok(_) => {
                    let _ = conn.process_new_packets().expect("server process_new_packets");
                    progress = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("server read_tls: {e}"),
            }
        }
        while conn.wants_write() {
            match conn.write_tls(sock) {
                Ok(0) => break,
                Ok(_) => progress = true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("server write_tls: {e}"),
            }
        }
        if !progress {
            return;
        }
    }
}

/// Test 1: Successful HTTPS proxying over `ServerXprt::Tls`.
#[test]
fn backend_tls_handshake_completes_and_data_flows_both_ways() {
    let (cert, key, pem) = test_certs("localhost");
    let (client_sock, mut server_sock) = socket_pair();
    let mut backend_server = ServerConnection::new(server_tls_config(cert, key))
        .expect("server conn");

    let (client_cfg, _ca_file) = backend_client_config_with_ca(&pem);
    let name = ServerName::try_from("localhost").expect("name");
    let mut xprt = ibex_rt::connect_tls(&client_sock, client_cfg, name)
        .expect("connect_tls");

    let fd = client_sock.as_fd();
    let mut buf = [0u8; 256];
    for _ in 0..40 {
        let _ = xprt.recv(fd, &mut buf);
        pump_server(&mut backend_server, &mut server_sock);
        let _ = xprt.recv(fd, &mut buf);
        pump_server(&mut backend_server, &mut server_sock);
        if xprt.is_ready() && !backend_server.is_handshaking() {
            break;
        }
    }
    assert!(xprt.is_ready(), "backend client transport never finished handshake");
    assert!(!backend_server.is_handshaking(), "backend server never finished handshake");
    assert_eq!(xprt.alpn(), Some(&b"http/1.1"[..]), "negotiated ALPN must be http/1.1");

    // Client to backend server
    assert!(matches!(
        xprt.send(fd, b"GET / HTTP/1.1\r\n\r\n").expect("send"),
        Io::Done(_)
    ));
    pump_server(&mut backend_server, &mut server_sock);

    let mut got = Vec::new();
    let mut b = [0u8; 64];
    for _ in 0..20 {
        if let Ok(n) = backend_server.reader().read(&mut b) {
            got.extend_from_slice(&b[..n]);
        }
        if got.starts_with(b"GET / HTTP/1.1") {
            break;
        }
        pump_server(&mut backend_server, &mut server_sock);
    }
    assert!(
        got.starts_with(b"GET / HTTP/1.1"),
        "backend server did not receive client request"
    );

    // Backend server to client
    backend_server.writer().write_all(b"HTTP/1.1 200 OK\r\n\r\n").expect("server write");
    pump_server(&mut backend_server, &mut server_sock);

    let mut out = Vec::new();
    for _ in 0..20 {
        match xprt.recv(fd, &mut buf).expect("recv") {
            Io::Done(n) if n > 0 => out.extend_from_slice(&buf[..n]),
            _ => {}
        }
        if out.starts_with(b"HTTP/1.1 200 OK") {
            break;
        }
        pump_server(&mut backend_server, &mut server_sock);
    }
    assert!(
        out.starts_with(b"HTTP/1.1 200 OK"),
        "client did not receive backend response"
    );
}

/// Test 2: `verify required` refuses an untrusted/self-signed certificate.
#[test]
fn backend_tls_verify_required_refuses_untrusted_certificate() {
    let (cert, key, _pem) = test_certs("localhost");
    let (client_sock, mut server_sock) = socket_pair();
    let mut backend_server = ServerConnection::new(server_tls_config(cert, key))
        .expect("server conn");

    // Default verify required without custom ca_file uses system roots -> untrusted self-signed cert is rejected
    let client_cfg = backend_client_config_system_ca();
    let name = ServerName::try_from("localhost").expect("name");
    let mut xprt = ibex_rt::connect_tls(&client_sock, client_cfg, name)
        .expect("connect_tls");

    let fd = client_sock.as_fd();
    let mut buf = [0u8; 256];
    let mut failed = false;
    for _ in 0..40 {
        let _ = xprt.recv(fd, &mut buf);
        pump_server(&mut backend_server, &mut server_sock);
        match xprt.recv(fd, &mut buf) {
            Err(_) | Ok(Io::Closed) => {
                failed = true;
                break;
            }
            Ok(_) => {}
        }
        if !backend_server.is_handshaking() && xprt.is_ready() {
            break;
        }
    }
    assert!(
        failed || !xprt.is_ready(),
        "verify required MUST refuse a backend presenting an untrusted certificate"
    );
}

/// Test 3: `verify none` accepts the self-signed certificate.
#[test]
fn backend_tls_verify_none_accepts_self_signed_certificate() {
    let (cert, key, _pem) = test_certs("localhost");
    let (client_sock, mut server_sock) = socket_pair();
    let mut backend_server = ServerConnection::new(server_tls_config(cert, key))
        .expect("server conn");

    let client_cfg = backend_client_config_verify_none();
    let name = ServerName::try_from("localhost").expect("name");
    let mut xprt = ibex_rt::connect_tls(&client_sock, client_cfg, name)
        .expect("connect_tls");

    let fd = client_sock.as_fd();
    let mut buf = [0u8; 256];
    for _ in 0..40 {
        let _ = xprt.recv(fd, &mut buf);
        pump_server(&mut backend_server, &mut server_sock);
        let _ = xprt.recv(fd, &mut buf);
        pump_server(&mut backend_server, &mut server_sock);
        if xprt.is_ready() && !backend_server.is_handshaking() {
            break;
        }
    }
    assert!(
        xprt.is_ready(),
        "verify none MUST successfully accept self-signed backend certificate"
    );
    assert!(!backend_server.is_handshaking());
}

/// Test 4: SNI mismatch is rejected when verifying server certificate.
#[test]
fn backend_tls_sni_mismatch_is_rejected() {
    // Backend presents certificate for "correct.example.com"
    let (cert, key, pem) = test_certs("correct.example.com");
    let (client_sock, mut server_sock) = socket_pair();
    let mut backend_server = ServerConnection::new(server_tls_config(cert, key))
        .expect("server conn");

    // Client trusts the CA/cert, but connects with SNI "wrong.example.com"
    let (client_cfg, _ca_file) = backend_client_config_with_ca(&pem);
    let name = ServerName::try_from("wrong.example.com").expect("name");
    let mut xprt = ibex_rt::connect_tls(&client_sock, client_cfg, name)
        .expect("connect_tls");

    let fd = client_sock.as_fd();
    let mut buf = [0u8; 256];
    let mut rejected = false;
    for _ in 0..40 {
        let _ = xprt.recv(fd, &mut buf);
        pump_server(&mut backend_server, &mut server_sock);
        match xprt.recv(fd, &mut buf) {
            Err(_) | Ok(Io::Closed) => {
                rejected = true;
                break;
            }
            Ok(_) => {}
        }
        if xprt.is_ready() {
            break;
        }
    }
    assert!(
        rejected || !xprt.is_ready(),
        "SNI mismatch against certificate SAN must be rejected during verification"
    );
}

/// Test 5: End-to-end `TcpSession` with `ServerXprt::Tls`.
#[test]
fn tcp_session_end_to_end_with_tls_backend() {
    let (cert, key, pem) = test_certs("localhost");
    let (mut cli_peer, cli_local) = socket_pair();
    let (mut srv_remote, srv_local) = socket_pair();

    let mut backend_server = ServerConnection::new(server_tls_config(cert, key))
        .expect("server conn");

    let (client_cfg, _ca_file) = backend_client_config_with_ca(&pem);
    let name = ServerName::try_from("localhost").expect("name");
    let srv_xprt = ibex_rt::connect_tls(&srv_local, client_cfg, name)
        .expect("connect_tls");

    let mut sess = TcpSession::new(
        cli_local.into(),
        Timeouts { client: 5000, server: 5000, connect: 5000 },
        0,
        Tick(1),
    );
    sess.attach_server_with_xprt(srv_local.into(), srv_xprt, Tick(1));
    sess.server_connected(Tick(1));

    // Queue HTTP request from client
    sess.req.put(b"GET /backend HTTP/1.1\r\nHost: localhost\r\n\r\n");

    for _ in 0..50 {
        let _ = sess.process(Tick(1));
        pump_server(&mut backend_server, &mut srv_remote);
        let _ = sess.process(Tick(1));
        if sess.srv_xprt.is_ready() && !backend_server.is_handshaking() && sess.req.is_empty() {
            break;
        }
    }

    assert!(
        sess.req.is_empty(),
        "request bytes should have been forwarded to backend server"
    );

    // Deliver response from backend server
    backend_server.writer().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").expect("write");
    let mut resp_buf = vec![0u8; 1024];
    let mut total_read = 0;
    for _ in 0..50 {
        pump_server(&mut backend_server, &mut srv_remote);
        let _ = sess.process(Tick(1));
        match cli_peer.read(&mut resp_buf[total_read..]) {
            Ok(n) if n > 0 => {
                total_read += n;
                if total_read >= 15 {
                    break;
                }
            }
            _ => {}
        }
    }

    assert!(
        resp_buf[..total_read].starts_with(b"HTTP/1.1 200 OK"),
        "TcpSession with ServerXprt::Tls received response: {:?}",
        String::from_utf8_lossy(&resp_buf[..total_read])
    );
}
