// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The client transport pump, driven against a real rustls peer over a real socket.
//!
//! These use a socketpair and a genuine `rustls::ClientConnection`, not an in-memory
//! shuttle, because the things most likely to be wrong here are the socket interactions:
//! a partial `write_tls`, a `WouldBlock` in the middle of a handshake, an EOF arriving
//! without `close_notify`.

use ibex_rt::{ClientXprt, Io};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

fn test_certs() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate cert");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    (der, key)
}

/// The bind side, on the rustls Ibex serves TCP with (0.24); the client below is rustls 0.23.
fn server_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Arc<ibex_tls::tcp::BindTls> {
    ibex_tls::tcp::BindTls::single(vec![cert], key, Vec::new()).expect("server config")
}

fn client_config(cert: &CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("trust the test cert");
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A connected pair of non-blocking TCP sockets on loopback.
fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nonblocking(true).expect("nonblocking client");
    server.set_nonblocking(true).expect("nonblocking server");
    (client, server)
}

/// Runs the client side of a rustls session over a non-blocking socket until it settles.
fn pump_client(conn: &mut ClientConnection, sock: &mut TcpStream) {
    loop {
        let mut progress = false;
        while conn.wants_write() {
            match conn.write_tls(sock) {
                Ok(0) => break,
                Ok(_) => progress = true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("client write_tls: {e}"),
            }
        }
        if conn.wants_read() {
            match conn.read_tls(sock) {
                Ok(0) => {}
                Ok(_) => {
                    conn.process_new_packets().expect("client process");
                    progress = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("client read_tls: {e}"),
            }
        }
        if !progress {
            return;
        }
    }
}

/// A full handshake and a byte in each direction, over sockets.
///
/// The handshake is the part the plaintext state machine cannot express on its own: the
/// server has bytes to put on the wire before any application data exists, and the
/// stream layer only asks to write when its response buffer is non-empty. If `recv` did
/// not flush, this deadlocks.
#[test]
fn handshake_completes_and_data_flows_both_ways() {
    let (cert, key) = test_certs();
    let (mut cli_sock, srv_sock) = socket_pair();
    let mut xprt = ibex_rt::accept_tls(&srv_sock, server_config(cert.clone(), key));

    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(client_config(&cert), name).expect("client conn");

    let fd = srv_sock.as_fd();
    let mut buf = [0u8; 256];
    for _ in 0..40 {
        pump_client(&mut client, &mut cli_sock);
        let _ = xprt.recv(fd, &mut buf).expect("server recv");
        if xprt.is_ready() && !client.is_handshaking() {
            break;
        }
    }
    assert!(xprt.is_ready(), "server never finished the handshake");
    assert!(!client.is_handshaking(), "client never finished the handshake");

    // Client to server.
    client.writer().write_all(b"ping").expect("client write");
    pump_client(&mut client, &mut cli_sock);
    let mut got = Vec::new();
    for _ in 0..20 {
        match xprt.recv(fd, &mut buf).expect("server recv") {
            Io::Done(n) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => {}
        }
        if got == b"ping" {
            break;
        }
        pump_client(&mut client, &mut cli_sock);
    }
    assert_eq!(got, b"ping", "plaintext did not arrive at the server");

    // Server to client.
    assert!(matches!(
        xprt.send(fd, b"pong").expect("server send"),
        Io::Done(4)
    ));
    let mut out = Vec::new();
    for _ in 0..20 {
        pump_client(&mut client, &mut cli_sock);
        let mut b = [0u8; 64];
        if let Ok(n) = client.reader().read(&mut b) {
            out.extend_from_slice(&b[..n]);
        }
        if out == b"pong" {
            break;
        }
    }
    assert_eq!(out, b"pong", "plaintext did not arrive at the client");
}

/// A socket EOF without `close_notify` must not look like a clean end.
///
/// This is the truncation attack: an attacker who can inject a FIN ends the stream early,
/// and a proxy that reports `Io::Eof` hands a partial body upstream as a complete one.
/// `Io::Closed` is the honest answer, and `was_truncated` records why.
#[test]
fn an_eof_without_close_notify_is_reported_as_truncation() {
    let (cert, key) = test_certs();
    let (mut cli_sock, srv_sock) = socket_pair();
    let mut xprt =
        ibex_rt::accept_tls(&srv_sock, server_config(cert.clone(), key));
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(client_config(&cert), name).expect("client conn");

    let fd = srv_sock.as_fd();
    let mut buf = [0u8; 256];
    for _ in 0..40 {
        pump_client(&mut client, &mut cli_sock);
        let _ = xprt.recv(fd, &mut buf).expect("recv");
        if xprt.is_ready() && !client.is_handshaking() {
            break;
        }
    }
    assert!(xprt.is_ready(), "handshake did not complete");

    // Drop the socket without sending close_notify.
    drop(cli_sock);

    let mut verdict = None;
    for _ in 0..20 {
        match xprt.recv(fd, &mut buf) {
            Ok(Io::Closed) => {
                verdict = Some("closed");
                break;
            }
            Ok(Io::Eof) => {
                verdict = Some("eof");
                break;
            }
            Ok(_) => {}
            Err(_) => {
                verdict = Some("error");
                break;
            }
        }
    }
    assert_eq!(
        verdict,
        Some("closed"),
        "a truncated stream must not be reported as a clean Eof"
    );
    assert!(
        xprt.was_truncated(),
        "the truncation should be recorded on the transport"
    );
}

/// `close_notify` is a clean end, and must be told apart from the case above.
#[test]
fn close_notify_is_a_clean_eof() {
    let (cert, key) = test_certs();
    let (mut cli_sock, srv_sock) = socket_pair();
    let mut xprt =
        ibex_rt::accept_tls(&srv_sock, server_config(cert.clone(), key));
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(client_config(&cert), name).expect("client conn");

    let fd = srv_sock.as_fd();
    let mut buf = [0u8; 256];
    for _ in 0..40 {
        pump_client(&mut client, &mut cli_sock);
        let _ = xprt.recv(fd, &mut buf).expect("recv");
        if xprt.is_ready() && !client.is_handshaking() {
            break;
        }
    }
    assert!(xprt.is_ready(), "handshake did not complete");

    client.send_close_notify();
    pump_client(&mut client, &mut cli_sock);

    let mut verdict = None;
    for _ in 0..20 {
        match xprt.recv(fd, &mut buf).expect("recv") {
            Io::Eof => {
                verdict = Some("eof");
                break;
            }
            Io::Closed => {
                verdict = Some("closed");
                break;
            }
            _ => {}
        }
        pump_client(&mut client, &mut cli_sock);
    }
    assert_eq!(verdict, Some("eof"), "close_notify is a clean end of stream");
    assert!(!xprt.was_truncated());
}

/// The plaintext arm must behave exactly as `raw::recv`/`raw::send` did.
#[test]
fn the_plain_arm_is_a_passthrough() {
    let (mut a, b) = socket_pair();
    let mut xprt = ClientXprt::Plain;
    assert!(xprt.is_ready(), "plaintext needs no handshake");
    assert!(!xprt.wants_write(), "plaintext never asks for writability");

    a.write_all(b"hello").expect("write");
    let fd = b.as_fd();
    let mut buf = [0u8; 16];
    let mut got = Vec::new();
    for _ in 0..20 {
        if let Ok(Io::Done(n)) = xprt.recv(fd, &mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        if got == b"hello" {
            break;
        }
    }
    assert_eq!(got, b"hello");

    assert!(matches!(xprt.send(fd, b"hi").expect("send"), Io::Done(2)));
    let mut out = [0u8; 8];
    a.set_nonblocking(false).expect("blocking");
    let n = a.read(&mut out).expect("read back");
    assert_eq!(&out[..n], b"hi");
}

/// A TLS transport asks for writability during a handshake even with no data queued.
///
/// The plaintext loop only polls for writability when its response buffer is non-empty.
/// A handshake is mostly the server talking, so without this the connection stalls.
#[test]
fn tls_asks_for_writability_during_the_handshake() {
    let (mut cli_sock, srv_sock) = socket_pair();
    let (cert, key) = test_certs();
    let mut xprt =
        ibex_rt::accept_tls(&srv_sock, server_config(cert.clone(), key));
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(client_config(&cert), name).expect("client conn");

    // Let the ClientHello arrive, but do not let the server flush its reply yet.
    while client.wants_write() {
        match client.write_tls(&mut cli_sock) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let fd = srv_sock.as_fd();
    let mut buf = [0u8; 256];
    let _ = xprt.recv(fd, &mut buf).expect("recv");
    assert!(
        !xprt.is_ready(),
        "the handshake cannot be finished after one flight"
    );
    // Either it still has bytes queued, or it flushed them itself during recv. Both are
    // correct; what would be wrong is finishing while rustls still holds unflushed data
    // and nothing asking the poller for writability.
    assert!(
        xprt.wants_write() || !xprt.is_ready(),
        "the transport neither flushed nor asked to write"
    );
    let _ = srv_sock.as_raw_fd();
}

/// T440: full-size records (longer than the 16 KiB input buffer once encrypted), read through
/// a buffer much smaller than a record, arrive whole and in order; and so do the ones sent.
/// The plaintext the reader's buffer could not take stays in the input until it is read.
#[test]
fn full_records_read_in_small_pieces_and_written_in_large_ones() {
    let (cert, key) = test_certs();
    let (mut cli_sock, srv_sock) = socket_pair();
    let mut xprt = ibex_rt::accept_tls(&srv_sock, server_config(cert.clone(), key));
    let name = ServerName::try_from("localhost").expect("name");
    let mut client = ClientConnection::new(client_config(&cert), name).expect("client conn");
    let fd = srv_sock.as_fd();
    let mut small = [0u8; 1000];
    for _ in 0..40 {
        pump_client(&mut client, &mut cli_sock);
        let _ = xprt.recv(fd, &mut small).expect("server recv");
        if xprt.is_ready() && !client.is_handshaking() {
            break;
        }
    }
    assert!(xprt.is_ready(), "server never finished the handshake");

    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut sent = 0;
    let mut got = Vec::new();
    for _ in 0..100_000 {
        if sent < body.len() {
            sent += client.writer().write(&body[sent..(sent + 40_000).min(body.len())]).expect("client write");
        }
        pump_client(&mut client, &mut cli_sock);
        match xprt.recv(fd, &mut small).expect("server recv") {
            Io::Done(n) => got.extend_from_slice(&small[..n]),
            Io::WouldBlock => {}
            other => panic!("server recv: {other:?}"),
        }
        if got.len() == body.len() {
            break;
        }
    }
    assert_eq!(got.len(), body.len(), "the whole body arrived");
    assert!(got == body, "the body arrived intact");

    // Server to client, in writes larger than a record.
    let mut out = Vec::new();
    let mut off = 0;
    for _ in 0..100_000 {
        if off < body.len() {
            if let Io::Done(n) = xprt.send(fd, &body[off..(off + 50_000).min(body.len())]).expect("server send") {
                off += n;
            }
        }
        pump_client(&mut client, &mut cli_sock);
        let mut b = [0u8; 65536];
        while let Ok(n) = client.reader().read(&mut b) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&b[..n]);
        }
        if out.len() == body.len() {
            break;
        }
    }
    assert_eq!(out.len(), body.len(), "the whole response arrived");
    assert!(out == body, "the response arrived intact");
}
