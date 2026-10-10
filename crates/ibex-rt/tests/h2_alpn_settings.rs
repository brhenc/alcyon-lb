// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A TLS client that negotiates `h2` and then says nothing is sent nothing: the server's
//! SETTINGS follow the client's preface. Measured on HAProxy 3.5-dev8-885761-29 (`bind ssl alpn
//! h2`, a client that handshakes and waits: no byte in 3 s). T217 removed the creation of the
//! connection's H2 context on ALPN alone, which no test reached and which showed nothing.

mod common;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::Read;
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn an_h2_alpn_client_that_sends_nothing_is_sent_nothing() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("dir");
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
    let pem = dir.path().join("c.pem");
    std::fs::write(&pem, format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem())).expect("pem");
    let tls = common::reserve_addr();
    let cfg = dir.path().join("ibex.cfg");
    std::fs::write(
        &cfg,
        format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 5s\n  timeout server 1s\n\
             frontend fe\n  bind {tls} ssl crt {} alpn h2,http/1.1\n  http-request return status 200\n",
            pem.display()
        ),
    )
    .expect("cfg");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ibex"))
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn().map(common::Ibex)
        .expect("spawn ibex");
    assert!(common::wait_listening(tls), "ibex never listened");

    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ck.cert.der().to_vec())).expect("root");
    let mut conf = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    conf.alpn_protocols = vec![b"h2".to_vec()];
    let conn = ClientConnection::new(Arc::new(conf), ServerName::try_from("localhost").expect("name")).expect("client");
    let sock = TcpStream::connect(tls).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    let mut s = StreamOwned::new(conn, sock);
    // Finish the handshake without sending application data.
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock).expect("handshake");
    }
    assert_eq!(s.conn.alpn_protocol(), Some(&b"h2"[..]));
    let mut head = [0u8; 9];
    let got = s.read_exact(&mut head);
    common::stop(&mut child);
    let err = got.expect_err("nothing before the client's preface");
    assert!(matches!(err.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut), "{err:?}");
}
