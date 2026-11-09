// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Integration tests verifying full TLS 1.3 handshake, bidirectional data exchange,
//! SNI dispatch, ALPN negotiation, and `TlsInfo` introspection over the binary's TLS
//! session ([`alcyon_tls::conn::TlsCtx`], rustls 0.24; T479 moved them off `RustlsTransport`).

use crate::common::{client_trusting, Pair, TestCert};
use alcyon_config::ast::BindConfig;
use alcyon_proto::transport::{TlsInfo, VerifyResult};
use alcyon_tls::conn::TlsCtx;

#[test]
fn test_tls13_handshake_and_bidirectional_data() {
    let cert = TestCert::new(vec!["example.com".to_string()]);
    let bind = cert.bind(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let mut p = Pair::new(bind, &client_trusting(&cert.cert_pem, vec![b"h2".to_vec()]), "example.com");

    // 1. Handshake
    p.complete();

    // 2. Check TlsInfo on both ends
    let (s_info, c_info) = (&p.srv.tls_info, &p.cli.tls_info);
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
    assert_eq!(p.send_to_server(request), request);

    // 4. Server -> Client data transfer
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, Alcyon!\n";
    assert_eq!(p.send_to_client(response), response);

    // 5. Shutdown write
    p.cli.close_notify();
    assert!(p.cli.wants_write(), "close_notify queued");
}

/// A `crt` file per name: an exact name and a wildcard, each served for its own SNI. Each
/// client trusts only the certificate it must be served, so the wrong one fails it.
#[test]
fn test_sni_multi_cert_dispatch() {
    let exact = TestCert::new(vec!["site-a.com".to_string()]);
    let wildcard = TestCert::new(vec!["*.wildcard.org".to_string()]);
    let dir = tempfile::TempDir::new().expect("tempdir");
    let mut crt = Vec::new();
    for (name, c) in [("a.pem", &exact), ("w.pem", &wildcard)] {
        let path = dir.path().join(name);
        std::fs::write(&path, c.bundle_pem()).expect("write");
        crt.push(path.to_string_lossy().to_string());
    }
    let bind = BindConfig {
        line: 0,
        sock: None,
        addr: "127.0.0.1:443".parse().expect("addr"),
        quic: false,
        ssl: true,
        crt,
        alpn: vec![],
        proto: None,
        accept_proxy: false,
        accept_proxy_v2: false,
        name: None,
        id: None,
        min_ver: None,
        max_ver: None,
    };
    let bind = alcyon_tls::tcp::from_bind_config(&bind).expect("bind");

    // Connect with SNI = "site-a.com"
    let mut p = Pair::new(bind.clone(), &client_trusting(&exact.cert_pem, vec![]), "site-a.com");
    p.complete();
    assert_eq!(p.srv.tls_info.sni(), Some("site-a.com"));
    assert_eq!(p.cli.tls_info.peer_verify(), VerifyResult::Ok);

    // Connect with SNI = "api.wildcard.org" (matches *.wildcard.org)
    let mut p = Pair::new(bind.clone(), &client_trusting(&wildcard.cert_pem, vec![]), "api.wildcard.org");
    p.complete();
    assert_eq!(p.srv.tls_info.sni(), Some("api.wildcard.org"));
    assert_eq!(p.cli.tls_info.peer_verify(), VerifyResult::Ok);

    // The wildcard's client asking for the exact name gets the exact name's certificate,
    // which it does not trust.
    let mut p = Pair::new(bind, &client_trusting(&wildcard.cert_pem, vec![]), "site-a.com");
    let (_, c) = p.handshake();
    assert!(c.is_err(), "the exact name's certificate, not the wildcard's");
}

#[test]
fn test_alpn_negotiation_fallback() {
    let cert = TestCert::new(vec!["example.com".to_string()]);
    // Server supports [http/1.1]
    let bind = cert.bind(vec![b"http/1.1".to_vec()]);
    // Client supports [h2, http/1.1]
    let cfg = client_trusting(&cert.cert_pem, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let mut p = Pair::new(bind, &cfg, "example.com");
    p.complete();

    // Should negotiate http/1.1
    assert_eq!(p.srv.tls_info.alpn(), Some(&b"http/1.1"[..]));
    assert_eq!(p.cli.tls_info.alpn(), Some(&b"http/1.1"[..]));
}

/// A capture size reaches the server session: one given a size taps the `ClientHello`, one
/// without does not (covercheck, T344).
#[test]
fn the_transport_capture_size_reaches_the_server_context() {
    let bind = TestCert::new(vec!["example.com".to_string()]).bind(vec![]);
    assert!(!TlsCtx::accept(bind.clone()).tapping());
    let mut capturing = TlsCtx::accept(bind);
    capturing.enable_capture(256);
    assert!(capturing.tapping());
}
