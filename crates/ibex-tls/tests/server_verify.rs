// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! How a server's certificate is checked (T113): `HAProxy`'s rules, not webpki's.
//!
//! `ssl_sock_srv_verifycbk` (src/ssl_sock.c): the chain is verified against the trust
//! anchors; the name is checked only against the SNI sent, or `verifyhost` when none was,
//! and not at all when neither is set. The name is matched against the dNSName SANs, or
//! against the subject CN when the certificate has no dNSName at all, with one `*` allowed
//! in the leftmost label (RFC 6125 6.4.3, `ssl_sock_srv_hostcheck`). Measured on
//! 3.5-dev8-885761-29 with `reg-tests/ssl/certs/verifyhost_*`: a CN-only certificate
//! verifies against a matching `verifyhost` (200), a mismatching `verifyhost` with no SNI
//! fails (503), and with neither SNI nor `verifyhost` the name is not checked (200).

use ibex_tls::{build_backend_client_config, hostcheck, BackendTlsOptions, ServerVerifier};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::Write;
use std::sync::Arc;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn make_ca(name: &str) -> Ca {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("self-signed CA");
    Ca { cert, key }
}

/// A leaf signed by `ca`, with `sans` as dNSNames (none: CN only) and `cn` as subject CN.
fn leaf(ca: &Ca, sans: &[&str], cn: &str) -> CertificateDer<'static> {
    let mut params = CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).expect("params");
    params.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().expect("key");
    params.signed_by(&key, &ca.cert, &ca.key).expect("sign").der().clone()
}

fn verifier_for(ca: &Ca) -> Arc<ServerVerifier> {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(ca.cert.pem().as_bytes()).expect("write");
    ServerVerifier::from_options(&BackendTlsOptions { ca_file: Some(f.path().to_path_buf()), ..Default::default() })
        .expect("verifier")
}

fn verify(v: &ServerVerifier, cert: &CertificateDer<'static>, name: &str) -> bool {
    let name = ServerName::try_from(name.to_string()).expect("name");
    v.verify_server_cert(cert, &[], &name, &[], UnixTime::now()).is_ok()
}

#[test]
fn hostcheck_follows_rfc_6125_as_haproxy_does() {
    assert!(hostcheck("www.test1.com", "www.test1.com"));
    assert!(hostcheck("WWW.test1.com", "www.TEST1.com"));
    assert!(!hostcheck("www.test1.com", "test1.com"));
    assert!(hostcheck("*.test1.com", "www.test1.com"));
    assert!(hostcheck("w*.test1.com", "www.test1.com"));
    assert!(hostcheck("*w.test1.com", "www.test1.com"));
    assert!(!hostcheck("*.test1.com", "a.b.test1.com"), "a wildcard covers one label");
    assert!(!hostcheck("*.test1.com", "test1.com"));
    assert!(!hostcheck("www.*.com", "www.test1.com"), "only the leftmost label may hold the wildcard");
    assert!(!hostcheck("**.test1.com", "www.test1.com"));
    assert!(!hostcheck("*", "www"));
}

#[test]
fn the_name_is_checked_against_the_sans_with_cn_as_a_fallback() {
    let ca = make_ca("Test Root");
    let v = verifier_for(&ca);
    let san = leaf(&ca, &["backend.example.com"], "other.example.com");
    assert!(verify(&v, &san, "backend.example.com"));
    assert!(!verify(&v, &san, "other.example.com"), "with a dNSName present the CN is not consulted");
    assert!(!verify(&v, &san, "mismatch.example"));

    let cn_only = leaf(&ca, &[], "backend.example.com");
    assert!(verify(&v, &cn_only, "backend.example.com"), "no dNSName: the CN counts");
    assert!(!verify(&v, &cn_only, "other.example.com"));

    let wild = leaf(&ca, &["*.example.com"], "x");
    assert!(verify(&v, &wild, "a.example.com"));
    assert!(!verify(&v, &wild, "a.b.example.com"));
}

#[test]
fn an_ip_address_name_means_the_name_is_not_checked_but_the_chain_is() {
    let ca = make_ca("Test Root");
    let v = verifier_for(&ca);
    let san = leaf(&ca, &["backend.example.com"], "x");
    assert!(verify(&v, &san, "127.0.0.1"), "no SNI and no verifyhost: HAProxy does not care about the name");

    let other = make_ca("Another Root");
    let foreign = leaf(&other, &["backend.example.com"], "x");
    assert!(!verify(&v, &foreign, "127.0.0.1"), "but the chain must still verify");
    assert!(!verify(&v, &foreign, "backend.example.com"));
}

#[test]
fn the_client_config_offers_what_the_server_line_asked_for() {
    let ca = make_ca("Test Root");
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(ca.cert.pem().as_bytes()).expect("write");
    let cfg = build_backend_client_config(&BackendTlsOptions {
        ca_file: Some(f.path().to_path_buf()),
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        ..Default::default()
    })
    .expect("config");
    assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(cfg.enable_sni);

    // No `alpn`: nothing is offered, as HAProxy offers nothing (measured: a server
    // offering h2,http/1.1 saw `alpn=None` from `server ... ssl verify none`).
    let cfg = build_backend_client_config(&BackendTlsOptions { verify_required: false, ..Default::default() }).expect("config");
    assert!(cfg.alpn_protocols.is_empty());

    // `verify required` with nothing to verify against is a configuration error, not a
    // silent fall-back to the system roots.
    let err = build_backend_client_config(&BackendTlsOptions::default()).expect_err("no CA");
    assert!(err.contains("CA"), "{err}");
}
