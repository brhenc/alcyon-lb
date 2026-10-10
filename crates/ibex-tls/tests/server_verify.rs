// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T260): installs a process-wide default rustls CryptoProvider, which every other test in a shared binary would see

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

/// A `crl-file` revokes: the leaf whose serial it lists fails, one it does not list passes.
#[test]
fn a_crl_file_revokes_the_certificate_it_names() {
    use rcgen::{CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams, SerialNumber};
    let ca = make_ca("CRL Root");
    let mut params = CertificateParams::new(vec!["backend.example.com".to_string()]).expect("params");
    params.serial_number = Some(SerialNumber::from(vec![0x42, 0x42]));
    let key = KeyPair::generate().expect("key");
    let revoked = params.signed_by(&key, &ca.cert, &ca.key).expect("sign").der().clone();
    let other = leaf(&ca, &["backend.example.com"], "x");

    let crl = CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2026, 1, 1),
        next_update: rcgen::date_time_ymd(2036, 1, 1),
        crl_number: SerialNumber::from(vec![1]),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from(vec![0x42, 0x42]),
            revocation_time: rcgen::date_time_ymd(2026, 1, 2),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca.cert, &ca.key)
    .expect("crl");
    let mut ca_f = tempfile::NamedTempFile::new().expect("tmp");
    ca_f.write_all(ca.cert.pem().as_bytes()).expect("write");
    let mut crl_f = tempfile::NamedTempFile::new().expect("tmp");
    crl_f.write_all(crl.pem().expect("pem").as_bytes()).expect("write");
    let v = ServerVerifier::from_options(&BackendTlsOptions {
        ca_file: Some(ca_f.path().to_path_buf()),
        crl_file: Some(crl_f.path().to_path_buf()),
        ..Default::default()
    })
    .expect("verifier with CRL");
    assert!(!verify(&v, &revoked, "backend.example.com"), "a revoked certificate must be refused");
    assert!(verify(&v, &other, "backend.example.com"), "one the CRL does not name passes");

    let err = ServerVerifier::from_options(&BackendTlsOptions {
        ca_file: Some(ca_f.path().to_path_buf()),
        crl_file: Some("/nonexistent/crl.pem".into()),
        ..Default::default()
    })
    .expect_err("missing crl-file");
    assert!(err.contains("/nonexistent/crl.pem"), "{err}");
    let err = ServerVerifier::from_options(&BackendTlsOptions {
        ca_file: Some(ca_f.path().to_path_buf()),
        crl_file: Some(ca_f.path().to_path_buf()),
        ..Default::default()
    })
    .expect_err("a PEM with no CRL in it");
    assert!(err.contains("No CRL"), "{err}");
}

/// `ca-file @system-ca` loads the system bundle (`HAProxy` warns when it is empty and
/// goes on); a test CA is not in it, so its certificate fails.
#[test]
fn system_ca_is_a_trust_store_that_knows_no_test_ca() {
    let ca = make_ca("Not In The System");
    let v = ServerVerifier::from_options(&BackendTlsOptions { ca_file: Some("@system-ca".into()), ..Default::default() })
        .expect("system roots");
    assert!(!verify(&v, &leaf(&ca, &["backend.example.com"], "x"), "backend.example.com"));
}

/// `ssl-min-ver` / `ssl-max-ver` narrow the offer; a range with nothing in it is refused
/// and says what this build speaks. `no-ssl-reuse` builds a config without resumption.
#[test]
fn version_limits_and_no_reuse() {
    use ibex_config::TlsVersion;
    let ca = make_ca("Root");
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(ca.cert.pem().as_bytes()).expect("write");
    let base = BackendTlsOptions { ca_file: Some(f.path().to_path_buf()), ..Default::default() };
    build_backend_client_config(&BackendTlsOptions { min_ver: Some(TlsVersion::Tls13), ..base.clone() }).expect("TLS 1.3 only");
    build_backend_client_config(&BackendTlsOptions { max_ver: Some(TlsVersion::Tls13), no_reuse: true, ..base.clone() })
        .expect("up to 1.3, no reuse");
    let err = build_backend_client_config(&BackendTlsOptions { min_ver: Some(TlsVersion::Tls13), max_ver: Some(TlsVersion::Tls12), ..base })
        .expect_err("nothing left");
    assert!(err.contains("no TLS version is left") && err.contains("TLSv1_3"), "{err}");
}

/// A TLS 1.2 handshake through the verifier. The `ibex` binary's rustls speaks TLS 1.3
/// only (no `tls12` feature in the workspace dependency); this crate's test build has
/// TLS 1.2 through the `tokio-rustls` dev-dependency, so here is where
/// `ssl-max-ver TLSv1.2` and `ServerVerifier::verify_tls12_signature` are exercised.
#[test]
fn a_tls12_handshake_verifies_the_servers_signature() {
    use ibex_config::TlsVersion;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    let ca = make_ca("TLS12 Root");
    let mut params = CertificateParams::new(vec!["backend.example.com".to_string()]).expect("params");
    params.distinguished_name.push(DnType::CommonName, "backend.example.com");
    let key = KeyPair::generate().expect("key");
    let cert = params.signed_by(&key, &ca.cert, &ca.key).expect("sign");
    let server_cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server config");
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(ca.cert.pem().as_bytes()).expect("write");
    let client_cfg = build_backend_client_config(&BackendTlsOptions {
        ca_file: Some(f.path().to_path_buf()),
        max_ver: Some(TlsVersion::Tls12),
        ..Default::default()
    })
    .expect("client config");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut conn = rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn");
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let mut b = [0u8; 4];
        tls.read_exact(&mut b).expect("read");
        tls.write_all(b"pong").expect("write");
        b
    });
    let mut sock = TcpStream::connect(addr).expect("connect");
    let name = ServerName::try_from("backend.example.com".to_string()).expect("name");
    let mut conn = rustls::ClientConnection::new(client_cfg, name).expect("client conn");
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(b"ping").expect("write");
    let mut b = [0u8; 4];
    tls.read_exact(&mut b).expect("read");
    assert_eq!(&b, b"pong");
    assert_eq!(tls.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2), "the handshake must have been TLS 1.2");
    assert_eq!(&server.join().expect("server thread"), b"ping");
}

#[test]
fn a_wildcard_needs_a_leftmost_label_long_enough_to_match() {
    assert!(!hostcheck("abc*def.example", "ab.example"));
    assert!(hostcheck("abc*def.example", "abcdef.example"));
}
