// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A `bind ... ssl` line's configuration, built as the binary builds it
//! ([`alcyon_tls::tcp::from_bind_config`], rustls 0.24; T479 moved these off `TlsConfig`).

use alcyon_config::ast::BindConfig;
use alcyon_proto::transport::TlsInfo;
use alcyon_tls::tcp::from_bind_config;
use std::fs;
use tempfile::TempDir;

use crate::common;

/// The bundle (certificate and key) and the certificate alone, in PEM.
fn generate_pem(sans: Vec<String>) -> (String, String) {
    let cert = common::TestCert::new(sans);
    (cert.bundle_pem(), cert.cert_pem)
}

/// What a configuration offers, as bytes.
fn alpn_of(cfg: &alcyon_tls::tcp::rustls24::ServerConfig) -> Vec<Vec<u8>> {
    cfg.alpn_protocols.iter().map(|p| p.as_ref().to_vec()).collect()
}

fn default_bind() -> BindConfig {
    BindConfig {
        line: 0,
        sock: None,
        addr: "127.0.0.1:443".parse().unwrap(),
        quic: false, ssl: true,
        crt: vec![],
        alpn: vec![],
        proto: None,
        accept_proxy: false,
        accept_proxy_v2: false,
        name: None,
        id: None,
        min_ver: None,
        max_ver: None,
    }
}

#[test]
fn test_sni_name_mismatch_filename() {
    let temp_dir = TempDir::new().unwrap();
    // Filename DOES NOT match SAN (actual-domain.com vs completely_different_name.pem)
    let cert_path = temp_dir.path().join("completely_different_name.pem");
    let (pem, cert_pem) = generate_pem(vec!["actual-domain.com".to_string()]);
    fs::write(&cert_path, pem).unwrap();

    let mut bind = default_bind();
    bind.crt = vec![cert_path.to_string_lossy().to_string()];

    // The server from the parsed config, a client requesting "actual-domain.com"
    let server = from_bind_config(&bind).expect("Should load config");
    let mut p = common::Pair::new(server, &common::client_trusting(&cert_pem, vec![]), "actual-domain.com");
    p.complete();

    assert_eq!(p.srv.tls_info.sni(), Some("actual-domain.com"));
}

#[test]
fn test_cert_path_does_not_exist() {
    let mut bind = default_bind();
    bind.crt = vec!["/tmp/does_not_exist.pem".to_string()];

    let err = from_bind_config(&bind).unwrap_err();
    assert!(err.contains("Failed to read metadata for /tmp/does_not_exist.pem") || err.contains("Failed to open file /tmp/does_not_exist.pem"));
}

#[test]
fn test_cert_no_private_key() {
    let temp_dir = TempDir::new().unwrap();
    let cert_path = temp_dir.path().join("nokey.com.pem");
    let (pem, _) = generate_pem(vec!["nokey.com".to_string()]);
    let pem = pem.split("-----BEGIN PRIVATE KEY-----").next().unwrap();
    fs::write(&cert_path, pem).unwrap();

    let mut bind = default_bind();
    bind.crt = vec![cert_path.to_string_lossy().to_string()];

    let err = from_bind_config(&bind).unwrap_err();
    assert!(err.contains("No private key found"));
}

#[test]
fn test_single_cert() {
    let temp_dir = TempDir::new().unwrap();
    let cert_path = temp_dir.path().join("example.com.pem");
    let (pem, _) = generate_pem(vec!["example.com".to_string()]);
    fs::write(&cert_path, pem).unwrap();

    let mut bind = default_bind();
    bind.crt = vec![cert_path.to_string_lossy().to_string()];

    let _config = from_bind_config(&bind).expect("Should load config");
}

#[test]
fn test_multiple_certs_sni() {
    let temp_dir = TempDir::new().unwrap();
    let cert1 = temp_dir.path().join("example.com.pem");
    let cert2 = temp_dir.path().join("api.example.com.pem");
    
    let (pem1, _) = generate_pem(vec!["example.com".to_string()]);
    let (pem2, _) = generate_pem(vec!["api.example.com".to_string()]);
    
    fs::write(&cert1, pem1).unwrap();
    fs::write(&cert2, pem2).unwrap();

    let mut bind = default_bind();
    bind.crt = vec![
        cert1.to_string_lossy().to_string(),
        cert2.to_string_lossy().to_string(),
    ];

    let _config = from_bind_config(&bind).expect("Should load config");
}

#[test]
fn test_load_directory() {
    let temp_dir = TempDir::new().unwrap();
    let cert1 = temp_dir.path().join("example.com.pem");
    let cert2 = temp_dir.path().join("api.example.com.pem");
    
    let (pem1, _) = generate_pem(vec!["example.com".to_string()]);
    let (pem2, _) = generate_pem(vec!["api.example.com".to_string()]);
    
    fs::write(&cert1, pem1).unwrap();
    fs::write(&cert2, pem2).unwrap();

    let mut bind = default_bind();
    bind.crt = vec![temp_dir.path().to_string_lossy().to_string()];

    let _config = from_bind_config(&bind).expect("Should load config");
}

/// Regression tests for the DER walk that produces the SNI names.
///
/// Restored after a task rewrote this file and dropped them. They are the reason the
/// parser is written the way it is, so losing them loses the argument for it.
mod san_extraction {
    use alcyon_tls::config::extract_dns_sans;
    use rcgen::generate_simple_self_signed;

    /// The names come from inside the certificate, wildcards included.
    #[test]
    fn sans_are_read_from_the_certificate() {
        let cert = generate_simple_self_signed(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "*.api.example.com".to_string(),
        ])
        .expect("generate");
        let names = extract_dns_sans(cert.cert.der().as_ref());
        assert!(names.contains(&"example.com".to_string()), "{names:?}");
        assert!(names.contains(&"www.example.com".to_string()), "{names:?}");
        assert!(
            names.contains(&"*.api.example.com".to_string()),
            "wildcards must survive: {names:?}"
        );
    }

    /// A malformed certificate must not take the process down.
    ///
    /// The first version of this parser sliced with a length it read out of the input
    /// and never checked against what remained, so a name declaring 127 bytes with two
    /// behind it panicked. Certificates are read from the operator's disk at startup, so
    /// a truncated file was enough to stop the proxy from booting.
    #[test]
    fn a_malformed_certificate_yields_nothing_rather_than_panicking() {
        let cases: &[&[u8]] = &[
            // A SAN whose declared name length runs past the end of the buffer.
            &[
                0x30, 0x0d, 0x30, 0x0b, 0xa3, 0x09, 0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55,
                0x1d, 0x11,
            ],
            // Indefinite-form length, which DER forbids.
            &[0x30, 0x80, 0x00, 0x00],
            // A length wider than a usize.
            &[0x30, 0x8f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            // Truncated mid-element.
            &[0x30, 0x20, 0x30],
            &[0x30],
            &[],
        ];
        for (i, der) in cases.iter().enumerate() {
            let names = extract_dns_sans(der);
            assert!(names.is_empty(), "case {i} produced {names:?}");
        }
    }

    /// The extension is found by walking the structure, not by scanning for its OID.
    ///
    /// The bytes `06 03 55 1D 11` can occur anywhere -- in a key, a signature, or a
    /// subject string someone chose -- and a scan finds the first of them and parses
    /// whatever follows as though it were the extension.
    #[test]
    fn the_oid_is_not_found_by_scanning() {
        let cert =
            generate_simple_self_signed(vec!["real.example".to_string()]).expect("generate");
        let mut der = Vec::new();
        der.extend_from_slice(&[0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0c, 0x30, 0x0a]);
        der.extend_from_slice(&[0x82, 0x08]);
        der.extend_from_slice(b"evil.com");
        let decoy_len = der.len();
        der.extend_from_slice(cert.cert.der().as_ref());

        let names = extract_dns_sans(&der);
        assert!(
            !names.contains(&"evil.com".to_string()),
            "a planted OID was parsed as the extension: {names:?}"
        );

        let real = extract_dns_sans(&der[decoy_len..]);
        assert_eq!(real, vec!["real.example".to_string()]);
    }

    /// SNI matching is case-insensitive, so the names are normalised on the way in.
    #[test]
    fn names_are_normalised_to_lowercase() {
        let cert = generate_simple_self_signed(vec!["MiXeD.Example.COM".to_string()])
            .expect("generate");
        let names = extract_dns_sans(cert.cert.der().as_ref());
        assert_eq!(names, vec!["mixed.example.com".to_string()]);
    }
}

/// ALPN must offer only what the runtime can serve.
mod alpn {
    use alcyon_config::ast::BindConfig;
    use alcyon_tls::tcp::from_bind_config;

    fn bind_with(alpn: Vec<String>, crt: String) -> BindConfig {
        BindConfig {
            line: 0,
            sock: None,
            addr: "127.0.0.1:8443".parse().expect("addr"),
            quic: false, ssl: true,
            crt: vec![crt],
            alpn,
            proto: None,
            accept_proxy: false,
            accept_proxy_v2: false,
            name: None,
            id: None,
            min_ver: None,
            max_ver: None,
        }
    }

    fn a_cert() -> (tempfile::TempDir, String) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("c.pem");
        std::fs::write(&path, super::common::generate_test_cert_bundle_pem(vec![
            "localhost".to_string(),
        ]))
        .expect("write");
        let p = path.to_string_lossy().to_string();
        (dir, p)
    }

    /// The default offer is h2 and HTTP/1.1.
    #[test]
    fn h2_is_advertised_by_default() {
        let (_dir, crt) = a_cert();
        let cfg = from_bind_config(&bind_with(Vec::new(), crt)).expect("build");
        assert_eq!(
            super::alpn_of(&cfg.config),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "both h2 and http/1.1 are offered by default"
        );
    }

    /// An operator asking for h2 gets h2 honoured.
    #[test]
    fn a_requested_h2_is_honoured() {
        let (_dir, crt) = a_cert();
        let bind = bind_with(vec!["h2".to_string(), "http/1.1".to_string()], crt);
        let cfg = from_bind_config(&bind).expect("build");
        assert_eq!(super::alpn_of(&cfg.config), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    /// Asking for nothing servable is an error, not an empty offer.
    #[test]
    fn requesting_only_unservable_protocols_is_refused() {
        let (_dir, crt) = a_cert();
        let bind = bind_with(vec!["spdy/3".to_string()], crt);
        let err = from_bind_config(&bind).expect_err("must refuse");
        assert!(err.contains("ALPN"), "{err}");
    }
}

/// The version bounds of a bind (T153): what the configuration parser has already checked
/// is checked again where the handshake configuration is built.
mod versions {
    use alcyon_config::ast::BindConfig;
    use alcyon_config::TlsVersion;
    use alcyon_tls::tcp::from_bind_config;

    fn bind(quic: bool, min: Option<TlsVersion>, max: Option<TlsVersion>) -> (tempfile::TempDir, BindConfig) {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("c.pem");
        std::fs::write(&path, super::common::generate_test_cert_bundle_pem(vec!["localhost".to_string()])).expect("write");
        let b = BindConfig {
            line: 0,
            sock: None,
            addr: "127.0.0.1:8443".parse().expect("addr"),
            quic,
            ssl: true,
            crt: vec![path.to_string_lossy().to_string()],
            alpn: vec!["http/1.1".to_string()],
            proto: None,
            accept_proxy: false,
            accept_proxy_v2: false,
            name: None,
            id: None,
            min_ver: min,
            max_ver: max,
        };
        (dir, b)
    }

    #[test]
    fn a_range_with_no_version_in_it_is_refused() {
        let (_d, b) = bind(false, Some(TlsVersion::Tls13), Some(TlsVersion::Tls12));
        let err = from_bind_config(&b).expect_err("nothing left");
        assert!(err.contains("all SSL/TLS versions are disabled for bind '127.0.0.1:8443'"), "{err}");
    }

    #[test]
    fn a_quic_bind_cannot_be_held_to_tls12() {
        let (_d, b) = bind(true, None, Some(TlsVersion::Tls12));
        let err = from_bind_config(&b).expect_err("QUIC is TLS 1.3");
        assert!(err.contains("QUIC needs TLS 1.3"), "{err}");
        // With no bound, or a bound that leaves 1.3, it builds (and offers 1.3 only).
        for (min, max) in [(None, None), (Some(TlsVersion::Tls12), None)] {
            let (_d, b) = bind(true, min, max);
            let built = from_bind_config(&b).expect("builds");
            let p = built.config.provider();
            assert!(p.tls12_cipher_suites.is_empty() && !p.tls13_cipher_suites.is_empty(), "TLS 1.3 only");
        }
    }

    #[test]
    fn version_ranges_narrow_what_rustls_speaks() {
        use alcyon_tls::TlsVersions;
        let names = alcyon_tls::versions_between;
        assert_eq!(names(None, None), TlsVersions { tls12: true, tls13: true });
        assert_eq!(names(Some(TlsVersion::Tls13), None), TlsVersions { tls12: false, tls13: true });
        assert_eq!(names(None, Some(TlsVersion::Tls12)), TlsVersions { tls12: true, tls13: false });
        assert!(names(Some(TlsVersion::Tls13), Some(TlsVersion::Tls12)).is_empty());
        assert!(!names(Some(TlsVersion::Tls12), Some(TlsVersion::Tls12)).is_empty());
    }
}

/// Session resumption lasts as long as `HAProxy`'s (T283). With no `tune.ssl.lifetime`,
/// `HAProxy` leaves OpenSSL's session timeout alone: 7200 s, which is the lifetime hint
/// of its NewSessionTicket (`openssl sess_id -text` after `s_client -sess_out`, TLS 1.2
/// and 1.3 alike, 3.5-dev8-885761-29), and past which OpenSSL refuses to resume.
/// rustls's own ticketer advertised 43200 s and kept its keys for as long.
mod resumption_lifetime {
    use alcyon_tls::tcp::from_bind_config;

    #[test]
    fn tickets_advertise_and_last_haproxys_7200_s() {
        let (_dir, crt) = super::a_test_cert();
        let cfg = from_bind_config(&super::a_test_bind(crt)).expect("build");
        let ticketer = cfg.config.ticketer.as_ref().expect("tickets are on by default, as in HAProxy");
        assert_eq!(ticketer.lifetime(), std::time::Duration::from_secs(7200), "the NewSessionTicket lifetime hint");
    }
}

fn a_test_cert() -> (tempfile::TempDir, String) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("c.pem");
    std::fs::write(&path, common::generate_test_cert_bundle_pem(vec!["localhost".to_string()])).expect("write");
    let p = path.to_string_lossy().to_string();
    (dir, p)
}

fn a_test_bind(crt: String) -> BindConfig {
    BindConfig { crt: vec![crt], ..default_bind() }
}
