use ibex_config::ast::BindConfig;
use ibex_tls::{TlsConfig, RustlsTransport, RustlsContext};
use std::fs;
use tempfile::TempDir;
use rustls::pki_types::ServerName;
use ibex_proto::transport::Transport;

mod common;

fn generate_pem(sans: Vec<String>) -> (String, rustls::pki_types::CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(sans).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    (format!("{cert_pem}{key_pem}"), rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec()))
}

fn default_bind() -> BindConfig {
    BindConfig {
        addr: "127.0.0.1:443".parse().unwrap(),
        ssl: true,
        crt: vec![],
        alpn: vec![],
        proto: None,
        accept_proxy: false,
        accept_proxy_v2: false,
    }
}

fn pump_handshake(
    server_transport: &RustlsTransport,
    server_ctx: &mut RustlsContext,
    client_transport: &RustlsTransport,
    client_ctx: &mut RustlsContext,
) {
    let mut iterations = 0;
    while (!server_ctx.handshake_done || !client_ctx.handshake_done) && iterations < 50 {
        iterations += 1;

        let _ = client_transport.handshake(client_ctx);
        let client_out = client_ctx.take_raw_output();
        if !client_out.is_empty() {
            server_ctx.feed_raw_input(&client_out);
        }

        let _ = server_transport.handshake(server_ctx);
        let server_out = server_ctx.take_raw_output();
        if !server_out.is_empty() {
            client_ctx.feed_raw_input(&server_out);
        }
    }
    assert!(server_ctx.handshake_done, "Server handshake timed out");
    assert!(client_ctx.handshake_done, "Client handshake timed out");
}

#[test]
fn test_sni_name_mismatch_filename() {
    let temp_dir = TempDir::new().unwrap();
    // Filename DOES NOT match SAN (actual-domain.com vs completely_different_name.pem)
    let cert_path = temp_dir.path().join("completely_different_name.pem");
    let (pem, der) = generate_pem(vec!["actual-domain.com".to_string()]);
    fs::write(&cert_path, pem).unwrap();

    let mut bind = default_bind();
    bind.crt = vec![cert_path.to_string_lossy().to_string()];

    // Create server transport using the parsed config
    let server_config = TlsConfig::from_bind_config(&bind).expect("Should load config");
    let server_transport = RustlsTransport::new_server(server_config);

    // Create client requesting "actual-domain.com"
    let root_store = common::build_root_store(&[der]);
    let client_config = TlsConfig::new().build_client_config(root_store).unwrap();
    let server_name = ServerName::try_from("actual-domain.com").unwrap();
    let client_transport = RustlsTransport::new_client(client_config, server_name);

    let mut server_ctx = server_transport.init(1, true).unwrap();
    let mut client_ctx = client_transport.init(2, false).unwrap();

    pump_handshake(
        &server_transport,
        &mut server_ctx,
        &client_transport,
        &mut client_ctx,
    );

    let s_info = server_transport.tls_info(&server_ctx).unwrap();
    assert_eq!(s_info.sni(), Some("actual-domain.com"));
}

#[test]
fn test_cert_path_does_not_exist() {
    let mut bind = default_bind();
    bind.crt = vec!["/tmp/does_not_exist.pem".to_string()];

    let err = TlsConfig::from_bind_config(&bind).unwrap_err();
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

    let err = TlsConfig::from_bind_config(&bind).unwrap_err();
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

    let _config = TlsConfig::from_bind_config(&bind).expect("Should load config");
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

    let _config = TlsConfig::from_bind_config(&bind).expect("Should load config");
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

    let _config = TlsConfig::from_bind_config(&bind).expect("Should load config");
}

/// Regression tests for the DER walk that produces the SNI names.
///
/// Restored after a task rewrote this file and dropped them. They are the reason the
/// parser is written the way it is, so losing them loses the argument for it.
mod san_extraction {
    use ibex_tls::config::extract_dns_sans;
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
    use ibex_config::ast::BindConfig;
    use ibex_tls::TlsConfig;

    fn bind_with(alpn: Vec<String>, crt: String) -> BindConfig {
        BindConfig {
            addr: "127.0.0.1:8443".parse().expect("addr"),
            ssl: true,
            crt: vec![crt],
            alpn,
            proto: None,
            accept_proxy: false,
            accept_proxy_v2: false,
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
        let cfg = TlsConfig::from_bind_config(&bind_with(Vec::new(), crt)).expect("build");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "both h2 and http/1.1 are offered by default"
        );
    }

    /// An operator asking for h2 gets h2 honoured.
    #[test]
    fn a_requested_h2_is_honoured() {
        let (_dir, crt) = a_cert();
        let bind = bind_with(vec!["h2".to_string(), "http/1.1".to_string()], crt);
        let cfg = TlsConfig::from_bind_config(&bind).expect("build");
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    /// Asking for nothing servable is an error, not an empty offer.
    #[test]
    fn requesting_only_unservable_protocols_is_refused() {
        let (_dir, crt) = a_cert();
        let bind = bind_with(vec!["spdy/3".to_string()], crt);
        let err = TlsConfig::from_bind_config(&bind).expect_err("must refuse");
        assert!(err.contains("ALPN"), "{err}");
    }
}
