// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T249: a `crt` whose key does not match, or whose certificate is not DER, is refused
//! with HAProxy's alert text; a `crt` directory is loaded once and shared.

use alcyon_config::ast::BindConfig;
use alcyon_tls::tcp::from_bind_config;
use std::sync::Arc;
use tempfile::TempDir;

fn bind(crt: Vec<String>) -> BindConfig {
    BindConfig {
        line: 0,
        sock: None,
        addr: "127.0.0.1:443".parse().unwrap(),
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
    }
}

fn pair(name: &str) -> (String, String) {
    let c = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    (c.cert.pem(), c.key_pair.serialize_pem())
}

#[test]
fn key_not_matching_certificate_is_refused() {
    let dir = TempDir::new().unwrap();
    let (cert, _) = pair("a.example");
    let (_, other_key) = pair("b.example");
    let p = dir.path().join("mism.pem");
    std::fs::write(&p, format!("{cert}{other_key}")).unwrap();
    let err = from_bind_config(&bind(vec![p.to_string_lossy().into()])).unwrap_err();
    assert_eq!(
        err,
        format!(
            "inconsistencies between private key and certificate loaded '{}'.",
            p.display()
        )
    );
}

#[test]
fn certificate_that_is_not_der_is_refused() {
    let dir = TempDir::new().unwrap();
    let (_, key) = pair("a.example");
    let p = dir.path().join("bad.pem");
    std::fs::write(
        &p,
        format!("-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n{key}"),
    )
    .unwrap();
    let err = from_bind_config(&bind(vec![p.to_string_lossy().into()])).unwrap_err();
    assert_eq!(
        err,
        format!("unable to load certificate from file '{}': wrong tag.", p.display())
    );
}

#[test]
fn crt_directory_is_loaded_once_and_shared() {
    let dir = TempDir::new().unwrap();
    for i in 0..3 {
        let (c, k) = pair(&format!("h{i}.example"));
        std::fs::write(dir.path().join(format!("c{i}.pem")), format!("{c}{k}")).unwrap();
    }
    let b = bind(vec![dir.path().to_string_lossy().into()]);
    let a1 = from_bind_config(&b).unwrap();
    let a2 = from_bind_config(&b).unwrap();
    assert!(Arc::ptr_eq(&a1, &a2));
}
