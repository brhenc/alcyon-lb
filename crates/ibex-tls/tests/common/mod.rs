// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

#![allow(dead_code)]

use ibex_tls::create_certified_key;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
use std::sync::Arc;

/// Generates a self-signed certificate and private key for the given subject alternative names.
pub fn generate_test_cert(sans: Vec<String>) -> (Arc<CertifiedKey>, CertificateDer<'static>) {
    let (key, der, _) = generate_test_cert_with_pem(sans);
    (key, der)
}

/// A PEM bundle holding the certificate and its key, as a `crt` file must.
///
/// `HAProxy` reads one file per `crt` entry and expects the key concatenated with the
/// chain. A helper that returns the certificate alone produces a file that cannot be
/// loaded, which is what `test_sni_name_mismatch_filename` was doing.
pub fn generate_test_cert_bundle_pem(sans: Vec<String>) -> String {
    let cert_key = generate_simple_self_signed(sans).expect("Failed to generate test certificate");
    format!("{}{}", cert_key.cert.pem(), cert_key.key_pair.serialize_pem())
}

/// Generates a self-signed certificate and private key with PEM encoding.
pub fn generate_test_cert_with_pem(
    sans: Vec<String>,
) -> (Arc<CertifiedKey>, CertificateDer<'static>, String) {
    let cert_key = generate_simple_self_signed(sans).expect("Failed to generate test certificate");
    let cert_der = CertificateDer::from(cert_key.cert.der().to_vec());
    let cert_pem = cert_key.cert.pem();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()));

    let certified_key = create_certified_key(vec![cert_der.clone()], &key_der)
        .expect("Failed to create CertifiedKey");

    (Arc::new(certified_key), cert_der, cert_pem)
}

/// Builds a `RootCertStore` containing the given test certificates.
pub fn build_root_store(certs: &[CertificateDer<'static>]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert.clone())
            .expect("Failed to add test root cert");
    }
    store
}
