// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Tests for `IbexCertResolver` backed by `ebtree::EbMbTree`.

mod common;

use common::generate_test_cert;
use ibex_tls::IbexCertResolver;
use std::sync::Arc;

#[test]
fn test_exact_sni_resolution() {
    let mut resolver = IbexCertResolver::new();

    let (cert_example, _) = generate_test_cert(vec!["example.com".to_string()]);
    let (cert_api, _) = generate_test_cert(vec!["api.example.com".to_string()]);
    let (cert_admin, _) = generate_test_cert(vec!["admin.example.com".to_string()]);

    resolver.add_exact("example.com", cert_example.clone());
    resolver.add_exact("api.example.com", cert_api.clone());
    resolver.add_exact("admin.example.com", cert_admin.clone());

    // Exact matches
    let res_example = resolver
        .resolve_domain("example.com")
        .expect("Found example.com");
    assert!(Arc::ptr_eq(&res_example, &cert_example));

    let res_api = resolver
        .resolve_domain("api.example.com")
        .expect("Found api.example.com");
    assert!(Arc::ptr_eq(&res_api, &cert_api));

    let res_admin = resolver
        .resolve_domain("admin.example.com")
        .expect("Found admin.example.com");
    assert!(Arc::ptr_eq(&res_admin, &cert_admin));

    // Case-insensitivity
    let res_case = resolver
        .resolve_domain("API.EXAMPLE.COM")
        .expect("Found uppercase API.EXAMPLE.COM");
    assert!(Arc::ptr_eq(&res_case, &cert_api));

    // Unknown domain with no default cert
    assert!(resolver.resolve_domain("unknown.org").is_none());
}

#[test]
fn test_wildcard_sni_resolution() {
    let mut resolver = IbexCertResolver::new();

    let (cert_wildcard, _) = generate_test_cert(vec!["*.example.com".to_string()]);
    let (cert_exact_api, _) = generate_test_cert(vec!["api.example.com".to_string()]);

    resolver.add_wildcard("*.example.com", cert_wildcard.clone());
    resolver.add_exact("api.example.com", cert_exact_api.clone());

    // Exact match has priority over wildcard
    let res_api = resolver
        .resolve_domain("api.example.com")
        .expect("Found api.example.com");
    assert!(Arc::ptr_eq(&res_api, &cert_exact_api));

    // Wildcard matches any other single-level subdomain
    let res_foo = resolver
        .resolve_domain("foo.example.com")
        .expect("Found foo.example.com");
    assert!(Arc::ptr_eq(&res_foo, &cert_wildcard));

    let res_bar = resolver
        .resolve_domain("bar.example.com")
        .expect("Found bar.example.com");
    assert!(Arc::ptr_eq(&res_bar, &cert_wildcard));

    // Wildcard case-insensitivity
    let res_upper = resolver
        .resolve_domain("SUB.EXAMPLE.COM")
        .expect("Found SUB.EXAMPLE.COM");
    assert!(Arc::ptr_eq(&res_upper, &cert_wildcard));

    // Multi-level subdomain (a.b.example.com) should not match *.example.com per RFC 6125
    assert!(resolver.resolve_domain("a.b.example.com").is_none());
}

#[test]
fn test_default_cert_fallback() {
    let mut resolver = IbexCertResolver::new();

    let (cert_default, _) = generate_test_cert(vec!["default.com".to_string()]);
    let (cert_exact, _) = generate_test_cert(vec!["special.com".to_string()]);

    resolver.set_default_cert(cert_default.clone());
    resolver.add_exact("special.com", cert_exact.clone());

    // Matched exact
    let res_special = resolver
        .resolve_domain("special.com")
        .expect("Found special.com");
    assert!(Arc::ptr_eq(&res_special, &cert_exact));

    // Fallback for unconfigured domain
    let res_other = resolver
        .resolve_domain("other.org")
        .expect("Fallback to default");
    assert!(Arc::ptr_eq(&res_other, &cert_default));
}
