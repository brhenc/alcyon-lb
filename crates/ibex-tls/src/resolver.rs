// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! Server certificate resolver backed by `EbMbTree` (`IbexCertResolver`).
//!
//! Implements `rustls::server::ResolvesServerCert` with $O(k)$ exact domain
//! and wildcard SNI lookup without dynamic hash collisions or regex matching.

use ebtree::EbMbTree;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

/// Fast, memory-safe certificate resolver using `ebtree::EbMbTree`.
#[derive(Clone, Debug)]
pub struct IbexCertResolver {
    certs: Vec<Arc<CertifiedKey>>,
    exact_tree: EbMbTree,
    wildcard_tree: EbMbTree,
    default_cert: Option<Arc<CertifiedKey>>,
}

impl Default for IbexCertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl IbexCertResolver {
    /// Creates an empty certificate resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            certs: Vec::new(),
            exact_tree: EbMbTree::new_unique(),
            wildcard_tree: EbMbTree::new_unique(),
            default_cert: None,
        }
    }

    /// Sets the default fallback certificate returned when SNI is absent or matches no entry.
    pub fn set_default_cert(&mut self, cert: Arc<CertifiedKey>) {
        self.default_cert = Some(cert);
    }

    /// Returns the default fallback certificate, if configured.
    #[must_use]
    pub fn default_cert(&self) -> Option<Arc<CertifiedKey>> {
        self.default_cert.clone()
    }

    /// Adds a certificate for an exact domain name (e.g. `"example.com"`, `"api.example.com"`).
    #[allow(clippy::cast_possible_truncation)]
    pub fn add_exact(&mut self, domain: &str, cert: Arc<CertifiedKey>) {
        let cert_idx = self.certs.len() as u32;
        self.certs.push(cert);
        let domain_lower = domain.to_ascii_lowercase();
        self.exact_tree.insert(domain_lower.as_bytes(), cert_idx);
    }

    /// Adds a certificate for a wildcard domain pattern (e.g. `"*.example.com"` or `"example.com"`).
    #[allow(clippy::cast_possible_truncation)]
    pub fn add_wildcard(&mut self, wildcard_domain: &str, cert: Arc<CertifiedKey>) {
        let cert_idx = self.certs.len() as u32;
        self.certs.push(cert);
        let domain_lower = wildcard_domain.to_ascii_lowercase();
        let suffix = domain_lower.strip_prefix("*.").unwrap_or(&domain_lower);
        self.wildcard_tree.insert(suffix.as_bytes(), cert_idx);
    }

    /// Automatically registers a domain or wildcard certificate.
    /// If `domain_pattern` starts with `*.`, it is registered as a wildcard,
    /// otherwise as an exact match.
    pub fn add_cert(&mut self, domain_pattern: &str, cert: Arc<CertifiedKey>) {
        if domain_pattern.starts_with("*.") {
            self.add_wildcard(domain_pattern, cert);
        } else {
            self.add_exact(domain_pattern, cert);
        }
    }

    /// Resolves a domain name directly to a [`CertifiedKey`].
    #[must_use]
    pub fn resolve_domain(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        let sni_lower = sni.to_ascii_lowercase();
        let sni_bytes = sni_lower.as_bytes();

        // 1. Exact match lookup in exact EbMbTree
        if let Some(idx) = self.exact_tree.lookup(sni_bytes) {
            return self.certs.get(idx as usize).cloned();
        }

        // 2. Wildcard match lookup: foo.example.com -> matches wildcard for example.com
        if let Some(dot_pos) = sni_lower.find('.') {
            let parent_suffix = &sni_lower[dot_pos + 1..];
            if let Some(idx) = self.wildcard_tree.lookup(parent_suffix.as_bytes()) {
                return self.certs.get(idx as usize).cloned();
            }
        }

        // 3. Fallback to default cert
        self.default_cert.clone()
    }
}

impl ResolvesServerCert for IbexCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = client_hello.server_name() {
            if let Some(cert) = self.resolve_domain(server_name) {
                return Some(cert);
            }
        }
        self.default_cert.clone()
    }
}
