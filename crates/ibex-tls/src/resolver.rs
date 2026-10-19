// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Server certificate resolver backed by `EbMbTree` (`IbexCertResolver`).
//!
//! Implements `rustls::server::ResolvesServerCert` with $O(k)$ exact domain
//! and wildcard SNI lookup without dynamic hash collisions or regex matching.

use ebtree::EbMbTree;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::Arc;

/// Fast, memory-safe certificate resolver using `ebtree::EbMbTree`.
///
/// `K` is what a name resolves to: rustls 0.23's [`CertifiedKey`] (QUIC), or rustls 0.24's
/// `Credentials` for the TCP binds ([`crate::tcp`]).
#[derive(Clone, Debug)]
pub struct IbexCertResolver<K = CertifiedKey> {
    certs: Vec<Arc<K>>,
    exact_tree: EbMbTree,
    wildcard_tree: EbMbTree,
    default_cert: Option<Arc<K>>,
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
        Self::empty()
    }
}

impl<K> IbexCertResolver<K> {
    /// Creates an empty certificate resolver for keys of type `K`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            certs: Vec::new(),
            exact_tree: EbMbTree::new_unique(),
            wildcard_tree: EbMbTree::new_unique(),
            default_cert: None,
        }
    }

    /// Sets the default fallback certificate returned when SNI is absent or matches no entry.
    pub fn set_default_cert(&mut self, cert: Arc<K>) {
        self.default_cert = Some(cert);
    }

    /// Returns the default fallback certificate, if configured.
    #[must_use]
    pub fn default_cert(&self) -> Option<Arc<K>> {
        self.default_cert.clone()
    }

    /// Adds a certificate for an exact domain name (e.g. `"example.com"`, `"api.example.com"`).
    pub fn add_exact(&mut self, domain: &str, cert: Arc<K>) {
        let cert_idx = u32::try_from(self.certs.len()).unwrap_or(u32::MAX);
        self.certs.push(cert);
        let domain_lower = domain.to_ascii_lowercase();
        self.exact_tree.insert(domain_lower.as_bytes(), cert_idx);
    }

    /// Adds a certificate for a wildcard domain pattern (e.g. `"*.example.com"` or `"example.com"`).
    pub fn add_wildcard(&mut self, wildcard_domain: &str, cert: Arc<K>) {
        let cert_idx = u32::try_from(self.certs.len()).unwrap_or(u32::MAX);
        self.certs.push(cert);
        let domain_lower = wildcard_domain.to_ascii_lowercase();
        let suffix = domain_lower.strip_prefix("*.").unwrap_or(&domain_lower);
        self.wildcard_tree.insert(suffix.as_bytes(), cert_idx);
    }

    /// Automatically registers a domain or wildcard certificate.
    /// If `domain_pattern` starts with `*.`, it is registered as a wildcard,
    /// otherwise as an exact match.
    pub fn add_cert(&mut self, domain_pattern: &str, cert: Arc<K>) {
        if domain_pattern.starts_with("*.") {
            self.add_wildcard(domain_pattern, cert);
        } else {
            self.add_exact(domain_pattern, cert);
        }
    }

    /// Resolves a domain name directly to its key (or the default).
    #[must_use]
    pub fn resolve_domain(&self, sni: &str) -> Option<Arc<K>> {
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
