// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! TLS configuration types and builders for `ibex-tls`.

use crate::resolver::IbexCertResolver;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::sync::Arc;

/// Installs the default `ring` crypto provider for the process.
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Supported TLS backend engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsEngineKind {
    /// Pure Rustls engine (default, memory-safe).
    Rustls,
    /// OpenSSL engine (FIPS & legacy compatibility).
    OpenSsl,
    /// `BoringSSL` engine.
    BoringSsl,
}

/// Unified TLS server configuration builder.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// Active TLS engine kind.
    pub engine: TlsEngineKind,
    /// Configured ALPN protocol list (e.g. `[b"h2", b"http/1.1"]`).
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Multi-certificate SNI resolver.
    pub cert_resolver: Option<Arc<IbexCertResolver>>,
    /// Whether session tickets are enabled for session resumption.
    pub session_tickets_enabled: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            engine: TlsEngineKind::Rustls,
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            cert_resolver: None,
            session_tickets_enabled: true,
        }
    }
}

impl TlsConfig {
    /// Creates a new TLS configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the SNI certificate resolver.
    #[must_use]
    pub fn with_cert_resolver(mut self, resolver: Arc<IbexCertResolver>) -> Self {
        self.cert_resolver = Some(resolver);
        self
    }

    /// Sets the ALPN protocols list.
    #[must_use]
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Builds a [`ServerConfig`] configured with the certificate resolver and ALPN protocols.
    ///
    /// # Errors
    /// Returns an error if no certificate resolver is configured or if configuration fails.
    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>, String> {
        let resolver = self
            .cert_resolver
            .clone()
            .ok_or_else(|| "Certificate resolver is required to build ServerConfig".to_string())?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("Protocol version error: {e:?}"))?
            .with_no_client_auth()
            .with_cert_resolver(resolver);

        config.alpn_protocols.clone_from(&self.alpn_protocols);
        if !self.session_tickets_enabled {
            config.send_tls13_tickets = 0;
        }

        Ok(Arc::new(config))
    }

    /// Builds a [`ClientConfig`] configured with trust roots and ALPN protocols.
    ///
    /// # Errors
    /// Returns an error if client configuration fails.
    pub fn build_client_config(
        &self,
        root_store: RootCertStore,
    ) -> Result<Arc<ClientConfig>, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("Protocol version error: {e:?}"))?
            .with_root_certificates(root_store)
            .with_no_client_auth();

        config.alpn_protocols.clone_from(&self.alpn_protocols);
        if !self.session_tickets_enabled {
            config.resumption = rustls::client::Resumption::disabled();
        }

        Ok(Arc::new(config))
    }
}

/// Helper to create a [`rustls::sign::CertifiedKey`] from DER certificates and private key.
///
/// # Errors
/// Returns an error if private key parsing or signing key creation fails.
pub fn create_certified_key(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: &PrivateKeyDer<'static>,
) -> Result<rustls::sign::CertifiedKey, String> {
    let key = rustls::crypto::ring::sign::any_supported_type(private_key)
        .map_err(|e| format!("Invalid private key: {e:?}"))?;
    Ok(rustls::sign::CertifiedKey::new(cert_chain, key))
}
