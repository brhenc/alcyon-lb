// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC configuration and TLS stack integration.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

use crate::error::{QuicError, Result};

/// Default ALPN protocol for HTTP/3 over QUIC.
pub const ALPN_H3: &[u8] = b"h3";

/// QUIC transport and endpoint configuration builder.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// Maximum idle timeout before closing an inactive connection.
    pub max_idle_timeout: Option<Duration>,
    /// Maximum concurrent bidirectional streams per connection.
    pub max_concurrent_bidi_streams: u64,
    /// Maximum concurrent unidirectional streams per connection.
    pub max_concurrent_uni_streams: u64,
    /// Per-stream receive window (flow control) in bytes.
    pub stream_receive_window: u64,
    /// Connection-level receive window (flow control) in bytes.
    pub receive_window: u64,
    /// Connection-level send window (flow control) in bytes.
    pub send_window: u64,
    /// Packet reordering threshold for loss detection.
    pub packet_threshold: u32,
    /// Initial RTT estimate.
    pub initial_rtt: Duration,
    /// Initial Maximum Transmission Unit (MTU) in bytes.
    pub initial_mtu: u16,
    /// Minimum MTU in bytes.
    pub min_mtu: u16,
    /// Whether UDP Generic Segmentation Offload (GSO) is enabled.
    pub enable_gso: bool,
    /// Configured ALPN protocols (e.g. `vec![b"h3".to_vec()]`).
    pub alpn_protocols: Vec<Vec<u8>>,
    /// Whether stateless reset packets are enabled.
    pub enable_stateless_reset: bool,
    /// Whether retry packets are required for address validation under load.
    pub require_retry: bool,
    /// Anti-amplification factor limit for unvalidated peer paths (default: 3, per RFC 9000 §8.1).
    pub anti_amplification_factor: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout: Some(Duration::from_secs(30)),
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            stream_receive_window: 512 * 1024,
            receive_window: 1024 * 1024,
            send_window: 1024 * 1024,
            packet_threshold: 3,
            // RFC 9002 §6.2.2 kInitialRtt, which is also quinn-proto's default and what
            // HAProxy behaves as. This was 100 ms, which fires the first PTO at ~300 ms
            // instead of ~1000 ms: a spurious handshake retransmission for every client
            // further away than 100 ms, and three times the burn rate on the
            // anti-amplification budget of a path that is not yet validated.
            initial_rtt: Duration::from_millis(333),
            initial_mtu: 1200,
            min_mtu: 1200,
            enable_gso: true,
            alpn_protocols: vec![ALPN_H3.to_vec()],
            enable_stateless_reset: true,
            require_retry: false,
            anti_amplification_factor: 3,
        }
    }
}

impl QuicConfig {
    /// Creates a new default `QuicConfig`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum idle timeout.
    #[must_use]
    pub fn with_max_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.max_idle_timeout = timeout;
        self
    }

    /// Sets the maximum concurrent bidirectional streams.
    #[must_use]
    pub const fn with_max_bidi_streams(mut self, max: u64) -> Self {
        self.max_concurrent_bidi_streams = max;
        self
    }

    /// Sets the maximum concurrent unidirectional streams.
    #[must_use]
    pub const fn with_max_uni_streams(mut self, max: u64) -> Self {
        self.max_concurrent_uni_streams = max;
        self
    }

    /// Sets the ALPN protocols list.
    #[must_use]
    pub fn with_alpn(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Sets the anti-amplification factor limit before address validation (default: 3).
    #[must_use]
    pub const fn with_anti_amplification_factor(mut self, factor: u64) -> Self {
        self.anti_amplification_factor = factor;
        self
    }

    /// Builds the `quinn_proto::TransportConfig` corresponding to these settings.
    #[must_use]
    pub fn build_transport_config(&self) -> quinn_proto::TransportConfig {
        let mut tc = quinn_proto::TransportConfig::default();

        if let Some(idle) = self.max_idle_timeout {
            if let Ok(varint_idle) = idle.try_into() {
                tc.max_idle_timeout(Some(varint_idle));
            }
        } else {
            tc.max_idle_timeout(None);
        }

        if let Ok(val) = u32::try_from(self.max_concurrent_bidi_streams) {
            tc.max_concurrent_bidi_streams(val.into());
        }
        if let Ok(val) = u32::try_from(self.max_concurrent_uni_streams) {
            tc.max_concurrent_uni_streams(val.into());
        }
        if let Ok(val) = u32::try_from(self.stream_receive_window) {
            tc.stream_receive_window(val.into());
        }
        if let Ok(val) = u32::try_from(self.receive_window) {
            tc.receive_window(val.into());
        }

        tc.send_window(self.send_window);
        tc.packet_threshold(self.packet_threshold);
        tc.initial_rtt(self.initial_rtt);
        tc.initial_mtu(self.initial_mtu);
        tc.min_mtu(self.min_mtu);
        tc.enable_segmentation_offload(self.enable_gso);

        tc
    }

    /// Builds the `quinn_proto::EndpointConfig` corresponding to these settings.
    #[must_use]
    pub fn build_endpoint_config(&self) -> quinn_proto::EndpointConfig {
        let mut ec = quinn_proto::EndpointConfig::default();
        if let Ok(ec_res) = ec.max_udp_payload_size(self.initial_mtu) {
            let _ = ec_res;
        }
        ec
    }

    /// Builds a `quinn_proto::ServerConfig` from a `rustls::ServerConfig`.
    ///
    /// # Errors
    /// Returns `QuicError::Tls` if the TLS configuration cannot be converted into a QUIC server crypto config.
    pub fn build_server_config(
        &self,
        tls_config: &ServerConfig,
    ) -> Result<Arc<quinn_proto::ServerConfig>> {
        // Ensure ALPN protocols are configured with HTTP/3
        let mut tls = tls_config.clone();
        if tls.alpn_protocols.is_empty() {
            tls.alpn_protocols.clone_from(&self.alpn_protocols);
        }

        let quic_crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
            .map_err(|e| QuicError::Tls(format!("failed to convert rustls ServerConfig for QUIC: {e}")))?;

        let mut server_config = quinn_proto::ServerConfig::with_crypto(Arc::new(quic_crypto));
        server_config.transport_config(Arc::new(self.build_transport_config()));

        Ok(Arc::new(server_config))
    }

    /// Loads certificates and private key from a PEM file and creates a `rustls::ServerConfig`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened, or if no certificates/private key are found.
    pub fn load_server_config_from_pem<P: AsRef<Path>>(
        &self,
        pem_path: P,
    ) -> Result<Arc<quinn_proto::ServerConfig>> {
        let path = pem_path.as_ref();
        let (certs, key) = load_pem_cert_and_key(path)?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certified_key = ibex_tls::create_certified_key(certs.clone(), &key)
            .map_err(|e| QuicError::Tls(format!("invalid key in {}: {e}", path.display())))?;

        let mut resolver = ibex_tls::IbexCertResolver::new();
        resolver.set_default_cert(Arc::new(certified_key.clone()));

        if let Some(first_cert) = certs.first() {
            for domain in ibex_tls::extract_dns_sans(first_cert.as_ref()) {
                resolver.add_cert(&domain, Arc::new(certified_key.clone()));
            }
        }

        let mut rustls_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| QuicError::Tls(format!("TLS protocol version error: {e:?}")))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        rustls_config.alpn_protocols.clone_from(&self.alpn_protocols);

        self.build_server_config(&rustls_config)
    }
}

/// Helper function to load certificates and private key from a single PEM file.
///
/// # Errors
/// Returns `QuicError::Config` if the file cannot be opened or parsed, or if no certificates or key are found.
pub fn load_pem_cert_and_key(
    path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let file = File::open(path)
        .map_err(|e| QuicError::Config(format!("failed to open certificate file {}: {e}", path.display())))?;
    let mut reader = BufReader::new(file);

    let mut certs = Vec::new();
    let mut private_key = None;

    for item in rustls_pemfile::read_all(&mut reader) {
        let item = item.map_err(|e| {
            QuicError::Config(format!("failed to parse PEM entry in {}: {e}", path.display()))
        })?;
        match item {
            rustls_pemfile::Item::X509Certificate(cert) => certs.push(cert),
            rustls_pemfile::Item::Pkcs1Key(key) => private_key = Some(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => private_key = Some(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => private_key = Some(PrivateKeyDer::Sec1(key)),
            _ => {}
        }
    }

    let key = private_key.ok_or_else(|| {
        QuicError::Config(format!("no private key found in {}", path.display()))
    })?;

    if certs.is_empty() {
        return Err(QuicError::Config(format!(
            "no certificates found in {}",
            path.display()
        )));
    }

    Ok((certs, key))
}
