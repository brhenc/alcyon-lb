// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC configuration and TLS stack integration.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use alcyon_tls::tcp::BindTls;
use rustls24::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{QuicError, Result};

/// Default ALPN protocol for HTTP/3 over QUIC.
pub const ALPN_H3: &[u8] = b"h3";

/// How long a Retry token is accepted: `HAProxy`'s `QUIC_RETRY_DURATION_SEC`.
pub const RETRY_TOKEN_LIFETIME: Duration = Duration::from_secs(10);

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
    /// `quic-force-retry` on the bind: every new connection is first answered by a Retry,
    /// whatever the half-open count.
    ///
    /// There is no stateless-reset switch: quinn-proto always answers a short-header packet
    /// for an unknown connection with a stateless reset, and so does `HAProxy` (it only
    /// limits the rate, `tune.quic.sec.stateless-reset-rate`, which Alcyon does not have).
    pub require_retry: bool,
    /// `tune.quic.fe.sec.retry-threshold` (default 100): once this many connections of the
    /// endpoint are half open (handshake started, peer address not yet validated), every new
    /// Initial without a token is answered by a Retry. The count is per endpoint, that is
    /// per worker, as `HAProxy`'s is per thread.
    pub retry_threshold: u64,
    /// `tune.alcyon.quic-ack-frequency on` (Q0): ask a peer that advertises `min_ack_delay` to
    /// acknowledge only every `threshold + 1` ack-eliciting packets, or after `max_delay`
    /// (default off: HAProxy sends no ACK_FREQUENCY, so the A/B stays fair).
    pub ack_frequency: Option<(u32, Duration)>,
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
            require_retry: false,
            retry_threshold: 100,
            ack_frequency: None,
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

    /// Sets the flow-control windows as `HAProxy` does (`quic_transport_params_init`): the
    /// connection may have `streams` request streams of `bufsize - 4` bytes in flight, and one
    /// stream `stream_data_ratio` percent of that (`tune.quic.fe.stream-data-ratio`).
    #[must_use]
    pub fn with_flow_windows(mut self, bufsize: usize, streams: u32, stream_data_ratio: u32) -> Self {
        let conn = u64::from(streams) * (bufsize.saturating_sub(4) as u64);
        self.receive_window = conn;
        self.stream_receive_window = conn * u64::from(stream_data_ratio) / 100;
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

    /// Sets `tune.quic.fe.sec.retry-threshold`.
    #[must_use]
    pub const fn with_retry_threshold(mut self, n: u64) -> Self {
        self.retry_threshold = n;
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

        // A value past the varint range becomes the largest varint; skipping the setter would
        // leave quinn's default, which for the two windows is unbounded.
        let varint = |v: u64| quinn_proto::VarInt::from_u64(v).unwrap_or(quinn_proto::VarInt::MAX);
        tc.max_concurrent_bidi_streams(varint(self.max_concurrent_bidi_streams));
        tc.max_concurrent_uni_streams(varint(self.max_concurrent_uni_streams));
        tc.stream_receive_window(varint(self.stream_receive_window));
        tc.receive_window(varint(self.receive_window));

        tc.send_window(self.send_window);
        tc.packet_threshold(self.packet_threshold);
        tc.initial_rtt(self.initial_rtt);
        tc.initial_mtu(self.initial_mtu);
        tc.min_mtu(self.min_mtu);
        tc.enable_segmentation_offload(self.enable_gso);

        // Q0 (`tune.alcyon.quic-ack-frequency`, off by default): ask a peer that advertises
        // `min_ack_delay` to acknowledge less often. Reaches the data path here, in
        // `TransportConfig::ack_frequency_config`, and then in quinn-proto's
        // `Connection::poll_transmit` (pending ACK_FREQUENCY); peers without the extension are
        // unaffected. It only asks: a hostile client can ignore it.
        if let Some((threshold, max_delay)) = self.ack_frequency {
            let mut ack_frequency = quinn_proto::AckFrequencyConfig::default();
            ack_frequency.max_ack_delay(Some(max_delay));
            ack_frequency.ack_eliciting_threshold(quinn_proto::VarInt::from_u32(threshold));
            tc.ack_frequency_config(Some(ack_frequency));
        }

        tc
    }

    /// Builds the `quinn_proto::EndpointConfig` corresponding to these settings, with a fresh
    /// stateless reset key ([`crate::crypto::ResetKey`]).
    ///
    /// # Errors
    /// The crypto provider has no random bytes for the key.
    pub fn build_endpoint_config(&self) -> Result<quinn_proto::EndpointConfig> {
        let key = crate::crypto::ResetKey::new().map_err(QuicError::Tls)?;
        let mut ec = quinn_proto::EndpointConfig::new(Arc::new(key));
        if let Ok(ec_res) = ec.max_udp_payload_size(self.initial_mtu) {
            let _ = ec_res;
        }
        Ok(ec)
    }

    /// Builds a `quinn_proto::ServerConfig` over a bind's TLS (rustls 0.24, T461), with a fresh
    /// address validation token key ([`crate::crypto::TokenKey`]).
    ///
    /// A bind with no ALPN gets these settings' (`h3`); it is then not rebuilt by a provider
    /// swap, which only the binds of a configuration file are.
    ///
    /// # Errors
    /// Returns `QuicError::Tls` if the TLS configuration cannot serve QUIC.
    pub fn build_server_config(&self, bind: &Arc<BindTls>) -> Result<Arc<quinn_proto::ServerConfig>> {
        let bind = if bind.config.alpn_protocols.is_empty() {
            let mut config = (*bind.config).clone();
            config.alpn_protocols = self.alpn_protocols.iter().map(|p| p.clone().into()).collect();
            Arc::new(BindTls::from_parts(Arc::new(config), Arc::clone(&bind.no_alpn), Arc::clone(&bind.resolver), bind.provider))
        } else {
            Arc::clone(bind)
        };
        let quic_crypto = crate::crypto::QuicServerConfig::new(bind)
            .map_err(|e| QuicError::Tls(format!("failed to build the QUIC TLS configuration: {e}")))?;
        let token_key = crate::crypto::TokenKey::new().map_err(QuicError::Tls)?;
        let mut server_config = quinn_proto::ServerConfig::new(Arc::new(quic_crypto), Arc::new(token_key));
        server_config.transport_config(Arc::new(self.build_transport_config()));
        // `QUIC_RETRY_DURATION_SEC`: a Retry token is good for 10 s (quinn-proto's default 15).
        server_config.retry_token_lifetime(RETRY_TOKEN_LIFETIME);

        Ok(Arc::new(server_config))
    }

    /// Loads certificates and private key from a PEM file and builds the QUIC server
    /// configuration serving them, on the active crypto provider.
    ///
    /// # Errors
    /// Returns an error if the file cannot be opened, or if no certificates/private key are found.
    pub fn load_server_config_from_pem<P: AsRef<Path>>(
        &self,
        pem_path: P,
    ) -> Result<Arc<quinn_proto::ServerConfig>> {
        let path = pem_path.as_ref();
        let (certs, key) = load_pem_cert_and_key(path)?;
        let bind = BindTls::single_tls13(certs, key, self.alpn_protocols.clone())
            .map_err(|e| QuicError::Tls(format!("invalid key in {}: {e}", path.display())))?;
        self.build_server_config(&bind)
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
