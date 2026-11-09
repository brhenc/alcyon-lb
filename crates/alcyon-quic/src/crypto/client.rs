// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The client half of QUIC's TLS on rustls 0.24 (T534): `qc::ClientConfig` over
//! `ClientConnectionBuilder::build_quic`, for QUIC to servers (T533). Not reached by any
//! configuration yet: `server ... quic4@` stays refused until T533's slices.
//!
//! What differs from the server half ([`super::TlsSession`]): the client writes first (its
//! `ClientHello` is made in `start_session`), verifies the server (webpki against a root store,
//! or `verify none`) and knows it by its certificate (`peer_identity`), checks Retry integrity
//! tags (`is_valid_retry`), and reads the server's transport parameters. 0-RTT is refused:
//! [`QuicClientConfig::new`] turns `enable_early_data` off, so no `ClientHello` offers early
//! data and `early_crypto` has nothing to give. The packet and header keys, the Initial suite,
//! the CRYPTO input buffer, the error mapping and the stack scrubbing are the server's.

use std::any::Any;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use alcyon_config::TlsCryptoProvider;
use alcyon_tls::provider;
use quinn_proto::crypto::{self as qc, ExportKeyingMaterialError, KeyPair, Keys};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError};
use rustls24::client::ClientSide;
use rustls24::crypto::Identity;
use rustls24::pki_types::{CertificateDer, ServerName};
use rustls24::quic::{self as rq, QuicEvent, Secrets, Suite, Version};
use rustls24::{ClientConfig, Connection, KeyingMaterialExporter};

use super::{
    export, initial_keys, initial_suite, interpret_version, next_keys, retry_tag_v1, take_handshake_scrubbed, transport_error,
    HandshakeData, Input,
};

/// A QUIC client configuration: a rustls 0.24 [`ClientConfig`] on one provider.
#[derive(Debug)]
pub struct QuicClientConfig {
    config: Arc<ClientConfig>,
    provider: TlsCryptoProvider,
}

impl QuicClientConfig {
    /// The QUIC client configuration over `config`, built on provider `provider`. Early data
    /// is turned off in it: Alcyon's QUIC client sends no 0-RTT.
    ///
    /// # Errors
    /// `config` offers no TLS 1.3 suite QUIC can use.
    pub fn new(config: Arc<ClientConfig>, provider: TlsCryptoProvider) -> Result<Self, String> {
        if !config.provider().tls13_cipher_suites.iter().any(|s| s.quic.is_some()) {
            return Err("QUIC requires TLS 1.3 cipher suites with a QUIC algorithm".into());
        }
        let config = if config.enable_early_data {
            let mut c = (*config).clone();
            c.enable_early_data = false;
            Arc::new(c)
        } else {
            config
        };
        Ok(Self { config, provider })
    }

    /// A configuration that verifies the server against `roots` (webpki: the chain, then the
    /// name the session is started for, `ServerName`, sent as SNI) and offers `alpn`.
    ///
    /// # Errors
    /// As [`Self::new`], or the verifier does not build (an empty root store).
    pub fn with_roots(roots: rustls24::RootCertStore, alpn: &[&[u8]], provider: TlsCryptoProvider) -> Result<Self, String> {
        let p = provider::of(provider, false, true);
        let verifier = rustls24::client::WebPkiServerVerifier::builder(Arc::new(roots), &p)
            .build()
            .map_err(|e| format!("unable to set up certificate verification: {e}"))?;
        let mut config = ClientConfig::builder(p)
            .with_webpki_verifier(Arc::new(verifier))
            .with_no_client_auth()
            .map_err(|e| format!("Protocol version error: {e:?}"))?;
        config.alpn_protocols = alpn.iter().map(|a| a.to_vec().into()).collect();
        Self::new(Arc::new(config), provider)
    }

    /// A configuration that does not verify the server (`verify none`: the handshake
    /// signature is still checked) and offers `alpn`.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn without_verification(alpn: &[&[u8]], provider: TlsCryptoProvider) -> Result<Self, String> {
        let options = alcyon_tls::config::BackendTlsOptions {
            verify_required: false,
            alpn: alpn.iter().map(|a| a.to_vec()).collect(),
            min_ver: Some(alcyon_config::TlsVersion::Tls13),
            max_ver: Some(alcyon_config::TlsVersion::Tls13),
            ..Default::default()
        };
        Self::new(alcyon_tls::tcp::build_backend_client_config_with(&options, provider)?, provider)
    }

    /// The rustls configuration sessions start on.
    #[must_use]
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.config
    }

    /// The provider sessions run on.
    #[must_use]
    pub fn provider(&self) -> TlsCryptoProvider {
        self.provider
    }

    /// The session's start: the `ClientHello`, with its key share, is made here, so the stack
    /// below goes as after any handshake step. Not inlined: its frame must not hold the
    /// scrubbed region.
    #[inline(never)]
    fn start_scrubbed(&self, version: Version, name: ServerName<'static>, params: Vec<u8>) -> Result<Connection<ClientSide, rq::Quic>, rustls24::Error> {
        let r = self.config.connect(name).build_quic(version, params);
        alcyon_alloc::scrub_stack();
        r
    }
}

impl qc::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn qc::Session>, ConnectError> {
        let version = interpret_version(version).map_err(|_| ConnectError::UnsupportedVersion)?;
        let name = ServerName::try_from(server_name.to_owned()).map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;
        let mut tp = Vec::new();
        params.write(&mut tp);
        // `new` checked the suites, the one refusal of `build_quic` besides the name's.
        let mut conn = self.start_scrubbed(version, name, tp).map_err(|_| ConnectError::UnsupportedVersion)?;
        let events = conn.events().collect();
        Ok(Box::new(ClientSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            conn,
            suite: initial_suite(self.provider),
            provider: self.provider,
            events,
            input: Input::default(),
            server_name: server_name.to_owned(),
            exporter: None,
        }))
    }
}

/// A QUIC client's TLS session.
pub struct ClientSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    /// rustls keeps a failed handshake's error and returns it again: no `Failed` state here.
    conn: Connection<ClientSide, rq::Quic>,
    suite: Suite,
    provider: TlsCryptoProvider,
    /// Handshake messages and key changes rustls produced and quinn has not taken yet.
    events: VecDeque<QuicEvent>,
    input: Input,
    /// The name the session was started for (SNI, and what the certificate is checked for).
    server_name: String,
    exporter: Option<KeyingMaterialExporter>,
}

impl ClientSession {
    /// [`Self::advance`], then the stack below this frame goes, as on the server
    /// (`TlsSession::advance_scrubbed`, T480): on every step taken while the handshake was not
    /// complete, the completing one included.
    #[inline(never)]
    fn advance_scrubbed(&mut self, was_handshaking: bool) -> Result<(), rustls24::Error> {
        let r = self.advance();
        if was_handshaking {
            alcyon_alloc::scrub_stack();
        }
        r
    }

    fn advance(&mut self) -> Result<(), rustls24::Error> {
        let r = self.conn.read_hs(&mut self.input);
        self.events.extend(self.conn.events());
        if r.is_ok() && self.exporter.is_none() && !self.conn.is_handshaking() {
            self.exporter = self.conn.exporter().ok();
            provider::count_handshake(self.provider);
        }
        r
    }
}

impl qc::Session for ClientSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.conn.alpn_protocol().map(|p| p.as_ref().to_vec()),
            server_name: Some(self.server_name.clone()),
            provider: Some(self.provider),
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // The server's chain as it sent it, as quinn gives it: `Vec<CertificateDer>`, the leaf
        // first. A raw public key (never offered; `Identity` is `non_exhaustive`) has no chain.
        let Identity::X509(c) = self.conn.peer_identity()?.identity() else { return None };
        let mut chain: Vec<CertificateDer<'static>> = vec![c.end_entity.clone().into_owned()];
        chain.extend(c.intermediates.iter().map(|i| i.clone().into_owned()));
        Some(Box::new(chain))
    }

    fn early_crypto(&self) -> Option<(Box<dyn qc::HeaderKey>, Box<dyn qc::PacketKey>)> {
        // `QuicClientConfig::new` turned early data off: no 0-RTT keys, ever.
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.input.push(buf);
        let was_handshaking = self.is_handshaking();
        self.advance_scrubbed(was_handshaking).map_err(|e| transport_error(&e))?;
        if !self.got_handshake_data && (self.conn.alpn_protocol().is_some() || !self.is_handshaking()) {
            // As quinn: the server's EncryptedExtensions are in once ALPN is known.
            self.got_handshake_data = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.conn.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => TransportParameters::read(Side::Client, &mut io::Cursor::new(buf)).map(Some).map_err(Into::into),
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        take_handshake_scrubbed(&mut self.events, &mut self.next_secrets, buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn qc::PacketKey>>> {
        next_keys(&mut self.next_secrets)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(tag_start) = payload.len().checked_sub(16) else { return false };
        let (body, tag) = payload.split_at(tag_start);
        let expected = retry_tag_v1(&self.suite, orig_dst_cid, &[header, body]);
        // Constant time: every byte is compared.
        expected.iter().zip(tag).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
    }

    fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: &[u8]) -> Result<(), ExportKeyingMaterialError> {
        export(self.exporter.as_ref(), output, label, context)
    }
}
