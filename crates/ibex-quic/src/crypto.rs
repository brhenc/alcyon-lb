// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// Ported from quinn-proto 0.11.19, `src/crypto/rustls.rs` and `src/crypto/ring_like.rs`:
//
//   Copyright (c) 2018 The quinn developers
//
//   Permission is hereby granted, free of charge, to any person obtaining a copy of this
//   software and associated documentation files (the "Software"), to deal in the Software
//   without restriction, including without limitation the rights to use, copy, modify, merge,
//   publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
//   to whom the Software is furnished to do so, subject to the following conditions:
//
//   The above copyright notice and this permission notice shall be included in all copies or
//   substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
//   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
//   PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
//   FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
//   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//   DEALINGS IN THE SOFTWARE.
//
// (quinn-proto is MIT or Apache-2.0; taken here under MIT.)

//! QUIC's TLS on rustls 0.24 (T461): `quinn_proto::crypto`'s traits over `rustls24::quic`, so
//! HTTP/3 runs on the provider TCP TLS runs on (`tune.ibex.crypto-provider`, T460).
//!
//! quinn-proto is built without `rustls-ring`: its own rustls (0.23) and *ring* are not linked.
//! What it took from *ring* directly, the stateless-reset HMAC ([`ResetKey`]), the address
//! validation token key ([`TokenKey`]) and the Retry integrity tag, comes from the provider
//! here. Each of these reads the [`ibex_tls::provider::active`] provider when it runs: the key
//! material is the endpoint's, the arithmetic the provider's, and HMAC-SHA256, HKDF and AES-GCM
//! give the same bytes on either, so a token issued before `set ssl crypto-provider` still
//! verifies after it.
//!
//! Server side only: Ibex's QUIC is a listener, and rustls 0.24.0-dev.2 has no QUIC client yet
//! (`FromConn<ClientSide>` is `todo!`).

use std::any::Any;
use std::io;
use std::sync::Arc;

use bytes::BytesMut;
use ibex_config::TlsCryptoProvider;
use ibex_tls::provider;
use ibex_tls::tcp::BindTls;
use quinn_proto::crypto::{
    self as qc, CryptoError, ExportKeyingMaterialError, KeyPair, Keys, UnsupportedVersion,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode};
use rustls24::crypto::cipher::{AeadKey, Iv};
use rustls24::crypto::tls13::{HkdfExpander, OkmBlock};
use rustls24::error::AlertDescription;
use rustls24::quic::{
    self as rq, KeyChange, QuicEvent, Secrets, ServerHandshake, Suite, Version,
};
use rustls24::server::ServerSide;
use rustls24::{Connection, KeyingMaterialExporter, ServerConfig, TlsInputBuffer};
use zeroize::Zeroize;

/// What a handshake settled that the listener asks for: quinn's `HandshakeData`, which
/// `Connection::crypto_session().handshake_data()` returns boxed.
#[derive(Debug, Clone, Default)]
pub struct HandshakeData {
    /// The negotiated application protocol (ALPN).
    pub protocol: Option<Vec<u8>>,
    /// The server name the client sent (SNI).
    pub server_name: Option<String>,
    /// The crypto provider the connection runs on.
    pub provider: Option<TlsCryptoProvider>,
}

/// The suite QUIC's Initial packets and Retry tags use (RFC 9001 5.2, 5.8), on provider `p`.
fn initial_suite(p: TlsCryptoProvider) -> Suite {
    Suite::try_from(provider::quic_initial_suite(p)).unwrap_or_else(|_| unreachable_suite())
}

/// rustls-ring and rustls-ringibex both define `quic` for every TLS 1.3 suite.
#[cold]
#[allow(clippy::panic)]
fn unreachable_suite() -> Suite {
    panic!("a TLS 1.3 suite of the provider without a QUIC algorithm")
}

/// A QUIC server configuration over a `bind ... quic ssl` line's TLS (`BindTls`).
///
/// A connection starts on the build of the bind for the provider active when its Initial
/// arrives ([`BindTls::into_current`]), and keeps it: a swap reaches new connections only.
pub struct QuicServerConfig {
    bind: Arc<BindTls>,
}

impl QuicServerConfig {
    /// The QUIC server configuration of `bind`.
    ///
    /// # Errors
    /// The bind's configuration offers no TLS 1.3 suite QUIC can use, or allows early data of
    /// a size other than 0 or `u32::MAX` (RFC 9001 4.6.1).
    pub fn new(bind: Arc<BindTls>) -> Result<Self, String> {
        let c = &bind.config;
        if c.max_early_data_size != 0 && c.max_early_data_size != u32::MAX {
            return Err("QUIC requires max_early_data_size of 0 or u32::MAX".into());
        }
        Ok(Self { bind })
    }

    fn current(&self) -> Arc<BindTls> {
        Arc::clone(&self.bind).into_current()
    }
}

impl qc::ServerConfig for QuicServerConfig {
    fn initial_keys(&self, version: u32, dst_cid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, *dst_cid, Side::Server, &initial_suite(self.current().provider)))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Called only for a version `initial_keys` took, and that is QUIC v1.
        let _ = version;
        let (nonce, key) = (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1);
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(u8::try_from(orig_dst_cid.len()).unwrap_or(u8::MAX));
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);
        // The Retry integrity tag is AES-128-GCM over the pseudo-packet with an empty payload:
        // QUIC's packet key of the Initial suite, its IV the fixed nonce, packet number 0.
        let suite = initial_suite(self.current().provider);
        let key = suite.quic.packet_key(AeadKey::from(key), Iv::from(nonce));
        let mut result = [0; 16];
        if let Ok(tag) = key.encrypt_in_place(0, &pseudo_packet, &mut [], None) {
            result.copy_from_slice(tag.as_ref());
        }
        result
    }

    fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters) -> Box<dyn qc::Session> {
        let version = interpret_version(version).unwrap_or(Version::V1);
        let bind = self.current();
        let mut tp = Vec::new();
        params.write(&mut tp);
        Box::new(TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            state: State::Hs(ServerHandshake::start(version)),
            suite: initial_suite(bind.provider),
            config: Arc::clone(&bind.config),
            provider: bind.provider,
            params: tp,
            events: std::collections::VecDeque::new(),
            input: Input::default(),
            server_name: None,
            exporter: None,
        })
    }
}

/// The TLS state of a session.
enum State {
    /// Waiting for more of the client's flight.
    Hs(rq::NeedsInput),
    /// The handshake is complete.
    Done(Connection<ServerSide, rq::Quic>),
    /// The handshake failed; the connection is being closed.
    Failed,
}

/// The CRYPTO stream bytes rustls has not consumed yet.
#[derive(Default)]
struct Input {
    buf: Vec<u8>,
    start: usize,
}

impl Input {
    fn push(&mut self, data: &[u8]) {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        self.buf.extend_from_slice(data);
    }
}

impl TlsInputBuffer for Input {
    fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..]
    }
    fn discard(&mut self, n: usize) {
        self.start = (self.start + n).min(self.buf.len());
    }
    fn received_close_notify(&mut self) {}
    fn has_seen_eof(&self) -> bool {
        false
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        // Handshake plaintext (the client's certificate, if any): wiped like the TCP buffers.
        self.buf.zeroize();
    }
}

/// A QUIC server's TLS session.
pub struct TlsSession {
    version: Version,
    got_handshake_data: bool,
    next_secrets: Option<Secrets>,
    state: State,
    suite: Suite,
    config: Arc<ServerConfig>,
    provider: TlsCryptoProvider,
    /// The transport parameters to send, TLS-encoded.
    params: Vec<u8>,
    /// Handshake messages and key changes rustls produced and quinn has not taken yet.
    events: std::collections::VecDeque<QuicEvent>,
    input: Input,
    server_name: Option<String>,
    exporter: Option<KeyingMaterialExporter>,
}

impl TlsSession {
    fn outputs(&self) -> Option<&rustls24::ConnectionOutputs> {
        match &self.state {
            State::Hs(n) => Some(n),
            State::Done(c) => Some(c),
            State::Failed => None,
        }
    }

    /// Runs the handshake on what `self.input` holds.
    fn advance(&mut self) -> Result<(), rustls24::Error> {
        let mut out = Vec::new();
        let result = self.advance_into(&mut out);
        self.events.extend(out);
        result
    }

    fn advance_into(&mut self, out: &mut Vec<QuicEvent>) -> Result<(), rustls24::Error> {
        match std::mem::replace(&mut self.state, State::Failed) {
            State::Hs(n) => {
                let mut next = n.process(&mut self.input, out)?;
                loop {
                    match next {
                        ServerHandshake::NeedsInput(n) => {
                            if self.server_name.is_none() {
                                self.server_name = n.side().server_name().map(|d| d.as_ref().to_owned());
                            }
                            self.state = State::Hs(n);
                            return Ok(());
                        }
                        ServerHandshake::Accepted(a) => {
                            self.server_name = a.client_hello().server_name().map(|d| d.as_ref().to_owned());
                            let after = a.choose_config(Arc::clone(&self.config), self.params.clone(), out)?;
                            // The rest of the input may hold more of the client's flight.
                            next = match after {
                                ServerHandshake::NeedsInput(n) => n.process(&mut self.input, out)?,
                                other => other,
                            };
                        }
                        ServerHandshake::Complete(mut c) => {
                            out.extend(c.events());
                            self.exporter = c.exporter().ok();
                            provider::count_handshake(self.provider);
                            self.state = State::Done(c);
                            return Ok(());
                        }
                        // A bind has no client verifier (`with_no_client_auth`), and the enum
                        // is `non_exhaustive`: either is a failure.
                        _ => return Err(rustls24::Error::General("unexpected QUIC server handshake state".into())),
                    }
                }
            }
            State::Done(mut c) => {
                let r = c.read_hs(&mut self.input);
                out.extend(c.events());
                self.state = State::Done(c);
                r
            }
            State::Failed => Err(rustls24::Error::HandshakeNotComplete),
        }
    }
}

impl qc::Session for TlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *dst_cid, side, &self.suite)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        Some(Box::new(HandshakeData {
            protocol: self.outputs().and_then(|o| o.alpn_protocol()).map(|p| p.as_ref().to_vec()),
            server_name: self.server_name.clone(),
            provider: Some(self.provider),
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        // A QUIC bind asks for no client certificate.
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn qc::HeaderKey>, Box<dyn qc::PacketKey>)> {
        let keys = match &self.state {
            State::Hs(n) => n.zero_rtt_keys(),
            State::Done(c) => c.zero_rtt_keys(),
            State::Failed => None,
        }?;
        Some((Box::new(HeaderKey(keys.header)), Box::new(PacketKey(keys.packet))))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Done(_))
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.input.push(buf);
        self.advance().map_err(|e| match AlertDescription::try_from(&e) {
            Ok(alert) => TransportError {
                code: TransportErrorCode::crypto(u8::from(alert)),
                frame: None,
                reason: e.to_string(),
            },
            Err(()) => TransportError {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame: None,
                reason: format!("TLS error: {e}"),
            },
        })?;
        if !self.got_handshake_data {
            // As quinn: the ClientHello is in once the server name or ALPN is known.
            let alpn = self.outputs().is_some_and(|o| o.alpn_protocol().is_some());
            if alpn || self.server_name.is_some() || !self.is_handshaking() {
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let buf = match &self.state {
            State::Hs(n) => n.quic_transport_parameters(),
            State::Done(c) => c.quic_transport_parameters(),
            State::Failed => None,
        };
        match buf {
            None => Ok(None),
            Some(buf) => TransportParameters::read(Side::Server, &mut io::Cursor::new(buf))
                .map(Some)
                .map_err(Into::into),
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        // The messages of the current level, up to the change of keys that ends it.
        while let Some(ev) = self.events.pop_front() {
            let change = match ev {
                QuicEvent::Message(m) => {
                    buf.extend_from_slice(&m);
                    continue;
                }
                QuicEvent::KeyChange(k) => k,
                _ => continue,
            };
            let keys = match change {
                KeyChange::Handshake { keys } => keys,
                KeyChange::OneRtt { keys, next } => {
                    self.next_secrets = Some(next);
                    keys
                }
            };
            return Some(keys_of(keys));
        }
        None
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn qc::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair { local: Box::new(PacketKey(keys.local)), remote: Box::new(PacketKey(keys.remote)) })
    }

    fn is_valid_retry(&self, _orig_dst_cid: &ConnectionId, _header: &[u8], _payload: &[u8]) -> bool {
        // A client's check; a server receives no Retry.
        false
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let exporter = self.exporter.as_ref().ok_or(ExportKeyingMaterialError)?;
        exporter.derive(label, Some(context), output).map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

/// RFC 9001 5.8.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];

/// A header protection key of rustls, as quinn takes it.
struct HeaderKey(Box<dyn rq::HeaderProtectionKey>);

impl qc::HeaderKey for HeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        // quinn sizes the packet so that the sample is there; a failure leaves it unchanged,
        // and the packet then fails its AEAD check.
        let _ = self.0.decrypt_in_place(&sample[..self.sample_size()], &mut first[0], &mut rest[pn_offset - 1..pn_end]);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        let _ = self.0.encrypt_in_place(&sample[..self.sample_size()], &mut first[0], &mut rest[pn_offset - 1..pn_end]);
    }

    fn sample_size(&self) -> usize {
        self.0.sample_len()
    }
}

/// A packet protection key of rustls, as quinn takes it.
struct PacketKey(Box<dyn rq::PacketKey>);

impl qc::PacketKey for PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.0.tag_len());
        // Fails only for a payload longer than the AEAD takes, which a datagram is not.
        if let Ok(tag) = self.0.encrypt_in_place(packet, &*header, payload, None) {
            tag_storage.copy_from_slice(tag.as_ref());
        }
    }

    fn decrypt(&self, packet: u64, header: &[u8], payload: &mut BytesMut) -> Result<(), CryptoError> {
        let plain = self.0.decrypt_in_place(packet, header, payload.as_mut(), None).map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

fn keys_of(keys: rq::Keys) -> Keys {
    Keys {
        header: KeyPair { local: Box::new(HeaderKey(keys.local.header)), remote: Box::new(HeaderKey(keys.remote.header)) },
        packet: KeyPair { local: Box::new(PacketKey(keys.local.packet)), remote: Box::new(PacketKey(keys.remote.packet)) },
    }
}

fn initial_keys(version: Version, dst_cid: ConnectionId, side: Side, suite: &Suite) -> Keys {
    let side = match side {
        Side::Client => rq::Side::Client,
        Side::Server => rq::Side::Server,
    };
    keys_of(suite.keys(&dst_cid, side, version))
}

fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    // quinn's list without the drafts (rustls 0.24 has no `V1Draft`): v1 and its quinn
    // aliases. quinn-proto's endpoint offers only these by default.
    match version {
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}

/// 64 random bytes from the provider's secure random source.
fn random_secret(p: TlsCryptoProvider) -> Result<[u8; 64], String> {
    let mut secret = [0u8; 64];
    provider::fill_random(p, &mut secret).map_err(|e| format!("QUIC key: no random bytes: {e:?}"))?;
    Ok(secret)
}

/// An endpoint's secret, keyed once per provider: the HMAC key schedule (or the HKDF PRK) is
/// built the first time a provider computes with it, not once per token.
struct Keyed {
    secret: [u8; 64],
    /// What `build` made of the secret on each provider, in `TlsCryptoProvider::ALL` order.
    built: [std::sync::OnceLock<Box<dyn HkdfExpander>>; 2],
    build: fn(&'static dyn rustls24::crypto::tls13::Hkdf, &[u8]) -> Box<dyn HkdfExpander>,
}

impl Keyed {
    fn new(build: fn(&'static dyn rustls24::crypto::tls13::Hkdf, &[u8]) -> Box<dyn HkdfExpander>) -> Result<Self, String> {
        Ok(Self { secret: random_secret(provider::active())?, built: Default::default(), build })
    }

    /// The secret keyed on the active provider (HMAC-SHA256 / HKDF-SHA256).
    fn on_active(&self) -> &dyn HkdfExpander {
        let p = provider::active();
        let i = TlsCryptoProvider::ALL.iter().position(|q| *q == p).unwrap_or(0).min(1);
        self.built[i].get_or_init(|| (self.build)(provider::quic_initial_suite(p).hkdf_provider, &self.secret)).as_ref()
    }
}

impl Drop for Keyed {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The stateless reset key of an endpoint (RFC 9000 10.3.2): a reset token is
/// HMAC-SHA256(key, connection ID || 0x01) (one HKDF-Expand block), a PRF under a random key,
/// computed by the active provider.
pub struct ResetKey(Keyed);

impl ResetKey {
    /// A fresh random key.
    ///
    /// # Errors
    /// The provider has no random bytes.
    pub fn new() -> Result<Self, String> {
        Keyed::new(|hkdf, secret| hkdf.expander_for_okm(&OkmBlock::new(&secret[..32]))).map(Self)
    }

    fn tag(&self, data: &[u8]) -> OkmBlock {
        self.0.on_active().expand_block(&[data])
    }
}

impl qc::HmacKey for ResetKey {
    fn sign(&self, data: &[u8], out: &mut [u8]) {
        let tag = self.tag(data);
        let n = out.len().min(tag.as_ref().len());
        out[..n].copy_from_slice(&tag.as_ref()[..n]);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let tag = self.tag(data);
        let tag = tag.as_ref();
        if tag.len() != signature.len() {
            return Err(CryptoError);
        }
        // Constant time: every byte is compared.
        let diff = tag.iter().zip(signature).fold(0u8, |d, (a, b)| d | (a ^ b));
        if diff == 0 { Ok(()) } else { Err(CryptoError) }
    }
}

/// The key of an endpoint's address validation tokens (Retry and `NEW_TOKEN`): an HKDF
/// master key, from which each token's AES-256-GCM key is derived, by the active provider.
pub struct TokenKey(Keyed);

impl TokenKey {
    /// A fresh random key.
    ///
    /// # Errors
    /// The provider has no random bytes.
    pub fn new() -> Result<Self, String> {
        Keyed::new(|hkdf, secret| hkdf.extract_from_secret(None, secret)).map(Self)
    }
}

impl qc::HandshakeTokenKey for TokenKey {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn qc::AeadKey> {
        let mut key = [0u8; 32];
        // 32 bytes is within HKDF-SHA256's 255 * 32.
        let _ = self.0.on_active().expand_slice(&[random_bytes], &mut key);
        let suite = provider::quic_token_suite(provider::active());
        let alg = Suite::try_from(suite).unwrap_or_else(|_| unreachable_suite()).quic;
        let packet = alg.packet_key(AeadKey::from(key), Iv::from([0u8; 12]));
        key.zeroize();
        Box::new(TokenAead(packet))
    }
}

/// One token's AEAD: AES-256-GCM with a zero nonce (each key seals one token).
struct TokenAead(Box<dyn rq::PacketKey>);

impl qc::AeadKey for TokenAead {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let tag = self.0.encrypt_in_place(0, additional_data, data, None).map_err(|_| CryptoError)?;
        data.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn open<'a>(&self, data: &'a mut [u8], additional_data: &[u8]) -> Result<&'a mut [u8], CryptoError> {
        let n = self.0.decrypt_in_place(0, additional_data, data, None).map_err(|_| CryptoError)?.len();
        Ok(&mut data[..n])
    }
}
