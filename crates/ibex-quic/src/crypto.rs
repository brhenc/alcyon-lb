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
//! The server half is here; the client half, for QUIC to servers (T533), is [`client`] (T534),
//! on the same key types.

use std::any::Any;
use std::collections::VecDeque;
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

pub mod client;
pub use client::QuicClientConfig;

/// What a handshake settled that the listener asks for: quinn's `HandshakeData`, which
/// `Connection::crypto_session().handshake_data()` returns boxed.
#[derive(Debug, Clone, Default)]
pub struct HandshakeData {
    /// The negotiated application protocol (ALPN).
    pub protocol: Option<Vec<u8>>,
    /// The server name the client sent (SNI); on a client session, the name it connected to.
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
        retry_tag_v1(&initial_suite(self.current().provider), orig_dst_cid, &[packet])
    }

    fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters) -> Box<dyn qc::Session> {
        Box::new(self.session(version, params))
    }
}

impl QuicServerConfig {
    fn session(&self, version: u32, params: &TransportParameters) -> TlsSession {
        let version = interpret_version(version).unwrap_or(Version::V1);
        let bind = self.current();
        let mut tp = Vec::new();
        params.write(&mut tp);
        TlsSession {
            version,
            got_handshake_data: false,
            next_secrets: None,
            state: State::Hs(ServerHandshake::start(version)),
            suite: initial_suite(bind.provider),
            config: Arc::clone(&bind.config),
            provider: bind.provider,
            params: tp,
            events: VecDeque::new(),
            input: Input::default(),
            server_name: None,
            exporter: None,
        }
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

/// A QUIC server's TLS session (the client's is [`client::ClientSession`]).
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
    events: VecDeque<QuicEvent>,
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
    /// [`Self::advance`], then what rustls and ring left on the stack below this frame (moved-from
    /// keys, `Copy` HMAC outputs, the ECDH point) goes, as `TlsCtx::handshake` does on TCP: on every
    /// exit of a step taken while the handshake was not complete, which includes the step that
    /// completes it, and not after it (T480, `tune.ibex.ssl-zero-buffers`). Not inlined: its frame
    /// must not hold the scrubbed region.
    #[inline(never)]
    fn advance_scrubbed(&mut self, was_handshaking: bool) -> Result<(), rustls24::Error> {
        let r = self.advance();
        if was_handshaking {
            ibex_alloc::scrub_stack();
        }
        r
    }

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
                            next = if let ServerHandshake::NeedsInput(n) = after { n.process(&mut self.input, out)? } else { after };
                        }
                        // A bind has no client verifier (`with_no_client_auth`), and the enum
                        // is `non_exhaustive`: any other state is a failure.
                        other => {
                            let ServerHandshake::Complete(mut c) = other else { return Err(rustls24::Error::General("unexpected QUIC server handshake state".into())) };
                            out.extend(c.events());
                            self.exporter = c.exporter().ok();
                            provider::count_handshake(self.provider);
                            self.state = State::Done(c);
                            return Ok(());
                        }
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
        };
        keys.map(|k| (Box::new(HeaderKey(k.header)) as Box<dyn qc::HeaderKey>, Box::new(PacketKey(k.packet)) as Box<dyn qc::PacketKey>))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        !matches!(self.state, State::Done(_))
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.input.push(buf);
        let was_handshaking = self.is_handshaking();
        self.advance_scrubbed(was_handshaking).map_err(|e| transport_error(&e))?;
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
        take_handshake_scrubbed(&mut self.events, &mut self.next_secrets, buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn qc::PacketKey>>> {
        next_keys(&mut self.next_secrets)
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
        export(self.exporter.as_ref(), output, label, context)
    }
}

/// The Retry integrity tag of QUIC v1 (RFC 9001 5.8) over the Retry packet `parts` (without
/// its tag) sent for a client's original destination connection ID `orig_dst_cid`:
/// AES-128-GCM over the pseudo-packet with an empty payload, QUIC's packet key of the Initial
/// `suite`, its IV the fixed nonce, packet number 0.
fn retry_tag_v1(suite: &Suite, orig_dst_cid: &ConnectionId, parts: &[&[u8]]) -> [u8; 16] {
    let (nonce, key) = (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1);
    let mut pseudo_packet = Vec::with_capacity(parts.iter().map(|p| p.len()).sum::<usize>() + orig_dst_cid.len() + 1);
    pseudo_packet.push(u8::try_from(orig_dst_cid.len()).unwrap_or(u8::MAX));
    pseudo_packet.extend_from_slice(orig_dst_cid);
    for p in parts {
        pseudo_packet.extend_from_slice(p);
    }
    let key = suite.quic.packet_key(AeadKey::from(key), Iv::from(nonce));
    let mut result = [0; 16];
    if let Ok(tag) = key.encrypt_in_place(0, &pseudo_packet, &mut [], None) {
        result.copy_from_slice(tag.as_ref());
    }
    result
}

/// What quinn reports for a handshake rustls refused: `CRYPTO_ERROR` (0x100 + the alert,
/// RFC 9001 4.8) when the error has an alert, `PROTOCOL_VIOLATION` otherwise.
fn transport_error(e: &rustls24::Error) -> TransportError {
    match AlertDescription::try_from(e) {
        Ok(alert) => TransportError { code: TransportErrorCode::crypto(u8::from(alert)), frame: None, reason: e.to_string() },
        Err(()) => TransportError { code: TransportErrorCode::PROTOCOL_VIOLATION, frame: None, reason: format!("TLS error: {e}") },
    }
}

/// [`take_handshake`], then, when it took an event, the stack below goes (T534). A
/// `QuicEvent` is a large enum: rustls builds one on its stack, where the secrets it derived
/// just before still are, and pushes the whole of it, padding included, so the bytes of the
/// variant that are not its fields can be a traffic secret's. Popping the event copies all of
/// it onto this stack, after the handshake step's scrub: the instrumented build found
/// `SERVER_HANDSHAKE_TRAFFIC_SECRET` there below the client (`stack_scrub.rs`). Not inlined: its
/// frame must not hold the scrubbed region.
#[inline(never)]
fn take_handshake_scrubbed(events: &mut VecDeque<QuicEvent>, next_secrets: &mut Option<Secrets>, buf: &mut Vec<u8>) -> Option<Keys> {
    let had = !events.is_empty();
    let keys = take_handshake(events, next_secrets, buf);
    if had {
        ibex_alloc::scrub_stack();
    }
    keys
}

/// `qc::Session::write_handshake` on either side: the messages of the current level, up to
/// the change of keys that ends it; the secrets of the next 1-RTT keys go to `next_secrets`.
#[inline(never)]
fn take_handshake(events: &mut VecDeque<QuicEvent>, next_secrets: &mut Option<Secrets>, buf: &mut Vec<u8>) -> Option<Keys> {
    while let Some(ev) = events.pop_front() {
        let change = match ev {
            QuicEvent::Message(m) => {
                buf.extend_from_slice(&m);
                continue;
            }
            QuicEvent::KeyChange(k) => k, _ => continue, // `QuicEvent` is non_exhaustive
        };
        let keys = match change {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                *next_secrets = Some(next);
                keys
            }
        };
        return Some(keys_of(keys));
    }
    None
}

/// `qc::Session::next_1rtt_keys` on either side (RFC 9001 6: the key update).
fn next_keys(next_secrets: &mut Option<Secrets>) -> Option<KeyPair<Box<dyn qc::PacketKey>>> {
    let keys = next_secrets.as_mut()?.next_packet_keys();
    Some(KeyPair { local: Box::new(PacketKey(keys.local)), remote: Box::new(PacketKey(keys.remote)) })
}

/// `qc::Session::export_keying_material` on either side.
fn export(exporter: Option<&KeyingMaterialExporter>, output: &mut [u8], label: &[u8], context: &[u8]) -> Result<(), ExportKeyingMaterialError> {
    let exporter = exporter.ok_or(ExportKeyingMaterialError)?;
    exporter.derive(label, Some(context), output).map_err(|_| ExportKeyingMaterialError)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use qc::ServerConfig as _;

    fn bind() -> Arc<BindTls> {
        bind_with(Vec::new())
    }

    fn bind_with(alpn: Vec<Vec<u8>>) -> Arc<BindTls> {
        bind_and_cert(alpn).0
    }

    fn bind_and_cert(alpn: Vec<Vec<u8>>) -> (Arc<BindTls>, rustls24::pki_types::CertificateDer<'static>) {
        use rustls24::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pair.serialize_der()));
        let der = CertificateDer::from(c.cert.der().to_vec());
        let bind = BindTls::single_tls13(vec![der.clone()], key, alpn).expect("bind");
        (bind, der)
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
    }

    /// RFC 9001 A.4: the Retry packet sent for a client Initial whose destination connection
    /// ID was 0x8394c8f03e515708 ends in this integrity tag.
    #[test]
    fn the_retry_tag_is_the_one_of_rfc_9001_a4() {
        let cfg = QuicServerConfig::new(bind()).expect("config");
        let odcid = ConnectionId::new(&hex("8394c8f03e515708"));
        let packet = hex("ff000000010008f067a5502a4262b5746f6b656e");
        assert_eq!(cfg.retry_tag(1, &odcid, &packet).to_vec(), hex("04a265ba2eff4d829058fb3f0f2496ba"));
        let mut other = packet.clone();
        other[0] ^= 1;
        assert_ne!(cfg.retry_tag(1, &odcid, &other).to_vec(), hex("04a265ba2eff4d829058fb3f0f2496ba"));
    }

    #[test]
    fn early_data_of_a_size_other_than_0_or_max_is_refused() {
        let mut b = bind();
        let inner = Arc::get_mut(&mut b).expect("unshared");
        Arc::make_mut(&mut inner.config).max_early_data_size = 1000;
        let e = QuicServerConfig::new(b).err().expect("refused");
        assert_eq!(e, "QUIC requires max_early_data_size of 0 or u32::MAX");
    }

    #[test]
    fn initial_keys_are_refused_for_a_version_that_is_not_v1() {
        let cfg = QuicServerConfig::new(bind()).expect("config");
        let cid = ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(cfg.initial_keys(0x1a2a_3a4a, &cid).is_err());
        assert!(cfg.initial_keys(1, &cid).is_ok());
    }

    fn pair() -> (Keys, Keys) {
        let cid = ConnectionId::new(&hex("8394c8f03e515708"));
        let suite = initial_suite(provider::active());
        (initial_keys(Version::V1, cid, Side::Client, &suite), initial_keys(Version::V1, cid, Side::Server, &suite))
    }

    #[test]
    fn a_packet_the_client_seals_opens_on_the_server_and_nowhere_else() {
        let (c, s) = pair();
        let header = [0xc3u8, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 7];
        let payload: Vec<u8> = (0..40u8).collect();
        let mut buf = header.to_vec();
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(&[0; 16]);
        assert_eq!(c.packet.local.tag_len(), 16);
        c.packet.local.encrypt(7, &mut buf, header.len());
        assert_ne!(&buf[header.len()..header.len() + 40], payload.as_slice());

        // Header protection: the first byte and the packet number change, and come back.
        let sealed = buf.clone();
        c.header.local.encrypt(16, &mut buf);
        assert_ne!(&buf[..header.len()], &header[..], "the header is protected");
        assert_eq!(&buf[20..], &sealed[20..], "the payload is left alone");
        assert_eq!(c.header.local.sample_size(), 16);
        s.header.remote.decrypt(16, &mut buf);
        assert_eq!(buf, sealed);

        let mut ok = BytesMut::from(&buf[header.len()..]);
        s.packet.remote.decrypt(7, &header, &mut ok).expect("opens");
        assert_eq!(&ok[..], payload.as_slice());
        // Another packet number, a changed header, a changed tag, the wrong side's key: no.
        assert!(s.packet.remote.decrypt(8, &header, &mut BytesMut::from(&buf[header.len()..])).is_err());
        let mut other = header;
        other[0] ^= 1;
        assert!(s.packet.remote.decrypt(7, &other, &mut BytesMut::from(&buf[header.len()..])).is_err());
        let mut torn = BytesMut::from(&buf[header.len()..]);
        let last = torn.len() - 1;
        torn[last] ^= 1;
        assert!(s.packet.remote.decrypt(7, &header, &mut torn).is_err());
        assert!(c.packet.remote.decrypt(7, &header, &mut BytesMut::from(&buf[header.len()..])).is_err());

        assert!(c.packet.local.confidentiality_limit() > 0);
        assert!(c.packet.local.integrity_limit() > 0);
    }

    #[test]
    fn the_crypto_input_hands_out_what_it_was_given_until_it_is_taken() {
        let mut i = Input::default();
        i.push(b"abcdef");
        assert_eq!(i.slice_mut(), b"abcdef");
        i.discard(2);
        assert_eq!(i.slice_mut(), b"cdef");
        i.push(b"gh");
        assert_eq!(i.slice_mut(), b"cdefgh");
        i.discard(100);
        assert!(i.slice_mut().is_empty());
        i.push(b"z");
        assert_eq!(i.slice_mut(), b"z", "a fully consumed buffer starts over");
        i.received_close_notify();
        assert!(!i.has_seen_eof());
    }

    #[test]
    fn reset_tokens_verify_only_for_their_connection_id() {
        let k = ResetKey::new().expect("key");
        assert_eq!(qc::HmacKey::signature_len(&k), 32);
        let mut sig = [0u8; 32];
        qc::HmacKey::sign(&k, b"cid-1", &mut sig);
        assert!(qc::HmacKey::verify(&k, b"cid-1", &sig).is_ok());
        assert!(qc::HmacKey::verify(&k, b"cid-2", &sig).is_err());
        assert!(qc::HmacKey::verify(&k, b"cid-1", &sig[..16]).is_err(), "a short signature is not a prefix match");
        let mut flipped = sig;
        flipped[31] ^= 1;
        assert!(qc::HmacKey::verify(&k, b"cid-1", &flipped).is_err());
        let mut short = [0u8; 16];
        qc::HmacKey::sign(&k, b"cid-1", &mut short);
        assert_eq!(short, sig[..16]);
        // Another key signs differently.
        let mut other = [0u8; 32];
        qc::HmacKey::sign(&ResetKey::new().expect("key"), b"cid-1", &mut other);
        assert_ne!(other, sig);
    }

    #[test]
    fn a_token_opens_with_its_key_bytes_and_its_additional_data_only() {
        use qc::HandshakeTokenKey as _;
        let k = TokenKey::new().expect("key");
        let aead = k.aead_from_hkdf(b"random-1");
        let mut data = b"address validation".to_vec();
        aead.seal(&mut data, b"ad").expect("seal");
        assert_eq!(data.len(), 18 + 16);
        let sealed = data.clone();
        assert_eq!(aead.open(&mut data, b"ad").expect("open"), b"address validation");
        let mut wrong_ad = sealed.clone();
        assert!(aead.open(&mut wrong_ad, b"other").is_err());
        let mut wrong_key = sealed.clone();
        assert!(k.aead_from_hkdf(b"random-2").open(&mut wrong_key, b"ad").is_err());
        let mut torn = sealed;
        torn[0] ^= 1;
        assert!(aead.open(&mut torn, b"ad").is_err());
        // The same bytes derive the same key.
        let mut again = b"x".to_vec();
        k.aead_from_hkdf(b"random-1").seal(&mut again, b"").expect("seal");
        assert_eq!(k.aead_from_hkdf(b"random-1").open(&mut again, b"").expect("open"), b"x");
    }

    #[test]
    fn a_session_before_its_handshake_has_nothing_to_give_and_a_bad_flight_fails_it() {
        use qc::Session as _;
        let cfg = Arc::new(QuicServerConfig::new(bind()).expect("config"));
        let mut s = cfg.start_session(1, &params());
        assert!(s.is_handshaking());
        assert!(s.handshake_data().is_none());
        assert!(s.peer_identity().is_none());
        assert!(s.early_crypto().is_none());
        assert_eq!(s.early_data_accepted(), None);
        assert!(s.next_1rtt_keys().is_none());
        assert!(!s.is_valid_retry(&ConnectionId::new(&[1; 8]), b"", b""));
        assert!(s.export_keying_material(&mut [0u8; 8], b"label", b"ctx").is_err());
        // A ClientHello with a body of two bytes: the session fails, and stays failed.
        let first = s.read_handshake(&[1, 0, 0, 2, 0xff, 0xff]).expect_err("bad hello");
        assert!(!first.reason.is_empty());
        assert!(s.read_handshake(&[]).is_err());
        assert!(s.handshake_data().is_none());
        assert!(s.early_crypto().is_none());
        assert!(s.transport_parameters().expect("none, not an error").is_none());
        assert!(s.write_handshake(&mut Vec::new()).is_none());
    }

    fn params() -> TransportParameters {
        TransportParameters::read(Side::Client, &mut io::Cursor::new(Vec::<u8>::new())).expect("empty parameters")
    }

    /// A server session that has completed its handshake against Ibex's client session
    /// (T534; it was quinn's on rustls 0.23), the CRYPTO bytes carried across with their levels
    /// ignored.
    fn established() -> TlsSession {
        established_pair().1
    }

    /// Both ends of [`established`].
    fn established_pair() -> (Box<dyn qc::Session>, TlsSession) {
        use qc::ClientConfig as _;
        use qc::Session as _;
        let (server_bind, cert) = bind_and_cert(vec![b"h3".to_vec()]);
        let mut roots = rustls24::RootCertStore::empty();
        roots.add(cert).expect("trust the test certificate");
        let cc = Arc::new(QuicClientConfig::with_roots(roots, &[b"h3"], provider::active()).expect("client config"));
        let mut client = cc.start_session(1, "localhost", &params()).expect("client session");
        let server_cfg = QuicServerConfig::new(server_bind).expect("config");
        let mut server = server_cfg.session(1, &params());
        let mut done = false;
        for _ in 0..8 {
            // Each level's bytes go over on their own, as quinn sends them.
            loop {
                let mut flight = Vec::new();
                let more = client.write_handshake(&mut flight).is_some();
                if !flight.is_empty() {
                    server.read_handshake(&flight).expect("server reads the client flight");
                }
                if !more {
                    break;
                }
            }
            loop {
                let mut flight = Vec::new();
                let more = server.write_handshake(&mut flight).is_some();
                if !flight.is_empty() {
                    client.read_handshake(&flight).expect("client reads the server flight");
                }
                if !more {
                    break;
                }
            }
            if !server.is_handshaking() && !client.is_handshaking() {
                done = true;
                break;
            }
        }
        assert!(done, "the handshake completes");
        (client, server)
    }

    /// RFC 9001 6: each side's next 1-RTT keys open what the other's next keys seal, and the
    /// keys of the phase before do not.
    #[test]
    fn the_next_1rtt_keys_of_each_side_cross() {
        use qc::Session as _;
        let (mut c, mut s) = established_pair();
        let seal = |k: &dyn qc::PacketKey, pn: u64| {
            let header = [0x40u8, 1, 2, 3];
            let mut buf = header.to_vec();
            buf.extend_from_slice(b"one-rtt payload");
            buf.extend_from_slice(&[0; 16]);
            k.encrypt(pn, &mut buf, header.len());
            (header, BytesMut::from(&buf[header.len()..]))
        };
        let c1 = c.next_1rtt_keys().expect("client: phase 1");
        let s1 = s.next_1rtt_keys().expect("server: phase 1");
        let (h, mut sealed) = seal(c1.local.as_ref(), 5);
        s1.remote.decrypt(5, &h, &mut sealed).expect("the server opens the client's phase-1 packet");
        assert_eq!(&sealed[..], b"one-rtt payload");
        let (h, mut sealed) = seal(s1.local.as_ref(), 6);
        c1.remote.decrypt(6, &h, &mut sealed).expect("the client opens the server's phase-1 packet");
        let c2 = c.next_1rtt_keys().expect("client: phase 2");
        let s2 = s.next_1rtt_keys().expect("server: phase 2");
        let (h, sealed) = seal(c2.local.as_ref(), 7);
        assert!(s1.remote.decrypt(7, &h, &mut sealed.clone()).is_err(), "phase 1 does not open phase 2");
        s2.remote.decrypt(7, &h, &mut sealed.clone()).expect("phase 2 opens phase 2");
    }

    /// RFC 9001 A.4 again, from the client's side: the Retry checks out, and not once changed.
    #[test]
    fn the_client_takes_the_retry_of_rfc_9001_a4_and_no_other() {
        use qc::ClientConfig as _;
        let cc = Arc::new(QuicClientConfig::without_verification(&[b"h3"], provider::active()).expect("client config"));
        let s = cc.start_session(1, "localhost", &params()).expect("client session");
        let odcid = ConnectionId::new(&hex("8394c8f03e515708"));
        let header = hex("ff000000010008f067a5502a4262b574");
        let mut payload = hex("6f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        assert!(s.is_valid_retry(&odcid, &header, &payload));
        assert!(!s.is_valid_retry(&ConnectionId::new(&hex("8394c8f03e515709")), &header, &payload), "another ODCID");
        let last = payload.len() - 1;
        payload[last] ^= 1;
        assert!(!s.is_valid_retry(&odcid, &header, &payload), "a changed tag");
        assert!(!s.is_valid_retry(&odcid, &header, &payload[..15]), "shorter than a tag");
    }

    #[test]
    fn a_client_configuration_with_no_root_is_refused() {
        let e = QuicClientConfig::with_roots(rustls24::RootCertStore::empty(), &[b"h3"], provider::active()).expect_err("refused");
        assert!(e.starts_with("unable to set up certificate verification: "), "{e}");
    }

    #[test]
    fn a_client_session_before_its_handshake_has_nothing_to_give() {
        use qc::ClientConfig as _;
        let cc = Arc::new(QuicClientConfig::without_verification(&[b"h3"], provider::active()).expect("client config"));
        assert!(Arc::clone(&cc).start_session(0x1a2a_3a4a, "localhost", &params()).is_err(), "not QUIC v1");
        let mut s = cc.start_session(1, "localhost", &params()).expect("client session");
        assert!(s.is_handshaking());
        assert!(s.handshake_data().is_none());
        assert!(s.peer_identity().is_none());
        assert!(s.early_crypto().is_none());
        assert!(s.next_1rtt_keys().is_none());
        assert!(s.transport_parameters().expect("none yet").is_none());
        assert!(s.export_keying_material(&mut [0u8; 8], b"label", b"ctx").is_err());
        let mut hello = Vec::new();
        assert!(s.write_handshake(&mut hello).is_none(), "the ClientHello is at the Initial level: no key change");
        assert_eq!(hello.first(), Some(&1), "a ClientHello");
        // A ServerHello with a body of two bytes: the session fails, and stays failed.
        let first = s.read_handshake(&[2, 0, 0, 2, 0xff, 0xff]).expect_err("bad hello");
        assert_ne!(first.reason, "");
        assert!(s.read_handshake(&[]).is_err());
        assert!(s.handshake_data().is_none());
    }

    #[test]
    fn a_completed_session_answers_from_its_handshake() {
        use qc::Session as _;
        let mut s = established();
        let hd = s.handshake_data().expect("data");
        let hd = hd.downcast_ref::<HandshakeData>().expect("ours");
        assert_eq!(hd.protocol.as_deref(), Some(&b"h3"[..]));
        assert_eq!(hd.server_name.as_deref(), Some("localhost"));
        assert!(s.transport_parameters().is_ok());
        assert!(s.early_crypto().is_none(), "no early data was offered");
        let mut out = [0u8; 16];
        s.export_keying_material(&mut out, b"EXPERIMENTAL ibex", b"ctx").expect("exporter");
        let mut again = [0u8; 16];
        s.export_keying_material(&mut again, b"EXPERIMENTAL ibex", b"ctx").expect("exporter");
        assert_eq!(out, again);
        assert_ne!(out, [0u8; 16]);
        // A handshake message after the handshake: rustls refuses what it does not expect.
        assert!(s.read_handshake(&[0x0b, 0, 0, 0]).is_err());
    }

    #[test]
    fn a_failed_session_has_no_outputs() {
        use qc::Session as _;
        let mut s = QuicServerConfig::new(bind()).expect("config").session(1, &params());
        s.read_handshake(&[1, 0, 0, 2, 0xff, 0xff]).expect_err("bad hello");
        s.got_handshake_data = true;
        let hd = s.handshake_data().expect("data");
        assert_eq!(hd.downcast_ref::<HandshakeData>().expect("ours").protocol, None);
    }

    #[test]
    #[should_panic(expected = "without a QUIC algorithm")]
    fn a_suite_without_a_quic_algorithm_is_a_bug() {
        let _ = unreachable_suite();
    }
}
