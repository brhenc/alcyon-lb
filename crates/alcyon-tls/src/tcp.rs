// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The TLS configurations of `bind ... ssl` and `server ... ssl` lines, on rustls 0.24 (T440;
//! QUIC too since T461, and the only rustls the binary links since T479).
//!
//! rustls 0.24 decrypts and encrypts in buffers its caller owns, which is what lets a
//! steady-state request over TLS allocate nothing. A bind is built from its [`BindPlan`]
//! (certificates, names, ALPN, versions).
//!
//! What differs from rustls 0.23 (which Alcyon used before), and how it is kept the same on the
//! wire:
//! - The protocol versions are the provider's cipher suite lists: a provider with no TLS 1.2
//!   suites speaks TLS 1.3 only (there is no `with_protocol_versions`).
//! - ring's ticket key type is private; [`rustls24::TicketRotator`] rotates keys made by the
//!   provider's factory, and [`Hint`] advertises the lifetime 0.23 advertised (twice the
//!   rotation period: the time a key decrypts for).

use crate::config::{
    cert_covers_name, cert_names, key_mismatch, load_crl_file, load_server_ca, shared_key, spoken_versions, unix_now,
    versions_between, wrong_tag, BackendTlsOptions, BindPlan, SESSION_CACHE_SIZE, SESSION_LIFETIME,
};
use crate::provider;
use crate::resolver::AlcyonCertResolver;
use crate::TlsCryptoProvider;
use alcyon_config::ast::BindConfig;
use rustls24::crypto::{CryptoProvider, Credentials, Identity, SelectedCredential, TicketProducer};
use rustls24::pki_types::ServerName;
use rustls24::server::{ClientHello, ServerCredentialResolver, ServerSessionKey, StoresServerSessions};
use rustls24::{ClientConfig, ServerConfig};
use std::sync::Arc;
use std::time::Duration;

pub use rustls24;

/// The provider of a version range (`ssl-min-ver` / `ssl-max-ver`); `None` when it rules out
/// every version this build speaks.
fn provider_between(
    kind: TlsCryptoProvider,
    min: Option<alcyon_config::TlsVersion>,
    max: Option<alcyon_config::TlsVersion>,
) -> Option<Arc<CryptoProvider>> {
    let v = versions_between(min, max);
    (!v.is_empty()).then(|| provider::of(kind, v.tls12, v.tls13))
}

/// A ticket key made by the provider for one rotation period of the outer rotator.
#[derive(Debug)]
struct TicketKey(Arc<dyn TicketProducer>);

impl TicketProducer for TicketKey {
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.0.encrypt(plain)
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.0.decrypt(cipher)
    }
    fn lifetime(&self) -> Duration {
        self.0.lifetime()
    }
}

/// A ticket key of provider `ALCYON` (`ring-alcyon` when true): a function, as the rotator wants.
fn ticket_key<const ALCYON: bool>() -> Result<Box<dyn TicketProducer>, rustls24::Error> {
    let kind = if ALCYON { TlsCryptoProvider::RingAlcyon } else { TlsCryptoProvider::Ring };
    Ok(Box::new(TicketKey(provider::ticketer(kind)?)))
}

fn ticket_key_of(kind: TlsCryptoProvider) -> fn() -> Result<Box<dyn TicketProducer>, rustls24::Error> {
    match kind {
        TlsCryptoProvider::Ring => ticket_key::<false>,
        TlsCryptoProvider::RingAlcyon => ticket_key::<true>,
    }
}

/// The rotator, advertising `SESSION_LIFETIME` as the ticket lifetime hint, as 0.23 did
/// (rustls 0.24's rotator advertises its rotation period, half of it).
#[derive(Debug)]
struct Hint(rustls24::TicketRotator);

impl TicketProducer for Hint {
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.0.encrypt(plain)
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.0.decrypt(cipher)
    }
    fn lifetime(&self) -> Duration {
        Duration::from_secs(u64::from(SESSION_LIFETIME))
    }
}

/// The session-ID cache: at most `cap` entries, oldest evicted first, entries refused once
/// `SESSION_LIFETIME` old. It grows as sessions are stored and every growth is fallible: when
/// memory (`-m`, `RLIMIT_DATA`) is short a session is simply not cached, never an abort (T507;
/// rustls's `ServerSessionMemoryCache` reserves its whole capacity up front and aborts).
/// Not an `alcyon_alloc::Pool`: entries are variable-sized and live behind rustls's
/// `StoresServerSessions` API (handshake path, not the request path), and the bound is `cap`.
#[derive(Debug)]
struct ExpiringSessions {
    cap: usize,
    inner: std::sync::Mutex<SessionMap>,
}

#[derive(Debug, Default)]
struct SessionMap {
    map: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    /// Insertion order; may hold keys already taken (dropped lazily).
    order: std::collections::VecDeque<Vec<u8>>,
}

fn try_copy(src: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(prefix.len() + src.len()).ok()?;
    v.extend_from_slice(prefix);
    v.extend_from_slice(src);
    Some(v)
}

impl ExpiringSessions {
    fn new(cap: usize) -> Self {
        Self { cap, inner: std::sync::Mutex::new(SessionMap::default()) }
    }

    fn fresh(stored: Option<Vec<u8>>) -> Option<Vec<u8>> {
        let mut v = stored?;
        let born = u64::from_be_bytes(v.get(..8)?.try_into().ok()?);
        if unix_now().saturating_sub(born) > u64::from(SESSION_LIFETIME) {
            return None;
        }
        v.drain(..8);
        Some(v)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SessionMap> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl SessionMap {
    /// Store `value` under `key`; false when memory is short (nothing changed that matters).
    fn insert(&mut self, cap: usize, key: &[u8], value: Vec<u8>) -> bool {
        if let Some(slot) = self.map.get_mut(key) {
            *slot = value;
            return true;
        }
        // Drop taken keys from the order list once it has twice the capacity (no allocation).
        if self.order.len() >= cap.saturating_mul(2) {
            let map = &self.map;
            self.order.retain(|k| map.contains_key(k));
        }
        while self.map.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.map.remove(&old);
                }
                None => break,
            }
        }
        let Some(k1) = try_copy(key, &[]) else { return false };
        let Some(k2) = try_copy(key, &[]) else { return false };
        if self.map.try_reserve(1).is_err() || self.order.try_reserve(1).is_err() {
            return false;
        }
        self.order.push_back(k2);
        self.map.insert(k1, value);
        true
    }
}

impl StoresServerSessions for ExpiringSessions {
    fn put(&self, key: ServerSessionKey<'_>, value: Vec<u8>) -> bool {
        let Some(v) = try_copy(&value, &unix_now().to_be_bytes()) else { return false };
        self.lock().insert(self.cap, key.as_ref(), v)
    }
    fn get(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        let stored = self.lock().map.get(key.as_ref()).and_then(|v| try_copy(v, &[]));
        Self::fresh(stored)
    }
    fn take(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        let stored = self.lock().map.remove(key.as_ref());
        Self::fresh(stored)
    }
    fn can_cache(&self) -> bool {
        true
    }
}

/// The certificates of a bind, by name, for rustls 0.24.
pub type CertResolver = AlcyonCertResolver<Credentials>;

impl CertResolver {
    /// The certificate a `ClientHello` gets: by its SNI, else the default.
    #[must_use]
    pub fn credentials_for(&self, hello: &ClientHello<'_>) -> Option<Arc<Credentials>> {
        // `resolve_domain` falls back to the default itself.
        hello.server_name().map_or_else(|| self.default_cert(), |name| self.resolve_domain(name.as_ref()))
    }
}

impl ServerCredentialResolver for CertResolver {
    fn resolve(&self, hello: &ClientHello<'_>) -> Result<SelectedCredential, rustls24::Error> {
        let creds = self.credentials_for(hello).ok_or(rustls24::Error::NoSuitableCertificate)?;
        creds
            .signer(hello.signature_schemes())
            .ok_or(rustls24::Error::PeerIncompatible(rustls24::error::PeerIncompatible::NoSignatureSchemesInCommon))
    }
}

/// What a TCP `bind ... ssl` line serves with: its configuration, the same with no ALPN
/// (for a client whose ALPN list has nothing in common with the bind's, which `HAProxy`
/// completes without ALPN), and its certificates (for the `ssl_f_*` fetches).
#[derive(Debug)]
pub struct BindTls {
    pub config: Arc<ServerConfig>,
    pub no_alpn: Arc<ServerConfig>,
    pub resolver: Arc<CertResolver>,
    /// The crypto provider both configurations run on (T460).
    pub provider: TlsCryptoProvider,
    /// The line it was built from, for a swap to build it again (`None`: built in memory).
    source: Option<BindConfig>,
    /// The same bind on the other provider, once a swap built it.
    other: std::sync::OnceLock<Arc<BindTls>>,
}

impl BindTls {
    /// A bind of these parts, which a swap does not build again.
    #[must_use]
    pub fn from_parts(config: Arc<ServerConfig>, no_alpn: Arc<ServerConfig>, resolver: Arc<CertResolver>, provider: TlsCryptoProvider) -> Self {
        Self { config, no_alpn, resolver, provider, source: None, other: std::sync::OnceLock::new() }
    }

    /// What a handshake starting now uses: this bind, or its build on the provider a swap made
    /// active (T460). One atomic load.
    #[must_use]
    pub fn into_current(self: Arc<Self>) -> Arc<Self> {
        if provider::active() == self.provider {
            return self;
        }
        match self.other.get() {
            Some(other) => Arc::clone(other),
            None => self,
        }
    }
}

impl provider::Rebuild for BindTls {
    fn prepare(self: Arc<Self>, p: TlsCryptoProvider) -> Result<Option<provider::Publish>, String> {
        let Some(source) = self.source.as_ref().filter(|_| p != self.provider && self.other.get().is_none()) else {
            return Ok(None);
        };
        let built = Arc::new(build_bind(source, p).map_err(|e| format!("bind {} ssl: {e}", source.addr))?);
        Ok(Some(Box::new(move || {
            let _ = self.other.set(built);
        })))
    }
}

/// Builds the TCP configuration of a `bind ... ssl` line on the [`provider::active`] provider.
/// Identical binds share one: a large `crt` directory is held in memory once, not once per
/// thread per bind.
///
/// # Errors
/// A certificate that cannot be loaded, a missing private key, a key that does not match its
/// certificate, an ALPN list with nothing servable, or a version range with nothing in it.
pub fn from_bind_config(bind: &BindConfig) -> Result<Arc<BindTls>, String> {
    from_bind_config_with(bind, provider::active())
}

/// [`from_bind_config`] on provider `kind`.
///
/// # Errors
/// As [`from_bind_config`].
pub fn from_bind_config_with(bind: &BindConfig, kind: TlsCryptoProvider) -> Result<Arc<BindTls>, String> {
    type Cache = std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<BindTls>>>;
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    // Binds alike on two providers are two configurations.
    let key = format!("{}\0{}", kind.name(), shared_key(bind).unwrap_or_default());
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(live) = cache.get(&key).and_then(std::sync::Weak::upgrade) {
        return Ok(live);
    }
    let mut built = build_bind(bind, kind)?;
    built.source = Some(bind.clone());
    let built = Arc::new(built);
    cache.retain(|_, w| w.strong_count() > 0);
    cache.insert(key, Arc::downgrade(&built));
    provider::register(Arc::downgrade(&built) as std::sync::Weak<dyn provider::Rebuild>);
    Ok(built)
}

fn build_bind(bind: &BindConfig, kind: TlsCryptoProvider) -> Result<BindTls, String> {
    let plan = BindPlan::of(bind)?;
    let v = plan.versions(bind)?;
    build(&plan, kind, v.tls12, v.tls13)
}

impl BindTls {
    /// A bind serving one certificate chain and its key, with `alpn`, TLS 1.2 and 1.3: what a
    /// `bind ... ssl crt <file>` line builds, without the file.
    ///
    /// # Errors
    /// The key does not load or does not match the certificate.
    pub fn single(
        certs: Vec<rustls24::pki_types::CertificateDer<'static>>,
        key: rustls24::pki_types::PrivateKeyDer<'static>,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Arc<Self>, String> {
        Self::single_with(certs, key, alpn, provider::active())
    }

    /// [`Self::single`] on provider `kind`.
    ///
    /// # Errors
    /// As [`Self::single`].
    pub fn single_with(
        certs: Vec<rustls24::pki_types::CertificateDer<'static>>,
        key: rustls24::pki_types::PrivateKeyDer<'static>,
        alpn: Vec<Vec<u8>>,
        kind: TlsCryptoProvider,
    ) -> Result<Arc<Self>, String> {
        let plan = BindPlan { alpn, pairs: vec![(certs, key, std::path::PathBuf::from("(memory)"))] };
        build(&plan, kind, true, true).map(Arc::new)
    }

    /// [`Self::single`] for QUIC: TLS 1.3 only (RFC 9001), on the active provider. A swap does
    /// not build it again (it has no `bind` line).
    ///
    /// # Errors
    /// As [`Self::single`].
    pub fn single_tls13(
        certs: Vec<rustls24::pki_types::CertificateDer<'static>>,
        key: rustls24::pki_types::PrivateKeyDer<'static>,
        alpn: Vec<Vec<u8>>,
    ) -> Result<Arc<Self>, String> {
        let plan = BindPlan { alpn, pairs: vec![(certs, key, std::path::PathBuf::from("(memory)"))] };
        build(&plan, provider::active(), false, true).map(Arc::new)
    }
}

fn build(plan: &BindPlan, kind: TlsCryptoProvider, tls12: bool, tls13: bool) -> Result<BindTls, String> {
    // The keys are loaded by the provider that signs with them; its key provider is the same
    // whatever the suites.
    let keys = provider::of(kind, true, true);
    let mut resolver = CertResolver::empty();
    let mut is_first = true;
    for (certs, key, file_path) in &plan.pairs {
        let identity = Arc::new(Identity::from_cert_chain(certs.clone()).map_err(|_| wrong_tag(file_path))?);
        let signing = keys.key_provider.load_private_key(key.clone_key()).map_err(|e| format!("Invalid private key: {e:?}"))?;
        // rustls-ring's three signing keys (RSA, ECDSA, Ed25519) all know their public half, so
        // the inconsistency is always a mismatch (never `InconsistentKeys::Unknown`); any other
        // error is a leaf that does not parse as a certificate.
        let creds = Credentials::new(Arc::clone(&identity), signing).map_err(|e| match e {
            rustls24::Error::InconsistentKeys(_) => key_mismatch(file_path),
            _ => wrong_tag(file_path),
        })?;
        let creds = Arc::new(creds);
        if is_first {
            resolver.set_default_cert(Arc::clone(&creds));
            is_first = false;
        }
        for domain in cert_names(certs) {
            resolver.add_cert(&domain, Arc::clone(&creds));
        }
    }
    let resolver = Arc::new(resolver);
    let mut config = ServerConfig::builder(provider::of(kind, tls12, tls13))
        .with_no_client_auth()
        .with_server_credential_resolver(Arc::clone(&resolver) as Arc<dyn ServerCredentialResolver>)
        .map_err(|e| format!("Protocol version error: {e:?}"))?;
    config.alpn_protocols = plan.alpn.iter().map(|p| p.clone().into()).collect();
    // Session resumption as `HAProxy` has it by default: stateless
    // tickets, and a session-ID cache of `tune.ssl.cachesize` (20000) entries.
    config.session_storage = Arc::new(ExpiringSessions::new(SESSION_CACHE_SIZE));
    config.ticketer = Some(Arc::new(Hint(
        rustls24::TicketRotator::new(Duration::from_secs(u64::from(SESSION_LIFETIME / 2)), ticket_key_of(kind))
            .map_err(|e| format!("session ticket keys: {e}"))?,
    )));
    let mut no_alpn = config.clone();
    no_alpn.alpn_protocols.clear();
    Ok(BindTls::from_parts(Arc::new(config), Arc::new(no_alpn), resolver, kind))
}

/// `verify none`: no server authentication, signatures still checked.
#[derive(Debug)]
pub struct NoServerAuth {
    provider: Arc<CryptoProvider>,
}

impl rustls24::client::danger::ServerVerifier for NoServerAuth {
    fn verify_identity<'a>(
        &self,
        identity: &rustls24::client::danger::ServerIdentity<'a, '_>,
    ) -> Result<rustls24::crypto::VerifiedIdentity<'a>, rustls24::Error> {
        Ok(rustls24::crypto::VerifiedIdentity::assertion(identity.identity.clone()))
    }

    fn verify_tls12_signature(
        &self,
        input: &rustls24::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<rustls24::client::danger::HandshakeSignatureValid, rustls24::Error> {
        rustls24::crypto::verify_tls12_signature(input, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        input: &rustls24::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<rustls24::client::danger::HandshakeSignatureValid, rustls24::Error> {
        rustls24::crypto::verify_tls13_signature(input, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls24::crypto::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        false
    }

    /// Sessions resumed by a client config are keyed by its verifier: none verifies alike.
    fn hash_config(&self, h: &mut dyn std::hash::Hasher) {
        h.write(b"alcyon:verify-none");
    }
}

/// The server certificate check of a `verify required` server line, with `HAProxy`'s
/// rules (`ssl_sock_srv_verifycbk`, `src/ssl_sock.c`) rather than webpki's.
///
/// The chain is verified by webpki against the `ca-file` anchors (and `crl-file`). The
/// name is where the two differ: `HAProxy` checks it only against the SNI it sent or, when
/// it sent none, against `verifyhost`, and not at all when neither is set; and it falls
/// back to the subject CN when the certificate has no dNSName, which webpki never does.
/// The engine encodes that in the [`ServerName`] it connects with: a DNS name is the name
/// to check (and send, unless the config's `enable_sni` is off), the server's IP address
/// means "no name to check". Measured on 3.5-dev8: a CN-only certificate passes a matching
/// `verifyhost`, and with neither SNI nor `verifyhost` any name passes.
#[derive(Debug)]
pub struct ServerVerifier {
    inner: rustls24::client::WebPkiServerVerifier,
}

impl ServerVerifier {
    /// Builds the verifier of a server line.
    ///
    /// # Errors
    /// No `ca-file` (`HAProxy`: "verify is enabled but no CA file specified"), or one
    /// that cannot be loaded, or a `crl-file` that cannot.
    pub fn from_options(options: &BackendTlsOptions, provider: &CryptoProvider) -> Result<Arc<Self>, String> {
        let Some(ca_path) = options.ca_file.as_deref() else {
            return Err("verify is enabled but no CA file specified".to_string());
        };
        let roots = load_server_ca(ca_path)?;
        let mut builder = rustls24::client::WebPkiServerVerifier::builder(Arc::new(roots), provider);
        if let Some(crl_path) = options.crl_file.as_deref() {
            builder = builder.with_crls(load_crl_file(crl_path)?);
        }
        let inner = builder.build().map_err(|e| format!("unable to set up certificate verification: {e}"))?;
        Ok(Arc::new(Self { inner }))
    }
}

impl rustls24::client::danger::ServerVerifier for ServerVerifier {
    fn verify_identity<'a>(
        &self,
        identity: &rustls24::client::danger::ServerIdentity<'a, '_>,
    ) -> Result<rustls24::crypto::VerifiedIdentity<'a>, rustls24::Error> {
        use rustls24::error::CertificateError;
        use rustls24::Error;
        match self.inner.verify_identity(identity) {
            // webpki verifies the chain before the name, so a name error means the chain
            // is good and only HAProxy's name rule is left to apply.
            Err(Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. })) => {
                let ok = || Ok(rustls24::crypto::VerifiedIdentity::assertion(identity.identity.clone()));
                // An IP address passes as before. `ServerName` is `non_exhaustive`: a kind of name
                // that is neither checks as the empty name, which no certificate covers. A raw
                // public key needs the client to offer it (it does not): no name either.
                let is_ip = matches!(identity.server_name, ServerName::IpAddress(_));
                let name = if let ServerName::DnsName(n) = identity.server_name { n.as_ref() } else { "" };
                let leaf: &[u8] = if let Identity::X509(c) = identity.identity { c.end_entity.as_ref() } else { &[] };
                if is_ip || cert_covers_name(leaf, name) {
                    ok()
                } else {
                    Err(Error::InvalidCertificate(CertificateError::NotValidForName))
                }
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        input: &rustls24::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<rustls24::client::danger::HandshakeSignatureValid, rustls24::Error> {
        self.inner.verify_tls12_signature(input)
    }

    fn verify_tls13_signature(
        &self,
        input: &rustls24::client::danger::SignatureVerificationInput<'_>,
    ) -> Result<rustls24::client::danger::HandshakeSignatureValid, rustls24::Error> {
        self.inner.verify_tls13_signature(input)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls24::crypto::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn request_ocsp_response(&self) -> bool {
        self.inner.request_ocsp_response()
    }

    fn hash_config(&self, h: &mut dyn std::hash::Hasher) {
        h.write(b"alcyon:verify-required");
        self.inner.hash_config(h);
    }
}

/// The [`ClientConfig`] of a server line (or its health check) on the [`provider::active`]
/// provider. `enable_sni` is on; the engine clones it off for a connection that verifies
/// against `verifyhost` without sending a name.
///
/// # Errors
/// `verify required` without a loadable `ca-file`, a `crl-file` or `crt` that cannot be
/// loaded, or a version range with nothing in it.
pub fn build_backend_client_config(options: &BackendTlsOptions) -> Result<Arc<ClientConfig>, String> {
    build_backend_client_config_with(options, provider::active())
}

/// [`build_backend_client_config`] on provider `kind`.
///
/// # Errors
/// As [`build_backend_client_config`].
pub fn build_backend_client_config_with(options: &BackendTlsOptions, kind: TlsCryptoProvider) -> Result<Arc<ClientConfig>, String> {
    let Some(provider) = provider_between(kind, options.min_ver, options.max_ver) else {
        return Err(format!(
            "no TLS version is left between 'ssl-min-ver' and 'ssl-max-ver': this build speaks {}",
            spoken_versions()
        ));
    };
    let verifier: Arc<dyn rustls24::client::danger::ServerVerifier> = if options.verify_required {
        ServerVerifier::from_options(options, &provider)?
    } else {
        Arc::new(NoServerAuth { provider: Arc::clone(&provider) })
    };
    let builder = ClientConfig::builder(provider).dangerous().with_custom_certificate_verifier(verifier);
    let mut config = if let Some(ref crt_path) = options.client_crt {
        let (certs, key) = crate::config::load_cert_file(crt_path)?;
        let bad = |e: String| format!("unable to load SSL certificate from file '{}': {e}", crt_path.display());
        let identity = Arc::new(Identity::from_cert_chain(certs).map_err(|e| bad(format!("{e:?}")))?);
        builder.with_client_auth_cert(identity, key).map_err(|e| bad(e.to_string()))?
    } else {
        builder.with_no_client_auth().map_err(|e| format!("Protocol version error: {e:?}"))?
    };
    config.alpn_protocols = options.alpn.iter().map(|p| p.clone().into()).collect();
    if options.no_reuse {
        config.resumption = rustls24::client::Resumption::disabled();
    }
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamped(born: u64, v: &[u8]) -> Vec<u8> {
        let mut s = born.to_be_bytes().to_vec();
        s.extend_from_slice(v);
        s
    }

    #[test]
    fn a_cached_session_is_returned_until_it_is_older_than_its_lifetime() {
        let now = unix_now();
        assert_eq!(ExpiringSessions::fresh(Some(stamped(now, b"state"))), Some(b"state".to_vec()));
        assert_eq!(ExpiringSessions::fresh(Some(stamped(now - u64::from(SESSION_LIFETIME) - 5, b"state"))), None);
        // No entry, and an entry too short to hold its date.
        assert_eq!(ExpiringSessions::fresh(None), None);
        assert_eq!(ExpiringSessions::fresh(Some(vec![1, 2, 3])), None);
    }

    /// The only lib test that changes the active provider (others read it through
    /// `provider::active` only by building configurations, which no other lib test does).
    #[test]
    fn a_handshake_takes_the_build_of_the_active_provider_when_the_bind_has_one() {
        use rustls24::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        assert_eq!(provider::active(), TlsCryptoProvider::Ring, "ring until set");
        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let one = |kind| {
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key_pair.serialize_der()));
            BindTls::single_with(vec![CertificateDer::from(c.cert.der().to_vec())], key, vec![], kind).expect("bind")
        };
        let ring = one(TlsCryptoProvider::Ring);
        assert!(Arc::ptr_eq(&Arc::clone(&ring).into_current(), &ring), "its own provider");
        provider::set_active(TlsCryptoProvider::RingAlcyon);
        // Built in memory, so no swap built it on ring-alcyon: it serves on its own provider.
        assert!(Arc::ptr_eq(&Arc::clone(&ring).into_current(), &ring), "no other build");
        let alcyon = one(TlsCryptoProvider::RingAlcyon);
        ring.other.set(Arc::clone(&alcyon)).expect("unset");
        assert!(Arc::ptr_eq(&Arc::clone(&ring).into_current(), &alcyon), "the other build");
        provider::set_active(TlsCryptoProvider::Ring);
        assert!(Arc::ptr_eq(&Arc::clone(&ring).into_current(), &ring), "back");
    }

    #[test]
    fn the_ticket_hint_is_twice_the_rotation_period_and_tickets_round_trip() {
        let hint = Hint(rustls24::TicketRotator::new(Duration::from_secs(u64::from(SESSION_LIFETIME / 2)), ticket_key::<false>).expect("rotator"));
        assert_eq!(hint.lifetime(), Duration::from_secs(u64::from(SESSION_LIFETIME)));
        assert!(ticket_key::<true>().expect("key").lifetime() > Duration::ZERO);
        let ticket = hint.encrypt(b"resume me").expect("encrypt");
        assert_eq!(hint.decrypt(&ticket).as_deref(), Some(&b"resume me"[..]));
    }
}

#[cfg(test)]
mod session_cache_tests {
    use super::*;

    #[test]
    fn the_oldest_session_goes_when_the_cache_is_full() {
        let mut m = SessionMap::default();
        for i in 0u8..3 {
            assert!(m.insert(3, &[i], vec![i]));
        }
        assert!(m.insert(3, &[1], vec![9]), "replace in place");
        assert_eq!(m.map.len(), 3);
        assert!(m.insert(3, &[3], vec![3]));
        assert_eq!(m.map.len(), 3);
        assert!(!m.map.contains_key(&[0u8][..]), "oldest evicted");
        assert_eq!(m.map.get(&[1u8][..]), Some(&vec![9]));
    }

    #[test]
    fn taken_keys_do_not_grow_the_order_list_without_bound() {
        let mut m = SessionMap::default();
        for i in 0u8..40 {
            assert!(m.insert(2, &[i], vec![i]));
            m.map.remove(&[i][..]);
        }
        assert!(m.order.len() <= 4, "{}", m.order.len());
    }

    #[test]
    fn put_get_take_and_expiry() {
        let c = ExpiringSessions::new(4);
        let born = unix_now().to_be_bytes();
        assert!(c.lock().insert(4, b"k", try_copy(b"v", &born).unwrap()));
        assert_eq!(ExpiringSessions::fresh(c.lock().map.get(&b"k"[..]).cloned()), Some(b"v".to_vec()));
        let old = (unix_now() - u64::from(SESSION_LIFETIME) - 10).to_be_bytes();
        assert_eq!(ExpiringSessions::fresh(try_copy(b"v", &old)), None);
        assert_eq!(ExpiringSessions::fresh(Some(vec![1, 2])), None, "too short");
        assert!(c.can_cache());
    }
}
