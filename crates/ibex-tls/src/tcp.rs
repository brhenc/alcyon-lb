// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The configurations of TLS over TCP, on rustls 0.24 (T440).
//!
//! rustls 0.24 decrypts and encrypts in buffers its caller owns, which is what lets a
//! steady-state request over TLS allocate nothing. QUIC stays on rustls 0.23 (`quinn-proto`
//! 0.11 needs it), so a `bind ... ssl` line builds its configuration once per rustls: the
//! QUIC one in [`crate::config`], the TCP one here, both from the same [`BindPlan`] so they
//! cannot disagree on certificates, names or ALPN.
//!
//! What differs from 0.23, and how it is kept the same on the wire:
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
use crate::resolver::IbexCertResolver;
use crate::TlsCryptoProvider;
use ibex_config::ast::BindConfig;
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
    min: Option<ibex_config::TlsVersion>,
    max: Option<ibex_config::TlsVersion>,
) -> Option<Arc<CryptoProvider>> {
    let versions = versions_between(min, max);
    let tls12 = versions.iter().any(|v| v.version == rustls::ProtocolVersion::TLSv1_2);
    let tls13 = versions.iter().any(|v| v.version == rustls::ProtocolVersion::TLSv1_3);
    (tls12 || tls13).then(|| provider::of(kind, tls12, tls13))
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

/// A ticket key of provider `IBEX` (`ring-ibex` when true): a function, as the rotator wants.
fn ticket_key<const IBEX: bool>() -> Result<Box<dyn TicketProducer>, rustls24::Error> {
    let kind = if IBEX { TlsCryptoProvider::RingIbex } else { TlsCryptoProvider::Ring };
    Ok(Box::new(TicketKey(provider::ticketer(kind)?)))
}

fn ticket_key_of(kind: TlsCryptoProvider) -> fn() -> Result<Box<dyn TicketProducer>, rustls24::Error> {
    match kind {
        TlsCryptoProvider::Ring => ticket_key::<false>,
        TlsCryptoProvider::RingIbex => ticket_key::<true>,
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

/// The session-ID cache, entries refused once `SESSION_LIFETIME` old (as in [`crate::config`]).
#[derive(Debug)]
struct ExpiringSessions {
    inner: Arc<rustls24::server::ServerSessionMemoryCache>,
}

impl ExpiringSessions {
    fn fresh(stored: Option<Vec<u8>>) -> Option<Vec<u8>> {
        let mut v = stored?;
        let born = u64::from_be_bytes(v.get(..8)?.try_into().ok()?);
        if unix_now().saturating_sub(born) > u64::from(SESSION_LIFETIME) {
            return None;
        }
        v.drain(..8);
        Some(v)
    }
}

impl StoresServerSessions for ExpiringSessions {
    fn put(&self, key: ServerSessionKey<'_>, value: Vec<u8>) -> bool {
        let mut v = unix_now().to_be_bytes().to_vec();
        v.extend_from_slice(&value);
        self.inner.put(key, v)
    }
    fn get(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        Self::fresh(self.inner.get(key))
    }
    fn take(&self, key: ServerSessionKey<'_>) -> Option<Vec<u8>> {
        Self::fresh(self.inner.take(key))
    }
    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

/// The certificates of a bind, by name, for rustls 0.24.
pub type CertResolver = IbexCertResolver<Credentials>;

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
}

/// Builds the TCP configuration of a `bind ... ssl` line on the [`provider::active`] provider.
/// Identical binds share one (as [`crate::TlsConfig::from_bind_config`] does for the QUIC one).
///
/// # Errors
/// As [`crate::TlsConfig::from_bind_config`].
pub fn from_bind_config(bind: &BindConfig) -> Result<Arc<BindTls>, String> {
    from_bind_config_with(bind, provider::active())
}

/// [`from_bind_config`] on provider `kind`.
///
/// # Errors
/// As [`crate::TlsConfig::from_bind_config`].
pub fn from_bind_config_with(bind: &BindConfig, kind: TlsCryptoProvider) -> Result<Arc<BindTls>, String> {
    type Cache = std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<BindTls>>>;
    static CACHE: std::sync::OnceLock<Cache> = std::sync::OnceLock::new();
    // Binds alike on two providers are two configurations.
    let key = format!("{}\0{}", kind.name(), shared_key(bind).unwrap_or_default());
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(live) = cache.get(&key).and_then(std::sync::Weak::upgrade) {
        return Ok(live);
    }
    let built = Arc::new(build_bind(bind, kind)?);
    cache.retain(|_, w| w.strong_count() > 0);
    cache.insert(key, Arc::downgrade(&built));
    Ok(built)
}

fn build_bind(bind: &BindConfig, kind: TlsCryptoProvider) -> Result<BindTls, String> {
    let plan = BindPlan::of(bind)?;
    let versions = plan.versions(bind)?;
    let tls12 = versions.iter().any(|v| v.version == rustls::ProtocolVersion::TLSv1_2);
    let tls13 = versions.iter().any(|v| v.version == rustls::ProtocolVersion::TLSv1_3);
    build(&plan, kind, tls12, tls13)
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
    // Session resumption as in `crate::config::TlsConfig::build_server_config`: stateless
    // tickets, and a session-ID cache of `tune.ssl.cachesize` (20000) entries.
    config.session_storage = Arc::new(ExpiringSessions { inner: rustls24::server::ServerSessionMemoryCache::new(SESSION_CACHE_SIZE) });
    config.ticketer = Some(Arc::new(Hint(
        rustls24::TicketRotator::new(Duration::from_secs(u64::from(SESSION_LIFETIME / 2)), ticket_key_of(kind))
            .map_err(|e| format!("session ticket keys: {e}"))?,
    )));
    let mut no_alpn = config.clone();
    no_alpn.alpn_protocols.clear();
    Ok(BindTls { config: Arc::new(config), no_alpn: Arc::new(no_alpn), resolver, provider: kind })
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
        h.write(b"ibex:verify-none");
    }
}

/// `verify required`, with `HAProxy`'s name rule: see [`crate::ServerVerifier`].
#[derive(Debug)]
pub struct ServerVerifier {
    inner: rustls24::client::WebPkiServerVerifier,
}

impl ServerVerifier {
    /// # Errors
    /// As [`crate::ServerVerifier::from_options`].
    pub fn from_options(options: &BackendTlsOptions, provider: &CryptoProvider) -> Result<Arc<Self>, String> {
        let Some(ca_path) = options.ca_file.as_deref() else {
            return Err("verify is enabled but no CA file specified".to_string());
        };
        let roots = rustls24::RootCertStore { roots: load_server_ca(ca_path)?.roots };
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
        h.write(b"ibex:verify-required");
        self.inner.hash_config(h);
    }
}

/// The [`ClientConfig`] of a server line (or its health check) on the [`provider::active`]
/// provider, as [`crate::build_backend_client_config`] builds it for rustls 0.23.
///
/// # Errors
/// As [`crate::build_backend_client_config`].
pub fn build_backend_client_config(options: &BackendTlsOptions) -> Result<Arc<ClientConfig>, String> {
    build_backend_client_config_with(options, provider::active())
}

/// [`build_backend_client_config`] on provider `kind`.
///
/// # Errors
/// As [`crate::build_backend_client_config`].
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

    #[test]
    fn the_ticket_hint_is_twice_the_rotation_period_and_tickets_round_trip() {
        let hint = Hint(rustls24::TicketRotator::new(Duration::from_secs(u64::from(SESSION_LIFETIME / 2)), ticket_key::<false>).expect("rotator"));
        assert_eq!(hint.lifetime(), Duration::from_secs(u64::from(SESSION_LIFETIME)));
        assert!(ticket_key::<true>().expect("key").lifetime() > Duration::ZERO);
        let ticket = hint.encrypt(b"resume me").expect("encrypt");
        assert_eq!(hint.decrypt(&ticket).as_deref(), Some(&b"resume me"[..]));
    }
}
