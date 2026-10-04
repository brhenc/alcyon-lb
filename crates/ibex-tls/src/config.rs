// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TLS configuration types and builders for `ibex-tls`.

use crate::resolver::IbexCertResolver;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
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

/// A custom certificate verifier that skips server authentication.
///
/// Used exclusively when `verify none` is explicitly configured for backend TLS.
#[derive(Debug)]
pub struct NoServerAuth {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl Default for NoServerAuth {
    fn default() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl NoServerAuth {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl rustls::client::danger::ServerCertVerifier for NoServerAuth {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Loads CA certificates from a PEM file or directory into a [`RootCertStore`].
///
/// # Errors
/// Returns an error if reading the file fails or no valid certificates are found.
pub fn load_ca_file(path: &std::path::Path) -> Result<RootCertStore, String> {
    let mut root_store = RootCertStore::empty();
    let file = std::fs::File::open(path)
        .map_err(|e| format!("Failed to open CA file {}: {}", path.display(), e))?;
    let mut reader = std::io::BufReader::new(file);
    let mut count = 0;
    for item in rustls_pemfile::read_all(&mut reader) {
        let item = item.map_err(|e| format!("Failed to read PEM in {}: {}", path.display(), e))?;
        if let rustls_pemfile::Item::X509Certificate(cert) = item {
            root_store
                .add(cert)
                .map_err(|e| format!("Failed to add certificate to root store: {e}"))?;
            count += 1;
        }
    }
    if count == 0 {
        return Err(format!("No CA certificates found in {}", path.display()));
    }
    Ok(root_store)
}

/// Standard locations for system CA certificate bundles.
const STANDARD_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// Loads the default system root CA certificate store.
#[must_use]
pub fn load_system_ca_roots() -> RootCertStore {
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        if let Ok(store) = load_ca_file(std::path::Path::new(&path)) {
            if !store.is_empty() {
                return store;
            }
        }
    }
    for path_str in STANDARD_CA_PATHS {
        let p = std::path::Path::new(path_str);
        if p.exists() {
            if let Ok(store) = load_ca_file(p) {
                if !store.is_empty() {
                    return store;
                }
            }
        }
    }
    RootCertStore::empty()
}

/// What a `server` line says about the TLS it speaks (`src/cfgparse-ssl.c`), as the
/// engine hands it over. The name to send and to verify against is decided per
/// connection, so it is not here.
#[derive(Clone, Debug)]
pub struct BackendTlsOptions {
    /// `verify required` (the default, `ssl-server-verify`) or `verify none`.
    pub verify_required: bool,
    /// `ca-file`: a PEM bundle, or `@system-ca` for the system's.
    pub ca_file: Option<std::path::PathBuf>,
    /// `crl-file`: PEM-encoded revocation lists.
    pub crl_file: Option<std::path::PathBuf>,
    /// `crt`: the client certificate and its key, in one PEM file.
    pub client_crt: Option<std::path::PathBuf>,
    /// `alpn`, in order. Empty offers nothing, as `HAProxy` offers nothing without it.
    pub alpn: Vec<Vec<u8>>,
    /// `ssl-min-ver`.
    pub min_ver: Option<ibex_config::TlsVersion>,
    /// `ssl-max-ver`.
    pub max_ver: Option<ibex_config::TlsVersion>,
    /// `no-ssl-reuse`: never resume a session.
    pub no_reuse: bool,
}

impl Default for BackendTlsOptions {
    fn default() -> Self {
        Self {
            verify_required: true,
            ca_file: None,
            crl_file: None,
            client_crt: None,
            alpn: Vec::new(),
            min_ver: None,
            max_ver: None,
            no_reuse: false,
        }
    }
}

/// The protocol versions a server line allows, out of those this build of rustls speaks
/// (TLS 1.3, and TLS 1.2 when the `tls12` feature is on).
fn protocol_versions(options: &BackendTlsOptions) -> Vec<&'static rustls::SupportedProtocolVersion> {
    use ibex_config::TlsVersion;
    // What a `server` line can name, against what rustls calls it. A version this build
    // of rustls does not speak is simply absent from `DEFAULT_VERSIONS`.
    const NAMED: &[(rustls::ProtocolVersion, TlsVersion)] =
        &[(rustls::ProtocolVersion::TLSv1_2, TlsVersion::Tls12), (rustls::ProtocolVersion::TLSv1_3, TlsVersion::Tls13)];
    let allowed = |v: TlsVersion| options.min_ver.is_none_or(|m| m <= v) && options.max_ver.is_none_or(|m| v <= m);
    rustls::DEFAULT_VERSIONS
        .iter()
        .copied()
        .filter(|v| NAMED.iter().any(|&(p, t)| p == v.version && allowed(t)))
        .collect()
}

/// What this build of rustls speaks, for the error when a server line allows none of it.
fn spoken_versions() -> String {
    rustls::DEFAULT_VERSIONS
        .iter()
        .map(|v| format!("{:?}", v.version))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Loads `path` as the trust anchors of a server line: `@system-ca` is the system's
/// bundle (`HAProxy` warns and loads nothing when it is empty).
///
/// # Errors
/// A bundle that cannot be read, or holds no certificate.
pub fn load_server_ca(path: &std::path::Path) -> Result<RootCertStore, String> {
    if path.as_os_str() == "@system-ca" {
        return Ok(load_system_ca_roots());
    }
    load_ca_file(path)
}

/// Loads the PEM-encoded CRLs of a `crl-file`.
fn load_crl_file(path: &std::path::Path) -> Result<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("Couldn't open the crl-file '{}' ({e})", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut crls = Vec::new();
    for item in rustls_pemfile::read_all(&mut reader) {
        let item = item.map_err(|e| format!("Failed to read PEM in {}: {e}", path.display()))?;
        if let rustls_pemfile::Item::Crl(crl) = item {
            crls.push(crl);
        }
    }
    if crls.is_empty() {
        return Err(format!("No CRL found in {}", path.display()));
    }
    Ok(crls)
}

/// `ssl_sock_srv_hostcheck` (`src/ssl_sock.c`): does the certificate name `pattern` cover
/// `hostname`? Case-insensitive; one `*` is allowed, in the leftmost label only, and
/// covers one label (RFC 6125 6.4.3).
#[must_use]
pub fn hostcheck(pattern: &str, hostname: &str) -> bool {
    if pattern.eq_ignore_ascii_case(hostname) {
        return true;
    }
    // The leftmost label of the pattern, which must end in a dot.
    let Some(pattern_dot) = pattern.find('.') else { return false };
    let left = &pattern[..pattern_dot];
    let mut stars = left.match_indices('*');
    let Some((wild, _)) = stars.next() else { return false };
    if stars.next().is_some() {
        return false;
    }
    // Every label but the leftmost must match.
    let Some(hostname_dot) = hostname.find('.') else { return false };
    if !pattern[pattern_dot..].eq_ignore_ascii_case(&hostname[hostname_dot..]) {
        return false;
    }
    // The leftmost label of the hostname must be long enough for the wildcard to match.
    let hleft = &hostname[..hostname_dot];
    let prefix = &left[..wild];
    let suffix = &left[wild + 1..];
    if hleft.len() < prefix.len() + suffix.len() {
        return false;
    }
    hleft[..prefix.len()].eq_ignore_ascii_case(prefix) && hleft[hleft.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// `ssl_sock_srv_verifycbk`'s name rule: `name` against the dNSName SANs, or against the
/// subject CN when the certificate has no dNSName at all.
fn cert_covers_name(der: &[u8], name: &str) -> bool {
    let sans = extract_dns_sans(der);
    if !sans.is_empty() {
        return sans.iter().any(|san| hostcheck(san, name));
    }
    extract_subject_cn(der).is_some_and(|cn| hostcheck(&cn, name))
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
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl ServerVerifier {
    /// Builds the verifier of a server line.
    ///
    /// # Errors
    /// No `ca-file` (`HAProxy`: "verify is enabled but no CA file specified"), or one
    /// that cannot be loaded, or a `crl-file` that cannot.
    pub fn from_options(options: &BackendTlsOptions) -> Result<Arc<Self>, String> {
        let Some(ca_path) = options.ca_file.as_deref() else {
            return Err("verify is enabled but no CA file specified".to_string());
        };
        let roots = load_server_ca(ca_path)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut builder = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider);
        if let Some(crl_path) = options.crl_file.as_deref() {
            builder = builder.with_crls(load_crl_file(crl_path)?);
        }
        let inner = builder.build().map_err(|e| format!("unable to set up certificate verification: {e}"))?;
        Ok(Arc::new(Self { inner }))
    }
}

impl rustls::client::danger::ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use rustls::client::danger::ServerCertVerified;
        use rustls::{CertificateError, Error};
        match self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            // webpki verifies the chain before the name, so a name error means the chain
            // is good and only HAProxy's name rule is left to apply.
            Err(Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. })) => {
                match server_name {
                    ServerName::IpAddress(_) => Ok(ServerCertVerified::assertion()),
                    ServerName::DnsName(name) if cert_covers_name(end_entity.as_ref(), name.as_ref()) => {
                        Ok(ServerCertVerified::assertion())
                    }
                    _ => Err(Error::InvalidCertificate(CertificateError::NotValidForName)),
                }
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Builds the [`ClientConfig`] of a server line. `enable_sni` is on; the engine clones
/// it off for a connection that verifies against `verifyhost` without sending a name.
///
/// # Errors
/// `verify required` without a loadable `ca-file`, a `crl-file` or `crt` that cannot be
/// loaded, or a version range with nothing in it.
pub fn build_backend_client_config(
    options: &BackendTlsOptions,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions = protocol_versions(options);
    if versions.is_empty() {
        return Err(format!(
            "no TLS version is left between 'ssl-min-ver' and 'ssl-max-ver': this build speaks {}",
            spoken_versions()
        ));
    }
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> = if options.verify_required {
        ServerVerifier::from_options(options)?
    } else {
        NoServerAuth::new()
    };
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("Protocol version error: {e:?}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = if let Some(ref crt_path) = options.client_crt {
        let (certs, key) = load_cert_file(crt_path)?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| format!("unable to load SSL certificate from file '{}': {e}", crt_path.display()))?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols.clone_from(&options.alpn);
    if options.no_reuse {
        config.resumption = rustls::client::Resumption::disabled();
    }
    Ok(Arc::new(config))
}

/// Parses a server name string (DNS hostname or IP address) into a [`ServerName`].
///
/// # Errors
/// Returns an error if the name is not a valid DNS name or IP address.
pub fn parse_server_name(name: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(name.to_string())
        .map_err(|e| format!("Invalid server name '{name}': {e:?}"))
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
use ibex_config::ast::BindConfig;

impl TlsConfig {
        /// # Errors
    /// Returns an error if certificates cannot be loaded, private keys are missing,
    /// or if the underlying `ServerConfig` builder fails.
    pub fn from_bind_config(bind: &BindConfig) -> Result<Arc<ServerConfig>, String> {
        let mut config = TlsConfig::new();

        // Advertise only what the runtime can actually serve.
        //
        // `TlsConfig::default` offers `h2, http/1.1`, and curl duly negotiated h2 against
        // a listener whose stream layer speaks HTTP/1 only -- the handshake succeeded,
        // the certificate verified, and then the connection died with a TLS decode error
        // because neither side was speaking what the other sent. Offering a protocol we
        // cannot serve breaks every client that prefers it, which today is most of them.
        //
        // The h2 mux in `ibex-proto` is wired into the engine, so `h2` is supported
        // alongside `http/1.1` and `http/1.0`.
        let requested: Vec<String> = if bind.alpn.is_empty() {
            vec!["h2".to_string(), "http/1.1".to_string()]
        } else {
            bind.alpn.clone()
        };
        let (supported, unsupported): (Vec<String>, Vec<String>) = requested
            .into_iter()
            .partition(|p| p == "h3" || p == "h2" || p == "http/1.1" || p == "http/1.0");
        for p in &unsupported {
            eprintln!(
                "[ibex] warning: bind {}: ALPN '{p}' is not served by this build and was \
                 not advertised",
                bind.addr
            );
        }
        if supported.is_empty() {
            return Err(format!(
                "bind {}: none of the requested ALPN protocols ({}) are served by this \
                 build; a client offering only those would have nothing to negotiate",
                bind.addr,
                unsupported.join(", ")
            ));
        }
        config = config.with_alpn(supported.iter().map(|s| s.as_bytes().to_vec()).collect());

        let mut resolver = IbexCertResolver::new();
        let mut is_first = true;

        for crt_path_str in &bind.crt {
            let path = std::path::Path::new(crt_path_str);
            let cert_key_pairs = load_certs_from_path(path)?;
            for (certs, key, _file_path) in cert_key_pairs {
                let certified_key = Arc::new(create_certified_key(certs.clone(), &key)?);
                if is_first {
                    resolver.set_default_cert(certified_key.clone());
                    is_first = false;
                }
                
                if let Some(cert_der) = certs.first() {
                    let mut names = extract_dns_sans(cert_der.as_ref());
                    if names.is_empty() {
                        if let Some(cn) = extract_subject_cn(cert_der.as_ref()) {
                            names.push(cn);
                        }
                    }
                    for domain in names {
                        resolver.add_cert(&domain, certified_key.clone());
                    }
                }
            }
        }

        if is_first {
            return Err("No certificates loaded for bind".to_string());
        }

        config = config.with_cert_resolver(Arc::new(resolver));
        config.build_server_config()
    }
}

fn load_certs_from_path(path: &std::path::Path) -> Result<Vec<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, std::path::PathBuf)>, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("Failed to read metadata for {}: {}", path.display(), e))?;
    if metadata.is_dir() {
        let mut all = Vec::new();
        let entries = std::fs::read_dir(path).map_err(|e| format!("Failed to read directory {}: {}", path.display(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry in {}: {}", path.display(), e))?;
            let entry_path = entry.path();
            if entry_path.is_file() {
                let (certs, key) = load_cert_file(&entry_path)?;
                all.push((certs, key, entry_path));
            }
        }
        Ok(all)
    } else {
        let (certs, key) = load_cert_file(path)?;
        Ok(vec![(certs, key, path.to_path_buf())])
    }
}

/// Loads certificates and a private key from a PEM file.
///
/// # Errors
/// Returns an error if the file cannot be opened, PEM parsing fails, or no private key / certificate is found.
pub fn load_cert_file(path: &std::path::Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("Failed to open file {}: {}", path.display(), e))?;
    let mut reader = std::io::BufReader::new(file);
    
    let mut certs = Vec::new();
    let mut private_key = None;
    
    for item in rustls_pemfile::read_all(&mut reader) {
        let item = item.map_err(|e| format!("Failed to read PEM from {}: {}", path.display(), e))?;
        match item {
            rustls_pemfile::Item::X509Certificate(cert) => certs.push(cert),
            rustls_pemfile::Item::Pkcs1Key(key) => private_key = Some(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => private_key = Some(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => private_key = Some(PrivateKeyDer::Sec1(key)),
            _ => {}
        }
    }
    
    let key = private_key.ok_or_else(|| format!("No private key found in {}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("No certificates found in {}", path.display()));
    }
    
    Ok((certs, key))
}

/// A bounds-checked DER cursor.
///
/// Every read is fallible. The previous version indexed slices directly, so a
/// certificate declaring a name longer than the bytes that follow it panicked the
/// process -- reachable from any truncated or corrupt file in a `crt` path, which is
/// to say from an operator mistake as easily as from an attacker.
struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// One DER element: its tag and its contents.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

impl<'a> Der<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Reads a definite-form length. Indefinite form is not legal in DER, and a length
    /// wider than a `usize` cannot describe a buffer we are holding, so both are refused
    /// rather than truncated into something that looks plausible.
    fn length(&mut self) -> Option<usize> {
        let first = self.byte()?;
        if first < 0x80 {
            return Some(first as usize);
        }
        let n = (first & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            return None;
        }
        let mut v: usize = 0;
        for _ in 0..n {
            v = v.checked_shl(8)? | self.byte()? as usize;
        }
        Some(v)
    }

    /// Reads one tag-length-value. `None` if the declared length exceeds what is left,
    /// which is the check whose absence caused the panic.
    fn tlv(&mut self) -> Option<Tlv<'a>> {
        let tag = self.byte()?;
        let len = self.length()?;
        let end = self.pos.checked_add(len)?;
        let value = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(Tlv { tag, value })
    }

    /// Reads the next element and descends into its contents.
    fn child(&mut self) -> Option<Der<'a>> {
        Some(Der::new(self.tlv()?.value))
    }
}

/// id-ce-subjectAltName, 2.5.29.17.
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// The DNS names a certificate is valid for, from its subjectAltName extension.
///
/// These are what a client sends in SNI, and what `IbexCertResolver` matches on, so they
/// have to come from inside the certificate. Deriving them from the filename -- which an
/// earlier version did -- means `/etc/ssl/wildcard-2024.pem` answers for the hostname
/// "wildcard-2024" and for nothing a client will ever ask for.
///
/// The structure is walked rather than scanned. Searching the whole encoding for the
/// bytes `06 03 55 1D 11` finds them wherever they happen to fall -- inside a public key,
/// a signature, an embedded certificate timestamp, or a subject string someone chose --
/// and then parses whatever follows as if it were the extension.
///
/// Returns an empty vector for anything malformed. A certificate with no usable names is
/// not fatal on its own: it still serves as the default, and `from_bind_config` fails
/// only when no certificate could be loaded at all.
#[must_use]
pub fn extract_dns_sans(der: &[u8]) -> Vec<String> {
    extract_dns_sans_inner(der).unwrap_or_default()
}

fn extract_dns_sans_inner(der: &[u8]) -> Option<Vec<String>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut cert = Der::new(der).child()?;
    // TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature, issuer,
    //                               validity, subject, subjectPublicKeyInfo, ...
    //                               [3] EXPLICIT extensions OPTIONAL }
    let mut tbs = cert.child()?;

    // Skip forward to the [3] context-specific element. The fields before it vary in
    // number and in whether they are present, so they are stepped over by structure
    // rather than counted.
    let mut extensions = None;
    while !tbs.is_empty() {
        let el = tbs.tlv()?;
        if el.tag == 0xA3 {
            extensions = Some(Der::new(el.value));
            break;
        }
    }
    let mut seq = extensions?.child()?; // Extensions ::= SEQUENCE OF Extension

    let mut names = Vec::new();
    while !seq.is_empty() {
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
        //                          extnValue OCTET STRING }
        let Some(ext) = seq.tlv() else { break };
        let mut ext = Der::new(ext.value);
        let Some(oid) = ext.tlv() else { continue };
        if oid.tag != 0x06 || oid.value != OID_SUBJECT_ALT_NAME {
            continue;
        }
        // `critical` is optional and defaults to false, so take whichever comes next and
        // step past it if it turns out to be the boolean.
        let Some(mut next) = ext.tlv() else { continue };
        if next.tag == 0x01 {
            let Some(after) = ext.tlv() else { continue };
            next = after;
        }
        if next.tag != 0x04 {
            continue;
        }
        // GeneralNames ::= SEQUENCE OF GeneralName; dNSName is [2] IA5String.
        let Some(mut general) = Der::new(next.value).child() else {
            continue;
        };
        while !general.is_empty() {
            let Some(name) = general.tlv() else { break };
            if name.tag == 0x82 {
                if let Ok(s) = std::str::from_utf8(name.value) {
                    if !s.is_empty() {
                        names.push(s.to_ascii_lowercase());
                    }
                }
            }
        }
    }
    Some(names)
}

/// Extracts the Subject Common Name (CN) from the certificate, if present.
/// Used as a fallback when no Subject Alternative Names (SANs) are present.
#[must_use]
pub fn extract_subject_cn(der: &[u8]) -> Option<String> {
    let mut cert = Der::new(der).child()?;
    let mut tbs = cert.child()?;

    let first_el = tbs.tlv()?;
    if first_el.tag == 0xA0 {
        let _serial = tbs.tlv()?; // serialNumber
    }
    let _signature = tbs.tlv()?;
    let _issuer = tbs.tlv()?;
    let _validity = tbs.tlv()?;
    let subject = tbs.tlv()?;

    if subject.tag != 0x30 { return None; }
    
    let mut rdn_seq = Der::new(subject.value);
    let mut cn = None;

    while !rdn_seq.is_empty() {
        let set = rdn_seq.tlv()?;
        if set.tag != 0x31 { continue; } // SET
        let mut rdn_set_der = Der::new(set.value);
        while !rdn_set_der.is_empty() {
            let seq = rdn_set_der.tlv()?;
            if seq.tag != 0x30 { continue; } // SEQUENCE
            let mut attr_seq_der = Der::new(seq.value);
            let oid = attr_seq_der.tlv()?;
            if oid.tag == 0x06 && oid.value == [0x55, 0x04, 0x03] {
                let value = attr_seq_der.tlv()?;
                if let Ok(s) = std::str::from_utf8(value.value) {
                    if !s.is_empty() {
                        cn = Some(s.to_string());
                    }
                }
            }
        }
    }
    cn
}
