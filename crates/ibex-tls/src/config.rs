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
        // `h2` is filtered out rather than rejected: an operator copying a working
        // HAProxy config should not be stopped by it, and dropping it from the offer
        // degrades to HTTP/1.1 instead of failing. Remove the filter when the h2 mux in
        // `ibex-proto` is wired into the engine.
        let requested: Vec<String> = if bind.alpn.is_empty() {
            vec!["http/1.1".to_string()]
        } else {
            bind.alpn.clone()
        };
        let (supported, unsupported): (Vec<String>, Vec<String>) = requested
            .into_iter()
            .partition(|p| p == "http/1.1" || p == "http/1.0");
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

fn load_cert_file(path: &std::path::Path) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
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
