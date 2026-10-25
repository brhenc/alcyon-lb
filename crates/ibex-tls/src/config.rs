// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! TLS configuration types and builders for `ibex-tls`.

use rustls24::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

/// Sessions a server keeps for resumption by session ID: `HAProxy`'s default
/// `tune.ssl.cachesize`.
pub(crate) const SESSION_CACHE_SIZE: usize = 20000;

/// How long a session can be resumed, in seconds: OpenSSL's default session timeout,
/// which `HAProxy` keeps unless `tune.ssl.lifetime` is set (Ibex refuses that keyword).
/// Its NewSessionTicket advertises it as the lifetime hint.
pub(crate) const SESSION_LIFETIME: u32 = 7200;

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Loads CA certificates from a PEM file or directory into a root store.
///
/// # Errors
/// Returns an error if reading the file fails or no valid certificates are found.
pub fn load_ca_file(path: &std::path::Path) -> Result<rustls24::RootCertStore, String> {
    let mut root_store = rustls24::RootCertStore::empty();
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
pub fn load_system_ca_roots() -> rustls24::RootCertStore {
    roots_from(std::env::var("SSL_CERT_FILE").ok().as_deref(), STANDARD_CA_PATHS)
}

/// The first non-empty CA bundle among `env_file` and then `standard`; no roots if none.
fn roots_from(env_file: Option<&str>, standard: &[&str]) -> rustls24::RootCertStore {
    if let Some(path) = env_file {
        if let Ok(store) = load_ca_file(std::path::Path::new(path)) {
            if !store.is_empty() {
                return store;
            }
        }
    }
    for path_str in standard {
        let p = std::path::Path::new(path_str);
        if p.exists() {
            if let Ok(store) = load_ca_file(p) {
                if !store.is_empty() {
                    return store;
                }
            }
        }
    }
    rustls24::RootCertStore::empty()
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

/// The protocol versions a handshake may use: TLS 1.2 and TLS 1.3, the two this build speaks
/// (rustls has nothing older). A pair of flags because that is what the provider of a version
/// range is built from ([`crate::provider::of`]: its cipher suite lists).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsVersions {
    pub tls12: bool,
    pub tls13: bool,
}

impl TlsVersions {
    /// No version left.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.tls12 && !self.tls13
    }
}

/// The protocol versions between `min` and `max`, out of those this build speaks (TLS 1.2
/// and 1.3): what `ssl-min-ver`, `ssl-max-ver`, `no-tlsvN` and `force-tlsvN` ask a
/// handshake to offer (`bind`) or to accept (`server`).
#[must_use]
pub fn versions_between(min: Option<ibex_config::TlsVersion>, max: Option<ibex_config::TlsVersion>) -> TlsVersions {
    use ibex_config::TlsVersion;
    let allowed = |v: TlsVersion| min.is_none_or(|m| m <= v) && max.is_none_or(|m| v <= m);
    TlsVersions { tls12: allowed(TlsVersion::Tls12), tls13: allowed(TlsVersion::Tls13) }
}

/// What this build speaks, for the error when a server line allows none of it (rustls's
/// names for the versions, newest first, as rustls 0.23's `DEFAULT_VERSIONS` listed them).
pub(crate) fn spoken_versions() -> String {
    "TLSv1_3, TLSv1_2".to_string()
}

/// Loads `path` as the trust anchors of a server line: `@system-ca` is the system's
/// bundle (`HAProxy` warns and loads nothing when it is empty).
///
/// # Errors
/// A bundle that cannot be read, or holds no certificate.
pub fn load_server_ca(path: &std::path::Path) -> Result<rustls24::RootCertStore, String> {
    if path.as_os_str() == "@system-ca" {
        return Ok(load_system_ca_roots());
    }
    load_ca_file(path)
}

/// Loads the PEM-encoded CRLs of a `crl-file`.
pub(crate) fn load_crl_file(path: &std::path::Path) -> Result<Vec<rustls24::pki_types::CertificateRevocationListDer<'static>>, String> {
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
pub(crate) fn cert_covers_name(der: &[u8], name: &str) -> bool {
    let sans = extract_dns_sans(der);
    if !sans.is_empty() {
        return sans.iter().any(|san| hostcheck(san, name));
    }
    extract_subject_cn(der).is_some_and(|cn| hostcheck(&cn, name))
}

/// Parses a server name string (DNS hostname or IP address) into a [`ServerName`].
///
/// # Errors
/// Returns an error if the name is not a valid DNS name or IP address.
pub fn parse_server_name(name: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(name.to_string())
        .map_err(|e| format!("Invalid server name '{name}': {e:?}"))
}

use ibex_config::ast::BindConfig;

/// What a `bind ... ssl` line asks for, whichever rustls builds it: the ALPN list it advertises
/// and the certificates of its `crt` files, loaded. What [`crate::tcp`] builds a bind from
/// (TCP and QUIC alike).
pub(crate) struct BindPlan {
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) pairs: Vec<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, std::path::PathBuf)>,
}

impl BindPlan {
    pub(crate) fn of(bind: &BindConfig) -> Result<Self, String> {
        // Advertise only what the runtime can actually serve.
        //
        // The default offer was `h2, http/1.1`, and curl duly negotiated h2 against
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
            ibex_config::stderr_line!(
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
        let mut pairs = Vec::new();
        for crt_path_str in &bind.crt {
            pairs.extend(load_certs_from_path(std::path::Path::new(crt_path_str))?);
        }
        if pairs.is_empty() {
            return Err("No certificates loaded for bind".to_string());
        }
        Ok(Self { alpn: supported.iter().map(|s| s.as_bytes().to_vec()).collect(), pairs })
    }

    /// The protocol versions the bind offers.
    pub(crate) fn versions(&self, bind: &BindConfig) -> Result<TlsVersions, String> {
        let mut versions = versions_between(bind.min_ver, bind.max_ver);
        if bind.quic {
            // QUIC is TLS 1.3 by definition (RFC 9001): never offer 1.2 there, whatever
            // the TCP binds of the proxy do.
            if !versions.tls13 {
                return Err(format!("bind {}: QUIC needs TLS 1.3, which 'ssl-max-ver' rules out", bind.addr));
            }
            versions.tls12 = false;
        }
        if versions.is_empty() {
            return Err(format!("all SSL/TLS versions are disabled for bind '{}'", bind.addr));
        }
        Ok(versions)
    }
}

pub(crate) fn key_mismatch(file_path: &std::path::Path) -> String {
    format!("inconsistencies between private key and certificate loaded '{}'.", file_path.display())
}

pub(crate) fn wrong_tag(file_path: &std::path::Path) -> String {
    format!("unable to load certificate from file '{}': wrong tag.", file_path.display())
}

/// The names a certificate is served for: its dNSName SANs, or its subject CN without any.
pub(crate) fn cert_names(certs: &[CertificateDer<'static>]) -> Vec<String> {
    let Some(cert_der) = certs.first() else { return Vec::new() };
    let mut names = extract_dns_sans(cert_der.as_ref());
    if names.is_empty() {
        if let Some(cn) = extract_subject_cn(cert_der.as_ref()) {
            names.push(cn);
        }
    }
    names
}

/// Identity of the config a bind would build: its options and the size and mtime of every
/// file it reads, so a renewed certificate is never served from a stale entry. `None`
/// when a file cannot be inspected (the build then reports the real error).
pub(crate) fn shared_key(bind: &BindConfig) -> Option<String> {
    use std::fmt::Write as _;
    let mut k = format!("{:?}|{:?}|{}|{:?}|{:?}", bind.crt, bind.alpn, bind.quic, bind.min_ver, bind.max_ver);
    for c in &bind.crt {
        let path = std::path::Path::new(c);
        let mut files = Vec::new();
        if std::fs::metadata(path).ok()?.is_dir() {
            for e in std::fs::read_dir(path).ok()? {
                files.push(e.ok()?.path());
            }
            files.sort();
        } else {
            files.push(path.to_path_buf());
        }
        for f in files {
            let m = std::fs::metadata(&f).ok()?;
            let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
            let _ = write!(k, "|{}:{}:{}", f.display(), m.len(), t.as_nanos());
        }
    }
    Some(k)
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
pub(crate) struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// One DER element: its tag and its contents.
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
}

impl<'a> Der<'a> {
    pub(crate) const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) const fn is_empty(&self) -> bool {
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
    pub(crate) fn tlv(&mut self) -> Option<Tlv<'a>> {
        let tag = self.byte()?;
        let len = self.length()?;
        let end = self.pos.checked_add(len)?;
        let value = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(Tlv { tag, value })
    }

    /// Reads the next element and descends into its contents.
    pub(crate) fn child(&mut self) -> Option<Der<'a>> {
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

#[cfg(test)]
mod ca_roots {
    use super::roots_from;

    #[test]
    fn no_bundle_anywhere_is_no_roots() {
        assert!(roots_from(Some("/nonexistent/ibex-ca.pem"), &["/nonexistent/other.pem"]).is_empty());
        assert!(roots_from(None, &[]).is_empty());
    }

    #[test]
    fn the_environment_bundle_wins_over_the_standard_ones() {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let path = std::env::temp_dir().join(format!("ibex-ca-roots-{}.pem", std::process::id()));
        std::fs::write(&path, c.cert.pem()).expect("write");
        let p = path.to_str().expect("utf8");
        assert_eq!(roots_from(Some(p), &[]).len(), 1);
        assert_eq!(roots_from(Some("/nonexistent/ibex-ca.pem"), &[p]).len(), 1);
        std::fs::remove_file(&path).ok();
    }
}
