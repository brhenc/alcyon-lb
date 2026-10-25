// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What a TLS connection negotiated ([`RustlsTlsInfo`], the `ssl_*` fetches' source) and the
//! certificate it presented ([`LocalCert`]); filled by [`crate::conn::TlsCtx`].

use ibex_proto::transport::{TlsInfo, VerifyResult};

/// Cached TLS session attributes implementing the sealed [`TlsInfo`] trait.
#[derive(Clone, Debug)]
pub struct RustlsTlsInfo {
    pub sni: Option<String>,
    pub cipher: Option<String>,
    pub protocol_version: Option<String>,
    pub alpn: Option<Vec<u8>>,
    pub session_resumed: bool,
    pub peer_verify: VerifyResult,
    pub peer_subject_dn: Option<String>,
    pub peer_issuer_dn: Option<String>,
    pub peer_not_after: Option<i64>,
    pub peer_has_cert: bool,
    /// The certificate this side presented (server side: the one the resolver picked for the
    /// `ClientHello`), for the `ssl_f_*` fetches. A shared handle: nothing is copied per connection.
    pub local_cert: Option<LocalCert>,
    /// The `ClientHello` as `tune.ssl.capture-buffer-size` keeps it (server side only); `None`
    /// when the size is 0 or the hello was too short to reach its cipher suites.
    pub capture: Option<crate::capture::SslCapture>,
}

/// The certificate a connection presented: a shared handle into its bind's resolver
/// ([`crate::conn`]).
#[derive(Clone, Debug)]
pub enum LocalCert {
    Tcp(std::sync::Arc<rustls24::crypto::Credentials>),
}

impl LocalCert {
    /// The DER of the leaf certificate.
    #[must_use]
    pub fn leaf(&self) -> Option<&[u8]> {
        match self {
            // A bind's identities are X.509 (`Identity::from_cert_chain`): never a raw key.
            Self::Tcp(c) => if let rustls24::crypto::Identity::X509(x) = &*c.identity { Some(x.end_entity.as_ref()) } else { None },
        }
    }
}

impl Default for RustlsTlsInfo {
    fn default() -> Self {
        Self {
            sni: None,
            cipher: None,
            protocol_version: None,
            alpn: None,
            session_resumed: false,
            peer_verify: VerifyResult::NotRequested,
            peer_subject_dn: None,
            peer_issuer_dn: None,
            peer_not_after: None,
            peer_has_cert: false,
            local_cert: None,
            capture: None,
        }
    }
}

impl TlsInfo for RustlsTlsInfo {
    fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    fn cipher(&self) -> Option<&str> {
        self.cipher.as_deref()
    }

    fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    fn session_resumed(&self) -> bool {
        self.session_resumed
    }

    fn peer_verify(&self) -> VerifyResult {
        self.peer_verify
    }

    fn peer_subject_dn(&self) -> Option<&str> {
        self.peer_subject_dn.as_deref()
    }

    fn peer_issuer_dn(&self) -> Option<&str> {
        self.peer_issuer_dn.as_deref()
    }

    fn peer_not_after(&self) -> Option<i64> {
        self.peer_not_after
    }

    fn peer_has_cert(&self) -> bool {
        self.peer_has_cert
    }
}
