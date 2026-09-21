//! TLS configuration types and key/certificate loaders.

/// Supported TLS backend engines
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsEngineKind {
    Rustls,
    OpenSsl,
    BoringSsl,
}

/// Unified TLS Configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub engine: TlsEngineKind,
    pub cert_chain_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub session_tickets_enabled: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            engine: TlsEngineKind::Rustls,
            cert_chain_pem: Vec::new(),
            private_key_pem: Vec::new(),
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            session_tickets_enabled: true,
        }
    }
}
