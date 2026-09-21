use crate::config::{TlsConfig, TlsEngineKind};
use async_trait::async_trait;
use ibex_core::error::IbexResult;

/// Abstraction trait for TLS Stream Acceptor (Server side)
#[async_trait]
pub trait TlsAcceptorProvider: Send + Sync {
    /// Returns the active TLS engine variant.
    fn engine_kind(&self) -> TlsEngineKind;

    /// Validates configuration and initializes certificates.
    fn initialize(&mut self, config: &TlsConfig) -> IbexResult<()>;
}

/// Factory for creating TLS Acceptor Providers
pub struct TlsProviderFactory;

impl TlsProviderFactory {
    pub fn create_acceptor(kind: TlsEngineKind) -> Box<dyn TlsAcceptorProvider> {
        match kind {
            TlsEngineKind::Rustls => Box::new(crate::rustls_impl::RustlsProvider::new()),
            TlsEngineKind::OpenSsl | TlsEngineKind::BoringSsl => {
                Box::new(crate::rustls_impl::RustlsProvider::new()) // Fallback to safe Rustls
            }
        }
    }
}
