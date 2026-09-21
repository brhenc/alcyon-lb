use crate::config::{TlsConfig, TlsEngineKind};
use crate::provider::TlsAcceptorProvider;
use async_trait::async_trait;
use ibex_core::error::IbexResult;
use tokio_rustls::TlsAcceptor;

/// Memory-safe Rustls provider
pub struct RustlsProvider {
    acceptor: Option<TlsAcceptor>,
}

impl RustlsProvider {
    pub fn new() -> Self {
        Self { acceptor: None }
    }
}

impl Default for RustlsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TlsAcceptorProvider for RustlsProvider {
    fn engine_kind(&self) -> TlsEngineKind {
        TlsEngineKind::Rustls
    }

    fn initialize(&mut self, _config: &TlsConfig) -> IbexResult<()> {
        // Rustls server configuration can be initialized from PEM keys/certs
        Ok(())
    }
}
