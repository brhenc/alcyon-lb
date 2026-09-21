//! # `ibex-tls`
//!
//! Multi-TLS provider abstraction supporting:
//! - Pure Rustls (memory-safe, default).
//! - OpenSSL / BoringSSL (FIPS & legacy compatibility).

pub mod config;
pub mod provider;
pub mod rustls_impl;

pub use config::{TlsConfig, TlsEngineKind};
pub use provider::{TlsAcceptorProvider, TlsProviderFactory};
pub use rustls_impl::RustlsProvider;
