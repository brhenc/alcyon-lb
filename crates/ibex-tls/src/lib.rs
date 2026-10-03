// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! # `ibex-tls`
//!
//! Pure memory-safe TLS transport layer and SNI resolver for Project Ibex.
//!
//! Features:
//! - Pure `#![forbid(unsafe_code)]` with `rustls 0.23`.
//! - $O(k)$ Exact and wildcard SNI resolution backed by `ebtree::EbMbTree` ([`IbexCertResolver`]).
//! - Pre-allocated, zero-allocation TLS state storage ([`TlsArena`], [`TlsSlot`]).
//! - Non-blocking transport implementing `ibex_proto::transport::Transport` and [`TlsInfo`] ([`RustlsTransport`]).
//! - Anti-DDoS TLS handshake budget defense with `ibex-sched` `Class::Heavy` / `state::HEAVY`.

#![forbid(unsafe_code)]

pub mod arena;
pub mod config;
pub mod resolver;
pub mod transport;

pub use arena::{
    TlsArena, TlsArenaError, TlsSession, TlsSlot, DEFAULT_TLS_BUF_CAPACITY, MAX_TLS_SLOTS,
};
pub use config::{
    build_backend_client_config, create_certified_key, extract_dns_sans,
    install_default_crypto_provider, load_ca_file, load_cert_file, load_system_ca_roots, parse_server_name,
    BackendTlsOptions, NoServerAuth, TlsConfig, TlsEngineKind,
};
pub use resolver::IbexCertResolver;
pub use transport::{RustlsContext, RustlsTlsInfo, RustlsTransport};
