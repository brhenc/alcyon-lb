// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

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
pub use config::{create_certified_key, TlsConfig, TlsEngineKind};
pub use resolver::IbexCertResolver;
pub use transport::{RustlsContext, RustlsTlsInfo, RustlsTransport};
