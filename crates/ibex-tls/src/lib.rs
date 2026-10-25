// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! # `ibex-tls`
//!
//! Pure memory-safe TLS transport layer and SNI resolver for Project Ibex.
//!
//! Features:
//! - Pure `#![forbid(unsafe_code)]` with rustls 0.24 ([`tcp`], [`conn`]).
//! - $O(k)$ Exact and wildcard SNI resolution backed by `ebtree::EbMbTree` ([`IbexCertResolver`]).
//! - What a session negotiated, for the `ssl_*` fetches ([`RustlsTlsInfo`]).
//! - Anti-DDoS TLS handshake budget defense with `ibex-sched` `Class::Heavy` / `state::HEAVY`.

#![forbid(unsafe_code)]

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod blocking;
pub mod capture;
pub mod cipher_names;
pub mod config;
pub mod conn;
pub mod ja4;
pub mod provider;
pub mod resolver;
pub mod tcp;
pub mod transport;
pub mod x509;

pub use config::{
    extract_dns_sans, extract_subject_cn, hostcheck, load_ca_file, load_cert_file, load_server_ca, load_system_ca_roots,
    parse_server_name, versions_between, BackendTlsOptions, TlsVersions,
};
pub use ibex_config::TlsCryptoProvider;
pub use ja4::Ja4Parts;
pub use capture::{exclude_tls_grease, HelloTap, SslCapture};
pub use resolver::IbexCertResolver;
pub use transport::{LocalCert, RustlsTlsInfo};
