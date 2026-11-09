// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.crypto-provider ring|ring-alcyon` (T460, Alcyon-only), `set ssl crypto-provider` and
//! `show ssl crypto-provider`.
//!
//! [`apply`] runs before any TLS configuration is built (`validate_tls`, `build_shared_state`)
//! and makes the configured provider [`alcyon_tls::provider::active`]: every TLS configuration
//! is built on it from then on: TCP binds, server lines and health checks; QUIC binds (T461,
//! `alcyon_quic::crypto`); log-forward TLS binds and ring TLS servers (T461,
//! `alcyon_tls::blocking`). Nothing is left on rustls 0.23, so nothing refuses `ring-alcyon`.
//!
//! [`set`] swaps the provider at run time ([`alcyon_tls::provider::swap`]). It holds for this
//! process: a reload (a new process) starts on the configured provider.

use alcyon_config::{Config, TlsCryptoProvider};
use std::io;

/// The provider `config` asks for (`ring` when it says nothing).
#[must_use]
pub fn configured(config: &Config) -> TlsCryptoProvider {
    config.global.as_ref().and_then(|g| g.crypto_provider).unwrap_or_default()
}

/// Makes the configured provider the one TLS configurations are built on.
///
/// # Errors
/// None today: every TLS user runs on either provider. Kept for the startup path's `?`.
pub fn apply(config: &Config) -> io::Result<()> {
    alcyon_tls::provider::set_active(configured(config));
    Ok(())
}

/// `set ssl crypto-provider <name>`: the answer. Every TLS configuration is built on the new
/// provider first; the swap happens only when all of them are, so a failure changes nothing.
#[must_use]
pub fn set(args: &str) -> String {
    let words: Vec<&str> = args.split_whitespace().collect();
    let Some(p) = (if let [one] = words.as_slice() { TlsCryptoProvider::from_name(one) } else { None }) else {
        return "'set ssl crypto-provider' expects 'ring' or 'ring-alcyon'.".to_string();
    };
    let was = alcyon_tls::provider::active();
    match alcyon_tls::provider::swap(p) {
        Ok(n) => format!("Crypto provider is now '{}' for new handshakes ({n} TLS configurations built for it).", p.name()),
        Err(e) => format!("Crypto provider unchanged ('{}'): {e}", was.name()),
    }
}

/// `show ssl crypto-provider`: the provider new handshakes use, and the handshakes completed on
/// each provider since start (front and back, health checks included).
#[must_use]
pub fn show() -> String {
    use std::fmt::Write;
    let mut out = format!("current {}", alcyon_tls::provider::active().name());
    for p in TlsCryptoProvider::ALL {
        let _ = write!(out, "\nprovider {} handshakes {}", p.name(), alcyon_tls::provider::handshakes(p));
    }
    out
}
