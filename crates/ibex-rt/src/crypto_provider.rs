// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ibex.crypto-provider ring|ring-ibex` (T460, Ibex-only) and `show ssl crypto-provider`.
//!
//! [`apply`] runs before any TLS configuration is built (`validate_tls`, `build_shared_state`)
//! and makes the configured provider [`ibex_tls::provider::active`]: every TCP TLS
//! configuration (binds, server lines, health checks) is built on it from then on. QUIC and
//! the rustls 0.23 users (log-forward TLS binds, ring TLS servers) cannot run on
//! `rustls-ringibex`; with `ring-ibex` and one of them, the configuration is refused rather
//! than half of the TLS running on vanilla ring unsaid (AGENTS.md section 5).

use ibex_config::{Config, LogForwardBind, TlsCryptoProvider};
use std::io;

/// The provider `config` asks for (`ring` when it says nothing).
#[must_use]
pub fn configured(config: &Config) -> TlsCryptoProvider {
    config.global.as_ref().and_then(|g| g.crypto_provider).unwrap_or_default()
}

/// The first TLS user of `config` still on rustls 0.23, named for the error.
fn rustls_023_user(config: &Config) -> Option<String> {
    let quic = |name: &str, binds: &[ibex_config::ast::BindConfig]| {
        binds.iter().find(|b| b.quic).map(|b| format!("QUIC bind {} in '{name}'", b.addr))
    };
    config
        .frontends
        .iter()
        .find_map(|f| quic(&f.name, &f.binds))
        .or_else(|| config.listens.iter().find_map(|l| quic(&l.name, &l.binds)))
        .or_else(|| {
            config.log_forwards.iter().find_map(|lf| {
                lf.binds.iter().find_map(|b| match b {
                    LogForwardBind::Tcp(b) if b.ssl => Some(format!("TLS bind {} in log-forward '{}'", b.addr, lf.name)),
                    _ => None,
                })
            })
        })
        .or_else(|| {
            config.rings.iter().find_map(|r| {
                r.servers.iter().find(|s| s.ssl).map(|s| format!("TLS server '{}' in ring '{}'", s.name, r.name))
            })
        })
}

/// Makes the configured provider the one TLS configurations are built on.
///
/// # Errors
/// `ring-ibex` with a TLS user that only vanilla ring can serve.
pub fn apply(config: &Config) -> io::Result<()> {
    let p = configured(config);
    if p == TlsCryptoProvider::RingIbex {
        if let Some(user) = rustls_023_user(config) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "'tune.ibex.crypto-provider ring-ibex' cannot serve the {user}: it runs on rustls 0.23, \
                     which only vanilla ring serves. Use 'tune.ibex.crypto-provider ring' or remove it."
                ),
            ));
        }
    }
    ibex_tls::provider::set_active(p);
    Ok(())
}

/// `show ssl crypto-provider`: the provider new handshakes use, and the handshakes completed on
/// each provider since start (front and back, health checks included).
#[must_use]
pub fn show() -> String {
    use std::fmt::Write;
    let mut out = format!("current {}\n", ibex_tls::provider::active().name());
    for p in TlsCryptoProvider::ALL {
        let _ = writeln!(out, "provider {} handshakes {}", p.name(), ibex_tls::provider::handshakes(p));
    }
    out.push('\n');
    out
}
