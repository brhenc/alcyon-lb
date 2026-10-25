// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ibex.crypto-provider ring|ring-ibex` (T460, Ibex-only), `set ssl crypto-provider` and
//! `show ssl crypto-provider`.
//!
//! [`apply`] runs before any TLS configuration is built (`validate_tls`, `build_shared_state`)
//! and makes the configured provider [`ibex_tls::provider::active`]: every TCP TLS
//! configuration (binds, server lines, health checks) is built on it from then on, and so is
//! every QUIC bind's (T461: QUIC is on rustls 0.24, `ibex_quic::crypto`). The rustls 0.23
//! users (log-forward TLS binds, ring TLS servers) cannot run on `rustls-ringibex`; with
//! `ring-ibex` and one of them, the configuration is refused rather than half of the TLS
//! running on vanilla ring unsaid (AGENTS.md section 5).
//!
//! [`set`] swaps the provider at run time ([`ibex_tls::provider::swap`]), refused in the same
//! case. It holds for this process: a reload (a new process) starts on the configured provider.

use ibex_config::{Config, LogForwardBind, TlsCryptoProvider};
use std::io;
use std::sync::{Mutex, PoisonError};

/// The TLS user of the running configuration that only vanilla ring serves, if any: what makes
/// `set ssl crypto-provider ring-ibex` refused too.
static RING_ONLY: Mutex<Option<String>> = Mutex::new(None);

fn refusal(user: &str) -> String {
    format!(
        "'tune.ibex.crypto-provider ring-ibex' cannot serve the {user}: it runs on rustls 0.23, \
         which only vanilla ring serves."
    )
}

/// The provider `config` asks for (`ring` when it says nothing).
#[must_use]
pub fn configured(config: &Config) -> TlsCryptoProvider {
    config.global.as_ref().and_then(|g| g.crypto_provider).unwrap_or_default()
}

/// The first TLS user of `config` still on rustls 0.23, named for the error.
fn rustls_023_user(config: &Config) -> Option<String> {
    config
        .log_forwards
        .iter()
        .find_map(|lf| {
            lf.binds.iter().find_map(|b| match b {
                LogForwardBind::Tcp(b) if b.ssl => Some(format!("TLS bind {} in log-forward '{}'", b.addr, lf.name)),
                _ => None,
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
    let user = rustls_023_user(config);
    if p == TlsCryptoProvider::RingIbex {
        if let Some(user) = &user {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} Use 'tune.ibex.crypto-provider ring' or remove it.", refusal(user)),
            ));
        }
    }
    *RING_ONLY.lock().unwrap_or_else(PoisonError::into_inner) = user;
    ibex_tls::provider::set_active(p);
    Ok(())
}

/// `set ssl crypto-provider <name>`: the answer. Every TLS configuration is built on the new
/// provider first; the swap happens only when all of them are, so a failure changes nothing.
#[must_use]
pub fn set(args: &str) -> String {
    let words: Vec<&str> = args.split_whitespace().collect();
    let Some(p) = (if let [one] = words.as_slice() { TlsCryptoProvider::from_name(one) } else { None }) else {
        return "'set ssl crypto-provider' expects 'ring' or 'ring-ibex'.".to_string();
    };
    let was = ibex_tls::provider::active();
    if p == TlsCryptoProvider::RingIbex {
        if let Some(user) = RING_ONLY.lock().unwrap_or_else(PoisonError::into_inner).as_deref() {
            return format!("Crypto provider unchanged ('{}'): {}", was.name(), refusal(user));
        }
    }
    match ibex_tls::provider::swap(p) {
        Ok(n) => format!("Crypto provider is now '{}' for new handshakes ({n} TLS configurations built for it).", p.name()),
        Err(e) => format!("Crypto provider unchanged ('{}'): {e}", was.name()),
    }
}

/// `show ssl crypto-provider`: the provider new handshakes use, and the handshakes completed on
/// each provider since start (front and back, health checks included).
#[must_use]
pub fn show() -> String {
    use std::fmt::Write;
    let mut out = format!("current {}", ibex_tls::provider::active().name());
    for p in TlsCryptoProvider::ALL {
        let _ = write!(out, "\nprovider {} handshakes {}", p.name(), ibex_tls::provider::handshakes(p));
    }
    out
}
