// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The rustls crypto provider TLS over TCP runs on (T460, `tune.ibex.crypto-provider`).
//!
//! Two providers are linked: upstream ring (`rustls-ring`, the default) and the ring fork that
//! wipes key material when it is freed (`vendor/ringibex` with its `zeroize` feature, through
//! `vendor/rustls-ringibex`). Every `ServerConfig` and `ClientConfig` of [`crate::tcp`] (binds,
//! server lines, health checks) gets its provider from [`of`]; a configuration remembers the
//! provider it was built on. [`active`] is the one new configurations are built on: set at
//! startup from the configuration, before any is built.
//!
//! QUIC and the 0.23 configurations of [`crate::config`] (log-forward TLS binds, ring servers)
//! are on rustls 0.23, which `rustls-ringibex` does not serve: the engine refuses `ring-ibex`
//! with any of them instead of letting them run on vanilla ring unsaid.

use ibex_config::TlsCryptoProvider;
use rustls24::crypto::CryptoProvider;
use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

static ACTIVE: AtomicU8 = AtomicU8::new(0);

const fn index(p: TlsCryptoProvider) -> u8 {
    match p {
        TlsCryptoProvider::Ring => 0,
        TlsCryptoProvider::RingIbex => 1,
    }
}

/// The provider new TCP TLS configurations are built on.
#[must_use]
pub fn active() -> TlsCryptoProvider {
    TlsCryptoProvider::ALL[usize::from(ACTIVE.load(Ordering::Relaxed))]
}

/// Sets the provider new TCP TLS configurations are built on.
pub fn set_active(p: TlsCryptoProvider) {
    ACTIVE.store(index(p), Ordering::Relaxed);
}

/// Handshakes completed on each provider since start, front and back (`show ssl crypto-provider`).
static HANDSHAKES: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Counts a handshake completed on provider `p`. Once per TLS connection, as `CumSslConns` is
/// counted (`stats::SslConnCount`); nothing per request.
pub fn count_handshake(p: TlsCryptoProvider) {
    HANDSHAKES[usize::from(index(p))].fetch_add(1, Ordering::Relaxed);
}

/// The handshakes completed on provider `p` since start.
#[must_use]
pub fn handshakes(p: TlsCryptoProvider) -> u64 {
    HANDSHAKES[usize::from(index(p))].load(Ordering::Relaxed)
}

/// The whole provider `p`, both TLS versions.
const fn base(p: TlsCryptoProvider) -> CryptoProvider {
    match p {
        TlsCryptoProvider::Ring => rustls24_ring::DEFAULT_PROVIDER,
        TlsCryptoProvider::RingIbex => rustls24_ringibex::DEFAULT_PROVIDER,
    }
}

/// Provider `p`, speaking the versions `tls12` and `tls13` allow: a provider with no suites of
/// a version does not speak it (rustls 0.24 has no `with_protocol_versions`).
#[must_use]
pub fn of(p: TlsCryptoProvider, tls12: bool, tls13: bool) -> Arc<CryptoProvider> {
    let mut c = base(p);
    if !tls12 {
        c.tls12_cipher_suites = Cow::Borrowed(&[]);
    }
    if !tls13 {
        c.tls13_cipher_suites = Cow::Borrowed(&[]);
    }
    Arc::new(c)
}

/// The ticket-key factory of provider `p`: a session ticket is sealed by the provider of the
/// configuration that issued it.
pub(crate) fn ticketer(p: TlsCryptoProvider) -> Result<Arc<dyn rustls24::crypto::TicketProducer>, rustls24::Error> {
    base(p).ticketer_factory.ticketer()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_is_active_until_set_and_each_index_names_its_provider() {
        for p in TlsCryptoProvider::ALL {
            assert_eq!(TlsCryptoProvider::ALL[usize::from(index(p))], p);
        }
        assert_eq!(active(), TlsCryptoProvider::Ring);
    }
}
