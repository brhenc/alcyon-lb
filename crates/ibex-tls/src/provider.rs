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
//! The swap at run time (`set ssl crypto-provider`, [`swap`]): every configuration built from
//! the configuration file is [`register`]ed. A swap builds each of them again on the new
//! provider (reading its certificate files again), and only when all of them are built does it
//! publish them and make the new provider [`active`]: a failure changes nothing. A handshake
//! reads [`active`] when it starts (an atomic load, the swap's only cost per connection) and
//! takes its configuration's build for that provider; a connection already open keeps the one
//! it started with. A configuration keeps both builds once it has them: swapping back reuses
//! the first, and nothing is built twice. Session tickets and session IDs are per build (the
//! ticket keys are the provider's): a session from before a swap resumes no more, and the
//! client gets a full handshake instead.
//!
//! QUIC and the 0.23 configurations of [`crate::config`] (log-forward TLS binds, ring servers)
//! are on rustls 0.23, which `rustls-ringibex` does not serve: the engine refuses `ring-ibex`
//! with any of them instead of letting them run on vanilla ring unsaid.

use ibex_config::TlsCryptoProvider;
use rustls24::crypto::CryptoProvider;
use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

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

/// What publishes a configuration built for a swap; run once every one is built.
pub type Publish = Box<dyn FnOnce() + Send>;

/// A TLS configuration a swap can build on another provider.
pub trait Rebuild: Send + Sync {
    /// Builds this configuration on `p`, unless it is built on `p` already (`Ok(None)`). It is
    /// not used until the returned [`Publish`] runs.
    ///
    /// # Errors
    /// What the configuration does not build with on `p`, naming it.
    fn prepare(self: Arc<Self>, p: TlsCryptoProvider) -> Result<Option<Publish>, String>;
}

/// The configurations a swap builds again. Weak: a configuration dropped (a `-c` check's, a
/// test's) is skipped and forgotten.
struct Registry {
    live: Vec<Weak<dyn Rebuild>>,
    /// Entries after the last sweep of the dropped ones: sweeps when the list has doubled.
    swept: usize,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry { live: Vec::new(), swept: 0 });

/// Registers a configuration built from the configuration file, for [`swap`].
pub fn register(c: Weak<dyn Rebuild>) {
    let mut r = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
    if r.live.len() >= 2 * r.swept.max(32) {
        r.live.retain(|w| w.strong_count() > 0);
        r.swept = r.live.len();
    }
    r.live.push(c);
}

/// Makes `p` the provider of the handshakes that start from now on, after building every
/// registered configuration on it. The number built.
///
/// # Errors
/// The first configuration that does not build on `p`: then nothing is published and the
/// provider is unchanged.
pub fn swap(p: TlsCryptoProvider) -> Result<usize, String> {
    // Held throughout: two swaps at once are one after the other.
    let mut r = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
    r.live.retain(|w| w.strong_count() > 0);
    r.swept = r.live.len();
    let mut publish = Vec::new();
    for c in r.live.iter().filter_map(Weak::upgrade) {
        if let Some(f) = c.prepare(p)? {
            publish.push(f);
        }
    }
    let built = publish.len();
    for f in publish {
        f();
    }
    set_active(p);
    Ok(built)
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
    fn each_index_names_its_provider() {
        for p in TlsCryptoProvider::ALL {
            assert_eq!(TlsCryptoProvider::ALL[usize::from(index(p))], p);
        }
    }

    struct Gone;

    impl Rebuild for Gone {
        fn prepare(self: Arc<Self>, _: TlsCryptoProvider) -> Result<Option<Publish>, String> {
            Ok(None)
        }
    }

    /// Configurations dropped (a `-c` check's) do not pile up: the list is swept of them once it
    /// has doubled since the last sweep.
    #[test]
    fn dropped_configurations_are_swept_from_the_registry() {
        for _ in 0..200 {
            register(Weak::<Gone>::new());
        }
        let r = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(r.live.len() <= 64, "{} entries kept", r.live.len());
        drop(r);
        // A live one would have been asked to rebuild; `Gone` has nothing to publish.
        assert!(Arc::new(Gone).prepare(TlsCryptoProvider::ALL[0]).unwrap().is_none());
    }
}
