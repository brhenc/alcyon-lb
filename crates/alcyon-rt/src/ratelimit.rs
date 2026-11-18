// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 The Alcyon authors
//
//! The per-process per-second rate limits: `global.cps_lim`, `global.sps_lim` and
//! `global.ssl_lim` (src/global-t.h), set at load by `maxconnrate` / `maxsessrate` /
//! `maxsslrate` (src/cfgparse-global.c) and at run time by `set rate-limit
//! connections|sessions|ssl-sessions global` (src/cli.c). A value of 0 is no limit, as in
//! `HAProxy`; a non-zero value is the ceiling the listeners must not pass per second.
//!
//! `show info` reads them for its `ConnRateLimit` / `SessRateLimit` / `SslRateLimit` lines
//! (src/stats.c), printing the signed value, so they are stored signed like `HAProxy`'s
//! `int`. The accept loop reads [`active`] first: with every limit 0 it is one load and the
//! loop does nothing else (the default configuration pays nothing per accept).

use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

static CONNS: AtomicI32 = AtomicI32::new(0);
static SESS: AtomicI32 = AtomicI32::new(0);
static SSL: AtomicI32 = AtomicI32::new(0);
/// Which limits are non-zero: bit 0 connections, bit 1 sessions, bit 2 SSL sessions. Recomputed
/// on every set so the accept loop can tell "no limit" with a single load.
static ACTIVE: AtomicU8 = AtomicU8::new(0);

/// The non-zero bits of the three limits, as the setters leave them.
fn recompute() -> u8 {
    let mut a = 0u8;
    if CONNS.load(Ordering::Relaxed) != 0 {
        a |= 1;
    }
    if SESS.load(Ordering::Relaxed) != 0 {
        a |= 2;
    }
    if SSL.load(Ordering::Relaxed) != 0 {
        a |= 4;
    }
    a
}

pub fn set_conns(v: i32) {
    CONNS.store(v, Ordering::Relaxed);
    ACTIVE.store(recompute(), Ordering::Relaxed);
}

pub fn set_sess(v: i32) {
    SESS.store(v, Ordering::Relaxed);
    ACTIVE.store(recompute(), Ordering::Relaxed);
}

pub fn set_ssl(v: i32) {
    SSL.store(v, Ordering::Relaxed);
    ACTIVE.store(recompute(), Ordering::Relaxed);
}

/// The non-zero limit bits (0 when no limit is set).
#[must_use]
pub fn active() -> u8 {
    ACTIVE.load(Ordering::Relaxed)
}

pub fn conns() -> i32 {
    CONNS.load(Ordering::Relaxed)
}

pub fn sess() -> i32 {
    SESS.load(Ordering::Relaxed)
}

pub fn ssl() -> i32 {
    SSL.load(Ordering::Relaxed)
}

/// `freq_ctr_remain` (include/haproxy/freq_ctr.h): the events still allowed in the
/// trailing second, `0` when the limit is reached. The oracle accepts a negative limit
/// (measured: `maxconnrate -1` loads, `show info` prints the unsigned value
/// `4294967295`) and its `freq` parameter is unsigned, so a negative one reads huge:
/// no limit, like `0`.
#[must_use]
pub fn remain(lim: i32, rate: u64) -> u64 {
    if lim <= 0 {
        u64::MAX
    } else {
        (lim as u64).saturating_sub(rate)
    }
}
