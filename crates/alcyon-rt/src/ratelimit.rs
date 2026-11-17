// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 The Alcyon authors
//
//! The process-wide rate limits `set rate-limit` changes at run time (HAProxy's
//! `global.cps_lim`, `global.sps_lim`, `global.ssl_lim` and `global.comp_rate_lim`, set
//! from `cli_parse_set_ratelimit`, src/cli.c). They start at 0, as `global` without
//! `maxconnrate`/`maxsessrate` leaves them, and `show info` reads the first two for its
//! `ConnRateLimit`/`SessRateLimit` lines (src/stats.c).

use std::sync::atomic::{AtomicU32, Ordering};

static CONNS: AtomicU32 = AtomicU32::new(0);
static SESS: AtomicU32 = AtomicU32::new(0);
static SSL: AtomicU32 = AtomicU32::new(0);
/// The compression-speed limit, in B/s: the command's kB/s value times 1024, as in HAProxy.
static COMP: AtomicU32 = AtomicU32::new(0);

pub fn set_conns(v: u32) {
    CONNS.store(v, Ordering::Relaxed);
}

pub fn set_sess(v: u32) {
    SESS.store(v, Ordering::Relaxed);
}

pub fn set_ssl(v: u32) {
    SSL.store(v, Ordering::Relaxed);
}

pub fn set_comp_kbs(v: u32) {
    COMP.store(v.saturating_mul(1024), Ordering::Relaxed);
}

pub fn conns() -> u32 {
    CONNS.load(Ordering::Relaxed)
}

pub fn sess() -> u32 {
    SESS.load(Ordering::Relaxed)
}

pub fn ssl() -> u32 {
    SSL.load(Ordering::Relaxed)
}
