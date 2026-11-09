// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.memory.prealloc on` (T468, Alcyon extension; `docs/design/memory-2026-10-24.md` Q1 and
//! 10): the pools sized from `maxconn` at start instead of grown on demand.
//!
//! What `maxconn` implies, per worker thread, `share = ceil(maxconn / nbthread)`:
//! * the standard `buffer` pool: `2 * maxconn` buffers in the process (request and response
//!   buffer, as `-m`'s arithmetic counts a connection, `globalconn::memmax_maxconn`), the
//!   smaller `tune.buffers.limit` when one is set; each thread fills its cache with its
//!   share, as floor objects (no `tune.memory.hot-size` eviction, kept by `pool_gc`), and the
//!   pool's limit is that total: a take past it is S5's refusal (the stream fails);
//! * the `session` arena: `share` slots made at start. It still grows, fallibly, past them:
//!   HTTP/2 streams take session slots too and `maxconn` does not bound them.
//!
//! The load refuses it without an explicit global `maxconn` or `-m` ([`check`]); each worker
//! fills its own pools in `Engine::new_worker` ([`plan`]).

use alcyon_config::ast::Config;

/// What the pools are sized to, per worker thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// Session slots this thread makes at start.
    pub sessions: usize,
    /// Standard buffers this thread's cache holds at start.
    pub buffers: usize,
    /// The process's limit on standard buffers (`tune.buffers.limit` semantics).
    pub buffers_limit: usize,
}

fn enabled(config: &Config) -> bool {
    config.global.as_ref().and_then(|g| g.memory_prealloc).unwrap_or(false)
}

/// Bytes the pools take for `maxconn` connections: two buffers and a session slot each.
fn implied_bytes(maxconn: u64, bufsize: u64) -> u64 {
    let slot = std::mem::size_of::<Option<crate::engine::SessionEntry>>() as u64;
    maxconn.saturating_mul(2 * bufsize + slot)
}

/// The load's check, before `-m` sizes `maxconn` (so under `-c` too): `memmax_mb` is `-m`.
///
/// # Errors
/// The alert the load exits 1 with.
pub fn check(config: &Config, memmax_mb: Option<u64>) -> Result<(), String> {
    if !enabled(config) {
        return Ok(());
    }
    let g = config.global.as_ref();
    let maxconn = g.and_then(|g| g.maxconn);
    match (maxconn, memmax_mb) {
        (None, None) => Err("'tune.memory.prealloc' needs an explicit global 'maxconn' or '-m' to size the pools.".into()),
        (Some(mc), Some(megs)) => {
            let bufsize = g.and_then(|g| g.bufsize).map_or(16384, |b| b as u64);
            let need = implied_bytes(u64::from(mc), bufsize);
            if need > megs.saturating_mul(1_048_576) {
                return Err(format!(
                    "'tune.memory.prealloc': maxconn {mc} needs {} MB of pools, more than the {megs} MB of '-m'.",
                    need.div_ceil(1_048_576)
                ));
            }
            Ok(())
        }
        // Without `maxconn`, `-m` computes one that fits it (`engine::apply_memmax`).
        _ => Ok(()),
    }
}

/// What this worker fills, from the `maxconn` the start settled (`-m` applied) and `nbthread`
/// (`stats::NBTHREAD`); `None` when the setting is off.
#[must_use]
pub fn plan(config: &Config) -> Option<Plan> {
    if !enabled(config) {
        return None;
    }
    let g = config.global.as_ref()?;
    let maxconn = g.maxconn? as usize;
    let threads = (crate::stats::NBTHREAD.load(std::sync::atomic::Ordering::Relaxed) as usize).max(1);
    let mut limit = maxconn.saturating_mul(2);
    if let Some(l) = g.buffers_limit.filter(|&l| l != 0) {
        limit = limit.min(l);
    }
    Some(Plan { sessions: maxconn.div_ceil(threads), buffers: limit.div_ceil(threads), buffers_limit: limit })
}
