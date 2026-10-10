// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `global maxconn` (T146 item 3): the number of client connections the process holds at
//! once, across every frontend and worker (`actconn`/`global.maxconn` in `HAProxy`).
//!
//! Past it the listeners stop accepting, and the connections wait in the kernel backlog
//! until one closes (`limit_listener(.., &global_listener_queue)`), as with a frontend's
//! own `maxconn`. The stats socket is not counted. State is process-wide, set when an
//! engine is built from a configuration that has a `maxconn`.

use std::sync::atomic::{AtomicU32, Ordering};

static CURR: AtomicU32 = AtomicU32::new(0);
/// The limit in force (`set maxconn global`); 0 is no limit.
static MAX: AtomicU32 = AtomicU32::new(0);
/// What the configuration said (`global.hardmaxconn`): `set maxconn global` stays below it.
static HARD: AtomicU32 = AtomicU32::new(0);

/// The `global.maxconn` `HAProxy` computes for a configuration without one
/// (`compute_ideal_maxconn`): half of what is left of the file descriptors after its own
/// -- 12, one per listener, and 10 for a `stats socket` -- measured on 3.5-dev8-885761-29
/// (it raises the soft limit to the hard one first, and one descriptor is not counted).
#[must_use]
pub fn ideal_maxconn(nofile_hard: Option<u64>, listeners: usize, stats_socket: bool) -> u32 {
    // Unlimited is what the kernel allows a process: `fs.nr_open`'s default.
    let nofile = nofile_hard.unwrap_or(1_048_576);
    let overhead = 12 + listeners as u64 + if stats_socket { 10 } else { 0 };
    u32::try_from((nofile.saturating_sub(1).saturating_sub(overhead)) / 2).unwrap_or(u32::MAX).max(1)
}

/// Called once per engine built from `config`: the limit is the configured `maxconn`, or the
/// one `HAProxy` computes from the file descriptor limit; counting starts from zero when it
/// is configured.
pub fn configure(maxconn: Option<u32>, listeners: usize, stats_socket: bool) {
    let hard_nofile = {
        let l = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        l.maximum
    };
    let v = maxconn.unwrap_or_else(|| ideal_maxconn(hard_nofile, listeners, stats_socket));
    MAX.store(v, Ordering::Relaxed);
    HARD.store(v, Ordering::Relaxed);
    if maxconn.is_some() {
        CURR.store(0, Ordering::Relaxed);
    }
}

/// `global.maxsock` as `HAProxy` computes it (`compute_ideal_maxsock` and the socket
/// eaters before it): 10, one per listener, 10 for the CLI's connections when there is a
/// stats socket, one per server with `check`, two per connection of `maxconn`, and three per
/// thread (a poller and a wake-up pipe). Measured on 3.5-dev8-885761-29 (`show info`
/// `Maxsock`): 225 for `maxconn 100`, `nbthread 1`, one `bind` and a stats socket; 234 with
/// `nbthread 4`; 227 with two checked servers; 4025 for `maxconn 2000`. Pipes (splicing)
/// are not counted: Ibex does not splice.
#[must_use]
pub fn maxsock(maxconn: u32, listeners: usize, stats_socket: bool, checks: usize, nbthread: usize) -> usize {
    let maxconn = usize::try_from(maxconn).unwrap_or(usize::MAX);
    10usize
        .saturating_add(listeners)
        .saturating_add(if stats_socket { 10 } else { 0 })
        .saturating_add(checks)
        .saturating_add(maxconn.saturating_mul(2))
        .saturating_add(nbthread.saturating_mul(3))
}

/// `tune.pool_low_count` and `tune.pool_high_count`: `ratio` percent of `maxsock`, rounded up.
#[must_use]
pub fn pool_count(maxsock: usize, ratio: u8) -> usize {
    maxsock.saturating_mul(usize::from(ratio)).saturating_add(99) / 100
}

/// A client connection was admitted.
pub fn acquire() {
    CURR.fetch_add(1, Ordering::Relaxed);
}

/// Takes a slot if there is one, atomically: false when `global maxconn` is reached.
pub fn try_acquire() -> bool {
    let max = MAX.load(Ordering::Relaxed);
    CURR.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| (max == 0 || c < max).then_some(c + 1)).is_ok()
}

/// A client connection closed.
pub fn release() {
    let _ = CURR.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(1)));
}

/// True when no further connection may be accepted.
#[must_use]
pub fn full() -> bool {
    let max = MAX.load(Ordering::Relaxed);
    max != 0 && CURR.load(Ordering::Relaxed) >= max
}

/// The limit in force, 0 for none.
#[must_use]
pub fn max() -> u32 {
    MAX.load(Ordering::Relaxed)
}

/// The configured limit, 0 for none.
#[must_use]
pub fn hard() -> u32 {
    HARD.load(Ordering::Relaxed)
}

/// `set maxconn global <v>`: above the configured limit is out of range, 0 or less means
/// that limit again (`cli_parse_set_maxconn_global`).
///
/// # Errors
/// `Value out of range.` when `v` is above the configured limit.
pub fn set(v: i64) -> Result<(), &'static str> {
    let hard = hard();
    if hard != 0 && v > i64::from(hard) {
        return Err("Value out of range.");
    }
    let v = if v <= 0 { hard } else { u32::try_from(v).unwrap_or(u32::MAX) };
    MAX.store(v, Ordering::Relaxed);
    Ok(())
}
