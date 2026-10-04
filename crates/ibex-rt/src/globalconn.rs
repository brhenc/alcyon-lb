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

/// Called once per engine built from `config`: a configuration without `maxconn` has no
/// limit, one with it starts counting from zero.
pub fn configure(maxconn: Option<u32>) {
    let v = maxconn.unwrap_or(0);
    MAX.store(v, Ordering::Relaxed);
    HARD.store(v, Ordering::Relaxed);
    if maxconn.is_some() {
        CURR.store(0, Ordering::Relaxed);
    }
}

/// A client connection was admitted.
pub fn acquire() {
    CURR.fetch_add(1, Ordering::Relaxed);
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
