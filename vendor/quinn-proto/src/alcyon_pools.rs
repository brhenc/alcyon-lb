// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Alcyon P1: feature `alcyon-pools`. The per-stream objects quinn creates by the thousand come from
//! `alcyon_alloc` pools (`docs/design/quic-transport-2026-11-01.md` 2.2), so they are counted,
//! bounded by `tune.memory.hot-size` and listed in `show pools`.

use alcyon_alloc::{Pool, PoolBox, Poolable};

/// A pooled object. quinn has no way to refuse an allocation, so a miss the pool refuses (only
/// `tune.fail-alloc` injection does, `-dMfail`) is asked again.
pub(crate) fn take<T: Poolable>(pool: &'static Pool<T>) -> PoolBox<T> {
    for _ in 0..64 {
        if let Some(b) = pool.take() {
            return b;
        }
    }
    panic!("pool {} refused 64 takes in a row", pool.spec().name)
}
