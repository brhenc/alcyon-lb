// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Counts of the per-request operations the rules path is held to (S7,
//! `docs/design/memory-2026-10-24.md` §1.3), on this thread: a test reads them around a batch of
//! requests and pins how many of each a request costs. They are plain thread-local counters
//! (an increment, no shared memory), always on, so the release build the instruction counts
//! are measured on does the same work.

use std::cell::Cell;

/// One kind of operation counted.
#[derive(Clone, Copy, Debug)]
pub enum Op {
    /// The request head written out of its HTX into the request buffer again.
    ReqRebuild = 0,
    /// A [`crate::registry::PhaseCtx`] copied (the per-rule [`crate::registry::SampleContext`] is two references, `Copy`, and not counted).
    CtxClone = 1,
    /// An expression looked up by its text ([`crate::expr::Expr::cached`]).
    ExprLookup = 2,
    /// The server connection counts read through the `RwLock`-guarded map (a server the
    /// pool's dense table does not cover).
    IdleLock = 3,
    /// A server's idle list looked up by hashing `(backend, server)`.
    IdleHash = 4,
    /// The round-robin trees compared with every server's weight and state (`Fwrr::sync`).
    LbSync = 5,
    /// A housekeeping concern of the engine run (idle purge, buffer trim, stick-table
    /// expiry): counted in debug builds only (L1).
    Housekeeping = 6,
    /// A pass of the engine loop (`step_at`): counted in debug builds only (L1, L2).
    Pass = 7,
    /// A stream run's context built from the configuration instead of kept: the timeouts
    /// the `*_timeout` fetches read converted from the proxies' settings, the capture slots'
    /// table (`Arc`) cloned. Counted in debug builds only (L3).
    RunSetup = 8,
    /// A stream run that looked at its timers (`check_timeouts`): counted in debug builds
    /// only (L3, T586).
    TimeoutCheck = 9,
    /// The sample context the `track-sc` rules of `http-request` read, built for a request:
    /// counted in debug builds only (T584). A proxy without such a rule builds none.
    TrackCtx = 10,
    /// A run of a stream (`step_stream_run`, an HTTP/3 owner's excepted): counted in debug
    /// builds only (T599).
    StreamRun = 11,
    /// What one side of a stream wants from the poller derived (`update_interests`): counted
    /// in debug builds only (T599). A side with no socket of its own derives nothing.
    WantDerive = 12,
    /// The rare checks of a stream run (connect log, rate max, deferred session rules, TCP
    /// inspection, ...) looked at: counted in debug builds only (T599). Not when none is armed.
    RareCheck = 13,
    /// The engine's dispatcher built: counted in debug builds only (T599). Once an engine.
    DispatcherBuild = 14,
    /// An HTTP/3 owner woken for the pass it is in by its stream (run or release): counted in
    /// debug builds only (T614b). One of the two wakes was a pass late before L2.
    H3OwnerWakeNow = 15,
}

const OPS: usize = 16;

thread_local! {
    static COUNTS: [Cell<u64>; OPS] = const { [const { Cell::new(0) }; OPS] };
}

/// Counts `n` of `op` on this thread.
#[inline]
pub fn note(op: Op, n: u64) {
    COUNTS.with(|c| {
        let c = &c[op as usize];
        c.set(c.get().wrapping_add(n));
    });
}

/// The counts on this thread so far, indexed by [`Op`].
#[must_use]
pub fn on_this_thread() -> [u64; OPS] {
    COUNTS.with(|c| std::array::from_fn(|i| c[i].get()))
}

/// A field of [`crate::registry::PhaseCtx`] that counts the context's copies: its
/// `Clone` is the context's.
#[derive(Debug, Default)]
pub struct CloneCount;

impl Clone for CloneCount {
    #[inline]
    fn clone(&self) -> Self {
        note(Op::CtxClone, 1);
        Self
    }
}
