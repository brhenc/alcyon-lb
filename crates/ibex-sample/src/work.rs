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
    /// A [`crate::registry::SampleContext`] copied.
    CtxClone = 1,
    /// An expression looked up by its text ([`crate::expr::Expr::cached`]).
    ExprLookup = 2,
    /// The server connection counts read through the `RwLock`-guarded map (a server the
    /// pool's dense table does not cover).
    IdleLock = 3,
    /// A server's idle list looked up by hashing `(backend, server)`.
    IdleHash = 4,
}

const OPS: usize = 5;

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

/// A field of [`crate::registry::SampleContext`] that counts the context's copies: its
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
