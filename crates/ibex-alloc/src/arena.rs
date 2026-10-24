// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `Arena<T>`: the index pools (session, applet, task) that sit beside [`crate::Pool`]
//! (`docs/design/memory-2026-10-24.md` 3.7).
//!
//! An arena is a `Vec` of slots addressed by index, pre-sized to `maxconn` (its *floor*, never
//! given back), owned by one engine thread. Three things are shared with the box pools:
//!
//! * `show pools` lists it through [`ArenaStats`], registered with the same
//!   [`crate::PoolRegistry`]; `used` is the slots in use, `cached` those that exist and are free.
//! * the fast path writes nothing another thread reads: the arena keeps plain counters and the
//!   owner publishes them once per loop pass ([`ArenaStats::publish`]);
//! * burst capacity (slots above the last one in use, and the pages a burst made resident) is
//!   given back **only by `pool_gc`**, through [`Arena::compact`]; a close never shrinks it
//!   (Q2: keep the peak, as `HAProxy`).
//!
//! Growth beyond the pre-size is fallible ([`grow_for_one`]): the caller refuses the connection.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{PoolHead, PoolReg};

/// What `pool_gc` asks of an arena.
pub trait Arena<T> {
    /// Slots that exist (in use or free).
    fn slots(&self) -> usize;
    /// Slots in use.
    fn live(&self) -> usize;
    /// Gives back the burst capacity: the free slots after the last one in use, and the
    /// capacity above the creation one. Returns the slots released. Never fails the process:
    /// when the fresh buffer cannot be had, the arena keeps the one it has and counts it.
    fn compact(&mut self) -> usize;
}

/// Process-wide counters of the arenas of one kind, summed over the workers; what `show pools`
/// prints. The arenas never read it and write it only through [`Self::publish`].
pub struct ArenaStats {
    reg: PoolReg,
    allocated: AtomicUsize,
    used: AtomicUsize,
    failures: AtomicUsize,
    compact_skipped: AtomicUsize,
}

/// What one arena has published, so it adds only the difference.
#[derive(Debug, Default, Clone, Copy)]
pub struct Published {
    slots: usize,
    live: usize,
}

impl ArenaStats {
    #[must_use]
    pub const fn new(name: &'static str, size: usize, align: usize, file: &'static str, line: u32) -> Self {
        Self {
            reg: PoolReg { name, size, flags: 0, align, file, line },
            allocated: AtomicUsize::new(0),
            used: AtomicUsize::new(0),
            failures: AtomicUsize::new(0),
            compact_skipped: AtomicUsize::new(0),
        }
    }

    /// Adds the change since the last call (once per loop pass, and only when something moved).
    #[inline]
    pub fn publish(&self, last: &mut Published, slots: usize, live: usize) {
        if last.slots != slots || last.live != live {
            self.publish_slow(last, slots, live);
        }
    }

    #[cold]
    #[inline(never)]
    fn publish_slow(&self, last: &mut Published, slots: usize, live: usize) {
        self.allocated.fetch_add(slots.wrapping_sub(last.slots), Ordering::Relaxed);
        self.used.fetch_add(live.wrapping_sub(last.live), Ordering::Relaxed);
        *last = Published { slots, live };
    }

    /// The arena goes away: takes its published share back.
    pub fn retire(&self, last: &mut Published) {
        self.publish(last, 0, 0);
    }

    /// A slot could not be had (the fallible grow, [`grow_for_one`]).
    pub fn failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A compaction skipped for want of memory for the fresh buffer (T453).
    pub fn skipped(&self) {
        self.compact_skipped.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn compactions_skipped(&self) -> usize {
        self.compact_skipped.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn failures(&self) -> usize {
        self.failures.load(Ordering::Relaxed)
    }

    /// The pool as `show pools` prints it.
    #[must_use]
    pub fn head(&self) -> PoolHead {
        let allocated = self.allocated.load(Ordering::Relaxed);
        let live = self.used.load(Ordering::Relaxed).min(allocated);
        PoolHead {
            name: self.reg.name,
            size: self.reg.size,
            align: self.reg.align,
            allocated,
            alloc_bytes: allocated * self.reg.size,
            used: live,
            cached: allocated - live,
            needed_avg: 0,
            failures: self.failures.load(Ordering::Relaxed),
            users: 1,
            reg: Some(self.reg.clone()),
        }
    }
}

/// Makes room for one more slot without the infallible growth of `push`, and for its index in
/// `free` when it is freed (a close must not allocate): `false`, with both vectors usable as
/// before, when the allocator refuses. The check on the fast path is one compare.
#[inline]
pub fn grow_for_one<T>(entries: &mut Vec<T>, free: &mut Vec<u32>) -> bool {
    entries.len() < entries.capacity() || grow_slots(entries, free)
}

#[cold]
#[inline(never)]
fn grow_slots<T>(entries: &mut Vec<T>, free: &mut Vec<u32>) -> bool {
    if entries.try_reserve(1).is_err() {
        return false;
    }
    let want = entries.capacity().saturating_sub(free.len());
    free.try_reserve(want).is_ok()
}

/// Moves `entries` to a fresh buffer of `cap` slots and frees the old one; `false`, leaving
/// `entries` as it was, when the fresh buffer cannot be had. Giving memory back must not
/// cost the process: `Vec::with_capacity` aborts on a failed allocation, `try_reserve_exact`
/// on an empty `Vec` reports it (T453).
pub fn move_to_fresh<T>(entries: &mut Vec<T>, cap: usize) -> bool {
    let mut fresh = Vec::new();
    if fresh.try_reserve_exact(cap.max(entries.len())).is_err() {
        return false;
    }
    fresh.append(entries);
    *entries = fresh;
    true
}

/// The compaction of an `Option` slot arena: pops the free slots at the end, drops the stale
/// indices from `free`, and when anything went (or `peak` says a burst wrote slots that stay
/// resident when only the length goes down) moves the live slots to a fresh buffer of the
/// creation capacity `floor`. Returns the slots released.
pub fn compact_slots<T>(
    entries: &mut Vec<Option<T>>,
    free: &mut Vec<u32>,
    live: usize,
    floor: usize,
    peak: &mut usize,
    stats: &ArenaStats,
) -> usize {
    let before = entries.len();
    while matches!(entries.last(), Some(None)) {
        entries.pop();
    }
    let cut = before - entries.len();
    if live == 0 {
        free.clear();
    } else {
        let len = entries.len();
        free.retain(|&i| (i as usize) < len);
    }
    let cap = floor.max(entries.len());
    if cap < entries.capacity() || *peak > entries.len() {
        if move_to_fresh(entries, cap) {
            *peak = entries.len();
        } else {
            stats.skipped();
        }
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    static S: ArenaStats = ArenaStats::new("t", 10, 8, "t.rs", 1);

    #[test]
    fn publish_adds_only_the_difference_and_retire_takes_it_back() {
        let st = ArenaStats::new("t", 10, 8, "t.rs", 1);
        let (mut a, mut b) = (Published::default(), Published::default());
        st.publish(&mut a, 3, 2);
        st.publish(&mut b, 4, 1);
        let h = st.head();
        assert_eq!((h.allocated, h.alloc_bytes, h.used, h.cached, h.size), (7, 70, 3, 4, 10));
        st.publish(&mut a, 1, 0);
        let h = st.head();
        assert_eq!((h.allocated, h.used, h.cached), (5, 1, 4));
        st.retire(&mut a);
        st.retire(&mut b);
        let h = st.head();
        assert_eq!((h.allocated, h.used, h.cached), (0, 0, 0));
        st.failed();
        st.skipped();
        assert_eq!((st.head().failures, st.failures(), st.compactions_skipped()), (1, 1, 1));
    }

    #[test]
    fn compact_slots_pops_the_tail_and_the_stale_free_indices() {
        let mut v: Vec<Option<u8>> = Vec::with_capacity(8);
        v.extend([Some(1), None, Some(2), None, None]);
        let mut free = vec![1u32, 3, 4];
        let mut peak = 5;
        let n = compact_slots(&mut v, &mut free, 2, 4, &mut peak, &S);
        assert_eq!((n, v.len(), free.clone(), peak), (2, 3, vec![1], 3));
        assert_eq!(v.capacity(), 4, "the creation capacity, in a fresh buffer");
        let mut e: Vec<Option<u8>> = vec![None, None];
        let mut free = vec![0u32, 1];
        let mut peak = 2;
        assert_eq!(compact_slots(&mut e, &mut free, 0, 0, &mut peak, &S), 2);
        assert!(e.is_empty() && free.is_empty());
    }

    #[test]
    fn grow_for_one_reserves_or_reports() {
        let (mut v, mut free): (Vec<u8>, Vec<u32>) = (Vec::new(), Vec::new());
        assert!(grow_for_one(&mut v, &mut free));
        assert!(v.capacity() >= 1 && free.capacity() >= v.capacity(), "a close has room for its index");
        v.push(1);
        v.reserve_exact(3);
        assert!(grow_for_one(&mut v, &mut free), "room left: nothing to do");
    }
}
