// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Spare strings and header lists per thread (T437, S1): a fetch takes its sample's string
//! here, and whoever is done with a sample gives the string back, so the samples of a steady
//! stream of requests reuse the same few strings instead of allocating new ones. The header
//! lists of the rules (`ibex_rt::reuse::PPairs`) are kept here too.
//!
//! Both are `ibex_alloc::Pool`s (`show pools` `spare_str`, `spare_list`): bounded by the
//! thread's `tune.memory.hot-size` budget together with every other pool, wiped when given
//! back under `tune.ibex.zero-spares`, emptied by `pool_gc`. At most [`SPARE_MAX`] strings
//! of at most [`KEEP_MAX`] bytes, and [`LISTS_MAX`] lists of at most [`LIST_KEEP_MAX`] entries.
//! The strings are handed out as plain `String`s ([`ibex_alloc::Pool::take_raw`]): they live
//! in samples, and leave the pool's count until they are given back.

use ibex_alloc::{declare_pool, PoolSpec, Poolable};

use crate::sample::Sample;

/// The spare strings kept per thread, at most.
pub const SPARE_MAX: usize = 512;
/// A string larger than this is let go rather than kept.
pub const KEEP_MAX: usize = 16 * 1024;
/// The spare header lists kept per thread, at most.
pub const LISTS_MAX: usize = 16;
/// A header list with room for more entries than this is let go rather than kept.
pub const LIST_KEEP_MAX: usize = 1024;
/// The least capacity a new string starts with, so that a reused one is seldom grown.
const MIN_CAP: usize = 64;
/// The bytes of one header list entry.
const PAIR: usize = std::mem::size_of::<(String, String)>();

declare_pool!(
    /// `show pools` `spare_str`.
    pub static SPARE_STR: Pool<String> = PoolSpec::new("spare_str").max_item(KEEP_MAX).max_count(SPARE_MAX).spares();
);

declare_pool!(
    /// `show pools` `spare_list`.
    pub static SPARE_LIST: Pool<PairList> = PoolSpec::new("spare_list").max_item(LIST_KEEP_MAX * PAIR).max_count(LISTS_MAX).spares();
);

/// A header list as the pool keeps it; its strings go back to [`SPARE_STR`] when it is.
#[derive(Debug, Default)]
pub struct PairList(pub Vec<(String, String)>);

impl Poolable for PairList {
    #[inline]
    fn footprint(&self) -> usize {
        self.0.capacity() * PAIR
    }
    #[inline]
    fn reset(&mut self, _wipe: bool) {
        // Each string is wiped by its own give.
        for (k, v) in self.0.drain(..) {
            give(k);
            give(v);
        }
    }
    #[inline]
    fn keep(&self, max_footprint: usize) -> bool {
        self.0.capacity() != 0 && self.footprint() <= max_footprint
    }
    fn try_new() -> Option<Self> {
        Some(PairList(Vec::new()))
    }
}

fn new_string() -> Option<String> {
    let mut s = String::new();
    s.try_reserve_exact(MIN_CAP).ok()?;
    Some(s)
}

/// An empty string, a spare one when there is one (an empty one with no capacity when memory
/// is short).
///
/// Not inlined, nor is [`give`]: the pool's take and give are inlined here, where the pool is
/// a known static and its thread-local cache is reached directly (an inlined copy at each
/// caller is code size; a call into a non-inlined `Pool` method reached the cache through
/// the `LocalKey`'s function pointer, ~800 instructions per request on the rules scenario).
#[must_use]
#[inline(never)]
pub fn string() -> String {
    SPARE_STR.take_raw(new_string).unwrap_or_default()
}

/// `src` in a [`string`].
#[must_use]
pub fn string_from(src: &str) -> String {
    let mut s = string();
    s.push_str(src);
    s
}

/// Gives `s` back for a later [`string`]: wiped when `tune.ibex.zero-spares` is on, whether
/// it is kept or freed.
#[inline(never)]
pub fn give(s: String) {
    // An empty one (a `mem::take`n field) has nothing to give: not even the pool's checks.
    if s.capacity() != 0 {
        SPARE_STR.give(s);
    }
}

/// Gives back the string of a text sample; any other sample is dropped.
pub fn give_sample(smp: Sample) {
    if let Sample::Str(s) = smp {
        give(s);
    }
}

/// An empty header list, a spare one when there is one.
#[must_use]
#[inline]
pub fn list() -> Vec<(String, String)> {
    SPARE_LIST.take_raw(PairList::try_new).map(|l| l.0).unwrap_or_default()
}

/// Gives back a header list, its strings given back first.
#[inline]
pub fn give_list(l: Vec<(String, String)>) {
    if l.capacity() != 0 {
        SPARE_LIST.give(PairList(l));
    }
}

/// Lists the spare pools in `show pools` from the start.
pub fn register_pools() {
    SPARE_STR.register();
    SPARE_LIST.register();
}

/// The bytes this thread keeps in spare strings and lists.
#[must_use]
pub fn thread_bytes() -> usize {
    SPARE_STR.local_bytes() + SPARE_LIST.local_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A string given back is the next one handed out, emptied, with its capacity.
    #[test]
    fn a_given_string_is_handed_out_again() {
        let mut s = string_from("abc");
        s.push_str(&"d".repeat(200));
        let cap = s.capacity();
        give_sample(Sample::Str(s));
        let t = string();
        assert_eq!(t.len(), 0);
        assert_eq!(t.capacity(), cap);
    }

    /// The give's fast path (the cache's `Vec` has room) empties the string as the slow one
    /// does: a run of gives, then as many takes, all come back empty.
    #[test]
    fn strings_given_in_a_run_come_back_empty() {
        let _ = ibex_alloc::drain_local_pools();
        for i in 0..8 {
            give(string_from(&format!("value-{i}")));
        }
        for _ in 0..8 {
            assert_eq!(string(), "");
        }
    }

    /// A list given back keeps its capacity, its strings go to the spare strings.
    #[test]
    fn a_given_list_gives_its_strings_back() {
        let _ = ibex_alloc::drain_local_pools();
        let mut l = list();
        l.push((string_from("a"), string_from("b")));
        let cap = l.capacity();
        give_list(l);
        assert_eq!(SPARE_STR.local_count(), 2);
        assert_eq!(thread_bytes(), cap * PAIR + 2 * MIN_CAP);
        assert_eq!(list().capacity(), cap);
    }
}
