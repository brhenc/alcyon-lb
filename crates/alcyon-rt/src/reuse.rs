// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Per-thread storage the request path reuses instead of allocating (T437).
//!
//! A `String` the rules are done with comes back here, cleared, and the next one taken has the
//! capacity it grew to, so a steady stream of requests through the same rules allocates
//! nothing (the response head's header list this served is HTX blocks since X3b-1). The strings are the
//! sample engine's spares ([`alcyon_sample::spare`], bounded), shared with the fetches.
//!
//! The scratch buffers ([`with_string`], [`with_bytes`]) are taken from their pool for the
//! call and given back after it (cleared, and wiped under `tune.alcyon.zero-spares`), so a call
//! made while one is out (a format rendered while a reply is built) gets another one instead
//! of a borrow error. All of it is `alcyon_alloc::Pool`s (`show pools` `spare_str`, `spare_list`,
//! `scratch_str`, `scratch_bytes`), emptied by `pool_gc`'s walk of the thread's pools.

use alcyon_alloc::{declare_pool, PoolSpec};

/// Calls nest a few deep at most (a format inside a reply inside a rule).
const SCRATCH_MAX: usize = 4;

declare_pool!(
    /// `show pools` `scratch_str`: what [`with_string`] lends. Kept up to `tune.memory.hot-size`.
    static SCRATCH_STR: Pool<String> = PoolSpec::new("scratch_str").max_count(SCRATCH_MAX).spares();
);

declare_pool!(
    /// `show pools` `scratch_bytes`: what [`with_bytes`] lends.
    static SCRATCH_BYTES: Pool<Vec<u8>> = PoolSpec::new("scratch_bytes").max_count(SCRATCH_MAX).spares();
);

pub use alcyon_sample::spare::{give, string, string_from};

/// Lists this module's pools (and the spare strings and lists) in `show pools` from the start.
pub fn register_pools() {
    alcyon_sample::spare::register_pools();
    SCRATCH_STR.register();
    SCRATCH_BYTES.register();
    crate::logfmt::register_pools();
    crate::txnlog::register_pools();
    crate::check::register_pools();
    alcyon_tls::conn::register_pools();
    crate::stats::register_pools();
    crate::proxy::register_pools();
    crate::txn::L7Retry::register_pools();
}

/// A [`string`] that is given back when it is dropped.
#[derive(Debug, Default)]
pub struct PString(String);

impl PString {
    /// An empty one, a spare string when there is one.
    #[must_use]
    pub fn new() -> Self {
        PString(string())
    }

    /// One holding `src`.
    #[must_use]
    pub fn of(src: &str) -> Self {
        PString(string_from(src))
    }
}

impl std::ops::Deref for PString {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

impl std::ops::DerefMut for PString {
    fn deref_mut(&mut self) -> &mut String {
        &mut self.0
    }
}

impl std::fmt::Display for PString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Drop for PString {
    fn drop(&mut self) {
        give(std::mem::take(&mut self.0));
    }
}

/// A short word of a head's first line (the version, the reason): a constant when it is the
/// usual one, else in a spare string, so that the usual response takes no string (X7).
#[derive(Debug)]
pub struct Word {
    usual: Option<&'static str>,
    text: String,
}

impl Word {
    /// The usual word `usual`.
    #[must_use]
    pub const fn usual(usual: &'static str) -> Self {
        Word { usual: Some(usual), text: String::new() }
    }

    /// Now the usual word `usual`.
    pub fn set_usual(&mut self, usual: &'static str) {
        self.usual = Some(usual);
    }

    /// Now `words` with one space between each, in the spare string it has or takes.
    pub fn set_words<'a>(&mut self, words: impl Iterator<Item = &'a str>) {
        self.usual = None;
        if self.text.capacity() == 0 {
            self.text = string();
        }
        self.text.clear();
        for (i, w) in words.enumerate() {
            if i > 0 {
                self.text.push(' ');
            }
            self.text.push_str(w);
        }
    }
}

impl std::ops::Deref for Word {
    type Target = str;
    fn deref(&self) -> &str {
        self.usual.unwrap_or(&self.text)
    }
}

impl std::fmt::Display for Word {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self)
    }
}

impl Drop for Word {
    fn drop(&mut self) {
        give(std::mem::take(&mut self.text));
    }
}

/// A header list whose strings, and the list itself, are given back when it is dropped.
#[derive(Debug, Default)]
pub struct PPairs(Vec<(String, String)>);

impl PPairs {
    /// An empty list, a spare one when there is one.
    #[must_use]
    pub fn new() -> Self {
        PPairs(alcyon_sample::spare::list())
    }
}

impl std::ops::Deref for PPairs {
    type Target = Vec<(String, String)>;
    fn deref(&self) -> &Vec<(String, String)> {
        &self.0
    }
}

impl std::ops::DerefMut for PPairs {
    fn deref_mut(&mut self) -> &mut Vec<(String, String)> {
        &mut self.0
    }
}

impl<'a> IntoIterator for &'a PPairs {
    type Item = &'a (String, String);
    type IntoIter = std::slice::Iter<'a, (String, String)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl Drop for PPairs {
    fn drop(&mut self) {
        alcyon_sample::spare::give_list(std::mem::take(&mut self.0));
    }
}

/// Runs `f` with an empty object of `pool`, given back after.
/// Takes a scratch string from its pool, else a new empty one (and the same for bytes below). Not inlined, nor are the gives:
/// each is instantiated once per pool with the pool a known static, so the pool's take and give
/// are inlined with its thread-local cache reached directly. Generic code holding the pool as
/// a value (a `with_pooled(pool, f)` inlined into each caller) reached the cache through an
/// outlined call and read the pool's limits from memory: ~200 instructions per request on the
/// rules scenario (ab1) for its two `with_string`s.
#[inline(never)]
fn take_str() -> String {
    SCRATCH_STR.take_raw(|| Some(String::new())).unwrap_or_default()
}

#[inline(never)]
fn give_str(s: String) {
    SCRATCH_STR.give(s);
}

#[inline(never)]
fn take_bytes() -> Vec<u8> {
    SCRATCH_BYTES.take_raw(|| Some(Vec::new())).unwrap_or_default()
}

#[inline(never)]
fn give_bytes(v: Vec<u8>) {
    SCRATCH_BYTES.give(v);
}

/// Runs `f` with an empty per-thread string, kept for the next call.
pub fn with_string<R>(f: impl FnOnce(&mut String) -> R) -> R {
    let mut s = take_str();
    let r = f(&mut s);
    give_str(s);
    r
}

/// A second [`with_string`], for a call that needs two at once.
pub fn with_string2<R>(f: impl FnOnce(&mut String) -> R) -> R {
    with_string(f)
}

/// Runs `f` with an empty per-thread byte buffer, kept for the next call.
pub fn with_bytes<R>(f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    let mut v = take_bytes();
    let r = f(&mut v);
    give_bytes(v);
    r
}

/// A second [`with_bytes`], for a call that needs two at once.
pub fn with_bytes2<R>(f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    with_bytes(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A string given back is the one the next caller gets, with its capacity.
    #[test]
    fn a_given_string_comes_back_empty_with_its_capacity() {
        let mut s = string();
        s.push_str(&"x".repeat(300));
        let cap = s.capacity();
        give(s);
        let t = string();
        assert_eq!(t.len(), 0);
        assert_eq!(t.capacity(), cap);
    }

    /// A dropped `PString` and `PPairs` give their storage back.
    #[test]
    fn dropped_guards_give_their_storage_back() {
        let cap = {
            let mut p = PString::of(&"y".repeat(500));
            p.push('z');
            p.capacity()
        };
        assert_eq!(string().capacity(), cap);
        let lcap = {
            let mut l = PPairs::new();
            l.push((string_from("a"), string_from("b")));
            l.capacity()
        };
        assert_eq!(PPairs::new().capacity(), lcap);
    }

    /// A list that never held anything, or one grown past what is kept, is not kept.
    #[test]
    fn an_empty_or_oversized_list_is_not_kept() {
        use alcyon_sample::spare::SPARE_LIST;
        let _ = alcyon_alloc::drain_local_pools();
        drop(PPairs::new());
        assert_eq!(SPARE_LIST.local_count(), 0);
        let mut big = PPairs::new();
        big.reserve(2000);
        drop(big);
        assert_eq!(SPARE_LIST.local_count(), 0);
        let mut one = PPairs::new();
        one.push((string_from("a"), string_from("b")));
        drop(one);
        assert_eq!(SPARE_LIST.local_count(), 1);
    }

    /// The thread's pool walk (`pool_gc`) frees the spares and the scratch buffers.
    #[test]
    fn the_pool_walk_frees_the_spares_and_the_scratch_buffers() {
        give(String::with_capacity(500));
        with_string(|s| s.reserve_exact(300));
        with_bytes(|b| b.reserve_exact(200));
        assert!(SCRATCH_STR.local_count() == 1 && SCRATCH_BYTES.local_count() == 1);
        assert!(alcyon_alloc::drain_local_pools() >= 3);
        assert_eq!(alcyon_alloc::local_hot_bytes(), 0);
        with_string(|s| assert_eq!(s.capacity(), 0));
    }

    /// A scratch taken while another call has it is a fresh one.
    #[test]
    fn a_nested_scratch_is_a_fresh_one() {
        with_string(|a| {
            a.push_str("outer");
            with_string(|b| {
                assert_eq!(b.len(), 0);
                b.push_str("inner");
            });
            assert_eq!(a, "outer");
        });
        with_bytes(|b| assert_eq!(b.len(), 0));
    }
}
