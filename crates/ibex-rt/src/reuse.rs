// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Per-thread storage the request path reuses instead of allocating (T437).
//!
//! The rules work on header lists of owned `String`s (the response head, the copy the
//! sample fetches read in `CURRENT_RES_HEADERS`). A `String` that leaves such a list comes
//! back here, cleared, and the next list takes it with the capacity it grew to, so a
//! steady stream of requests through the same rules allocates nothing. The strings are the
//! sample engine's spares ([`ibex_sample::spare`], bounded), shared with the fetches.
//!
//! The scratch buffers ([`with_string`], [`with_bytes`]) are taken out of their slot for
//! the call and put back after it, so a call made while one is out (a format rendered
//! while a reply is built) gets a fresh one instead of a borrow error.

use std::cell::{Cell, RefCell};

thread_local! {
    static STR_SLOT: Cell<Option<String>> = const { Cell::new(None) };
    static STR_SLOT2: Cell<Option<String>> = const { Cell::new(None) };
    static BYTES_SLOT: Cell<Option<Vec<u8>>> = const { Cell::new(None) };
    static BYTES_SLOT2: Cell<Option<Vec<u8>>> = const { Cell::new(None) };
    static SPARE_LISTS: RefCell<Vec<Vec<(String, String)>>> = const { RefCell::new(Vec::new()) };
}

/// `pool_gc` (T445): frees this thread's scratch strings and byte buffers (wiped first: they
/// held request data) and its spare header lists (their strings go back to the spare
/// strings, which the caller drains after this).
#[must_use]
pub fn drain_thread_spares() -> usize {
    let mut n = 0;
    for slot in [&STR_SLOT, &STR_SLOT2] {
        if let Ok(Some(s)) = slot.try_with(Cell::take) {
            ibex_alloc::wipe_vec(&mut s.into_bytes());
            n += 1;
        }
    }
    for slot in [&BYTES_SLOT, &BYTES_SLOT2] {
        if let Ok(Some(mut b)) = slot.try_with(Cell::take) {
            ibex_alloc::wipe_vec(&mut b);
            n += 1;
        }
    }
    let lists = SPARE_LISTS.try_with(|l| l.try_borrow_mut().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default()).unwrap_or_default();
    n += lists.len();
    for mut l in lists {
        clear_pairs(&mut l);
    }
    n
}

pub use ibex_sample::spare::{give, string, string_from};

/// Empties `v`, its strings given back; `v` keeps its capacity.
pub fn clear_pairs(v: &mut Vec<(String, String)>) {
    for (k, val) in v.drain(..) {
        give(k);
        give(val);
    }
}

/// [`Vec::retain`] on a header list, the strings of what goes given back.
pub fn retain_pairs(v: &mut Vec<(String, String)>, mut keep: impl FnMut(&(String, String)) -> bool) {
    let mut i = 0;
    while i < v.len() {
        if keep(&v[i]) {
            i += 1;
        } else {
            let (k, val) = v.remove(i);
            give(k);
            give(val);
        }
    }
}

/// Makes `dst` a copy of `src`, reusing the strings `dst` has: what `clone_from` does, but
/// the strings past the end of `src` are given back rather than freed, and the ones added
/// are spares.
pub fn copy_pairs(dst: &mut Vec<(String, String)>, src: &[(String, String)]) {
    while dst.len() > src.len() {
        if let Some((k, v)) = dst.pop() {
            give(k);
            give(v);
        }
    }
    for (d, s) in dst.iter_mut().zip(src) {
        d.0.clone_from(&s.0);
        d.1.clone_from(&s.1);
    }
    let have = dst.len();
    for (k, v) in &src[have..] {
        dst.push((string_from(k), string_from(v)));
    }
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

/// A header list whose strings, and the list itself, are given back when it is dropped.
#[derive(Debug, Default)]
pub struct PPairs(Vec<(String, String)>);

/// The spare lists kept per thread.
const SPARE_LISTS_MAX: usize = 16;

impl PPairs {
    /// An empty list, a spare one when there is one.
    #[must_use]
    pub fn new() -> Self {
        PPairs(SPARE_LISTS.with(|s| s.borrow_mut().pop()).unwrap_or_default())
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
        let mut v = std::mem::take(&mut self.0);
        clear_pairs(&mut v);
        if v.capacity() > 0 && v.capacity() <= 1024 {
            SPARE_LISTS.with(|s| {
                let mut s = s.borrow_mut();
                if s.len() < SPARE_LISTS_MAX {
                    s.push(v);
                }
            });
        }
    }
}

fn with_slot<T: Default, R>(slot: &'static std::thread::LocalKey<Cell<Option<T>>>, f: impl FnOnce(&mut T) -> R, clear: fn(&mut T)) -> R {
    let mut buf = slot.with(Cell::take).unwrap_or_default();
    clear(&mut buf);
    let r = f(&mut buf);
    slot.with(|s| s.set(Some(buf)));
    r
}

/// Runs `f` with an empty per-thread string, kept for the next call.
pub fn with_string<R>(f: impl FnOnce(&mut String) -> R) -> R {
    with_slot(&STR_SLOT, f, String::clear)
}

/// A second [`with_string`], for a call that needs two at once.
pub fn with_string2<R>(f: impl FnOnce(&mut String) -> R) -> R {
    with_slot(&STR_SLOT2, f, String::clear)
}

/// Runs `f` with an empty per-thread byte buffer, kept for the next call.
pub fn with_bytes<R>(f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    with_slot(&BYTES_SLOT, f, Vec::clear)
}

/// A second [`with_bytes`], for a call that needs two at once.
pub fn with_bytes2<R>(f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    with_slot(&BYTES_SLOT2, f, Vec::clear)
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

    /// `copy_pairs` gives `dst` the contents of `src` whatever their lengths.
    #[test]
    fn copy_pairs_copies_longer_and_shorter_lists() {
        let a = vec![("a".to_string(), "1".to_string()), ("b".to_string(), "2".to_string())];
        let mut d = vec![("z".to_string(), "9".to_string())];
        copy_pairs(&mut d, &a);
        assert_eq!(d, a);
        copy_pairs(&mut d, &a[..1]);
        assert_eq!(d, a[..1]);
        let mut v = a.clone();
        retain_pairs(&mut v, |(k, _)| k == "b");
        assert_eq!(v, a[1..]);
        clear_pairs(&mut v);
        assert_eq!(v.len(), 0);
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
        while SPARE_LISTS.with(|s| s.borrow_mut().pop()).is_some() {}
        drop(PPairs::new());
        assert_eq!(SPARE_LISTS.with(|s| s.borrow().len()), 0);
        let mut big = PPairs::new();
        big.reserve(2000);
        drop(big);
        assert_eq!(SPARE_LISTS.with(|s| s.borrow().len()), 0);
        let mut one = PPairs::new();
        one.push((string_from("a"), string_from("b")));
        drop(one);
        assert_eq!(SPARE_LISTS.with(|s| s.borrow().len()), 1);
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
