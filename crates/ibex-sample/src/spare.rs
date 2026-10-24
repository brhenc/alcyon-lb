// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Spare strings per thread (T437): a fetch takes its sample's string here, and whoever is
//! done with a sample gives the string back, so the samples of a steady stream of requests
//! reuse the same few strings instead of allocating new ones. Bounded: [`SPARE_MAX`] strings
//! of at most [`KEEP_MAX`] bytes each.

use std::cell::RefCell;

use crate::sample::Sample;

/// The spare strings kept per thread.
pub const SPARE_MAX: usize = 512;
/// A string larger than this is let go rather than kept.
pub const KEEP_MAX: usize = 16 * 1024;
/// The least capacity a new string starts with, so that a reused one is seldom grown.
const MIN_CAP: usize = 64;

thread_local! {
    static SPARE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// An empty string, a spare one when there is one.
#[must_use]
pub fn string() -> String {
    SPARE.with(|s| s.borrow_mut().pop()).unwrap_or_else(|| String::with_capacity(MIN_CAP))
}

/// `src` in a [`string`].
#[must_use]
pub fn string_from(src: &str) -> String {
    let mut s = string();
    s.push_str(src);
    s
}

/// Gives `s` back for a later [`string`].
pub fn give(mut s: String) {
    if s.capacity() == 0 || s.capacity() > KEEP_MAX {
        return;
    }
    s.clear();
    SPARE.with(|sp| {
        let mut sp = sp.borrow_mut();
        if sp.len() < SPARE_MAX {
            sp.push(s);
        }
    });
}

/// Gives back the string of a text sample; any other sample is dropped.
pub fn give_sample(smp: Sample) {
    if let Sample::Str(s) = smp {
        give(s);
    }
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
}
