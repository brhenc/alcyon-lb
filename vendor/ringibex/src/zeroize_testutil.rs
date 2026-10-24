// Copyright 2026 Ibex contributors.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


//! Helpers for the `zeroize` tests (ring-ibex). Built only with
//! `--features zeroize` under `cfg(test)`.

extern crate std;

use core::{
    mem::{size_of, ManuallyDrop, MaybeUninit},
    ptr,
};
use std::prelude::v1::*;

pub(crate) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Moves `value` into a fresh heap allocation, snapshots its bytes, runs its
/// destructor *in place* (the allocation stays live), snapshots the bytes
/// again with volatile reads, and frees the allocation without a second drop.
/// Returns `(before, after)`.
pub(crate) fn before_and_after_drop<T>(value: T) -> (Vec<u8>, Vec<u8>) {
    let mut b = ManuallyDrop::new(Box::new(value));
    let p = &mut **b as *mut T;
    let snap = |p: *const T| -> Vec<u8> {
        (0..size_of::<T>())
            .map(|i| {
                // SAFETY: the allocation is live; reading padding as a byte is
                // fine in practice for this test.
                unsafe { ptr::read_volatile((p as *const MaybeUninit<u8>).add(i)).assume_init() }
            })
            .collect()
    };
    let before = snap(p);
    // SAFETY: `p` points to a valid `T`, dropped exactly once.
    unsafe { ptr::drop_in_place(p) };
    let after = snap(p);
    // SAFETY: free the box without dropping `T` again.
    unsafe { drop(Box::from_raw(p as *mut MaybeUninit<T>)) };
    (before, after)
}

/// Asserts `needle` is present in the value before drop and absent after.
#[track_caller]
pub(crate) fn assert_needle_wiped<T>(value: T, needle: &[u8], what: &str) {
    let (before, after) = before_and_after_drop(value);
    assert!(contains(&before, needle), "{what}: needle not found before drop (test is vacuous)");
    assert!(!contains(&after, needle), "{what}: secret survived drop");
}

/// Asserts the whole value is non-zero before drop and all zero after.
#[track_caller]
pub(crate) fn assert_all_zero_after<T>(value: T, what: &str) {
    let (before, after) = before_and_after_drop(value);
    assert!(before.iter().any(|&b| b != 0), "{what}: all zero before drop (vacuous)");
    assert!(after.iter().all(|&b| b == 0), "{what}: bytes survived drop");
}

/// A global allocator that, while armed, inspects every block just before it is
/// freed and counts the blocks that contain the armed needle. This observes heap
/// memory without reading freed memory.
pub(crate) mod spy {
    extern crate std;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::alloc::{GlobalAlloc, Layout, System};

    pub(crate) struct Spy;

    const MAX: usize = 64;
    static ARMED: AtomicBool = AtomicBool::new(false);
    static LEN: AtomicUsize = AtomicUsize::new(0);
    static NEEDLE: [AtomicUsize; MAX] = [const { AtomicUsize::new(0) }; MAX];
    static FOUND: AtomicUsize = AtomicUsize::new(0);
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe impl GlobalAlloc for Spy {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            unsafe { System.alloc(l) }
        }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            unsafe { System.alloc_zeroed(l) }
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            unsafe {
                scan(p, l.size());
                System.realloc(p, l, n)
            }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            unsafe {
                scan(p, l.size());
                System.dealloc(p, l)
            }
        }
    }

    unsafe fn scan(p: *mut u8, size: usize) {
        if !ARMED.load(SeqCst) {
            return;
        }
        let n = LEN.load(SeqCst);
        if n == 0 || size < n {
            return;
        }
        // SAFETY: `p..p+size` is the block being freed.
        let block = unsafe { core::slice::from_raw_parts(p, size) };
        let hit = block.windows(n).any(|w| w.iter().enumerate().all(|(i, &b)| b as usize == NEEDLE[i].load(SeqCst)));
        if hit {
            let _ = FOUND.fetch_add(1, SeqCst);
        }
    }

    /// Runs `f` (which should drop the secret) and returns how many freed blocks held `needle`.
    pub(crate) fn blocks_freed_with<R>(needle: &[u8], f: impl FnOnce() -> R) -> usize {
        assert!(needle.len() <= MAX && !needle.is_empty());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for (i, &b) in needle.iter().enumerate() {
            NEEDLE[i].store(b as usize, SeqCst);
        }
        LEN.store(needle.len(), SeqCst);
        FOUND.store(0, SeqCst);
        ARMED.store(true, SeqCst);
        drop(f());
        ARMED.store(false, SeqCst);
        LEN.store(0, SeqCst);
        FOUND.load(SeqCst)
    }

    #[global_allocator]
    static A: Spy = Spy;
}
