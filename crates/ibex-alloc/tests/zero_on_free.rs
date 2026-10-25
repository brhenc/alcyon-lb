// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (AGENTS.md rule 6): installs the counting #[global_allocator] and sets the
// process-wide `tune.ibex.zero-on-free`, which every other test's frees in a shared binary
// would follow.

//! T459: `tune.ibex.zero-on-free off|soft|hard`. What the system allocator is handed back when
//! a block is freed, seen through [`ibex_alloc::watch_freed`] (the allocator copies the first
//! bytes of the block at the moment it gives it to the system, so the test never reads freed
//! memory): the secret with `off`, zeros with `hard`, nothing yet with `soft` (the block waits
//! in this thread's quarantine), then zeros after an idle pass, after the age bound under
//! load, past the byte bound, and after `pool_gc`.

use ibex_alloc::zero_on_free::{self as zof, ZeroOnFree};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[global_allocator]
static ALLOC: ibex_alloc::CountingAllocator = ibex_alloc::CountingAllocator::new();

/// The setting and the watch are process-wide: the tests take turns.
static TURN: Mutex<()> = Mutex::new(());

/// A size no other code in this binary frees while a test watches it.
const SIZE: usize = 4093;
const SECRET: &[u8] = b"-----BEGIN PRIVATE KEY----- MC4CAQAwBQYDK2VwBCIEIHNlY3J";

/// Frees a block of [`SIZE`] bytes that starts with the secret, watched.
fn free_secret() {
    let mut v = vec![0x41u8; SIZE];
    v[..SECRET.len()].copy_from_slice(SECRET);
    ibex_alloc::watch_freed(SIZE);
    drop(std::hint::black_box(v));
}

fn turn(mode: ZeroOnFree) -> std::sync::MutexGuard<'static, ()> {
    let g = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    zof::set_bounds(0, Duration::from_millis(100));
    zof::set_zero_on_free(mode);
    // This thread runs passes: its frees are quarantined under `soft`.
    zof::pass(Instant::now(), false);
    let _ = zof::drain_local();
    g
}

fn zeros(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&x| x == 0)
}

#[test]
fn off_hands_the_secret_to_the_system_allocator() {
    let _t = turn(ZeroOnFree::Off);
    free_secret();
    let got = ibex_alloc::freed_bytes().expect("freed at once");
    assert_eq!(&got[..SECRET.len()], SECRET);
}

#[test]
fn hard_wipes_the_block_before_freeing_it() {
    let _t = turn(ZeroOnFree::Hard);
    let before = zof::local_stats().wiped;
    free_secret();
    let got = ibex_alloc::freed_bytes().expect("freed at once");
    assert!(zeros(&got), "hard: {got:?}");
    assert!(zof::local_stats().wiped > before);
    assert_eq!(zof::local_stats().blocks, 0, "hard keeps nothing");
    zof::set_zero_on_free(ZeroOnFree::Off);
}

#[test]
fn hard_wipes_the_old_block_of_a_moving_realloc() {
    let _t = turn(ZeroOnFree::Hard);
    let mut v: Vec<u8> = Vec::with_capacity(SIZE);
    v.extend_from_slice(SECRET);
    ibex_alloc::watch_freed(SIZE);
    v.reserve_exact(SIZE * 4);
    let got = ibex_alloc::freed_bytes().expect("the old block was freed");
    assert!(zeros(&got), "the old block of the realloc: {got:?}");
    assert_eq!(&v[..SECRET.len()], SECRET, "the new block has the contents");
    zof::set_zero_on_free(ZeroOnFree::Off);
}

#[test]
fn soft_keeps_the_block_until_an_idle_pass_then_wipes_it() {
    let _t = turn(ZeroOnFree::Soft);
    free_secret();
    assert_eq!(ibex_alloc::freed_bytes(), None, "soft: the block waits in the quarantine");
    let s = zof::local_stats();
    assert!(s.blocks >= 1 && s.bytes >= SIZE, "{s:?}");
    zof::pass(Instant::now(), false);
    // A busy pass frees up to its budget; the block may be gone already. An idle pass frees all.
    zof::pass(Instant::now(), true);
    let got = ibex_alloc::freed_bytes().expect("an idle pass frees the quarantine");
    assert!(zeros(&got), "soft, after the idle pass: {got:?}");
    assert_eq!(zof::local_stats().blocks, 0);
    zof::set_zero_on_free(ZeroOnFree::Off);
}

#[test]
fn soft_under_continuous_load_wipes_what_is_older_than_the_age_bound() {
    let _t = turn(ZeroOnFree::Soft);
    // The busy passes' budget would free the block: give them none to spend.
    zof::set_pass_budget(0);
    let t0 = Instant::now();
    zof::pass(t0, false);
    free_secret();
    let expired = zof::local_stats().expired;
    zof::pass(t0 + Duration::from_millis(50), false);
    assert_eq!(ibex_alloc::freed_bytes(), None, "younger than the bound: kept under load");
    zof::pass(t0 + Duration::from_millis(101), false);
    let got = ibex_alloc::freed_bytes().expect("older than the bound: freed by a busy pass");
    assert!(zeros(&got), "soft, past the age bound: {got:?}");
    assert!(zof::local_stats().expired > expired);
    zof::set_pass_budget(zof::PASS_BUDGET_DEFAULT);
    zof::set_zero_on_free(ZeroOnFree::Off);
}

#[test]
fn soft_under_a_free_storm_stays_within_its_bytes_and_counts_the_forced_wipes() {
    let _t = turn(ZeroOnFree::Soft);
    let max = 64 * 1024;
    zof::set_bounds(max, Duration::from_secs(3600));
    zof::pass(Instant::now(), false);
    let forced = zof::local_stats().forced;
    let mut peak = 0;
    for i in 0..2000usize {
        drop(std::hint::black_box(vec![u8::try_from(i % 251).unwrap_or(1) | 1; 1000 + i % 300]));
        peak = peak.max(zof::local_stats().bytes);
    }
    assert!(peak <= max, "the quarantine reached {peak} bytes over {max}");
    assert!(peak > max / 2, "the quarantine was used: {peak}");
    assert!(zof::local_stats().forced > forced + 1000, "{:?}", zof::local_stats());
    // A block larger than the bound is wiped at once (forced as well).
    free_big_secret(max * 2);
    let got = ibex_alloc::freed_bytes().expect("too big to wait");
    assert!(zeros(&got), "{got:?}");
    // A bound lowered under what waits: the next pass frees down to it (forced).
    zof::set_bounds(max, Duration::from_secs(3600));
    zof::set_pass_budget(0);
    zof::pass(Instant::now(), false);
    for _ in 0..8 {
        drop(std::hint::black_box(vec![7u8; 4000]));
    }
    let (held, forced) = (zof::local_stats().bytes, zof::local_stats().forced);
    assert!(held >= 8 * 4000, "{held}");
    zof::set_bounds(10_000, Duration::from_secs(3600));
    zof::pass(Instant::now(), false);
    assert!(zof::local_stats().bytes <= 10_000, "{:?}", zof::local_stats());
    assert!(zof::local_stats().forced >= forced + 5);
    zof::set_pass_budget(zof::PASS_BUDGET_DEFAULT);
    zof::set_zero_on_free(ZeroOnFree::Off);
    let _ = zof::drain_local();
}

fn free_big_secret(n: usize) {
    let mut v = vec![0x42u8; n];
    v[..SECRET.len()].copy_from_slice(SECRET);
    ibex_alloc::watch_freed(n);
    drop(std::hint::black_box(v));
}

#[test]
fn pool_gc_drains_the_quarantine() {
    let _t = turn(ZeroOnFree::Soft);
    free_secret();
    assert_eq!(ibex_alloc::freed_bytes(), None);
    assert!(ibex_alloc::drain_local_pools() >= 1, "the quarantined block counts as freed");
    let got = ibex_alloc::freed_bytes().expect("pool_gc frees the quarantine");
    assert!(zeros(&got), "{got:?}");
    assert_eq!(zof::local_stats().bytes, 0);
    zof::set_zero_on_free(ZeroOnFree::Off);
}

#[test]
fn a_thread_without_passes_wipes_at_once_and_a_thread_drains_when_it_ends() {
    let _t = turn(ZeroOnFree::Soft);
    // No pass on this thread: nothing would ever free its quarantine, so it has none.
    std::thread::spawn(|| {
        free_secret();
        let got = ibex_alloc::freed_bytes().expect("a thread without passes frees at once");
        assert!(zeros(&got), "{got:?}");
    })
    .join()
    .unwrap();
    // A thread with passes keeps the block, and frees it (wiped) when it ends.
    std::thread::spawn(|| {
        zof::pass(Instant::now(), false);
        free_secret();
        assert_eq!(ibex_alloc::freed_bytes(), None);
    })
    .join()
    .unwrap();
    let got = ibex_alloc::freed_bytes().expect("the thread's end frees its quarantine");
    assert!(zeros(&got), "{got:?}");
    // Switching away from soft frees the rest at the next pass.
    free_secret();
    zof::set_zero_on_free(ZeroOnFree::Off);
    zof::pass(Instant::now(), false);
    let got = ibex_alloc::freed_bytes().expect("off: the quarantine is emptied");
    assert!(zeros(&got), "{got:?}");
    let s = zof::stats();
    assert!(s.queued >= 2 && s.wiped >= 1, "process figures: {s:?}");
}

#[test]
fn the_setting_names_and_the_failed_allocation_retry() {
    let _t = turn(ZeroOnFree::Soft);
    assert_eq!(ZeroOnFree::parse("hard"), Some(ZeroOnFree::Hard));
    assert_eq!(ZeroOnFree::parse("soft"), Some(ZeroOnFree::Soft));
    assert_eq!(ZeroOnFree::parse("off"), Some(ZeroOnFree::Off));
    assert_eq!(ZeroOnFree::parse("on"), None);
    assert_eq!(ZeroOnFree::Soft.name(), "soft");
    assert_eq!(ZeroOnFree::Off.name(), "off");
    assert_eq!(ZeroOnFree::Hard.name(), "hard");
    assert_eq!(zof::zero_on_free(), ZeroOnFree::Soft);
    // A refused allocation frees the quarantine first (it may hold what the allocation needs).
    free_secret();
    assert_eq!(ibex_alloc::freed_bytes(), None);
    ibex_alloc::fail_thread_allocs_from(1 << 20);
    let got = std::alloc::Layout::from_size_align(2 << 20, 8).map(|l| {
        // SAFETY: a non-zero size; freed below when it was had.
        let p = unsafe { std::alloc::alloc(l) };
        if !p.is_null() {
            // SAFETY: allocated just above with this layout.
            unsafe { std::alloc::dealloc(p, l) };
        }
        p.is_null()
    });
    ibex_alloc::fail_thread_allocs_from(usize::MAX);
    assert_eq!(got, Ok(true), "refused");
    let got = ibex_alloc::freed_bytes().expect("the refusal emptied the quarantine");
    assert!(zeros(&got), "{got:?}");
    zof::set_zero_on_free(ZeroOnFree::Off);
}

/// The `ibex` binary's allocator, called directly (this binary's global one is the counting
/// allocator): it applies the setting on its frees and reallocations, and a refused allocation
/// empties the quarantine and is tried once more.
#[test]
fn the_process_allocator_applies_the_setting_and_retries_after_emptying_the_quarantine() {
    use std::alloc::{GlobalAlloc, Layout};
    let _t = turn(ZeroOnFree::Hard);
    let a = ibex_alloc::IbexAllocator;
    let l = Layout::from_size_align(SIZE, 8).expect("layout");
    // SAFETY: each block is used within its layout and freed once, by the same allocator.
    unsafe {
        let p = a.alloc(l);
        assert!(!p.is_null());
        p.copy_from_nonoverlapping(SECRET.as_ptr(), SECRET.len());
        ibex_alloc::watch_freed(SIZE);
        let q = a.realloc(p, l, SIZE * 2);
        assert!(!q.is_null());
        assert!(zeros(&ibex_alloc::freed_bytes().expect("the old block was freed")), "hard realloc");
        assert_eq!(std::slice::from_raw_parts(q, SECRET.len()), SECRET);
        let l2 = Layout::from_size_align(SIZE * 2, 8).expect("layout");
        a.dealloc(q, l2);

        zof::set_zero_on_free(ZeroOnFree::Off);
        let p = a.alloc_zeroed(l);
        assert!(!p.is_null() && *p == 0);
        let q = a.realloc(p, l, SIZE * 2);
        assert!(!q.is_null());
        a.dealloc(q, l2);

        // Too much for any system: refused, also after the quarantine was emptied.
        zof::set_zero_on_free(ZeroOnFree::Soft);
        zof::pass(Instant::now(), false);
        let huge = Layout::from_size_align(1 << 62, 8).expect("layout");
        for f in 0..4 {
            zof::set_zero_on_free(ZeroOnFree::Soft);
            free_secret();
            assert_eq!(ibex_alloc::freed_bytes(), None, "quarantined");
            if f == 3 {
                // Off again before a pass: a plain reallocation, refused, empties what is left.
                zof::set_zero_on_free(ZeroOnFree::Off);
            }
            let p = a.alloc(l);
            let got = match f {
                0 => a.alloc(huge),
                1 => a.alloc_zeroed(huge),
                _ => a.realloc(p, l, 1 << 62),
            };
            assert!(got.is_null(), "{f} {got:p}");
            assert!(zeros(&ibex_alloc::freed_bytes().expect("the refusal emptied the quarantine")), "{f}");
            a.dealloc(p, l);
        }
    }
    zof::set_zero_on_free(ZeroOnFree::Off);
    let _ = zof::drain_local();
}
