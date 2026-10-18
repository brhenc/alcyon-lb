// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (AGENTS.md rule 6): asserts on the process-wide buffer counters, which the
// buffers of any other test in a shared binary would move.

//! `allocated` of the buffer pools counts live buffers: one that does not fit the thread
//! cache when it is freed (or replaced by a promotion) goes back to the heap and leaves the
//! count (M3). Read through `show pools`' own providers.

use ibex_rt::buf::{self, Buf};
use std::sync::Mutex;

/// The tests take turns: they read the same counters.
static TURN: Mutex<()> = Mutex::new(());

/// The thread cache of each class (`MAX_CACHED_PER_THREAD`).
const CACHE: usize = 64;

fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    buf::init_buffer_sizes(16384, 1024, Some(65536));
    g
}

fn counts(head: Option<ibex_alloc::PoolHead>) -> (usize, usize, usize) {
    let h = head.expect("pool configured");
    (h.allocated, h.used, h.cached)
}

#[test]
fn a_large_buffer_beyond_the_thread_cache_is_no_longer_allocated() {
    let _g = setup();
    std::thread::spawn(|| {
        let (a0, u0, c0) = counts(buf::large_buffer_pool_stats());
        let bufs: Vec<Buf> = (0..=CACHE).map(|_| Buf::large()).collect();
        assert_eq!(counts(buf::large_buffer_pool_stats()), (a0 + CACHE + 1, u0 + CACHE + 1, c0));
        drop(bufs);
        // one did not fit the cache: it is back on the heap, so it is not allocated
        assert_eq!(counts(buf::large_buffer_pool_stats()), (a0 + CACHE, u0, c0 + CACHE));
    })
    .join()
    .unwrap();
}

#[test]
fn a_small_buffer_replaced_by_a_promotion_beyond_the_cache_is_no_longer_allocated() {
    let _g = setup();
    std::thread::spawn(|| {
        let (a0, u0, c0) = counts(buf::small_buffer_pool_stats());
        let mut bufs: Vec<Buf> = (0..=CACHE).map(|_| Buf::small()).collect();
        assert_eq!(counts(buf::small_buffer_pool_stats()), (a0 + CACHE + 1, u0 + CACHE + 1, c0));
        for b in &mut bufs {
            assert!(b.promote_to_standard());
        }
        // 64 small buffers went to the cache, the 65th back to the heap
        assert_eq!(counts(buf::small_buffer_pool_stats()), (a0 + CACHE, u0, c0 + CACHE));
    })
    .join()
    .unwrap();
}

/// The counters of an arena, read through the pool head `show pools` prints.
#[test]
fn arena_counters_follow_slots_and_give_them_back() {
    let c = buf::ArenaCounters::new();
    let reg = || ibex_alloc::PoolReg { name: "t", size: 10, flags: 0, align: 8, file: "t.rs", line: 1 };
    for _ in 0..3 {
        c.slot_created();
    }
    c.slot_used();
    c.slot_used();
    let h = c.head(reg());
    assert_eq!((h.allocated, h.alloc_bytes, h.used, h.cached), (3, 30, 2, 1));
    c.slot_released();
    c.slots_trimmed(1);
    let h = c.head(reg());
    assert_eq!((h.allocated, h.used, h.cached), (2, 1, 1));
    c.arena_dropped(2, 1);
    let h = c.head(reg());
    assert_eq!((h.allocated, h.used, h.cached), (0, 0, 0));
}
