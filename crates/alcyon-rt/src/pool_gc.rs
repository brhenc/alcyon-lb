// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `HAProxy`'s `pool_gc` (`src/pool.c:974`): the caches give their memory back, then the
//! heap is trimmed (T445).
//!
//! `HAProxy` isolates the threads and frees every pool's shared free list down to
//! `minavail`, then calls `malloc_trim(0)`. It does so on `SIGQUIT` (`dump`), `SIGUSR1`
//! (`sig_soft_stop`), `SIGTTOU` (`sig_pause`), while stopping once stick-table entries were
//! trashed (`src/proxy.c:3715`), and before retrying an `SSL_new` that failed.
//!
//! Alcyon's caches are per thread (`thread_local!`), and only their own thread can empty them.
//! [`pool_gc`] raises a process-wide generation and empties the calling thread's caches at
//! once; every engine thread calls [`poll`] on each pass of its loop (at most a poll timeout,
//! 100 ms, apart) and empties its own when the generation moved. No thread waits for another,
//! where `thread_isolate` stops them all.
//!
//! What is emptied ([`drain_thread_caches`]): every `alcyon_alloc::Pool` the thread used, found by
//! the registry walk (`alcyon_alloc::drain_local_pools`) and not by a list kept here: the buffers
//! (`buffer`, `small_buffer`, `large_buffer`), spare strings and header lists, scratch buffers,
//! log lines (`logline`), captures (`caphdr`), variable stores (`vars`), check runs, stats rows,
//! scrape boxes and queue waits (`pendconn`). A cache that is not a `declare_pool!` is not
//! drained, and `harness/pool_layout.py` refuses to build one. Kept: the Prometheus exporter's
//! prewarmed scrape state (like `HAProxy`'s trash, which `pool_gc` does not free either), and
//! the compiled regex and expression caches, which are configuration. The session, applet and task
//! arenas are owned by the engine thread, not by a `thread_local!`: after [`poll`] sees a request
//! the engine calls their `alcyon_alloc::Arena::compact` (`Engine::compact_arenas`), which gives
//! back the burst capacity. A close never does (Q2: the peak is kept, as `HAProxy`).
//! What held request or log data was wiped when it was given back (`tune.alcyon.zero-spares`, `tune.alcyon.zero-buffers`).

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Raised by every request; a thread whose last seen value differs empties its caches.
static GENERATION: AtomicU64 = AtomicU64::new(0);
/// Thread drains done, for `show`-style diagnostics and the tests.
static DRAINS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static SEEN: Cell<u64> = const { Cell::new(0) };
}

/// Runs the collector: every thread's caches are emptied and the heap trimmed.
///
/// The entry point for an allocation that failed and is retried once (T448, as
/// `ssl_sock.c:6074` retries `SSL_new` after `pool_gc(NULL)`). Callable from any thread,
/// also one that is not an engine worker. The calling thread's caches are emptied and the
/// heap is trimmed before it returns, so a retry right after it finds that memory free;
/// the other workers empty theirs at their next loop pass, without being stopped.
pub fn pool_gc() {
    request();
    drain_thread_caches();
    let _ = alcyon_alloc::trim_heap();
}

/// Asks every engine thread to empty its caches at its next loop pass (the signal paths:
/// `SIGQUIT`, `SIGTTOU`, `SIGUSR1`, the stop path). Async-signal-safe in effect: one atomic add.
pub fn request() {
    GENERATION.fetch_add(1, Ordering::Release);
}

/// Called by each engine thread on every pass of its loop: empties this thread's caches if a
/// collection was requested since it last looked. Returns whether it did, so the engine can
/// empty what it owns itself.
pub fn poll() -> bool {
    let g = GENERATION.load(Ordering::Acquire);
    let seen = SEEN.try_with(Cell::get).unwrap_or(g);
    if seen == g {
        return false;
    }
    let _ = SEEN.try_with(|s| s.set(g));
    if drain_thread_caches() > 0 {
        let _ = alcyon_alloc::trim_heap();
    }
    true
}

/// Thread drains done since the process started.
#[must_use]
pub fn drains() -> usize {
    DRAINS.load(Ordering::Relaxed)
}

/// Empties every cache of the calling thread; returns how many objects were freed.
pub fn drain_thread_caches() -> usize {
    // Every `alcyon_alloc::Pool` this thread used, found by the registry walk: a cache that is
    // not declared with `declare_pool!` is not drained, and `harness/pool_layout.py` refuses it.
    let n = alcyon_alloc::drain_local_pools();
    DRAINS.fetch_add(1, Ordering::Relaxed);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What this thread caches is freed, and a second pass finds nothing; a request is seen
    /// by the thread's `poll`.
    #[test]
    fn the_thread_caches_are_emptied_and_a_request_is_seen_once() {
        drop(crate::buf::Buf::standard());
        crate::logfmt::recycle_line(b"a log line".to_vec());
        let mut slot = None;
        crate::txnlog::set_capture(&mut slot, b"a captured header");
        crate::txnlog::clear_capture(&mut slot);
        assert!(drain_thread_caches() >= 3, "a buffer, a line and a capture were cached");
        assert_eq!(drain_thread_caches(), 0);

        let _ = poll();
        let before = drains();
        pool_gc();
        assert!(drains() > before);
        // (Not "and then no more": an engine test soft-stopping meanwhile requests another.)
        assert!(poll(), "the request is seen by this thread's loop");
    }
}
