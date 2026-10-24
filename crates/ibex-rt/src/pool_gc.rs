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
//! Ibex's caches are per thread (`thread_local!`), and only their own thread can empty them.
//! [`pool_gc`] raises a process-wide generation and empties the calling thread's caches at
//! once; every engine thread calls [`poll`] on each pass of its loop (at most a poll timeout,
//! 100 ms, apart) and empties its own when the generation moved. No thread waits for another,
//! where `thread_isolate` stops them all.
//!
//! What is emptied ([`drain_thread_caches`]): the buffer pools (`show pools` `buffer`,
//! `small_buffer`, `large_buffer`), the spare log lines, capture buffers, scratch strings and
//! header lists, variable stores, check runs and stats rows. Kept: the one scratch buffer a
//! thread formats into (log ring, syslog line, the Prometheus exporter's prewarmed scrape
//! state, like `HAProxy`'s trash, which `pool_gc` does not free either), and the compiled
//! regex and expression caches, which are configuration. The session and applet arenas
//! give back their burst capacity as connections close, so they hold nothing to empty.
//! What held request or log data is wiped first when `tune.ibex.zero-buffers` is on (cached
//! buffers were wiped when released).

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
    let _ = ibex_alloc::trim_heap();
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
        let _ = ibex_alloc::trim_heap();
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
    let mut n = crate::buf::drain_thread_cache();
    n += crate::logfmt::drain_spare_lines();
    n += crate::txnlog::drain_capture_spares();
    n += crate::check::drain_run_pool();
    n += crate::stats::drain_row_pool();
    // The header lists give their strings back to the spare strings: before those go.
    n += crate::reuse::drain_thread_spares();
    n += ibex_sample::vars::drain_spare(ibex_alloc::wipe_vec);
    // TODO(T444): the spare strings (`ibex_sample::spare`) are emptied here, by the function
    // T444 adds to drop (and wipe) a thread's spare strings; the supervisor joins it at merge:
    //     n += ibex_sample::spare::<T444's drain>();
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
