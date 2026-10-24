// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T453): its #[global_allocator] fails large allocations on demand.

//! The session arena gives memory back after a burst; doing so must not cost the process.
//!
//! T446 saw Ibex serve a burst of 5000 connections under `prlimit --as`, then abort while
//! the arena moved its live slots to a fresh buffer of the old capacity (104 MB): a second
//! allocation of the full size, made to free the first. Here that allocation fails. The
//! arena must keep its old buffer, count the skipped trim, and the process must live.

use std::cell::Cell;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};

use ibex_alloc::{fail_thread_allocs_from, CountingAllocator};
use ibex_rt::engine::{session_trims_skipped, SessionArena, SessionEntry};
use ibex_rt::proxy::{TcpSession, Timeouts};
use ibex_rt::Interest;
use ibex_sched::{TaskRef, Tick};

/// Fails large allocations on the thread that asks ([`fail_thread_allocs_from`]).
#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

/// Allocations of at least this many bytes fail while the arena is emptied.
const LIMIT: usize = 64 * std::mem::size_of::<Option<SessionEntry>>();

fn entry() -> SessionEntry {
    let fd = OwnedFd::from(File::open("/dev/null").expect("open /dev/null"));
    let raw = fd.as_raw_fd();
    SessionEntry {
        sess: TcpSession::new(fd, Timeouts::default(), 3, Tick(1000)),
        task: TaskRef::NONE,
        proxy_idx: 0,
        backend_idx: 0,
        srv_backend_idx: 0,
        target_server_idx: None,
        cli_raw_fd: raw,
        srv_raw_fd: None,
        cli_interest: Interest::NONE,
        srv_interest: Interest::NONE,
        actconn_reclaimed: false,
        stats_done: false,
        be_counted: Cell::new(u32::MAX),
        connect_log_due: false,
        rate_max_due: false,
        srv_served: 0,
        log_line: None,
        log_err: false,
        log_sd: 0,
    }
}

/// A burst that fills the pre-sized arena, then every connection closes while no large
/// allocation can succeed: the arena keeps the buffer it has and counts the trim it skipped.
#[test]
fn a_trim_whose_fresh_buffer_cannot_be_had_keeps_the_old_one() {
    const FLOOR: usize = 512;
    const BURST: u32 = 300;
    let mut arena = SessionArena::with_capacity(FLOOR);
    let idx: Vec<u32> = (0..BURST).map(|_| arena.alloc(entry()).expect("slot")).collect();
    assert_eq!(arena.capacity(), FLOOR);
    let skipped = session_trims_skipped();

    fail_thread_allocs_from(LIMIT);
    // Last first, so the tail is trimmed on every close.
    for &i in idx.iter().rev() {
        assert!(arena.free(i).is_some());
    }
    fail_thread_allocs_from(usize::MAX);

    assert_eq!(arena.live(), 0);
    assert_eq!(arena.capacity(), FLOOR, "the old buffer is kept");
    assert!(session_trims_skipped() > skipped, "the skipped trim is counted");

    // With memory back, the next trim goes through.
    let i = arena.alloc(entry()).expect("slot");
    let before = session_trims_skipped();
    assert!(arena.free(i).is_some());
    assert_eq!(session_trims_skipped(), before, "a trim that can have its buffer is done");
    assert_eq!(arena.capacity(), FLOOR, "the fresh buffer keeps the creation capacity");
}
