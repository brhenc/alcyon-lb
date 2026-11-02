// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T453): its #[global_allocator] fails large allocations on demand.

//! The session arena gives memory back after a burst, in `pool_gc` only; doing so must not cost
//! the process.
//!
//! T446 saw Ibex serve a burst of 5000 connections under `prlimit --as`, then abort while
//! the arena moved its live slots to a fresh buffer of the old capacity (104 MB): a second
//! allocation of the full size, made to free the first. Here that allocation fails. The
//! arena must keep its old buffer, count the skipped trim, and the process must live.

use std::cell::Cell;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};

use ibex_alloc::{fail_thread_allocs_from, Arena, CountingAllocator};

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
        buf_wait: ibex_rt::buf_wait::WaitState::default(),
        parked: false,
    }
}

/// A burst that fills the pre-sized arena and then closes: the close keeps the peak (Q2). Then
/// `compact` (what `pool_gc` runs) while no large allocation can succeed: the arena keeps the
/// buffer it has and counts the compaction it skipped; with memory back, it is done.
#[test]
fn a_compaction_whose_fresh_buffer_cannot_be_had_keeps_the_old_one() {
    const FLOOR: usize = 512;
    const BURST: u32 = 300;
    let mut arena = SessionArena::with_capacity(FLOOR);
    let idx: Vec<u32> = (0..BURST).map(|_| arena.alloc(entry()).expect("slot")).collect();
    assert_eq!(arena.capacity(), FLOOR);
    for &i in idx.iter().rev() {
        assert!(arena.free(i).is_some());
    }
    assert_eq!((arena.live(), arena.slots()), (0, BURST as usize), "a close keeps the peak");
    let skipped = session_trims_skipped();

    fail_thread_allocs_from(LIMIT);
    let released = arena.compact();
    fail_thread_allocs_from(usize::MAX);
    assert_eq!(released, BURST as usize, "the tail is dropped even when the copy cannot be made");
    assert_eq!(arena.capacity(), FLOOR, "the old buffer is kept");
    assert!(session_trims_skipped() > skipped, "the skipped compaction is counted");

    // With memory back, the next compaction goes through (a slot written again, then freed).
    let i = arena.alloc(entry()).expect("slot");
    assert!(arena.free(i).is_some());
    let before = session_trims_skipped();
    assert_eq!(arena.compact(), 1);
    assert_eq!(session_trims_skipped(), before, "a compaction that can have its buffer is done");
    assert_eq!(arena.capacity(), FLOOR, "the fresh buffer keeps the creation capacity");
}

/// Growing past the pre-size is fallible: when the allocator refuses, `alloc` is `None` (the
/// connection is refused), the failure is counted, and the arena is as it was.
#[test]
fn a_slot_past_the_presize_that_cannot_be_had_is_refused() {
    const FLOOR: usize = 64;
    let mut arena = SessionArena::with_capacity(FLOOR);
    for _ in 0..FLOOR {
        arena.alloc(entry()).expect("slot");
    }
    let failures = ibex_rt::engine::SESSION_POOL.failures();
    fail_thread_allocs_from(LIMIT);
    let refused = arena.alloc(entry());
    fail_thread_allocs_from(usize::MAX);
    assert!(refused.is_none(), "no slot when the arena cannot grow");
    assert_eq!(ibex_rt::engine::SESSION_POOL.failures(), failures + 1);
    assert_eq!((arena.live(), arena.slots(), arena.capacity()), (FLOOR, FLOOR, FLOOR));
    assert!(arena.alloc(entry()).is_some(), "with memory back it grows");
}

/// The applet arena is an arena too: a close keeps the slots, `compact` gives them back, and a
/// slot past the pre-size that cannot be had is refused.
#[test]
fn the_applet_arena_keeps_a_burst_until_compacted_and_refuses_when_full() {
    use ibex_rt::{AppletArena, CliApplet};
    use std::os::unix::net::UnixStream;
    const FLOOR: usize = 64;
    let applet = || CliApplet::new(UnixStream::pair().expect("pair").0, Tick(1000));
    let mut arena = AppletArena::with_capacity(FLOOR);
    let idx: Vec<u32> = (0..FLOOR + 6).map(|_| arena.alloc(applet()).expect("slot")).collect();
    assert!(arena.capacity() > FLOOR);
    for &i in idx.iter().skip(1).rev() {
        assert!(arena.free(i).is_some());
    }
    assert_eq!((arena.live(), arena.slots()), (1, FLOOR + 6), "a close keeps the peak");
    arena.publish();
    assert_eq!(arena.compact(), FLOOR + 5);
    assert_eq!((arena.slots(), arena.capacity()), (1, FLOOR));
    let again = arena.alloc(applet()).expect("slot");
    assert_eq!(again, 1, "a new applet takes the next slot, no stale free index");
    assert!(arena.get(again).is_some() && arena.get_mut(0).is_some());
    assert_eq!(arena.iter().count(), 2);
    let failures = ibex_rt::applet::APPCTX_POOL.failures();
    while arena.slots() < FLOOR {
        arena.alloc(applet()).expect("slot");
    }
    let one = applet();
    fail_thread_allocs_from(1024);
    let refused = arena.alloc(one);
    fail_thread_allocs_from(usize::MAX);
    assert!(refused.is_none());
    assert_eq!(ibex_rt::applet::APPCTX_POOL.failures(), failures + 1);
}

/// The task arena grows fallibly too: a task past the pre-size that cannot be had is `None`.
#[test]
fn a_task_past_the_presize_that_cannot_be_had_is_refused() {
    use ibex_sched::{Kind, TaskArena, WorkKind, TASK_POOL};
    let mut tasks = TaskArena::with_capacity(64);
    for i in 0..64 {
        tasks.alloc(WorkKind::new(Kind::Synthetic, i)).expect("slot");
    }
    let failures = TASK_POOL.failures();
    fail_thread_allocs_from(1024);
    let refused = tasks.alloc(WorkKind::new(Kind::Synthetic, 64));
    fail_thread_allocs_from(usize::MAX);
    assert!(refused.is_none());
    assert_eq!(TASK_POOL.failures(), failures + 1);
    assert_eq!(tasks.live(), 64, "the refused task is not counted");
    assert!(tasks.alloc(WorkKind::new(Kind::Synthetic, 64)).is_some());
}

/// `pool_gc` on the task arena while the fresh buffer cannot be had: the tail goes, the buffer
/// stays, the skip is counted.
#[test]
fn a_task_compaction_whose_fresh_buffer_cannot_be_had_keeps_the_old_one() {
    use ibex_sched::{Kind, TaskArena, WorkKind, TASK_POOL};
    let mut tasks = TaskArena::with_capacity(8);
    let refs: Vec<_> = (0..200).map(|i| tasks.alloc(WorkKind::new(Kind::Synthetic, i)).expect("slot")).collect();
    for &r in &refs {
        tasks.free(r);
    }
    let skipped = TASK_POOL.compactions_skipped();
    fail_thread_allocs_from(200); // the fresh 8 x 32 bytes is refused
    let released = tasks.compact();
    fail_thread_allocs_from(usize::MAX);
    assert_eq!(released, 200);
    assert!(tasks.capacity() >= 200, "the old buffer is kept");
    assert_eq!(TASK_POOL.compactions_skipped(), skipped + 1);
}

/// The switch fails growing reallocations too, not only fresh allocations: a `Vec` that
/// already holds memory and asks for more past the limit gets an error, and gets it again
/// once the limit is lifted.
#[test]
fn a_growing_realloc_past_the_limit_fails() {
    let mut v: Vec<u8> = Vec::with_capacity(64);
    v.push(1);
    fail_thread_allocs_from(LIMIT);
    let refused = v.try_reserve_exact(LIMIT);
    fail_thread_allocs_from(usize::MAX);
    assert!(refused.is_err(), "a growing realloc past the limit is refused");
    assert_eq!(v, [1], "the vector is left as it was");
    assert!(v.try_reserve_exact(LIMIT).is_ok(), "with the limit lifted it succeeds");
}
