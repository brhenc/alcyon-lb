// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
// Own binary (T465): its #[global_allocator] fails this thread's allocations on demand.

//! Taking a task off its queues never allocates, and a task whose queue slots cannot be had is
//! refused when it is created (`tradeoff.md` 6.23, T465).
//!
//! S5's T446 run (`RLIMIT_DATA` 640 MB, 20000 connections) aborted with "memory allocation of
//! 64 bytes failed" in `ebtree::Eb32Tree::unlink_and_recycle`: the timer tree's free list grew
//! on a delete, from `Scheduler::unlink_wq` / `destroy`. A delete is how memory is given back;
//! it must not need any.

use ibex_alloc::{fail_thread_allocs_from, CountingAllocator};
use ibex_sched::task::{state, CallSite, Kind};
use ibex_sched::{Scheduler, Tick, WorkKind};

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

fn synth(i: u32) -> WorkKind {
    WorkKind::new(Kind::Synthetic, i)
}

/// Every allocation on this thread fails while `f` runs.
fn with_allocations_failing<R>(f: impl FnOnce() -> R) -> R {
    fail_thread_allocs_from(1);
    let r = f();
    fail_thread_allocs_from(usize::MAX);
    r
}

#[test]
fn timers_and_run_queue_entries_are_deleted_while_allocations_fail() {
    let mut s = Scheduler::with_capacity(64);
    let tasks: Vec<_> = (0..64).map(|i| s.create(synth(i)).expect("create")).collect();
    for (i, &t) in (0u32..).zip(&tasks) {
        s.queue_timer(t, Tick(10 + i));
    }
    let woken = with_allocations_failing(|| {
        for &t in &tasks[..16] {
            s.destroy(t);
        }
        s.set_now(Tick(40));
        let woken = s.wake_expired_tasks();
        for &t in &tasks[16..] {
            s.destroy(t);
        }
        woken
    });
    assert_eq!(woken, 15, "the timers at 26..=40 expired");
    assert_eq!(s.run_queue_len(), 0);
    assert_eq!(s.next_expiry(), Tick::ETERNITY);
    assert_eq!(s.tasks.live(), 0);
}

#[test]
fn a_task_whose_queue_slots_cannot_be_had_is_not_created() {
    let mut s = Scheduler::with_capacity(4);
    let first: Vec<_> = (0..4).map(|i| s.create(synth(i)).expect("create")).collect();
    for &t in &first {
        s.queue_timer(t, Tick(100));
        s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
    }
    // The task arena has room for a fifth task; the trees, sized with the first four, do not.
    s.tasks.reserve(60);
    let fifth = with_allocations_failing(|| {
        let t = s.create(synth(4));
        if let Some(t) = t {
            s.queue_timer(t, Tick(100));
            s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
        }
        t
    });
    assert!(fifth.is_none(), "created a task whose timer slot cannot be had");
    assert_eq!(s.tasks.live(), 4);
    let more: Vec<_> = (5..40).map(|i| s.create(synth(i)).expect("create once memory is back")).collect();
    for &t in &more {
        s.queue_timer(t, Tick(100));
        s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
    }
    assert_eq!(s.run_queue_len(), 39);
}

#[test]
fn tasks_reserved_at_boot_are_destroyed_while_allocations_fail() {
    let mut s = Scheduler::with_capacity(4);
    s.reserve(60);
    let tasks: Vec<_> = (0..60).map(|i| s.create(synth(i)).expect("create")).collect();
    for &t in &tasks {
        s.queue_timer(t, Tick(100));
    }
    with_allocations_failing(|| {
        for &t in &tasks {
            s.destroy(t);
        }
    });
    assert_eq!(s.tasks.live(), 0);
    assert!(s.create(synth(0)).is_some());
}
