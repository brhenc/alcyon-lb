// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The tests that justify writing a scheduler instead of adopting a runtime.
//!
//! Each one targets a mechanism from `design/003-scheduler.md` and a corresponding
//! attack. A scheduler can pass every functional test while failing all of these, which
//! is precisely why they exist: the properties are invisible under ordinary load and
//! only show up when someone is trying to hurt you.

use alcyon_sched::sched::{Class, CLASSES};
use alcyon_sched::task::{state, CallSite, Kind};
use alcyon_sched::{Dispatch, Outcome, Scheduler, Tick, WorkKind, RUNQUEUE_DEPTH};

/// Records what ran, in order.
#[derive(Default)]
struct Recorder {
    ran: Vec<WorkKind>,
}

impl Dispatch for Recorder {
    fn run(&mut self, kind: WorkKind, _state: u32) -> Outcome {
        self.ran.push(kind);
        Outcome::Keep
    }
}

fn synth(i: u32) -> WorkKind {
    WorkKind::new(Kind::Synthetic, i)
}

// ---- 1. TL_HEAVY = 1: the TLS handshake flood defence ----------------------------

#[test]
fn heavy_work_never_runs_twice_in_one_pass() {
    // A TLS handshake is cheap to request and expensive to serve. If a thread could run
    // handshakes back to back, a flood would starve established connections.
    let mut s = Scheduler::with_capacity(1024);
    let mut d = Recorder::default();

    for i in 0..100 {
        let t = s.create(synth(i)).expect("alloc");
        s.tasks.get_mut(t).state |= state::HEAVY;
        s.tasklet_wakeup(t, Class::Heavy, state::WOKEN_IO);
    }

    let ran = s.process_runnable_tasks(&mut d);
    assert_eq!(
        ran, 1,
        "a pass ran {ran} heavy items; the budget is 1 and a handshake flood would \
         starve everything else"
    );
    assert_eq!(s.stats().runs_by_class[Class::Heavy as usize], 1);
}

#[test]
fn heavy_flood_does_not_starve_established_connections() {
    // 10k pending handshakes alongside a little ordinary I/O. The I/O must still be
    // served promptly, which is the property that keeps p99 flat under attack.
    let mut s = Scheduler::with_capacity(20_000);
    let mut d = Recorder::default();

    for i in 0..10_000 {
        let t = s.create(synth(i)).expect("alloc");
        s.tasks.get_mut(t).state |= state::HEAVY;
        s.tasklet_wakeup(t, Class::Heavy, state::WOKEN_IO);
    }
    // Ten established connections with I/O ready.
    for i in 0..10 {
        let t = s.create(synth(1_000_000 + i)).expect("alloc");
        s.tasklet_wakeup(t, Class::Urgent, state::WOKEN_IO);
    }

    s.process_runnable_tasks(&mut d);

    let urgent_ran = d.ran.iter().filter(|k| k.index() >= 1_000_000).count();
    assert_eq!(
        urgent_ran, 10,
        "all 10 urgent I/O items must run in the first pass despite 10k queued \
         handshakes; only {urgent_ran} did"
    );
    assert_eq!(s.stats().runs_by_class[Class::Heavy as usize], 1);
}

// ---- 2. TL_BULK: the bandwidth-hog defence ----------------------------------------

#[test]
fn bulk_work_is_capped_well_below_normal() {
    let mut s = Scheduler::with_capacity(4096);
    let mut d = Recorder::default();

    for i in 0..1000 {
        let t = s.create(synth(i)).expect("alloc");
        s.tasklet_wakeup(t, Class::Bulk, state::WOKEN_IO);
    }
    for i in 0..1000 {
        let t = s.create(synth(1_000_000 + i)).expect("alloc");
        s.tasklet_wakeup(t, Class::Urgent, state::WOKEN_IO);
    }

    s.process_runnable_tasks(&mut d);

    let bulk = s.stats().runs_by_class[Class::Bulk as usize];
    let urgent = s.stats().runs_by_class[Class::Urgent as usize];
    assert!(
        urgent > bulk * 4,
        "urgent {urgent} should dominate bulk {bulk}; one large transfer must not \
         monopolise the thread"
    );
}

#[test]
fn self_waking_tasks_get_demoted_to_bulk() {
    // A task that asks to run again is a streaming pump. It must be demoted so it
    // cannot hold the thread against everything else.
    struct AlwaysWakes;
    impl Dispatch for AlwaysWakes {
        fn run(&mut self, _k: WorkKind, _s: u32) -> Outcome {
            Outcome::Wake
        }
    }

    let mut s = Scheduler::with_capacity(16);
    let t = s.create(synth(1)).expect("alloc");
    s.tasklet_wakeup(t, Class::Normal, state::WOKEN_IO);

    s.process_runnable_tasks(&mut AlwaysWakes);

    assert_ne!(
        s.tasks.get(t).state & state::SELF_WAKING,
        0,
        "asking to run again must mark the task self-waking"
    );
    assert_eq!(
        s.stats().runs_by_class[Class::Normal as usize],
        1,
        "the first run happens in Normal"
    );

    // Every subsequent pass must charge it to Bulk, not Normal.
    s.process_runnable_tasks(&mut AlwaysWakes);
    assert_eq!(
        s.stats().runs_by_class[Class::Bulk as usize],
        1,
        "a self-waking task must be charged to Bulk on requeue"
    );
    assert_eq!(
        s.stats().runs_by_class[Class::Normal as usize],
        1,
        "and must not keep consuming Normal budget"
    );
}

#[test]
fn a_self_waking_task_cannot_starve_normal_work() {
    // The property that matters: one pump plus a lot of ordinary work. The pump must
    // not crowd the ordinary work out.
    struct Mixed;
    impl Dispatch for Mixed {
        fn run(&mut self, k: WorkKind, _s: u32) -> Outcome {
            if k.index() == 0 {
                Outcome::Wake // the pump
            } else {
                Outcome::Done
            }
        }
    }

    let mut s = Scheduler::with_capacity(2048);
    let pump = s.create(synth(0)).expect("alloc");
    s.tasklet_wakeup(pump, Class::Normal, state::WOKEN_IO);
    for i in 1..500 {
        let t = s.create(synth(i)).expect("alloc");
        s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
    }

    for _ in 0..10 {
        s.process_runnable_tasks(&mut Mixed);
    }

    let bulk = s.stats().runs_by_class[Class::Bulk as usize];
    let normal = s.stats().runs_by_class[Class::Normal as usize];
    assert!(
        normal > bulk * 10,
        "normal work {normal} must dominate the self-waking pump {bulk}"
    );
}

// ---- 3. Bounded work per pass: the timer thundering herd --------------------------

#[test]
fn simultaneous_timer_expiry_cannot_stall_the_thread() {
    // 50k timers all due in the same millisecond. The scan must stop at the clamp.
    let mut s = Scheduler::with_capacity(60_000);
    s.set_now(Tick(1000));

    for i in 0..50_000 {
        let t = s.create(synth(i)).expect("alloc");
        s.queue_timer(t, Tick(1001));
    }

    s.set_now(Tick(2000));
    let woken = s.wake_expired_tasks();

    assert!(
        woken <= RUNQUEUE_DEPTH as usize,
        "one expiry scan woke {woken}, above the {RUNQUEUE_DEPTH} clamp; a thundering \
         herd would stall the thread"
    );
    assert_eq!(
        s.stats().timer_scan_clamped,
        1,
        "the scan should have reported hitting its clamp"
    );
}

#[test]
fn run_pass_is_bounded_regardless_of_queue_depth() {
    let mut s = Scheduler::with_capacity(60_000);
    let mut d = Recorder::default();

    for i in 0..50_000 {
        let t = s.create(synth(i)).expect("alloc");
        s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
    }

    let ran = s.process_runnable_tasks(&mut d);
    assert!(
        ran <= RUNQUEUE_DEPTH as usize,
        "one pass ran {ran}, above the {RUNQUEUE_DEPTH} clamp"
    );
    assert!(s.runnable() > 0, "the rest must remain queued, not dropped");
}

// ---- 4. Lazy timer requeue: the slowloris defence ---------------------------------

#[test]
fn extending_a_timeout_touches_no_tree_node() {
    // THE slowloris test. 1000 connections, each dribbling a byte 100 times, every
    // byte pushing its timeout further out. A naive scheduler performs 100k timer
    // remove+reinsert pairs -- overhead manufactured entirely by the attacker, for
    // timers that will never fire. This must perform none.
    let mut s = Scheduler::with_capacity(4096);
    s.set_now(Tick(10_000));

    let conns: Vec<_> = (0..1000)
        .map(|i| {
            let t = s.create(synth(i)).expect("alloc");
            s.queue_timer(t, Tick(20_000));
            t
        })
        .collect();

    let inserts_after_setup = s.stats().timer_inserts;
    let deletes_after_setup = s.stats().timer_deletes;
    assert_eq!(inserts_after_setup, 1000);

    for round in 1..=100u32 {
        for (n, &t) in conns.iter().enumerate() {
            let offset = u32::try_from(n).unwrap_or(0) % 7;
            s.queue_timer(t, Tick(20_000 + round * 10 + offset));
        }
    }

    assert_eq!(
        s.stats().timer_inserts,
        inserts_after_setup,
        "extending timeouts inserted tree nodes; this is the slowloris amplification"
    );
    assert_eq!(
        s.stats().timer_deletes,
        deletes_after_setup,
        "extending timeouts deleted tree nodes"
    );
    assert_eq!(
        s.stats().timer_requeue_skipped,
        100_000,
        "all 100k extensions should have been absorbed without touching the tree"
    );
}

#[test]
fn shortening_a_timeout_does_move_the_node() {
    // The converse: moving a deadline *earlier* must take effect immediately, or a
    // timeout would fire late.
    let mut s = Scheduler::with_capacity(16);
    s.set_now(Tick(1000));
    let t = s.create(synth(1)).expect("alloc");
    s.queue_timer(t, Tick(5000));
    let before = s.stats().timer_inserts;

    s.queue_timer(t, Tick(2000));
    assert_eq!(
        s.stats().timer_inserts,
        before + 1,
        "an earlier deadline must be reinserted"
    );

    s.set_now(Tick(2001));
    assert_eq!(s.wake_expired_tasks(), 1, "the earlier deadline must fire");
}

#[test]
fn lazily_extended_timers_still_fire_at_the_right_time() {
    // The correctness obligation that pays for the optimisation: a stale key must be
    // repaired on encounter, and the task must not fire early.
    let mut s = Scheduler::with_capacity(16);
    s.set_now(Tick(1000));

    let t = s.create(synth(1)).expect("alloc");
    s.queue_timer(t, Tick(1100));
    s.queue_timer(t, Tick(5000)); // lazy: tree still says 1100
    assert_eq!(s.stats().timer_requeue_skipped, 1);

    // At 1200 the tree entry looks due but the task is not.
    s.set_now(Tick(1200));
    assert_eq!(s.wake_expired_tasks(), 0, "must not fire early");
    assert_eq!(
        s.stats().timer_lazy_repairs,
        1,
        "the stale key should have been repaired on encounter"
    );

    s.set_now(Tick(5001));
    assert_eq!(s.wake_expired_tasks(), 1, "must fire at the real deadline");
}

// ---- ordering and fairness --------------------------------------------------------

#[test]
fn equal_priority_runs_fifo() {
    let mut s = Scheduler::with_capacity(64);
    let mut d = Recorder::default();
    for i in 0..20 {
        let t = s.create(synth(i)).expect("alloc");
        s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
    }
    s.process_runnable_tasks(&mut d);
    let order: Vec<u32> = d.ran.iter().map(|k| k.index()).collect();
    assert_eq!(order, (0..20).collect::<Vec<u32>>(), "must be FIFO");
}

#[test]
fn negative_nice_runs_earlier() {
    let mut s = Scheduler::with_capacity(64);
    let mut d = Recorder::default();

    for i in 0..10 {
        let t = s.create(synth(i)).expect("alloc");
        s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
    }
    // Queued last, but with priority.
    let vip = s.create(synth(999)).expect("alloc");
    s.tasks.get_mut(vip).nice = -1;
    s.wakeup(vip, state::WOKEN_MSG, CallSite::UNKNOWN);

    s.process_runnable_tasks(&mut d);
    assert_eq!(
        d.ran.first().map(|k| k.index()),
        Some(999),
        "a niced task queued last must still run first"
    );
}

#[test]
fn a_task_cannot_run_twice_in_one_pass() {
    // src/task.c:543. A task that re-queues itself must not be re-run in the same
    // pass, or a single task could hold the thread indefinitely.
    struct Requeue {
        count: usize,
    }
    impl Dispatch for Requeue {
        fn run(&mut self, _k: WorkKind, _s: u32) -> Outcome {
            self.count += 1;
            Outcome::Keep
        }
    }

    let mut s = Scheduler::with_capacity(16);
    let t = s.create(synth(1)).expect("alloc");
    s.tasklet_wakeup(t, Class::Normal, state::WOKEN_IO);

    let mut d = Requeue { count: 0 };
    s.process_runnable_tasks(&mut d);
    assert_eq!(d.count, 1);

    // Re-queue and run again: a new pass, so it may run once more.
    s.tasklet_wakeup(t, Class::Normal, state::WOKEN_IO);
    s.process_runnable_tasks(&mut d);
    assert_eq!(d.count, 2, "a fresh pass must allow it to run again");
}

// ---- lifecycle --------------------------------------------------------------------

#[test]
fn done_tasks_are_freed_and_slots_reused() {
    struct Finisher;
    impl Dispatch for Finisher {
        fn run(&mut self, _k: WorkKind, _s: u32) -> Outcome {
            Outcome::Done
        }
    }

    let mut s = Scheduler::with_capacity(64);
    for i in 0..10 {
        let t = s.create(synth(i)).expect("alloc");
        s.wakeup(t, state::WOKEN_MSG, CallSite::UNKNOWN);
    }
    assert_eq!(s.tasks.live(), 10);
    s.process_runnable_tasks(&mut Finisher);
    assert_eq!(s.tasks.live(), 0, "finished tasks must be freed");
    assert!(!s.has_work());
}

#[test]
fn destroying_a_timed_task_unlinks_it() {
    let mut s = Scheduler::with_capacity(16);
    s.set_now(Tick(100));
    let t = s.create(synth(1)).expect("alloc");
    s.queue_timer(t, Tick(200));
    s.destroy(t);
    assert_eq!(s.tasks.live(), 0);
    s.set_now(Tick(300));
    assert_eq!(s.wake_expired_tasks(), 0, "a destroyed timer must not fire");
}

#[test]
fn next_expiry_reports_the_earliest_deadline() {
    let mut s = Scheduler::with_capacity(64);
    s.set_now(Tick(1000));
    assert_eq!(s.next_expiry(), Tick::ETERNITY, "empty tree means eternity");

    for e in [5000u32, 2000, 9000, 3000] {
        let t = s.create(synth(e)).expect("alloc");
        s.queue_timer(t, Tick(e));
    }
    assert_eq!(s.next_expiry(), Tick(2000));
}

#[test]
fn all_classes_are_covered_by_weights() {
    assert_eq!(CLASSES, 5);
}
