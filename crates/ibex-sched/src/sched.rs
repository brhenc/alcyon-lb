// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/task.c (process_runnable_tasks, run_tasks_from_lists,
// wake_expired_tasks, __task_wakeup, __task_queue) and include/haproxy/task.h.
// Copyright (C) 2000-2026 Willy Tarreau <w@1wt.eu> and HAProxy contributors.
// See LICENSE in the repository root.

//! The scheduler proper.

use crate::task::{state, CallSite, NodeRef, TaskArena, TaskRef, WorkKind};
use crate::tick::Tick;
use ebtree::Eb32Tree;

/// Items processed per pass before the loop yields. `HAProxy`'s `RUNQUEUE_DEPTH`.
pub const RUNQUEUE_DEPTH: u32 = 280;

/// Scheduling classes, in descending priority.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Class {
    /// Rare but time-sensitive. At most one per pass.
    Rt = 0,
    /// I/O callbacks. Roughly half of CPU bandwidth.
    Urgent = 1,
    /// Ordinary tasks. Roughly the other half.
    Normal = 2,
    /// Self-waking work such as bulk streaming, capped near 3% so one large
    /// transfer cannot monopolise a thread.
    Bulk = 3,
    /// Expensive computation, canonically a TLS handshake. **At most one per pass**,
    /// which is what stops a handshake flood starving established connections.
    Heavy = 4,
}

/// Number of scheduling classes.
pub const CLASSES: usize = 5;

/// Per-pass budgets. These are `HAProxy`'s numbers (`src/task.c:720`) and the two
/// extremes are the load-bearing ones: `Heavy` = 1 and `Bulk` = 4.
const DEFAULT_WEIGHTS: [u32; CLASSES] = [1, 64, 60, 4, 1];

impl Class {
    const ALL: [Class; CLASSES] = [
        Class::Rt,
        Class::Urgent,
        Class::Normal,
        Class::Bulk,
        Class::Heavy,
    ];

    #[inline]
    const fn idx(self) -> usize {
        self as usize
    }
}

/// What a task's execution decided about its own future.
///
/// C expresses "run me again" as a side effect: the task calls `task_wakeup()` on
/// itself from inside its own `process` function. Rust cannot express that directly,
/// since the scheduler is already mutably borrowed for the duration of the call — and
/// that turns out to be an improvement. Making it a return value means the scheduler
/// learns about self-waking *from the type* rather than by inspecting state afterwards,
/// so the `Bulk` demotion cannot be missed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Still alive, nothing more to do now. Leave it allocated and unqueued.
    Keep,
    /// Run me again. The task is re-queued and marked self-waking, which demotes it to
    /// [`Class::Bulk`] so a streaming pump cannot monopolise the thread.
    Wake,
    /// Finished; unlink from every queue and free the slot.
    Done,
}

/// Runs the work a task names.
///
/// Taken as a generic parameter of the run loop rather than stored, so dispatch is a
/// direct monomorphised call with no allocation, no vtable and no indirection — see
/// `design/006-data-layout.md` §2.
pub trait Dispatch {
    /// Executes `kind`. `state` carries the `state::WOKEN_*` bits that caused this run.
    fn run(&mut self, kind: WorkKind, state: u32) -> Outcome;

    /// A task the last run woke for this pass (`wake_now`): the owner of a connection and
    /// its stream hand each other work, and the one woken runs in the same pass, not after
    /// another `epoll_wait`. Asked after every run until `None`. A task may run twice in a
    /// pass this way; a third wake waits for the next pass.
    #[inline]
    fn pop_wake_now(&mut self) -> Option<TaskRef> {
        None
    }
}

/// Counters, kept because the adversarial-load properties are otherwise unobservable
/// and therefore untestable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub timer_inserts: u64,
    pub timer_deletes: u64,
    /// Timeout extensions that touched **no** tree node. The slowloris metric: under a
    /// dribbling-bytes attack this should climb while `timer_inserts` stays flat.
    pub timer_requeue_skipped: u64,
    /// Stale keys repaired lazily during an expiry scan.
    pub timer_lazy_repairs: u64,
    /// Expiry scans that stopped because they hit the per-pass clamp.
    pub timer_scan_clamped: u64,
    /// Run passes that stopped because they hit the per-pass clamp.
    pub run_clamped: u64,
    pub tasks_run: u64,
    pub runs_by_class: [u64; CLASSES],
    pub passes: u64,
}

/// A singly-linked intrusive list of tasks.
///
/// Singly linked so the link fits in the 32-byte task. Removal from the middle is done
/// by setting `state::KILLED` and skipping the task when it is popped, rather than by
/// unlinking — O(1) either way, and it saves the back-pointer.
#[derive(Clone, Debug)]
struct TaskletList {
    head: TaskRef,
    tail: TaskRef,
    len: u32,
}

impl TaskletList {
    const fn new() -> Self {
        TaskletList {
            head: TaskRef::NONE,
            tail: TaskRef::NONE,
            len: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A single thread's scheduler. Deliberately not `Send`: under thread-per-core the
/// affinity invariant is enforced by the type system rather than by convention.
pub struct Scheduler {
    /// Task storage. Public so subsystems can read and set `nice`, `expire`, etc.
    pub tasks: TaskArena,
    /// Run queue, keyed by `ticks + nice * RUNQUEUE_DEPTH`.
    rqueue: Eb32Tree,
    /// Wait queue, keyed by expiry tick.
    timers: Eb32Tree,
    tasklets: [TaskletList; CLASSES],
    rqueue_ticks: u32,
    rq_total: u32,
    niced_tasks: u32,
    now: Tick,
    loops: u16,
    stats: Stats,
    /// Marker making the type `!Send`, so a scheduler cannot cross threads.
    _not_send: core::marker::PhantomData<*const ()>,
}

impl Scheduler {
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Scheduler {
            tasks: TaskArena::with_capacity(cap),
            rqueue: Eb32Tree::with_capacity(cap),
            timers: Eb32Tree::with_capacity(cap),
            tasklets: [const { TaskletList::new() }; CLASSES],
            rqueue_ticks: 0,
            rq_total: 0,
            niced_tasks: 0,
            now: Tick(1),
            loops: 0,
            stats: Stats::default(),
            _not_send: core::marker::PhantomData,
        }
    }

    #[must_use]
    pub const fn stats(&self) -> &Stats {
        &self.stats
    }

    #[must_use]
    pub const fn now(&self) -> Tick {
        self.now
    }

    /// Advances the clock. In production this comes from the poll loop.
    pub fn set_now(&mut self, now: Tick) {
        self.now = now;
    }

    #[must_use]
    pub const fn runnable(&self) -> u32 {
        self.rq_total
    }

    /// The class a task belongs in, given its state. `Heavy` and self-waking `Bulk`
    /// both take precedence over `Normal`.
    fn class_for(&self, r: TaskRef) -> Class {
        let st = self.tasks.get(r).state;
        if st & state::HEAVY != 0 {
            Class::Heavy
        } else if st & state::SELF_WAKING != 0 {
            Class::Bulk
        } else {
            Class::Normal
        }
    }

    /// True if any class has work pending.
    #[must_use]
    pub fn has_work(&self) -> bool {
        self.rq_total > 0 || self.tasklets.iter().any(|l| !l.is_empty())
    }

    /// Whether `r` names a live task. A task the scheduler freed (its run returned
    /// [`Outcome::Done`]) is not, and a caller holding its reference must drop it.
    #[must_use]
    #[inline]
    pub fn is_live(&self, r: TaskRef) -> bool {
        self.tasks.is_live(r)
    }

    /// Total number of currently allocated tasks in the arena.
    #[must_use]
    #[inline]
    pub const fn live_tasks(&self) -> usize {
        self.tasks.live()
    }

    /// Total number of tasks currently in the run queue and tasklet lists.
    #[must_use]
    pub fn run_queue_len(&self) -> usize {
        self.rq_total as usize + self.tasklets.iter().map(|l| l.len as usize).sum::<usize>()
    }

    // ---- queue membership --------------------------------------------------------

    /// Marks `r` as linked into a tasklet list, first checking it is in none.
    ///
    /// The lists are singly linked and counted, so a task linked twice is not visible
    /// where it happens: it shows up passes later as a cycle or as `pop_tasklet`
    /// underflowing a length (T100). This is where it is caught instead.
    fn mark_linked(tasks: &mut TaskArena, r: TaskRef) {
        let t = tasks.get_mut(r);
        debug_assert!(!t.freed(), "linking a freed task {r:?} into a tasklet list");
        debug_assert!(
            !t.in_tasklet_list(),
            "task {r:?} linked twice into the tasklet lists"
        );
        t.state |= state::IN_TL;
    }

    /// Whether `r` may be scheduled: false for a freed slot, which no scheduling
    /// operation may touch. A stale reference to one is a caller's bug (T100): debug
    /// builds stop on it, and release builds refuse the operation rather than corrupt
    /// the queues with it.
    fn usable(&self, r: TaskRef, op: &str) -> bool {
        let freed = self.tasks.get(r).freed();
        debug_assert!(!freed, "{op} on freed task {r:?}");
        !freed
    }

    fn push_tasklet(&mut self, class: Class, r: TaskRef) {
        let Self {
            tasks, tasklets, ..
        } = self;
        Self::mark_linked(tasks, r);
        tasks.get_mut(r).tl_next = TaskRef::NONE;
        let l = &mut tasklets[class.idx()];
        if l.tail.is_none() {
            l.head = r;
        } else {
            tasks.get_mut(l.tail).tl_next = r;
        }
        l.tail = r;
        l.len += 1;
    }

    fn push_tasklet_front(&mut self, class: Class, r: TaskRef) {
        let Self {
            tasks, tasklets, ..
        } = self;
        Self::mark_linked(tasks, r);
        let l = &mut tasklets[class.idx()];
        tasks.get_mut(r).tl_next = l.head;
        l.head = r;
        if l.tail.is_none() {
            l.tail = r;
        }
        l.len += 1;
    }

    fn pop_tasklet(&mut self, class: Class) -> Option<TaskRef> {
        let Self {
            tasks, tasklets, ..
        } = self;
        let l = &mut tasklets[class.idx()];
        if l.head.is_none() {
            return None;
        }
        let r = l.head;
        let next = tasks.get(r).tl_next;
        l.head = next;
        if next.is_none() {
            l.tail = TaskRef::NONE;
        }
        debug_assert!(
            l.len > 0,
            "tasklet list {class:?} non-empty with a length of 0"
        );
        l.len -= 1;
        let t = tasks.get_mut(r);
        debug_assert!(
            t.in_tasklet_list(),
            "popped task {r:?} was not marked as linked"
        );
        t.tl_next = TaskRef::NONE;
        t.state &= !state::IN_TL;
        Some(r)
    }

    /// Removes a task from the run queue if present.
    fn unlink_rq(&mut self, r: TaskRef) {
        let node = self.tasks.get(r).rq_ref;
        if node.is_none() {
            return;
        }
        self.rqueue.delete(node.0);
        let t = self.tasks.get_mut(r);
        t.rq_ref = NodeRef::NONE;

        if t.nice != 0 {
            self.niced_tasks = self.niced_tasks.saturating_sub(1);
        }
        self.rq_total = self.rq_total.saturating_sub(1);
    }

    /// Removes a task from the wait queue if present.
    fn unlink_wq(&mut self, r: TaskRef) {
        let node = self.tasks.get(r).wq_ref;
        if node.is_none() {
            return;
        }
        self.timers.delete(node.0);
        self.stats.timer_deletes += 1;
        let t = self.tasks.get_mut(r);
        t.wq_ref = NodeRef::NONE;
        t.state &= !state::IN_WQ;
    }

    fn insert_wq(&mut self, r: TaskRef) {
        let expire = self.tasks.get(r).expire;
        debug_assert!(expire.is_set());
        let node = self.timers.insert(expire.0, r.0);
        self.stats.timer_inserts += 1;
        let t = self.tasks.get_mut(r);
        t.wq_ref = NodeRef(node);
        t.state |= state::IN_WQ;
    }

    // ---- public scheduling API ----------------------------------------------------

    /// Makes room, at boot, for `additional` more tasks that will each wait on a timer:
    /// the task arena and the timer tree grow once to the size needed rather than by
    /// doubling (T304: 60,000 health checks grew both to 65,536 slots).
    pub fn reserve(&mut self, additional: usize) {
        self.tasks.reserve(additional);
        // As large as the arena, so that `create` finds it so (fallible: `create` tries again).
        let _ = self.timers.try_reserve_total(self.tasks.capacity());
    }

    /// Allocates a task. `None` when its slot, or its room in the timer tree, cannot be had:
    /// each task holds at most one timer node, so a tree as large as the task arena never
    /// grows on an insert (T465). The run queue grows on a wakeup, fallibly
    /// ([`Self::wakeup`]): reserving it here too would cost every task its node up front.
    pub fn create(&mut self, kind: WorkKind) -> Option<TaskRef> {
        let r = self.tasks.alloc(kind)?;
        let cap = self.tasks.capacity();
        if self.timers.capacity() < cap {
            return self.reserve_timer(r, cap);
        }
        Some(r)
    }

    #[cold]
    #[inline(never)]
    fn reserve_timer(&mut self, r: TaskRef, cap: usize) -> Option<TaskRef> {
        if self.timers.try_reserve_total(cap) {
            return Some(r);
        }
        crate::task::TASK_POOL.failed();
        self.tasks.free(r);
        None
    }

    /// Destroys a task, unlinking it from every queue first.
    pub fn destroy(&mut self, r: TaskRef) {
        if r.is_none() || self.tasks.get(r).freed() {
            return;
        }
        self.unlink_rq(r);
        self.unlink_wq(r);
        if self.tasks.get(r).in_tasklet_list() {
            // Still linked into a tasklet list; defer the free until it is popped.
            self.tasks.get_mut(r).state |= state::KILLED;
            return;
        }
        // `QUEUED` without a tasklet list was the run queue, now left.
        self.tasks.get_mut(r).state &= !state::QUEUED;
        self.tasks.free(r);
    }

    /// Schedules a task to run, inserting it into the run queue.
    ///
    /// Mirrors `__task_wakeup()`. The key is a monotonically increasing ticket offset by
    /// `nice * RUNQUEUE_DEPTH`, which gets FIFO ordering among equal priorities and
    /// priority as a displacement, both out of one ordered structure.
    pub fn wakeup(&mut self, r: TaskRef, reason: u32, caller: CallSite) {
        if self.usable(r, "wakeup") {
            self.wakeup_live(r, reason, caller);
        }
    }

    fn wakeup_live(&mut self, r: TaskRef, reason: u32, caller: CallSite) {
        {
            let t = self.tasks.get_mut(r);
            if t.state & (state::QUEUED | state::RUNNING) != 0 {
                // Already pending, or waking itself mid-run. Record the reason only;
                // re-queueing would double-run it.
                t.state |= reason;
                t.caller = caller;
                return;
            }
            t.state |= state::QUEUED | reason;
            t.caller = caller;
        }

        if !self.rqueue.try_room_for_one() {
            // No memory for its node: the task goes to the Normal list, where the run queue
            // would have moved it, without its place in the order (T465).
            self.push_tasklet(Class::Normal, r);
            return;
        }

        self.rqueue_ticks = self.rqueue_ticks.wrapping_add(1);
        let mut key = self.rqueue_ticks;

        let nice = self.tasks.get(r).nice;
        if nice != 0 {
            let offset =
                i32::from(nice).saturating_mul(i32::try_from(RUNQUEUE_DEPTH).unwrap_or(i32::MAX));
            key = key.wrapping_add(u32::from_ne_bytes(offset.to_ne_bytes()));
            self.niced_tasks += 1;
        }

        let node = self.rqueue.insert(key, r.0);
        self.tasks.get_mut(r).rq_ref = NodeRef(node);
        self.rq_total += 1;
    }

    /// Schedules a task directly into a tasklet class, bypassing the run queue.
    /// This is the path I/O readiness callbacks take.
    pub fn tasklet_wakeup(&mut self, r: TaskRef, class: Class, reason: u32) {
        if self.usable(r, "tasklet_wakeup") {
            self.tasklet_wakeup_live(r, class, reason);
        }
    }

    fn tasklet_wakeup_live(&mut self, r: TaskRef, class: Class, reason: u32) {
        let heavy = {
            let t = self.tasks.get_mut(r);
            if t.state & state::QUEUED != 0 {
                t.state |= reason;
                return;
            }
            t.state |= state::QUEUED | reason;
            t.state & state::HEAVY != 0
        };
        // A heavy task goes to `Heavy` whoever wakes it, as `__tasklet_wakeup_here`
        // (src/task.c) checks `TASK_HEAVY` before the class the caller asked for: the
        // one-per-pass cap means nothing if an I/O wakeup can put it among the urgent.
        self.push_tasklet(if heavy { Class::Heavy } else { class }, r);
    }

    /// Marks `r` heavy (a TLS handshake in progress: `TASK_HEAVY`, set by `ssl_sock_init`)
    /// or not (cleared once the handshake is done). A heavy task is woken into `Heavy`,
    /// of which one runs per pass.
    pub fn set_heavy(&mut self, r: TaskRef, heavy: bool) {
        if self.usable(r, "set_heavy") {
            let t = self.tasks.get_mut(r);
            if heavy {
                t.state |= state::HEAVY;
            } else {
                t.state &= !state::HEAVY;
            }
        }
    }

    /// Whether `r` is marked heavy.
    #[must_use]
    pub fn is_heavy(&self, r: TaskRef) -> bool {
        self.tasks.is_live(r) && self.tasks.get(r).state & state::HEAVY != 0
    }

    /// Sets a task's timeout.
    ///
    /// **This is the slowloris defence.** Mirrors `task_queue()`: if the task already
    /// has a timer and the new expiry is *not earlier* than the one recorded in the
    /// tree, the tree is left completely alone and only the task's own field is
    /// updated. Extending a timeout — which is what every received byte does — costs
    /// zero tree operations.
    ///
    /// The stale key is repaired lazily by [`Self::wake_expired_tasks`], and only if
    /// that entry is ever actually examined.
    pub fn queue_timer(&mut self, r: TaskRef, expire: Tick) {
        if self.usable(r, "queue_timer") {
            self.queue_timer_live(r, expire);
        }
    }

    fn queue_timer_live(&mut self, r: TaskRef, expire: Tick) {
        self.tasks.get_mut(r).expire = expire;

        if !expire.is_set() {
            return;
        }

        if self.tasks.get(r).in_wq() {
            let node = self.tasks.get(r).wq_ref;
            let tree_key = Tick(self.timers.key_of(node.0));
            if !expire.is_before(tree_key) {
                // Later than what the tree says. Leave it; repair on encounter.
                self.stats.timer_requeue_skipped += 1;
                return;
            }
            self.unlink_wq(r);
        }

        self.insert_wq(r);
    }

    /// The earliest pending expiry, for sizing the poll timeout.
    #[must_use]
    pub fn next_expiry(&self) -> Tick {
        self.timers
            .lookup_ge(self.now.0.wrapping_sub(Tick::LOOK_BACK))
            .or_else(|| self.timers.first())
            .map_or(Tick::ETERNITY, |n| Tick(self.timers.key_of(n)))
    }

    // ---- the two loops -------------------------------------------------------------

    /// Wakes every task whose timer has expired.
    ///
    /// Mirrors `wake_expired_tasks()`. Bounded at [`RUNQUEUE_DEPTH`] per call, so a
    /// flood of simultaneously-expiring timers cannot stall the thread — the scan
    /// returns and I/O gets serviced.
    pub fn wake_expired_tasks(&mut self) -> usize {
        let mut budget = RUNQUEUE_DEPTH;
        let mut woken = 0usize;

        loop {
            if budget == 0 {
                self.stats.timer_scan_clamped += 1;
                break;
            }
            budget -= 1;

            // Scan the key space as a circle: look from half the tick space behind,
            // and on falling off the end wrap to the first entry.
            let Some(node) = self
                .timers
                .lookup_ge(self.now.0.wrapping_sub(Tick::LOOK_BACK))
                .or_else(|| self.timers.first())
            else {
                break;
            };

            let tr = TaskRef(self.timers.data_of(node));
            let tree_key = self.timers.key_of(node);
            let expire = self.tasks.get(tr).expire;

            if expire.is_expired(self.now) {
                self.unlink_wq(tr);
                self.wakeup(tr, state::WOKEN_TIMER, CallSite::UNKNOWN);
                woken += 1;
            } else if expire.0 != tree_key {
                // A lazy extension left a stale key here. Repair it now and carry on;
                // this is the deferred cost of never having touched the tree earlier.
                self.unlink_wq(tr);
                if expire.is_set() {
                    self.insert_wq(tr);
                }
                self.stats.timer_lazy_repairs += 1;
            } else {
                // Correctly placed and not due. Everything after it is later still.
                break;
            }
        }

        woken
    }

    /// Computes this pass's per-class budgets.
    ///
    /// Weights are scaled into `max_processed`, but `Rt` and `Heavy` keep a hard cap of
    /// one regardless of scaling — that cap is the anti-starvation guarantee, not a
    /// tuning parameter.
    fn compute_budgets(&self, max_processed: u32) -> [u32; CLASSES] {
        let mut max = [0u32; CLASSES];
        for c in Class::ALL {
            let i = c.idx();
            let has = if c == Class::Normal {
                !self.tasklets[i].is_empty() || self.rq_total > 0
            } else {
                !self.tasklets[i].is_empty()
            };
            if has {
                max[i] = DEFAULT_WEIGHTS[i];
            }
        }

        let total: u32 = max.iter().sum();
        if total == 0 {
            return max;
        }

        for m in &mut max {
            if *m != 0 {
                *m = (m.saturating_mul(max_processed) / total).max(1);
            }
        }

        // Hard caps. Never more than one Rt or Heavy item in a single pass.
        max[Class::Rt.idx()] = max[Class::Rt.idx()].min(1);
        max[Class::Heavy.idx()] = max[Class::Heavy.idx()].min(1);
        max
    }

    /// Runs one scheduling pass.
    ///
    /// Mirrors `process_runnable_tasks()` followed by `run_tasks_from_lists()`.
    /// Returns the number of tasks executed.
    pub fn process_runnable_tasks<D: Dispatch>(&mut self, d: &mut D) -> usize {
        self.loops = self.loops.wrapping_add(1);
        self.stats.passes += 1;

        let mut max_processed = RUNQUEUE_DEPTH;
        if self.niced_tasks > 0 {
            max_processed = max_processed.div_ceil(4);
        }
        if max_processed < self.rq_total && self.rq_total <= 2 * max_processed {
            // Moderately over budget: deliberately do only half, splitting one long
            // pass into two shorter ones to cut latency.
            max_processed = self.rq_total / 2;
        }

        let mut budgets = self.compute_budgets(max_processed);

        // Drain the run queue into the Normal tasklet list, in key order.
        //
        // The scan is *circular* relative to `rqueue_ticks`, exactly as
        // `src/task.c:861` does it, and this is load-bearing rather than defensive.
        // A task with `nice = -1` gets key `ticks - RUNQUEUE_DEPTH`, which underflows
        // to a very large u32; read as an ordinary integer it sorts last, which is the
        // precise opposite of the intended priority. Read as a point on a circle
        // half a tick-space behind the current counter, it sorts first, as intended.
        let pull = budgets[Class::Normal.idx()];
        for _ in 0..pull {
            let Some(node) = self
                .rqueue
                .lookup_ge(self.rqueue_ticks.wrapping_sub(Tick::LOOK_BACK))
                .or_else(|| self.rqueue.first())
            else {
                break;
            };
            let tr = TaskRef(self.rqueue.data_of(node));
            self.unlink_rq(tr);
            self.push_tasklet(Class::Normal, tr);
        }
        if self.rq_total > 0 {
            self.stats.run_clamped += 1;
        }

        self.run_tasks_from_lists(d, &mut budgets)
    }

    fn run_tasks_from_lists<D: Dispatch>(
        &mut self,
        d: &mut D,
        budgets: &mut [u32; CLASSES],
    ) -> usize {
        let mut done = 0usize;
        // Runs the pass's instant wakes may add, over every class (as `HAProxy`'s lists take
        // what is woken while they run, within the pass's budget).
        let mut instant_left = RUNQUEUE_DEPTH;

        let mut ci = 0;
        while ci < CLASSES {
            let c = Class::ALL[ci];
            let i = c.idx();
            // An instant wake into a class before this one: look at it again after.
            let mut back: Option<usize> = None;
            while budgets[i] > 0 {
                let Some(tr) = self.pop_tasklet(c) else { break };

                if self.tasks.get(tr).killed() {
                    self.tasks.get_mut(tr).state &= !state::QUEUED;
                    self.unlink_rq(tr);
                    self.unlink_wq(tr);
                    self.tasks.free(tr);
                    continue;
                }

                // Anti-starvation: a task that already ran in this pass goes back and its
                // whole class stops, so a self-requeueing task cannot run twice. One woken
                // for this pass by another task (`pop_wake_now`) runs a second time; a third
                // waits.
                {
                    let t = self.tasks.get_mut(tr);
                    if t.last_run == self.loops {
                        if t.state & (state::WOKEN_NOW | state::RERAN) != state::WOKEN_NOW {
                            self.push_tasklet_front(c, tr);
                            budgets[i] = 0;
                            break;
                        }
                        t.state |= state::RERAN;
                    } else {
                        t.state &= !state::RERAN;
                    }
                }

                let (kind, st) = {
                    let t = self.tasks.get_mut(tr);
                    t.last_run = self.loops;
                    t.state &= !(state::QUEUED | state::WOKEN_NOW);
                    t.state |= state::RUNNING;
                    (t.kind, t.state)
                };

                let outcome = d.run(kind, st);

                {
                    let t = self.tasks.get_mut(tr);
                    t.state &= !(state::RUNNING | state::WOKEN_ANY);
                }

                budgets[i] -= 1;
                done += 1;
                self.stats.tasks_run += 1;
                self.stats.runs_by_class[i] += 1;

                match outcome {
                    Outcome::Done => self.destroy(tr),
                    Outcome::Wake => {
                        // Asked to run again from inside its own execution. Mark it
                        // self-waking and requeue into the class that implies, which
                        // for anything but Heavy means Bulk and its ~3% budget.
                        self.tasks.get_mut(tr).state |= state::SELF_WAKING;
                        let class = self.class_for(tr);
                        self.tasklet_wakeup(tr, class, state::WOKEN_MSG);
                    }
                    Outcome::Keep => {}
                }

                while let Some(r) = d.pop_wake_now() {
                    let Some(into) = self.wake_now(r) else { continue };
                    // `Rt` and `Heavy` keep their one a pass.
                    if instant_left > 0 && !matches!(into, Class::Rt | Class::Heavy) {
                        instant_left -= 1;
                        budgets[into.idx()] += 1;
                    }
                    if into.idx() < i {
                        back = Some(back.map_or(into.idx(), |b| b.min(into.idx())));
                    }
                }
            }
            ci = back.unwrap_or(ci + 1);
        }

        done
    }

    /// Queues `r` for this pass, from another task's run (`Dispatch::pop_wake_now`):
    /// `Urgent`, or `Heavy` for a heavy task, as an I/O wakeup. Returns the class it was
    /// put in, `None` when it was already queued (it runs in this pass anyway) or is gone.
    fn wake_now(&mut self, r: TaskRef) -> Option<Class> {
        if !self.tasks.is_live(r) {
            return None;
        }
        let t = self.tasks.get_mut(r);
        if t.state & state::KILLED != 0 {
            return None;
        }
        t.state |= state::WOKEN_NOW;
        if t.state & state::QUEUED != 0 {
            t.state |= state::WOKEN_IO;
            return None;
        }
        let class = if t.state & state::HEAVY != 0 { Class::Heavy } else { Class::Urgent };
        self.tasklet_wakeup_live(r, class, state::WOKEN_IO);
        Some(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::Kind;

    /// Runs every task, recording which ran, and returns the outcome the test chose.
    struct Runner {
        runs: Vec<u32>,
        outcome: Outcome,
    }

    impl Dispatch for Runner {
        fn run(&mut self, kind: WorkKind, _state: u32) -> Outcome {
            self.runs.push(kind.index());
            self.outcome
        }
    }

    /// Runs every task; the run of task index `from` wakes `target` for the pass, every
    /// time (L2's owner and stream handing each other work).
    struct Waker {
        runs: Vec<u32>,
        from: u32,
        target: TaskRef,
        pending: Option<TaskRef>,
        outcome: Outcome,
    }

    impl Dispatch for Waker {
        fn run(&mut self, kind: WorkKind, _state: u32) -> Outcome {
            self.runs.push(kind.index());
            if kind.index() == self.from {
                self.pending = Some(self.target);
            }
            self.outcome
        }

        fn pop_wake_now(&mut self) -> Option<TaskRef> {
            self.pending.take()
        }
    }

    /// A task woken for the pass by another's run runs in that pass, and a second time if it
    /// had run already; a third wake in the pass waits for the next one.
    #[test]
    fn a_task_woken_now_runs_in_the_pass_twice_at_most() {
        let mut s = Scheduler::with_capacity(8);
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        // A wakes itself on every run: it runs twice in the pass, not once and not forever.
        let mut d = Waker { runs: Vec::new(), from: 1, target: a, pending: None, outcome: Outcome::Keep };
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
        s.process_runnable_tasks(&mut d);
        assert_eq!(d.runs, [1, 1], "woken now: a second run in the pass, the third refused");
        // The third wake is not lost: it runs in the next pass (and twice again).
        d.runs.clear();
        s.process_runnable_tasks(&mut d);
        assert_eq!(d.runs, [1, 1]);

        // B, woken by A's run, runs in A's pass (it had not run in it).
        let mut s = Scheduler::with_capacity(8);
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        let b = s.create(WorkKind::new(Kind::Synthetic, 2)).expect("alloc");
        let mut d = Waker { runs: Vec::new(), from: 1, target: b, pending: None, outcome: Outcome::Keep };
        s.tasklet_wakeup(a, Class::Normal, state::WOKEN_IO);
        s.process_runnable_tasks(&mut d);
        assert_eq!(d.runs, [1, 2], "woken into Urgent from a Normal run: the pass goes back for it");
        assert_eq!(s.run_queue_len(), 0);
    }

    /// A task woken for the pass that is gone (freed, or killed and waiting in a list to be)
    /// is not run: the wake is dropped.
    #[test]
    fn a_wake_now_of_a_task_gone_is_dropped() {
        let mut s = Scheduler::with_capacity(8);
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        let b = s.create(WorkKind::new(Kind::Synthetic, 2)).expect("alloc");
        s.destroy(b);
        let mut d = Waker { runs: Vec::new(), from: 1, target: b, pending: None, outcome: Outcome::Keep };
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
        s.process_runnable_tasks(&mut d);
        assert_eq!(d.runs, [1], "a freed task is not woken");

        // C is queued behind A, then destroyed: killed, its free deferred to its turn.
        let c = s.create(WorkKind::new(Kind::Synthetic, 3)).expect("alloc");
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
        s.tasklet_wakeup(c, Class::Normal, state::WOKEN_IO);
        s.destroy(c);
        d.runs.clear();
        d.target = c;
        s.process_runnable_tasks(&mut d);
        assert_eq!(d.runs, [1], "a killed task is not run");
        assert_eq!(s.live_tasks(), 1);
    }

    /// The Bulk demotion still applies to self-wakes: a task that returns `Outcome::Wake`
    /// runs once a pass, not twice.
    #[test]
    fn a_self_wake_still_waits_for_the_next_pass() {
        let mut s = Scheduler::with_capacity(8);
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        let mut d = Runner { runs: Vec::new(), outcome: Outcome::Wake };
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
        s.process_runnable_tasks(&mut d);
        assert_eq!(d.runs, [1]);
        assert_ne!(s.tasks.get(a).state & state::SELF_WAKING, 0);
        s.process_runnable_tasks(&mut d);
        assert_eq!(d.runs, [1, 1]);
        assert_eq!(s.stats().runs_by_class[Class::Bulk.idx()], 1, "the second run is Bulk's");
    }

    fn drain(s: &mut Scheduler, d: &mut Runner) {
        for _ in 0..8 {
            s.process_runnable_tasks(d);
        }
    }

    /// A task that ran to `Outcome::Done`, so the scheduler freed it.
    fn a_finished_task(s: &mut Scheduler, d: &mut Runner) -> TaskRef {
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
        drain(s, d);
        assert_eq!(s.live_tasks(), 0);
        a
    }

    /// The rest of T100's sequence at the scheduler: the caller queued the finished
    /// task's timer anyway, the freed slot was woken into the run queue and handed to a
    /// new task with that membership forgotten, and the next passes ran the new task
    /// from two lists until `pop_tasklet` underflowed a length.
    #[cfg(not(debug_assertions))]
    fn stale_timer_on_a_freed_task(s: &mut Scheduler, d: &mut Runner) {
        let a = a_finished_task(s, d);
        s.queue_timer(a, s.now()); // the stale timer update
        s.wakeup(a, state::WOKEN_MSG, CallSite::UNKNOWN); // and stale wakeups
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
        s.set_now(Tick(s.now().0 + 10));
        s.wake_expired_tasks();
        let b = s.create(WorkKind::new(Kind::Synthetic, 2)).expect("alloc");
        assert_eq!(a, b, "the freed slot is reused");
        s.tasklet_wakeup(b, Class::Urgent, state::WOKEN_IO);
        drain(s, d);
    }

    /// Queueing a freed task is the bug, and a debug build stops at it, not three
    /// passes later when `pop_tasklet` underflows a list length.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "queue_timer on freed task")]
    fn a_freed_task_is_never_queued() {
        let mut s = Scheduler::with_capacity(4);
        let mut d = Runner {
            runs: Vec::new(),
            outcome: Outcome::Done,
        };
        let a = a_finished_task(&mut s, &mut d);
        s.queue_timer(a, s.now());
    }

    /// Nor woken, by either path.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "tasklet_wakeup on freed task")]
    fn a_freed_task_is_never_woken_into_a_tasklet_list() {
        let mut s = Scheduler::with_capacity(4);
        let mut d = Runner {
            runs: Vec::new(),
            outcome: Outcome::Done,
        };
        let a = a_finished_task(&mut s, &mut d);
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "wakeup on freed task")]
    fn a_freed_task_is_never_woken_into_the_run_queue() {
        let mut s = Scheduler::with_capacity(4);
        let mut d = Runner {
            runs: Vec::new(),
            outcome: Outcome::Done,
        };
        let a = a_finished_task(&mut s, &mut d);
        s.wakeup(a, state::WOKEN_MSG, CallSite::UNKNOWN);
    }

    /// In a release build the stale operation is refused: the lists stay consistent and
    /// the new task runs once.
    #[test]
    #[cfg(not(debug_assertions))]
    fn a_freed_task_is_never_queued() {
        let mut s = Scheduler::with_capacity(4);
        let mut d = Runner {
            runs: Vec::new(),
            outcome: Outcome::Done,
        };
        stale_timer_on_a_freed_task(&mut s, &mut d);
        assert_eq!(d.runs, vec![1, 2]);
        assert_eq!(s.run_queue_len(), 0);
        assert_eq!(s.live_tasks(), 0);
    }

    /// A task is in at most one tasklet list, once. A second link is caught at the link.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "linked twice")]
    fn a_task_is_never_linked_twice() {
        let mut s = Scheduler::with_capacity(4);
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        s.push_tasklet(Class::Urgent, a);
        s.push_tasklet(Class::Normal, a);
    }

    /// `destroy` on a task waiting in the run queue (in no tasklet list) frees it. It
    /// used to read `QUEUED` as "in a tasklet list", mark the task killed for a pop that
    /// never came, and leak the slot.
    #[test]
    fn destroying_a_task_in_the_run_queue_frees_it() {
        let mut s = Scheduler::with_capacity(4);
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        s.wakeup(a, state::WOKEN_MSG, CallSite::UNKNOWN);
        s.destroy(a);
        assert_eq!(s.live_tasks(), 0, "the slot leaked");
        assert_eq!(s.run_queue_len(), 0);
        let mut d = Runner {
            runs: Vec::new(),
            outcome: Outcome::Keep,
        };
        drain(&mut s, &mut d);
        assert!(d.runs.is_empty());
    }

    /// `destroy` on a task in a tasklet list defers the free to the pop, and the task
    /// does not run.
    #[test]
    fn destroying_a_task_in_a_tasklet_list_defers_the_free() {
        let mut s = Scheduler::with_capacity(4);
        let a = s.create(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        s.tasklet_wakeup(a, Class::Urgent, state::WOKEN_IO);
        s.destroy(a);
        assert_eq!(s.live_tasks(), 1, "still linked: freed on the pop");
        let mut d = Runner {
            runs: Vec::new(),
            outcome: Outcome::Keep,
        };
        drain(&mut s, &mut d);
        assert!(d.runs.is_empty());
        assert_eq!(s.live_tasks(), 0);
        assert_eq!(s.run_queue_len(), 0);
    }
}
