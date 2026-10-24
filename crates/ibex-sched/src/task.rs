// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/task-t.h and task.h.
// Copyright (C) 2000-2026 Willy Tarreau <w@1wt.eu> and HAProxy contributors.
// See LICENSE in the repository root.

//! Tasks, and the arena they live in.
//!
//! See `design/006-data-layout.md`. The headline constraint is that a task occupies
//! **32 bytes — two per cache line** — against `HAProxy`'s 128 (two cache lines *per*
//! task). At 60,000 backends that difference shows up less in total bytes than in the
//! working set of a timer-tree walk.

use crate::tick::Tick;

/// Index into the per-thread [`TaskArena`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TaskRef(pub u32);

impl TaskRef {
    pub const NONE: TaskRef = TaskRef(u32::MAX);
    #[must_use]
    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }
}

/// Index of a node inside one of the scheduler's ebtree arenas.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NodeRef(pub u32);

impl NodeRef {
    pub const NONE: NodeRef = NodeRef(u32::MAX);
    #[must_use]
    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }
}

/// Index into a static registry of wakeup call sites.
///
/// `HAProxy` carries an 8-byte `const struct ha_caller *` in **every** task,
/// unconditionally and not behind `DEBUG_TASK` — someone decided that diagnosing a
/// stuck task in production is worth the space on every task in existence. That
/// judgement is worth keeping; at 4 bytes it also fits inside the 32-byte budget.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CallSite(pub u32);

impl CallSite {
    pub const UNKNOWN: CallSite = CallSite(u32::MAX);
}

/// What kind of work a task represents, packed into 4 bytes.
///
/// Replaces C's `process` function pointer plus `void *context` (16 bytes and an
/// indirect call) with an 8-bit tag and a 24-bit index — 16.7M objects per kind, against
/// a 60k target. Unpacking is a shift and a mask; the C form risks a branch
/// mispredict on an indirect call and erases the type entirely, which is why `HAProxy` has
/// to reconstruct "what is this task" separately in `show sess` and `show fd`.
///
/// Here the tag *is* the answer, so introspection is free.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct WorkKind(u32);

/// Discriminants for [`WorkKind`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// A stream (one HTTP transaction) being processed.
    Stream = 0,
    /// Mux-level I/O on a connection.
    MuxIo = 1,
    /// An applet: the CLI, the stats page, peers.
    Applet = 2,
    /// A health check.
    Check = 3,
    /// Listener-level work, e.g. resuming after `maxconn`.
    Listener = 4,
    /// Synthetic work used by tests and benchmarks.
    Synthetic = 5,
}

impl Kind {
    #[must_use]
    #[inline]
    const fn from_tag(t: u8) -> Option<Kind> {
        match t {
            0 => Some(Kind::Stream),
            1 => Some(Kind::MuxIo),
            2 => Some(Kind::Applet),
            3 => Some(Kind::Check),
            4 => Some(Kind::Listener),
            5 => Some(Kind::Synthetic),
            _ => None,
        }
    }
}

/// Largest index a [`WorkKind`] can address.
pub const MAX_KIND_INDEX: u32 = (1 << 24) - 1;

impl WorkKind {
    /// # Panics
    /// If `index` exceeds [`MAX_KIND_INDEX`].
    #[must_use]
    #[inline]
    pub const fn new(kind: Kind, index: u32) -> Self {
        assert!(index <= MAX_KIND_INDEX, "WorkKind index out of range");
        WorkKind(((kind as u32) << 24) | index)
    }

    /// The discriminant. `None` only if the tag was never written.
    #[must_use]
    #[inline]
    pub const fn kind(self) -> Option<Kind> {
        Kind::from_tag(self.0.to_be_bytes()[0])
    }

    /// The subsystem-owned index this task refers to.
    #[must_use]
    #[inline]
    pub const fn index(self) -> u32 {
        self.0 & MAX_KIND_INDEX
    }
}

impl core::fmt::Debug for WorkKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.kind() {
            Some(k) => write!(f, "{k:?}#{}", self.index()),
            None => write!(f, "WorkKind(invalid:{:#x})", self.0),
        }
    }
}

/// Task state bits. Mirrors `HAProxy`'s `TASK_*`.
pub mod state {
    /// Currently executing.
    pub const RUNNING: u32 = 1 << 0;
    /// In the run queue or a tasklet list, awaiting execution.
    pub const QUEUED: u32 = 1 << 1;
    /// Present in the wait queue (has a pending timer).
    pub const IN_WQ: u32 = 1 << 2;
    /// Scheduled for destruction; skipped when dequeued.
    ///
    /// Tasklet lists are singly linked, so removal from the middle is done by setting
    /// this bit rather than by unlinking. See [`super::Task`].
    pub const KILLED: u32 = 1 << 3;
    /// Re-woke itself while running: classified into `Bulk` to cap its bandwidth.
    pub const SELF_WAKING: u32 = 1 << 4;
    /// Computationally expensive (e.g. a TLS handshake): classified into `Heavy`,
    /// of which at most one runs per pass.
    pub const HEAVY: u32 = 1 << 5;
    /// Linked into a tasklet list. `QUEUED` alone does not say which queue: a task in
    /// the run queue is `QUEUED` too, and reading one as the other leaked tasks.
    pub const IN_TL: u32 = 1 << 6;
    /// The slot is on the arena's free list. Any scheduling operation on it is a stale
    /// reference: linking it is how T100's lists were corrupted.
    pub const FREED: u32 = 1 << 7;

    /// Woken because its timer expired.
    pub const WOKEN_TIMER: u32 = 1 << 8;
    /// Woken by I/O readiness.
    pub const WOKEN_IO: u32 = 1 << 9;
    /// Woken by another task or thread.
    pub const WOKEN_MSG: u32 = 1 << 10;
    /// Woken for any reason.
    pub const WOKEN_ANY: u32 = WOKEN_TIMER | WOKEN_IO | WOKEN_MSG;
}

/// A unit of schedulable work. Exactly 32 bytes.
///
/// Note what is *not* here: a thread id. `HAProxy` needs `int tid` because its tasks are
/// pool-allocated from a shared heap, so a task does not know its own thread. Under
/// thread-per-core with an arena per thread, **the arena a task lives in is its thread**,
/// and cross-thread wakeups name the target in the message rather than in the task. The
/// affinity decision pays for itself in the layout.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Task {
    /// `state::*` bits.
    pub state: u32,
    /// What to run.
    pub kind: WorkKind,
    /// Next expiry, or [`Tick::ETERNITY`].
    pub expire: Tick,
    /// Run-queue ebtree node, or `NONE`.
    pub rq_ref: NodeRef,
    /// Wait-queue ebtree node, or `NONE`.
    pub wq_ref: NodeRef,
    /// Next task in a tasklet list, or `NONE`.
    pub tl_next: TaskRef,
    /// Where the last wakeup came from.
    pub caller: CallSite,
    /// Priority offset, -1024..=1024. Negative runs earlier.
    pub nice: i16,
    /// Poll-loop counter at last execution.
    ///
    /// Not accounting: `src/task.c:543` compares this against the loop counter to stop
    /// a task running twice in one pass, which is an anti-starvation guard.
    pub last_run: u16,
}

const _: () = assert!(
    core::mem::size_of::<Task>() == 32,
    "Task must stay at 32 bytes: two per cache line, against HAProxy's 128"
);

impl Task {
    #[must_use]
    pub const fn new(kind: WorkKind) -> Self {
        Task {
            state: 0,
            kind,
            expire: Tick::ETERNITY,
            rq_ref: NodeRef::NONE,
            wq_ref: NodeRef::NONE,
            tl_next: TaskRef::NONE,
            caller: CallSite::UNKNOWN,
            nice: 0,
            last_run: 0,
        }
    }

    #[must_use]
    #[inline]
    pub const fn in_wq(&self) -> bool {
        self.state & state::IN_WQ != 0
    }

    #[must_use]
    #[inline]
    pub const fn queued(&self) -> bool {
        self.state & state::QUEUED != 0
    }

    #[must_use]
    #[inline]
    pub const fn killed(&self) -> bool {
        self.state & state::KILLED != 0
    }

    #[must_use]
    #[inline]
    pub const fn in_tasklet_list(&self) -> bool {
        self.state & state::IN_TL != 0
    }

    #[must_use]
    #[inline]
    pub const fn freed(&self) -> bool {
        self.state & state::FREED != 0
    }
}

/// Slots of every worker's [`TaskArena`], for `show pools` (pool `task`).
pub static TASK_POOL: ibex_alloc::ArenaStats = ibex_alloc::ArenaStats::new(
    "task",
    core::mem::size_of::<Task>(),
    core::mem::align_of::<Task>(),
    file!(),
    line!(),
);

/// `show pools` provider for the `task` pool: the slots ever created, those in use.
#[allow(clippy::unnecessary_wraps)]
#[must_use]
pub fn task_pool_stats() -> Option<ibex_alloc::PoolHead> {
    Some(TASK_POOL.head())
}

/// Per-thread task storage: an [`ibex_alloc::Arena`] (design 3.7).
///
/// Sized at boot; growth past that is fallible (`alloc` returns `None`), and the capacity a
/// burst made is given back only by [`ibex_alloc::Arena::compact`] (`pool_gc`).
#[derive(Debug)]
pub struct TaskArena {
    tasks: Vec<Task>,
    free: Vec<u32>,
    live: usize,
    floor: usize,
    peak: usize,
    published: ibex_alloc::arena::Published,
}

impl Drop for TaskArena {
    fn drop(&mut self) {
        TASK_POOL.retire(&mut self.published);
    }
}

impl ibex_alloc::Arena<Task> for TaskArena {
    fn slots(&self) -> usize {
        self.tasks.len()
    }

    fn live(&self) -> usize {
        self.live
    }

    fn compact(&mut self) -> usize {
        let before = self.tasks.len();
        while self.tasks.last().is_some_and(Task::freed) {
            self.tasks.pop();
        }
        let cut = before - self.tasks.len();
        let len = self.tasks.len();
        if self.live == 0 {
            self.free.clear();
        } else {
            self.free.retain(|&i| (i as usize) < len);
        }
        let cap = self.floor.max(len);
        if cap < self.tasks.capacity() || self.peak > len {
            if ibex_alloc::arena::move_to_fresh(&mut self.tasks, cap) {
                self.peak = len;
            } else {
                TASK_POOL.skipped();
            }
        }
        cut
    }
}

impl TaskArena {
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        TaskArena {
            tasks: Vec::with_capacity(cap),
            free: Vec::with_capacity(cap),
            live: 0,
            floor: cap,
            peak: 0,
            published: ibex_alloc::arena::Published::default(),
        }
    }

    /// Adds this arena's change since the last pass to `show pools` (once per loop pass).
    #[inline]
    pub fn publish(&mut self) {
        TASK_POOL.publish(&mut self.published, self.tasks.len(), self.live);
    }

    #[must_use]
    #[inline]
    pub const fn live(&self) -> usize {
        self.live
    }

    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.tasks.capacity()
    }

    /// Makes room for `additional` more tasks at once (see [`crate::Scheduler::reserve`]).
    pub fn reserve(&mut self, additional: usize) {
        self.tasks.reserve(additional);
    }

    /// Allocates a task. Returns `None` if the arena is exhausted.
    pub fn alloc(&mut self, kind: WorkKind) -> Option<TaskRef> {
        self.live += 1;
        if let Some(i) = self.free.pop() {
            let old = &self.tasks[i as usize];
            debug_assert!(
                old.state == state::FREED && old.rq_ref.is_none() && old.wq_ref.is_none(),
                "reusing a freed task slot that is still linked: {old:?}"
            );
            self.tasks[i as usize] = Task::new(kind);
            return Some(TaskRef(i));
        }
        let i = u32::try_from(self.tasks.len()).ok()?;
        if i == u32::MAX || !ibex_alloc::arena::grow_for_one(&mut self.tasks, &mut self.free) {
            if i != u32::MAX {
                TASK_POOL.failed();
            }
            self.live -= 1;
            return None;
        }
        self.tasks.push(Task::new(kind));
        self.peak = self.peak.max(self.tasks.len());
        Some(TaskRef(i))
    }

    /// Returns a slot to the free list. The caller must have unlinked it from every
    /// queue first.
    pub fn free(&mut self, r: TaskRef) {
        debug_assert!(!r.is_none());
        if self.free.contains(&r.0) {
            return;
        }
        let t = &mut self.tasks[r.0 as usize];
        debug_assert!(t.rq_ref.is_none(), "freeing a task still in the run queue");
        debug_assert!(t.wq_ref.is_none(), "freeing a task still in the wait queue");
        debug_assert!(
            !t.in_tasklet_list(),
            "freeing a task still in a tasklet list"
        );
        t.state = state::FREED;
        t.tl_next = TaskRef::NONE;
        self.free.push(r.0);
        self.live = self.live.saturating_sub(1);
    }

    /// Whether `r` names an allocated task rather than a slot on the free list.
    #[must_use]
    #[inline]
    pub fn is_live(&self, r: TaskRef) -> bool {
        !r.is_none() && self.tasks.get(r.0 as usize).is_some_and(|t| !t.freed())
    }

    #[must_use]
    #[inline]
    pub fn get(&self, r: TaskRef) -> &Task {
        &self.tasks[r.0 as usize]
    }

    #[inline]
    pub fn get_mut(&mut self, r: TaskRef) -> &mut Task {
        &mut self.tasks[r.0 as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_is_two_per_cache_line() {
        assert_eq!(core::mem::size_of::<Task>(), 32);
        assert_eq!(64 / core::mem::size_of::<Task>(), 2);
    }

    #[test]
    fn workkind_roundtrips() {
        for (k, i) in [
            (Kind::Stream, 0),
            (Kind::Check, 60_000),
            (Kind::Applet, MAX_KIND_INDEX),
            (Kind::Synthetic, 1),
        ] {
            let w = WorkKind::new(k, i);
            assert_eq!(w.kind(), Some(k), "tag lost for {k:?}");
            assert_eq!(w.index(), i, "index lost for {k:?}");
        }
    }

    #[test]
    fn workkind_spans_the_sixty_thousand_backend_target() {
        const { assert!(MAX_KIND_INDEX > 60_000 * 100) };
    }

    /// A close keeps the burst's slots; `compact` (pool_gc) drops the free ones at the end, keeps
    /// a live one and the free slots below it, and the creation capacity.
    #[test]
    fn compact_gives_back_the_tail_only_when_asked() {
        use ibex_alloc::Arena;
        let mut a = TaskArena::with_capacity(4);
        let refs: Vec<TaskRef> = (0..40).map(|i| a.alloc(WorkKind::new(Kind::Synthetic, i)).expect("alloc")).collect();
        for &r in refs.iter().skip(2).rev() {
            a.free(r);
        }
        assert_eq!((a.slots(), a.live()), (40, 2), "a free keeps the peak");
        assert!(a.capacity() >= 40);
        a.publish();
        assert_eq!(a.compact(), 38);
        assert_eq!((a.slots(), a.live(), a.capacity()), (2, 2, 4), "back to the creation capacity");
        assert!(a.is_live(refs[0]) && a.is_live(refs[1]) && !a.is_live(refs[5]));
        let t = a.alloc(WorkKind::new(Kind::Synthetic, 9)).expect("alloc");
        assert_eq!(t, TaskRef(2), "no stale free index survived");
        a.free(refs[0]);
        a.free(t);
        assert_eq!(a.compact(), 1, "the free slot below the live one stays");
        assert_eq!(a.slots(), 2);
        a.publish();
        assert!(task_pool_stats().is_some());
    }

    #[test]
    fn arena_reuses_freed_slots() {
        let mut a = TaskArena::with_capacity(4);
        let t1 = a.alloc(WorkKind::new(Kind::Synthetic, 1)).expect("alloc");
        assert_eq!(a.live(), 1);
        a.free(t1);
        assert_eq!(a.live(), 0);
        let t2 = a.alloc(WorkKind::new(Kind::Synthetic, 2)).expect("alloc");
        assert_eq!(t1, t2, "freed slot should be reused");
        assert_eq!(
            a.get(t2).kind.index(),
            2,
            "reused slot must be reinitialised"
        );
    }
}
