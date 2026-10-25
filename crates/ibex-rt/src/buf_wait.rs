// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The buffer wait queue (`HAProxy`'s `buffer_wq`, `include/haproxy/dynbuf.h`; memory slice S6,
//! `docs/design/memory-q3-2026-10-25.md` §2): a stream refused a standard buffer because the
//! pool is at `tune.buffers.limit` waits here, per thread, by criticality, and is woken when a
//! buffer is given back on its thread (`offer_buffers`).
//!
//! The steady path does not come here: a take served by the thread cache never looks at the
//! queue. A give looks at one thread-local byte ([`offer`]), as `HAProxy`'s `offer_buffers`
//! looks at `th_ctx->bufq_map`.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use crate::mailbox::{Mailboxes, Signal};

use ibex_sched::TaskRef;

/// What the buffer is for, most critical first (`DB_CRIT_TO_QUEUE`: `DB_MUX_TX` 0,
/// `DB_CHANNEL` 1, `DB_SE_RX` 2, `DB_MUX_RX` 3). A refused take waits behind every waiter of
/// its class and of the more critical ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    /// A buffer to send to the client (a local response).
    MuxTx = 0,
    /// The stream's own HTX.
    Channel = 1,
    /// A receive buffer for the server side.
    SeRx = 2,
    /// A connection's receive buffer from the client: new work, served last.
    MuxRx = 3,
}

/// A stream's place in the wait queue, in one byte (`SessionEntry` is bounded in size):
/// whether it is queued, and whether it was just woken for a buffer given back (refused again,
/// it goes back to the front).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitState(u8);

impl WaitState {
    const QUEUED: u8 = 0x01;
    const OFFERED: u8 = 0x02;
    /// Queued for a buffer to read the client into: the client socket is not polled for
    /// reading meanwhile (the poller is level-triggered: unread bytes would wake it at once).
    const CLI: u8 = 0x04;
    /// The same for the server socket.
    const SRV: u8 = 0x08;

    /// Queued for `class`: the side it would read is not polled until it is woken.
    pub fn enqueued(&mut self, class: Class) {
        let side = match class {
            Class::MuxRx => Self::CLI,
            Class::SeRx => Self::SRV,
            Class::MuxTx | Class::Channel => 0,
        };
        self.0 = (self.0 & !(Self::CLI | Self::SRV)) | Self::QUEUED | side;
    }

    /// Whether it waits to read the client.
    #[must_use]
    #[inline]
    pub fn mutes_cli(self) -> bool {
        self.0 & Self::CLI != 0
    }

    /// Whether it waits to read the server.
    #[must_use]
    #[inline]
    pub fn mutes_srv(self) -> bool {
        self.0 & Self::SRV != 0
    }

    #[must_use]
    #[inline]
    pub fn queued(self) -> bool {
        self.0 & Self::QUEUED != 0
    }

    /// Out of the queue (woken): both sides polled again.
    pub fn dequeued(&mut self) {
        self.0 &= !(Self::QUEUED | Self::CLI | Self::SRV);
    }

    pub fn set_offered(&mut self, on: bool) {
        self.0 = if on { self.0 | Self::OFFERED } else { self.0 & !Self::OFFERED };
    }

    /// Whether it was woken for a buffer, once.
    pub fn take_offered(&mut self) -> bool {
        let was = self.0 & Self::OFFERED != 0;
        self.0 &= !Self::OFFERED;
        was
    }
}

/// A waiter: the stream's task and its session slot (the slot is checked against the task when
/// it is woken, so a slot reused by another stream is not woken by mistake).
type Waiter = (TaskRef, u32);

/// No slot.
const NIL: u32 = u32::MAX;

/// The four FIFO queues as lists threaded through arrays indexed by session slot (S6b §3): a
/// stream is in one queue at most, so the arrays sized for the thread's sessions at start
/// ([`presize`]) hold every waiter there can be, and queueing allocates nothing. A slot past
/// them (the session arena grew past its presize) grows them, fallibly.
struct Queues {
    next: Vec<u32>,
    prev: Vec<u32>,
    /// The waiting stream's task; [`NIL`]: the slot is in no queue.
    task: Vec<u32>,
    head: [u32; 4],
    tail: [u32; 4],
    len: [usize; 4],
}

impl Queues {
    const fn new() -> Self {
        Queues { next: Vec::new(), prev: Vec::new(), task: Vec::new(), head: [NIL; 4], tail: [NIL; 4], len: [0; 4] }
    }

    /// Slots `0..n`, filled in within the room [`presize`] reserved (no allocation), past it
    /// grown; false when memory is short.
    fn grow(&mut self, n: usize) -> bool {
        let more = n.saturating_sub(self.task.len());
        if more == 0 {
            return true;
        }
        if self.next.try_reserve_exact(more).is_err() || self.prev.try_reserve_exact(more).is_err() || self.task.try_reserve_exact(more).is_err() {
            return false;
        }
        self.next.resize(n, NIL);
        self.prev.resize(n, NIL);
        self.task.resize(n, NIL);
        true
    }

    fn push(&mut self, q: usize, slot: u32, task: TaskRef, front: bool) {
        let i = slot as usize;
        self.task[i] = task.0;
        if front {
            self.prev[i] = NIL;
            self.next[i] = self.head[q];
            match self.head[q] {
                NIL => self.tail[q] = slot,
                h => self.prev[h as usize] = slot,
            }
            self.head[q] = slot;
        } else {
            self.next[i] = NIL;
            self.prev[i] = self.tail[q];
            match self.tail[q] {
                NIL => self.head[q] = slot,
                t => self.next[t as usize] = slot,
            }
            self.tail[q] = slot;
        }
        self.len[q] += 1;
    }

    /// Takes `slot` out of queue `q`, which holds it.
    fn unlink(&mut self, q: usize, slot: u32) {
        let i = slot as usize;
        let (p, n) = (self.prev[i], self.next[i]);
        match p {
            NIL => self.head[q] = n,
            p => self.next[p as usize] = n,
        }
        match n {
            NIL => self.tail[q] = p,
            n => self.prev[n as usize] = p,
        }
        self.task[i] = NIL;
        self.len[q] -= 1;
    }

    /// The queue holding `slot`, if one does (walked from its end to the head: cold).
    fn queue_of(&self, slot: u32) -> Option<usize> {
        if self.task.get(slot as usize).is_none_or(|&t| t == NIL) {
            return None;
        }
        let mut h = slot;
        while self.prev[h as usize] != NIL {
            h = self.prev[h as usize];
        }
        self.head.iter().position(|&x| x == h)
    }

    fn map(&self) -> u8 {
        self.len.iter().enumerate().fold(0, |m, (i, &n)| if n > 0 { m | 1 << i } else { m })
    }
}

thread_local! {
    /// The four queues, FIFO each.
    static QUEUES: RefCell<Queues> = const { RefCell::new(Queues::new()) };
    /// Bit `q` set while queue `q` has waiters (`th_ctx->bufq_map`).
    static MAP: Cell<u8> = const { Cell::new(0) };
    /// The class (+1) a buffer was refused for in the stream running now (0: none), for the
    /// engine to queue it after the run.
    static WANT: Cell<u8> = const { Cell::new(0) };
    /// Buffers given back while there were waiters, not yet handed to one by the engine.
    static OFFERED: Cell<u32> = const { Cell::new(0) };
    /// This thread's worker id among the [`BOXES`] ([`join`]); `usize::MAX`: none.
    static WID: Cell<usize> = const { Cell::new(usize::MAX) };
}

// Across threads (S6b): a thread's cache can hold free buffers counted against the limit while
// another thread's stream waits. The waiting threads are known here; a thread with free
// buffers puts them on the pool's shelf and signals them (`Mailboxes::signal`, no allocation).
// Written only when a thread's queues go from empty to not or back, read on a give only
// through [`ANY_WAITING`].

/// Bit `w % 64` of word `w / 64`: worker `w` has streams waiting for a buffer.
static WAITING: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
/// How many workers have streams waiting: the one load a give makes besides [`MAP`].
static ANY_WAITING: AtomicUsize = AtomicUsize::new(0);
/// Every worker's mailbox, to signal them.
static BOXES: Mutex<Option<Weak<Mailboxes>>> = Mutex::new(None);

/// This thread is worker `wid` of `boxes` (`Engine::share_mailboxes`).
pub fn join(boxes: &Arc<Mailboxes>, wid: usize) {
    WID.set(wid);
    *BOXES.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::downgrade(boxes));
}

fn boxes() -> Option<Arc<Mailboxes>> {
    BOXES.lock().unwrap_or_else(PoisonError::into_inner).as_ref().and_then(Weak::upgrade)
}

/// The queues' map becomes `map`: a thread that starts waiting asks the others for their
/// cached buffers; one whose queues are empty again is no longer signalled.
fn set_map(map: u8) {
    let old = MAP.replace(map);
    let wid = WID.get();
    if (old == 0) == (map == 0) || wid >= WAITING.len() * 64 {
        return;
    }
    let (word, bit) = (&WAITING[wid / 64], 1u64 << (wid % 64));
    if map == 0 {
        word.fetch_and(!bit, Ordering::AcqRel);
        ANY_WAITING.fetch_sub(1, Ordering::AcqRel);
        return;
    }
    word.fetch_or(bit, Ordering::AcqRel);
    ANY_WAITING.fetch_add(1, Ordering::AcqRel);
    if let Some(b) = boxes() {
        for w in (0..b.len()).filter(|&w| w != wid) {
            b.signal(w, Signal::ShelveBuffers);
        }
    }
}

/// Buffers were put on the shelf (the pool's hook): every other waiting worker is told.
pub fn shelved() {
    if ANY_WAITING.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(b) = boxes() else { return };
    let me = WID.get();
    for (i, word) in WAITING.iter().enumerate() {
        let mut bits = word.load(Ordering::Acquire);
        while bits != 0 {
            let w = i * 64 + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if w != me {
                b.signal(w, Signal::BuffersShelved);
            }
        }
    }
}

/// Whether this thread has streams waiting for a buffer.
#[must_use]
pub fn has_waiters() -> bool {
    MAP.get() != 0
}

/// Another thread put buffers on the shelf: as many of this thread's waiters are offered one
/// (each takes it from the shelf on its miss), up to how many wait.
pub fn offer_shelved() {
    let n = crate::buf::shelved_standard().min(waiting().iter().sum());
    OFFERED.set(OFFERED.get().saturating_add(u32::try_from(n).unwrap_or(u32::MAX)));
}

/// Whether a stream refused a standard buffer should wait for one rather than fail: the pool
/// is at `tune.buffers.limit` (a refusal of the allocator itself, or one injected by
/// `tune.fail-alloc`, fails the stream as in S5).
#[must_use]
pub fn should_wait() -> bool {
    crate::buf::standard_at_limit()
}

/// The running stream was refused a buffer of `class` at the limit: queued after its run.
pub fn want(class: Class) {
    WANT.set(class as u8 + 1);
}

/// Whether the stream that just ran was refused a buffer (one thread-local byte per run).
#[must_use]
#[inline]
pub fn wanted() -> bool {
    WANT.get() != 0
}

/// The class the stream that just ran was refused, once.
#[must_use]
pub fn take_want() -> Option<Class> {
    let c = match WANT.replace(0) {
        1 => Class::MuxTx,
        2 => Class::Channel,
        3 => Class::SeRx,
        4 => Class::MuxRx,
        _ => return None,
    };
    Some(c)
}

/// Sizes the queues for the thread's `n` session slots, at start (S6b §3): queueing then
/// allocates nothing. False when memory is short (they grow on use instead, fallibly).
#[must_use]
pub fn presize(n: usize) -> bool {
    QUEUES.with(|q| {
        let mut q = q.borrow_mut();
        // Reserved, not filled: untouched, the pages cost no resident memory (as the session
        // arena's); a slot is filled in when it first waits, within this room.
        let more = n.saturating_sub(q.task.len());
        q.next.try_reserve_exact(more).is_ok() && q.prev.try_reserve_exact(more).is_ok() && q.task.try_reserve_exact(more).is_ok()
    })
}

/// Puts the stream of `task` (session slot `slot`) in queue `class`: at the back, or at the
/// front when it was just woken and refused again (it keeps its place). `false` when the queue
/// cannot grow (a slot past [`presize`] and memory short: the caller fails the stream).
#[must_use]
pub fn enter(task: TaskRef, slot: u32, class: Class, front: bool) -> bool {
    QUEUES.with(|q| {
        let mut q = q.borrow_mut();
        if slot == NIL || !q.grow(slot as usize + 1) {
            return false;
        }
        if let Some(old) = q.queue_of(slot) {
            q.unlink(old, slot);
        }
        q.push(class as usize, slot, task, front);
        let map = q.map();
        drop(q);
        set_map(map);
        true
    })
}

/// Takes the stream in session slot `slot` out of the queue it is in (it ended while waiting).
pub fn leave(slot: u32) {
    QUEUES.with(|q| {
        let mut q = q.borrow_mut();
        if let Some(c) = q.queue_of(slot) {
            q.unlink(c, slot);
        }
        let map = q.map();
        drop(q);
        set_map(map);
    });
}

/// A standard buffer was given back on this thread: counted for a waiter, if there is one;
/// else, when another thread waits, this thread's cached buffers go on the shelf for it (S6b).
#[inline(always)]
#[allow(clippy::inline_always)] // a byte and a word read on the give path; the rest is out of line
pub fn offer() {
    if MAP.get() != 0 || ANY_WAITING.load(Ordering::Relaxed) != 0 {
        offer_slow();
    }
}

#[cold]
#[inline(never)]
fn offer_slow() {
    if MAP.get() != 0 {
        OFFERED.set(OFFERED.get() + 1);
    } else {
        let _ = crate::buf::shelve_standard();
    }
}

/// A buffer offered to a waiter that had gone: it is the next one's.
pub fn reoffer() {
    OFFERED.set(OFFERED.get() + 1);
}

/// Whether the engine has waiters to wake for buffers given back.
#[must_use]
#[inline]
pub fn pending() -> bool {
    OFFERED.get() != 0
}

/// The next waiter to hand a given-back buffer to, most critical queue first, oldest first
/// (one per buffer, `__offer_buffers`' `count`); `None` when the buffers given back are all
/// handed out or nobody waits.
#[must_use]
pub fn next_offered() -> Option<Waiter> {
    let n = OFFERED.get();
    if n == 0 {
        return None;
    }
    QUEUES.with(|q| {
        let mut q = q.borrow_mut();
        let Some(c) = (0..4).find(|&c| q.head[c] != NIL) else {
            OFFERED.set(0);
            return None;
        };
        let slot = q.head[c];
        let task = TaskRef(q.task[slot as usize]);
        q.unlink(c, slot);
        let map = q.map();
        drop(q);
        set_map(map);
        OFFERED.set(n - 1);
        Some((task, slot))
    })
}

/// How many streams wait on this thread, per queue.
#[must_use]
pub fn waiting() -> [usize; 4] {
    QUEUES.with(|q| q.borrow().len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiters_are_offered_most_critical_first_then_oldest_first() {
        assert!(enter(TaskRef(1), 1, Class::MuxRx, false));
        assert!(enter(TaskRef(2), 2, Class::MuxRx, false));
        assert!(enter(TaskRef(3), 3, Class::SeRx, false));
        assert_eq!(next_offered(), None, "nothing given back yet");
        for _ in 0..4 {
            offer();
        }
        assert_eq!(next_offered(), Some((TaskRef(3), 3)));
        assert_eq!(next_offered(), Some((TaskRef(1), 1)));
        assert!(enter(TaskRef(1), 1, Class::MuxRx, true), "refused again: back at the front");
        assert_eq!(next_offered(), Some((TaskRef(1), 1)));
        assert_eq!(next_offered(), Some((TaskRef(2), 2)));
        assert_eq!(next_offered(), None);
        assert!(!pending(), "an offer with nobody waiting is not kept");
        assert_eq!(waiting(), [0; 4]);
    }

    #[test]
    fn a_stream_that_leaves_is_not_offered_and_a_give_without_waiters_counts_nothing() {
        offer();
        assert!(!pending());
        assert!(enter(TaskRef(7), 7, Class::MuxRx, false));
        leave(7);
        assert_eq!(waiting(), [0; 4]);
        offer();
        assert!(!pending(), "the queue is empty again: nothing to offer");
    }

    /// Only a wait to read mutes a side: one for a local reply or the stream's HTX mutes none.
    #[test]
    fn a_wait_mutes_the_side_it_would_read() {
        for (class, cli, srv) in [(Class::MuxRx, true, false), (Class::SeRx, false, true), (Class::MuxTx, false, false), (Class::Channel, false, false)] {
            let mut w = WaitState::default();
            w.enqueued(class);
            assert_eq!((w.queued(), w.mutes_cli(), w.mutes_srv()), (true, cli, srv), "{class:?}");
            w.dequeued();
            assert_eq!((w.queued(), w.mutes_cli(), w.mutes_srv()), (false, false, false), "{class:?}");
        }
    }

    /// The class a stream was refused is handed to the engine once, whichever it was.
    #[test]
    fn the_wanted_class_is_taken_once() {
        assert_eq!(take_want(), None);
        for class in [Class::MuxTx, Class::Channel, Class::SeRx, Class::MuxRx] {
            want(class);
            assert!(wanted());
            assert_eq!(take_want(), Some(class));
            assert!(!wanted());
            assert_eq!(take_want(), None);
        }
    }

    /// S6b §3: presized, queueing allocates nothing (the room stays what `presize` reserved),
    /// and a stream leaves from the middle of a queue, the head or the tail, the order of the
    /// others kept; a stream queued again moves to its new queue.
    #[test]
    fn presized_queues_allocate_nothing_and_keep_their_order() {
        assert!(presize(64));
        let room = QUEUES.with(|q| (q.borrow().task.capacity(), q.borrow().next.capacity(), q.borrow().prev.capacity()));
        for slot in 0..64 {
            assert!(enter(TaskRef(slot + 100), slot, if slot % 2 == 0 { Class::MuxRx } else { Class::SeRx }, false));
        }
        assert_eq!(QUEUES.with(|q| (q.borrow().task.capacity(), q.borrow().next.capacity(), q.borrow().prev.capacity())), room, "nothing allocated");
        assert_eq!(waiting(), [0, 0, 32, 32]);
        leave(1);
        leave(63);
        leave(31);
        assert!(enter(TaskRef(102), 2, Class::MuxTx, false), "queued again: moves");
        assert!(enter(TaskRef(9), 9, Class::SeRx, true), "to the front");
        assert_eq!(waiting(), [1, 0, 29, 31]);
        for _ in 0..64 {
            offer();
        }
        let mut order = Vec::new();
        while let Some((t, slot)) = next_offered() {
            order.push((t.0, slot));
        }
        let mut want = vec![(102, 2), (9, 9)];
        want.extend((3..63).step_by(2).filter(|&s| s != 9 && s != 31).map(|s| (s + 100, s)));
        want.extend((0..64).step_by(2).filter(|&s| s != 2).map(|s| (s + 100, s)));
        assert_eq!(order, want);
        assert_eq!(waiting(), [0; 4]);
        leave(5);
        assert!(!enter(TaskRef(1), NIL, Class::MuxRx, false), "no such slot");
    }

    /// Queues made at run time (the thread-local's are const-evaluated) are empty.
    #[test]
    fn queues_made_at_run_time_are_empty() {
        let q = Queues::new();
        assert_eq!((q.map(), q.len, q.head, q.task.len()), (0, [0; 4], [NIL; 4], 0));
        assert_eq!(q.queue_of(3), None);
    }

    /// A buffer offered to a waiter that had gone goes to the next one.
    #[test]
    fn a_reoffered_buffer_goes_to_the_next_waiter() {
        assert!(enter(TaskRef(5), 5, Class::SeRx, false));
        assert!(!pending());
        reoffer();
        assert!(pending());
        assert_eq!(next_offered(), Some((TaskRef(5), 5)));
        assert!(!pending());
    }
}
