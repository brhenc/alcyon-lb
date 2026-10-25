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
use std::collections::VecDeque;

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

    #[must_use]
    #[inline]
    pub fn queued(self) -> bool {
        self.0 & Self::QUEUED != 0
    }

    pub fn set_queued(&mut self, on: bool) {
        self.0 = if on { self.0 | Self::QUEUED } else { self.0 & !Self::QUEUED };
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

thread_local! {
    /// The four queues, FIFO each.
    static QUEUES: RefCell<[VecDeque<Waiter>; 4]> = const { RefCell::new([VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new()]) };
    /// Bit `q` set while queue `q` has waiters (`th_ctx->bufq_map`).
    static MAP: Cell<u8> = const { Cell::new(0) };
    /// The class (+1) a buffer was refused for in the stream running now (0: none), for the
    /// engine to queue it after the run.
    static WANT: Cell<u8> = const { Cell::new(0) };
    /// Buffers given back while there were waiters, not yet handed to one by the engine.
    static OFFERED: Cell<u32> = const { Cell::new(0) };
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

/// Puts the stream of `task` (session slot `slot`) in queue `class`: at the back, or at the
/// front when it was just woken and refused again (it keeps its place). `false` when the queue
/// cannot grow (the caller fails the stream instead).
#[must_use]
pub fn enter(task: TaskRef, slot: u32, class: Class, front: bool) -> bool {
    QUEUES.with(|q| {
        let q = &mut q.borrow_mut()[class as usize];
        if q.try_reserve(1).is_err() {
            return false;
        }
        if front {
            q.push_front((task, slot));
        } else {
            q.push_back((task, slot));
        }
        MAP.set(MAP.get() | (1 << class as u8));
        true
    })
}

/// Takes the stream of `task` out of every queue (it ended while waiting).
pub fn leave(task: TaskRef) {
    QUEUES.with(|q| {
        let mut q = q.borrow_mut();
        let mut map = 0;
        for (i, queue) in q.iter_mut().enumerate() {
            queue.retain(|&(t, _)| t != task);
            if !queue.is_empty() {
                map |= 1 << i;
            }
        }
        MAP.set(map);
    });
}

/// A standard buffer was given back on this thread: counted for a waiter, if there is one.
#[inline(always)]
#[allow(clippy::inline_always)] // one byte read on the give path; the rest is out of line
pub fn offer() {
    if MAP.get() != 0 {
        offer_slow();
    }
}

#[cold]
#[inline(never)]
fn offer_slow() {
    OFFERED.set(OFFERED.get() + 1);
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
        for (i, queue) in q.iter_mut().enumerate() {
            if let Some(w) = queue.pop_front() {
                if queue.is_empty() {
                    MAP.set(MAP.get() & !(1 << i));
                }
                OFFERED.set(n - 1);
                return Some(w);
            }
        }
        OFFERED.set(0);
        None
    })
}

/// How many streams wait on this thread, per queue.
#[must_use]
pub fn waiting() -> [usize; 4] {
    QUEUES.with(|q| {
        let q = q.borrow();
        [q[0].len(), q[1].len(), q[2].len(), q[3].len()]
    })
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
        leave(TaskRef(7));
        assert_eq!(waiting(), [0; 4]);
        offer();
        assert!(!pending(), "the queue is empty again: nothing to offer");
    }
}
