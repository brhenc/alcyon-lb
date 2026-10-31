// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Requests from one worker to every worker, answered without blocking anyone (T218).
//!
//! A worker's streams live in its own arena, which no other thread may touch. `HAProxy`
//! walks every thread's stream list from the CLI thread under `thread_isolate()`; Ibex
//! instead asks: the CLI posts a [`Msg`] to each worker's mailbox and wakes it through an
//! eventfd registered in its poller. Each worker answers into a shared [`Gather`] from its
//! own loop, and the one that completes it posts [`Msg::Wake`] back to the asking worker,
//! which wakes the waiting task. Nobody waits on a lock held across work: the mailbox and
//! gather mutexes guard a `Vec` push each.
//!
//! A worker that has stopped (its engine dropped) closes its mailbox, answering what was
//! still queued with the empty reply; a post to a closed mailbox is answered the same way
//! by the sender. A gather therefore always completes.

use ibex_sched::task::TaskRef;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// What one worker asks of another.
pub enum Msg {
    /// List this worker's streams (`show sess`).
    ShowSess(Arc<Gather<Vec<SessSnap>>>),
    /// List this worker's QUIC connections (`show quic`, T524).
    ShowQuic(Arc<Gather<Vec<QuicSnap>>>),
    /// Shut down this worker's streams that match; reply how many.
    Shutdown(Arc<SessFilter>, Arc<Gather<usize>>),
    /// A gather a task of this worker waits on is complete: wake the task.
    Wake(TaskRef),
    /// To worker 0: a `do-resolve` question its sections answer (T489).
    DoResolve(ibex_alloc::PoolBox<Box<crate::resolvers::DrMsg>>),
    /// Back to the worker that asked: the answer, for its cache and the waiting stream.
    DoResolved(ibex_alloc::PoolBox<Box<crate::resolvers::DrMsg>>),
}

impl Msg {
    /// The answer of a worker that will never run: nothing.
    fn answer_empty(self, wid: usize) {
        match self {
            Msg::ShowSess(g) => g.reply(wid, Vec::new()),
            Msg::ShowQuic(g) => g.reply(wid, Vec::new()),
            Msg::Shutdown(_, g) => g.reply(wid, 0),
            // The stream that asked gives up at its deadline.
            Msg::Wake(_) | Msg::DoResolve(_) | Msg::DoResolved(_) => {}
        }
    }
}

/// The streams a `shutdown session(s)` names. Indices are into the shared proxies.
#[derive(Clone, Copy, Debug)]
pub enum SessFilter {
    /// `shutdown sessions server <be>/<srv>`.
    Server { be: usize, srv: usize },
    /// `shutdown sessions backend <be>`.
    Backend(usize),
    /// `shutdown session <id>`, an id `show sess` printed.
    Id(u64),
}

/// One stream as `show sess` prints it: values copied on the stream's worker, at the moment
/// it answered. Timers are milliseconds from then (`None`: not armed), as `HAProxy` prints
/// them relative to `now_ms`.
#[derive(Clone, Debug)]
pub struct SessSnap {
    /// What `show sess` prints in place of `HAProxy`'s stream pointer; see [`sess_id`].
    pub id: u64,
    /// When the stream started, for listing a worker's streams in their creation order.
    pub created: std::time::Instant,
    /// What `age=` counts from: the request's first byte for HTTP (`request_ts`).
    pub since: std::time::Instant,
    pub proto: &'static str,
    /// The client address, `None` for a CLI connection (`src=unix:1`).
    pub src: Option<std::net::SocketAddr>,
    /// Proxy indices: the frontend (`None`: the CLI's `GLOBAL`), the backend if it is one,
    /// and the server.
    pub fe: Option<usize>,
    pub be: Option<usize>,
    pub srv: Option<usize>,
    pub req_in: usize,
    pub rep_in: usize,
    pub cli_fd: i32,
    pub srv_fd: i32,
    pub cli_rex: Option<i64>,
    pub srv_rex: Option<i64>,
    /// The client side's send-blocked timer (`scf` `wex=`); `None` when nothing waits on the client.
    pub cli_wex: Option<i64>,
    pub exp: Option<i64>,
    pub c_exp: Option<i64>,
    /// Connection retries done (`s->conn_retries`, which counts up in HAProxy 3.x).
    pub retries: u16,
    pub uri: Option<String>,
}

/// One QUIC connection as `show quic` prints it, copied on its worker (T524).
#[derive(Clone, Debug)]
pub struct QuicSnap {
    pub worker: usize,
    /// The frontend (proxy index) the listener serves, `None` for a listener without one.
    pub fe: Option<usize>,
    /// The connection's key: the destination CID of its first Initial.
    pub id: ibex_quic::ConnectionId,
    pub phase: ibex_quic::ConnPhase,
    pub local: std::net::SocketAddr,
    pub peer: std::net::SocketAddr,
    pub lost_packets: u64,
}

/// The id `show sess` prints for stream `idx` of worker `wid`'s arena, and `shutdown
/// session` takes. Like `HAProxy`'s pointer, it may name a later stream once this one ends.
#[must_use]
pub fn sess_id(wid: usize, idx: u32) -> u64 {
    ((wid as u64 + 1) << 32) | u64::from(idx)
}

/// The worker and arena index of a [`sess_id`].
#[must_use]
pub fn sess_id_parts(id: u64) -> Option<(usize, u32)> {
    let wid = usize::try_from(id >> 32).ok()?.checked_sub(1)?;
    Some((wid, u32::try_from(id & 0xFFFF_FFFF).ok()?))
}

#[derive(Default)]
struct Inbox {
    msgs: Vec<Msg>,
    closed: bool,
}

struct Mailbox {
    inbox: Mutex<Inbox>,
    efd: OwnedFd,
    /// The worker is stopping and has nothing left to serve, or is gone ([`Mailboxes::all_done`]).
    done: AtomicBool,
    /// [`Signal`]s posted without a message (no allocation): bits, cleared by [`Mailboxes::take_signals`].
    signals: AtomicU8,
}

/// What a worker is told without a [`Msg`] (S6b, the buffer wait queue across threads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Signal {
    /// Another thread waits for a standard buffer: put the cached ones on the pool's shelf.
    ShelveBuffers = 1,
    /// Buffers were put on the shelf: wake this thread's buffer waiters.
    BuffersShelved = 2,
}

/// One mailbox per worker.
pub struct Mailboxes {
    boxes: Vec<Mailbox>,
}

impl Mailboxes {
    /// Mailboxes for `workers` workers.
    ///
    /// # Errors
    /// `eventfd` failure.
    pub fn new(workers: usize) -> io::Result<Arc<Self>> {
        let boxes = (0..workers.max(1))
            .map(|_| {
                let efd = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK)?;
                Ok(Mailbox { inbox: Mutex::new(Inbox::default()), efd, done: AtomicBool::new(false), signals: AtomicU8::new(0) })
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Arc::new(Self { boxes }))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.boxes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty()
    }

    /// The descriptor worker `wid` polls for its mailbox.
    #[must_use]
    pub fn fd(&self, wid: usize) -> BorrowedFd<'_> {
        self.boxes[wid].efd.as_fd()
    }

    /// Queues `msg` for worker `wid` and wakes it. A stopped worker's share is answered
    /// empty here.
    pub fn post(&self, wid: usize, msg: Msg) {
        let Some(b) = self.boxes.get(wid) else {
            msg.answer_empty(wid);
            return;
        };
        let mut inbox = b.inbox.lock().unwrap_or_else(PoisonError::into_inner);
        if inbox.closed {
            drop(inbox);
            msg.answer_empty(wid);
            return;
        }
        inbox.msgs.push(msg);
        drop(inbox);
        let _ = rustix::io::write(&b.efd, &1u64.to_ne_bytes());
    }

    /// Tells worker `wid` `sig` and wakes it: one atomic and an eventfd write, nothing allocated.
    pub fn signal(&self, wid: usize, sig: Signal) {
        if let Some(b) = self.boxes.get(wid) {
            b.signals.fetch_or(sig as u8, Ordering::Release);
            let _ = rustix::io::write(&b.efd, &1u64.to_ne_bytes());
        }
    }

    /// Whether worker `wid` was told `sig` since it last looked, and the others it was told;
    /// clears them. After [`Self::take`] (which clears the wakeup), so that a signal posted
    /// between the two wakes the worker again.
    #[must_use]
    pub fn take_signals(&self, wid: usize) -> u8 {
        self.boxes.get(wid).map_or(0, |b| b.signals.swap(0, Ordering::Acquire))
    }

    /// Sends a message made by `make` to every worker.
    pub fn broadcast(&self, make: impl Fn() -> Msg) {
        for wid in 0..self.boxes.len() {
            self.post(wid, make());
        }
    }

    /// What is queued for worker `wid`, clearing its wakeup.
    #[must_use]
    pub fn take(&self, wid: usize) -> Vec<Msg> {
        let Some(b) = self.boxes.get(wid) else {
            return Vec::new();
        };
        let mut buf = [0u8; 8];
        let _ = rustix::io::read(&b.efd, &mut buf);
        std::mem::take(&mut b.inbox.lock().unwrap_or_else(PoisonError::into_inner).msgs)
    }

    /// A stopping worker `wid` has no session left: it goes on serving its mailbox until
    /// every worker is done ([`Self::all_done`]).
    pub fn mark_done(&self, wid: usize) {
        if let Some(b) = self.boxes.get(wid) {
            b.done.store(true, Ordering::Relaxed);
        }
    }

    /// Every worker is done with its soft stop, or gone: they may all leave. `HAProxy`'s
    /// threads leave together (`run_poll_loop`, `stopping_thread_mask`), so that a thread
    /// finished early is still there for the others: for a CLI session's `show sess`, and
    /// to empty its pool cache on the soft stop's `pool_gc` (T456).
    #[must_use]
    pub fn all_done(&self) -> bool {
        self.boxes.iter().all(|b| b.done.load(Ordering::Relaxed))
    }

    /// Worker `wid` stops: what it was asked and anything asked later is answered empty.
    pub fn close(&self, wid: usize) {
        let Some(b) = self.boxes.get(wid) else {
            return;
        };
        b.done.store(true, Ordering::Relaxed);
        let msgs = {
            let mut inbox = b.inbox.lock().unwrap_or_else(PoisonError::into_inner);
            inbox.closed = true;
            std::mem::take(&mut inbox.msgs)
        };
        for m in msgs {
            m.answer_empty(wid);
        }
    }
}

/// The replies of every worker to one request, and who to wake when the last is in.
pub struct Gather<R> {
    state: Mutex<(Vec<Option<R>>, usize)>,
    waiter: (usize, TaskRef),
    boxes: Arc<Mailboxes>,
}

impl<R> Gather<R> {
    /// A gather of one reply per worker of `boxes`, waking `task` of worker `wid` when done.
    #[must_use]
    pub fn new(boxes: &Arc<Mailboxes>, wid: usize, task: TaskRef) -> Arc<Self> {
        let n = boxes.len();
        Arc::new(Self {
            state: Mutex::new(((0..n).map(|_| None).collect(), n)),
            waiter: (wid, task),
            boxes: Arc::clone(boxes),
        })
    }

    /// Worker `wid`'s reply. The last one wakes the waiter.
    pub fn reply(&self, wid: usize, r: R) {
        let done = {
            let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(slot) = st.0.get_mut(wid) else {
                return;
            };
            if slot.is_some() {
                return;
            }
            *slot = Some(r);
            st.1 -= 1;
            st.1 == 0
        };
        if done {
            self.boxes.post(self.waiter.0, Msg::Wake(self.waiter.1));
        }
    }

    /// Every worker's reply, in worker order, once all are in.
    #[must_use]
    pub fn take(&self) -> Option<Vec<R>> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.1 != 0 {
            return None;
        }
        Some(st.0.iter_mut().filter_map(Option::take).collect())
    }
}

/// `human_time(t, 1)` of `HAProxy` (`src/tools.c`): at most two units of `d`, `h`, `m`,
/// `s`; `?` for a negative value.
#[must_use]
pub fn human_time(secs: i64) -> String {
    use std::fmt::Write as _;
    const MINUTE: i64 = 60;
    const HOUR: i64 = 3600;
    const DAY: i64 = 86400;
    if secs < 0 {
        return "?".into();
    }
    let t = secs;
    let mut out = String::new();
    let mut cnt = 2;
    if t >= DAY {
        let _ = write!(out, "{}d", t / DAY);
        cnt -= 1;
    }
    if cnt > 0 && t % DAY / HOUR != 0 {
        let _ = write!(out, "{}h", t % DAY / HOUR);
        cnt -= 1;
    }
    if cnt > 0 && t % HOUR / MINUTE != 0 {
        let _ = write!(out, "{}m", t % HOUR / MINUTE);
        cnt -= 1;
    }
    if (cnt > 0 && t % MINUTE != 0) || t == 0 {
        let _ = write!(out, "{}s", t % MINUTE);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_time_matches_haproxy() {
        assert_eq!(human_time(0), "0s");
        assert_eq!(human_time(26), "26s");
        assert_eq!(human_time(60), "1m");
        assert_eq!(human_time(3725), "1h2m");
        assert_eq!(human_time(90061), "1d1h");
        assert_eq!(human_time(86400 + 5), "1d5s");
        assert_eq!(human_time(-1), "?");
    }

    #[test]
    fn a_gather_completes_with_a_stopped_worker_and_wakes_the_waiter() {
        let boxes = Mailboxes::new(3).expect("eventfd");
        boxes.close(2);
        let g: Arc<Gather<usize>> = Gather::new(&boxes, 0, TaskRef::NONE);
        boxes.broadcast(|| Msg::Shutdown(Arc::new(SessFilter::Id(1)), Arc::clone(&g)));
        assert!(g.take().is_none(), "workers 0 and 1 have not answered");
        for wid in 0..2 {
            for m in boxes.take(wid) {
                if let Msg::Shutdown(_, g) = m {
                    g.reply(wid, wid + 1);
                }
            }
        }
        assert_eq!(g.take(), Some(vec![1, 2, 0]));
        assert!(matches!(boxes.take(0).as_slice(), [Msg::Wake(_)]), "the waiter is woken");
        assert_eq!(sess_id_parts(sess_id(3, 7)), Some((3, 7)));
        assert_eq!(sess_id_parts(7), None);
    }

    #[test]
    fn queued_and_late_requests_to_a_stopped_worker_are_answered_empty() {
        let boxes = Mailboxes::new(2).expect("eventfd");
        assert!(!boxes.is_empty());
        let g: Arc<Gather<Vec<SessSnap>>> = Gather::new(&boxes, 0, TaskRef::NONE);
        // Queued before worker 1 stops, then the stop: answered by `close`.
        boxes.post(1, Msg::ShowSess(Arc::clone(&g)));
        boxes.post(1, Msg::Wake(TaskRef::NONE));
        boxes.close(1);
        // A worker that does not exist answers nothing, and asks nothing.
        boxes.post(7, Msg::ShowSess(Arc::clone(&g)));
        assert!(boxes.take(7).is_empty());
        boxes.close(7);
        // A reply from no such worker, and a second reply, change nothing.
        g.reply(9, vec![]);
        g.reply(1, vec![]);
        assert!(g.take().is_none(), "worker 0 has not answered");
        boxes.post(0, Msg::ShowSess(Arc::clone(&g)));
        for m in boxes.take(0) {
            if let Msg::ShowSess(g) = m {
                g.reply(0, Vec::new());
            }
        }
        assert_eq!(g.take().map(|v| v.len()), Some(2));
    }
}
