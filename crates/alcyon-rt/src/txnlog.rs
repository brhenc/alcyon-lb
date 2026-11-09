// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/stream-t.h (struct strm_logs) and src/log.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What one stream measured for its log line: an HTTP transaction, or a TCP connection.
//!
//! `HAProxy` keeps these in `struct strm_logs` as milliseconds from the stream's start,
//! -1 for an event that never happened; this records the instants and converts them when
//! the line is built. A new stream starts at the accept, and on a kept-alive connection
//! when the previous transaction ends -- the next request's idle time is measured from
//! there, as `HAProxy` measures it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::proxy::{Ending, Which};

/// The process-wide stream counter, `%rt` (`global.req_count`).
static STREAM_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct StreamLog {
    /// `accept_ts`: the stream's start.
    pub start: Instant,
    /// The first byte of the request arrived (end of `t_idle`).
    pub first_byte: Option<Instant>,
    /// The request head was complete (`request_ts`).
    pub request: Option<Instant>,
    /// [`StreamLog::date`], once worked out ((0, 0): not yet).
    date_cache: std::cell::Cell<(i64, u32)>,
    /// The connection to a server was first attempted (`t_queue`).
    pub queue: Option<Instant>,
    /// The index of the server the stream chose in `srv_backend_idx`, kept while no connection
    /// is attached (connecting, retrying): HAProxy's `s->target` stays on the server, so
    /// the line names it (`%s`) when the client leaves before the connect succeeds. Held as
    /// index + 1 in four bytes, which keeps `SessionEntry` within its bound (struct_sizes.rs).
    pub server: Option<std::num::NonZeroU32>,
    /// The connection to the server was established (`t_connect`).
    pub connect: Option<Instant>,
    /// The response head arrived (`t_data`).
    pub data: Option<Instant>,
    /// The session's byte counters when the stream started.
    pub bytes_in_at_start: u64,
    pub bytes_out_at_start: u64,
    /// Bytes read from the server for this stream: `%B` counts these (`HAProxy` logs 0
    /// for a response the proxy produced itself).
    pub bytes_from_server: u64,
    /// `option checkcache` blocked a response: the alert is still to be sent to the backend's
    /// loggers (`http_process_res_common` logs it at level alert before the stream's line).
    pub checkcache_blocked: bool,
    /// The request line as received, for `%r` and `%HU`..; set only for a request that
    /// parsed (`txn->uri`), so a refused one logs `<BADREQ>`. Its buffer is kept from one
    /// stream of a connection to the next ([`StreamLog::restart`], T437).
    pub request_line: crate::proxy::ReqText,
    /// Header capture slots: request (`capture request header`, `http-request capture`)
    /// and response.
    pub req_captures: Vec<Option<Vec<u8>>>,
    pub res_captures: Vec<Option<Vec<u8>>>,
    /// `unique-id-format`'s value for this stream.
    pub unique_id: Option<String>,
    /// The configuration line of the last rule that ended a rule set for this request
    /// (`s->last_rule_line`), for `last_rule_file` and `last_rule_line`.
    pub last_rule: Option<u32>,
    /// `set-priority-class` and `set-priority-offset` (`s->priority_class`, `priority_offset`).
    pub prio_class: i32,
    pub prio_offset: i32,
    /// `%rt`.
    pub uniq_id: u64,
    /// The termination state, when the proxy itself ended the stream: `PR` for a denied
    /// or unparsable request, `LR` for one answered by a rule (`return`, `redirect`).
    pub term: Option<[u8; 2]>,
    /// The status of a reply sent with no transaction to carry it: the 408 for a request
    /// that never arrived, the 400 for one the client abandoned.
    pub status: Option<u16>,
    /// A retry was balanced anew (`SF_REDISP`): `%rc` is written with a `+` in front.
    pub redispatched: bool,
    /// The stream was answered by an applet (the stats page): `when(toapplet)`.
    pub applet: bool,
    /// How many requests were in the backend's queue, this one among them, when it joined
    /// it (`%bq`); 0 for one that never queued.
    pub be_queue: u32,
    /// `option logasap`: the line went out with the response head; none follows.
    pub asap_done: bool,
    /// The status of the response a server sent for this stream (`txn->server_status`), 0 when
    /// none did: what `%[server_status]` reads at the end of the stream (T467).
    pub srv_status: u16,
}

/// Capture buffers let go of, at most this many kept per thread for the next captures.
const SPARE_CAPTURES: usize = 64;

alcyon_alloc::declare_pool!(
    /// `show pools` `caphdr` (`HAProxy`'s name for the same objects): the buffers of capture
    /// values that ended with their stream, for the next ones (T437): a capture of a kept-alive
    /// request reuses one instead of allocating. They held captured headers: wiped when given
    /// back under `tune.alcyon.zero-spares`.
    static CAPHDR: Pool<Vec<u8>> = alcyon_alloc::PoolSpec::new("caphdr").max_count(SPARE_CAPTURES).spares();
);

/// Lists the pool in `show pools` from the start.
pub fn register_pools() {
    CAPHDR.register();
}

/// Puts `v` in the capture slot `slot`, in the memory it holds already or in a spare buffer.
pub fn set_capture(slot: &mut Option<Vec<u8>>, v: &[u8]) {
    let buf = slot.get_or_insert_with(|| CAPHDR.take_raw(|| Some(Vec::new())).unwrap_or_default());
    buf.clear();
    buf.extend_from_slice(v);
}

/// Empties the capture slot `slot`, its buffer kept for a later capture.
pub fn clear_capture(slot: &mut Option<Vec<u8>>) {
    if let Some(b) = slot.take() {
        CAPHDR.give(b);
    }
}

/// Empties every slot of `caps` and the list itself (its capacity kept).
pub fn release_captures(caps: &mut Vec<Option<Vec<u8>>>) {
    for c in caps.iter_mut() {
        clear_capture(c);
    }
    caps.clear();
}

/// `to` as a copy of `from`, from the memory it and its values hold.
fn copy_captures(to: &mut Vec<Option<Vec<u8>>>, from: &[Option<Vec<u8>>]) {
    reset_captures(to, from.len());
    for (t, f) in to.iter_mut().zip(from) {
        if let Some(v) = f {
            set_capture(t, v);
        }
    }
}

/// `caps` as `n` empty slots, from the memory it and its values hold.
pub fn reset_captures(caps: &mut Vec<Option<Vec<u8>>>, n: usize) {
    release_captures(caps);
    caps.resize(n, None);
}

/// A server index as `StreamLog::server` holds it (index + 1); `None` past `u32::MAX - 1`.
#[must_use]
pub fn server_slot(idx: usize) -> Option<std::num::NonZeroU32> {
    std::num::NonZeroU32::new(u32::try_from(idx).ok()?.checked_add(1)?)
}

thread_local! {
    /// The loop's clock for this pass (`now_ns`, refreshed by `clock_update_date` after the poller).
    static LOOP_NOW: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
    /// The same instant as [`crate::statcnt::now_ms`] reads it (0: not set), worked out once a pass.
    static LOOP_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The pass's `now_ms`, 0 where no loop runs.
#[must_use]
pub fn loop_ms() -> u64 {
    LOOP_MS.with(std::cell::Cell::get)
}

/// Sets the thread's clock for the pass that is starting (once per loop iteration, after the poller).
pub fn set_loop_now(t: Instant) {
    LOOP_NOW.with(|c| c.set(Some(t)));
    LOOP_MS.with(|c| c.set(crate::statcnt::ms_at(t)));
}

/// The time every log timer is stamped from: the loop's per-iteration clock, as `HAProxy`'s
/// `now_ns`, so two events of one pass carry one timestamp. A clock read where no loop runs.
#[must_use]
pub fn loop_now() -> Instant {
    LOOP_NOW.with(std::cell::Cell::get).unwrap_or_else(|| {
        crate::probe::clock_read();
        Instant::now()
    })
}

thread_local! {
    /// A wall-clock reading and the monotonic instant it was taken at, renewed once a second.
    static WALL_BASE: std::cell::Cell<Option<(Instant, SystemTime)>> = const { std::cell::Cell::new(None) };
}

impl StreamLog {
    /// `accept_date`: the stream's start as unix seconds and milliseconds. Worked out from a
    /// wall-clock base read at most once a second, and only when something asks for it: a
    /// stream nobody logs or fetches the date of costs no `SystemTime::now` (T579, C1).
    #[must_use]
    pub fn date(&self) -> (i64, u32) {
        // Seconds 0 (1970) marks it not worked out yet.
        let d = self.date_cache.get();
        if d.0 != 0 {
            return d;
        }
        let d = self.date_uncached();
        self.date_cache.set(d);
        d
    }

    fn date_uncached(&self) -> (i64, u32) {
        let (at, wall) = WALL_BASE.with(|c| match c.get() {
            Some(b) if loop_now().saturating_duration_since(b.0) < std::time::Duration::from_secs(1) => b,
            _ => {
                crate::probe::wall_read();
                let b = (loop_now(), SystemTime::now());
                c.set(Some(b));
                b
            }
        });
        let d = if self.start >= at {
            wall + self.start.duration_since(at)
        } else {
            wall - at.duration_since(self.start)
        };
        let d = d.duration_since(UNIX_EPOCH).unwrap_or_default();
        (i64::try_from(d.as_secs()).unwrap_or(0), d.subsec_millis())
    }

    /// A stream starting now, on a session whose counters read `bytes_in`/`bytes_out`.
    #[must_use]
    pub fn start(bytes_in: u64, bytes_out: u64) -> StreamLog {
        crate::probe::stream_log_start();
        StreamLog {
            start: loop_now(),
            date_cache: std::cell::Cell::new((0, 0)),
            first_byte: None,
            request: None,
            queue: None,
            server: None,
            connect: None,
            data: None,
            bytes_in_at_start: bytes_in,
            bytes_out_at_start: bytes_out,
            bytes_from_server: 0,
            checkcache_blocked: false,
            request_line: crate::proxy::ReqText::default(),
            req_captures: Vec::new(),
            res_captures: Vec::new(),
            unique_id: None,
            last_rule: None,
            prio_class: 0,
            prio_offset: 0,
            uniq_id: STREAM_COUNTER.fetch_add(1, Ordering::Relaxed),
            term: None,
            status: None,
            redispatched: false,
            applet: false,
            asap_done: false,
            srv_status: 0,
            be_queue: 0,
        }
    }

    /// The next stream of the connection starts now: as [`StreamLog::start`], in place (O1a):
    /// the buffers of the one that ended (the request line, the capture slots) are kept for
    /// it, emptied, so that a kept-alive request does not allocate them again (T437), and no
    /// `StreamLog` is built. Every field is named (no `..`): one added to the struct does not
    /// compile here until its reset is written.
    pub fn reset(&mut self, bytes_in: u64, bytes_out: u64) {
        let StreamLog {
            start,
            first_byte,
            request,
            date_cache,
            queue,
            server,
            connect,
            data,
            bytes_in_at_start,
            bytes_out_at_start,
            bytes_from_server,
            checkcache_blocked,
            request_line,
            req_captures,
            res_captures,
            unique_id,
            last_rule,
            prio_class,
            prio_offset,
            uniq_id,
            term,
            status,
            redispatched,
            applet,
            be_queue,
            asap_done,
            srv_status,
        } = self;
        *start = loop_now();
        *first_byte = None;
        *request = None;
        date_cache.set((0, 0));
        *queue = None;
        *server = None;
        *connect = None;
        *data = None;
        *bytes_in_at_start = bytes_in;
        *bytes_out_at_start = bytes_out;
        *bytes_from_server = 0;
        *checkcache_blocked = false;
        request_line.reset();
        release_captures(req_captures);
        release_captures(res_captures);
        *unique_id = None;
        *last_rule = None;
        *prio_class = 0;
        *prio_offset = 0;
        *uniq_id = STREAM_COUNTER.fetch_add(1, Ordering::Relaxed);
        *term = None;
        *status = None;
        *redispatched = false;
        *applet = false;
        *be_queue = 0;
        *asap_done = false;
        *srv_status = 0;
    }

    /// Makes this log a copy of `src`, in the memory it has: the capture lists, their values, the
    /// request line and the unique id keep their buffers (CP3). `Clone::clone_from` of a derived
    /// `Clone` is `*self = src.clone()`, which allocates the lists anew for every stream an HTTP/2
    /// connection starts. No `Clone`: this is the one copy a log has, and every field is named
    /// (no `..`), so one added to the struct does not compile here until its copy is written.
    pub fn clone_from(&mut self, src: &StreamLog) {
        let StreamLog {
            start,
            first_byte,
            request,
            date_cache,
            queue,
            server,
            connect,
            data,
            bytes_in_at_start,
            bytes_out_at_start,
            bytes_from_server,
            checkcache_blocked,
            request_line,
            req_captures,
            res_captures,
            unique_id,
            last_rule,
            prio_class,
            prio_offset,
            uniq_id,
            term,
            status,
            redispatched,
            applet,
            be_queue,
            asap_done,
            srv_status,
        } = self;
        (*start, *first_byte, *request) = (src.start, src.first_byte, src.request);
        date_cache.set(src.date_cache.get());
        (*queue, *server, *connect, *data) = (src.queue, src.server, src.connect, src.data);
        (*bytes_in_at_start, *bytes_out_at_start, *bytes_from_server) = (src.bytes_in_at_start, src.bytes_out_at_start, src.bytes_from_server);
        *checkcache_blocked = src.checkcache_blocked;
        request_line.set_opt(src.request_line.as_deref());
        copy_captures(req_captures, &src.req_captures);
        copy_captures(res_captures, &src.res_captures);
        unique_id.clone_from(&src.unique_id);
        (*last_rule, *prio_class, *prio_offset, *uniq_id) = (src.last_rule, src.prio_class, src.prio_offset, src.uniq_id);
        (*term, *status) = (src.term, src.status);
        (*redispatched, *applet, *be_queue, *asap_done, *srv_status) = (src.redispatched, src.applet, src.be_queue, src.asap_done, src.srv_status);
    }

    /// Milliseconds from the stream's start to `t`, -1 if it never happened.
    #[must_use]
    pub fn ms(&self, t: Option<Instant>) -> i64 {
        t.map_or(-1, |t| i64::try_from(t.saturating_duration_since(self.start).as_millis()).unwrap_or(i64::MAX))
    }

    /// Records the first request byte, once.
    pub fn first_byte_now(&mut self) {
        self.first_byte.get_or_insert_with(loop_now);
    }

    /// `%ts`: the cause and the phase the stream ended in (`sess_term_cond`,
    /// `sess_fin_state`), unless the code that ended it set them in `term`. `rsp_done`:
    /// the whole response was sent.
    #[must_use]
    pub fn term_state(&self, ending: Option<Ending>, http: bool, rsp_done: bool) -> [u8; 2] {
        if let Some(t) = self.term {
            return t;
        }
        let cause = match ending {
            None | Some(Ending::Complete) => return *b"--",
            Some(Ending::ClientAbort) => b'C',
            Some(Ending::ServerAbort | Ending::ConnectFailed) => b'S',
            Some(Ending::Timeout(Which::Client)) => b'c',
            Some(Ending::Timeout(_)) => b's',
            Some(Ending::Error) => b'I',
        };
        let phase = if http && self.request.is_none() {
            b'R'
        } else if self.connect.is_none() {
            b'C'
        } else if http && self.data.is_none() {
            b'H'
        } else if matches!(cause, b'c' | b'C') && rsp_done {
            // The response was all sent and the client side failed: still sending the last
            // data (`SF_FINST_L`, `http_set_term_flags`).
            b'L'
        } else {
            b'D'
        };
        [cause, phase]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each phase in the order `HAProxy` tests the stream's progress, and each cause.
    #[test]
    fn term_state_is_cause_then_phase() {
        let mut l = StreamLog::start(0, 0);
        assert_eq!(l.term_state(None, true, false), *b"--");
        assert_eq!(l.term_state(Some(Ending::Complete), true, false), *b"--");
        assert_eq!(l.term_state(Some(Ending::ClientAbort), true, false), *b"CR");
        assert_eq!(l.term_state(Some(Ending::Error), false, false), *b"IC");
        l.request = Some(Instant::now());
        assert_eq!(l.term_state(Some(Ending::ConnectFailed), true, false), *b"SC");
        l.connect = Some(Instant::now());
        assert_eq!(l.term_state(Some(Ending::Timeout(Which::Server)), true, false), *b"sH");
        l.data = Some(Instant::now());
        assert_eq!(l.term_state(Some(Ending::ServerAbort), true, false), *b"SD");
        assert_eq!(l.term_state(Some(Ending::Timeout(Which::Client)), true, true), *b"cL");
        assert_eq!(l.term_state(Some(Ending::Timeout(Which::Client)), true, false), *b"cD");
        l.term = Some(*b"PR");
        assert_eq!(l.term_state(Some(Ending::Complete), true, false), *b"PR");
    }

    /// `reset` leaves the log as `start` builds it (O1a): every field a stream wrote is gone,
    /// the stream's start and its `%rt` are new.
    #[test]
    fn reset_is_a_new_start_in_place() {
        let mut l = StreamLog::start(1, 2);
        let t = Instant::now();
        (l.first_byte, l.request, l.queue, l.connect, l.data) = (Some(t), Some(t), Some(t), Some(t), Some(t));
        l.server = server_slot(3);
        l.bytes_from_server = 9;
        l.checkcache_blocked = true;
        l.request_line.set("GET / HTTP/1.1");
        l.req_captures = vec![None, None];
        set_capture(&mut l.req_captures[1], b"x");
        l.res_captures = vec![None];
        set_capture(&mut l.res_captures[0], b"y");
        l.unique_id = Some("id".into());
        (l.last_rule, l.prio_class, l.prio_offset) = (Some(4), 5, 6);
        (l.term, l.status, l.redispatched, l.applet, l.be_queue, l.asap_done, l.srv_status) = (Some(*b"PR"), Some(400), true, true, 7, true, 200);
        let _ = l.date();
        let id = l.uniq_id;
        l.reset(10, 20);
        let mut fresh = StreamLog::start(10, 20);
        assert!(l.uniq_id > id);
        (fresh.start, fresh.uniq_id) = (l.start, l.uniq_id);
        assert_eq!(format!("{l:?}"), format!("{fresh:?}"));
    }
}
