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

#[derive(Clone, Debug)]
pub struct StreamLog {
    /// `accept_ts`: the stream's start.
    pub start: Instant,
    /// The first byte of the request arrived (end of `t_idle`).
    pub first_byte: Option<Instant>,
    /// The request head was complete (`request_ts`).
    pub request: Option<Instant>,
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

ibex_alloc::declare_pool!(
    /// `show pools` `caphdr` (`HAProxy`'s name for the same objects): the buffers of capture
    /// values that ended with their stream, for the next ones (T437): a capture of a kept-alive
    /// request reuses one instead of allocating. They held captured headers: wiped when given
    /// back under `tune.ibex.zero-spares`.
    static CAPHDR: Pool<Vec<u8>> = ibex_alloc::PoolSpec::new("caphdr").max_count(SPARE_CAPTURES).spares();
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
}

/// Sets the thread's clock for the pass that is starting (once per loop iteration, after the poller).
pub fn set_loop_now(t: Instant) {
    LOOP_NOW.with(|c| c.set(Some(t)));
}

/// The time every log timer is stamped from: the loop's per-iteration clock, as `HAProxy`'s
/// `now_ns`, so two events of one pass carry one timestamp. A clock read where no loop runs.
#[must_use]
pub fn loop_now() -> Instant {
    LOOP_NOW.with(std::cell::Cell::get).unwrap_or_else(Instant::now)
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
        StreamLog {
            start: loop_now(),
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

    /// The next stream of the connection starts now: as [`StreamLog::start`], but the
    /// buffers of the one that ended (the request line, the capture slots) are kept for it,
    /// emptied, so that a kept-alive request does not allocate them again (T437).
    pub fn restart(&mut self, bytes_in: u64, bytes_out: u64) {
        let mut request_line = std::mem::take(&mut self.request_line);
        request_line.reset();
        let mut request_slots = std::mem::take(&mut self.req_captures);
        release_captures(&mut request_slots);
        let mut response_slots = std::mem::take(&mut self.res_captures);
        release_captures(&mut response_slots);
        *self = StreamLog::start(bytes_in, bytes_out);
        self.request_line = request_line;
        self.req_captures = request_slots;
        self.res_captures = response_slots;
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
}
