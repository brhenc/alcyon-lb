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
    /// `accept_date`: the same moment, as unix seconds and milliseconds.
    pub date: (i64, u32),
    /// The first byte of the request arrived (end of `t_idle`).
    pub first_byte: Option<Instant>,
    /// The request head was complete (`request_ts`).
    pub request: Option<Instant>,
    /// The connection to a server was first attempted (`t_queue`).
    pub queue: Option<Instant>,
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
    /// The request line as received, for `%r` and `%HU`..; set only for a request that
    /// parsed (`txn->uri`), so a refused one logs `<BADREQ>`.
    pub request_line: Option<String>,
    /// Header capture slots: request (`capture request header`, `http-request capture`)
    /// and response.
    pub req_captures: Vec<Option<Vec<u8>>>,
    pub res_captures: Vec<Option<Vec<u8>>>,
    /// `unique-id-format`'s value for this stream.
    pub unique_id: Option<String>,
    /// `%rt`.
    pub uniq_id: u64,
    /// The termination state, when the proxy itself ended the stream: `PR` for a denied
    /// or unparsable request, `LR` for one answered by a rule (`return`, `redirect`).
    pub term: Option<[u8; 2]>,
    /// The status of a reply sent with no transaction to carry it: the 408 for a request
    /// that never arrived, the 400 for one the client abandoned.
    pub status: Option<u16>,
}

impl StreamLog {
    /// A stream starting now, on a session whose counters read `bytes_in`/`bytes_out`.
    #[must_use]
    pub fn start(bytes_in: u64, bytes_out: u64) -> StreamLog {
        let date = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        StreamLog {
            start: Instant::now(),
            date: (i64::try_from(date.as_secs()).unwrap_or(0), date.subsec_millis()),
            first_byte: None,
            request: None,
            queue: None,
            connect: None,
            data: None,
            bytes_in_at_start: bytes_in,
            bytes_out_at_start: bytes_out,
            bytes_from_server: 0,
            request_line: None,
            req_captures: Vec::new(),
            res_captures: Vec::new(),
            unique_id: None,
            uniq_id: STREAM_COUNTER.fetch_add(1, Ordering::Relaxed),
            term: None,
            status: None,
        }
    }

    /// Milliseconds from the stream's start to `t`, -1 if it never happened.
    #[must_use]
    pub fn ms(&self, t: Option<Instant>) -> i64 {
        t.map_or(-1, |t| i64::try_from(t.saturating_duration_since(self.start).as_millis()).unwrap_or(i64::MAX))
    }

    /// Records the first request byte, once.
    pub fn first_byte_now(&mut self) {
        self.first_byte.get_or_insert_with(Instant::now);
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
