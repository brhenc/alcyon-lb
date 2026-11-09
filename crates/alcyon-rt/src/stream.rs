// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/stream-t.h (struct stream) and src/stream.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The per-request state of a session, `HAProxy`'s `struct stream` (O1a,
//! `docs/design/engine-architecture-2026-11-01.md` §4.3): the HTTP transaction, what the
//! stream measured for its log line (and its captures), its variables, the stick keys it
//! took and the timeouts its rules set.
//!
//! An HTTP/1 connection keeps its one stream from request to request, inside its session,
//! and resets it in place at each transaction's end ([`Stream::reset`]), where `HAProxy`
//! frees the stream and allocates the next (`stream_free`/`stream_new`). An HTTP/2 or HTTP/3
//! stream is still a session of its own until O1b; the type is the one those streams will hold
//! by stream id.
//!
//! Not a pool object (the plan's §4.3 row said one): measured (ab1 keepalive, release-perf,
//! user ins/req), a `Box<Stream>` taken from a `stream` pool cost +0.33k a request over the
//! stream held in the session (36,243 and 36,207 against 35,912; base bd5f534e 36,046): every
//! `sess.strm.*` access loads the box's pointer first. On HTTP/1 the stream lives exactly as
//! long as its session, whose entry is already the per-connection object; O1b decides where
//! the multiplexed streams' memory comes from.
//!
//! What is not here yet, and stays on the session: the backend side (the server connection
//! and its transport, which an HTTP/1 connection keeps from one request to the next), the
//! task and the timers (the session's on HTTP/1, one stream at a time). O1b moves them for the
//! multiplexed streams.

use crate::proxy::{Timeouts, TimeoutsSet};
use crate::txn::HttpTxn;
use crate::txnlog::StreamLog;
use alcyon_stick_table::StickKey;

pub struct Stream {
    /// The HTTP transaction in progress: `None` between requests, and always in `mode
    /// tcp`. What may be forwarded in each direction is decided by its message states.
    pub txn: Option<HttpTxn>,
    /// What this stream measured for its log line, and its captures and unique ID.
    pub log: StreamLog,
    /// The stream's variables, every scope (`sess.`, `txn.`, `req.`, `res.`); in the thread's
    /// `CURRENT_VARS` while the stream runs, swapped (T364 S6). The `sess.` scope rides with
    /// the stream while a connection has one stream (HTTP/1); O1b keeps it on the connection.
    pub vars: alcyon_sample::VarStore,
    /// The keys `stick on` and `stick store-request` took from the request, each with the
    /// proxy whose table keeps it: stored with the server that answers.
    pub stick_stores: Vec<(usize, StickKey)>,
    /// What `http-request set-timeout` set for the stream in progress; `None` until a rule
    /// sets one, so a stream that sets none allocates nothing.
    pub timeouts_set: Option<Box<TimeoutsSet>>,
}

impl Stream {
    /// A stream for a session starting now.
    #[must_use]
    pub fn start() -> Stream {
        crate::probe::stream_take();
        Stream {
            txn: None,
            log: StreamLog::start(0, 0),
            vars: alcyon_sample::VarStore::new(),
            stick_stores: Vec::new(),
            timeouts_set: None,
        }
    }

    /// The transaction is over and the connection waits for its next request: this stream
    /// becomes that request's, in place (no `Stream` taken, no `StreamLog` built). What the
    /// ended request set goes: the transaction, the log's measures and captures, the `txn.`
    /// and `req.`/`res.` variables, the stick keys, and the timeouts a rule set (`timeouts`
    /// gets back the ones from before). The session's byte counters read `bytes_in` and
    /// `bytes_out` now.
    pub fn reset(&mut self, bytes_in: u64, bytes_out: u64, timeouts: &mut Timeouts) {
        self.log.reset(bytes_in, bytes_out);
        self.txn = None;
        self.vars.clear_txn();
        if let Some(set) = self.timeouts_set.take() {
            *timeouts = set.before;
        }
        self.stick_stores.clear();
    }
}
