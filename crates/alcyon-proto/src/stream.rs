// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/stream-t.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stream: one transaction, with a connector at each end.

use crate::endpoint::StConn;
use crate::session::SessionId;
use alcyon_sched::{TaskRef, Tick};

/// Index into a thread's stream arena.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct StreamId(pub u32);

impl StreamId {
    pub const NONE: StreamId = StreamId(u32::MAX);
    #[must_use]
    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }
}

/// Stream state bits. `HAProxy`'s `SF_*`.
pub mod stream_flags {
    /// A backend has been selected.
    pub const BE_ASSIGNED: u32 = 1 << 0;
    /// The stream holds a server slot.
    pub const SRV_ASSIGNED: u32 = 1 << 1;
    /// Waiting in a server queue.
    pub const QUEUED: u32 = 1 << 2;
    /// The request has been fully forwarded.
    pub const REQ_DONE: u32 = 1 << 3;
    /// The response has been fully forwarded.
    pub const RES_DONE: u32 = 1 << 4;
    /// Operating as an opaque tunnel (CONNECT, upgrade).
    pub const TUNNEL: u32 = 1 << 5;
    /// Terminated because of an error.
    pub const ERR: u32 = 1 << 6;
    /// Terminated because of a timeout.
    pub const TIMEOUT: u32 = 1 << 7;
}

/// One transaction.
///
/// Note what it points at: two [`StConn`]s, never a connection. Whether either end is a
/// mux stream on a socket or an applet is invisible from here, which is what lets the
/// CLI and the stats page be served by this same engine. See
/// [`crate::endpoint::Endpoint`].
#[derive(Clone, Debug)]
pub struct Stream {
    /// The session this stream belongs to. Many streams may share one.
    pub session: SessionId,
    /// Frontend-side connector: faces the client.
    pub scf: StConn,
    /// Backend-side connector: faces the server, or an applet.
    pub scb: StConn,
    /// Selected backend, once one is chosen.
    pub backend: Option<u32>,
    /// Selected server, once one is chosen.
    pub server: Option<u32>,
    pub flags: u32,
    /// The task that drives this stream through the analyser pipeline.
    pub task: TaskRef,
    /// Connection attempts made so far.
    pub conn_retries: u16,
    /// Deadline for the current connect attempt.
    pub conn_exp: Tick,
    /// Per-stream timeout overrides, settable by `set-timeout` actions.
    pub timeout_connect: Option<u32>,
    pub timeout_server: Option<u32>,
    pub timeout_tunnel: Option<u32>,
    /// Where rule evaluation resumes after a yield, so a long rule list can be
    /// interrupted without restarting.
    pub rule_cursor: Option<(u32, u32)>,
    /// Rules evaluated since the last yield, bounding work per pass on untrusted input.
    pub rules_evaluated: u32,
    /// Stick counters at content scope, by index.
    pub stick_counters: [u32; 3],
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub client_addr: Option<std::net::SocketAddr>,
    pub proxy_info: Option<crate::proxy_protocol::ProxyInfo>,
}

impl Stream {
    #[must_use]
    pub const fn new(session: SessionId) -> Self {
        Stream {
            session,
            scf: StConn::new(),
            scb: StConn::new(),
            backend: None,
            server: None,
            flags: 0,
            task: TaskRef::NONE,
            conn_retries: 0,
            conn_exp: Tick::ETERNITY,
            timeout_connect: None,
            timeout_server: None,
            timeout_tunnel: None,
            rule_cursor: None,
            rules_evaluated: 0,
            stick_counters: [u32::MAX; 3],
            bytes_in: 0,
            bytes_out: 0,
            client_addr: None,
            proxy_info: None,
        }
    }

    #[must_use]
    #[inline]
    pub const fn has(&self, f: u32) -> bool {
        self.flags & f != 0
    }

    /// True once both directions have finished forwarding.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.has(stream_flags::REQ_DONE) && self.has(stream_flags::RES_DONE)
    }
}
