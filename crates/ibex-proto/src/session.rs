// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/session-t.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The session: one client connection's context.

use crate::conn::ConnId;
use ibex_sched::{TaskRef, Tick};
use std::net::SocketAddr;

/// Index into a thread's session arena.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(pub u32);

impl SessionId {
    pub const NONE: SessionId = SessionId(u32::MAX);
    #[must_use]
    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }
}

/// Connection-level context, distinct from the per-transaction [`crate::Stream`].
///
/// # Why this is a separate object
///
/// **A session has many streams.** Under HTTP/1 the ratio looks like 1:1 and the two
/// can be conflated without immediate consequence; under HTTP/2 one connection spawns
/// many concurrent streams and the conflation stops working. `HAProxy` split these in 1.8
/// for exactly that reason.
///
/// The division is not arbitrary. Anything scoped to *the connection* lives here —
/// which frontend accepted it, the handshake timeout, the tcp-connection stick
/// counters, the session-scope variables, the private backend connections reserved to
/// this client. Anything scoped to *a request* lives in the stream.
///
/// Ibex targets H1 only, so this could be collapsed today. It is kept separate because
/// the alternative is a rewrite of everything downstream the first time a second stream
/// appears on one connection.
#[derive(Clone, Debug)]
pub struct Session {
    /// Frontend that accepted this session, by index.
    pub frontend: u32,
    /// Listener it arrived on, by index.
    pub listener: u32,
    /// The originating client connection.
    pub origin: ConnId,
    /// When the connection was accepted.
    pub accept_ts: Tick,
    /// Handshake duration once known.
    pub handshake_ms: Option<u32>,
    /// How long the connection sat idle before this request.
    pub idle_ms: Option<u32>,
    /// Task enforcing the handshake timeout.
    pub task: TaskRef,
    /// Backend connections reserved to this session and unusable by others.
    pub private_conns: Vec<ConnId>,
    /// Idle connections this session is responsible for.
    pub idle_conns: u32,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
    /// Stick counters tracked at tcp-connection scope, by index into the stick tables.
    pub stick_counters: [u32; 3],
    /// Number of streams currently alive on this session. Always 1 under H1; the
    /// field exists so that stops being an assumption baked into the engine.
    pub stream_count: u32,
}

impl Session {
    #[must_use]
    pub fn new(frontend: u32, listener: u32, origin: ConnId, now: Tick) -> Self {
        Session {
            frontend,
            listener,
            origin,
            accept_ts: now,
            handshake_ms: None,
            idle_ms: None,
            task: TaskRef::NONE,
            private_conns: Vec::new(),
            idle_conns: 0,
            src: None,
            dst: None,
            stick_counters: [u32::MAX; 3],
            stream_count: 0,
        }
    }
}
