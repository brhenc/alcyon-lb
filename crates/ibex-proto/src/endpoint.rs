// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/stconn-t.h (struct sedesc, struct stconn).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The pivot: stream endpoint descriptors and stream connectors.
//!
//! This is the indirection that lets one stream engine serve H1, passthrough, the CLI,
//! the stats page and peers without knowing which it is talking to.

use crate::conn::ConnId;

/// What sits at the far end of a [`StConn`].
///
/// `HAProxy` writes this as `void *se` plus an `enum obj_type` in the first field of
/// whatever `se` points at — a tagged union checked by convention, where getting the
/// tag wrong is undefined behaviour. Here it is an ordinary enum, and the entire class
/// of "wrong type behind the void pointer" ceases to exist.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Endpoint {
    /// Nothing attached yet.
    None,
    /// A stream inside a mux, on a connection.
    MuxStream { conn: ConnId, stream: u32 },
    /// An applet: the CLI, the stats page, peers, DNS.
    ///
    /// The stream treats this exactly like a backend connection, which is why the
    /// runtime socket and stats page need no special handling anywhere in the engine.
    Applet { appctx: u32 },
}

impl Endpoint {
    #[must_use]
    pub const fn is_none(self) -> bool {
        matches!(self, Endpoint::None)
    }

    /// The connection behind this endpoint, if it is connection-based. Applets have
    /// none, which is the point of the abstraction.
    #[must_use]
    pub const fn conn(self) -> Option<ConnId> {
        match self {
            Endpoint::MuxStream { conn, .. } => Some(conn),
            _ => None,
        }
    }
}

/// Flags on a stream endpoint descriptor. `HAProxy`'s `SE_FL_*`.
pub mod se_flags {
    /// The endpoint has been attached.
    pub const ATTACHED: u32 = 1 << 0;
    /// No more data will be produced by this endpoint.
    pub const EOS: u32 = 1 << 1;
    /// The endpoint reported an error.
    pub const ERROR: u32 = 1 << 2;
    /// End of input: the current message is complete.
    pub const EOI: u32 = 1 << 3;
    /// The endpoint will not accept more data.
    pub const SHUT_WANTED: u32 = 1 << 4;
    /// The endpoint has room for more outgoing data.
    pub const WANT_ROOM: u32 = 1 << 5;
    /// Receiving is currently blocked.
    pub const RCV_MORE: u32 = 1 << 6;
}

/// Wrapper for [`se_flags`] values.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct SeFlags(pub u32);

impl SeFlags {
    #[must_use]
    #[inline]
    pub const fn has(self, f: u32) -> bool {
        self.0 & f != 0
    }
    #[inline]
    pub const fn set(&mut self, f: u32) {
        self.0 |= f;
    }
    #[inline]
    pub const fn clear(&mut self, f: u32) {
        self.0 &= !f;
    }
}

/// Stream endpoint descriptor. `HAProxy`'s `struct sedesc`.
///
/// Owned by the endpoint side, referenced by the stream side. Its job is to survive a
/// mux stream being detached and reattached without the stream noticing.
#[derive(Clone, Debug)]
pub struct SeDesc {
    /// The mux stream or applet at this end.
    pub endpoint: Endpoint,
    /// Back-reference to the connector, if attached.
    pub sc: Option<u32>,
    pub flags: SeFlags,
    /// Bytes known still to arrive for the current message, if the framing says.
    pub known_input: Option<u64>,
    /// Bytes known still to be sent for the current message.
    pub known_output: Option<u64>,
}

impl Default for SeDesc {
    fn default() -> Self {
        Self::new()
    }
}

impl SeDesc {
    #[must_use]
    pub const fn new() -> Self {
        SeDesc {
            endpoint: Endpoint::None,
            sc: None,
            flags: SeFlags(0),
            known_input: None,
            known_output: None,
        }
    }
}

/// State of a stream connector. `HAProxy`'s `SC_ST_*`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ScState {
    /// Not connected, no intention to.
    Init,
    /// Waiting for a free server slot.
    Queue,
    /// A target has been chosen; the connection is not started.
    Assigned,
    /// Connecting.
    Connecting,
    /// Connected, still completing a handshake.
    Ready,
    /// Established and usable (both read and write open).
    Established,
    /// Read side is closed; write side remains open to drain data.
    ShutR,
    /// Write side is closed; read side remains open.
    ShutW,
    /// Closed cleanly.
    Closed,
    /// Failed.
    Error,
}

impl ScState {
    /// Whether this state allows reading data from the endpoint.
    #[must_use]
    #[inline]
    pub const fn can_read(self) -> bool {
        matches!(self, ScState::Ready | ScState::Established | ScState::ShutW)
    }

    /// Whether this state allows writing data to the endpoint.
    #[must_use]
    #[inline]
    pub const fn can_write(self) -> bool {
        matches!(self, ScState::Ready | ScState::Established | ScState::ShutR)
    }

    /// Whether the endpoint is fully closed or errored.
    #[must_use]
    #[inline]
    pub const fn is_closed(self) -> bool {
        matches!(self, ScState::Closed | ScState::Error)
    }
}

/// Flags on a stream connector. `HAProxy`'s `SC_FL_*`.
pub mod sc_flags {
    /// The application will not read more.
    pub const ABRT_DONE: u32 = 1 << 0;
    /// The application will not write more.
    pub const SHUT_DONE: u32 = 1 << 1;
    /// Waiting for room in the input buffer.
    pub const NEED_ROOM: u32 = 1 << 2;
    /// Do not read for now (e.g. waiting on the other side).
    pub const DONT_READ: u32 = 1 << 3;
    /// Read as much as possible.
    pub const MAY_FASTFWD: u32 = 1 << 4;
}

/// Wrapper for [`sc_flags`] values.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct ScFlags(pub u32);

impl ScFlags {
    #[must_use]
    #[inline]
    pub const fn has(self, f: u32) -> bool {
        self.0 & f != 0
    }
    #[inline]
    pub const fn set(&mut self, f: u32) {
        self.0 |= f;
    }
    #[inline]
    pub const fn clear(&mut self, f: u32) {
        self.0 &= !f;
    }
}

/// Stream connector: one of a stream's two ends. `HAProxy`'s `struct stconn`.
#[derive(Clone, Debug)]
pub struct StConn {
    pub state: ScState,
    pub flags: ScFlags,
    /// The endpoint descriptor this connector drives.
    pub sedesc: SeDesc,
    /// Bytes read from the endpoint over this connector's life.
    pub bytes_in: u64,
    /// Bytes written to the endpoint.
    pub bytes_out: u64,
    /// I/O inactivity timeout for this side.
    pub ioto: ibex_sched::Tick,
}

impl Default for StConn {
    fn default() -> Self {
        Self::new()
    }
}

impl StConn {
    #[must_use]
    pub const fn new() -> Self {
        StConn {
            state: ScState::Init,
            flags: ScFlags(0),
            sedesc: SeDesc::new(),
            bytes_in: 0,
            bytes_out: 0,
            ioto: ibex_sched::Tick::ETERNITY,
        }
    }

    /// True once the endpoint can carry data.
    #[must_use]
    pub const fn is_established(&self) -> bool {
        matches!(self.state, ScState::Established)
    }

    /// Attaches an endpoint.
    pub const fn attach(&mut self, ep: Endpoint) {
        self.sedesc.endpoint = ep;
        self.sedesc.flags.set(se_flags::ATTACHED);
    }

    /// Detaches the endpoint, leaving the connector reusable. This is what lets a mux
    /// hand a connection back to the pool while the stream lives on.
    pub const fn detach(&mut self) {
        self.sedesc.endpoint = Endpoint::None;
        self.sedesc.flags.clear(se_flags::ATTACHED);
    }
}
