// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/connection-t.h (struct connection).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The connection: a coordination struct holding one instance of each layer.

use crate::transport::TransportKind;
use std::net::SocketAddr;
use std::os::fd::RawFd;

/// Index into a thread's connection arena.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ConnId(pub u32);

impl ConnId {
    pub const NONE: ConnId = ConnId(u32::MAX);
    #[must_use]
    #[inline]
    pub const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }
}

/// Connection state bits. `HAProxy`'s `CO_FL_*`.
pub mod conn_flags {
    /// Outgoing connection (to a server) rather than incoming.
    pub const OUTGOING: u32 = 1 << 0;
    /// The socket is connected.
    pub const CONNECTED: u32 = 1 << 1;
    /// A transport handshake is still pending.
    pub const HANDSHAKE: u32 = 1 << 2;
    /// Read side closed.
    pub const READ_SHUT: u32 = 1 << 3;
    /// Write side closed.
    pub const WRITE_SHUT: u32 = 1 << 4;
    /// An error was reported.
    pub const ERROR: u32 = 1 << 5;
    /// Sitting in a server's idle pool.
    pub const IDLE: u32 = 1 << 6;
    /// Reserved to one session and not shareable.
    pub const PRIVATE: u32 = 1 << 7;
    /// Waiting for read readiness.
    pub const WANT_READ: u32 = 1 << 8;
    /// Waiting for write readiness.
    pub const WANT_WRITE: u32 = 1 << 9;
}

/// Wrapper for [`conn_flags`] values.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct ConnFlags(pub u32);

impl ConnFlags {
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

/// A connection.
///
/// # Why the layer instances are not stored here
///
/// `HAProxy` keeps three vtable pointers plus three `void *` contexts inside `struct
/// connection` (48 bytes of the 264-byte object), so a connection carries its own
/// dispatch table. The obvious Rust transliteration is `Box<dyn Transport>` plus
/// `Box<dyn Mux>`, which costs two heap allocations and two vtable indirections **per
/// connection** — at 60k connections, 120k allocations whose only purpose is to answer
/// a question with two or three possible answers.
///
/// Instead the traits stay open, and dispatch is closed at the composition root: the
/// runtime crate defines an enum over the transports and muxes it was built with and
/// implements the traits by delegation. The contract is extensible, the dispatch is a
/// `match`, and nothing is allocated. See `design/006-data-layout.md` §2 — the same
/// reasoning that made `WorkKind` an enum rather than a function pointer.
///
/// `transport` and `mux` here are therefore *selectors*, not owners.
#[derive(Clone, Debug)]
pub struct Connection {
    pub fd: RawFd,
    pub flags: ConnFlags,
    /// Which transport implementation this connection uses.
    pub transport: TransportKind,
    /// Which mux implementation, by index into the runtime's mux table.
    pub mux: u8,
    /// Owning session, if any. Backend connections in an idle pool have none.
    pub session: Option<u32>,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
    /// Task woken when this connection becomes readable or writable.
    pub io_task: ibex_sched::TaskRef,
    /// Error code, meaningful when [`conn_flags::ERROR`] is set.
    pub err: u16,
}

impl Connection {
    #[must_use]
    pub const fn new(fd: RawFd, transport: TransportKind, mux: u8) -> Self {
        Connection {
            fd,
            flags: ConnFlags(0),
            transport,
            mux,
            session: None,
            src: None,
            dst: None,
            io_task: ibex_sched::TaskRef::NONE,
            err: 0,
        }
    }

    #[must_use]
    pub const fn is_outgoing(&self) -> bool {
        self.flags.has(conn_flags::OUTGOING)
    }

    #[must_use]
    pub const fn handshake_pending(&self) -> bool {
        self.flags.has(conn_flags::HANDSHAKE)
    }

    #[must_use]
    pub const fn usable(&self) -> bool {
        self.flags.has(conn_flags::CONNECTED)
            && !self.flags.has(conn_flags::ERROR)
            && !self.flags.has(conn_flags::HANDSHAKE)
    }
}
