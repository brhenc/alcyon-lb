// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/connection-t.h, stconn-t.h, session-t.h,
// stream-t.h and applet-t.h.
// Copyright (C) 2000-2026 Willy Tarreau <w@1wt.eu> and HAProxy contributors.
// See LICENSE in the repository root.

//! The layer model.
//!
//! Five layers, each a vtable, with the layers above and below never learning each
//! other's concrete types. See `design/001-layering.md`.
//!
//! ```text
//!   Protocol          L4     accept / connect / bind        tcp, unix
//!        |
//!   Transport         L5/6   byte transport, stackable      raw, tls
//!        |
//!   Mux               L7     framing: wire <-> HTX          h1, passthrough
//!        |
//!   SeDesc / StConn   --     the pivot                      "stream endpoint"
//!        |
//!   Stream            L7     the transaction
//!        |
//!   Session           --     connection-level context (1 session : N streams)
//! ```
//!
//! # The pivot
//!
//! A [`Stream`] never points at a [`Connection`]. It points at two [`StConn`]s, each
//! holding a [`SeDesc`], and a `SeDesc`'s endpoint is *either* a mux stream or an
//! applet. The stream cannot tell which and does not try.
//!
//! That indirection is why one code path serves H1, passthrough, the CLI, the stats
//! page and peers. In `HAProxy` every one of those is a `struct applet` behind this same
//! interface — build the pivot first and the runtime socket and stats page are ordinary
//! endpoints rather than special cases bolted onto the stream engine.
//!
//! # What Rust changes
//!
//! `HAProxy` stores `void *xprt_ctx`, `void *ctx` and `void *se`, recovering the type at
//! runtime from an `enum obj_type` first field — a hand-rolled tagged union checked by
//! convention. Here each vtable is a trait with an associated context type, and the
//! endpoint is a real enum, so `obj_type` disappears from every struct that carried it.

#![forbid(unsafe_code)]

pub mod conn;
pub mod endpoint;
pub mod mux;
pub mod proto;
pub mod session;
pub mod stream;
pub mod transport;

pub use conn::{ConnFlags, Connection, ConnId};
pub use endpoint::{Endpoint, SeDesc, SeFlags, StConn, ScFlags, ScState};
pub use mux::{Mux, MuxFlags, MuxOps, ShutMode};
pub use proto::{Protocol, ProtoKind};
pub use session::{Session, SessionId};
pub use stream::{Stream, StreamId};
pub use transport::{Transport, TransportKind, TlsInfo};
