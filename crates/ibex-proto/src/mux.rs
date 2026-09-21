// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/connection-t.h (struct mux_ops).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! L7: the mux layer. `HAProxy`'s `struct mux_ops`.
//!
//! A mux turns wire bytes into framed messages and back. It is selected at runtime —
//! by ALPN, or by `proto` on a `bind` line — which is what makes "swap the HTTP parser
//! without reconnecting" a property of the architecture rather than a feature.

use crate::conn::ConnId;
use crate::endpoint::SeDesc;
use std::io;

/// Capabilities a mux declares. `HAProxy`'s `MX_FL_*`.
pub mod mux_flags {
    /// Carries more than one stream per connection.
    pub const MULTIPLEXED: u32 = 1 << 0;
    /// Understands HTX framing rather than raw bytes.
    pub const HTX: u32 = 1 << 1;
    /// May reuse a connection for a different session.
    pub const REUSABLE: u32 = 1 << 2;
    /// Cannot receive more than one request per connection.
    pub const NO_KEEPALIVE: u32 = 1 << 3;
}

/// Wrapper for [`mux_flags`] values.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct MuxFlags(pub u32);

impl MuxFlags {
    #[must_use]
    #[inline]
    pub const fn has(self, f: u32) -> bool {
        self.0 & f != 0
    }
}

/// How to shut a stream down.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ShutMode {
    /// Orderly: finish in-flight data first.
    Normal,
    /// Immediate: discard and reset.
    Reset,
}

/// Static description of a mux implementation, used to select one at bind time.
#[derive(Clone, Debug)]
pub struct MuxOps {
    /// Name as it appears in config (`proto h1`) and in `show fd`.
    pub name: &'static str,
    /// ALPN token that selects this mux, if any.
    pub alpn: Option<&'static [u8]>,
    pub flags: MuxFlags,
}

/// Framing between the transport and the stream layer.
///
/// # On swapping muxes at runtime
///
/// `HAProxy` already selects a mux per connection at runtime, so "runtime-switchable
/// parser" describes the existing architecture rather than an addition to it. What is
/// *not* coherent is switching mid-connection: H1 framing is stateful — chunked
/// encoding, pipelining, `Connection:` semantics — so handing partially-consumed state
/// to a different implementation is either a no-op or a correctness hazard.
///
/// The defensible version, and the one Ibex targets: **two interchangeable H1 muxes**,
/// one strict and one lenient, selectable per bind, and differentially fuzzed against
/// each other. Any input on which they disagree about framing is a request-smuggling
/// candidate by construction.
pub trait Mux {
    /// Per-connection mux state.
    type Ctx;

    fn ops(&self) -> &'static MuxOps;

    /// Initialises mux state for a connection.
    ///
    /// # Errors
    /// Propagates setup failure.
    fn init(&self, conn: ConnId, is_server: bool) -> io::Result<Self::Ctx>;

    /// Consumes transport bytes and advances framing. Returns how many were consumed.
    ///
    /// # Errors
    /// Returns a protocol error if the input is malformed.
    fn parse(&self, ctx: &mut Self::Ctx, input: &[u8]) -> io::Result<usize>;

    /// Moves parsed data from the mux into the stream's buffer.
    ///
    /// # Errors
    /// Propagates mux-level failures.
    fn rcv_buf(&self, ctx: &mut Self::Ctx, sd: &mut SeDesc, out: &mut [u8]) -> io::Result<usize>;

    /// Takes data from the stream and frames it for the wire.
    ///
    /// # Errors
    /// Propagates mux-level failures.
    fn snd_buf(&self, ctx: &mut Self::Ctx, sd: &mut SeDesc, input: &[u8]) -> io::Result<usize>;

    /// Bytes the mux wants written to the transport.
    fn pending_output<'a>(&self, ctx: &'a Self::Ctx) -> &'a [u8];

    /// Reports how many output bytes were accepted by the transport.
    fn consume_output(&self, ctx: &mut Self::Ctx, n: usize);

    /// Shuts down one stream.
    fn shut(&self, ctx: &mut Self::Ctx, sd: &mut SeDesc, mode: ShutMode);

    /// Streams still available on this connection. Zero means it cannot be reused.
    fn avail_streams(&self, ctx: &Self::Ctx) -> u32;

    /// Streams currently in use.
    fn used_streams(&self, ctx: &Self::Ctx) -> u32;

    /// Whether the connection may go back to the idle pool.
    fn is_reusable(&self, ctx: &Self::Ctx) -> bool {
        self.ops().flags.has(mux_flags::REUSABLE) && self.used_streams(ctx) == 0
    }
}
