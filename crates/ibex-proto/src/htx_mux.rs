// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What the stream engine's bridge needs from a multiplexed client connection (T503,
//! `docs/design/h3-engine-2026-10-26.md` section 2.4): the h2 mux and the h3 mux both keep
//! their streams' decoded requests as HTX and take the responses as HTTP/1 heads and body
//! bytes, so one bridge (`h2_bridge`, generic over this in slice H3a) serves both, as
//! `HAProxy`'s `h2s` and `qcs` both feed a `struct stream`.

use crate::h2::HeadFacts;
use crate::htx::{Htx, RxHead};
use crate::mux_h2::H2ReqHead;

/// Why the data path resets a stream, in each protocol's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxReset {
    /// The response was cut short (the server left): h2 `CANCEL`, h3 `H3_REQUEST_CANCELLED`.
    Cancel,
    /// The response cannot be carried (a broken body, a tunnel): h2 `INTERNAL_ERROR`, h3
    /// `H3_INTERNAL_ERROR`.
    Internal,
    /// The stream will not be served (soft stop past GOAWAY): h2 `REFUSED_STREAM`, h3
    /// `H3_REQUEST_REJECTED`.
    Refused,
}

/// One stream of a multiplexed connection, as the bridge reads it.
pub trait HtxStream {
    /// The decoded request after its head: `Eoh`, then `Data`, `Trailer`, `Eot`, `Eom`.
    fn rx_htx(&self) -> &Htx;
    fn rx_htx_mut(&mut self) -> &mut Htx;
    /// A child serves it.
    fn dispatched(&self) -> bool;
    fn set_dispatched(&mut self);
    /// DATA bytes in [`Self::rx_htx`] the data path has not taken.
    fn rx_buffered(&self) -> usize;
    /// Reset by the client or by the mux.
    fn is_reset(&self) -> bool;
    /// The request head as its checked fields (T437, E1), until the data path takes it.
    fn req_head(&self) -> Option<&H2ReqHead>;
    fn take_req_fields(&mut self) -> Option<Box<H2ReqHead>>;
    /// CP2b: the request head as the HTX blocks the mux wrote into the memory the stream's
    /// buffer adopts, what the writer said of them and the length of the `scheme://authority`
    /// after them; `None` for a head kept as its fields.
    fn take_rx_head(&mut self) -> Option<(RxHead, HeadFacts, usize)>;
    /// No memory could be had for the head's blocks: the stream is answered 500 (S5).
    fn no_memory(&self) -> bool;
    /// A request `HAProxy` takes and answers 400.
    fn bad_request(&self) -> bool;
    /// The request's `content-length`, as the mux read it (one value, however the client
    /// wrote it): the forwarded head carries it once, in its canonical form (T509).
    fn content_length(&self) -> Option<u64> {
        None
    }
}

/// A multiplexed client connection, as the bridge drives it. Stream ids are the protocol's
/// (an h2 id fits in `u32`, an h3 one is a QUIC stream id).
pub trait HtxMux {
    type Stream: HtxStream;
    fn stream(&self, id: u64) -> Option<&Self::Stream>;
    fn stream_mut(&mut self, id: u64) -> Option<&mut Self::Stream>;
    /// The lowest stream with its whole head that no child serves yet, if one may be
    /// served now.
    fn next_dispatch(&self) -> Option<u64>;
    /// A head the data path took ([`HtxStream::take_req_fields`]), for the next streams.
    fn give_back_head(&mut self, head: Box<H2ReqHead>);
    /// A DATA block's bytes the data path wrote out whole, for the next DATA frame (h3: a
    /// pool, T512); an
    /// implementation without a pool drops it.
    const GIVE_DATA: fn(Vec<u8>);
    /// Sends an HTTP/1 response head (status line and headers, without the blank line or
    /// with it) as the protocol's HEADERS. False if it is not a response head.
    fn send_head(&mut self, id: u64, head: &[u8], end_stream: bool) -> bool;
    /// [`Self::send_head`] of a head already parsed (E2): its status and its fields, the
    /// names in lower case, in order.
    fn send_head_fields<'h, N: AsRef<[u8]>>(&mut self, id: u64, status: u16, fields: impl Iterator<Item = (N, &'h [u8])>, end_stream: bool) -> bool;
    /// Sends as much of `data` as [`Self::data_budget`] allows: the bytes taken.
    fn send_data(&mut self, id: u64, data: &[u8], end_stream: bool) -> usize;
    /// Sends the response's trailers, which end the stream.
    fn send_trailers(&mut self, id: u64, trailers: &[(&str, &str)]) -> bool;
    /// Sends an interim (1xx) response head. False if it is not one.
    fn send_interim(&mut self, id: u64, head: &[u8]) -> bool;
    /// The DATA bytes the stream may be given now (`usize::MAX` for one that is gone).
    fn data_budget(&self, id: u64) -> usize;
    /// The data path took `n` DATA bytes of the stream: room for more.
    fn rx_taken(&mut self, id: u64, n: usize);
    fn reset(&mut self, id: u64, why: MuxReset);
    fn is_reset(&self, id: u64) -> bool;
    /// Bytes wait for the transport.
    fn tx_pending(&self) -> bool;
    /// Protocol glitches counted on the connection (`tune.*.glitches-threshold`).
    fn glitches(&self) -> u64;
}
