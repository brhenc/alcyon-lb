// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/3 connection state, sitting between the QUIC transport and HTX.
//!
//! `h3.rs` parses frames and `qpack.rs` decodes header blocks; neither knows about
//! connections, and nothing drove them. This is the piece that was missing: it tracks the
//! unidirectional streams HTTP/3 requires, answers a request stream, and encodes the
//! response.
//!
//! ### Scope
//!
//! QPACK is **static-table only**, in both directions. The connection advertises
//! `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, which
//! RFC 9204 permits and which obliges a compliant encoder — nghttp3 included — to use only
//! the 99-entry static table and literals. That removes the encoder/decoder stream state
//! machine entirely. The two streams still have to be *tolerated*, because the client opens
//! them regardless, so they are read and discarded.

use crate::h3::{parse_varint, H3Error};
use crate::qpack::StaticRef;

/// Stream type prefixes for unidirectional streams, RFC 9114 §6.2.
pub const STREAM_TYPE_CONTROL: u64 = 0x00;
pub const STREAM_TYPE_PUSH: u64 = 0x01;
pub const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
pub const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// Frame types we emit. RFC 9114 §7.2.
const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;
const FRAME_GOAWAY: u64 = 0x07;

/// Settings identifiers, RFC 9114 §7.2.4.1 and RFC 9204 §5.
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// Appends a QUIC variable-length integer (RFC 9000 §16).
///
/// The top two bits of the first byte select the width, so the usable range shrinks as the
/// value grows: 6 bits in one byte, 14 in two, 30 in four, 62 in eight.
pub fn encode_varint(out: &mut Vec<u8>, v: u64) {
    if v < 64 {
        out.push(v as u8);
    } else if v < 16_384 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1_073_741_824 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Appends a frame: type, length, payload.
pub fn encode_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    encode_varint(out, frame_type);
    encode_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// The SETTINGS frame this endpoint sends on its control stream.
///
/// Capacity and blocked-streams are zero on purpose: that is what makes the static-only
/// QPACK decoder legal rather than a shortcut.
#[must_use]
pub fn encode_settings() -> Vec<u8> {
    let mut frame = Vec::new();
    encode_settings_into(&mut frame);
    frame
}

/// Appends [`encode_settings`]'s frame to `out`.
pub fn encode_settings_into(out: &mut Vec<u8>) {
    let pairs = [(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0), (SETTINGS_QPACK_BLOCKED_STREAMS, 0), (SETTINGS_MAX_FIELD_SECTION_SIZE, 65_536)];
    let mut payload = [0u8; 48];
    let mut n = 0;
    for (id, value) in pairs {
        for v in [id, value] {
            let mut b = [0u8; 8];
            let len = varint_into(&mut b, v);
            payload[n..n + len].copy_from_slice(&b[..len]);
            n += len;
        }
    }
    encode_frame(out, FRAME_SETTINGS, &payload[..n]);
}

/// `v` as a QUIC variable-length integer in `buf`: its length.
fn varint_into(buf: &mut [u8; 8], v: u64) -> usize {
    let (len, tag) = if v < 64 {
        (1, 0u64)
    } else if v < 16_384 {
        (2, 0x40)
    } else if v < 1_073_741_824 {
        (4, 0x80)
    } else {
        (8, 0xc0)
    };
    let tagged = v | (tag << (8 * (len - 1)));
    buf[..len].copy_from_slice(&tagged.to_be_bytes()[8 - len..]);
    len
}

/// The bytes that open our control stream: the stream type, then SETTINGS.
#[must_use]
pub fn encode_control_stream_open() -> Vec<u8> {
    let mut out = Vec::new();
    encode_varint(&mut out, STREAM_TYPE_CONTROL);
    out.extend_from_slice(&encode_settings());
    out
}

/// Encodes a GOAWAY frame (RFC 9114 section 5.2): the server will process no request stream
/// at or above `stream_id`, so a client may retry those elsewhere.
#[must_use]
pub fn encode_goaway(stream_id: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_varint(&mut payload, stream_id);
    let mut frame = Vec::new();
    encode_frame(&mut frame, FRAME_GOAWAY, &payload);
    frame
}

/// Appends a prefixed integer (RFC 7541 §5.1, which QPACK reuses).
fn encode_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, mask: u8, mut value: usize) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(mask | (value as u8));
        return;
    }
    out.push(mask | (max as u8));
    value -= max;
    while value >= 128 {
        out.push(((value % 128) + 128) as u8);
        value /= 128;
    }
    out.push(value as u8);
}

/// Appends a string literal without Huffman coding.
///
/// Huffman would be smaller; leaving it off keeps the encoder to one page and makes the
/// bytes readable in a capture, which matters more while this path is being brought up.
fn encode_string(out: &mut Vec<u8>, s: &[u8], prefix_bits: u8, mask: u8) {
    encode_prefixed_int(out, prefix_bits, mask, s.len());
    out.extend_from_slice(s);
}

/// Encodes a header list as a QPACK field section using only the static table and literals.
///
/// The field section prefix is `Required Insert Count = 0, Delta Base = 0`, which says the
/// section references no dynamic entries and can therefore be decoded immediately.
#[must_use]
pub fn encode_field_section(headers: &[(String, String)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];
    for (name, value) in headers {
        put_field(&mut out, &name.to_ascii_lowercase(), value.as_bytes());
    }
    out
}

/// Appends one field line (`name` lowercase): a static reference with one search of the
/// table ([`crate::qpack::static_ref`]), else literals. Allocates nothing.
fn put_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    match crate::qpack::static_ref_octets(name, value) {
        // Indexed field line, static table: 1 1 index(6+)
        StaticRef::Full(idx) => encode_prefixed_int(out, 6, 0xc0, idx),
        StaticRef::Name(idx) => {
            // Literal with name reference, static table: 0 1 N=0 T=1 index(4+)
            encode_prefixed_int(out, 4, 0x50, idx);
            encode_string(out, value, 7, 0x00);
        }
        StaticRef::None => {
            // Literal with literal name: 0 0 1 N=0 H=0 len(3+)
            encode_string(out, name.as_bytes(), 3, 0x20);
            encode_string(out, value, 7, 0x00);
        }
    }
}

/// Encodes a complete HTTP/3 response: a HEADERS frame, then DATA if there is a body.
#[must_use]
pub fn encode_response(status: u16, extra_headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut headers = vec![(":status".to_string(), status.to_string())];
    headers.extend_from_slice(extra_headers);

    let field_section = encode_field_section(&headers);
    let mut out = Vec::new();
    encode_frame(&mut out, FRAME_HEADERS, &field_section);
    if !body.is_empty() {
        encode_frame(&mut out, FRAME_DATA, body);
    }
    out
}

/// What a unidirectional stream turned out to be, once its type prefix arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniStreamKind {
    Control,
    QpackEncoder,
    QpackDecoder,
    Push,
    /// An unknown type. RFC 9114 §6.2 requires these be tolerated, not treated as errors.
    Unknown(u64),
}

/// Reads the stream-type prefix from a unidirectional stream.
///
/// Returns the kind and how many bytes it consumed, or `None` if the prefix has not fully
/// arrived yet — a varint can be split across datagrams like anything else.
#[must_use]
pub fn read_uni_stream_type(buf: &[u8]) -> Option<(UniStreamKind, usize)> {
    let mut offset = 0usize;
    let ty = parse_varint(buf, &mut offset).ok()?;
    let kind = match ty {
        STREAM_TYPE_CONTROL => UniStreamKind::Control,
        STREAM_TYPE_PUSH => UniStreamKind::Push,
        STREAM_TYPE_QPACK_ENCODER => UniStreamKind::QpackEncoder,
        STREAM_TYPE_QPACK_DECODER => UniStreamKind::QpackDecoder,
        other => UniStreamKind::Unknown(other),
    };
    Some((kind, offset))
}

/// Extracts the HEADERS field section from a request stream's buffered bytes.
///
/// Returns `Ok(None)` when the frame has not fully arrived, which is the common case on the
/// first readable event. Unknown frame types are skipped rather than rejected, because that
/// is the extension mechanism and clients do send grease.
///
/// # Errors
/// Returns an error if a frame header is malformed, or announces a non-DATA frame longer
/// than `max_frame` ([`H3Error::ExcessiveLoad`]).
pub fn take_request_headers(buf: &[u8], max_frame: usize) -> Result<Option<Vec<u8>>, H3Error> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let start = offset;
        let Ok(frame_type) = parse_varint(buf, &mut offset) else {
            return Ok(None);
        };
        let Ok(len) = parse_varint(buf, &mut offset) else {
            // The length varint has not fully arrived. `start` is kept for readability at
            // the call site; nothing resumes from it, because the caller re-scans from zero
            // once more bytes land.
            let _ = start;
            return Ok(None);
        };
        // HAProxy (`h3.c` `h3_rcv_buf`): any frame but DATA longer than the stream's receive
        // buffer is H3_EXCESSIVE_LOAD, decided from the frame header, before a payload
        // byte is buffered.
        if frame_type != FRAME_DATA && len > max_frame as u64 {
            return Err(H3Error::ExcessiveLoad);
        }
        let len = usize::try_from(len).map_err(|_| H3Error::FrameError)?;
        if offset.saturating_add(len) > buf.len() {
            return Ok(None);
        }
        let payload = &buf[offset..offset + len];
        offset += len;
        if frame_type == FRAME_HEADERS {
            return Ok(Some(payload.to_vec()));
        }
    }
    Ok(None)
}


// ---------------------------------------------------------------------------------------
// The mux: `H3MuxContext` (HAProxy's qcc + h3c) and `H3StreamCtx` (qcs + h3s), T503
// ---------------------------------------------------------------------------------------
//
// Transport-agnostic, as `mux_h2` is: the owner (the QUIC connection's session, slice H3a)
// reads a stream from quinn only while [`H3MuxContext::rx_room`] says so, hands the bytes to
// [`H3MuxContext::recv`], writes what [`H3MuxContext::next_tx`] / [`H3MuxContext::tx_bytes`]
// hold back to quinn, and carries out the [`H3Signal`]s (`STOP_SENDING`, `RESET_STREAM`).
// A connection error is `Err` from `recv` and stays in [`H3MuxContext::error`]: the owner
// closes the connection with that code. Design: `docs/design/h3-engine-2026-10-26.md` §2-§6.

use crate::h2::{check_request_fields, check_trailer_fields};
use crate::hpack::DecodedFields;
use crate::htx::{HeaderField, Htx, HtxBlock};
use crate::htx_mux::{HtxMux, HtxStream, MuxReset};
use crate::mux_h2::{status_text, H2ReqHead, StreamMap};
use crate::qpack::{decode_decoder_stream, decode_encoder_stream, decode_qpack_static_into};
use ibex_alloc::{PoolBox, Poolable};
use std::collections::VecDeque;

/// `tune.bufsize` (16384) less 4: the largest frame other than DATA a stream takes
/// (`qcm_stream_rx_bufsz()`); one announced longer is `H3_EXCESSIVE_LOAD` from its header
/// (`h3.c:2050`).
pub const MAX_FRAME: usize = 16380;
/// The longest frame header: two 8-byte varints.
const FRAME_HEADER_MAX: usize = 16;
/// The raw bytes a stream holds before they are framed: one frame of [`MAX_FRAME`] and its
/// header. What the client sends beyond waits in quinn, under the stream's window.
pub const RX_CAP: usize = MAX_FRAME + FRAME_HEADER_MAX;
/// The DATA bytes a stream's HTX holds for its child: `htx_free_data_space` of an empty
/// `tune.bufsize` buffer (its 40-byte header, one 8-byte block), as HAProxy's `app_buf` and
/// h2's receive slot. A stream holding this many is not read until its child takes some.
pub const RX_DATA_ROOM: usize = 16384 - 40 - 8;
/// The response bytes a stream holds that quinn has not taken: past this the child's `rep`
/// waits, so a client that reads slowly stalls its own stream only.
pub const TX_ROOM: usize = 65536;
/// `tune.quic.fe.stream.max-concurrent`: the children an owner runs at once.
pub const MAX_CONCURRENT: u32 = 100;
/// The spare request heads a connection keeps (as h2's `SPARE_STREAMS`).
const SPARE_HEADS: usize = 4;

const FRAME_CANCEL_PUSH: u64 = 0x03;
const FRAME_PUSH_PROMISE: u64 = 0x05;
const FRAME_MAX_PUSH_ID: u64 = 0x0d;
const H3_NO_ERROR: u64 = 0x100;
const MESSAGE_ERROR: u64 = H3Error::MessageError as u64;
const REQUEST_REJECTED: u64 = H3Error::RequestRejected as u64;

/// Connection-specific fields: never in an HTTP/3 message (RFC 9114 section 4.2), dropped
/// from a response head.
const HOP_BY_HOP: [&str; 5] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

ibex_alloc::declare_pool!(
    /// `show pools` `qcs`: request streams (HAProxy's `qcs` + `h3s`), with their buffers.
    static QCS: Pool<H3StreamCtx> = ibex_alloc::PoolSpec::new("qcs");
);
ibex_alloc::declare_pool!(
    /// `show pools` `qcc`: HTTP/3 connections (HAProxy's `qcc` + `h3c`).
    static QCC: Pool<H3MuxContext> = ibex_alloc::PoolSpec::new("qcc");
);
ibex_alloc::declare_pool!(
    /// `show pools` `h3_data`: the bytes of a request's DATA blocks (`rx_htx`), given back
    /// once the data path wrote them out (T512: one allocation a request with a body).
    static H3_DATA: Pool<Vec<u8>> = ibex_alloc::PoolSpec::new("h3_data").max_item(2 * RX_DATA_ROOM).max_count(16);
);

/// A request stream's state, both directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H3StreamState {
    #[default]
    Open,
    /// The client's FIN has been read.
    HalfClosedRemote,
    /// Our FIN has been written.
    HalfClosedLocal,
    Closed,
    /// Reset, by the client or by the mux, with this code.
    Reset(u64),
}

/// Where a request stream's frame sequence is (`h3s->st_req`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ReqPhase {
    #[default]
    Before,
    Headers,
    Data,
    Trailers,
}

/// What the owner must do on the transport for the mux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Signal {
    /// `STOP_SENDING` (quinn `stop_sending`): read no more of this stream.
    StopSending { id: u64, code: u64 },
    /// `RESET_STREAM` (quinn `reset_stream`).
    ResetStream { id: u64, code: u64 },
}

/// A request stream (`docs/design/h3-engine-2026-10-26.md` §2.1). From the `qcs` pool.
#[derive(Debug, Default)]
pub struct H3StreamCtx {
    pub id: u64,
    pub state: H3StreamState,
    /// Bytes read from quinn not yet framed (at most [`RX_CAP`]).
    pub rx: Vec<u8>,
    /// The decoded request after its head: `Eoh`, `Data`, `Trailer`s, `Eot`, `Eom`.
    pub rx_htx: Htx,
    /// DATA bytes in `rx_htx` the child has not taken ([`HtxMux::rx_taken`]).
    pub rx_buffered: usize,
    pub dispatched: bool,
    /// Frames quinn has not taken, from `tx_head` on.
    pub tx: Vec<u8>,
    tx_head: usize,
    /// The response's last frame is in `tx`: the FIN follows its last byte.
    pub tx_fin: bool,
    pub fin_sent: bool,
    /// When the stream opened, in the owner's ticks: the `timeout http-request` base while
    /// its head is partial (`qcs->start`).
    pub head_start: u64,
    /// An interim response went out (`H3_SF_SENT_INTERIM`).
    pub interim_sent: bool,
    /// A request `HAProxy` takes and answers 400 ([`check_request_fields`]).
    pub bad_request: bool,
    /// The head as its checked fields, as h2's (T437, E1), until the data path takes it.
    pub req_head: Option<Box<H2ReqHead>>,
    pub content_length: Option<u64>,
    /// The body's length when the whole request came with its head (FIN in that read):
    /// HAProxy's h1 side then writes a `content-length`, not chunks.
    pub known_body: Option<u64>,
    /// DATA payload announced so far (`h3s->data_len`).
    pub data_len: u64,
    phase: ReqPhase,
    /// Payload bytes of the DATA frame in progress not yet in `rx_htx`.
    data_left: u64,
    /// The client's FIN has arrived: `rx` holds the end of the stream.
    fin: bool,
    /// `Eom` is in `rx_htx`.
    eom: bool,
}

impl H3StreamCtx {
    fn tx_pending(&self) -> &[u8] {
        &self.tx[self.tx_head..]
    }

    fn is_live(&self) -> bool {
        !matches!(self.state, H3StreamState::Reset(_))
    }
}

impl Poolable for H3StreamCtx {
    fn footprint(&self) -> usize {
        std::mem::size_of::<Self>() + self.rx.capacity() + self.tx.capacity() + self.req_head.as_ref().map_or(0, |h| h.capacity())
    }

    fn reset(&mut self, wipe: bool) {
        let (mut rx, mut tx, mut htx, mut head) =
            (std::mem::take(&mut self.rx), std::mem::take(&mut self.tx), std::mem::take(&mut self.rx_htx), self.req_head.take());
        if wipe {
            ibex_alloc::wipe_bytes(&mut rx);
            ibex_alloc::wipe_bytes(&mut tx);
            if let Some(h) = head.as_mut() {
                h.wipe();
            }
        }
        rx.clear();
        tx.clear();
        htx.clear();
        if let Some(h) = head.as_mut() {
            h.clear();
        }
        *self = Self { rx, tx, rx_htx: htx, req_head: head, ..Self::default() };
    }

    fn try_new() -> Option<Self> {
        Some(Self::default())
    }
}

/// A unidirectional stream the client opened.
#[derive(Debug, Default)]
struct UniStream {
    /// `None` until its type has arrived.
    kind: Option<UniStreamKind>,
    rx: Vec<u8>,
}

/// An HTTP/3 connection (`docs/design/h3-engine-2026-10-26.md` §2.1). From the `qcc` pool.
#[derive(Debug)]
pub struct H3MuxContext {
    pub streams: StreamMap<PoolBox<H3StreamCtx>, u64>,
    uni: StreamMap<UniStream, u64>,
    /// Our control stream, once the owner has opened it ([`Self::open_control`]).
    pub control_out: Option<u64>,
    control_tx: Vec<u8>,
    control_head: usize,
    pub control_in: Option<u64>,
    pub qpack_enc_in: Option<u64>,
    pub qpack_dec_in: Option<u64>,
    pub settings_sent: bool,
    pub settings_recv: bool,
    pub goaway_sent: Option<u64>,
    pub goaway_recv: Option<u64>,
    /// The request stream after the last one opened: the id a GOAWAY carries.
    pub next_request: u64,
    pub max_concurrent: u32,
    /// Protocol errors counted (`qcc_report_glitch`).
    pub glitch_count: u32,
    pub last_client_stream_id: Option<u64>,
    /// The connection error: the owner closes the connection with it.
    pub error: Option<H3Error>,
    /// The frontend's `option accept-unsafe-violations-in-http-request` (`:path` check).
    pub relaxed_path: bool,
    signals: VecDeque<H3Signal>,
    decoded: DecodedFields,
    // Boxed: the bridge takes a head as the `Box` h2's `H2Dispatch` carries, and gives it back.
    #[allow(clippy::vec_box)]
    spare_heads: Vec<Box<H2ReqHead>>,
    /// A field section being encoded, kept for the next.
    scratch: Vec<u8>,
    /// A header name lowercased, kept for the next.
    lower: String,
    /// The stream [`Self::next_tx`] gave last (round robin).
    tx_last: Option<u64>,
}

impl Default for H3MuxContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Poolable for H3MuxContext {
    fn footprint(&self) -> usize {
        std::mem::size_of::<Self>() + self.control_tx.capacity() + self.scratch.capacity() + self.lower.capacity()
    }

    fn reset(&mut self, _wipe: bool) {
        // The streams go back to `qcs` as they drop; the rest is per connection.
        *self = Self::new();
    }

    fn try_new() -> Option<Self> {
        Some(Self::new())
    }
}

/// A client unidirectional stream id (RFC 9000 section 2.1: bit 1 set).
const fn is_uni(id: u64) -> bool {
    id & 0x2 != 0
}

impl H3MuxContext {
    #[must_use]
    pub fn new() -> Self {
        Self {
            streams: StreamMap::new(),
            uni: StreamMap::new(),
            control_out: None,
            control_tx: Vec::new(),
            control_head: 0,
            control_in: None,
            qpack_enc_in: None,
            qpack_dec_in: None,
            settings_sent: false,
            settings_recv: false,
            goaway_sent: None,
            goaway_recv: None,
            next_request: 0,
            max_concurrent: MAX_CONCURRENT,
            glitch_count: 0,
            last_client_stream_id: None,
            error: None,
            relaxed_path: false,
            signals: VecDeque::new(),
            decoded: DecodedFields::default(),
            spare_heads: Vec::new(),
            scratch: Vec::new(),
            lower: String::new(),
            tx_last: None,
        }
    }

    /// A connection from the `qcc` pool; `None` when memory is short.
    #[must_use]
    pub fn take() -> Option<PoolBox<Self>> {
        QCC.take()
    }

    /// The owner opened our control stream `id`: its type and SETTINGS go out first.
    pub fn open_control(&mut self, id: u64) {
        self.control_out = Some(id);
        encode_varint(&mut self.control_tx, STREAM_TYPE_CONTROL);
        encode_settings_into(&mut self.control_tx);
        self.settings_sent = true;
    }

    /// How many bytes of stream `id` the owner may read from quinn now: none while the
    /// stream's HTX holds a buffer of DATA its child has not taken (the client's window
    /// holds the rest back, §2.3).
    #[must_use]
    pub fn rx_room(&self, id: u64) -> usize {
        if is_uni(id) {
            return match self.uni.get(&id) {
                Some(u) if !matches!(u.kind, Some(UniStreamKind::Unknown(_))) => RX_CAP.saturating_sub(u.rx.len()),
                _ => RX_CAP,
            };
        }
        match self.streams.get(&id) {
            Some(st) if st.rx_buffered >= RX_DATA_ROOM => 0,
            Some(st) => RX_CAP.saturating_sub(st.rx.len()),
            None => RX_CAP,
        }
    }

    /// Bytes of stream `id` read from quinn (`fin`: the stream ends with them), at the
    /// owner's tick `now`.
    ///
    /// # Errors
    /// A connection error (also kept in [`Self::error`]): the owner closes the connection
    /// with its code. Stream errors are [`H3Signal`]s, not errors.
    pub fn recv(&mut self, id: u64, data: &[u8], fin: bool, now: u64) -> Result<(), H3Error> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let r = if is_uni(id) { self.recv_uni(id, data, fin) } else { self.recv_req(id, data, fin, now) };
        self.conn_result(r)
    }

    fn conn_result(&mut self, r: Result<(), H3Error>) -> Result<(), H3Error> {
        if let Err(e) = r {
            self.error = Some(e);
            self.glitch_count += 1;
        }
        r
    }

    fn recv_req(&mut self, id: u64, data: &[u8], fin: bool, now: u64) -> Result<(), H3Error> {
        if !self.streams.contains_key(&id) {
            if id < self.next_request {
                // A stream that is over: what still comes is dropped.
                return Ok(());
            }
            // A STREAM frame opens every lower stream too (RFC 9000 section 3.2;
            // `qcc_init_stream_remote`).
            let mut open = self.next_request;
            self.next_request = id + 4;
            self.last_client_stream_id = Some(id);
            while open <= id {
                if self.goaway_sent.is_some_and(|g| open >= g) {
                    self.stream_signals(open, REQUEST_REJECTED);
                } else {
                    let mut st = QCS.take().ok_or(H3Error::InternalError)?;
                    st.id = open;
                    st.head_start = now;
                    self.streams.insert(open, st);
                }
                open += 4;
            }
        }
        let Some(st) = self.streams.get_mut(&id).filter(|st| st.is_live() && !st.fin) else {
            return Ok(());
        };
        st.rx.extend_from_slice(data);
        st.fin = fin;
        self.demux_req(id)
    }

    /// Frames what stream `id` holds.
    fn demux_req(&mut self, id: u64) -> Result<(), H3Error> {
        let Self { streams, decoded, spare_heads, relaxed_path, .. } = self;
        let Some(st) = streams.get_mut(&id) else { return Ok(()) };
        let mut shared = Shared { decoded, spare_heads, relaxed: *relaxed_path };
        if let Some(code) = demux(st, &mut shared)? {
            if code != REQUEST_REJECTED {
                self.glitch_count += 1;
            }
            self.stream_error(id, code);
        }
        Ok(())
    }

    /// Stream `id` is in error: read no more of it, reset it (`qcc_abort_stream_read` +
    /// `qcc_reset_stream`).
    fn stream_error(&mut self, id: u64, code: u64) {
        self.stream_signals(id, code);
        self.stream_gone(id, code);
    }

    fn stream_signals(&mut self, id: u64, code: u64) {
        self.signals.push_back(H3Signal::StopSending { id, code });
        self.signals.push_back(H3Signal::ResetStream { id, code });
    }

    /// Stream `id` is reset: one no child serves is let go, as h2's; the one being served
    /// is marked for its child and its response dropped.
    fn stream_gone(&mut self, id: u64, code: u64) {
        match self.streams.get_mut(&id) {
            Some(st) if st.dispatched => {
                st.state = H3StreamState::Reset(code);
                st.tx.clear();
                st.tx_head = 0;
                st.tx_fin = false;
            }
            Some(_) => {
                self.streams.remove(&id);
            }
            None => {}
        }
    }

    fn recv_uni(&mut self, id: u64, data: &[u8], fin: bool) -> Result<(), H3Error> {
        let u = self.uni.entry(id).or_insert_with(UniStream::default);
        if let Some(UniStreamKind::Unknown(_)) = u.kind {
            return Ok(());
        }
        u.rx.extend_from_slice(data);
        if u.kind.is_none() {
            let Some((kind, n)) = read_uni_stream_type(&u.rx) else { return Ok(()) };
            u.rx.drain(..n);
            let slot = match kind {
                UniStreamKind::Control => &mut self.control_in,
                UniStreamKind::QpackEncoder => &mut self.qpack_enc_in,
                UniStreamKind::QpackDecoder => &mut self.qpack_dec_in,
                // A client may not open a push stream (h3.c:232).
                UniStreamKind::Push => return Err(H3Error::StreamCreationError),
                UniStreamKind::Unknown(_) => {
                    // Read no more of it (h3.c:286, `H3_ERR_NO_ERROR`); what still comes is
                    // read and dropped.
                    u.kind = Some(kind);
                    u.rx = Vec::new();
                    self.signals.push_back(H3Signal::StopSending { id, code: H3_NO_ERROR });
                    return Ok(());
                }
            };
            if slot.is_some() {
                return Err(H3Error::StreamCreationError);
            }
            *slot = Some(id);
            u.kind = Some(kind);
        }
        // Closing a critical stream is a connection error (RFC 9114 section 6.2.1, RFC 9204
        // section 4.2).
        if fin {
            return Err(H3Error::ClosedCriticalStream);
        }
        let used = match u.kind {
            Some(UniStreamKind::QpackEncoder) => decode_encoder_stream(&u.rx)?,
            Some(UniStreamKind::QpackDecoder) => decode_decoder_stream(&u.rx)?,
            _ => control_frames(&u.rx, &mut self.settings_recv, &mut self.goaway_recv)?,
        };
        u.rx.drain(..used);
        Ok(())
    }

    /// The client reset stream `id` (`RESET_STREAM`).
    ///
    /// # Errors
    /// `H3_CLOSED_CRITICAL_STREAM` for its control or a QPACK stream.
    pub fn on_reset(&mut self, id: u64, code: u64) -> Result<(), H3Error> {
        if is_uni(id) {
            let critical = [self.control_in, self.qpack_enc_in, self.qpack_dec_in].contains(&Some(id));
            let r = if critical { Err(H3Error::ClosedCriticalStream) } else { Ok(()) };
            return self.conn_result(r);
        }
        self.stream_gone(id, code);
        Ok(())
    }

    /// The client wants no more of stream `id` (`STOP_SENDING`): its response is dropped
    /// and the stream reset with the client's code (`qcc_recv_stop_sending`).
    ///
    /// # Errors
    /// `H3_CLOSED_CRITICAL_STREAM` for our control stream.
    pub fn on_stop_sending(&mut self, id: u64, code: u64) -> Result<(), H3Error> {
        if Some(id) == self.control_out {
            return self.conn_result(Err(H3Error::ClosedCriticalStream));
        }
        if self.streams.contains_key(&id) {
            self.signals.push_back(H3Signal::ResetStream { id, code });
            self.stream_gone(id, code);
        }
        Ok(())
    }

    /// The next thing the owner must do on the transport.
    pub fn take_signal(&mut self) -> Option<H3Signal> {
        self.signals.pop_front()
    }

    /// The start of the oldest stream without its whole head, if one is: the owner's
    /// `timeout http-request` runs from it (`qcc->opening_list`, design §5).
    #[must_use]
    pub fn head_partial(&self) -> Option<u64> {
        self.streams.values().filter(|st| st.phase == ReqPhase::Before).map(|st| st.head_start).min()
    }

    /// Announces the end of the connection: GOAWAY with [`Self::next_request`] on our
    /// control stream, once. A stream opened past it is rejected (`H3_REQUEST_REJECTED`),
    /// so the client retries it elsewhere.
    pub fn send_goaway(&mut self) {
        if self.goaway_sent.is_some() {
            return;
        }
        let id = self.next_request;
        encode_varint(&mut self.control_tx, FRAME_GOAWAY);
        let mut len = [0u8; 8];
        let n = varint_into(&mut len, id);
        encode_varint(&mut self.control_tx, n as u64);
        self.control_tx.extend_from_slice(&len[..n]);
        self.goaway_sent = Some(id);
    }

    /// The next stream with bytes or a FIN for quinn: our control stream first, then the
    /// request streams round robin.
    pub fn next_tx(&mut self) -> Option<u64> {
        if self.control_head < self.control_tx.len() {
            return self.control_out;
        }
        let wants = |st: &&PoolBox<H3StreamCtx>| !st.tx_pending().is_empty() || st.tx_fin && !st.fin_sent;
        let after = self.tx_last.map_or(0, |l| l + 1);
        let pick = self.streams.values().filter(wants).find(|st| st.id >= after).or_else(|| self.streams.values().find(wants)).map(|st| st.id);
        self.tx_last = pick.or(self.tx_last);
        pick
    }

    /// The bytes of stream `id` quinn has not taken.
    #[must_use]
    pub fn tx_bytes(&self, id: u64) -> &[u8] {
        if Some(id) == self.control_out {
            return &self.control_tx[self.control_head..];
        }
        self.streams.get(&id).map_or(&[], |st| st.tx_pending())
    }

    /// Quinn took `n` bytes of stream `id`.
    pub fn tx_written(&mut self, id: u64, n: usize) {
        if Some(id) == self.control_out {
            self.control_head = (self.control_head + n).min(self.control_tx.len());
            if self.control_head == self.control_tx.len() {
                self.control_tx.clear();
                self.control_head = 0;
            }
        } else if let Some(st) = self.streams.get_mut(&id) {
            st.tx_head = (st.tx_head + n).min(st.tx.len());
            if st.tx_head == st.tx.len() {
                st.tx.clear();
                st.tx_head = 0;
            }
        }
    }

    /// The owner must finish stream `id` (quinn `finish`): its response is all out.
    #[must_use]
    pub fn fin_due(&self, id: u64) -> bool {
        self.streams.get(&id).is_some_and(|st| st.tx_fin && !st.fin_sent && st.tx_pending().is_empty())
    }

    /// The owner finished stream `id`.
    pub fn fin_written(&mut self, id: u64) {
        if let Some(st) = self.streams.get_mut(&id) {
            st.fin_sent = true;
            st.state = match st.state {
                H3StreamState::HalfClosedRemote => H3StreamState::Closed,
                H3StreamState::Open => H3StreamState::HalfClosedLocal,
                s => s,
            };
        }
    }

    /// Stream `id` is over (its child ended): its context goes back to `qcs`.
    pub fn release(&mut self, id: u64) {
        self.streams.remove(&id);
    }

    /// Demuxes what waits in stream `id` after its child took some DATA; a connection
    /// error is kept in [`Self::error`].
    fn resume(&mut self, id: u64) {
        if self.error.is_none() {
            let r = self.demux_req(id);
            let _ = self.conn_result(r);
        }
    }

    /// The response head (`status`, `headers`) of stream `id` as a HEADERS frame.
    fn put_head<'h>(&mut self, id: u64, status: Option<u16>, headers: impl Iterator<Item = (&'h str, &'h [u8])>) {
        self.put_head_of(id, status, headers, false);
    }

    /// [`Self::put_head`]; `lowered`: the names are in lower case already (E2).
    fn put_head_of<'h>(&mut self, id: u64, status: Option<u16>, headers: impl Iterator<Item = (&'h str, &'h [u8])>, lowered: bool) {
        let Self { streams, scratch, lower, .. } = self;
        let Some(st) = streams.get_mut(&id) else { return };
        scratch.clear();
        scratch.extend_from_slice(&[0x00, 0x00]);
        if let Some(status) = status {
            let mut digits = [0u8; 5];
            put_field(scratch, ":status", status_text(status, &mut digits).as_bytes());
        }
        for (name, value) in headers {
            let name = if lowered {
                name
            } else {
                lower.clear();
                lower.push_str(name);
                lower.make_ascii_lowercase();
                lower.as_str()
            };
            if HOP_BY_HOP.contains(&name) || name.starts_with(':') {
                continue;
            }
            put_field(scratch, name, value);
        }
        encode_varint(&mut st.tx, FRAME_HEADERS);
        encode_varint(&mut st.tx, scratch.len() as u64);
        st.tx.extend_from_slice(scratch);
    }

    fn live(&self, id: u64) -> bool {
        self.streams.get(&id).is_some_and(|st| st.is_live())
    }
}

/// What the demux of a stream borrows from its connection.
struct Shared<'a> {
    decoded: &'a mut DecodedFields,
    #[allow(clippy::vec_box)]
    spare_heads: &'a mut Vec<Box<H2ReqHead>>,
    relaxed: bool,
}

/// Frames what `st.rx` holds into `st.rx_htx`, as `h3_rcv_buf`: `Ok(Some(code))` is a
/// stream error, `Err` a connection error.
fn demux(st: &mut H3StreamCtx, sh: &mut Shared) -> Result<Option<u64>, H3Error> {
    let rx = std::mem::take(&mut st.rx);
    let r = demux_frames(st, &rx, sh);
    st.rx = rx;
    let used = match r {
        Ok((used, None)) => used,
        Ok((_, err)) => return Ok(err),
        Err(e) => return Err(e),
    };
    st.rx.drain(..used);
    if !st.fin || st.eom {
        return Ok(None);
    }
    let rem = st.rx.len() as u64;
    if st.data_left > rem || (st.data_left == 0 && rem > 0) {
        // A frame cut by the FIN (RFC 9114 section 7.1, h3.c:2029).
        return Err(H3Error::FrameError);
    }
    if st.data_left > 0 {
        // The rest of the DATA is here, waiting for room.
        return Ok(None);
    }
    if st.phase == ReqPhase::Before || st.content_length.is_some_and(|cl| cl != st.data_len) {
        return Ok(Some(MESSAGE_ERROR));
    }
    end_of_message(st);
    Ok(None)
}

fn end_of_message(st: &mut H3StreamCtx) {
    st.rx_htx.push(HtxBlock::Eom);
    st.eom = true;
    st.state = H3StreamState::HalfClosedRemote;
}

/// The frames of `rx`: how many bytes were used, and a stream error.
fn demux_frames(st: &mut H3StreamCtx, rx: &[u8], sh: &mut Shared) -> Result<(usize, Option<u64>), H3Error> {
    let mut used = 0usize;
    loop {
        if st.data_left > 0 {
            let room = RX_DATA_ROOM.saturating_sub(st.rx_buffered);
            let n = usize::try_from(st.data_left).unwrap_or(usize::MAX).min(rx.len() - used).min(room);
            if n == 0 {
                return Ok((used, None));
            }
            // Not onto a block the bridge took whole and emptied: its cursor is past it (T509).
            if let Some(HtxBlock::Data(d)) = st.rx_htx.blocks_mut().last_mut().filter(|b| matches!(b, HtxBlock::Data(d) if !d.is_empty())) {
                d.extend_from_slice(&rx[used..used + n]);
            } else {
                let mut d = H3_DATA.take_raw(|| Some(Vec::new())).unwrap_or_default();
                d.extend_from_slice(&rx[used..used + n]);
                st.rx_htx.push(HtxBlock::Data(d));
            }
            st.rx_buffered += n;
            st.data_left -= n as u64;
            used += n;
            continue;
        }
        let rest = &rx[used..];
        let mut off = 0;
        let Ok(ty) = parse_varint(rest, &mut off) else { return Ok((used, None)) };
        let Ok(len) = parse_varint(rest, &mut off) else { return Ok((used, None)) };
        check_request_frame(st.phase, ty)?;
        if ty == FRAME_DATA {
            st.data_len += len;
            // Checked against the length when the frame's header arrives, before any of
            // its payload goes on (h3.c:2003).
            if st.content_length.is_some_and(|cl| st.data_len > cl) {
                return Ok((used, Some(MESSAGE_ERROR)));
            }
            used += off;
            st.data_left = len;
            st.phase = ReqPhase::Data;
            continue;
        }
        if len > MAX_FRAME as u64 {
            return Err(H3Error::ExcessiveLoad);
        }
        let len = len as usize;
        if rest.len() - off < len {
            return Ok((used, None));
        }
        let payload = &rest[off..off + len];
        used += off + len;
        let last = st.fin && used == rx.len();
        let err = match (ty, st.phase) {
            (FRAME_HEADERS, ReqPhase::Before) => on_headers(st, payload, &rx[used..], last, sh)?,
            (FRAME_HEADERS, _) => on_trailers(st, payload, last, sh)?,
            // Unknown and reserved frames are skipped (RFC 9114 section 9); one that ends a
            // stream without a head leaves a malformed request (h3.c:2215).
            _ => (last && st.phase == ReqPhase::Before).then_some(MESSAGE_ERROR),
        };
        if err.is_some() {
            return Ok((used, err));
        }
    }
}

/// `h3_check_frame_valid` for a request stream.
fn check_request_frame(phase: ReqPhase, ty: u64) -> Result<(), H3Error> {
    let ok = match ty {
        FRAME_DATA => matches!(phase, ReqPhase::Headers | ReqPhase::Data),
        FRAME_HEADERS => phase != ReqPhase::Trailers,
        FRAME_CANCEL_PUSH | FRAME_SETTINGS | FRAME_PUSH_PROMISE | FRAME_GOAWAY | FRAME_MAX_PUSH_ID => false,
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(H3Error::FrameUnexpected)
    }
}

/// The request's HEADERS (`h3_req_headers_to_htx`). `rest`: what follows in the stream.
fn on_headers(st: &mut H3StreamCtx, payload: &[u8], rest: &[u8], last: bool, sh: &mut Shared) -> Result<Option<u64>, H3Error> {
    decode_qpack_static_into(payload, sh.decoded)?;
    let f = &*sh.decoded;
    // The pseudo-headers first, as HAProxy's loop: one it does not know (`:protocol`
    // included: no extended CONNECT, RFC 9220 is out) is a message error; then CONNECT is
    // rejected (h3.c:938; measured: RESET_STREAM 0x10b, 0x10e with `:protocol`).
    let (mut method, mut scheme, mut path, mut authority) = (None, false, false, false);
    for (n, v) in f.iter() {
        match n {
            b":method" => method = Some(v),
            b":scheme" => scheme = true,
            b":path" => path = true,
            b":authority" | b"host" => authority = true,
            _ if n.starts_with(b":") => return Ok(Some(MESSAGE_ERROR)),
            _ => {}
        }
    }
    if method == Some(b"CONNECT") {
        return Ok(Some(REQUEST_REJECTED));
    }
    // Neither `:authority` nor `host`: measured on 3.5-dev7 (T509), RESET_STREAM 0x10e and
    // nothing to the server.
    if method.is_none() || !scheme || !path || !authority {
        return Ok(Some(MESSAGE_ERROR));
    }
    let Ok(bad) = check_request_fields(f.iter(), sh.relaxed) else { return Ok(Some(MESSAGE_ERROR)) };
    // What h2 takes and answers 400 (a method or scheme that is not a token) is a message
    // error over h3: measured on 3.5-dev7 (T509). A `:path` with a blank under
    // `option accept-unsafe-violations-in-http-request` keeps h2's 400 (not measured).
    if bad && !sh.relaxed {
        return Ok(Some(MESSAGE_ERROR));
    }
    let mut cl = None;
    for (_, v) in f.iter().filter(|(n, _)| *n == b"content-length") {
        match std::str::from_utf8(v).ok().and_then(crate::h2::content_length_value) {
            Some(x) if cl.is_none_or(|c| c == x) => cl = Some(x),
            _ => return Ok(Some(MESSAGE_ERROR)),
        }
    }
    // A length the stream cannot have: it ends here (h3.c:1099).
    if last && cl.is_some_and(|c| c != 0) {
        return Ok(Some(MESSAGE_ERROR));
    }
    let mut head = st.req_head.take().or_else(|| sh.spare_heads.pop()).unwrap_or_default();
    if head.write(f).is_err() {
        if sh.spare_heads.len() < SPARE_HEADS {
            sh.spare_heads.push(head);
        }
        return Ok(Some(MESSAGE_ERROR));
    }
    st.req_head = Some(head);
    st.bad_request = bad;
    st.content_length = cl;
    st.rx_htx.push(HtxBlock::Eoh);
    st.phase = ReqPhase::Headers;
    if last {
        st.known_body = Some(0);
        end_of_message(st);
    } else if st.fin {
        st.known_body = complete_body_len(rest);
    }
    Ok(None)
}

/// A second HEADERS: the request's trailers (`h3_trailers_to_htx`).
fn on_trailers(st: &mut H3StreamCtx, payload: &[u8], last: bool, sh: &mut Shared) -> Result<Option<u64>, H3Error> {
    decode_qpack_static_into(payload, sh.decoded)?;
    // A name or value that is not UTF-8 reads as a NUL here, and is refused (T454).
    if check_trailer_fields(sh.decoded.iter_text()).is_err() {
        return Ok(Some(MESSAGE_ERROR));
    }
    for (name, value) in sh.decoded.iter_text() {
        st.rx_htx.push(HtxBlock::Trailer(HeaderField { name: name.to_string(), value: value.to_string() }));
    }
    st.rx_htx.push(HtxBlock::Eot);
    st.phase = ReqPhase::Trailers;
    if last {
        end_of_message(st);
    }
    Ok(None)
}


/// The DATA payload `buf` holds if it is complete frames only.
fn complete_body_len(mut buf: &[u8]) -> Option<u64> {
    let mut n = 0u64;
    while !buf.is_empty() {
        let mut off = 0;
        let ty = parse_varint(buf, &mut off).ok()?;
        let len = usize::try_from(parse_varint(buf, &mut off).ok()?).ok()?;
        let end = off.checked_add(len).filter(|&e| e <= buf.len())?;
        if ty == FRAME_DATA {
            n += len as u64;
        }
        buf = &buf[end..];
    }
    Some(n)
}

/// The client's control stream (`h3_rcv_buf` on `H3S_T_CTRL`): the bytes its complete
/// frames took.
fn control_frames(rx: &[u8], settings_recv: &mut bool, goaway_recv: &mut Option<u64>) -> Result<usize, H3Error> {
    let mut used = 0;
    loop {
        let rest = &rx[used..];
        let mut off = 0;
        let Ok(ty) = parse_varint(rest, &mut off) else { return Ok(used) };
        let Ok(len) = parse_varint(rest, &mut off) else { return Ok(used) };
        // `h3_check_frame_valid` for the control stream.
        match ty {
            FRAME_DATA | FRAME_HEADERS | FRAME_PUSH_PROMISE => return Err(H3Error::FrameUnexpected),
            FRAME_SETTINGS if *settings_recv => return Err(H3Error::FrameUnexpected),
            FRAME_SETTINGS => {}
            _ if !*settings_recv => return Err(H3Error::MissingSettings),
            _ => {}
        }
        if len > MAX_FRAME as u64 {
            return Err(H3Error::ExcessiveLoad);
        }
        let len = len as usize;
        if rest.len() - off < len {
            return Ok(used);
        }
        let payload = &rest[off..off + len];
        used += off + len;
        match ty {
            FRAME_SETTINGS => {
                parse_settings(payload)?;
                *settings_recv = true;
            }
            FRAME_GOAWAY => {
                let mut o = 0;
                let id = parse_varint(payload, &mut o).map_err(|_| H3Error::FrameError)?;
                // A GOAWAY may only lower the id (h3.c:1866).
                if goaway_recv.is_some_and(|g| id > g) {
                    return Err(H3Error::IdError);
                }
                *goaway_recv = Some(id);
            }
            // From a client, a CANCEL_PUSH names a push that never was (h3.c:2140).
            FRAME_CANCEL_PUSH | FRAME_MAX_PUSH_ID if len == 0 => return Err(H3Error::FrameError),
            FRAME_CANCEL_PUSH => return Err(H3Error::IdError),
            _ => {}
        }
    }
}

/// A SETTINGS payload (`h3_parse_settings_frm`): a truncated pair is `H3_FRAME_ERROR`; a
/// repeated id below 8 (HAProxy's mask is `sizeof(long)` bits wide in name only) or an
/// HTTP/2 id `H3_SETTINGS_ERROR`. The values are not used: the static encoder needs none.
fn parse_settings(payload: &[u8]) -> Result<(), H3Error> {
    let mut seen = 0u8;
    let mut o = 0;
    while o < payload.len() {
        let id = parse_varint(payload, &mut o).map_err(|_| H3Error::FrameError)?;
        parse_varint(payload, &mut o).map_err(|_| H3Error::FrameError)?;
        if id < 8 {
            if seen & (1 << id) != 0 {
                return Err(H3Error::SettingsError);
            }
            seen |= 1 << id;
        }
        if matches!(id, 0x0 | 0x2 | 0x3 | 0x4 | 0x5) {
            return Err(H3Error::SettingsError);
        }
    }
    Ok(())
}

impl HtxStream for H3StreamCtx {
    fn rx_htx(&self) -> &Htx {
        &self.rx_htx
    }
    fn rx_htx_mut(&mut self) -> &mut Htx {
        &mut self.rx_htx
    }
    fn dispatched(&self) -> bool {
        self.dispatched
    }
    fn set_dispatched(&mut self) {
        self.dispatched = true;
    }
    fn rx_buffered(&self) -> usize {
        self.rx_buffered
    }
    fn is_reset(&self) -> bool {
        !self.is_live()
    }
    fn req_head(&self) -> Option<&H2ReqHead> {
        self.req_head.as_deref()
    }
    fn take_req_fields(&mut self) -> Option<Box<H2ReqHead>> {
        self.req_head.take()
    }
    fn bad_request(&self) -> bool {
        self.bad_request
    }
    fn content_length(&self) -> Option<u64> {
        self.content_length
    }
}

fn give_h3_data(v: Vec<u8>) {
    H3_DATA.give(v);
}

impl HtxMux for H3MuxContext {
    type Stream = H3StreamCtx;

    const GIVE_DATA: fn(Vec<u8>) = give_h3_data;

    fn stream(&self, id: u64) -> Option<&H3StreamCtx> {
        self.streams.get(&id).map(|b| &**b)
    }

    fn stream_mut(&mut self, id: u64) -> Option<&mut H3StreamCtx> {
        self.streams.get_mut(&id).map(|b| &mut **b)
    }

    fn next_dispatch(&self) -> Option<u64> {
        let serving = self.streams.values().filter(|st| st.dispatched).count();
        if serving >= self.max_concurrent as usize {
            return None;
        }
        self.streams.values().find(|st| !st.dispatched && st.is_live() && st.phase != ReqPhase::Before).map(|st| st.id)
    }

    fn give_back_head(&mut self, mut head: Box<H2ReqHead>) {
        if self.spare_heads.len() < SPARE_HEADS {
            head.clear();
            self.spare_heads.push(head);
        }
    }

    fn send_head(&mut self, id: u64, head: &[u8], end_stream: bool) -> bool {
        // A reset stream takes anything, and drops it.
        if !self.live(id) {
            return true;
        }
        let Some((status, headers)) = crate::response_head::mux_head_lines(head) else { return false };
        self.put_head(id, Some(status), headers);
        if let Some(st) = self.streams.get_mut(&id).filter(|_| end_stream) {
            st.tx_fin = true;
        }
        true
    }

    fn send_head_fields<'h>(&mut self, id: u64, status: u16, fields: impl Iterator<Item = (&'h str, &'h [u8])>, end_stream: bool) -> bool {
        if !self.live(id) {
            return true;
        }
        self.put_head_of(id, Some(status), fields, true);
        if let Some(st) = self.streams.get_mut(&id).filter(|_| end_stream) {
            st.tx_fin = true;
        }
        true
    }

    fn send_data(&mut self, id: u64, data: &[u8], end_stream: bool) -> usize {
        let budget = self.data_budget(id);
        let Some(st) = self.streams.get_mut(&id).filter(|st| st.is_live()) else { return data.len() };
        let n = data.len().min(budget);
        if n > 0 {
            encode_varint(&mut st.tx, FRAME_DATA);
            encode_varint(&mut st.tx, n as u64);
            st.tx.extend_from_slice(&data[..n]);
        }
        if end_stream && n == data.len() {
            st.tx_fin = true;
        }
        n
    }

    fn send_trailers(&mut self, id: u64, trailers: &[(&str, &str)]) -> bool {
        if self.live(id) {
            self.put_head(id, None, trailers.iter().map(|&(n, v)| (n, v.as_bytes())));
            if let Some(st) = self.streams.get_mut(&id) {
                st.tx_fin = true;
            }
        }
        true
    }

    fn send_interim(&mut self, id: u64, head: &[u8]) -> bool {
        if !self.live(id) {
            return true;
        }
        let Some((status, headers)) = crate::response_head::mux_head_lines(head).filter(|(s, _)| (100..200).contains(s)) else { return false };
        self.put_head(id, Some(status), headers);
        if let Some(st) = self.streams.get_mut(&id) {
            st.interim_sent = true;
        }
        true
    }

    fn data_budget(&self, id: u64) -> usize {
        match self.streams.get(&id) {
            Some(st) if st.is_live() => TX_ROOM.saturating_sub(st.tx_pending().len() + FRAME_HEADER_MAX),
            _ => usize::MAX,
        }
    }

    fn rx_taken(&mut self, id: u64, n: usize) {
        if let Some(st) = self.streams.get_mut(&id) {
            st.rx_buffered = st.rx_buffered.saturating_sub(n);
            self.resume(id);
        }
    }

    fn reset(&mut self, id: u64, why: MuxReset) {
        if !self.live(id) {
            return;
        }
        let code = match why {
            MuxReset::Cancel => H3Error::RequestCancelled,
            MuxReset::Internal => H3Error::InternalError,
            MuxReset::Refused => H3Error::RequestRejected,
        } as u64;
        self.signals.push_back(H3Signal::ResetStream { id, code });
        self.stream_gone(id, code);
    }

    fn is_reset(&self, id: u64) -> bool {
        self.streams.get(&id).is_some_and(|st| !st.is_live())
    }

    fn tx_pending(&self) -> bool {
        self.control_head < self.control_tx.len() || self.streams.values().any(|st| !st.tx_pending().is_empty() || self.fin_due(st.id))
    }

    fn glitches(&self) -> u64 {
        u64::from(self.glitch_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_into_writes_every_width() {
        for v in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, (1 << 62) - 1] {
            let mut b = [0u8; 8];
            let n = varint_into(&mut b, v);
            let mut want = Vec::new();
            encode_varint(&mut want, v);
            assert_eq!(&b[..n], &want[..], "value {v}");
        }
    }

    #[test]
    fn a_stream_given_back_wiped_keeps_its_memory_and_nothing_else() {
        let mut st = H3StreamCtx { id: 8, rx: b"secret".to_vec(), tx: b"reply".to_vec(), dispatched: true, ..H3StreamCtx::default() };
        let mut head = Box::<H2ReqHead>::default();
        *head = H2ReqHead::of("GET", "/secret", &[("x-secret", "1")]);
        st.req_head = Some(head);
        st.rx_htx.push(HtxBlock::Eoh);
        let cap = st.rx.capacity();
        Poolable::reset(&mut st, true);
        assert_eq!((st.id, st.dispatched, st.rx.len(), st.tx.len()), (0, false, 0, 0));
        assert_eq!(st.rx.capacity(), cap, "the buffer is kept for the next stream");
        assert_eq!(st.rx_htx.blocks(), &[] as &[HtxBlock]);
        assert!(st.req_head.as_ref().is_some_and(|h| h.line.is_empty() && h.bytes.is_empty()));
        Poolable::reset(&mut st, false);
        assert!(st.footprint() >= std::mem::size_of::<H3StreamCtx>());
    }

    #[test]
    fn varint_round_trips_at_every_width() {
        for v in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut buf = Vec::new();
            encode_varint(&mut buf, v);
            let mut off = 0;
            assert_eq!(parse_varint(&buf, &mut off).unwrap(), v, "value {v}");
            assert_eq!(off, buf.len(), "consumed the whole encoding for {v}");
        }
    }

    #[test]
    fn status_200_uses_the_static_table() {
        // RFC 9204 static index 25 is (":status", "200"). An indexed static field line is
        // 0b11 followed by the index in 6 bits, so 0xc0 | 25 = 0xd9.
        let out = encode_field_section(&[(":status".into(), "200".into())]);
        assert_eq!(out, vec![0x00, 0x00, 0xd9]);
    }

    #[test]
    fn a_header_not_in_the_static_table_becomes_a_literal() {
        let out = encode_field_section(&[("x-ibex".into(), "1".into())]);
        assert_eq!(&out[..2], &[0x00, 0x00], "field section prefix");
        assert!(out.len() > 3, "a literal name and value follow");
    }

    #[test]
    fn settings_advertises_zero_capacity_and_zero_blocked_streams() {
        let s = encode_settings();
        let mut off = 0;
        assert_eq!(parse_varint(&s, &mut off).unwrap(), FRAME_SETTINGS);
        let len = parse_varint(&s, &mut off).unwrap() as usize;
        let payload = &s[off..off + len];
        let mut p = 0;
        assert_eq!(parse_varint(payload, &mut p).unwrap(), SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        assert_eq!(parse_varint(payload, &mut p).unwrap(), 0, "capacity must be 0");
        assert_eq!(parse_varint(payload, &mut p).unwrap(), SETTINGS_QPACK_BLOCKED_STREAMS);
        assert_eq!(parse_varint(payload, &mut p).unwrap(), 0, "blocked streams must be 0");
    }

    #[test]
    fn uni_stream_types_are_recognised_and_unknown_ones_tolerated() {
        assert_eq!(read_uni_stream_type(&[0x00]).unwrap().0, UniStreamKind::Control);
        assert_eq!(read_uni_stream_type(&[0x02]).unwrap().0, UniStreamKind::QpackEncoder);
        assert_eq!(read_uni_stream_type(&[0x03]).unwrap().0, UniStreamKind::QpackDecoder);
        assert!(matches!(
            read_uni_stream_type(&[0x21]).unwrap().0,
            UniStreamKind::Unknown(_)
        ));
        assert!(read_uni_stream_type(&[]).is_none(), "an empty prefix is not yet readable");
    }

    #[test]
    fn take_request_headers_skips_unknown_frames_and_waits_for_a_partial_one() {
        let mut buf = Vec::new();
        encode_frame(&mut buf, 0x21, b"grease");
        encode_frame(&mut buf, FRAME_HEADERS, &[0x00, 0x00, 0xd9]);
        assert_eq!(
            take_request_headers(&buf, 16380).unwrap(),
            Some(vec![0x00, 0x00, 0xd9]),
            "a grease frame before HEADERS must be skipped"
        );

        let partial = &buf[..buf.len() - 1];
        assert_eq!(
            take_request_headers(partial, 16380).unwrap(),
            None,
            "an incomplete frame is not an error"
        );
    }

    #[test]
    fn a_response_is_headers_then_data() {
        let out = encode_response(200, &[], b"hi");
        let mut off = 0;
        assert_eq!(parse_varint(&out, &mut off).unwrap(), FRAME_HEADERS);
        let hlen = parse_varint(&out, &mut off).unwrap() as usize;
        off += hlen;
        assert_eq!(parse_varint(&out, &mut off).unwrap(), FRAME_DATA);
        let dlen = parse_varint(&out, &mut off).unwrap() as usize;
        assert_eq!(&out[off..off + dlen], b"hi");
    }
}
