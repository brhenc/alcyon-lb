// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/mux_h2.c and include/haproxy/mux_h2.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 Multiplexer implementing the [`Mux`] trait over [`Htx`].
//!
//! Handles connection preface negotiation, concurrent stream multiplexing (streams 1, 3, 5, 7, ...),
//! HPACK compression/decompression, connection and stream-level flow control (`WINDOW_UPDATE`),
//! stream resets (`RST_STREAM`), and graceful connection shutdown (`GOAWAY`).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::manual_let_else,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

use crate::conn::ConnId;
use crate::endpoint::{Endpoint, SeDesc};
use crate::h2::{
    frame_flags, Frame, FrameHeader, FrameType, H2ConnState, H2Error, H2StreamState, SettingsParameter,
    DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE, FRAME_HEADER_LEN, H2_CONN_PREFACE,
    MAX_MAX_FRAME_SIZE, MAX_WINDOW_SIZE, MIN_MAX_FRAME_SIZE,
};
use crate::hpack::{DecodedFields, HpackDecoder, HpackEncoder};
use crate::htx::{HeaderField, HttpVersion, Htx, HtxBlock};
use crate::mux::{mux_flags, Mux, MuxFlags, MuxOps, ShutMode};
use std::io;

/// Output waiting for the client past which the demux stops: what a client that reads
/// nothing can make the connection queue in replies (RST_STREAM, PING and SETTINGS ACKs).
pub const TX_ROOM: usize = 65536;

/// The size of one receive buffer of the connection's budget (`tune.bufsize`, 16 KB).
const RX_BUF: usize = 16384;
/// The body bytes one receive buffer holds: [`RX_BUF`] less the HTX header (40 bytes) and
/// one data block (8), `htx_free_data_space` of an empty rxbuf. A 16 KB DATA frame spans two.
const RX_SLOT_DATA: usize = RX_BUF - 40 - 8;

static H2_OPS: MuxOps = MuxOps {
    name: "h2",
    alpn: Some(b"h2"),
    flags: MuxFlags(mux_flags::MULTIPLEXED | mux_flags::HTX | mux_flags::REUSABLE),
};

/// Per-stream multiplexer context tracking flow control and HTX representation.
#[derive(Debug, Clone)]
pub struct H2StreamCtx {
    pub id: u32,
    pub state: H2StreamState,
    pub rx_htx: Htx,
    pub send_window: i32,
    pub recv_window: i32,
    pub reset_reason: Option<H2Error>,
    pub is_shut: bool,
    pub dispatched: bool,
    /// DATA payload bytes in `rx_htx` the data path has not taken yet ([`H2MuxContext::rx_taken`]).
    /// A stream holds at most its receive window of them: the next DATA frame waits in
    /// `rx_buf`, and the connection's demux with it, until they drain (T235).
    pub rx_buffered: usize,
    /// DATA payload bytes the stream has stored since it last held none: where its next
    /// byte falls in its chain of receive buffers ([`Self::rx_slots`]).
    pub rx_fill: usize,
    /// The receive window the stream has been granted beyond the initial one, as a size: 0
    /// until a body that needs more starts to flow ([`H2MuxContext::grow_rx_window`]). The
    /// stream holds at most this much (or the initial window) of DATA the data path has not
    /// taken ([`MuxH2::demux_blocked`]).
    pub rx_limit: usize,
    /// The request is one `HAProxy` takes and answers 400 (`HTX_FL_PARSING_ERROR`): a
    /// method or scheme that is not a token, a URI with a control byte
    /// ([`crate::h2::check_request_fields`]). It is not forwarded.
    pub bad_request: bool,
    /// The request head of a stream of a server connection, as HTTP/1.1 (T437): what the
    /// data path forwards, written once from the decoded fields. `rx_htx` then holds no
    /// start line nor headers, only the end of the head and what follows. `None` for a
    /// head kept as HTX blocks ([`H2ReqHead`]).
    pub req_head: Option<Box<H2ReqHead>>,
    /// The request's first `content-length`, as a number, kept for the stream's window
    /// (the head written as text is taken by the data path).
    pub req_content_length: Option<usize>,
}

/// A request head as HTTP/1.1, from the fields of its HEADERS (T437): `METHOD PATH
/// HTTP/1.1`, the host the authority makes when there is no `host` header, the other
/// headers, the blank line, as [`Htx::to_h1_wire`] writes the blocks
/// `pseudo_headers_to_htx` makes; then the `scheme://authority` prefix of the start line
/// `HAProxy` logs, if the request had both. Kept from one stream of the connection to the
/// next ([`H2MuxContext::spare_heads`]).
#[derive(Debug, Clone, Default)]
pub struct H2ReqHead {
    /// The head, then the prefix.
    pub text: String,
    /// The end of the head (its blank line included) in `text`.
    pub head_len: usize,
    /// The method: `text[..method_len]`.
    pub method_len: usize,
    /// The path in `text`.
    pub uri: (usize, usize),
    /// The prefix in `text` (empty without one).
    pub abs: (usize, usize),
    /// The headers, as the HTX had them: name start, name end, value start, value end.
    pub fields: Vec<(u32, u32, u32, u32)>,
    /// The fields' names and values, in bytes (`%U` counts them).
    pub field_bytes: usize,
    /// The head has a start line (`method` and `uri` are its).
    pub has_line: bool,
}

impl H2ReqHead {
    /// No head; the memory is kept.
    pub fn clear(&mut self) {
        self.text.clear();
        self.fields.clear();
        (self.head_len, self.method_len, self.uri, self.abs, self.field_bytes, self.has_line) = (0, 0, (0, 0), (0, 0), 0, false);
    }

    /// A head of `wire` alone: no start line or field of its own (a head made elsewhere).
    #[must_use]
    pub fn from_wire(wire: &str) -> Self {
        Self { text: wire.to_string(), head_len: wire.len(), ..Self::default() }
    }

    /// The head as HTTP/1.1, up to and with its blank line.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.text.as_bytes()[..self.head_len]
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.text[..self.method_len]
    }

    #[must_use]
    pub fn uri(&self) -> &str {
        &self.text[self.uri.0..self.uri.1]
    }

    /// `scheme://authority`, when the request had both.
    #[must_use]
    pub fn abs_prefix(&self) -> Option<&str> {
        (self.abs.1 > self.abs.0).then(|| &self.text[self.abs.0..self.abs.1])
    }

    /// The headers in order, as name and value.
    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.fields.iter().map(|&(a, b, c, d)| (&self.text[a as usize..b as usize], &self.text[c as usize..d as usize]))
    }

    /// The first value of header `name` (ASCII case-insensitive), as `Htx::get_header`.
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }

    fn push_field(&mut self, name: &str, value: &str) {
        let pos = |t: &String| u32::try_from(t.len()).unwrap_or(u32::MAX);
        let a = pos(&self.text);
        self.text.push_str(name);
        let b = pos(&self.text);
        self.text.push_str(": ");
        let c = pos(&self.text);
        self.text.push_str(value);
        let d = pos(&self.text);
        self.text.push_str("\r\n");
        self.fields.push((a, b, c, d));
        self.field_bytes += name.len() + value.len();
    }

    /// The `cookie` field of the values `values`, joined with "; "; none, no field.
    fn push_cookies<'a>(&mut self, values: impl Iterator<Item = &'a str>) {
        let pos = |t: &String| u32::try_from(t.len()).unwrap_or(u32::MAX);
        let mut first = true;
        let (mut a, mut b, mut c) = (0, 0, 0);
        for v in values {
            if first {
                first = false;
                a = pos(&self.text);
                self.text.push_str("cookie");
                b = pos(&self.text);
                self.text.push_str(": ");
                c = pos(&self.text);
            } else {
                self.text.push_str("; ");
            }
            self.text.push_str(v);
        }
        if !first {
            let d = pos(&self.text);
            self.text.push_str("\r\n");
            self.fields.push((a, b, c, d));
            self.field_bytes += "cookie".len() + (d - c) as usize;
        }
    }

    /// Writes the request of `fields`, checked as
    /// `pseudo_headers_to_htx` checks it, and refused as `HAProxy` 3.5-dev8 refuses it
    /// (measured, T437): without `:method`, with a `:status`, or with a `:protocol` outside
    /// an extended CONNECT. A `host` after the first is dropped, as `HAProxy` drops it.
    /// Every request of a server connection is written this way.
    pub(crate) fn write(&mut self, fields: &DecodedFields) -> Result<(), &'static str> {
        self.clear();
        let (mut method, mut path, mut authority, mut host, mut scheme, mut protocol) = (None, None, None, None, false, false);
        let mut seen_regular = false;
        for (n, v) in fields.iter() {
            if n.starts_with(':') {
                if seen_regular {
                    return Err("pseudo-header after regular header");
                }
                let slot = match n {
                    ":method" => &mut method,
                    ":path" => {
                        if path.is_none() && v.is_empty() {
                            return Err("empty :path");
                        }
                        &mut path
                    }
                    ":authority" => &mut authority,
                    ":scheme" | ":protocol" => {
                        let seen = if n == ":scheme" { &mut scheme } else { &mut protocol };
                        if *seen {
                            return Err("duplicate pseudo-header");
                        }
                        *seen = true;
                        continue;
                    }
                    _ => return Err("unknown pseudo-header"),
                };
                if slot.is_some() {
                    return Err("duplicate pseudo-header");
                }
                *slot = Some(v);
            } else {
                seen_regular = true;
                if n.eq_ignore_ascii_case("host") && host.is_none() {
                    host = Some(v);
                }
            }
        }
        if let (Some(a), Some(h)) = (authority, host) {
            if !a.eq_ignore_ascii_case(h) {
                return Err("authority and host mismatch");
            }
        }
        let method = method.ok_or("no :method")?;
        // `:protocol` is an extended CONNECT's (RFC 8441), consumed as the HTX conversion
        // consumes it.
        if protocol && method != "CONNECT" {
            return Err(":protocol outside CONNECT");
        }
        self.has_line = true;
        self.text.push_str(method);
        self.method_len = self.text.len();
        self.text.push(' ');
        let start = self.text.len();
        // `:path *` with an `:authority` is the absolute form without a path, which
        // `HAProxy` writes as `/`, as `*` for OPTIONS (`h2_prepare_htx_reqline`; measured,
        // T451).
        let path = match path {
            Some("*") if authority.is_some() && method != "OPTIONS" => "/",
            p => p.unwrap_or("/"),
        };
        self.text.push_str(path);
        self.uri = (start, self.text.len());
        self.text.push_str(" HTTP/1.1\r\n");
        if let (Some(a), None) = (authority, host) {
            self.push_field("host", a);
        }
        let mut host_seen = false;
        for (n, v) in fields.iter().filter(|(n, _)| !n.starts_with(':')) {
            if n.eq_ignore_ascii_case("host") {
                if host_seen {
                    continue;
                }
                host_seen = true;
            }
            // The cookie fields are merged after the others (below).
            if n == "cookie" {
                continue;
            }
            // A value's leading and trailing blanks go, as `h2_make_htx_request` trims them
            // (RFC 9113 section 8.2.1).
            self.push_field(n, v.trim_matches([' ', '\t']));
        }
        // RFC 9113 section 8.2.3: the cookie fields are one line, their values joined with
        // "; " and their blanks kept, after the other fields (`h2_make_htx_request`;
        // measured, T506).
        self.push_cookies(fields.iter().filter(|(n, _)| *n == "cookie").map(|(_, v)| v));
        self.text.push_str("\r\n");
        self.head_len = self.text.len();
        // `HAProxy`'s start line: the first `:scheme` and `:authority`.
        if let (Some(sc), Some(a)) = (fields.get(":scheme"), fields.get(":authority")) {
            let start = self.text.len();
            self.text.push_str(sc);
            self.text.push_str("://");
            self.text.push_str(a);
            self.abs = (start, self.text.len());
        }
        Ok(())
    }
}

impl H2StreamCtx {
    /// The request's method, until the data path takes the head.
    #[must_use]
    pub fn request_method(&self) -> Option<&str> {
        self.req_head.as_ref().map(|h| h.method())
    }

    /// The request's path, until the data path takes the head.
    #[must_use]
    pub fn request_uri(&self) -> Option<&str> {
        self.req_head.as_ref().map(|h| h.uri())
    }

    /// The first value of the request's header `name`, until the data path takes the head.
    #[must_use]
    pub fn request_header(&self, name: &str) -> Option<&str> {
        self.req_head.as_ref().and_then(|h| h.get_header(name))
    }

    /// The request's `content-length`, as a number, even once the data path has taken the
    /// head.
    #[must_use]
    pub fn request_content_length(&self) -> Option<usize> {
        self.req_content_length
    }
}

/// The streams of a connection by id, in id order, as a `BTreeMap` iterates them: a sorted
/// `Vec` (T437), whose memory a connection serving one stream after another keeps, where
/// the map allocated a node for its first stream and freed it with its last. Generic over
/// the stream and its id (T503): `H2StreamCtx` by `u32` for HTTP/2, the h3 mux's streams by
/// QUIC stream id.
#[derive(Debug, Clone)]
pub struct StreamMap<S = H2StreamCtx, K = u32> {
    v: Vec<(K, S)>,
}

impl<S, K> Default for StreamMap<S, K> {
    fn default() -> Self {
        Self { v: Vec::new() }
    }
}

/// Past this many slots, a map left empty gives its memory back.
const STREAM_MAP_KEEP: usize = 16;

impl<S, K: Ord + Copy> StreamMap<S, K> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn pos(&self, id: K) -> Result<usize, usize> {
        self.v.binary_search_by_key(&id, |e| e.0)
    }

    #[must_use]
    pub fn get(&self, id: &K) -> Option<&S> {
        self.pos(*id).ok().map(|i| &self.v[i].1)
    }

    pub fn get_mut(&mut self, id: &K) -> Option<&mut S> {
        self.pos(*id).ok().map(|i| &mut self.v[i].1)
    }

    #[must_use]
    pub fn contains_key(&self, id: &K) -> bool {
        self.pos(*id).is_ok()
    }

    /// Inserts `s` as stream `id`: the stream it replaces, if there was one.
    pub fn insert(&mut self, id: K, s: S) -> Option<S> {
        match self.pos(id) {
            Ok(i) => Some(std::mem::replace(&mut self.v[i].1, s)),
            Err(i) => {
                self.v.insert(i, (id, s));
                None
            }
        }
    }

    pub fn remove(&mut self, id: &K) -> Option<S> {
        let i = self.pos(*id).ok()?;
        let s = self.v.remove(i).1;
        self.shrink();
        Some(s)
    }

    /// Keeps the streams `f` says to keep.
    pub fn retain(&mut self, mut f: impl FnMut(&K, &mut S) -> bool) {
        self.v.retain_mut(|(id, s)| f(id, s));
        self.shrink();
    }

    fn shrink(&mut self) {
        if self.v.is_empty() && self.v.capacity() > STREAM_MAP_KEEP {
            self.v = Vec::new();
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.v.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v.is_empty()
    }

    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &K> + Clone + '_ {
        self.v.iter().map(|(id, _)| id)
    }

    pub fn values(&self) -> impl DoubleEndedIterator<Item = &S> + Clone + '_ {
        self.v.iter().map(|(_, s)| s)
    }

    pub fn values_mut(&mut self) -> impl DoubleEndedIterator<Item = &mut S> + '_ {
        self.v.iter_mut().map(|(_, s)| s)
    }

    /// The stream `id`, as `BTreeMap::entry` gives it.
    pub fn entry(&mut self, id: K) -> StreamEntry<'_, S, K> {
        StreamEntry { map: self, id }
    }
}

/// [`StreamMap::entry`].
pub struct StreamEntry<'a, S = H2StreamCtx, K = u32> {
    map: &'a mut StreamMap<S, K>,
    id: K,
}

impl<'a, S, K: Ord + Copy> StreamEntry<'a, S, K> {
    /// Runs `f` on the stream, if there is one.
    pub fn and_modify(self, f: impl FnOnce(&mut S)) {
        if let Some(s) = self.map.get_mut(&self.id) {
            f(s);
        }
    }

    /// The stream, inserted from `f` if there was none.
    pub fn or_insert_with(self, f: impl FnOnce() -> S) -> &'a mut S {
        let i = match self.map.pos(self.id) {
            Ok(i) => i,
            Err(i) => {
                self.map.v.insert(i, (self.id, f()));
                i
            }
        };
        &mut self.map.v[i].1
    }
}

impl H2StreamCtx {
    /// The connection's receive buffers the stream holds with `extra` more bytes stored: one
    /// per [`RX_SLOT_DATA`] the bytes it was given span, less those the data path has
    /// emptied. `HAProxy` keeps a buffer until it is empty (`h2s_put_rxbuf`), so a stream
    /// whose 16 KB frame was mostly taken still holds two.
    #[must_use]
    pub fn rx_slots(&self, extra: usize) -> usize {
        let (fill, held) = (self.rx_fill + extra, self.rx_buffered + extra);
        if held == 0 {
            return 0;
        }
        fill.div_ceil(RX_SLOT_DATA) - (fill - held) / RX_SLOT_DATA
    }

    #[must_use]
    pub fn new(id: u32, initial_send_window: i32, initial_recv_window: i32) -> Self {
        Self {
            id,
            state: H2StreamState::Idle,
            rx_htx: Htx::new(),
            send_window: initial_send_window,
            recv_window: initial_recv_window,
            reset_reason: None,
            is_shut: false,
            dispatched: false,
            rx_buffered: 0,
            rx_fill: 0,
            rx_limit: 0,
            bad_request: false,
            req_head: None,
            req_content_length: None,
        }
    }
}

/// Configuration for HTTP/2 flood mitigation knobs matching HAProxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct H2FloodConfig {
    /// Caps total streams per connection (`tune.h2.fe.max-total-streams`). Default: 0 (unlimited).
    pub max_total_streams: usize,
    /// Threshold of glitch frames before graceful GOAWAY (75%) and hard close (100%) (`tune.h2.fe.glitches-threshold`). Default: 0 (disabled).
    pub glitches_threshold: usize,
    /// The limit advertised to a client and enforced on its streams
    /// (`tune.h2.{,fe.}max-concurrent-streams`); `None` is the default, 100. 0 advertises
    /// nothing and refuses every stream.
    pub max_concurrent_streams: Option<u32>,
    /// The connection's receive budget in bytes (`tune.h2.fe.rxbuf`); 0 is the default, one
    /// buffer per allowed stream ([`H2MuxContext::rx_budget`]).
    pub rxbuf: usize,
}

/// HTTP/2 Connection Context.
pub struct H2MuxContext {
    pub conn: ConnId,
    pub is_server: bool,
    pub conn_state: H2ConnState,
    pub rx_buf: Vec<u8>,
    pub tx_buf: Vec<u8>,
    pub tx_consumed: usize,
    pub streams: StreamMap,
    pub conn_send_window: i32,
    pub conn_recv_window: i32,
    /// The connection window has been opened wide ([`Self::rx_taken`]).
    pub rx_window_opened: bool,
    pub remote_initial_window: i32,
    pub local_initial_window: i32,
    /// How many streams may be open at once: on a server connection the client's, as
    /// advertised (`SETTINGS_MAX_CONCURRENT_STREAMS`); on a client connection ours, as the
    /// server's SETTINGS say.
    pub max_concurrent_streams: u32,
    pub max_frame_size: u32,
    pub last_client_stream_id: u32,
    pub last_server_stream_id: u32,
    pub settings_ack_received: bool,
    pub goaway_sent: Option<(u32, H2Error)>,
    pub goaway_received: Option<(u32, H2Error)>,
    pub decoder: HpackDecoder,
    pub encoder: HpackEncoder,
    pub is_shut: bool,
    pub reset_count: u32,
    pub ping_count: u32,
    pub settings_count: u32,
    pub continuation_stream: Option<u32>,
    pub continuation_flags: u8,
    pub continuation_buf: Vec<u8>,
    pub continuation_count: u32,
    /// Payload length of the frame being handled, padding included: what flow control counts.
    pub rx_frame_len: u32,
    pub flood_config: H2FloodConfig,
    /// The frontend's `option accept-unsafe-violations-in-http-request`: a request's
    /// `:path` gets the relaxed check of `h2_make_htx_request(.., relaxed)` (T451).
    pub relaxed_path: bool,
    pub total_streams: usize,
    pub glitch_count: usize,
    pub graceful_goaway_sent: bool,
    /// The highest stream id that has had an entry in `streams`. A closed stream is taken
    /// out of the map when its transaction ends; an id at or below this one and not in the
    /// map is a closed stream, not a new one.
    pub highest_opened: u32,
    /// A response header's name lowercased ([`Self::send_headers_frame`]), kept for the next.
    lower_name: String,
    /// What the data path stages a response body in before it goes out as DATA frames,
    /// kept from one to the next (T437).
    pub body_scratch: Vec<u8>,
    /// The fields of the header block being handled, decoded into memory kept for the next.
    decoded: DecodedFields,
    /// A HEADERS frame's block, copied out of `rx_buf` to be decoded.
    block_scratch: Vec<u8>,
    /// The memory of request heads the data path has taken ([`H2ReqHead`]), for the next.
    pub spare_heads: Vec<Box<H2ReqHead>>,
    /// The memory of the HTX of streams that are over, for the next (at most
    /// [`SPARE_STREAMS`]).
    pub spare_htx: Vec<Htx>,
}

/// How many spare heads and HTX a connection keeps while it serves streams; an idle one
/// keeps [`IDLE_SPARES`] of each ([`H2MuxContext::trim_idle`]).
pub const SPARE_STREAMS: usize = 4;

/// The spares an idle connection keeps: two, as a client sending one request after the
/// other has two streams at once for a moment (the next one opens before the last one's
/// end has been seen); with one, every other stream allocated again.
pub const IDLE_SPARES: usize = 2;

/// `status` as its decimal digits in `buf`.
pub(crate) fn status_text(status: u16, buf: &mut [u8; 5]) -> &str {
    let mut n = status;
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    std::str::from_utf8(&buf[i..]).unwrap_or("0")
}

impl H2MuxContext {
    #[must_use]
    pub fn new(conn: ConnId, is_server: bool) -> Self {
        Self {
            conn,
            is_server,
            conn_state: if is_server {
                H2ConnState::ExpectPreface
            } else {
                H2ConnState::ExpectSettings
            },
            rx_buf: Vec::with_capacity(8192),
            tx_buf: Vec::with_capacity(8192),
            tx_consumed: 0,
            streams: StreamMap::new(),
            conn_send_window: DEFAULT_INITIAL_WINDOW_SIZE,
            conn_recv_window: DEFAULT_INITIAL_WINDOW_SIZE,
            rx_window_opened: false,
            remote_initial_window: DEFAULT_INITIAL_WINDOW_SIZE,
            local_initial_window: DEFAULT_INITIAL_WINDOW_SIZE,
            max_concurrent_streams: 100,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            last_client_stream_id: 0,
            last_server_stream_id: 0,
            settings_ack_received: false,
            goaway_sent: None,
            goaway_received: None,
            decoder: HpackDecoder::new(),
            encoder: HpackEncoder::new(),
            is_shut: false,
            reset_count: 0,
            ping_count: 0,
            settings_count: 0,
            continuation_stream: None,
            continuation_flags: 0,
            continuation_buf: Vec::new(),
            continuation_count: 0,
            rx_frame_len: 0,
            flood_config: H2FloodConfig::default(),
            relaxed_path: false,
            total_streams: 0,
            glitch_count: 0,
            graceful_goaway_sent: false,
            highest_opened: 0,
            lower_name: String::new(),
            body_scratch: Vec::new(),
            decoded: DecodedFields::default(),
            block_scratch: Vec::new(),
            spare_heads: Vec::new(),
            spare_htx: Vec::new(),
        }
    }

    /// Appends a frame to `tx_buf` for transmission to transport.
    pub fn enqueue_frame(&mut self, frame: &Frame) {
        self.tx_rewind();
        frame.encode_into(&mut self.tx_buf);
    }

    /// A stream that is over gives its memory back for the next ones (T437).
    pub fn recycle_stream(&mut self, s: &mut H2StreamCtx) {
        // (Its head, if it had one, is the data path's: `dispatch_next` took it. A stream
        // reset before that is let go by `stream_reset`, not here.)
        if self.spare_htx.len() < SPARE_STREAMS {
            let mut htx = std::mem::take(&mut s.rx_htx);
            htx.clear();
            self.spare_htx.push(htx);
        }
    }

    /// The connection serves no stream: it keeps the memory a client sending one request
    /// after the other needs, not what the busiest moment needed ([`IDLE_SPARES`], a small
    /// body stage).
    pub fn trim_idle(&mut self) {
        self.spare_heads.truncate(IDLE_SPARES);
        self.spare_htx.truncate(IDLE_SPARES);
        if self.body_scratch.capacity() > 4096 {
            self.body_scratch = Vec::new();
        }
    }

    /// A request head the data path took ([`H2StreamCtx::req_head`]) is given back.
    pub fn give_back_head(&mut self, mut h: Box<H2ReqHead>) {
        if self.spare_heads.len() < SPARE_STREAMS {
            h.clear();
            self.spare_heads.push(h);
        }
    }

    /// `tx_buf` starts over once all of it has been sent.
    fn tx_rewind(&mut self) {
        if self.tx_consumed > 0 && self.tx_consumed >= self.tx_buf.len() {
            self.tx_buf.clear();
            self.tx_consumed = 0;
        }
    }

    /// Appends the header of a frame to `tx_buf` (the payload follows it, written by the
    /// caller, then [`Self::end_frame`] sets its length): where it starts.
    fn begin_frame(&mut self, frame_type: FrameType, flags: u8, stream_id: u32) -> usize {
        self.tx_rewind();
        let at = self.tx_buf.len();
        self.tx_buf.extend_from_slice(&FrameHeader { length: 0, frame_type, flags, stream_id }.encode());
        at
    }

    /// The frame begun at `at` ends with what `tx_buf` holds: its length is written.
    fn end_frame(&mut self, at: usize) {
        let len = u32::try_from(self.tx_buf.len() - at - FRAME_HEADER_LEN).unwrap_or(u32::MAX);
        self.tx_buf[at..at + 3].copy_from_slice(&len.to_be_bytes()[1..]);
    }

    /// Sends a connection-level or stream-level GOAWAY frame and updates state.
    pub fn send_goaway(&mut self, last_stream_id: u32, error_code: H2Error, debug: &[u8]) {
        self.goaway_sent = Some((last_stream_id, error_code));
        let frame = Frame::GoAway {
            last_stream_id,
            error_code,
            debug_data: debug.to_vec(),
        };
        self.enqueue_frame(&frame);
        self.conn_state = H2ConnState::GoAwaySent;
    }

    /// After `parse` failed: makes sure the connection error is announced. Most errors have
    /// sent their GOAWAY already; one that has not gets INTERNAL_ERROR. The GOAWAY stays
    /// queued so the owner can flush it before closing.
    pub fn ensure_goaway(&mut self) {
        if self.conn_state != H2ConnState::GoAwaySent {
            self.send_goaway(self.last_client_stream_id, H2Error::InternalError, b"connection error");
        }
    }

    /// Announces a graceful shutdown: GOAWAY with `NO_ERROR` and last-stream-id 2^31-1, so
    /// streams already open finish and the client opens new ones elsewhere. Unlike
    /// [`Self::send_goaway`] it does not stop parsing. `HAProxy` does the same when the
    /// frontend is stopping (`src/mux_h2.c:5308`, last_sid `(1U << 31) - 1` at `:5330`).
    pub fn send_graceful_goaway(&mut self) {
        if self.graceful_goaway_sent || self.goaway_sent.is_some() {
            return;
        }
        self.graceful_goaway_sent = true;
        let last_stream_id = (1 << 31) - 1;
        self.goaway_sent = Some((last_stream_id, H2Error::NoError));
        let frame = Frame::GoAway {
            last_stream_id,
            error_code: H2Error::NoError,
            debug_data: Vec::new(),
        };
        self.enqueue_frame(&frame);
    }

    /// Sends a WINDOW_UPDATE frame on stream 0 (connection) or a specific stream.
    pub fn send_window_update(&mut self, stream_id: u32, increment: u32) {
        if increment == 0 {
            return;
        }
        let frame = Frame::WindowUpdate {
            stream_id,
            increment,
        };
        self.enqueue_frame(&frame);
        if stream_id == 0 {
            self.conn_recv_window = self.conn_recv_window.saturating_add(i32::try_from(increment).unwrap_or(i32::MAX));
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_window = stream.recv_window.saturating_add(i32::try_from(increment).unwrap_or(i32::MAX));
        }
    }

    /// The data path took `n` of the DATA bytes stream `stream_id` holds: as much room for
    /// more, so a demux held on that stream may go on ([`Self::resume`]).
    pub fn rx_taken(&mut self, stream_id: u32, n: usize) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.rx_buffered = s.rx_buffered.saturating_sub(n);
            if s.rx_buffered == 0 {
                s.rx_fill = 0;
            }
        }
        // The first update of the connection window opens it wide (`h2c_send_conn_wu`,
        // `H2_CF_WINDOW_OPENED`): what the connection can be sent is bounded by the streams'
        // windows and the budget, not by this one.
        if !self.rx_window_opened && n > 0 {
            self.rx_window_opened = true;
            let inc = i32::MAX.saturating_sub(self.conn_recv_window);
            self.send_window_update(0, inc.max(0) as u32);
        }
    }

    /// The most DATA the connection holds for streams the data path has not taken from: one
    /// buffer of [`RX_BUF`] per stream it allows, at least `tune.h2.fe.rxbuf` bytes, and one
    /// more (`bl_init(h2c->shared_rx_bufs, nb_rxbufs + 1)`, `mux_h2.c`). The fuzz target
    /// `h2_mux` holds the connection to 2 MiB with this.
    #[must_use]
    pub fn rx_budget(&self) -> usize {
        let forced = self.flood_config.rxbuf.div_ceil(RX_BUF - 9);
        (forced.max(self.max_concurrent_streams as usize) + 1) * RX_BUF
    }

    /// The connection's receive buffers ([`Self::rx_budget`] less the list head of
    /// `bl_init(nb_rxbufs + 1)`): what the streams' stored DATA may occupy.
    #[must_use]
    pub fn rx_slots(&self) -> usize {
        self.rx_budget() / RX_BUF - 1
    }

    /// Grows the receive window of stream `stream_id`, which is receiving a body, to its
    /// share of the budget (`h2c_update_strm_rx_win`): every existing stream is given one
    /// buffer, a stream that is not receiving keeps just that, an eighth of the streams the
    /// connection allows is kept for new ones, and the rest is shared among the streams
    /// that receive, rounded up to a buffer. Only ever grows; what was granted stays, and
    /// the budget itself is enforced by the demux ([`MuxH2::demux_blocked`]).
    fn grow_rx_window(&mut self, stream_id: u32) {
        let initial = usize::try_from(self.local_initial_window).unwrap_or(0);
        let Some(st) = self.streams.get(&stream_id) else { return };
        if st.state != H2StreamState::Open {
            return;
        }
        // A body that fits the window already is not worth more (`H2_SF_DATA_CLEN`).
        if st.request_content_length().is_some_and(|l| l <= initial) {
            return;
        }
        let open = |s: &&H2StreamCtx| !matches!(s.state, H2StreamState::Closed | H2StreamState::Reset(_));
        let nb_sc = self.streams.values().filter(open).count();
        let receiving = self.streams.values().filter(|s| s.state == H2StreamState::Open).count().max(1);
        let bufs = self.rx_budget() / RX_BUF;
        let allocatable = bufs.saturating_sub(nb_sc.saturating_sub(receiving));
        let reserved = (self.max_concurrent_streams as usize).saturating_sub(nb_sc).div_ceil(8);
        let to_share = allocatable.saturating_sub(reserved);
        let win = (RX_BUF * to_share).div_ceil(receiving).div_ceil(RX_BUF) * RX_BUF;
        let cur = st.rx_limit.max(initial);
        if win > cur {
            let inc = u32::try_from(win - cur).unwrap_or(u32::MAX).min(i32::MAX as u32);
            if let Some(st) = self.streams.get_mut(&stream_id) {
                st.rx_limit = win;
            }
            self.send_window_update(stream_id, inc);
        }
    }

    /// Whether the transport should read more for this connection: not while a whole
    /// frame already waits in `rx_buf` (its stream's buffer is full, or the output is),
    /// as HAProxy stops reading while its demux is blocked. The client is held by TCP.
    #[must_use]
    pub fn wants_input(&self) -> bool {
        self.rx_buf.len() < FRAME_HEADER_LEN + DEFAULT_MAX_FRAME_SIZE as usize
    }

    /// Demuxes what waits in `rx_buf` after what held it has drained.
    pub fn resume(&mut self) {
        if !self.rx_buf.is_empty() && self.conn_state != H2ConnState::GoAwaySent {
            let _ = MuxH2.parse(self, &[]).map_err(|_| self.ensure_goaway());
        }
    }

    /// Sends a RST_STREAM frame to terminate an individual stream.
    pub fn send_rst_stream(&mut self, stream_id: u32, error_code: H2Error) {
        let frame = Frame::RstStream {
            stream_id,
            error_code,
        };
        self.enqueue_frame(&frame);
        self.stream_reset(stream_id, error_code);
    }

    /// A stream reset either way: one no transaction has taken is let go at once, as
    /// HAProxy frees an h2s no stream is attached to; the one being served is marked, for
    /// the data path to see. Kept, every reset stream held its decoded request until the
    /// transaction on the connection ended -- rapid reset grew without bound (T235).
    fn stream_reset(&mut self, stream_id: u32, error_code: H2Error) {
        if self.streams.get(&stream_id).is_some_and(|s| !s.dispatched) {
            self.streams.remove(&stream_id);
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = H2StreamState::Reset(error_code);
            stream.reset_reason = Some(error_code);
            stream.is_shut = true;
        }
    }

    /// Encodes and queues a HEADERS frame for a response, dropping the connection-specific
    /// headers HTTP/2 forbids (RFC 7540 section 8.1.2.2). Encoded straight into `tx_buf`,
    /// the names lowercased in a buffer the connection keeps (T437).
    fn send_headers_frame<'h>(&mut self, stream_id: u32, status: u16, headers: impl Iterator<Item = (&'h str, &'h str)>, end_stream: bool) {
        let flags = if end_stream {
            frame_flags::END_HEADERS | frame_flags::END_STREAM
        } else {
            frame_flags::END_HEADERS
        };
        let at = self.begin_frame(FrameType::Headers, flags, stream_id);
        let mut digits = [0u8; 5];
        self.encoder.encode_field(":status", status_text(status, &mut digits), &mut self.tx_buf);
        let mut lower = std::mem::take(&mut self.lower_name);
        for (name, val) in headers {
            lower.clear();
            lower.push_str(name);
            lower.make_ascii_lowercase();
            if matches!(lower.as_str(), "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade") {
                continue;
            }
            self.encoder.encode_field(&lower, val, &mut self.tx_buf);
        }
        self.lower_name = lower;
        self.end_frame(at);
    }

    /// Parses an HTTP/1 response head (status line and headers, with or without the
    /// final blank line) and sends it as a HEADERS frame; the body follows through
    /// [`Self::send_data`]. `end_stream` is for a response without a body. Returns false
    /// if `head` is not a response head.
    pub fn send_h1_head(&mut self, stream_id: u32, head: &[u8], end_stream: bool) -> bool {
        // A reset stream takes nothing more (RFC 9113 5.1): the head is discarded, as
        // [`Self::send_data`] discards a body (T273 B).
        if self.streams.get(&stream_id).is_some_and(|s| matches!(s.state, H2StreamState::Reset(_))) {
            return true;
        }
        // Borrowed unless the head is not UTF-8.
        let head_str = String::from_utf8_lossy(head);
        let mut lines = head_str.lines();
        let Some(status_line) = lines.next() else { return false };
        let Some(code) = status_line.split_whitespace().nth(1) else { return false };
        let Ok(status) = code.parse::<u16>() else { return false };
        let headers = lines.filter_map(|line| line.split_once(':')).map(|(name, val)| (name.trim(), val.trim()));
        self.send_headers_frame(stream_id, status, headers, end_stream);
        true
    }

    /// How many DATA bytes the connection and stream send windows allow now, and the
    /// room left in the output buffer ([`TX_ROOM`]): a client that opens its windows wide
    /// and reads nothing stops the response copy, hence the server read, as `HAProxy`'s
    /// one-buffer mux does (T342). A stream that is gone takes anything (it is
    /// discarded), so its budget is unbounded.
    #[must_use]
    pub fn data_budget(&self, stream_id: u32) -> usize {
        match self.streams.get(&stream_id) {
            Some(st) if !matches!(st.state, H2StreamState::Reset(_) | H2StreamState::Closed) => {
                let room = TX_ROOM.saturating_sub(self.tx_buf.len() - self.tx_consumed);
                usize::try_from(self.conn_send_window.min(st.send_window)).unwrap_or(0).min(room)
            }
            _ => usize::MAX,
        }
    }

    /// Sends as much of `data` as the connection and stream send windows (and the peer's
    /// maximum frame size) allow, as DATA frames, and returns how many bytes were taken.
    /// The caller keeps the rest and offers it again once a WINDOW_UPDATE has arrived.
    /// `end_stream` is honoured only when all of `data` was taken, on the last frame
    /// (an empty `data` with `end_stream` sends an empty DATA frame, which no window
    /// can refuse). A stream that is gone (reset by the peer) takes everything and
    /// discards it.
    pub fn send_data(&mut self, stream_id: u32, data: &[u8], end_stream: bool) -> usize {
        let Some(stream) = self.streams.get(&stream_id) else {
            return data.len();
        };
        if matches!(stream.state, H2StreamState::Reset(_) | H2StreamState::Closed) {
            return data.len();
        }
        let mut sent = 0;
        while sent < data.len() {
            let stream_win = self.streams.get(&stream_id).map_or(0, |s| s.send_window);
            let win = self.conn_send_window.min(stream_win);
            if win <= 0 {
                break;
            }
            let n = (data.len() - sent).min(win as usize).min(self.max_frame_size as usize);
            if n == 0 {
                // Never true once SETTINGS are validated; a zero-size chunk would spin here.
                break;
            }
            let last = end_stream && sent + n == data.len();
            let at = self.begin_frame(FrameType::Data, if last { frame_flags::END_STREAM } else { 0 }, stream_id);
            self.tx_buf.extend_from_slice(&data[sent..sent + n]);
            self.end_frame(at);
            self.conn_send_window -= n as i32;
            if let Some(s) = self.streams.get_mut(&stream_id) {
                s.send_window -= n as i32;
            }
            sent += n;
        }
        if data.is_empty() && end_stream {
            let at = self.begin_frame(FrameType::Data, frame_flags::END_STREAM, stream_id);
            self.end_frame(at);
        }
        if end_stream && sent == data.len() {
            self.local_end_stream(stream_id);
        }
        sent
    }

    /// Sends an interim (1xx) response head, an HTTP/1 one, as a HEADERS frame without
    /// END_STREAM (T503; `h2s_snd_fhdrs` for a 1xx). False if `head` is not a 1xx head.
    pub fn send_interim(&mut self, stream_id: u32, head: &[u8]) -> bool {
        if self.streams.get(&stream_id).is_some_and(|s| matches!(s.state, H2StreamState::Reset(_))) {
            return true;
        }
        let head_str = String::from_utf8_lossy(head);
        let mut lines = head_str.lines();
        let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse::<u16>().ok());
        let Some(status) = status.filter(|s| (100..200).contains(s)) else { return false };
        let headers = lines.filter_map(|line| line.split_once(':')).map(|(name, val)| (name.trim(), val.trim()));
        self.send_headers_frame(stream_id, status, headers, false);
        true
    }

    /// Sends the response's trailers as a HEADERS frame that ends the stream (T503;
    /// `h2s_snd_ftrl`), the names lowercased.
    pub fn send_trailers(&mut self, stream_id: u32, trailers: &[(&str, &str)]) -> bool {
        if self.streams.get(&stream_id).is_some_and(|s| matches!(s.state, H2StreamState::Reset(_))) {
            return true;
        }
        let at = self.begin_frame(FrameType::Headers, frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id);
        let mut lower = std::mem::take(&mut self.lower_name);
        for (name, val) in trailers {
            lower.clear();
            lower.push_str(name);
            lower.make_ascii_lowercase();
            self.encoder.encode_field(&lower, val, &mut self.tx_buf);
        }
        self.lower_name = lower;
        self.end_frame(at);
        self.local_end_stream(stream_id);
        true
    }

    /// The stream's state once we have sent END_STREAM.
    fn local_end_stream(&mut self, stream_id: u32) {
        self.streams.entry(stream_id).and_modify(|stream| {
            stream.state = match stream.state {
                H2StreamState::HalfClosedRemote => H2StreamState::Closed,
                _ => H2StreamState::HalfClosedLocal,
            };
        });
    }
}

impl crate::htx_mux::HtxStream for H2StreamCtx {
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
        matches!(self.state, H2StreamState::Reset(_))
    }
    fn req_head(&self) -> Option<&H2ReqHead> {
        self.req_head.as_deref()
    }
    fn take_req_head(&mut self) -> Option<Box<H2ReqHead>> {
        self.req_head.take()
    }
    fn bad_request(&self) -> bool {
        self.bad_request
    }
}

/// The h2 mux as the bridge drives it (T503, design section 2.4): its own methods, by a
/// `u64` id (an h2 id is 31 bits; one past that names no stream).
impl crate::htx_mux::HtxMux for H2MuxContext {
    type Stream = H2StreamCtx;

    fn stream(&self, id: u64) -> Option<&H2StreamCtx> {
        self.streams.get(&u32::try_from(id).ok()?)
    }

    fn stream_mut(&mut self, id: u64) -> Option<&mut H2StreamCtx> {
        self.streams.get_mut(&u32::try_from(id).ok()?)
    }

    /// As `h2_bridge::dispatch_next` picks: the lowest stream with its head that is
    /// neither served, closed nor reset.
    fn next_dispatch(&self) -> Option<u64> {
        self.streams
            .values()
            .find(|st| {
                !st.dispatched
                    && st.state != H2StreamState::Closed
                    && !matches!(st.state, H2StreamState::Reset(_))
                    && st.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Eoh))
            })
            .map(|st| u64::from(st.id))
    }

    fn give_back_head(&mut self, head: Box<H2ReqHead>) {
        H2MuxContext::give_back_head(self, head);
    }

    fn send_head(&mut self, id: u64, head: &[u8], end_stream: bool) -> bool {
        self.send_h1_head(u32::try_from(id).unwrap_or(u32::MAX), head, end_stream)
    }

    fn send_data(&mut self, id: u64, data: &[u8], end_stream: bool) -> usize {
        H2MuxContext::send_data(self, u32::try_from(id).unwrap_or(u32::MAX), data, end_stream)
    }

    fn send_trailers(&mut self, id: u64, trailers: &[(&str, &str)]) -> bool {
        H2MuxContext::send_trailers(self, u32::try_from(id).unwrap_or(u32::MAX), trailers)
    }

    fn send_interim(&mut self, id: u64, head: &[u8]) -> bool {
        H2MuxContext::send_interim(self, u32::try_from(id).unwrap_or(u32::MAX), head)
    }

    fn data_budget(&self, id: u64) -> usize {
        H2MuxContext::data_budget(self, u32::try_from(id).unwrap_or(u32::MAX))
    }

    /// Credits the stream and demuxes what waited, as `pump_request_body` does.
    fn rx_taken(&mut self, id: u64, n: usize) {
        H2MuxContext::rx_taken(self, u32::try_from(id).unwrap_or(u32::MAX), n);
        self.resume();
    }

    fn reset(&mut self, id: u64, why: crate::htx_mux::MuxReset) {
        let code = match why {
            crate::htx_mux::MuxReset::Cancel => H2Error::Cancel,
            crate::htx_mux::MuxReset::Internal => H2Error::InternalError,
            crate::htx_mux::MuxReset::Refused => H2Error::RefusedStream,
        };
        self.send_rst_stream(u32::try_from(id).unwrap_or(u32::MAX), code);
    }

    fn is_reset(&self, id: u64) -> bool {
        crate::htx_mux::HtxMux::stream(self, id).is_some_and(|s| matches!(s.state, H2StreamState::Reset(_)))
    }

    fn tx_pending(&self) -> bool {
        self.tx_buf.len() > self.tx_consumed
    }

    fn glitches(&self) -> u64 {
        self.glitch_count as u64
    }
}

/// Bytes of decoded header names and values a request may carry: `tune.bufsize` (16384)
/// less `tune.maxrewrite` (1024), the room HAProxy's request buffer gives a head.
const MAX_REQUEST_HEAD_BYTES: usize = 16384 - 1024;

/// Header fields a request may carry once converted (HAProxy's `tune.http.maxhdr` 101,
/// less one: measured, host + 99 headers pass and host + 100 are refused).
const MAX_REQUEST_HEADERS: usize = 100;

/// Trailer fields a request may carry: HAProxy's `tune.http.maxhdr` (101). Measured: 101
/// fields pass, 102 are RST_STREAM PROTOCOL_ERROR.
const MAX_REQUEST_TRAILERS: usize = 101;

/// The room HAProxy's 16 KB rx buffer leaves trailers, each field costing its name and
/// value plus [`TRAILER_BLOCK_OVERHEAD`]. Measured: one field of 16327 decoded bytes
/// passes and of 16328 is reset; five of 3259 pass and five of 3261 are reset.
const MAX_REQUEST_TRAILER_ROOM: usize = 16335;
const TRAILER_BLOCK_OVERHEAD: usize = 8;

/// HTTP/2 Multiplexer.
#[derive(Debug, Clone, Copy, Default)]
pub struct MuxH2;

impl Mux for MuxH2 {
    type Ctx = H2MuxContext;

    fn ops(&self) -> &'static MuxOps {
        &H2_OPS
    }

    fn init(&self, conn: ConnId, is_server: bool) -> io::Result<Self::Ctx> {
        let mut ctx = H2MuxContext::new(conn, is_server);

        if !is_server {
            // Client sends connection preface: 24-byte magic + initial SETTINGS frame
            ctx.tx_buf.extend_from_slice(H2_CONN_PREFACE);
            let settings_frame = Frame::Settings {
                flags: 0,
                settings: vec![
                    (
                        SettingsParameter::MaxConcurrentStreams,
                        ctx.max_concurrent_streams,
                    ),
                    (
                        SettingsParameter::InitialWindowSize,
                        ctx.local_initial_window as u32,
                    ),
                ],
            };
            ctx.enqueue_frame(&settings_frame);
        }

        Ok(ctx)
    }

    fn parse(&self, ctx: &mut Self::Ctx, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() && ctx.rx_buf.is_empty() {
            return Ok(0);
        }
        if ctx.conn_state == H2ConnState::GoAwaySent {
            // No frame is processed after a connection error: do not keep what follows.
            return Ok(input.len());
        }

        ctx.rx_buf.extend_from_slice(input);
        let mut consumed = 0;

        // Step 1: Server connection preface exchange
        if ctx.is_server && ctx.conn_state == H2ConnState::ExpectPreface {
            if ctx.rx_buf.len() < H2_CONN_PREFACE.len() {
                // Incomplete client preface, await more bytes
                return Ok(input.len());
            }

            if &ctx.rx_buf[..H2_CONN_PREFACE.len()] != H2_CONN_PREFACE {
                ctx.conn_state = H2ConnState::Error(H2Error::ProtocolError);
                ctx.send_goaway(0, H2Error::ProtocolError, b"invalid connection preface");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid HTTP/2 connection preface",
                ));
            }

            consumed += H2_CONN_PREFACE.len();
            ctx.conn_state = H2ConnState::ExpectSettings;

            // Server immediately replies with its own initial SETTINGS frame. A limit of 0
            // is not advertised (HAProxy sends no MAX_CONCURRENT_STREAMS then), yet every
            // stream is refused.
            let mut settings = Vec::with_capacity(2);
            if ctx.max_concurrent_streams > 0 {
                settings.push((SettingsParameter::MaxConcurrentStreams, ctx.max_concurrent_streams));
            }
            settings.push((SettingsParameter::InitialWindowSize, ctx.local_initial_window as u32));
            let server_settings = Frame::Settings {
                flags: 0,
                settings,
            };
            ctx.enqueue_frame(&server_settings);
        }

        // Step 2: Demultiplex incoming frames
        while ctx.rx_buf.len() >= consumed + FRAME_HEADER_LEN {
            if ctx.conn_state == H2ConnState::GoAwaySent {
                break;
            }
            if ctx.tx_buf.len() - ctx.tx_consumed > TX_ROOM {
                // The output the client has not read is full: no frame is processed, so
                // none is answered, until it reads (`H2_CF_DEM_MROOM`, T235).
                break;
            }
            let slice = &ctx.rx_buf[consumed..];
            let header = FrameHeader::decode(slice)?;
            if header.length > DEFAULT_MAX_FRAME_SIZE {
                // Longer than the SETTINGS_MAX_FRAME_SIZE we advertise (we send none, so the
                // default 16384): refused on its header, before the payload is buffered
                // (RFC 9113 section 4.2; HAProxy: GOAWAY FRAME_SIZE_ERROR, last stream processed).
                ctx.send_goaway(ctx.last_client_stream_id, H2Error::FrameSizeError, b"frame too large");
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/2 frame larger than max frame size"));
            }

            let total_frame_len = FRAME_HEADER_LEN + header.length as usize;
            if slice.len() < total_frame_len {
                // Incomplete frame payload, await more bytes
                break;
            }
            if Self::demux_blocked(ctx, &header) {
                break;
            }

            let payload = &slice[FRAME_HEADER_LEN..total_frame_len];
            if header.frame_type == FrameType::Headers {
                // The block is decoded from a copy in memory the connection keeps, not a
                // frame of its own (T437).
                let mut block = std::mem::take(&mut ctx.block_scratch);
                block.clear();
                match Frame::headers_block(&header, payload) {
                    Ok(b) => block.extend_from_slice(b),
                    Err(e) => {
                        let code = if e.kind() == io::ErrorKind::InvalidInput { H2Error::FrameSizeError } else { H2Error::ProtocolError };
                        ctx.send_goaway(header.stream_id, code, b"frame decode error");
                        return Err(e);
                    }
                }
                consumed += total_frame_len;
                ctx.rx_frame_len = header.length;
                let r = Self::handle_headers(ctx, header.flags, header.stream_id, &block);
                ctx.block_scratch = block;
                r?;
                continue;
            }
            let frame = match Frame::decode(&header, payload) {
                Ok(f) => f,
                Err(e) => {
                    // InvalidInput marks FRAME_SIZE_ERROR (see `h2::strip_padding`).
                    let code = if e.kind() == io::ErrorKind::InvalidInput {
                        H2Error::FrameSizeError
                    } else {
                        H2Error::ProtocolError
                    };
                    ctx.send_goaway(header.stream_id, code, b"frame decode error");
                    return Err(e);
                }
            };

            consumed += total_frame_len;
            ctx.rx_frame_len = header.length;
            Self::handle_frame(ctx, frame)?;
        }

        // Compact consumed bytes from rx_buf
        if consumed > 0 {
            ctx.rx_buf.drain(..consumed);
        }

        Ok(input.len())
    }

    fn rcv_buf(&self, ctx: &mut Self::Ctx, sd: &mut SeDesc, out: &mut [u8]) -> io::Result<usize> {
        let stream_id = match sd.endpoint {
            Endpoint::MuxStream { stream, .. } => stream,
            _ => return Ok(0),
        };

        let stream = match ctx.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(0),
        };

        // Export parsed HTX data to output buffer; a head kept as text goes before the
        // blocks, which then start with its blank line.
        let mut wire = stream.rx_htx.to_h1_wire();
        if let Some(h) = &stream.req_head {
            let head = h.wire();
            wire.splice(..0, head[..head.len() - 2].iter().copied());
        }
        if wire.is_empty() {
            return Ok(0);
        }
        let n = wire.len().min(out.len());
        out[..n].copy_from_slice(&wire[..n]);
        Ok(n)
    }

    fn snd_buf(&self, ctx: &mut Self::Ctx, sd: &mut SeDesc, input: &[u8]) -> io::Result<usize> {
        let stream_id = match sd.endpoint {
            Endpoint::MuxStream { stream, .. } => stream,
            _ => return Ok(0),
        };

        // Flow control check
        let stream_win = ctx.streams.get(&stream_id).map_or(0, |s| s.send_window);
        let available_win = ctx.conn_send_window.min(stream_win);

        if available_win <= 0 {
            // Blocked by flow control: cannot transmit DATA frame until WINDOW_UPDATE arrives
            return Ok(0);
        }

        let send_len = (input.len())
            .min(available_win as usize)
            .min(ctx.max_frame_size as usize);
        if send_len == 0 {
            return Ok(0);
        }

        let data_slice = &input[..send_len];
        let data_frame = Frame::Data {
            flags: 0,
            stream_id,
            data: data_slice.to_vec(),
        };
        ctx.enqueue_frame(&data_frame);

        // Deduct from flow control windows
        ctx.conn_send_window -= send_len as i32;
        if let Some(stream) = ctx.streams.get_mut(&stream_id) {
            stream.send_window -= send_len as i32;
        }

        Ok(send_len)
    }

    fn pending_output<'a>(&self, ctx: &'a Self::Ctx) -> &'a [u8] {
        if ctx.tx_consumed >= ctx.tx_buf.len() {
            &[]
        } else {
            &ctx.tx_buf[ctx.tx_consumed..]
        }
    }

    fn consume_output(&self, ctx: &mut Self::Ctx, n: usize) {
        ctx.tx_consumed += n;
        if ctx.tx_consumed >= ctx.tx_buf.len() {
            ctx.tx_buf.clear();
            ctx.tx_consumed = 0;
        } else if ctx.tx_consumed >= TX_ROOM && ctx.tx_consumed >= ctx.tx_buf.len() / 2 {
            // A client that reads part of what waits, never all of it, would otherwise keep
            // every byte ever sent on the connection here (T288). What was read goes once it
            // is at least half the buffer: the bytes moved are fewer than those let go.
            ctx.tx_buf.drain(..ctx.tx_consumed);
            ctx.tx_consumed = 0;
        }
    }

    fn shut(&self, ctx: &mut Self::Ctx, sd: &mut SeDesc, mode: ShutMode) {
        let stream_id = match sd.endpoint {
            Endpoint::MuxStream { stream, .. } => stream,
            _ => return,
        };

        match mode {
            ShutMode::Reset => {
                ctx.send_rst_stream(stream_id, H2Error::Cancel);
            }
            ShutMode::Normal => {
                // Send an empty DATA frame with END_STREAM flag to half-close local
                let end_frame = Frame::Data {
                    flags: frame_flags::END_STREAM,
                    stream_id,
                    data: Vec::new(),
                };
                ctx.enqueue_frame(&end_frame);
                if let Some(stream) = ctx.streams.get_mut(&stream_id) {
                    stream.state = match stream.state {
                        H2StreamState::HalfClosedRemote => H2StreamState::Closed,
                        _ => H2StreamState::HalfClosedLocal,
                    };
                    stream.is_shut = true;
                }
            }
        }
    }

    fn avail_streams(&self, ctx: &Self::Ctx) -> u32 {
        if ctx.is_shut || ctx.conn_state == H2ConnState::Closed {
            0
        } else {
            ctx.max_concurrent_streams
                .saturating_sub(ctx.streams.len() as u32)
        }
    }

    fn used_streams(&self, ctx: &Self::Ctx) -> u32 {
        ctx.streams.len() as u32
    }
}

impl MuxH2 {
    /// Whether the frame `header` announces must wait: DATA for a stream that already holds
    /// its receive window of bytes (`H2_CF_DEM_SFULL`), or that would need more of the
    /// connection's receive buffers than are free (`H2_CF_DEM_RXBUF`: `h2s_get_rxbuf` finds
    /// no slot). The window is not policed -- HAProxy does not either -- but what a client
    /// sends past it stays in the socket, and so do the HEADERS behind it: streams whose
    /// server is slow to connect hold the demux, not a pending connect each (T322, MY-10:
    /// `HAProxy` holds 7 streams of the red team's shape, Ibex opened all 100).
    ///
    /// The first frame is let through whatever the buffers hold only when no stream holds
    /// any, so that a pool smaller than a frame cannot wedge the connection (`HAProxy`
    /// takes what fits of a frame and so always moves).
    fn demux_blocked(ctx: &H2MuxContext, header: &FrameHeader) -> bool {
        if header.frame_type != crate::h2::FrameType::Data || !ctx.is_server {
            return false;
        }
        let limit = usize::try_from(ctx.local_initial_window).unwrap_or(0).max(DEFAULT_MAX_FRAME_SIZE as usize);
        let Some(s) = ctx.streams.get(&header.stream_id) else { return false };
        if s.state != H2StreamState::Open {
            return false;
        }
        let len = header.length as usize;
        if s.rx_buffered > 0 && s.rx_buffered + len > limit.max(s.rx_limit) {
            return true;
        }
        let held: usize = ctx.streams.values().map(|s| s.rx_slots(0)).sum();
        held > 0 && held - s.rx_slots(0) + s.rx_slots(len) > ctx.rx_slots()
    }

    fn process_headers_block(
        ctx: &mut H2MuxContext,
        stream_id: u32,
        flags: u8,
        header_block: &[u8],
    ) -> io::Result<()> {
        // The fields are decoded into memory the connection keeps (T437), taken out while
        // the block is handled.
        let mut decoded = std::mem::take(&mut ctx.decoded);
        let r = Self::process_decoded_block(ctx, stream_id, flags, header_block, &mut decoded);
        ctx.decoded = decoded;
        r
    }

    fn process_decoded_block(
        ctx: &mut H2MuxContext,
        stream_id: u32,
        flags: u8,
        header_block: &[u8],
        decoded: &mut DecodedFields,
    ) -> io::Result<()> {
        if !ctx.streams.contains_key(&stream_id) && stream_id <= ctx.highest_opened {
            // HEADERS on a stream that is closed, or that was skipped and so can no longer
            // be opened: a connection error STREAM_CLOSED (RFC 9113 section 5.1.1; HAProxy
            // measured: GOAWAY with the highest stream id seen, then close). It was a stream
            // error, and a client that reads nothing had a reply queued for each (T235).
            ctx.send_goaway(ctx.highest_opened, H2Error::StreamClosed, b"HEADERS on a closed stream");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HEADERS on a closed stream"));
        }
        // Decoded before anything may refuse the stream: the client's encoder has added
        // these fields to its table whatever becomes of the stream (T235).
        if let Err(e) = ctx.decoder.decode_into(header_block, decoded) {
            ctx.send_goaway(stream_id, e, b"HPACK compression error");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HPACK compression error"));
        }

        if !ctx.streams.contains_key(&stream_id) {
            let active = ctx
                .streams
                .values()
                .filter(|s| matches!(s.state, H2StreamState::Open | H2StreamState::HalfClosedRemote | H2StreamState::HalfClosedLocal))
                .count();
            if active >= ctx.max_concurrent_streams as usize {
                ctx.send_rst_stream(stream_id, H2Error::RefusedStream);
                return Ok(());
            }
        }

        // A second HEADERS on a stream whose head is complete is the request's trailers
        // (RFC 9113 section 8.1): they end the stream, carry no pseudo-header, and are kept
        // as trailer blocks for the data path to forward.
        if ctx.is_server
            && ctx.streams.get(&stream_id).is_some_and(|s| s.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Eoh)))
        {
            let ended = ctx.streams.get(&stream_id).is_some_and(|s| s.rx_htx.is_eom());
            if ended {
                ctx.send_rst_stream(stream_id, H2Error::StreamClosed);
                return Ok(());
            }
            // Trailers get the room HAProxy's rx buffer gives them (T271): past it, a stream
            // error, so a client cannot park decoded trailers of any size in each stream.
            let trailer_bytes: usize = decoded.iter().map(|(n, v)| n.len() + v.len()).sum();
            let too_big = decoded.len() > MAX_REQUEST_TRAILERS
                || trailer_bytes + TRAILER_BLOCK_OVERHEAD * decoded.len() > MAX_REQUEST_TRAILER_ROOM;
            // A trailer field is checked as `http_trailers_to_htx` checks it (T449): one
            // with CR or LF would end the chunked body early for the server.
            let malformed = crate::h2::check_trailer_fields(decoded.iter()).is_err();
            if (flags & frame_flags::END_STREAM) == 0 || too_big || malformed || decoded.iter().any(|(n, _)| n.starts_with(':')) {
                ctx.send_rst_stream(stream_id, H2Error::ProtocolError);
                return Ok(());
            }
            ctx.streams.entry(stream_id).and_modify(|stream| {
                for (name, value) in decoded.iter() {
                    stream.rx_htx.push(HtxBlock::Trailer(HeaderField { name: name.to_string(), value: value.to_string() }));
                }
                stream.rx_htx.push(HtxBlock::Eot);
                stream.rx_htx.push(HtxBlock::Eom);
                stream.state = H2StreamState::HalfClosedRemote;
            });
            return Ok(());
        }

        // HAProxy keeps at most tune.http.maxhdr - 1 (100) header fields in a request,
        // counting the host made from :authority; more is a stream error PROTOCOL_ERROR.
        let regular = decoded.iter().filter(|(n, _)| !n.starts_with(':')).count();
        let host_from_authority = decoded.iter().any(|(n, _)| n == ":authority")
            && !decoded.iter().any(|(n, _)| n == "host");
        let too_many = ctx.is_server && regular + usize::from(host_from_authority) > MAX_REQUEST_HEADERS;
        // The decoded request must fit HAProxy's request buffer less its rewrite reserve
        // (tune.bufsize 16384 - tune.maxrewrite 1024): one-byte HPACK references to a large
        // table entry otherwise decode to megabytes per request (T242, fuzz h2_mux).
        // Measured: four 3800-byte fields pass, four 3850-byte fields are RST_STREAM
        // PROTOCOL_ERROR.
        let too_big = ctx.is_server
            && decoded.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>() > MAX_REQUEST_HEAD_BYTES;

        // Each field is checked before any head is written from it (T449): a CR LF in a
        // value, a name or a pseudo-header written into the HTTP/1 head is a header, or a
        // request, the server trusts. Malformed is a stream error; a method or URI HAProxy
        // takes and then refuses is a 400.
        // A client connection's response gets the name and value checks of
        // `h2_make_htx_response` (no runtime path speaks h2 to a server yet: `proto h2` on
        // a server is refused by the parser).
        let fields = decoded.iter();
        let checked = if ctx.is_server {
            crate::h2::check_request_fields(fields, ctx.relaxed_path)
        } else {
            crate::h2::check_response_fields(fields).map(|()| false)
        };
        // A server connection's request head is written as HTTP/1.1 text, in memory a
        // stream before it used (T437); what that form does not take keeps the HTX blocks.
        let as_text = ctx.is_server && !too_many && !too_big;
        let spare_htx = ctx.spare_htx.pop();
        let stream = ctx.streams.entry(stream_id).or_insert_with(|| {
            let mut s = H2StreamCtx::new(
                stream_id,
                ctx.remote_initial_window,
                ctx.local_initial_window,
            );
            if let Some(htx) = spare_htx {
                s.rx_htx = htx;
            }
            s
        });

        stream.state = H2StreamState::Open;
        ctx.highest_opened = ctx.highest_opened.max(stream_id);

        // Extract pseudo-headers and construct HTX blocks
        stream.bad_request = checked == Ok(true);
        let converted = if too_many || too_big || checked.is_err() {
            Err(())
        } else if as_text {
            let mut head = stream.req_head.take().or_else(|| ctx.spare_heads.pop()).unwrap_or_default();
            if head.write(decoded).is_ok() {
                stream.req_content_length = head.get_header("content-length").and_then(|v| v.trim().parse::<usize>().ok());
                stream.req_head = Some(head);
                stream.rx_htx.push(HtxBlock::Eoh);
                Ok(())
            } else {
                ctx.spare_heads.push(head);
                Err(())
            }
        } else {
            // A response head (a client connection), as HTX blocks.
            crate::htx::pseudo_headers_to_htx(decoded.to_fields(), HttpVersion::Http20).map(|blocks| blocks.into_iter().for_each(|b| stream.rx_htx.push(b))).map_err(|_| ())
        };
        if converted.is_err() {
            ctx.send_rst_stream(stream_id, H2Error::ProtocolError);
            return Ok(());
        }

        if (flags & frame_flags::END_STREAM) != 0 {
            stream.rx_htx.push(HtxBlock::Eom);
            stream.state = H2StreamState::HalfClosedRemote;
        }

        Ok(())
    }

    /// A HEADERS frame (`header_block` without its padding and priority fields).
    fn handle_headers(ctx: &mut H2MuxContext, flags: u8, stream_id: u32, header_block: &[u8]) -> io::Result<()> {
        if let Some(c_sid) = ctx.continuation_stream {
            // As `handle_frame` answers any other frame where a CONTINUATION was due.
            ctx.send_goaway(c_sid, H2Error::ProtocolError, b"expected CONTINUATION frame");
            return Ok(());
        }
        if stream_id == 0 {
            ctx.send_goaway(0, H2Error::ProtocolError, b"HEADERS on stream 0");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HEADERS on stream 0",
            ));
        }

        // Verify client stream parity (client streams must be odd)
        if ctx.is_server && stream_id.is_multiple_of(2) {
            ctx.send_goaway(
                stream_id,
                H2Error::ProtocolError,
                b"even stream id from client",
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Even stream ID received from client",
            ));
        }

        if ctx.is_server && stream_id > ctx.last_client_stream_id {
            ctx.last_client_stream_id = stream_id;
        }

        if ctx.is_server {
            ctx.total_streams = ctx.total_streams.saturating_add(1);
            if ctx.flood_config.max_total_streams > 0
                && ctx.total_streams >= ctx.flood_config.max_total_streams
            {
                ctx.send_goaway(
                    stream_id,
                    H2Error::NoError,
                    b"max-total-streams reached",
                );
                return Ok(());
            }
        }

        // (A block cannot pass 65536 bytes here: `parse` refuses a frame past 16384.)
        if (flags & frame_flags::END_HEADERS) == 0 {
            ctx.continuation_stream = Some(stream_id);
            ctx.continuation_flags = flags;
            ctx.continuation_buf = header_block.to_vec();
            ctx.continuation_count = 0;
            return Ok(());
        }

        Self::process_headers_block(ctx, stream_id, flags, header_block)
    }

    fn handle_frame(ctx: &mut H2MuxContext, frame: Frame) -> io::Result<()> {
        if let Some(c_sid) = ctx.continuation_stream {
            if let Frame::Continuation {
                stream_id,
                flags,
                header_block,
            } = frame
            {
                if stream_id != c_sid {
                    ctx.send_goaway(stream_id, H2Error::ProtocolError, b"continuation on wrong stream");
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "CONTINUATION on wrong stream",
                    ));
                }
                ctx.continuation_count = ctx.continuation_count.saturating_add(1);
                if ctx.continuation_count > 100
                    || ctx.continuation_buf.len() + header_block.len() > 65536
                {
                    ctx.send_goaway(
                        stream_id,
                        H2Error::EnhanceYourCalm,
                        b"CONTINUATION flood / header list too large",
                    );
                    return Ok(());
                }
                ctx.continuation_buf.extend_from_slice(&header_block);
                if (flags & frame_flags::END_HEADERS) != 0 {
                    let combined_flags = ctx.continuation_flags;
                    let combined_block = std::mem::take(&mut ctx.continuation_buf);
                    ctx.continuation_stream = None;
                    ctx.continuation_count = 0;
                    return Self::process_headers_block(ctx, c_sid, combined_flags, &combined_block);
                }
                return Ok(());
            }

            ctx.send_goaway(c_sid, H2Error::ProtocolError, b"expected CONTINUATION frame");
            return Ok(());
        }

        match frame {
            Frame::Settings { flags, settings } => {
                if (flags & frame_flags::ACK) != 0 {
                    // Settings ACK received from peer
                    ctx.settings_ack_received = true;
                } else {
                    ctx.settings_count = ctx.settings_count.saturating_add(1);
                    if ctx.settings_count > 100 {
                        ctx.send_goaway(0, H2Error::EnhanceYourCalm, b"SETTINGS flood detected");
                        return Ok(());
                    }
                    // Peer sent settings: validate them all before applying any (RFC 9113
                    // section 6.5.2). HAProxy answers GOAWAY with the last stream processed and
                    // does not acknowledge.
                    let invalid = settings.iter().find_map(|(param, val)| match param {
                        SettingsParameter::EnablePush if *val > 1 => Some(H2Error::ProtocolError),
                        SettingsParameter::InitialWindowSize if *val > MAX_WINDOW_SIZE as u32 => {
                            Some(H2Error::FlowControlError)
                        }
                        SettingsParameter::MaxFrameSize
                            if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(val) =>
                        {
                            Some(H2Error::ProtocolError)
                        }
                        _ => None,
                    });
                    if let Some(code) = invalid {
                        ctx.send_goaway(ctx.last_client_stream_id, code, b"invalid SETTINGS value");
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP/2 SETTINGS value"));
                    }
                    // Peer sent settings: apply parameters
                    for (param, val) in settings {
                        match param {
                            SettingsParameter::InitialWindowSize => {
                                let new_win = val as i32;
                                let delta = new_win - ctx.remote_initial_window;
                                // A stream window past 2^31-1 is a connection error
                                // FLOW_CONTROL_ERROR (RFC 9113 section 6.9.2). HAProxy keeps
                                // `sws + miw` in an int32_t that wraps: no error, the stream
                                // stalls; the RFC's answer is kept here (checked before
                                // anything is applied).
                                if delta > 0 && ctx.streams.values().any(|st| st.send_window.checked_add(delta).is_none()) {
                                    ctx.send_goaway(
                                        ctx.last_client_stream_id,
                                        H2Error::FlowControlError,
                                        b"SETTINGS_INITIAL_WINDOW_SIZE overflows a stream window",
                                    );
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "SETTINGS_INITIAL_WINDOW_SIZE overflows a stream window",
                                    ));
                                }
                                ctx.remote_initial_window = new_win;
                                for stream in ctx.streams.values_mut() {
                                    stream.send_window = stream.send_window.saturating_add(delta);
                                }
                            }
                            // The peer's limit bounds the streams we open: a client's
                            // limits the server's pushes (which a proxy never sends), not
                            // its own requests, whose limit is the one advertised (T280).
                            SettingsParameter::MaxConcurrentStreams if !ctx.is_server => {
                                ctx.max_concurrent_streams = val;
                            }
                            SettingsParameter::MaxConcurrentStreams => {}
                            SettingsParameter::MaxFrameSize => {
                                ctx.max_frame_size = val;
                            }
                            SettingsParameter::HeaderTableSize => {
                                // The peer's decoder may hold this much; the encoder uses no
                                // more than the 4096 it starts with (a larger table would need
                                // a size update, and grows with every header sent; T235).
                                ctx.encoder.dynamic_table.set_max_size((val as usize).min(4096));
                            }
                            _ => {}
                        }
                    }

                    // Acknowledge settings with an empty SETTINGS ACK frame
                    let ack = Frame::Settings {
                        flags: frame_flags::ACK,
                        settings: Vec::new(),
                    };
                    ctx.enqueue_frame(&ack);

                    if ctx.conn_state == H2ConnState::ExpectSettings {
                        ctx.conn_state = H2ConnState::Open;
                    }
                }
            }


            Frame::Data {
                flags,
                stream_id,
                data,
            } => {
                if stream_id == 0 {
                    ctx.send_goaway(0, H2Error::ProtocolError, b"DATA on stream 0");
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "DATA on stream 0",
                    ));
                }

                // Padding counts toward flow control (RFC 9113 section 6.1).
                let data_len = ctx.rx_frame_len.max(data.len() as u32).min(i32::MAX as u32) as i32;
                ctx.conn_recv_window = ctx.conn_recv_window.saturating_sub(data_len);

                let after_end = ctx.is_server
                    && ctx.streams.get(&stream_id).is_some_and(|s| s.state == H2StreamState::HalfClosedRemote);
                if after_end {
                    // DATA after the client's END_STREAM: a stream error STREAM_CLOSED
                    // (RFC 9113 section 5.1; HAProxy measured: RST_STREAM 5, the request is
                    // not answered), and the bytes are not kept.
                    ctx.send_rst_stream(stream_id, H2Error::StreamClosed);
                } else if let Some(stream) = ctx.streams.get_mut(&stream_id) {
                    stream.recv_window = stream.recv_window.saturating_sub(data_len);
                    // Kept only while the stream receives: once the response is over (half-
                    // closed local) or the stream reset, nothing will take the body any more,
                    // so it is counted and dropped.
                    if !data.is_empty() && stream.state == H2StreamState::Open {
                        stream.rx_buffered += data.len();
                        stream.rx_fill += data.len();
                        stream.rx_htx.push(HtxBlock::Data(data));
                    }
                    if (flags & frame_flags::END_STREAM) != 0 {
                        match stream.state {
                            H2StreamState::HalfClosedLocal => stream.state = H2StreamState::Closed,
                            H2StreamState::Open => {
                                stream.rx_htx.push(HtxBlock::Eom);
                                stream.state = H2StreamState::HalfClosedRemote;
                            }
                            // A reset stream stays reset.
                            _ => {}
                        }
                    }
                }

                if (flags & frame_flags::END_STREAM) == 0 {
                    ctx.grow_rx_window(stream_id);
                }

                // Automatic window replenishment: once opened wide, when a billion bytes
                // went; before, when the window falls below 32 KB.
                let (low, full) = if ctx.rx_window_opened { (1 << 30, i32::MAX) } else { (32768, DEFAULT_INITIAL_WINDOW_SIZE) };
                if ctx.conn_recv_window < low {
                    let replenish = (i64::from(full) - i64::from(ctx.conn_recv_window)).clamp(0, i64::from(i32::MAX)) as u32;
                    ctx.send_window_update(0, replenish);
                }
            }

            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                // A frame for a stream that was never opened is a connection error
                // (`h2_frame_check_vs_state`, measured: GOAWAY PROTOCOL_ERROR, last stream
                // the highest one seen); one for a closed stream is ignored whatever its
                // increment (`h2c_handle_window_update`).
                let idle = stream_id != 0
                    && ctx.is_server
                    && stream_id > ctx.last_client_stream_id
                    && !ctx.streams.contains_key(&stream_id);
                if idle {
                    ctx.send_goaway(ctx.last_client_stream_id, H2Error::ProtocolError, b"WINDOW_UPDATE on an idle stream");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "WINDOW_UPDATE on an idle stream"));
                }
                if increment == 0 {
                    // Zero on the connection is a connection error, on a stream a stream
                    // error (RFC 9113 section 6.9, `h2c_handle_window_update`, measured).
                    if stream_id == 0 {
                        ctx.send_goaway(
                            ctx.last_client_stream_id,
                            H2Error::ProtocolError,
                            b"zero window update increment",
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Zero window update increment",
                        ));
                    }
                    if ctx.streams.contains_key(&stream_id) {
                        ctx.send_rst_stream(stream_id, H2Error::ProtocolError);
                    }
                    return Ok(());
                }

                // Past 2^31-1 the window overflows (RFC 9113 6.9.1): a connection error for
                // the connection window, a stream error for a stream's. HAProxy sends
                // GOAWAY / RST_STREAM FLOW_CONTROL_ERROR (measured, T297).
                if stream_id == 0 {
                    match ctx.conn_send_window.checked_add(increment as i32) {
                        Some(w) if increment <= i32::MAX as u32 => ctx.conn_send_window = w,
                        _ => {
                            ctx.send_goaway(
                                ctx.last_client_stream_id,
                                H2Error::FlowControlError,
                                b"connection window overflow",
                            );
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "WINDOW_UPDATE overflows the connection window",
                            ));
                        }
                    }
                } else if let Some(stream) = ctx.streams.get_mut(&stream_id) {
                    match stream.send_window.checked_add(increment as i32) {
                        Some(w) if increment <= i32::MAX as u32 => stream.send_window = w,
                        _ => ctx.send_rst_stream(stream_id, H2Error::FlowControlError),
                    }
                }
            }

            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                ctx.reset_count = ctx.reset_count.saturating_add(1);
                ctx.glitch_count = ctx.glitch_count.saturating_add(1);

                if ctx.flood_config.glitches_threshold > 0 {
                    let threshold_75 = (ctx.flood_config.glitches_threshold * 75) / 100;
                    if ctx.glitch_count >= ctx.flood_config.glitches_threshold {
                        ctx.send_goaway(
                            ctx.last_client_stream_id,
                            H2Error::EnhanceYourCalm,
                            b"glitches-threshold exceeded",
                        );
                        return Ok(());
                    } else if ctx.glitch_count >= threshold_75 && !ctx.graceful_goaway_sent {
                        ctx.graceful_goaway_sent = true;
                        ctx.goaway_sent = Some((0x7fff_ffff, H2Error::NoError));
                        let frame = Frame::GoAway {
                            last_stream_id: 0x7fff_ffff,
                            error_code: H2Error::NoError,
                            debug_data: b"graceful shutdown (glitches threshold 75%)".to_vec(),
                        };
                        ctx.enqueue_frame(&frame);
                    }
                }

                ctx.stream_reset(stream_id, error_code);
            }

            Frame::GoAway {
                last_stream_id,
                error_code,
                ..
            } => {
                ctx.goaway_received = Some((last_stream_id, error_code));
                ctx.conn_state = H2ConnState::GoAwayReceived;
            }

            Frame::Ping { flags, opaque_data } => {
                if (flags & frame_flags::ACK) == 0 {
                    ctx.ping_count = ctx.ping_count.saturating_add(1);
                    if ctx.ping_count > 100 {
                        ctx.send_goaway(0, H2Error::EnhanceYourCalm, b"PING flood detected");
                        return Ok(());
                    }
                    // Send PING ACK reply with exact same opaque_data
                    let ping_ack = Frame::Ping {
                        flags: frame_flags::ACK,
                        opaque_data,
                    };
                    ctx.enqueue_frame(&ping_ack);
                }
            }

            Frame::Continuation { stream_id, .. } => {
                ctx.send_goaway(
                    stream_id,
                    H2Error::ProtocolError,
                    b"unexpected CONTINUATION frame",
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected CONTINUATION frame",
                ));
            }

            // RFC 9113 5.3.1: a stream cannot depend on itself, a connection error here
            // (`h2c_handle_priority`, measured: GOAWAY PROTOCOL_ERROR). Otherwise a client
            // could use it, with a request before it in the same read, as a reset trigger
            // (MadeYouReset, T309).
            Frame::Priority {
                stream_id,
                stream_dependency,
                ..
            } if stream_dependency == stream_id => {
                ctx.send_goaway(
                    ctx.last_client_stream_id,
                    H2Error::ProtocolError,
                    b"PRIORITY depends on itself",
                );
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PRIORITY depends on itself",
                ));
            }

            // HEADERS do not come here: `parse` hands them to `handle_headers` (T437).
            Frame::Headers { .. }
            | Frame::Priority { .. }
            | Frame::PushPromise { .. }
            | Frame::Unknown { .. } => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htx::HeaderField;

    #[test]
    fn test_server_preface_exchange_and_settings() {
        let mux = MuxH2;
        let mut ctx = mux.init(ConnId(1), true).expect("init");

        // Client sends preface + initial settings
        let mut client_bytes = Vec::new();
        client_bytes.extend_from_slice(H2_CONN_PREFACE);
        let settings = Frame::Settings {
            flags: 0,
            settings: vec![(SettingsParameter::InitialWindowSize, 131_072)],
        };
        client_bytes.extend_from_slice(&settings.encode());

        let consumed = mux.parse(&mut ctx, &client_bytes).expect("parse preface");
        assert_eq!(consumed, client_bytes.len());
        assert_eq!(ctx.conn_state, H2ConnState::Open);
        assert_eq!(ctx.remote_initial_window, 131_072);

        // Server should have enqueued its SETTINGS and SETTINGS ACK
        let pending = mux.pending_output(&ctx);
        assert!(!pending.is_empty());
    }

    #[test]
    fn test_stream_multiplexing_and_htx_parsing() {
        let mux = MuxH2;
        let mut ctx = mux.init(ConnId(1), true).expect("init");

        // Handshake
        let mut handshake = Vec::new();
        handshake.extend_from_slice(H2_CONN_PREFACE);
        handshake.extend_from_slice(
            &Frame::Settings {
                flags: 0,
                settings: vec![],
            }
            .encode(),
        );
        mux.parse(&mut ctx, &handshake).expect("handshake");

        // Client sends request on Stream 1
        let mut enc = HpackEncoder::new();
        let headers1 = vec![
            HeaderField {
                name: ":method".into(),
                value: "GET".into(),
            },
            HeaderField {
                name: ":path".into(),
                value: "/stream1".into(),
            },
        ];
        let block1 = enc.encode(&headers1);
        let frame1 = Frame::Headers {
            flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
            stream_id: 1,
            header_block: block1,
        };

        // Client sends request on Stream 3
        let headers3 = vec![
            HeaderField {
                name: ":method".into(),
                value: "POST".into(),
            },
            HeaderField {
                name: ":path".into(),
                value: "/stream3".into(),
            },
        ];
        let block3 = enc.encode(&headers3);
        let frame3 = Frame::Headers {
            flags: frame_flags::END_HEADERS,
            stream_id: 3,
            header_block: block3,
        };
        let data3 = Frame::Data {
            flags: frame_flags::END_STREAM,
            stream_id: 3,
            data: b"hello stream 3".to_vec(),
        };

        let mut req_stream = Vec::new();
        req_stream.extend_from_slice(&frame1.encode());
        req_stream.extend_from_slice(&frame3.encode());
        req_stream.extend_from_slice(&data3.encode());

        mux.parse(&mut ctx, &req_stream).expect("parse requests");

        assert_eq!(mux.used_streams(&ctx), 2);
        let s1 = ctx.streams.get(&1).unwrap();
        assert_eq!(s1.request_uri(), Some("/stream1"));
        assert_eq!(s1.state, H2StreamState::HalfClosedRemote);

        let s3 = ctx.streams.get(&3).unwrap();
        assert_eq!(s3.request_uri(), Some("/stream3"));
        assert_eq!(s3.rx_htx.body_bytes(), b"hello stream 3");
    }

    #[test]
    fn response_data_stops_at_the_windows_and_resumes_after_a_window_update() {
        let mux = MuxH2;
        let mut ctx = mux.init(ConnId(1), true).expect("init");
        ctx.streams.insert(1, H2StreamCtx::new(1, 10, 100));
        assert!(!ctx.send_h1_head(1, b"garbage", false));
        assert!(!ctx.send_h1_head(1, b"", false));
        assert!(!ctx.send_h1_head(1, b"HTTP/1.1 abc", false));
        assert!(ctx.send_h1_head(1, b"HTTP/1.1 200 OK\r\nContent-Length: 25", false));
        assert_eq!(ctx.data_budget(1), 10);
        // 25 bytes against a 10-byte stream window: 10 go, END_STREAM is not sent.
        assert_eq!(ctx.send_data(1, &[7; 25], true), 10);
        assert_eq!(ctx.data_budget(1), 0);
        assert_eq!(ctx.send_data(1, &[7; 15], true), 0);
        ctx.streams.get_mut(&1).unwrap().send_window += 15;
        assert_eq!(ctx.send_data(1, &[7; 15], true), 15);
        assert_eq!(ctx.streams.get(&1).unwrap().state, H2StreamState::HalfClosedLocal);
        // A stream that is gone takes and discards anything; an empty END_STREAM needs no window.
        assert_eq!(ctx.data_budget(3), usize::MAX);
        assert_eq!(ctx.send_data(3, &[1; 5], true), 5);
        ctx.streams.insert(5, H2StreamCtx::new(5, 0, 0));
        ctx.streams.get_mut(&5).unwrap().state = H2StreamState::HalfClosedRemote;
        assert_eq!(ctx.send_data(5, &[], true), 0);
        assert_eq!(ctx.streams.get(&5).unwrap().state, H2StreamState::Closed);
    }

    /// Defence in depth behind SETTINGS validation (T234): a zero max frame size sends
    /// nothing instead of looping on empty DATA frames.
    #[test]
    fn send_data_with_a_zero_max_frame_size_sends_nothing() {
        let mut ctx = MuxH2.init(ConnId(1), true).expect("init");
        ctx.streams.insert(1, H2StreamCtx::new(1, 100, 100));
        ctx.max_frame_size = 0;
        let before = ctx.tx_buf.len();
        assert_eq!(ctx.send_data(1, &[7; 25], true), 0);
        assert_eq!(ctx.tx_buf.len(), before);
    }

    /// Settings are validated before any is applied (T234); nothing is buffered after the
    /// GOAWAY.
    #[test]
    fn an_invalid_setting_applies_none_of_the_frame() {
        let mut ctx = MuxH2.init(ConnId(1), true).expect("init");
        let mut wire = H2_CONN_PREFACE.to_vec();
        // MAX_CONCURRENT_STREAMS 7 then MAX_FRAME_SIZE 0.
        wire.extend_from_slice(&[0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 7, 0, 5, 0, 0, 0, 0]);
        let mcs = ctx.max_concurrent_streams;
        assert!(MuxH2.parse(&mut ctx, &wire).is_err());
        assert_eq!(ctx.max_frame_size, DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(ctx.max_concurrent_streams, mcs);
        assert_eq!(ctx.goaway_sent, Some((0, H2Error::ProtocolError)));
        let buffered = ctx.rx_buf.len();
        assert!(MuxH2.parse(&mut ctx, &[0; 64]).is_ok());
        assert_eq!(ctx.rx_buf.len(), buffered);
    }

    /// A closed stream is taken out of the map when its transaction ends (T186). HEADERS
    /// on its id again is still a closed stream's, not a new request: a connection error
    /// STREAM_CLOSED naming the highest stream seen (HAProxy measured: GOAWAY last 1,
    /// STREAM_CLOSED, close; T235 -- it was an RST_STREAM, queued for every such frame).
    #[test]
    fn headers_on_a_closed_stream_let_go_are_goaway_stream_closed() {
        let mux = MuxH2;
        let mut ctx = mux.init(ConnId(1), true).expect("init");
        let mut hello = H2_CONN_PREFACE.to_vec();
        hello.extend_from_slice(&Frame::Settings { flags: 0, settings: vec![] }.encode());
        mux.parse(&mut ctx, &hello).expect("handshake");
        let mut enc = HpackEncoder::new();
        let get = |enc: &mut HpackEncoder, path: &str, id: u32| {
            let block = enc.encode(&[
                HeaderField { name: ":method".into(), value: "GET".into() },
                HeaderField { name: ":path".into(), value: path.into() },
            ]);
            Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: id, header_block: block }.encode()
        };
        mux.parse(&mut ctx, &get(&mut enc, "/one", 1)).expect("stream 1");
        assert!(ctx.streams.contains_key(&1));
        ctx.streams.remove(&1);
        let sent = ctx.tx_buf.len();
        assert!(mux.parse(&mut ctx, &get(&mut enc, "/again", 1)).is_err());
        assert!(!ctx.streams.contains_key(&1), "a closed stream was opened again");
        let g = &ctx.tx_buf[sent..];
        assert_eq!((g[3], &g[9..13], &g[13..17]), (0x7, &[0, 0, 0, 1][..], &[0, 0, 0, 5][..]), "{g:?}");
        assert_eq!(ctx.conn_state, H2ConnState::GoAwaySent);
    }

    /// While more than [`TX_ROOM`] of output waits for the client, no frame is processed,
    /// so none is answered: a client that reads nothing cannot make replies pile up (T235).
    #[test]
    fn a_full_output_holds_the_demux_until_the_client_reads() {
        let (mux, mut ctx) = open_conn();
        ctx.tx_buf.resize(TX_ROOM + 1, 0);
        let ping = Frame::Ping { flags: 0, opaque_data: [7; 8] }.encode();
        let before = ctx.tx_buf.len();
        mux.parse(&mut ctx, &ping).expect("ping");
        assert_eq!(ctx.tx_buf.len(), before, "a PING was answered past a full output");
        mux.consume_output(&mut ctx, TX_ROOM + 1);
        ctx.resume();
        assert_eq!(ctx.tx_buf.len(), 17, "the PING is answered once the client has read");
    }

    /// A client that always reads part of what is waiting -- never all of it -- keeps the
    /// output from draining to empty. What it has read must still be let go: kept, the
    /// output buffer held every byte ever sent on the connection (T288, MY-3).
    #[test]
    fn output_read_in_part_does_not_keep_what_was_read() {
        let mut ctx = MuxH2.init(ConnId(1), true).expect("init");
        ctx.streams.insert(1, H2StreamCtx::new(1, i32::MAX, 100));
        ctx.conn_send_window = i32::MAX;
        for k in 0..20_000u32 {
            let byte = u8::try_from(k % 251).unwrap();
            assert_eq!(ctx.send_data(1, &[byte; 1000], false), 1000);
            // The client reads all but the last 100 bytes waiting.
            let pending = MuxH2.pending_output(&ctx).len();
            MuxH2.consume_output(&mut ctx, pending - 100);
            assert_eq!(MuxH2.pending_output(&ctx), &[byte; 100][..], "the unread tail stays");
        }
        // 20 MB went through; what is kept is bounded by what waits, not by what was sent.
        assert!(ctx.tx_buf.len() <= 4 * TX_ROOM, "tx_buf holds {} bytes", ctx.tx_buf.len());
        assert!(ctx.tx_buf.capacity() <= 8 * TX_ROOM, "tx_buf capacity {} bytes", ctx.tx_buf.capacity());
    }

    /// SETTINGS_MAX_CONCURRENT_STREAMS from a client limits pushes, which a proxy never
    /// sends: a server-role connection keeps its own limit (T280). A client-role one
    /// (we are the client) takes the server's.
    #[test]
    fn peer_max_concurrent_streams_applies_to_client_role_only() {
        let settings = Frame::Settings {
            flags: 0,
            settings: vec![(SettingsParameter::MaxConcurrentStreams, 1)],
        }
        .encode();
        let mut hello = H2_CONN_PREFACE.to_vec();
        hello.extend_from_slice(&settings);
        let mut server = MuxH2.init(ConnId(1), true).expect("init");
        let own = server.max_concurrent_streams;
        MuxH2.parse(&mut server, &hello).expect("server parse");
        assert_eq!(server.max_concurrent_streams, own);
        let mut client = MuxH2.init(ConnId(2), false).expect("init");
        MuxH2.parse(&mut client, &settings).expect("client parse");
        assert_eq!(client.max_concurrent_streams, 1);
    }

    /// WINDOW_UPDATE past 2^31-1 (HAProxy, measured): GOAWAY FLOW_CONTROL_ERROR for the
    /// connection window, RST_STREAM FLOW_CONTROL_ERROR for a stream's; exactly 2^31-1 is fine.
    #[test]
    fn window_update_overflow_is_flow_control_error() {
        let (mux, mut ctx) = open_conn();
        let inc = i32::MAX as u32 - ctx.conn_send_window as u32;
        let wu = |sid, inc| Frame::WindowUpdate { stream_id: sid, increment: inc }.encode();
        mux.parse(&mut ctx, &wu(0, inc)).expect("exactly the maximum");
        assert_eq!(ctx.conn_send_window, i32::MAX);
        assert!(mux.parse(&mut ctx, &wu(0, 1)).is_err());
        assert_eq!(ctx.goaway_sent.map(|g| g.1), Some(H2Error::FlowControlError));

        let (mux, mut ctx) = open_conn();
        ctx.streams.insert(1, H2StreamCtx::new(1, i32::MAX - 5, 100));
        mux.parse(&mut ctx, &wu(1, 5)).expect("exactly the maximum");
        assert_eq!(ctx.streams.get(&1).map(|s| s.send_window), Some(i32::MAX));
        let before = ctx.tx_buf.len();
        mux.parse(&mut ctx, &wu(1, 1)).expect("a stream error is not a connection error");
        assert!(ctx.tx_buf[before..].windows(9).any(|w| w[3] == 3 && w[5..9] == [0, 0, 0, 1]), "no RST_STREAM");
        assert!(ctx.goaway_sent.is_none());
        let rst_code = &ctx.tx_buf[ctx.tx_buf.len() - 4..];
        assert_eq!(rst_code, &[0, 0, 0, 3]);
    }

    /// A client that sends DATA past the window it was granted (not policed, as in HAProxy)
    /// drives the receive window negative, down to i32::MIN: the replenishment must not
    /// overflow (it did: `i32::MAX - window`, a panic in debug, a wrapped increment in release)
    /// and must stay a legal increment.
    #[test]
    fn receive_window_far_below_zero_is_replenished_without_overflow() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open");
        ctx.rx_window_opened = true;
        ctx.conn_recv_window = i32::MIN + 10;
        let before = ctx.tx_buf.len();
        mux.parse(&mut ctx, &data(1, 100, 0)).expect("data");
        let wu = ctx.tx_buf[before..].windows(13).find(|w| w[3] == 8 && w[5..9] == [0, 0, 0, 0]).expect("WINDOW_UPDATE");
        let inc = u32::from_be_bytes([wu[9], wu[10], wu[11], wu[12]]);
        assert!(inc <= i32::MAX as u32 && inc > 0, "increment {inc:#x}");
    }

    /// T449: a response with a field the HTTP/1 head cannot carry is a stream error for a
    /// client connection, as `h2_make_htx_response` makes it; a clean one is taken.
    #[test]
    fn a_response_field_with_crlf_resets_the_stream_on_a_client_connection() {
        let response = |id: u32, name: &str, value: &str| {
            let block = HpackEncoder::new().encode(&[
                HeaderField { name: ":status".into(), value: "200".into() },
                HeaderField { name: name.into(), value: value.into() },
            ]);
            Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: id, header_block: block }.encode()
        };
        let settings = Frame::Settings { flags: 0, settings: vec![] }.encode();
        for (name, value, ok) in [("x-r", "a", true), ("x-r", "a\r\nx-injected: 1", false), ("x-r", "a\0b", false), ("X-R", "1", false)] {
            let mut client = MuxH2.init(ConnId(2), false).expect("init");
            MuxH2.parse(&mut client, &settings).expect("settings");
            let before = client.tx_buf.len();
            MuxH2.parse(&mut client, &response(1, name, value)).expect("a stream error is not a connection error");
            let rst = client.tx_buf[before..].windows(13).any(|w| w[3] == 3 && w[5..9] == [0, 0, 0, 1] && w[9..13] == [0, 0, 0, 1]);
            assert_eq!(!rst, ok, "{name}: {value:?}");
            assert_eq!(client.streams.get(&1).is_some_and(|s| s.rx_htx.res_line().is_some()), ok, "{name}: {value:?}");
        }
    }

    fn open_conn() -> (MuxH2, H2MuxContext) {
        let mux = MuxH2;
        let mut ctx = mux.init(ConnId(1), true).expect("init");
        let mut hello = H2_CONN_PREFACE.to_vec();
        hello.extend_from_slice(&Frame::Settings { flags: 0, settings: vec![] }.encode());
        mux.parse(&mut ctx, &hello).expect("handshake");
        (mux, ctx)
    }

    fn post_headers(id: u32) -> Vec<u8> {
        let block = HpackEncoder::new().encode(&[
            HeaderField { name: ":method".into(), value: "POST".into() },
            HeaderField { name: ":path".into(), value: "/".into() },
        ]);
        Frame::Headers { flags: frame_flags::END_HEADERS, stream_id: id, header_block: block }.encode()
    }

    fn data(id: u32, n: usize, flags: u8) -> Vec<u8> {
        Frame::Data { flags, stream_id: id, data: vec![b'd'; n] }.encode()
    }

    /// A stream holds at most its receive window of DATA: the frame past it waits in
    /// `rx_buf` (the connection stops asking for input) until the data path takes some
    /// (T235). The window of a stream that receives a body grows at its first DATA to its
    /// share of the budget (T313: 88 buffers of 16 KB for the only stream of a default
    /// connection, as `HAProxy` measured), so that is what it holds.
    #[test]
    fn data_past_the_stream_window_waits_until_the_stream_drains() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open");
        let mut wire = Vec::new();
        for _ in 0..90 {
            wire.extend(data(1, 16384, 0));
        }
        mux.parse(&mut ctx, &wire).expect("data");
        // 88 frames fit the grown window, the 89th does not.
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_buffered), Some(88 * 16384));
        assert!(!ctx.wants_input(), "two frames wait: no more input");
        ctx.rx_taken(1, 16384);
        ctx.resume();
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_buffered), Some(88 * 16384));
        ctx.rx_taken(1, 88 * 16384);
        ctx.resume();
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_buffered), Some(16384));
        assert!(ctx.rx_buf.is_empty() && ctx.wants_input());
    }

    /// The window increments sent on `stream` (0: the connection) since `from` of `tx_buf`.
    fn wu_sent(ctx: &H2MuxContext, from: usize, stream: u32) -> Vec<u64> {
        let (mut out, mut i) = (Vec::new(), from);
        while i + 9 <= ctx.tx_buf.len() {
            let len = (usize::from(ctx.tx_buf[i]) << 16) | (usize::from(ctx.tx_buf[i + 1]) << 8) | usize::from(ctx.tx_buf[i + 2]);
            let sid = u32::from_be_bytes([ctx.tx_buf[i + 5], ctx.tx_buf[i + 6], ctx.tx_buf[i + 7], ctx.tx_buf[i + 8]]);
            if ctx.tx_buf[i + 3] == 8 && sid == stream {
                let p = &ctx.tx_buf[i + 9..i + 13];
                out.push(u64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]])));
            }
            i += 9 + len;
        }
        out
    }

    /// `HAProxy` 3.5-dev8 (measured, one POST and 64 KB of DATA): the stream's window grows
    /// by 1409024 at the first DATA, and the connection's opens by 2147434496 at the first
    /// update. Ibex's initial stream window is 65535, not 16384: the grown window is the
    /// same 88 buffers, so the stream is granted 88 x 16384 - 65535.
    #[test]
    fn a_receiving_stream_is_granted_its_share_and_the_connection_window_opens_wide() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open");
        let before = ctx.tx_buf.len();
        mux.parse(&mut ctx, &data(1, 16384, 0)).expect("data");
        assert_eq!(wu_sent(&ctx, before, 1), vec![88 * 16384 - 65535]);
        assert!(wu_sent(&ctx, before, 0).iter().sum::<u64>() < 65536, "the connection window is not opened before a byte is taken");
        let before = ctx.tx_buf.len();
        let open_from = ctx.conn_recv_window;
        ctx.rx_taken(1, 16384);
        assert_eq!(wu_sent(&ctx, before, 0), vec![i64::from(i32::MAX).saturating_sub(i64::from(open_from)) as u64]);
        assert_eq!(ctx.conn_recv_window, i32::MAX);
        // A body that fits the initial window gets no growth.
        let small = Frame::Headers {
            flags: frame_flags::END_HEADERS,
            stream_id: 3,
            header_block: {
                HpackEncoder::new().encode(&[
                    HeaderField { name: ":method".into(), value: "POST".into() },
                    HeaderField { name: ":path".into(), value: "/".into() },
                    HeaderField { name: "content-length".into(), value: "100".into() },
                ])
            },
        }
        .encode();
        mux.parse(&mut ctx, &small).expect("open 3");
        let before = ctx.tx_buf.len();
        mux.parse(&mut ctx, &data(3, 100, 0)).expect("data 3");
        assert!(wu_sent(&ctx, before, 3).is_empty(), "{:?}", wu_sent(&ctx, before, 3));
    }

    /// The budget: with no stream consumed, 100 streams send DATA until the connection holds
    /// its buffers (100 of 16 KB; a 16 KB frame spans two), and not a frame more; the rest
    /// waits. The fuzz target `h2_mux` holds the connection under 2 MiB with the same.
    #[test]
    fn the_connection_holds_no_more_than_its_budget_of_unconsumed_data() {
        let (mux, mut ctx) = open_conn();
        for k in 0..100 {
            mux.parse(&mut ctx, &post_headers(1 + 2 * k)).expect("open");
        }
        let budget = ctx.rx_budget();
        assert_eq!(budget, 101 * 16384);
        let mut wire = Vec::new();
        for _ in 0..40 {
            for k in 0..100 {
                wire.extend(data(1 + 2 * k, 16384, 0));
            }
        }
        // The transport reads only while the connection wants input.
        for chunk in wire.chunks(16393) {
            if !ctx.wants_input() {
                break;
            }
            let _ = mux.parse(&mut ctx, chunk);
        }
        let held: usize = ctx.streams.values().map(|s| s.rx_buffered).sum();
        assert!(held <= budget, "held {held} > budget {budget}");
        let slots: usize = ctx.streams.values().map(|s| s.rx_slots(0)).sum();
        assert_eq!((slots, ctx.rx_slots()), (100, 100), "every buffer is used, held {held}");
        assert!(ctx.rx_buf.len() < 3 * 16393, "only the frames waiting are kept: {}", ctx.rx_buf.len());
        // Taking a stream's data makes room for the frames waiting.
        let taken = ctx.streams.get(&1).map_or(0, |s| s.rx_buffered);
        ctx.rx_taken(1, taken);
        ctx.resume();
        let held2: usize = ctx.streams.values().map(|s| s.rx_buffered).sum();
        assert!(held2 > held - taken, "held {held2} after taking {taken} of {held}");
    }

    /// The red team's shape (MY-10): one POST of 88 x 16 KB, then POSTs of one 16 KB frame,
    /// nothing taken (the server connect hangs). `HAProxy` 3.5-dev8 (`show sess all`): the
    /// big stream holds 89 receive buffers, streams 3 to 11 two each, stream 13 one and the
    /// demux stops there (`.maxid=13 .nbst=7`); the HEADERS behind it stay in the socket.
    #[test]
    fn streams_stop_being_demuxed_when_the_receive_buffers_are_used() {
        let (mux, mut ctx) = open_conn();
        let mut wire = post_headers(1);
        for _ in 0..88 {
            wire.extend(data(1, 16384, 0));
        }
        for k in 1..100 {
            wire.extend(post_headers(1 + 2 * k));
            wire.extend(data(1 + 2 * k, 16384, 0));
        }
        for chunk in wire.chunks(16393) {
            if !ctx.wants_input() {
                break;
            }
            let _ = mux.parse(&mut ctx, chunk);
        }
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_slots(0)), Some(89));
        assert_eq!(ctx.streams.keys().copied().collect::<Vec<_>>(), vec![1, 3, 5, 7, 9, 11, 13]);
        assert_eq!(ctx.streams.get(&13).map(|s| s.rx_buffered), Some(0), "the frame of 13 waits");
        assert!(!ctx.wants_input(), "the connection is not read");
        // A stream the data path empties gives its buffers back, and the demux goes on.
        ctx.rx_taken(3, 16384);
        ctx.resume();
        assert_eq!(ctx.streams.get(&13).map(|s| s.rx_buffered), Some(16384));
        assert!(ctx.streams.contains_key(&15));
    }

    /// `tune.h2.fe.rxbuf` raises the budget (`nb_rxbufs = max(rxbuf / (bufsize - 9), streams)`).
    #[test]
    fn the_rxbuf_setting_raises_the_budget() {
        let (_, mut ctx) = open_conn();
        assert_eq!(ctx.rx_budget(), 101 * 16384);
        ctx.flood_config.rxbuf = 8 << 20;
        assert_eq!(ctx.rx_budget(), (8usize << 20).div_ceil(16375).max(100) * 16384 + 16384);
        ctx.flood_config.rxbuf = 1 << 20;
        assert_eq!(ctx.rx_budget(), 101 * 16384, "under the per-stream floor");
    }

    /// DATA after the client's END_STREAM is a stream error STREAM_CLOSED (HAProxy measured:
    /// RST_STREAM 5), and is not kept; DATA after the response is over is dropped (T235).
    #[test]
    fn data_after_end_stream_is_reset_and_not_kept() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open");
        mux.parse(&mut ctx, &data(1, 10, frame_flags::END_STREAM)).expect("end");
        let sent = ctx.tx_buf.len();
        mux.parse(&mut ctx, &data(1, 1000, 0)).expect("after end");
        let rst = &ctx.tx_buf[sent..];
        assert_eq!((rst.len(), rst[3], &rst[9..13]), (13, 0x3, &[0, 0, 0, 5][..]), "{rst:?}");
        // No transaction had taken it: the reset stream is let go, its request with it.
        assert!(!ctx.streams.contains_key(&1));
        // Stream 3's response is over: what it still sends is counted and dropped.
        mux.parse(&mut ctx, &post_headers(3)).expect("open 3");
        ctx.streams.get_mut(&3).expect("3").state = H2StreamState::HalfClosedLocal;
        mux.parse(&mut ctx, &data(3, 1000, 0)).expect("data 3");
        assert_eq!(ctx.streams.get(&3).map(|s| (s.rx_buffered, s.rx_htx.body_bytes().len())), Some((0, 0)));
        // Its END_STREAM closes it.
        mux.parse(&mut ctx, &data(3, 0, frame_flags::END_STREAM)).expect("end 3");
        assert_eq!(ctx.streams.get(&3).map(|s| s.state), Some(H2StreamState::Closed));
    }

    /// A reset stream no transaction has taken is let go at once, whichever side reset it;
    /// the one being served stays, marked, for the data path to see (T235, rapid reset).
    #[test]
    fn a_reset_stream_not_taken_is_let_go() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open 1");
        mux.parse(&mut ctx, &post_headers(3)).expect("open 3");
        ctx.streams.get_mut(&1).expect("1").dispatched = true;
        let rst = |id: u32| Frame::RstStream { stream_id: id, error_code: H2Error::Cancel }.encode();
        mux.parse(&mut ctx, &rst(1)).expect("rst 1");
        mux.parse(&mut ctx, &rst(3)).expect("rst 3");
        assert_eq!(ctx.streams.get(&1).map(|s| s.state), Some(H2StreamState::Reset(H2Error::Cancel)));
        assert!(!ctx.streams.contains_key(&3));
        // DATA on the reset stream being served is counted and dropped, END_STREAM too.
        mux.parse(&mut ctx, &data(1, 100, frame_flags::END_STREAM)).expect("data 1");
        assert_eq!(ctx.streams.get(&1).map(|s| (s.state, s.rx_buffered)), Some((H2StreamState::Reset(H2Error::Cancel), 0)));
        mux.parse(&mut ctx, &post_headers(5)).expect("open 5");
        ctx.send_rst_stream(5, H2Error::ProtocolError);
        assert!(!ctx.streams.contains_key(&5));
    }

    /// Nothing goes out on a stream once it is reset, the response head no more than its
    /// body (RFC 9113 5.1; T273 B).
    #[test]
    fn a_reset_stream_is_sent_no_response() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open 1");
        ctx.streams.get_mut(&1).expect("1").dispatched = true;
        mux.parse(&mut ctx, &Frame::RstStream { stream_id: 1, error_code: H2Error::Cancel }.encode()).expect("rst 1");
        let before = mux.pending_output(&ctx).len();
        assert!(ctx.send_h1_head(1, b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n", false), "taken and dropped");
        ctx.send_data(1, b"ok", true);
        assert_eq!(mux.pending_output(&ctx).len(), before, "no frame on the reset stream");
    }

    /// SETTINGS_HEADER_TABLE_SIZE bounds the table our encoder may use, it does not size it:
    /// the encoder stays at 4096 (the default, which no size update has changed), whatever
    /// larger value the peer announces -- 2^32-1 let the table grow to all a client asked (T235).
    #[test]
    fn a_huge_header_table_size_leaves_the_encoder_at_4096() {
        let (mux, mut ctx) = open_conn();
        let s = Frame::Settings { flags: 0, settings: vec![(SettingsParameter::HeaderTableSize, u32::MAX)] };
        mux.parse(&mut ctx, &s.encode()).expect("settings");
        assert_eq!(ctx.encoder.dynamic_table.max_size(), 4096);
        let s = Frame::Settings { flags: 0, settings: vec![(SettingsParameter::HeaderTableSize, 256)] };
        mux.parse(&mut ctx, &s.encode()).expect("settings");
        assert_eq!(ctx.encoder.dynamic_table.max_size(), 256);
    }

    /// HEADERS refused over the stream limit are HPACK-decoded all the same: the client's
    /// encoder has added their fields to its table, and the next request refers to them.
    /// Not decoded, the tables parted and that request was a COMPRESSION_ERROR (T235).
    #[test]
    fn a_refused_stream_keeps_the_hpack_table_in_step() {
        let (mux, mut ctx) = open_conn();
        let mut enc = HpackEncoder::new();
        let mut get = |id: u32, extra: &str| {
            let block = enc.encode(&[
                HeaderField { name: ":method".into(), value: "GET".into() },
                HeaderField { name: ":path".into(), value: "/".into() },
                HeaderField { name: "x-extra".into(), value: extra.into() },
            ]);
            Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: id, header_block: block }.encode()
        };
        for i in 0..100 {
            mux.parse(&mut ctx, &get(2 * i + 1, "a")).expect("open");
        }
        let sent = ctx.tx_buf.len();
        mux.parse(&mut ctx, &get(201, "refused")).expect("refused");
        assert_eq!(ctx.tx_buf[sent + 3], 0x3, "not refused with RST_STREAM");
        ctx.streams.remove(&1);
        mux.parse(&mut ctx, &get(203, "refused")).expect("the next request decodes");
        let x = ctx.streams.get(&203).and_then(|s| s.request_header("x-extra").map(str::to_owned));
        assert_eq!(x.as_deref(), Some("refused"));
    }

    /// RFC 9113 section 6.1: padding counts toward flow control; only the data reaches the stream.
    #[test]
    fn padded_data_counts_its_padding_in_the_windows() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open");
        // Pad length 4, "abc", 4 bytes of padding: 8 bytes on the wire.
        let mut raw = vec![0, 0, 8, 0, frame_flags::PADDED, 0, 0, 0, 1, 4, b'a', b'b', b'c', 0, 0, 0, 0];
        mux.parse(&mut ctx, &raw).expect("padded data");
        assert_eq!(ctx.conn_recv_window, DEFAULT_INITIAL_WINDOW_SIZE - 8);
        // The stream's window was grown to its share of the budget (T313): 88 buffers.
        assert_eq!(ctx.streams.get(&1).map(|s| s.recv_window), Some(88 * 16384 - 8));
        // A pad length that does not fit is a connection error, PROTOCOL_ERROR.
        raw = vec![0, 0, 2, 0, frame_flags::PADDED, 0, 0, 0, 1, 9, b'a'];
        assert!(mux.parse(&mut ctx, &raw).is_err());
        let goaway = ctx.tx_buf.windows(9).any(|w| w[3] == 7);
        assert!(goaway, "no GOAWAY sent");
    }

    #[test]
    fn ensure_goaway_announces_an_unannounced_error_once() {
        let (_mux, mut ctx) = open_conn();
        ctx.ensure_goaway();
        let n = ctx.tx_buf.len();
        assert_eq!(ctx.conn_state, H2ConnState::GoAwaySent);
        assert!(ctx.tx_buf.windows(9).any(|w| w[3] == 7));
        ctx.ensure_goaway();
        assert_eq!(ctx.tx_buf.len(), n, "a second GOAWAY was queued");
    }

    /// A padded frame that cannot hold its pad length byte is FRAME_SIZE_ERROR (HAProxy).
    #[test]
    fn padded_frame_without_pad_length_is_goaway_frame_size_error() {
        let (mux, mut ctx) = open_conn();
        let sent = ctx.tx_buf.len();
        let raw = [0, 0, 0, 1, frame_flags::PADDED | frame_flags::END_HEADERS, 0, 0, 0, 1];
        assert!(mux.parse(&mut ctx, &raw).is_err());
        let g = &ctx.tx_buf[sent..];
        let at = g.windows(9).position(|w| w[3] == 7).expect("GOAWAY");
        assert_eq!(&g[at + 9 + 4..at + 9 + 8], &[0, 0, 0, 6], "{g:?}");
    }

    /// T242 (fuzz h2_mux): an HPACK block of one-byte references to a 4000-byte dynamic
    /// table entry decodes to ~380 KB per request; requests a slow backend has not taken
    /// stay in their streams. What sixty such requests (10 KB on the wire) hold must stay
    /// bounded.
    #[test]
    fn hpack_references_do_not_amplify_what_the_connection_holds() {
        let (mux, mut ctx) = open_conn();
        let mut first = vec![0x82, 0x86, 0x84, 0x40, 0x01, b'x', 0x7f];
        let mut n = 4000 - 127;
        while n >= 128 {
            first.push((n & 0x7f) as u8 | 0x80);
            n >>= 7;
        }
        first.push(n as u8);
        first.extend(std::iter::repeat_n(b'a', 4000));
        first.extend(std::iter::repeat_n(0xbe, 90));
        let mut wire = Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: 1, header_block: first }.encode();
        for id in (3..123).step_by(2) {
            let mut block = vec![0x82, 0x86, 0x84];
            block.extend(std::iter::repeat_n(0xbe, 95));
            wire.extend(Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: id, header_block: block }.encode());
        }
        // A control that fits: two references (8 KB), so that the sum below counts something.
        let mut block = vec![0x82, 0x86, 0x84];
        block.extend(std::iter::repeat_n(0xbe, 2));
        wire.extend(Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: 125, header_block: block }.encode());
        let _ = mux.parse(&mut ctx, &wire);
        let held: usize = ctx
            .streams
            .values()
            .flat_map(|s| s.rx_htx.blocks())
            .map(|b| match b {
                HtxBlock::Header(h) => h.name.len() + h.value.len(),
                _ => 0,
            })
            .sum::<usize>()
            // A head kept as text (T437) holds its fields there.
            + ctx.streams.values().map(|s| s.req_head.as_ref().map_or(0, |h| h.field_bytes)).sum::<usize>();
        assert!(held >= 8000, "the control request is held: {held}");
        assert!(held <= 2 << 20, "{} streams hold {held} bytes of headers from {} bytes", ctx.streams.len(), wire.len());
    }

    /// The edge HAProxy shows (measured on 3.5-dev8): `:method GET`, `:scheme http`,
    /// `:path /`, `:authority a` and four `x` fields of 3800 bytes are answered; of 3850
    /// bytes, the stream is reset with PROTOCOL_ERROR and the connection lives on.
    #[test]
    fn a_request_head_past_the_buffer_is_a_stream_error() {
        for (len, refused) in [(3800usize, false), (3850, true)] {
            let (mux, mut ctx) = open_conn();
            let mut block = vec![0x82, 0x86, 0x84, 0x41, 0x01, b'a', 0x40, 0x01, b'x', 0x7f];
            let mut n = len - 127;
            while n >= 128 {
                block.push((n & 0x7f) as u8 | 0x80);
                n >>= 7;
            }
            block.push(n as u8);
            block.extend(std::iter::repeat_n(b'a', len));
            block.extend([0xbe; 3]);
            let sent = ctx.tx_buf.len();
            let wire = Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: 1, header_block: block }.encode();
            mux.parse(&mut ctx, &wire).expect("no connection error");
            let rst = ctx.tx_buf[sent..].windows(13).any(|w| w[3] == 3 && w[5..9] == [0, 0, 0, 1] && w[9..13] == [0, 0, 0, 1]);
            assert_eq!(rst, refused, "len {len}");
            let kept = ctx.streams.get(&1).is_some_and(|s| s.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Eoh)));
            assert_eq!(kept, !refused, "len {len}");
            assert!(ctx.goaway_sent.is_none());
        }
    }

    /// A trailers block: `x` = `len` bytes added to the HPACK table, then `refs` one-byte
    /// references to it, so `refs + 1` fields of `len + 1` decoded bytes (T271).
    fn trailers(id: u32, len: usize, refs: usize) -> Vec<u8> {
        let mut block = vec![0x40, 0x01, b'x'];
        if len < 127 {
            block.push(len as u8);
        } else {
            block.push(0x7f);
            let mut n = len - 127;
            while n >= 128 {
                block.push((n & 0x7f) as u8 | 0x80);
                n >>= 7;
            }
            block.push(n as u8);
        }
        block.extend(std::iter::repeat_n(b'a', len));
        block.extend(std::iter::repeat_n(0xbe, refs));
        Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: id, header_block: block }
            .encode()
    }

    /// Request trailers get the room HAProxy's rx buffer gives them (T271; T242 kept 202
    /// fields of 4 KB per stream). Measured on 3.5-dev8, a POST with a DATA frame, then a
    /// trailers HEADERS: one field of 16327 decoded bytes passes and of 16328 is reset;
    /// five of 3259 pass and five of 3261 are reset; 101 fields pass and 102 are reset --
    /// each RST_STREAM PROTOCOL_ERROR, the connection kept. What passes is
    /// `sum(name + value) + 8 * fields <= 16335` (an HTX block per field in a 16 KB buffer).
    #[test]
    fn request_trailers_past_the_buffer_are_a_stream_error() {
        for (len, refs, refused) in [
            (16326usize, 0usize, false),
            (16327, 0, true),
            (3258, 4, false),
            (3260, 4, true),
            (50, 100, false),
            (50, 101, true),
            (4000, 100, true),
        ] {
            let (mux, mut ctx) = open_conn();
            mux.parse(&mut ctx, &post_headers(1)).expect("open");
            mux.parse(&mut ctx, &data(1, 3, 0)).expect("data");
            let sent = ctx.tx_buf.len();
            mux.parse(&mut ctx, &trailers(1, len, refs)).expect("no connection error");
            let case = format!("{} fields of {}", refs + 1, len + 1);
            let rst = ctx.tx_buf[sent..].windows(13).any(|w| w[3] == 3 && w[5..9] == [0, 0, 0, 1] && w[9..13] == [0, 0, 0, 1]);
            assert_eq!(rst, refused, "RST_STREAM PROTOCOL_ERROR for {case}");
            let held: usize = ctx
                .streams
                .values()
                .flat_map(|s| s.rx_htx.blocks())
                .map(|b| match b {
                    HtxBlock::Trailer(h) => h.name.len() + h.value.len(),
                    _ => 0,
                })
                .sum();
            assert_eq!(held, if refused { 0 } else { (refs + 1) * (len + 1) }, "trailer bytes kept for {case}");
            assert!(ctx.goaway_sent.is_none(), "{case}");
        }
    }

    /// A field literal without indexing, new name, no Huffman.
    fn lit(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut v = vec![0, u8::try_from(name.len()).unwrap()];
        v.extend_from_slice(name);
        v.push(u8::try_from(value.len()).unwrap());
        v.extend_from_slice(value);
        v
    }

    /// What the connection sent after `from`, as (type, stream, error code) per frame (no
    /// SETTINGS); for a GOAWAY, the last stream it names in place of its stream (0).
    fn sent(ctx: &H2MuxContext, from: usize) -> Vec<(u8, u32, u32)> {
        let (b, mut i, mut out) = (&ctx.tx_buf, from, Vec::new());
        while i + 9 <= b.len() {
            let len = (usize::from(b[i]) << 16) | (usize::from(b[i + 1]) << 8) | usize::from(b[i + 2]);
            let sid = u32::from_be_bytes([b[i + 5], b[i + 6], b[i + 7], b[i + 8]]);
            // An RST_STREAM carries its code at 9, a GOAWAY after the last stream id at 13;
            // a frame with no such field (SETTINGS) has no code.
            let at = if b[i + 3] == 7 { 13 } else { 9 };
            let code = b.get(i + at..i + at + 4).map_or(0, |c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
            let sid = if b[i + 3] == 7 { u32::from_be_bytes([b[i + 9], b[i + 10], b[i + 11], b[i + 12]]) } else { sid };
            if b[i + 3] != 4 {
                out.push((b[i + 3], sid, code));
            }
            i += 9 + len;
        }
        out
    }

    /// The frames sent for one connection's `wire` (after the handshake).
    fn answer(wire: &[u8]) -> (H2MuxContext, Vec<(u8, u32, u32)>) {
        let (mux, mut ctx) = open_conn();
        let from = ctx.tx_buf.len();
        let _ = mux.parse(&mut ctx, wire);
        let s = sent(&ctx, from);
        (ctx, s)
    }

    fn headers(flags: u8, id: u32, block: Vec<u8>) -> Vec<u8> {
        Frame::Headers { flags, stream_id: id, header_block: block }.encode()
    }

    /// T437: requests HAProxy 3.5-dev8 refuses with RST_STREAM PROTOCOL_ERROR (measured
    /// 2026-10-19, h2c, raw frames): no `:method`, a `:status`, `:protocol` on a GET, an
    /// empty `:path`, two `:method`.
    #[test]
    fn malformed_request_heads_are_reset_as_haproxy_resets_them() {
        let auth = lit(b":authority", b"a");
        let cases: [(&str, Vec<u8>); 6] = [
            ("no :method", [&[0x86u8, 0x84][..], &auth].concat()),
            (":status", [&[0x82u8, 0x86, 0x84, 0x88][..], &auth].concat()),
            (":status alone", [&[0x88u8][..], &auth].concat()),
            (":protocol on a GET", [&[0x82u8, 0x86, 0x84][..], &auth, &lit(b":protocol", b"websocket")].concat()),
            ("empty :path", [&[0x82u8, 0x86][..], &lit(b":path", b""), &auth].concat()),
            ("two :method", [&[0x82u8, 0x82, 0x86, 0x84][..], &auth].concat()),
        ];
        for (what, block) in cases {
            let (ctx, s) = answer(&headers(frame_flags::END_HEADERS | frame_flags::END_STREAM, 1, block));
            assert_eq!(s, vec![(3, 1, 1)], "{what}: not RST_STREAM PROTOCOL_ERROR");
            assert!(ctx.streams.get(&1).is_none_or(|st| st.req_head.is_none()), "{what}: a head was kept");
        }
    }

    /// T437: a request with two `host` headers is taken, with the first (HAProxy 3.5-dev8,
    /// measured: the server receives `GET / HTTP/1.1` and `host: a` alone).
    #[test]
    fn a_second_host_header_is_dropped_as_haproxy_drops_it() {
        for block in [
            [&[0x82u8, 0x86, 0x84][..], &lit(b"host", b"a"), &lit(b"host", b"b")].concat(),
            [&[0x82u8, 0x86, 0x84][..], &lit(b":authority", b"a"), &lit(b"host", b"a"), &lit(b"host", b"b")].concat(),
        ] {
            let (ctx, s) = answer(&headers(frame_flags::END_HEADERS | frame_flags::END_STREAM, 1, block));
            assert_eq!(s, vec![], "the request was refused");
            let head = ctx.streams.get(&1).and_then(|st| st.req_head.as_ref()).expect("a head");
            assert_eq!(head.wire(), b"GET / HTTP/1.1\r\nhost: a\r\n\r\n");
        }
    }

    /// T437: connection errors HAProxy 3.5-dev8 answers with GOAWAY (measured): HEADERS on
    /// stream 0 (PROTOCOL_ERROR, last stream 0), a field literal cut short (COMPRESSION_ERROR),
    /// HEADERS while a CONTINUATION is expected (PROTOCOL_ERROR).
    #[test]
    fn broken_header_frames_are_connection_errors_as_haproxy_s() {
        let req = vec![0x82, 0x86, 0x84];
        let (_, s) = answer(&headers(frame_flags::END_HEADERS | frame_flags::END_STREAM, 0, req.clone()));
        assert_eq!(s, vec![(7, 0, 1)], "HEADERS on stream 0");
        for cut in [vec![0x82, 0x86, 0x84, 0x00, 0x03, b'a', b'b'], vec![0x82, 0x86, 0x84, 0x00, 0x01, b'a']] {
            let (_, s) = answer(&headers(frame_flags::END_HEADERS | frame_flags::END_STREAM, 1, cut));
            assert_eq!(s, vec![(7, 1, 9)], "a cut literal");
        }
        let wire = [headers(frame_flags::END_STREAM, 1, vec![0x82, 0x86]), headers(frame_flags::END_HEADERS | frame_flags::END_STREAM, 3, req)].concat();
        let (_, s) = answer(&wire);
        assert_eq!(s, vec![(7, 1, 1)], "HEADERS where a CONTINUATION was due");
    }

    /// T437: an extended CONNECT (`:protocol`, RFC 8441), which HAProxy 3.5-dev8 takes
    /// (measured: answered 200), is taken; a second `:protocol` is reset (measured:
    /// RST_STREAM PROTOCOL_ERROR).
    #[test]
    fn an_extended_connect_is_taken_and_a_second_protocol_reset() {
        let block = [lit(b":method", b"CONNECT"), vec![0x86, 0x84], lit(b":authority", b"a"), lit(b":protocol", b"websocket"), lit(b"content-length", b"3")].concat();
        let (ctx, s) = answer(&headers(frame_flags::END_HEADERS, 1, block.clone()));
        assert_eq!(s, vec![]);
        let st = ctx.streams.get(&1).expect("the stream");
        assert_eq!((st.request_method(), st.request_uri(), st.request_header("Content-Length")), (Some("CONNECT"), Some("/"), Some("3")));
        assert_eq!(st.request_content_length(), Some(3));
        let twice = [block, lit(b":protocol", b"websocket")].concat();
        let (_, s) = answer(&headers(frame_flags::END_HEADERS, 1, twice));
        assert_eq!(s, vec![(3, 1, 1)]);
    }

    /// The stream map answers as the `BTreeMap` it replaced (T437): an insert over a stream
    /// gives the old one back, `entry` finds the stream it has.
    #[test]
    fn the_stream_map_replaces_and_finds_as_a_btreemap() {
        let mut m = StreamMap::new();
        assert!(m.insert(3, H2StreamCtx::new(3, 1, 1)).is_none());
        assert!(m.insert(1, H2StreamCtx::new(1, 1, 1)).is_none());
        let old = m.insert(3, H2StreamCtx::new(3, 2, 2)).expect("the stream it replaced");
        assert_eq!((old.send_window, m.len()), (1, 2));
        m.entry(3).or_insert_with(|| H2StreamCtx::new(3, 9, 9)).recv_window = 7;
        assert_eq!(m.get(&3).map(|s| (s.send_window, s.recv_window)), Some((2, 7)), "or_insert_with made a new stream");
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![1, 3]);
    }
}
