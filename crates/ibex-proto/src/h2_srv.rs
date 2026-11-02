// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 to a server, one stream at a time (T537, slice B-H1 of T535): a codec without I/O
//! between the session's HTTP/1.1 text and the server's frames.
//!
//! The session keeps writing an HTTP/1.1 request ([`H2SrvCodec::send_request`]) and reading an
//! HTTP/1.1 response ([`H2SrvCodec::response`]); in between are the frames a connection to an
//! h2 server carries ([`H2SrvCodec::output`] to write, [`H2SrvCodec::receive`] for what was
//! read). One stream at a time is HAProxy's behaviour under the default `http-reuse safe`
//! (T535 §2: an h2 client's 10 concurrent streams take 10 server connections there too).
//!
//! As HAProxy 3.5-dev8 writes it (measured, `tests/it/h2_srv_codec.rs`):
//! - the preface, then SETTINGS `ENABLE_PUSH 0, ENABLE_CONNECT_PROTOCOL 1, INITIAL_WINDOW_SIZE
//!   16384, MAX_CONCURRENT_STREAMS 100`; on the server's SETTINGS an ACK and a WINDOW_UPDATE
//!   that opens the connection window to 2^31-1;
//! - HEADERS `:method :scheme [:authority] :path` then the fields, HPACK without a dynamic
//!   table of its own and without Huffman ([`crate::hpack::encode_field_stateless`]); the
//!   scheme `https` unless the target is absolute; `:authority` only from an absolute target,
//!   and then no `host`; `connection`, `proxy-connection`, `keep-alive`, `upgrade`,
//!   `transfer-encoding` dropped, `te` kept only as `trailers`;
//! - the body as DATA under the server's windows, a chunked body de-chunked (the chunks one
//!   call has in one DATA frame), its end an empty DATA with END_STREAM or the trailers as a
//!   HEADERS with END_STREAM;
//! - the response as HTTP/1.1 text: `HTTP/1.1 <status> <reason>` (HAProxy's reasons), the
//!   fields, `content-length` kept, else `transfer-encoding: chunked` (also for a response
//!   whose HEADERS ends the stream), chunk sizes in uppercase hex, trailers in the last chunk
//!   and, after a content-length body, kept for an h2 or h3 client ([`H2SrvCodec::take_late_trailers`]; the body's last byte waits for the stream's end) and dropped for an h1 one, 1xx passed on, 204/304/HEAD bodyless.
//!
//! Memory: per connection, from the `h2c_srv` pool ([`H2SrvCodec::take`]); a warm codec keeps
//! its buffers and HPACK table and allocates nothing per request.

use crate::h2::{frame_flags, FrameHeader, FrameType, Frame, H2_CONN_PREFACE, DEFAULT_MAX_FRAME_SIZE, FRAME_HEADER_LEN, MAX_WINDOW_SIZE};
use crate::htx::HtxSliceRef;
use crate::hpack::{encode_field_stateless, DecodedFields, HpackDecoder, DEFAULT_DYNAMIC_TABLE_MAX_SIZE};

ibex_alloc::declare_pool!(
    /// `show pools` `h2c_srv`: the h2 codec of a connection to a server (HAProxy's `h2c` +
    /// `h2s` of a backend connection), with its buffers and HPACK table.
    static H2C_SRV: Pool<H2SrvCodec> = ibex_alloc::PoolSpec::new("h2c_srv");
);

ibex_alloc::declare_pool!(
    /// `show pools` `h2_trailers`: the trailer section an h2 server sent after a content-length
    /// body, on its way to an h2 or h3 client (T559). Rare; bounded by the HPACK block limit.
    static H2_TRAILERS: Pool<Vec<u8>> = ibex_alloc::PoolSpec::new("h2_trailers").max_item(16384);
);

/// Why a request or its response cannot go on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrvH2Error {
    /// The request cannot be written as h2 (CONNECT, a head that is not HTTP/1.1 text).
    Unsupported(&'static str),
    /// The response is malformed: no or a bad `:status`, a connection-specific field, DATA
    /// before HEADERS, a body longer or shorter than its content-length. The stream was reset
    /// PROTOCOL_ERROR. HAProxy: 502, `PH--`.
    BadResponse,
    /// The server reset the stream with `code`. Before the head (`after_head` false): HAProxy
    /// 502 `SH--`; after it, the response is truncated (`SD--`).
    Reset { code: u32, after_head: bool },
    /// The stream was never processed (GOAWAY with a lower last stream id, or REFUSED_STREAM
    /// before the head): safe to send again on another connection.
    Refused,
    /// A connection error with this code: a GOAWAY is in [`H2SrvCodec::output`], then close.
    Connection(u32),
}

/// How the request body is framed in the HTTP/1.1 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ReqBody {
    /// No request in progress.
    #[default]
    Idle,
    /// `content-length` bytes still to send.
    Length(u64),
    /// Chunked: at a chunk-size line.
    ChunkSize,
    /// Chunked: data bytes of the current chunk still to send.
    ChunkData(u64),
    /// Chunked: the CRLF after a chunk's data.
    ChunkCrlf,
    /// Chunked: after the last chunk, the trailer section.
    Trailers,
    /// All sent (END_STREAM written).
    Done,
    /// The response ended first: the rest of the request is read and dropped.
    Discard,
}

/// Where the response is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Rsp {
    /// No final head yet (1xx may have been given).
    #[default]
    Waiting,
    /// The final head given; the body is framed as said.
    Body { chunked: bool, bodyless: bool, left: Option<u64> },
    /// The stream ended (END_STREAM read).
    Done,
}

/// The h2 codec of one connection to a server, one stream at a time.
#[derive(Debug)]
pub struct H2SrvCodec {
    /// Frames to write, from `out_off`.
    out: Vec<u8>,
    out_off: usize,
    /// Bytes read, not yet a whole frame.
    inb: Vec<u8>,
    /// Response text for the session, from `rsp_off`.
    rsp: Vec<u8>,
    rsp_off: usize,
    /// A header block in progress (HEADERS then CONTINUATION).
    hblock: Vec<u8>,
    /// The stream of `hblock`, 0 for none; its HEADERS flags.
    hb_stream: u32,
    hb_flags: u8,
    /// A request header block before it is cut into frames.
    scratch: Vec<u8>,
    dec: HpackDecoder,
    fields: DecodedFields,
    /// The next stream id, the stream in progress (0: none), streams opened.
    next_id: u32,
    cur: u32,
    opened: u32,
    req: ReqBody,
    rsp_state: Rsp,
    head_req: bool,
    /// Our send windows and the server's settings.
    conn_win: i64,
    strm_win: i64,
    peer_init_win: i64,
    peer_max_frame: usize,
    /// DATA bytes read and not yet granted back: on the stream, on the connection.
    rx_strm: u32,
    rx_conn: u32,
    /// What the server may still send: on the stream (our SETTINGS, 16384, and our grants),
    /// on the connection (65535 and our grants).
    strm_rx_win: i64,
    conn_rx_win: i64,
    conn_window_opened: bool,
    goaway: Option<u32>,
    /// A connection error was sent; nothing more is read or written but the GOAWAY.
    conn_error: Option<u32>,
    /// A stream error found while [`Self::advance_response`] read held frames, given by the
    /// next call that can return it.
    stream_error: Option<SrvH2Error>,
    /// The last stream ended on an error.
    failed: bool,
    /// T559: the last DATA byte of a content-length body, held back until the stream ends so
    /// that trailers after it can be told to the session first ([`Self::take_late_trailers`]).
    held: Option<u8>,
    /// The trailer section (`name: value\r\n` lines, the blank line) that followed a
    /// content-length body, for a client that can carry it; an h1 client never asks.
    late: Vec<u8>,
    /// No new stream on this connection.
    no_reuse: bool,
    /// X3b-2: the index of the last final response head written into [`Self::rsp`], as
    /// [`crate::response_head::check_response_head`] would make it of those bytes, for the
    /// engine to read instead of parsing them ([`Self::take_head_index`]). `None` for a head
    /// that index would not hold (more fields than it takes, a byte that is not visible ASCII,
    /// a field the check would write again): the engine parses that one.
    head_ix: Option<crate::response_head::RspHead>,
}

impl Default for H2SrvCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl ibex_alloc::Poolable for H2SrvCodec {
    fn footprint(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.out.capacity()
            + self.inb.capacity()
            + self.rsp.capacity()
            + self.hblock.capacity()
            + self.scratch.capacity()
            + self.late.capacity()
            + self.dec.dynamic_table.size()
    }

    fn reset(&mut self, wipe: bool) {
        if wipe {
            for v in [&mut self.out, &mut self.inb, &mut self.rsp, &mut self.hblock, &mut self.scratch, &mut self.late] {
                ibex_alloc::wipe_vec(v);
            }
        }
        self.restart();
    }

    fn try_new() -> Option<Self> {
        Some(Self::new())
    }
}

/// The largest response text kept before frames stop being read: a stream window (16384)
/// and its framing.
const RSP_ROOM: usize = 32 * 1024;

/// HAProxy's SETTINGS for a connection to a server, in its order.
const SETTINGS: [(u16, u32); 4] = [(0x2, 0), (0x8, 1), (0x4, OUR_INITIAL_WINDOW), (0x3, 100)];
const OUR_INITIAL_WINDOW: u32 = 16_384;

/// `H2_INITIAL_WINDOW_INCREMENT`: the connection window's opening, added to the first
/// connection WINDOW_UPDATE.
const CONN_WINDOW_OPENING: u32 = MAX_WINDOW_SIZE as u32 - 65_535;

#[cfg(debug_assertions)]
thread_local! {
    static TEXT_HEADS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Request heads this thread's codecs read as HTTP/1.1 text ([`H2SrvCodec::send_request`])
/// instead of taking them as HTX blocks ([`H2SrvCodec::send_head`]); debug builds, 0 in
/// release. X8 pins that a head the engine holds as blocks is not parsed again.
#[must_use]
pub fn text_heads() -> u64 {
    #[cfg(debug_assertions)]
    return TEXT_HEADS.with(std::cell::Cell::get);
    #[cfg(not(debug_assertions))]
    0
}

fn push_frame_header(out: &mut Vec<u8>, len: usize, typ: FrameType, flags: u8, sid: u32) {
    let h = FrameHeader { length: len as u32, frame_type: typ, flags, stream_id: sid };
    out.extend_from_slice(&h.encode());
}

fn crlf_at(b: &[u8]) -> Option<usize> {
    memchr::memmem::find(b, b"\r\n")
}

fn trim(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| !matches!(c, b' ' | b'\t')).unwrap_or(b.len());
    let e = b.iter().rposition(|c| !matches!(c, b' ' | b'\t')).map_or(s, |e| e + 1);
    &b[s..e.max(s)]
}

fn parse_u64(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 19 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(b.iter().fold(0u64, |a, &d| a * 10 + u64::from(d - b'0')))
}

/// `te` as HAProxy keeps it: `trailers` found, at the end or before a comma.
fn te_has_trailers(v: &[u8]) -> bool {
    let lower = |i: usize| v[i..i + 8].eq_ignore_ascii_case(b"trailers");
    (0..v.len().saturating_sub(7)).find(|&i| lower(i)).is_some_and(|i| v.len() == i + 8 || v[i + 8] == b',')
}

impl H2SrvCodec {
    /// A codec for a new connection: the preface and SETTINGS are in [`Self::output`].
    #[must_use]
    pub fn new() -> Self {
        let mut c = Self {
            out: Vec::with_capacity(512),
            out_off: 0,
            inb: Vec::new(),
            rsp: Vec::new(),
            rsp_off: 0,
            hblock: Vec::new(),
            hb_stream: 0,
            hb_flags: 0,
            scratch: Vec::new(),
            dec: HpackDecoder::new(),
            fields: DecodedFields::default(),
            next_id: 1,
            cur: 0,
            opened: 0,
            req: ReqBody::Idle,
            rsp_state: Rsp::Waiting,
            head_req: false,
            conn_win: 65_535,
            strm_win: 65_535,
            peer_init_win: 65_535,
            peer_max_frame: DEFAULT_MAX_FRAME_SIZE as usize,
            rx_strm: 0,
            rx_conn: 0,
            strm_rx_win: i64::from(OUR_INITIAL_WINDOW),
            conn_rx_win: 65_535,
            conn_window_opened: false,
            goaway: None,
            conn_error: None,
            stream_error: None,
            failed: false,
            held: None,
            late: Vec::new(),
            head_ix: None,
            no_reuse: false,
        };
        c.restart();
        c
    }

    /// A codec from this thread's `h2c_srv` pool (its buffers kept from the connection
    /// before), `None` when memory is short.
    #[must_use]
    pub fn take() -> Option<ibex_alloc::PoolBox<Self>> {
        H2C_SRV.take()
    }

    /// Back to a new connection's state, the memory kept.
    fn restart(&mut self) {
        self.out.clear();
        self.out_off = 0;
        self.inb.clear();
        self.rsp.clear();
        self.rsp_off = 0;
        self.held = None;
        self.late.clear();
        self.head_ix = None;
        self.hblock.clear();
        self.hb_stream = 0;
        self.hb_flags = 0;
        self.scratch.clear();
        self.dec.dynamic_table.clear();
        self.dec.dynamic_table.set_max_size(DEFAULT_DYNAMIC_TABLE_MAX_SIZE);
        self.dec.max_allowed_table_size = DEFAULT_DYNAMIC_TABLE_MAX_SIZE;
        self.fields.clear();
        self.next_id = 1;
        self.cur = 0;
        self.opened = 0;
        self.req = ReqBody::Idle;
        self.rsp_state = Rsp::Waiting;
        self.head_req = false;
        self.conn_win = 65_535;
        self.strm_win = 65_535;
        self.peer_init_win = 65_535;
        self.peer_max_frame = DEFAULT_MAX_FRAME_SIZE as usize;
        self.rx_strm = 0;
        self.rx_conn = 0;
        self.strm_rx_win = i64::from(OUR_INITIAL_WINDOW);
        self.conn_rx_win = 65_535;
        self.conn_window_opened = false;
        self.goaway = None;
        self.conn_error = None;
        self.stream_error = None;
        self.failed = false;
        self.no_reuse = false;
        self.out.extend_from_slice(H2_CONN_PREFACE);
        push_frame_header(&mut self.out, SETTINGS.len() * 6, FrameType::Settings, 0, 0);
        for (id, v) in SETTINGS {
            self.out.extend_from_slice(&id.to_be_bytes());
            self.out.extend_from_slice(&v.to_be_bytes());
        }
    }

    /// Frames to write to the server.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.out[self.out_off..]
    }

    /// `n` bytes of [`Self::output`] were written.
    pub fn advance_output(&mut self, n: usize) {
        self.out_off = (self.out_off + n).min(self.out.len());
        if self.out_off == self.out.len() {
            self.out.clear();
            self.out_off = 0;
        }
    }

    /// Response text for the session.
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.rsp[self.rsp_off..]
    }

    /// The session took `n` bytes of [`Self::response`]. Once it took all, the DATA bytes
    /// behind them are granted back to the server (WINDOW_UPDATE), and frames held for room
    /// are read on.
    pub fn advance_response(&mut self, n: usize) {
        self.rsp_off = (self.rsp_off + n).min(self.rsp.len());
        if self.rsp_off < self.rsp.len() {
            return;
        }
        self.rsp.clear();
        self.rsp_off = 0;
        self.grant();
        if !self.inb.is_empty() {
            // Frames held while the text was full; an error comes back on the next call.
            if let Err(e) = self.process() {
                self.stream_error.get_or_insert(e);
            }
        }
    }

    /// WINDOW_UPDATE for the DATA bytes the session took: the stream's while it is open, then
    /// the connection's, the first of which also opens it to 2^31-1 (`h2c_send_conn_wu`:
    /// HAProxy's first increment is what it read plus 2^31-1-65535, measured `0x7fff0002`
    /// after a 2-byte body).
    fn grant(&mut self) {
        if self.conn_error.is_some() {
            return;
        }
        if self.rx_strm > 0 && self.cur != 0 && !matches!(self.rsp_state, Rsp::Done) {
            push_frame_header(&mut self.out, 4, FrameType::WindowUpdate, 0, self.cur);
            self.out.extend_from_slice(&self.rx_strm.to_be_bytes());
            self.strm_rx_win += i64::from(self.rx_strm);
        }
        self.rx_strm = 0;
        if self.rx_conn > 0 {
            let mut inc = self.rx_conn;
            if !self.conn_window_opened {
                self.conn_window_opened = true;
                inc = inc.saturating_add(CONN_WINDOW_OPENING);
            }
            push_frame_header(&mut self.out, 4, FrameType::WindowUpdate, 0, 0);
            self.out.extend_from_slice(&inc.to_be_bytes());
            self.conn_rx_win += i64::from(inc);
            self.rx_conn = 0;
        }
    }

    /// No stream in progress: a request may start.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.cur == 0
    }

    /// The last stream's response ended (END_STREAM read and its text written).
    #[must_use]
    pub fn response_complete(&self) -> bool {
        self.cur == 0 && self.opened > 0 && !self.failed
    }

    /// A new stream may be opened on this connection.
    #[must_use]
    pub fn reusable(&self) -> bool {
        !self.no_reuse && self.goaway.is_none() && self.conn_error.is_none() && self.next_id < 0x7fff_fff0
    }

    /// Streams opened on this connection (for `max-reuse`).
    #[must_use]
    pub fn streams(&self) -> u32 {
        self.opened
    }

    fn conn_fail(&mut self, code: u32) -> SrvH2Error {
        if self.conn_error.is_none() {
            self.conn_error = Some(code);
            self.no_reuse = true;
            push_frame_header(&mut self.out, 8, FrameType::GoAway, 0, 0);
            self.out.extend_from_slice(&0u32.to_be_bytes());
            self.out.extend_from_slice(&code.to_be_bytes());
        }
        SrvH2Error::Connection(code)
    }

    /// Ends the current stream on an error: RST_STREAM `rst` when given (the server has not
    /// closed it), the stream forgotten, the connection kept unless the request was cut.
    fn stream_fail(&mut self, e: SrvH2Error, rst: Option<u32>) -> SrvH2Error {
        if let Some(code) = rst {
            push_frame_header(&mut self.out, 4, FrameType::RstStream, 0, self.cur);
            self.out.extend_from_slice(&code.to_be_bytes());
        }
        if !matches!(self.req, ReqBody::Done | ReqBody::Idle) {
            // The session still has request bytes for this stream: not worth sorting out.
            self.no_reuse = true;
        }
        self.cur = 0;
        self.req = ReqBody::Idle;
        self.rsp_state = Rsp::Waiting;
        self.failed = true;
        e
    }

    // ------------------------------------------------------------------------------------
    // Request side
    // ------------------------------------------------------------------------------------

    /// Takes HTTP/1.1 request text: a head when no stream is in progress, then its body.
    /// Returns the bytes of `src` used; fewer when the head is not whole yet, the server's
    /// window is spent, or a chunk-size line or the trailers are not whole yet.
    ///
    /// # Errors
    /// [`SrvH2Error::Unsupported`] for a request h2 cannot carry here (nothing written), a
    /// connection or stream error from before.
    pub fn send_request(&mut self, src: &[u8]) -> Result<usize, SrvH2Error> {
        if let Some(code) = self.conn_error {
            return Err(SrvH2Error::Connection(code));
        }
        let mut used = 0;
        if self.req == ReqBody::Idle {
            if src.is_empty() {
                return Ok(0);
            }
            self.can_open()?;
            used = self.start_request(src)?;
            if used == 0 {
                return Ok(0);
            }
        }
        used += self.send_body(&src[used..]);
        Ok(used)
    }

    /// What stops a new stream: a stream error from before, a connection that cannot carry one.
    fn can_open(&mut self) -> Result<(), SrvH2Error> {
        if let Some(e) = self.stream_error.take() {
            return Err(e);
        }
        if !self.reusable() {
            return Err(SrvH2Error::Refused);
        }
        Ok(())
    }

    /// The head of the next request as the blocks of its HTX (X8): HEADERS (and
    /// CONTINUATION) written from the request line and the header blocks, nothing parsed.
    /// `chunked`: the body that follows is chunked though no `transfer-encoding` block says
    /// so (an HTTP/2 or HTTP/3 client's, which the engine frames as chunks). The body goes
    /// through [`Self::send_request`] after it, as the bytes that follow the head.
    ///
    /// # Errors
    /// As [`Self::send_request`], and [`SrvH2Error::Unsupported`] for a head with no request
    /// line.
    pub fn send_head(&mut self, htx: HtxSliceRef<'_>, chunked: bool) -> Result<(), SrvH2Error> {
        if let Some(code) = self.conn_error {
            return Err(SrvH2Error::Connection(code));
        }
        debug_assert!(self.req == ReqBody::Idle, "a head while a request is in progress");
        self.can_open()?;
        let Some(rl) = htx.req_line_bytes() else { return Err(SrvH2Error::Unsupported("request line")) };
        self.open_stream(rl.method, rl.uri, chunked, htx.header_bytes().map(|(n, v, latin1)| Ok((n, v, latin1))))
    }

    /// The head: HEADERS (and CONTINUATION). Returns the bytes used, 0 when not whole.
    fn start_request(&mut self, src: &[u8]) -> Result<usize, SrvH2Error> {
        let Some(end) = memchr::memmem::find(src, b"\r\n\r\n") else { return Ok(0) };
        #[cfg(debug_assertions)]
        TEXT_HEADS.with(|c| c.set(c.get() + 1));
        let head = &src[..end + 2];
        let Some(rl_end) = crlf_at(head) else { return Err(SrvH2Error::Unsupported("request line")) };
        let rl = &head[..rl_end];
        let mut parts = rl.splitn(3, |&b| b == b' ');
        let (Some(method), Some(target), Some(ver)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(SrvH2Error::Unsupported("request line"));
        };
        if !ver.starts_with(b"HTTP/1.") {
            return Err(SrvH2Error::Unsupported("request line"));
        }
        let mut rest = &head[rl_end + 2..];
        let lines = std::iter::from_fn(|| {
            let e = crlf_at(rest)?;
            let line = &rest[..e];
            rest = &rest[e + 2..];
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                return Some(Err(SrvH2Error::Unsupported("header line without a colon")));
            };
            Some(Ok((trim(&line[..colon]), trim(&line[colon + 1..]), false)))
        });
        self.open_stream(method, target, false, lines)?;
        Ok(end + 4)
    }

    /// The stream a request opens, from its method, target and header fields (name, value,
    /// whether the value is held as Latin-1 text, [`ibex_regex::bytetext`]), as
    /// `h2s_snd_bhdrs` writes it: scheme and authority from an absolute target, userinfo
    /// dropped, `*` or `/` for an empty path, CONNECT refused, the connection-specific
    /// fields dropped. `chunked`: the body is chunked whatever the fields say.
    fn open_stream<'a>(
        &mut self,
        method: &[u8],
        target: &[u8],
        chunked: bool,
        fields: impl Iterator<Item = Result<(&'a [u8], &'a [u8], bool), SrvH2Error>>,
    ) -> Result<(), SrvH2Error> {
        self.head_ix = None;
        if method.is_empty() || target.is_empty() {
            return Err(SrvH2Error::Unsupported("request line"));
        }
        if method == b"CONNECT" {
            return Err(SrvH2Error::Unsupported("CONNECT to an h2 server"));
        }
        // h2s_snd_bhdrs: an absolute target gives the scheme and the authority (less any
        // userinfo); an origin-form one leaves the scheme `https`.
        let mut scheme: &[u8] = b"https";
        let mut auth: &[u8] = b"";
        let mut path = target;
        if target[0] != b'/' && target[0] != b'*' {
            if let Some(c) = target.iter().position(|&b| b == b':') {
                if target.len() > c + 2 && &target[c + 1..c + 3] == b"//" {
                    scheme = &target[..c];
                    let rest = &target[c + 3..];
                    let a = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
                    auth = &rest[..a];
                    if let Some(at) = auth.iter().rposition(|&b| b == b'@') {
                        auth = &auth[at + 1..];
                    }
                    path = &rest[a..];
                }
            }
        }
        if path.is_empty() {
            path = if method == b"OPTIONS" { b"*" } else { b"/" };
        }

        let mut body = if chunked { ReqBody::ChunkSize } else { ReqBody::Done };
        let mut blk = std::mem::take(&mut self.scratch);
        blk.clear();
        match method {
            b"GET" => blk.push(0x82),
            b"POST" => blk.push(0x83),
            m => encode_field_stateless(b":method", m, &mut blk),
        }
        match scheme {
            b"https" => blk.push(0x87),
            b"http" => blk.push(0x86),
            s => encode_field_stateless(b":scheme", s, &mut blk),
        }
        if !auth.is_empty() {
            encode_field_stateless(b":authority", auth, &mut blk);
        }
        match path {
            b"/" => blk.push(0x84),
            b"/index.html" => blk.push(0x85),
            p => encode_field_stateless(b":path", p, &mut blk),
        }
        for field in fields {
            let (name, value, latin1) = match field {
                Ok(f) => f,
                Err(e) => {
                    self.scratch = blk;
                    return Err(e);
                }
            };
            // The bytes a Latin-1 value stands for; borrowed unless one is escaped.
            let value = match std::str::from_utf8(value) {
                Ok(text) if latin1 => ibex_regex::bytetext::text_to_bytes(text),
                _ => std::borrow::Cow::Borrowed(value),
            };
            let value = &*value;
            let is = |n: &[u8]| name.eq_ignore_ascii_case(n);
            if is(b"connection") || is(b"proxy-connection") || is(b"keep-alive") || is(b"upgrade") {
                continue;
            }
            if is(b"transfer-encoding") {
                if value.len() >= 7 && value[value.len() - 7..].eq_ignore_ascii_case(b"chunked") {
                    body = ReqBody::ChunkSize;
                }
                continue;
            }
            if is(b"host") && !auth.is_empty() {
                continue;
            }
            if is(b"te") {
                if te_has_trailers(value) {
                    encode_field_stateless(b"te", b"trailers", &mut blk);
                }
                continue;
            }
            if is(b"content-length") && body == ReqBody::Done {
                match parse_u64(value) {
                    Some(0) => {}
                    Some(n) => body = ReqBody::Length(n),
                    None => {
                        self.scratch = blk;
                        return Err(SrvH2Error::Unsupported("content-length"));
                    }
                }
            }
            encode_field_stateless(name, value, &mut blk);
        }
        self.cur = self.next_id;
        self.next_id += 2;
        self.opened += 1;
        self.strm_win = self.peer_init_win;
        self.rx_strm = 0;
        self.strm_rx_win = i64::from(OUR_INITIAL_WINDOW);
        self.head_req = method == b"HEAD";
        self.failed = false;
        self.held = None;
        self.late.clear();
        self.rsp_state = Rsp::Waiting;
        self.req = body;
        let es = if body == ReqBody::Done { frame_flags::END_STREAM } else { 0 };
        self.put_header_block(&blk, es);
        self.scratch = blk;
        Ok(())
    }

    /// One header block as HEADERS and CONTINUATION frames of at most the server's
    /// MAX_FRAME_SIZE (`h2_fragment_headers`).
    fn put_header_block(&mut self, blk: &[u8], es: u8) {
        let max = self.peer_max_frame.max(1);
        let mut chunks = blk.chunks(max).peekable();
        let first = chunks.next().unwrap_or(&[]);
        let last = chunks.peek().is_none();
        let eh = if last { frame_flags::END_HEADERS } else { 0 };
        push_frame_header(&mut self.out, first.len(), FrameType::Headers, eh | es, self.cur);
        self.out.extend_from_slice(first);
        while let Some(c) = chunks.next() {
            let eh = if chunks.peek().is_none() { frame_flags::END_HEADERS } else { 0 };
            push_frame_header(&mut self.out, c.len(), FrameType::Continuation, eh, self.cur);
            self.out.extend_from_slice(c);
        }
    }

    /// The window left for DATA now.
    fn window(&self) -> usize {
        self.conn_win.min(self.strm_win).clamp(0, i64::from(MAX_WINDOW_SIZE)) as usize
    }

    /// Body bytes: DATA frames under the windows. Returns the bytes used.
    fn send_body(&mut self, src: &[u8]) -> usize {
        let mut used = 0;
        // The DATA frame being filled: where its header is, its length so far.
        let mut open: Option<(usize, usize)> = None;
        loop {
            match self.req {
                ReqBody::Idle | ReqBody::Done => break,
                ReqBody::Discard => {
                    used = src.len();
                    break;
                }
                ReqBody::Length(left) => {
                    let n = self.data_room(open).min(src.len() - used).min(usize::try_from(left).unwrap_or(usize::MAX));
                    if n == 0 {
                        break;
                    }
                    self.put_data(&mut open, &src[used..used + n]);
                    used += n;
                    let left = left - n as u64;
                    if left == 0 {
                        self.close_data(&mut open, true);
                        self.req = ReqBody::Done;
                    } else {
                        self.req = ReqBody::Length(left);
                        if self.data_room(open) == 0 {
                            self.close_data(&mut open, false);
                        }
                    }
                }
                ReqBody::ChunkSize => {
                    let Some(e) = crlf_at(&src[used..]) else { break };
                    let line = &src[used..used + e];
                    let digits = line.iter().position(|&b| !b.is_ascii_hexdigit()).unwrap_or(line.len());
                    let size = line[..digits].iter().take(15).fold(0u64, |a, &d| (a << 4) | u64::from((d as char).to_digit(16).unwrap_or(0)));
                    used += e + 2;
                    self.req = if size == 0 { ReqBody::Trailers } else { ReqBody::ChunkData(size) };
                }
                ReqBody::ChunkData(left) => {
                    let n = self.data_room(open).min(src.len() - used).min(usize::try_from(left).unwrap_or(usize::MAX));
                    if n == 0 {
                        break;
                    }
                    self.put_data(&mut open, &src[used..used + n]);
                    used += n;
                    let left = left - n as u64;
                    self.req = if left == 0 { ReqBody::ChunkCrlf } else { ReqBody::ChunkData(left) };
                    if self.data_room(open) == 0 {
                        self.close_data(&mut open, false);
                    }
                }
                ReqBody::ChunkCrlf => {
                    if src.len() - used < 2 {
                        break;
                    }
                    used += 2;
                    self.req = ReqBody::ChunkSize;
                }
                ReqBody::Trailers => {
                    let t = &src[used..];
                    if t.starts_with(b"\r\n") {
                        self.close_data(&mut open, false);
                        push_frame_header(&mut self.out, 0, FrameType::Data, frame_flags::END_STREAM, self.cur);
                        used += 2;
                        self.req = ReqBody::Done;
                        continue;
                    }
                    let Some(end) = memchr::memmem::find(t, b"\r\n\r\n") else { break };
                    self.close_data(&mut open, false);
                    let mut blk = std::mem::take(&mut self.scratch);
                    blk.clear();
                    let mut rest = &t[..end + 2];
                    while let Some(e) = crlf_at(rest) {
                        let line = &rest[..e];
                        rest = &rest[e + 2..];
                        if let Some(colon) = line.iter().position(|&b| b == b':') {
                            encode_field_stateless(trim(&line[..colon]), trim(&line[colon + 1..]), &mut blk);
                        }
                    }
                    self.put_header_block(&blk, frame_flags::END_STREAM);
                    self.scratch = blk;
                    used += end + 4;
                    self.req = ReqBody::Done;
                }
            }
        }
        self.close_data(&mut open, false);
        used
    }

    /// Room for DATA bytes now: the windows and the frame being filled.
    fn data_room(&self, open: Option<(usize, usize)>) -> usize {
        let in_frame = open.map_or(0, |(_, l)| l);
        self.window().min(self.peer_max_frame.saturating_sub(in_frame))
    }

    fn put_data(&mut self, open: &mut Option<(usize, usize)>, d: &[u8]) {
        let (at, len) = *open.get_or_insert_with(|| {
            let at = self.out.len();
            push_frame_header(&mut self.out, 0, FrameType::Data, 0, self.cur);
            (at, 0)
        });
        self.out.extend_from_slice(d);
        *open = Some((at, len + d.len()));
        self.conn_win -= d.len() as i64;
        self.strm_win -= d.len() as i64;
    }

    /// Writes the length (and END_STREAM) of the DATA frame being filled.
    fn close_data(&mut self, open: &mut Option<(usize, usize)>, es: bool) {
        if let Some((at, len)) = open.take() {
            let h = FrameHeader { length: len as u32, frame_type: FrameType::Data, flags: if es { frame_flags::END_STREAM } else { 0 }, stream_id: self.cur };
            self.out[at..at + FRAME_HEADER_LEN].copy_from_slice(&h.encode());
        }
    }

    // ------------------------------------------------------------------------------------
    // Response side
    // ------------------------------------------------------------------------------------

    /// Bytes read from the server. Frames are handled until the response text has
    /// [`RSP_ROOM`]; the rest waits in the codec for [`Self::advance_response`].
    ///
    /// # Errors
    /// The stream's or the connection's error ([`SrvH2Error`]); after a connection error the
    /// GOAWAY is in [`Self::output`].
    pub fn receive(&mut self, src: &[u8]) -> Result<(), SrvH2Error> {
        if let Some(code) = self.conn_error {
            return Err(SrvH2Error::Connection(code));
        }
        if let Some(e) = self.stream_error.take() {
            self.inb.extend_from_slice(src);
            return Err(e);
        }
        self.inb.extend_from_slice(src);
        self.process()?;
        if self.response().is_empty() {
            self.grant();
        }
        Ok(())
    }

    fn process(&mut self) -> Result<(), SrvH2Error> {
        if let Some(code) = self.conn_error {
            return Err(SrvH2Error::Connection(code));
        }
        let mut at = 0;
        let mut stream_err = None;
        let r = loop {
            if self.rsp.len() - self.rsp_off >= RSP_ROOM {
                break Ok(());
            }
            let buf = &self.inb[at..];
            if buf.len() < FRAME_HEADER_LEN {
                break Ok(());
            }
            let Ok(h) = FrameHeader::decode(buf) else { break Ok(()) };
            if h.length > DEFAULT_MAX_FRAME_SIZE {
                break Err(self.conn_fail(0x6));
            }
            let total = FRAME_HEADER_LEN + h.length as usize;
            if buf.len() < total {
                break Ok(());
            }
            // The payload is moved out of `inb` for the call (its memory kept).
            let mut inb = std::mem::take(&mut self.inb);
            let r = self.on_frame(&h, &inb[at + FRAME_HEADER_LEN..at + total]);
            at += total;
            std::mem::swap(&mut self.inb, &mut inb);
            match r {
                Err(e @ SrvH2Error::Connection(_)) => break Err(e),
                // A stream error: the frames after it (a GOAWAY) are still read.
                Err(e) => {
                    stream_err.get_or_insert(e);
                }
                Ok(()) => {}
            }
        };
        self.inb.drain(..at);
        r?;
        stream_err.map_or(Ok(()), Err)
    }

    fn on_frame(&mut self, h: &FrameHeader, p: &[u8]) -> Result<(), SrvH2Error> {
        if self.hb_stream != 0 && (h.frame_type != FrameType::Continuation || h.stream_id != self.hb_stream) {
            return Err(self.conn_fail(0x1));
        }
        match h.frame_type {
            FrameType::Data => {
                if h.stream_id == 0 {
                    return Err(self.conn_fail(0x1));
                }
                self.rx_conn = self.rx_conn.saturating_add(h.length);
                self.conn_rx_win -= i64::from(h.length);
                if self.conn_rx_win < 0 {
                    return Err(self.conn_fail(0x3));
                }
                if h.stream_id != self.cur {
                    return self.closed_stream(h.stream_id);
                }
                self.rx_strm = self.rx_strm.saturating_add(h.length);
                self.strm_rx_win -= i64::from(h.length);
                if self.strm_rx_win < 0 {
                    return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x3)));
                }
                let mut d = p;
                if h.flags & frame_flags::PADDED != 0 {
                    let Some((&pad, rest)) = d.split_first() else { return Err(self.conn_fail(0x6)) };
                    if usize::from(pad) > rest.len() {
                        return Err(self.conn_fail(0x1));
                    }
                    d = &rest[..rest.len() - usize::from(pad)];
                }
                self.on_data(d, h.flags & frame_flags::END_STREAM != 0)
            }
            FrameType::Headers => {
                if h.stream_id == 0 {
                    return Err(self.conn_fail(0x1));
                }
                let block = match Frame::headers_block(h, p) {
                    Ok(b) => b,
                    Err(e) => return Err(self.conn_fail(if e.kind() == std::io::ErrorKind::InvalidInput { 0x6 } else { 0x1 })),
                };
                self.hblock.clear();
                self.hblock.extend_from_slice(block);
                self.hb_flags = h.flags;
                if h.flags & frame_flags::END_HEADERS == 0 {
                    self.hb_stream = h.stream_id;
                    return Ok(());
                }
                self.on_header_block(h.stream_id)
            }
            FrameType::Continuation => {
                if self.hb_stream == 0 {
                    return Err(self.conn_fail(0x1));
                }
                self.hblock.extend_from_slice(p);
                if h.flags & frame_flags::END_HEADERS == 0 {
                    return Ok(());
                }
                self.hb_stream = 0;
                self.on_header_block(h.stream_id)
            }
            FrameType::RstStream => {
                if h.stream_id == 0 || p.len() != 4 {
                    return Err(self.conn_fail(if p.len() != 4 { 0x6 } else { 0x1 }));
                }
                let code = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
                if h.stream_id != self.cur {
                    return Ok(());
                }
                let before = self.rsp_state == Rsp::Waiting;
                let e = if before && code == 0x7 { SrvH2Error::Refused } else { SrvH2Error::Reset { code, after_head: !before } };
                Err(self.stream_fail(e, None))
            }
            FrameType::Settings => self.on_settings(h, p),
            FrameType::PushPromise => Err(self.conn_fail(0x1)),
            FrameType::Ping => {
                if h.stream_id != 0 || p.len() != 8 {
                    return Err(self.conn_fail(if p.len() != 8 { 0x6 } else { 0x1 }));
                }
                if h.flags & frame_flags::ACK == 0 {
                    push_frame_header(&mut self.out, 8, FrameType::Ping, frame_flags::ACK, 0);
                    self.out.extend_from_slice(p);
                }
                Ok(())
            }
            FrameType::GoAway => {
                if h.stream_id != 0 || p.len() < 8 {
                    return Err(self.conn_fail(0x1));
                }
                let last = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff;
                self.goaway = Some(self.goaway.map_or(last, |g| g.min(last)));
                self.no_reuse = true;
                if self.cur != 0 && self.cur > last {
                    return Err(self.stream_fail(SrvH2Error::Refused, None));
                }
                Ok(())
            }
            FrameType::WindowUpdate => {
                if p.len() != 4 {
                    return Err(self.conn_fail(0x6));
                }
                let inc = i64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
                if h.stream_id == 0 {
                    if inc == 0 {
                        return Err(self.conn_fail(0x1));
                    }
                    self.conn_win += inc;
                    if self.conn_win > i64::from(MAX_WINDOW_SIZE) {
                        return Err(self.conn_fail(0x3));
                    }
                } else if h.stream_id == self.cur {
                    if inc == 0 {
                        return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1)));
                    }
                    self.strm_win += inc;
                    if self.strm_win > i64::from(MAX_WINDOW_SIZE) {
                        return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x3)));
                    }
                }
                Ok(())
            }
            // PRIORITY and unknown types are ignored (RFC 9113 sections 5.5, 6.3).
            _ => Ok(()),
        }
    }

    /// A frame for a stream that is not the current one: closed (earlier) streams are
    /// ignored, a stream we never opened is a connection error.
    fn closed_stream(&mut self, sid: u32) -> Result<(), SrvH2Error> {
        if sid >= self.next_id || sid.is_multiple_of(2) {
            return Err(self.conn_fail(0x1));
        }
        Ok(())
    }

    fn on_settings(&mut self, h: &FrameHeader, p: &[u8]) -> Result<(), SrvH2Error> {
        if h.stream_id != 0 {
            return Err(self.conn_fail(0x1));
        }
        if h.flags & frame_flags::ACK != 0 {
            return if p.is_empty() { Ok(()) } else { Err(self.conn_fail(0x6)) };
        }
        if !p.len().is_multiple_of(6) {
            return Err(self.conn_fail(0x6));
        }
        for s in p.chunks_exact(6) {
            let id = u16::from_be_bytes([s[0], s[1]]);
            let v = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
            match id {
                0x4 => {
                    if v > MAX_WINDOW_SIZE as u32 {
                        return Err(self.conn_fail(0x3));
                    }
                    let d = i64::from(v) - self.peer_init_win;
                    self.peer_init_win = i64::from(v);
                    if self.cur != 0 {
                        self.strm_win += d;
                    }
                }
                0x5 => {
                    if !(16_384..=16_777_215).contains(&v) {
                        return Err(self.conn_fail(0x1));
                    }
                    self.peer_max_frame = v as usize;
                }
                0x2 if v > 1 => return Err(self.conn_fail(0x1)),
                _ => {}
            }
        }
        push_frame_header(&mut self.out, 0, FrameType::Settings, frame_flags::ACK, 0);
        Ok(())
    }

    fn on_header_block(&mut self, sid: u32) -> Result<(), SrvH2Error> {
        let block = std::mem::take(&mut self.hblock);
        let r = self.dec.decode_into(&block, &mut self.fields);
        self.hblock = block;
        if r.is_err() {
            return Err(self.conn_fail(0x9));
        }
        if sid != self.cur || self.cur == 0 {
            return self.closed_stream(sid);
        }
        let es = self.hb_flags & frame_flags::END_STREAM != 0;
        match self.rsp_state {
            // (`Done` has no current stream: not here.)
            Rsp::Waiting | Rsp::Done => self.on_response_head(es),
            Rsp::Body { chunked, .. } => {
                // Trailers: END_STREAM, no pseudo-header.
                if !es || crate::h2::check_trailer_fields(self.fields.iter_text()).is_err() {
                    return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1)));
                }
                if chunked {
                    self.rsp.extend_from_slice(b"0\r\n");
                    for (n, v) in self.fields.iter_text() {
                        push_field(&mut self.rsp, n, v);
                    }
                    self.rsp.extend_from_slice(b"\r\n");
                }
                // After a content-length body HAProxy's h1 side drops the trailers (measured),
                // an h2 or h3 client gets them (T559): kept for `take_late_trailers`, and the
                // last body byte goes out only now, so they are known before the body is.
                if !chunked {
                    self.late.clear();
                    for (n, v) in self.fields.iter_text() {
                        push_field(&mut self.late, n, v);
                    }
                    self.late.extend_from_slice(b"\r\n");
                }
                self.release_held();
                self.end_response(false);
                Ok(())
            }
        }
    }

    fn on_response_head(&mut self, es: bool) -> Result<(), SrvH2Error> {
        let mut status: Option<u16> = None;
        let mut regular = false;
        let mut cl: Option<u64> = None;
        let mut bad = crate::h2::check_response_fields(self.fields.iter_text()).is_err();
        for (n, v) in self.fields.iter_text() {
            if let Some(p) = n.strip_prefix(':') {
                bad |= p != "status" || regular || status.is_some();
                let b = v.as_bytes();
                status = (b.len() == 3 && b.iter().all(u8::is_ascii_digit)).then(|| v.parse().unwrap_or(0));
                continue;
            }
            regular = true;
            bad |= matches!(n, "connection" | "proxy-connection" | "keep-alive" | "upgrade" | "transfer-encoding");
            if n == "content-length" {
                match parse_u64(v.as_bytes()) {
                    Some(l) if cl.is_none_or(|c| c == l) => cl = Some(l),
                    _ => bad = true,
                }
            }
        }
        let status = match status {
            Some(s) if !bad && s >= 100 && s != 101 => s,
            _ => return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1))),
        };
        let interim = status < 200;
        if interim && es {
            return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1)));
        }
        let bodyless = self.head_req || status == 204 || status == 304;
        let chunked = !interim && !bodyless && cl.is_none();
        let r = &mut self.rsp;
        let base = r.len();
        r.extend_from_slice(b"HTTP/1.1 ");
        r.extend_from_slice(&crate::actions::status_digits(status));
        r.push(b' ');
        let reason = crate::actions::status_reason_phrase(status);
        r.extend_from_slice(reason.as_bytes());
        r.extend_from_slice(b"\r\n");
        // The index of the head as it is written (X3b-2): what `check_response_head` makes of
        // a canonical head, so the engine does not parse it. An interim head is not indexed
        // (the engine reads the final one), nor one with a duplicate `content-length` (the
        // check drops it) or a `content-length` on a 204.
        let mut ix = (!interim && !(cl.is_some() && status == 204))
            .then(|| crate::response_head::RspHead::written(status, 15 + reason.len() as u32));
        // (Every reason phrase is a non-empty ASCII word: the start line is canonical.)
        debug_assert!(15 + reason.len() == r.len() - base && !reason.is_empty() && reason.is_ascii());
        let mut cls = 0;
        for (n, v) in self.fields.iter_text().filter(|(n, _)| !n.starts_with(':')) {
            let at = r.len() - base;
            push_field(r, n, v);
            if n == "content-length" {
                cls += 1;
                let b = v.as_bytes();
                if cls > 1 || b.len() > 1 && b[0] == b'0' {
                    ix = None;
                }
            }
            ix = ix.filter(|_| written_field_canonical(n, v) && u32::try_from(r.len() - base).is_ok());
            if let Some(i) = ix.as_mut() {
                #[allow(clippy::cast_possible_truncation)]
                let ok = i.push_written(at as u32, (at + n.len()) as u32, (r.len() - base) as u32);
                if !ok {
                    ix = None;
                }
            }
        }
        if chunked {
            let at = r.len() - base;
            r.extend_from_slice(b"transfer-encoding: chunked\r\n");
            #[allow(clippy::cast_possible_truncation)]
            if ix.as_mut().is_some_and(|i| !i.push_written(at as u32, (at + 17) as u32, (r.len() - base) as u32)) {
                ix = None;
            }
        }
        r.extend_from_slice(b"\r\n");
        self.head_ix = ix.and_then(|mut i| {
            i.len = u32::try_from(r.len() - base).ok()?;
            Some(i)
        });
        if interim {
            return Ok(());
        }
        self.rsp_state = Rsp::Body { chunked, bodyless, left: if bodyless { None } else { cl } };
        if es {
            if cl.is_some_and(|l| l > 0) && !bodyless {
                return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1)));
            }
            self.end_response(chunked);
        }
        Ok(())
    }

    fn on_data(&mut self, d: &[u8], es: bool) -> Result<(), SrvH2Error> {
        let Rsp::Body { chunked, bodyless, left } = self.rsp_state else {
            return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1)));
        };
        if !bodyless && !d.is_empty() {
            if let Some(l) = left {
                if d.len() as u64 > l {
                    return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1)));
                }
                self.rsp_state = Rsp::Body { chunked, bodyless, left: Some(l - d.len() as u64) };
            }
            if chunked {
                push_chunk_size(&mut self.rsp, d.len());
                self.rsp.extend_from_slice(d);
                self.rsp.extend_from_slice(b"\r\n");
            } else {
                // The body's last byte waits for the stream's end (T559).
                let last = !es && matches!(self.rsp_state, Rsp::Body { left: Some(0), .. });
                self.rsp.extend_from_slice(&d[..d.len() - usize::from(last)]);
                if last {
                    self.held = d.last().copied();
                }
            }
        }
        if es {
            self.release_held();
            if let Rsp::Body { left: Some(l), .. } = self.rsp_state {
                if l > 0 {
                    return Err(self.stream_fail(SrvH2Error::BadResponse, Some(0x1)));
                }
            }
            self.end_response(chunked);
        }
        Ok(())
    }

    /// END_STREAM read: the last chunk when chunked, the stream closed when the request is
    /// all sent, else the request is cut (RST_STREAM CANCEL) and the connection not reused.
    /// Writes the body byte [`Self::held`] back, the stream having ended.
    fn release_held(&mut self) {
        if let Some(b) = self.held.take() {
            self.rsp.push(b);
        }
    }

    /// X3b-2: the index of the final response head last written into the response bytes,
    /// once (see [`Self::head_ix`]); `None` for a head the caller must parse.
    pub fn take_head_index(&mut self) -> Option<crate::response_head::RspHead> {
        self.head_ix.take()
    }

    /// The trailer section that followed the content-length body of the last response, as
    /// text for `h2_bridge` (T559), once; empty for none.
    pub fn take_late_trailers(&mut self) -> Option<ibex_alloc::PoolBox<Vec<u8>>> {
        if self.late.is_empty() {
            return None;
        }
        // No buffer to be had: the trailers are dropped, as for an h1 client.
        let b = H2_TRAILERS.take().map(|mut b| {
            b.extend_from_slice(&self.late);
            b
        });
        self.late.clear();
        b
    }

    fn end_response(&mut self, last_chunk: bool) {
        if last_chunk {
            self.rsp.extend_from_slice(b"0\r\n\r\n");
        }
        self.rsp_state = Rsp::Done;
        if self.req != ReqBody::Done {
            push_frame_header(&mut self.out, 4, FrameType::RstStream, 0, self.cur);
            self.out.extend_from_slice(&0x8u32.to_be_bytes());
            self.no_reuse = true;
            self.req = ReqBody::Discard;
        } else {
            self.req = ReqBody::Idle;
        }
        self.cur = 0;
        self.rx_strm = 0;
    }
}

/// A field line [`push_field`] writes is one `check_response_head` indexes as it is: a token
/// name, a value of visible ASCII and blanks with none at either end.
fn written_field_canonical(n: &str, v: &str) -> bool {
    let v = v.as_bytes();
    !n.is_empty()
        && n.bytes().all(crate::response_head::is_token)
        && v.iter().all(|&c| c == b'\t' || (b' '..=b'~').contains(&c))
        && v.first().is_none_or(|&c| c != b' ' && c != b'\t')
        && v.last().is_none_or(|&c| c != b' ' && c != b'\t')
}

fn push_field(out: &mut Vec<u8>, n: &str, v: &str) {
    out.extend_from_slice(n.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(v.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// A chunk size as HAProxy's h1 side writes it: uppercase hex.
fn push_chunk_size(out: &mut Vec<u8>, n: usize) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut d = [0u8; 16];
    let mut i = d.len();
    let mut v = n;
    loop {
        i -= 1;
        d[i] = HEX[v & 0xf];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    out.extend_from_slice(&d[i..]);
    out.extend_from_slice(b"\r\n");
}

