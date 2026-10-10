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
    frame_flags, Frame, FrameHeader, H2ConnState, H2Error, H2StreamState, SettingsParameter,
    DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_FRAME_SIZE, FRAME_HEADER_LEN, H2_CONN_PREFACE,
    MAX_MAX_FRAME_SIZE, MAX_WINDOW_SIZE, MIN_MAX_FRAME_SIZE,
};
use crate::hpack::{HpackDecoder, HpackEncoder};
use crate::htx::{HeaderField, HttpVersion, Htx, HtxBlock};
use crate::mux::{mux_flags, Mux, MuxFlags, MuxOps, ShutMode};
use std::collections::BTreeMap;
use std::io;

/// Output waiting for the client past which the demux stops: what a client that reads
/// nothing can make the connection queue in replies (RST_STREAM, PING and SETTINGS ACKs).
pub const TX_ROOM: usize = 65536;

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
    /// `scheme://authority` of a request that carried both pseudo-headers: what `HAProxy`
    /// puts before the path in the start line it logs and counts (`GET http://x/g HTTP/2.0`).
    pub abs_prefix: Option<String>,
}

impl H2StreamCtx {
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
            abs_prefix: None,
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
}

/// HTTP/2 Connection Context.
pub struct H2MuxContext {
    pub conn: ConnId,
    pub is_server: bool,
    pub conn_state: H2ConnState,
    pub rx_buf: Vec<u8>,
    pub tx_buf: Vec<u8>,
    pub tx_consumed: usize,
    pub streams: BTreeMap<u32, H2StreamCtx>,
    pub conn_send_window: i32,
    pub conn_recv_window: i32,
    pub remote_initial_window: i32,
    pub local_initial_window: i32,
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
    pub total_streams: usize,
    pub glitch_count: usize,
    pub graceful_goaway_sent: bool,
    /// The highest stream id that has had an entry in `streams`. A closed stream is taken
    /// out of the map when its transaction ends; an id at or below this one and not in the
    /// map is a closed stream, not a new one.
    pub highest_opened: u32,
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
            streams: BTreeMap::new(),
            conn_send_window: DEFAULT_INITIAL_WINDOW_SIZE,
            conn_recv_window: DEFAULT_INITIAL_WINDOW_SIZE,
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
            total_streams: 0,
            glitch_count: 0,
            graceful_goaway_sent: false,
            highest_opened: 0,
        }
    }

    /// Appends a frame to `tx_buf` for transmission to transport.
    pub fn enqueue_frame(&mut self, frame: &Frame) {
        if self.tx_consumed > 0 && self.tx_consumed >= self.tx_buf.len() {
            self.tx_buf.clear();
            self.tx_consumed = 0;
        }
        let encoded = frame.encode();
        self.tx_buf.extend_from_slice(&encoded);
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
            self.conn_recv_window = self.conn_recv_window.saturating_add(increment as i32);
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_window = stream.recv_window.saturating_add(increment as i32);
        }
    }

    /// The data path took `n` of the DATA bytes stream `stream_id` holds: as much room for
    /// more, so a demux held on that stream may go on ([`Self::resume`]).
    pub fn rx_taken(&mut self, stream_id: u32, n: usize) {
        if let Some(s) = self.streams.get_mut(&stream_id) {
            s.rx_buffered = s.rx_buffered.saturating_sub(n);
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
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = H2StreamState::Reset(error_code);
            stream.reset_reason = Some(error_code);
            stream.is_shut = true;
        }
    }

    /// Encodes and queues a HEADERS frame for a response, dropping the connection-specific
    /// headers HTTP/2 forbids (RFC 7540 section 8.1.2.2).
    fn send_headers_frame(&mut self, stream_id: u32, status: u16, headers: &[(String, String)], end_stream: bool) {
        let mut hpack_headers = vec![HeaderField {
            name: ":status".to_string(),
            value: status.to_string(),
        }];
        for (name, val) in headers {
            let lower = name.to_ascii_lowercase();
            if lower == "connection"
                || lower == "keep-alive"
                || lower == "proxy-connection"
                || lower == "transfer-encoding"
                || lower == "upgrade"
            {
                continue;
            }
            hpack_headers.push(HeaderField {
                name: lower,
                value: val.clone(),
            });
        }
        let header_block = self.encoder.encode(&hpack_headers);
        let flags = if end_stream {
            frame_flags::END_HEADERS | frame_flags::END_STREAM
        } else {
            frame_flags::END_HEADERS
        };
        self.enqueue_frame(&Frame::Headers {
            flags,
            stream_id,
            header_block,
        });
    }

    /// Parses an HTTP/1 response head (status line and headers, with or without the
    /// final blank line) and sends it as a HEADERS frame; the body follows through
    /// [`Self::send_data`]. `end_stream` is for a response without a body. Returns false
    /// if `head` is not a response head.
    pub fn send_h1_head(&mut self, stream_id: u32, head: &[u8], end_stream: bool) -> bool {
        let head_str = String::from_utf8_lossy(head);
        let mut lines = head_str.lines();
        let Some(status_line) = lines.next() else { return false };
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return false;
        }
        let Ok(status) = parts[1].parse::<u16>() else { return false };
        let mut headers = Vec::new();
        for line in lines {
            if let Some((name, val)) = line.split_once(':') {
                headers.push((name.trim().to_string(), val.trim().to_string()));
            }
        }
        self.send_headers_frame(stream_id, status, &headers, end_stream);
        true
    }

    /// How many DATA bytes the connection and stream send windows allow now. A stream
    /// that is gone takes anything (it is discarded), so its budget is unbounded.
    #[must_use]
    pub fn data_budget(&self, stream_id: u32) -> usize {
        match self.streams.get(&stream_id) {
            Some(st) if !matches!(st.state, H2StreamState::Reset(_) | H2StreamState::Closed) => {
                usize::try_from(self.conn_send_window.min(st.send_window)).unwrap_or(0)
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
            self.enqueue_frame(&Frame::Data {
                flags: if last { frame_flags::END_STREAM } else { 0 },
                stream_id,
                data: data[sent..sent + n].to_vec(),
            });
            self.conn_send_window -= n as i32;
            if let Some(s) = self.streams.get_mut(&stream_id) {
                s.send_window -= n as i32;
            }
            sent += n;
        }
        if data.is_empty() && end_stream {
            self.enqueue_frame(&Frame::Data { flags: frame_flags::END_STREAM, stream_id, data: Vec::new() });
        }
        if end_stream && sent == data.len() {
            self.local_end_stream(stream_id);
        }
        sent
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

/// Header fields a request may carry once converted (HAProxy's `tune.http.maxhdr` 101,
/// less one: measured, host + 99 headers pass and host + 100 are refused).
const MAX_REQUEST_HEADERS: usize = 100;

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

            // Server immediately replies with its own initial SETTINGS frame
            let server_settings = Frame::Settings {
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

        // Export parsed HTX data to output buffer
        let wire = stream.rx_htx.to_h1_wire();
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
    /// its receive window of bytes (`H2_CF_DEM_SFULL`). The window is not policed -- HAProxy
    /// does not either -- but what a client sends past it stays in the socket.
    fn demux_blocked(ctx: &H2MuxContext, header: &FrameHeader) -> bool {
        if header.frame_type != crate::h2::FrameType::Data || !ctx.is_server {
            return false;
        }
        let limit = usize::try_from(ctx.local_initial_window).unwrap_or(0).max(DEFAULT_MAX_FRAME_SIZE as usize);
        ctx.streams.get(&header.stream_id).is_some_and(|s| {
            s.state == H2StreamState::Open && s.rx_buffered > 0 && s.rx_buffered + header.length as usize > limit
        })
    }

    fn process_headers_block(
        ctx: &mut H2MuxContext,
        stream_id: u32,
        flags: u8,
        header_block: &[u8],
    ) -> io::Result<()> {
        if !ctx.streams.contains_key(&stream_id) && stream_id <= ctx.highest_opened {
            // HEADERS on a stream that is closed, or that was skipped and so can no longer
            // be opened: a connection error STREAM_CLOSED (RFC 9113 section 5.1.1; HAProxy
            // measured: GOAWAY with the highest stream id seen, then close). It was a stream
            // error, and a client that reads nothing had a reply queued for each (T235).
            ctx.send_goaway(ctx.highest_opened, H2Error::StreamClosed, b"HEADERS on a closed stream");
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HEADERS on a closed stream"));
        }
        if !ctx.streams.contains_key(&stream_id) {
            let active = ctx
                .streams
                .values()
                .filter(|s| s.state == H2StreamState::Open || s.state == H2StreamState::HalfClosedRemote)
                .count();
            if active >= ctx.max_concurrent_streams as usize {
                ctx.send_rst_stream(stream_id, H2Error::RefusedStream);
                return Ok(());
            }
        }

        let decoded_headers = ctx.decoder.decode(header_block).map_err(|e| {
            ctx.send_goaway(stream_id, e, b"HPACK compression error");
            io::Error::new(io::ErrorKind::InvalidData, "HPACK compression error")
        })?;

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
            if (flags & frame_flags::END_STREAM) == 0 || decoded_headers.iter().any(|h| h.name.starts_with(':')) {
                ctx.send_rst_stream(stream_id, H2Error::ProtocolError);
                return Ok(());
            }
            ctx.streams.entry(stream_id).and_modify(|stream| {
                for h in decoded_headers {
                    stream.rx_htx.push(HtxBlock::Trailer(h));
                }
                stream.rx_htx.push(HtxBlock::Eot);
                stream.rx_htx.push(HtxBlock::Eom);
                stream.state = H2StreamState::HalfClosedRemote;
            });
            return Ok(());
        }

        // HAProxy keeps at most tune.http.maxhdr - 1 (100) header fields in a request,
        // counting the host made from :authority; more is a stream error PROTOCOL_ERROR.
        let regular = decoded_headers.iter().filter(|h| !h.name.starts_with(':')).count();
        let host_from_authority = decoded_headers.iter().any(|h| h.name == ":authority")
            && !decoded_headers.iter().any(|h| h.name == "host");
        let too_many = ctx.is_server && regular + usize::from(host_from_authority) > MAX_REQUEST_HEADERS;

        let abs_prefix = {
            let get = |n: &str| decoded_headers.iter().find(|h| h.name == n).map(|h| h.value.as_str());
            get(":scheme").zip(get(":authority")).map(|(s, a)| format!("{s}://{a}"))
        };
        let stream = ctx.streams.entry(stream_id).or_insert_with(|| {
            H2StreamCtx::new(
                stream_id,
                ctx.remote_initial_window,
                ctx.local_initial_window,
            )
        });

        stream.state = H2StreamState::Open;
        stream.abs_prefix = abs_prefix;
        ctx.highest_opened = ctx.highest_opened.max(stream_id);

        // Extract pseudo-headers and construct HTX blocks
        let converted = if too_many {
            Err(())
        } else {
            crate::htx::pseudo_headers_to_htx(decoded_headers, HttpVersion::Http20).map_err(|_| ())
        };
        match converted {
            Ok(blocks) => {
                for b in blocks {
                    stream.rx_htx.push(b);
                }
            }
            Err(_) => {
                ctx.send_rst_stream(stream_id, H2Error::ProtocolError);
                return Ok(());
            }
        }

        if (flags & frame_flags::END_STREAM) != 0 {
            stream.rx_htx.push(HtxBlock::Eom);
            stream.state = H2StreamState::HalfClosedRemote;
        }

        Ok(())
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
                                ctx.remote_initial_window = new_win;
                                for stream in ctx.streams.values_mut() {
                                    stream.send_window = stream.send_window.saturating_add(delta);
                                }
                            }
                            SettingsParameter::MaxConcurrentStreams => {
                                ctx.max_concurrent_streams = val;
                            }
                            SettingsParameter::MaxFrameSize => {
                                ctx.max_frame_size = val;
                            }
                            SettingsParameter::HeaderTableSize => {
                                ctx.encoder.dynamic_table.set_max_size(val as usize);
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

            Frame::Headers {
                flags,
                stream_id,
                header_block,
            } => {
                if stream_id == 0 {
                    ctx.send_goaway(0, H2Error::ProtocolError, b"HEADERS on stream 0");
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HEADERS on stream 0",
                    ));
                }

                // Verify client stream parity (client streams must be odd)
                if ctx.is_server && (stream_id % 2 == 0) {
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

                if (flags & frame_flags::END_HEADERS) == 0 {
                    if header_block.len() > 65536 {
                        ctx.send_goaway(stream_id, H2Error::EnhanceYourCalm, b"header block too large");
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Header block too large"));
                    }
                    ctx.continuation_stream = Some(stream_id);
                    ctx.continuation_flags = flags;
                    ctx.continuation_buf = header_block;
                    ctx.continuation_count = 0;
                    return Ok(());
                }

                Self::process_headers_block(ctx, stream_id, flags, &header_block)?;
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
                    // Once the response is over (half-closed local) nothing will take the
                    // body any more: it is counted and dropped, not kept.
                    if !data.is_empty() && stream.state != H2StreamState::HalfClosedLocal {
                        stream.rx_buffered += data.len();
                        stream.rx_htx.push(HtxBlock::Data(data));
                    }
                    if (flags & frame_flags::END_STREAM) != 0 {
                        stream.rx_htx.push(HtxBlock::Eom);
                        stream.state = match stream.state {
                            H2StreamState::HalfClosedLocal => H2StreamState::Closed,
                            _ => H2StreamState::HalfClosedRemote,
                        };
                    }
                }

                // Automatic window replenishment if receive window falls below 32KB
                if ctx.conn_recv_window < 32768 {
                    let replenish = (DEFAULT_INITIAL_WINDOW_SIZE - ctx.conn_recv_window) as u32;
                    ctx.send_window_update(0, replenish);
                }
            }

            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                if increment == 0 {
                    ctx.send_goaway(
                        stream_id,
                        H2Error::ProtocolError,
                        b"zero window update increment",
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Zero window update increment",
                    ));
                }

                if stream_id == 0 {
                    ctx.conn_send_window = ctx.conn_send_window.saturating_add(increment as i32);
                } else if let Some(stream) = ctx.streams.get_mut(&stream_id) {
                    stream.send_window = stream.send_window.saturating_add(increment as i32);
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

                if let Some(stream) = ctx.streams.get_mut(&stream_id) {
                    stream.state = H2StreamState::Reset(error_code);
                    stream.reset_reason = Some(error_code);
                    stream.is_shut = true;
                }
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

            Frame::Priority { .. }
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
        assert_eq!(s1.rx_htx.req_line().unwrap().uri, "/stream1");
        assert_eq!(s1.state, H2StreamState::HalfClosedRemote);

        let s3 = ctx.streams.get(&3).unwrap();
        assert_eq!(s3.rx_htx.req_line().unwrap().uri, "/stream3");
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
    /// `rx_buf` (the connection stops asking for input) until the data path takes some (T235).
    #[test]
    fn data_past_the_stream_window_waits_until_the_stream_drains() {
        let (mux, mut ctx) = open_conn();
        mux.parse(&mut ctx, &post_headers(1)).expect("open");
        let mut wire = Vec::new();
        for _ in 0..5 {
            wire.extend(data(1, 16384, 0));
        }
        mux.parse(&mut ctx, &wire).expect("data");
        // Three frames fit the 65535-byte window, the fourth does not.
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_buffered), Some(3 * 16384));
        assert!(!ctx.wants_input(), "two frames wait: no more input");
        ctx.rx_taken(1, 16384);
        ctx.resume();
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_buffered), Some(3 * 16384));
        ctx.rx_taken(1, 3 * 16384);
        ctx.resume();
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_buffered), Some(16384));
        assert!(ctx.rx_buf.is_empty() && ctx.wants_input());
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
        assert_eq!(ctx.streams.get(&1).map(|s| s.rx_htx.body_bytes().len()), Some(10));
        // Stream 3's response is over: what it still sends is counted and dropped.
        mux.parse(&mut ctx, &post_headers(3)).expect("open 3");
        ctx.streams.get_mut(&3).expect("3").state = H2StreamState::HalfClosedLocal;
        mux.parse(&mut ctx, &data(3, 1000, 0)).expect("data 3");
        assert_eq!(ctx.streams.get(&3).map(|s| (s.rx_buffered, s.rx_htx.body_bytes().len())), Some((0, 0)));
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
        assert_eq!(ctx.streams.get(&1).map(|s| s.recv_window), Some(DEFAULT_INITIAL_WINDOW_SIZE - 8));
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
}
