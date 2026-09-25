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
};
use crate::hpack::{HpackDecoder, HpackEncoder};
use crate::htx::{HeaderField, HttpVersion, Htx, HtxBlock};
use crate::mux::{mux_flags, Mux, MuxFlags, MuxOps, ShutMode};
use std::collections::BTreeMap;
use std::io;

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
    pub flood_config: H2FloodConfig,
    pub total_streams: usize,
    pub glitch_count: usize,
    pub graceful_goaway_sent: bool,
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
            flood_config: H2FloodConfig::default(),
            total_streams: 0,
            glitch_count: 0,
            graceful_goaway_sent: false,
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

    /// Sends an HTTP/2 response on the given stream ID with status and headers.
    pub fn send_response(
        &mut self,
        stream_id: u32,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
    ) {
        let mut hpack_headers = vec![HeaderField {
            name: ":status".to_string(),
            value: status.to_string(),
        }];
        for (name, val) in headers {
            let lower = name.to_ascii_lowercase();
            // RFC 7540 §8.1.2.2: connection-specific headers must not be sent in HTTP/2
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
        let end_stream = body.is_empty();
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

        if !body.is_empty() {
            let max_chunk = self.max_frame_size as usize;
            let mut offset = 0;
            while offset < body.len() {
                let chunk_len = (body.len() - offset).min(max_chunk);
                let is_last = offset + chunk_len >= body.len();
                let flags = if is_last { frame_flags::END_STREAM } else { 0 };
                self.enqueue_frame(&Frame::Data {
                    flags,
                    stream_id,
                    data: body[offset..offset + chunk_len].to_vec(),
                });
                offset += chunk_len;
            }
        }

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = match stream.state {
                H2StreamState::HalfClosedRemote => H2StreamState::Closed,
                _ => H2StreamState::HalfClosedLocal,
            };
        }
    }

    /// Parses an HTTP/1 response buffer and encodes it as HTTP/2 HEADERS/DATA frames.
    pub fn send_h1_response(&mut self, stream_id: u32, h1_bytes: &[u8]) -> bool {
        let (head, body) = if let Some(pos) = h1_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            (&h1_bytes[..pos], &h1_bytes[pos + 4..])
        } else if let Some(pos) = h1_bytes.windows(2).position(|w| w == b"\n\n") {
            (&h1_bytes[..pos], &h1_bytes[pos + 2..])
        } else {
            return false;
        };

        let head_str = String::from_utf8_lossy(head);
        let mut lines = head_str.lines();
        let status_line = match lines.next() {
            Some(l) => l,
            None => return false,
        };
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return false;
        }
        let status: u16 = match parts[1].parse() {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut headers = Vec::new();
        for line in lines {
            if let Some((name, val)) = line.split_once(':') {
                headers.push((name.trim().to_string(), val.trim().to_string()));
            }
        }

        self.send_response(stream_id, status, &headers, body);
        true
    }
}

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
        if input.is_empty() {
            return Ok(0);
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
            let slice = &ctx.rx_buf[consumed..];
            let header = FrameHeader::decode(slice)?;

            let total_frame_len = FRAME_HEADER_LEN + header.length as usize;
            if slice.len() < total_frame_len {
                // Incomplete frame payload, await more bytes
                break;
            }

            let payload = &slice[FRAME_HEADER_LEN..total_frame_len];
            let frame = match Frame::decode(&header, payload) {
                Ok(f) => f,
                Err(e) => {
                    ctx.send_goaway(
                        header.stream_id,
                        H2Error::ProtocolError,
                        b"frame decode error",
                    );
                    return Err(e);
                }
            };

            consumed += total_frame_len;
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
    fn process_headers_block(
        ctx: &mut H2MuxContext,
        stream_id: u32,
        flags: u8,
        header_block: &[u8],
    ) -> io::Result<()> {
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

        let stream = ctx.streams.entry(stream_id).or_insert_with(|| {
            H2StreamCtx::new(
                stream_id,
                ctx.remote_initial_window,
                ctx.local_initial_window,
            )
        });

        stream.state = H2StreamState::Open;

        // Extract pseudo-headers and construct HTX blocks
        match crate::htx::pseudo_headers_to_htx(decoded_headers, HttpVersion::Http20) {
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

                let data_len = data.len() as i32;
                ctx.conn_recv_window = ctx.conn_recv_window.saturating_sub(data_len);

                if let Some(stream) = ctx.streams.get_mut(&stream_id) {
                    stream.recv_window = stream.recv_window.saturating_sub(data_len);
                    if !data.is_empty() {
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
}
