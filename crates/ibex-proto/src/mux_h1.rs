// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/mux_h1.c and include/haproxy/mux_h1.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/1.1 Multiplexer implementing the [`Mux`] trait over [`Htx`].
//!
//! Features:
//! - Strict `#![forbid(unsafe_code)]` compliance.
//! - Connection reuse policies: `Safe`, `Always`, `Never`.
//! - Chunked transfer decoding (with trailers) on ingress and encoding on egress.
//! - Full keep-alive state machine supporting pipelining and connection recycling.
//! - WebSocket and HTTP CONNECT protocol upgrade tunnel mode.

use crate::conn::ConnId;
use crate::endpoint::SeDesc;
use crate::h1::{H1Parser, H1Phase};
use crate::htx::HtxBuffer;
use crate::mux::{mux_flags, Mux, MuxFlags, MuxOps, ShutMode};
use std::io;

static H1_OPS: MuxOps = MuxOps {
    name: "h1",
    alpn: Some(b"http/1.1"),
    flags: MuxFlags(mux_flags::HTX | mux_flags::REUSABLE),
};

/// Connection reuse policy for HTTP/1.1 connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H1ReuseMode {
    /// Connection is never reused for subsequent requests (`http-reuse never`).
    Never,
    /// Connection is safely reused for clean, idle connections (`http-reuse safe`).
    #[default]
    Safe,
    /// Connection is aggressively reused for any subsequent request (`http-reuse always`).
    Always,
}

/// Overall connection-level lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1ConnState {
    /// Connection is idle, waiting for an incoming request.
    Idle,
    /// Connection is actively processing a stream transaction.
    Active,
    /// Connection has been upgraded to a raw bidirectional tunnel (WebSocket / CONNECT).
    Tunnel,
    /// Connection has finished its transaction and is closing (`Connection: close`).
    Closing,
    /// Connection is closed.
    Closed,
    /// A framing or protocol error occurred.
    Error,
}

/// Stream-level transaction lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1StreamState {
    /// Initial idle stream state.
    Idle,
    /// Receiving request headers.
    ReqHeaders,
    /// Receiving request body.
    ReqBody,
    /// Request fully received (EOM reached).
    ReqDone,
    /// Sending response headers.
    ResHeaders,
    /// Sending response body.
    ResBody,
    /// Stream transaction finished.
    Done,
    /// Stream error or reset.
    Error,
}

/// The most of a message head `snd_buf` holds while waiting for its end.
const MAX_TX_HEAD: usize = 64 * 1024;

/// Connection context for the H1 multiplexer.
pub struct H1MuxContext {
    pub conn: ConnId,
    pub is_server: bool,
    pub reuse_mode: H1ReuseMode,
    pub state: H1ConnState,
    pub stream_state: H1StreamState,
    pub parser: H1Parser,
    pub rx_htx_buf: HtxBuffer,
    pub tx_buf: Vec<u8>,
    pub tx_consumed: usize,
    pub tx_chunked: bool,
    /// The head of the message being written has been seen: the rest is body.
    pub tx_head_done: bool,
    /// The start of a message head whose end has not been written yet.
    pub tx_head_pending: Vec<u8>,
    pub streams_used: u32,
    pub streams_total: u64,
    pub is_shut: bool,
    pub is_tunnel: bool,
    pub has_error: bool,
    pub conn_close: bool,
    pub is_upgrade: bool,
    pub raw_rx_buf: Vec<u8>,
    pub tunnel_rx_buf: Vec<u8>,
    pub rx_wire_buf: Vec<u8>,
    pub rx_wire_consumed: usize,
}

impl H1MuxContext {
    /// Creates a new connection context.
    #[must_use]
    pub fn new(conn: ConnId, is_server: bool, reuse_mode: H1ReuseMode) -> Self {
        Self {
            conn,
            is_server,
            reuse_mode,
            state: H1ConnState::Idle,
            stream_state: H1StreamState::Idle,
            parser: H1Parser::new(is_server),
            rx_htx_buf: HtxBuffer::new(),
            tx_buf: Vec::with_capacity(4096),
            tx_consumed: 0,
            tx_chunked: false,
            tx_head_done: false,
            tx_head_pending: Vec::new(),
            streams_used: 0,
            streams_total: 0,
            is_shut: false,
            is_tunnel: false,
            has_error: false,
            conn_close: false,
            is_upgrade: false,
            raw_rx_buf: Vec::new(),
            tunnel_rx_buf: Vec::new(),
            rx_wire_buf: Vec::new(),
            rx_wire_consumed: 0,
        }
    }

    /// Configures the connection reuse policy.
    pub fn set_reuse_mode(&mut self, mode: H1ReuseMode) {
        self.reuse_mode = mode;
    }

    /// Resets stream state for the next request/response on this keep-alive connection.
    pub fn reset_for_next_stream(&mut self) {
        self.parser.reset(self.is_server);
        self.rx_htx_buf.clear();
        self.rx_wire_buf.clear();
        self.rx_wire_consumed = 0;
        self.tx_chunked = false;
        self.tx_head_done = false;
        self.tx_head_pending.clear();
        self.is_upgrade = false;
        self.stream_state = H1StreamState::Idle;
    }

    /// Marks current stream transaction as finished and advances the keep-alive state machine.
    pub fn finish_stream(&mut self) {
        self.stream_state = H1StreamState::Done;

        if self.is_tunnel {
            return;
        }

        if self.conn_close || self.parser.connection_close {
            self.conn_close = true;
            self.state = H1ConnState::Closing;
            self.streams_used = 0;
        } else {
            self.streams_used = 0;
            self.streams_total += 1;
            self.state = H1ConnState::Idle;
            self.reset_for_next_stream();
        }
    }

    /// Alias for `finish_stream` matching the test suite contract.
    pub fn release_stream(&mut self) {
        self.finish_stream();
    }

    /// Switches the connection into raw bidirectional tunnel mode.
    pub fn enter_tunnel(&mut self) {
        self.is_tunnel = true;
        self.state = H1ConnState::Tunnel;
        self.conn_close = false;
    }

    /// Appends a chunk of body data during chunked transfer encoding.
    pub fn send_chunk(&mut self, chunk: &[u8]) {
        if !chunk.is_empty() {
            let hdr = format!("{:X}\r\n", chunk.len());
            self.tx_buf.extend_from_slice(hdr.as_bytes());
            self.tx_buf.extend_from_slice(chunk);
            self.tx_buf.extend_from_slice(b"\r\n");
        }
    }

    /// Emits the terminal `0\r\n` chunk and optional trailers, concluding the chunked transfer.
    pub fn finish_chunked(&mut self, trailers: Option<&[(&str, &str)]>) {
        self.tx_buf.extend_from_slice(b"0\r\n");
        if let Some(tlrs) = trailers {
            for (name, val) in tlrs {
                let line = format!("{}: {}\r\n", name, val);
                self.tx_buf.extend_from_slice(line.as_bytes());
            }
        }
        self.tx_buf.extend_from_slice(b"\r\n");
        self.tx_chunked = false;
        self.finish_stream();
    }

    /// Returns `true` if raw RX buffer has invalid lingering data preventing safe reuse.
    #[must_use]
    pub fn has_unclean_rx(&self) -> bool {
        if self.raw_rx_buf.is_empty() {
            return false;
        }
        let trimmed = self.raw_rx_buf.trim_ascii_start();
        if trimmed.is_empty() {
            return false;
        }
        // If remaining bytes do not look like an HTTP start-line, connection is unclean
        !(trimmed.starts_with(b"GET ")
            || trimmed.starts_with(b"POST ")
            || trimmed.starts_with(b"HEAD ")
            || trimmed.starts_with(b"PUT ")
            || trimmed.starts_with(b"DELETE ")
            || trimmed.starts_with(b"OPTIONS ")
            || trimmed.starts_with(b"CONNECT ")
            || trimmed.starts_with(b"HTTP/"))
    }
}

fn strip_connection_close_header(input: &[u8]) -> Vec<u8> {
    let Ok(s) = std::str::from_utf8(input) else {
        return input.to_vec();
    };
    let Some((first_line, rest)) = s.split_once("\r\n") else {
        return input.to_vec();
    };
    let Some((headers, body)) = rest.split_once("\r\n\r\n") else {
        return input.to_vec();
    };

    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(first_line.as_bytes());
    out.extend_from_slice(b"\r\n");

    for line in headers.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("close") {
                continue;
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body.as_bytes());
    out
}

/// HTTP/1.1 Multiplexer implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct MuxH1;

impl MuxH1 {
    /// Creates an H1 mux.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Initializes mux context with an explicit reuse policy.
    pub fn init_with_reuse(
        &self,
        conn: ConnId,
        is_server: bool,
        reuse_mode: H1ReuseMode,
    ) -> io::Result<H1MuxContext> {
        Ok(H1MuxContext::new(conn, is_server, reuse_mode))
    }
}

impl Mux for MuxH1 {
    type Ctx = H1MuxContext;

    fn ops(&self) -> &'static MuxOps {
        &H1_OPS
    }

    fn init(&self, conn: ConnId, is_server: bool) -> io::Result<Self::Ctx> {
        Ok(H1MuxContext::new(conn, is_server, H1ReuseMode::Safe))
    }

    fn parse(&self, ctx: &mut Self::Ctx, input: &[u8]) -> io::Result<usize> {
        if ctx.is_shut {
            return Ok(0);
        }

        // In tunnel mode, pass all raw bytes directly to the tunnel buffer
        if ctx.is_tunnel {
            ctx.tunnel_rx_buf.extend_from_slice(input);
            let _ = ctx.rx_htx_buf.push_raw_data(input);
            return Ok(input.len());
        }

        if ctx.state == H1ConnState::Idle {
            ctx.state = H1ConnState::Active;
            ctx.streams_used = 1;
            ctx.stream_state = H1StreamState::ReqHeaders;
        }

        let to_parse = if ctx.raw_rx_buf.is_empty() {
            input
        } else {
            ctx.raw_rx_buf.extend_from_slice(input);
            &ctx.raw_rx_buf[..]
        };

        let consumed = match ctx.rx_htx_buf.with_slice_mut(|s| ctx.parser.parse(to_parse, s)) {
            Ok(c) => c,
            Err(e) => {
                ctx.has_error = true;
                ctx.state = H1ConnState::Error;
                ctx.streams_used = 0;
                return Err(e);
            }
        };

        if ctx.parser.connection_close {
            ctx.conn_close = true;
        }
        if ctx.parser.is_upgrade {
            ctx.is_upgrade = true;
        }

        // Track stream phase transitions
        if matches!(
            ctx.parser.phase,
            H1Phase::BodyFixed { .. } | H1Phase::BodyChunked { .. } | H1Phase::Trailers
        ) {
            ctx.stream_state = H1StreamState::ReqBody;
        }

        // Check if parsing finished
        if ctx.parser.phase == H1Phase::Done {
            ctx.stream_state = H1StreamState::ReqDone;

            // If raw_rx_buf had bytes, drain consumed
            if !ctx.raw_rx_buf.is_empty() {
                ctx.raw_rx_buf.drain(..consumed.min(ctx.raw_rx_buf.len()));
            }
            return Ok(consumed);
        }

        if ctx.parser.phase == H1Phase::Error {
            ctx.has_error = true;
            ctx.state = H1ConnState::Error;
            ctx.stream_state = H1StreamState::Error;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP/1.1 framing syntax error",
            ));
        }

        if !ctx.raw_rx_buf.is_empty() {
            ctx.raw_rx_buf.drain(..consumed.min(ctx.raw_rx_buf.len()));
            Ok(consumed)
        } else {
            Ok(consumed)
        }
    }

    fn rcv_buf(&self, ctx: &mut Self::Ctx, _sd: &mut SeDesc, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        // In tunnel mode, drain tunnel RX buffer
        if ctx.is_tunnel {
            if ctx.tunnel_rx_buf.is_empty() {
                return Ok(0);
            }
            let n = ctx.tunnel_rx_buf.len().min(out.len());
            out[..n].copy_from_slice(&ctx.tunnel_rx_buf[..n]);
            ctx.tunnel_rx_buf.drain(..n);
            return Ok(n);
        }

        if ctx.rx_wire_buf.is_empty() {
            ctx.rx_wire_buf = ctx.rx_htx_buf.to_h1_wire();
            ctx.rx_wire_consumed = 0;
        }

        if ctx.rx_wire_consumed >= ctx.rx_wire_buf.len() {
            return Ok(0);
        }

        let avail = ctx.rx_wire_buf.len() - ctx.rx_wire_consumed;
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&ctx.rx_wire_buf[ctx.rx_wire_consumed..ctx.rx_wire_consumed + n]);
        ctx.rx_wire_consumed += n;

        if ctx.rx_wire_consumed >= ctx.rx_wire_buf.len() {
            ctx.rx_wire_buf.clear();
            ctx.rx_wire_consumed = 0;
        }

        Ok(n)
    }

    fn snd_buf(&self, ctx: &mut Self::Ctx, _sd: &mut SeDesc, input: &[u8]) -> io::Result<usize> {
        if ctx.is_shut {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Connection is shut",
            ));
        }

        if ctx.tx_consumed > 0 && ctx.tx_consumed >= ctx.tx_buf.len() {
            ctx.tx_buf.clear();
            ctx.tx_consumed = 0;
        }

        // In tunnel mode, forward raw bytes directly
        if ctx.is_tunnel {
            ctx.tx_buf.extend_from_slice(input);
            return Ok(input.len());
        }

        // If chunked egress is active, frame the input slice as a chunk
        if ctx.tx_chunked {
            ctx.send_chunk(input);
            return Ok(input.len());
        }

        // Once the head has been written, what follows is body: it is forwarded as it is and
        // never inspected (IBEX-H1MUX-SNDBUF-SNIFF-001).
        if ctx.tx_head_done {
            ctx.tx_buf.extend_from_slice(input);
            return Ok(input.len());
        }

        // Inspect start line and headers (only those) for protocol upgrade or connection
        // directives. A head that is not complete yet is held until it is, so that a header
        // line split over two writes is seen whole.
        let joined;
        let whole: &[u8] = if ctx.tx_head_pending.is_empty() {
            input
        } else {
            joined = [ctx.tx_head_pending.as_slice(), input].concat();
            &joined
        };
        let Some(end) = whole.windows(4).position(|w| w == b"\r\n\r\n") else {
            if ctx.tx_head_pending.len() + input.len() > MAX_TX_HEAD {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "message head too large"));
            }
            ctx.tx_head_pending.extend_from_slice(input);
            return Ok(input.len());
        };
        ctx.tx_head_done = true;
        let (head, body) = whole.split_at(end + 4);
        ctx.tx_head_pending.clear();
        let head_str = std::str::from_utf8(head).unwrap_or("");
        let head_lower = head_str.to_ascii_lowercase();
        // A header line is what starts a line: the same words inside a value are not it.
        let has_line = |line: &str| head_lower.split("\r\n").skip(1).any(|l| l.starts_with(line));
        if head_str.starts_with("HTTP/1.1 101") || head_str.starts_with("HTTP/1.0 101") {
            ctx.enter_tunnel();
        } else if (head_str.starts_with("HTTP/1.1 200") || head_str.starts_with("HTTP/1.0 200")) && ctx.is_upgrade {
            ctx.enter_tunnel();
        }

        if has_line("transfer-encoding: chunked") {
            ctx.tx_chunked = true;
        }

        let close = has_line("connection: close");
        if !ctx.is_server && !ctx.conn_close && close {
            ctx.tx_buf.extend_from_slice(&strip_connection_close_header(head));
        } else {
            if close {
                ctx.conn_close = true;
            }
            ctx.tx_buf.extend_from_slice(head);
        }
        if !body.is_empty() {
            if ctx.tx_chunked {
                ctx.send_chunk(body);
            } else {
                ctx.tx_buf.extend_from_slice(body);
            }
        }

        // If complete bodyless response was buffered and not upgrading, mark stream done
        if !ctx.is_tunnel && !ctx.tx_chunked && ctx.tx_head_done {
            let cl_zero = has_line("content-length: 0");
            let is_head = head_str.starts_with("HTTP/1.1 204") || head_str.starts_with("HTTP/1.1 304") || cl_zero;
            if is_head {
                ctx.finish_stream();
            }
        }

        Ok(input.len())
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

            if ctx.state == H1ConnState::Closing {
                ctx.state = H1ConnState::Closed;
                ctx.is_shut = true;
            }
        } else if ctx.tx_consumed >= 65_536 && ctx.tx_consumed >= ctx.tx_buf.len() / 2 {
            // A peer that reads part of what waits, never all of it, would otherwise keep
            // every byte ever sent here (T288, T297): what was read goes once it is at
            // least half the buffer, so the bytes moved are fewer than those let go.
            ctx.tx_buf.drain(..ctx.tx_consumed);
            ctx.tx_consumed = 0;
        }
    }

    fn shut(&self, ctx: &mut Self::Ctx, _sd: &mut SeDesc, _mode: ShutMode) {
        ctx.is_shut = true;
        ctx.state = H1ConnState::Closed;
        ctx.streams_used = 0;
    }

    fn avail_streams(&self, ctx: &Self::Ctx) -> u32 {
        if ctx.is_shut || ctx.is_tunnel || ctx.has_error || ctx.conn_close {
            return 0;
        }

        match ctx.reuse_mode {
            H1ReuseMode::Never => {
                if ctx.streams_total > 0 || ctx.streams_used > 0 {
                    0
                } else {
                    1
                }
            }
            H1ReuseMode::Safe | H1ReuseMode::Always => {
                if ctx.streams_used == 0 && ctx.state == H1ConnState::Idle {
                    1
                } else {
                    0
                }
            }
        }
    }

    fn used_streams(&self, ctx: &Self::Ctx) -> u32 {
        ctx.streams_used
    }

    fn is_reusable(&self, ctx: &Self::Ctx) -> bool {
        if ctx.is_shut || ctx.is_tunnel || ctx.has_error || ctx.conn_close {
            return false;
        }

        match ctx.reuse_mode {
            H1ReuseMode::Never => false,
            H1ReuseMode::Safe => {
                ctx.streams_used == 0 && ctx.state == H1ConnState::Idle && !ctx.has_unclean_rx()
            }
            H1ReuseMode::Always => ctx.streams_used == 0 && ctx.state == H1ConnState::Idle,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::Endpoint;

    /// A peer that reads part of the output, never all, must not make the buffer keep what
    /// it has read (the T288 defect of `mux_h2`, found again in this mux by T297).
    #[test]
    fn output_read_in_part_does_not_keep_what_was_read() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(1), false).expect("init");
        for k in 0..20_000u32 {
            let byte = u8::try_from(k % 251).unwrap();
            ctx.tx_buf.extend_from_slice(&[byte; 1000]);
            // The peer reads all but the last 100 bytes waiting.
            let pending = mux.pending_output(&ctx).len();
            mux.consume_output(&mut ctx, pending - 100);
            assert_eq!(mux.pending_output(&ctx), &[byte; 100][..], "the unread tail stays");
        }
        // 20 MB went through; what is kept is bounded by what waits, not by what was sent.
        assert!(ctx.tx_buf.len() <= 262_144, "tx_buf holds {} bytes", ctx.tx_buf.len());
        assert!(ctx.tx_buf.capacity() <= 524_288, "tx_buf capacity {} bytes", ctx.tx_buf.capacity());
    }

    #[test]
    fn h1_mux_parses_request_and_generates_output() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(1), false).expect("init");
        assert_eq!(mux.ops().name, "h1");

        let req = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let consumed = mux.parse(&mut ctx, req).expect("parse");
        assert_eq!(consumed, req.len());

        let mut sd = SeDesc {
            endpoint: Endpoint::MuxStream {
                conn: ConnId(1),
                stream: 1,
            },
            ..SeDesc::new()
        };

        let mut out = [0u8; 128];
        let n = mux.rcv_buf(&mut ctx, &mut sd, &mut out).expect("rcv_buf");
        assert!(n > 0);
        let out_str = std::str::from_utf8(&out[..n]).expect("utf8");
        assert!(out_str.contains("GET /index.html HTTP/1.1"));

        mux.snd_buf(&mut ctx, &mut sd, b"HTTP/1.1 200 OK\r\n\r\n")
            .expect("snd_buf");
        assert_eq!(mux.pending_output(&ctx), b"HTTP/1.1 200 OK\r\n\r\n");
        mux.consume_output(&mut ctx, 19);
        assert_eq!(mux.pending_output(&ctx), b"");
    }

    #[test]
    fn h1_mux_keep_alive_multiple_transactions() {
        let mux = MuxH1;
        let mut ctx = mux
            .init_with_reuse(ConnId(1), false, H1ReuseMode::Safe)
            .expect("init");
        let mut sd = SeDesc::new();

        // Transaction 1
        let req1 = b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n";
        mux.parse(&mut ctx, req1).expect("parse req1");
        assert_eq!(ctx.streams_used, 1);
        assert_eq!(ctx.rx_htx_buf.req_line().unwrap().uri, "/first");

        let mut out = [0u8; 256];
        mux.rcv_buf(&mut ctx, &mut sd, &mut out).expect("rcv1");
        mux.snd_buf(
            &mut ctx,
            &mut sd,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("snd1");

        assert_eq!(ctx.streams_used, 0);
        assert_eq!(ctx.streams_total, 1);
        assert_eq!(ctx.state, H1ConnState::Idle);
        assert_eq!(mux.avail_streams(&ctx), 1);
        assert!(mux.is_reusable(&ctx));

        // Transaction 2 on same connection
        let req2 = b"POST /second HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        mux.parse(&mut ctx, req2).expect("parse req2");
        assert_eq!(ctx.streams_used, 1);
        assert_eq!(ctx.rx_htx_buf.req_line().unwrap().method, "POST");
        assert_eq!(ctx.rx_htx_buf.body_bytes(), b"hello");

        mux.rcv_buf(&mut ctx, &mut sd, &mut out).expect("rcv2");
        mux.snd_buf(
            &mut ctx,
            &mut sd,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("snd2");

        assert_eq!(ctx.streams_used, 0);
        assert_eq!(ctx.streams_total, 2);
        assert!(mux.is_reusable(&ctx));
    }

    #[test]
    fn h1_mux_connection_close_disables_reuse() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(2), false).expect("init");
        let mut sd = SeDesc::new();

        let req = b"GET /close HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        mux.parse(&mut ctx, req).expect("parse close req");
        assert!(ctx.conn_close);

        mux.snd_buf(
            &mut ctx,
            &mut sd,
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("snd");

        assert_eq!(ctx.state, H1ConnState::Closing);
        assert_eq!(mux.avail_streams(&ctx), 0);
        assert!(!mux.is_reusable(&ctx));

        // Consume remaining output -> closes
        let len = mux.pending_output(&ctx).len();
        mux.consume_output(&mut ctx, len);
        assert_eq!(ctx.state, H1ConnState::Closed);
    }

    #[test]
    fn h1_mux_reuse_mode_never() {
        let mux = MuxH1;
        let mut ctx = mux
            .init_with_reuse(ConnId(3), false, H1ReuseMode::Never)
            .expect("init");
        let mut sd = SeDesc::new();

        let req = b"GET /once HTTP/1.1\r\nHost: example.com\r\n\r\n";
        mux.parse(&mut ctx, req).expect("parse");
        mux.snd_buf(
            &mut ctx,
            &mut sd,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("snd");

        assert_eq!(ctx.streams_total, 1);
        assert_eq!(mux.avail_streams(&ctx), 0);
        assert!(!mux.is_reusable(&ctx));
    }

    #[test]
    fn h1_mux_chunked_transfer_decoding_with_trailers() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(4), false).expect("init");

        let raw = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nChecksum: abcd1234\r\n\r\n";
        let consumed = mux.parse(&mut ctx, raw).expect("parse chunked");
        assert_eq!(consumed, raw.len());
        assert!(ctx.rx_htx_buf.is_eom());
        assert_eq!(ctx.rx_htx_buf.body_bytes(), b"hello world");
        assert_eq!(
            ctx.rx_htx_buf.get_trailer("expires"),
            Some("Wed, 21 Oct 2026 07:28:00 GMT")
        );
        assert_eq!(ctx.rx_htx_buf.get_trailer("checksum"), Some("abcd1234"));
    }

    #[test]
    fn h1_mux_chunked_transfer_encoding_with_trailers() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(5), false).expect("init");
        let mut sd = SeDesc::new();

        // Start chunked response
        mux.snd_buf(
            &mut ctx,
            &mut sd,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .expect("snd hdr");
        assert!(ctx.tx_chunked);

        // Send two chunks
        mux.snd_buf(&mut ctx, &mut sd, b"chunk one").expect("snd1");
        mux.snd_buf(&mut ctx, &mut sd, b" and two").expect("snd2");

        // Finish with trailers
        ctx.finish_chunked(Some(&[("X-Integrity", "valid")]));

        let out = mux.pending_output(&ctx);
        let out_str = std::str::from_utf8(out).expect("utf8");
        assert!(out_str.contains("Transfer-Encoding: chunked\r\n\r\n"));
        assert!(out_str.contains("9\r\nchunk one\r\n"));
        assert!(out_str.contains("8\r\n and two\r\n"));
        assert!(out_str.contains("0\r\nX-Integrity: valid\r\n\r\n"));
    }

    #[test]
    fn h1_mux_websocket_upgrade_tunnel() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(6), false).expect("init");
        let mut sd = SeDesc::new();

        let req = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        mux.parse(&mut ctx, req).expect("parse upgrade");
        assert!(ctx.is_upgrade);

        let res = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        mux.snd_buf(&mut ctx, &mut sd, res).expect("snd 101");

        assert!(ctx.is_tunnel);
        assert_eq!(ctx.state, H1ConnState::Tunnel);
        assert_eq!(mux.avail_streams(&ctx), 0);
        assert!(!mux.is_reusable(&ctx));

        // Subsequent raw WebSocket payload in ingress
        let ws_frame_client = b"\x81\x05hello";
        let consumed = mux.parse(&mut ctx, ws_frame_client).expect("parse tunnel");
        assert_eq!(consumed, ws_frame_client.len());

        let mut out = [0u8; 32];
        let n = mux
            .rcv_buf(&mut ctx, &mut sd, &mut out)
            .expect("rcv tunnel");
        assert_eq!(&out[..n], ws_frame_client);

        // Subsequent raw WebSocket payload in egress
        let ws_frame_server = b"\x81\x05world";
        mux.snd_buf(&mut ctx, &mut sd, ws_frame_server)
            .expect("snd tunnel");

        // Clear header from tx_buf
        mux.consume_output(&mut ctx, res.len());
        assert_eq!(mux.pending_output(&ctx), ws_frame_server);
    }

    #[test]
    fn h1_mux_connect_tunnel() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(7), false).expect("init");
        let mut sd = SeDesc::new();

        let req = b"CONNECT target.internal:443 HTTP/1.1\r\nHost: target.internal:443\r\n\r\n";
        mux.parse(&mut ctx, req).expect("parse connect");
        assert!(ctx.is_upgrade);

        let res = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        mux.snd_buf(&mut ctx, &mut sd, res).expect("snd 200");

        assert!(ctx.is_tunnel);
        assert_eq!(ctx.state, H1ConnState::Tunnel);
        assert_eq!(mux.avail_streams(&ctx), 0);

        // Bi-directional tunnel traffic
        let tls_client_hello = b"\x16\x03\x01\x00\x10...";
        mux.parse(&mut ctx, tls_client_hello).expect("parse tls");
        let mut out = [0u8; 32];
        let n = mux.rcv_buf(&mut ctx, &mut sd, &mut out).expect("rcv tls");
        assert_eq!(&out[..n], tls_client_hello);
    }

    #[test]
    fn h1_mux_pipelined_requests() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(8), false).expect("init");
        let mut sd = SeDesc::new();

        let pipelined = b"GET /first HTTP/1.1\r\nHost: a.com\r\n\r\nGET /second HTTP/1.1\r\nHost: b.com\r\n\r\n";
        let consumed1 = mux.parse(&mut ctx, pipelined).expect("parse pipelined");
        assert_eq!(consumed1, 36);

        // First transaction
        assert_eq!(ctx.rx_htx_buf.req_line().unwrap().uri, "/first");
        let mut out = [0u8; 128];
        mux.rcv_buf(&mut ctx, &mut sd, &mut out).expect("rcv1");
        mux.snd_buf(
            &mut ctx,
            &mut sd,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("snd1");

        // Detach / complete first stream by sending complete response
        assert_eq!(ctx.streams_used, 0);

        // After finishing first stream, remaining pipelined bytes are parsed
        let consumed2 = mux
            .parse(&mut ctx, &pipelined[consumed1..])
            .expect("parse second");
        assert_eq!(consumed1 + consumed2, pipelined.len());
        assert_eq!(ctx.rx_htx_buf.req_line().unwrap().uri, "/second");
    }

    #[test]
    fn h1_mux_malformed_input_transitions_to_error() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(9), false).expect("init");

        let bad_req = b"GET / HTTP/1.1\r\nBadHeaderWithoutColon\r\n\r\n";
        let res = mux.parse(&mut ctx, bad_req);
        assert!(res.is_err());
        assert!(ctx.has_error);
        assert_eq!(ctx.state, H1ConnState::Error);
        assert_eq!(mux.avail_streams(&ctx), 0);
        assert!(!mux.is_reusable(&ctx));
    }

    #[test]
    fn h1_mux_client_keepalive_strips_server_connection_close() {
        let mux = MuxH1;
        let mut ctx = mux.init(ConnId(10), false).expect("init");
        let mut sd = SeDesc::new();

        let req = b"GET /keepalive HTTP/1.1\r\nHost: example.com\r\n\r\n";
        mux.parse(&mut ctx, req).expect("parse req");
        assert!(!ctx.conn_close);

        let res = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        mux.snd_buf(&mut ctx, &mut sd, res).expect("snd");

        // Verify that Connection: close was stripped from outgoing buffer
        let out = mux.pending_output(&ctx);
        let out_str = std::str::from_utf8(out).expect("utf8");
        assert!(
            !out_str.to_ascii_lowercase().contains("connection: close"),
            "Expected Connection: close stripped from client response, got: {out_str}"
        );

        // Verify that client keep-alive state was preserved
        assert!(!ctx.conn_close);
        assert_eq!(ctx.state, H1ConnState::Idle);
        assert_eq!(mux.avail_streams(&ctx), 1);
        assert!(mux.is_reusable(&ctx));
    }

    #[test]
    fn h1_mux_strip_connection_close_edge_cases() {
        assert_eq!(strip_connection_close_header(b"\xff\xff"), b"\xff\xff");
        assert_eq!(strip_connection_close_header(b"NoNewlines"), b"NoNewlines");
        assert_eq!(strip_connection_close_header(b"HTTP/1.1 200 OK\r\nNoEndOfHeaders"), b"HTTP/1.1 200 OK\r\nNoEndOfHeaders");
        assert_eq!(strip_connection_close_header(b"HTTP/1.1 200 OK\r\nNoColonHeader\r\n\r\n"), b"HTTP/1.1 200 OK\r\nNoColonHeader\r\n\r\n");
    }
}
