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
#![allow(
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools,
    clippy::module_name_repetitions,
    clippy::uninlined_format_args,
    clippy::if_not_else,
    clippy::bool_to_int_with_if,
    clippy::if_same_then_else,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::unnecessary_map_or,
    clippy::manual_let_else,
    clippy::chunks_exact_to_as_chunks,
    clippy::collapsible_match,
    clippy::doc_markdown,
    clippy::must_use_candidate
)]

pub mod actions;
pub mod conn;
pub mod endpoint;
pub mod exp;
pub mod ffi_h1;
pub mod h1;
pub mod parser;
pub mod h2;
pub mod hpack;
pub mod htx;
pub mod mux;
pub mod mux_h1;
pub mod mux_h2;
pub mod mux_pt;
pub mod proto;
pub mod proxy_protocol;
pub mod session;
pub mod stream;
pub mod transport;

pub use actions::{
    build_synthetic_response, default_body_for_status, format_log_format_string,
    inject_http_header, inject_http_header_with_len, remove_http_header,
    remove_http_header_with_len, status_reason_phrase,
};
pub use conn::{ConnFlags, ConnId, Connection};
pub use endpoint::{Endpoint, ScFlags, ScState, SeDesc, SeFlags, StConn};
pub use exp::{apply_cliexp, apply_srvexp, extract_cookie, rewrite_header_block, CompiledExp};
pub use h1::{H1Parser, H1Phase};
pub use parser::{
    available, build, Differential, DifferentialStream, HttpParser, HttpStream, Mismatch,
    OnMismatch, ParserKind,
};
pub use h2::{
    frame_flags, Frame, FrameHeader, FrameType, H2ConnState, H2Error, H2StreamState,
    SettingsParameter, DEFAULT_HEADER_TABLE_SIZE, DEFAULT_INITIAL_WINDOW_SIZE,
    DEFAULT_MAX_FRAME_SIZE, FRAME_HEADER_LEN, H2_CONN_PREFACE, MAX_WINDOW_SIZE,
};
pub use hpack::{
    decode_integer, encode_integer, DynamicTable, HpackDecoder, HpackEncoder, TableEntry,
    DEFAULT_DYNAMIC_TABLE_MAX_SIZE, STATIC_TABLE, STATIC_TABLE_LEN,
};
pub use htx::{
    HeaderField, HttpMethod, HttpVersion, Htx, HtxBlock, HtxBlockDesc, HtxBlockType, HtxBuffer,
    HtxError, RequestLine, ResponseLine,
};
pub use mux::{Mux, MuxFlags, MuxOps, ShutMode};
pub use mux_h1::{H1MuxContext, MuxH1};
pub use mux_h2::{H2FloodConfig, H2MuxContext, H2StreamCtx, MuxH2};
pub use mux_pt::{MuxPt, PtMuxContext};
pub use proto::{ProtoKind, Protocol};
pub use proxy_protocol::{
    calculate_crc32c, encode_proxy_v1, encode_proxy_v2, parse_proxy_header, ssl_client_flags,
    tlv_types, update_crc32c_in_buffer, ProxyAddress, ProxyCommand, ProxyEncodeError, ProxyHeader,
    ProxyInfo, ProxyParseError, ProxyTransport, ProxyVersion, SslTlv, Tlv, TlvBuilder, TlvIter,
    PP1_MAX_LINE_LEN, PP1_PREFIX, PP2_ADDR_LEN_INET, PP2_ADDR_LEN_INET6, PP2_ADDR_LEN_UNIX,
    PP2_HEADER_LEN, PP2_SIGNATURE,
};
pub use session::{Session, SessionId};
pub use stream::{Stream, StreamId};
pub use transport::{TlsInfo, Transport, TransportKind};
