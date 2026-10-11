// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/h1.c, src/mux_h1.c and include/haproxy/h1.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/1.1 Wire Parser and Framing.
//!
//! Converts raw HTTP/1.1 and HTTP/1.0 wire streams into [`Htx`] blocks.

use crate::htx::{HtxBlockType, HtxSlice};
use std::io;

/// Current parser phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H1Phase {
    StartLine,
    Headers,
    BodyFixed {
        remaining: usize,
    },
    BodyChunked {
        chunk_rem: usize,
        waiting_crlf: bool,
    },
    Trailers,
    Done,
    Error,
}

/// An HTTP/1 message refused with a status other than 400, carried inside the
/// `io::Error` of a parse: `HAProxy` answers 413 and 422 to some requests its parser
/// accepts (`h1_process_input` in mux_h1.c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal(pub u16);

/// A [`Refusal`] with what caused it, as the payload of an `io::Error`.
#[derive(Debug)]
struct RefusalWhy(u16, &'static str);

impl std::fmt::Display for RefusalWhy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (refused with {})", self.1, self.0)
    }
}

impl std::error::Error for RefusalWhy {}

impl Refusal {
    #[must_use]
    pub fn error(status: u16, why: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, RefusalWhy(status, why))
    }

    /// The status an error from a parse asks for: its own, or 400.
    #[must_use]
    pub fn status_of(e: &io::Error) -> u16 {
        e.get_ref().and_then(|e| e.downcast_ref::<RefusalWhy>()).map_or(400, |r| r.0)
    }
}

/// The `Transfer-Encoding` lines of a head, read as one list in order, by the rules of
/// `HAProxy`'s `h1_parse_xfer_enc_header` (src/h1.c).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct TransferCodings {
    /// At least one `Transfer-Encoding` line.
    pub present: bool,
    /// The last coding of the list is `chunked`: the message is chunked.
    pub chunked_last: bool,
    /// A coding other than `chunked` (`H1_MF_TE_OTHER`).
    pub other: bool,
    /// Every such coding is `gzip`, `deflate` or `compress`.
    pub other_known: bool,
    /// An empty line or element, a trailing comma, `chunked` twice, or (in a request) a
    /// coding after `chunked`.
    pub invalid: bool,
}

impl TransferCodings {
    pub fn of<N: AsRef<str>, V: AsRef<str>>(headers: impl Iterator<Item = (N, V)>, is_response: bool) -> Self {
        let lws = |c: char| c == ' ' || c == '\t';
        let mut t = TransferCodings { other_known: true, ..TransferCodings::default() };
        let mut chunked_seen = false;
        for (_, value) in headers.filter(|(n, _)| n.as_ref().eq_ignore_ascii_case("transfer-encoding")) {
            t.present = true;
            let v = value.as_ref().trim_matches(lws);
            if v.is_empty() || v.ends_with(',') {
                t.invalid = true;
            }
            for word in v.split(',').map(|w| w.trim_matches(lws)) {
                t.chunked_last = false;
                if word.is_empty() {
                    t.invalid = true;
                } else if word.eq_ignore_ascii_case("chunked") {
                    t.invalid |= chunked_seen;
                    chunked_seen = true;
                    t.chunked_last = true;
                } else {
                    t.invalid |= chunked_seen && !is_response;
                    t.other = true;
                    t.other_known &= ["gzip", "deflate", "compress"].iter().any(|k| word.eq_ignore_ascii_case(k));
                }
            }
        }
        t
    }
}

/// HTTP/1.1 Parser state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct H1Parser {
    pub is_response: bool,
    pub phase: H1Phase,
    pub content_length: Option<usize>,
    pub is_chunked: bool,
    pub is_upgrade: bool,
    pub connection_close: bool,
    /// Set when the message carried both `Content-Length` and `Transfer-Encoding`.
    /// The Content-Length was dropped per RFC 7230 §3.3.3 and the connection must not
    /// be reused.
    pub framing_conflict: bool,
    pub saw_bare_cr: bool,
    pub prev_delim_len: usize,
    /// Set when the request head was rewritten while parsing it -- a repeated `Host`
    /// dropped, or the authority and `Host` normalised (`crate::authority`) -- so the
    /// head must be forwarded from the HTX, not as received.
    pub head_rewritten: bool,
    /// `option accept-unsafe-violations-in-http-request`: a `#` in the request target, and
    /// a forbidden character in an authority, are let through. Kept across `reset`.
    pub accept_unsafe_request: bool,
    /// The status a message that parsed must still be refused with (422: a request with a
    /// transfer coding other than chunked). Cleared by `reset`.
    pub refusal: Option<u16>,
}

impl H1Parser {
    #[must_use]
    pub fn new(is_response: bool) -> Self {
        H1Parser {
            is_response,
            phase: H1Phase::StartLine,
            content_length: None,
            is_chunked: false,
            is_upgrade: false,
            connection_close: false,
            framing_conflict: false,
            saw_bare_cr: false,
            prev_delim_len: 2,
            head_rewritten: false,
            accept_unsafe_request: false,
            refusal: None,
        }
    }

    /// Resets the parser for the next HTTP request/response on a reused/keep-alive connection.
    pub fn reset(&mut self, is_response: bool) {
        self.is_response = is_response;
        self.phase = H1Phase::StartLine;
        self.content_length = None;
        self.is_chunked = false;
        self.is_upgrade = false;
        self.connection_close = false;
        self.saw_bare_cr = false;
        self.prev_delim_len = 2;
        self.head_rewritten = false;
        self.refusal = None;
    }

    /// Finalizes parsing on connection close / EOF (for HTTP/1.0 close delimiter fallback).
    pub fn finish(&mut self, htx: &mut HtxSlice<'_>) {
        if matches!(
            self.phase,
            H1Phase::BodyFixed {
                remaining: usize::MAX
            }
        ) {
            let _ = htx.push_eom();
            self.phase = H1Phase::Done;
        }
    }

    /// Parses wire bytes into an [`HtxSlice`] transaction.
    /// Returns the number of consumed bytes.
    ///
    /// # Errors
    /// Returns an error if the HTTP stream contains framing syntax violations.
    pub fn parse(&mut self, input: &[u8], htx: &mut HtxSlice<'_>) -> io::Result<usize> {
        let mut cursor = 0;

        while cursor < input.len() && self.phase != H1Phase::Done && self.phase != H1Phase::Error {
            match self.phase {
                H1Phase::StartLine => {
                    let consumed = self.parse_start_line(&input[cursor..], htx)?;
                    if consumed == 0 {
                        break;
                    }
                    cursor += consumed;
                }
                H1Phase::Headers => {
                    let consumed = self.parse_headers(&input[cursor..], htx)?;
                    if consumed == 0 {
                        break;
                    }
                    cursor += consumed;
                }
                H1Phase::BodyFixed { ref mut remaining } => {
                    let consumed = Self::parse_body_fixed(&input[cursor..], htx, remaining)?;
                    if consumed == 0 {
                        break;
                    }
                    cursor += consumed;
                    if *remaining == 0 {
                        htx.push_eom()
                            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
                        self.phase = H1Phase::Done;
                    }
                }
                H1Phase::BodyChunked { .. } => {
                    let (consumed, reached_last_chunk) =
                        self.parse_body_chunked(&input[cursor..], htx)?;
                    cursor += consumed;
                    if reached_last_chunk {
                        self.phase = H1Phase::Trailers;
                    }
                    if consumed == 0 {
                        break;
                    }
                }
                H1Phase::Trailers => {
                    let (consumed, is_done) = self.parse_trailers(&input[cursor..], htx)?;
                    cursor += consumed;
                    if is_done {
                        htx.push_eom()
                            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
                        self.phase = H1Phase::Done;
                        break;
                    }
                    if consumed == 0 {
                        break;
                    }
                }
                H1Phase::Done | H1Phase::Error => break,
            }
        }

        Ok(cursor)
    }

    fn find_line_end(&mut self, buf: &[u8]) -> Option<(usize, usize)> {
        for i in 0..buf.len() {
            if buf[i] == b'\r' {
                if i + 1 < buf.len() {
                    if buf[i + 1] == b'\n' {
                        return Some((i, 2));
                    }
                    // A CR not followed by LF is not a line terminator. Recognising it
                    // as one lets `GET / HTTP/1.1\rHost: h\r\r` parse, which HAProxy 3.5
                    // answers 400 to -- and a hop that disagrees about where lines end
                    // disagrees about where the message ends.
                    self.saw_bare_cr = true;
                    return Some((i, 1));
                }
                if self.saw_bare_cr {
                    return Some((i, 1));
                }
                // Single trailing \r might be part of CRLF across chunks
                return None;
            }
            if buf[i] == b'\n' {
                return Some((i, 1));
            }
        }
        None
    }

    fn parse_start_line(&mut self, input: &[u8], htx: &mut HtxSlice<'_>) -> io::Result<usize> {
        let Some((line_end, delim_len)) = self.find_line_end(input) else {
            return Ok(0);
        };
        let line_bytes = &input[..line_end];
        let line_str = std::str::from_utf8(line_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in start line")
        })?;

        if self.is_response {
            let (version, status, reason) = parse_response_line_borrowed(line_str)?;
            htx.push_res_line(version, status, reason)
                .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
        } else {
            let (method, uri, version) = parse_request_line_borrowed(line_str)?;
            htx.push_req_line(method, uri, version)
                .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
        }

        self.prev_delim_len = delim_len;
        self.phase = H1Phase::Headers;
        Ok(line_end + delim_len)
    }

    fn parse_headers(&mut self, input: &[u8], htx: &mut HtxSlice<'_>) -> io::Result<usize> {
        let Some((line_end, delim_len)) = self.find_line_end(input) else {
            return Ok(0);
        };

        if self.saw_bare_cr {
            self.phase = H1Phase::Error;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bare CR is not a line terminator",
            ));
        }

        if line_end == 0 {
            htx.finalize_last_header();
            // Empty line -> End of headers
            htx.push_eoh()
                .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            self.on_headers_finished(htx)?;
            self.prev_delim_len = delim_len;
            Ok(delim_len)
        } else {
            let header_bytes = &input[..line_end];
            if header_bytes.starts_with(b" ") || header_bytes.starts_with(b"\t") {
                // Multiline header (obs-fold): append to previous header.
                // RFC 9112 §5.2 / HAProxy replaces preceding CRLF with 2 SP (or LF with 1 SP)
                // and preserves the continuation line's leading whitespace run.
                let prefix = if self.prev_delim_len == 2 { "  " } else { " " };
                let folded_val = std::str::from_utf8(header_bytes)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid folded header")
                    })?;
                let mut combined = String::with_capacity(prefix.len() + folded_val.len());
                combined.push_str(prefix);
                combined.push_str(folded_val);
                htx.append_to_last_header(&combined).map_err(|_| {
                    self.phase = H1Phase::Error;
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "obs-fold continuation with no preceding header",
                    )
                })?;
                // Forwarded unfolded, from the HTX, as HAProxy does (tasks/T276).
                self.head_rewritten = true;
                self.prev_delim_len = delim_len;
                return Ok(line_end + delim_len);
            }

            let header_str = std::str::from_utf8(header_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid header string"))?;

            let (name, value) = parse_header_field_borrowed(header_str)?;
            htx.finalize_last_header();
            htx.push_header(name, value)
                .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            self.prev_delim_len = delim_len;
            Ok(line_end + delim_len)
        }
    }

    fn parse_trailers(&mut self, input: &[u8], htx: &mut HtxSlice<'_>) -> io::Result<(usize, bool)> {
        let mut cursor = 0;
        while cursor < input.len() {
            let Some((line_end, delim_len)) = self.find_line_end(&input[cursor..]) else {
                return Ok((cursor, false));
            };

            if line_end == 0 {
                htx.finalize_last_trailer();
                // Empty line -> End of trailers
                htx.push_eot()
                    .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
                self.prev_delim_len = delim_len;
                return Ok((cursor + delim_len, true));
            }

            let trailer_bytes = &input[cursor..cursor + line_end];
            if trailer_bytes.starts_with(b" ") || trailer_bytes.starts_with(b"\t") {
                // Multiline trailer (obs-fold)
                let prefix = if self.prev_delim_len == 2 { "  " } else { " " };
                let folded_val = std::str::from_utf8(trailer_bytes)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid folded trailer")
                    })?;
                let mut combined = String::with_capacity(prefix.len() + folded_val.len());
                combined.push_str(prefix);
                combined.push_str(folded_val);
                let _ = htx.append_to_last_trailer(&combined);
            } else {
                let trailer_str = std::str::from_utf8(trailer_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid trailer string")
                })?;
                let (name, value) = parse_header_field_borrowed(trailer_str)?;
                htx.finalize_last_trailer();
                htx.push_trailer(name, value)
                    .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            }

            self.prev_delim_len = delim_len;
            cursor += line_end + delim_len;
        }
        Ok((cursor, false))
    }


    fn on_headers_finished(&mut self, htx: &mut HtxSlice<'_>) -> io::Result<()> {
        if !self.is_response {
            // The authority against `Host`, as HAProxy checks it at the end of the head
            // (`h1_parse_msg_hdrs`) and normalises it (`http_scheme_based_normalize`).
            match crate::authority::check_and_normalize(htx, self.accept_unsafe_request) {
                Ok(rewritten) => self.head_rewritten |= rewritten,
                Err(e) => {
                    self.phase = H1Phase::Error;
                    return Err(e);
                }
            }
        }
        let last_start_line = (0..htx.num_blocks())
            .rev()
            .find(|&i| matches!(htx.block_type(i), Some(HtxBlockType::ReqLine | HtxBlockType::ResLine)))
            .map_or(0, |i| i + 1);

        let mut seen_cl: Option<usize> = None;
        let mut first_cl_idx: Option<usize> = None;
        let mut duplicate_cl = false;
        let mut comma_cl = false;

        let sref = htx.as_ref();
        for i in last_start_line..sref.num_blocks() {
            if sref.block_type(i) != Some(HtxBlockType::Header) {
                continue;
            }
            let desc = sref.read_desc(i);
            let s = desc.addr as usize;
            let nl = desc.name_len as usize;
            let vl = desc.value_len as usize;
            let Ok(h_name) = std::str::from_utf8(&sref.buf()[s..s + nl]) else { continue };
            if !h_name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if first_cl_idx.is_none() {
                first_cl_idx = Some(i);
            } else {
                duplicate_cl = true;
            }
            
            let Ok(h_val) = std::str::from_utf8(&sref.buf()[s + nl..s + nl + vl]) else { continue };
            let raw = h_val.trim();

            let mut parts = raw.split(',').map(str::trim);
            let Some(first) = parts.next() else {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty Content-Length",
                ));
            };
            if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Content-Length value",
                ));
            }
            for p in parts {
                if p != first {
                    self.phase = H1Phase::Error;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "conflicting Content-Length list values",
                    ));
                }
                comma_cl = true;
            }
            let Ok(len) = first.parse::<usize>() else {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Content-Length out of range",
                ));
            };
            if seen_cl.is_some_and(|prev| prev != len) {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "conflicting Content-Length values",
                ));
            }
            seen_cl = Some(len);
        }
        self.content_length = seen_cl;



        if duplicate_cl || comma_cl {
            // Forwarded as the one value it stands for (tasks/T276).
            self.head_rewritten = true;
            let first_idx = first_cl_idx.unwrap();
            let mut val_buf = [0u8; 20];
            let val_bytes = {
                use std::io::Write;
                let mut slice = &mut val_buf[..];
                write!(slice, "{}", seen_cl.unwrap()).unwrap();
                let len = 20 - slice.len();
                &val_buf[..len]
            };
            
            htx.replace_block_value(first_idx, val_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            
            let num_blocks = htx.as_ref().num_blocks();
            for i in (first_idx + 1..num_blocks).rev() {
                if htx.as_ref().block_type(i) == Some(HtxBlockType::Header) {
                    let desc = htx.as_ref().read_desc(i);
                    let s = desc.addr as usize;
                    let nl = desc.name_len as usize;
                    if let Ok(name) = std::str::from_utf8(&htx.as_ref().buf()[s..s+nl]) {
                        if name.eq_ignore_ascii_case("content-length") {
                            htx.remove_block(i);
                        }
                    }
                }
            }
        }

        // `Transfer-Encoding` on every line, in order, as one list (RFC 9110 section 5.3),
        // read the way HAProxy's `h1_parse_xfer_enc_header` reads it: reading only the
        // first line framed `gzip` + `chunked` on two lines as a request without a body,
        // while the next hop read a chunked one (tasks/T276, V&V VV-1).
        let te = TransferCodings::of(htx.headers(), self.is_response);
        if te.invalid {
            self.phase = H1Phase::Error;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid Transfer-Encoding"));
        }
        self.is_chunked = te.chunked_last;
        if te.present && self.content_length.is_some() {
            // T-E + C-L: the length goes and the connection closes (`h1_parse_msg_hdrs`).
            self.content_length = None;
            htx.remove_header("content-length");
            self.framing_conflict = true;
            self.connection_close = true;
        }
        let is_http11 = htx.req_line().map_or_else(|| htx.res_line().is_some_and(|r| r.version == "HTTP/1.1"), |r| r.version == "HTTP/1.1");
        if te.present && !is_http11 {
            // T-E in HTTP/1.0: the connection closes after this message.
            self.connection_close = true;
        }
        if !self.is_response {
            // A request whose last coding is not chunked has no length (RFC 9112 section
            // 6.3): 400, as `h1_parse_msg_hdrs` refuses it.
            if te.present && !te.chunked_last {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "request Transfer-Encoding without final chunked"));
            }
            // `h1_process_input` in mux_h1.c, in this order: an HTTP/1.0 GET, HEAD or
            // DELETE with a body is 413, then any coding but chunked is 422.
            let method = htx.req_line().map(|r| r.method);
            let body = self.is_chunked || self.content_length.is_some_and(|n| n > 0);
            if !is_http11 && body && method.is_some_and(|m| ["GET", "HEAD", "DELETE"].contains(&m)) {
                self.phase = H1Phase::Error;
                return Err(Refusal::error(413, "HTTP/1.0 GET/HEAD/DELETE with a body"));
            }
            if te.other {
                // Refused with 422 either way. A coding Ibex has never heard of is a parse
                // error; `gzip`, `deflate` and `compress` parse (crates/ibex-proto/tests/
                // h1_strictness.rs holds this parser to that) and the proxy refuses the
                // request on `refusal`, before anything is forwarded.
                if !te.other_known {
                    self.phase = H1Phase::Error;
                    return Err(Refusal::error(422, "transfer coding other than chunked"));
                }
                self.refusal = Some(422);
            }
        }

        let is_http10 = htx
            .req_line()
            .map_or(false, |r| r.version == "HTTP/1.0")
            || htx
                .res_line()
                .map_or(false, |r| r.version == "HTTP/1.0");

        if let Some(conn) = htx.get_header("connection") {
            if conn.eq_ignore_ascii_case("close") {
                self.connection_close = true;
            } else if conn.eq_ignore_ascii_case("keep-alive") {
                self.connection_close = false;
            }
        } else if is_http10 {
            self.connection_close = true;
        }

        if let Some(meth) = htx.req_line().map(|r| r.method) {
            if meth.eq_ignore_ascii_case("CONNECT") {
                self.is_upgrade = true;
            }
        }
        if htx.get_header("upgrade").is_some() {
            self.is_upgrade = true;
        }

        if self.is_chunked {
            self.phase = H1Phase::BodyChunked {
                chunk_rem: 0,
                waiting_crlf: false,
            };
        } else if let Some(len) = self.content_length {
            if len == 0 {
                htx.push_eom()
                    .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
                self.phase = H1Phase::Done;
            } else {
                self.phase = H1Phase::BodyFixed { remaining: len };
            }
        } else if self.is_response && !self.is_upgrade {
            self.phase = H1Phase::BodyFixed {
                remaining: usize::MAX,
            };
        } else {
            htx.push_eom()
                .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            self.phase = H1Phase::Done;
        }

        Ok(())
    }

    fn parse_body_fixed(
        input: &[u8],
        htx: &mut HtxSlice<'_>,
        remaining: &mut usize,
    ) -> io::Result<usize> {
        let available = input.len();
        if available == 0 {
            return Ok(0);
        }

        let take = if *remaining == usize::MAX {
            available
        } else {
            available.min(*remaining)
        };

        htx.push_data(&input[..take])
            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
        if *remaining != usize::MAX {
            *remaining -= take;
        }
        Ok(take)
    }

    fn parse_body_chunked(
        &mut self,
        input: &[u8],
        htx: &mut HtxSlice<'_>,
    ) -> io::Result<(usize, bool)> {
        let (mut chunk_rem, mut waiting_crlf) = match self.phase {
            H1Phase::BodyChunked {
                chunk_rem,
                waiting_crlf,
            } => (chunk_rem, waiting_crlf),
            _ => return Ok((0, false)),
        };

        let mut cursor = 0;

        if waiting_crlf {
            if cursor >= input.len() {
                self.phase = H1Phase::BodyChunked {
                    chunk_rem,
                    waiting_crlf,
                };
                return Ok((cursor, false));
            }
            if input[cursor..].starts_with(b"\r\n") {
                cursor += 2;
                waiting_crlf = false;
            } else if input[cursor..].starts_with(b"\n") {
                cursor += 1;
                waiting_crlf = false;
            } else if input[cursor..].starts_with(b"\r") {
                if input.len() - cursor == 1 && !self.saw_bare_cr {
                    self.phase = H1Phase::BodyChunked {
                        chunk_rem,
                        waiting_crlf,
                    };
                    return Ok((cursor, false));
                }
                cursor += 1;
                waiting_crlf = false;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Malformed chunk boundary",
                ));
            }
        }

        if chunk_rem == 0 && !waiting_crlf {
            let Some((line_end, delim_len)) = self.find_line_end(&input[cursor..]) else {
                self.phase = H1Phase::BodyChunked {
                    chunk_rem,
                    waiting_crlf,
                };
                return Ok((cursor, false));
            };
            let len_str = std::str::from_utf8(&input[cursor..cursor + line_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid chunk len"))?;
            // No trimming: RFC 9112 7.1 allows no whitespace around a chunk size, and
            // ` 5 ` is read as 5 by a lenient hop and rejected by a strict one.
            // HAProxy 3.5 answers 400.
            let len_part = len_str.split(';').next().unwrap_or("");
            // Hex digits only. `from_str_radix` accepts a leading '+' or '-', so
            // `+5\r\n` would parse as chunk size 5 -- HAProxy 3.5 answers 400 to that,
            // and a size a peer reads differently is a desync primitive.
            if len_part.is_empty() || !len_part.bytes().all(|b| b.is_ascii_hexdigit()) {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid chunk size",
                ));
            }
            let chunk_size = usize::from_str_radix(len_part, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid hex chunk size")
            })?;

            cursor += line_end + delim_len;

            if chunk_size == 0 {
                return Ok((cursor, true));
            }

            chunk_rem = chunk_size;
        }

        if chunk_rem > 0 {
            let available = input.len() - cursor;
            if available > 0 {
                let take = available.min(chunk_rem);
                htx.push_data(&input[cursor..cursor + take])
                    .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
                cursor += take;
                chunk_rem -= take;
                if chunk_rem == 0 {
                    waiting_crlf = true;
                }
            }
        }

        self.phase = H1Phase::BodyChunked {
            chunk_rem,
            waiting_crlf,
        };
        Ok((cursor, false))
    }
}

fn parse_request_line_borrowed(line: &str) -> io::Result<(&str, &str, &str)> {
    let mut parts = line.split_whitespace();
    let method_str = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP method"))?;
    let uri = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP URI"))?;
    let version_str = parts.next().unwrap_or("HTTP/1.1");

    // Request-target forms (RFC 9112 section 3.2), as HAProxy's H1 parser enforces them
    // (`reg-tests/http-messaging/h1_request_target_validation.vtc`): origin-form `/...`,
    // absolute-form `scheme://authority...` with any scheme, asterisk-form only for
    // OPTIONS, authority-form `host:port` only for CONNECT.
    let absolute_form = |u: &str| {
        u.split_once("://").is_some_and(|(scheme, rest)| {
            scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                && !rest.is_empty()
        })
    };
    let is_valid = match method_str {
        "CONNECT" => !uri.starts_with('/') && !uri.contains("://") && uri.contains(':'),
        "OPTIONS" => uri == "*" || uri.starts_with('/') || absolute_form(uri),
        _ => uri.starts_with('/') || absolute_form(uri),
    };

    if !is_valid {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid request target"));
    }

    Ok((method_str, uri, version_str))
}

fn parse_response_line_borrowed(line: &str) -> io::Result<(&str, u16, &str)> {
    let mut parts = line.splitn(3, ' ');
    let version_str = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP version"))?;
    let status_str = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP status"))?;
    let reason = parts.next().unwrap_or("").trim();

    let status = status_str
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP status code"))?;

    Ok((version_str, status, reason))
}

/// True for RFC 9110 `tchar`, the only octets allowed in a header field name.
const fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn parse_header_field_borrowed(line: &str) -> io::Result<(&str, &str)> {
    let (name, val) = line
        .split_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Header missing colon"))?;

    // RFC 9112 5.1 is unusually blunt here: a server MUST reject, with 400, any
    // request containing whitespace between the field name and the colon.
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty header field name",
        ));
    }
    if !name.bytes().all(is_tchar) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid character in header field name",
        ));
    }

    // Field values may not carry NUL, CR or LF.
    if val.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid character in header field value",
        ));
    }

    Ok((name, val.trim_start_matches([' ', '\t'])))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal reads as its cause and status, and its status is what `status_of` returns;
    /// any other error is a 400.
    #[test]
    fn a_refusal_names_its_cause_and_status() {
        let e = Refusal::error(413, "HTTP/1.0 GET/HEAD/DELETE with a body");
        assert_eq!(e.to_string(), "HTTP/1.0 GET/HEAD/DELETE with a body (refused with 413)");
        assert_eq!(Refusal::status_of(&e), 413);
        assert_eq!(Refusal::status_of(&io::Error::new(io::ErrorKind::InvalidData, "x")), 400);
    }

    /// A header value that is not UTF-8 is a 400, whatever the header. The rest of the proxy reads
    /// headers as text (ACLs, fetches, rule actions); a header it cannot read but the server
    /// receives would walk around `http-request deny if { req.hdr(x-admin) -m found }` (T158).
    #[test]
    fn a_header_value_that_is_not_utf8_is_refused_for_every_header() {
        for name in [
            "x-admin", "Content-Length", "transfer-encoding", "Connection", "PROXY-CONNECTION", "keep-alive",
            "Host", "Expect", "upgrade", "TE", "Trailer", "Cookie", "Forwarded",
        ] {
            let mut raw = b"POST / HTTP/1.1\r\nHost: h\r\n".to_vec();
            raw.extend_from_slice(name.as_bytes());
            raw.extend_from_slice(b": 5\xff\r\n\r\n");
            let mut buf = [0u8; 4096];
            let mut htx = HtxSlice::new(&mut buf);
            assert!(H1Parser::new(false).parse(&raw, &mut htx).is_err(), "{name}");
        }
    }

    #[test]
    fn parse_http_get_request() {
        let req =
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        let mut parser = H1Parser::new(false);
        let mut buf = [0u8; 4096];
        let mut htx = HtxSlice::new(&mut buf);

        let consumed = parser.parse(req, &mut htx).expect("parse");
        assert_eq!(consumed, req.len());
        assert_eq!(parser.phase, H1Phase::Done);

        let sref = htx.as_ref();
        assert_eq!(sref.req_line().unwrap().method, "GET");
        assert_eq!(sref.req_line().unwrap().uri, "/index.html");
        assert_eq!(sref.get_header("host"), Some("example.com"));
        assert!(sref.is_eom());
    }

    #[test]
    fn parse_http_post_with_content_length() {
        let req =
            b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world";
        let mut parser = H1Parser::new(false);
        let mut buf = [0u8; 4096];
        let mut htx = HtxSlice::new(&mut buf);

        let consumed = parser.parse(req, &mut htx).expect("parse");
        assert_eq!(consumed, req.len());
        assert_eq!(parser.phase, H1Phase::Done);
        assert_eq!(htx.as_ref().body_bytes(), b"hello world");
        assert!(htx.as_ref().is_eom());
    }

    #[test]
    fn parse_http_chunked_response() {
        let res = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut parser = H1Parser::new(true);
        let mut buf = [0u8; 4096];
        let mut htx = HtxSlice::new(&mut buf);

        let consumed = parser.parse(res, &mut htx).expect("parse");
        assert_eq!(consumed, res.len());
        assert_eq!(parser.phase, H1Phase::Done);
        assert_eq!(htx.as_ref().res_line().unwrap().status, 200);
        assert_eq!(htx.as_ref().body_bytes(), b"hello world");
        assert!(htx.as_ref().is_eom());
    }

    #[test]
    fn parse_http_post_with_duplicate_cl_agreeing() {
        let req =
            b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\nContent-Length: 11\r\n\r\nhello worldExtra";
        let mut parser = H1Parser::new(false);
        let mut buf = [0u8; 4096];
        let mut htx = HtxSlice::new(&mut buf);

        let consumed = parser.parse(req, &mut htx).expect("parse");
        // We should consume exactly up to the end of "hello world", leaving "Extra"
        assert_eq!(consumed, req.len() - 5);
        assert_eq!(parser.phase, H1Phase::Done);
        assert_eq!(htx.as_ref().body_bytes(), b"hello world");
        assert!(htx.as_ref().is_eom());
        // Verify headers are collapsed
        let hdrs: Vec<_> = htx.as_ref().headers().filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).collect();
        assert_eq!(hdrs.len(), 1);
        assert_eq!(hdrs[0].1, "11");
    }

    #[test]
    fn parse_http_post_with_comma_cl_agreeing() {
        let req =
            b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11, 11\r\n\r\nhello worldExtra";
        let mut parser = H1Parser::new(false);
        let mut buf = [0u8; 4096];
        let mut htx = HtxSlice::new(&mut buf);

        let consumed = parser.parse(req, &mut htx).expect("parse");
        assert_eq!(consumed, req.len() - 5);
        assert_eq!(parser.phase, H1Phase::Done);
        assert_eq!(htx.as_ref().body_bytes(), b"hello world");
        assert!(htx.as_ref().is_eom());
        let hdrs: Vec<_> = htx.as_ref().headers().filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).collect();
        assert_eq!(hdrs.len(), 1);
        assert_eq!(hdrs[0].1, "11");
    }
}

#[cfg(test)]
mod request_target_tests {
    use super::parse_request_line_borrowed;

    #[test]
    fn test_request_target_validation() {
        // Valid
        assert!(parse_request_line_borrowed("OPTIONS * HTTP/1.1").is_ok());
        assert!(parse_request_line_borrowed("GET / HTTP/1.1").is_ok());
        assert!(parse_request_line_borrowed("GET http://haproxy.org/ HTTP/1.1").is_ok());
        assert!(parse_request_line_borrowed("CONNECT haproxy.org:80 HTTP/1.1").is_ok());
        // HAProxy accepts any scheme, in any case, in absolute-form.
        assert!(parse_request_line_borrowed("GET ftp://h/x HTTP/1.1").is_ok());
        assert!(parse_request_line_borrowed("GET HTTP://h/x HTTP/1.1").is_ok());
        assert!(parse_request_line_borrowed("GET http:// HTTP/1.1").is_err());

        // Invalid
        assert!(parse_request_line_borrowed("OPTIONS */test HTTP/1.1").is_err());
        assert!(parse_request_line_borrowed("GET * HTTP/1.1").is_err());
        assert!(parse_request_line_borrowed("CONNECT haproxy.org HTTP/1.1").is_err());
        assert!(parse_request_line_borrowed("CONNECT / HTTP/1.1").is_err());
        assert!(parse_request_line_borrowed("CONNECT http://haproxy.org:80 HTTP/1.1").is_err());
        assert!(parse_request_line_borrowed("GET haproxy.org:80 HTTP/1.1").is_err());
        assert!(parse_request_line_borrowed("GET admin HTTP/1.1").is_err());
        assert!(parse_request_line_borrowed("GET admin/a/b HTTP/1.1").is_err());
    }
}
