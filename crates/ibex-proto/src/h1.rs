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
struct RefusalWhy(u16, &'static str, bool);

impl std::fmt::Display for RefusalWhy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (refused with {})", self.1, self.0)
    }
}

impl std::error::Error for RefusalWhy {}

impl Refusal {
    #[must_use]
    pub fn error(status: u16, why: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, RefusalWhy(status, why, false))
    }

    /// A [`Refusal::error`] that is not answered: the connection closes with nothing
    /// written, and the status is only logged (`HAProxy` on Content-Length lines that
    /// differ, T286).
    #[must_use]
    pub fn quiet(status: u16, why: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, RefusalWhy(status, why, true))
    }

    /// Whether the error from a parse is one that is not answered ([`Refusal::quiet`]).
    #[must_use]
    pub fn is_quiet(e: &io::Error) -> bool {
        e.get_ref().and_then(|e| e.downcast_ref::<RefusalWhy>()).is_some_and(|r| r.2)
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
    /// An empty line or element, a trailing comma, `chunked` twice, or (in a request) a
    /// coding after `chunked`.
    pub invalid: bool,
}

impl TransferCodings {
    pub fn of<N: AsRef<str>, V: AsRef<str>>(headers: impl Iterator<Item = (N, V)>, is_response: bool) -> Self {
        let lws = |c: char| c == ' ' || c == '\t';
        let mut t = TransferCodings::default();
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
    /// Header lines of the request head so far, against [`MAX_REQUEST_HEADERS`].
    pub header_lines: u16,
    /// The last header line was a `TE` that is not sent on (its continuation lines are not).
    last_dropped: bool,
}

/// Header lines a request or response head may carry: `HAProxy`'s `tune.http.maxhdr` (101)
/// less one. Measured on 3.5-dev8: 100 lines pass, 101 are a 400 logged `PR--` for a
/// request and a 502 logged `PH--` for a response (T285). Ibex refuses `tune.http.maxhdr`,
/// so the limit is the default. Lines [`uncounted`] are not counted.
pub const MAX_REQUEST_HEADERS: u16 = 100;

/// A `Connection` line holding only `close` and `keep-alive` tokens, or none (an empty
/// value, T286): `HAProxy` empties and
/// drops it while parsing (`h1_parse_connection_header`), so it does not count against
/// [`MAX_REQUEST_HEADERS`]. Measured: 100 lines and `Connection: close` pass, 100 and
/// `Connection: foo` or `Connection: close, foo` do not.
#[must_use]
pub fn uncounted(name: &[u8], value: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"connection") && {
        let mut tokens = value.split(|&b| b == b',').map(<[u8]>::trim_ascii).filter(|t| !t.is_empty());
        tokens.all(|t| t.eq_ignore_ascii_case(b"close") || t.eq_ignore_ascii_case(b"keep-alive"))
    }
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
            header_lines: 0,
            last_dropped: false,
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
        self.header_lines = 0;
        self.last_dropped = false;
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

    /// The `Upgrade` side of a request head, as `HAProxy` reads it (`h1_parse_upgrade_header`,
    /// `h1_postparse_req_hdrs` in src/h1_htx.c, `h1_search_websocket_key` in src/mux_h1.c):
    /// `h2c` and `h2` are taken out of every `Upgrade` line and a line left empty goes; every
    /// `Upgrade` line goes when no `Connection` line carries `upgrade` (the token goes from
    /// `Connection` in the other case, on the way out). A websocket handshake (`upgrade` in
    /// `Connection`, `websocket` in `Upgrade`) without a `Sec-WebSocket-Key` of 24 characters
    /// is refused with 400, but with `option accept-unsafe-violations-in-http-request`.
    fn check_upgrade(&mut self, htx: &mut HtxSlice<'_>) -> io::Result<()> {
        let mut conn_upg = false;
        let (mut websocket, mut key) = (false, false);
        // Each `Upgrade` line's index and, when it changes, what it becomes (empty: it goes).
        let mut edits: Vec<(usize, Option<String>)> = Vec::new();
        let named = |n: &[u8]| n.eq_ignore_ascii_case(b"connection") || n.eq_ignore_ascii_case(b"upgrade") || n.eq_ignore_ascii_case(b"sec-websocket-key");
        for (i, name, value) in htx.as_ref().header_blocks_where(named) {
            if name.eq_ignore_ascii_case("connection") {
                conn_upg |= crate::upgrade::tokens(value).any(|t| t.eq_ignore_ascii_case("upgrade"));
            } else if name.eq_ignore_ascii_case("upgrade") {
                let clean = crate::upgrade::clean_value(value);
                let v = clean.as_deref().unwrap_or(value);
                websocket |= crate::upgrade::tokens(v).any(|t| t.eq_ignore_ascii_case("websocket"));
                edits.push((i, clean));
            } else if name.eq_ignore_ascii_case("sec-websocket-key") {
                key |= value.len() == 24;
            }
        }
        if conn_upg && websocket && !key && !self.accept_unsafe_request {
            self.phase = H1Phase::Error;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "websocket handshake without a valid Sec-WebSocket-Key"));
        }
        for (i, clean) in edits.into_iter().rev() {
            if !conn_upg || clean.as_deref() == Some("") {
                htx.remove_block(i);
            } else if let Some(v) = clean {
                htx.replace_block_value(i, v.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            } else {
                continue;
            }
            self.head_rewritten = true;
        }
        Ok(())
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
        // The first CR or LF decides (T433: found with `memchr2`, not a byte at a time).
        if let Some(i) = memchr::memchr2(b'\r', b'\n', buf) {
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
        if !self.is_response {
            return self.parse_request_line(input, htx);
        }
        let Some((line_end, delim_len)) = self.find_line_end(input) else {
            return Ok(0);
        };
        let line_bytes = &input[..line_end];
        let line_str = std::str::from_utf8(line_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in start line")
        })?;

        let (version, status, reason) = parse_response_line_borrowed(line_str)?;
        htx.push_res_line(version, status, reason)
            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;

        self.prev_delim_len = delim_len;
        // A line ended by LF alone goes to the server ended by CRLF, as HAProxy writes the
        // head again from HTX: a hop that requires CRLF would otherwise see another message
        // (T285, V&V VV-8).
        self.head_rewritten |= delim_len == 1;
        self.phase = H1Phase::Headers;
        Ok(line_end + delim_len)
    }

    /// A request line, read byte by byte as `HAProxy` reads it ([`scan_request_line`]).
    /// The HTX keeps the parts as received, the version too; a line that is not written to
    /// the server as it came (blanks, a version from 1.1 up but `HTTP/1.1`, a bare LF) has
    /// the head forwarded from the HTX.
    fn parse_request_line(&mut self, input: &[u8], htx: &mut HtxSlice<'_>) -> io::Result<usize> {
        let span = match scan_request_line(input, self.accept_unsafe_request) {
            ReqLineScan::Incomplete => return Ok(0),
            ReqLineScan::Invalid => {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request line"));
            }
            ReqLineScan::Complete(span) => span,
        };
        let text = |r: std::ops::Range<usize>| {
            std::str::from_utf8(&input[r]).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in start line"))
        };
        let (method, uri, version) = (text(span.method)?, text(span.uri)?, text(span.version)?);
        check_request_target(method, uri)?;
        htx.push_req_line(method, uri, version)
            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
        self.prev_delim_len = span.eol_len;
        self.head_rewritten |= span.eol_len == 1 || !span.canonical;
        self.phase = H1Phase::Headers;
        Ok(span.eol + span.eol_len)
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
            self.head_rewritten |= delim_len == 1;
            Ok(delim_len)
        } else {
            let header_bytes = &input[..line_end];
            if header_bytes.starts_with(b" ") || header_bytes.starts_with(b"\t") {
                // Multiline header (obs-fold): append to previous header.
                // RFC 9112 §5.2 / HAProxy replaces preceding CRLF with 2 SP (or LF with 1 SP)
                // and preserves the continuation line's leading whitespace run.
                let prefix = if self.prev_delim_len == 2 { "  " } else { " " };
                let folded = header_bytes;
                if folded.iter().any(|&b| b == 0 || b == b'\r') {
                    self.phase = H1Phase::Error;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid character in header field value"));
                }
                if self.last_dropped {
                    // The continuation of a header that is not sent on.
                    self.head_rewritten = true;
                    self.prev_delim_len = delim_len;
                    return Ok(line_end + delim_len);
                }
                let appended = match std::str::from_utf8(folded) {
                    Ok(folded_val) if !htx.last_header_is_latin1() && !ibex_regex::bytetext::has_escapes(folded_val) => {
                        let mut combined = String::with_capacity(prefix.len() + folded_val.len());
                        combined.push_str(prefix);
                        combined.push_str(folded_val);
                        htx.append_to_last_header(&combined)
                    }
                    // obs-text that is not UTF-8, here or in the line it continues (T285).
                    _ => htx.append_latin1_to_last_header(prefix, folded),
                };
                appended.map_err(|_| {
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

            let (name, value) = parse_header_field(header_bytes)?;
            self.header_lines += u16::from(!uncounted(name.as_bytes(), value));
            if !self.is_response && self.header_lines > MAX_REQUEST_HEADERS {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "too many header lines"));
            }
            htx.finalize_last_header();
            // `TE` is hop-by-hop: `HAProxy` sends on `te: trailers` when a token of it is
            // exactly `trailers`, and nothing otherwise, so that a server that honours `TE`
            // does not compress or chunk for a client that never asked (T286).
            self.last_dropped = false;
            if !self.is_response && name.eq_ignore_ascii_case("te") {
                if value.split(|&b| b == b',').any(|t| t.trim_ascii() == b"trailers") {
                    htx.push_header("te", "trailers").map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
                } else {
                    self.last_dropped = true;
                }
                self.head_rewritten = true;
                self.prev_delim_len = delim_len;
                return Ok(line_end + delim_len);
            }
            match std::str::from_utf8(value) {
                Ok(value) => htx.push_header(name, value),
                // obs-text (RFC 9110 section 5.5) that is not UTF-8: Latin-1 from an old
                // client, which HAProxy forwards as received (T285, V&V VV-8).
                Err(_) => htx.push_header_latin1(name, value),
            }
            .map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
            // Anything but `name: value` and CRLF is written again from the HTX, as
            // HAProxy writes it: one space after the colon, the value's blanks trimmed.
            // (`finalize_last_header` trims the value's trailing blanks in the HTX.)
            self.head_rewritten |= delim_len == 1
                || header_bytes.len() != name.len() + 2 + value.len()
                || header_bytes[name.len() + 1] != b' '
                || value.last().is_some_and(|&b| b == b' ' || b == b'\t');
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
        // `0005`: forwarded as `5` (T285).
        let mut padded_cl = false;

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
            padded_cl |= first.len() > 1 && first.starts_with('0');
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
                return Err(Refusal::quiet(400, "conflicting Content-Length values"));
            }
            seen_cl = Some(len);
        }
        self.content_length = seen_cl;



        // Every flag is set along with a first header and a parsed value (a value that is not
        // UTF-8 is refused before the head gets here), so the pair is there whenever one is.
        let to_rewrite = if duplicate_cl || comma_cl || padded_cl { first_cl_idx.zip(seen_cl) } else { None };
        if let Some((first_idx, cl)) = to_rewrite {
            // Forwarded as the one value it stands for (tasks/T276), in canonical digits.
            self.head_rewritten = true;
            // Canonical decimal digits of `cl`, formatted by hand (usize is at most 20 digits).
            let mut val_buf = [0u8; 20];
            let mut start = val_buf.len();
            let mut n = cl;
            loop {
                start -= 1;
                val_buf[start] = b'0' + (n % 10) as u8;
                n /= 10;
                if n == 0 {
                    break;
                }
            }
            let val_bytes = &val_buf[start..];

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
        let te = TransferCodings::of(
            htx.as_ref().header_blocks_where(|n| n.eq_ignore_ascii_case(b"transfer-encoding")).map(|(_, n, v)| (n, v)),
            self.is_response,
        );
        if te.invalid {
            self.phase = H1Phase::Error;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid Transfer-Encoding"));
        }
        self.is_chunked = te.chunked_last;
        if !self.is_response && te.chunked_last {
            // A request's only coding is `chunked`, which goes to the server in lower case.
            let odd: Vec<usize> = htx
                .as_ref()
                .header_blocks_where(|n| n.eq_ignore_ascii_case(b"transfer-encoding"))
                .filter(|(_, _, v)| *v != "chunked" && v.eq_ignore_ascii_case("chunked"))
                .map(|(i, _, _)| i)
                .collect();
            for i in odd {
                htx.replace_block_value(i, b"chunked").map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e))?;
                self.head_rewritten = true;
            }
        }
        if te.present && self.content_length.is_some() {
            // T-E + C-L: the length goes and the connection closes (`h1_parse_msg_hdrs`).
            self.content_length = None;
            htx.remove_header("content-length");
            self.framing_conflict = true;
            self.connection_close = true;
        }
        // The start line, read once: what follows edits headers only.
        let req_line = htx.req_line().map(|r| (r.version, ["GET", "HEAD", "DELETE"].contains(&r.method), r.method.eq_ignore_ascii_case("CONNECT")));
        let res_version = htx.res_line().map(|r| r.version);
        let is_http11 = req_line.map_or(res_version == Some("HTTP/1.1"), |(v, ..)| version_is_11(v.as_bytes()));
        let is_http10 = req_line.is_some_and(|(v, ..)| v == "HTTP/1.0") || res_version == Some("HTTP/1.0");
        let (bodiless_method, is_connect) = req_line.map_or((false, false), |(_, b, c)| (b, c));
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
            let body = self.is_chunked || self.content_length.is_some_and(|n| n > 0);
            if !is_http11 && body && bodiless_method {
                self.phase = H1Phase::Error;
                return Err(Refusal::error(413, "HTTP/1.0 GET/HEAD/DELETE with a body"));
            }
            if te.other {
                // 422, `gzip`, `deflate` and `compress` too: a coding the proxy does not
                // decode is not forwarded (`H1_MF_TE_OTHER` in `h1_process_input`).
                self.phase = H1Phase::Error;
                return Err(Refusal::error(422, "transfer coding other than chunked"));
            }
        }

        if !self.is_response {
            self.check_upgrade(htx)?;
        }

        if let Some(conn) = htx.get_header("connection") {
            if conn.eq_ignore_ascii_case("close") {
                self.connection_close = true;
            } else if conn.eq_ignore_ascii_case("keep-alive") {
                self.connection_close = false;
            }
        } else if is_http10 {
            self.connection_close = true;
        }

        if is_connect {
            self.is_upgrade = true;
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

/// `HTTP/<digit>.<digit>`, the whole of a request line's version.
#[must_use]
pub fn is_http_version(v: &str) -> bool {
    matches!(v.as_bytes(), [b'H', b'T', b'T', b'P', b'/', a, b'.', b] if a.is_ascii_digit() && b.is_ascii_digit())
}

/// Whether a request's `HTTP/<digit>.<digit>` version is 1.1 or later, as `HAProxy` sets
/// `H1_MF_VER_11`: such a request is forwarded as `HTTP/1.1` and keeps its connection
/// without `Connection: keep-alive`.
#[must_use]
pub fn version_is_11(v: &[u8]) -> bool {
    v.len() == 8 && (v[5] > b'1' || (v[5] == b'1' && v[7] >= b'1'))
}

/// A request line read by [`scan_request_line`]: where its parts are in the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReqLineSpan {
    pub method: std::ops::Range<usize>,
    pub uri: std::ops::Range<usize>,
    pub version: std::ops::Range<usize>,
    /// Where the line's terminator (CRLF or LF) starts, and its length.
    pub eol: usize,
    pub eol_len: usize,
    /// The line is `method SP uri SP version` as `HAProxy` writes it to the server: one
    /// space between the parts and a version below 1.1 or exactly `HTTP/1.1`.
    pub canonical: bool,
}

/// The outcome of [`scan_request_line`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReqLineScan {
    /// No refused byte yet, and no end of line.
    Incomplete,
    /// A byte `HAProxy` refuses: the request is a 400.
    Invalid,
    Complete(ReqLineSpan),
}

/// Reads the request line at the start of `buf` as `HAProxy`'s parser does
/// (`h1_headers_to_hdr_list` from `H1_MSG_RQMETH`, then `h1_process_req_vsn`): a method of
/// token bytes, spaces or tabs, a target of the bytes 0x21 to 0x7e (`#` and bytes from 0x80
/// on only with `accept_unsafe`), spaces or tabs, and `HTTP/<digit>.<digit>` ended by CRLF
/// or LF. A refused byte is found before the line is whole, as `HAProxy` answers it at once.
/// No version (an HTTP/0.9 request) is refused as well. One pass, no allocation.
#[must_use]
pub fn scan_request_line(buf: &[u8], accept_unsafe: bool) -> ReqLineScan {
    use ReqLineScan::{Complete, Incomplete, Invalid};
    let len = buf.len();
    let spht = |b: u8| b == b' ' || b == b'\t';
    let mut i = buf.iter().position(|&b| !is_tchar(b)).unwrap_or(len);
    if i == len {
        return Incomplete;
    }
    let method = 0..i;
    if i == 0 || !spht(buf[i]) {
        return Invalid;
    }
    let mut canonical = buf[i] == b' ';
    i += 1;
    while i < len && spht(buf[i]) {
        canonical = false;
        i += 1;
    }
    let start = i;
    while i < len {
        match buf[i] {
            b'#' if !accept_unsafe => return Invalid,
            0x21..=0x7e => {}
            0x80.. if accept_unsafe => {}
            _ => break,
        }
        i += 1;
    }
    if i == len {
        return Incomplete;
    }
    // A target ended by anything but a blank (a control byte, or the line's end: no
    // version) is refused, and so is an empty one (the first byte was not 0x21..0x7e).
    if i == start || !spht(buf[i]) {
        return Invalid;
    }
    let uri = start..i;
    canonical &= buf[i] == b' ';
    i += 1;
    while i < len && spht(buf[i]) {
        canonical = false;
        i += 1;
    }
    let start = i;
    // `HTTP_IS_VER_TOKEN`: upper-case letters, digits, `.` and `/`.
    while i < len && matches!(buf[i], b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'/') {
        i += 1;
    }
    if i == len {
        return Incomplete;
    }
    let eol_len = match buf[i] {
        b'\n' => 1,
        b'\r' if i + 1 == len => return Incomplete,
        b'\r' if buf[i + 1] == b'\n' => 2,
        _ => return Invalid,
    };
    let v = &buf[start..i];
    if !matches!(v, [b'H', b'T', b'T', b'P', b'/', a, b'.', b] if a.is_ascii_digit() && b.is_ascii_digit()) {
        return Invalid;
    }
    canonical &= !version_is_11(v) || v == b"HTTP/1.1";
    Complete(ReqLineSpan { method, uri, version: start..i, eol: i, eol_len, canonical })
}

/// Whether the header lines of a request head not yet whole, from `at` in `buf`, already
/// hold a byte `HAProxy`'s parser refuses (`H1_MSG_HDR_FIRST` to `H1_MSG_HDR_L2_LWS`): a
/// first line that starts with a blank, a name byte that is not a token or an empty name, a
/// NUL in a value, a CR not followed by LF. It answers 400 at that byte; waiting for the
/// rest of the head would be a 408. Without `accept_unsafe` only, which lets the name and
/// NUL bytes through. One pass, no allocation.
#[must_use]
pub fn header_lines_invalid(buf: &[u8], mut at: usize, accept_unsafe: bool) -> bool {
    let len = buf.len();
    let mut first = true;
    // After a CR: the LF, or nothing yet.
    let cr_ok = |i: usize| i + 1 >= len || buf[i + 1] == b'\n';
    while at < len {
        match buf[at] {
            // The blank line: the end of the head.
            b'\r' => return !cr_ok(at),
            b'\n' => return false,
            b' ' | b'\t' if first => return !accept_unsafe,
            b' ' | b'\t' => {}
            _ => {
                let name = buf[at..].iter().position(|&b| !is_tchar(b)).map_or(len, |p| at + p);
                if name == len {
                    return false;
                }
                if (name == at || buf[name] != b':') && !accept_unsafe {
                    return true;
                }
                at = name;
            }
        }
        // The value (or what follows a name with unsafe bytes), to its line's end.
        let Some(p) = buf[at..].iter().position(|&b| b == b'\r' || b == b'\n' || (b == 0 && !accept_unsafe)) else {
            return false;
        };
        at += p;
        match buf[at] {
            0 => return true,
            b'\r' if !cr_ok(at) => return true,
            b'\r' => at += 2,
            _ => at += 1,
        }
        first = false;
    }
    false
}

/// What the `Content-Length` lines of a head not yet whole already settle
/// ([`content_length_early`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClEarly {
    /// Nothing wrong yet: wait for the rest of the head.
    Fine,
    /// A value that is not a number, or a list of different values in the first line: 400.
    Bad,
    /// A value that differs from an earlier line's: the connection closes, nothing written
    /// (`HAProxy` logs a 400; [`Refusal::quiet`]).
    Conflict,
}

/// The `Content-Length` lines of a request head not yet whole, from `at` in `buf`, read as
/// `HAProxy` reads them as each line completes (`h1_headers_to_hdr_list`,
/// `h1_parse_cont_len_header`, T315). A line counts once it ends with LF and a byte of the
/// next is in. A value is a list of decimal numbers that fit 64 bits; the list of the first
/// line holds one number; a number that differs from an earlier line's is a [`ClEarly::Conflict`].
/// It stops at the end of the head, which the full parse judges. One pass, no allocation.
#[must_use]
pub fn content_length_early(buf: &[u8], mut at: usize) -> ClEarly {
    let mut seen: Option<u64> = None;
    while at < buf.len() {
        let Some(nl) = buf[at..].iter().position(|&b| b == b'\n') else { break };
        let end = at + nl;
        // The next line's first byte decides nothing but whether this one is folded; a line
        // is judged once it is there.
        if end + 1 >= buf.len() {
            break;
        }
        let line = &buf[at..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        at = end + 1;
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else { continue };
        if !line[..colon].eq_ignore_ascii_case(b"content-length") {
            continue;
        }
        let value = line[colon + 1..].trim_ascii();
        let first_line = seen.is_none();
        for (i, item) in value.split(|&b| b == b',').enumerate() {
            let item = item.trim_ascii();
            if item.is_empty() || !item.iter().all(u8::is_ascii_digit) {
                return ClEarly::Bad;
            }
            let Some(n) = std::str::from_utf8(item).ok().and_then(|s| s.parse::<u64>().ok()) else { return ClEarly::Bad };
            match seen {
                Some(prev) if prev != n => return if first_line && i > 0 { ClEarly::Bad } else { ClEarly::Conflict },
                _ => seen = Some(n),
            }
        }
    }
    ClEarly::Fine
}

#[cfg(test)]
fn parse_request_line_borrowed(line: &str) -> io::Result<(&str, &str, &str)> {
    let mut parts = line.split_whitespace();
    let method_str = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP method"))?;
    let uri = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP URI"))?;
    // `method target HTTP/<digit>.<digit>`, and no blank after the version: anything else
    // is a 400 (measured on 3.5-dev8-885761-29, T286).
    let version_str = parts.next().filter(|v| is_http_version(v) && line.ends_with(v)).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP version"))?;
    // (A fourth token is refused above: the version is the last token of the line.)
    check_request_target(method_str, uri)?;
    Ok((method_str, uri, version_str))
}

fn check_request_target(method_str: &str, uri: &str) -> io::Result<()> {

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
    Ok(())
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

/// [`parse_header_field`] of a line that is text.
fn parse_header_field_borrowed(line: &str) -> io::Result<(&str, &str)> {
    let (name, value) = parse_header_field(line.as_bytes())?;
    // The value starts after an ASCII byte of `line`, so on a character boundary.
    Ok((name, &line[line.len() - value.len()..]))
}

/// The name and the value of a header line, the value without its leading blanks. The name
/// is a token, so text; the value is bytes, any but NUL, CR and LF.
fn parse_header_field(line: &[u8]) -> io::Result<(&str, &[u8])> {
    let colon = memchr::memchr(b':', line)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Header missing colon"))?;
    let (name, val) = (&line[..colon], &line[colon + 1..]);

    // RFC 9112 5.1 is unusually blunt here: a server MUST reject, with 400, any
    // request containing whitespace between the field name and the colon.
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty header field name",
        ));
    }
    if !name.iter().copied().all(is_tchar) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid character in header field name",
        ));
    }
    // Tokens are ASCII.
    let name = std::str::from_utf8(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid header field name"))?;

    // Field values may not carry NUL, CR or LF.
    if memchr::memchr3(0, b'\r', b'\n', val).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid character in header field value",
        ));
    }

    let start = val.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(val.len());
    Ok((name, &val[start..]))
}

#[cfg(test)]
mod tests {
    /// T433: `find_line_end` with `memchr2` ends a line where the byte-at-a-time loop did,
    /// with the same bare-CR state, on short strings of `a`, CR and LF and on long lines.
    #[test]
    fn find_line_end_ends_where_the_bytewise_loop_did() {
        fn bytewise(saw_bare_cr: &mut bool, buf: &[u8]) -> Option<(usize, usize)> {
            for i in 0..buf.len() {
                if buf[i] == b'\r' {
                    if i + 1 < buf.len() {
                        if buf[i + 1] == b'\n' {
                            return Some((i, 2));
                        }
                        *saw_bare_cr = true;
                        return Some((i, 1));
                    }
                    if *saw_bare_cr {
                        return Some((i, 1));
                    }
                    return None;
                }
                if buf[i] == b'\n' {
                    return Some((i, 1));
                }
            }
            None
        }
        let mut bufs: Vec<Vec<u8>> = Vec::new();
        for len in 0..=6u32 {
            for mut code in 0..3usize.pow(len) {
                let mut b = Vec::new();
                for _ in 0..len {
                    b.push(b"a\r\n"[code % 3]);
                    code /= 3;
                }
                bufs.push(b);
            }
        }
        for n in [15, 16, 17, 31, 32, 33, 64, 100] {
            for tail in [&b""[..], b"\r", b"\n", b"\r\n", b"\ra", b"\na"] {
                let mut b = vec![b'x'; n];
                b.extend_from_slice(tail);
                bufs.push(b);
            }
        }
        for b in &bufs {
            for bare in [false, true] {
                let mut p = H1Parser::new(false);
                p.saw_bare_cr = bare;
                let mut want_bare = bare;
                assert_eq!(p.find_line_end(b), bytewise(&mut want_bare, b), "{b:?} {bare}");
                assert_eq!(p.saw_bare_cr, want_bare, "{b:?} {bare}");
            }
        }
    }

    /// A continuation line of a `TE` that is not sent on goes with it, not to the header
    /// before (T286).
    #[test]
    fn a_fold_after_a_dropped_te_is_dropped() {
        let mut buf = [0u8; 4096];
        let mut htx = HtxSlice::new(&mut buf);
        let mut p = H1Parser::new(false);
        p.parse(b"GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nTE: gzip\r\n , deflate\r\nX-B: 2\r\n\r\n", &mut htx).unwrap();
        let hs: Vec<(String, String)> = htx.as_ref().headers().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        assert_eq!(hs, [("Host".into(), "x".into()), ("X-A".into(), "1".into()), ("X-B".into(), "2".into())]);
    }

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

    /// A header value that is not UTF-8 -- Latin-1 -- is taken as `HAProxy` takes it (T285):
    /// a 400 in `Host`, `Content-Length` and `Transfer-Encoding`, whose values it parses, and
    /// passed in any other header, held as text so that rules and ACLs read it (T158), and
    /// written back to the server as the bytes received.
    #[test]
    fn a_latin1_header_value_is_refused_only_where_it_frames_or_routes() {
        let parse = |name: &str| {
            let mut raw = b"POST / HTTP/1.1\r\n".to_vec();
            if name != "Host" {
                raw.extend_from_slice(b"Host: h\r\n");
            }
            raw.extend_from_slice(name.as_bytes());
            raw.extend_from_slice(b": 5\xff\r\nContent-Length: 0\r\n\r\n");
            let mut buf = [0u8; 4096];
            let mut htx = HtxSlice::new(&mut buf);
            let mut p = H1Parser::new(false);
            p.parse(&raw, &mut htx).map(|_| (htx.as_ref().headers().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.to_string()), htx.as_ref().to_h1_wire()))
        };
        for name in ["Content-Length", "transfer-encoding", "Host"] {
            assert!(parse(name).is_err(), "{name}");
        }
        for name in ["x-admin", "Connection", "PROXY-CONNECTION", "keep-alive", "Expect", "User-Agent", "Trailer", "Cookie", "Forwarded"] {
            let (text, wire) = parse(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(text.as_deref(), Some("5\u{f7ff}"), "{name}");
            let line = format!("{name}: 5").into_bytes().into_iter().chain([0xff, b'\r', b'\n']).collect::<Vec<u8>>();
            assert!(wire.windows(line.len()).any(|w| w == line), "{name}: {}", wire.escape_ascii());
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

    /// A valid head arriving a byte at a time is never refused early (T291): every prefix
    /// of it is incomplete or, once the line is in, complete.
    #[test]
    fn no_prefix_of_a_valid_head_is_refused() {
        use super::{header_lines_invalid, scan_request_line, ReqLineScan};
        let heads: [&[u8]; 4] = [
            b"GET /a?b=c HTTP/1.1\r\nHost: a\r\nX-Y: v:w\r\n folded\r\n\r\n",
            b"POST\t/x  HTTP/1.0\nHost: a\nContent-Length: 0\n\n",
            b"OPTIONS * HTTP/1.1\r\nHost: a\n\r\n",
            b"GET http://h/p HTTP/9.9\r\nA:\r\nB: \t\x80\xff\r\n\r\n",
        ];
        for head in heads {
            for n in 1..=head.len() {
                let p = &head[..n];
                let scan = scan_request_line(p, false);
                assert_ne!(scan, ReqLineScan::Invalid, "{p:?} refused");
                if let ReqLineScan::Complete(l) = scan {
                    assert!(!header_lines_invalid(p, l.eol + l.eol_len, false), "{p:?} refused");
                }
            }
        }
        let refused: [&[u8]; 5] = [b"GET /\0", b"GE(", b"GET / HTTP/1.1 ", b"GET / HTTP/1.1\r\r", b"GET  \x80"];
        for p in refused {
            assert_eq!(scan_request_line(p, false), ReqLineScan::Invalid, "{p:?}");
        }
        assert!(matches!(scan_request_line(b"GET /\x80# HTTP/1.1\r\n", true), ReqLineScan::Complete(_)));
        assert!(header_lines_invalid(b"GET / HTTP/1.1\r\n\tX: y\r\n", 16, false));
        assert!(!header_lines_invalid(b"GET / HTTP/1.1\r\nX\0: y\0\r\n", 16, true));
    }

    /// No prefix of a valid head, repeated equal `Content-Length` lines included, is settled
    /// early; a bad value or a list of different values is a 400, a later different value a
    /// quiet close (T315).
    #[test]
    fn content_length_early_settles_only_bad_lines() {
        use super::{content_length_early, ClEarly};
        let heads: [&[u8]; 3] = [
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5, 5\r\nX: y\r\n\r\nhello",
            b"POST / HTTP/1.1\nContent-Length: 0\nnocolon\n\n",
            b"GET / HTTP/1.1\r\n\r\nContent-Length: x\r\n\r\n",
        ];
        for head in heads {
            for n in 1..=head.len() {
                assert_eq!(content_length_early(&head[..n], 0), ClEarly::Fine, "{:?}", &head[..n]);
            }
        }
        let cases: [(&[u8], ClEarly); 6] = [
            (b"P / HTTP/1.1\r\nContent-Length: +5\r\nX", ClEarly::Bad),
            (b"P / HTTP/1.1\r\nContent-Length: 5,\r\nX", ClEarly::Bad),
            (b"P / HTTP/1.1\r\nContent-Length: 5, 6\r\nX", ClEarly::Bad),
            (b"P / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\nX", ClEarly::Bad),
            (b"P / HTTP/1.1\r\nContent-Length: 5\r\ncontent-length: 10\r\nX", ClEarly::Conflict),
            (b"P / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5, 6\r\nX", ClEarly::Conflict),
        ];
        for (buf, want) in cases {
            assert_eq!(content_length_early(buf, 0), want, "{buf:?}");
            assert_eq!(content_length_early(&buf[..buf.len() - 1], 0), ClEarly::Fine, "{buf:?} without the next line's byte");
        }
    }

    /// A request line not yet whole is waited on: nothing is consumed, nothing refused (T291).
    #[test]
    fn a_partial_request_line_is_waited_on() {
        use super::{H1Parser, H1Phase, HtxSlice};
        let mut buf = vec![0u8; 4096];
        let mut htx = HtxSlice::new(&mut buf);
        let mut p = H1Parser::new(false);
        assert_eq!(p.parse(b"GET /a HTTP/1.", &mut htx).expect("not refused"), 0);
        assert_eq!(p.phase, H1Phase::StartLine);
        assert_eq!(p.parse(b"GET /a HTTP/1.1\r\nHost: a\r\n\r\n", &mut htx).expect("parsed"), 28);
        assert_eq!(p.phase, H1Phase::Done);
    }
}
