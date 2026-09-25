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

        if let Some(te) = htx.get_header("transfer-encoding") {
            let mut unknown = false;
            let mut chunked_count = 0;
            let mut last_coding: Option<&str> = None;

            for coding in te.split(',').map(str::trim) {
                if coding.is_empty() {
                    continue;
                }
                last_coding = Some(coding);
                if coding.eq_ignore_ascii_case("chunked") {
                    chunked_count += 1;
                } else if !coding.eq_ignore_ascii_case("gzip")
                    && !coding.eq_ignore_ascii_case("deflate")
                    && !coding.eq_ignore_ascii_case("compress")
                {
                    unknown = true;
                }
            }

            let chunked_last = last_coding.is_some_and(|c| c.eq_ignore_ascii_case("chunked"));

            if unknown || chunked_count > 1 || (chunked_count == 1 && !chunked_last) {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Transfer-Encoding",
                ));
            }
            if chunked_last {
                self.is_chunked = true;
            }
        }

        if self.is_chunked && self.content_length.is_some() {
            self.content_length = None;
            htx.remove_header("content-length");
            self.framing_conflict = true;
            self.connection_close = true;
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
