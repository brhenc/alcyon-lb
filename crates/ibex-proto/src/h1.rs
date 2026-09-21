// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/h1.c, src/mux_h1.c and include/haproxy/h1.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/1.1 Wire Parser and Framing.
//!
//! Converts raw HTTP/1.1 and HTTP/1.0 wire streams into [`Htx`] blocks.

use crate::htx::{HeaderField, HttpMethod, HttpVersion, Htx, HtxBlock, RequestLine, ResponseLine};
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
    }

    /// Finalizes parsing on connection close / EOF (for HTTP/1.0 close delimiter fallback).
    pub fn finish(&mut self, htx: &mut Htx) {
        if matches!(
            self.phase,
            H1Phase::BodyFixed {
                remaining: usize::MAX
            }
        ) {
            htx.push(HtxBlock::Eom);
            self.phase = H1Phase::Done;
        }
    }

    /// Parses wire bytes into an [`Htx`] transaction.
    /// Returns the number of consumed bytes.
    ///
    /// # Errors
    /// Returns an error if the HTTP stream contains framing syntax violations.
    pub fn parse(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize> {
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
                    let consumed = Self::parse_body_fixed(&input[cursor..], htx, remaining);
                    if consumed == 0 {
                        break;
                    }
                    cursor += consumed;
                    if *remaining == 0 {
                        htx.push(HtxBlock::Eom);
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
                        htx.push(HtxBlock::Eom);
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

    fn parse_start_line(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize> {
        let Some((line_end, delim_len)) = self.find_line_end(input) else {
            return Ok(0);
        };
        let line_bytes = &input[..line_end];
        let line_str = std::str::from_utf8(line_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in start line")
        })?;

        if self.is_response {
            let res = parse_response_line(line_str)?;
            htx.push(HtxBlock::ResLine(res));
        } else {
            let req = parse_request_line(line_str)?;
            htx.push(HtxBlock::ReqLine(req));
        }

        self.phase = H1Phase::Headers;
        Ok(line_end + delim_len)
    }

    fn parse_headers(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<usize> {
        let Some((line_end, delim_len)) = self.find_line_end(input) else {
            return Ok(0);
        };

        if line_end == 0 {
            // Empty line -> End of headers
            htx.push(HtxBlock::Eoh);
            self.on_headers_finished(htx)?;
            Ok(delim_len)
        } else {
            let header_bytes = &input[..line_end];
            if header_bytes.starts_with(b" ") || header_bytes.starts_with(b"\t") {
                // Multiline header (obs-fold): append to previous header
                let folded_val = std::str::from_utf8(header_bytes)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid folded header")
                    })?
                    .trim();
                if let Some(HtxBlock::Header(prev)) = htx
                    .blocks_mut()
                    .iter_mut()
                    .rev()
                    .find(|b| matches!(b, HtxBlock::Header(_)))
                {
                    prev.value.push(' ');
                    prev.value.push_str(folded_val);
                }
                return Ok(line_end + delim_len);
            }

            let header_str = std::str::from_utf8(header_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid header string"))?;

            let header = parse_header_field(header_str)?;
            htx.push(HtxBlock::Header(header));
            Ok(line_end + delim_len)
        }
    }

    fn parse_trailers(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<(usize, bool)> {
        let mut cursor = 0;
        while cursor < input.len() {
            let Some((line_end, delim_len)) = self.find_line_end(&input[cursor..]) else {
                return Ok((cursor, false));
            };

            if line_end == 0 {
                // Empty line -> End of trailers
                return Ok((cursor + delim_len, true));
            }

            let trailer_bytes = &input[cursor..cursor + line_end];
            if trailer_bytes.starts_with(b" ") || trailer_bytes.starts_with(b"\t") {
                // Multiline trailer (obs-fold)
                let folded_val = std::str::from_utf8(trailer_bytes)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid folded trailer")
                    })?
                    .trim();
                if let Some(HtxBlock::Trailer(prev)) = htx
                    .blocks_mut()
                    .iter_mut()
                    .rev()
                    .find(|b| matches!(b, HtxBlock::Trailer(_)))
                {
                    prev.value.push(' ');
                    prev.value.push_str(folded_val);
                }
            } else {
                let trailer_str = std::str::from_utf8(trailer_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid trailer string")
                })?;
                let trailer = parse_header_field(trailer_str)?;
                htx.push(HtxBlock::Trailer(trailer));
            }

            cursor += line_end + delim_len;
        }
        Ok((cursor, false))
    }

    fn on_headers_finished(&mut self, htx: &mut Htx) -> io::Result<()> {
        // A Content-Length we cannot parse is a protocol error, not something to
        // shrug off. RFC 9112 6.3: a value that is not a valid decimal makes the
        // message unframeable, and silently ignoring it is a smuggling primitive --
        // we would treat the body as the start of the *next* request while the
        // backend treats it as a body.
        //
        // Verified against HAProxy 3.5: `Content-Length: -5` gets 400 Bad Request,
        // where Ibex previously answered 200 and left "hello" unconsumed on the
        // connection to become the next request.
        //
        // Strict by construction: ASCII digits only. `parse::<usize>()` alone is not
        // enough because it accepts a leading `+`, and it silently tolerates values
        // that HAProxy rejects.
        // Scan only the headers of the *current* message. An `Htx` is reused across
        // keep-alive requests, so iterating every header would compare request N's
        // Content-Length against request N-1's and report a bogus conflict.
        let start = htx
            .blocks()
            .iter()
            .rposition(|b| matches!(b, HtxBlock::ReqLine(_) | HtxBlock::ResLine(_)))
            .map_or(0, |i| i + 1);

        let mut seen_cl: Option<usize> = None;
        for block in &htx.blocks()[start..] {
            let HtxBlock::Header(h) = block else { continue };
            if !h.name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            let raw = h.value.trim();
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Content-Length value",
                ));
            }
            let Ok(len) = raw.parse::<usize>() else {
                self.phase = H1Phase::Error;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Content-Length out of range",
                ));
            };
            // Duplicate Content-Length headers must agree; conflicting values are the
            // other classic desync, since each hop may pick a different one.
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

        if let Some(te) = htx.get_header("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                self.is_chunked = true;
            }
        }

        // RFC 7230 §3.3.3 rule 3: when a message carries both Transfer-Encoding and
        // Content-Length, the Transfer-Encoding wins and the Content-Length **must be
        // removed before forwarding**. Leaving both in place is the canonical CL.TE
        // request-smuggling desync: we frame the message by chunked encoding while a
        // backend honouring Content-Length frames it differently, so bytes we treat as
        // the start of the *next* request are read by the backend as body -- or worse,
        // bytes we forward as body are read by the backend as a new request.
        //
        // Verified against HAProxy 3.5 on
        //   POST /smuggle ... Content-Length: 6, Transfer-Encoding: chunked, "0\r\n\r\nX"
        // HAProxy strips Content-Length, forwards only chunked framing, drops the
        // trailing X, and marks the connection non-reusable. We now do the same.
        if self.is_chunked && self.content_length.is_some() {
            self.content_length = None;
            htx.remove_header("content-length");
            self.framing_conflict = true;
            // The connection cannot be safely reused: any trailing bytes are of
            // ambiguous ownership, so a later request on this connection could be
            // prefixed by them.
            self.connection_close = true;
        }

        let is_http10 = htx
            .req_line()
            .map_or(false, |r| r.version == HttpVersion::Http10)
            || htx
                .res_line()
                .map_or(false, |r| r.version == HttpVersion::Http10);

        if let Some(conn) = htx.get_header("connection") {
            if conn.eq_ignore_ascii_case("close") {
                self.connection_close = true;
            } else if conn.eq_ignore_ascii_case("keep-alive") {
                self.connection_close = false;
            }
        } else if is_http10 {
            self.connection_close = true;
        }

        if let Some(meth) = htx.req_line().map(|r| &r.method) {
            if matches!(meth, HttpMethod::Connect) {
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
                htx.push(HtxBlock::Eom);
                self.phase = H1Phase::Done;
            } else {
                self.phase = H1Phase::BodyFixed { remaining: len };
            }
        } else if self.is_response && !self.is_upgrade {
            self.phase = H1Phase::BodyFixed {
                remaining: usize::MAX,
            };
        } else {
            htx.push(HtxBlock::Eom);
            self.phase = H1Phase::Done;
        }
    
        Ok(())
    }

    fn parse_body_fixed(input: &[u8], htx: &mut Htx, remaining: &mut usize) -> usize {
        let available = input.len();
        if available == 0 {
            return 0;
        }

        let take = if *remaining == usize::MAX {
            available
        } else {
            available.min(*remaining)
        };

        htx.push(HtxBlock::Data(input[..take].to_vec()));
        if *remaining != usize::MAX {
            *remaining -= take;
        }
        take
    }

    fn parse_body_chunked(&mut self, input: &[u8], htx: &mut Htx) -> io::Result<(usize, bool)> {
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
            let len_part = len_str.split(';').next().unwrap_or("").trim();
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
                htx.push(HtxBlock::Data(input[cursor..cursor + take].to_vec()));
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

fn parse_request_line(line: &str) -> io::Result<RequestLine> {
    let mut parts = line.split_whitespace();
    let method_str = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP method"))?;
    let uri = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP URI"))?
        .to_string();
    let version_str = parts.next().unwrap_or("HTTP/1.1");

    Ok(RequestLine {
        method: HttpMethod::from_bytes(method_str.as_bytes()),
        uri,
        version: HttpVersion::from_bytes(version_str.as_bytes()),
    })
}

fn parse_response_line(line: &str) -> io::Result<ResponseLine> {
    let mut parts = line.splitn(3, ' ');
    let version_str = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP version"))?;
    let status_str = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing HTTP status"))?;
    let reason = parts.next().unwrap_or("").trim().to_string();

    let status = status_str
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP status code"))?;

    Ok(ResponseLine {
        version: HttpVersion::from_bytes(version_str.as_bytes()),
        status,
        reason,
    })
}

fn parse_header_field(line: &str) -> io::Result<HeaderField> {
    let (name, val) = line
        .split_once(':')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Header missing colon"))?;
    Ok(HeaderField {
        name: name.trim().to_string(),
        value: val.trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_get_request() {
        let req =
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        let mut parser = H1Parser::new(false);
        let mut htx = Htx::new();

        let consumed = parser.parse(req, &mut htx).expect("parse");
        assert_eq!(consumed, req.len());
        assert_eq!(parser.phase, H1Phase::Done);

        assert_eq!(htx.req_line().unwrap().method, HttpMethod::Get);
        assert_eq!(htx.req_line().unwrap().uri, "/index.html");
        assert_eq!(htx.get_header("host"), Some("example.com"));
        assert!(htx.is_eom());
    }

    #[test]
    fn parse_http_post_with_content_length() {
        let req =
            b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world";
        let mut parser = H1Parser::new(false);
        let mut htx = Htx::new();

        let consumed = parser.parse(req, &mut htx).expect("parse");
        assert_eq!(consumed, req.len());
        assert_eq!(parser.phase, H1Phase::Done);
        assert_eq!(htx.body_bytes(), b"hello world");
        assert!(htx.is_eom());
    }

    #[test]
    fn parse_http_chunked_response() {
        let res = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut parser = H1Parser::new(true);
        let mut htx = Htx::new();

        let consumed = parser.parse(res, &mut htx).expect("parse");
        assert_eq!(consumed, res.len());
        assert_eq!(parser.phase, H1Phase::Done);
        assert_eq!(htx.res_line().unwrap().status, 200);
        assert_eq!(htx.body_bytes(), b"hello world");
        assert!(htx.is_eom());
    }
}
