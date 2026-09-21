//! Pingora-style zero-copy HTTP/1.x stream parser adapter.

use crate::simd::SimdScanner;
use ibex_core::error::{IbexError, IbexResult};

/// Represents a parsed HTTP Request Header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

/// Pingora HTTP Parser Adapter
#[derive(Debug, Default)]
pub struct PingoraHttpParser;

impl PingoraHttpParser {
    pub fn new() -> Self {
        Self
    }

    /// Parses an HTTP request from raw bytes into `ParsedHttpRequest`.
    pub fn parse_request(&self, src: &[u8]) -> IbexResult<Option<(ParsedHttpRequest, usize)>> {
        let first_crlf = match SimdScanner::find_crlf(src) {
            Some(pos) => pos,
            None => return Ok(None),
        };

        let start_line = std::str::from_utf8(&src[..first_crlf])
            .map_err(|e| IbexError::Parser(e.to_string()))?;
        let mut parts = start_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| IbexError::Parser("Missing method".into()))?
            .to_string();
        let uri = parts
            .next()
            .ok_or_else(|| IbexError::Parser("Missing URI".into()))?
            .to_string();
        let version = parts
            .next()
            .ok_or_else(|| IbexError::Parser("Missing HTTP version".into()))?
            .to_string();

        let mut headers = Vec::with_capacity(16);
        let mut offset = first_crlf + 2;

        for _ in 0..128 {
            if offset >= src.len() {
                return Ok(None);
            }
            if src[offset..].starts_with(b"\r\n") {
                offset += 2;
                return Ok(Some((
                    ParsedHttpRequest {
                        method,
                        uri,
                        version,
                        headers,
                    },
                    offset,
                )));
            }

            let crlf = match SimdScanner::find_crlf(&src[offset..]) {
                Some(p) => offset + p,
                None => return Ok(None),
            };

            let header_line = std::str::from_utf8(&src[offset..crlf])
                .map_err(|e| IbexError::Parser(e.to_string()))?;
            if let Some(colon) = header_line.find(':') {
                let name = header_line[..colon].trim().to_string();
                let val = header_line[colon + 1..].trim().to_string();
                headers.push((name, val));
            }

            offset = crlf + 2;
        }

        Err(IbexError::Parser("Header limit exceeded".into()))
    }
}
