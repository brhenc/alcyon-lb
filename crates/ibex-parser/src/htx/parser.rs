//! Pure Rust HAProxy HTX Stream Parser.

use super::{HtxBlockType, HtxBuffer};
use crate::simd::SimdScanner;
use ibex_core::error::{IbexError, IbexResult};
use ibex_core::ibex_assert;

/// Pure Rust HTX Parser
#[derive(Debug, Default)]
pub struct HtxParser {
    pub htx: HtxBuffer,
}

impl HtxParser {
    /// Creates a new HTX parser with pre-allocated storage.
    pub fn new() -> Self {
        Self {
            htx: HtxBuffer::with_capacity(16384, 64),
        }
    }

    /// Parses an incoming HTTP/1.1 request buffer into HTX blocks.
    /// Returns the number of bytes consumed if a complete header section was parsed.
    pub fn parse_request_headers(&mut self, src: &[u8]) -> IbexResult<Option<usize>> {
        ibex_assert!(!src.is_empty(), "Source buffer non-empty");
        self.htx.reset();

        let mut offset = 0;

        // 1. Parse Request Start Line
        let start_line_crlf = match SimdScanner::find_crlf(&src[offset..]) {
            Some(pos) => offset + pos,
            None => return Ok(None), // Need more data
        };

        let start_line = &src[offset..start_line_crlf];
        let data_off = self.htx.push_data(start_line);
        self.htx
            .push_block(HtxBlockType::ReqStartLine, data_off, start_line.len(), 0);
        offset = start_line_crlf + 2;

        // 2. Parse Headers
        for _ in 0..128 {
            if offset >= src.len() {
                return Ok(None);
            }

            // Check for empty line (end of headers)
            if src[offset..].starts_with(b"\r\n") {
                offset += 2;
                return Ok(Some(offset));
            }

            let header_crlf = match SimdScanner::find_crlf(&src[offset..]) {
                Some(pos) => offset + pos,
                None => return Ok(None),
            };

            let header_line = &src[offset..header_crlf];
            if let Some(colon_pos) = SimdScanner::find_colon(header_line) {
                let name = header_line[..colon_pos].trim_ascii();
                let value = header_line[colon_pos + 1..].trim_ascii();

                let mut combined = Vec::with_capacity(name.len() + value.len() + 2);
                combined.extend_from_slice(name);
                combined.push(b':');
                combined.push(b' ');
                combined.extend_from_slice(value);

                let h_off = self.htx.push_data(&combined);
                self.htx.push_block(
                    HtxBlockType::Header,
                    h_off,
                    combined.len(),
                    name.len() as u32,
                );
            }

            offset = header_crlf + 2;
        }

        Err(IbexError::Parser("Header count limit exceeded".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_htx_request_parsing() {
        let mut parser = HtxParser::new();
        let raw = b"GET /v1/status HTTP/1.1\r\nHost: api.internal\r\nUser-Agent: ibex-test\r\n\r\n";
        let consumed = parser
            .parse_request_headers(raw)
            .expect("parse succeeds")
            .expect("header complete");

        assert_eq!(consumed, raw.len());
        assert_eq!(parser.htx.blocks.len(), 3); // Start line + 2 headers
        assert_eq!(parser.htx.blocks[0].blk_type, HtxBlockType::ReqStartLine);
        assert_eq!(parser.htx.blocks[1].blk_type, HtxBlockType::Header);
        assert_eq!(parser.htx.blocks[2].blk_type, HtxBlockType::Header);
    }
}
