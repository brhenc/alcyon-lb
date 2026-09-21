//! Runtime Parser Switcher allowing dynamic switching between HTX and Pingora parsers.

use crate::htx::parser::HtxParser;
use crate::pingora_adapter::PingoraHttpParser;
use ibex_core::error::{IbexError, IbexResult};

/// Active parser engine variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserEngineKind {
    Htx,
    Pingora,
}

/// Unified Parsed Request Representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedHttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub parser_used: ParserEngineKind,
}

/// Dynamic Runtime Parser Switcher
pub struct DynamicParserSwitcher {
    active_engine: ParserEngineKind,
    htx_parser: HtxParser,
    pingora_parser: PingoraHttpParser,
}

impl DynamicParserSwitcher {
    /// Creates a new switcher with default engine.
    pub fn new(initial_engine: ParserEngineKind) -> Self {
        Self {
            active_engine: initial_engine,
            htx_parser: HtxParser::new(),
            pingora_parser: PingoraHttpParser::new(),
        }
    }

    /// Dynamically switches the active parser engine at runtime.
    pub fn switch_engine(&mut self, new_engine: ParserEngineKind) {
        self.active_engine = new_engine;
    }

    /// Currently active engine.
    pub fn active_engine(&self) -> ParserEngineKind {
        self.active_engine
    }

    /// Parses incoming request bytes using the currently active engine.
    pub fn parse_request(&mut self, src: &[u8]) -> IbexResult<Option<(UnifiedHttpRequest, usize)>> {
        match self.active_engine {
            ParserEngineKind::Htx => {
                if let Some(consumed) = self.htx_parser.parse_request_headers(src)? {
                    // Convert HTX representation to UnifiedHttpRequest
                    let mut method = String::new();
                    let mut uri = String::new();
                    let mut version = String::new();
                    let mut headers = Vec::new();

                    for blk in &self.htx_parser.htx.blocks {
                        match blk.blk_type {
                            crate::htx::HtxBlockType::ReqStartLine => {
                                let data = self.htx_parser.htx.get_block_data(blk)?;
                                let line = std::str::from_utf8(data)
                                    .map_err(|e| IbexError::Parser(e.to_string()))?;
                                let mut parts = line.split_whitespace();
                                method = parts.next().unwrap_or("GET").to_string();
                                uri = parts.next().unwrap_or("/").to_string();
                                version = parts.next().unwrap_or("HTTP/1.1").to_string();
                            }
                            crate::htx::HtxBlockType::Header => {
                                let data = self.htx_parser.htx.get_block_data(blk)?;
                                let line = std::str::from_utf8(data)
                                    .map_err(|e| IbexError::Parser(e.to_string()))?;
                                if let Some(colon) = line.find(':') {
                                    headers.push((
                                        line[..colon].trim().to_string(),
                                        line[colon + 1..].trim().to_string(),
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }

                    Ok(Some((
                        UnifiedHttpRequest {
                            method,
                            uri,
                            version,
                            headers,
                            parser_used: ParserEngineKind::Htx,
                        },
                        consumed,
                    )))
                } else {
                    Ok(None)
                }
            }
            ParserEngineKind::Pingora => {
                if let Some((parsed, consumed)) = self.pingora_parser.parse_request(src)? {
                    Ok(Some((
                        UnifiedHttpRequest {
                            method: parsed.method,
                            uri: parsed.uri,
                            version: parsed.version,
                            headers: parsed.headers,
                            parser_used: ParserEngineKind::Pingora,
                        },
                        consumed,
                    )))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_parser_switching() {
        let mut switcher = DynamicParserSwitcher::new(ParserEngineKind::Htx);
        let raw = b"GET /switch-test HTTP/1.1\r\nHost: example.org\r\n\r\n";

        // 1. Parse with HTX
        let (req1, _) = switcher
            .parse_request(raw)
            .expect("parse HTX")
            .expect("complete");
        assert_eq!(req1.parser_used, ParserEngineKind::Htx);
        assert_eq!(req1.uri, "/switch-test");

        // 2. Switch at runtime to Pingora
        switcher.switch_engine(ParserEngineKind::Pingora);
        let (req2, _) = switcher
            .parse_request(raw)
            .expect("parse Pingora")
            .expect("complete");
        assert_eq!(req2.parser_used, ParserEngineKind::Pingora);
        assert_eq!(req2.uri, "/switch-test");
    }
}
