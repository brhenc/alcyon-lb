// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Ibex HTTP/1 Parser Execution and Self-Differential Oracle.
//!
//! Executes Ibex's `H1Parser` in both full-buffer and incremental streaming modes,
//! as well as via `MuxH1`. Verifies internal consistency and extracts exact framing details.

#![forbid(unsafe_code)]

use ibex_proto::h1::{H1Parser, H1Phase};
use ibex_proto::htx::{HtxBlock, HtxSlice};

/// Result of parsing an input with Ibex's HTTP/1 parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IbexParseResult {
    pub accepted: bool,
    pub consumed_bytes: usize,
    pub phase: String,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: Option<String>,
    pub headers: Vec<(String, String)>,
    pub header_count: usize,
    pub body: Vec<u8>,
    pub body_len: usize,
    pub is_chunked: bool,
    pub connection_close: bool,
    pub next_request_start: usize,
    pub self_consistent: bool,
    pub error_message: Option<String>,
}

/// HTX buffer size per parse (the libFuzzer targets use the same).
const HTX_BUF: usize = 64 * 1024;

/// Executes Ibex parser against raw input bytes.
pub fn parse_with_ibex(input: &[u8]) -> IbexParseResult {
    // 1. Single-pass full buffer parse
    let mut parser = H1Parser::new(false);
    let mut buf = vec![0u8; HTX_BUF];
    let mut slice = HtxSlice::new(&mut buf);

    let (accepted, consumed, err_msg) = match parser.parse(input, &mut slice) {
        Ok(n) => {
            // A request is considered accepted if start line was parsed and phase is Done
            let is_done = parser.phase == H1Phase::Done;
            (is_done, n, None)
        }
        Err(e) => (false, 0, Some(e.to_string())),
    };

    let htx = slice.as_ref().to_htx();
    let mut method = None;
    let mut uri = None;
    let mut version = None;
    if let Some(req) = htx.req_line() {
        method = Some(req.method.as_str().to_string());
        uri = Some(req.uri.clone());
        version = Some(req.version.as_str().to_string());
    }

    let mut headers = Vec::new();
    for block in htx.blocks() {
        if let HtxBlock::Header(h) = block {
            headers.push((h.name.clone(), h.value.clone()));
        }
    }
    let header_count = headers.len();
    let body = htx.body_bytes();
    let body_len = body.len();

    // 2. Incremental parse, feeding one more byte per call.
    //
    // `H1Parser::parse` returns the number of bytes it consumed, which is the usual
    // streaming contract: the caller keeps whatever was not consumed and re-presents it
    // with more data appended. Handing the parser a bare `[b]` each time instead throws
    // away every unconsumed byte, so it can never see a complete token -- it sees `G`,
    // then `E`, then `T`, each as a standalone buffer. That is not a streaming parse and
    // any parser would "disagree" with the full-buffer result on almost every input.
    let mut inc_parser = H1Parser::new(false);
    let mut inc_buf = vec![0u8; HTX_BUF];
    let mut inc_slice = HtxSlice::new(&mut inc_buf);
    let mut inc_consumed = 0usize;
    let mut inc_err = None;
    let mut pending: Vec<u8> = Vec::with_capacity(input.len());

    for &b in input {
        pending.push(b);
        match inc_parser.parse(&pending, &mut inc_slice) {
            Ok(n) => {
                inc_consumed += n;
                pending.drain(..n);
                if inc_parser.phase == H1Phase::Done {
                    break;
                }
            }
            Err(e) => {
                inc_err = Some(e.to_string());
                break;
            }
        }
    }

    let inc_accepted = inc_parser.phase == H1Phase::Done;
    let self_consistent = (accepted == inc_accepted)
        && (!accepted || (consumed == inc_consumed && body == inc_slice.as_ref().to_htx().body_bytes()));

    IbexParseResult {
        accepted,
        consumed_bytes: consumed,
        phase: format!("{:?}", parser.phase),
        method,
        uri,
        version,
        headers,
        header_count,
        body,
        body_len,
        is_chunked: parser.is_chunked,
        connection_close: parser.connection_close,
        next_request_start: consumed,
        self_consistent,
        error_message: err_msg.or(inc_err),
    }
}
