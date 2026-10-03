// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Structured and Combinatorial HTTP/1 Request Generator.
//!
//! Focuses on high-risk HTTP/1 framing ambiguity classes that produce real CVEs:
//! 1. Content-Length & Transfer-Encoding conflict (CL.TE, TE.CL, TE.TE)
//! 2. Duplicate or conflicting Content-Length headers
//! 3. Transfer-Encoding variations (casing, whitespace, trailing `, identity`)
//! 4. Obs-fold continuation lines (leading SP/TAB on continuations)
//! 5. Line terminator variations (CRLF, LF-only, CR-only, mixed, doubled)
//! 6. Chunk size formatting (leading zeros, +/- signs, hex casing, chunk extensions)
//! 7. Header name malformations (NUL bytes, space before colon, non-ASCII)
//! 8. Pipelined requests with ambiguous body boundaries
//! 9. Oversized headers, URIs, and field counts at and past limits
//! 10. Combinatorial mutations and fuzz permutations

#![forbid(unsafe_code)]

/// A generated test case with metadata about the class it targets.
#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub class: AmbiguityClass,
    pub description: String,
    pub raw_bytes: Vec<u8>,
    pub expected_body: Option<Vec<u8>>,
    pub is_pipelined: bool,
}

/// Category of HTTP framing ambiguity targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmbiguityClass {
    ClTeConflict,
    DuplicateContentLength,
    TransferEncodingVariations,
    ObsFoldContinuation,
    LineTerminatorVariations,
    ChunkSizeAndExtensions,
    HeaderNameMalformations,
    PipelinedAmbiguity,
    OversizedLimits,
    CombinatorialMutation,
    BaselineValid,
}

impl AmbiguityClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            AmbiguityClass::ClTeConflict => "CL-TE / TE-CL Conflict",
            AmbiguityClass::DuplicateContentLength => "Duplicate / Conflicting Content-Length",
            AmbiguityClass::TransferEncodingVariations => "Transfer-Encoding Formatting & Casing",
            AmbiguityClass::ObsFoldContinuation => "Obs-Fold Continuation Lines",
            AmbiguityClass::LineTerminatorVariations => "Line Terminator Variations (CR/LF)",
            AmbiguityClass::ChunkSizeAndExtensions => "Chunk Size & Extensions",
            AmbiguityClass::HeaderNameMalformations => "Header Name Malformations",
            AmbiguityClass::PipelinedAmbiguity => "Pipelined Request Boundaries",
            AmbiguityClass::OversizedLimits => "Oversized Headers & Limits",
            AmbiguityClass::CombinatorialMutation => "Combinatorial Mutations",
            AmbiguityClass::BaselineValid => "Baseline Valid HTTP/1",
        }
    }
}

/// Lightweight deterministic pseudo-random number generator (XorShift64) for reproducibility.
pub struct Prng {
    state: u64,
}

impl Prng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (self.next_u64() as usize) % max
        }
    }

    pub fn choose<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[self.next_usize(slice.len())]
    }
}

/// Generates a comprehensive suite of structured HTTP/1 test cases targeting all ambiguity classes.
pub fn generate_structured_corpus() -> Vec<TestCase> {
    let mut cases = Vec::new();

    // ========================================================================
    // 0. Baseline Valid Cases
    // ========================================================================
    cases.push(TestCase {
        name: "baseline_simple_get".into(),
        class: AmbiguityClass::BaselineValid,
        description: "Standard HTTP/1.1 GET request with Host header".into(),
        raw_bytes: b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "baseline_post_fixed_length".into(),
        class: AmbiguityClass::BaselineValid,
        description: "Standard HTTP/1.1 POST request with Content-Length".into(),
        raw_bytes: b"POST /api/v1/submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world".to_vec(),
        expected_body: Some(b"hello world".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "baseline_chunked_body".into(),
        class: AmbiguityClass::BaselineValid,
        description: "Standard HTTP/1.1 POST request with Chunked body".into(),
        raw_bytes: b"POST /api/chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec(),
        expected_body: Some(b"hello world".to_vec()),
        is_pipelined: false,
    });

    // ========================================================================
    // 1. Content-Length & Transfer-Encoding Ambiguity (CL-TE / TE-CL)
    // ========================================================================
    cases.push(TestCase {
        name: "cl_te_both_present_cl_first".into(),
        class: AmbiguityClass::ClTeConflict,
        description: "Both Content-Length and Transfer-Encoding: chunked present (CL first). Body contains chunked 0 and smuggled prefix.".into(),
        raw_bytes: b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_te_both_present_te_first".into(),
        class: AmbiguityClass::ClTeConflict,
        description: "Both Transfer-Encoding: chunked and Content-Length present (TE first).".into(),
        raw_bytes: b"POST /smuggle HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_te_conflicting_lengths_te_cl_smuggle".into(),
        class: AmbiguityClass::ClTeConflict,
        description: "TE-CL smuggling payload: CL specifies 4 bytes, but TE chunked specifies 11 bytes + end chunk.".into(),
        raw_bytes: b"POST /transfer HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_te_multiple_te_headers".into(),
        class: AmbiguityClass::ClTeConflict,
        description: "Multiple Transfer-Encoding headers: first 'identity', second 'chunked' alongside Content-Length.".into(),
        raw_bytes: b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    // ========================================================================
    // 2. Duplicate or Conflicting Content-Length Headers
    // ========================================================================
    cases.push(TestCase {
        name: "duplicate_cl_identical".into(),
        class: AmbiguityClass::DuplicateContentLength,
        description: "Duplicate Content-Length headers with identical values (5 and 5).".into(),
        raw_bytes: b"POST /dup-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "duplicate_cl_conflicting_values".into(),
        class: AmbiguityClass::DuplicateContentLength,
        description: "Conflicting Content-Length headers (5 and 10).".into(),
        raw_bytes: b"POST /conflict-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhelloworld".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_comma_separated_values".into(),
        class: AmbiguityClass::DuplicateContentLength,
        description: "Content-Length with comma-separated values '5, 5'.".into(),
        raw_bytes: b"POST /comma-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5, 5\r\n\r\nhello".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_comma_separated_conflicting".into(),
        class: AmbiguityClass::DuplicateContentLength,
        description: "Content-Length with comma-separated conflicting values '5, 10'.".into(),
        raw_bytes: b"POST /comma-conflict HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5, 10\r\n\r\nhello".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_signed_positive".into(),
        class: AmbiguityClass::DuplicateContentLength,
        description: "Content-Length with leading '+' sign (+5).".into(),
        raw_bytes: b"POST /signed-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: +5\r\n\r\nhello".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_signed_negative".into(),
        class: AmbiguityClass::DuplicateContentLength,
        description: "Content-Length with negative sign (-5).".into(),
        raw_bytes: b"POST /signed-neg-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: -5\r\n\r\nhello".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "cl_overflow_u64".into(),
        class: AmbiguityClass::DuplicateContentLength,
        description: "Content-Length with massive integer overflowing 64-bit integer.".into(),
        raw_bytes: b"POST /overflow-cl HTTP/1.1\r\nHost: example.com\r\nContent-Length: 99999999999999999999999999999999\r\n\r\nhello".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    // ========================================================================
    // 3. Transfer-Encoding Casing, Whitespace, and Trailing identity
    // ========================================================================
    cases.push(TestCase {
        name: "te_mixed_case".into(),
        class: AmbiguityClass::TransferEncodingVariations,
        description: "Transfer-Encoding with mixed casing: 'cHuNkEd'.".into(),
        raw_bytes: b"POST /casing HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: cHuNkEd\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: Some(b"hello".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "te_trailing_identity".into(),
        class: AmbiguityClass::TransferEncodingVariations,
        description: "Transfer-Encoding: chunked, identity (RFC 9112 §6.1 invalid final encoding).".into(),
        raw_bytes: b"POST /trailing-id HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "te_leading_identity".into(),
        class: AmbiguityClass::TransferEncodingVariations,
        description: "Transfer-Encoding: identity, chunked.".into(),
        raw_bytes: b"POST /leading-id HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: identity, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "te_tab_whitespace".into(),
        class: AmbiguityClass::TransferEncodingVariations,
        description: "Transfer-Encoding with tab separator: 'Transfer-Encoding:\tchunked'.".into(),
        raw_bytes: b"POST /te-tab HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding:\tchunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: Some(b"hello".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "te_prefix_unknown_encoding".into(),
        class: AmbiguityClass::TransferEncodingVariations,
        description: "Transfer-Encoding containing chunked substring in unrecognized token: 'not-chunked'.".into(),
        raw_bytes: b"POST /te-unknown HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: not-chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    // ========================================================================
    // 4. Obs-Fold Continuation Lines
    // ========================================================================
    cases.push(TestCase {
        name: "obs_fold_space_continuation".into(),
        class: AmbiguityClass::ObsFoldContinuation,
        description: "Header folded across lines with leading space (RFC 7230 obs-fold).".into(),
        raw_bytes: b"GET /obs-fold HTTP/1.1\r\nHost: example.com\r\nX-Header: first-line\r\n second-line\r\n\r\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "obs_fold_tab_continuation".into(),
        class: AmbiguityClass::ObsFoldContinuation,
        description: "Header folded across lines with leading tab.".into(),
        raw_bytes: b"GET /obs-tab HTTP/1.1\r\nHost: example.com\r\nX-Header: first-line\r\n\tsecond-line\r\n\r\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "obs_fold_transfer_encoding".into(),
        class: AmbiguityClass::ObsFoldContinuation,
        description: "Obs-fold on Transfer-Encoding header line itself.".into(),
        raw_bytes: b"POST /obs-te HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding:\r\n chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "obs_fold_first_line".into(),
        class: AmbiguityClass::ObsFoldContinuation,
        description: "Obs-fold immediately after request line (no preceding header).".into(),
        raw_bytes: b"GET /obs-first HTTP/1.1\r\n folded-without-header: value\r\nHost: example.com\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    // ========================================================================
    // 5. Line Terminator Variations (CRLF, LF-only, CR-only, Doubled)
    // ========================================================================
    cases.push(TestCase {
        name: "line_term_lf_only".into(),
        class: AmbiguityClass::LineTerminatorVariations,
        description: "HTTP request using LF-only (\\n) line endings throughout.".into(),
        raw_bytes: b"GET /lf-only HTTP/1.1\nHost: example.com\nX-Header: value\n\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "line_term_cr_only".into(),
        class: AmbiguityClass::LineTerminatorVariations,
        description: "HTTP request using CR-only (\\r) line endings throughout.".into(),
        raw_bytes: b"GET /cr-only HTTP/1.1\rHost: example.com\rX-Header: value\r\r".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "line_term_mixed_crlf_and_lf".into(),
        class: AmbiguityClass::LineTerminatorVariations,
        description: "Request line uses CRLF, headers use LF only.".into(),
        raw_bytes: b"GET /mixed HTTP/1.1\r\nHost: example.com\nX-Header: value\n\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "line_term_bare_cr_in_header_value".into(),
        class: AmbiguityClass::LineTerminatorVariations,
        description: "Bare CR character embedded in header value.".into(),
        raw_bytes: b"GET /bare-cr HTTP/1.1\r\nHost: example.com\r\nX-Bad: val\rue\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "line_term_doubled_crlf_before_headers".into(),
        class: AmbiguityClass::LineTerminatorVariations,
        description: "Doubled CRLF immediately following request line.".into(),
        raw_bytes: b"GET /doubled HTTP/1.1\r\n\r\nHost: example.com\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    // ========================================================================
    // 6. Chunk Size Formatting & Chunk Extensions
    // ========================================================================
    cases.push(TestCase {
        name: "chunk_leading_zeros".into(),
        class: AmbiguityClass::ChunkSizeAndExtensions,
        description: "Chunk size formatted with leading zeros (00005).".into(),
        raw_bytes: b"POST /chunk-zeros HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n00005\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: Some(b"hello".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "chunk_signed_plus".into(),
        class: AmbiguityClass::ChunkSizeAndExtensions,
        description: "Chunk size formatted with leading '+' sign (+5).".into(),
        raw_bytes: b"POST /chunk-plus HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "chunk_extension_standard".into(),
        class: AmbiguityClass::ChunkSizeAndExtensions,
        description: "Chunk extension with key-value parameters: '5;ext=foo;bar=123'.".into(),
        raw_bytes: b"POST /chunk-ext HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=foo;bar=123\r\nhello\r\n0;final=true\r\n\r\n".to_vec(),
        expected_body: Some(b"hello".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "chunk_extension_quoted_semicolon".into(),
        class: AmbiguityClass::ChunkSizeAndExtensions,
        description: "Chunk extension with quoted string containing semicolons.".into(),
        raw_bytes: b"POST /chunk-quoted HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=\"quoted;with;semis\"\r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: Some(b"hello".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "chunk_whitespace_around_size".into(),
        class: AmbiguityClass::ChunkSizeAndExtensions,
        description: "Chunk size line with leading and trailing whitespace around size hex: ' 5 '.".into(),
        raw_bytes: b"POST /chunk-ws HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n 5 \r\nhello\r\n0\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    // ========================================================================
    // 7. Header Name Malformations (NUL, Space Before Colon, Non-ASCII)
    // ========================================================================
    cases.push(TestCase {
        name: "header_space_before_colon".into(),
        class: AmbiguityClass::HeaderNameMalformations,
        description: "Header with whitespace before colon: 'X-Header : value' (RFC 7230 §3.2.4 violation).".into(),
        raw_bytes: b"GET /space-before-colon HTTP/1.1\r\nHost: example.com\r\nX-Header : value\r\n\r\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "header_tab_before_colon".into(),
        class: AmbiguityClass::HeaderNameMalformations,
        description: "Header with TAB character before colon: 'X-Header\t: value'.".into(),
        raw_bytes: b"GET /tab-before-colon HTTP/1.1\r\nHost: example.com\r\nX-Header\t: value\r\n\r\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "header_nul_in_name".into(),
        class: AmbiguityClass::HeaderNameMalformations,
        description: "Header name containing embedded NUL (\\x00) byte: 'X-Foo\\x00Bar: val'.".into(),
        raw_bytes: b"GET /nul-in-name HTTP/1.1\r\nHost: example.com\r\nX-Foo\x00Bar: value\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "header_nul_in_value".into(),
        class: AmbiguityClass::HeaderNameMalformations,
        description: "Header value containing embedded NUL (\\x00) byte: 'X-Header: val\\x00ue'.".into(),
        raw_bytes: b"GET /nul-in-value HTTP/1.1\r\nHost: example.com\r\nX-Header: val\x00ue\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "header_missing_colon".into(),
        class: AmbiguityClass::HeaderNameMalformations,
        description: "Header line completely missing colon separator: 'HeaderWithoutColon'.".into(),
        raw_bytes: b"GET /missing-colon HTTP/1.1\r\nHost: example.com\r\nHeaderWithoutColon\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    cases.push(TestCase {
        name: "header_empty_name".into(),
        class: AmbiguityClass::HeaderNameMalformations,
        description: "Header line with empty name before colon: ': empty-name-value'.".into(),
        raw_bytes: b"GET /empty-name HTTP/1.1\r\nHost: example.com\r\n: empty-name-value\r\n\r\n".to_vec(),
        expected_body: None,
        is_pipelined: false,
    });

    // ========================================================================
    // 8. Pipelined Requests with Boundary Ambiguities
    // ========================================================================
    cases.push(TestCase {
        name: "pipelined_standard_two_requests".into(),
        class: AmbiguityClass::PipelinedAmbiguity,
        description: "Two back-to-back pipelined GET requests on the same connection.".into(),
        raw_bytes: b"GET /first HTTP/1.1\r\nHost: a.com\r\n\r\nGET /second HTTP/1.1\r\nHost: b.com\r\n\r\n".to_vec(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: true,
    });

    cases.push(TestCase {
        name: "pipelined_body_underflow_smuggle".into(),
        class: AmbiguityClass::PipelinedAmbiguity,
        description: "Request 1 specifies CL: 4, but body is 8 bytes before Request 2 start line.".into(),
        raw_bytes: b"POST /p1 HTTP/1.1\r\nHost: a.com\r\nContent-Length: 4\r\n\r\n1234EXTRA_BYTESGET /p2 HTTP/1.1\r\nHost: b.com\r\n\r\n".to_vec(),
        expected_body: Some(b"1234".to_vec()),
        is_pipelined: true,
    });

    cases.push(TestCase {
        name: "pipelined_chunked_premature_end".into(),
        class: AmbiguityClass::PipelinedAmbiguity,
        description: "Request 1 terminates chunked stream early with 0\\r\\n\\r\\n, followed by second request.".into(),
        raw_bytes: b"POST /p-chunk HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\nGET /p-after HTTP/1.1\r\nHost: b.com\r\n\r\n".to_vec(),
        expected_body: Some(b"test".to_vec()),
        is_pipelined: true,
    });

    // ========================================================================
    // 9. Limits and Oversized Elements
    // ========================================================================
    let long_uri = format!("GET /{} HTTP/1.1\r\nHost: example.com\r\n\r\n", "a".repeat(4096));
    cases.push(TestCase {
        name: "oversized_uri_4k".into(),
        class: AmbiguityClass::OversizedLimits,
        description: "Request with 4 KiB long URI path.".into(),
        raw_bytes: long_uri.into_bytes(),
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    let mut many_hdrs = Vec::new();
    many_hdrs.extend_from_slice(b"GET /many-headers HTTP/1.1\r\nHost: example.com\r\n");
    for i in 0..120 {
        many_hdrs.extend_from_slice(format!("X-Custom-Header-{i:03}: value_{i}\r\n").as_bytes());
    }
    many_hdrs.extend_from_slice(b"\r\n");
    cases.push(TestCase {
        name: "oversized_header_count_120".into(),
        class: AmbiguityClass::OversizedLimits,
        description: "Request containing 120 unique custom headers.".into(),
        raw_bytes: many_hdrs,
        expected_body: Some(b"".to_vec()),
        is_pipelined: false,
    });

    let long_hdr_name = format!("{}: test\r\n\r\n", "X-".to_string() + &"a".repeat(300));
    let mut long_hdr_req = b"GET /long-hdr HTTP/1.1\r\nHost: example.com\r\n".to_vec();
    long_hdr_req.extend_from_slice(long_hdr_name.as_bytes());
    cases.push(TestCase {
        name: "oversized_header_name_300b".into(),
        class: AmbiguityClass::OversizedLimits,
        description: "Header name exceeding HTX limit of 255 bytes (302 bytes name).".into(),
        raw_bytes: long_hdr_req,
        expected_body: None,
        is_pipelined: false,
    });

    cases
}

/// Generates randomized mutations based on a deterministic seed.
pub fn generate_mutated_cases(seed: u64, count: usize) -> Vec<TestCase> {
    let mut prng = Prng::new(seed);
    let base_cases = generate_structured_corpus();
    let mut mutated = Vec::with_capacity(count);

    let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "PROPFIND", "INVALID_METHOD"];
    let uris = ["/", "/index.html", "/api/v1/resource", "/deep/nested/path?q=1&v=2", "/%20encoded%20", "/\x00bad"];
    let versions = ["HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/0.9", "HTTP/1.2", "HTTP/9.9", ""];
    let line_endings = [b"\r\n".as_slice(), b"\n".as_slice(), b"\r".as_slice(), b"\r\r\n".as_slice()];

    for i in 0..count {
        let mutation_type = prng.next_usize(6);
        match mutation_type {
            0 => {
                // Mutate a base structured case by inserting/replacing bytes
                let base = prng.choose(&base_cases);
                let mut bytes = base.raw_bytes.clone();
                if !bytes.is_empty() {
                    let pos = prng.next_usize(bytes.len());
                    let byte_mut_type = prng.next_usize(4);
                    match byte_mut_type {
                        0 => bytes[pos] = 0x00, // NUL
                        1 => bytes[pos] = b' ',  // SP
                        2 => bytes[pos] = b':',  // Colon
                        _ => bytes[pos] = 0xFF,  // Non-ASCII
                    }
                }
                mutated.push(TestCase {
                    name: format!("mutated_base_{i}_{}", base.name),
                    class: AmbiguityClass::CombinatorialMutation,
                    description: format!("Mutated byte in {}", base.name),
                    raw_bytes: bytes,
                    expected_body: None,
                    is_pipelined: false,
                });
            }
            1 => {
                // Generate randomized start-line variations
                let meth = prng.choose(&methods);
                let uri = prng.choose(&uris);
                let ver = prng.choose(&versions);
                let delim = prng.choose(&line_endings);

                let mut raw = Vec::new();
                raw.extend_from_slice(meth.as_bytes());
                raw.push(b' ');
                raw.extend_from_slice(uri.as_bytes());
                if !ver.is_empty() {
                    raw.push(b' ');
                    raw.extend_from_slice(ver.as_bytes());
                }
                raw.extend_from_slice(delim);
                raw.extend_from_slice(b"Host: example.com\r\n\r\n");

                mutated.push(TestCase {
                    name: format!("mutated_startline_{i}"),
                    class: AmbiguityClass::CombinatorialMutation,
                    description: format!("Randomized start-line {meth} {uri} {ver}"),
                    raw_bytes: raw,
                    expected_body: Some(b"".to_vec()),
                    is_pipelined: false,
                });
            }
            2 => {
                // Generate randomized chunked streams with variations
                let chunks_count = 1 + prng.next_usize(5);
                let mut raw = b"POST /mut-chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                let mut body = Vec::new();
                for _c in 0..chunks_count {
                    let chunk_len = 1 + prng.next_usize(16);
                    let chunk_data: Vec<u8> = (0..chunk_len).map(|j| b'a' + (j as u8 % 26)).collect();
                    let hex_str = if prng.next_usize(2) == 0 {
                        format!("{chunk_len:x}\r\n")
                    } else {
                        format!("{chunk_len:X}\r\n")
                    };
                    raw.extend_from_slice(hex_str.as_bytes());
                    raw.extend_from_slice(&chunk_data);
                    raw.extend_from_slice(b"\r\n");
                    body.extend_from_slice(&chunk_data);
                }
                raw.extend_from_slice(b"0\r\n\r\n");

                mutated.push(TestCase {
                    name: format!("mutated_chunked_{i}"),
                    class: AmbiguityClass::CombinatorialMutation,
                    description: format!("Randomized chunked sequence of {chunks_count} chunks"),
                    raw_bytes: raw,
                    expected_body: Some(body),
                    is_pipelined: false,
                });
            }
            3 => {
                // Generate randomized header whitespace and delimiter permutations
                let mut raw = b"GET /mut-headers HTTP/1.1\r\nHost: example.com\r\n".to_vec();
                let hdrs_count = 2 + prng.next_usize(6);
                for h in 0..hdrs_count {
                    let ws_before = if prng.next_usize(3) == 0 { " " } else { "" };
                    let ws_after = if prng.next_usize(2) == 0 { "  " } else { " " };
                    let line = format!("X-Header-{h}{ws_before}:{ws_after}value_{h}\r\n");
                    raw.extend_from_slice(line.as_bytes());
                }
                raw.extend_from_slice(b"\r\n");

                mutated.push(TestCase {
                    name: format!("mutated_headers_ws_{i}"),
                    class: AmbiguityClass::CombinatorialMutation,
                    description: "Randomized header whitespace permutations".into(),
                    raw_bytes: raw,
                    expected_body: Some(b"".to_vec()),
                    is_pipelined: false,
                });
            }
            4 => {
                // Combinations of CL and TE with random payload sizes
                let cl_val = prng.next_usize(20);
                let payload_len = prng.next_usize(20);
                let payload: Vec<u8> = (0..payload_len).map(|j| b'0' + (j as u8 % 10)).collect();

                let mut raw = format!(
                    "POST /cl-te-rand HTTP/1.1\r\nHost: example.com\r\nContent-Length: {cl_val}\r\nTransfer-Encoding: chunked\r\n\r\n"
                ).into_bytes();
                raw.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
                raw.extend_from_slice(&payload);
                raw.extend_from_slice(b"\r\n0\r\n\r\n");

                mutated.push(TestCase {
                    name: format!("mutated_cl_te_rand_{i}"),
                    class: AmbiguityClass::CombinatorialMutation,
                    description: format!("Combinatorial CL ({cl_val}) vs TE with payload len ({payload_len})"),
                    raw_bytes: raw,
                    expected_body: None,
                    is_pipelined: false,
                });
            }
            _ => {
                // Pipelined randomized pairs
                let req1 = format!("GET /p1_{i} HTTP/1.1\r\nHost: a.com\r\n\r\n");
                let req2 = format!("GET /p2_{i} HTTP/1.1\r\nHost: b.com\r\n\r\n");
                let mut raw = req1.into_bytes();
                raw.extend_from_slice(req2.as_bytes());

                mutated.push(TestCase {
                    name: format!("mutated_pipelined_pair_{i}"),
                    class: AmbiguityClass::PipelinedAmbiguity,
                    description: "Randomized pipelined pair".into(),
                    raw_bytes: raw,
                    expected_body: Some(b"".to_vec()),
                    is_pipelined: true,
                });
            }
        }
    }

    mutated
}
