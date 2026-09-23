// SPDX-License-Identifier: GPL-2.0-or-later
// Ibex HTTP/1.1 Protocol Conformance & Stress Test Harness

#![forbid(unsafe_code)]

use ibex_proto::h1::{H1Parser, H1Phase};
use ibex_proto::htx::{
    HeaderField, HttpMethod, HttpVersion, HtxBlock, HtxBlockType, HtxSlice, RequestLine,
};
use ibex_proto::mux::Mux;
use ibex_proto::mux_h1::{H1StreamState, MuxH1};
use ibex_proto::ConnId;

// ============================================================================
// 1. Chunked Transfer Encoding Tests
// ============================================================================

#[test]
fn test_chunked_single_chunk() {
    let wire = b"POST /upload HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 b\r\n\
                 hello world\r\n\
                 0\r\n\
                 \r\n";

    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser.parse(wire, &mut htx).expect("parse chunked");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.req_line().unwrap().method, "POST");
    assert_eq!(htx.body_bytes(), b"hello world");
    assert!(htx.is_eom());
    assert_eq!(htx.trailers().count(), 0);
}

#[test]
fn test_chunked_multiple_varying_sizes() {
    // Chunks of varying sizes: 1, 2, 5, 16 (0x10), 32 (0x20), 0 (end)
    let payload_1 = b"A";
    let payload_2 = b"BC";
    let payload_3 = b"DEFGH";
    let payload_4 = b"0123456789abcdef";
    let payload_5 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";

    let wire = format!(
        "HTTP/1.1 200 OK\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         1\r\n{}\r\n\
         2\r\n{}\r\n\
         5\r\n{}\r\n\
         10\r\n{}\r\n\
         20\r\n{}\r\n\
         0\r\n\
         \r\n",
        std::str::from_utf8(payload_1).unwrap(),
        std::str::from_utf8(payload_2).unwrap(),
        std::str::from_utf8(payload_3).unwrap(),
        std::str::from_utf8(payload_4).unwrap(),
        std::str::from_utf8(payload_5).unwrap(),
    );

    let mut parser = H1Parser::new(true);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser
        .parse(wire.as_bytes(), &mut htx)
        .expect("parse varying chunks");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.res_line().unwrap().status, 200);

    let mut expected_body = Vec::new();
    expected_body.extend_from_slice(payload_1);
    expected_body.extend_from_slice(payload_2);
    expected_body.extend_from_slice(payload_3);
    expected_body.extend_from_slice(payload_4);
    expected_body.extend_from_slice(payload_5);

    assert_eq!(htx.body_bytes(), expected_body);
    assert!(htx.is_eom());
}

#[test]
fn test_chunked_with_extensions() {
    // Chunk extensions: `1a;name=val;flag\r\n...`, `0;final=true\r\n\r\n`
    let wire = b"HTTP/1.1 200 OK\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 5;ext1=val;ext2\r\n\
                 hello\r\n\
                 6;token=\"quoted\"\r\n\
                 \x20world\r\n\
                 0;end=yes\r\n\
                 \r\n";

    let mut parser = H1Parser::new(true);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser
        .parse(wire, &mut htx)
        .expect("parse chunked with extensions");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.body_bytes(), b"hello world");
    assert!(htx.is_eom());
}

#[test]
fn test_chunked_trailer_headers() {
    let wire = b"POST /data HTTP/1.1\r\n\
                 Host: example.com\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Trailer: Expires, X-Checksum\r\n\
                 \r\n\
                 5\r\n\
                 Ibex!\r\n\
                 0\r\n\
                 Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\n\
                 X-Checksum: d41d8cd98f00b204e9800998ecf8427e\r\n\
                 \r\n";

    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser
        .parse(wire, &mut htx)
        .expect("parse chunked with trailers");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.body_bytes(), b"Ibex!");
    assert!(htx.is_eom());

    assert_eq!(
        htx.get_trailer("expires"),
        Some("Wed, 21 Oct 2026 07:28:00 GMT")
    );
    assert_eq!(
        htx.get_trailer("X-CHECKSUM"),
        Some("d41d8cd98f00b204e9800998ecf8427e")
    );
    assert_eq!(htx.trailers().count(), 2);
}

#[test]
fn test_chunked_trailers_with_multiline_obs_fold() {
    let wire = b"HTTP/1.1 200 OK\r\n\
                 Transfer-Encoding: chunked\r\n\
                 \r\n\
                 4\r\n\
                 test\r\n\
                 0\r\n\
                 X-Multi-Trailer: line1\r\n\
                 \x20continued-line2\r\n\
                 \tcontinued-line3\r\n\
                 \r\n";

    let mut parser = H1Parser::new(true);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser
        .parse(wire, &mut htx)
        .expect("parse trailers obs fold");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.body_bytes(), b"test");
    assert_eq!(
        htx.get_trailer("x-multi-trailer"),
        Some("line1 continued-line2 continued-line3")
    );
}

#[test]
fn test_chunked_streaming_incremental_bytes() {
    let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

    let mut parser = H1Parser::new(true);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let mut feed_pos = 0;
    let mut buffer = Vec::new();
    while feed_pos < wire.len() || !buffer.is_empty() {
        if feed_pos < wire.len() {
            let next_feed = (feed_pos + 3).min(wire.len());
            buffer.extend_from_slice(&wire[feed_pos..next_feed]);
            feed_pos = next_feed;
        }
        let n = parser.parse(&buffer, &mut htx).expect("incremental parse");
        if n > 0 {
            buffer.drain(..n);
        }
        if parser.phase == H1Phase::Done {
            break;
        }
    }

    assert_eq!(feed_pos, wire.len());
    assert!(buffer.is_empty());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.body_bytes(), b"Wikipedia");
    assert!(htx.is_eom());
}

// ============================================================================
// 2. HTTP Keep-Alive & Connection Reuse Tests (50+ Sequential & Pipelined)
// ============================================================================

#[test]
fn test_keep_alive_55_sequential_requests() {
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(1), false).expect("init mux");

    for i in 1..=55 {
        let req = format!(
            "GET /resource/{i} HTTP/1.1\r\n\
             Host: api.ibex.internal\r\n\
             X-Seq-Id: {i}\r\n\
             Connection: keep-alive\r\n\
             \r\n"
        );

        let consumed = mux
            .parse(&mut ctx, req.as_bytes())
            .expect("parse sequential");
        assert_eq!(consumed, req.len());
        assert_eq!(ctx.parser.phase, H1Phase::Done);

        let req_line = ctx.rx_htx_buf.req_line().expect("req_line");
        assert_eq!(req_line.method, "GET");
        assert_eq!(req_line.uri, format!("/resource/{i}"));
        assert_eq!(
            ctx.rx_htx_buf.get_header("x-seq-id"),
            Some(i.to_string().as_str())
        );
        assert!(!ctx.parser.connection_close);

        // Simulate stream completion and connection reuse
        ctx.release_stream();
        assert_eq!(mux.avail_streams(&ctx), 1);
    }
}

#[test]
fn test_keep_alive_60_pipelined_requests() {
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(42), false).expect("init mux");

    // Build 60 pipelined requests back-to-back in a single buffer
    let mut pipeline_buffer = Vec::new();
    for i in 1..=60 {
        let req = format!(
            "POST /pipeline/{i} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Length: 4\r\n\
             \r\n\
             P{i:03}"
        );
        pipeline_buffer.extend_from_slice(req.as_bytes());
    }

    let mut cursor = 0;
    let mut requests_handled = 0;

    while cursor < pipeline_buffer.len() {
        let consumed = mux
            .parse(&mut ctx, &pipeline_buffer[cursor..])
            .expect("parse pipelined slice");
        assert!(consumed > 0, "must make progress on pipelined buffer");
        cursor += consumed;

        if ctx.parser.phase == H1Phase::Done {
            requests_handled += 1;
            let expected_uri = format!("/pipeline/{requests_handled}");
            assert_eq!(ctx.rx_htx_buf.req_line().unwrap().uri, expected_uri);

            let expected_body = format!("P{requests_handled:03}");
            assert_eq!(ctx.rx_htx_buf.body_bytes(), expected_body.as_bytes());

            // Release stream for next pipelined request on the same connection
            ctx.release_stream();
        }
    }

    assert_eq!(cursor, pipeline_buffer.len());
    assert_eq!(requests_handled, 60);
}

#[test]
fn test_keep_alive_connection_close_semantics() {
    let req = b"GET /close HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    parser.parse(req, &mut htx).expect("parse close");
    assert_eq!(parser.phase, H1Phase::Done);
    assert!(
        parser.connection_close,
        "Connection: close must be recognized"
    );

    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(7), false).expect("init");
    mux.parse(&mut ctx, req).expect("mux parse close");
    ctx.release_stream();
    // Because connection_close was received, avail_streams must be 0
    assert_eq!(mux.avail_streams(&ctx), 0);
}

// ============================================================================
// 3. HTTP/1.0 Fallback Without Content-Length (Close Delimiter)
// ============================================================================

#[test]
fn test_http10_fallback_without_content_length_close_delimiter() {
    let wire_headers = b"HTTP/1.0 200 OK\r\n\
                         Content-Type: text/html\r\n\
                         Server: Legacy-Http10/0.9\r\n\
                         \r\n";
    let wire_body = b"<html><body>Legacy payload without Content-Length delimiter</body></html>";

    let mut parser = H1Parser::new(true);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let n1 = parser.parse(wire_headers, &mut htx).expect("parse headers");
    assert_eq!(n1, wire_headers.len());
    // Phase should be BodyFixed with usize::MAX (close delimiter mode)
    assert_eq!(
        parser.phase,
        H1Phase::BodyFixed {
            remaining: usize::MAX
        }
    );

    let n2 = parser
        .parse(wire_body, &mut htx)
        .expect("parse body stream");
    assert_eq!(n2, wire_body.len());
    assert_eq!(
        parser.phase,
        H1Phase::BodyFixed {
            remaining: usize::MAX
        }
    );

    // Server shuts down / closes connection (EOF delimiter)
    parser.finish(&mut htx);
    assert_eq!(parser.phase, H1Phase::Done);
    assert!(htx.is_eom());
    assert_eq!(htx.body_bytes(), wire_body);
    assert_eq!(htx.res_line().unwrap().version, "HTTP/1.0");
    assert!(
        parser.connection_close,
        "HTTP/1.0 defaults to connection close"
    );
}

#[test]
fn test_http10_with_explicit_keep_alive() {
    let req = b"GET /keep-alive-10 HTTP/1.0\r\n\
                Host: legacy.com\r\n\
                Connection: keep-alive\r\n\
                \r\n";

    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    parser
        .parse(req, &mut htx)
        .expect("parse http10 keep-alive");
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.req_line().unwrap().version, "HTTP/1.0");
    assert!(
        !parser.connection_close,
        "HTTP/1.0 with Connection: keep-alive should not force close"
    );
}

// ============================================================================
// 4. HTTP Method Handling (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
// ============================================================================

#[test]
fn test_http_methods_suite() {
    struct TestCase {
        raw: &'static [u8],
        expected_method: &'static str,
        expected_uri: &'static str,
        expected_body: &'static [u8],
    }

    let cases = vec![
        TestCase {
            raw: b"GET /items HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: "GET",
            expected_uri: "/items",
            expected_body: b"",
        },
        TestCase {
            raw: b"POST /items HTTP/1.1\r\nHost: api.io\r\nContent-Length: 9\r\n\r\n{\"id\": 1}",
            expected_method: "POST",
            expected_uri: "/items",
            expected_body: b"{\"id\": 1}",
        },
        TestCase {
            raw: b"PUT /items/1 HTTP/1.1\r\nHost: api.io\r\nContent-Length: 13\r\n\r\n{\"name\": \"b\"}",
            expected_method: "PUT",
            expected_uri: "/items/1",
            expected_body: b"{\"name\": \"b\"}",
        },
        TestCase {
            raw: b"DELETE /items/1 HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: "DELETE",
            expected_uri: "/items/1",
            expected_body: b"",
        },
        TestCase {
            raw: b"HEAD /items HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: "HEAD",
            expected_uri: "/items",
            expected_body: b"",
        },
        TestCase {
            raw: b"OPTIONS * HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: "OPTIONS",
            expected_uri: "*",
            expected_body: b"",
        },
        TestCase {
            raw: b"PATCH /items/1 HTTP/1.1\r\nHost: api.io\r\nContent-Length: 17\r\n\r\n{\"status\": \"act\"}",
            expected_method: "PATCH",
            expected_uri: "/items/1",
            expected_body: b"{\"status\": \"act\"}",
        },
    ];

    for tc in cases {
        let mut parser = H1Parser::new(false);
        let mut buf = [0u8; 8192];
        let mut htx = HtxSlice::new(&mut buf);

        let consumed = parser.parse(tc.raw, &mut htx).expect("parse method");
        assert_eq!(consumed, tc.raw.len());
        assert_eq!(parser.phase, H1Phase::Done);

        let req = htx.req_line().unwrap();
        assert_eq!(req.method, tc.expected_method);
        assert_eq!(req.uri, tc.expected_uri);
        assert_eq!(htx.body_bytes(), tc.expected_body);

        // Verify HTX wire serialization roundtrip preserves method
        let wire = htx.to_h1_wire();
        let wire_str = String::from_utf8(wire).expect("utf8");
        assert!(wire_str.starts_with(tc.expected_method));
    }
}

// ============================================================================
// 5. Header Boundary Edge Cases: CR-only, LF-only, CRLF, Multiline Fold
// ============================================================================

#[test]
fn test_header_crlf_standard() {
    let wire = b"GET /crlf HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\n\r\n";
    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser.parse(wire, &mut htx).expect("parse crlf");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.get_header("host"), Some("example.com"));
    assert_eq!(htx.get_header("x-custom"), Some("value"));
}

#[test]
fn test_header_lf_only() {
    let wire = b"GET /lf-only HTTP/1.1\nHost: example.org\nX-Single-Line: ok\n\n";
    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser.parse(wire, &mut htx).expect("parse lf only");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.req_line().unwrap().uri, "/lf-only");
    assert_eq!(htx.get_header("host"), Some("example.org"));
    assert_eq!(htx.get_header("x-single-line"), Some("ok"));

    // Verify wire serialization normalizes to standard CRLF
    let normalized = htx.to_h1_wire();
    assert!(normalized.windows(2).any(|w| w == b"\r\n"));
    assert!(
        !normalized.contains(&b'\n')
            || normalized
                .windows(2)
                .all(|w| w[1] != b'\n' || w[0] == b'\r')
    );
}

#[test]
fn test_header_cr_only_is_rejected() {
    // A CR not followed by LF is not a line terminator. This test previously asserted
    // that Ibex accepted CR-only framing and normalised it to CRLF; verified against a
    // live HAProxy 3.5, that input gets 400 Bad request.
    //
    // Accepting it is worse than merely lenient: a hop that disagrees about where lines
    // end disagrees about where the message ends, which is a desync primitive.
    let wire = b"GET /cr-only HTTP/1.1\rHost: example.net\rX-Header: cr_val\r\r";
    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    assert!(
        parser.parse(wire, &mut htx).is_err(),
        "bare-CR framing must be rejected, as HAProxy 3.5 does"
    );
}

#[test]
fn test_header_crlf_still_normalizes() {
    let wire = b"GET /cr-only HTTP/1.1\r\nHost: example.net\r\nX-Header: cr_val\r\n\r\n";
    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);
    let consumed = parser.parse(wire, &mut htx).expect("parse crlf");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.get_header("host"), Some("example.net"));

    // Verify wire serialization normalizes to canonical CRLF
    let wire_out = htx.to_h1_wire();
    assert!(wire_out.starts_with(b"GET /cr-only HTTP/1.1\r\n"));
    assert!(wire_out.ends_with(b"\r\n\r\n"));
}

#[test]
fn test_header_multiline_obs_fold_spaces_and_tabs() {
    let wire = b"GET /obs-fold HTTP/1.1\r\nHost: example.com\r\nSubject: This is a test of\r\n folded header fields using\r\n\tRFC7230 obs-fold rules\r\nAccept: */*\r\n\r\n";

    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    let consumed = parser.parse(wire, &mut htx).expect("parse obs fold");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(
        htx.get_header("subject"),
        Some("This is a test of folded header fields using RFC7230 obs-fold rules")
    );
    assert_eq!(htx.get_header("accept"), Some("*/*"));

    // Serialization replaces obs-fold with standard single-line header
    let serialized = String::from_utf8(htx.to_h1_wire()).unwrap();
    assert!(serialized.contains(
        "Subject: This is a test of folded header fields using RFC7230 obs-fold rules\r\n"
    ));
}

#[test]
fn test_header_whitespace_and_case_insensitivity() {
    // Whitespace *around the value* is trimmed and lookups are case-insensitive.
    let wire = b"GET /ws HTTP/1.1\r\n\
                 CoNtEnT-TyPe:    application/json ; charset=utf-8   \r\n\
                 X-Padded:   padded_value   \r\n\
                 \r\n";

    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);

    parser.parse(wire, &mut htx).expect("parse whitespace");
    assert_eq!(
        htx.get_header("content-type"),
        Some("application/json ; charset=utf-8")
    );
    assert_eq!(
        htx.get_header("CONTENT-TYPE"),
        Some("application/json ; charset=utf-8")
    );
    assert_eq!(htx.get_header("x-padded"), Some("padded_value"));
}

#[test]
fn test_whitespace_before_colon_is_rejected() {
    // Whitespace *before the colon* is a different matter. RFC 9112 5.1 requires a
    // server to reject it with 400, and HAProxy 3.5 does. This previously parsed as a
    // trimmed "X-Spaced" header.
    //
    // It matters because `Content-Length : 5` is ignored by a hop demanding a strict
    // token and honoured by one that trims, and the two then disagree on body length.
    let wire = b"GET /ws HTTP/1.1\r\nHost: h\r\nX-Spaced :   padded_value\r\n\r\n";
    let mut parser = H1Parser::new(false);
    let mut buf = [0u8; 8192];
    let mut htx = HtxSlice::new(&mut buf);
    assert!(parser.parse(wire, &mut htx).is_err());
}

// ============================================================================
// Stage 1: MuxH1 Receive Path HTX Block Sequence Tests
// ============================================================================

#[test]
fn test_stage1_mux_h1_block_sequence_content_length() {
    let wire = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world";
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(101), false).expect("init mux");

    let consumed = mux.parse(&mut ctx, wire).expect("parse content-length");
    assert_eq!(consumed, wire.len());
    assert_eq!(ctx.stream_state, H1StreamState::ReqDone);
    assert!(ctx.rx_htx_buf.is_eom());
    assert_eq!(ctx.rx_htx_buf.body_bytes(), b"hello world");

    // Block-by-block sequence verification
    assert_eq!(
        ctx.rx_htx_buf.active_block_types(),
        vec![
            HtxBlockType::ReqLine,
            HtxBlockType::Header,
            HtxBlockType::Header,
            HtxBlockType::Eoh,
            HtxBlockType::Data,
            HtxBlockType::Eom,
        ]
    );

    let blocks = ctx.rx_htx_buf.to_blocks();
    assert_eq!(
        blocks[0],
        HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Post,
            uri: "/submit".into(),
            version: HttpVersion::Http11,
        })
    );
    assert_eq!(
        blocks[1],
        HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "example.com".into(),
        })
    );
    assert_eq!(
        blocks[2],
        HtxBlock::Header(HeaderField {
            name: "Content-Length".into(),
            value: "11".into(),
        })
    );
    assert_eq!(blocks[3], HtxBlock::Eoh);
    assert_eq!(blocks[4], HtxBlock::Data(b"hello world".to_vec()));
    assert_eq!(blocks[5], HtxBlock::Eom);
}

#[test]
fn test_stage1_mux_h1_block_sequence_chunked() {
    let wire = b"POST /chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(102), false).expect("init mux");

    let consumed = mux.parse(&mut ctx, wire).expect("parse chunked");
    assert_eq!(consumed, wire.len());
    assert_eq!(ctx.stream_state, H1StreamState::ReqDone);
    assert!(ctx.rx_htx_buf.is_eom());
    assert_eq!(ctx.rx_htx_buf.body_bytes(), b"hello world");

    assert_eq!(
        ctx.rx_htx_buf.active_block_types(),
        vec![
            HtxBlockType::ReqLine,
            HtxBlockType::Header,
            HtxBlockType::Header,
            HtxBlockType::Eoh,
            HtxBlockType::Data,
            HtxBlockType::Data,
            HtxBlockType::Eot,
            HtxBlockType::Eom,
        ]
    );

    let blocks = ctx.rx_htx_buf.to_blocks();
    assert_eq!(
        blocks[0],
        HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Post,
            uri: "/chunked".into(),
            version: HttpVersion::Http11,
        })
    );
    assert_eq!(
        blocks[1],
        HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "example.com".into(),
        })
    );
    assert_eq!(
        blocks[2],
        HtxBlock::Header(HeaderField {
            name: "Transfer-Encoding".into(),
            value: "chunked".into(),
        })
    );
    assert_eq!(blocks[3], HtxBlock::Eoh);
    assert_eq!(blocks[4], HtxBlock::Data(b"hello".to_vec()));
    assert_eq!(blocks[5], HtxBlock::Data(b" world".to_vec()));
    assert_eq!(blocks[6], HtxBlock::Eot);
    assert_eq!(blocks[7], HtxBlock::Eom);
}

#[test]
fn test_stage1_mux_h1_block_sequence_chunked_with_trailers() {
    let wire = b"POST /trailers HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nExpires: never\r\nChecksum: abc123\r\n\r\n";
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(103), false).expect("init mux");

    let consumed = mux.parse(&mut ctx, wire).expect("parse chunked with trailers");
    assert_eq!(consumed, wire.len());
    assert_eq!(ctx.stream_state, H1StreamState::ReqDone);
    assert!(ctx.rx_htx_buf.is_eom());
    assert_eq!(ctx.rx_htx_buf.body_bytes(), b"hello");

    assert_eq!(
        ctx.rx_htx_buf.active_block_types(),
        vec![
            HtxBlockType::ReqLine,
            HtxBlockType::Header,
            HtxBlockType::Header,
            HtxBlockType::Eoh,
            HtxBlockType::Data,
            HtxBlockType::Trailer,
            HtxBlockType::Trailer,
            HtxBlockType::Eot,
            HtxBlockType::Eom,
        ]
    );

    let blocks = ctx.rx_htx_buf.to_blocks();
    assert_eq!(
        blocks[0],
        HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Post,
            uri: "/trailers".into(),
            version: HttpVersion::Http11,
        })
    );
    assert_eq!(
        blocks[1],
        HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "example.com".into(),
        })
    );
    assert_eq!(
        blocks[2],
        HtxBlock::Header(HeaderField {
            name: "Transfer-Encoding".into(),
            value: "chunked".into(),
        })
    );
    assert_eq!(blocks[3], HtxBlock::Eoh);
    assert_eq!(blocks[4], HtxBlock::Data(b"hello".to_vec()));
    assert_eq!(
        blocks[5],
        HtxBlock::Trailer(HeaderField {
            name: "Expires".into(),
            value: "never".into(),
        })
    );
    assert_eq!(
        blocks[6],
        HtxBlock::Trailer(HeaderField {
            name: "Checksum".into(),
            value: "abc123".into(),
        })
    );
    assert_eq!(blocks[7], HtxBlock::Eot);
    assert_eq!(blocks[8], HtxBlock::Eom);
}

#[test]
fn test_stage1_mux_h1_block_sequence_no_body() {
    let wire = b"GET /no-body HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(104), false).expect("init mux");

    let consumed = mux.parse(&mut ctx, wire).expect("parse no body");
    assert_eq!(consumed, wire.len());
    assert_eq!(ctx.stream_state, H1StreamState::ReqDone);
    assert!(ctx.rx_htx_buf.is_eom());
    assert_eq!(ctx.rx_htx_buf.body_len(), 0);

    assert_eq!(
        ctx.rx_htx_buf.active_block_types(),
        vec![
            HtxBlockType::ReqLine,
            HtxBlockType::Header,
            HtxBlockType::Header,
            HtxBlockType::Eoh,
            HtxBlockType::Eom,
        ]
    );

    let blocks = ctx.rx_htx_buf.to_blocks();
    assert_eq!(
        blocks[0],
        HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Get,
            uri: "/no-body".into(),
            version: HttpVersion::Http11,
        })
    );
    assert_eq!(
        blocks[1],
        HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "example.com".into(),
        })
    );
    assert_eq!(
        blocks[2],
        HtxBlock::Header(HeaderField {
            name: "Accept".into(),
            value: "*/*".into(),
        })
    );
    assert_eq!(blocks[3], HtxBlock::Eoh);
    assert_eq!(blocks[4], HtxBlock::Eom);
}

#[test]
fn test_stage1_mux_h1_block_sequence_cl_te_conflict() {
    let wire = b"POST /conflict HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(105), false).expect("init mux");

    let consumed = mux.parse(&mut ctx, wire).expect("parse cl-te conflict");
    assert_eq!(consumed, wire.len());
    assert_eq!(ctx.stream_state, H1StreamState::ReqDone);
    assert!(ctx.rx_htx_buf.is_eom());
    assert!(ctx.conn_close, "CL+TE conflict must force connection: close");
    assert!(ctx.parser.framing_conflict, "Framing conflict flag must be set");
    assert_eq!(
        ctx.rx_htx_buf.get_header("content-length"),
        None,
        "Content-Length must be removed per RFC 7230 §3.3.3"
    );

    // Active block types omit tombstoned Content-Length block
    assert_eq!(
        ctx.rx_htx_buf.active_block_types(),
        vec![
            HtxBlockType::ReqLine,
            HtxBlockType::Header,
            HtxBlockType::Header,
            HtxBlockType::Eoh,
            HtxBlockType::Data,
            HtxBlockType::Eot,
            HtxBlockType::Eom,
        ]
    );

    let blocks = ctx.rx_htx_buf.to_blocks();
    assert_eq!(
        blocks[0],
        HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Post,
            uri: "/conflict".into(),
            version: HttpVersion::Http11,
        })
    );
    assert_eq!(
        blocks[1],
        HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "example.com".into(),
        })
    );
    assert_eq!(
        blocks[2],
        HtxBlock::Header(HeaderField {
            name: "Transfer-Encoding".into(),
            value: "chunked".into(),
        })
    );
    assert_eq!(blocks[3], HtxBlock::Eoh);
    assert_eq!(blocks[4], HtxBlock::Data(b"hello".to_vec()));
    assert_eq!(blocks[5], HtxBlock::Eot);
    assert_eq!(blocks[6], HtxBlock::Eom);

    // Verify defrag removes the Unused tombstone in-place and invariants hold
    ctx.rx_htx_buf.defrag();
    assert_eq!(ctx.rx_htx_buf.block_types(), ctx.rx_htx_buf.active_block_types());
    ctx.rx_htx_buf
        .check_invariants()
        .expect("invariants must hold after defrag");
}

#[test]
fn test_stage3_htx_ruleset_mutation_parity() {
    let wire = b"GET /v1/users?page=1 HTTP/1.1\r\nHost: example.com\r\nX-Foo: bar\r\nX-Remove-Me: gone\r\nUser-Agent: test\r\n\r\n";
    let mux = MuxH1;
    let mut ctx = mux.init(ConnId(106), false).expect("init mux");

    let consumed = mux.parse(&mut ctx, wire).expect("parse base request");
    assert_eq!(consumed, wire.len());

    // Apply rule mutations directly via HTX block ops
    // 1. set-path to /v2/users
    ctx.rx_htx_buf.set_path("/v2/users").expect("set_path");
    // 2. del-header on X-Remove-Me
    ctx.rx_htx_buf.remove_header("X-Remove-Me");
    // 3. replace-header User-Agent -> ibex/1.0
    ctx.rx_htx_buf
        .replace_header("User-Agent", "test", "ibex/1.0")
        .expect("replace_header");
    // 4. set-header X-Foo -> baz (updates existing)
    ctx.rx_htx_buf.set_header("X-Foo", "baz").expect("set_header");
    // 5. add-header X-Added: yes (appends new header)
    ctx.rx_htx_buf.add_header("X-Added", "yes").expect("add_header");

    let wire_out = ctx.rx_htx_buf.to_h1_wire();
    let expected = b"GET /v2/users?page=1 HTTP/1.1\r\nHost: example.com\r\nX-Foo: baz\r\nUser-Agent: ibex/1.0\r\nX-Added: yes\r\n\r\n";
    assert_eq!(
        std::str::from_utf8(&wire_out).unwrap(),
        std::str::from_utf8(expected).unwrap(),
        "HTX mutation ruleset must match expected normalized wire form"
    );

    ctx.rx_htx_buf
        .check_invariants()
        .expect("invariants must hold after mutation ruleset");
}

#[test]
fn test_stage3_htx_defrag_threshold_below_at_above() {
    use ibex_proto::htx::{HtxBuffer, HTX_DEFRAG_THRESHOLD_BYTES};

    // 1. Below threshold: 511 fragmented bytes
    let mut buf = HtxBuffer::new();
    buf.push_req_line("GET", "/test", "HTTP/1.1").expect("req line");
    // Push header with 511 bytes value
    let pad511 = "a".repeat(511);
    buf.push_header("X-Pad", &pad511).expect("pad header");
    buf.push_header("Host", "example.com").expect("host");
    buf.push_eoh().expect("eoh");

    // Remove pad header, creating 511+name bytes of fragmentation
    buf.remove_header("X-Pad");
    let frag_before = buf.fragmented_bytes();
    assert!(frag_before >= 511, "must have at least 511 fragmented bytes, got {frag_before}");

    // Test below threshold: set threshold to frag_before + 1
    let triggered_below = buf.maybe_defrag_threshold(frag_before + 1);
    assert!(
        !triggered_below,
        "maybe_defrag below threshold must NOT trigger defrag"
    );
    assert_eq!(buf.fragmented_bytes(), frag_before);

    // 2. Exactly at threshold: set threshold to frag_before
    let triggered_at = buf.maybe_defrag_threshold(frag_before);
    assert!(
        triggered_at,
        "maybe_defrag exactly at threshold MUST trigger defrag"
    );
    assert_eq!(
        buf.fragmented_bytes(),
        0,
        "fragmented bytes must drop to 0 after defrag at threshold"
    );
    buf.check_invariants().expect("invariants must hold after defrag at threshold");

    // Assert block sequence survives intact
    assert_eq!(buf.get_header("Host"), Some("example.com"));
    assert_eq!(buf.get_header("X-Pad"), None);

    // 3. Above threshold: create 1024 fragmented bytes and test against HTX_DEFRAG_THRESHOLD_BYTES (512)
    let pad1024 = "b".repeat(1024);
    buf.push_header("X-Pad-Big", &pad1024).expect("big pad");
    buf.push_header("X-Keep", "alive").expect("keep header");
    buf.remove_header("X-Pad-Big");
    let frag_big = buf.fragmented_bytes();
    assert!(
        frag_big >= 1024,
        "must have at least 1024 fragmented bytes, got {frag_big}"
    );
    assert!(
        frag_big > HTX_DEFRAG_THRESHOLD_BYTES,
        "frag_big ({frag_big}) must be above default threshold ({HTX_DEFRAG_THRESHOLD_BYTES})"
    );

    let triggered_above = buf.maybe_defrag();
    assert!(
        triggered_above,
        "maybe_defrag above threshold MUST trigger defrag"
    );
    assert_eq!(
        buf.fragmented_bytes(),
        0,
        "fragmented bytes must drop to 0 after defrag above threshold"
    );
    buf.check_invariants().expect("invariants must hold after defrag above threshold");

    assert_eq!(buf.get_header("X-Keep"), Some("alive"));
    assert_eq!(buf.get_header("Host"), Some("example.com"));
}


