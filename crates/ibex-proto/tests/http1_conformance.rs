// SPDX-License-Identifier: GPL-2.0-or-later
// Ibex HTTP/1.1 Protocol Conformance & Stress Test Harness

#![forbid(unsafe_code)]
#![allow(clippy::all)]

use ibex_proto::h1::{H1Parser, H1Phase};
use ibex_proto::htx::{HttpMethod, HttpVersion, Htx};
use ibex_proto::mux::Mux;
use ibex_proto::mux_h1::MuxH1;
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
    let mut htx = Htx::new();

    let consumed = parser.parse(wire, &mut htx).expect("parse chunked");
    assert_eq!(consumed, wire.len());
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.req_line().unwrap().method, HttpMethod::Post);
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
    let mut htx = Htx::new();

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
    let mut htx = Htx::new();

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
    let mut htx = Htx::new();

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
    let mut htx = Htx::new();

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
    let mut htx = Htx::new();

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

        let req_line = ctx.rx_htx.req_line().expect("req_line");
        assert_eq!(req_line.method, HttpMethod::Get);
        assert_eq!(req_line.uri, format!("/resource/{i}"));
        assert_eq!(
            ctx.rx_htx.get_header("x-seq-id"),
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
            assert_eq!(ctx.rx_htx.req_line().unwrap().uri, expected_uri);

            let expected_body = format!("P{requests_handled:03}");
            assert_eq!(ctx.rx_htx.body_bytes(), expected_body.as_bytes());

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
    let mut htx = Htx::new();

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
    let mut htx = Htx::new();

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
    assert_eq!(htx.res_line().unwrap().version, HttpVersion::Http10);
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
    let mut htx = Htx::new();

    parser
        .parse(req, &mut htx)
        .expect("parse http10 keep-alive");
    assert_eq!(parser.phase, H1Phase::Done);
    assert_eq!(htx.req_line().unwrap().version, HttpVersion::Http10);
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
        expected_method: HttpMethod,
        expected_uri: &'static str,
        expected_body: &'static [u8],
    }

    let cases = vec![
        TestCase {
            raw: b"GET /items HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: HttpMethod::Get,
            expected_uri: "/items",
            expected_body: b"",
        },
        TestCase {
            raw: b"POST /items HTTP/1.1\r\nHost: api.io\r\nContent-Length: 9\r\n\r\n{\"id\": 1}",
            expected_method: HttpMethod::Post,
            expected_uri: "/items",
            expected_body: b"{\"id\": 1}",
        },
        TestCase {
            raw: b"PUT /items/1 HTTP/1.1\r\nHost: api.io\r\nContent-Length: 13\r\n\r\n{\"name\": \"b\"}",
            expected_method: HttpMethod::Put,
            expected_uri: "/items/1",
            expected_body: b"{\"name\": \"b\"}",
        },
        TestCase {
            raw: b"DELETE /items/1 HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: HttpMethod::Delete,
            expected_uri: "/items/1",
            expected_body: b"",
        },
        TestCase {
            raw: b"HEAD /items HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: HttpMethod::Head,
            expected_uri: "/items",
            expected_body: b"",
        },
        TestCase {
            raw: b"OPTIONS * HTTP/1.1\r\nHost: api.io\r\n\r\n",
            expected_method: HttpMethod::Options,
            expected_uri: "*",
            expected_body: b"",
        },
        TestCase {
            raw: b"PATCH /items/1 HTTP/1.1\r\nHost: api.io\r\nContent-Length: 17\r\n\r\n{\"status\": \"act\"}",
            expected_method: HttpMethod::Patch,
            expected_uri: "/items/1",
            expected_body: b"{\"status\": \"act\"}",
        },
    ];

    for tc in cases {
        let mut parser = H1Parser::new(false);
        let mut htx = Htx::new();

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
        assert!(wire_str.starts_with(tc.expected_method.as_str()));
    }
}

// ============================================================================
// 5. Header Boundary Edge Cases: CR-only, LF-only, CRLF, Multiline Fold
// ============================================================================

#[test]
fn test_header_crlf_standard() {
    let wire = b"GET /crlf HTTP/1.1\r\nHost: example.com\r\nX-Custom: value\r\n\r\n";
    let mut parser = H1Parser::new(false);
    let mut htx = Htx::new();

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
    let mut htx = Htx::new();

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
    let mut htx = Htx::new();

    assert!(
        parser.parse(wire, &mut htx).is_err(),
        "bare-CR framing must be rejected, as HAProxy 3.5 does"
    );
}

#[test]
fn test_header_crlf_still_normalizes() {
    let wire = b"GET /cr-only HTTP/1.1\r\nHost: example.net\r\nX-Header: cr_val\r\n\r\n";
    let mut parser = H1Parser::new(false);
    let mut htx = Htx::new();
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
    let mut htx = Htx::new();

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
    let wire = b"GET /ws HTTP/1.1\r\n\
                 CoNtEnT-TyPe:    application/json ; charset=utf-8   \r\n\
                 X-Spaced :   padded_value   \r\n\
                 \r\n";

    let mut parser = H1Parser::new(false);
    let mut htx = Htx::new();

    parser.parse(wire, &mut htx).expect("parse whitespace");
    assert_eq!(
        htx.get_header("content-type"),
        Some("application/json ; charset=utf-8")
    );
    assert_eq!(
        htx.get_header("CONTENT-TYPE"),
        Some("application/json ; charset=utf-8")
    );
    assert_eq!(htx.get_header("x-spaced"), Some("padded_value"));
}
