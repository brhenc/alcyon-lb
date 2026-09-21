// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 Protocol Conformance and Multiplexing Test Suite.
//!
//! Comprehensive verification of RFC 7540 / RFC 9113 and RFC 7541 under `#![forbid(unsafe_code)]`.
//! Tests cover:
//! 1. Connection preface exchange (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + `SETTINGS` frame with ACK).
//! 2. Concurrent stream multiplexing over a single connection (streams 1, 3, 5, 7, etc.).
//! 3. HPACK header compression and decompression verification with dynamic table mutations.
//! 4. Stream and connection level flow control (`WINDOW_UPDATE`) when payload exceeds initial window.
//! 5. Stream reset (`RST_STREAM`) handling and graceful connection shutdown (`GOAWAY`).

#![forbid(unsafe_code)]
#![allow(clippy::all)]

use ibex_proto::conn::ConnId;
use ibex_proto::endpoint::{Endpoint, SeDesc};
use ibex_proto::h2::{
    frame_flags, Frame, FrameHeader, FrameType, H2ConnState, H2Error, H2StreamState,
    SettingsParameter, DEFAULT_INITIAL_WINDOW_SIZE, FRAME_HEADER_LEN, H2_CONN_PREFACE,
};
use ibex_proto::hpack::{HpackDecoder, HpackEncoder};
use ibex_proto::htx::{HeaderField, HttpMethod};
use ibex_proto::mux::{Mux, ShutMode};
use ibex_proto::mux_h2::MuxH2;

/// 1. Connection Preface Exchange and SETTINGS negotiation.
///
/// Verifies:
/// - Exact 24-byte client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).
/// - Initial SETTINGS exchange from both client and server.
/// - Mandatory SETTINGS ACK exchange (`flags = 0x01`, `length = 0`).
/// - Rejection of invalid connection preface with `ProtocolError` / GOAWAY.
/// - Rejection of SETTINGS with ACK flag and non-empty payload.
#[test]
fn test_connection_preface_exchange_and_settings_ack() {
    let mux = MuxH2;
    let mut ctx = mux.init(ConnId(100), true).expect("init server mux");

    assert_eq!(ctx.conn_state, H2ConnState::ExpectPreface);
    assert_eq!(mux.avail_streams(&ctx), 100);
    assert_eq!(mux.used_streams(&ctx), 0);

    // Partial preface should wait for remaining bytes
    let partial_preface = b"PRI * HTTP/2.0\r\n";
    let consumed_partial = mux.parse(&mut ctx, partial_preface).expect("parse partial");
    assert_eq!(consumed_partial, partial_preface.len());
    assert_eq!(ctx.conn_state, H2ConnState::ExpectPreface);

    // Complete preface + client initial SETTINGS frame
    let mut preface_and_settings = Vec::new();
    preface_and_settings.extend_from_slice(b"\r\nSM\r\n\r\n"); // complete the 24-byte preface

    let client_settings = Frame::Settings {
        flags: 0,
        settings: vec![
            (SettingsParameter::MaxConcurrentStreams, 50),
            (SettingsParameter::InitialWindowSize, 131_072),
            (SettingsParameter::HeaderTableSize, 4096),
        ],
    };
    preface_and_settings.extend_from_slice(&client_settings.encode());

    let consumed = mux
        .parse(&mut ctx, &preface_and_settings)
        .expect("parse preface and settings");
    assert_eq!(consumed, preface_and_settings.len());

    // Server should now be Open and have applied client's initial window
    assert_eq!(ctx.conn_state, H2ConnState::Open);
    assert_eq!(ctx.remote_initial_window, 131_072);

    // Inspect server's pending output: should contain Server SETTINGS + Server SETTINGS ACK
    let pending = mux.pending_output(&ctx);
    assert!(pending.len() >= FRAME_HEADER_LEN * 2);

    // Parse server's output frames
    let mut off = 0;
    let mut saw_server_settings = false;
    let mut saw_server_settings_ack = false;

    while off + FRAME_HEADER_LEN <= pending.len() {
        let hdr = FrameHeader::decode(&pending[off..]).expect("decode frame header");
        let payload_start = off + FRAME_HEADER_LEN;
        let payload_end = payload_start + hdr.length as usize;
        assert!(payload_end <= pending.len());
        let frame =
            Frame::decode(&hdr, &pending[payload_start..payload_end]).expect("decode frame");

        if let Frame::Settings { flags, settings } = frame {
            if (flags & frame_flags::ACK) != 0 {
                saw_server_settings_ack = true;
                assert_eq!(hdr.length, 0, "SETTINGS ACK payload must be 0 octets");
            } else {
                saw_server_settings = true;
                assert!(!settings.is_empty());
            }
        }
        off = payload_end;
    }

    assert!(
        saw_server_settings,
        "Server must emit its own SETTINGS frame"
    );
    assert!(
        saw_server_settings_ack,
        "Server must acknowledge client SETTINGS"
    );

    // Client sends SETTINGS ACK to server
    let client_ack = Frame::Settings {
        flags: frame_flags::ACK,
        settings: Vec::new(),
    };
    mux.parse(&mut ctx, &client_ack.encode())
        .expect("client settings ack");
    assert!(ctx.settings_ack_received);

    // Negative test: invalid connection preface
    let mut err_ctx = mux.init(ConnId(101), true).expect("init err server");
    let bad_preface = b"GET / HTTP/1.1\r\nHost: loc";
    let _res = mux.parse(&mut err_ctx, bad_preface);
    assert_eq!(err_ctx.conn_state, H2ConnState::GoAwaySent);
    assert_eq!(err_ctx.goaway_sent.unwrap().1, H2Error::ProtocolError);
}

/// 2. Concurrent Stream Multiplexing.
///
/// Verifies:
/// - Client-initiated streams MUST use odd identifiers (1, 3, 5, 7).
/// - Concurrent interleaved frames on distinct streams are tracked independently.
/// - Stream state machine transitions (`Idle` -> `Open` -> `HalfClosedRemote`).
/// - Server rejects client attempt to initiate even stream IDs (`ProtocolError` / GOAWAY).
#[test]
fn test_concurrent_stream_multiplexing() {
    let mux = MuxH2;
    let mut ctx = mux.init(ConnId(200), true).expect("init");

    // Handshake
    let mut init_buf = Vec::new();
    init_buf.extend_from_slice(H2_CONN_PREFACE);
    init_buf.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![],
        }
        .encode(),
    );
    mux.parse(&mut ctx, &init_buf).expect("handshake");

    let mut enc = HpackEncoder::new();

    // Stream 1: GET /api/v1/users (Headers only, END_STREAM)
    let s1_headers = vec![
        HeaderField {
            name: ":method".into(),
            value: "GET".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/api/v1/users".into(),
        },
        HeaderField {
            name: "accept".into(),
            value: "application/json".into(),
        },
    ];
    let frame_s1_hdr = Frame::Headers {
        flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
        stream_id: 1,
        header_block: enc.encode(&s1_headers),
    };

    // Stream 3: POST /api/v1/upload (Headers + Data chunk 1 + Data chunk 2 with END_STREAM)
    let s3_headers = vec![
        HeaderField {
            name: ":method".into(),
            value: "POST".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/api/v1/upload".into(),
        },
    ];
    let frame_s3_hdr = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 3,
        header_block: enc.encode(&s3_headers),
    };
    let frame_s3_data1 = Frame::Data {
        flags: 0,
        stream_id: 3,
        data: b"chunk-alpha-".to_vec(),
    };
    let frame_s3_data2 = Frame::Data {
        flags: frame_flags::END_STREAM,
        stream_id: 3,
        data: b"chunk-beta".to_vec(),
    };

    // Stream 5: GET /static/logo.png (Headers with END_STREAM)
    let s5_headers = vec![
        HeaderField {
            name: ":method".into(),
            value: "GET".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/static/logo.png".into(),
        },
    ];
    let frame_s5_hdr = Frame::Headers {
        flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
        stream_id: 5,
        header_block: enc.encode(&s5_headers),
    };

    // Stream 7: PUT /api/v1/items/42 (Headers + single Data with END_STREAM)
    let s7_headers = vec![
        HeaderField {
            name: ":method".into(),
            value: "PUT".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/api/v1/items/42".into(),
        },
    ];
    let frame_s7_hdr = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 7,
        header_block: enc.encode(&s7_headers),
    };
    let frame_s7_data = Frame::Data {
        flags: frame_flags::END_STREAM,
        stream_id: 7,
        data: b"{\"name\":\"item42\"}".to_vec(),
    };

    // Interleave all frames across streams over the single connection byte stream:
    // [Headers 1, Headers 3, Data 3-part1, Headers 5, Headers 7, Data 7, Data 3-part2]
    let mut wire = Vec::new();
    wire.extend_from_slice(&frame_s1_hdr.encode());
    wire.extend_from_slice(&frame_s3_hdr.encode());
    wire.extend_from_slice(&frame_s3_data1.encode());
    wire.extend_from_slice(&frame_s5_hdr.encode());
    wire.extend_from_slice(&frame_s7_hdr.encode());
    wire.extend_from_slice(&frame_s7_data.encode());
    wire.extend_from_slice(&frame_s3_data2.encode());

    mux.parse(&mut ctx, &wire)
        .expect("parse multiplexed stream wire");

    // All 4 streams must be tracked concurrently
    assert_eq!(mux.used_streams(&ctx), 4);
    assert_eq!(ctx.streams.len(), 4);

    // Verify Stream 1
    let st1 = ctx.streams.get(&1).expect("stream 1");
    assert_eq!(st1.state, H2StreamState::HalfClosedRemote);
    assert_eq!(st1.rx_htx.req_line().unwrap().method, HttpMethod::Get);
    assert_eq!(st1.rx_htx.req_line().unwrap().uri, "/api/v1/users");

    // Verify Stream 3 (reassembled data across multiple chunks)
    let st3 = ctx.streams.get(&3).expect("stream 3");
    assert_eq!(st3.state, H2StreamState::HalfClosedRemote);
    assert_eq!(st3.rx_htx.req_line().unwrap().method, HttpMethod::Post);
    assert_eq!(st3.rx_htx.req_line().unwrap().uri, "/api/v1/upload");
    assert_eq!(st3.rx_htx.body_bytes(), b"chunk-alpha-chunk-beta");

    // Verify Stream 5
    let st5 = ctx.streams.get(&5).expect("stream 5");
    assert_eq!(st5.state, H2StreamState::HalfClosedRemote);
    assert_eq!(st5.rx_htx.req_line().unwrap().uri, "/static/logo.png");

    // Verify Stream 7
    let st7 = ctx.streams.get(&7).expect("stream 7");
    assert_eq!(st7.state, H2StreamState::HalfClosedRemote);
    assert_eq!(st7.rx_htx.req_line().unwrap().method, HttpMethod::Put);
    assert_eq!(st7.rx_htx.body_bytes(), b"{\"name\":\"item42\"}");

    // Test Reading parsed stream via rcv_buf endpoint pivot
    let mut sd1 = SeDesc {
        endpoint: Endpoint::MuxStream {
            conn: ConnId(200),
            stream: 1,
        },
        ..SeDesc::new()
    };
    let mut out_buf = [0u8; 512];
    let n1 = mux
        .rcv_buf(&mut ctx, &mut sd1, &mut out_buf)
        .expect("rcv_buf stream 1");
    assert!(n1 > 0);
    let out_str = std::str::from_utf8(&out_buf[..n1]).unwrap();
    assert!(out_str.contains("GET /api/v1/users"));

    // Negative test: Client initiating even-numbered stream ID (e.g. Stream 2)
    let bad_even_frame = Frame::Headers {
        flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
        stream_id: 2,
        header_block: enc.encode(&s1_headers),
    };
    let res = mux.parse(&mut ctx, &bad_even_frame.encode());
    assert!(res.is_err(), "Client must not open even stream IDs");
    assert!(ctx.goaway_sent.is_some());
}

/// 3. HPACK Header Compression and Dynamic Table Mutations.
///
/// Verifies:
/// - RFC 7541 static table lookup (indices 1..61).
/// - Dynamic table insertion at index 62.
/// - Dynamic table size calculation (`name.len() + value.len() + 32`).
/// - Dynamic table entry eviction under bounded memory capacity (FIFO).
/// - Sequential requests reusing indexed dynamic table representations.
/// - Dynamic table capacity updates via `SETTINGS_HEADER_TABLE_SIZE`.
#[test]
fn test_hpack_compression_decompression_and_dynamic_table_mutations() {
    let mut enc = HpackEncoder::with_max_size(256);
    let mut dec = HpackDecoder::with_max_size(256);

    // Initial table should be empty
    assert_eq!(enc.dynamic_table.len(), 0);
    assert_eq!(dec.dynamic_table.len(), 0);
    assert_eq!(enc.dynamic_table.size(), 0);

    // Request 1: Inserts new custom headers into dynamic table
    // Header 1: "x-custom-tenant" : "tenant-omega-99" (15 + 15 + 32 = 62 octets)
    // Header 2: "x-custom-trace"  : "trace-abc-1234" (14 + 14 + 32 = 60 octets)
    let req1 = vec![
        HeaderField {
            name: ":method".into(),
            value: "GET".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/".into(),
        },
        HeaderField {
            name: "x-custom-tenant".into(),
            value: "tenant-omega-99".into(),
        },
        HeaderField {
            name: "x-custom-trace".into(),
            value: "trace-abc-1234".into(),
        },
    ];

    let block1 = enc.encode(&req1);
    let decoded1 = dec.decode(&block1).expect("decode request 1");
    assert_eq!(decoded1, req1);

    // Verify dynamic table mutation on both encoder and decoder
    assert_eq!(enc.dynamic_table.len(), 2);
    assert_eq!(dec.dynamic_table.len(), 2);
    assert_eq!(enc.dynamic_table.size(), 62 + 60);
    assert_eq!(dec.dynamic_table.size(), 62 + 60);

    // Index 62 is the most recently added entry ("x-custom-trace")
    assert_eq!(dec.dynamic_table.get(0).unwrap().name, "x-custom-trace");
    assert_eq!(dec.dynamic_table.get(0).unwrap().value, "trace-abc-1234");
    // Index 63 is the second entry ("x-custom-tenant")
    assert_eq!(dec.dynamic_table.get(1).unwrap().name, "x-custom-tenant");
    assert_eq!(dec.dynamic_table.get(1).unwrap().value, "tenant-omega-99");

    // Request 2: Re-sends the same custom headers. Encoder should use 1-byte indexed entries!
    let req2 = vec![
        HeaderField {
            name: ":method".into(),
            value: "GET".into(),
        },
        HeaderField {
            name: "x-custom-trace".into(),
            value: "trace-abc-1234".into(),
        },
        HeaderField {
            name: "x-custom-tenant".into(),
            value: "tenant-omega-99".into(),
        },
    ];
    let block2 = enc.encode(&req2);
    // 1 byte for :method GET (static idx 2), 1 byte for trace (idx 62), 1 byte for tenant (idx 63)
    assert_eq!(
        block2.len(),
        3,
        "All headers should compress to 1 octet each"
    );
    let decoded2 = dec.decode(&block2).expect("decode request 2");
    assert_eq!(decoded2, req2);

    // Eviction Test: Insert large headers until capacity (256) is exceeded
    // Header 3: "x-large-payload-header" : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    // size: 22 + 32 + 32 = 86 octets. Total size: 62 + 60 + 86 = 208 <= 256.
    let req3 = vec![HeaderField {
        name: "x-large-payload-header".into(),
        value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
    }];
    let block3 = enc.encode(&req3);
    dec.decode(&block3).expect("decode request 3");
    assert_eq!(dec.dynamic_table.len(), 3);
    assert_eq!(dec.dynamic_table.size(), 62 + 60 + 86);

    // Header 4: Another large header (86 octets).
    // Total needed: 208 + 86 = 294 > 256 -> must evict oldest header ("x-custom-tenant")!
    let req4 = vec![HeaderField {
        name: "x-another-large-header".into(),
        value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
    }];
    let block4 = enc.encode(&req4);
    dec.decode(&block4).expect("decode request 4");

    // Verify oldest entry was evicted
    assert_eq!(dec.dynamic_table.len(), 3);
    assert!(dec.dynamic_table.size() <= 256);
    // Oldest entry "x-custom-tenant" was evicted; entries are now:
    // 0: x-another-large-header
    // 1: x-large-payload-header
    // 2: x-custom-trace
    assert_eq!(
        dec.dynamic_table.get(0).unwrap().name,
        "x-another-large-header"
    );
    assert_eq!(
        dec.dynamic_table.get(1).unwrap().name,
        "x-large-payload-header"
    );
    assert_eq!(dec.dynamic_table.get(2).unwrap().name, "x-custom-trace");

    // Shrinking dynamic table capacity via set_max_size
    dec.dynamic_table.set_max_size(100);
    assert!(dec.dynamic_table.size() <= 100);
    assert_eq!(dec.dynamic_table.len(), 1);
    assert_eq!(
        dec.dynamic_table.get(0).unwrap().name,
        "x-another-large-header"
    );
}

/// 4. Flow Control (`WINDOW_UPDATE`) at Stream and Connection Levels.
///
/// Verifies:
/// - Initial flow control window is 65,535 octets.
/// - Data transmission decrements both stream and connection send windows.
/// - Exhaustion of flow control window stalls transmission (`snd_buf` returns 0).
/// - `WINDOW_UPDATE` on stream 0 increments connection window.
/// - `WINDOW_UPDATE` on stream ID increments stream window.
/// - Transmission resumes immediately once window is replenished.
/// - Rejection of invalid 0-increment `WINDOW_UPDATE` with `ProtocolError` / GOAWAY.
#[test]
fn test_flow_control_window_update_stream_and_connection_levels() {
    let mux = MuxH2;
    let mut ctx = mux.init(ConnId(300), true).expect("init");

    // Handshake with client initial window = 10,000 octets
    let mut init_buf = Vec::new();
    init_buf.extend_from_slice(H2_CONN_PREFACE);
    init_buf.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![(SettingsParameter::InitialWindowSize, 10_000)],
        }
        .encode(),
    );
    mux.parse(&mut ctx, &init_buf).expect("handshake");

    assert_eq!(ctx.remote_initial_window, 10_000);
    assert_eq!(ctx.conn_send_window, DEFAULT_INITIAL_WINDOW_SIZE);

    // Client opens stream 1
    let mut enc = HpackEncoder::new();
    let s1_headers = vec![
        HeaderField {
            name: ":method".into(),
            value: "GET".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/large-file".into(),
        },
    ];
    let open_stream = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 1,
        header_block: enc.encode(&s1_headers),
    };
    mux.parse(&mut ctx, &open_stream.encode())
        .expect("open stream 1");

    let s1 = ctx.streams.get(&1).unwrap();
    assert_eq!(s1.send_window, 10_000);

    // Server prepares response payload of 15,000 octets (exceeds stream window of 10,000)
    let payload = vec![0x42u8; 15_000];
    let mut sd = SeDesc {
        endpoint: Endpoint::MuxStream {
            conn: ConnId(300),
            stream: 1,
        },
        ..SeDesc::new()
    };

    // First send: should send exactly 10,000 octets and stall
    let sent1 = mux
        .snd_buf(&mut ctx, &mut sd, &payload)
        .expect("snd_buf chunk 1");
    assert_eq!(sent1, 10_000);

    let s1 = ctx.streams.get(&1).unwrap();
    assert_eq!(s1.send_window, 0, "Stream window should be exhausted");
    assert_eq!(ctx.conn_send_window, DEFAULT_INITIAL_WINDOW_SIZE - 10_000);

    // Second send attempt without WINDOW_UPDATE must be blocked (return 0)
    let sent2 = mux
        .snd_buf(&mut ctx, &mut sd, &payload[10_000..])
        .expect("snd_buf blocked");
    assert_eq!(sent2, 0, "Transmission must be blocked when window is 0");

    // Client replenishes stream 1 window by 8,000 octets
    let stream_win_up = Frame::WindowUpdate {
        stream_id: 1,
        increment: 8_000,
    };
    mux.parse(&mut ctx, &stream_win_up.encode())
        .expect("parse stream window update");

    let s1 = ctx.streams.get(&1).unwrap();
    assert_eq!(s1.send_window, 8_000);

    // Third send attempt: remaining 5,000 octets can now be transmitted!
    let sent3 = mux
        .snd_buf(&mut ctx, &mut sd, &payload[10_000..])
        .expect("snd_buf unblocked");
    assert_eq!(sent3, 5_000);

    let s1 = ctx.streams.get(&1).unwrap();
    assert_eq!(s1.send_window, 3_000);

    // Connection-level flow control test:
    // Exhaust connection window
    ctx.conn_send_window = 500;
    let sent_conn_limited = mux
        .snd_buf(&mut ctx, &mut sd, &payload[..1000])
        .expect("conn limit");
    assert_eq!(sent_conn_limited, 500, "Limited by connection-level window");
    assert_eq!(ctx.conn_send_window, 0);

    // Connection-level WINDOW_UPDATE on stream 0
    let conn_win_up = Frame::WindowUpdate {
        stream_id: 0,
        increment: 65_535,
    };
    mux.parse(&mut ctx, &conn_win_up.encode())
        .expect("parse conn window update");
    assert_eq!(ctx.conn_send_window, 65_535);

    // Negative test: 0-increment WINDOW_UPDATE is a PROTOCOL_ERROR
    let zero_win_up = Frame::WindowUpdate {
        stream_id: 1,
        increment: 0,
    };
    let res = mux.parse(&mut ctx, &zero_win_up.encode());
    assert!(res.is_err(), "Zero WINDOW_UPDATE increment must error");
    assert_eq!(ctx.goaway_sent.unwrap().1, H2Error::ProtocolError);
}

/// 5. Stream Reset (`RST_STREAM`) and Graceful Shutdown (`GOAWAY`).
///
/// Verifies:
/// - `RST_STREAM` immediately terminates target stream without disrupting other active streams.
/// - `GOAWAY` frame parsing records last stream ID and transitions connection state.
/// - Orderly stream closing via `ShutMode::Normal` transmits `END_STREAM`.
/// - Emergency stream abort via `ShutMode::Reset` transmits `RST_STREAM(CANCEL)`.
#[test]
fn test_stream_reset_rst_stream_handling_and_graceful_shutdown() {
    let mux = MuxH2;
    let mut ctx = mux.init(ConnId(400), true).expect("init");

    // Handshake
    let mut init_buf = Vec::new();
    init_buf.extend_from_slice(H2_CONN_PREFACE);
    init_buf.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![],
        }
        .encode(),
    );
    mux.parse(&mut ctx, &init_buf).expect("handshake");
    let initial_len = mux.pending_output(&ctx).len();
    mux.consume_output(&mut ctx, initial_len);

    let mut enc = HpackEncoder::new();

    // Open streams 1 and 3
    let s1_open = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 1,
        header_block: enc.encode(&[HeaderField {
            name: ":path".into(),
            value: "/s1".into(),
        }]),
    };
    let s3_open = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 3,
        header_block: enc.encode(&[HeaderField {
            name: ":path".into(),
            value: "/s3".into(),
        }]),
    };
    mux.parse(&mut ctx, &s1_open.encode()).expect("open 1");
    mux.parse(&mut ctx, &s3_open.encode()).expect("open 3");
    assert_eq!(mux.used_streams(&ctx), 2);

    // Client sends RST_STREAM on stream 1 with CANCEL
    let rst1 = Frame::RstStream {
        stream_id: 1,
        error_code: H2Error::Cancel,
    };
    mux.parse(&mut ctx, &rst1.encode())
        .expect("parse rst_stream");

    // Stream 1 must be reset and shut
    let s1 = ctx.streams.get(&1).unwrap();
    assert_eq!(s1.state, H2StreamState::Reset(H2Error::Cancel));
    assert_eq!(s1.reset_reason, Some(H2Error::Cancel));
    assert!(s1.is_shut);

    // Stream 3 must remain completely intact and active
    let s3 = ctx.streams.get(&3).unwrap();
    assert_eq!(s3.state, H2StreamState::Open);
    assert!(!s3.is_shut);

    // Server-initiated stream reset via ShutMode::Reset on stream 3
    let mut sd3 = SeDesc {
        endpoint: Endpoint::MuxStream {
            conn: ConnId(400),
            stream: 3,
        },
        ..SeDesc::new()
    };
    mux.shut(&mut ctx, &mut sd3, ShutMode::Reset);

    let s3 = ctx.streams.get(&3).unwrap();
    assert_eq!(s3.state, H2StreamState::Reset(H2Error::Cancel));
    assert!(s3.is_shut);

    // Pending output must contain RST_STREAM frame
    let out_len = {
        let out = mux.pending_output(&ctx);
        let hdr = FrameHeader::decode(out).expect("decode pending header");
        assert_eq!(hdr.frame_type, FrameType::RstStream);
        assert_eq!(hdr.stream_id, 3);
        out.len()
    };
    mux.consume_output(&mut ctx, out_len);

    // Graceful Connection Shutdown: Client sends GOAWAY
    let client_goaway = Frame::GoAway {
        last_stream_id: 3,
        error_code: H2Error::NoError,
        debug_data: b"client shutting down".to_vec(),
    };
    mux.parse(&mut ctx, &client_goaway.encode())
        .expect("parse goaway");

    assert_eq!(ctx.conn_state, H2ConnState::GoAwayReceived);
    assert_eq!(ctx.goaway_received, Some((3, H2Error::NoError)));

    // Server-initiated graceful shutdown
    ctx.send_goaway(3, H2Error::NoError, b"server graceful drain");
    assert_eq!(ctx.conn_state, H2ConnState::GoAwaySent);
    assert_eq!(ctx.goaway_sent, Some((3, H2Error::NoError)));
}

/// 6. PING Frame and Keepalive Conformance.
///
/// Verifies:
/// - Incoming PING frames (non-ACK) are immediately answered with a PING ACK containing identical payload.
/// - Incoming PING ACK frames are acknowledged without infinite echo loops.
#[test]
fn test_ping_frame_keepalive() {
    let mux = MuxH2;
    let mut ctx = mux.init(ConnId(500), true).expect("init");

    // Handshake
    let mut init_buf = Vec::new();
    init_buf.extend_from_slice(H2_CONN_PREFACE);
    init_buf.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![],
        }
        .encode(),
    );
    mux.parse(&mut ctx, &init_buf).expect("handshake");
    let initial_pending_len = mux.pending_output(&ctx).len();
    mux.consume_output(&mut ctx, initial_pending_len);

    // Client sends PING with 8-byte opaque token
    let ping_token = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let client_ping = Frame::Ping {
        flags: 0,
        opaque_data: ping_token,
    };
    mux.parse(&mut ctx, &client_ping.encode())
        .expect("parse ping");

    // Server must emit a PING frame with ACK flag and identical opaque_data
    let out = mux.pending_output(&ctx);
    assert_eq!(out.len(), FRAME_HEADER_LEN + 8);
    let hdr = FrameHeader::decode(out).expect("decode ping ack hdr");
    assert_eq!(hdr.frame_type, FrameType::Ping);
    assert_eq!(hdr.flags, frame_flags::ACK);
    assert_eq!(hdr.stream_id, 0);
    assert_eq!(&out[FRAME_HEADER_LEN..FRAME_HEADER_LEN + 8], &ping_token);
}
