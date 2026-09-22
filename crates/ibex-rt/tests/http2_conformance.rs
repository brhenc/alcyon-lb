// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 Runtime Conformance and Multiplexing Test Suite.
//!
//! Verifies HTTP/2 protocol conformance over live TCP loopback sockets under `#![forbid(unsafe_code)]`.
//! Tests cover:
//! 1. Connection preface exchange (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + `SETTINGS` frame with ACK).
//! 2. Concurrent stream multiplexing over a single connection (streams 1, 3, 5, 7, etc.).
//! 3. HPACK header compression and decompression verification with dynamic table mutations.
//! 4. Stream and connection level flow control (`WINDOW_UPDATE`) when payload exceeds initial window.
//! 5. Stream reset (`RST_STREAM`) handling and graceful connection shutdown (`GOAWAY`).

#![forbid(unsafe_code)]

use ibex_proto::conn::ConnId;
use ibex_proto::endpoint::{Endpoint, SeDesc};
use ibex_proto::h2::{
    frame_flags, Frame, FrameHeader, H2ConnState, H2Error, H2StreamState, SettingsParameter,
    FRAME_HEADER_LEN, H2_CONN_PREFACE,
};
use ibex_proto::hpack::HpackEncoder;
use ibex_proto::htx::{HeaderField, HttpMethod};
use ibex_proto::mux::Mux;
use ibex_proto::mux_h2::MuxH2;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Helper to set up a loopback non-blocking/blocking TCP socket pair for testing.
fn setup_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let client = TcpStream::connect(addr).expect("connect client");
    let (server, _) = listener.accept().expect("accept server");

    client.set_nodelay(true).unwrap();
    server.set_nodelay(true).unwrap();

    (client, server)
}

/// 1. Connection Preface Exchange and SETTINGS negotiation over live TCP socket.
#[test]
fn test_rt_http2_socket_preface_and_settings_exchange() {
    let (mut client_sock, mut server_sock) = setup_tcp_pair();
    let mux = MuxH2;
    let mut server_ctx = mux.init(ConnId(1), true).expect("init server mux");

    // Client sends preface + client initial SETTINGS
    let mut client_bytes = Vec::new();
    client_bytes.extend_from_slice(H2_CONN_PREFACE);
    let client_settings = Frame::Settings {
        flags: 0,
        settings: vec![
            (SettingsParameter::MaxConcurrentStreams, 100),
            (SettingsParameter::InitialWindowSize, 65535),
        ],
    };
    client_bytes.extend_from_slice(&client_settings.encode());
    client_sock
        .write_all(&client_bytes)
        .expect("client write preface");

    // Server reads from socket into staging buffer and parses
    let mut buf = [0u8; 1024];
    let n = server_sock.read(&mut buf).expect("server read preface");
    assert!(n >= H2_CONN_PREFACE.len());

    mux.parse(&mut server_ctx, &buf[..n])
        .expect("server parse preface");
    assert_eq!(server_ctx.conn_state, H2ConnState::Open);

    // Server flushes response frames (server SETTINGS + server SETTINGS ACK) back through socket
    let pending = mux.pending_output(&server_ctx);
    assert!(!pending.is_empty());
    let pending_len = pending.len();
    server_sock
        .write_all(pending)
        .expect("server write settings");
    mux.consume_output(&mut server_ctx, pending_len);

    // Client receives server SETTINGS and SETTINGS ACK
    let mut client_rx = [0u8; 1024];
    let crx_len = client_sock
        .read(&mut client_rx)
        .expect("client read settings");
    assert!(crx_len >= FRAME_HEADER_LEN * 2);

    // Parse server frames from client side
    let mut off = 0;
    let mut saw_settings = false;
    let mut saw_ack = false;
    while off + FRAME_HEADER_LEN <= crx_len {
        let hdr = FrameHeader::decode(&client_rx[off..]).expect("decode hdr");
        let end = off + FRAME_HEADER_LEN + hdr.length as usize;
        let frame =
            Frame::decode(&hdr, &client_rx[off + FRAME_HEADER_LEN..end]).expect("decode frame");
        if let Frame::Settings { flags, .. } = frame {
            if (flags & frame_flags::ACK) != 0 {
                saw_ack = true;
            } else {
                saw_settings = true;
            }
        }
        off = end;
    }

    assert!(saw_settings, "Client must receive server SETTINGS");
    assert!(saw_ack, "Client must receive server SETTINGS ACK");

    // Client sends SETTINGS ACK to complete negotiation
    let client_ack = Frame::Settings {
        flags: frame_flags::ACK,
        settings: Vec::new(),
    };
    client_sock
        .write_all(&client_ack.encode())
        .expect("client send ack");

    let ack_n = server_sock.read(&mut buf).expect("server read ack");
    mux.parse(&mut server_ctx, &buf[..ack_n])
        .expect("server parse ack");
    assert!(server_ctx.settings_ack_received);
}

/// 2. Concurrent Stream Multiplexing over a live TCP connection (Streams 1, 3, 5, 7).
#[test]
fn test_rt_http2_socket_multiplexing_concurrent_streams() {
    let (mut client_sock, mut server_sock) = setup_tcp_pair();
    let mux = MuxH2;
    let mut server_ctx = mux.init(ConnId(2), true).expect("init");

    // Handshake
    let mut init = Vec::new();
    init.extend_from_slice(H2_CONN_PREFACE);
    init.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![],
        }
        .encode(),
    );
    client_sock.write_all(&init).unwrap();

    let mut buf = [0u8; 4096];
    let n = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..n]).unwrap();
    let srv_pending_len = mux.pending_output(&server_ctx).len();
    mux.consume_output(&mut server_ctx, srv_pending_len);

    let mut enc = HpackEncoder::new();

    // Prepare requests for streams 1, 3, 5, 7
    let stream_ids = [1u32, 3, 5, 7];
    let mut wire_batch = Vec::new();

    for &sid in &stream_ids {
        let headers = vec![
            HeaderField {
                name: ":method".into(),
                value: "GET".into(),
            },
            HeaderField {
                name: ":path".into(),
                value: format!("/item/{sid}"),
            },
        ];
        let frame = Frame::Headers {
            flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
            stream_id: sid,
            header_block: enc.encode(&headers),
        };
        wire_batch.extend_from_slice(&frame.encode());
    }

    // Client writes all 4 multiplexed streams in a single socket burst
    client_sock.write_all(&wire_batch).unwrap();

    let rn = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..rn]).unwrap();

    // Verify all 4 streams exist in server context concurrently
    assert_eq!(mux.used_streams(&server_ctx), 4);
    for &sid in &stream_ids {
        let stream = server_ctx.streams.get(&sid).expect("stream exists");
        assert_eq!(stream.state, H2StreamState::HalfClosedRemote);
        assert_eq!(stream.rx_htx.req_line().unwrap().method, HttpMethod::Get);
        assert_eq!(
            stream.rx_htx.req_line().unwrap().uri,
            format!("/item/{sid}")
        );

        // Verify rcv_buf read
        let mut sd = SeDesc {
            endpoint: Endpoint::MuxStream {
                conn: ConnId(2),
                stream: sid,
            },
            ..SeDesc::new()
        };
        let mut out = [0u8; 256];
        let rcv_len = mux.rcv_buf(&mut server_ctx, &mut sd, &mut out).unwrap();
        assert!(rcv_len > 0);
        let out_str = std::str::from_utf8(&out[..rcv_len]).unwrap();
        assert!(out_str.contains(&format!("/item/{sid}")));
    }
}

/// 3. HPACK Header Compression and Dynamic Table Mutations over TCP socket.
#[test]
fn test_rt_http2_hpack_dynamic_table_socket_pipeline() {
    let (mut client_sock, mut server_sock) = setup_tcp_pair();
    let mux = MuxH2;
    let mut server_ctx = mux.init(ConnId(3), true).expect("init");

    // Handshake
    let mut init = Vec::new();
    init.extend_from_slice(H2_CONN_PREFACE);
    init.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![],
        }
        .encode(),
    );
    client_sock.write_all(&init).unwrap();

    let mut buf = [0u8; 4096];
    let n = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..n]).unwrap();
    let srv_pending_len = mux.pending_output(&server_ctx).len();
    mux.consume_output(&mut server_ctx, srv_pending_len);

    let mut enc = HpackEncoder::new();

    // Request 1: New custom headers (mutates dynamic table)
    let req1_headers = vec![
        HeaderField {
            name: ":method".into(),
            value: "GET".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/index".into(),
        },
        HeaderField {
            name: "x-api-key".into(),
            value: "secret-key-12345".into(),
        },
    ];
    let frame1 = Frame::Headers {
        flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
        stream_id: 1,
        header_block: enc.encode(&req1_headers),
    };
    client_sock.write_all(&frame1.encode()).unwrap();

    let n1 = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..n1]).unwrap();

    // Verify server's decoder table contains 2 entries (:path and x-api-key)
    assert_eq!(server_ctx.decoder.dynamic_table.len(), 2);
    assert_eq!(
        server_ctx.decoder.dynamic_table.get(0).unwrap().name,
        "x-api-key"
    );
    assert_eq!(
        server_ctx.decoder.dynamic_table.get(0).unwrap().value,
        "secret-key-12345"
    );
    assert_eq!(
        server_ctx.decoder.dynamic_table.get(1).unwrap().name,
        ":path"
    );
    assert_eq!(
        server_ctx.decoder.dynamic_table.get(1).unwrap().value,
        "/index"
    );

    // Request 2: Reuses x-api-key (encoded with compact 1-byte index)
    let req2_headers = vec![
        HeaderField {
            name: ":method".into(),
            value: "GET".into(),
        },
        HeaderField {
            name: ":path".into(),
            value: "/status".into(),
        },
        HeaderField {
            name: "x-api-key".into(),
            value: "secret-key-12345".into(),
        },
    ];
    let frame2_block = enc.encode(&req2_headers);
    let frame2 = Frame::Headers {
        flags: frame_flags::END_HEADERS | frame_flags::END_STREAM,
        stream_id: 3,
        header_block: frame2_block,
    };
    client_sock.write_all(&frame2.encode()).unwrap();

    let n2 = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..n2]).unwrap();

    let st3 = server_ctx.streams.get(&3).expect("stream 3 exists");
    assert_eq!(st3.rx_htx.get_header("x-api-key"), Some("secret-key-12345"));
}

/// 4. Flow Control (`WINDOW_UPDATE`) when payload exceeds initial window over socket.
#[test]
fn test_rt_http2_socket_flow_control_window_update() {
    let (mut client_sock, mut server_sock) = setup_tcp_pair();
    let mux = MuxH2;
    let mut server_ctx = mux.init(ConnId(4), true).expect("init");

    // Handshake: client configures small initial window of 2,048 octets
    let mut init = Vec::new();
    init.extend_from_slice(H2_CONN_PREFACE);
    init.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![(SettingsParameter::InitialWindowSize, 2048)],
        }
        .encode(),
    );
    client_sock.write_all(&init).unwrap();

    let mut buf = [0u8; 8192];
    let n = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..n]).unwrap();
    let srv_pending_len = mux.pending_output(&server_ctx).len();
    mux.consume_output(&mut server_ctx, srv_pending_len);

    assert_eq!(server_ctx.remote_initial_window, 2048);

    // Client opens stream 1
    let mut enc = HpackEncoder::new();
    let open_frame = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 1,
        header_block: enc.encode(&[HeaderField {
            name: ":path".into(),
            value: "/data".into(),
        }]),
    };
    client_sock.write_all(&open_frame.encode()).unwrap();
    let on = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..on]).unwrap();

    // Server sends 5,000 bytes (exceeds window of 2,048)
    let payload = vec![0xAAu8; 5000];
    let mut sd = SeDesc {
        endpoint: Endpoint::MuxStream {
            conn: ConnId(4),
            stream: 1,
        },
        ..SeDesc::new()
    };

    let sent1 = mux.snd_buf(&mut server_ctx, &mut sd, &payload).unwrap();
    assert_eq!(sent1, 2048, "Must only transmit up to initial window size");

    // Window is now exhausted
    let sent2 = mux
        .snd_buf(&mut server_ctx, &mut sd, &payload[2048..])
        .unwrap();
    assert_eq!(sent2, 0, "Further sends must stall while window is 0");

    // Server transmits the 2048 bytes over socket
    let out = mux.pending_output(&server_ctx);
    let out_len = out.len();
    server_sock.write_all(out).unwrap();
    mux.consume_output(&mut server_ctx, out_len);

    // Client reads the DATA frame over socket
    let mut client_data_buf = [0u8; 4096];
    let cr = client_sock.read(&mut client_data_buf).unwrap();
    assert!(cr >= FRAME_HEADER_LEN + 2048);

    // Client replenishes stream window by 4,096 bytes via WINDOW_UPDATE frame
    let win_up = Frame::WindowUpdate {
        stream_id: 1,
        increment: 4096,
    };
    client_sock.write_all(&win_up.encode()).unwrap();

    let wn = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..wn]).unwrap();

    // Server stream window is now 4,096; remaining 2,952 bytes can be transmitted
    let sent3 = mux
        .snd_buf(&mut server_ctx, &mut sd, &payload[2048..])
        .unwrap();
    assert_eq!(
        sent3, 2952,
        "Remaining payload is transmitted after WINDOW_UPDATE"
    );
}

/// 5. Stream Reset (`RST_STREAM`) and Graceful Shutdown (`GOAWAY`) over live TCP socket.
#[test]
fn test_rt_http2_socket_stream_reset_and_goaway() {
    let (mut client_sock, mut server_sock) = setup_tcp_pair();
    let mux = MuxH2;
    let mut server_ctx = mux.init(ConnId(5), true).expect("init");

    // Handshake
    let mut init = Vec::new();
    init.extend_from_slice(H2_CONN_PREFACE);
    init.extend_from_slice(
        &Frame::Settings {
            flags: 0,
            settings: vec![],
        }
        .encode(),
    );
    client_sock.write_all(&init).unwrap();

    let mut buf = [0u8; 4096];
    let n = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..n]).unwrap();
    let srv_pending_len = mux.pending_output(&server_ctx).len();
    mux.consume_output(&mut server_ctx, srv_pending_len);

    let mut enc = HpackEncoder::new();

    // Open streams 1 and 3
    let s1 = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 1,
        header_block: enc.encode(&[HeaderField {
            name: ":path".into(),
            value: "/s1".into(),
        }]),
    };
    let s3 = Frame::Headers {
        flags: frame_flags::END_HEADERS,
        stream_id: 3,
        header_block: enc.encode(&[HeaderField {
            name: ":path".into(),
            value: "/s3".into(),
        }]),
    };
    client_sock.write_all(&s1.encode()).unwrap();
    client_sock.write_all(&s3.encode()).unwrap();

    let open_n = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..open_n]).unwrap();
    assert_eq!(mux.used_streams(&server_ctx), 2);

    // Client resets stream 1 with RST_STREAM (CANCEL)
    let rst = Frame::RstStream {
        stream_id: 1,
        error_code: H2Error::Cancel,
    };
    client_sock.write_all(&rst.encode()).unwrap();

    let rst_n = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..rst_n]).unwrap();

    // Stream 1 is reset; Stream 3 remains active
    let st1 = server_ctx.streams.get(&1).unwrap();
    assert_eq!(st1.state, H2StreamState::Reset(H2Error::Cancel));
    assert!(st1.is_shut);

    let st3 = server_ctx.streams.get(&3).unwrap();
    assert_eq!(st3.state, H2StreamState::Open);
    assert!(!st3.is_shut);

    // Client initiates graceful GOAWAY shutdown
    let goaway = Frame::GoAway {
        last_stream_id: 3,
        error_code: H2Error::NoError,
        debug_data: b"normal shutdown".to_vec(),
    };
    client_sock.write_all(&goaway.encode()).unwrap();

    let ga_n = server_sock.read(&mut buf).unwrap();
    mux.parse(&mut server_ctx, &buf[..ga_n]).unwrap();

    assert_eq!(server_ctx.conn_state, H2ConnState::GoAwayReceived);
    assert_eq!(server_ctx.goaway_received, Some((3, H2Error::NoError)));
}
