// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The HTTP/3 mux (`H3MuxContext`, T503) from frame vectors: what a client's request and
//! unidirectional streams become (HTX, a stream error, a connection error), and the frames
//! a response is encoded to. Expected codes are the oracle's (`HAProxy` 3.5-dev7 + QUIC,
//! `docs/design/h3-engine-2026-10-26.md` section 8, and `tasks/T503-progress.md` for the rows
//! measured in this task); where only `h3.c`/`qpack-dec.c` say, the line is cited.

use ibex_proto::h3::{parse_varint, H3Error};
use ibex_proto::htx::HtxBlock;
use ibex_proto::htx_mux::{HtxMux, HtxStream, MuxReset};
use ibex_proto::mux_h3::{self, H3MuxContext, H3Signal, H3StreamState, RX_DATA_ROOM, TX_ROOM};
use ibex_proto::qpack;

const DATA: u64 = 0x00;
const HEADERS: u64 = 0x01;
const SETTINGS: u64 = 0x04;
const GOAWAY: u64 = 0x07;

fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    mux_h3::encode_frame(&mut v, ty, payload);
    v
}

fn fields(f: &[(&str, &str)]) -> Vec<u8> {
    let f: Vec<(String, String)> = f.iter().map(|(n, v)| ((*n).to_string(), (*v).to_string())).collect();
    mux_h3::encode_field_section(&f)
}

fn headers(f: &[(&str, &str)]) -> Vec<u8> {
    frame(HEADERS, &fields(f))
}

const GET: &[(&str, &str)] = &[(":method", "GET"), (":scheme", "https"), (":authority", "localhost"), (":path", "/plain")];

fn post(extra: &[(&str, &str)]) -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> =
        vec![(":method", "POST".into()), (":scheme", "https".into()), (":authority", "localhost".into()), (":path", "/up".into())];
    for (n, val) in extra {
        v.push((Box::leak((*n).to_string().into_boxed_str()), (*val).to_string()));
    }
    v
}

fn headers_owned(f: &[(&'static str, String)]) -> Vec<u8> {
    let f: Vec<(&str, &str)> = f.iter().map(|(n, v)| (*n, v.as_str())).collect();
    headers(&f)
}

fn frames(mut b: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let mut off = 0;
        let ty = parse_varint(b, &mut off).expect("type");
        let len = parse_varint(b, &mut off).expect("len") as usize;
        out.push((ty, b[off..off + len].to_vec()));
        b = &b[off + len..];
    }
    out
}

fn decoded(fs: &[u8]) -> Vec<(String, String)> {
    qpack::decode_qpack_static(fs).expect("decodes").into_iter().map(|f| (f.name, f.value)).collect()
}

fn signals(m: &mut H3MuxContext) -> Vec<H3Signal> {
    std::iter::from_fn(|| m.take_signal()).collect()
}

fn mux() -> H3MuxContext {
    let mut m = H3MuxContext::new();
    m.open_control(3);
    m
}

/// A client control stream with its SETTINGS, on stream 2.
fn with_settings(m: &mut H3MuxContext) {
    let mut b = vec![0x00];
    b.extend(frame(SETTINGS, &[]));
    m.recv(2, &b, false, 0).expect("settings");
}

/// The stream's error codes as signals: (stop sending, reset).
fn stream_error(sig: &[H3Signal], id: u64) -> Option<u64> {
    let stop = sig.iter().find_map(|s| match *s {
        H3Signal::StopSending { id: i, code } if i == id => Some(code),
        _ => None,
    });
    let reset = sig.iter().find_map(|s| match *s {
        H3Signal::ResetStream { id: i, code } if i == id => Some(code),
        _ => None,
    });
    assert_eq!(stop, reset, "a stream error aborts the read and resets the stream with one code, as qcc_abort_stream_read + qcc_reset_stream");
    reset
}

#[test]
fn a_get_becomes_a_head_and_the_end_of_the_message() {
    let mut m = mux();
    m.recv(0, &headers(GET), true, 7).expect("request");
    assert_eq!(m.next_dispatch(), Some(0));
    let st = m.stream(0).expect("stream");
    assert_eq!(st.rx_htx().blocks(), &[HtxBlock::Eoh, HtxBlock::Eom]);
    assert_eq!(st.state, H3StreamState::HalfClosedRemote);
    assert_eq!(st.known_body, Some(0), "FIN with the head: bodyless");
    let head = st.req_head().expect("head");
    assert_eq!(head.method(), "GET");
    assert_eq!(head.uri(), "/plain");
    assert_eq!(head.get_header("host"), Some(&b"localhost"[..]));
    assert_eq!(head.abs_prefix(), Some("https://localhost"));
    assert_eq!(signals(&mut m), vec![]);
    assert_eq!(m.head_partial(), None);
    assert_eq!(m.next_request, 4, "GOAWAY id: the stream after the last one opened");
}

#[test]
fn a_head_in_pieces_waits_and_arms_the_http_request_timer() {
    let mut m = mux();
    let req = headers(GET);
    for (i, b) in req.iter().enumerate() {
        assert!(m.next_dispatch().is_none(), "byte {i}: no head yet");
        m.recv(0, std::slice::from_ref(b), false, 100 + i as u64).expect("piece");
        if i + 1 < req.len() {
            assert_eq!(m.head_partial(), Some(100), "the oldest partial head's start");
        }
    }
    assert_eq!(m.next_dispatch(), Some(0));
    assert_eq!(m.head_partial(), None);
    assert_eq!(m.stream(0).expect("stream").known_body, None, "no FIN yet: length unknown");
    m.recv(0, &[], true, 200).expect("fin");
    assert!(m.stream(0).expect("stream").rx_htx().is_eom());
}

#[test]
fn a_body_is_held_to_one_buffer_and_the_rest_waits_in_the_transport() {
    let mut m = mux();
    let body = vec![b'x'; RX_DATA_ROOM + 5000];
    m.recv(0, &headers_owned(&post(&[("content-length", &body.len().to_string())])), false, 0).expect("head");
    let mut df = Vec::new();
    mux_h3::encode_varint(&mut df, DATA);
    mux_h3::encode_varint(&mut df, body.len() as u64);
    m.recv(0, &df, false, 0).expect("data header");
    // The owner reads only what the stream has room for; the rest stays in quinn.
    let mut sent = 0;
    while m.rx_room(0) > 0 && sent < body.len() {
        let n = m.rx_room(0).min(body.len() - sent).min(1000);
        m.recv(0, &body[sent..sent + n], false, 0).expect("body");
        sent += n;
    }
    let st = m.stream(0).expect("stream");
    assert_eq!(st.rx_buffered, RX_DATA_ROOM, "the HTX holds one buffer of DATA");
    assert!(sent < body.len(), "the rest of the body was not read");
    let data: usize = st.rx_htx().blocks().iter().map(|b| if let HtxBlock::Data(d) = b { d.len() } else { 0 }).sum();
    assert_eq!(data, RX_DATA_ROOM);
    // The child takes it all: room again, and what waited in rx goes on.
    m.rx_taken(0, RX_DATA_ROOM);
    m.stream_mut(0).expect("stream").rx_htx_mut().clear();
    assert!(m.rx_room(0) > 0);
    m.recv(0, &body[sent..], true, 0).expect("rest");
    let st = m.stream(0).expect("stream");
    assert_eq!(st.rx_buffered, body.len() - RX_DATA_ROOM);
    assert!(st.rx_htx().is_eom());
    assert_eq!(signals(&mut m), vec![]);
}

#[test]
fn request_trailers_become_trailer_blocks() {
    let mut m = mux();
    let mut b = headers_owned(&post(&[]));
    b.extend(frame(DATA, b"abc"));
    b.extend(headers(&[("x-t", "1")]));
    m.recv(0, &b, true, 0).expect("request");
    let st = m.stream(0).expect("stream");
    assert_eq!(
        st.rx_htx().blocks(),
        &[
            HtxBlock::Eoh,
            HtxBlock::Data(b"abc".to_vec()),
            HtxBlock::Trailer(ibex_proto::htx::HeaderField { name: "x-t".into(), value: "1".into() }),
            HtxBlock::Eot,
            HtxBlock::Eom
        ]
    );
    assert_eq!(st.known_body, Some(3), "the whole request came with its head: its length is known");
}

#[test]
fn trailers_with_a_pseudo_header_are_a_message_error() {
    let mut m = mux();
    let mut b = headers_owned(&post(&[]));
    b.extend(frame(DATA, b"abc"));
    b.extend(headers(&[(":path", "/x")]));
    m.recv(0, &b, true, 0).expect("stream error only");
    assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10e));
    assert!(m.stream(0).is_none(), "an undispatched stream in error is let go");
}

#[test]
fn connect_is_rejected_on_its_stream_and_the_connection_goes_on() {
    // Oracle: [RESET 4 0x10b], connection stays open (design section 8).
    let mut m = mux();
    m.recv(0, &headers(&[(":method", "CONNECT"), (":authority", "localhost:443")]), false, 0).expect("stream error only");
    assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10b));
    assert!(m.stream(0).is_none() && m.next_dispatch().is_none());
    assert!(m.error.is_none());
    // Later bytes of the rejected stream are dropped, not a new stream.
    m.recv(0, &frame(DATA, b"zz"), true, 0).expect("ignored");
    assert!(m.stream(0).is_none());
    m.recv(4, &headers(GET), true, 0).expect("next request");
    assert_eq!(m.next_dispatch(), Some(4));
}

#[test]
fn extended_connect_is_a_message_error() {
    // Oracle: [RESET 4 0x10e] for :method CONNECT with :protocol websocket.
    let mut m = mux();
    let req = [(":method", "CONNECT"), (":scheme", "https"), (":authority", "localhost"), (":path", "/ws"), (":protocol", "websocket")];
    m.recv(0, &headers(&req), false, 0).expect("stream error only");
    assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10e));
}

#[test]
fn malformed_requests_are_message_errors() {
    let cases: &[(&str, Vec<(&str, &str)>)] = &[
        ("no :path", vec![(":method", "GET"), (":scheme", "https"), (":authority", "a")]),
        ("no :scheme", vec![(":method", "GET"), (":authority", "a"), (":path", "/")]),
        ("unknown pseudo-header", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), (":x", "1")]),
        ("connection header", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), ("connection", "close")]),
        ("te other than trailers", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), ("te", "gzip")]),
        ("bad content-length", vec![(":method", "GET"), (":scheme", "https"), (":path", "/"), ("content-length", "+5")]),
        ("pseudo after regular", vec![(":method", "GET"), ("x", "1"), (":scheme", "https"), (":path", "/")]),
        // Measured on 3.5-dev7 (T509, aioquic): RESET_STREAM 0x10e, nothing to the server.
        ("neither :authority nor host", vec![(":method", "GET"), (":scheme", "https"), (":path", "/")]),
    ];
    for (what, f) in cases {
        let mut m = mux();
        m.recv(0, &headers(f), true, 0).expect("stream error only");
        assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10e), "{what}");
        assert!(m.glitch_count > 0, "{what}: a glitch, as qcc_report_glitch");
    }
    // `te: trailers` is the one value allowed (h3.c:1123).
    let mut m = mux();
    m.recv(0, &headers(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), ("host", "a"), ("te", "trailers")]), true, 0).expect("ok");
    assert_eq!(m.next_dispatch(), Some(0));
    // A method or a scheme that is not a token, which h2 takes and answers 400, is a message
    // error over h3: measured on 3.5-dev7 (T509, aioquic), `G(T`, `G E T`, an empty
    // method, `ht tp` and an empty scheme each RESET_STREAM 0x10e.
    for (what, f) in [
        ("method G(T", [(":method", "G(T"), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
        ("method G E T", [(":method", "G E T"), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
        ("empty method", [(":method", ""), (":scheme", "https"), (":path", "/"), (":authority", "a")]),
        ("scheme ht tp", [(":method", "GET"), (":scheme", "ht tp"), (":path", "/"), (":authority", "a")]),
        ("empty scheme", [(":method", "GET"), (":scheme", ""), (":path", "/"), (":authority", "a")]),
    ] {
        let mut m = mux();
        m.recv(0, &headers(&f), true, 0).expect("stream error only");
        assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10e), "{what}");
    }
}

#[test]
fn a_body_against_its_content_length_is_a_message_error() {
    for (cl, body, fin) in [("5", &b"abc"[..], true), ("2", &b"abc"[..], false), ("1", &b""[..], true)] {
        let mut m = mux();
        let mut b = headers_owned(&post(&[("content-length", cl)]));
        if !body.is_empty() {
            b.extend(frame(DATA, body));
        }
        m.recv(0, &b, fin, 0).expect("stream error only");
        assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10e), "content-length {cl}, body {body:?}");
    }
}

#[test]
fn frame_sequence_errors_close_the_connection() {
    // Measured on 3.5-dev7: DATA before HEADERS closes with 0x105.
    let mut m = mux();
    assert_eq!(m.recv(0, &frame(DATA, b"hi"), true, 0), Err(H3Error::FrameUnexpected));
    assert_eq!(m.error, Some(H3Error::FrameUnexpected));
    assert_eq!(m.recv(4, &headers(GET), true, 0), Err(H3Error::FrameUnexpected), "nothing more after a connection error");

    // HEADERS after the trailers (RFC 9114 section 4.1, h3.c:418).
    let mut m = mux();
    let mut b = headers_owned(&post(&[]));
    b.extend(headers(&[("x-t", "1")]));
    b.extend(headers(&[("x-t", "2")]));
    assert_eq!(m.recv(0, &b, false, 0), Err(H3Error::FrameUnexpected));

    // SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, PUSH_PROMISE on a request stream.
    for ty in [0x04, 0x07, 0x0d, 0x03, 0x05] {
        let mut m = mux();
        assert_eq!(m.recv(0, &frame(ty, &[0]), false, 0), Err(H3Error::FrameUnexpected), "frame {ty:#x}");
    }

    // A frame other than DATA past bufsize - 4, from its header (h3.c:2050).
    let mut m = mux();
    let mut b = Vec::new();
    mux_h3::encode_varint(&mut b, HEADERS);
    mux_h3::encode_varint(&mut b, 16381);
    assert_eq!(m.recv(0, &b, false, 0), Err(H3Error::ExcessiveLoad));

    // A frame cut by the FIN (h3.c:2029), DATA or not.
    let mut m = mux();
    let mut b = headers_owned(&post(&[]));
    b.extend(&frame(DATA, b"abcdef")[..4]);
    assert_eq!(m.recv(0, &b, true, 0), Err(H3Error::FrameError));
    let mut m = mux();
    assert_eq!(m.recv(0, &headers(GET)[..3], true, 0), Err(H3Error::FrameError));

    // A field section that refers to the dynamic table (qpack-dec.c:302).
    let mut m = mux();
    assert_eq!(m.recv(0, &frame(HEADERS, &[0x01, 0x00, 0xd1]), true, 0), Err(H3Error::QpackDecompressionFailed));
}

#[test]
fn unknown_frames_are_skipped_but_not_in_place_of_the_head() {
    let mut m = mux();
    let mut b = frame(0x21, b"grease");
    b.extend(frame(0x02, b"h2 priority"));
    b.extend(headers(GET));
    b.extend(frame(0x21, b""));
    m.recv(0, &b, true, 0).expect("request");
    assert_eq!(m.next_dispatch(), Some(0));
    // A stream that ends with only an unknown frame has no head: a message error (h3.c:2215).
    let mut m = mux();
    m.recv(0, &frame(0x21, b"x"), true, 0).expect("stream error only");
    assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10e));
}

#[test]
fn the_control_stream_rules() {
    // Ours: the stream type, then SETTINGS 0x1 = 0, 0x7 = 0, 0x6 = 65536.
    let m = mux();
    assert_eq!(m.control_out, Some(3));
    let ctl = m.tx_bytes(3);
    assert_eq!(ctl[0], 0x00, "control stream type");
    let f = frames(&ctl[1..]);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].0, SETTINGS);
    let mut at = 0;
    let mut kv = Vec::new();
    while at < f[0].1.len() {
        kv.push((parse_varint(&f[0].1, &mut at).unwrap(), parse_varint(&f[0].1, &mut at).unwrap()));
    }
    assert_eq!(kv, vec![(0x1, 0), (0x7, 0), (0x6, 65536)]);

    let open = |b: &[u8]| {
        let mut m = mux();
        let mut v = vec![0x00];
        v.extend_from_slice(b);
        let r = m.recv(2, &v, false, 0);
        (m, r)
    };
    let (m, r) = open(&frame(SETTINGS, &[0x21, 0x01, 0x06, 0x40, 0x64]));
    assert_eq!(r, Ok(()));
    assert!(m.settings_recv);
    assert_eq!(open(&frame(0x21, b"")).1, Err(H3Error::MissingSettings), "an unknown frame before SETTINGS (h3.c:479)");
    assert_eq!(open(&frame(GOAWAY, &[0])).1, Err(H3Error::MissingSettings));
    assert_eq!(open(&frame(DATA, b"")).1, Err(H3Error::FrameUnexpected));
    let mut two = frame(SETTINGS, &[]);
    two.extend(frame(SETTINGS, &[]));
    assert_eq!(open(&two).1, Err(H3Error::FrameUnexpected), "a second SETTINGS");
    assert_eq!(open(&frame(SETTINGS, &[0x02, 0x00])).1, Err(H3Error::SettingsError), "an HTTP/2 setting id");
    assert_eq!(open(&frame(SETTINGS, &[0x01, 0x00, 0x01, 0x00])).1, Err(H3Error::SettingsError), "a duplicate");
    assert_eq!(open(&frame(SETTINGS, &[0x01])).1, Err(H3Error::FrameError), "a truncated pair");
    let mut big = Vec::new();
    mux_h3::encode_varint(&mut big, SETTINGS);
    mux_h3::encode_varint(&mut big, 16381);
    assert_eq!(open(&big).1, Err(H3Error::ExcessiveLoad));

    let mut after = frame(SETTINGS, &[]);
    after.extend(frame(0x0d, &[0x05]));
    after.extend(frame(0x21, b"grease"));
    after.extend(frame(GOAWAY, &[0x08]));
    let (mut m, r) = open(&after);
    assert_eq!(r, Ok(()), "MAX_PUSH_ID and unknown frames are skipped");
    assert_eq!(m.goaway_recv, Some(8));
    assert_eq!(m.recv(2, &frame(GOAWAY, &[0x04]), false, 0), Ok(()), "a GOAWAY may lower the id");
    assert_eq!(m.recv(2, &frame(GOAWAY, &[0x08]), false, 0), Err(H3Error::IdError), "never raise it (h3.c:1866)");

    let mut bad = frame(SETTINGS, &[]);
    bad.extend(frame(GOAWAY, &[]));
    assert_eq!(open(&bad).1, Err(H3Error::FrameError), "a GOAWAY without its id");
    let mut cp = frame(SETTINGS, &[]);
    cp.extend(frame(0x03, &[0x00]));
    assert_eq!(open(&cp).1, Err(H3Error::IdError), "CANCEL_PUSH from a client (h3.c:2140)");
    let mut cp0 = frame(SETTINGS, &[]);
    cp0.extend(frame(0x03, &[]));
    assert_eq!(open(&cp0).1, Err(H3Error::FrameError));
    let mut mp0 = frame(SETTINGS, &[]);
    mp0.extend(frame(0x0d, &[]));
    assert_eq!(open(&mp0).1, Err(H3Error::FrameError));
    let mut pp = frame(SETTINGS, &[]);
    pp.extend(frame(0x05, &[0x00]));
    assert_eq!(open(&pp).1, Err(H3Error::FrameUnexpected), "PUSH_PROMISE");
    let mut hd = frame(SETTINGS, &[]);
    hd.extend(frame(HEADERS, &[0, 0]));
    assert_eq!(open(&hd).1, Err(H3Error::FrameUnexpected), "HEADERS on the control stream");

    // The control stream closed, or a second one.
    let (mut m, _) = open(&frame(SETTINGS, &[]));
    assert_eq!(m.recv(2, &[], true, 0), Err(H3Error::ClosedCriticalStream));
    let (mut m, _) = open(&frame(SETTINGS, &[]));
    assert_eq!(m.recv(6, &[0x00], false, 0), Err(H3Error::StreamCreationError));
    let (mut m, _) = open(&frame(SETTINGS, &[]));
    assert_eq!(m.on_reset(2, 0x100), Err(H3Error::ClosedCriticalStream));
    // A push stream from a client (h3.c:232).
    let mut m = mux();
    assert_eq!(m.recv(2, &[0x01], false, 0), Err(H3Error::StreamCreationError));
}

#[test]
fn the_qpack_streams_take_capacity_zero_and_nothing_else() {
    // Measured on 3.5-dev7: capacity 0 accepted, the connection serves the next GET;
    // capacity 5 and an insertion close it with 0x201; an Insert Count Increment with
    // 0x202; a Section Acknowledgment is skipped.
    let mut m = mux();
    with_settings(&mut m);
    m.recv(6, &[0x02], false, 0).expect("encoder stream");
    m.recv(10, &[0x03], false, 0).expect("decoder stream");
    m.recv(6, &[0x20, 0x3f], false, 0).expect("capacity 0, then the first byte of a long one");
    assert_eq!(m.recv(6, &[0x00], false, 0), Err(H3Error::QpackEncoderStreamError), "31: not 0");

    let enc = |b: &[u8]| {
        let mut m = mux();
        m.recv(6, &[0x02], false, 0).expect("encoder stream");
        m.recv(6, b, false, 0)
    };
    assert_eq!(enc(&[0x25]), Err(H3Error::QpackEncoderStreamError), "capacity 5");
    assert_eq!(enc(&[0x41, b'a', 0x01, b'b']), Err(H3Error::QpackEncoderStreamError), "insert with a literal name");
    assert_eq!(enc(&[0x80 | 0x11, 0x01, b'b']), Err(H3Error::QpackEncoderStreamError), "insert with a name reference");
    assert_eq!(enc(&[0x00]), Err(H3Error::QpackEncoderStreamError), "duplicate");
    assert_eq!(enc(&[0x20, 0x20]), Ok(()));

    let dec = |b: &[u8]| {
        let mut m = mux();
        m.recv(10, &[0x03], false, 0).expect("decoder stream");
        m.recv(10, b, false, 0)
    };
    assert_eq!(dec(&[0x80, 0x41, 0x7f]), Ok(()), "section ack, stream cancellation, half an instruction");
    assert_eq!(dec(&[0x01]), Err(H3Error::QpackDecoderStreamError), "insert count increment");
    assert_eq!(dec(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]), Err(H3Error::QpackDecoderStreamError), "past 62 bits");

    // Either stream closed, or opened twice (qpack-dec.c:142, h3.c:256).
    let mut m = mux();
    m.recv(6, &[0x02], false, 0).expect("encoder stream");
    assert_eq!(m.recv(6, &[], true, 0), Err(H3Error::ClosedCriticalStream));
    let mut m = mux();
    m.recv(10, &[0x03], false, 0).expect("decoder stream");
    assert_eq!(m.recv(10, &[], true, 0), Err(H3Error::ClosedCriticalStream));
    let mut m = mux();
    m.recv(6, &[0x02], false, 0).expect("encoder stream");
    assert_eq!(m.recv(10, &[0x02], false, 0), Err(H3Error::StreamCreationError));
    let mut m = mux();
    m.recv(6, &[0x03], false, 0).expect("decoder stream");
    assert_eq!(m.recv(10, &[0x03], false, 0), Err(H3Error::StreamCreationError));
}

#[test]
fn an_unknown_unidirectional_stream_is_read_no_more() {
    // h3.c:286: `qcc_abort_stream_read(qcs, H3_ERR_NO_ERROR)`; the connection goes on
    // (measured: the next GET is answered).
    let mut m = mux();
    m.recv(14, &[0x21, b'h', b'i'], false, 0).expect("tolerated");
    assert_eq!(signals(&mut m), vec![H3Signal::StopSending { id: 14, code: 0x100 }]);
    assert!(m.rx_room(14) > 0, "what still comes is read and dropped, so it never holds the window");
    m.recv(14, b"more", true, 0).expect("dropped");
    m.recv(18, &[], false, 0).expect("no type yet");
    m.recv(0, &headers(GET), true, 0).expect("request");
    assert_eq!(m.next_dispatch(), Some(0));
}

#[test]
fn a_response_with_trailers_is_the_oracle_s_three_frames() {
    // Oracle: [HEADERS 4 [:status 200, trailer x-sum], DATA 4 b'abc', HEADERS 4 [x-sum 42] fin].
    let mut m = mux();
    m.recv(0, &headers(GET), true, 0).expect("request");
    assert!(m.send_head(0, b"HTTP/1.1 200 OK\r\nTrailer: x-sum\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive", false));
    assert_eq!(m.send_data(0, b"abc", false), 3);
    assert!(m.send_trailers(0, &[("X-Sum", "42")]));
    assert_eq!(m.next_tx(), Some(3), "the control stream first");
    m.tx_written(3, m.tx_bytes(3).len());
    assert_eq!(m.next_tx(), Some(0));
    let f = frames(m.tx_bytes(0));
    assert_eq!(f.len(), 3);
    assert_eq!((f[0].0, decoded(&f[0].1)), (HEADERS, vec![(":status".into(), "200".into()), ("trailer".into(), "x-sum".into())]));
    assert_eq!((f[1].0, f[1].1.clone()), (DATA, b"abc".to_vec()));
    assert_eq!((f[2].0, decoded(&f[2].1)), (HEADERS, vec![("x-sum".into(), "42".into())]));
    assert!(!m.fin_due(0), "the FIN goes with the last byte");
    let n = m.tx_bytes(0).len();
    m.tx_written(0, n - 1);
    assert!(!m.fin_due(0));
    m.tx_written(0, 1);
    assert!(m.fin_due(0));
    m.fin_written(0);
    assert!(!m.fin_due(0));
    assert_eq!(m.stream(0).expect("stream").state, H3StreamState::Closed);
    assert_eq!(m.next_tx(), None);
    m.release(0);
    assert!(m.stream(0).is_none());
}

#[test]
fn an_interim_response_goes_before_the_final_one_without_fin() {
    let mut m = mux();
    m.recv(0, &headers(GET), true, 0).expect("request");
    assert!(!m.send_interim(0, b"HTTP/1.1 200 OK"), "not an interim status");
    assert!(m.send_interim(0, b"HTTP/1.1 103 Early Hints\r\nlink: </s.css>; rel=preload"));
    assert!(m.stream(0).expect("stream").interim_sent);
    assert!(m.send_head(0, b"HTTP/1.1 200 OK\r\ncontent-length: 0", true));
    let f = frames(m.tx_bytes(0));
    assert_eq!(decoded(&f[0].1), vec![(":status".into(), "103".into()), ("link".into(), "</s.css>; rel=preload".into())]);
    assert_eq!(decoded(&f[1].1), vec![(":status".into(), "200".into()), ("content-length".into(), "0".into())]);
    assert!(!m.send_head(0, b"garbage", false), "not a response head");
    assert!(!m.send_head(0, b"HTTP/1.1 abc", false), "not a status");
}

#[test]
fn the_response_is_held_to_the_stream_s_tx_room() {
    let mut m = mux();
    m.recv(0, &headers(GET), true, 0).expect("request");
    assert!(m.send_head(0, b"HTTP/1.1 200 OK", false));
    let big = vec![b'y'; TX_ROOM * 2];
    let n = m.send_data(0, &big, true);
    assert!(n > 0 && n < TX_ROOM, "{n}");
    assert_eq!(m.data_budget(0), 0);
    assert_eq!(m.send_data(0, &big[n..], true), 0, "no room: nothing taken");
    assert!(!m.stream(0).expect("stream").tx_fin, "the FIN waits for the last byte");
    let held = m.tx_bytes(0).len();
    m.tx_written(0, held);
    assert!(m.data_budget(0) > 0 && m.tx_pending());
    let rest = m.send_data(0, &big[n..], true);
    assert!(rest > 0);
    // An empty last write ends the stream.
    let mut m2 = mux();
    m2.recv(0, &headers(GET), true, 0).expect("request");
    m2.send_head(0, b"HTTP/1.1 200 OK", false);
    assert_eq!(m2.send_data(0, &[], true), 0);
    assert!(m2.stream(0).expect("stream").tx_fin);
}

#[test]
fn goaway_rejects_the_streams_past_it() {
    let mut m = mux();
    m.recv(0, &headers(GET), true, 0).expect("request");
    m.tx_written(3, m.tx_bytes(3).len());
    m.send_goaway();
    assert_eq!(m.goaway_sent, Some(4));
    assert_eq!(frames(m.tx_bytes(3)), vec![(GOAWAY, vec![0x04])]);
    m.send_goaway();
    assert_eq!(frames(m.tx_bytes(3)).len(), 1, "sent once");
    m.recv(4, &headers(GET), true, 0).expect("stream error only");
    assert_eq!(stream_error(&signals(&mut m), 4), Some(0x10b), "rejected: the client may retry it elsewhere");
    assert_eq!(m.next_dispatch(), Some(0));
}

#[test]
fn resets_either_way() {
    let mut m = mux();
    m.recv(0, &headers(GET), false, 0).expect("request");
    m.recv(4, &headers(GET), false, 0).expect("request");
    // The client resets a stream nothing serves: let go.
    assert_eq!(m.on_reset(0, 0x10c), Ok(()));
    assert!(m.stream(0).is_none());
    // One being served is marked for the child; its response is dropped.
    let id = m.next_dispatch().expect("stream 4");
    m.stream_mut(id).expect("stream").set_dispatched();
    assert!(m.next_dispatch().is_none());
    m.send_head(4, b"HTTP/1.1 200 OK", false);
    assert_eq!(m.on_stop_sending(4, 0x10c), Ok(()));
    assert!(HtxMux::is_reset(&m, 4));
    assert!(m.stream(4).expect("stream").is_reset());
    assert_eq!(signals(&mut m), vec![H3Signal::ResetStream { id: 4, code: 0x10c }], "the code copied, as qcc_recv_stop_sending");
    assert_eq!(m.tx_bytes(4), b"", "the response is dropped");
    assert!(m.send_head(4, b"HTTP/1.1 200 OK", false), "a reset stream takes anything");
    assert_eq!(m.send_data(4, b"abc", true), 3);
    assert!(m.send_trailers(4, &[]));
    assert_eq!(m.data_budget(4), usize::MAX);
    // The mux resets one (a child ending with an error).
    m.recv(8, &headers(GET), false, 0).expect("request");
    HtxMux::reset(&mut m, 8, MuxReset::Internal);
    assert_eq!(signals(&mut m), vec![H3Signal::ResetStream { id: 8, code: 0x102 }]);
    m.recv(12, &headers(GET), false, 0).expect("request");
    m.stream_mut(12).expect("stream").set_dispatched();
    HtxMux::reset(&mut m, 12, MuxReset::Cancel);
    HtxMux::reset(&mut m, 12, MuxReset::Refused);
    assert_eq!(signals(&mut m), vec![H3Signal::ResetStream { id: 12, code: 0x10c }], "once");
    assert_eq!(m.stream(12).expect("kept for the child").state, H3StreamState::Reset(0x10c));
    // Streams that do not exist.
    assert_eq!(m.on_reset(400, 0x10c), Ok(()));
    assert_eq!(m.on_stop_sending(400, 0x10c), Ok(()));
    assert!(m.send_head(400, b"HTTP/1.1 200 OK", true));
    assert_eq!(m.send_data(400, b"x", true), 1);
    assert_eq!(m.rx_room(400), mux_h3::RX_CAP, "a new stream may send a buffer");
    assert_eq!(m.tx_bytes(400), b"");
    m.tx_written(400, 5);
    m.fin_written(400);
    m.rx_taken(400, 5);
    assert!(!m.fin_due(400));
}

#[test]
fn the_trait_serves_a_stream_as_the_bridge_will() {
    fn serve<M: HtxMux>(m: &mut M) -> Option<u64> {
        let id = m.next_dispatch()?;
        let st = m.stream_mut(id)?;
        st.set_dispatched();
        let head = st.take_req_fields()?;
        assert!(st.req_head().is_none());
        assert!(!st.is_reset() && !st.bad_request() && st.rx_buffered() == 0);
        let wire = String::from_utf8_lossy(&head.to_wire()).into_owned();
        assert!(wire.starts_with("GET /plain HTTP/1.1\r\n"), "{wire}");
        m.give_back_head(head);
        assert!(m.send_head(id, b"HTTP/1.1 200 OK", false));
        let n = m.data_budget(id).min(2);
        assert_eq!(m.send_data(id, &b"ok"[..n], true), 2);
        m.rx_taken(id, 0);
        assert!(m.tx_pending());
        Some(id)
    }
    let mut m = mux();
    m.recv(0, &headers(GET), true, 0).expect("request");
    assert_eq!(serve(&mut m), Some(0));
    assert_eq!(m.glitches(), 0);
    // The next stream reuses the head's memory.
    m.recv(4, &headers(GET), true, 0).expect("request");
    assert_eq!(serve(&mut m), Some(4));
}

#[test]
fn at_most_max_concurrent_streams_are_dispatched() {
    let mut m = mux();
    m.max_concurrent = 2;
    for id in [0u64, 4, 8] {
        m.recv(id, &headers(GET), true, 0).expect("request");
    }
    for _ in 0..2 {
        let id = m.next_dispatch().expect("a slot");
        m.stream_mut(id).expect("stream").set_dispatched();
    }
    assert_eq!(m.next_dispatch(), None, "the third head waits for a slot");
    m.release(0);
    assert_eq!(m.next_dispatch(), Some(8));
}

#[test]
fn the_contexts_come_from_the_qcs_and_qcc_pools() {
    let ctx = H3MuxContext::take().expect("qcc");
    drop(ctx);
    let mut m = H3MuxContext::take().expect("qcc");
    m.open_control(3);
    m.recv(0, &headers(GET), true, 0).expect("request");
    let mut names = Vec::new();
    ibex_alloc::for_each_pool(|p| names.push(p.name()));
    assert!(names.contains(&"qcs") && names.contains(&"qcc"), "{names:?}");
}

#[test]
fn the_static_encoder_finds_what_a_scan_of_the_table_finds() {
    for (i, (n, v)) in qpack::STATIC_TABLE.iter().enumerate() {
        let first_pair = qpack::STATIC_TABLE.iter().position(|e| e == &(*n, *v)).expect("present");
        assert_eq!(qpack::static_ref(n, v), qpack::StaticRef::Full(first_pair), "entry {i}");
        let first_name = qpack::STATIC_TABLE.iter().position(|e| e.0 == *n).expect("present");
        assert_eq!(qpack::static_ref(n, "\u{1}nothing"), qpack::StaticRef::Name(first_name), "entry {i}");
    }
    assert_eq!(qpack::static_ref("x-ibex", "1"), qpack::StaticRef::None);
    assert_eq!(qpack::static_ref("", ""), qpack::StaticRef::None);
    assert_eq!(qpack::static_ref("zzzz", ""), qpack::StaticRef::None);
}

#[test]
fn the_corners_of_the_stream_and_connection_state() {
    // A context made by `Default` is a new one.
    let d = H3MuxContext::default();
    assert_eq!((d.max_concurrent, d.next_request, d.control_out), (mux_h3::MAX_CONCURRENT, 0, None));

    // The client may not stop our control stream (RFC 9114 section 6.2.1).
    let mut m = mux();
    assert_eq!(m.on_stop_sending(3, 0x100), Err(H3Error::ClosedCriticalStream));

    // Our FIN before the client's: half-closed local; a reset stream stays reset.
    let mut m = mux();
    m.recv(0, &headers(GET), false, 0).expect("request");
    m.recv(4, &headers(GET), false, 0).expect("request");
    m.stream_mut(4).expect("stream").set_dispatched();
    assert!(HtxStream::dispatched(m.stream(4).expect("stream")));
    m.fin_written(0);
    assert_eq!(m.stream(0).expect("stream").state, H3StreamState::HalfClosedLocal);
    HtxMux::reset(&mut m, 4, MuxReset::Refused);
    assert_eq!(signals(&mut m), vec![H3Signal::ResetStream { id: 4, code: 0x10b }]);
    m.fin_written(4);
    assert_eq!(m.stream(4).expect("stream").state, H3StreamState::Reset(0x10b));
    assert!(m.send_interim(4, b"HTTP/1.1 103 Early Hints"), "a reset stream takes an interim head too");

    // Two different lengths in one content-length.
    let mut m = mux();
    m.recv(0, &headers_owned(&post(&[("content-length", "5, 6")])), false, 0).expect("stream error only");
    assert_eq!(stream_error(&signals(&mut m), 0), Some(0x10e));

    // A control frame in pieces waits for the rest.
    let mut m = mux();
    let mut b = vec![0x00];
    b.extend(frame(SETTINGS, &[0x01, 0x00]));
    m.recv(2, &b[..3], false, 0).expect("part");
    assert!(!m.settings_recv);
    assert!(m.rx_room(2) < mux_h3::RX_CAP, "the control stream holds its partial frame");
    m.recv(2, &b[3..], false, 0).expect("rest");
    assert!(m.settings_recv);
}

#[test]
fn a_fin_with_more_data_than_room_waits_for_the_child() {
    let mut m = mux();
    let body = vec![b'q'; RX_DATA_ROOM + 100];
    let mut b = headers_owned(&post(&[]));
    b.extend(frame(DATA, &body));
    // An owner that read past `rx_room` (the whole stream at once): the DATA beyond the
    // HTX's room waits in `rx`, and the end of the message with it.
    m.recv(0, &b, true, 0).expect("request");
    let st = m.stream(0).expect("stream");
    assert_eq!(st.rx_buffered, RX_DATA_ROOM);
    assert!(!st.rx_htx().is_eom(), "100 bytes are still to come");
    assert_eq!(m.rx_room(0), 0);
    m.stream_mut(0).expect("stream").rx_htx_mut().clear();
    m.rx_taken(0, RX_DATA_ROOM);
    let st = m.stream(0).expect("stream");
    assert_eq!(st.rx_buffered, 100);
    assert!(st.rx_htx().is_eom());
    assert_eq!(st.known_body, Some(body.len() as u64));
}

/// The bridge takes a DATA block whole by emptying it and moving its cursor past it
/// (`h2_bridge::pump_h2_body`): DATA that comes after goes into a block of its own, or it
/// sits behind the cursor and the upload stalls (T509: a 100 KB POST through the engine).
#[test]
fn data_after_a_block_the_bridge_emptied_is_a_block_of_its_own() {
    let mut m = mux();
    m.recv(0, &headers_owned(&post(&[])), false, 0).expect("ok");
    m.recv(0, &frame(0x00, b"abc"), false, 0).expect("ok");
    let st = m.stream_mut(0).expect("stream");
    let at = st.rx_htx().blocks().iter().position(|b| matches!(b, HtxBlock::Data(_))).expect("a DATA block");
    if let HtxBlock::Data(d) = &mut st.rx_htx_mut().blocks_mut()[at] {
        *d = Vec::new();
    }
    m.rx_taken(0, 3);
    m.recv(0, &frame(0x00, b"def"), false, 0).expect("ok");
    let blocks = m.stream(0).expect("stream").rx_htx().blocks();
    assert!(matches!(&blocks[at + 1], HtxBlock::Data(d) if d == b"def"), "{blocks:?}");
}
