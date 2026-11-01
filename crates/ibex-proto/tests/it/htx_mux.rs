// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The h2 mux through the `HtxMux` trait the bridge will be generic over (T503, design
//! section 2.4): the same operations as the h3 mux's (`h3_mux.rs`), on an HTTP/2 stream,
//! with the two the h2 mux did not have, response trailers and interim responses.

use ibex_proto::conn::ConnId;
use ibex_proto::h2::{frame_flags, Frame, FrameHeader, FrameType, FRAME_HEADER_LEN, H2_CONN_PREFACE};
use ibex_proto::hpack::{HpackDecoder, HpackEncoder};
use ibex_proto::htx::HeaderField;
use ibex_proto::htx_mux::{HtxMux, HtxStream, MuxReset};
use ibex_proto::mux::Mux;
use ibex_proto::mux_h2::{H2MuxContext, MuxH2};

fn field(n: &str, v: &str) -> HeaderField {
    HeaderField { name: n.into(), value: v.into() }
}

/// A server connection with one GET on stream 1 (and one on stream 3 left open).
fn h2_with_get() -> H2MuxContext {
    let mut ctx = MuxH2.init(ConnId(1), true).expect("init");
    let mut b = H2_CONN_PREFACE.to_vec();
    b.extend(Frame::Settings { flags: 0, settings: vec![] }.encode());
    let mut enc = HpackEncoder::new();
    let get = [field(":method", "GET"), field(":scheme", "https"), field(":authority", "localhost"), field(":path", "/plain")];
    b.extend(Frame::Headers { flags: frame_flags::END_HEADERS | frame_flags::END_STREAM, stream_id: 1, header_block: enc.encode(&get) }.encode());
    b.extend(Frame::Headers { flags: frame_flags::END_HEADERS, stream_id: 3, header_block: enc.encode(&get) }.encode());
    MuxH2.parse(&mut ctx, &b).expect("request");
    ctx.tx_consumed = ctx.tx_buf.len();
    ctx
}

/// The HEADERS frames of `ctx`'s output, decoded, with their flags.
fn sent_headers(ctx: &H2MuxContext) -> Vec<(u8, Vec<(String, String)>)> {
    let mut dec = HpackDecoder::new();
    let mut out = Vec::new();
    let mut b = &ctx.tx_buf[ctx.tx_consumed..];
    while b.len() >= FRAME_HEADER_LEN {
        let h = FrameHeader::decode(b).expect("header");
        let payload = &b[FRAME_HEADER_LEN..FRAME_HEADER_LEN + h.length as usize];
        if h.frame_type == FrameType::Headers {
            let f = dec.decode(payload).expect("hpack").into_iter().map(|f| (f.name, f.value)).collect();
            out.push((h.flags, f));
        }
        b = &b[FRAME_HEADER_LEN + h.length as usize..];
    }
    out
}

#[test]
fn the_h2_mux_serves_a_stream_through_the_trait() {
    let mut m = h2_with_get();
    let id = m.next_dispatch().expect("stream 1");
    assert_eq!(id, 1);
    let st = m.stream_mut(id).expect("stream");
    assert!(!st.dispatched() && !st.is_reset() && !st.bad_request());
    assert_eq!(st.rx_buffered(), 0);
    assert!(st.rx_htx().is_eom());
    assert!(st.rx_htx_mut().is_eoh());
    st.set_dispatched();
    assert!(st.dispatched());
    let head = st.take_req_fields().expect("head");
    assert!(st.req_head().is_none());
    m.give_back_head(head);
    assert_eq!(m.next_dispatch(), Some(3), "the next stream with a head");
    assert!(m.stream(5).is_none() && m.stream(1 << 40).is_none());

    assert!(m.send_interim(1, b"HTTP/1.1 103 Early Hints\r\nlink: </s.css>"));
    assert!(!m.send_interim(1, b"HTTP/1.1 200 OK"), "not interim");
    assert!(!m.send_interim(1, b"nonsense"));
    assert!(m.send_head(1, b"HTTP/1.1 200 OK\r\ntrailer: x-sum", false));
    assert!(m.data_budget(1) >= 3);
    assert_eq!(m.send_data(1, b"abc", false), 3);
    assert!(m.send_trailers(1, &[("X-Sum", "42")]));
    assert!(m.tx_pending());
    let h = sent_headers(&m);
    assert_eq!(h.len(), 3);
    assert_eq!(h[0].1, vec![(":status".to_string(), "103".to_string()), ("link".into(), "</s.css>".into())]);
    assert_eq!(h[0].0 & frame_flags::END_STREAM, 0, "an interim head does not end the stream");
    assert_eq!(h[2].1, vec![("x-sum".to_string(), "42".to_string())]);
    assert_ne!(h[2].0 & frame_flags::END_STREAM, 0, "the trailers end it");
    assert!(m.rx_taken_is_harmless());
    assert_eq!(m.glitches(), 0);

    // A reset stream takes anything and sends nothing (one no child serves is let go).
    m.stream_mut(3).expect("stream 3").set_dispatched();
    HtxMux::reset(&mut m, 3, MuxReset::Cancel);
    assert!(HtxMux::is_reset(&m, 3));
    let before = m.tx_buf.len();
    assert!(m.send_trailers(3, &[("a", "b")]));
    assert!(m.send_interim(3, b"HTTP/1.1 100 Continue"));
    assert_eq!(m.tx_buf.len(), before);
    assert!(!HtxMux::is_reset(&m, 1 << 40));
}

#[test]
fn the_h2_reset_codes() {
    for (why, code) in [(MuxReset::Cancel, 0x8u32), (MuxReset::Internal, 0x2), (MuxReset::Refused, 0x7)] {
        let mut m = h2_with_get();
        HtxMux::reset(&mut m, 3, why);
        let b = &m.tx_buf[m.tx_consumed..];
        let h = FrameHeader::decode(b).expect("header");
        assert_eq!(h.frame_type, FrameType::RstStream);
        let got = u32::from_be_bytes(b[FRAME_HEADER_LEN..FRAME_HEADER_LEN + 4].try_into().expect("code"));
        assert_eq!(got, code, "{why:?}");
    }
}

trait RxTaken {
    fn rx_taken_is_harmless(&mut self) -> bool;
}

impl RxTaken for H2MuxContext {
    /// Through the trait, `rx_taken` credits the stream and resumes the demux, as the
    /// bridge's `pump_request_body` does.
    fn rx_taken_is_harmless(&mut self) -> bool {
        HtxMux::rx_taken(self, 1, 0);
        HtxMux::rx_taken(self, 1 << 40, 0);
        true
    }
}

/// What the bridge will do, generic over the mux: every call goes through the trait.
fn respond<M: HtxMux>(m: &mut M, id: u64) {
    let head = m.stream_mut(id).and_then(HtxStream::take_req_fields).expect("head");
    m.give_back_head(head);
    assert!(m.send_interim(id, b"HTTP/1.1 100 Continue"));
    assert!(m.send_head(id, b"HTTP/1.1 200 OK", false));
    let n = m.data_budget(id).min(2);
    assert_eq!(m.send_data(id, &b"ok"[..n], false), 2);
    assert!(m.send_trailers(id, &[("x-a", "1")]));
}

#[test]
fn the_bridge_s_calls_through_the_trait_on_h2() {
    let mut m = h2_with_get();
    respond(&mut m, 1);
    let h = sent_headers(&m);
    assert_eq!(h.len(), 3, "100, 200, trailers");
    assert_eq!(h[2].1, vec![("x-a".to_string(), "1".to_string())]);
}

/// A response field value that is not UTF-8 goes to an h2 client as its octets, as `HAProxy`
/// 3.5-dev8 sends it (measured: `X-A: a\xff\xfeb` from the server arrives as those four
/// bytes). Ibex sent U+FFFD for each, reading the head as lossy text (found by E2).
#[test]
fn a_response_value_that_is_not_utf8_goes_to_the_h2_client_as_its_octets() {
    let mut m = h2_with_get();
    assert!(m.send_head(1, b"HTTP/1.1 200 OK\r\nX-A: a\xff\xfeb\r\nContent-Length: 2", false));
    let b = &m.tx_buf[m.tx_consumed..];
    let h = FrameHeader::decode(b).expect("header");
    assert_eq!(h.frame_type, FrameType::Headers);
    let mut f = ibex_proto::hpack::DecodedFields::default();
    HpackDecoder::new().decode_into(&b[FRAME_HEADER_LEN..FRAME_HEADER_LEN + h.length as usize], &mut f).expect("hpack");
    assert_eq!(f.get(b"x-a"), Some(&b"a\xff\xfeb"[..]));
    assert_eq!(f.get(b"content-length"), Some(&b"2"[..]));
}
