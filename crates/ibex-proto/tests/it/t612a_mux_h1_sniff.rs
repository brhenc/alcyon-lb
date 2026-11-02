// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T612a (IBEX-H1MUX-SNDBUF-SNIFF-001): `MuxH1::snd_buf` chooses the framing of what it sends
//! from the message head only; body bytes (and header values) never switch the connection
//! into tunnel mode, chunk the following writes, or finish the stream.

use ibex_proto::mux::Mux;
use ibex_proto::SeDesc;
use ibex_proto::mux_h1::MuxH1;
use ibex_proto::ConnId;

fn ctx() -> (MuxH1, ibex_proto::mux_h1::H1MuxContext, SeDesc) {
    let mux = MuxH1;
    let ctx = mux.init(ConnId(1), false).expect("init");
    (mux, ctx, SeDesc::new())
}

#[test]
fn a_body_that_looks_like_a_101_does_not_open_a_tunnel() {
    let (mux, mut c, mut sd) = ctx();
    mux.snd_buf(&mut c, &mut sd, b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n").unwrap();
    mux.snd_buf(&mut c, &mut sd, b"HTTP/1.1 101 Switching Protocols").unwrap();
    assert!(!c.is_tunnel);
}

#[test]
fn body_bytes_in_the_same_slice_as_the_head_are_not_sniffed() {
    let (mux, mut c, mut sd) = ctx();
    let msg = b"HTTP/1.1 200 OK\r\nContent-Length: 70\r\n\r\ntransfer-encoding: chunked\r\nconnection: close\r\ncontent-length: 0\r\n";
    mux.snd_buf(&mut c, &mut sd, msg).unwrap();
    assert!(!c.tx_chunked, "body text chunked the connection");
    assert!(!c.conn_close, "body text closed the connection");
    assert_eq!(c.streams_total, 0, "body text finished the stream");
    assert_eq!(mux.pending_output(&c), &msg[..]);
}

#[test]
fn a_header_value_is_not_a_header_line() {
    let (mux, mut c, mut sd) = ctx();
    mux.snd_buf(&mut c, &mut sd, b"HTTP/1.1 200 OK\r\nX-Note: content-length: 0\r\nContent-Length: 5\r\n\r\n").unwrap();
    assert_eq!(c.streams_total, 0, "a header value finished the stream");
}

#[test]
fn a_real_head_still_decides_the_framing() {
    let (mux, mut c, mut sd) = ctx();
    mux.snd_buf(&mut c, &mut sd, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
    assert!(c.tx_chunked);
    let (mux, mut c, mut sd) = ctx();
    mux.snd_buf(&mut c, &mut sd, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
    assert_eq!(c.streams_total, 1);
}
