// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! What `recvmmsg` reports when a datagram does not fit.
//!
//! `recvmmsg` is called with `MSG_TRUNC`, which on a datagram socket asks the kernel to
//! report the *real* size of the packet rather than the number of bytes copied. That makes
//! `truncated` correct, and it makes `len` a number that can exceed the buffer it describes.
//! A caller writing the obvious `&msg.buf[..msg.len]` then panics on a datagram it did not
//! choose the size of.

use ibex_mmsg::{recvmmsg, RecvMsg};
use std::net::UdpSocket;
use std::os::fd::AsFd;

#[test]
fn a_datagram_larger_than_the_buffer_is_reported_as_truncated() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let addr = server.local_addr().expect("addr");

    // 1200 bytes is the QUIC Initial size this path exists to carry.
    let payload = vec![b'Q'; 1200];
    client.send_to(&payload, addr).expect("send");

    let mut buf = [0u8; 1199];
    let mut cmsg = [0u8; 128];
    let mut msgs = vec![RecvMsg {
        buf: &mut buf,
        cmsg_buf: &mut cmsg,
        len: 0,
        wire_len: 0,
        src_addr: None,
        dst_addr: None,
        truncated: false,
    }];

    let n = recvmmsg(server.as_fd(), &mut msgs).expect("recvmmsg");
    assert_eq!(n, 1, "one datagram was sent");

    let m = &msgs[0];
    assert!(m.truncated, "a 1200-byte datagram into a 1199-byte buffer must report truncated");

    // The contract every caller will assume, and the one that decides whether
    // `&msg.buf[..msg.len]` is a panic waiting for a 1200-byte packet.
    assert!(
        m.len <= m.buf.len(),
        "len ({}) must not exceed the buffer it describes ({}); \
         MSG_TRUNC makes the kernel report the wire length, so a caller slicing \
         buf[..len] panics on any oversized datagram",
        m.len,
        m.buf.len()
    );
    assert_eq!(m.len, 1199, "len reports what is in the buffer");
    assert_eq!(m.wire_len, 1200, "wire_len keeps the size the sender chose");
}
