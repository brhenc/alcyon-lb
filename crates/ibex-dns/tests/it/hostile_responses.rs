// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A DNS response is attacker-influenced input.
//!
//! The resolver reads packets from whatever answered, which on a hostile network is not
//! necessarily the nameserver that was asked. The decoder therefore has to refuse malformed
//! input rather than loop, allocate without bound, or panic — and this has to be asserted,
//! not observed. The first version of this test built a compression-pointer loop, printed
//! the result with `println!`, and asserted nothing, so it passed whatever happened.

use hickory_proto::op::Message;

/// RFC 1035 §4.1.4 name compression: a pointer must refer *backwards* to a prior label.
/// One pointing at itself is the classic decoder infinite loop.
#[test]
fn a_compression_pointer_loop_is_refused() {
    let buf = vec![
        0x12, 0x34, // ID
        0x81, 0x80, // flags: QR RD RA
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        0x03, b'w', b'w', b'w', 0x00, // question name "www."
        0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN   -- answer begins at offset 21
        0xc0, 21, // answer name: pointer to offset 21, i.e. itself
        0x00, 0x01, 0x00, 0x01, // TYPE A, CLASS IN
        0x00, 0x00, 0x00, 0x3c, // TTL
        0x00, 0x04, // RDLENGTH
        0x01, 0x02, 0x03, 0x04, // 1.2.3.4
    ];

    let res = Message::from_vec(&buf);
    assert!(
        res.is_err(),
        "a self-referential compression pointer must be refused, got: {res:?}"
    );
}

#[test]
fn a_truncated_message_is_refused_not_panicked_on() {
    // A well-formed header claiming one question, and then nothing.
    let buf = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let res = Message::from_vec(&buf);
    assert!(res.is_err(), "a header with no body must be refused, got: {res:?}");
}

#[test]
fn an_empty_packet_is_refused_not_panicked_on() {
    assert!(Message::from_vec(&[]).is_err(), "an empty packet must be refused");
}

#[test]
fn a_header_claiming_more_records_than_it_carries_is_refused() {
    let buf = vec![
        0x12, 0x34, 0x81, 0x80, //
        0x00, 0x01, // QDCOUNT 1
        0xff, 0xff, // ANCOUNT 65535, and none follow
        0x00, 0x00, 0x00, 0x00, //
        0x03, b'w', b'w', b'w', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let res = Message::from_vec(&buf);
    assert!(
        res.is_err(),
        "a count far exceeding the payload must be refused rather than driving an \
         allocation loop, got: {res:?}"
    );
}
