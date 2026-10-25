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

// ---- The resolver itself (T482): what reaches `Resolver::handle_response`. ----

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use ibex_dns::{Protocol, Question, Received, Requester, Resolver, ResolverConfig};

use crate::resolver_behavior::{a_rec, a_response, response};

fn ns1() -> SocketAddr {
    "127.0.0.1:53".parse().unwrap()
}

/// A resolver with one query for `name` in flight; returns it and the query's message id.
fn in_flight(name: &str, t0: Instant) -> (Resolver, u16) {
    let mut r = Resolver::new(ResolverConfig { nameservers: vec![ns1()], ..ResolverConfig::default() });
    r.query(t0, name, Question::v4(), Requester::Server).unwrap();
    let (_, _, buf) = r.poll_transmit(t0).unwrap();
    (r, u16::from_be_bytes([buf[0], buf[1]]))
}

// B.P2: a reply with the right id but for another name was accepted as the answer.
#[test]
fn a_reply_for_another_name_is_not_accepted() {
    let t0 = Instant::now();
    let (mut r, id) = in_flight("a1.test", t0);
    let evil = response(id, "evil.test", RecordType::A, ResponseCode::NoError, vec![a_rec("evil.test", Ipv4Addr::new(6, 6, 6, 6), 60)]);
    assert_eq!(r.handle_response(t0, ns1(), Protocol::Udp, &evil), Received::Invalid);
    assert!(r.poll_result().is_none(), "a reply for another name must not end the resolution");
}

// The id is kept across retries (A.t4), so a spoofed reply has one id to guess per resolution;
// once the resolution ended, a second reply with that id is `outdated` and changes nothing.
#[test]
fn a_reply_after_the_resolution_ended_is_outdated() {
    let t0 = Instant::now();
    let (mut r, id) = in_flight("a1.test", t0);
    let (_, _, again) = r.poll_transmit(t0 + Duration::from_secs(1)).unwrap();
    assert_eq!(u16::from_be_bytes([again[0], again[1]]), id, "the retry reuses the id");
    let ok = a_response(id, "a1.test", Ipv4Addr::new(10, 0, 0, 1), 60);
    assert_eq!(r.handle_response(t0, ns1(), Protocol::Udp, &ok), Received::Valid);
    assert!(r.poll_result().unwrap().1.is_ok());
    let spoof = a_response(id, "a1.test", Ipv4Addr::new(6, 6, 6, 6), 60);
    assert_eq!(r.handle_response(t0, ns1(), Protocol::Udp, &spoof), Received::Outdated);
    assert!(r.poll_result().is_none());
}

// resolvers.c:2401: a UDP datagram longer than accepted_payload_size is `too_big`, dropped
// before it is decoded. B.P8 decoded 64,020 bytes.
#[test]
fn a_65535_byte_udp_reply_is_dropped_as_too_big() {
    let t0 = Instant::now();
    let (mut r, id) = in_flight("a1.test", t0);
    let mut buf = a_response(id, "a1.test", Ipv4Addr::new(10, 0, 0, 1), 60);
    buf.resize(65_535, 0);
    assert_eq!(r.handle_response(t0, ns1(), Protocol::Udp, &buf), Received::TooBig);
    assert!(r.poll_result().is_none());
}

// resolvers.c:1120: qdcount must be 1.
#[test]
fn a_question_less_reply_is_invalid() {
    let t0 = Instant::now();
    let (mut r, id) = in_flight("a1.test", t0);
    let mut m = Message::from_vec(&a_response(id, "a1.test", Ipv4Addr::new(6, 6, 6, 6), 60)).unwrap();
    m.take_queries();
    assert_eq!(r.handle_response(t0, ns1(), Protocol::Udp, &m.to_vec().unwrap()), Received::Invalid);
    assert!(r.poll_result().is_none());
}

// resolv_read_name returns 0 for the root name and the record is `invalid_resp`
// (resolvers.c:1227): an answer whose owner is "." is not an answer for the name asked.
#[test]
fn an_answer_with_a_zero_length_name_is_invalid() {
    let t0 = Instant::now();
    let (mut r, id) = in_flight("a1.test", t0);
    let buf = response(id, "a1.test", RecordType::A, ResponseCode::NoError, vec![a_rec(".", Ipv4Addr::new(6, 6, 6, 6), 60)]);
    assert_eq!(r.handle_response(t0, ns1(), Protocol::Udp, &buf), Received::Invalid);
    assert!(r.poll_result().is_none());
}

// B.P11 kept as a test: random and mutated replies carrying the live id must not panic.
#[test]
fn random_and_mutated_replies_do_not_panic() {
    let t0 = Instant::now();
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for i in 0..20_000u32 {
        let (mut r, id) = in_flight("f.test", t0);
        let base = a_response(id, "f.test", Ipv4Addr::new(1, 2, 3, 4), 60);
        #[allow(clippy::cast_possible_truncation)]
        let mut b: Vec<u8> = if i % 2 == 0 {
            base
        } else {
            (0..(rnd() % 600) as usize).map(|_| rnd() as u8).collect()
        };
        if b.len() >= 2 {
            #[allow(clippy::cast_possible_truncation)]
            if i % 2 == 0 {
                for _ in 0..=(rnd() % 4) {
                    let k = (rnd() as usize) % b.len();
                    b[k] = rnd() as u8;
                }
            }
            b[..2].copy_from_slice(&id.to_be_bytes());
        }
        let proto = if i % 3 == 0 { Protocol::Tcp } else { Protocol::Udp };
        let _ = r.handle_response(t0, ns1(), proto, &b);
        let _ = r.poll_result();
        let _ = r.poll_transmit(t0);
    }
}
