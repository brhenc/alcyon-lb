// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T358 #5 (F2): a QPACK field section of more than 201 field lines is refused,
//! as `HAProxy`'s decoder (src/qpack-dec.c:316-320, list of `global.tune.max_http_hdr * 2` = 202
//! entries, the last kept for the end marker).

use ibex_proto::h3::H3Error;
use ibex_proto::qpack::decode_qpack_static;

fn indexed(n: usize) -> Vec<u8> {
    let mut b = vec![0x00, 0x00];
    b.extend(std::iter::repeat_n(0xd9u8, n)); // static index 25 `:status 200`
    b
}

#[test]
fn up_to_201_fields_decode() {
    for n in [1usize, 2, 100, 200, 201] {
        let r = decode_qpack_static(&indexed(n)).unwrap_or_else(|e| panic!("{n} fields: {e:?}"));
        assert_eq!(r.len(), n, "{n} fields");
    }
}

#[test]
fn the_202nd_field_is_refused() {
    for n in [202usize, 203, 300, 5000] {
        assert!(matches!(decode_qpack_static(&indexed(n)), Err(H3Error::QpackDecompressionFailed)), "{n} fields");
    }
}

#[test]
fn a_mixed_block_counts_every_field_line() {
    // 100 indexed, one literal with a static name reference (:path = "a"), then indexed again.
    let mk = |tail: usize| {
        let mut b = indexed(100);
        b.extend_from_slice(&[0x51, 0x01, b'a']);
        b.extend(std::iter::repeat_n(0xd9u8, tail));
        b
    };
    assert_eq!(decode_qpack_static(&mk(100)).expect("201 mixed").len(), 201);
    assert!(matches!(decode_qpack_static(&mk(101)), Err(H3Error::QpackDecompressionFailed)));
}
