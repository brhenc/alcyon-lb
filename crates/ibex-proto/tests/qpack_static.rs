// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use ibex_proto::h3::H3Error;
use ibex_proto::qpack::decode_qpack_static;

#[test]
fn test_qpack_empty() {
    let res = decode_qpack_static(&[]);
    assert_eq!(res.unwrap(), vec![]);
}

#[test]
fn test_qpack_static_index() {
    // ric=0, base=0 => 0x00 0x00
    // index 17 => :method GET
    // T=1 => 11xx xxxx => 0xc0 | 17 = 0xd1
    let data = [0x00, 0x00, 0xd1];
    let res = decode_qpack_static(&data).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].name, ":method");
    assert_eq!(res[0].value, "GET");
}

#[test]
fn test_qpack_literal_name_ref() {
    // 0x00 0x00
    // name ref 1 (:path), value "/hello"
    // 0 1 0 1 NameIdx(4+) => 0x51
    // value "/hello" (len 6) => 0x06, 'h','e','l','l','o'
    // no huffman
    let data = [0x00, 0x00, 0x51, 0x06, b'/', b'h', b'e', b'l', b'l', b'o'];
    let res = decode_qpack_static(&data).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].name, ":path");
    assert_eq!(res[0].value, "/hello");
}

#[test]
fn test_qpack_literal_without_name_ref() {
    // ric=0, base=0
    // 0 0 1 N H NameLen(3+) => 0x20
    // name "foo" (len 3) => 0x23, 'f','o','o'
    // value "bar" (len 3) => 0x03, 'b','a','r'
    let data = [0x00, 0x00, 0x23, b'f', b'o', b'o', 0x03, b'b', b'a', b'r'];
    let res = decode_qpack_static(&data).unwrap();
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].name, "foo");
    assert_eq!(res[0].value, "bar");
}

#[test]
fn test_qpack_non_zero_ric() {
    let data = [0x01, 0x00, 0xd1]; // ric=1
    let res = decode_qpack_static(&data);
    assert_eq!(res.unwrap_err(), H3Error::QpackDecompressionFailed);
}

#[test]
fn test_qpack_dynamic_index() {
    // 0x00 0x00
    // 1 0 Index(6+) => 0x80
    let data = [0x00, 0x00, 0x80];
    let res = decode_qpack_static(&data);
    assert_eq!(res.unwrap_err(), H3Error::QpackDecompressionFailed);
}

#[test]
fn test_qpack_literal_dynamic_name_ref() {
    // 0x00 0x00
    // 0 1 0 0 NameIdx(4+) => 0x40
    let data = [0x00, 0x00, 0x40, 0x01, b'a'];
    let res = decode_qpack_static(&data);
    assert_eq!(res.unwrap_err(), H3Error::QpackDecompressionFailed);
}

#[test]
fn test_qpack_malformed_string_length() {
    // length goes out of bounds
    // 0x00 0x00
    // 0x51 (name ref 1)
    // 0x7f + large bytes
    let data = [0x00, 0x00, 0x51, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
    let res = decode_qpack_static(&data);
    assert!(res.is_err());
}
