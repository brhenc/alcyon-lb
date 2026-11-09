// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use alcyon_proto::h3::H3Error;
use alcyon_proto::qpack::decode_qpack_static;

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

/// T454: a string with a byte that is not UTF-8 decodes (each such byte as a NUL, the field
/// checks then refuse it on its stream) instead of failing the decompression, which is a
/// connection error.
#[test]
fn a_byte_that_is_not_utf8_is_a_nul_not_a_decompression_failure() {
    // Required Insert Count 0, Base 0, then a literal field line with a literal name `x-\xe9`
    // and value `a\xe9b`.
    let data = vec![0x00, 0x00, 0x23, b'x', b'-', 0xe9, 0x03, b'a', 0xe9, b'b'];
    let res = decode_qpack_static(&data).expect("decodes");
    assert_eq!((res[0].name.as_str(), res[0].value.as_str()), ("x-\0", "a\0b"));
    // The same name, Huffman-coded.
    let mut name = Vec::new();
    alcyon_proto::hpack::encode_huffman(b"x-\xe9", &mut name);
    let mut data = vec![0x00, 0x00, 0x28 | u8::try_from(name.len()).expect("short")];
    data[2] |= 0x20;
    data.extend_from_slice(&name);
    data.extend_from_slice(&[0x01, b'v']);
    let res = decode_qpack_static(&data).expect("decodes");
    assert_eq!(res[0].name, "x-\0");
}
