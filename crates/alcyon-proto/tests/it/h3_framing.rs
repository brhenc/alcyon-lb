// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use alcyon_proto::h3::{parse_varint, parse_frame, Frame, H3Error};

#[test]
fn test_varint() {
    // 1-byte
    let data1 = [0x25];
    let mut off = 0;
    assert_eq!(parse_varint(&data1, &mut off).unwrap(), 37);
    assert_eq!(off, 1);

    // 2-byte: 0x40 0x25 => 37
    let data2 = [0x40, 0x25];
    off = 0;
    assert_eq!(parse_varint(&data2, &mut off).unwrap(), 37);
    assert_eq!(off, 2);

    // 4-byte: 0x9d 0x7f 0x3e 0x7d => 494878333
    let data4 = [0x9d, 0x7f, 0x3e, 0x7d];
    off = 0;
    assert_eq!(parse_varint(&data4, &mut off).unwrap(), 494_878_333);
    assert_eq!(off, 4);

    // 8-byte: 0xc2 0x19 0x7c 0x5e 0xff 0x14 0xe8 0x8c => 151288809941952652
    let data8 = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    off = 0;
    assert_eq!(parse_varint(&data8, &mut off).unwrap(), 151_288_809_941_952_652);
    assert_eq!(off, 8);

    // Boundaries: max 1-byte = 63
    let data1_max = [0x3f];
    off = 0;
    assert_eq!(parse_varint(&data1_max, &mut off).unwrap(), 63);

    // Max 2-byte = 16383 = 0x3fff
    let data2_max = [0x7f, 0xff];
    off = 0;
    assert_eq!(parse_varint(&data2_max, &mut off).unwrap(), 16383);

    // Max 4-byte = 1073741823 = 0x3fffffff
    let data4_max = [0xbf, 0xff, 0xff, 0xff];
    off = 0;
    assert_eq!(parse_varint(&data4_max, &mut off).unwrap(), 1_073_741_823);

    // Max 8-byte = 2^62 - 1 = 0x3fffffffffffffff
    let data8_max = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    off = 0;
    assert_eq!(parse_varint(&data8_max, &mut off).unwrap(), (1 << 62) - 1);

    // Truncated buffer
    let data_trunc = [0x80, 0x01]; // Needs 4 bytes, got 2
    off = 0;
    assert_eq!(parse_varint(&data_trunc, &mut off).unwrap_err(), H3Error::FrameError);
}

#[test]
fn test_frame_grease() {
    // DATA frame: type 0x00, len 0x02, payload [0x11, 0x22]
    // Grease frame: type 0x21 (1 * 0x1f + 0x21 is 0x40, let's use 0x40 => 1-byte varint is 0x40? No, 0x40 is 2-byte varint!
    // Wait, 0x21 as 1-byte is 0x21. length 1, payload [0x99]
    // SETTINGS frame: type 0x04, len 0x00
    let mut data = vec![];
    data.extend_from_slice(&[0x00, 0x02, 0x11, 0x22]); // DATA
    data.extend_from_slice(&[0x21, 0x01, 0x99]);       // GREASE
    data.extend_from_slice(&[0x04, 0x00]);             // SETTINGS

    let mut off = 0;
    let f1 = parse_frame(&data, &mut off).unwrap();
    assert_eq!(f1, Frame::Data(&[0x11, 0x22]));

    let f2 = parse_frame(&data, &mut off).unwrap();
    assert_eq!(f2, Frame::Unknown(0x21, &[0x99]));

    let f3 = parse_frame(&data, &mut off).unwrap();
    assert_eq!(f3, Frame::Settings(&[]));
}

#[test]
fn test_frame_attacker_controlled_length() {
    // Frame claiming 2^62-1 bytes
    // Type 0x00 (DATA)
    // Len: 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    let data = vec![0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let mut off = 0;
    let res = parse_frame(&data, &mut off);
    assert_eq!(res.unwrap_err(), H3Error::FrameError);
}

#[test]
fn test_frame_truncated() {
    // Frame header parsed, but missing payload
    let data = [0x00, 0x05, 0x01, 0x02];
    let mut off = 0;
    let res = parse_frame(&data, &mut off);
    assert_eq!(res.unwrap_err(), H3Error::FrameError);
}
