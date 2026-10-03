// SPDX-License-Identifier: MIT
// Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>. See crates/slz/LICENSE.

use crate::tables::CRC32_FAST;

pub fn crc32_by4(mut crc: u32, buf: &[u8]) -> u32 {
    let mut i = 0;
    while i + 4 <= buf.len() {
        crc ^= u32::from_le_bytes(buf[i..i+4].try_into().unwrap());
        crc = CRC32_FAST[3][(crc & 0xff) as usize] ^
              CRC32_FAST[2][((crc >> 8) & 0xff) as usize] ^
              CRC32_FAST[1][((crc >> 16) & 0xff) as usize] ^
              CRC32_FAST[0][(crc >> 24) as usize];
        i += 4;
    }
    while i < buf.len() {
        crc = CRC32_FAST[0][((crc ^ (buf[i] as u32)) & 0xff) as usize] ^ (crc >> 8);
        i += 1;
    }
    crc
}

pub fn adler32_block(adler: u32, buf: &[u8]) -> u32 {
    let mut s1 = adler & 0xffff;
    let mut s2 = (adler >> 16) & 0xffff;
    for &b in buf {
        s1 = (s1 + b as u32) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    (s2 << 16) + s1
}
