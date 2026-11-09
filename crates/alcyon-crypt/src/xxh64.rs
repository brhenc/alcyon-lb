// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `XXH64` (`XXH64()` of the xxHash library `HAProxy` bundles): the `xxh64` converter's hash
//! and the `ClientHello` capture's hash of the offered cipher suites
//! (`ssl_fc_cipherlist_xxh`). Here so that `alcyon-sample` and `alcyon-tls` share one copy.

/// `XXH64` algorithm.
#[must_use]
pub fn hash_xxh64(input: &[u8], seed: u64) -> u64 {
    const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
    const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
    const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
    const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

    let len = input.len();
    let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
    let mut h64: u64;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        let mut chunks = input.chunks_exact(32);
        for chunk in &mut chunks {
            let mut sub = chunk.chunks_exact(8);
            let b1 = u64::from_le_bytes(sub.next().unwrap_or(&[0; 8]).try_into().unwrap_or([0; 8]));
            let b2 = u64::from_le_bytes(sub.next().unwrap_or(&[0; 8]).try_into().unwrap_or([0; 8]));
            let b3 = u64::from_le_bytes(sub.next().unwrap_or(&[0; 8]).try_into().unwrap_or([0; 8]));
            let b4 = u64::from_le_bytes(sub.next().unwrap_or(&[0; 8]).try_into().unwrap_or([0; 8]));

            v1 = v1.wrapping_add(b1.wrapping_mul(PRIME64_2)).rotate_left(31).wrapping_mul(PRIME64_1);
            v2 = v2.wrapping_add(b2.wrapping_mul(PRIME64_2)).rotate_left(31).wrapping_mul(PRIME64_1);
            v3 = v3.wrapping_add(b3.wrapping_mul(PRIME64_2)).rotate_left(31).wrapping_mul(PRIME64_1);
            v4 = v4.wrapping_add(b4.wrapping_mul(PRIME64_2)).rotate_left(31).wrapping_mul(PRIME64_1);
        }

        h64 = v1.rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));

        let merge_round = |mut h: u64, val: u64| -> u64 {
            let k1 = val.wrapping_mul(PRIME64_2).rotate_left(31).wrapping_mul(PRIME64_1);
            h = (h ^ k1).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4);
            h
        };

        h64 = merge_round(h64, v1);
        h64 = merge_round(h64, v2);
        h64 = merge_round(h64, v3);
        h64 = merge_round(h64, v4);
        // T327: the length is added before the 8, 4 and 1-byte tails, as in xxHash.
        h64 = h64.wrapping_add(len_u64);

        let rem = chunks.remainder();
        let mut rem_8 = rem.chunks_exact(8);
        for chunk in &mut rem_8 {
            let val = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            let k1 = val.wrapping_mul(PRIME64_2).rotate_left(31).wrapping_mul(PRIME64_1);
            h64 = (h64 ^ k1).rotate_left(27).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4);
        }
        let rem_8_rem = rem_8.remainder();
        let mut rem_4 = rem_8_rem.chunks_exact(4);
        for chunk in &mut rem_4 {
            let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
            h64 = (h64 ^ (u64::from(val).wrapping_mul(PRIME64_1))).rotate_left(23).wrapping_mul(PRIME64_2).wrapping_add(PRIME64_3);
        }
        for &b in rem_4.remainder() {
            h64 = (h64 ^ (u64::from(b).wrapping_mul(PRIME64_5))).rotate_left(11).wrapping_mul(PRIME64_1);
        }
    } else {
        h64 = seed.wrapping_add(PRIME64_5).wrapping_add(len_u64);
        let mut chunks_8 = input.chunks_exact(8);
        for chunk in &mut chunks_8 {
            let val = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            let k1 = val.wrapping_mul(PRIME64_2).rotate_left(31).wrapping_mul(PRIME64_1);
            h64 = (h64 ^ k1).rotate_left(27).wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4);
        }
        let rem_8 = chunks_8.remainder();
        let mut chunks_4 = rem_8.chunks_exact(4);
        for chunk in &mut chunks_4 {
            let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
            h64 = (h64 ^ (u64::from(val).wrapping_mul(PRIME64_1))).rotate_left(23).wrapping_mul(PRIME64_2).wrapping_add(PRIME64_3);
        }
        for &b in chunks_4.remainder() {
            h64 = (h64 ^ (u64::from(b).wrapping_mul(PRIME64_5))).rotate_left(11).wrapping_mul(PRIME64_1);
        }
    }

    h64 ^= h64 >> 33;
    h64 = h64.wrapping_mul(PRIME64_2);
    h64 ^= h64 >> 29;
    h64 = h64.wrapping_mul(PRIME64_3);
    h64 ^= h64 >> 32;
    h64
}
