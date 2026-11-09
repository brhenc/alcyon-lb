// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `XXH3` 64-bit (`XXH3_64bits_withSeed()` of the xxHash library `HAProxy` bundles, which is
//! what `XXH3(data, len, seed)` expands to in `include/haproxy/xxhash.h`): the `xxh3`
//! converter's hash. Ported from `include/import/xxhash.h`; safe Rust, no SIMD.

#![allow(clippy::cast_possible_truncation)] // the 128-bit fold and the 32-bit seed swap truncate on purpose

const PRIME32_1: u64 = 0x9E37_79B1;
const PRIME32_2: u64 = 0x85EB_CA77;
const PRIME32_3: u64 = 0xC2B2_AE3D;
const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

const SECRET_SIZE: usize = 192;
const STRIPE: usize = 64;
const BLOCK: usize = 1024;

const K_SECRET: [u8; SECRET_SIZE] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

fn r64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn r32(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u64::from(u32::from_le_bytes(a))
}

fn mul128_fold64(a: u64, b: u64) -> u64 {
    let p = u128::from(a) * u128::from(b);
    (p as u64) ^ ((p >> 64) as u64)
}

fn avalanche(mut h: u64) -> u64 {
    h ^= h >> 37;
    h = h.wrapping_mul(0x1656_6791_9E37_79F9);
    h ^ (h >> 32)
}

fn xxh64_avalanche(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^ (h >> 32)
}

fn mix16(input: &[u8], at: usize, secret: &[u8], sat: usize, seed: u64) -> u64 {
    let lo = r64(input, at);
    let hi = r64(input, at + 8);
    mul128_fold64(lo ^ r64(secret, sat).wrapping_add(seed), hi ^ r64(secret, sat + 8).wrapping_sub(seed))
}

fn len_0to16(input: &[u8], seed: u64) -> u64 {
    let len = input.len();
    let s = &K_SECRET;
    if len > 8 {
        let flip1 = (r64(s, 24) ^ r64(s, 32)).wrapping_add(seed);
        let flip2 = (r64(s, 40) ^ r64(s, 48)).wrapping_sub(seed);
        let lo = r64(input, 0) ^ flip1;
        let hi = r64(input, len - 8) ^ flip2;
        let acc = (len as u64).wrapping_add(lo.swap_bytes()).wrapping_add(hi).wrapping_add(mul128_fold64(lo, hi));
        avalanche(acc)
    } else if len >= 4 {
        let seed = seed ^ (u64::from((seed as u32).swap_bytes()) << 32);
        let in1 = r32(input, 0);
        let in2 = r32(input, len - 4);
        let flip = (r64(s, 8) ^ r64(s, 16)).wrapping_sub(seed);
        let mut h = (in2.wrapping_add(in1 << 32)) ^ flip;
        h ^= h.rotate_left(49) ^ h.rotate_left(24);
        h = h.wrapping_mul(0x9FB2_1C65_1E98_DF25);
        h ^= (h >> 35).wrapping_add(len as u64);
        h = h.wrapping_mul(0x9FB2_1C65_1E98_DF25);
        h ^ (h >> 28)
    } else if len > 0 {
        let c1 = u64::from(input[0]);
        let c2 = u64::from(input[len >> 1]);
        let c3 = u64::from(input[len - 1]);
        let combined = (c1 << 16) | (c2 << 24) | c3 | ((len as u64) << 8);
        let flip = (r32(s, 0) ^ r32(s, 4)).wrapping_add(seed);
        xxh64_avalanche(combined ^ flip)
    } else {
        xxh64_avalanche(seed ^ (r64(s, 56) ^ r64(s, 64)))
    }
}

fn len_17to128(input: &[u8], seed: u64) -> u64 {
    let len = input.len();
    let s = &K_SECRET[..];
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = acc.wrapping_add(mix16(input, 48, s, 96, seed));
                acc = acc.wrapping_add(mix16(input, len - 64, s, 112, seed));
            }
            acc = acc.wrapping_add(mix16(input, 32, s, 64, seed));
            acc = acc.wrapping_add(mix16(input, len - 48, s, 80, seed));
        }
        acc = acc.wrapping_add(mix16(input, 16, s, 32, seed));
        acc = acc.wrapping_add(mix16(input, len - 32, s, 48, seed));
    }
    acc = acc.wrapping_add(mix16(input, 0, s, 0, seed));
    acc = acc.wrapping_add(mix16(input, len - 16, s, 16, seed));
    avalanche(acc)
}

fn len_129to240(input: &[u8], seed: u64) -> u64 {
    let len = input.len();
    let s = &K_SECRET[..];
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    for i in 0..8 {
        acc = acc.wrapping_add(mix16(input, 16 * i, s, 16 * i, seed));
    }
    acc = avalanche(acc);
    for i in 8..len / 16 {
        acc = acc.wrapping_add(mix16(input, 16 * i, s, 16 * (i - 8) + 3, seed));
    }
    // XXH3_SECRET_SIZE_MIN (136) - XXH3_MIDSIZE_LASTOFFSET (17)
    acc = acc.wrapping_add(mix16(input, len - 16, s, 136 - 17, seed));
    avalanche(acc)
}

fn accumulate_512(acc: &mut [u64; 8], input: &[u8], at: usize, secret: &[u8], sat: usize) {
    for i in 0..8 {
        let v = r64(input, at + 8 * i);
        let k = v ^ r64(secret, sat + 8 * i);
        acc[i ^ 1] = acc[i ^ 1].wrapping_add(v);
        acc[i] = acc[i].wrapping_add((k & 0xFFFF_FFFF).wrapping_mul(k >> 32));
    }
}

fn scramble(acc: &mut [u64; 8], secret: &[u8], sat: usize) {
    for (i, a) in acc.iter_mut().enumerate() {
        let mut v = *a;
        v ^= v >> 47;
        v ^= r64(secret, sat + 8 * i);
        *a = v.wrapping_mul(PRIME32_1);
    }
}

fn long(input: &[u8], secret: &[u8]) -> u64 {
    let len = input.len();
    let mut acc = [PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1];
    let per_block = (SECRET_SIZE - STRIPE) / 8;
    let nb_blocks = (len - 1) / BLOCK;
    for n in 0..nb_blocks {
        for s in 0..per_block {
            accumulate_512(&mut acc, input, n * BLOCK + s * STRIPE, secret, s * 8);
        }
        scramble(&mut acc, secret, SECRET_SIZE - STRIPE);
    }
    let nb_stripes = ((len - 1) - BLOCK * nb_blocks) / STRIPE;
    for s in 0..nb_stripes {
        accumulate_512(&mut acc, input, nb_blocks * BLOCK + s * STRIPE, secret, s * 8);
    }
    accumulate_512(&mut acc, input, len - STRIPE, secret, SECRET_SIZE - STRIPE - 7);
    let mut result = (len as u64).wrapping_mul(PRIME64_1);
    for i in 0..4 {
        result = result.wrapping_add(mul128_fold64(
            acc[2 * i] ^ r64(secret, 11 + 16 * i),
            acc[2 * i + 1] ^ r64(secret, 11 + 16 * i + 8),
        ));
    }
    avalanche(result)
}

/// `XXH3_64bits_withSeed`.
#[must_use]
pub fn hash_xxh3(input: &[u8], seed: u64) -> u64 {
    let len = input.len();
    if len <= 16 {
        len_0to16(input, seed)
    } else if len <= 128 {
        len_17to128(input, seed)
    } else if len <= 240 {
        len_129to240(input, seed)
    } else if seed == 0 {
        long(input, &K_SECRET)
    } else {
        let mut secret = [0u8; SECRET_SIZE];
        for i in 0..SECRET_SIZE / 16 {
            let lo = r64(&K_SECRET, 16 * i).wrapping_add(seed);
            let hi = r64(&K_SECRET, 16 * i + 8).wrapping_sub(seed);
            secret[16 * i..16 * i + 8].copy_from_slice(&lo.to_le_bytes());
            secret[16 * i + 8..16 * i + 16].copy_from_slice(&hi.to_le_bytes());
        }
        long(input, &secret)
    }
}
