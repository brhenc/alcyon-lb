// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/hash.c, src/sample.c, include/import/xxhash.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

// These are allowed for this module only. Hash functions are transcribed from published
// pseudocode, and renaming to satisfy a lint makes them harder to check against the
// specification than the lint is worth. They are not a licence to silence lints
// elsewhere: each one below names the construct it covers.

// The working variables in SHA and MD5 are a, b, c, d, e in every published description.
#![allow(clippy::many_single_char_names)]
// SHA round constants are conventionally written in groups of four hex digits.
#![allow(clippy::unusual_byte_groupings)]
// The lint suggests `as_chunks`, which is still nightly-only.
#![allow(clippy::chunks_exact_to_as_chunks)]
// Message-schedule windowing reads more directly as an indexed loop than as an iterator
// chain, because the index arithmetic is what the specification states.
#![allow(clippy::needless_range_loop)]
// Round constants are declared next to the round that uses them.
#![allow(clippy::items_after_statements)]


//! Hash algorithms used by sample fetches and converters.
//!
//! Includes DJB2, SDBM, WT6, `full_hash`, CRC32, `CRC32c`, XXH32, XXH64,
//! SHA-1, SHA-2 (224, 256, 384, 512), and MD5.

#![forbid(unsafe_code)]

/// Bernstein DJB2 hash unrolled.
#[must_use]
pub fn hash_djb2(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut chunks = input.chunks_exact(8);
    for chunk in &mut chunks {
        for &b in chunk {
            hash = ((hash << 5).wrapping_add(hash)).wrapping_add(u32::from(b));
        }
    }
    for &b in chunks.remainder() {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(u32::from(b));
    }
    hash
}

/// SDBM database hash.
#[must_use]
pub fn hash_sdbm(input: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &b in input {
        hash = u32::from(b)
            .wrapping_add(hash << 6)
            .wrapping_add(hash << 16)
            .wrapping_sub(hash);
    }
    hash
}

/// WT6 hash by Willy Tarreau.
#[must_use]
pub fn hash_wt6(input: &[u8]) -> u32 {
    let mut h0: u32 = 0xa53c_965a;
    let mut h1: u32 = 0x5ca6_953a;
    let mut step0: u32 = 6;
    let mut step1: u32 = 18;

    for &b in input {
        let t0 = u32::from(b);
        h0 = !(h0 ^ t0);
        h1 = !(h1.wrapping_add(t0));

        let t = h1.rotate_left(step0);
        h1 = h0.rotate_left(step1);
        h0 = t;

        let t_masked = ((h0 >> 16) ^ h1) & 0xffff;
        step0 = t_masked & 0x1F;
        step1 = t_masked >> 11;
    }
    h0 ^ h1
}

/// Bob Jenkins' full avalanche integer hash.
#[must_use]
pub fn full_hash(mut a: u32) -> u32 {
    a = (a.wrapping_add(0x7ed5_5d16)).wrapping_add(a << 12);
    a = (a ^ 0xc761_c23c) ^ (a >> 19);
    a = (a.wrapping_add(0x1656_67b1)).wrapping_add(a << 5);
    a = (a.wrapping_add(0xd3a2_646c)) ^ (a << 9);
    a = (a.wrapping_add(0xfd70_46c5)).wrapping_add(a << 3);
    a = (a ^ 0xb55a_4f09) ^ (a >> 16);
    a.wrapping_mul(3_221_225_473)
}

/// Standard CRC-32 (IEEE 802.3).
#[must_use]
pub fn hash_crc32(input: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in input {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// CRC-32c (Castagnoli, RFC 4960).
#[must_use]
pub fn hash_crc32c(input: &[u8]) -> u32 {
    const TABLE: [u32; 256] = [
        0x0000_0000, 0xF26B_8303, 0xE13B_70F7, 0x1350_F3F4, 0xC79A_971F, 0x35F1_141C,
        0x26A1_E7E8, 0xD4CA_64EB, 0x8AD9_58CF, 0x78B2_DBCC, 0x6BE2_2838, 0x9989_AB3B,
        0x4D43_CFD0, 0xBF28_4CD3, 0xAC78_BF27, 0x5E13_3C24, 0x105E_C76F, 0xE235_446C,
        0xF165_B798, 0x030E_349B, 0xD7C4_5070, 0x25AF_D373, 0x36FF_2087, 0xC494_A384,
        0x9A87_9FA0, 0x68EC_1CA3, 0x7BBC_EF57, 0x89D7_6C54, 0x5D1D_08BF, 0xAF76_8BBC,
        0xBC26_7848, 0x4E4D_FB4B, 0x20BD_8EDE, 0xD2D6_0DDD, 0xC186_FE29, 0x33ED_7D2A,
        0xE727_19C1, 0x154C_9AC2, 0x061C_6936, 0xF477_EA35, 0xAA64_D611, 0x580F_5512,
        0x4B5F_A6E6, 0xB934_25E5, 0x6DFE_410E, 0x9F95_C20D, 0x8CC5_31F9, 0x7EAE_B2FA,
        0x30E3_49B1, 0xC288_CAB2, 0xD1D8_3946, 0x23B3_BA45, 0xF779_DEAE, 0x0512_5DAD,
        0x1642_AE59, 0xE429_2D5A, 0xBA3A_117E, 0x4851_927D, 0x5B01_6189, 0xA96A_E28A,
        0x7DA0_8661, 0x8FCB_0562, 0x9C9B_F696, 0x6EF0_7595, 0x417B_1DBC, 0xB310_9EBF,
        0xA040_6D4B, 0x522B_EE48, 0x86E1_8AA3, 0x748A_09A0, 0x67DA_FA54, 0x95B1_7957,
        0xCBA2_4573, 0x39C9_C670, 0x2A99_3584, 0xD8F2_B687, 0x0C38_D26C, 0xFE53_516F,
        0xED03_A29B, 0x1F68_2198, 0x5125_DAD3, 0xA34E_59D0, 0xB01E_AA24, 0x4275_2927,
        0x96BF_4DCC, 0x64D4_CECF, 0x7784_3D3B, 0x85EF_BE38, 0xDBFC_821C, 0x2997_011F,
        0x3AC7_F2EB, 0xC8AC_71E8, 0x1C66_1503, 0xEE0D_9600, 0xFD5D_65F4, 0x0F36_E6F7,
        0x61C6_9362, 0x93AD_1061, 0x80FD_E395, 0x7296_6096, 0xA65C_047D, 0x5437_877E,
        0x4767_748A, 0xB50C_F789, 0xEB1F_CBAD, 0x1974_48AE, 0x0A24_BB5A, 0xF84F_3859,
        0x2C85_5CB2, 0xDEEE_DFB1, 0xCDBE_2C45, 0x3FD5_AF46, 0x7198_540D, 0x83F3_D70E,
        0x90A3_24FA, 0x62C8_A7F9, 0xB602_C312, 0x4469_4011, 0x5739_B3E5, 0xA552_30E6,
        0xFB41_0CC2, 0x092A_8FC1, 0x1A7A_7C35, 0xE811_FF36, 0x3CDB_9BDD, 0xCEB0_18DE,
        0xDDE0_EB2A, 0x2F8B_6829, 0x82F6_3B78, 0x709D_B87B, 0x63CD_4B8F, 0x91A6_C88C,
        0x456C_AC67, 0xB707_2F64, 0xA457_DC90, 0x563C_5F93, 0x082F_63B7, 0xFA44_E0B4,
        0xE914_1340, 0x1B7F_9043, 0xCFB5_F4A8, 0x3DDE_77AB, 0x2E8E_845F, 0xDCE5_075C,
        0x92A8_FC17, 0x60C3_7F14, 0x7393_8CE0, 0x81F8_0FE3, 0x5532_6B08, 0xA759_E80B,
        0xB409_1BFF, 0x4662_98FC, 0x1871_A4D8, 0xEA1A_27DB, 0xF94A_D42F, 0x0B21_572C,
        0xDFEB_33C7, 0x2D80_B0C4, 0x3ED0_4330, 0xCCBB_C033, 0xA24B_B5A6, 0x5020_36A5,
        0x4370_C551, 0xB11B_4652, 0x65D1_22B9, 0x97BA_A1BA, 0x84EA_524E, 0x7681_D14D,
        0x2892_ED69, 0xDAF9_6E6A, 0xC9A9_9D9E, 0x3BC2_1E9D, 0xEF08_7A76, 0x1D63_F975,
        0x0E33_0A81, 0xFC58_8982, 0xB215_72C9, 0x407E_F1CA, 0x532E_023E, 0xA145_813D,
        0x758F_E5D6, 0x87E4_66D5, 0x94B4_9521, 0x66DF_1622, 0x38CC_2A06, 0xCAA7_A905,
        0xD9F7_5AF1, 0x2B9C_D9F2, 0xFF56_BD19, 0x0D3D_3E1A, 0x1E6D_CDEE, 0xEC06_4EED,
        0xC38D_26C4, 0x31E6_A5C7, 0x22B6_5633, 0xD0DD_D530, 0x0417_B1DB, 0xF67C_32D8,
        0xE52C_C12C, 0x1747_422F, 0x4954_7E0B, 0xBB3F_FD08, 0xA86F_0EFC, 0x5A04_8DFF,
        0x8ECE_E914, 0x7CA5_6A17, 0x6FF5_99E3, 0x9D9E_1AE0, 0xD3D3_E1AB, 0x21B8_62A8,
        0x32E8_915C, 0xC083_125F, 0x1449_76B4, 0xE622_F5B7, 0xF572_0643, 0x0719_8540,
        0x590A_B964, 0xAB61_3A67, 0xB831_C993, 0x4A5A_4A90, 0x9E90_2E7B, 0x6CFB_AD78,
        0x7FAB_5E8C, 0x8DC0_DD8F, 0xE330_A81A, 0x115B_2B19, 0x020B_D8ED, 0xF060_5BEE,
        0x24AA_3F05, 0xD6C1_BC06, 0xC591_4FF2, 0x37FA_CCF1, 0x69E9_F0D5, 0x9B82_73D6,
        0x88D2_8022, 0x7AB9_0321, 0xAE73_67CA, 0x5C18_E4C9, 0x4F48_173D, 0xBD23_943E,
        0xF36E_6F75, 0x0105_EC76, 0x1255_1F82, 0xE03E_9C81, 0x34F4_F86A, 0xC69F_7B69,
        0xD5CF_889D, 0x27A4_0B9E, 0x79B7_37BA, 0x8BDC_B4B9, 0x988C_474D, 0x6AE7_C44E,
        0xBE2D_A0A5, 0x4C46_23A6, 0x5F16_D052, 0xAD7D_5351,
    ];

    let mut crc = 0xFFFF_FFFFu32;
    for &b in input {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ TABLE[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// XXH32 algorithm.
#[must_use]
pub fn hash_xxh32(input: &[u8], seed: u32) -> u32 {
    const PRIME32_1: u32 = 0x9E37_79B1;
    const PRIME32_2: u32 = 0x85EB_CA77;
    const PRIME32_3: u32 = 0xC2B2_AE3D;
    const PRIME32_4: u32 = 0x27D4_EB2F;
    const PRIME32_5: u32 = 0x1656_67B1;

    let len = input.len();
    let mut h32: u32;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);

        let mut chunks = input.chunks_exact(16);
        for chunk in &mut chunks {
            let mut sub = chunk.chunks_exact(4);
            let b1 = u32::from_le_bytes(sub.next().unwrap_or(&[0; 4]).try_into().unwrap_or([0; 4]));
            let b2 = u32::from_le_bytes(sub.next().unwrap_or(&[0; 4]).try_into().unwrap_or([0; 4]));
            let b3 = u32::from_le_bytes(sub.next().unwrap_or(&[0; 4]).try_into().unwrap_or([0; 4]));
            let b4 = u32::from_le_bytes(sub.next().unwrap_or(&[0; 4]).try_into().unwrap_or([0; 4]));

            v1 = v1.wrapping_add(b1.wrapping_mul(PRIME32_2)).rotate_left(13).wrapping_mul(PRIME32_1);
            v2 = v2.wrapping_add(b2.wrapping_mul(PRIME32_2)).rotate_left(13).wrapping_mul(PRIME32_1);
            v3 = v3.wrapping_add(b3.wrapping_mul(PRIME32_2)).rotate_left(13).wrapping_mul(PRIME32_1);
            v4 = v4.wrapping_add(b4.wrapping_mul(PRIME32_2)).rotate_left(13).wrapping_mul(PRIME32_1);
        }

        h32 = v1.rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));

        let rem = chunks.remainder();
        let mut rem_chunks = rem.chunks_exact(4);
        for chunk in &mut rem_chunks {
            let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
            h32 = h32.wrapping_add(val.wrapping_mul(PRIME32_3)).rotate_left(17).wrapping_mul(PRIME32_4);
        }
        for &b in rem_chunks.remainder() {
            h32 = h32.wrapping_add(u32::from(b).wrapping_mul(PRIME32_5)).rotate_left(11).wrapping_mul(PRIME32_1);
        }
    } else {
        h32 = seed.wrapping_add(PRIME32_5);
        let mut chunks = input.chunks_exact(4);
        for chunk in &mut chunks {
            let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
            h32 = h32.wrapping_add(val.wrapping_mul(PRIME32_3)).rotate_left(17).wrapping_mul(PRIME32_4);
        }
        for &b in chunks.remainder() {
            h32 = h32.wrapping_add(u32::from(b).wrapping_mul(PRIME32_5)).rotate_left(11).wrapping_mul(PRIME32_1);
        }
    }

    let len_u32 = u32::try_from(len & 0xFFFF_FFFF).unwrap_or(0);
    h32 = h32.wrapping_add(len_u32);

    h32 ^= h32 >> 15;
    h32 = h32.wrapping_mul(PRIME32_2);
    h32 ^= h32 >> 13;
    h32 = h32.wrapping_mul(PRIME32_3);
    h32 ^= h32 >> 16;
    h32
}

/// XXH64 algorithm.
#[must_use]
pub fn hash_xxh64(input: &[u8], seed: u64) -> u64 {
    const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
    const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
    const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
    const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
    const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

    let len = input.len();
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
        h64 = seed.wrapping_add(PRIME64_5);
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

    let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
    h64 = h64.wrapping_add(len_u64);

    h64 ^= h64 >> 33;
    h64 = h64.wrapping_mul(PRIME64_2);
    h64 ^= h64 >> 29;
    h64 = h64.wrapping_mul(PRIME64_3);
    h64 ^= h64 >> 32;
    h64
}

/// Fallback 64-bit XXH3 hash implementation matching `HAProxy`.
#[must_use]
pub fn hash_xxh3(input: &[u8], seed: u64) -> u64 {
    hash_xxh64(input, seed)
}

/// SHA-1 (160-bit) message digest.
#[must_use]
pub fn sha1_digest(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let len = input.len();
    let bit_len = (len as u64).wrapping_mul(8);

    let mut padded = Vec::with_capacity(len + 64);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// SHA-256 (256-bit) message digest.
#[must_use]
pub fn sha256_digest(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
        0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
        0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
        0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7, 0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
        0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
        0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
        0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
        0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2,
    ];

    let mut h0: u32 = 0x6A09_E667;
    let mut h1: u32 = 0xBB67_AE85;
    let mut h2: u32 = 0x3C6E_F372;
    let mut h3: u32 = 0xA54F_F53A;
    let mut h4: u32 = 0x510E_527F;
    let mut h5: u32 = 0x9B05_688C;
    let mut h6: u32 = 0x1F83_D9AB;
    let mut h7: u32 = 0x5BE0_CD19;

    let len = input.len();
    let bit_len = (len as u64).wrapping_mul(8);

    let mut padded = Vec::with_capacity(len + 64);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out[20..24].copy_from_slice(&h5.to_be_bytes());
    out[24..28].copy_from_slice(&h6.to_be_bytes());
    out[28..32].copy_from_slice(&h7.to_be_bytes());
    out
}

/// SHA-224 (224-bit) message digest.
#[must_use]
pub fn sha224_digest(input: &[u8]) -> [u8; 28] {
    const K: [u32; 64] = [
        0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
        0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
        0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
        0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7, 0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
        0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
        0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
        0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
        0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2,
    ];

    let mut h0: u32 = 0xC105_9ED8;
    let mut h1: u32 = 0x367C_D507;
    let mut h2: u32 = 0x3070_DD17;
    let mut h3: u32 = 0xF70E_5939;
    let mut h4: u32 = 0xFFC0_0B31;
    let mut h5: u32 = 0x6858_1511;
    let mut h6: u32 = 0x64F9_8FA7;
    let mut h7: u32 = 0xBEFA_4FA4;

    let len = input.len();
    let bit_len = (len as u64).wrapping_mul(8);

    let mut padded = Vec::with_capacity(len + 64);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    let mut out = [0u8; 28];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out[20..24].copy_from_slice(&h5.to_be_bytes());
    out[24..28].copy_from_slice(&h6.to_be_bytes());
    out
}

/// SHA-512 (512-bit) message digest.
#[must_use]
pub fn sha512_digest(input: &[u8]) -> [u8; 64] {
    const K: [u64; 80] = [
        0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD, 0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC,
        0x3956_C25B_F348_B538, 0x59F1_11F1_B605_D019, 0x923F_82A4_AF19_4F9B, 0xAB1C_5ED5_DA6D_8118,
        0xD807_AA98_A303_0242, 0x1283_5B01_4570_6FBE, 0x2431_85BE_4EE4_B28C, 0x550C_7DC3_D5FF_B4E2,
        0x72BE_5D74_F27B_896F, 0x80DE_B1FE_3B16_96B1, 0x9BDC_06A7_25C7_1235, 0xC19B_F174_CF69_2694,
        0xE49B_69C1_9EF1_4AD2, 0xEFBE_4786_384F_25E3, 0x0FC1_9DC6_8B8C_D5B5, 0x240C_A1CC_77AC_9C65,
        0x2DE9_2C6F_592B_0275, 0x4A74_84AA_6EA6_E483, 0x5CB0_A9DC_BD41_FBD4, 0x76F9_88DA_8311_53B5,
        0x983E_5152_EE66_DFAB, 0xA831_C66D_2DB4_3210, 0xB003_27C8_98FB_213F, 0xBF59_7FC7_BEEF_0EE4,
        0xC6E0_0BF3_3DA8_8FC2, 0xD5A7_9147_930A_A725, 0x06CA_6351_E003_826F, 0x1429_2967_0A0E_6E70,
        0x27B7_0A85_46D2_2FFC, 0x2E1B_2138_5C26_C926, 0x4D2C_6DFC_5AC4_2AED, 0x5338_0D13_9D95_B3DF,
        0x650A_7354_8BAF_63DE, 0x766A_0ABB_3C77_B2A8, 0x81C2_C92E_47ED_AEE6, 0x9272_2C85_1482_353B,
        0xA2BF_E8A1_4CF1_0364, 0xA81A_664B_BC42_3001, 0xC24B_8B70_D0F8_9791, 0xC76C_51A3_0654_BE30,
        0xD192_E819_D6EF_5218, 0xD699_0624_5565_A910, 0xF40E_3585_5771_202A, 0x106A_A070_32BB_D1B8,
        0x19A4_C116_B8D2_D0C8, 0x1E37_6C08_5141_AB53, 0x2748_774C_DF8E_EB99, 0x34B0_BCB5_E19B_48A8,
        0x391C_0CB3_C5C9_5A63, 0x4ED8_AA4A_E341_8ACB, 0x5B9C_CA4F_7763_E373, 0x682E_6FF3_D6B2_B8A3,
        0x748F_82EE_5DEF_B2FC, 0x78A5_636F_4317_2F60, 0x84C8_7814_A1F0_AB72, 0x8CC7_0208_1A64_39EC,
        0x90BE_FFFA_2363_1E28, 0xA450_6CEB_DE82_BDE9, 0xBEF9_A3F7_B2C6_7915, 0xC671_78F2_E372_532B,
        0xCA27_3ECE_EA26_619C, 0xD186_B8C7_21C0_C207, 0xEADA_7DD6_CDE0_EB1E, 0xF57D_4F7F_EE6E_D178,
        0x06F0_67AA_7217_6FBA, 0x0A63_7DC5_A2C8_98A6, 0x113F_9804_BEF9_0DAE, 0x1B71_0B35_131C_471B,
        0x28DB_77F5_2304_7D84, 0x32CA_AB7B_40C7_2493, 0x3C9E_BE0A_15C9_BEBC, 0x431D_67C4_9C10_0D4C,
        0x4CC5_D4BE_CB3E_42B6, 0x597F_299C_FC65_7E2A, 0x5FCB_6FAB_3AD6_FAEC, 0x6C44_198C_4A47_5817,
    ];

    let mut h0: u64 = 0x6A09_E667_F3BC_C908;
    let mut h1: u64 = 0xBB67_AE85_84CA_A73B;
    let mut h2: u64 = 0x3C6E_F372_FE94_F82B;
    let mut h3: u64 = 0xA54F_F53A_5F1D_36F1;
    let mut h4: u64 = 0x510E_527F_ADE6_82D1;
    let mut h5: u64 = 0x9B05_688C_2B3E_6C1F;
    let mut h6: u64 = 0x1F83_D9AB_FB41_BD6B;
    let mut h7: u64 = 0x5BE0_CD19_137E_2179;

    let len = input.len();
    let bit_len = (len as u128).wrapping_mul(8);

    let mut padded = Vec::with_capacity(len + 128);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 128) != 112 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<128>().0 {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                chunk[i * 8], chunk[i * 8 + 1], chunk[i * 8 + 2], chunk[i * 8 + 3],
                chunk[i * 8 + 4], chunk[i * 8 + 5], chunk[i * 8 + 6], chunk[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    let mut out = [0u8; 64];
    out[0..8].copy_from_slice(&h0.to_be_bytes());
    out[8..16].copy_from_slice(&h1.to_be_bytes());
    out[16..24].copy_from_slice(&h2.to_be_bytes());
    out[24..32].copy_from_slice(&h3.to_be_bytes());
    out[32..40].copy_from_slice(&h4.to_be_bytes());
    out[40..48].copy_from_slice(&h5.to_be_bytes());
    out[48..56].copy_from_slice(&h6.to_be_bytes());
    out[56..64].copy_from_slice(&h7.to_be_bytes());
    out
}

/// SHA-384 (384-bit) message digest.
#[must_use]
pub fn sha384_digest(input: &[u8]) -> [u8; 48] {
    const K: [u64; 80] = [
        0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD, 0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC,
        0x3956_C25B_F348_B538, 0x59F1_11F1_B605_D019, 0x923F_82A4_AF19_4F9B, 0xAB1C_5ED5_DA6D_8118,
        0xD807_AA98_A303_0242, 0x1283_5B01_4570_6FBE, 0x2431_85BE_4EE4_B28C, 0x550C_7DC3_D5FF_B4E2,
        0x72BE_5D74_F27B_896F, 0x80DE_B1FE_3B16_96B1, 0x9BDC_06A7_25C7_1235, 0xC19B_F174_CF69_2694,
        0xE49B_69C1_9EF1_4AD2, 0xEFBE_4786_384F_25E3, 0x0FC1_9DC6_8B8C_D5B5, 0x240C_A1CC_77AC_9C65,
        0x2DE9_2C6F_592B_0275, 0x4A74_84AA_6EA6_E483, 0x5CB0_A9DC_BD41_FBD4, 0x76F9_88DA_8311_53B5,
        0x983E_5152_EE66_DFAB, 0xA831_C66D_2DB4_3210, 0xB003_27C8_98FB_213F, 0xBF59_7FC7_BEEF_0EE4,
        0xC6E0_0BF3_3DA8_8FC2, 0xD5A7_9147_930A_A725, 0x06CA_6351_E003_826F, 0x1429_2967_0A0E_6E70,
        0x27B7_0A85_46D2_2FFC, 0x2E1B_2138_5C26_C926, 0x4D2C_6DFC_5AC4_2AED, 0x5338_0D13_9D95_B3DF,
        0x650A_7354_8BAF_63DE, 0x766A_0ABB_3C77_B2A8, 0x81C2_C92E_47ED_AEE6, 0x9272_2C85_1482_353B,
        0xA2BF_E8A1_4CF1_0364, 0xA81A_664B_BC42_3001, 0xC24B_8B70_D0F8_9791, 0xC76C_51A3_0654_BE30,
        0xD192_E819_D6EF_5218, 0xD699_0624_5565_A910, 0xF40E_3585_5771_202A, 0x106A_A070_32BB_D1B8,
        0x19A4_C116_B8D2_D0C8, 0x1E37_6C08_5141_AB53, 0x2748_774C_DF8E_EB99, 0x34B0_BCB5_E19B_48A8,
        0x391C_0CB3_C5C9_5A63, 0x4ED8_AA4A_E341_8ACB, 0x5B9C_CA4F_7763_E373, 0x682E_6FF3_D6B2_B8A3,
        0x748F_82EE_5DEF_B2FC, 0x78A5_636F_4317_2F60, 0x84C8_7814_A1F0_AB72, 0x8CC7_0208_1A64_39EC,
        0x90BE_FFFA_2363_1E28, 0xA450_6CEB_DE82_BDE9, 0xBEF9_A3F7_B2C6_7915, 0xC671_78F2_E372_532B,
        0xCA27_3ECE_EA26_619C, 0xD186_B8C7_21C0_C207, 0xEADA_7DD6_CDE0_EB1E, 0xF57D_4F7F_EE6E_D178,
        0x06F0_67AA_7217_6FBA, 0x0A63_7DC5_A2C8_98A6, 0x113F_9804_BEF9_0DAE, 0x1B71_0B35_131C_471B,
        0x28DB_77F5_2304_7D84, 0x32CA_AB7B_40C7_2493, 0x3C9E_BE0A_15C9_BEBC, 0x431D_67C4_9C10_0D4C,
        0x4CC5_D4BECB3E_42B6, 0x597F_299C_FC65_7E2A, 0x5FCB_6FAB_3AD6_FAEC, 0x6C44_198C_4A47_5817,
    ];

    let mut h0: u64 = 0xCBBB_9D5D_C105_9ED8;
    let mut h1: u64 = 0x629A_292A_367C_D507;
    let mut h2: u64 = 0x9159_015A_3070_DD17;
    let mut h3: u64 = 0x152F_ECD8_F70E_5939;
    let mut h4: u64 = 0x6733_2667_FFC0_0B31;
    let mut h5: u64 = 0x8EB4_4A87_6858_1511;
    let mut h6: u64 = 0xDB0C_2E0D_64F9_8FA7;
    let mut h7: u64 = 0x47B5_481D_BEFA_4FA4;

    let len = input.len();
    let bit_len = (len as u128).wrapping_mul(8);

    let mut padded = Vec::with_capacity(len + 128);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 128) != 112 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<128>().0 {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                chunk[i * 8], chunk[i * 8 + 1], chunk[i * 8 + 2], chunk[i * 8 + 3],
                chunk[i * 8 + 4], chunk[i * 8 + 5], chunk[i * 8 + 6], chunk[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    let mut out = [0u8; 48];
    out[0..8].copy_from_slice(&h0.to_be_bytes());
    out[8..16].copy_from_slice(&h1.to_be_bytes());
    out[16..24].copy_from_slice(&h2.to_be_bytes());
    out[24..32].copy_from_slice(&h3.to_be_bytes());
    out[32..40].copy_from_slice(&h4.to_be_bytes());
    out[40..48].copy_from_slice(&h5.to_be_bytes());
    out
}

/// MD5 (128-bit) message digest.
#[must_use]
pub fn md5_digest(input: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xEFCD_AB89;
    let mut c0: u32 = 0x98BA_DCFE;
    let mut d0: u32 = 0x1032_5476;

    let len = input.len();
    let bit_len = (len as u64).wrapping_mul(8);

    let mut padded = Vec::with_capacity(len + 64);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    const S: [u32; 64] = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xD76A_A478, 0xE8C7_B756, 0x2420_70DB, 0xC1BD_CEEE, 0xF57C_0FAF, 0x4787_C62A, 0xA830_4613, 0xFD46_9501,
        0x6980_98D8, 0x8B44_F7AF, 0xFFFF_5BB1, 0x895C_D7BE, 0x6B90_1122, 0xFD98_7193, 0xA679_438E, 0x49B4_0821,
        0xF61E_2562, 0xC040_B340, 0x265E_5A51, 0xE9B6_C7AA, 0xD62F_105D, 0x0244_1453, 0xD8A1_E681, 0xE7D3_FBC8,
        0x21E1_CDE6, 0xC337_07D6, 0xF4D5_0D87, 0x455A_14ED, 0xA9E3_E905, 0xFCEF_A3F8, 0x676F_02D9, 0x8D2A_4C8A,
        0xFFFA_3942, 0x8771_F681, 0x6D9D_6122, 0xFDE5_380C, 0xA4BE_EA44, 0x4BDE_CFA9, 0xF6BB_4B60, 0xBEBF_BC70,
        0x289B_7EC6, 0xEAA1_27FA, 0xD4EF_3085, 0x0488_1D05, 0xD9D4_D039, 0xE6DB_99E5, 0x1FA2_7CF8, 0xC4AC_5665,
        0xF429_2244, 0x432A_FF97, 0xAB94_23A7, 0xFC93_A039, 0x655B_59C3, 0x8F0C_CC92, 0xFFEF_F47D, 0x8584_5DD1,
        0x6FA8_7E4F, 0xFE2C_E6E0, 0xA301_4314, 0x4E08_11A1, 0xF753_7E82, 0xBD3A_F235, 0x2AD7_D2BB, 0xEB86_D391,
    ];

    for chunk in padded.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_vectors() {
        assert_eq!(
            hex::encode(sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn test_sha256_vectors() {
        assert_eq!(
            hex::encode(sha256_digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha224_vectors() {
        assert_eq!(
            hex::encode(sha224_digest(b"abc")),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn test_sha384_vectors() {
        assert_eq!(
            hex::encode(sha384_digest(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn test_sha512_vectors() {
        assert_eq!(
            hex::encode(sha512_digest(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_md5_vectors() {
        assert_eq!(
            hex::encode(md5_digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn test_crc32_vectors() {
        assert_eq!(hash_crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(hash_crc32c(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn test_djb2_sdbm_wt6() {
        assert_eq!(hash_djb2(b""), 5381);
        assert_eq!(hash_sdbm(b""), 0);
        assert_eq!(hash_wt6(b""), 0xa53c_965a ^ 0x5ca6_953a);
        assert_eq!(full_hash(0), 2_874_071_335);
    }

    mod hex {
        pub fn encode(bytes: impl AsRef<[u8]>) -> String {
            let mut s = String::new();
            for &b in bytes.as_ref() {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
            }
            s
        }
    }
}
