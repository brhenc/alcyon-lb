// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `XXH3_64bits_withSeed` against python3 `xxhash.xxh3_64_intdigest` (xxhash 4.0.1) for every
//! length class (0, 1-3, 4-8, 9-16, 17-128, 129-240, 241+, 1 KB, 1 MB) and seeds 0, 1, 2^63-1,
//! 2^64-1. `tests/xxh3_vectors.txt` holds them.

#![allow(clippy::cast_possible_truncation)]

use ibex_crypt::xxh3::hash_xxh3;

#[test]
fn matches_the_reference_library() {
    let mut n = 0;
    for line in include_str!("../xxh3_vectors.txt").lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<u64> = line.split(' ').map(|x| x.parse().unwrap()).collect();
        let data: Vec<u8> = (0..f[0]).map(|i| (i * 131 + 17) as u8).collect();
        assert_eq!(hash_xxh3(&data, f[1]), f[2], "len {} seed {}", f[0], f[1]);
        n += 1;
    }
    assert_eq!(n, 148);
}
