// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A deterministic, position-dependent byte stream, and a checker for it.
//!
//! Byte `i` of stream `seed` is a function of `(seed, i)` with no short period, so a
//! byte lost, duplicated or reordered anywhere shows up at the first position after it --
//! which a repeated `a` or a short cycle would hide.

fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn word(seed: u64, i: u64) -> [u8; 8] {
    splitmix64(seed.wrapping_mul(0xD6E8_FEB8_6659_FD93) ^ (i >> 3)).to_le_bytes()
}

/// Byte `i` of stream `seed`.
#[must_use]
pub fn byte(seed: u64, i: u64) -> u8 {
    word(seed, i)[usize::try_from(i & 7).unwrap_or(0)]
}

/// Fills `buf` with bytes `start..start + buf.len()` of stream `seed`.
pub fn fill(seed: u64, start: u64, buf: &mut [u8]) {
    for (i, b) in (start..).zip(buf.iter_mut()) {
        *b = byte(seed, i);
    }
}

/// `len` bytes of stream `seed` from position 0.
#[must_use]
pub fn bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    fill(seed, 0, &mut v);
    v
}

/// Checks a stream as it arrives, in pieces of any size.
#[derive(Debug, Clone)]
pub struct Checker {
    seed: u64,
    pos: u64,
    /// The first position at which the stream differed, with what arrived and what was due.
    pub mismatch: Option<(u64, u8, u8)>,
}

impl Checker {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { seed, pos: 0, mismatch: None }
    }

    /// Bytes checked so far.
    #[must_use]
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Checks the next `data.len()` bytes. Returns false once any byte has differed.
    pub fn feed(&mut self, data: &[u8]) -> bool {
        if self.mismatch.is_some() {
            self.pos += data.len() as u64;
            return false;
        }
        let start = self.pos;
        for (i, &b) in data.iter().enumerate() {
            let at = start + i as u64;
            let want = byte(self.seed, at);
            if b != want {
                self.mismatch = Some((at, b, want));
                break;
            }
        }
        // Every byte counts towards the position, matching or not.
        self.pos = start + data.len() as u64;
        self.mismatch.is_none()
    }

    /// A description of the first difference, if there was one.
    #[must_use]
    pub fn error(&self) -> Option<String> {
        self.mismatch.map(|(at, got, want)| {
            format!("stream {:#x}: byte {at} is {got:#04x}, expected {want:#04x}", self.seed)
        })
    }
}
