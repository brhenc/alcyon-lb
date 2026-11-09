// Copyright 2015-2025 Brian Smith.
// Portions Copyright (c) 2014, 2015, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{Key, Tag, KEY_LEN, TAG_LEN};
use crate::c;
use core::num::NonZeroUsize;

// XXX/TODO(MSRV): change to `pub(super)`.
pub(in super::super) struct State {
    state: poly1305_state_st,
}

// Keep in sync with `poly1305_state_st` in poly1305.c
#[repr(C, align(64))]
struct poly1305_state_st {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    key: [u8; 16],
}

// ring-alcyon: r, s and the `s` half of the one-time key.
#[cfg(feature = "zeroize")]
impl Drop for State {
    fn drop(&mut self) {
        // SAFETY: `poly1305_state_st` is plain integers; wiping its bytes is valid.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                (&mut self.state as *mut poly1305_state_st).cast::<u8>(),
                core::mem::size_of::<poly1305_state_st>(),
            )
        };
        zeroize::Zeroize::zeroize(bytes);
    }
}

impl State {
    pub(super) fn new_context(key: Key) -> super::Context {
        prefixed_extern! {
            fn CRYPTO_poly1305_init(state: &mut poly1305_state_st, key: &[u8; KEY_LEN]);
        }
        let mut r = Self {
            state: poly1305_state_st {
                r0: 0,
                r1: 0,
                r2: 0,
                r3: 0,
                r4: 0,
                s1: 0,
                s2: 0,
                s3: 0,
                s4: 0,
                h0: 0,
                h1: 0,
                h2: 0,
                h3: 0,
                h4: 0,
                key: [0u8; 16],
            },
        };
        // `key` wipes itself when it drops (feature `zeroize`); no copy of it is made here.
        unsafe { CRYPTO_poly1305_init(&mut r.state, &key.key_and_nonce) }
        super::Context::Fallback(r)
    }

    // `input.len % BLOCK_LEN == 0` must be true for every call except the
    // final one.
    pub(super) fn update_internal(&mut self, input: &[u8]) {
        prefixed_extern! {
            fn CRYPTO_poly1305_update(
                state: &mut poly1305_state_st,
                input: *const u8,
                in_len: c::NonZero_size_t);
        }
        if let Some(len) = NonZeroUsize::new(input.len()) {
            let input = input.as_ptr();
            unsafe { CRYPTO_poly1305_update(&mut self.state, input, len) }
        }
    }

    pub(super) fn finish(mut self) -> Tag {
        prefixed_extern! {
            fn CRYPTO_poly1305_finish(statep: &mut poly1305_state_st, mac: &mut [u8; TAG_LEN]);
        }
        let mut tag = Tag([0u8; TAG_LEN]);
        unsafe { CRYPTO_poly1305_finish(&mut self.state, &mut tag.0) }
        tag
    }
}

// ring-alcyon (zrev): the state holds the clamped r, s and the raw `s` half of the one-time key.
#[cfg(all(test, feature = "zeroize"))]
mod zeroize_tests {
    use super::*;

    #[test]
    fn poly1305_state_is_wiped() {
        let mut key = [0u8; KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = 0x31 + i as u8;
        }
        let needle = key[16..].to_vec();
        let ctx = State::new_context(Key::new(key));
        crate::zeroize_testutil::assert_needle_wiped(ctx, &needle, "poly1305 State");
    }
}
