// Copyright 2026 Ibex contributors.
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


//! Tests for the `zeroize` feature (ring-ibex): HMAC keyed state must not
//! survive being dropped. Built only with `--features zeroize`.

extern crate std;

use super::*;
use crate::{digest, zeroize_testutil::assert_needle_wiped};

const KEY: &[u8] = b"an HMAC key that is secret, 32 B";

#[test]
fn hmac_key_state_is_wiped() {
    for alg in [HMAC_SHA256, HMAC_SHA384, HMAC_SHA512] {
        let key = Key::new(alg, KEY);
        let (inner, outer) = key.states_for_test();
        assert_ne!(inner, outer);
        let inner_c = inner.clone();
        assert_needle_wiped(key.clone(), &inner_c, "hmac::Key inner");
        assert_needle_wiped(key, &outer, "hmac::Key outer");
    }
}

#[test]
fn hmac_context_state_is_wiped() {
    let key = Key::new(HMAC_SHA256, KEY);
    let (inner, outer) = key.states_for_test();
    // The inner context's state advances with `update`; check before updating.
    let ctx = Context::with_key(&key);
    assert_needle_wiped(ctx.clone(), &outer, "hmac::Context outer");
    assert_needle_wiped(ctx, &inner, "hmac::Context inner");
}

#[test]
fn digest_context_state_is_wiped() {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(&[0x5a; 64]);
    let st = ctx.state_bytes_for_test();
    assert_needle_wiped(ctx, &st, "digest::Context");
}
