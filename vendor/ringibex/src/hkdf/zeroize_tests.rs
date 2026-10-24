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


//! Tests for the `zeroize` feature (ring-ibex): HKDF salt and PRK. Built only
//! with `--features zeroize`.

extern crate std;

use super::*;
use crate::zeroize_testutil::assert_needle_wiped;

#[test]
fn prk_is_wiped() {
    let prk = Prk::new_less_safe(HKDF_SHA256, b"a pseudo random key of 32 bytes!!");
    let (inner, outer) = prk.0.states_for_test();
    assert_needle_wiped(prk.clone(), &inner, "hkdf::Prk inner");
    assert_needle_wiped(prk, &outer, "hkdf::Prk outer");
}

#[test]
fn salt_is_wiped() {
    let salt = Salt::new(HKDF_SHA384, b"a secret salt");
    let (inner, outer) = salt.0.states_for_test();
    assert_needle_wiped(Salt::new(HKDF_SHA384, b"a secret salt"), &inner, "hkdf::Salt inner");
    assert_needle_wiped(salt, &outer, "hkdf::Salt outer");
}
