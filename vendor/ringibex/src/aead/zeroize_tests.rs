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


//! Tests for the `zeroize` feature (ring-ibex): AEAD key schedules must not
//! survive being dropped. Built only with `--features zeroize`.

extern crate std;

use super::*;
use crate::{
    aead::{
        aes::{self, KeyBytes},
        chacha,
        gcm::{self, KeyValue},
        poly1305,
    },
    cpu::{self, GetFeature as _},
    zeroize_testutil::{assert_all_zero_after, assert_needle_wiped},
};

const K32: [u8; 32] = [
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x0a,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x02,
];

#[test]
fn aes_fallback_key_schedule_is_wiped() {
    let k = aes::fallback::Key::new(KeyBytes::AES_256(&K32)).unwrap();
    assert_all_zero_after(k, "aes::fallback::Key");
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn aes_hw_key_schedule_is_wiped() {
    let cpu = cpu::features();
    let Some(req) = cpu.get_feature() else { return };
    let k = aes::hw::Key::new(KeyBytes::AES_256(&K32), req, cpu.get_feature()).unwrap();
    assert_needle_wiped(k, &K32, "aes::hw::Key");
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn aes_vp_key_schedule_is_wiped() {
    let cpu = cpu::features();
    let Some(req) = cpu.get_feature() else { return };
    let k = aes::vp::Key::new(KeyBytes::AES_256(&K32), req).unwrap();
    assert_all_zero_after(k, "aes::vp::Key");
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn ghash_clmul_table_is_wiped() {
    let cpu = cpu::features();
    let Some(req) = cpu.get_feature() else { return };
    let k = gcm::clmul::Key::new(KeyValue::new(*b"0123456789abcdef"), req);
    assert_all_zero_after(k, "gcm::clmul::Key");
}

#[test]
fn ghash_fallback_key_is_wiped() {
    let k = gcm::fallback::Key::new(KeyValue::new(*b"0123456789abcdef"));
    assert_all_zero_after(k, "gcm::fallback::Key");
}

#[test]
fn ghash_key_value_is_wiped() {
    assert_all_zero_after(KeyValue::new(*b"0123456789abcdef"), "gcm::KeyValue");
}

#[test]
fn chacha_key_is_wiped() {
    assert_needle_wiped(chacha::Key::new(K32), &K32, "chacha::Key");
}

#[test]
fn poly1305_key_is_wiped() {
    assert_needle_wiped(poly1305::Key::new(K32), &K32, "poly1305::Key");
}

#[test]
fn less_safe_key_aes_256_gcm_is_wiped() {
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &K32).unwrap());
    assert_needle_wiped(k, &K32, "LessSafeKey(AES-256-GCM)");
}

#[test]
fn less_safe_key_aes_128_gcm_is_wiped() {
    let k = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &K32[..16]).unwrap());
    assert_needle_wiped(k, &K32[..16], "LessSafeKey(AES-128-GCM)");
}

#[test]
fn unbound_key_chacha20_poly1305_is_wiped() {
    let k = UnboundKey::new(&CHACHA20_POLY1305, &K32).unwrap();
    assert_needle_wiped(k, &K32, "UnboundKey(CHACHA20_POLY1305)");
}

#[test]
fn quic_header_protection_key_is_wiped() {
    let k = quic::HeaderProtectionKey::new(&quic::CHACHA20, &K32).unwrap();
    assert_needle_wiped(k, &K32, "quic::HeaderProtectionKey(ChaCha20)");
    let k = quic::HeaderProtectionKey::new(&quic::AES_256, &K32).unwrap();
    assert_needle_wiped(k, &K32, "quic::HeaderProtectionKey(AES-256)");
}
