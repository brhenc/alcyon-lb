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

/// The 16 xmm registers right after an AES-128-GCM seal, read by the first
/// instructions after the call returns. Not inlined, so that the call and the
/// read sit in one small frame with nothing between them.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn xmm_after_seal(key: &LessSafeKey, in_out: &mut [u8]) -> [[u8; 16]; 16] {
    let mut regs = [[0u8; 16]; 16];
    let p = regs.as_mut_ptr().cast::<u8>();
    let r = key.seal_in_place_separate_tag(Nonce::assume_unique_for_key([7; 12]), Aad::empty(), in_out);
    // SAFETY: `p` points at 256 writable bytes; the stores are unaligned.
    unsafe {
        core::arch::asm!(
            "movdqu [{p}], xmm0", "movdqu [{p} + 16], xmm1", "movdqu [{p} + 32], xmm2",
            "movdqu [{p} + 48], xmm3", "movdqu [{p} + 64], xmm4", "movdqu [{p} + 80], xmm5",
            "movdqu [{p} + 96], xmm6", "movdqu [{p} + 112], xmm7", "movdqu [{p} + 128], xmm8",
            "movdqu [{p} + 144], xmm9", "movdqu [{p} + 160], xmm10", "movdqu [{p} + 176], xmm11",
            "movdqu [{p} + 192], xmm12", "movdqu [{p} + 208], xmm13", "movdqu [{p} + 224], xmm14",
            "movdqu [{p} + 240], xmm15",
            p = in(reg) p,
            options(nostack, preserves_flags),
        );
    }
    let _ = core::hint::black_box(r.is_ok());
    regs
}

/// T462 (Ibex): after a seal, no xmm register holds an AES round key, the
/// GHASH key H or an entry of its table (ZEROIZE.md section 2).
#[cfg(target_arch = "x86_64")]
#[test]
fn seal_leaves_no_aes_or_ghash_key_in_the_xmm_registers() {
    let cpu = cpu::features();
    let Some(req) = cpu.get_feature() else { return };
    let k16: [u8; 16] = K32[..16].try_into().unwrap();
    // The schedule the AES-NI code uses, from the same key setup.
    let hw = aes::hw::Key::new(KeyBytes::AES_128(&k16), req, cpu.get_feature()).unwrap();
    let sched = hw.inner_less_safe() as *const aes::AES_KEY as *const u8;
    // SAFETY: reads the bytes of a live `AES_KEY` (plain integers).
    let sched = unsafe { core::slice::from_raw_parts(sched, core::mem::size_of::<aes::AES_KEY>()) };
    let round_keys: std::vec::Vec<[u8; 16]> =
        sched.chunks_exact(16).take(11).map(|c| c.try_into().unwrap()).collect();
    assert_eq!(round_keys[0], k16, "round key 0 is the key itself");
    // The GHASH key H = AES_K(0) and the table of its powers the AVX code reads.
    let h = aes::EncryptBlock::encrypt_block(&hw, [0u8; 16]);
    let mut needles = round_keys.clone();
    needles.push(h);
    if let Some(ghash_req) = cpu.get_feature() {
        let g = gcm::clmulavxmovbe::Key::new(KeyValue::new(h), ghash_req);
        let gp = &g as *const gcm::clmulavxmovbe::Key as *const u8;
        // SAFETY: reads the bytes of a live key table (plain integers).
        let gb = unsafe { core::slice::from_raw_parts(gp, core::mem::size_of_val(&g)) };
        needles.extend(gb.chunks_exact(16).map(|c| <[u8; 16]>::try_from(c).unwrap()));
    }
    needles.retain(|n| n.iter().any(|&b| b != 0));

    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &k16).unwrap());
    let mut data = [0x5au8; 576];
    let regs = xmm_after_seal(&key, &mut data);
    let found: std::vec::Vec<(usize, usize)> = regs
        .iter()
        .enumerate()
        .flat_map(|(r, v)| needles.iter().enumerate().filter(move |(_, k)| *k == v).map(move |(i, _)| (r, i)))
        .collect();
    assert!(found.is_empty(), "(xmm, key block) pairs left after seal: {found:?}");
}
