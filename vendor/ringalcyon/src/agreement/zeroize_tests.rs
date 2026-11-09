// Copyright 2026 Alcyon contributors.
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

//! Tests for the `zeroize` feature (ring-alcyon): key-agreement secrets must not
//! survive being dropped. Built only with `--features zeroize`.

extern crate std;

use super::*;
use std::prelude::v1::*;
use core::{
    mem::{ManuallyDrop, MaybeUninit},
    ptr,
};

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

const P256_PRIV: [u8; 32] = [
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x0a,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01, 0x02,
];

#[test]
fn seed_is_wiped_on_drop() {
    let seed = ec::Seed::from_bytes(
        ECDH_P256.curve,
        untrusted::Input::from(&P256_PRIV),
        cpu::features(),
    )
    .unwrap();
    let mut seed = ManuallyDrop::new(Box::new(seed));
    let p: *const u8 = seed.bytes_less_safe().as_ptr();
    // SAFETY: the box is still allocated; only its contents are dropped.
    unsafe { ptr::drop_in_place(&mut **seed as *mut ec::Seed) };
    let after: Vec<u8> = (0..32).map(|i| unsafe { ptr::read_volatile(p.add(i)) }).collect();
    assert_eq!(after, [0u8; 32], "Seed bytes survived drop");
    // SAFETY: free the box without running Drop a second time.
    unsafe { drop(Box::from_raw(&mut **seed as *mut ec::Seed as *mut MaybeUninit<ec::Seed>)) };
}

#[inline(never)]
fn do_agree(alg: &'static Algorithm, seed_bytes: &[u8]) -> Vec<u8> {
    let peer = EphemeralPrivateKey::generate(alg, &rand::SystemRandom::new()).unwrap();
    let peer_pub = peer.compute_public_key().unwrap();
    let seed = ec::Seed::from_bytes(alg.curve, untrusted::Input::from(seed_bytes), cpu::features())
        .unwrap();
    let mine = EphemeralPrivateKey {
        private_key: seed,
        algorithm: alg,
    };
    agree_ephemeral(mine, &UnparsedPublicKey::new(alg, peer_pub.as_ref()), |s| s.to_vec()).unwrap()
}

// Reads stack memory below the caller that earlier calls used.
#[inline(never)]
fn stack_has(needle: &[u8]) -> bool {
    let buf = MaybeUninit::<[u8; 32768]>::uninit();
    let p = core::hint::black_box(buf.as_ptr() as *const u8);
    let v: Vec<u8> = (0..32768).map(|i| unsafe { ptr::read_volatile(p.add(i)) }).collect();
    contains(&v, needle)
}

fn shared_secret_not_on_stack(alg: &'static Algorithm, seed_bytes: &[u8]) {
    let ss = do_agree(alg, seed_bytes);
    assert!(ss.len() >= 32 && ss.iter().any(|b| *b != 0));
    assert!(!stack_has(&ss), "shared secret left on the stack");
}

#[test]
fn x25519_shared_secret_not_on_stack() {
    shared_secret_not_on_stack(&X25519, &P256_PRIV);
}

#[test]
fn p256_shared_secret_not_on_stack() {
    shared_secret_not_on_stack(&ECDH_P256, &P256_PRIV);
}

#[test]
fn p384_shared_secret_not_on_stack() {
    let mut k = [0u8; 48];
    k[..32].copy_from_slice(&P256_PRIV);
    k[32..].copy_from_slice(&P256_PRIV[..16]);
    shared_secret_not_on_stack(&ECDH_P384, &k);
}

// The private scalar is parsed into a (little-endian limbs) `Scalar` that is
// copied around the stack by `ecdh`; none of it may be left behind.
#[test]
fn p256_private_scalar_not_on_stack() {
    let _ = do_agree(&ECDH_P256, &P256_PRIV);
    let mut le = P256_PRIV;
    le.reverse();
    assert!(!stack_has(&le), "private scalar left on the stack");
}

#[test]
fn x25519_masked_private_scalar_not_on_stack() {
    let _ = do_agree(&X25519, &P256_PRIV);
    let mut masked = P256_PRIV;
    masked[0] &= 248;
    masked[31] &= 127;
    masked[31] |= 64;
    assert!(!stack_has(&masked), "masked private scalar left on the stack");
}
