// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! AES in the two modes `aes_cbc_*` and `aes_gcm_*` need: CBC with PKCS#7 padding and GCM
//! with a tag of 16 bytes, for keys of 128, 192 and 256 bits.
//!
//! The block cipher, CBC, the counter mode and GHASH are the `RustCrypto` crates `aes`,
//! `cbc`, `ctr` and `ghash`: pure Rust, constant time (hardware AES where the CPU has it,
//! the fixsliced software implementation otherwise). What is written here is the glue GCM
//! is made of: `J0`, the counter start, the tag. It is not `aes-gcm`'s `AesGcm` because that
//! one fixes the nonce length in its type (12 bytes, or one instantiation per length), while
//! `HAProxy` takes any length from 1 byte up; the tests check this glue against `AesGcm` for
//! the lengths it can be instantiated with, against the GCM specification's vectors for the
//! others, and against ciphertexts measured on `HAProxy`.

use aes::cipher::{block_padding::Pkcs7, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use ghash::universal_hash::UniversalHash;
use ghash::GHash;

const BLOCK: usize = 16;

/// Runs `$body` with `$c` naming the AES variant `$key`'s length selects.
macro_rules! with_aes {
    ($key:expr, $c:ident => $body:expr) => {
        match $key.len() {
            16 => {
                type $c = Aes128;
                $body
            }
            24 => {
                type $c = Aes192;
                $body
            }
            _ => {
                type $c = Aes256;
                $body
            }
        }
    };
}

/// An AES key of 16, 24 or 32 bytes.
pub struct Aes {
    key: Vec<u8>,
}

impl Aes {
    /// `None` for a key of any other length.
    #[must_use]
    pub fn new(key: &[u8]) -> Option<Aes> {
        matches!(key.len(), 16 | 24 | 32).then(|| Aes { key: key.to_vec() })
    }

    /// Encrypts one block.
    #[must_use]
    #[allow(clippy::expect_used, reason = "Aes::new admits only 16/24/32-byte keys (the field is private) and IV/counter are fixed-size blocks, so the length-checked constructor cannot fail")]
    pub fn encrypt_block(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut b = (*block).into();
        with_aes!(self.key, C => C::new_from_slice(&self.key).expect("key length checked").encrypt_block(&mut b));
        b.into()
    }

    /// Decrypts one block.
    #[must_use]
    #[allow(clippy::expect_used, reason = "Aes::new admits only 16/24/32-byte keys (the field is private) and IV/counter are fixed-size blocks, so the length-checked constructor cannot fail")]
    pub fn decrypt_block(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let mut b = (*block).into();
        with_aes!(self.key, C => C::new_from_slice(&self.key).expect("key length checked").decrypt_block(&mut b));
        b.into()
    }
}

/// CBC encryption with PKCS#7 padding; the result is a whole number of blocks, one more
/// than `data` fills.
#[must_use]
#[allow(clippy::expect_used, reason = "Aes::new admits only 16/24/32-byte keys (the field is private) and IV/counter are fixed-size blocks, so the length-checked constructor cannot fail")]
pub fn cbc_encrypt(aes: &Aes, iv: &[u8; BLOCK], data: &[u8]) -> Vec<u8> {
    with_aes!(aes.key, C => cbc::Encryptor::<C>::new_from_slices(&aes.key, iv)
        .expect("key and iv lengths checked")
        .encrypt_padded_vec_mut::<Pkcs7>(data))
}

/// CBC decryption; `None` when `data` is not a whole, non-empty number of blocks or its
/// padding is not valid PKCS#7.
#[must_use]
#[allow(clippy::expect_used, reason = "Aes::new admits only 16/24/32-byte keys (the field is private) and IV/counter are fixed-size blocks, so the length-checked constructor cannot fail")]
pub fn cbc_decrypt(aes: &Aes, iv: &[u8; BLOCK], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    with_aes!(aes.key, C => cbc::Decryptor::<C>::new_from_slices(&aes.key, iv)
        .expect("key and iv lengths checked")
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .ok())
}

fn length_block(a_bytes: usize, b_bytes: usize) -> [u8; BLOCK] {
    let mut l = [0u8; BLOCK];
    l[..8].copy_from_slice(&((a_bytes as u64) * 8).to_be_bytes());
    l[8..].copy_from_slice(&((b_bytes as u64) * 8).to_be_bytes());
    l
}

/// The pre-counter block `J0` for a nonce of any length (NIST SP 800-38D, 7.1).
fn gcm_j0(h: &[u8; BLOCK], nonce: &[u8]) -> [u8; BLOCK] {
    if nonce.len() == 12 {
        let mut j = [0u8; BLOCK];
        j[..12].copy_from_slice(nonce);
        j[15] = 1;
        j
    } else {
        let mut g = GHash::new(&(*h).into());
        g.update_padded(nonce);
        g.update_padded(&length_block(0, nonce.len()));
        g.finalize().into()
    }
}

/// Everything GCM does to `data`: the counter-mode transformation (`apply`) and the tag over
/// `aad` and the cipher text; `encrypt` says which side of `apply` the cipher text is on.
#[allow(clippy::expect_used, reason = "Aes::new admits only 16/24/32-byte keys (the field is private) and IV/counter are fixed-size blocks, so the length-checked constructor cannot fail")]
fn gcm(aes: &Aes, nonce: &[u8], aad: &[u8], data: &[u8], encrypt: bool) -> (Vec<u8>, [u8; BLOCK]) {
    let h = aes.encrypt_block(&[0u8; BLOCK]);
    let j0 = gcm_j0(&h, nonce);
    // The counter starts one past J0, over its last 32 bits.
    let mut start = j0;
    let n = u32::from_be_bytes([j0[12], j0[13], j0[14], j0[15]]).wrapping_add(1);
    start[12..].copy_from_slice(&n.to_be_bytes());
    let mut out = data.to_vec();
    with_aes!(aes.key, C => ctr::Ctr32BE::<C>::new_from_slices(&aes.key, &start)
        .expect("key and counter lengths checked")
        .apply_keystream(&mut out));
    let cipher = if encrypt { &out[..] } else { data };
    let mut g = GHash::new(&h.into());
    g.update_padded(aad);
    g.update_padded(cipher);
    g.update_padded(&length_block(aad.len(), cipher.len()));
    let mut tag = aes.encrypt_block(&j0);
    for (t, s) in tag.iter_mut().zip(g.finalize()) {
        *t ^= s;
    }
    (out, tag)
}

/// GCM encryption with a nonce of any non-zero length: the cipher text and the 16-byte tag.
#[must_use]
pub fn gcm_encrypt(aes: &Aes, nonce: &[u8], aad: &[u8], data: &[u8]) -> Option<(Vec<u8>, [u8; BLOCK])> {
    if nonce.is_empty() {
        return None;
    }
    Some(gcm(aes, nonce, aad, data, true))
}

/// GCM decryption; `None` when the tag does not authenticate the cipher text and aad.
#[must_use]
pub fn gcm_decrypt(aes: &Aes, nonce: &[u8], aad: &[u8], data: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    if nonce.is_empty() || tag.len() != BLOCK {
        return None;
    }
    let (plain, want) = gcm(aes, nonce, aad, data, false);
    // no early exit on the first difference
    if want.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return None;
    }
    Some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
    }

    fn xor_block(a: &mut [u8; BLOCK], b: &[u8; BLOCK]) {
        for (x, y) in a.iter_mut().zip(b) {
            *x ^= y;
        }
    }

    fn block(s: &str) -> [u8; BLOCK] {
        unhex(s).try_into().expect("16 bytes")
    }

    /// FIPS 197 appendix C: the same plain text under the three key sizes.
    #[test]
    fn fips_197_blocks() {
        let plain = block("00112233445566778899aabbccddeeff");
        for (key, want) in [
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let aes = Aes::new(&unhex(key)).expect("key");
            assert_eq!(aes.encrypt_block(&plain), block(want), "key {key}");
            assert_eq!(aes.decrypt_block(&block(want)), plain, "key {key}");
        }
        assert!(Aes::new(&[0; 15]).is_none());
        assert!(Aes::new(&[]).is_none());
    }

    /// NIST SP 800-38A F.2.1 (CBC-AES128): the first two blocks, without the padding block.
    #[test]
    fn sp800_38a_cbc() {
        let aes = Aes::new(&unhex("2b7e151628aed2a6abf7158809cf4f3c")).expect("key");
        let iv = block("000102030405060708090a0b0c0d0e0f");
        let plain = unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let cipher = cbc_encrypt(&aes, &iv, &plain);
        assert_eq!(&cipher[..32], &unhex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")[..]);
        assert_eq!(cipher.len(), 48);
        assert_eq!(cbc_decrypt(&aes, &iv, &cipher), Some(plain));
    }

    #[test]
    fn cbc_padding_is_checked() {
        let aes = Aes::new(&[7; 16]).expect("key");
        let iv = [1; BLOCK];
        for len in [0, 1, 15, 16, 17, 31, 32] {
            let data = vec![0xa5; len];
            let c = cbc_encrypt(&aes, &iv, &data);
            assert_eq!(c.len() % BLOCK, 0);
            assert!(c.len() > len);
            assert_eq!(cbc_decrypt(&aes, &iv, &c), Some(data));
        }
        assert_eq!(cbc_decrypt(&aes, &iv, &[]), None);
        assert_eq!(cbc_decrypt(&aes, &iv, &[0; 15]), None);
        // a pad of 0, of 17, and one whose bytes differ
        for tail in [[0u8; 1].as_slice(), &[17], &[2, 3]] {
            let mut p = vec![9u8; BLOCK - tail.len()];
            p.extend_from_slice(tail);
            let mut b: [u8; BLOCK] = p.try_into().expect("block");
            xor_block(&mut b, &iv);
            let c = aes.encrypt_block(&b);
            assert_eq!(cbc_decrypt(&aes, &iv, &c), None, "tail {tail:?}");
        }
    }

    /// The GCM test cases 1, 2 and 4 of the original GCM specification (128-bit key), a
    /// 60-byte message with aad and a 12-byte nonce.
    #[test]
    fn gcm_spec_vectors() {
        let aes = Aes::new(&[0; 16]).expect("key");
        let (c, t) = gcm_encrypt(&aes, &[0; 12], &[], &[]).expect("enc");
        assert!(c.is_empty());
        assert_eq!(t, block("58e2fccefa7e3061367f1d57a4e7455a"));
        let (c, t) = gcm_encrypt(&aes, &[0; 12], &[], &[0; 16]).expect("enc");
        assert_eq!(c, unhex("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(t, block("ab6e47d42cec13bdf53a67b21257bddf"));

        let aes = Aes::new(&unhex("feffe9928665731c6d6a8f9467308308")).expect("key");
        let nonce = unhex("cafebabefacedbaddecaf888");
        let plain = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let (c, t) = gcm_encrypt(&aes, &nonce, &aad, &plain).expect("enc");
        assert_eq!(
            c,
            unhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
        );
        assert_eq!(t, block("5bc94fbc3221a5db94fae95ae7121a47"));
        assert_eq!(gcm_decrypt(&aes, &nonce, &aad, &c, &t), Some(plain));
        assert_eq!(gcm_decrypt(&aes, &nonce, &[], &c, &t), None);
        let mut bad = t;
        bad[15] ^= 1;
        assert_eq!(gcm_decrypt(&aes, &nonce, &aad, &c, &bad), None);
        assert_eq!(gcm_decrypt(&aes, &nonce, &aad, &c, &t[..12]), None);
        assert_eq!(gcm_encrypt(&aes, &[], &aad, &c), None);
        // test case 5: an 8-byte nonce, which goes through GHASH to make J0
        let (_, t) = gcm_encrypt(&aes, &unhex("cafebabefacedbad"), &aad, &unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )).expect("enc");
        assert_eq!(t, block("3612d2e79e3b0785561be14aaca2fccb"));
    }

    /// The same cipher texts and tags as the `aes-gcm` crate's `AesGcm`, for the three key
    /// sizes and the nonce lengths it is instantiated with here (12 and 16 bytes).
    #[test]
    fn gcm_agrees_with_aes_gcm() {
        use aes_gcm::aead::consts::{U12, U16};
        use aes_gcm::aead::generic_array::GenericArray;
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::AesGcm;

        macro_rules! check {
            ($aes:ty, $n:ty, $key:expr, $nonce:expr) => {{
                let key: Vec<u8> = $key;
                let reference = AesGcm::<$aes, $n>::new(GenericArray::from_slice(&key));
                let ours = Aes::new(&key).expect("key");
                for len in [0usize, 1, 15, 16, 17, 33, 100] {
                    let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                    let aad = b"associated";
                    let nonce: &[u8] = $nonce;
                    let want = reference
                        .encrypt(GenericArray::from_slice(nonce), Payload { msg: &data, aad })
                        .expect("reference seal");
                    let (c, t) = gcm_encrypt(&ours, nonce, aad, &data).expect("enc");
                    assert_eq!(&want[..len], &c[..], "cipher, len {len}");
                    assert_eq!(&want[len..], &t[..], "tag, len {len}");
                    assert_eq!(gcm_decrypt(&ours, nonce, aad, &c, &t), Some(data));
                }
            }};
        }
        check!(aes::Aes128, U12, vec![0x42; 16], &[9u8; 12]);
        check!(aes::Aes192, U12, (0..24).collect(), &[9u8; 12]);
        check!(aes::Aes256, U12, (0..32).collect(), &[9u8; 12]);
        check!(aes::Aes128, U16, vec![0x42; 16], &[7u8; 16]);
        check!(aes::Aes192, U16, (0..24).collect(), &[7u8; 16]);
        check!(aes::Aes256, U16, (0..32).collect(), &[7u8; 16]);
    }
}
