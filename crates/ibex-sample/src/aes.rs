// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! AES (FIPS 197) with the two modes `aes_cbc_*` and `aes_gcm_*` need: CBC with PKCS#7
//! padding and GCM (NIST SP 800-38D) with a tag of 16 bytes.
//!
//! Written here because the workspace's TLS stack (`ring`) offers neither CBC nor 192-bit
//! keys nor nonces of other lengths than 12 bytes, and `OpenSSL`, which `HAProxy` uses,
//! offers all of them. The S-box is looked up by index, so the timing of a block depends
//! on its data; this is meant for the sample converters, which see what the configuration
//! gives them, not for protecting keys from a co-located attacker. TLS does not use it.

use std::sync::LazyLock;

const BLOCK: usize = 16;

/// The S-box and its inverse, generated as FIPS 197 section 5.1.1 describes: the
/// multiplicative inverse in GF(2^8) followed by the affine transform.
fn gen_sboxes() -> ([u8; 256], [u8; 256]) {
    let mut sbox = [0u8; 256];
    let mut inv = [0u8; 256];
    let mut p: u8 = 1;
    let mut q: u8 = 1;
    loop {
        // p *= 3
        p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1b } else { 0 };
        // q /= 3
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        if q & 0x80 != 0 {
            q ^= 0x09;
        }
        let x = q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
        sbox[p as usize] = x ^ 0x63;
        if p == 1 {
            break;
        }
    }
    sbox[0] = 0x63;
    let mut i = 0;
    while i < 256 {
        inv[sbox[i] as usize] = i as u8;
        i += 1;
    }
    (sbox, inv)
}

static SBOXES: LazyLock<([u8; 256], [u8; 256])> = LazyLock::new(gen_sboxes);

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

fn gmul8(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    r
}

/// An expanded AES key.
pub struct Aes {
    round_keys: Vec<[u8; BLOCK]>,
}

impl Aes {
    /// The key schedule for a key of 16, 24 or 32 bytes; `None` for any other length.
    #[must_use]
    pub fn new(key: &[u8]) -> Option<Aes> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return None,
        };
        let rounds = nk + 6;
        let mut w: Vec<[u8; 4]> = key.chunks(4).map(|c| [c[0], c[1], c[2], c[3]]).collect();
        let mut rcon: u8 = 1;
        for i in nk..4 * (rounds + 1) {
            let mut t = w[i - 1];
            if i % nk == 0 {
                t = [SBOXES.0[t[1] as usize] ^ rcon, SBOXES.0[t[2] as usize], SBOXES.0[t[3] as usize], SBOXES.0[t[0] as usize]];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| SBOXES.0[b as usize]);
            }
            let p = w[i - nk];
            w.push([p[0] ^ t[0], p[1] ^ t[1], p[2] ^ t[2], p[3] ^ t[3]]);
        }
        let round_keys = w
            .chunks(4)
            .map(|c| {
                let mut k = [0u8; BLOCK];
                for (i, word) in c.iter().enumerate() {
                    k[4 * i..4 * i + 4].copy_from_slice(word);
                }
                k
            })
            .collect();
        Some(Aes { round_keys })
    }

    fn add_round_key(&self, s: &mut [u8; BLOCK], round: usize) {
        for (b, k) in s.iter_mut().zip(&self.round_keys[round]) {
            *b ^= k;
        }
    }

    /// Encrypts one block.
    #[must_use]
    pub fn encrypt_block(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let rounds = self.round_keys.len() - 1;
        let mut s = *block;
        self.add_round_key(&mut s, 0);
        for round in 1..=rounds {
            for b in &mut s {
                *b = SBOXES.0[*b as usize];
            }
            // ShiftRows: row r of the state (bytes r, r+4, r+8, r+12) rotates left by r.
            let t = s;
            for c in 0..4 {
                for r in 0..4 {
                    s[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
                }
            }
            if round != rounds {
                for c in 0..4 {
                    let col = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                    for r in 0..4 {
                        s[4 * c + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                    }
                }
            }
            self.add_round_key(&mut s, round);
        }
        s
    }

    /// Decrypts one block.
    #[must_use]
    pub fn decrypt_block(&self, block: &[u8; BLOCK]) -> [u8; BLOCK] {
        let rounds = self.round_keys.len() - 1;
        let mut s = *block;
        self.add_round_key(&mut s, rounds);
        for round in (0..rounds).rev() {
            let t = s;
            for c in 0..4 {
                for r in 0..4 {
                    s[r + 4 * ((c + r) % 4)] = t[r + 4 * c];
                }
            }
            for b in &mut s {
                *b = SBOXES.1[*b as usize];
            }
            self.add_round_key(&mut s, round);
            if round != 0 {
                for c in 0..4 {
                    let col = [s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]];
                    for r in 0..4 {
                        s[4 * c + r] = gmul8(col[r], 14)
                            ^ gmul8(col[(r + 1) % 4], 11)
                            ^ gmul8(col[(r + 2) % 4], 13)
                            ^ gmul8(col[(r + 3) % 4], 9);
                    }
                }
            }
        }
        s
    }
}

fn xor_block(a: &mut [u8; BLOCK], b: &[u8; BLOCK]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

/// CBC encryption with PKCS#7 padding; the result is a whole number of blocks, one more
/// than `data` fills.
#[must_use]
pub fn cbc_encrypt(aes: &Aes, iv: &[u8; BLOCK], data: &[u8]) -> Vec<u8> {
    let pad = BLOCK - data.len() % BLOCK;
    let mut padded = data.to_vec();
    padded.resize(data.len() + pad, u8::try_from(pad).unwrap_or(0));
    let mut prev = *iv;
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks_exact(BLOCK) {
        let mut b = [0u8; BLOCK];
        b.copy_from_slice(chunk);
        xor_block(&mut b, &prev);
        prev = aes.encrypt_block(&b);
        out.extend_from_slice(&prev);
    }
    out
}

/// CBC decryption; `None` when `data` is not a whole, non-empty number of blocks or its
/// padding is not valid PKCS#7.
#[must_use]
pub fn cbc_decrypt(aes: &Aes, iv: &[u8; BLOCK], data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || data.len() % BLOCK != 0 {
        return None;
    }
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(BLOCK) {
        let mut c = [0u8; BLOCK];
        c.copy_from_slice(chunk);
        let mut b = aes.decrypt_block(&c);
        xor_block(&mut b, &prev);
        out.extend_from_slice(&b);
        prev = c;
    }
    let pad = usize::from(*out.last()?);
    if pad == 0 || pad > BLOCK || out[out.len() - pad..].iter().any(|&b| usize::from(b) != pad) {
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

/// Multiplication in GF(2^128) as GCM defines it (bit 0 is the most significant).
fn gf128_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    z
}

fn ghash(h: u128, parts: &[&[u8]]) -> u128 {
    let mut y = 0u128;
    for part in parts {
        for chunk in part.chunks(BLOCK) {
            let mut b = [0u8; BLOCK];
            b[..chunk.len()].copy_from_slice(chunk);
            y = gf128_mul(y ^ u128::from_be_bytes(b), h);
        }
    }
    y
}

fn length_block(a_bytes: usize, b_bytes: usize) -> [u8; BLOCK] {
    let mut l = [0u8; BLOCK];
    l[..8].copy_from_slice(&((a_bytes as u64) * 8).to_be_bytes());
    l[8..].copy_from_slice(&((b_bytes as u64) * 8).to_be_bytes());
    l
}

/// The counter block `J0` for a nonce of any length.
fn gcm_j0(h: u128, nonce: &[u8]) -> [u8; BLOCK] {
    if nonce.len() == 12 {
        let mut j = [0u8; BLOCK];
        j[..12].copy_from_slice(nonce);
        j[15] = 1;
        j
    } else {
        ghash(h, &[nonce, &length_block(0, nonce.len())]).to_be_bytes()
    }
}

fn gcm_ctr(aes: &Aes, j0: &[u8; BLOCK], data: &[u8]) -> Vec<u8> {
    let mut counter = *j0;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK) {
        // inc32 on the last four bytes
        let n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]).wrapping_add(1);
        counter[12..].copy_from_slice(&n.to_be_bytes());
        let ks = aes.encrypt_block(&counter);
        out.extend(chunk.iter().zip(ks).map(|(d, k)| d ^ k));
    }
    out
}

fn gcm_tag(aes: &Aes, h: u128, j0: &[u8; BLOCK], aad: &[u8], cipher: &[u8]) -> [u8; BLOCK] {
    let s = ghash(h, &[aad, cipher, &length_block(aad.len(), cipher.len())]);
    let mut tag = aes.encrypt_block(j0);
    for (t, s) in tag.iter_mut().zip(s.to_be_bytes()) {
        *t ^= s;
    }
    tag
}

/// GCM encryption with a nonce of any non-zero length: the cipher text and the 16-byte tag.
#[must_use]
pub fn gcm_encrypt(aes: &Aes, nonce: &[u8], aad: &[u8], data: &[u8]) -> Option<(Vec<u8>, [u8; BLOCK])> {
    if nonce.is_empty() {
        return None;
    }
    let h = u128::from_be_bytes(aes.encrypt_block(&[0u8; BLOCK]));
    let j0 = gcm_j0(h, nonce);
    let cipher = gcm_ctr(aes, &j0, data);
    let tag = gcm_tag(aes, h, &j0, aad, &cipher);
    Some((cipher, tag))
}

/// GCM decryption; `None` when the tag does not authenticate the cipher text and aad.
#[must_use]
pub fn gcm_decrypt(aes: &Aes, nonce: &[u8], aad: &[u8], data: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
    if nonce.is_empty() || tag.len() != BLOCK {
        return None;
    }
    let h = u128::from_be_bytes(aes.encrypt_block(&[0u8; BLOCK]));
    let j0 = gcm_j0(h, nonce);
    let want = gcm_tag(aes, h, &j0, aad, data);
    // no early exit on the first difference
    if want.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return None;
    }
    Some(gcm_ctr(aes, &j0, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
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

    /// The same cipher texts and tags as `ring`, for 128 and 256-bit keys and a 12-byte nonce.
    #[test]
    fn gcm_agrees_with_ring() {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
        for (alg, key) in [(&AES_128_GCM, vec![0x42u8; 16]), (&AES_256_GCM, (0..32).collect::<Vec<u8>>())] {
            let ring_key = LessSafeKey::new(UnboundKey::new(alg, &key).expect("ring key"));
            let aes = Aes::new(&key).expect("key");
            for len in [0usize, 1, 15, 16, 17, 33, 100] {
                let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
                let aad = b"associated";
                let nonce = [9u8; 12];
                let mut buf = data.clone();
                ring_key
                    .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
                    .expect("seal");
                let (c, t) = gcm_encrypt(&aes, &nonce, aad, &data).expect("enc");
                assert_eq!(&buf[..len], &c[..], "cipher, len {len}");
                assert_eq!(&buf[len..], &t[..], "tag, len {len}");
            }
        }
    }
}
