// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/auth.c (check_user) and src/cfgparse.c (cfg_parse_users), which
// hand the `userlist` hashes to crypt(3).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `crypt(3)` password hashes of a `userlist`, verified in safe Rust.
//!
//! `HAProxy` computes `crypt(password, stored_hash)` and compares the whole result with
//! `stored_hash`. This crate does the same for the formats that can be done without C:
//! `$1$` (MD5-crypt), `$5$` (SHA-256-crypt), `$6$` (SHA-512-crypt) and `$2a$`/`$2b$`/`$2y$`
//! (bcrypt). What glibc also verifies (DES, `BSDi`, `$y$` (yescrypt), `$sha1$`, `$md5$`, `$3$`,
//! `$2x$`) is refused by [`CryptHash::parse`] with [`Refusal::Format`]; what glibc itself
//! refuses is [`Refusal::Invalid`].
//!
//! The setting (salt, rounds, cost) is validated as libxcrypt validates it, measured with
//! glibc 2.4x `crypt()` on 2026-10-04: see `tests/vectors.txt`.

pub mod xxh64;

use md5::{Digest, Md5};
use std::fmt::Write as _;
use subtle::ConstantTimeEq;

/// The alphabet of `crypt(3)`'s base 64.
const B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Why a hash is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// glibc `crypt()` returns NULL for it: unknown prefix, malformed setting, rounds out of range.
    Invalid,
    /// glibc verifies it, this crate does not: the name of the format.
    Format(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Md5,
    Sha256,
    Sha512,
    Bcrypt,
}

/// A hash the crate can verify passwords against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptHash {
    scheme: Scheme,
    stored: String,
}

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'/'
}

/// The salt characters libxcrypt accepts in the `$1$`, `$5$` and `$6$` formats: printable
/// ASCII other than `:` (and the `$` that ends it).
fn is_salt_char(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && b != b':' && b != b'$'
}

/// Emits `n` characters of the 24 bits `b2 b1 b0`, low six bits first.
fn b64_from_24bit(out: &mut String, b2: u8, b1: u8, b0: u8, n: usize) {
    let mut w = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
    for _ in 0..n {
        out.push(char::from(B64[(w & 0x3f) as usize]));
        w >>= 6;
    }
}

/// The salt of a `$1$`/`$5$`/`$6$` setting: up to `max` characters, ended by `$` or the end.
/// Returns `(salt, rest)`, where `rest` starts at the `$` that ended the salt if any.
fn salt_of(s: &str, max: usize) -> Result<(&str, &str), Refusal> {
    let end = s.bytes().position(|b| b == b'$').unwrap_or(s.len());
    let (field, rest) = s.split_at(end);
    if !field.bytes().all(is_salt_char) {
        return Err(Refusal::Invalid);
    }
    Ok((&field[..field.len().min(max)], rest))
}

/// The `rounds=N$` of a `$5$`/`$6$` setting, which libxcrypt reads strictly: decimal digits
/// without sign or leading zero, between 1000 and 999999999, then `$`.
fn rounds_of(s: &str) -> Result<(Option<u32>, &str), Refusal> {
    let Some(r) = s.strip_prefix("rounds=") else { return Ok((None, s)) };
    let Some((digits, rest)) = r.split_once('$') else { return Err(Refusal::Invalid) };
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::Invalid);
    }
    match digits.parse::<u32>() {
        Ok(n @ 1000..=999_999_999) => Ok((Some(n), rest)),
        _ => Err(Refusal::Invalid),
    }
}

/// Cuts a password at its first NUL, as the C string `crypt()` gets it.
fn c_string(password: &[u8]) -> &[u8] {
    &password[..password.iter().position(|&b| b == 0).unwrap_or(password.len())]
}

fn sha512_hash(pass: &[u8], stored: &str) -> Option<String> {
    let body = stored.strip_prefix("$6$")?;
    let (rounds, body) = rounds_of(body).ok()?;
    let (salt, _) = salt_of(body, 16).ok()?;
    let params = sha_crypt::Params::new(rounds.unwrap_or(sha_crypt::Params::RECOMMENDED_ROUNDS)).ok()?;
    let d = sha_crypt::sha512_crypt(pass, salt.as_bytes(), params);
    let mut out = String::from("$6$");
    if let Some(r) = rounds {
        let _ = write!(out, "rounds={r}$");
    }
    out.push_str(salt);
    out.push('$');
    for (a, b, c) in [
        (0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
        (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
        (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41),
    ] {
        b64_from_24bit(&mut out, d[a], d[b], d[c], 4);
    }
    b64_from_24bit(&mut out, 0, 0, d[63], 2);
    Some(out)
}

fn sha256_hash(pass: &[u8], stored: &str) -> Option<String> {
    let body = stored.strip_prefix("$5$")?;
    let (rounds, body) = rounds_of(body).ok()?;
    let (salt, _) = salt_of(body, 16).ok()?;
    let params = sha_crypt::Params::new(rounds.unwrap_or(sha_crypt::Params::RECOMMENDED_ROUNDS)).ok()?;
    let d = sha_crypt::sha256_crypt(pass, salt.as_bytes(), params);
    let mut out = String::from("$5$");
    if let Some(r) = rounds {
        let _ = write!(out, "rounds={r}$");
    }
    out.push_str(salt);
    out.push('$');
    for (a, b, c) in [
        (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14), (15, 25, 5), (6, 16, 26),
        (27, 7, 17), (18, 28, 8), (9, 19, 29),
    ] {
        b64_from_24bit(&mut out, d[a], d[b], d[c], 4);
    }
    b64_from_24bit(&mut out, 0, d[31], d[30], 3);
    Some(out)
}

/// MD5-crypt (`$1$`), after Poul-Henning Kamp's algorithm.
fn md5_hash(pass: &[u8], stored: &str) -> Option<String> {
    let body = stored.strip_prefix("$1$")?;
    let (salt, _) = salt_of(body, 8).ok()?;
    let salt = salt.as_bytes();
    let alt = Md5::new().chain_update(pass).chain_update(salt).chain_update(pass).finalize();
    let mut ctx = Md5::new().chain_update(pass).chain_update(b"$1$").chain_update(salt);
    let mut left = pass.len();
    while left > 0 {
        ctx.update(&alt[..left.min(16)]);
        left = left.saturating_sub(16);
    }
    let mut i = pass.len();
    while i > 0 {
        if i & 1 == 1 {
            ctx.update([0u8]);
        } else {
            ctx.update(&pass[..1]);
        }
        i >>= 1;
    }
    let mut fin = ctx.finalize();
    for i in 0..1000 {
        let mut c = Md5::new();
        if i & 1 == 1 {
            c.update(pass);
        } else {
            c.update(fin);
        }
        if i % 3 != 0 {
            c.update(salt);
        }
        if i % 7 != 0 {
            c.update(pass);
        }
        if i & 1 == 1 {
            c.update(fin);
        } else {
            c.update(pass);
        }
        fin = c.finalize();
    }
    let mut out = format!("$1${}$", String::from_utf8_lossy(salt));
    for (a, b, c) in [(0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)] {
        b64_from_24bit(&mut out, fin[a], fin[b], fin[c], 4);
    }
    b64_from_24bit(&mut out, 0, 0, fin[11], 2);
    Some(out)
}

/// The `$2a$NN$` + 22 salt characters that make a bcrypt setting; the cost is 04 to 31.
fn bcrypt_setting_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 29
        && b[0] == b'$'
        && b[1] == b'2'
        && matches!(b[2], b'a' | b'b' | b'y')
        && b[3] == b'$'
        && b[4].is_ascii_digit()
        && b[5].is_ascii_digit()
        && b[6] == b'$'
        && matches!((b[4] - b'0') * 10 + (b[5] - b'0'), 4..=31)
        && b[7..29].iter().all(|&c| is_b64(c))
}

impl CryptHash {
    /// Reads a stored hash as `crypt(3)` reads a setting.
    ///
    /// # Errors
    /// [`Refusal::Invalid`] where glibc `crypt()` returns NULL, [`Refusal::Format`] for a
    /// format glibc verifies and this crate does not. A hash that is well formed up to its
    /// salt but whose tail is cut short is accepted, as glibc accepts it: it matches nothing.
    pub fn parse(stored: &str) -> Result<Self, Refusal> {
        let b = stored.as_bytes();
        let scheme = if let Some(rest) = stored.strip_prefix('$') {
            let id = rest.split('$').next().unwrap_or("");
            // The id is closed by a `$`; what follows it is the setting.
            let Some(body) = rest[id.len()..].strip_prefix('$') else { return Err(Refusal::Invalid) };
            match id {
                "1" => {
                    salt_of(body, 8)?;
                    Scheme::Md5
                }
                "5" | "6" => {
                    let (_, body) = rounds_of(body)?;
                    salt_of(body, 16)?;
                    if id == "5" {
                        Scheme::Sha256
                    } else {
                        Scheme::Sha512
                    }
                }
                "2a" | "2b" | "2y" => {
                    if !bcrypt_setting_ok(stored) {
                        return Err(Refusal::Invalid);
                    }
                    Scheme::Bcrypt
                }
                "2x" if bcrypt_setting_ok(&format!("$2a{}", &stored[3..])) => return Err(Refusal::Format("bcrypt $2x$")),
                "y" | "gy" if stored.len() > 8 && stored.bytes().all(|c| (0x21..=0x7e).contains(&c)) => {
                    return Err(Refusal::Format("yescrypt ($y$)"));
                }
                "sha1" if stored.len() > 8 => return Err(Refusal::Format("SunMD5/sha1crypt")),
                "md5" if stored.len() > 6 => return Err(Refusal::Format("SunMD5/sha1crypt")),
                "3" if stored.len() > 3 => return Err(Refusal::Format("NT-hash")),
                _ => return Err(Refusal::Invalid),
            }
        } else if b.first() == Some(&b'_') {
            return Err(if b.len() >= 9 && b.iter().skip(1).all(|&c| is_b64(c)) { Refusal::Format("BSDi extended DES crypt") } else { Refusal::Invalid });
        } else if b.len() >= 2 && b.iter().all(|&c| is_b64(c)) {
            return Err(Refusal::Format("DES crypt"));
        } else {
            return Err(Refusal::Invalid);
        };
        Ok(Self { scheme, stored: stored.to_string() })
    }

    /// Whether `password` hashes to the stored value. The comparison of the final hash is
    /// constant-time. The password is cut at its first NUL, as `crypt()` reads a C string.
    #[must_use]
    pub fn verify(&self, password: &[u8]) -> bool {
        let pass = c_string(password);
        let computed = match self.scheme {
            Scheme::Md5 => md5_hash(pass, &self.stored),
            Scheme::Sha256 => sha256_hash(pass, &self.stored),
            Scheme::Sha512 => sha512_hash(pass, &self.stored),
            // The crate compares the hash part in constant time itself; a tail cut short
            // is an error there, and matches nothing here.
            Scheme::Bcrypt => return bcrypt::verify(pass, &self.stored).unwrap_or(false),
        };
        computed.is_some_and(|c| bool::from(c.as_bytes().ct_eq(self.stored.as_bytes())))
    }
}
