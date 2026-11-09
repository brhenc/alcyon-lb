// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Every verdict of `tests/vectors.txt` was produced by glibc `crypt()` (the library `HAProxy`
//! calls); `tests/vectors.py` regenerates the file.

use alcyon_crypt::{CryptHash, Refusal};

const VECTORS: &str = include_str!("../vectors.txt");

#[test]
fn verdicts_agree_with_glibc_crypt() {
    let mut n = 0;
    let mut formats = 0;
    for line in VECTORS.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 3, "{line}");
        let (stored, pass, verdict) = (f[0], f[1], f[2]);
        n += 1;
        let parsed = CryptHash::parse(stored);
        match verdict {
            "ok" | "no" => {
                let h = parsed.unwrap_or_else(|e| panic!("{stored}: {e:?}"));
                assert_eq!(h.verify(pass.as_bytes()), verdict == "ok", "{stored} / {pass:?}");
            }
            v => {
                let (load, matches) = v.split_once(',').expect("verdict");
                if load == "load:NULL" {
                    assert_eq!(parsed.err(), Some(Refusal::Invalid), "{stored}");
                } else {
                    match parsed {
                        Ok(h) => assert_eq!(h.verify(pass.as_bytes()), matches == "match:yes", "{stored} / {pass:?}"),
                        Err(Refusal::Format(_)) => formats += 1,
                        Err(Refusal::Invalid) => panic!("{stored}: glibc loads it"),
                    }
                }
            }
        }
    }
    assert!(n > 800 && formats >= 8, "{n} {formats}");
}

#[test]
fn the_password_is_read_as_a_c_string() {
    // glibc is handed a C string: what follows a NUL is not part of the password.
    let h = CryptHash::parse("$1$1G0VykCx$OwomHlpoy3dfHps5jUrK81").expect("md5");
    assert!(h.verify(b"secret\0tail"));
    assert!(!h.verify(b"\0secret"));
}

#[test]
fn the_refusals_name_what_they_are() {
    assert_eq!(CryptHash::parse("KX9oOBGuoeCIs").err(), Some(Refusal::Format("DES crypt")));
    assert_eq!(CryptHash::parse("$9$salt$abc").err(), Some(Refusal::Invalid));
    assert_eq!(CryptHash::parse("").err(), Some(Refusal::Invalid));
}
