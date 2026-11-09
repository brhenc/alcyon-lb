// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! R2: `UserRegex::is_match_bytes`, the matcher's entry point for a sample of bytes. Every
//! verdict was measured on HAProxy 3.5-dev8-885761-29 (`req.hdr(x) -m reg <pattern>`, PCRE2
//! without UTF): an escaped non-ASCII character is its bytes, and a pattern that needs
//! `fancy-regex` (look-ahead) reads a Latin-1 byte as one character.

use alcyon_regex::bytetext::bytes_to_text;
use alcyon_regex::UserRegex;

#[test]
fn a_byte_subject_matches_as_pcre2_without_utf_reads_it() {
    // (pattern as the configuration's bytes, subject, HAProxy's verdict)
    let rows: &[(&[u8], &[u8], bool)] = &[
        // `"^caf\\é$"`: a backslash before a non-ASCII character escapes its first byte.
        (b"^caf\\\xc3\xa9$", b"caf\xc3\xa9", true),
        (b"^caf\\\xc3\xa9$", b"caf\xe9", false),
        // `"^caf(?=\xe9)"`: look-ahead, so `fancy-regex`, over a Latin-1 byte.
        (b"^caf(?=\xe9)", b"caf\xe9", true),
        (b"^caf(?=\xe9)", b"caf\xc3\xa9", false),
    ];
    for &(pattern, subject, want) in rows {
        let re = UserRegex::new(&bytes_to_text(pattern)).expect("compiles");
        assert_eq!(re.is_match_bytes(subject), want, "{} on {}", pattern.escape_ascii(), subject.escape_ascii());
    }
    assert!(UserRegex::new(&bytes_to_text(b"^caf(?=\xe9)")).unwrap().is_backtracking());
}
