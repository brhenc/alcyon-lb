// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A regex runs over bytes, as PCRE does without UTF mode (T296): `.` matches one byte, so
//! a UTF-8 `é` (C3 A9) is two of them, and a class holds bytes, not characters.
//!
//! Every expected value was measured on `HAProxy` 3.5-dev8-885761-29 with
//! `req.hdr(x) -m reg` on the values `\xc3\xa9`, `\xe9` and `\xe2\x82\xac`.

use ibex_regex::bytetext::bytes_to_text;
use ibex_regex::UserRegex;

fn m(pattern: &[u8], value: &[u8]) -> bool {
    UserRegex::new_nocapture(&bytes_to_text(pattern)).unwrap().is_match(&bytes_to_text(value))
}

#[test]
fn dot_is_one_byte_of_a_utf8_character() {
    assert!(!m(b"^.$", b"\xc3\xa9"));
    assert!(m(b"^..$", b"\xc3\xa9"));
    assert!(m(b"^.{2}$", b"\xc3\xa9"));
    assert!(m(b"^...$", b"\xe2\x82\xac"));
    assert!(!m(b"^.$", b"\xe2\x82\xac"));
    assert!(m(b"^.$", b"\xe9"));
    assert!(m(b"^.$", b"a"));
    assert!(m(b"(?s)^.$", b"\xe9"));
}

#[test]
fn a_negated_class_and_a_non_word_are_one_byte() {
    assert!(!m(b"^[^a]$", b"\xc3\xa9"));
    assert!(m(b"^[^a][^a]$", b"\xc3\xa9"));
    assert!(m(b"^\\W\\W$", b"\xc3\xa9"));
    assert!(m(b"^\\W$", b"\xe9"));
    assert!(!m(b"^\\w$", b"\xc3\xa9"));
    assert!(m(b"^\\S$", b"\xe9"));
    assert!(!m(b"^\\S$", b"\xc3\xa9"));
}

#[test]
fn a_literal_non_ascii_character_in_the_pattern_is_its_bytes() {
    assert!(m("^é$".as_bytes(), b"\xc3\xa9"));
    // `é+` is C3 then A9 one or more times.
    assert!(m("^é+$".as_bytes(), b"\xc3\xa9\xa9"));
    assert!(!m("^é+$".as_bytes(), b"\xc3\xa9\xc3\xa9"));
    // `[é]` is a class of two bytes: it matches one byte, and `[é][é]` two.
    assert!(!m("^[é]$".as_bytes(), b"\xc3\xa9"));
    assert!(m("^[é][é]$".as_bytes(), b"\xc3\xa9"));
    assert!(m("^[é]$".as_bytes(), b"\xc3"));
}

#[test]
fn no_case_folding_above_ascii() {
    let re = UserRegex::with_case_nocapture("^É$", true).unwrap();
    assert!(!re.is_match("\u{e9}"));
    assert!(re.is_match("\u{c9}"));
    assert!(m(b"^[\x80-\xff]+$", b"\xc3\xa9"));
}

#[test]
fn captures_and_replacements_are_bytes() {
    let re = UserRegex::new("^(.)(.)$").unwrap();
    let c = re.captures("\u{e9}").expect("two bytes");
    assert_eq!(c.get(1), Some(bytes_to_text(b"\xc3").as_str()));
    assert_eq!(c.get(2), Some(bytes_to_text(b"\xa9").as_str()));
    let mut out = String::new();
    c.expand("$2$1", &mut out);
    assert_eq!(out, bytes_to_text(b"\xa9\xc3"));
    assert!(UserRegex::new("^(.)$").unwrap().captures("\u{e9}").is_none());

    let re = UserRegex::new("^.").unwrap();
    assert_eq!(re.replace("\u{e9}", "x"), bytes_to_text(b"x\xa9"));
    assert_eq!(UserRegex::new(".").unwrap().replace_all("a\u{e9}", "-"), "---");
    let re = UserRegex::new("(?P<n>.)").unwrap();
    let c = re.captures("\u{e9}").unwrap();
    let mut out = String::new();
    c.expand("[${n}]", &mut out);
    assert_eq!(out, format!("[{}]", bytes_to_text(b"\xc3")));
}

#[test]
fn backtracking_patterns_are_bytes_too() {
    assert!(!m(b"^(?=.)(.)$", b"\xc3\xa9"));
    assert!(m(b"^(?=.)(.)(.)$", b"\xc3\xa9"));
    assert_eq!(UserRegex::new("(?=.)(.)").unwrap().replace_all("\u{e9}", "-"), "--");
}
