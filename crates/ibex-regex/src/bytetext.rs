// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Bytes held as text, losslessly (T286).
//!
//! A header value, a configuration pattern or a sample string is a Rust `String`, and
//! `HAProxy`'s are bytes: obs-text (0x80-0xFF) that is not UTF-8 is legal in a header
//! (RFC 9110 section 5.5), and `req.hdr(x) -m str "caf\xe9"` must compare those bytes.
//! Valid UTF-8 stays what it is. A byte that is not part of a valid sequence is held as the
//! private-use character of the same number plus U+F700 (U+F780-U+F7FF), one character for
//! one byte, so `.` in a regex, `length` and a pattern all see one byte. The text a valid
//! sequence would give in that range is itself held as its bytes, so the mapping is
//! one-to-one: [`text_to_bytes`] of [`bytes_to_text`] is the input, always.

use std::borrow::Cow;

const BASE: u32 = 0xF700;

/// The character that stands for the byte `b` (0x80-0xFF).
#[must_use]
pub fn escape_byte(b: u8) -> char {
    char::from_u32(BASE + u32::from(b)).unwrap_or('\u{FFFD}')
}

/// The byte a character of U+F780-U+F7FF stands for.
#[must_use]
pub fn unescape_char(c: char) -> Option<u8> {
    let n = u32::from(c).checked_sub(BASE)?;
    u8::try_from(n).ok().filter(|b| *b >= 0x80)
}

/// Whether `text` holds a character [`escape_byte`] gave, so that its bytes are not its
/// UTF-8.
#[must_use]
pub fn has_escapes(text: &str) -> bool {
    !text.is_ascii() && text.chars().any(|c| unescape_char(c).is_some())
}

/// `bytes` as text.
#[must_use]
pub fn bytes_to_text(bytes: &[u8]) -> String {
    if let Ok(valid) = std::str::from_utf8(bytes) {
        if !has_escapes(valid) {
            return valid.to_owned();
        }
    }
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        let (valid, bad) = match std::str::from_utf8(rest) {
            Ok(v) => (v, 0),
            Err(e) => {
                let n = e.valid_up_to();
                (std::str::from_utf8(&rest[..n]).unwrap_or(""), e.error_len().unwrap_or(rest.len() - n))
            }
        };
        for c in valid.chars() {
            if unescape_char(c).is_some() {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push(escape_byte(b));
                }
            } else {
                out.push(c);
            }
        }
        let n = valid.len();
        for &b in &rest[n..n + bad] {
            out.push(escape_byte(b));
        }
        rest = &rest[n + bad..];
    }
    out
}

/// The bytes `text` stands for, borrowed when it holds no escaped byte.
#[must_use]
pub fn text_to_bytes(text: &str) -> Cow<'_, [u8]> {
    if !has_escapes(text) {
        return Cow::Borrowed(text.as_bytes());
    }
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        if let Some(b) = unescape_char(c) {
            out.push(b);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    Cow::Owned(out)
}

/// The number of bytes `text` stands for.
#[must_use]
pub fn text_len(text: &str) -> usize {
    if text.is_ascii() {
        return text.len();
    }
    text.chars().map(|c| if unescape_char(c).is_some() { 1 } else { c.len_utf8() }).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_is_kept_and_other_bytes_are_one_character_each() {
        assert_eq!(bytes_to_text(b"caf\xc3\xa9"), "caf\u{e9}");
        let t = bytes_to_text(b"caf\xe9");
        assert_eq!(t.chars().count(), 4);
        assert_eq!(text_len(&t), 4);
        assert_eq!(text_to_bytes(&t).as_ref(), b"caf\xe9");
        assert_ne!(t, "caf\u{e9}");
    }

    #[test]
    fn the_mapping_round_trips_whatever_the_bytes() {
        let mut all: Vec<u8> = (0..=255).collect();
        all.extend_from_slice(b"\xef\x9e\xa9 \xc3\xa9\xe9 \xf0\x9f\x98 \xc3");
        for chunk in [&all[..], &all[100..], b"\xef\x9e\xa9", b"\xc3", b"", b"abc"] {
            assert_eq!(text_to_bytes(&bytes_to_text(chunk)).as_ref(), chunk);
        }
        // Real U+F7A9 (EF 9E A9) is held as three bytes, not as the byte A9.
        let t = bytes_to_text(b"\xef\x9e\xa9");
        assert_eq!(text_len(&t), 3);
        assert_eq!(unescape_char('\u{F7A9}'), Some(0xA9));
    }
}
