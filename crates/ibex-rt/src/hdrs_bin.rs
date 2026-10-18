// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T382: the list `add-headers-bin`, `set-headers-bin` and `del-headers-bin` read, the format
//! `req.hdrs_bin` writes: for each header a varint length and the name, a varint length and
//! the value; the list ends with two empty strings (`del-headers-bin` reads only the names:
//! a length and a name, ended by a 0). The walk follows `http_action_set_headers_bin` and
//! `http_action_del_headers_bin` (`src/http_act.c`) step by step, including what a list
//! that is cut or never terminated does.

/// How a walk of a list ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Walk {
    /// The terminator was read: every entry was applied.
    Done,
    /// A rewrite failed (`fail_rewrite`): the list is cut inside an entry, or the header did
    /// not fit. A 500 in strict mode, the end of the rule otherwise.
    Rewrite,
    /// The list ended with no terminator ("invalid encoding"): a 500 whatever the mode.
    Invalid,
}

/// `decode_varint` (include/haproxy/intops.h); `None` when the buffer ends inside it.
fn varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *buf.get(*pos)?;
    *pos += 1;
    let mut i = u64::from(first);
    if first < 240 {
        return Some(i);
    }
    let mut shift = 4u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        i = i.wrapping_add(u64::from(b).checked_shl(shift).unwrap_or(0));
        shift += 7;
        if b < 128 {
            return Some(i);
        }
    }
}

/// `is_immutable_header` (include/haproxy/http.h): names a rule must not rewrite.
fn immutable(name: &[u8]) -> bool {
    [&b"expect"[..], b"trailer", b"upgrade", b"connection", b"keep-alive", b"content-length", b"proxy-connection", b"transfer-encoding", b"proxy-authenticate", b"proxy-authorization"]
        .iter()
        .any(|n| n.eq_ignore_ascii_case(name))
}

/// The next length-prefixed string of `bin`.
fn string<'a>(bin: &'a [u8], pos: &mut usize, len: u64) -> Option<&'a [u8]> {
    let end = pos.checked_add(usize::try_from(len).ok()?).filter(|e| *e <= bin.len())?;
    let s = &bin[*pos..end];
    *pos = end;
    Some(s)
}

/// Walks a list of `set-headers-bin` / `add-headers-bin`: `f(name, value)` is called for each
/// entry whose name starts with `prefix` (case-sensitively) and is not immutable, and says
/// whether the header could be written. A name holding a NUL is skipped: no header has one.
pub(crate) fn walk_set(bin: &[u8], prefix: &str, f: &mut dyn FnMut(&str, &str) -> bool) -> Walk {
    let mut pos = 0;
    while pos < bin.len() {
        let Some(sz) = varint(bin, &mut pos) else { return Walk::Rewrite };
        if sz == 0 {
            return if varint(bin, &mut pos) == Some(0) { Walk::Done } else { Walk::Rewrite };
        }
        let Some(name) = string(bin, &mut pos, sz) else { return Walk::Rewrite };
        let Some(sz) = varint(bin, &mut pos) else { return Walk::Rewrite };
        let Some(value) = string(bin, &mut pos, sz) else { return Walk::Rewrite };
        if !name.starts_with(prefix.as_bytes()) || immutable(name) || name.contains(&0) {
            continue;
        }
        if !f(&String::from_utf8_lossy(name), &String::from_utf8_lossy(value)) {
            return Walk::Rewrite;
        }
    }
    Walk::Invalid
}

/// Walks a list of `del-headers-bin`: `f(name)` for each name that is not immutable. The list
/// ends at its first 0 length.
pub(crate) fn walk_del(bin: &[u8], f: &mut dyn FnMut(&str)) -> Walk {
    let mut pos = 0;
    while pos < bin.len() {
        let Some(sz) = varint(bin, &mut pos) else { return Walk::Rewrite };
        if sz == 0 {
            return Walk::Done;
        }
        let Some(name) = string(bin, &mut pos, sz) else { return Walk::Rewrite };
        if immutable(name) || name.contains(&0) {
            continue;
        }
        f(&String::from_utf8_lossy(name));
    }
    Walk::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_reads_what_hdrs_bin_writes() {
        // The first byte below 240 is the value; from 240 each next byte adds its low 7 bits, shifted by 4, 11, ...
        let mut p = 0;
        assert_eq!(varint(&[0xF0, 0x00], &mut p), Some(240));
        p = 0;
        assert_eq!(varint(&[0xF0], &mut p), None);
        p = 0;
        assert_eq!(varint(&[0xFF, 0x05], &mut p), Some(255 + (5 << 4)));
    }

    #[test]
    fn terminators() {
        let mut n = 0;
        assert_eq!(walk_set(&[3, b'x', b'-', b'a', 1, b'x', 0, 0], "", &mut |_, _| { n += 1; true }), Walk::Done);
        assert_eq!(n, 1);
        assert_eq!(walk_set(&[3, b'x', b'-', b'a', 1, b'x'], "", &mut |_, _| true), Walk::Invalid);
        assert_eq!(walk_set(&[0], "", &mut |_, _| true), Walk::Rewrite);
        assert_eq!(walk_del(&[0, 7], &mut |_| {}), Walk::Done);
        assert_eq!(walk_del(&[3, b'x', b'-', b'a'], &mut |_| {}), Walk::Invalid);
        assert_eq!(walk_del(&[9, b'x'], &mut |_| {}), Walk::Rewrite);
    }
}
