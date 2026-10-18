// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `JA4` TLS client fingerprint (FoxIO, `technical_details/JA4.md`), an Ibex-only addition:
//! `HAProxy` has no `JA4`. Written from the specification text; no `FoxIO` code is used.
//! JA4 itself (TLS client fingerprinting only, not the rest of JA4+) is licensed BSD-3-Clause
//! by `FoxIO` (`LICENSE-JA4` in <https://github.com/FoxIO-LLC/ja4>), whose notice is kept in
//! `docs/differences.md`.
//!
//! [`parse`] reads a whole `ClientHello` (not the truncated capture) and returns the readable
//! part `a` and the two lists to hash; the hashing (`SHA-256`, 12 hex characters) is done by the
//! fetch, which has the digest.

/// What JA4 needs from a `ClientHello`: `t13d1516h2` and the text of the two hashed parts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ja4Parts {
    /// `t`, the version, `d`/`i`, cipher count, extension count, ALPN ends: `t13d1516h2`.
    pub a: String,
    /// The sorted cipher suites, 4 lower-case hex digits each, comma-joined; empty for none.
    pub b: String,
    /// The sorted extension ids without SNI and ALPN, then `_` and the signature algorithms in
    /// their order; empty when there is no extension to hash.
    pub c: String,
}

fn is_grease(v: u16) -> bool {
    let [hi, lo] = v.to_be_bytes();
    hi == lo && lo & 0x0f == 0x0a
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

fn pairs(b: &[u8]) -> impl Iterator<Item = u16> + '_ {
    b.chunks_exact(2).filter_map(|p| match p {
        [a, b] => Some(u16::from_be_bytes([*a, *b])),
        _ => None,
    })
}

fn joined(v: &[u16]) -> String {
    v.iter().map(|x| format!("{x:04x}")).collect::<Vec<_>>().join(",")
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

/// The first and last character of the first ALPN value; hex characters of the value when
/// either end is not an ASCII letter or digit (spec examples: `0xAB 0xCD` is `ad`).
fn alpn_ends(first: Option<&[u8]>) -> String {
    let Some(val) = first.filter(|x| !x.is_empty()) else { return "00".to_string() };
    let (Some(&head), Some(&tail)) = (val.first(), val.last()) else { return "00".to_string() };
    if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
        return format!("{}{}", char::from(head), char::from(tail));
    }
    let hex: String = val.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut c = hex.chars();
    let a = c.next().unwrap_or('0');
    let z = c.next_back().unwrap_or(a);
    format!("{a}{z}")
}

/// Parses the handshake message `msg` (from its type byte) as a `ClientHello`; `None` when it is
/// not one or is malformed.
#[must_use]
pub fn parse(msg: &[u8]) -> Option<Ja4Parts> {
    if *msg.first()? != 1 {
        return None;
    }
    let len = (usize::from(*msg.get(1)?) << 16) | (usize::from(*msg.get(2)?) << 8) | usize::from(*msg.get(3)?);
    let body = msg.get(4..4 + len)?;
    let legacy = be16(body, 0)?;
    let mut pos = 2 + 32;
    pos += usize::from(*body.get(pos)?) + 1;
    let cs_len = usize::from(be16(body, pos)?);
    pos += 2;
    let suites = body.get(pos..pos + cs_len)?;
    pos += cs_len;
    pos += usize::from(*body.get(pos)?) + 1;

    let mut ciphers: Vec<u16> = pairs(suites).filter(|c| !is_grease(*c)).collect();
    ciphers.sort_unstable();

    let mut version = legacy;
    let (mut sni, mut alpn_first) = (false, None);
    let mut ext_count = 0usize;
    let mut exts: Vec<u16> = Vec::new();
    let mut sigalgs: Vec<u16> = Vec::new();
    // A hello may end after the compression methods: no extensions.
    if let Some(total) = be16(body, pos) {
        pos += 2;
        let mut rest = body.get(pos..pos + usize::from(total))?;
        while !rest.is_empty() {
            let id = be16(rest, 0)?;
            let l = usize::from(be16(rest, 2)?);
            let data = rest.get(4..4 + l)?;
            rest = rest.get(4 + l..)?;
            if is_grease(id) {
                continue;
            }
            ext_count += 1;
            match id {
                0 => sni = true,
                16 => {
                    // protocol_name_list: 2-byte length, then 1-byte-prefixed names.
                    let first_len = usize::from(*data.get(2)?);
                    alpn_first = data.get(3..3 + first_len);
                }
                _ => exts.push(id),
            }
            match id {
                43 => {
                    let n = usize::from(*data.first()?);
                    let list = data.get(1..1 + n)?;
                    version = pairs(list).filter(|v| !is_grease(*v)).max().unwrap_or(legacy);
                }
                13 => {
                    let n = usize::from(be16(data, 0)?);
                    sigalgs = pairs(data.get(2..2 + n)?).filter(|s| !is_grease(*s)).collect();
                }
                _ => {}
            }
        }
    }
    exts.retain(|e| *e != 16);
    exts.sort_unstable();
    let c = if exts.is_empty() {
        String::new()
    } else if sigalgs.is_empty() {
        joined(&exts)
    } else {
        format!("{}_{}", joined(&exts), joined(&sigalgs))
    };
    Some(Ja4Parts {
        a: format!(
            "t{}{}{:02}{:02}{}",
            version_code(version),
            if sni { 'd' } else { 'i' },
            ciphers.len().min(99),
            ext_count.min(99),
            alpn_ends(alpn_first)
        ),
        b: joined(&ciphers),
        c,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_examples_from_the_spec() {
        for (v, want) in [
            (&[0xab][..], "ab"),
            (&[0x20], "20"),
            (&[0xab, 0xcd], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xab], "3b"),
            (&[0x61, 0x20], "60"),
            (&[0x30, 0x31, 0xab, 0xcd], "3d"),
            (&[0x30, 0xab, 0xcd, 0x31], "01"),
            (b"h2", "h2"),
            (b"http/1.1", "h1"),
            (b"x", "xx"),
        ] {
            assert_eq!(alpn_ends(Some(v)), want, "{v:02x?}");
        }
        assert_eq!(alpn_ends(None), "00");
        assert_eq!(alpn_ends(Some(&[])), "00");
    }

    #[test]
    fn grease_values() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && is_grease(0x7a7a));
        assert!(!is_grease(0x0a1a) && !is_grease(0x1301) && !is_grease(0x0b0b));
    }

    #[test]
    fn malformed_is_none() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[2, 0, 0, 0]).is_none());
        assert!(parse(&[1, 0, 0, 5, 3, 3, 0, 0, 0]).is_none());
        // A well-formed length and a body that ends in the random.
        assert!(parse(&[1, 0, 0, 4, 3, 3, 0, 0]).is_none());
    }
}
