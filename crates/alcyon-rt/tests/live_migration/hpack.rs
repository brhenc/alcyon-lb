// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HPACK (RFC 7541), written for this harness and sharing nothing with `alcyon_proto`.
//!
//! The harness checks that Alcyon's HPACK state survives a migration. Checking it with
//! Alcyon's own HPACK code would let one bug on both sides cancel out, so this is separate:
//! a full decoder (dynamic table, size updates, Huffman) and the encoder-side table the
//! client needs to emit indexed references. Its correctness is checked against the
//! RFC 7541 Appendix C examples by tests in `live_migration.rs`.

use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;

/// RFC 7541 Appendix A.
pub const STATIC: [(&str, &str); 61] = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
    (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""),
    ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
    ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""),
    ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""),
    ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
];

/// RFC 7541 Appendix B: (code, bit length) for symbols 0..=256, transcribed from
/// `HAProxy`'s `src/hpack-huff.c`.
#[rustfmt::skip]
#[allow(clippy::unreadable_literal)]
const HUFFMAN: [(u32, u8); 257] = [
    (0x00001ff8, 13), (0x007fffd8, 23), (0x0fffffe2, 28), (0x0fffffe3, 28), (0x0fffffe4, 28),
    (0x0fffffe5, 28), (0x0fffffe6, 28), (0x0fffffe7, 28), (0x0fffffe8, 28), (0x00ffffea, 24),
    (0x3ffffffc, 30), (0x0fffffe9, 28), (0x0fffffea, 28), (0x3ffffffd, 30), (0x0fffffeb, 28),
    (0x0fffffec, 28), (0x0fffffed, 28), (0x0fffffee, 28), (0x0fffffef, 28), (0x0ffffff0, 28),
    (0x0ffffff1, 28), (0x0ffffff2, 28), (0x3ffffffe, 30), (0x0ffffff3, 28), (0x0ffffff4, 28),
    (0x0ffffff5, 28), (0x0ffffff6, 28), (0x0ffffff7, 28), (0x0ffffff8, 28), (0x0ffffff9, 28),
    (0x0ffffffa, 28), (0x0ffffffb, 28), (0x00000014, 6), (0x000003f8, 10), (0x000003f9, 10),
    (0x00000ffa, 12), (0x00001ff9, 13), (0x00000015, 6), (0x000000f8, 8), (0x000007fa, 11),
    (0x000003fa, 10), (0x000003fb, 10), (0x000000f9, 8), (0x000007fb, 11), (0x000000fa, 8),
    (0x00000016, 6), (0x00000017, 6), (0x00000018, 6), (0x00000000, 5), (0x00000001, 5),
    (0x00000002, 5), (0x00000019, 6), (0x0000001a, 6), (0x0000001b, 6), (0x0000001c, 6),
    (0x0000001d, 6), (0x0000001e, 6), (0x0000001f, 6), (0x0000005c, 7), (0x000000fb, 8),
    (0x00007ffc, 15), (0x00000020, 6), (0x00000ffb, 12), (0x000003fc, 10), (0x00001ffa, 13),
    (0x00000021, 6), (0x0000005d, 7), (0x0000005e, 7), (0x0000005f, 7), (0x00000060, 7),
    (0x00000061, 7), (0x00000062, 7), (0x00000063, 7), (0x00000064, 7), (0x00000065, 7),
    (0x00000066, 7), (0x00000067, 7), (0x00000068, 7), (0x00000069, 7), (0x0000006a, 7),
    (0x0000006b, 7), (0x0000006c, 7), (0x0000006d, 7), (0x0000006e, 7), (0x0000006f, 7),
    (0x00000070, 7), (0x00000071, 7), (0x00000072, 7), (0x000000fc, 8), (0x00000073, 7),
    (0x000000fd, 8), (0x00001ffb, 13), (0x0007fff0, 19), (0x00001ffc, 13), (0x00003ffc, 14),
    (0x00000022, 6), (0x00007ffd, 15), (0x00000003, 5), (0x00000023, 6), (0x00000004, 5),
    (0x00000024, 6), (0x00000005, 5), (0x00000025, 6), (0x00000026, 6), (0x00000027, 6),
    (0x00000006, 5), (0x00000074, 7), (0x00000075, 7), (0x00000028, 6), (0x00000029, 6),
    (0x0000002a, 6), (0x00000007, 5), (0x0000002b, 6), (0x00000076, 7), (0x0000002c, 6),
    (0x00000008, 5), (0x00000009, 5), (0x0000002d, 6), (0x00000077, 7), (0x00000078, 7),
    (0x00000079, 7), (0x0000007a, 7), (0x0000007b, 7), (0x00007ffe, 15), (0x000007fc, 11),
    (0x00003ffd, 14), (0x00001ffd, 13), (0x0ffffffc, 28), (0x000fffe6, 20), (0x003fffd2, 22),
    (0x000fffe7, 20), (0x000fffe8, 20), (0x003fffd3, 22), (0x003fffd4, 22), (0x003fffd5, 22),
    (0x007fffd9, 23), (0x003fffd6, 22), (0x007fffda, 23), (0x007fffdb, 23), (0x007fffdc, 23),
    (0x007fffdd, 23), (0x007fffde, 23), (0x00ffffeb, 24), (0x007fffdf, 23), (0x00ffffec, 24),
    (0x00ffffed, 24), (0x003fffd7, 22), (0x007fffe0, 23), (0x00ffffee, 24), (0x007fffe1, 23),
    (0x007fffe2, 23), (0x007fffe3, 23), (0x007fffe4, 23), (0x001fffdc, 21), (0x003fffd8, 22),
    (0x007fffe5, 23), (0x003fffd9, 22), (0x007fffe6, 23), (0x007fffe7, 23), (0x00ffffef, 24),
    (0x003fffda, 22), (0x001fffdd, 21), (0x000fffe9, 20), (0x003fffdb, 22), (0x003fffdc, 22),
    (0x007fffe8, 23), (0x007fffe9, 23), (0x001fffde, 21), (0x007fffea, 23), (0x003fffdd, 22),
    (0x003fffde, 22), (0x00fffff0, 24), (0x001fffdf, 21), (0x003fffdf, 22), (0x007fffeb, 23),
    (0x007fffec, 23), (0x001fffe0, 21), (0x001fffe1, 21), (0x003fffe0, 22), (0x001fffe2, 21),
    (0x007fffed, 23), (0x003fffe1, 22), (0x007fffee, 23), (0x007fffef, 23), (0x000fffea, 20),
    (0x003fffe2, 22), (0x003fffe3, 22), (0x003fffe4, 22), (0x007ffff0, 23), (0x003fffe5, 22),
    (0x003fffe6, 22), (0x007ffff1, 23), (0x03ffffe0, 26), (0x03ffffe1, 26), (0x000fffeb, 20),
    (0x0007fff1, 19), (0x003fffe7, 22), (0x007ffff2, 23), (0x003fffe8, 22), (0x01ffffec, 25),
    (0x03ffffe2, 26), (0x03ffffe3, 26), (0x03ffffe4, 26), (0x07ffffde, 27), (0x07ffffdf, 27),
    (0x03ffffe5, 26), (0x00fffff1, 24), (0x01ffffed, 25), (0x0007fff2, 19), (0x001fffe3, 21),
    (0x03ffffe6, 26), (0x07ffffe0, 27), (0x07ffffe1, 27), (0x03ffffe7, 26), (0x07ffffe2, 27),
    (0x00fffff2, 24), (0x001fffe4, 21), (0x001fffe5, 21), (0x03ffffe8, 26), (0x03ffffe9, 26),
    (0x0ffffffd, 28), (0x07ffffe3, 27), (0x07ffffe4, 27), (0x07ffffe5, 27), (0x000fffec, 20),
    (0x00fffff3, 24), (0x000fffed, 20), (0x001fffe6, 21), (0x003fffe9, 22), (0x001fffe7, 21),
    (0x001fffe8, 21), (0x007ffff3, 23), (0x003fffea, 22), (0x003fffeb, 22), (0x01ffffee, 25),
    (0x01ffffef, 25), (0x00fffff4, 24), (0x00fffff5, 24), (0x03ffffea, 26), (0x007ffff4, 23),
    (0x03ffffeb, 26), (0x07ffffe6, 27), (0x03ffffec, 26), (0x03ffffed, 26), (0x07ffffe7, 27),
    (0x07ffffe8, 27), (0x07ffffe9, 27), (0x07ffffea, 27), (0x07ffffeb, 27), (0x0ffffffe, 28),
    (0x07ffffec, 27), (0x07ffffed, 27), (0x07ffffee, 27), (0x07ffffef, 27), (0x07fffff0, 27),
    (0x03ffffee, 26), (0x3fffffff, 30),
];

fn huffman_map() -> &'static HashMap<(u8, u32), u16> {
    static MAP: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
    MAP.get_or_init(|| {
        HUFFMAN
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((len, code), u16::try_from(sym).unwrap_or(0)))
            .collect()
    })
}

/// Decodes a Huffman-coded string.
///
/// # Errors
/// An EOS symbol in the data, a code longer than 30 bits, or padding that is longer than
/// seven bits or not all ones (RFC 7541 section 5.2).
pub fn huffman_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let map = huffman_map();
    let mut out = Vec::new();
    let (mut code, mut len) = (0u32, 0u8);
    for &byte in data {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if let Some(&sym) = map.get(&(len, code)) {
                if sym == 256 {
                    return Err("EOS symbol inside a Huffman string".into());
                }
                out.push(u8::try_from(sym).unwrap_or(0));
                code = 0;
                len = 0;
            } else if len > 30 {
                return Err(format!("no Huffman code matches {len} bits"));
            }
        }
    }
    if len > 7 || code != (1u32 << len) - 1 {
        return Err(format!("bad Huffman padding: {len} bits {code:#b}"));
    }
    Ok(out)
}

/// Decodes an HPACK integer with an `n`-bit prefix at `buf[*pos]`.
///
/// # Errors
/// Truncation or overflow.
pub fn decode_int(buf: &[u8], pos: &mut usize, n: u8) -> Result<usize, String> {
    let max = (1usize << n) - 1;
    let first = *buf.get(*pos).ok_or("truncated integer")?;
    *pos += 1;
    let mut v = usize::from(first) & max;
    if v < max {
        return Ok(v);
    }
    let mut shift = 0;
    loop {
        let b = *buf.get(*pos).ok_or("truncated integer")?;
        *pos += 1;
        v = v.checked_add(usize::from(b & 0x7f).checked_shl(shift).ok_or("integer overflow")?).ok_or("integer overflow")?;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
        if shift > 28 {
            return Err("integer overflow".into());
        }
    }
}

/// Encodes `v` with an `n`-bit prefix, the top bits of the first byte being `flags`.
#[must_use]
pub fn encode_int(v: usize, n: u8, flags: u8) -> Vec<u8> {
    let max = (1usize << n) - 1;
    if v < max {
        return vec![flags | u8::try_from(v).unwrap_or(0)];
    }
    let mut out = vec![flags | u8::try_from(max).unwrap_or(0)];
    let mut rest = v - max;
    while rest >= 128 {
        out.push(u8::try_from(rest % 128).unwrap_or(0) | 0x80);
        rest /= 128;
    }
    out.push(u8::try_from(rest).unwrap_or(0));
    out
}

fn decode_str(buf: &[u8], pos: &mut usize) -> Result<String, String> {
    let huff = buf.get(*pos).ok_or("truncated string")? & 0x80 != 0;
    let len = decode_int(buf, pos, 7)?;
    let raw = buf.get(*pos..*pos + len).ok_or("truncated string")?;
    *pos += len;
    let bytes = if huff { huffman_decode(raw)? } else { raw.to_vec() };
    String::from_utf8(bytes).map_err(|_| "non-UTF-8 header string".to_string())
}

fn entry_size(n: &str, v: &str) -> usize {
    32 + n.len() + v.len()
}

/// A dynamic table (RFC 7541 section 2.3.2), newest entry first.
#[derive(Debug, Clone)]
pub struct Table {
    pub entries: VecDeque<(String, String)>,
    size: usize,
    pub max: usize,
}

impl Table {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self { entries: VecDeque::new(), size: 0, max }
    }

    fn evict(&mut self) {
        while self.size > self.max {
            let Some((n, v)) = self.entries.pop_back() else { break };
            self.size -= entry_size(&n, &v);
        }
    }

    pub fn insert(&mut self, n: String, v: String) {
        let sz = entry_size(&n, &v);
        if sz > self.max {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.size += sz;
        self.entries.push_front((n, v));
        self.evict();
    }

    pub fn resize(&mut self, max: usize) {
        self.max = max;
        self.evict();
    }

    /// Entry `idx` of the combined index space: 1..=61 static, 62.. dynamic.
    ///
    /// # Errors
    /// An index that names nothing -- for a decoder, the sign of a table out of step.
    pub fn get(&self, idx: usize) -> Result<(String, String), String> {
        if idx == 0 {
            return Err("index 0".into());
        }
        if idx <= STATIC.len() {
            let (n, v) = STATIC[idx - 1];
            return Ok((n.to_string(), v.to_string()));
        }
        self.entries.get(idx - STATIC.len() - 1).cloned().ok_or_else(|| {
            format!("index {idx} is past the end of the dynamic table ({} entries)", self.entries.len())
        })
    }

    /// The combined index of an exact (name, value) entry in the dynamic table.
    #[must_use]
    pub fn find(&self, n: &str, v: &str) -> Option<usize> {
        self.entries.iter().position(|(a, b)| a == n && b == v).map(|i| i + STATIC.len() + 1)
    }
}

/// An HPACK decoder.
#[derive(Debug, Clone)]
pub struct Decoder {
    pub table: Table,
    /// The `SETTINGS_HEADER_TABLE_SIZE` we advertised: a size update may not exceed it.
    pub limit: usize,
}

impl Decoder {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self { table: Table::new(limit), limit }
    }

    /// Decodes one complete header block.
    ///
    /// # Errors
    /// Any malformed representation, or a reference the table cannot satisfy.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(String, String)>, String> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                let idx = decode_int(block, &mut pos, 7)?;
                out.push(self.table.get(idx)?);
            } else if b & 0xc0 == 0x40 {
                let idx = decode_int(block, &mut pos, 6)?;
                let n = if idx == 0 { decode_str(block, &mut pos)? } else { self.table.get(idx)?.0 };
                let v = decode_str(block, &mut pos)?;
                self.table.insert(n.clone(), v.clone());
                out.push((n, v));
            } else if b & 0xe0 == 0x20 {
                let sz = decode_int(block, &mut pos, 5)?;
                if sz > self.limit {
                    return Err(format!("table size update to {sz}, above the {} we allowed", self.limit));
                }
                if !out.is_empty() {
                    return Err("table size update after a header field".into());
                }
                self.table.resize(sz);
            } else {
                let idx = decode_int(block, &mut pos, 4)?;
                let n = if idx == 0 { decode_str(block, &mut pos)? } else { self.table.get(idx)?.0 };
                let v = decode_str(block, &mut pos)?;
                out.push((n, v));
            }
        }
        Ok(out)
    }
}

fn raw_str(s: &str) -> Vec<u8> {
    let mut v = encode_int(s.len(), 7, 0);
    v.extend_from_slice(s.as_bytes());
    v
}

/// The client's encoder: emits plain (non-Huffman) literals and indexed references, and
/// keeps the table the peer's decoder must be keeping too.
#[derive(Debug, Clone)]
pub struct Encoder {
    pub table: Table,
}

impl Encoder {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self { table: Table::new(max) }
    }

    /// An indexed field for an entry already in the table.
    ///
    /// # Panics
    /// When the entry is not in the table: a test bug.
    #[must_use]
    pub fn indexed(&self, n: &str, v: &str) -> Vec<u8> {
        let idx = self.table.find(n, v).unwrap_or_else(|| panic!("{n}: {v} is not in the encoder table"));
        encode_int(idx, 7, 0x80)
    }

    /// A literal with incremental indexing and a literal name; the entry is added.
    pub fn literal_indexed(&mut self, n: &str, v: &str) -> Vec<u8> {
        let mut out = vec![0x40];
        out.extend(raw_str(n));
        out.extend(raw_str(v));
        self.table.insert(n.to_string(), v.to_string());
        out
    }

    /// A literal without indexing, naming a static entry by index (0 for a literal name).
    #[must_use]
    pub fn literal_plain(name_idx: usize, n: &str, v: &str) -> Vec<u8> {
        let mut out = encode_int(name_idx, 4, 0);
        if name_idx == 0 {
            out.extend(raw_str(n));
        }
        out.extend(raw_str(v));
        out
    }
}
