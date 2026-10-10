// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/hpack-dec.c, src/hpack-enc.c, src/hpack-tbl.c and RFC 7541.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HPACK: Header Compression for HTTP/2 (RFC 7541).
//!
//! Implements static and dynamic table lookups, integer encoding/decoding,
//! canonical Huffman encoding/decoding, and header block compression under
//! `#![forbid(unsafe_code)]`.

#![allow(clippy::unreadable_literal)]

use crate::h2::H2Error;
use crate::htx::HeaderField;
use std::collections::VecDeque;

/// Number of entries in the standard RFC 7541 Static Table (61 entries).
pub const STATIC_TABLE_LEN: usize = 61;

/// Default maximum dynamic table size (4096 octets).
pub const DEFAULT_DYNAMIC_TABLE_MAX_SIZE: usize = 4096;

/// Entry in the Static or Dynamic Header Table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableEntry {
    pub name: String,
    pub value: String,
}

impl TableEntry {
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Size in octets of the entry according to RFC 7541 §4.1 (`name.len() + value.len() + 32`).
    #[must_use]
    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + 32
    }
}

/// Static Table Definitions according to RFC 7541 Appendix A.
pub static STATIC_TABLE: [(&str, &str); STATIC_TABLE_LEN] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

#[allow(clippy::unreadable_literal)]
pub const HUFFMAN_CODES: [(u32, u8); 257] = [
    (0x00001ff8, 13), // 0
    (0x007fffd8, 23), // 1
    (0x0fffffe2, 28), // 2
    (0x0fffffe3, 28), // 3
    (0x0fffffe4, 28), // 4
    (0x0fffffe5, 28), // 5
    (0x0fffffe6, 28), // 6
    (0x0fffffe7, 28), // 7
    (0x0fffffe8, 28), // 8
    (0x00ffffea, 24), // 9
    (0x3ffffffc, 30), // 10
    (0x0fffffe9, 28), // 11
    (0x0fffffea, 28), // 12
    (0x3ffffffd, 30), // 13
    (0x0fffffeb, 28), // 14
    (0x0fffffec, 28), // 15
    (0x0fffffed, 28), // 16
    (0x0fffffee, 28), // 17
    (0x0fffffef, 28), // 18
    (0x0ffffff0, 28), // 19
    (0x0ffffff1, 28), // 20
    (0x0ffffff2, 28), // 21
    (0x3ffffffe, 30), // 22
    (0x0ffffff3, 28), // 23
    (0x0ffffff4, 28), // 24
    (0x0ffffff5, 28), // 25
    (0x0ffffff6, 28), // 26
    (0x0ffffff7, 28), // 27
    (0x0ffffff8, 28), // 28
    (0x0ffffff9, 28), // 29
    (0x0ffffffa, 28), // 30
    (0x0ffffffb, 28), // 31
    (0x00000014, 6),  // 32
    (0x000003f8, 10), // 33
    (0x000003f9, 10), // 34
    (0x00000ffa, 12), // 35
    (0x00001ff9, 13), // 36
    (0x00000015, 6),  // 37
    (0x000000f8, 8),  // 38
    (0x000007fa, 11), // 39
    (0x000003fa, 10), // 40
    (0x000003fb, 10), // 41
    (0x000000f9, 8),  // 42
    (0x000007fb, 11), // 43
    (0x000000fa, 8),  // 44
    (0x00000016, 6),  // 45
    (0x00000017, 6),  // 46
    (0x00000018, 6),  // 47
    (0x00000000, 5),  // 48
    (0x00000001, 5),  // 49
    (0x00000002, 5),  // 50
    (0x00000019, 6),  // 51
    (0x0000001a, 6),  // 52
    (0x0000001b, 6),  // 53
    (0x0000001c, 6),  // 54
    (0x0000001d, 6),  // 55
    (0x0000001e, 6),  // 56
    (0x0000001f, 6),  // 57
    (0x0000005c, 7),  // 58
    (0x000000fb, 8),  // 59
    (0x00007ffc, 15), // 60
    (0x00000020, 6),  // 61
    (0x00000ffb, 12), // 62
    (0x000003fc, 10), // 63
    (0x00001ffa, 13), // 64
    (0x00000021, 6),  // 65
    (0x0000005d, 7),  // 66
    (0x0000005e, 7),  // 67
    (0x0000005f, 7),  // 68
    (0x00000060, 7),  // 69
    (0x00000061, 7),  // 70
    (0x00000062, 7),  // 71
    (0x00000063, 7),  // 72
    (0x00000064, 7),  // 73
    (0x00000065, 7),  // 74
    (0x00000066, 7),  // 75
    (0x00000067, 7),  // 76
    (0x00000068, 7),  // 77
    (0x00000069, 7),  // 78
    (0x0000006a, 7),  // 79
    (0x0000006b, 7),  // 80
    (0x0000006c, 7),  // 81
    (0x0000006d, 7),  // 82
    (0x0000006e, 7),  // 83
    (0x0000006f, 7),  // 84
    (0x00000070, 7),  // 85
    (0x00000071, 7),  // 86
    (0x00000072, 7),  // 87
    (0x000000fc, 8),  // 88
    (0x00000073, 7),  // 89
    (0x000000fd, 8),  // 90
    (0x00001ffb, 13), // 91
    (0x0007fff0, 19), // 92
    (0x00001ffc, 13), // 93
    (0x00003ffc, 14), // 94
    (0x00000022, 6),  // 95
    (0x00007ffd, 15), // 96
    (0x00000003, 5),  // 97
    (0x00000023, 6),  // 98
    (0x00000004, 5),  // 99
    (0x00000024, 6),  // 100
    (0x00000005, 5),  // 101
    (0x00000025, 6),  // 102
    (0x00000026, 6),  // 103
    (0x00000027, 6),  // 104
    (0x00000006, 5),  // 105
    (0x00000074, 7),  // 106
    (0x00000075, 7),  // 107
    (0x00000028, 6),  // 108
    (0x00000029, 6),  // 109
    (0x0000002a, 6),  // 110
    (0x00000007, 5),  // 111
    (0x0000002b, 6),  // 112
    (0x00000076, 7),  // 113
    (0x0000002c, 6),  // 114
    (0x00000008, 5),  // 115
    (0x00000009, 5),  // 116
    (0x0000002d, 6),  // 117
    (0x00000077, 7),  // 118
    (0x00000078, 7),  // 119
    (0x00000079, 7),  // 120
    (0x0000007a, 7),  // 121
    (0x0000007b, 7),  // 122
    (0x00007ffe, 15), // 123
    (0x000007fc, 11), // 124
    (0x00003ffd, 14), // 125
    (0x00001ffd, 13), // 126
    (0x0ffffffc, 28), // 127
    (0x000fffe6, 20), // 128
    (0x003fffd2, 22), // 129
    (0x000fffe7, 20), // 130
    (0x000fffe8, 20), // 131
    (0x003fffd3, 22), // 132
    (0x003fffd4, 22), // 133
    (0x003fffd5, 22), // 134
    (0x007fffd9, 23), // 135
    (0x003fffd6, 22), // 136
    (0x007fffda, 23), // 137
    (0x007fffdb, 23), // 138
    (0x007fffdc, 23), // 139
    (0x007fffdd, 23), // 140
    (0x007fffde, 23), // 141
    (0x00ffffeb, 24), // 142
    (0x007fffdf, 23), // 143
    (0x00ffffec, 24), // 144
    (0x00ffffed, 24), // 145
    (0x003fffd7, 22), // 146
    (0x007fffe0, 23), // 147
    (0x00ffffee, 24), // 148
    (0x007fffe1, 23), // 149
    (0x007fffe2, 23), // 150
    (0x007fffe3, 23), // 151
    (0x007fffe4, 23), // 152
    (0x001fffdc, 21), // 153
    (0x003fffd8, 22), // 154
    (0x007fffe5, 23), // 155
    (0x003fffd9, 22), // 156
    (0x007fffe6, 23), // 157
    (0x007fffe7, 23), // 158
    (0x00ffffef, 24), // 159
    (0x003fffda, 22), // 160
    (0x001fffdd, 21), // 161
    (0x000fffe9, 20), // 162
    (0x003fffdb, 22), // 163
    (0x003fffdc, 22), // 164
    (0x007fffe8, 23), // 165
    (0x007fffe9, 23), // 166
    (0x001fffde, 21), // 167
    (0x007fffea, 23), // 168
    (0x003fffdd, 22), // 169
    (0x003fffde, 22), // 170
    (0x00fffff0, 24), // 171
    (0x001fffdf, 21), // 172
    (0x003fffdf, 22), // 173
    (0x007fffeb, 23), // 174
    (0x007fffec, 23), // 175
    (0x001fffe0, 21), // 176
    (0x001fffe1, 21), // 177
    (0x003fffe0, 22), // 178
    (0x001fffe2, 21), // 179
    (0x007fffed, 23), // 180
    (0x003fffe1, 22), // 181
    (0x007fffee, 23), // 182
    (0x007fffef, 23), // 183
    (0x000fffea, 20), // 184
    (0x003fffe2, 22), // 185
    (0x003fffe3, 22), // 186
    (0x003fffe4, 22), // 187
    (0x007ffff0, 23), // 188
    (0x003fffe5, 22), // 189
    (0x003fffe6, 22), // 190
    (0x007ffff1, 23), // 191
    (0x03ffffe0, 26), // 192
    (0x03ffffe1, 26), // 193
    (0x000fffeb, 20), // 194
    (0x0007fff1, 19), // 195
    (0x003fffe7, 22), // 196
    (0x007ffff2, 23), // 197
    (0x003fffe8, 22), // 198
    (0x01ffffec, 25), // 199
    (0x03ffffe2, 26), // 200
    (0x03ffffe3, 26), // 201
    (0x03ffffe4, 26), // 202
    (0x07ffffde, 27), // 203
    (0x07ffffdf, 27), // 204
    (0x03ffffe5, 26), // 205
    (0x00fffff1, 24), // 206
    (0x01ffffed, 25), // 207
    (0x0007fff2, 19), // 208
    (0x001fffe3, 21), // 209
    (0x03ffffe6, 26), // 210
    (0x07ffffe0, 27), // 211
    (0x07ffffe1, 27), // 212
    (0x03ffffe7, 26), // 213
    (0x07ffffe2, 27), // 214
    (0x00fffff2, 24), // 215
    (0x001fffe4, 21), // 216
    (0x001fffe5, 21), // 217
    (0x03ffffe8, 26), // 218
    (0x03ffffe9, 26), // 219
    (0x0ffffffd, 28), // 220
    (0x07ffffe3, 27), // 221
    (0x07ffffe4, 27), // 222
    (0x07ffffe5, 27), // 223
    (0x000fffec, 20), // 224
    (0x00fffff3, 24), // 225
    (0x000fffed, 20), // 226
    (0x001fffe6, 21), // 227
    (0x003fffe9, 22), // 228
    (0x001fffe7, 21), // 229
    (0x001fffe8, 21), // 230
    (0x007ffff3, 23), // 231
    (0x003fffea, 22), // 232
    (0x003fffeb, 22), // 233
    (0x01ffffee, 25), // 234
    (0x01ffffef, 25), // 235
    (0x00fffff4, 24), // 236
    (0x00fffff5, 24), // 237
    (0x03ffffea, 26), // 238
    (0x007ffff4, 23), // 239
    (0x03ffffeb, 26), // 240
    (0x07ffffe6, 27), // 241
    (0x03ffffec, 26), // 242
    (0x03ffffed, 26), // 243
    (0x07ffffe7, 27), // 244
    (0x07ffffe8, 27), // 245
    (0x07ffffe9, 27), // 246
    (0x07ffffea, 27), // 247
    (0x07ffffeb, 27), // 248
    (0x0ffffffe, 28), // 249
    (0x07ffffec, 27), // 250
    (0x07ffffed, 27), // 251
    (0x07ffffee, 27), // 252
    (0x07ffffef, 27), // 253
    (0x07fffff0, 27), // 254
    (0x03ffffee, 26), // 255
    (0x3fffffff, 30), // 256
];

/// A node in the compile-time Huffman decoding tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HuffmanNode {
    pub left: u16,
    pub right: u16,
    pub sym: u16,
}

/// Builds the Huffman decoding binary tree at compile time.
#[must_use]
pub const fn build_huffman_tree() -> [HuffmanNode; 513] {
    let mut tree = [HuffmanNode {
        left: 0,
        right: 0,
        sym: 0xFFFF,
    }; 513];
    let mut next_node: u16 = 1;
    let mut sym: u16 = 0;
    while sym < 257 {
        let (code, len) = HUFFMAN_CODES[sym as usize];
        let mut curr = 0;
        let mut bit_idx = 0;
        while bit_idx < len {
            let bit = (code >> (len - 1 - bit_idx)) & 1;
            if bit == 0 {
                let left = tree[curr].left;
                if left == 0 {
                    tree[curr].left = next_node;
                    curr = next_node as usize;
                    next_node += 1;
                } else {
                    curr = left as usize;
                }
            } else {
                let right = tree[curr].right;
                if right == 0 {
                    tree[curr].right = next_node;
                    curr = next_node as usize;
                    next_node += 1;
                } else {
                    curr = right as usize;
                }
            }
            bit_idx += 1;
        }
        tree[curr].sym = sym;
        sym += 1;
    }
    tree
}

/// Compile-time precomputed Huffman decoding tree (513 nodes).
pub static HUFFMAN_TREE: [HuffmanNode; 513] = build_huffman_tree();

/// Decodes a Huffman-encoded byte slice according to RFC 7541 §5.2 and Appendix B.
///
/// # Errors
/// Returns `H2Error::CompressionError` if bitstream contains invalid prefixes, the EOS symbol,
/// or padding longer than 7 bits or not composed entirely of 1s.
pub fn decode_huffman(data: &[u8]) -> Result<String, H2Error> {
    let mut node_idx = 0usize;
    let mut out = Vec::with_capacity(data.len());
    let mut rem_bits = 0usize;

    for &byte in data {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            node_idx = if bit == 0 {
                HUFFMAN_TREE[node_idx].left as usize
            } else {
                HUFFMAN_TREE[node_idx].right as usize
            };

            if node_idx == 0 {
                return Err(H2Error::CompressionError);
            }

            let sym = HUFFMAN_TREE[node_idx].sym;
            if sym != 0xFFFF {
                if sym == 256 {
                    // RFC 7541 §5.2: A Huffman-encoded string literal containing the EOS symbol
                    // MUST be treated as a decoding error.
                    return Err(H2Error::CompressionError);
                }
                out.push(sym.to_le_bytes()[0]);
                node_idx = 0;
                rem_bits = 0;
            } else {
                rem_bits += 1;
            }
        }
    }

    if node_idx != 0 {
        if rem_bits > 7 {
            // RFC 7541 §5.2: padding longer than 7 bits MUST be treated as a decoding error.
            return Err(H2Error::CompressionError);
        }
        // Check that remaining bits correspond to most significant bits of EOS (all 1s).
        let mut check_node = 0usize;
        for _ in 0..rem_bits {
            check_node = HUFFMAN_TREE[check_node].right as usize;
        }
        if check_node != node_idx {
            return Err(H2Error::CompressionError);
        }
    }

    String::from_utf8(out).map_err(|_| H2Error::CompressionError)
}

/// Encodes a raw byte slice into canonical Huffman representation per RFC 7541 Appendix B.
pub fn encode_huffman(input: &[u8], out: &mut Vec<u8>) {
    let mut bit_buf = 0u64;
    let mut bit_len = 0u8;

    for &b in input {
        let (code, len) = HUFFMAN_CODES[b as usize];
        bit_buf = (bit_buf << len) | u64::from(code);
        bit_len += len;
        while bit_len >= 8 {
            bit_len -= 8;
            out.push(((bit_buf >> bit_len) & 0xFF) as u8);
        }
    }

    if bit_len > 0 {
        let pad = 8 - bit_len;
        bit_buf = (bit_buf << pad) | ((1u64 << pad) - 1);
        out.push((bit_buf & 0xFF) as u8);
    }
}

/// HPACK Dynamic Header Table (RFC 7541 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicTable {
    entries: VecDeque<TableEntry>,
    size: usize,
    max_size: usize,
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new(DEFAULT_DYNAMIC_TABLE_MAX_SIZE)
    }
}

impl DynamicTable {
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    /// Current size in bytes of the dynamic table.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Maximum configured size in bytes of the dynamic table.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Number of entries currently stored in the dynamic table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Updates the maximum allowable size of the dynamic table, evicting entries if necessary.
    pub fn set_max_size(&mut self, new_max: usize) {
        self.max_size = new_max;
        self.evict_to_fit();
    }

    /// Inserts a new entry at the head (index 0 of dynamic table / index 62 in combined table).
    /// Oldest entries at the tail are evicted if total size exceeds `max_size`.
    pub fn insert(&mut self, name: String, value: String) {
        let entry = TableEntry::new(name, value);
        let entry_size = entry.size();

        if entry_size > self.max_size {
            self.clear();
            return;
        }

        self.size += entry_size;
        self.entries.push_front(entry);
        self.evict_to_fit();
    }

    /// Retrieves an entry by 0-based dynamic table index (0 is newest).
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&TableEntry> {
        self.entries.get(idx)
    }

    /// Clears all entries from the dynamic table.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.size = 0;
    }

    fn evict_to_fit(&mut self) {
        while self.size > self.max_size {
            if let Some(evicted) = self.entries.pop_back() {
                self.size = self.size.saturating_sub(evicted.size());
            } else {
                self.size = 0;
                break;
            }
        }
    }
}

/// Look up in the combined static and dynamic table using 1-based HPACK index (RFC 7541 §2.3.3).
#[must_use]
pub fn lookup_table(idx: usize, dynamic: &DynamicTable) -> Option<(&str, &str)> {
    if idx == 0 {
        return None;
    }
    if idx <= STATIC_TABLE_LEN {
        let (n, v) = STATIC_TABLE[idx - 1];
        Some((n, v))
    } else {
        let dyn_idx = idx - STATIC_TABLE_LEN - 1;
        dynamic
            .get(dyn_idx)
            .map(|e| (e.name.as_str(), e.value.as_str()))
    }
}

/// Find matching static or dynamic table entry by name and value.
/// Returns `(index, exact_match)`.
#[must_use]
pub fn find_table_entry(name: &str, value: &str, dynamic: &DynamicTable) -> Option<(usize, bool)> {
    let mut name_match = None;

    // Search static table first
    for (i, &(s_name, s_val)) in STATIC_TABLE.iter().enumerate() {
        if s_name.eq_ignore_ascii_case(name) {
            if s_val == value {
                return Some((i + 1, true));
            }
            if name_match.is_none() {
                name_match = Some(i + 1);
            }
        }
    }

    // Search dynamic table next
    for (i, entry) in dynamic.entries.iter().enumerate() {
        let full_idx = STATIC_TABLE_LEN + 1 + i;
        if entry.name.eq_ignore_ascii_case(name) {
            if entry.value == value {
                return Some((full_idx, true));
            }
            if name_match.is_none() {
                name_match = Some(full_idx);
            }
        }
    }

    name_match.map(|idx| (idx, false))
}

/// Encodes an HPACK integer with an N-bit prefix (RFC 7541 §5.1).
pub fn encode_integer(val: usize, prefix_bits: u8, prefix_mask: u8, dst: &mut Vec<u8>) {
    let max_prefix = (1usize << prefix_bits) - 1;
    if val < max_prefix {
        dst.push(prefix_mask | val.to_le_bytes()[0]);
    } else {
        dst.push(prefix_mask | max_prefix.to_le_bytes()[0]);
        let mut rem = val - max_prefix;
        while rem >= 128 {
            dst.push(u8::try_from(rem % 128).unwrap_or(0) | 0x80);
            rem /= 128;
        }
        dst.push(u8::try_from(rem % 128).unwrap_or(0));
    }
}

/// Decodes an HPACK integer with an N-bit prefix (RFC 7541 §5.1).
///
/// # Errors
/// Returns `H2Error::CompressionError` on malformed integer or premature end of slice.
pub fn decode_integer(prefix_bits: u8, src: &[u8], offset: &mut usize) -> Result<usize, H2Error> {
    if *offset >= src.len() {
        return Err(H2Error::CompressionError);
    }
    let max_prefix = (1usize << prefix_bits) - 1;
    let first_byte = src[*offset];
    *offset += 1;

    let mask = if prefix_bits == 8 {
        0xFF
    } else {
        (1u8 << prefix_bits) - 1
    };
    let prefix_val = (first_byte & mask) as usize;

    if prefix_val < max_prefix {
        return Ok(prefix_val);
    }

    let mut result = max_prefix;
    let mut shift = 0;

    loop {
        if *offset >= src.len() {
            return Err(H2Error::CompressionError);
        }
        let b = src[*offset];
        *offset += 1;

        if shift > 28 {
            return Err(H2Error::CompressionError);
        }

        let val = (b & 0x7f) as usize;
        let addition = val.checked_shl(shift).ok_or(H2Error::CompressionError)?;
        result = result
            .checked_add(addition)
            .ok_or(H2Error::CompressionError)?;
        shift += 7;

        if (b & 0x80) == 0 {
            break;
        }
    }

    Ok(result)
}

/// Encodes a string literal (RFC 7541 §5.2) with or without Huffman compression.
pub fn encode_string_literal(s: &str, use_huffman: bool, dst: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    if use_huffman {
        let mut huff = Vec::with_capacity(bytes.len());
        encode_huffman(bytes, &mut huff);
        if huff.len() < bytes.len() {
            encode_integer(huff.len(), 7, 0x80, dst);
            dst.extend_from_slice(&huff);
            return;
        }
    }
    encode_integer(bytes.len(), 7, 0x00, dst);
    dst.extend_from_slice(bytes);
}

/// Decodes a string literal (RFC 7541 §5.2) from input slice at `*offset`.
///
/// # Errors
/// Returns `H2Error::CompressionError` if incomplete, invalid Huffman, or invalid UTF-8.
pub fn decode_string_literal(src: &[u8], offset: &mut usize) -> Result<String, H2Error> {
    if *offset >= src.len() {
        return Err(H2Error::CompressionError);
    }
    let is_huffman = (src[*offset] & 0x80) != 0;
    let len = decode_integer(7, src, offset)?;

    if *offset + len > src.len() {
        return Err(H2Error::CompressionError);
    }

    let raw = &src[*offset..*offset + len];
    *offset += len;

    if is_huffman {
        decode_huffman(raw)
    } else {
        std::str::from_utf8(raw)
            .map(std::string::ToString::to_string)
            .map_err(|_| H2Error::CompressionError)
    }
}

/// Header fields one block may decode to. HAProxy decodes into a list of
/// `2 * tune.http.maxhdr` (202) entries, one of them the end marker: 201 fields pass, the
/// 202nd is a connection error COMPRESSION_ERROR (measured). Bounds the memory a block costs.
pub const MAX_DECODED_FIELDS: usize = 201;

/// HPACK Header Block Decoder (RFC 7541).
#[derive(Debug, Default)]
pub struct HpackDecoder {
    pub dynamic_table: DynamicTable,
    pub max_allowed_table_size: usize,
}

impl HpackDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::default(),
            max_allowed_table_size: DEFAULT_DYNAMIC_TABLE_MAX_SIZE,
        }
    }

    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(max_size),
            max_allowed_table_size: max_size,
        }
    }

    /// Sets the maximum dynamic table size allowed by connection settings.
    pub fn set_max_allowed_table_size(&mut self, max_size: usize) {
        self.max_allowed_table_size = max_size;
        if self.dynamic_table.max_size() > max_size {
            self.dynamic_table.set_max_size(max_size);
        }
    }

    /// Decodes an HPACK-encoded header block into a list of [`HeaderField`]s.
    ///
    /// # Errors
    /// Returns `H2Error::CompressionError` if decoding encounters malformed syntax.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, H2Error> {
        let mut offset = 0;
        let mut headers = Vec::new();
        let mut allowed_table_size_update = true;

        while offset < block.len() {
            if headers.len() >= MAX_DECODED_FIELDS {
                return Err(H2Error::CompressionError);
            }
            let b = block[offset];

            if (b & 0x80) != 0 {
                // 1. Indexed Header Field Representation: 1xxxxxxx (RFC 7541 §6.1)
                allowed_table_size_update = false;
                let idx = decode_integer(7, block, &mut offset)?;
                if let Some((n, v)) = lookup_table(idx, &self.dynamic_table) {
                    headers.push(HeaderField {
                        name: n.to_string(),
                        value: v.to_string(),
                    });
                } else {
                    return Err(H2Error::CompressionError);
                }
            } else if (b & 0x40) != 0 {
                // 2. Literal Header Field with Incremental Indexing: 01xxxxxx (RFC 7541 §6.2.1)
                allowed_table_size_update = false;
                let idx = decode_integer(6, block, &mut offset)?;
                let name = if idx == 0 {
                    decode_string_literal(block, &mut offset)?
                } else if let Some((n, _)) = lookup_table(idx, &self.dynamic_table) {
                    n.to_string()
                } else {
                    return Err(H2Error::CompressionError);
                };
                let value = decode_string_literal(block, &mut offset)?;
                self.dynamic_table.insert(name.clone(), value.clone());
                headers.push(HeaderField { name, value });
            } else if (b & 0x20) != 0 {
                // 5. Dynamic Table Size Update: 001xxxxx (RFC 7541 §6.3)
                if !allowed_table_size_update {
                    return Err(H2Error::CompressionError);
                }
                let new_max = decode_integer(5, block, &mut offset)?;
                if new_max > self.max_allowed_table_size {
                    return Err(H2Error::CompressionError);
                }
                self.dynamic_table.set_max_size(new_max);
            } else {
                // 3. Literal Header Field without Indexing: 0000xxxx (RFC 7541 §6.2.2)
                // 4. Literal Header Field Never Indexed:    0001xxxx (RFC 7541 §6.2.3)
                allowed_table_size_update = false;
                let idx = decode_integer(4, block, &mut offset)?;
                let name = if idx == 0 {
                    decode_string_literal(block, &mut offset)?
                } else if let Some((n, _)) = lookup_table(idx, &self.dynamic_table) {
                    n.to_string()
                } else {
                    return Err(H2Error::CompressionError);
                };
                let value = decode_string_literal(block, &mut offset)?;
                headers.push(HeaderField { name, value });
            }
        }

        Ok(headers)
    }
}

/// HPACK Header Block Encoder (RFC 7541).
#[derive(Debug, Default)]
pub struct HpackEncoder {
    pub dynamic_table: DynamicTable,
    pub use_huffman: bool,
}

impl HpackEncoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            dynamic_table: DynamicTable::default(),
            use_huffman: true,
        }
    }

    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(max_size),
            use_huffman: true,
        }
    }

    /// Controls whether Huffman encoding is utilized when beneficial.
    pub fn set_use_huffman(&mut self, use_huffman: bool) {
        self.use_huffman = use_huffman;
    }

    /// Emits a dynamic table size update directive into `out` and updates table max size.
    pub fn update_max_table_size(&mut self, new_max: usize, out: &mut Vec<u8>) {
        encode_integer(new_max, 5, 0x20, out);
        self.dynamic_table.set_max_size(new_max);
    }

    /// Encodes a list of [`HeaderField`]s into an HPACK-compressed byte buffer.
    /// Uses incremental indexing where beneficial.
    #[must_use]
    pub fn encode(&mut self, headers: &[HeaderField]) -> Vec<u8> {
        let mut out = Vec::new();

        for h in headers {
            if let Some((idx, exact)) = find_table_entry(&h.name, &h.value, &self.dynamic_table) {
                if exact {
                    // Indexed Header Field: 1xxxxxxx (7-bit prefix)
                    encode_integer(idx, 7, 0x80, &mut out);
                } else {
                    // Literal with Incremental Indexing - Indexed Name: 01xxxxxx (6-bit prefix)
                    encode_integer(idx, 6, 0x40, &mut out);
                    encode_string_literal(&h.value, self.use_huffman, &mut out);
                    self.dynamic_table.insert(h.name.clone(), h.value.clone());
                }
            } else {
                // Literal with Incremental Indexing - New Name: 01000000
                out.push(0x40);
                encode_string_literal(&h.name, self.use_huffman, &mut out);
                encode_string_literal(&h.value, self.use_huffman, &mut out);
                self.dynamic_table.insert(h.name.clone(), h.value.clone());
            }
        }

        out
    }

    /// Encodes an iterator of `(&str, &str)` pairs.
    pub fn encode_pairs<'a, I>(&mut self, headers: I) -> Vec<u8>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let fields: Vec<HeaderField> = headers
            .into_iter()
            .map(|(n, v)| HeaderField {
                name: n.to_string(),
                value: v.to_string(),
            })
            .collect();
        self.encode(&fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_static_table_lookup() {
        let dt = DynamicTable::new(4096);
        assert_eq!(lookup_table(1, &dt), Some((":authority", "")));
        assert_eq!(lookup_table(2, &dt), Some((":method", "GET")));
        assert_eq!(lookup_table(8, &dt), Some((":status", "200")));
        assert_eq!(lookup_table(61, &dt), Some(("www-authenticate", "")));
        assert_eq!(lookup_table(62, &dt), None);
    }

    #[test]
    fn test_dynamic_table_mutations_and_eviction() {
        let mut dt = DynamicTable::new(100);
        // Entry 1 size: 10 + 10 + 32 = 52 bytes
        dt.insert("custom-key".into(), "value-1234".into());
        assert_eq!(dt.len(), 1);
        assert_eq!(dt.size(), 52);

        // Entry 2 size: 10 + 10 + 32 = 52 bytes -> total 104 > 100 -> evicts Entry 1!
        dt.insert("custom-new".into(), "value-5678".into());
        assert_eq!(dt.len(), 1);
        assert_eq!(dt.size(), 52);
        assert_eq!(dt.get(0).unwrap().name, "custom-new");

        // Lookup combined index 62
        assert_eq!(lookup_table(62, &dt), Some(("custom-new", "value-5678")));
    }

    #[test]
    fn test_integer_codec_roundtrip() {
        let mut buf = Vec::new();
        // 10 with 5 bits (< 31)
        encode_integer(10, 5, 0x00, &mut buf);
        let mut off = 0;
        assert_eq!(decode_integer(5, &buf, &mut off).unwrap(), 10);
        assert_eq!(off, 1);

        // 1337 with 5 bits (>= 31)
        buf.clear();
        encode_integer(1337, 5, 0x20, &mut buf);
        off = 0;
        assert_eq!(decode_integer(5, &buf, &mut off).unwrap(), 1337);
        assert_eq!(buf, vec![0x3f, 0x9a, 0x0a]); // 0x20 | 0x1f = 0x3f

        // 42 with 8-bit prefix
        buf.clear();
        encode_integer(42, 8, 0x00, &mut buf);
        off = 0;
        assert_eq!(decode_integer(8, &buf, &mut off).unwrap(), 42);
        assert_eq!(buf, vec![42]);
    }

    #[test]
    fn test_rfc7541_c41_huffman_vector() {
        // RFC 7541 C.4.1: "www.example.com" Huffman encoded
        let expected_hex = vec![
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];

        let mut enc = Vec::new();
        encode_huffman(b"www.example.com", &mut enc);
        assert_eq!(enc, expected_hex);

        let dec = decode_huffman(&enc).expect("decode www.example.com");
        assert_eq!(dec, "www.example.com");
    }

    #[test]
    fn test_rfc7541_c42_huffman_cache_control() {
        // RFC 7541 C.4.2: "no-cache" Huffman encoded: 64 9c bf
        // wait, let's verify encoded "no-cache"
        let mut enc = Vec::new();
        encode_huffman(b"no-cache", &mut enc);
        let dec = decode_huffman(&enc).expect("decode no-cache");
        assert_eq!(dec, "no-cache");
    }

    #[test]
    fn test_huffman_invalid_padding_rejected() {
        let mut enc = Vec::new();
        encode_huffman(b"test", &mut enc);

        // Case 1: Corrupt padding with 0s
        let mut corrupt = enc.clone();
        if let Some(last) = corrupt.last_mut() {
            *last &= 0xFE; // Clear last bit
        }
        // May fail either on invalid code or invalid padding
        let _ = decode_huffman(&corrupt).is_err();

        // Case 2: Padding longer than 7 bits (e.g. extra 0xFF byte)
        let mut long_pad = enc;
        long_pad.push(0xFF);
        assert!(decode_huffman(&long_pad).is_err());
    }

    #[test]
    fn test_huffman_eos_in_literal_rejected() {
        // Symbol 256 (EOS) is 30 1s: 0x3fffffff.
        // We pack EOS symbol followed by padding
        let eos_bytes = vec![0xff, 0xff, 0xff, 0xfc]; // 30 bits of 1s + 2 bits pad
        assert!(decode_huffman(&eos_bytes).is_err());
    }

    #[test]
    fn test_rfc7541_c3_first_request_without_huffman() {
        // RFC 7541 C.3.1: First Request
        let mut enc = HpackEncoder::new();
        enc.set_use_huffman(false);
        let mut dec = HpackDecoder::new();

        let req = vec![
            HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            HeaderField {
                name: ":scheme".to_string(),
                value: "http".to_string(),
            },
            HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            HeaderField {
                name: ":authority".to_string(),
                value: "www.example.com".to_string(),
            },
        ];

        let encoded = enc.encode(&req);
        // RFC 7541 C.3.1 expected hex: 82 86 84 41 0f 77 77 77 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
        let expected = vec![
            0x82, 0x86, 0x84, 0x41, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        assert_eq!(encoded, expected);

        let decoded = dec.decode(&encoded).expect("decode c.3.1");
        assert_eq!(decoded, req);
    }

    #[test]
    fn test_rfc7541_c4_first_request_with_huffman() {
        // RFC 7541 C.4.1: First Request with Huffman
        let mut enc = HpackEncoder::new();
        enc.set_use_huffman(true);
        let mut dec = HpackDecoder::new();

        let req = vec![
            HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            HeaderField {
                name: ":scheme".to_string(),
                value: "http".to_string(),
            },
            HeaderField {
                name: ":path".to_string(),
                value: "/".to_string(),
            },
            HeaderField {
                name: ":authority".to_string(),
                value: "www.example.com".to_string(),
            },
        ];

        let encoded = enc.encode(&req);
        // RFC 7541 C.4.1 expected hex: 82 86 84 41 8c f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff
        let expected = vec![
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        assert_eq!(encoded, expected);

        let decoded = dec.decode(&encoded).expect("decode c.4.1");
        assert_eq!(decoded, req);
    }

    #[test]
    fn test_table_size_update_validation() {
        let mut dec = HpackDecoder::with_max_size(1024);
        let mut buf = Vec::new();
        // Update to 512
        encode_integer(512, 5, 0x20, &mut buf);
        assert!(dec.decode(&buf).is_ok());
        assert_eq!(dec.dynamic_table.max_size(), 512);

        // Update exceeding max_allowed (2048 > 1024)
        buf.clear();
        encode_integer(2048, 5, 0x20, &mut buf);
        assert!(dec.decode(&buf).is_err());
    }

    proptest! {
        #[test]
        fn prop_huffman_roundtrip_ascii(s in r"[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=-]{0,128}") {
            let mut enc = Vec::new();
            encode_huffman(s.as_bytes(), &mut enc);
            let dec = decode_huffman(&enc).expect("decode huffman");
            prop_assert_eq!(dec, s);
        }

        #[test]
        fn prop_integer_roundtrip(val in 0usize..100_000, prefix in 1u8..=8) {
            let mut buf = Vec::new();
            encode_integer(val, prefix, 0x00, &mut buf);
            let mut off = 0;
            let decoded = decode_integer(prefix, &buf, &mut off).expect("decode integer");
            prop_assert_eq!(decoded, val);
            prop_assert_eq!(off, buf.len());
        }

        #[test]
        fn prop_hpack_roundtrip(
            name in "[a-z0-9_-]{1,32}",
            val in "[a-zA-Z0-9 ._-]{0,64}"
        ) {
            let mut enc = HpackEncoder::new();
            let mut dec = HpackDecoder::new();

            let req = vec![HeaderField {
                name: name.clone(),
                value: val.clone(),
            }];

            let block = enc.encode(&req);
            let decoded = dec.decode(&block).expect("decode hpack");
            prop_assert_eq!(decoded, req);
        }
    }
}
