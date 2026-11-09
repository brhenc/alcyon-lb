// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use crate::h3::H3Error;
use crate::hpack::{decode_huffman_into, decode_integer, DecodedFields};
use crate::htx::HeaderField;

pub const STATIC_TABLE: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Decodes a field section with the static table and literals only (Alcyon advertises a
/// dynamic table capacity of 0, as `HAProxy` does), into fields it allocates.
///
/// # Errors
/// [`H3Error::QpackDecompressionFailed`] as [`decode_qpack_static_into`].
pub fn decode_qpack_static(block: &[u8]) -> Result<Vec<HeaderField>, H3Error> {
    let mut out = DecodedFields::default();
    decode_qpack_static_into(block, &mut out)?;
    Ok(out.to_fields())
}

/// Decodes a field section into `out` (memory the caller keeps from one section to the
/// next, T437; cleared first): static references and literals only. A Required Insert Count
/// that is not 0, any dynamic or post-base reference, a static index past the table, a
/// truncated or bad Huffman string, or more than [`crate::hpack::MAX_DECODED_FIELDS`] fields
/// is `QPACK_DECOMPRESSION_FAILED`, as `HAProxy`'s `qpack_decode_fs` (`qpack-dec.c:302-466`).
/// The strings are kept as the octets they stand for (E1): the field checks read bytes, a
/// name that is not a token (one with a byte that is not UTF-8, T454) is a message error on
/// its stream, not a connection error.
///
/// # Errors
/// [`H3Error::QpackDecompressionFailed`].
pub fn decode_qpack_static_into(block: &[u8], out: &mut DecodedFields) -> Result<(), H3Error> {
    const FAIL: H3Error = H3Error::QpackDecompressionFailed;
    out.clear();
    if block.is_empty() {
        return Ok(());
    }
    let mut offset = 0;
    // Required Insert Count (8+): not 0 is a connection error (RFC 9204 section 2.2.3).
    if decode_integer(8, block, &mut offset).map_err(|_| FAIL)? != 0 {
        return Err(FAIL);
    }
    // Delta Base (7+), of no use without a dynamic table.
    decode_integer(7, block, &mut offset).map_err(|_| FAIL)?;
    let mut count = 0usize;
    while offset < block.len() {
        // T358 #5: at most 201 field lines, as HAProxy's decoder (src/qpack-dec.c:316-320: a
        // list of `tune.max_http_hdr * 2` = 202 entries, the last one kept for the end marker)
        // and Alcyon's HPACK.
        if count >= crate::hpack::MAX_DECODED_FIELDS {
            return Err(FAIL);
        }
        count += 1;
        let b = block[offset];
        let (start, text, huff) = out.begin_field();
        let mid = if (b & 0xc0) == 0xc0 {
            // Indexed Field Line, static (1 T=1 index(6+)).
            let (name, value) = static_entry(decode_integer(6, block, &mut offset).map_err(|_| FAIL)?)?;
            text.extend_from_slice(name.as_bytes());
            let mid = pos(text);
            text.extend_from_slice(value.as_bytes());
            mid
        } else if (b & 0xd0) == 0x50 {
            // Literal Field Line with Name Reference, static (0 1 N T=1 index(4+)), N either way.
            let (name, _) = static_entry(decode_integer(4, block, &mut offset).map_err(|_| FAIL)?)?;
            text.extend_from_slice(name.as_bytes());
            let mid = pos(text);
            push_string(block, &mut offset, 7, text, huff)?;
            mid
        } else if (b & 0xe0) == 0x20 {
            // Literal Field Line with Literal Name (0 0 1 N H len(3+)).
            push_string(block, &mut offset, 3, text, huff)?;
            let mid = pos(text);
            push_string(block, &mut offset, 7, text, huff)?;
            mid
        } else {
            // Dynamic references (indexed, name reference with T=0) and post-base ones.
            return Err(FAIL);
        };
        out.end_field(start, mid);
    }
    Ok(())
}

fn pos(text: &[u8]) -> u32 {
    u32::try_from(text.len()).unwrap_or(u32::MAX)
}

/// The static table's entry `idx`.
fn static_entry(idx: usize) -> Result<(&'static str, &'static str), H3Error> {
    STATIC_TABLE.get(idx).copied().ok_or(H3Error::QpackDecompressionFailed)
}

/// Appends the string literal at `*offset` (its length an integer of `prefix` bits, the bit
/// above them the Huffman flag, RFC 9204 section 4.1.2) to `text`, as octets.
fn push_string(block: &[u8], offset: &mut usize, prefix: u8, text: &mut Vec<u8>, huff: &mut Vec<u8>) -> Result<(), H3Error> {
    const FAIL: H3Error = H3Error::QpackDecompressionFailed;
    let first = *block.get(*offset).ok_or(FAIL)?;
    let is_huffman = first & (1 << prefix) != 0;
    let len = decode_integer(prefix, block, offset).map_err(|_| FAIL)?;
    let raw = block.get(*offset..offset.saturating_add(len)).ok_or(FAIL)?;
    *offset += len;
    if is_huffman {
        huff.clear();
        decode_huffman_into(raw, huff).map_err(|_| FAIL)?;
        text.extend_from_slice(huff);
    } else {
        text.extend_from_slice(raw);
    }
    Ok(())
}

/// A QPACK prefixed integer at the start of `buf` (RFC 9204 section 4.1.1): its value and
/// its length, `Ok(None)` when it has not fully arrived.
///
/// # Errors
/// An integer past 62 bits.
fn prefixed_int(buf: &[u8], prefix: u8) -> Result<Option<(u64, usize)>, ()> {
    let Some(&first) = buf.first() else { return Ok(None) };
    let max = (1u64 << prefix) - 1;
    let v = u64::from(first) & max;
    if v < max {
        return Ok(Some((v, 1)));
    }
    let mut v = max;
    for (i, &b) in buf[1..].iter().enumerate() {
        // Nine continuation bytes carry 63 bits: the most a 62-bit value needs.
        if i >= 9 {
            return Err(());
        }
        v += u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(Some((v, i + 2)));
        }
    }
    Ok(None)
}

/// What the client's encoder stream may carry to a decoder whose dynamic table capacity is
/// 0 (RFC 9204 section 4.3): `Set Dynamic Table Capacity` to 0, nothing else. Consumes the
/// complete instructions at the start of `buf` and returns how many bytes they took.
///
/// # Errors
/// `QPACK_ENCODER_STREAM_ERROR` for a capacity that is not 0 or any insertion or duplicate,
/// as `HAProxy`'s `qpack_decode_enc` (`qpack-dec.c:155-177`; measured on 3.5-dev7: capacity 5
/// and an insertion with a literal name both close the connection with 0x201).
pub fn decode_encoder_stream(buf: &[u8]) -> Result<usize, H3Error> {
    let mut used = 0;
    while used < buf.len() {
        if buf[used] & 0xe0 != 0x20 {
            return Err(H3Error::QpackEncoderStreamError);
        }
        match prefixed_int(&buf[used..], 5) {
            Ok(Some((0, n))) => used += n,
            Ok(None) => break,
            Ok(Some(_)) | Err(()) => return Err(H3Error::QpackEncoderStreamError),
        }
    }
    Ok(used)
}

/// What the client's decoder stream may carry to an encoder that never inserts (RFC 9204
/// section 4.4): `Section Acknowledgment` and `Stream Cancellation`, skipped as `HAProxy`'s
/// `qpack_decode_dec` skips them (measured: the connection goes on). Returns the bytes the
/// complete instructions at the start of `buf` took.
///
/// # Errors
/// `QPACK_DECODER_STREAM_ERROR` for an `Insert Count Increment` (measured on 3.5-dev7: 0x202)
/// or an integer past 62 bits.
pub fn decode_decoder_stream(buf: &[u8]) -> Result<usize, H3Error> {
    let mut used = 0;
    while used < buf.len() {
        let b = buf[used];
        let prefix = if b & 0x80 != 0 {
            7
        } else if b & 0x40 != 0 {
            6
        } else {
            return Err(H3Error::QpackDecoderStreamError);
        };
        match prefixed_int(&buf[used..], prefix) {
            Ok(Some((_, n))) => used += n,
            Ok(None) => break,
            Err(()) => return Err(H3Error::QpackDecoderStreamError),
        }
    }
    Ok(used)
}

/// How the static encoder writes one field: the static entry matching both name and value,
/// the first entry with the name, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticRef {
    Full(usize),
    Name(usize),
    None,
}

/// The static table's (name, value) and name references, sorted for a binary search: built
/// by the compiler, so a response head costs one search per field and no allocation.
const SORTED: [(&str, &str, u8); 99] = sorted_table();

const fn str_cmp(a: &str, b: &str) -> i32 {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut i = 0;
    while i < a.len() && i < b.len() {
        if a[i] != b[i] {
            return a[i] as i32 - b[i] as i32;
        }
        i += 1;
    }
    a.len() as i32 - b.len() as i32
}

const fn entry_cmp(a: (&str, &str, u8), b: (&str, &str, u8)) -> i32 {
    let c = str_cmp(a.0, b.0);
    if c != 0 {
        return c;
    }
    let c = str_cmp(a.1, b.1);
    if c != 0 {
        return c;
    }
    a.2 as i32 - b.2 as i32
}

const fn sorted_table() -> [(&'static str, &'static str, u8); 99] {
    let mut t = [("", "", 0u8); 99];
    let mut i = 0;
    while i < 99 {
        t[i] = (STATIC_TABLE[i].0, STATIC_TABLE[i].1, i as u8);
        i += 1;
    }
    // Insertion sort, at compile time.
    let mut i = 1;
    while i < 99 {
        let mut j = i;
        while j > 0 && entry_cmp(t[j - 1], t[j]) > 0 {
            let tmp = t[j - 1];
            t[j - 1] = t[j];
            t[j] = tmp;
            j -= 1;
        }
        i += 1;
    }
    t
}

/// The static reference for `name` (lowercase) and `value`: the lowest index matching both,
/// else the lowest matching the name (what a linear scan of the table finds).
#[must_use]
pub fn static_ref(name: &str, value: &str) -> StaticRef {
    static_ref_octets(name, value.as_bytes())
}

/// [`static_ref`] of a value that is octets (a response field as the server sent it, E2).
#[must_use]
pub fn static_ref_octets(name: &str, value: &[u8]) -> StaticRef {
    static_ref_bytes(name.as_bytes(), value)
}

/// [`static_ref_octets`] of a name that is bytes (a token: what a response head holds, T581).
#[must_use]
pub fn static_ref_bytes(name: &[u8], value: &[u8]) -> StaticRef {
    // `SORTED` is in (name, value, index) order, and `str`'s `Ord` is the byte order
    // `str_cmp` sorted it by: one binary search on the name (memcmp, not the const byte
    // loop), then a walk of that name's few entries. The first with the value is the lowest
    // index of the pair; the lowest index of the run is the name-only reference (T539:
    // two searches of `str_cmp` were ~1.7 % of an HTTP/3 request).
    let first = SORTED.partition_point(|&(n, _, _)| n.as_bytes() < name);
    let mut lowest = None;
    for &(n, v, i) in &SORTED[first..] {
        if n.as_bytes() != name {
            break;
        }
        if v.as_bytes() == value {
            return StaticRef::Full(usize::from(i));
        }
        lowest = Some(lowest.map_or(i, |l: u8| l.min(i)));
    }
    lowest.map_or(StaticRef::None, |i| StaticRef::Name(usize::from(i)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sorted_table_is_the_static_table_in_order() {
        // `SORTED` is built by the compiler; built again here, at run time, it must be the
        // same, every entry once, in (name, value, index) order.
        let t = sorted_table();
        assert_eq!(t, SORTED);
        assert!(t.windows(2).all(|w| entry_cmp(w[0], w[1]) < 0));
        let mut idx: Vec<u8> = t.iter().map(|e| e.2).collect();
        idx.sort_unstable();
        assert_eq!(idx, (0..99).collect::<Vec<u8>>());
        assert_eq!(entry_cmp(t[3], t[3]), 0);
    }
}
