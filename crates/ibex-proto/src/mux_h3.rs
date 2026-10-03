// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/3 connection state, sitting between the QUIC transport and HTX.
//!
//! `h3.rs` parses frames and `qpack.rs` decodes header blocks; neither knows about
//! connections, and nothing drove them. This is the piece that was missing: it tracks the
//! unidirectional streams HTTP/3 requires, answers a request stream, and encodes the
//! response.
//!
//! ### Scope
//!
//! QPACK is **static-table only**, in both directions. The connection advertises
//! `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, which
//! RFC 9204 permits and which obliges a compliant encoder — nghttp3 included — to use only
//! the 99-entry static table and literals. That removes the encoder/decoder stream state
//! machine entirely. The two streams still have to be *tolerated*, because the client opens
//! them regardless, so they are read and discarded.

use crate::h3::{parse_varint, H3Error};
use crate::qpack::STATIC_TABLE;

/// Stream type prefixes for unidirectional streams, RFC 9114 §6.2.
pub const STREAM_TYPE_CONTROL: u64 = 0x00;
pub const STREAM_TYPE_PUSH: u64 = 0x01;
pub const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
pub const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// Frame types we emit. RFC 9114 §7.2.
const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;

/// Settings identifiers, RFC 9114 §7.2.4.1 and RFC 9204 §5.
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;

/// Appends a QUIC variable-length integer (RFC 9000 §16).
///
/// The top two bits of the first byte select the width, so the usable range shrinks as the
/// value grows: 6 bits in one byte, 14 in two, 30 in four, 62 in eight.
pub fn encode_varint(out: &mut Vec<u8>, v: u64) {
    if v < 64 {
        out.push(v as u8);
    } else if v < 16_384 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1_073_741_824 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Appends a frame: type, length, payload.
pub fn encode_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    encode_varint(out, frame_type);
    encode_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// The SETTINGS frame this endpoint sends on its control stream.
///
/// Capacity and blocked-streams are zero on purpose: that is what makes the static-only
/// QPACK decoder legal rather than a shortcut.
#[must_use]
pub fn encode_settings() -> Vec<u8> {
    let mut payload = Vec::new();
    encode_varint(&mut payload, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    encode_varint(&mut payload, 0);
    encode_varint(&mut payload, SETTINGS_QPACK_BLOCKED_STREAMS);
    encode_varint(&mut payload, 0);
    encode_varint(&mut payload, SETTINGS_MAX_FIELD_SECTION_SIZE);
    encode_varint(&mut payload, 65_536);

    let mut frame = Vec::new();
    encode_frame(&mut frame, FRAME_SETTINGS, &payload);
    frame
}

/// The bytes that open our control stream: the stream type, then SETTINGS.
#[must_use]
pub fn encode_control_stream_open() -> Vec<u8> {
    let mut out = Vec::new();
    encode_varint(&mut out, STREAM_TYPE_CONTROL);
    out.extend_from_slice(&encode_settings());
    out
}

/// Finds a static-table entry matching both name and value.
fn static_index_of(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == value)
}

/// Finds the first static-table entry with this name, whatever its value.
fn static_index_of_name(name: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|(n, _)| *n == name)
}

/// Appends a prefixed integer (RFC 7541 §5.1, which QPACK reuses).
fn encode_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, mask: u8, mut value: usize) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(mask | (value as u8));
        return;
    }
    out.push(mask | (max as u8));
    value -= max;
    while value >= 128 {
        out.push(((value % 128) + 128) as u8);
        value /= 128;
    }
    out.push(value as u8);
}

/// Appends a string literal without Huffman coding.
///
/// Huffman would be smaller; leaving it off keeps the encoder to one page and makes the
/// bytes readable in a capture, which matters more while this path is being brought up.
fn encode_string(out: &mut Vec<u8>, s: &str, prefix_bits: u8, mask: u8) {
    encode_prefixed_int(out, prefix_bits, mask, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// Encodes a header list as a QPACK field section using only the static table and literals.
///
/// The field section prefix is `Required Insert Count = 0, Delta Base = 0`, which says the
/// section references no dynamic entries and can therefore be decoded immediately.
#[must_use]
pub fn encode_field_section(headers: &[(String, String)]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00];

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if let Some(idx) = static_index_of(&lower, value) {
            // Indexed field line, static table: 1 1 index(6+)
            encode_prefixed_int(&mut out, 6, 0xc0, idx);
        } else if let Some(idx) = static_index_of_name(&lower) {
            // Literal with name reference, static table: 0 1 N=0 index(4+)
            encode_prefixed_int(&mut out, 4, 0x50, idx);
            encode_string(&mut out, value, 7, 0x00);
        } else {
            // Literal with literal name: 0 0 1 N=0 H=0 len(3+)
            encode_string(&mut out, &lower, 3, 0x20);
            encode_string(&mut out, value, 7, 0x00);
        }
    }
    out
}

/// Encodes a complete HTTP/3 response: a HEADERS frame, then DATA if there is a body.
#[must_use]
pub fn encode_response(status: u16, extra_headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut headers = vec![(":status".to_string(), status.to_string())];
    headers.extend_from_slice(extra_headers);

    let field_section = encode_field_section(&headers);
    let mut out = Vec::new();
    encode_frame(&mut out, FRAME_HEADERS, &field_section);
    if !body.is_empty() {
        encode_frame(&mut out, FRAME_DATA, body);
    }
    out
}

/// What a unidirectional stream turned out to be, once its type prefix arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniStreamKind {
    Control,
    QpackEncoder,
    QpackDecoder,
    Push,
    /// An unknown type. RFC 9114 §6.2 requires these be tolerated, not treated as errors.
    Unknown(u64),
}

/// Reads the stream-type prefix from a unidirectional stream.
///
/// Returns the kind and how many bytes it consumed, or `None` if the prefix has not fully
/// arrived yet — a varint can be split across datagrams like anything else.
#[must_use]
pub fn read_uni_stream_type(buf: &[u8]) -> Option<(UniStreamKind, usize)> {
    let mut offset = 0usize;
    let ty = parse_varint(buf, &mut offset).ok()?;
    let kind = match ty {
        STREAM_TYPE_CONTROL => UniStreamKind::Control,
        STREAM_TYPE_PUSH => UniStreamKind::Push,
        STREAM_TYPE_QPACK_ENCODER => UniStreamKind::QpackEncoder,
        STREAM_TYPE_QPACK_DECODER => UniStreamKind::QpackDecoder,
        other => UniStreamKind::Unknown(other),
    };
    Some((kind, offset))
}

/// Extracts the HEADERS field section from a request stream's buffered bytes.
///
/// Returns `Ok(None)` when the frame has not fully arrived, which is the common case on the
/// first readable event. Unknown frame types are skipped rather than rejected, because that
/// is the extension mechanism and clients do send grease.
///
/// # Errors
/// Returns an error if a frame header is malformed.
pub fn take_request_headers(buf: &[u8]) -> Result<Option<Vec<u8>>, H3Error> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let start = offset;
        let Ok(frame_type) = parse_varint(buf, &mut offset) else {
            return Ok(None);
        };
        let Ok(len) = parse_varint(buf, &mut offset) else {
            // The length varint has not fully arrived. `start` is kept for readability at
            // the call site; nothing resumes from it, because the caller re-scans from zero
            // once more bytes land.
            let _ = start;
            return Ok(None);
        };
        let len = usize::try_from(len).map_err(|_| H3Error::FrameError)?;
        if offset + len > buf.len() {
            return Ok(None);
        }
        let payload = &buf[offset..offset + len];
        offset += len;
        if frame_type == FRAME_HEADERS {
            return Ok(Some(payload.to_vec()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_at_every_width() {
        for v in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut buf = Vec::new();
            encode_varint(&mut buf, v);
            let mut off = 0;
            assert_eq!(parse_varint(&buf, &mut off).unwrap(), v, "value {v}");
            assert_eq!(off, buf.len(), "consumed the whole encoding for {v}");
        }
    }

    #[test]
    fn status_200_uses_the_static_table() {
        // RFC 9204 static index 25 is (":status", "200"). An indexed static field line is
        // 0b11 followed by the index in 6 bits, so 0xc0 | 25 = 0xd9.
        let out = encode_field_section(&[(":status".into(), "200".into())]);
        assert_eq!(out, vec![0x00, 0x00, 0xd9]);
    }

    #[test]
    fn a_header_not_in_the_static_table_becomes_a_literal() {
        let out = encode_field_section(&[("x-ibex".into(), "1".into())]);
        assert_eq!(&out[..2], &[0x00, 0x00], "field section prefix");
        assert!(out.len() > 3, "a literal name and value follow");
    }

    #[test]
    fn settings_advertises_zero_capacity_and_zero_blocked_streams() {
        let s = encode_settings();
        let mut off = 0;
        assert_eq!(parse_varint(&s, &mut off).unwrap(), FRAME_SETTINGS);
        let len = parse_varint(&s, &mut off).unwrap() as usize;
        let payload = &s[off..off + len];
        let mut p = 0;
        assert_eq!(parse_varint(payload, &mut p).unwrap(), SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        assert_eq!(parse_varint(payload, &mut p).unwrap(), 0, "capacity must be 0");
        assert_eq!(parse_varint(payload, &mut p).unwrap(), SETTINGS_QPACK_BLOCKED_STREAMS);
        assert_eq!(parse_varint(payload, &mut p).unwrap(), 0, "blocked streams must be 0");
    }

    #[test]
    fn uni_stream_types_are_recognised_and_unknown_ones_tolerated() {
        assert_eq!(read_uni_stream_type(&[0x00]).unwrap().0, UniStreamKind::Control);
        assert_eq!(read_uni_stream_type(&[0x02]).unwrap().0, UniStreamKind::QpackEncoder);
        assert_eq!(read_uni_stream_type(&[0x03]).unwrap().0, UniStreamKind::QpackDecoder);
        assert!(matches!(
            read_uni_stream_type(&[0x21]).unwrap().0,
            UniStreamKind::Unknown(_)
        ));
        assert!(read_uni_stream_type(&[]).is_none(), "an empty prefix is not yet readable");
    }

    #[test]
    fn take_request_headers_skips_unknown_frames_and_waits_for_a_partial_one() {
        let mut buf = Vec::new();
        encode_frame(&mut buf, 0x21, b"grease");
        encode_frame(&mut buf, FRAME_HEADERS, &[0x00, 0x00, 0xd9]);
        assert_eq!(
            take_request_headers(&buf).unwrap(),
            Some(vec![0x00, 0x00, 0xd9]),
            "a grease frame before HEADERS must be skipped"
        );

        let partial = &buf[..buf.len() - 1];
        assert_eq!(
            take_request_headers(partial).unwrap(),
            None,
            "an incomplete frame is not an error"
        );
    }

    #[test]
    fn a_response_is_headers_then_data() {
        let out = encode_response(200, &[], b"hi");
        let mut off = 0;
        assert_eq!(parse_varint(&out, &mut off).unwrap(), FRAME_HEADERS);
        let hlen = parse_varint(&out, &mut off).unwrap() as usize;
        off += hlen;
        assert_eq!(parse_varint(&out, &mut off).unwrap(), FRAME_DATA);
        let dlen = parse_varint(&out, &mut off).unwrap() as usize;
        assert_eq!(&out[off..off + dlen], b"hi");
    }
}
