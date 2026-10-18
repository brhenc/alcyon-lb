// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use crate::h3::H3Error;
use crate::hpack::{decode_huffman, decode_integer};
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

pub fn decode_qpack_static(block: &[u8]) -> Result<Vec<HeaderField>, H3Error> {
    if block.is_empty() {
        return Ok(Vec::new());
    }

    let mut offset = 0;
    
    // Parse Required Insert Count (8+)
    let ric = decode_integer(8, block, &mut offset).map_err(|_| H3Error::QpackDecompressionFailed)?;
    if ric != 0 {
        return Err(H3Error::QpackDecompressionFailed); // non-zero is a connection error
    }
    
    // Parse Base (7+)
    let _delta_base = decode_integer(7, block, &mut offset).map_err(|_| H3Error::QpackDecompressionFailed)?;
    
    let mut headers = Vec::new();

    while offset < block.len() {
        // T358 #5: at most 201 field lines, as HAProxy's decoder (src/qpack-dec.c:316-320: a list of
        // `tune.max_http_hdr * 2` = 202 entries, the last one kept for the end marker) and Ibex's HPACK.
        if headers.len() >= crate::hpack::MAX_DECODED_FIELDS {
            return Err(H3Error::QpackDecompressionFailed);
        }
        let b = block[offset];
        if (b & 0xc0) == 0xc0 {
            // Indexed Field Line (Static)
            let idx = decode_integer(6, block, &mut offset).map_err(|_| H3Error::QpackDecompressionFailed)?;
            if idx >= STATIC_TABLE.len() {
                return Err(H3Error::QpackDecompressionFailed);
            }
            let (name, value) = STATIC_TABLE[idx];
            headers.push(HeaderField {
                name: name.to_string(),
                value: value.to_string(),
            });
        } else if (b & 0xc0) == 0x80 {
            // Indexed Field Line (Dynamic)
            return Err(H3Error::QpackDecompressionFailed);
        } else if (b & 0xf0) == 0x50 {
            // Literal Field Line with Name Reference (Static)
            let idx = decode_integer(4, block, &mut offset).map_err(|_| H3Error::QpackDecompressionFailed)?;
            if idx >= STATIC_TABLE.len() {
                return Err(H3Error::QpackDecompressionFailed);
            }
            let name = STATIC_TABLE[idx].0.to_string();
            let value = decode_qpack_string(block, &mut offset)?;
            headers.push(HeaderField { name, value });
        } else if (b & 0xf0) == 0x40 {
            // Literal Field Line with Name Reference (Dynamic)
            return Err(H3Error::QpackDecompressionFailed);
        } else if (b & 0xf0) == 0x70 {
            // Literal Field Line with Name Reference (Static, N=1)
            let idx = decode_integer(4, block, &mut offset).map_err(|_| H3Error::QpackDecompressionFailed)?;
            if idx >= STATIC_TABLE.len() {
                return Err(H3Error::QpackDecompressionFailed);
            }
            let name = STATIC_TABLE[idx].0.to_string();
            let value = decode_qpack_string(block, &mut offset)?;
            headers.push(HeaderField { name, value });
        } else if (b & 0xf0) == 0x60 {
            // Literal Field Line with Name Reference (Dynamic, N=1)
            return Err(H3Error::QpackDecompressionFailed);
        } else if (b & 0xe0) == 0x20 {
            // Literal Field Line without Name Reference
            let name = decode_qpack_string_3bit(block, &mut offset)?;
            let value = decode_qpack_string(block, &mut offset)?;
            headers.push(HeaderField { name, value });
        } else {
            // Post-Base dynamic references
            return Err(H3Error::QpackDecompressionFailed);
        }
    }
    
    Ok(headers)
}

fn decode_qpack_string(block: &[u8], offset: &mut usize) -> Result<String, H3Error> {
    if *offset >= block.len() { return Err(H3Error::QpackDecompressionFailed); }
    let is_huffman = (block[*offset] & 0x80) != 0;
    let len = decode_integer(7, block, offset).map_err(|_| H3Error::QpackDecompressionFailed)?;
    if *offset + len > block.len() { return Err(H3Error::QpackDecompressionFailed); }
    let raw = &block[*offset..*offset + len];
    *offset += len;
    
    if is_huffman {
        decode_huffman(raw).map_err(|_| H3Error::QpackDecompressionFailed)
    } else {
        std::str::from_utf8(raw).map(std::string::ToString::to_string).map_err(|_| H3Error::QpackDecompressionFailed)
    }
}

fn decode_qpack_string_3bit(block: &[u8], offset: &mut usize) -> Result<String, H3Error> {
    if *offset >= block.len() { return Err(H3Error::QpackDecompressionFailed); }
    let is_huffman = (block[*offset] & 0x08) != 0;
    let len = decode_integer(3, block, offset).map_err(|_| H3Error::QpackDecompressionFailed)?;
    if *offset + len > block.len() { return Err(H3Error::QpackDecompressionFailed); }
    let raw = &block[*offset..*offset + len];
    *offset += len;
    
    if is_huffman {
        decode_huffman(raw).map_err(|_| H3Error::QpackDecompressionFailed)
    } else {
        std::str::from_utf8(raw).map(std::string::ToString::to_string).map_err(|_| H3Error::QpackDecompressionFailed)
    }
}
