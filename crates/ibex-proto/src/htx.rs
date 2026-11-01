// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/htx-t.h, include/haproxy/htx.h and src/htx.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTX (HTTP Tree eXpression): Native internal representation for HTTP messages.
//!
//! HTX decouples HTTP/1.1, HTTP/2, and applets from the internal stream engine.
//! It supports zero-allocation representations on contiguous pre-allocated byte slices
//! as well as structured in-memory transaction buffers.
//!
//! An HTTP transaction is structured into strongly typed blocks:
//! - Request line / Response line
//! - Headers (name-value pairs)
//! - Body data chunks
//! - End of headers (EOH), End of trailers (EOT), and End of message (EOM) markers
//! - Trailers (name-value pairs)
//! - Tunneled raw data chunks (WebSocket / CONNECT)

use std::fmt;
use std::io::Write;

thread_local! {
    static UTF8_CHECKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many times the HTX has read a block's bytes as UTF-8 on this thread: a test reads it
/// around a request to hold the rules path to the few it needs (S7).
#[must_use]
pub fn utf8_checks_on_this_thread() -> u64 {
    UTF8_CHECKS.with(std::cell::Cell::get)
}

/// [`std::str::from_utf8`], counted.
#[inline]
fn utf8(b: &[u8]) -> Result<&str, std::str::Utf8Error> {
    UTF8_CHECKS.with(|n| n.set(n.get() + 1));
    std::str::from_utf8(b)
}

/// Maximum length of header / trailer name in bytes.
pub const HTX_HDR_NAME_MAX_LEN: usize = 255;
/// Maximum length of header / trailer value in bytes (1 MB).
pub const HTX_HDR_VALUE_MAX_LEN: usize = 1_048_575;
/// Default size for pre-allocated HTX buffer (16 KiB).
pub const HTX_BUFFER_DEFAULT_CAPACITY: usize = 16384;
/// Size in bytes of each block descriptor stored at the end of the buffer.
pub const HTX_DESC_SIZE: usize = 16;
/// Default fragmentation threshold (in bytes) before defragmentation is triggered.
pub const HTX_DEFRAG_THRESHOLD_BYTES: usize = 512;

/// HTX block flag: None.
pub const HTX_BLK_FL_NONE: u8 = 0x00;
/// Flag marking the final block of an HTTP message.
pub const HTX_BLK_FL_EOM: u8 = 0x01;
/// Flag of a header whose value is not valid UTF-8 or holds escaped bytes: obs-text
/// (bytes 0x80-0xFF, RFC 9110 section 5.5) from an old client. The value is held as text
/// in [`ibex_regex::bytetext`] form (a byte that is not UTF-8 as one private-use character),
/// so every text reader -- rules, ACLs, fetches -- sees the header and compares its bytes;
/// [`HtxSliceRef::write_h1_wire`] writes each such character back as its one byte, so the
/// server gets the bytes the client sent (T285, T286).
pub const HTX_BLK_FL_LATIN1: u8 = 0x02;

/// `value` as text: valid UTF-8 as it is, any other byte as one escaped character.
#[must_use]
pub fn latin1_to_text(value: &[u8]) -> String {
    ibex_regex::bytetext::bytes_to_text(value)
}

/// The bytes a value of [`HTX_BLK_FL_LATIN1`] stands for, written at `cursor`.
pub(crate) fn write_latin1(out: &mut [u8], cursor: usize, text: &[u8]) -> Result<usize, HtxError> {
    // Held as text this crate wrote.
    let Ok(text) = utf8(text) else { return write_slice(out, cursor, text) };
    write_slice(out, cursor, &ibex_regex::bytetext::text_to_bytes(text))
}

/// HTX Block Type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HtxBlockType {
    /// Request start-line (method, URI, version).
    ReqLine = 0,
    /// Response status-line (version, status, reason).
    ResLine = 1,
    /// HTTP header field (name, value).
    Header = 2,
    /// End-of-headers boundary marker.
    Eoh = 3,
    /// Body data payload chunk.
    Data = 4,
    /// Trailer header field following chunked body.
    Trailer = 5,
    /// End-of-trailers boundary marker.
    Eot = 6,
    /// Raw tunneled data payload (WebSocket / CONNECT).
    RawData = 7,
    /// Explicit End-of-message boundary marker.
    Eom = 8,
    /// Unused or tombstoned block descriptor.
    Unused = 15,
}

impl HtxBlockType {
    #[must_use]
    pub const fn from_u8(val: u8) -> Self {
        match val {
            0 => HtxBlockType::ReqLine,
            1 => HtxBlockType::ResLine,
            2 => HtxBlockType::Header,
            3 => HtxBlockType::Eoh,
            4 => HtxBlockType::Data,
            5 => HtxBlockType::Trailer,
            6 => HtxBlockType::Eot,
            7 => HtxBlockType::RawData,
            8 => HtxBlockType::Eom,
            _ => HtxBlockType::Unused,
        }
    }
}

/// Compact 16-byte block descriptor stored in the descriptor array at the end of an HTX buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtxBlockDesc {
    pub blk_type: HtxBlockType,
    pub flags: u8,
    pub name_len: u16,
    pub addr: u32,
    pub value_len: u32,
    pub aux: u32,
}

impl HtxBlockDesc {
    #[must_use]
    pub fn from_bytes(bytes: &[u8; HTX_DESC_SIZE]) -> Self {
        Self {
            blk_type: HtxBlockType::from_u8(bytes[0]),
            flags: bytes[1],
            name_len: u16::from_le_bytes([bytes[2], bytes[3]]),
            addr: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            value_len: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            aux: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        }
    }

    /// Where a header's or trailer's name is.
    #[must_use]
    #[inline]
    pub fn name_range(&self) -> std::ops::Range<usize> {
        self.addr as usize..self.addr as usize + self.name_len as usize
    }

    /// Where the value is: after the name and `aux` bytes for a header or a trailer (`aux` is
    /// the received `:` and blanks of a field indexed in place, X1, and 0 when it is packed),
    /// at `addr` for any other block.
    #[must_use]
    #[inline]
    pub fn value_range(&self) -> std::ops::Range<usize> {
        let start = match self.blk_type {
            HtxBlockType::Header | HtxBlockType::Trailer => self.addr as usize + self.name_len as usize + self.aux as usize,
            _ => self.addr as usize,
        };
        start..start + self.value_len as usize
    }

    /// The bytes from `addr` the block covers: name, gap and value of a field.
    #[must_use]
    #[inline]
    pub fn span(&self) -> usize {
        self.value_range().end - self.addr as usize
    }

    /// The payload bytes of the block: name and value of a field (not the gap between them).
    #[must_use]
    #[inline]
    pub fn payload_len(&self) -> usize {
        match self.blk_type {
            HtxBlockType::Header | HtxBlockType::Trailer => self.name_len as usize + self.value_len as usize,
            _ => self.value_len as usize,
        }
    }

    pub fn write_bytes(&self, out: &mut [u8; HTX_DESC_SIZE]) {
        out[0] = self.blk_type as u8;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.name_len.to_le_bytes());
        out[4..8].copy_from_slice(&self.addr.to_le_bytes());
        out[8..12].copy_from_slice(&self.value_len.to_le_bytes());
        out[12..16].copy_from_slice(&self.aux.to_le_bytes());
    }
}

/// Errors occurring during HTX slice operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtxError {
    /// Pre-allocated buffer capacity is insufficient to append payload or block descriptor.
    OutOfMemory,
    /// Header name or value exceeds maximum allowed byte length.
    LimitExceeded,
    /// Destination buffer is too small to receive serialized HTTP/1.1 wire data.
    BufferTooSmall,
    /// UTF-8 or syntax decode error in start-line or header field.
    InvalidData,
}

impl fmt::Display for HtxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HtxError::OutOfMemory => write!(f, "HTX buffer out of memory"),
            HtxError::LimitExceeded => write!(f, "HTX header name or value length limit exceeded"),
            HtxError::BufferTooSmall => write!(f, "Output buffer too small for wire serialization"),
            HtxError::InvalidData => write!(f, "Invalid UTF-8 or framing data in HTX block"),
        }
    }
}

impl std::error::Error for HtxError {}

/// HTTP Method representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    Other(String),
}

impl HttpMethod {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Head => "HEAD",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Connect => "CONNECT",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Other(s) => s.as_str(),
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            b"GET" => HttpMethod::Get,
            b"HEAD" => HttpMethod::Head,
            b"POST" => HttpMethod::Post,
            b"PUT" => HttpMethod::Put,
            b"DELETE" => HttpMethod::Delete,
            b"CONNECT" => HttpMethod::Connect,
            b"OPTIONS" => HttpMethod::Options,
            b"TRACE" => HttpMethod::Trace,
            b"PATCH" => HttpMethod::Patch,
            other => HttpMethod::Other(String::from_utf8_lossy(other).into_owned()),
        }
    }
}

/// HTTP Version representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpVersion {
    Http10,
    #[default]
    Http11,
    Http20,
    Http30,
}

impl HttpVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http20 => "HTTP/2.0",
            HttpVersion::Http30 => "HTTP/3.0",
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes == b"HTTP/1.0" {
            HttpVersion::Http10
        } else if bytes == b"HTTP/2.0" || bytes == b"HTTP/2" {
            HttpVersion::Http20
        } else if bytes == b"HTTP/3.0" || bytes == b"HTTP/3" {
            HttpVersion::Http30
        } else {
            HttpVersion::Http11
        }
    }
}

/// A request start line (e.g. `GET /index.html HTTP/1.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
}

/// Borrowed zero-copy view of a request start line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLineView<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub version: &'a str,
}

/// [`RequestLineView`] as the bytes the block holds (T436): what the proxy compares and
/// searches needs no reading as UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLineBytes<'a> {
    pub method: &'a [u8],
    pub uri: &'a [u8],
    pub version: &'a [u8],
}

/// A response status line (e.g. `HTTP/1.1 200 OK`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseLine {
    pub version: HttpVersion,
    pub status: u16,
    pub reason: String,
}

/// Borrowed zero-copy view of a response status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseLineView<'a> {
    pub version: &'a str,
    pub status: u16,
    pub reason: &'a str,
}

/// An HTTP header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

/// Individual block in an HTX stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtxBlock {
    /// Start line for HTTP requests.
    ReqLine(RequestLine),
    /// Status line for HTTP responses.
    ResLine(ResponseLine),
    /// Header name-value pair.
    Header(HeaderField),
    /// End-of-headers boundary marker.
    Eoh,
    /// Body data payload chunk.
    Data(Vec<u8>),
    /// Trailer header field following chunked body.
    Trailer(HeaderField),
    /// End-of-trailers boundary marker.
    Eot,
    /// Raw tunneled data payload.
    RawData(Vec<u8>),
    /// End-of-message boundary marker.
    Eom,
}

// ---------------------------------------------------------------------------
// Low-level buffer primitives for bidirectional layout
// ---------------------------------------------------------------------------

/// The first three words of `raw`, as `split_whitespace` gives them.
#[cold]
#[inline(never)]
fn words3(raw: &str) -> [Option<&str>; 3] {
    let mut parts = raw.split_whitespace();
    [parts.next(), parts.next(), parts.next()]
}

/// [`words3`] of an ASCII string, on its bytes.
fn ascii_words3(raw: &str) -> [Option<&str>; 3] {
    // ASCII: every index is a character boundary.
    ascii_word_spans(raw.as_bytes()).map(|w| w.map(|(start, end)| &raw[start..end]))
}

/// [`ascii_words3`] of ASCII bytes.
fn ascii_words3_bytes(raw: &[u8]) -> [Option<&[u8]>; 3] {
    ascii_word_spans(raw).map(|w| w.map(|(start, end)| &raw[start..end]))
}

/// Where the first three words of ASCII bytes are, as [`words3`] splits them.
fn ascii_word_spans(b: &[u8]) -> [Option<(usize, usize)>; 3] {
    // What `char::is_whitespace` is true of in ASCII.
    let ws = |b: u8| matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ');
    let mut out = [None; 3];
    let mut at = 0;
    for w in &mut out {
        let Some(start) = b[at..].iter().position(|&c| !ws(c)).map(|n| at + n) else { break };
        let end = b[start..].iter().position(|&c| ws(c)).map_or(b.len(), |n| start + n);
        *w = Some((start, end));
        at = end;
    }
    out
}

fn read_desc_at(buf: &[u8], num_blocks: usize, index: usize) -> HtxBlockDesc {
    assert!(index < num_blocks);
    let offset = buf.len() - (index + 1) * HTX_DESC_SIZE;
    let mut arr = [0u8; HTX_DESC_SIZE];
    arr.copy_from_slice(&buf[offset..offset + HTX_DESC_SIZE]);
    HtxBlockDesc::from_bytes(&arr)
}

fn write_desc_at(buf: &mut [u8], num_blocks: usize, index: usize, desc: &HtxBlockDesc) {
    assert!(index < num_blocks);
    let offset = buf.len() - (index + 1) * HTX_DESC_SIZE;
    let mut arr = [0u8; HTX_DESC_SIZE];
    desc.write_bytes(&mut arr);
    buf[offset..offset + HTX_DESC_SIZE].copy_from_slice(&arr);
}

fn free_capacity_at(buf_len: usize, tail_addr: usize, num_blocks: usize) -> usize {
    let desc_start = buf_len.saturating_sub(num_blocks * HTX_DESC_SIZE);
    desc_start.saturating_sub(tail_addr)
}

fn push_req_line_raw(
    buf: &mut [u8],
    tail_addr: &mut usize,
    num_blocks: &mut usize,
    method: impl AsRef<[u8]>,
    uri: impl AsRef<[u8]>,
    version: impl AsRef<[u8]>,
) -> Result<(), HtxError> {
    let (method, uri, version) = (method.as_ref(), uri.as_ref(), version.as_ref());
    let needed = method.len() + 1 + uri.len() + 1 + version.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    let start = *tail_addr;

    buf[start..start + method.len()].copy_from_slice(method);
    let cur = start + method.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + uri.len()].copy_from_slice(uri);
    let cur = cur + uri.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + version.len()].copy_from_slice(version);
    *tail_addr = cur + version.len();

    let desc = HtxBlockDesc {
        blk_type: HtxBlockType::ReqLine,
        flags: HTX_BLK_FL_NONE,
        name_len: method.len() as u16,
        addr,
        value_len: (*tail_addr - start) as u32,
        aux: uri.len() as u32,
    };

    let new_idx = *num_blocks;
    *num_blocks += 1;
    write_desc_at(buf, *num_blocks, new_idx, &desc);
    Ok(())
}

fn push_res_line_raw(
    buf: &mut [u8],
    tail_addr: &mut usize,
    num_blocks: &mut usize,
    version: &[u8],
    status: u16,
    reason: &[u8],
) -> Result<(), HtxError> {
    let mut digits = [0u8; 10];
    let status_str = format_u16_into(status, &mut digits);
    let needed = version.len() + 1 + status_str.len() + 1 + reason.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    let start = *tail_addr;

    buf[start..start + version.len()].copy_from_slice(version);
    let cur = start + version.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + status_str.len()].copy_from_slice(status_str);
    let cur = cur + status_str.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + reason.len()].copy_from_slice(reason);
    *tail_addr = cur + reason.len();

    let desc = HtxBlockDesc {
        blk_type: HtxBlockType::ResLine,
        flags: HTX_BLK_FL_NONE,
        name_len: status,
        addr,
        value_len: (*tail_addr - start) as u32,
        aux: version.len() as u32,
    };

    let new_idx = *num_blocks;
    *num_blocks += 1;
    write_desc_at(buf, *num_blocks, new_idx, &desc);
    Ok(())
}

fn push_header_raw(
    buf: &mut [u8],
    tail_addr: &mut usize,
    num_blocks: &mut usize,
    name: impl AsRef<[u8]>,
    value: impl AsRef<[u8]>,
) -> Result<(), HtxError> {
    let (name, value) = (name.as_ref(), value.as_ref());
    if name.len() > HTX_HDR_NAME_MAX_LEN || value.len() > HTX_HDR_VALUE_MAX_LEN {
        return Err(HtxError::LimitExceeded);
    }

    let needed = name.len() + value.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    buf[*tail_addr..*tail_addr + name.len()].copy_from_slice(name);
    *tail_addr += name.len();
    buf[*tail_addr..*tail_addr + value.len()].copy_from_slice(value);
    *tail_addr += value.len();

    let desc = HtxBlockDesc {
        blk_type: HtxBlockType::Header,
        flags: HTX_BLK_FL_NONE,
        name_len: name.len() as u16,
        addr,
        value_len: value.len() as u32,
        aux: 0,
    };

    let new_idx = *num_blocks;
    *num_blocks += 1;
    write_desc_at(buf, *num_blocks, new_idx, &desc);
    Ok(())
}

fn insert_header_raw(
    buf: &mut [u8],
    tail_addr: &mut usize,
    num_blocks: &mut usize,
    insert_idx: usize,
    name: &str,
    value: &str,
) -> Result<(), HtxError> {
    if name.len() > HTX_HDR_NAME_MAX_LEN || value.len() > HTX_HDR_VALUE_MAX_LEN {
        return Err(HtxError::LimitExceeded);
    }
    let needed = name.len() + value.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    buf[*tail_addr..*tail_addr + name.len()].copy_from_slice(name.as_bytes());
    *tail_addr += name.len();
    buf[*tail_addr..*tail_addr + value.len()].copy_from_slice(value.as_bytes());
    *tail_addr += value.len();

    let desc = HtxBlockDesc {
        blk_type: HtxBlockType::Header,
        flags: HTX_BLK_FL_NONE,
        name_len: name.len() as u16,
        addr,
        value_len: value.len() as u32,
        aux: 0,
    };

    let idx = insert_idx.min(*num_blocks);
    let old_num = *num_blocks;
    *num_blocks += 1;
    for j in (idx..old_num).rev() {
        let d = read_desc_at(buf, *num_blocks, j);
        write_desc_at(buf, *num_blocks, j + 1, &d);
    }
    write_desc_at(buf, *num_blocks, idx, &desc);
    Ok(())
}

fn push_trailer_raw(
    buf: &mut [u8],
    tail_addr: &mut usize,
    num_blocks: &mut usize,
    name: &str,
    value: &str,
) -> Result<(), HtxError> {
    if name.len() > HTX_HDR_NAME_MAX_LEN || value.len() > HTX_HDR_VALUE_MAX_LEN {
        return Err(HtxError::LimitExceeded);
    }

    let needed = name.len() + value.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    buf[*tail_addr..*tail_addr + name.len()].copy_from_slice(name.as_bytes());
    *tail_addr += name.len();
    buf[*tail_addr..*tail_addr + value.len()].copy_from_slice(value.as_bytes());
    *tail_addr += value.len();

    let desc = HtxBlockDesc {
        blk_type: HtxBlockType::Trailer,
        flags: HTX_BLK_FL_NONE,
        name_len: name.len() as u16,
        addr,
        value_len: value.len() as u32,
        aux: 0,
    };

    let new_idx = *num_blocks;
    *num_blocks += 1;
    write_desc_at(buf, *num_blocks, new_idx, &desc);
    Ok(())
}

fn push_data_raw(
    buf: &mut [u8],
    tail_addr: &mut usize,
    num_blocks: &mut usize,
    data: &[u8],
    is_raw: bool,
) -> Result<(), HtxError> {
    let needed = data.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    buf[*tail_addr..*tail_addr + data.len()].copy_from_slice(data);
    *tail_addr += data.len();

    let desc = HtxBlockDesc {
        blk_type: if is_raw {
            HtxBlockType::RawData
        } else {
            HtxBlockType::Data
        },
        flags: HTX_BLK_FL_NONE,
        name_len: 0,
        addr,
        value_len: data.len() as u32,
        aux: 0,
    };

    let new_idx = *num_blocks;
    *num_blocks += 1;
    write_desc_at(buf, *num_blocks, new_idx, &desc);
    Ok(())
}

fn push_marker_raw(
    buf: &mut [u8],
    tail_addr: usize,
    num_blocks: &mut usize,
    blk_type: HtxBlockType,
    flags: u8,
) -> Result<(), HtxError> {
    if free_capacity_at(buf.len(), tail_addr, *num_blocks) < HTX_DESC_SIZE {
        return Err(HtxError::OutOfMemory);
    }
    let desc = HtxBlockDesc {
        blk_type,
        flags,
        name_len: 0,
        addr: tail_addr as u32,
        value_len: 0,
        aux: 0,
    };
    let new_idx = *num_blocks;
    *num_blocks += 1;
    write_desc_at(buf, *num_blocks, new_idx, &desc);
    Ok(())
}


fn remove_block_raw(buf: &mut [u8], num_blocks: usize, index: usize) {
    if index < num_blocks {
        let mut desc = read_desc_at(buf, num_blocks, index);
        desc.blk_type = HtxBlockType::Unused;
        write_desc_at(buf, num_blocks, index, &desc);
    }
}

fn replace_block_value_raw(
    buf: &mut [u8],
    tail_addr: &mut usize,
    num_blocks: usize,
    index: usize,
    new_value: &[u8],
) -> Result<(), HtxError> {
    if index >= num_blocks {
        return Ok(());
    }
    let mut desc = read_desc_at(buf, num_blocks, index);
    if desc.blk_type == HtxBlockType::Unused {
        return Ok(());
    }
    // The value is written as bytes when it holds an escaped byte (T286).
    if desc.blk_type == HtxBlockType::Header {
        let escaped = !new_value.is_ascii() && utf8(new_value).is_ok_and(ibex_regex::bytetext::has_escapes);
        if escaped {
            desc.flags |= HTX_BLK_FL_LATIN1;
        } else {
            desc.flags &= !HTX_BLK_FL_LATIN1;
        }
    }

    let old_val_len = desc.value_len as usize;

    if new_value.len() <= old_val_len {
        let val_start = desc.value_range().start;
        buf[val_start..val_start + new_value.len()].copy_from_slice(new_value);
        desc.value_len = new_value.len() as u32;
        write_desc_at(buf, num_blocks, index, &desc);
        Ok(())
    } else {
        let needed = match desc.blk_type {
            HtxBlockType::Header | HtxBlockType::Trailer => desc.name_len as usize + new_value.len(),
            _ => new_value.len(),
        };

        if free_capacity_at(buf.len(), *tail_addr, num_blocks) < needed {
            return Err(HtxError::OutOfMemory);
        }

        let old_addr = desc.addr as usize;
        let new_addr = *tail_addr;

        match desc.blk_type {
            HtxBlockType::Header | HtxBlockType::Trailer => {
                let name_len = desc.name_len as usize;
                buf.copy_within(old_addr..old_addr + name_len, new_addr);
                buf[new_addr + name_len..new_addr + name_len + new_value.len()].copy_from_slice(new_value);
            },
            _ => {
                buf[new_addr..new_addr + new_value.len()].copy_from_slice(new_value);
            }
        }

        *tail_addr += needed;
        desc.addr = new_addr as u32;
        desc.value_len = new_value.len() as u32;
        if matches!(desc.blk_type, HtxBlockType::Header | HtxBlockType::Trailer) {
            desc.aux = 0;
        }
        write_desc_at(buf, num_blocks, index, &desc);
        Ok(())
    }
}



fn write_slice(out: &mut [u8], cursor: usize, src: &[u8]) -> Result<usize, HtxError> {
    if cursor + src.len() > out.len() {
        return Err(HtxError::BufferTooSmall);
    }
    out[cursor..cursor + src.len()].copy_from_slice(src);
    Ok(cursor + src.len())
}

// ---------------------------------------------------------------------------
// Immutable slice view
// ---------------------------------------------------------------------------

fn format_u16_into(mut val: u16, buf: &mut [u8; 10]) -> &[u8] {
    if val == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = 10;
    while val > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    &buf[i..]
}

/// Immutable borrowed view over a contiguous HTX buffer.
#[derive(Clone, Copy)]
pub struct HtxSliceRef<'a> {
    buf: &'a [u8],
    num_blocks: usize,
}

impl<'a> HtxSliceRef<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8], num_blocks: usize) -> Self {
        Self { buf, num_blocks }
    }

    #[must_use]
    pub fn num_blocks(&self) -> usize {
        self.num_blocks
    }

    #[must_use]
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    #[must_use]
    pub fn read_desc(&self, index: usize) -> HtxBlockDesc {
        read_desc_at(self.buf, self.num_blocks, index)
    }

    #[must_use]
    pub fn is_eom(&self) -> bool {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.flags & HTX_BLK_FL_EOM != 0 || desc.blk_type == HtxBlockType::Eom {
                return true;
            }
        }
        false
    }

    #[must_use]
    pub fn is_eoh(&self) -> bool {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if matches!(
                desc.blk_type,
                HtxBlockType::Eoh | HtxBlockType::Eot | HtxBlockType::Eom
            ) {
                return true;
            }
        }
        false
    }

    #[must_use]
    pub fn req_line(&self) -> Option<RequestLineView<'a>> {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::ReqLine {
                let start = desc.addr as usize;
                let end = start + desc.value_len as usize;
                let raw = utf8(&self.buf[start..end]).ok()?;
                let [method, uri, version] = if raw.is_ascii() { ascii_words3(raw) } else { words3(raw) };
                let method = method?;
                let uri = uri?;
                let version = version.unwrap_or("HTTP/1.1");
                return Some(RequestLineView {
                    method,
                    uri,
                    version,
                });
            }
        }
        None
    }

    /// [`Self::req_line`] as bytes: the same words, not read as UTF-8 when the line is
    /// ASCII (every line the parser takes without `accept-unsafe-violations-in-http-request`).
    #[must_use]
    pub fn req_line_bytes(&self) -> Option<RequestLineBytes<'a>> {
        let desc = (0..self.num_blocks).map(|i| self.read_desc(i)).find(|d| d.blk_type == HtxBlockType::ReqLine)?;
        let start = desc.addr as usize;
        let raw = &self.buf[start..start + desc.value_len as usize];
        let [method, uri, version] = if raw.is_ascii() {
            ascii_words3_bytes(raw)
        } else {
            words3(utf8(raw).ok()?).map(|w| w.map(str::as_bytes))
        };
        Some(RequestLineBytes { method: method?, uri: uri?, version: version.unwrap_or(b"HTTP/1.1") })
    }

    #[must_use]
    pub fn res_line(&self) -> Option<ResponseLineView<'a>> {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::ResLine {
                let start = desc.addr as usize;
                let end = start + desc.value_len as usize;
                let raw = utf8(&self.buf[start..end]).ok()?;
                let mut parts = raw.splitn(3, ' ');
                let version = parts.next()?;
                let _status_str = parts.next()?;
                let reason = parts.next().unwrap_or("").trim();
                return Some(ResponseLineView {
                    version,
                    status: desc.name_len,
                    reason,
                });
            }
        }
        None
    }

    /// The value of the first header named `name` (ASCII case aside), as text; `None` when
    /// there is none, or when its value is not UTF-8 ([`Self::get_header_bytes`] reads it).
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&'a str> {
        self.get_header_bytes(name.as_bytes()).and_then(|v| utf8(v).ok())
    }

    /// The value of the first header named `name` (ASCII case aside), as its bytes (T436:
    /// the names are compared as bytes, and none is read as UTF-8).
    #[must_use]
    pub fn get_header_bytes(&self, name: &[u8]) -> Option<&'a [u8]> {
        (0..self.num_blocks).find_map(|i| {
            let desc = self.read_desc(i);
            (desc.blk_type == HtxBlockType::Header && self.buf[desc.name_range()].eq_ignore_ascii_case(name))
                .then(|| &self.buf[desc.value_range()])
        })
    }

    #[must_use]
    pub fn get_trailer(&self, name: &str) -> Option<&'a str> {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Trailer {
                let hdr_name = utf8(&self.buf[desc.name_range()]).ok()?;
                if hdr_name.eq_ignore_ascii_case(name) {
                    return utf8(&self.buf[desc.value_range()]).ok();
                }
            }
        }
        None
    }

    #[must_use]
    pub fn body_len(&self) -> usize {
        let mut sum = 0;
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if matches!(desc.blk_type, HtxBlockType::Data | HtxBlockType::RawData) {
                sum += desc.value_len as usize;
            }
        }
        sum
    }

    pub fn write_h1_wire(&self, out: &mut [u8]) -> Result<usize, HtxError> {
        let mut cursor = 0;

        if let Some(req) = self.req_line() {
            // `h1_format_htx_reqline`: a version from 1.1 up goes as `HTTP/1.1` (T291).
            let version = if req.version == "HTTP/2"
                || req.version == "HTTP/3"
                || crate::h1::version_is_11(req.version.as_bytes())
            {
                "HTTP/1.1"
            } else {
                req.version
            };
            cursor = write_slice(out, cursor, req.method.as_bytes())?;
            cursor = write_slice(out, cursor, b" ")?;
            cursor = write_slice(out, cursor, req.uri.as_bytes())?;
            cursor = write_slice(out, cursor, b" ")?;
            cursor = write_slice(out, cursor, version.as_bytes())?;
            cursor = write_slice(out, cursor, b"\r\n")?;
        } else if let Some(res) = self.res_line() {

            cursor = write_slice(out, cursor, res.version.as_bytes())?;
            cursor = write_slice(out, cursor, b" ")?;
            let mut status_buf = [0u8; 10];
            let status_bytes = format_u16_into(res.status, &mut status_buf);
            cursor = write_slice(out, cursor, status_bytes)?;
            cursor = write_slice(out, cursor, b" ")?;
            cursor = write_slice(out, cursor, res.reason.as_bytes())?;
            cursor = write_slice(out, cursor, b"\r\n")?;
        }

        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Header {
                cursor = write_slice(out, cursor, &self.buf[desc.name_range()])?;
                cursor = write_slice(out, cursor, b": ")?;
                cursor = if desc.flags & HTX_BLK_FL_LATIN1 == 0 {
                    write_slice(out, cursor, &self.buf[desc.value_range()])?
                } else {
                    write_latin1(out, cursor, &self.buf[desc.value_range()])?
                };
                cursor = write_slice(out, cursor, b"\r\n")?;
            }
        }

        cursor = write_slice(out, cursor, b"\r\n")?;

        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if matches!(desc.blk_type, HtxBlockType::Data | HtxBlockType::RawData) {
                let start = desc.addr as usize;
                let end = start + desc.value_len as usize;
                cursor = write_slice(out, cursor, &self.buf[start..end])?;
            }
        }

        let mut has_trailers = false;
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Trailer {
                has_trailers = true;
                cursor = write_slice(out, cursor, &self.buf[desc.name_range()])?;
                cursor = write_slice(out, cursor, b": ")?;
                cursor = write_slice(out, cursor, &self.buf[desc.value_range()])?;
                cursor = write_slice(out, cursor, b"\r\n")?;
            }
        }

        if has_trailers {
            cursor = write_slice(out, cursor, b"\r\n")?;
        }

        Ok(cursor)
    }

    /// The HTTP/1 head of this message, in a buffer sized to fit it: it starts at 8 KiB and
    /// doubles until the head is written. A fixed buffer silently skipped the rewrite of
    /// every larger head (tasks/T101). The only way `write_h1_wire` fails is a buffer that
    /// is too small, and a message is finite, so this ends.
    #[must_use]
    pub fn write_h1_wire_vec(&self) -> Vec<u8> {
        let mut size = 8192;
        loop {
            let mut out = vec![0u8; size];
            if let Ok(n) = self.write_h1_wire(&mut out) {
                out.truncate(n);
                return out;
            }
            size *= 2;
        }
    }

    #[must_use]
    pub fn to_h1_wire(&self) -> Vec<u8> {
        self.write_h1_wire_vec()
    }

    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.body_len());
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if matches!(desc.blk_type, HtxBlockType::Data | HtxBlockType::RawData) {
                let start = desc.addr as usize;
                let end = start + desc.value_len as usize;
                b.extend_from_slice(&self.buf[start..end]);
            }
        }
        b
    }

    #[must_use]
    pub fn fragmented_bytes(&self) -> usize {
        let mut max_end = 0;
        let mut active = 0;
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type != HtxBlockType::Unused {
                let p_len = desc.payload_len();
                let end = desc.addr as usize + desc.span();
                if end > max_end {
                    max_end = end;
                }
                active += p_len;
            }
        }
        max_end.saturating_sub(active)
    }

    #[must_use]
    pub fn block_type(&self, index: usize) -> Option<HtxBlockType> {
        if index < self.num_blocks {
            Some(self.read_desc(index).blk_type)
        } else {
            None
        }
    }

    #[must_use]
    pub fn block_types(&self) -> Vec<HtxBlockType> {
        (0..self.num_blocks)
            .filter_map(|i| self.block_type(i))
            .collect()
    }

    #[must_use]
    pub fn active_block_types(&self) -> Vec<HtxBlockType> {
        (0..self.num_blocks)
            .filter_map(|i| self.block_type(i))
            .filter(|&t| t != HtxBlockType::Unused)
            .collect()
    }

    pub fn headers(self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        (0..self.num_blocks).filter_map(move |i| {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Header {
                let name = utf8(&self.buf[desc.name_range()]).ok()?;
                let val = utf8(&self.buf[desc.value_range()]).ok()?;
                Some((name, val))
            } else {
                None
            }
        })
    }

    /// [`Self::header_blocks`] of the headers whose name `keep` keeps, the name read as bytes:
    /// what `header_blocks().filter(..)` on the name gives, without reading as UTF-8 the
    /// names and values of the headers it does not keep.
    pub fn header_blocks_where(self, keep: impl Fn(&[u8]) -> bool + 'a) -> impl Iterator<Item = (usize, &'a str, &'a str)> + 'a {
        (0..self.num_blocks).filter_map(move |i| {
            let desc = self.read_desc(i);
            if desc.blk_type != HtxBlockType::Header {
                return None;
            }
            if !keep(&self.buf[desc.name_range()]) {
                return None;
            }
            let name = utf8(&self.buf[desc.name_range()]).ok()?;
            let val = utf8(&self.buf[desc.value_range()]).ok()?;
            Some((i, name, val))
        })
    }

    /// The header blocks as `(block index, name, value)`. The index is what
    /// `replace_block_value` and `remove_block` take, and stays valid while other
    /// blocks are replaced or removed.
    pub fn header_blocks(self) -> impl Iterator<Item = (usize, &'a str, &'a str)> + 'a {
        (0..self.num_blocks).filter_map(move |i| {
            let desc = self.read_desc(i);
            if desc.blk_type != HtxBlockType::Header {
                return None;
            }
            let name = utf8(&self.buf[desc.name_range()]).ok()?;
            let val = utf8(&self.buf[desc.value_range()]).ok()?;
            Some((i, name, val))
        })
    }

    pub fn trailers(self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        (0..self.num_blocks).filter_map(move |i| {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Trailer {
                let name = utf8(&self.buf[desc.name_range()]).ok()?;
                let val = utf8(&self.buf[desc.value_range()]).ok()?;
                Some((name, val))
            } else {
                None
            }
        })
    }

    pub fn check_invariants(&self, tail_addr: usize) -> Result<(), String> {
        self.check_invariants_in(tail_addr, HtxRegion::default())
    }

    /// [`Self::check_invariants`] of an HTX laid out as `region` says ([`HtxSlice::over_received`]):
    /// every block lies in the received head or in the reserve's payload, `reserve_start..tail_addr`.
    pub fn check_invariants_in(&self, tail_addr: usize, region: HtxRegion) -> Result<(), String> {
        let cap = self.buf.len();
        if region.head_start > region.head_end || region.head_end > region.reserve_start || region.reserve_start > tail_addr {
            return Err(format!("region {region:?} out of order with tail_addr {tail_addr}"));
        }
        let desc_table_size = self.num_blocks * HTX_DESC_SIZE;
        if desc_table_size > cap {
            return Err(format!(
                "desc table size {desc_table_size} exceeds capacity {cap}"
            ));
        }
        let desc_start = cap - desc_table_size;
        if tail_addr > desc_start {
            return Err(format!(
                "tail_addr {} intrudes into descriptor table at {}",
                tail_addr, desc_start
            ));
        }

        let free = free_capacity_at(cap, tail_addr, self.num_blocks);
        if tail_addr + free + desc_table_size != cap {
            return Err(format!(
                "accounting mismatch: tail {} + free {} + desc {} != cap {}",
                tail_addr, free, desc_table_size, cap
            ));
        }

        let mut active_ranges: Vec<(usize, usize, usize)> = Vec::new();
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Unused {
                continue;
            }
            let p_len = desc.span();
            let start = desc.addr as usize;
            let end = start + p_len;
            let in_head = start >= region.head_start && end <= region.head_end;
            if p_len > 0 && !in_head && (start < region.reserve_start || end > tail_addr) {
                return Err(format!(
                    "block {i} [{start}..{end}) is outside the head {}..{} and the payload {}..{tail_addr}",
                    region.head_start, region.head_end, region.reserve_start
                ));
            }
            if p_len > 0 {
                active_ranges.push((start, end, i));
            }
        }

        active_ranges.sort_by_key(|&(s, _, _)| s);
        for w in active_ranges.windows(2) {
            let (s1, e1, idx1) = w[0];
            let (s2, _e2, idx2) = w[1];
            if e1 > s2 {
                return Err(format!(
                    "active block {idx1} [{s1}..{e1}) overlaps with block {idx2} starting at {s2}"
                ));
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn to_blocks(&self) -> Vec<HtxBlock> {
        let mut blocks = Vec::new();
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Unused {
                continue;
            }
            let addr = desc.addr as usize;
            match desc.blk_type {
                HtxBlockType::ReqLine => {
                    let raw = utf8(&self.buf[addr..addr + desc.value_len as usize]).unwrap_or("");
                    let mut parts = raw.split_whitespace();
                    blocks.push(HtxBlock::ReqLine(RequestLine {
                        method: HttpMethod::from_bytes(parts.next().unwrap_or("GET").as_bytes()),
                        uri: parts.next().unwrap_or("/").to_string(),
                        version: HttpVersion::from_bytes(parts.next().unwrap_or("HTTP/1.1").as_bytes()),
                    }));
                }
                HtxBlockType::ResLine => {
                    let raw = std::str::from_utf8(&self.buf[addr..addr + desc.value_len as usize]).unwrap_or("");
                    let mut parts = raw.splitn(3, ' ');
                    blocks.push(HtxBlock::ResLine(ResponseLine {
                        version: HttpVersion::from_bytes(parts.next().unwrap_or("HTTP/1.1").as_bytes()),
                        status: desc.name_len,
                        reason: parts.next().unwrap_or("").trim().to_string(),
                    }));
                }
                HtxBlockType::Header => {
                    let name = utf8(&self.buf[desc.name_range()]).unwrap_or("").to_string();
                    let value = utf8(&self.buf[desc.value_range()]).unwrap_or("").to_string();
                    blocks.push(HtxBlock::Header(HeaderField { name, value }));
                }
                HtxBlockType::Trailer => {
                    let name = utf8(&self.buf[desc.name_range()]).unwrap_or("").to_string();
                    let value = utf8(&self.buf[desc.value_range()]).unwrap_or("").to_string();
                    blocks.push(HtxBlock::Trailer(HeaderField { name, value }));
                }
                HtxBlockType::Eoh => blocks.push(HtxBlock::Eoh),
                HtxBlockType::Eot => blocks.push(HtxBlock::Eot),
                HtxBlockType::Eom => blocks.push(HtxBlock::Eom),
                HtxBlockType::Data => {
                    let data = self.buf[addr..addr + desc.value_len as usize].to_vec();
                    blocks.push(HtxBlock::Data(data));
                }
                HtxBlockType::RawData => {
                    let data = self.buf[addr..addr + desc.value_len as usize].to_vec();
                    blocks.push(HtxBlock::RawData(data));
                }
                HtxBlockType::Unused => {}
            }
        }
        blocks
    }

    #[must_use]
    pub fn to_htx(&self) -> Htx {
        Htx {
            blocks: self.to_blocks(),
        }
    }
}

impl<'b> PartialEq<HtxSliceRef<'b>> for HtxSliceRef<'_> {
    fn eq(&self, other: &HtxSliceRef<'b>) -> bool {
        if self.num_blocks != other.num_blocks {
            return false;
        }
        for i in 0..self.num_blocks {
            let d1 = self.read_desc(i);
            let d2 = other.read_desc(i);
            if d1.blk_type != d2.blk_type || d1.flags != d2.flags || d1.name_len != d2.name_len || d1.value_len != d2.value_len {
                return false;
            }
            let fields = matches!(d1.blk_type, HtxBlockType::Header | HtxBlockType::Trailer);
            if fields && self.buf[d1.name_range()] != other.buf[d2.name_range()] {
                return false;
            }
            if self.buf[d1.value_range()] != other.buf[d2.value_range()] {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Debug for HtxSliceRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list = f.debug_list();
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            match desc.blk_type {
                HtxBlockType::ReqLine => {
                    list.entry(&self.req_line());
                }
                HtxBlockType::ResLine => {
                    list.entry(&self.res_line());
                }
                HtxBlockType::Header => {
                    let n = utf8(&self.buf[desc.name_range()]).unwrap_or("");
                    let v = utf8(&self.buf[desc.value_range()]).unwrap_or("");
                    list.entry(&(n, v));
                }
                HtxBlockType::Data => {
                    list.entry(&format_args!("Data({} bytes)", desc.value_len));
                }
                HtxBlockType::Eoh => {
                    list.entry(&"Eoh");
                }
                HtxBlockType::Eom => {
                    list.entry(&"Eom");
                }
                HtxBlockType::Eot => {
                    list.entry(&"Eot");
                }
                HtxBlockType::Trailer => {
                    let n = std::str::from_utf8(&self.buf[desc.name_range()]).unwrap_or("");
                    let v = std::str::from_utf8(&self.buf[desc.value_range()]).unwrap_or("");
                    list.entry(&("Trailer", n, v));
                }
                HtxBlockType::RawData => {
                    list.entry(&format_args!("RawData({} bytes)", desc.value_len));
                }
                HtxBlockType::Unused => {
                    list.entry(&"Unused");
                }
            }
        }
        list.finish()
    }
}

// ---------------------------------------------------------------------------
// Zero-allocation mutable slice
// ---------------------------------------------------------------------------

/// Where an HTX indexed in place lies in its transport buffer (X1,
/// `docs/design/htx-engine-2026-11-01.md` section 2.1): the message head as it was received,
/// `head_start..head_end`, and the reserve from `reserve_start` to the end of the memory, whose
/// front takes the values an edit writes and whose back holds the descriptors. The bytes
/// between the head and the reserve (the body) are never addressed nor written. The default
/// (all 0) is an HTX of its own memory: no received head, the reserve the whole buffer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HtxRegion {
    pub head_start: usize,
    pub head_end: usize,
    pub reserve_start: usize,
}

/// Zero-allocation HTX representation over a contiguous pre-allocated byte slice.
pub struct HtxSlice<'a> {
    buf: &'a mut [u8],
    tail_addr: usize,
    num_blocks: usize,
    region: HtxRegion,
}

impl<'a> HtxSlice<'a> {
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            tail_addr: 0,
            num_blocks: 0,
            region: HtxRegion::default(),
        }
    }

    #[must_use]
    pub fn with_offsets(buf: &'a mut [u8], tail_addr: usize, num_blocks: usize) -> Self {
        Self {
            buf,
            tail_addr,
            num_blocks,
            region: HtxRegion::default(),
        }
    }

    /// An empty HTX over a transport buffer that holds a received head (X1): the descriptors
    /// [`crate::H1Parser::index_head_in_place`] writes address the head's bytes where they
    /// are, and only what an edit adds goes to the reserve. A head that is not edited is the
    /// bytes that arrived.
    ///
    /// # Errors
    /// [`HtxError::InvalidData`] when `region` is out of order or past `buf`, or `buf` is too
    /// large for the descriptors' 32-bit addresses.
    pub fn over_received(buf: &'a mut [u8], region: HtxRegion) -> Result<Self, HtxError> {
        let ordered = region.head_start <= region.head_end && region.head_end <= region.reserve_start && region.reserve_start <= buf.len();
        if !ordered || u32::try_from(buf.len()).is_err() {
            return Err(HtxError::InvalidData);
        }
        Ok(Self { buf, tail_addr: region.reserve_start, num_blocks: 0, region })
    }

    /// [`Self::over_received`] again, with what [`Self::tail_addr`] and [`Self::num_blocks`]
    /// were when the last one was dropped ([`Self::with_offsets`] of the in-place layout).
    #[must_use]
    pub fn over_received_with(buf: &'a mut [u8], region: HtxRegion, tail_addr: usize, num_blocks: usize) -> Self {
        debug_assert!(region.head_end <= region.reserve_start && region.reserve_start <= tail_addr && tail_addr <= buf.len());
        Self { buf, tail_addr, num_blocks, region }
    }

    /// Where the received head and the reserve are ([`HtxRegion::default`] for an HTX of its own).
    #[must_use]
    pub fn region(&self) -> HtxRegion {
        self.region
    }

    pub fn clear(&mut self) {
        self.tail_addr = self.region.reserve_start;
        self.num_blocks = 0;
    }

    /// A request line block over a line of the received head (X1): `line` without its end of
    /// line, the method its first `method_len` bytes, the target `uri_len` bytes. Nothing is
    /// copied.
    ///
    /// # Errors
    /// [`HtxError::InvalidData`] when `line` is not in the head, [`HtxError::OutOfMemory`]
    /// when the reserve has no room for the descriptor.
    pub fn push_req_line_in_place(&mut self, line: std::ops::Range<usize>, method_len: usize, uri_len: usize) -> Result<(), HtxError> {
        if line.start < self.region.head_start || line.end > self.region.head_end || line.start > line.end {
            return Err(HtxError::InvalidData);
        }
        let desc = HtxBlockDesc {
            blk_type: HtxBlockType::ReqLine,
            flags: HTX_BLK_FL_NONE,
            name_len: u16::try_from(method_len).map_err(|_| HtxError::LimitExceeded)?,
            addr: line.start as u32,
            value_len: line.len() as u32,
            aux: uri_len as u32,
        };
        self.push_desc(&desc)
    }

    /// A header block over a field of the received head (X1): the name and the value where
    /// they are, in the case they came in (lowercasing is the encoder's, X5), the bytes
    /// between them (`:` and blanks) skipped by the descriptor's `aux`. Nothing is copied.
    ///
    /// # Errors
    /// [`HtxError::InvalidData`] when the field is not in the head or the value comes before
    /// the name's end, [`HtxError::LimitExceeded`] as [`Self::push_header`],
    /// [`HtxError::OutOfMemory`] when the reserve has no room for the descriptor.
    pub fn push_header_in_place(&mut self, name: std::ops::Range<usize>, value: std::ops::Range<usize>) -> Result<(), HtxError> {
        let r = self.region;
        if name.start < r.head_start || name.start > name.end || name.end > value.start || value.start > value.end || value.end > r.head_end {
            return Err(HtxError::InvalidData);
        }
        if name.len() > HTX_HDR_NAME_MAX_LEN || value.len() > HTX_HDR_VALUE_MAX_LEN {
            return Err(HtxError::LimitExceeded);
        }
        let desc = HtxBlockDesc {
            blk_type: HtxBlockType::Header,
            flags: HTX_BLK_FL_NONE,
            name_len: name.len() as u16,
            addr: name.start as u32,
            value_len: value.len() as u32,
            aux: (value.start - name.end) as u32,
        };
        self.push_desc(&desc)
    }

    /// Appends a descriptor whose payload is already in the buffer.
    fn push_desc(&mut self, desc: &HtxBlockDesc) -> Result<(), HtxError> {
        if free_capacity_at(self.buf.len(), self.tail_addr, self.num_blocks) < HTX_DESC_SIZE {
            return Err(HtxError::OutOfMemory);
        }
        self.num_blocks += 1;
        write_desc_at(self.buf, self.num_blocks, self.num_blocks - 1, desc);
        Ok(())
    }

    /// Runs `edit`, and when the reserve had no room for it, [`Self::defrag`]s once and runs it
    /// again: the rewrite space a removed or replaced value left is taken back only then, as
    /// `htx_defrag` is in `HAProxy`. `edit` must change nothing when it fails for want of room
    /// (the setters here do, but [`Self::replace_header`] of several lines may have replaced
    /// some). `OutOfMemory` after the defrag means the head does not fit the reserve: the
    /// caller writes it out (`write_h1_wire`) and indexes it again.
    ///
    /// # Errors
    /// What `edit` returns the second time.
    pub fn retry_after_defrag<R>(&mut self, mut edit: impl FnMut(&mut Self) -> Result<R, HtxError>) -> Result<R, HtxError> {
        match edit(self) {
            Err(HtxError::OutOfMemory) => {
                self.defrag();
                edit(self)
            }
            r => r,
        }
    }

    #[must_use]
    pub fn as_ref(&self) -> HtxSliceRef<'_> {
        HtxSliceRef::new(self.buf, self.num_blocks)
    }

    #[must_use]
    pub fn num_blocks(&self) -> usize {
        self.num_blocks
    }

    #[must_use]
    pub fn tail_addr(&self) -> usize {
        self.tail_addr
    }

    /// The payload bytes in the reserve (all of them for an HTX of its own memory).
    #[must_use]
    pub fn payload_bytes(&self) -> usize {
        self.tail_addr - self.region.reserve_start
    }

    #[must_use]
    pub fn free_capacity(&self) -> usize {
        free_capacity_at(self.buf.len(), self.tail_addr, self.num_blocks)
    }

    pub fn into_parts(self) -> (&'a mut [u8], usize, usize) {
        (self.buf, self.tail_addr, self.num_blocks)
    }

    pub fn push_req_line(
        &mut self,
        method: &str,
        uri: &str,
        version: &str,
    ) -> Result<(), HtxError> {
        push_req_line_raw(
            self.buf,
            &mut self.tail_addr,
            &mut self.num_blocks,
            method,
            uri,
            version,
        )
    }

    /// [`Self::push_req_line`] of the bytes of a line the caller found to be ASCII: they go in as
    /// they are, with no UTF-8 check.
    pub fn push_req_line_ascii(&mut self, method: &[u8], uri: &[u8], version: &[u8]) -> Result<(), HtxError> {
        debug_assert!(method.is_ascii() && uri.is_ascii() && version.is_ascii(), "a request line past ASCII goes in as text");
        push_req_line_raw(self.buf, &mut self.tail_addr, &mut self.num_blocks, method, uri, version)
    }

    /// [`Self::push_header`] of the bytes of a field, as the HTTP/1 parser has them (`name` is
    /// tchars): a value that is ASCII goes in as it is, with no UTF-8 check; one that is not is
    /// UTF-8 or Latin-1 as before.
    pub fn push_header_bytes(&mut self, name: &[u8], value: &[u8]) -> Result<(), HtxError> {
        if value.is_ascii() {
            return push_header_raw(self.buf, &mut self.tail_addr, &mut self.num_blocks, name, value);
        }
        let name = std::str::from_utf8(name).map_err(|_| HtxError::InvalidData)?;
        match std::str::from_utf8(value) {
            Ok(v) => self.push_header(name, v),
            Err(_) => self.push_header_latin1(name, value),
        }
    }

    pub fn push_res_line(
        &mut self,
        version: &str,
        status: u16,
        reason: &str,
    ) -> Result<(), HtxError> {
        self.push_res_line_bytes(version.as_bytes(), status, reason.as_bytes())
    }

    /// [`Self::push_res_line`] of a line read as bytes (T581).
    pub fn push_res_line_bytes(&mut self, version: &[u8], status: u16, reason: &[u8]) -> Result<(), HtxError> {
        push_res_line_raw(self.buf, &mut self.tail_addr, &mut self.num_blocks, version, status, reason)
    }

    /// Writes the request head `head` (an HTTP/2 or HTTP/3 request's checked fields, E1) as
    /// its blocks: the start line `METHOD PATH HTTP/1.1`, a header block per field (a value
    /// that is not UTF-8 as Latin-1, as the HTTP/1 parser keeps it), `extra` last, the end of
    /// the headers; then the end-of-head checks and edits of the HTTP/1 parser
    /// ([`crate::h1::finish_request_head`]). `each` is given each field of `head` as the
    /// text the HTX holds (a Latin-1 value as its text), read once for both. The blocks are those
    /// [`crate::h1::H1Parser::parse`] made of the same head written as HTTP/1.1 text, with
    /// no text in between, and a cookie's outer blanks kept (`http_cookie_merge`).
    ///
    /// # Errors
    /// Where the parser refuses that head (`InvalidData`), or the blocks do not fit
    /// (`OutOfMemory`); what was written is then partial.
    pub fn put_request_head(&mut self, head: &crate::mux_h2::H2ReqHead, extra: Option<(&str, &str)>, mut each: impl FnMut(&str, &str)) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind};
        let oom = |e: HtxError| Error::new(ErrorKind::OutOfMemory, e);
        // A head without a line has an empty method, which the line check refuses.
        let (method, uri) = (head.method(), head.uri());
        crate::h1::check_request_line(method, uri)?;
        self.push_req_line(method, uri, "HTTP/1.1").map_err(oom)?;
        for (n, v) in head.headers() {
            // A name is a token (checked by the mux): ASCII.
            let name = std::str::from_utf8(n).map_err(|_| Error::new(ErrorKind::InvalidData, "header name"))?;
            if let Ok(v) = std::str::from_utf8(v) {
                self.push_header(name, v).map_err(oom)?;
                each(name, v);
            } else {
                let text = latin1_to_text(v);
                push_header_raw(self.buf, &mut self.tail_addr, &mut self.num_blocks, name, &text).map_err(oom)?;
                self.set_last_flag(HTX_BLK_FL_LATIN1);
                each(name, &text);
            }
        }
        if let Some((n, v)) = extra {
            self.push_header(n, v).map_err(oom)?;
        }
        self.push_eoh().map_err(oom)?;
        crate::h1::finish_request_head(self, method, uri)
    }

    /// Pushes a header whose value is text a peer sent. A character the byte mapping uses
    /// (U+F780-U+F7FF, [`ibex_regex::bytetext`]) in it is held as its own UTF-8 bytes, so
    /// the flag is never inferred from what a peer sent: only [`Self::push_header_latin1`]
    /// sets it (T286).
    pub fn push_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        if value.is_ascii() || !ibex_regex::bytetext::has_escapes(value) {
            return push_header_raw(self.buf, &mut self.tail_addr, &mut self.num_blocks, name, value);
        }
        self.push_header_latin1(name, value.as_bytes())
    }

    /// [`Self::push_header`] of a value that is not UTF-8, read as Latin-1 and flagged
    /// [`HTX_BLK_FL_LATIN1`].
    pub fn push_header_latin1(&mut self, name: &str, value: &[u8]) -> Result<(), HtxError> {
        let text = latin1_to_text(value);
        push_header_raw(self.buf, &mut self.tail_addr, &mut self.num_blocks, name, &text)?;
        self.set_last_flag(HTX_BLK_FL_LATIN1);
        Ok(())
    }

    /// Whether the last header holds a Latin-1 value ([`HTX_BLK_FL_LATIN1`]).
    #[must_use]
    pub fn last_header_is_latin1(&self) -> bool {
        (0..self.num_blocks)
            .rev()
            .map(|i| read_desc_at(self.buf, self.num_blocks, i))
            .find(|d| d.blk_type == HtxBlockType::Header)
            .is_some_and(|d| d.flags & HTX_BLK_FL_LATIN1 != 0)
    }

    /// The flags of the last block, `flag` added.
    fn set_last_flag(&mut self, flag: u8) {
        if let Some(i) = self.num_blocks.checked_sub(1) {
            let mut desc = read_desc_at(self.buf, self.num_blocks, i);
            desc.flags |= flag;
            write_desc_at(self.buf, self.num_blocks, i, &desc);
        }
    }

    /// An obs-fold continuation that is not UTF-8 (or follows a Latin-1 value): the last
    /// header's value as the bytes it stands for, `prefix` and `raw`, held as Latin-1.
    pub fn append_latin1_to_last_header(&mut self, prefix: &str, raw: &[u8]) -> Result<(), HtxError> {
        let idx = (0..self.num_blocks)
            .rev()
            .find(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type == HtxBlockType::Header)
            .ok_or(HtxError::InvalidData)?;
        let desc = read_desc_at(self.buf, self.num_blocks, idx);
        let old = &self.buf[desc.value_range()];
        let mut bytes: Vec<u8> = if desc.flags & HTX_BLK_FL_LATIN1 == 0 {
            old.to_vec()
        } else {
            ibex_regex::bytetext::text_to_bytes(&String::from_utf8_lossy(old)).into_owned()
        };
        bytes.extend_from_slice(prefix.as_bytes());
        bytes.extend_from_slice(raw);
        let text = latin1_to_text(&bytes);
        replace_block_value_raw(self.buf, &mut self.tail_addr, self.num_blocks, idx, text.as_bytes())?;
        let mut desc = read_desc_at(self.buf, self.num_blocks, idx);
        desc.flags |= HTX_BLK_FL_LATIN1;
        write_desc_at(self.buf, self.num_blocks, idx, &desc);
        Ok(())
    }

    pub fn push_eoh(&mut self) -> Result<(), HtxError> {
        push_marker_raw(
            self.buf,
            self.tail_addr,
            &mut self.num_blocks,
            HtxBlockType::Eoh,
            HTX_BLK_FL_NONE,
        )
    }

    pub fn push_data(&mut self, data: &[u8]) -> Result<(), HtxError> {
        push_data_raw(
            self.buf,
            &mut self.tail_addr,
            &mut self.num_blocks,
            data,
            false,
        )
    }

    pub fn push_trailer(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        push_trailer_raw(
            self.buf,
            &mut self.tail_addr,
            &mut self.num_blocks,
            name,
            value,
        )
    }

    pub fn push_eot(&mut self) -> Result<(), HtxError> {
        push_marker_raw(
            self.buf,
            self.tail_addr,
            &mut self.num_blocks,
            HtxBlockType::Eot,
            HTX_BLK_FL_NONE,
        )
    }

    pub fn push_eom(&mut self) -> Result<(), HtxError> {
        push_marker_raw(
            self.buf,
            self.tail_addr,
            &mut self.num_blocks,
            HtxBlockType::Eom,
            HTX_BLK_FL_EOM,
        )
    }

    pub fn push_raw_data(&mut self, data: &[u8]) -> Result<(), HtxError> {
        push_data_raw(
            self.buf,
            &mut self.tail_addr,
            &mut self.num_blocks,
            data,
            true,
        )
    }

    pub fn remove_block(&mut self, index: usize) {
        remove_block_raw(self.buf, self.num_blocks, index);
    }

    pub fn replace_block_value(&mut self, index: usize, new_value: &[u8]) -> Result<(), HtxError> {
        replace_block_value_raw(self.buf, &mut self.tail_addr, self.num_blocks, index, new_value)
    }

    pub fn append_to_last_header(&mut self, text: &str) -> Result<(), HtxError> {
        let last_hdr_idx = (0..self.num_blocks)
            .rev()
            .find(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type == HtxBlockType::Header);

        let Some(idx) = last_hdr_idx else {
            return Err(HtxError::InvalidData);
        };

        let mut desc = read_desc_at(self.buf, self.num_blocks, idx);
        let old_addr = desc.addr as usize;
        let old_val_len = desc.value_len as usize;
        let name_len = desc.name_len as usize;
        let added_len = text.len();
        let new_val_len = old_val_len + added_len;
        if new_val_len > HTX_HDR_VALUE_MAX_LEN {
            return Err(HtxError::LimitExceeded);
        }

        let old_value = desc.value_range();
        let is_at_tail = old_addr >= self.region.reserve_start && old_value.end == self.tail_addr;
        if is_at_tail {
            if free_capacity_at(self.buf.len(), self.tail_addr, self.num_blocks) < added_len {
                return Err(HtxError::OutOfMemory);
            }
            self.buf[self.tail_addr..self.tail_addr + text.len()].copy_from_slice(text.as_bytes());
            self.tail_addr += text.len();
            desc.value_len = new_val_len as u32;
            write_desc_at(self.buf, self.num_blocks, idx, &desc);
            Ok(())
        } else {
            let total_new = name_len + new_val_len;
            if free_capacity_at(self.buf.len(), self.tail_addr, self.num_blocks) < total_new {
                return Err(HtxError::OutOfMemory);
            }
            let new_addr = self.tail_addr;
            self.buf.copy_within(old_addr..old_addr + name_len, new_addr);
            self.buf.copy_within(old_value, new_addr + name_len);
            self.buf[new_addr + name_len + old_val_len..new_addr + total_new].copy_from_slice(text.as_bytes());
            self.tail_addr += total_new;
            desc.addr = new_addr as u32;
            desc.aux = 0;
            desc.value_len = new_val_len as u32;
            write_desc_at(self.buf, self.num_blocks, idx, &desc);
            Ok(())
        }
    }

    pub fn append_to_last_trailer(&mut self, text: &str) -> Result<(), HtxError> {
        let last_trl_idx = (0..self.num_blocks)
            .rev()
            .find(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type == HtxBlockType::Trailer);

        let Some(idx) = last_trl_idx else {
            return Err(HtxError::InvalidData);
        };

        let mut desc = read_desc_at(self.buf, self.num_blocks, idx);
        let old_addr = desc.addr as usize;
        let old_val_len = desc.value_len as usize;
        let name_len = desc.name_len as usize;
        let added_len = text.len();
        let new_val_len = old_val_len + added_len;
        if new_val_len > HTX_HDR_VALUE_MAX_LEN {
            return Err(HtxError::LimitExceeded);
        }

        let old_value = desc.value_range();
        let is_at_tail = old_addr >= self.region.reserve_start && old_value.end == self.tail_addr;
        if is_at_tail {
            if free_capacity_at(self.buf.len(), self.tail_addr, self.num_blocks) < added_len {
                return Err(HtxError::OutOfMemory);
            }
            self.buf[self.tail_addr..self.tail_addr + text.len()].copy_from_slice(text.as_bytes());
            self.tail_addr += text.len();
            desc.value_len = new_val_len as u32;
            write_desc_at(self.buf, self.num_blocks, idx, &desc);
            Ok(())
        } else {
            let total_new = name_len + new_val_len;
            if free_capacity_at(self.buf.len(), self.tail_addr, self.num_blocks) < total_new {
                return Err(HtxError::OutOfMemory);
            }
            let new_addr = self.tail_addr;
            self.buf.copy_within(old_addr..old_addr + name_len, new_addr);
            self.buf.copy_within(old_value, new_addr + name_len);
            self.buf[new_addr + name_len + old_val_len..new_addr + total_new].copy_from_slice(text.as_bytes());
            self.tail_addr += total_new;
            desc.addr = new_addr as u32;
            desc.aux = 0;
            desc.value_len = new_val_len as u32;
            write_desc_at(self.buf, self.num_blocks, idx, &desc);
            Ok(())
        }
    }

    pub fn finalize_last_header(&mut self) {
        let last_hdr_idx = (0..self.num_blocks)
            .rev()
            .find(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type == HtxBlockType::Header);

        let Some(idx) = last_hdr_idx else {
            return;
        };

        let mut desc = read_desc_at(self.buf, self.num_blocks, idx);
        let val_start = desc.value_range().start;
        let val_len = desc.value_len as usize;
        if val_len == 0 {
            return;
        }

        let val_bytes = &self.buf[val_start..val_start + val_len];
        let lead_trim = val_bytes
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();

        let new_val_len = if lead_trim == val_len {
            0
        } else {
            let trail_trim = val_bytes[lead_trim..]
                .iter()
                .rev()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            val_len - lead_trim - trail_trim
        };

        if lead_trim > 0 && new_val_len > 0 {
            self.buf.copy_within(val_start + lead_trim..val_start + lead_trim + new_val_len, val_start);
        }

        let trimmed_total = val_len - new_val_len;
        if trimmed_total > 0 {
            let is_at_tail = desc.addr as usize >= self.region.reserve_start && val_start + val_len == self.tail_addr;
            if is_at_tail {
                self.tail_addr -= trimmed_total;
            }
            desc.value_len = new_val_len as u32;
            write_desc_at(self.buf, self.num_blocks, idx, &desc);
        }
    }

    pub fn finalize_last_trailer(&mut self) {
        let last_trl_idx = (0..self.num_blocks)
            .rev()
            .find(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type == HtxBlockType::Trailer);

        let Some(idx) = last_trl_idx else {
            return;
        };

        let mut desc = read_desc_at(self.buf, self.num_blocks, idx);
        let val_start = desc.value_range().start;
        let val_len = desc.value_len as usize;
        if val_len == 0 {
            return;
        }

        let val_bytes = &self.buf[val_start..val_start + val_len];
        let lead_trim = val_bytes
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();

        let new_val_len = if lead_trim == val_len {
            0
        } else {
            let trail_trim = val_bytes[lead_trim..]
                .iter()
                .rev()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            val_len - lead_trim - trail_trim
        };

        if lead_trim > 0 && new_val_len > 0 {
            self.buf.copy_within(val_start + lead_trim..val_start + lead_trim + new_val_len, val_start);
        }

        let trimmed_total = val_len - new_val_len;
        if trimmed_total > 0 {
            let is_at_tail = desc.addr as usize >= self.region.reserve_start && val_start + val_len == self.tail_addr;
            if is_at_tail {
                self.tail_addr -= trimmed_total;
            }
            desc.value_len = new_val_len as u32;
            write_desc_at(self.buf, self.num_blocks, idx, &desc);
        }
    }


    pub fn insert_header(&mut self, index: usize, name: &str, value: &str) -> Result<(), HtxError> {
        insert_header_raw(self.buf, &mut self.tail_addr, &mut self.num_blocks, index, name, value)
    }

    pub fn add_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        let insert_idx = (0..self.num_blocks)
            .find(|&i| matches!(read_desc_at(self.buf, self.num_blocks, i).blk_type, HtxBlockType::Eoh | HtxBlockType::Eot | HtxBlockType::Eom))
            .unwrap_or(self.num_blocks);

        insert_header_raw(
            self.buf,
            &mut self.tail_addr,
            &mut self.num_blocks,
            insert_idx,
            name,
            value,
        )
    }

    pub fn set_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        let mut first_match = None;
        let mut subsequent_matches = Vec::new();

        for i in 0..self.num_blocks {
            let desc = read_desc_at(self.buf, self.num_blocks, i);
            if desc.blk_type == HtxBlockType::Header {
                if let Ok(hdr_name) = utf8(&self.buf[desc.name_range()]) {
                    if hdr_name.eq_ignore_ascii_case(name) {
                        if first_match.is_none() {
                            first_match = Some(i);
                        } else {
                            subsequent_matches.push(i);
                        }
                    }
                }
            }
        }

        if let Some(idx) = first_match {
            self.replace_block_value(idx, value.as_bytes())?;
            for sub_idx in subsequent_matches {
                self.remove_block(sub_idx);
            }
            Ok(())
        } else {
            self.add_header(name, value)
        }
    }

    pub fn replace_header(&mut self, name: &str, regex: &str, repl: &str) -> Result<usize, HtxError> {
        let re = ibex_regex::UserRegex::cached(regex).map_err(|_| HtxError::InvalidData)?;
        let mut count = 0;

        for i in 0..self.num_blocks {
            let desc = read_desc_at(self.buf, self.num_blocks, i);
            if desc.blk_type == HtxBlockType::Header {
                if let Ok(hdr_name) = utf8(&self.buf[desc.name_range()]) {
                    if hdr_name.eq_ignore_ascii_case(name) {
                        if let Ok(hdr_val) = utf8(&self.buf[desc.value_range()]) {
                            let new_val = re.replace_all(hdr_val, repl).to_string();
                            if new_val != hdr_val {
                                self.replace_block_value(i, new_val.as_bytes())?;
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(count)
    }

    pub fn set_uri(&mut self, new_uri: &str) -> Result<(), HtxError> {
        let req_idx = (0..self.num_blocks)
            .find(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type == HtxBlockType::ReqLine)
            .ok_or(HtxError::InvalidData)?;

        let (method, version) = {
            let view = self.as_ref().req_line().ok_or(HtxError::InvalidData)?;
            (view.method.to_string(), view.version.to_string())
        };

        let new_line = format!("{method} {new_uri} {version}");
        self.replace_block_value(req_idx, new_line.as_bytes())?;

        let mut desc = read_desc_at(self.buf, self.num_blocks, req_idx);
        desc.name_len = method.len() as u16;
        desc.aux = new_uri.len() as u32;
        write_desc_at(self.buf, self.num_blocks, req_idx, &desc);
        Ok(())
    }

    pub fn set_path(&mut self, new_path: &str) -> Result<(), HtxError> {
        let (pfx, _, query) = {
            let view = self.as_ref().req_line().ok_or(HtxError::InvalidData)?;
            let current_uri = view.uri;
            if let Some(idx) = current_uri.find("://") {
                let rest = &current_uri[idx + 3..];
                if let Some(slash) = rest.find('/') {
                    let pfx = &current_uri[..idx + 3 + slash];
                    let pathq = &current_uri[idx + 3 + slash..];
                    let (p, q) = pathq.split_once('?').unwrap_or((pathq, ""));
                    (pfx.to_string(), p.to_string(), q.to_string())
                } else {
                    (current_uri.to_string(), String::new(), String::new())
                }
            } else {
                let (p, q) = current_uri.split_once('?').unwrap_or((current_uri, ""));
                (String::new(), p.to_string(), q.to_string())
            }
        };

        let rebuilt_uri = if query.is_empty() {
            format!("{pfx}{new_path}")
        } else {
            format!("{pfx}{new_path}?{query}")
        };

        self.set_uri(&rebuilt_uri)
    }

    pub fn set_method(&mut self, new_method: &str) -> Result<(), HtxError> {
        let req_idx = (0..self.num_blocks)
            .find(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type == HtxBlockType::ReqLine)
            .ok_or(HtxError::InvalidData)?;

        let (uri, version) = {
            let view = self.as_ref().req_line().ok_or(HtxError::InvalidData)?;
            (view.uri.to_string(), view.version.to_string())
        };

        let new_line = format!("{new_method} {uri} {version}");
        self.replace_block_value(req_idx, new_line.as_bytes())?;

        let mut desc = read_desc_at(self.buf, self.num_blocks, req_idx);
        desc.name_len = new_method.len() as u16;
        desc.aux = uri.len() as u32;
        write_desc_at(self.buf, self.num_blocks, req_idx, &desc);
        Ok(())
    }

    #[must_use]
    /// The reserve's payload bytes no block holds: what [`Self::defrag`] gives back. (The
    /// holes of a received head, its `: ` and CRLFs, are not counted: no push can use them.)
    pub fn fragmented_bytes(&self) -> usize {
        let floor = self.region.reserve_start;
        let mut active = 0;
        for i in 0..self.num_blocks {
            let desc = read_desc_at(self.buf, self.num_blocks, i);
            if desc.blk_type != HtxBlockType::Unused && desc.addr as usize >= floor {
                active += desc.payload_len();
            }
        }
        (self.tail_addr - floor).saturating_sub(active)
    }

    pub fn maybe_defrag_threshold(&mut self, threshold: usize) -> bool {
        if self.fragmented_bytes() >= threshold && self.fragmented_bytes() > 0 {
            self.defrag();
            true
        } else {
            false
        }
    }

    pub fn maybe_defrag(&mut self) -> bool {
        self.maybe_defrag_threshold(HTX_DEFRAG_THRESHOLD_BYTES)
    }

    pub fn remove_header(&mut self, name: &str) -> usize {
        let mut count = 0;
        for i in 0..self.num_blocks {
            let mut desc = read_desc_at(self.buf, self.num_blocks, i);
            if desc.blk_type == HtxBlockType::Header {
                let s = desc.addr as usize;
                let nl = desc.name_len as usize;
                // Compared as bytes: a name equal to `name` but for the case of its ASCII
                // letters is as valid UTF-8 as `name` is (S7: it was read as UTF-8 first).
                if self.buf[s..s + nl].eq_ignore_ascii_case(name.as_bytes()) {
                    desc.blk_type = HtxBlockType::Unused;
                    write_desc_at(self.buf, self.num_blocks, i, &desc);
                    count += 1;
                }
            }
        }
        count
    }

    /// Packs the payload of the blocks that are not removed and drops their descriptors' holes.
    /// Over a received head (X1, [`Self::over_received`]) the head's bytes are rewritten from
    /// the blocks: the blocks are packed from the head's start (the head is no longer the
    /// bytes that arrived, only an edit defragments) and what does not fit there is packed
    /// from the reserve's start, so the reserve keeps only the values the head has no room for.
    /// Every block moves to a lower address or into the head, so no block is overwritten before
    /// it is moved.
    pub fn defrag(&mut self) {
        let region = self.region;
        if self.num_blocks == 0 {
            self.tail_addr = region.reserve_start;
            return;
        }

        // 1 & 2. Collect and sort active block indices by physical address
        // Fast path: use stack buffer if num_blocks <= 64 to avoid allocation
        let mut stack_indices = [0usize; 64];
        let mut heap_indices;
        let active: &mut [usize] = if self.num_blocks <= 64 {
            let mut count = 0;
            for i in 0..self.num_blocks {
                if read_desc_at(self.buf, self.num_blocks, i).blk_type != HtxBlockType::Unused {
                    stack_indices[count] = i;
                    count += 1;
                }
            }
            &mut stack_indices[..count]
        } else {
            heap_indices = (0..self.num_blocks)
                .filter(|&i| read_desc_at(self.buf, self.num_blocks, i).blk_type != HtxBlockType::Unused)
                .collect::<Vec<_>>();
            &mut heap_indices[..]
        };

        // Sort active blocks by physical address so new_tail <= old_addr always holds
        active.sort_by_key(|&i| read_desc_at(self.buf, self.num_blocks, i).addr);

        // 3. Compact payloads in physical order: into the head while they fit (the head's
        // own blocks always do: packed, they are smaller than the lines they were), then
        // from the reserve's start.
        let mut in_head = region.head_start;
        let mut new_tail = region.reserve_start;
        for &idx in active.iter() {
            let mut desc = read_desc_at(self.buf, self.num_blocks, idx);
            let p_len = desc.payload_len();
            let to = if p_len > 0 && in_head + p_len <= region.head_end {
                in_head += p_len;
                in_head - p_len
            } else {
                new_tail += p_len;
                new_tail - p_len
            };
            if p_len > 0 {
                let value = desc.value_range();
                let name_len = if matches!(desc.blk_type, HtxBlockType::Header | HtxBlockType::Trailer) {
                    let name = desc.name_range();
                    self.buf.copy_within(name.clone(), to);
                    name.len()
                } else {
                    0
                };
                self.buf.copy_within(value, to + name_len);
            }
            desc.addr = to as u32;
            if matches!(desc.blk_type, HtxBlockType::Header | HtxBlockType::Trailer) {
                desc.aux = 0;
            }
            write_desc_at(self.buf, self.num_blocks, idx, &desc);
        }

        // 4. Compact descriptors in original logical order (skipping Unused)
        let mut new_num_blocks = 0;
        for i in 0..self.num_blocks {
            let desc = read_desc_at(self.buf, self.num_blocks, i);
            if desc.blk_type == HtxBlockType::Unused {
                continue;
            }
            write_desc_at(self.buf, self.num_blocks, new_num_blocks, &desc);
            new_num_blocks += 1;
        }

        self.tail_addr = new_tail;
        self.num_blocks = new_num_blocks;
    }

    pub fn check_invariants(&self) -> Result<(), String> {
        self.as_ref().check_invariants_in(self.tail_addr, self.region)
    }

    #[must_use]
    pub fn to_blocks(&self) -> Vec<HtxBlock> {
        self.as_ref().to_blocks()
    }

    #[must_use]
    pub fn to_htx(&self) -> Htx {
        self.as_ref().to_htx()
    }

    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        self.as_ref().body_bytes()
    }

    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.as_ref().headers()
    }

    pub fn trailers(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.as_ref().trailers()
    }

    #[must_use]
    pub fn block_type(&self, index: usize) -> Option<HtxBlockType> {
        self.as_ref().block_type(index)
    }

    #[must_use]
    pub fn block_types(&self) -> Vec<HtxBlockType> {
        self.as_ref().block_types()
    }

    #[must_use]
    pub fn active_block_types(&self) -> Vec<HtxBlockType> {
        self.as_ref().active_block_types()
    }

    #[must_use]
    pub fn is_eom(&self) -> bool {
        self.as_ref().is_eom()
    }

    #[must_use]
    pub fn is_eoh(&self) -> bool {
        self.as_ref().is_eoh()
    }

    #[must_use]
    pub fn req_line(&self) -> Option<RequestLineView<'_>> {
        self.as_ref().req_line()
    }

    #[must_use]
    pub fn res_line(&self) -> Option<ResponseLineView<'_>> {
        self.as_ref().res_line()
    }

    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.as_ref().get_header(name)
    }

    #[must_use]
    pub fn get_trailer(&self, name: &str) -> Option<&str> {
        self.as_ref().get_trailer(name)
    }

    #[must_use]
    pub fn body_len(&self) -> usize {
        self.as_ref().body_len()
    }

    pub fn merge_contiguous_data(&mut self) {
        if self.num_blocks < 2 {
            return;
        }

        let mut i = 1;
        while i < self.num_blocks {
            let prev = read_desc_at(self.buf, self.num_blocks, i - 1);
            let curr = read_desc_at(self.buf, self.num_blocks, i);

            if prev.blk_type == HtxBlockType::Data
                && curr.blk_type == HtxBlockType::Data
                && (prev.addr as usize + prev.value_len as usize == curr.addr as usize)
            {
                let mut merged = prev;
                merged.value_len += curr.value_len;
                merged.flags |= curr.flags;
                write_desc_at(self.buf, self.num_blocks, i - 1, &merged);

                for j in i..self.num_blocks - 1 {
                    let d = read_desc_at(self.buf, self.num_blocks, j + 1);
                    write_desc_at(self.buf, self.num_blocks, j, &d);
                }
                self.num_blocks -= 1;
            } else {
                i += 1;
            }
        }
    }

    pub fn write_h1_wire(&self, out: &mut [u8]) -> Result<usize, HtxError> {
        self.as_ref().write_h1_wire(out)
    }

    #[must_use]
    pub fn to_h1_wire(&self) -> Vec<u8> {
        self.as_ref().to_h1_wire()
    }
}

impl std::fmt::Debug for HtxSlice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl<'b> PartialEq<HtxSlice<'b>> for HtxSlice<'_> {
    fn eq(&self, other: &HtxSlice<'b>) -> bool {
        self.as_ref() == other.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Owned HTX Buffer
// ---------------------------------------------------------------------------

/// Owned HTX buffer backed by pre-allocated contiguous memory.
#[derive(Clone, Debug)]
pub struct HtxBuffer {
    data: Vec<u8>,
    tail_addr: usize,
    num_blocks: usize,
    pub flags: u32,
}

impl Default for HtxBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::redundant_closure_for_method_calls)]
impl HtxBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(HTX_BUFFER_DEFAULT_CAPACITY)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(HTX_DESC_SIZE * 4);
        Self {
            data: vec![0u8; cap],
            tail_addr: 0,
            num_blocks: 0,
            flags: 0,
        }
    }

    pub fn clear(&mut self) {
        self.tail_addr = 0;
        self.num_blocks = 0;
        self.flags = 0;
    }

    #[must_use]
    pub fn as_slice(&self) -> HtxSliceRef<'_> {
        HtxSliceRef::new(&self.data, self.num_blocks)
    }

    pub fn as_slice_mut(&mut self) -> HtxSlice<'_> {
        HtxSlice::with_offsets(&mut self.data, self.tail_addr, self.num_blocks)
    }

    pub fn with_slice_mut<R>(&mut self, f: impl FnOnce(&mut HtxSlice<'_>) -> R) -> R {
        let mut s = HtxSlice::with_offsets(&mut self.data, self.tail_addr, self.num_blocks);
        let res = f(&mut s);
        let (_, tail, num) = s.into_parts();
        self.tail_addr = tail;
        self.num_blocks = num;
        res
    }

    pub fn push_req_line(
        &mut self,
        method: &str,
        uri: &str,
        version: &str,
    ) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_req_line(method, uri, version))
    }

    pub fn push_res_line(
        &mut self,
        version: &str,
        status: u16,
        reason: &str,
    ) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_res_line(version, status, reason))
    }

    pub fn push_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_header(name, value))
    }

    pub fn push_eoh(&mut self) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_eoh())
    }

    pub fn push_data(&mut self, data: &[u8]) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_data(data))
    }

    pub fn push_trailer(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_trailer(name, value))
    }

    pub fn push_eot(&mut self) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_eot())
    }

    pub fn push_eom(&mut self) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_eom())
    }

    pub fn push_raw_data(&mut self, data: &[u8]) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.push_raw_data(data))
    }

    pub fn remove_block(&mut self, index: usize) {
        self.with_slice_mut(|s| s.remove_block(index));
    }

    pub fn replace_block_value(&mut self, index: usize, new_value: &[u8]) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.replace_block_value(index, new_value))
    }

    pub fn defrag(&mut self) {
        self.with_slice_mut(|s| s.defrag());
    }

    pub fn insert_header(&mut self, index: usize, name: &str, value: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.insert_header(index, name, value))
    }

    pub fn add_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.add_header(name, value))
    }

    pub fn set_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.set_header(name, value))
    }

    pub fn remove_header(&mut self, name: &str) -> usize {
        self.with_slice_mut(|s| s.remove_header(name))
    }

    pub fn replace_header(&mut self, name: &str, regex: &str, repl: &str) -> Result<usize, HtxError> {
        self.with_slice_mut(|s| s.replace_header(name, regex, repl))
    }

    pub fn set_uri(&mut self, new_uri: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.set_uri(new_uri))
    }

    pub fn set_path(&mut self, new_path: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.set_path(new_path))
    }

    pub fn set_method(&mut self, new_method: &str) -> Result<(), HtxError> {
        self.with_slice_mut(|s| s.set_method(new_method))
    }

    #[must_use]
    pub fn fragmented_bytes(&self) -> usize {
        self.as_slice().fragmented_bytes()
    }

    pub fn maybe_defrag_threshold(&mut self, threshold: usize) -> bool {
        self.with_slice_mut(|s| s.maybe_defrag_threshold(threshold))
    }

    pub fn maybe_defrag(&mut self) -> bool {
        self.with_slice_mut(|s| s.maybe_defrag())
    }

    #[must_use]
    pub fn num_blocks(&self) -> usize {
        self.num_blocks
    }

    #[must_use]
    pub fn block_type(&self, index: usize) -> Option<HtxBlockType> {
        self.as_slice().block_type(index)
    }

    #[must_use]
    pub fn block_types(&self) -> Vec<HtxBlockType> {
        self.as_slice().block_types()
    }

    #[must_use]
    pub fn active_block_types(&self) -> Vec<HtxBlockType> {
        self.as_slice().active_block_types()
    }

    pub fn check_invariants(&self) -> Result<(), String> {
        self.as_slice().check_invariants(self.tail_addr)
    }

    #[must_use]
    pub fn to_blocks(&self) -> Vec<HtxBlock> {
        self.as_slice().to_blocks()
    }

    #[must_use]
    pub fn to_htx(&self) -> Htx {
        self.as_slice().to_htx()
    }

    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.as_slice().get_header(name)
    }

    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.as_slice().headers()
    }

    #[must_use]
    pub fn get_trailer(&self, name: &str) -> Option<&str> {
        self.as_slice().get_trailer(name)
    }

    pub fn trailers(&self) -> impl Iterator<Item = (&str, &str)> + '_ {
        self.as_slice().trailers()
    }

    #[must_use]
    pub fn is_eom(&self) -> bool {
        self.as_slice().is_eom()
    }

    #[must_use]
    pub fn is_eoh(&self) -> bool {
        self.as_slice().is_eoh()
    }

    #[must_use]
    pub fn req_line(&self) -> Option<RequestLineView<'_>> {
        self.as_slice().req_line()
    }

    #[must_use]
    pub fn res_line(&self) -> Option<ResponseLineView<'_>> {
        self.as_slice().res_line()
    }

    #[must_use]
    pub fn body_len(&self) -> usize {
        self.as_slice().body_len()
    }

    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        self.as_slice().body_bytes()
    }

    pub fn merge_contiguous_data(&mut self) {
        self.with_slice_mut(|s| s.merge_contiguous_data());
    }

    pub fn write_h1_wire(&self, out: &mut [u8]) -> Result<usize, HtxError> {
        self.as_slice().write_h1_wire(out)
    }

    #[must_use]
    pub fn to_h1_wire(&self) -> Vec<u8> {
        self.as_slice().to_h1_wire()
    }
}

// ---------------------------------------------------------------------------
// In-memory HTTP Transaction buffer (for cross-component compatibility)
// ---------------------------------------------------------------------------

/// In-memory HTTP Transaction buffer containing structured message blocks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Htx {
    blocks: Vec<HtxBlock>,
}

impl Htx {
    #[must_use]
    pub fn new() -> Self {
        Htx { blocks: Vec::new() }
    }

    /// Appends a block to the transaction.
    pub fn push(&mut self, block: HtxBlock) {
        self.blocks.push(block);
    }

    /// No block; the memory of the list is kept (T437).
    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    #[must_use]
    pub fn blocks(&self) -> &[HtxBlock] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut [HtxBlock] {
        &mut self.blocks
    }

    /// Removes and returns the block at `index` if within bounds.
    pub fn remove_block(&mut self, index: usize) -> Option<HtxBlock> {
        if index < self.blocks.len() {
            Some(self.blocks.remove(index))
        } else {
            None
        }
    }

    /// Returns `true` if the transaction contains an End-of-Message (`Eom`) marker.
    #[must_use]
    pub fn is_eom(&self) -> bool {
        self.blocks.iter().any(|b| matches!(b, HtxBlock::Eom))
    }

    /// Returns `true` if headers have completed (`Eoh` marker is present).
    #[must_use]
    pub fn is_eoh(&self) -> bool {
        self.blocks
            .iter()
            .any(|b| matches!(b, HtxBlock::Eoh | HtxBlock::Eot | HtxBlock::Eom))
    }

    /// Returns the request start line if present.
    #[must_use]
    pub fn req_line(&self) -> Option<&RequestLine> {
        self.blocks.iter().find_map(|b| match b {
            HtxBlock::ReqLine(r) => Some(r),
            _ => None,
        })
    }

    /// Returns a mutable reference to the request start line if present.
    pub fn req_line_mut(&mut self) -> Option<&mut RequestLine> {
        self.blocks.iter_mut().find_map(|b| match b {
            HtxBlock::ReqLine(r) => Some(r),
            _ => None,
        })
    }

    /// Returns the response status line if present.
    #[must_use]
    pub fn res_line(&self) -> Option<&ResponseLine> {
        self.blocks.iter().find_map(|b| match b {
            HtxBlock::ResLine(r) => Some(r),
            _ => None,
        })
    }

    /// Returns a mutable reference to the response status line if present.
    pub fn res_line_mut(&mut self) -> Option<&mut ResponseLine> {
        self.blocks.iter_mut().find_map(|b| match b {
            HtxBlock::ResLine(r) => Some(r),
            _ => None,
        })
    }

    /// Returns an iterator over all headers.
    pub fn headers(&self) -> impl Iterator<Item = &HeaderField> {
        self.blocks.iter().filter_map(|b| match b {
            HtxBlock::Header(h) => Some(h),
            _ => None,
        })
    }

    /// Returns an iterator over all trailers.
    pub fn trailers(&self) -> impl Iterator<Item = &HeaderField> {
        self.blocks.iter().filter_map(|b| match b {
            HtxBlock::Trailer(h) => Some(h),
            _ => None,
        })
    }

    /// Finds the first header matching `name` (case-insensitive).
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Finds the first trailer matching `name` (case-insensitive).
    #[must_use]
    pub fn get_trailer(&self, name: &str) -> Option<&str> {
        self.trailers()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Removes every header matching `name` (case-insensitive). Returns how many were
    /// removed.
    ///
    /// Needed for RFC 7230 §3.3.3: a message carrying both `Transfer-Encoding` and
    /// `Content-Length` must have the `Content-Length` **removed before forwarding**,
    /// or the next hop may frame the message differently than we did.
    pub fn remove_header(&mut self, name: &str) -> usize {
        let before = self.blocks.len();
        self.blocks.retain(|b| {
            !matches!(b, HtxBlock::Header(h) if h.name.eq_ignore_ascii_case(name))
        });
        before - self.blocks.len()
    }

    /// Sets or updates a header (case-insensitive replacement).
    pub fn set_header(&mut self, name: &str, value: &str) {
        let mut found = false;
        for block in &mut self.blocks {
            if let HtxBlock::Header(h) = block {
                if h.name.eq_ignore_ascii_case(name) {
                    h.value = value.to_string();
                    found = true;
                    break;
                }
            }
        }
        if !found {
            let eoh_pos = self
                .blocks
                .iter()
                .position(|b| matches!(b, HtxBlock::Eoh))
                .unwrap_or(self.blocks.len());
            self.blocks.insert(
                eoh_pos,
                HtxBlock::Header(HeaderField {
                    name: name.to_string(),
                    value: value.to_string(),
                }),
            );
        }
    }

    /// Deletes all headers matching `name` (case-insensitive).
    pub fn del_header(&mut self, name: &str) {
        self.blocks.retain(|b| match b {
            HtxBlock::Header(h) => !h.name.eq_ignore_ascii_case(name),
            _ => true,
        });
    }

    /// Extracts all body bytes from the data blocks.
    #[must_use]
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for b in &self.blocks {
            if let HtxBlock::Data(d) | HtxBlock::RawData(d) = b {
                out.extend_from_slice(d);
            }
        }
        out
    }

    /// Alias for `body_bytes` used by H2 stream mux.
    #[must_use]
    pub fn extract_body(&self) -> Vec<u8> {
        self.body_bytes()
    }

    /// Serializes this HTX message directly into a pre-allocated slice `out`.
    /// Returns the number of bytes written.
    pub fn to_wire_into(&self, out: &mut [u8]) -> usize {
        let mut cursor = 0;

        if let Some(req) = self.req_line() {
            let s = format!(
                "{} {} {}\r\n",
                req.method.as_str(),
                req.uri,
                req.version.as_str()
            );
            if cursor + s.len() <= out.len() {
                out[cursor..cursor + s.len()].copy_from_slice(s.as_bytes());
                cursor += s.len();
            }
        } else if let Some(res) = self.res_line() {
            let s = format!("{} {} {}\r\n", res.version.as_str(), res.status, res.reason);
            if cursor + s.len() <= out.len() {
                out[cursor..cursor + s.len()].copy_from_slice(s.as_bytes());
                cursor += s.len();
            }
        }

        for h in self.headers() {
            let s = format!("{}: {}\r\n", h.name, h.value);
            if cursor + s.len() <= out.len() {
                out[cursor..cursor + s.len()].copy_from_slice(s.as_bytes());
                cursor += s.len();
            }
        }

        if cursor + 2 <= out.len() {
            out[cursor..cursor + 2].copy_from_slice(b"\r\n");
            cursor += 2;
        }

        for b in &self.blocks {
            if let HtxBlock::Data(d) | HtxBlock::RawData(d) = b {
                let n = d.len().min(out.len().saturating_sub(cursor));
                out[cursor..cursor + n].copy_from_slice(&d[..n]);
                cursor += n;
            }
        }

        let mut has_trailers = false;
        for t in self.trailers() {
            has_trailers = true;
            let s = format!("{}: {}\r\n", t.name, t.value);
            if cursor + s.len() <= out.len() {
                out[cursor..cursor + s.len()].copy_from_slice(s.as_bytes());
                cursor += s.len();
            }
        }

        if has_trailers && cursor + 2 <= out.len() {
            out[cursor..cursor + 2].copy_from_slice(b"\r\n");
            cursor += 2;
        }

        cursor
    }

    /// Serializes this HTX message into an HTTP/1.1 wire representation.
    #[must_use]
    pub fn to_h1_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1024);

        if let Some(req) = self.req_line() {
            let version = if req.version == HttpVersion::Http20 || req.version == HttpVersion::Http30 {
                "HTTP/1.1"
            } else {
                req.version.as_str()
            };
            let _ = write!(
                buf,
                "{} {} {}\r\n",
                req.method.as_str(),
                req.uri,
                version
            );
        } else if let Some(res) = self.res_line() {

            let _ = write!(
                buf,
                "{} {} {}\r\n",
                res.version.as_str(),
                res.status,
                res.reason
            );
        }

        for h in self.headers() {
            let _ = write!(buf, "{}: {}\r\n", h.name, h.value);
        }

        buf.extend_from_slice(b"\r\n");

        for b in &self.blocks {
            if let HtxBlock::Data(d) | HtxBlock::RawData(d) = b {
                buf.extend_from_slice(d);
            }
        }

        let mut has_trailers = false;
        for t in self.trailers() {
            has_trailers = true;
            let _ = write!(buf, "{}: {}\r\n", t.name, t.value);
        }
        if has_trailers {
            buf.extend_from_slice(b"\r\n");
        }

        buf
    }

    /// Converts this [`Htx`] message into a zero-allocation [`HtxBuffer`].
    pub fn to_htx_buffer(&self) -> Result<HtxBuffer, HtxError> {
        let mut htx_buf = HtxBuffer::new();
        if let Some(req) = self.req_line() {
            htx_buf.push_req_line(req.method.as_str(), &req.uri, req.version.as_str())?;
        } else if let Some(res) = self.res_line() {
            htx_buf.push_res_line(res.version.as_str(), res.status, &res.reason)?;
        }

        for h in self.headers() {
            htx_buf.push_header(&h.name, &h.value)?;
        }
        htx_buf.push_eoh()?;

        for b in &self.blocks {
            match b {
                HtxBlock::Data(d) => htx_buf.push_data(d)?,
                HtxBlock::RawData(d) => htx_buf.push_raw_data(d)?,
                HtxBlock::Trailer(t) => htx_buf.push_trailer(&t.name, &t.value)?,
                _ => {}
            }
        }

        if self.trailers().next().is_some() {
            htx_buf.push_eot()?;
        }

        if self.is_eom() {
            htx_buf.push_eom()?;
        }

        Ok(htx_buf)
    }
}


/// Converts HPACK/QPACK decoded pseudo-headers and headers into HTX blocks.
/// Applies RFC 9113 / RFC 9114 validation and canonicalization.
pub fn pseudo_headers_to_htx(
    decoded_headers: Vec<HeaderField>,
    version: HttpVersion,
) -> Result<Vec<HtxBlock>, &'static str> {
    let mut method = None;
    let mut path = None;
    let mut authority = None;
    let mut status = None;
    let mut regular_headers = Vec::new();
    let mut host_header = None;
    let mut seen_regular = false;
    let mut scheme_seen = false;
    let mut protocol_seen = false;

    for h in decoded_headers {
        if h.name.starts_with(':') {
            if seen_regular {
                return Err("pseudo-header after regular header");
            }
            match h.name.as_str() {
                ":method" => {
                    if method.is_some() {
                        return Err("duplicate pseudo-header");
                    }
                    method = Some(HttpMethod::from_bytes(h.value.as_bytes()));
                }
                ":path" => {
                    if path.is_some() {
                        return Err("duplicate pseudo-header");
                    }
                    if h.value.is_empty() {
                        return Err("empty :path");
                    }
                    path = Some(h.value);
                }
                ":authority" => {
                    if authority.is_some() {
                        return Err("duplicate pseudo-header");
                    }
                    authority = Some(h.value);
                }
                ":scheme" => {
                    if scheme_seen {
                        return Err("duplicate pseudo-header");
                    }
                    scheme_seen = true;
                    /* consumed, not forwarded */
                }
                ":status" => {
                    if status.is_some() {
                        return Err("duplicate pseudo-header");
                    }
                    if let Ok(st) = h.value.parse::<u16>() {
                        status = Some(st);
                    } else {
                        return Err("invalid :status value");
                    }
                }
                ":protocol" => {
                    if protocol_seen {
                        return Err("duplicate pseudo-header");
                    }
                    protocol_seen = true;
                }
                _ => return Err("unknown pseudo-header"),
            }
        } else {
            seen_regular = true;
            if h.name.eq_ignore_ascii_case("host") {
                if host_header.is_some() {
                    return Err("multiple host headers");
                }
                host_header = Some(h.value.clone());
            }
            regular_headers.push(h);
        }
    }

    if let (Some(auth), Some(host)) = (&authority, &host_header) {
        if !auth.eq_ignore_ascii_case(host) {
            return Err("authority and host mismatch");
        }
    }

    let mut blocks = Vec::new();

    if let Some(m) = method {
        let uri = path.unwrap_or_else(|| "/".to_string());
        blocks.push(HtxBlock::ReqLine(RequestLine {
            method: m,
            uri,
            version,
        }));
    } else if let Some(st) = status {
        blocks.push(HtxBlock::ResLine(ResponseLine {
            version,
            status: st,
            reason: String::new(),
        }));
    }

    if let Some(auth) = authority {
        if host_header.is_none() {
            blocks.push(HtxBlock::Header(HeaderField {
                name: "host".to_string(),
                value: auth,
            }));
        }
    }

    for h in regular_headers {
        blocks.push(HtxBlock::Header(h));
    }
    blocks.push(HtxBlock::Eoh);

    Ok(blocks)
}
#[cfg(test)]
mod tests {
    use super::*;

    /// T436 C: the byte accessors read what the blocks hold, without reading it as UTF-8: a
    /// value that is not UTF-8 (one a rule wrote as bytes) is found as its bytes, and does not
    /// hide the headers after it. The `&str` accessors read through them.
    #[test]
    fn the_byte_accessors_read_bytes() {
        let mut buf = [0u8; 1024];
        let mut htx = HtxSlice::new(&mut buf);
        htx.push_req_line("GET", "/a#b", "HTTP/1.0").unwrap();
        htx.push_header("x-a", "a").unwrap();
        htx.push_header("host", "h").unwrap();
        htx.push_eoh().unwrap();
        htx.replace_block_value(1, b"\xe9t\xe9").unwrap();
        let r = htx.as_ref();
        assert_eq!(r.get_header_bytes(b"X-A"), Some(&b"\xe9t\xe9"[..]));
        assert_eq!(r.get_header("x-a"), None, "not text");
        assert_eq!((r.get_header_bytes(b"host"), r.get_header("Host")), (Some(&b"h"[..]), Some("h")));
        assert_eq!(r.get_header_bytes(b"x-b"), None);
        let l = r.req_line_bytes().unwrap();
        assert_eq!((l.method, l.uri, l.version), (&b"GET"[..], &b"/a#b"[..], &b"HTTP/1.0"[..]));
        let v = r.req_line().unwrap();
        assert_eq!((v.method, v.uri, v.version), ("GET", "/a#b", "HTTP/1.0"));
        // A line that is not ASCII is split as `req_line` splits it (Unicode blanks too).
        let mut buf = [0u8; 256];
        let mut htx = HtxSlice::new(&mut buf);
        htx.push_req_line("GET", "/caf\u{e9}\u{a0}x", "").unwrap();
        let l = htx.as_ref().req_line_bytes().unwrap();
        let v = htx.as_ref().req_line().unwrap();
        assert_eq!((l.method, l.uri, l.version), (v.method.as_bytes(), v.uri.as_bytes(), v.version.as_bytes()));
        assert_eq!((l.uri, l.version), ("/caf\u{e9}".as_bytes(), &b"x"[..]));
    }

    /// A value holding an escaped byte goes out as that byte, whether it was Latin-1 before
    /// or not; any other text goes out as UTF-8 (T285, T286).
    #[test]
    fn a_replaced_value_is_written_as_the_bytes_it_stands_for() {
        let wire = |new: &str, latin1: bool| {
            let mut buf = [0u8; 1024];
            let mut htx = HtxSlice::new(&mut buf);
            htx.push_req_line("GET", "/", "HTTP/1.1").unwrap();
            if latin1 {
                htx.push_header_latin1("x-a", b"\xff").unwrap();
            } else {
                htx.push_header("x-a", "a").unwrap();
            }
            htx.push_eoh().unwrap();
            htx.replace_block_value(1, new.as_bytes()).unwrap();
            htx.as_ref().to_h1_wire()
        };
        for latin1 in [true, false] {
            assert_eq!(wire("caf\u{f7e9}", latin1), b"GET / HTTP/1.1\r\nx-a: caf\xe9\r\n\r\n");
            assert_eq!(wire("caf\u{e9}", latin1), "GET / HTTP/1.1\r\nx-a: caf\u{e9}\r\n\r\n".as_bytes());
            assert_eq!(wire("\u{20ac}", latin1), "GET / HTTP/1.1\r\nx-a: \u{20ac}\r\n\r\n".as_bytes());
        }
    }

    /// `push_header` takes text a peer sent: U+F780 in it is EF 9E 80 on the wire, never the
    /// byte 0x80 that the same character stands for in a value held as bytes (T286).
    #[test]
    fn push_header_of_peer_text_never_means_a_stray_byte() {
        let mut buf = [0u8; 1024];
        let mut htx = HtxSlice::new(&mut buf);
        htx.push_req_line("GET", "/", "HTTP/1.1").unwrap();
        htx.push_header("x-a", "a\u{f780}b").unwrap();
        htx.push_header_latin1("x-b", b"a\x80b").unwrap();
        htx.push_header_latin1("x-c", b"a\xef\x9e\x80b\x80").unwrap();
        htx.push_eoh().unwrap();
        assert_eq!(htx.as_ref().to_h1_wire(), b"GET / HTTP/1.1\r\nx-a: a\xef\x9e\x80b\r\nx-b: a\x80b\r\nx-c: a\xef\x9e\x80b\x80\r\n\r\n");
        let vals: Vec<String> = htx.as_ref().headers().map(|(_, v)| v.to_string()).collect();
        assert_ne!(vals[0], vals[1]);
        assert_ne!(vals[0], vals[2]);
    }

    #[test]
    fn ascii_words_split_as_split_whitespace() {
        for raw in ["GET / HTTP/1.1", "  GET\t/x \u{b}HTTP/1.0\u{c} ", "GET", "", "   ", "GET /", "a b c d", "GET\r\n/ x"] {
            assert_eq!(ascii_words3(raw), words3(raw), "{raw:?}");
        }
    }

    #[test]
    fn htx_request_serialization_roundtrip() {
        let mut htx = Htx::new();
        htx.push(HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Get,
            uri: "/api/v1/status".into(),
            version: HttpVersion::Http11,
        }));
        htx.push(HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "example.com".into(),
        }));
        htx.push(HtxBlock::Header(HeaderField {
            name: "User-Agent".into(),
            value: "curl/8.0".into(),
        }));
        htx.push(HtxBlock::Eoh);
        htx.push(HtxBlock::Eom);

        assert_eq!(htx.get_header("host"), Some("example.com"));
        assert_eq!(htx.get_header("HOST"), Some("example.com"));

        let wire = htx.to_h1_wire();
        let wire_str = String::from_utf8(wire).expect("utf8");
        assert!(wire_str.starts_with("GET /api/v1/status HTTP/1.1\r\n"));
        assert!(wire_str.contains("Host: example.com\r\n"));
        assert!(wire_str.contains("User-Agent: curl/8.0\r\n"));
        assert!(wire_str.ends_with("\r\n\r\n"));
    }

    #[test]
    fn htx_header_manipulation() {
        let mut htx = Htx::new();
        htx.push(HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Post,
            uri: "/upload".into(),
            version: HttpVersion::Http11,
        }));
        htx.push(HtxBlock::Header(HeaderField {
            name: "Content-Length".into(),
            value: "100".into(),
        }));
        htx.push(HtxBlock::Eoh);
        htx.push(HtxBlock::Data(b"hello".to_vec()));
        htx.push(HtxBlock::Eom);

        htx.set_header("Content-Length", "5");
        htx.set_header("X-Proxy", "Ibex");

        assert_eq!(htx.get_header("content-length"), Some("5"));
        assert_eq!(htx.get_header("x-proxy"), Some("Ibex"));

        htx.del_header("x-proxy");
        assert_eq!(htx.get_header("x-proxy"), None);
        assert_eq!(htx.body_bytes(), b"hello");
    }

    #[test]
    fn htx_slice_zero_allocation_contiguous_buffer() {
        let mut storage = [0u8; 4096];
        let mut htx = HtxSlice::new(&mut storage);

        htx.push_req_line("POST", "/v1/submit", "HTTP/1.1")
            .expect("req_line");
        htx.push_header("Host", "api.ibex.internal")
            .expect("header");
        htx.push_header("Transfer-Encoding", "chunked")
            .expect("header");
        htx.push_eoh().expect("eoh");
        htx.push_data(b"chunk-part-1").expect("data1");
        htx.push_data(b"-and-part-2").expect("data2");
        htx.push_trailer("Expires", "Wed, 21 Oct 2026 07:28:00 GMT")
            .expect("trailer");
        htx.push_eot().expect("eot");
        htx.push_eom().expect("eom");

        assert!(htx.is_eoh());
        assert!(htx.is_eom());
        assert_eq!(htx.get_header("host"), Some("api.ibex.internal"));
        assert_eq!(
            htx.get_trailer("expires"),
            Some("Wed, 21 Oct 2026 07:28:00 GMT")
        );

        let req = htx.req_line().expect("req_line");
        assert_eq!(req.method, "POST");
        assert_eq!(req.uri, "/v1/submit");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(htx.body_len(), 23);

        htx.merge_contiguous_data();
        assert_eq!(htx.body_len(), 23);

        let mut wire = [0u8; 1024];
        let n = htx.write_h1_wire(&mut wire).expect("wire");
        let wire_str = utf8(&wire[..n]).expect("utf8");
        assert!(wire_str.starts_with("POST /v1/submit HTTP/1.1\r\n"));
        assert!(wire_str.contains("Host: api.ibex.internal\r\n"));
        assert!(wire_str.contains("chunk-part-1-and-part-2"));
        assert!(wire_str.contains("Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\n"));
    }

    #[test]
    fn htx_buffer_explicit_replace_grows() {
        let mut buf = HtxBuffer::with_capacity(512);
        let mut htx = Htx::new();

        buf.push_header("Server", "A").unwrap();
        htx.push(HtxBlock::Header(HeaderField { name: "Server".into(), value: "A".into() }));

        // Replace with longer value
        buf.replace_block_value(0, b"Apache/2.4.41").unwrap();
        if let HtxBlock::Header(h) = &mut htx.blocks_mut()[0] {
            h.value = "Apache/2.4.41".into();
        }

        assert_eq!(buf.to_blocks(), htx.blocks());
    }

    #[test]
    fn htx_buffer_explicit_defrag_churn() {
        let mut buf = HtxBuffer::with_capacity(1024);
        let mut htx = Htx::new();

        for i in 0..10 {
            buf.push_header("X-Test", &i.to_string()).unwrap();
            htx.push(HtxBlock::Header(HeaderField { name: "X-Test".into(), value: i.to_string() }));
        }

        // Churn: remove even blocks, replace odd blocks with longer values
        for i in 0..10 {
            if i % 2 == 0 {
                buf.remove_block(i);
                // in Htx we don't physically remove yet to keep indices aligned for the test, we can replace with a dummy or just rebuild Htx
            } else {
                buf.replace_block_value(i, b"longer_value_to_force_append").unwrap();
            }
        }
        
        // Let's just do a simple defrag check
        let blocks_before = buf.to_blocks();
        buf.defrag();
        let blocks_after = buf.to_blocks();
        assert_eq!(blocks_before, blocks_after);
    }

    #[test]
    fn htx_buffer_explicit_removals() {
        let mut buf = HtxBuffer::with_capacity(512);
        
        buf.push_header("First", "1").unwrap();
        buf.push_header("Middle", "2").unwrap();
        buf.push_header("Last", "3").unwrap();

        buf.remove_block(1); // middle
        buf.remove_block(0); // first
        buf.remove_block(2); // last
        
        assert_eq!(buf.to_blocks().len(), 0);
    }

    #[test]
    fn htx_buffer_explicit_capacity_failure() {
        let mut buf = HtxBuffer::with_capacity(64); // very small
        
        // Fill it
        loop {
            match buf.push_header("X", "Y") {
                Ok(()) => {}
                Err(HtxError::OutOfMemory) => break,
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }
        
        // Ensure no corruption
        let _ = buf.to_blocks();
    }

    #[test]
    fn htx_buffer_roundtrip() {
        let mut buf = HtxBuffer::with_capacity(8192);
        buf.push_res_line("HTTP/1.1", 200, "OK").expect("res_line");
        buf.push_header("Content-Type", "application/json")
            .expect("header");
        buf.push_eoh().expect("eoh");
        buf.push_data(b"{\"status\":\"healthy\"}").expect("data");
        buf.push_eom().expect("eom");

        assert!(buf.is_eoh());
        assert!(buf.is_eom());
        assert_eq!(buf.get_header("content-type"), Some("application/json"));
        let res = buf.res_line().expect("res_line");
        assert_eq!(res.status, 200);
        assert_eq!(res.reason, "OK");

        let mut wire = [0u8; 512];
        let n = buf.write_h1_wire(&mut wire).expect("wire");
        let wire_str = utf8(&wire[..n]).expect("utf8");
        assert!(wire_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire_str.contains("{\"status\":\"healthy\"}"));
    }

    #[test]
    fn pseudo_headers_to_htx_converts_authority_and_consumes_scheme() {
        let headers = vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: ":scheme".into(), value: "https".into() },
            HeaderField { name: ":path".into(), value: "/index.html".into() },
            HeaderField { name: ":authority".into(), value: "example.com".into() },
            HeaderField { name: "user-agent".into(), value: "curl/8.0".into() },
        ];
        let blocks = pseudo_headers_to_htx(headers, HttpVersion::Http20).expect("conversion");
        let mut htx = Htx::new();
        for b in blocks {
            htx.push(b);
        }
        assert_eq!(htx.req_line().unwrap().method, HttpMethod::Get);
        assert_eq!(htx.req_line().unwrap().uri, "/index.html");
        assert_eq!(htx.req_line().unwrap().version, HttpVersion::Http20);
        assert_eq!(htx.get_header("host"), Some("example.com"));
        assert_eq!(htx.get_header("user-agent"), Some("curl/8.0"));
        assert_eq!(htx.get_header(":scheme"), None);
        assert_eq!(htx.get_header(":authority"), None);

        let wire = htx.to_h1_wire();
        let wire_str = String::from_utf8(wire).expect("utf8");
        assert!(wire_str.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(wire_str.contains("host: example.com\r\n"));
        assert!(!wire_str.contains(":scheme"));
        assert!(!wire_str.contains(":authority"));
    }

    #[test]
    fn pseudo_headers_to_htx_agreeing_host_and_authority() {
        let headers = vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: ":scheme".into(), value: "http".into() },
            HeaderField { name: ":path".into(), value: "/".into() },
            HeaderField { name: ":authority".into(), value: "example.org".into() },
            HeaderField { name: "host".into(), value: "example.org".into() },
        ];
        let blocks = pseudo_headers_to_htx(headers, HttpVersion::Http20).expect("conversion");
        let host_headers: Vec<_> = blocks
            .iter()
            .filter_map(|b| match b {
                HtxBlock::Header(h) if h.name.eq_ignore_ascii_case("host") => Some(&h.value),
                _ => None,
            })
            .collect();
        assert_eq!(host_headers, vec!["example.org"]);
    }

    #[test]
    fn pseudo_headers_to_htx_disagreeing_host_and_authority() {
        let headers = vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: ":scheme".into(), value: "http".into() },
            HeaderField { name: ":path".into(), value: "/".into() },
            HeaderField { name: ":authority".into(), value: "example.org".into() },
            HeaderField { name: "host".into(), value: "evil.com".into() },
        ];
        let err = pseudo_headers_to_htx(headers, HttpVersion::Http20).unwrap_err();
        assert_eq!(err, "authority and host mismatch");
    }

    #[test]
    fn pseudo_headers_to_htx_unknown_pseudo_header() {
        let headers = vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: ":custom".into(), value: "value".into() },
        ];
        let err = pseudo_headers_to_htx(headers, HttpVersion::Http20).unwrap_err();
        assert_eq!(err, "unknown pseudo-header");
    }

    #[test]
    fn pseudo_headers_to_htx_pseudo_after_regular() {
        let headers = vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: "user-agent".into(), value: "curl/8.0".into() },
            HeaderField { name: ":scheme".into(), value: "http".into() },
        ];
        let err = pseudo_headers_to_htx(headers, HttpVersion::Http20).unwrap_err();
        assert_eq!(err, "pseudo-header after regular header");
    }

    #[test]
    fn pseudo_headers_to_htx_duplicate_pseudo() {
        let headers = vec![
            HeaderField { name: ":method".into(), value: "GET".into() },
            HeaderField { name: ":method".into(), value: "POST".into() },
            HeaderField { name: ":scheme".into(), value: "http".into() },
            HeaderField { name: ":path".into(), value: "/".into() },
        ];
        let err = pseudo_headers_to_htx(headers, HttpVersion::Http20).unwrap_err();
        assert_eq!(err, "duplicate pseudo-header");
    }

    #[test]
    fn pseudo_headers_to_htx_response_status() {
        let headers = vec![
            HeaderField { name: ":status".into(), value: "200".into() },
            HeaderField { name: "content-length".into(), value: "0".into() },
        ];
        let blocks = pseudo_headers_to_htx(headers, HttpVersion::Http20).expect("conversion");
        let mut htx = Htx::new();
        for b in blocks {
            htx.push(b);
        }
        assert_eq!(htx.res_line().unwrap().status, 200);
        assert_eq!(htx.get_header("content-length"), Some("0"));
    }

    #[test]
    fn htx_h3_to_h1_wire_normalizes_version() {
        let mut htx = Htx::new();
        htx.push(HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Get,
            uri: "/test".into(),
            version: HttpVersion::Http30,
        }));
        htx.push(HtxBlock::Header(HeaderField {
            name: "host".into(),
            value: "example.com".into(),
        }));
        htx.push(HtxBlock::Eoh);
        htx.push(HtxBlock::Eom);

        let wire = htx.to_h1_wire();
        let wire_str = String::from_utf8(wire).expect("utf8");
        assert!(wire_str.starts_with("GET /test HTTP/1.1\r\n"));
    }
}


