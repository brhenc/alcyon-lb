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

/// Maximum length of header / trailer name in bytes.
pub const HTX_HDR_NAME_MAX_LEN: usize = 255;
/// Maximum length of header / trailer value in bytes (1 MB).
pub const HTX_HDR_VALUE_MAX_LEN: usize = 1_048_575;
/// Default size for pre-allocated HTX buffer (16 KiB).
pub const HTX_BUFFER_DEFAULT_CAPACITY: usize = 16384;
/// Size in bytes of each block descriptor stored at the end of the buffer.
pub const HTX_DESC_SIZE: usize = 16;

/// HTX block flag: None.
pub const HTX_BLK_FL_NONE: u8 = 0x00;
/// Flag marking the final block of an HTTP message.
pub const HTX_BLK_FL_EOM: u8 = 0x01;

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
}

impl HttpVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http20 => "HTTP/2.0",
        }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes == b"HTTP/1.0" {
            HttpVersion::Http10
        } else if bytes == b"HTTP/2.0" || bytes == b"HTTP/2" {
            HttpVersion::Http20
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
    method: &str,
    uri: &str,
    version: &str,
) -> Result<(), HtxError> {
    let needed = method.len() + 1 + uri.len() + 1 + version.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    let start = *tail_addr;

    buf[start..start + method.len()].copy_from_slice(method.as_bytes());
    let cur = start + method.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + uri.len()].copy_from_slice(uri.as_bytes());
    let cur = cur + uri.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + version.len()].copy_from_slice(version.as_bytes());
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
    version: &str,
    status: u16,
    reason: &str,
) -> Result<(), HtxError> {
    let status_str = status.to_string();
    let needed = version.len() + 1 + status_str.len() + 1 + reason.len() + HTX_DESC_SIZE;
    if free_capacity_at(buf.len(), *tail_addr, *num_blocks) < needed {
        return Err(HtxError::OutOfMemory);
    }

    let addr = *tail_addr as u32;
    let start = *tail_addr;

    buf[start..start + version.len()].copy_from_slice(version.as_bytes());
    let cur = start + version.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + status_str.len()].copy_from_slice(status_str.as_bytes());
    let cur = cur + status_str.len();
    buf[cur] = b' ';
    let cur = cur + 1;
    buf[cur..cur + reason.len()].copy_from_slice(reason.as_bytes());
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

    let new_idx = *num_blocks;
    *num_blocks += 1;
    write_desc_at(buf, *num_blocks, new_idx, &desc);
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

/// Immutable borrowed view over a contiguous HTX buffer.
#[derive(Debug, Clone, Copy)]
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

    fn read_desc(&self, index: usize) -> HtxBlockDesc {
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
                let raw = std::str::from_utf8(&self.buf[start..end]).ok()?;
                let mut parts = raw.split_whitespace();
                let method = parts.next()?;
                let uri = parts.next()?;
                let version = parts.next().unwrap_or("HTTP/1.1");
                return Some(RequestLineView {
                    method,
                    uri,
                    version,
                });
            }
        }
        None
    }

    #[must_use]
    pub fn res_line(&self) -> Option<ResponseLineView<'a>> {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::ResLine {
                let start = desc.addr as usize;
                let end = start + desc.value_len as usize;
                let raw = std::str::from_utf8(&self.buf[start..end]).ok()?;
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

    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&'a str> {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Header {
                let name_start = desc.addr as usize;
                let name_end = name_start + desc.name_len as usize;
                let hdr_name = std::str::from_utf8(&self.buf[name_start..name_end]).ok()?;
                if hdr_name.eq_ignore_ascii_case(name) {
                    let val_start = name_end;
                    let val_end = val_start + desc.value_len as usize;
                    return std::str::from_utf8(&self.buf[val_start..val_end]).ok();
                }
            }
        }
        None
    }

    #[must_use]
    pub fn get_trailer(&self, name: &str) -> Option<&'a str> {
        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Trailer {
                let name_start = desc.addr as usize;
                let name_end = name_start + desc.name_len as usize;
                let hdr_name = std::str::from_utf8(&self.buf[name_start..name_end]).ok()?;
                if hdr_name.eq_ignore_ascii_case(name) {
                    let val_start = name_end;
                    let val_end = val_start + desc.value_len as usize;
                    return std::str::from_utf8(&self.buf[val_start..val_end]).ok();
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
            cursor = write_slice(
                out,
                cursor,
                format!("{} {} {}\r\n", req.method, req.uri, req.version).as_bytes(),
            )?;
        } else if let Some(res) = self.res_line() {
            cursor = write_slice(
                out,
                cursor,
                format!("{} {} {}\r\n", res.version, res.status, res.reason).as_bytes(),
            )?;
        }

        for i in 0..self.num_blocks {
            let desc = self.read_desc(i);
            if desc.blk_type == HtxBlockType::Header {
                let name_start = desc.addr as usize;
                let name_end = name_start + desc.name_len as usize;
                let val_end = name_end + desc.value_len as usize;
                cursor = write_slice(out, cursor, &self.buf[name_start..name_end])?;
                cursor = write_slice(out, cursor, b": ")?;
                cursor = write_slice(out, cursor, &self.buf[name_end..val_end])?;
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
                let name_start = desc.addr as usize;
                let name_end = name_start + desc.name_len as usize;
                let val_end = name_end + desc.value_len as usize;
                cursor = write_slice(out, cursor, &self.buf[name_start..name_end])?;
                cursor = write_slice(out, cursor, b": ")?;
                cursor = write_slice(out, cursor, &self.buf[name_end..val_end])?;
                cursor = write_slice(out, cursor, b"\r\n")?;
            }
        }

        if has_trailers {
            cursor = write_slice(out, cursor, b"\r\n")?;
        }

        Ok(cursor)
    }
}

// ---------------------------------------------------------------------------
// Zero-allocation mutable slice
// ---------------------------------------------------------------------------

/// Zero-allocation HTX representation over a contiguous pre-allocated byte slice.
pub struct HtxSlice<'a> {
    buf: &'a mut [u8],
    tail_addr: usize,
    num_blocks: usize,
}

impl<'a> HtxSlice<'a> {
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            tail_addr: 0,
            num_blocks: 0,
        }
    }

    pub fn clear(&mut self) {
        self.tail_addr = 0;
        self.num_blocks = 0;
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
    pub fn payload_bytes(&self) -> usize {
        self.tail_addr
    }

    #[must_use]
    pub fn free_capacity(&self) -> usize {
        free_capacity_at(self.buf.len(), self.tail_addr, self.num_blocks)
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

    pub fn push_res_line(
        &mut self,
        version: &str,
        status: u16,
        reason: &str,
    ) -> Result<(), HtxError> {
        push_res_line_raw(
            self.buf,
            &mut self.tail_addr,
            &mut self.num_blocks,
            version,
            status,
            reason,
        )
    }

    pub fn push_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        push_header_raw(
            self.buf,
            &mut self.tail_addr,
            &mut self.num_blocks,
            name,
            value,
        )
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
        if self.num_blocks > 0 {
            let last_idx = self.num_blocks - 1;
            let mut desc = read_desc_at(self.buf, self.num_blocks, last_idx);
            desc.flags |= HTX_BLK_FL_EOM;
            write_desc_at(self.buf, self.num_blocks, last_idx, &desc);
            return Ok(());
        }

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
    pub fn as_ref(&self) -> HtxSliceRef<'_> {
        HtxSliceRef::new(&self.data, self.num_blocks)
    }

    pub fn push_req_line(
        &mut self,
        method: &str,
        uri: &str,
        version: &str,
    ) -> Result<(), HtxError> {
        push_req_line_raw(
            &mut self.data,
            &mut self.tail_addr,
            &mut self.num_blocks,
            method,
            uri,
            version,
        )
    }

    pub fn push_res_line(
        &mut self,
        version: &str,
        status: u16,
        reason: &str,
    ) -> Result<(), HtxError> {
        push_res_line_raw(
            &mut self.data,
            &mut self.tail_addr,
            &mut self.num_blocks,
            version,
            status,
            reason,
        )
    }

    pub fn push_header(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        push_header_raw(
            &mut self.data,
            &mut self.tail_addr,
            &mut self.num_blocks,
            name,
            value,
        )
    }

    pub fn push_eoh(&mut self) -> Result<(), HtxError> {
        push_marker_raw(
            &mut self.data,
            self.tail_addr,
            &mut self.num_blocks,
            HtxBlockType::Eoh,
            HTX_BLK_FL_NONE,
        )
    }

    pub fn push_data(&mut self, data: &[u8]) -> Result<(), HtxError> {
        push_data_raw(
            &mut self.data,
            &mut self.tail_addr,
            &mut self.num_blocks,
            data,
            false,
        )
    }

    pub fn push_trailer(&mut self, name: &str, value: &str) -> Result<(), HtxError> {
        push_trailer_raw(
            &mut self.data,
            &mut self.tail_addr,
            &mut self.num_blocks,
            name,
            value,
        )
    }

    pub fn push_eot(&mut self) -> Result<(), HtxError> {
        push_marker_raw(
            &mut self.data,
            self.tail_addr,
            &mut self.num_blocks,
            HtxBlockType::Eot,
            HTX_BLK_FL_NONE,
        )
    }

    pub fn push_eom(&mut self) -> Result<(), HtxError> {
        if self.num_blocks > 0 {
            let last_idx = self.num_blocks - 1;
            let mut desc = read_desc_at(&self.data, self.num_blocks, last_idx);
            desc.flags |= HTX_BLK_FL_EOM;
            write_desc_at(&mut self.data, self.num_blocks, last_idx, &desc);
            return Ok(());
        }

        push_marker_raw(
            &mut self.data,
            self.tail_addr,
            &mut self.num_blocks,
            HtxBlockType::Eom,
            HTX_BLK_FL_EOM,
        )
    }

    pub fn push_raw_data(&mut self, data: &[u8]) -> Result<(), HtxError> {
        push_data_raw(
            &mut self.data,
            &mut self.tail_addr,
            &mut self.num_blocks,
            data,
            true,
        )
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
    pub fn body_len(&self) -> usize {
        self.as_ref().body_len()
    }

    pub fn merge_contiguous_data(&mut self) {
        if self.num_blocks < 2 {
            return;
        }

        let mut i = 1;
        while i < self.num_blocks {
            let prev = read_desc_at(&self.data, self.num_blocks, i - 1);
            let curr = read_desc_at(&self.data, self.num_blocks, i);

            if prev.blk_type == HtxBlockType::Data
                && curr.blk_type == HtxBlockType::Data
                && (prev.addr as usize + prev.value_len as usize == curr.addr as usize)
            {
                let mut merged = prev;
                merged.value_len += curr.value_len;
                merged.flags |= curr.flags;
                write_desc_at(&mut self.data, self.num_blocks, i - 1, &merged);

                for j in i..self.num_blocks - 1 {
                    let d = read_desc_at(&self.data, self.num_blocks, j + 1);
                    write_desc_at(&mut self.data, self.num_blocks, j, &d);
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

    #[must_use]
    pub fn blocks(&self) -> &[HtxBlock] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut [HtxBlock] {
        &mut self.blocks
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
            let _ = write!(
                buf,
                "{} {} {}\r\n",
                req.method.as_str(),
                req.uri,
                req.version.as_str()
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let wire_str = std::str::from_utf8(&wire[..n]).expect("utf8");
        assert!(wire_str.starts_with("POST /v1/submit HTTP/1.1\r\n"));
        assert!(wire_str.contains("Host: api.ibex.internal\r\n"));
        assert!(wire_str.contains("chunk-part-1-and-part-2"));
        assert!(wire_str.contains("Expires: Wed, 21 Oct 2026 07:28:00 GMT\r\n"));
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
        let wire_str = std::str::from_utf8(&wire[..n]).expect("utf8");
        assert!(wire_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire_str.contains("{\"status\":\"healthy\"}"));
    }
}
