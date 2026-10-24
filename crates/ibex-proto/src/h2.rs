// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/mux_h2.c and RFC 7540 / RFC 9113.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! HTTP/2 Protocol Constants, Frame Codecs, and Multiplexer State Machine.
//!
//! Complies strictly with RFC 7540 / RFC 9113 under `#![forbid(unsafe_code)]`.

use crate::hpack::{HpackDecoder, HpackEncoder};
use crate::htx::HeaderField;
use std::collections::BTreeMap;
use std::io;

/// Standard HTTP/2 Client Connection Preface (24 bytes).
pub const H2_CONN_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Length in bytes of an HTTP/2 Frame Header (9 octets).
pub const FRAME_HEADER_LEN: usize = 9;

/// Default initial flow control window size for both streams and connections (65,535 octets).
pub const DEFAULT_INITIAL_WINDOW_SIZE: i32 = 65_535;

/// Default maximum frame payload size (16,384 octets).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// Default HPACK dynamic header table size (4,096 octets).
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4_096;

/// Maximum allowable window update increment and window size (2^31 - 1).
pub const MAX_WINDOW_SIZE: i32 = 0x7fff_ffff;

/// Minimum allowable max frame size (RFC 7540 §6.5.2: 16,384).
pub const MIN_MAX_FRAME_SIZE: u32 = 16_384;

/// Maximum allowable max frame size (RFC 7540 §6.5.2: 16,777,215).
pub const MAX_MAX_FRAME_SIZE: u32 = 16_777_215;

/// HTTP/2 Frame Types (RFC 7540 §11.2).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    Unknown(u8),
}

impl From<u8> for FrameType {
    fn from(b: u8) -> Self {
        match b {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::GoAway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            other => FrameType::Unknown(other),
        }
    }
}

impl From<FrameType> for u8 {
    fn from(t: FrameType) -> Self {
        match t {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Priority => 0x2,
            FrameType::RstStream => 0x3,
            FrameType::Settings => 0x4,
            FrameType::PushPromise => 0x5,
            FrameType::Ping => 0x6,
            FrameType::GoAway => 0x7,
            FrameType::WindowUpdate => 0x8,
            FrameType::Continuation => 0x9,
            FrameType::Unknown(other) => other,
        }
    }
}

/// HTTP/2 Frame Flags.
pub mod frame_flags {
    /// End of Stream flag (`DATA`, `HEADERS`).
    pub const END_STREAM: u8 = 0x01;
    /// Acknowledgment flag (`SETTINGS`, `PING`).
    pub const ACK: u8 = 0x01;
    /// End of Headers flag (`HEADERS`, `PUSH_PROMISE`, `CONTINUATION`).
    pub const END_HEADERS: u8 = 0x04;
    /// Padded flag (`DATA`, `HEADERS`, `PUSH_PROMISE`).
    pub const PADDED: u8 = 0x08;
    /// Priority flag (`HEADERS`).
    pub const PRIORITY: u8 = 0x20;
}

/// HTTP/2 SETTINGS Parameters (RFC 7540 §6.5.2).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum SettingsParameter {
    HeaderTableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
    Unknown(u16),
}

impl From<u16> for SettingsParameter {
    fn from(v: u16) -> Self {
        match v {
            0x1 => SettingsParameter::HeaderTableSize,
            0x2 => SettingsParameter::EnablePush,
            0x3 => SettingsParameter::MaxConcurrentStreams,
            0x4 => SettingsParameter::InitialWindowSize,
            0x5 => SettingsParameter::MaxFrameSize,
            0x6 => SettingsParameter::MaxHeaderListSize,
            other => SettingsParameter::Unknown(other),
        }
    }
}

impl From<SettingsParameter> for u16 {
    fn from(p: SettingsParameter) -> Self {
        match p {
            SettingsParameter::HeaderTableSize => 0x1,
            SettingsParameter::EnablePush => 0x2,
            SettingsParameter::MaxConcurrentStreams => 0x3,
            SettingsParameter::InitialWindowSize => 0x4,
            SettingsParameter::MaxFrameSize => 0x5,
            SettingsParameter::MaxHeaderListSize => 0x6,
            SettingsParameter::Unknown(other) => other,
        }
    }
}

/// HTTP/2 Error Codes (RFC 7540 §7).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum H2Error {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
    Unknown(u32),
}

impl From<u32> for H2Error {
    fn from(v: u32) -> Self {
        match v {
            0x0 => H2Error::NoError,
            0x1 => H2Error::ProtocolError,
            0x2 => H2Error::InternalError,
            0x3 => H2Error::FlowControlError,
            0x4 => H2Error::SettingsTimeout,
            0x5 => H2Error::StreamClosed,
            0x6 => H2Error::FrameSizeError,
            0x7 => H2Error::RefusedStream,
            0x8 => H2Error::Cancel,
            0x9 => H2Error::CompressionError,
            0xa => H2Error::ConnectError,
            0xb => H2Error::EnhanceYourCalm,
            0xc => H2Error::InadequateSecurity,
            0xd => H2Error::Http11Required,
            other => H2Error::Unknown(other),
        }
    }
}

impl From<H2Error> for u32 {
    fn from(e: H2Error) -> Self {
        match e {
            H2Error::NoError => 0x0,
            H2Error::ProtocolError => 0x1,
            H2Error::InternalError => 0x2,
            H2Error::FlowControlError => 0x3,
            H2Error::SettingsTimeout => 0x4,
            H2Error::StreamClosed => 0x5,
            H2Error::FrameSizeError => 0x6,
            H2Error::RefusedStream => 0x7,
            H2Error::Cancel => 0x8,
            H2Error::CompressionError => 0x9,
            H2Error::ConnectError => 0xa,
            H2Error::EnhanceYourCalm => 0xb,
            H2Error::InadequateSecurity => 0xc,
            H2Error::Http11Required => 0xd,
            H2Error::Unknown(other) => other,
        }
    }
}

/// 9-byte HTTP/2 Frame Header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32,
    pub frame_type: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    /// Encodes the 9-byte frame header into big-endian wire format.
    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut buf = [0u8; FRAME_HEADER_LEN];
        let len_bytes = self.length.to_be_bytes();
        buf[0] = len_bytes[1];
        buf[1] = len_bytes[2];
        buf[2] = len_bytes[3];
        buf[3] = self.frame_type.into();
        buf[4] = self.flags;
        let sid_bytes = (self.stream_id & 0x7fff_ffff).to_be_bytes();
        buf[5..9].copy_from_slice(&sid_bytes);
        buf
    }

    /// Decodes a 9-byte frame header from a slice.
    ///
    /// # Errors
    /// Returns `io::Error` if the slice is shorter than 9 bytes.
    pub fn decode(src: &[u8]) -> io::Result<Self> {
        if src.len() < FRAME_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete HTTP/2 frame header",
            ));
        }
        let length = u32::from_be_bytes([0, src[0], src[1], src[2]]);
        let frame_type = FrameType::from(src[3]);
        let flags = src[4];
        let stream_id = u32::from_be_bytes([src[5], src[6], src[7], src[8]]) & 0x7fff_ffff;

        Ok(FrameHeader {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }
}

/// Structured HTTP/2 Frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        flags: u8,
        stream_id: u32,
        data: Vec<u8>,
    },
    Headers {
        flags: u8,
        stream_id: u32,
        header_block: Vec<u8>,
    },
    Priority {
        stream_id: u32,
        stream_dependency: u32,
        weight: u8,
        exclusive: bool,
    },
    RstStream {
        stream_id: u32,
        error_code: H2Error,
    },
    Settings {
        flags: u8,
        settings: Vec<(SettingsParameter, u32)>,
    },
    PushPromise {
        flags: u8,
        stream_id: u32,
        promised_stream_id: u32,
        header_block: Vec<u8>,
    },
    Ping {
        flags: u8,
        opaque_data: [u8; 8],
    },
    GoAway {
        last_stream_id: u32,
        error_code: H2Error,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    Continuation {
        flags: u8,
        stream_id: u32,
        header_block: Vec<u8>,
    },
    Unknown {
        header: FrameHeader,
        payload: Vec<u8>,
    },
}

/// A decode error that is FRAME_SIZE_ERROR rather than PROTOCOL_ERROR on the wire
/// (`io::ErrorKind::InvalidInput`; the mux maps it).
fn frame_size_error(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// Removes the pad length byte and the trailing padding of a PADDED frame (RFC 9113
/// sections 6.1/6.2). `fixed` is the number of mandatory bytes that follow the pad length
/// byte. A pad length that leaves no room for them is PROTOCOL_ERROR; a PADDED frame with
/// no pad length byte is FRAME_SIZE_ERROR (both measured on HAProxy 3.5-dev8).
fn strip_padding(flags: u8, payload: &[u8], fixed: usize) -> io::Result<&[u8]> {
    if (flags & frame_flags::PADDED) == 0 {
        return Ok(payload);
    }
    let Some((&pad, rest)) = payload.split_first() else {
        return Err(frame_size_error("PADDED frame without a pad length"));
    };
    let pad = usize::from(pad);
    if pad + fixed > rest.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "pad length exceeds the frame payload"));
    }
    Ok(&rest[..rest.len() - pad])
}

impl Frame {
    /// Encodes the complete frame (header + payload) into wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Appends the complete frame (header + payload) to `out`, in the memory it has (T437).
    #[allow(clippy::too_many_lines)]
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Data {
                flags,
                stream_id,
                data,
            } => {
                let hdr = FrameHeader {
                    length: u32::try_from(data.len()).unwrap_or(u32::MAX),
                    frame_type: FrameType::Data,
                    flags: *flags,
                    stream_id: *stream_id,
                };
                out.extend_from_slice(&hdr.encode());
                out.extend_from_slice(data);
            }
            Frame::Headers {
                flags,
                stream_id,
                header_block,
            } => {
                let hdr = FrameHeader {
                    length: u32::try_from(header_block.len()).unwrap_or(u32::MAX),
                    frame_type: FrameType::Headers,
                    flags: *flags,
                    stream_id: *stream_id,
                };
                out.extend_from_slice(&hdr.encode());
                out.extend_from_slice(header_block);
            }
            Frame::Priority {
                stream_id,
                stream_dependency,
                weight,
                exclusive,
            } => {
                let hdr = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority,
                    flags: 0,
                    stream_id: *stream_id,
                };
                out.extend_from_slice(&hdr.encode());
                let dep = if *exclusive {
                    *stream_dependency | 0x8000_0000
                } else {
                    *stream_dependency & 0x7fff_ffff
                };
                out.extend_from_slice(&dep.to_be_bytes());
                out.push(*weight);
            }
            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                let hdr = FrameHeader {
                    length: 4,
                    frame_type: FrameType::RstStream,
                    flags: 0,
                    stream_id: *stream_id,
                };
                out.extend_from_slice(&hdr.encode());
                let err_num: u32 = (*error_code).into();
                out.extend_from_slice(&err_num.to_be_bytes());
            }
            Frame::Settings { flags, settings } => {
                let payload_len = u32::try_from(settings.len().saturating_mul(6)).unwrap_or(u32::MAX);
                let hdr = FrameHeader {
                    length: payload_len,
                    frame_type: FrameType::Settings,
                    flags: *flags,
                    stream_id: 0,
                };
                out.extend_from_slice(&hdr.encode());
                for (param, val) in settings {
                    let p_id: u16 = (*param).into();
                    out.extend_from_slice(&p_id.to_be_bytes());
                    out.extend_from_slice(&val.to_be_bytes());
                }
            }
            Frame::PushPromise {
                flags,
                stream_id,
                promised_stream_id,
                header_block,
            } => {
                let payload_len = u32::try_from(4usize.saturating_add(header_block.len())).unwrap_or(u32::MAX);
                let hdr = FrameHeader {
                    length: payload_len,
                    frame_type: FrameType::PushPromise,
                    flags: *flags,
                    stream_id: *stream_id,
                };
                out.extend_from_slice(&hdr.encode());
                out.extend_from_slice(&(promised_stream_id & 0x7fff_ffff).to_be_bytes());
                out.extend_from_slice(header_block);
            }
            Frame::Ping { flags, opaque_data } => {
                let hdr = FrameHeader {
                    length: 8,
                    frame_type: FrameType::Ping,
                    flags: *flags,
                    stream_id: 0,
                };
                out.extend_from_slice(&hdr.encode());
                out.extend_from_slice(opaque_data);
            }
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                let payload_len = u32::try_from(8usize.saturating_add(debug_data.len())).unwrap_or(u32::MAX);
                let hdr = FrameHeader {
                    length: payload_len,
                    frame_type: FrameType::GoAway,
                    flags: 0,
                    stream_id: 0,
                };
                out.extend_from_slice(&hdr.encode());
                out.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
                let err_num: u32 = (*error_code).into();
                out.extend_from_slice(&err_num.to_be_bytes());
                out.extend_from_slice(debug_data);
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                let hdr = FrameHeader {
                    length: 4,
                    frame_type: FrameType::WindowUpdate,
                    flags: 0,
                    stream_id: *stream_id,
                };
                out.extend_from_slice(&hdr.encode());
                out.extend_from_slice(&(increment & 0x7fff_ffff).to_be_bytes());
            }
            Frame::Continuation {
                flags,
                stream_id,
                header_block,
            } => {
                let hdr = FrameHeader {
                    length: u32::try_from(header_block.len()).unwrap_or(u32::MAX),
                    frame_type: FrameType::Continuation,
                    flags: *flags,
                    stream_id: *stream_id,
                };
                out.extend_from_slice(&hdr.encode());
                out.extend_from_slice(header_block);
            }
            Frame::Unknown { header, payload } => {
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(payload);
            }
        }
    }

    /// The header block of a HEADERS frame's payload, as [`Self::decode`] takes it, without
    /// a copy (T437): the padding and the priority fields are left out.
    ///
    /// # Errors
    /// As [`Self::decode`] for a HEADERS frame.
    pub fn headers_block<'p>(header: &FrameHeader, payload: &'p [u8]) -> io::Result<&'p [u8]> {
        // RFC 9113 section 6.2: [pad length] [E + stream dependency + weight] block [padding].
        let mut body = strip_padding(header.flags, payload, if (header.flags & frame_flags::PRIORITY) != 0 { 5 } else { 0 })?;
        if (header.flags & frame_flags::PRIORITY) != 0 {
            if body.len() < 5 {
                return Err(frame_size_error("HEADERS priority field truncated"));
            }
            let dep = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7fff_ffff;
            if dep == header.stream_id {
                // Measured on HAProxy 3.5-dev8: GOAWAY PROTOCOL_ERROR.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HEADERS stream depends on itself",
                ));
            }
            body = &body[5..];
        }
        Ok(body)
    }

    /// Decodes a complete frame given its header and payload bytes.
    ///
    /// # Errors
    /// Returns `io::Error` on invalid framing or length mismatch.
    #[allow(clippy::too_many_lines)]
    pub fn decode(header: &FrameHeader, payload: &[u8]) -> io::Result<Self> {
        if payload.len() != header.length as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Payload length mismatch: header claims {}, got {}",
                    header.length,
                    payload.len()
                ),
            ));
        }

        match header.frame_type {
            FrameType::Data => Ok(Frame::Data {
                flags: header.flags,
                stream_id: header.stream_id,
                data: strip_padding(header.flags, payload, 0)?.to_vec(),
            }),
            FrameType::Headers => Ok(Frame::Headers {
                flags: header.flags,
                stream_id: header.stream_id,
                header_block: Self::headers_block(header, payload)?.to_vec(),
            }),
            FrameType::Priority => {
                if payload.len() != 5 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PRIORITY frame payload must be 5 bytes",
                    ));
                }
                let raw_dep = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let exclusive = (raw_dep & 0x8000_0000) != 0;
                let stream_dependency = raw_dep & 0x7fff_ffff;
                let weight = payload[4];
                Ok(Frame::Priority {
                    stream_id: header.stream_id,
                    stream_dependency,
                    weight,
                    exclusive,
                })
            }
            FrameType::RstStream => {
                if payload.len() != 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "RST_STREAM payload must be 4 bytes",
                    ));
                }
                let err_num = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Frame::RstStream {
                    stream_id: header.stream_id,
                    error_code: H2Error::from(err_num),
                })
            }
            FrameType::Settings => {
                if !payload.len().is_multiple_of(6) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SETTINGS payload must be a multiple of 6 bytes",
                    ));
                }
                if (header.flags & frame_flags::ACK) != 0 && !payload.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SETTINGS ACK frame must have length 0",
                    ));
                }
                let mut settings = Vec::new();
                #[allow(clippy::chunks_exact_to_as_chunks)]
                for chunk in payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                    let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                    settings.push((SettingsParameter::from(id), val));
                }
                Ok(Frame::Settings {
                    flags: header.flags,
                    settings,
                })
            }
            FrameType::PushPromise => {
                let body = strip_padding(header.flags, payload, 4)?;
                if body.len() < 4 {
                    return Err(frame_size_error("PUSH_PROMISE frame payload too short"));
                }
                let promised_stream_id =
                    u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7fff_ffff;
                Ok(Frame::PushPromise {
                    flags: header.flags,
                    stream_id: header.stream_id,
                    promised_stream_id,
                    header_block: body[4..].to_vec(),
                })
            }
            FrameType::Ping => {
                if payload.len() != 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PING payload must be 8 bytes",
                    ));
                }
                let mut opaque_data = [0u8; 8];
                opaque_data.copy_from_slice(payload);
                Ok(Frame::Ping {
                    flags: header.flags,
                    opaque_data,
                })
            }
            FrameType::GoAway => {
                if payload.len() < 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "GOAWAY payload must be at least 8 bytes",
                    ));
                }
                let last_stream_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff;
                let err_num = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                Ok(Frame::GoAway {
                    last_stream_id,
                    error_code: H2Error::from(err_num),
                    debug_data: payload[8..].to_vec(),
                })
            }
            FrameType::WindowUpdate => {
                if payload.len() != 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "WINDOW_UPDATE payload must be 4 bytes",
                    ));
                }
                let increment =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff;
                // A zero increment decodes: whether it is a stream or a connection error
                // depends on the stream, which only the mux knows (RFC 9113 section 6.9).
                Ok(Frame::WindowUpdate {
                    stream_id: header.stream_id,
                    increment,
                })
            }
            FrameType::Continuation => Ok(Frame::Continuation {
                flags: header.flags,
                stream_id: header.stream_id,
                header_block: payload.to_vec(),
            }),
            FrameType::Unknown(_) => Ok(Frame::Unknown {
                header: *header,
                payload: payload.to_vec(),
            }),
        }
    }
}

/// Streaming HTTP/2 frame parser that decodes frames from a byte slice.
#[derive(Debug, Clone, Default)]
pub struct H2FrameParser {
    pub max_frame_size: u32,
}

impl H2FrameParser {
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }

    #[must_use]
    pub fn with_max_frame_size(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }

    /// Parses a single frame from `input`.
    /// Returns `Ok(Some((frame, consumed_bytes)))` when a full frame is decoded,
    /// `Ok(None)` when more bytes are needed, or `Err(H2Error)` on protocol error.
    ///
    /// # Errors
    /// Returns [`H2Error::FrameSizeError`] if frame payload exceeds `max_frame_size`,
    /// or [`H2Error::ProtocolError`] if framing syntax is violated.
    pub fn parse(&self, input: &[u8]) -> Result<Option<(Frame, usize)>, H2Error> {
        if input.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        let header =
            FrameHeader::decode(&input[..FRAME_HEADER_LEN]).map_err(|_| H2Error::ProtocolError)?;

        if header.length > self.max_frame_size {
            return Err(H2Error::FrameSizeError);
        }

        let total_len = FRAME_HEADER_LEN + (header.length as usize);
        if input.len() < total_len {
            return Ok(None);
        }

        let payload = &input[FRAME_HEADER_LEN..total_len];
        let frame = Frame::decode(&header, payload).map_err(|_| H2Error::ProtocolError)?;
        Ok(Some((frame, total_len)))
    }
}

/// HTTP/2 Connection Lifecycle State.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum H2ConnState {
    /// Awaiting client 24-byte preface (`PRI * HTTP/2.0...`).
    ExpectPreface,
    /// Preface received; awaiting client initial SETTINGS frame.
    ExpectSettings,
    /// Connection preface and initial settings exchanged; active multiplexing.
    Open,
    /// Outgoing GOAWAY sent; connection is draining or shutting down.
    GoAwaySent,
    /// Incoming GOAWAY received; no new streams permitted.
    GoAwayReceived,
    /// Connection closed.
    Closed,
    /// Unrecoverable connection error.
    Error(H2Error),
}

/// HTTP/2 Stream Lifecycle State (RFC 7540 §5.1).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum H2StreamState {
    /// Stream is idle; no frames sent or received.
    Idle,
    /// Stream is open; bidirectional frame transmission allowed.
    Open,
    /// Half-closed remote: remote endpoint sent `END_STREAM`.
    HalfClosedRemote,
    /// Half-closed local: local endpoint sent `END_STREAM`.
    HalfClosedLocal,
    /// Stream reset by `RST_STREAM`.
    Reset(H2Error),
    /// Stream closed.
    Closed,
}

/// Individual HTTP/2 stream state and per-stream flow control tracking (RFC 7540 §5.1, §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Stream {
    pub id: u32,
    pub state: H2StreamState,
    pub send_window: i32,
    pub recv_window: i32,
    pub is_local: bool,
}

impl H2Stream {
    #[must_use]
    pub fn new(
        id: u32,
        initial_send_window: i32,
        initial_recv_window: i32,
        is_local: bool,
    ) -> Self {
        Self {
            id,
            state: H2StreamState::Idle,
            send_window: initial_send_window,
            recv_window: initial_recv_window,
            is_local,
        }
    }

    /// Handles stream state transition when sending HEADERS.
    ///
    /// # Errors
    /// Returns [`H2Error::StreamClosed`] if stream is already closed or reset.
    pub fn on_send_headers(&mut self, end_stream: bool) -> Result<(), H2Error> {
        match self.state {
            H2StreamState::Idle => {
                self.state = if end_stream {
                    H2StreamState::HalfClosedLocal
                } else {
                    H2StreamState::Open
                };
                Ok(())
            }
            H2StreamState::Open => {
                if end_stream {
                    self.state = H2StreamState::HalfClosedLocal;
                }
                Ok(())
            }
            H2StreamState::HalfClosedRemote => {
                if end_stream {
                    self.state = H2StreamState::Closed;
                }
                Ok(())
            }
            H2StreamState::HalfClosedLocal | H2StreamState::Closed | H2StreamState::Reset(_) => {
                Err(H2Error::StreamClosed)
            }
        }
    }

    /// Handles stream state transition when receiving HEADERS.
    ///
    /// # Errors
    /// Returns [`H2Error::StreamClosed`] if stream is already closed or reset.
    pub fn on_recv_headers(&mut self, end_stream: bool) -> Result<(), H2Error> {
        match self.state {
            H2StreamState::Idle => {
                self.state = if end_stream {
                    H2StreamState::HalfClosedRemote
                } else {
                    H2StreamState::Open
                };
                Ok(())
            }
            H2StreamState::Open => {
                if end_stream {
                    self.state = H2StreamState::HalfClosedRemote;
                }
                Ok(())
            }
            H2StreamState::HalfClosedLocal => {
                if end_stream {
                    self.state = H2StreamState::Closed;
                }
                Ok(())
            }
            H2StreamState::HalfClosedRemote | H2StreamState::Closed | H2StreamState::Reset(_) => {
                Err(H2Error::StreamClosed)
            }
        }
    }

    /// Handles sending DATA on this stream, deducting from per-stream send window.
    ///
    /// # Errors
    /// Returns [`H2Error::FlowControlError`] if length exceeds available window,
    /// or [`H2Error::StreamClosed`] if stream is not in sending state.
    pub fn on_send_data(&mut self, len: usize, end_stream: bool) -> Result<(), H2Error> {
        match self.state {
            H2StreamState::Open | H2StreamState::HalfClosedRemote => {
                let len_i32 = i32::try_from(len).map_err(|_| H2Error::FlowControlError)?;
                if len_i32 > self.send_window {
                    return Err(H2Error::FlowControlError);
                }
                self.send_window -= len_i32;
                if end_stream {
                    self.state = match self.state {
                        H2StreamState::HalfClosedRemote => H2StreamState::Closed,
                        _ => H2StreamState::HalfClosedLocal,
                    };
                }
                Ok(())
            }
            _ => Err(H2Error::StreamClosed),
        }
    }

    /// Handles receiving DATA on this stream, deducting from per-stream recv window.
    ///
    /// # Errors
    /// Returns [`H2Error::StreamClosed`] if stream is not in receiving state.
    pub fn on_recv_data(&mut self, len: usize, end_stream: bool) -> Result<(), H2Error> {
        match self.state {
            H2StreamState::Open | H2StreamState::HalfClosedLocal => {
                let len_i32 = i32::try_from(len).map_err(|_| H2Error::FlowControlError)?;
                self.recv_window = self.recv_window.saturating_sub(len_i32);
                if end_stream {
                    self.state = match self.state {
                        H2StreamState::HalfClosedLocal => H2StreamState::Closed,
                        _ => H2StreamState::HalfClosedRemote,
                    };
                }
                Ok(())
            }
            _ => Err(H2Error::StreamClosed),
        }
    }

    /// Resets the stream upon sending or receiving `RST_STREAM`.
    pub fn on_rst(&mut self, err: H2Error) {
        self.state = H2StreamState::Reset(err);
    }

    /// Updates send window on receiving `WINDOW_UPDATE`.
    ///
    /// # Errors
    /// Returns [`H2Error::FlowControlError`] if increment causes window to exceed 2^31 - 1.
    pub fn update_send_window(&mut self, increment: u32) -> Result<(), H2Error> {
        let new_w = i64::from(self.send_window) + i64::from(increment);
        if new_w > i64::from(MAX_WINDOW_SIZE) {
            return Err(H2Error::FlowControlError);
        }
        self.send_window = i32::try_from(new_w).map_err(|_| H2Error::FlowControlError)?;
        Ok(())
    }

    /// Adjusts send window when `SETTINGS_INITIAL_WINDOW_SIZE` changes.
    ///
    /// # Errors
    /// Returns [`H2Error::FlowControlError`] if adjustment causes window to exceed 2^31 - 1.
    pub fn adjust_initial_window(&mut self, delta: i32) -> Result<(), H2Error> {
        let new_w = i64::from(self.send_window) + i64::from(delta);
        if new_w > i64::from(MAX_WINDOW_SIZE) {
            return Err(H2Error::FlowControlError);
        }
        self.send_window = i32::try_from(new_w).map_err(|_| H2Error::FlowControlError)?;
        Ok(())
    }
}

/// Endpoint role in the HTTP/2 connection.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum H2Role {
    Client,
    Server,
}

/// Events emitted when processing HTTP/2 frames in the multiplexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2Event {
    Headers {
        stream_id: u32,
        headers: Vec<HeaderField>,
        end_stream: bool,
    },
    Data {
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    RstStream {
        stream_id: u32,
        error_code: H2Error,
    },
    Ping {
        opaque_data: [u8; 8],
        is_ack: bool,
    },
    GoAway {
        last_stream_id: u32,
        error_code: H2Error,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    SettingsUpdated,
    SettingsAck,
}

/// HTTP/2 Stream Multiplexer managing concurrent streams, connection and stream flow control,
/// HPACK dynamic table state, and frame dispatch under `#![forbid(unsafe_code)]`.
#[derive(Debug)]
pub struct H2Multiplexer {
    pub role: H2Role,
    pub conn_state: H2ConnState,
    pub conn_send_window: i32,
    pub conn_recv_window: i32,
    pub remote_initial_window: i32,
    pub local_initial_window: i32,
    pub max_frame_size: u32,
    pub max_concurrent_streams: u32,
    pub next_stream_id: u32,
    pub last_remote_stream_id: u32,
    pub streams: BTreeMap<u32, H2Stream>,
    pub hpack_decoder: HpackDecoder,
    pub hpack_encoder: HpackEncoder,
    continuation_stream: Option<u32>,
    continuation_buffer: Vec<u8>,
    continuation_end_stream: bool,
}

impl H2Multiplexer {
    /// Creates a new HTTP/2 Multiplexer instance with the specified role.
    #[must_use]
    pub fn new(role: H2Role) -> Self {
        let conn_state = match role {
            H2Role::Server => H2ConnState::ExpectPreface,
            H2Role::Client => H2ConnState::Open,
        };
        let next_stream_id = match role {
            H2Role::Client => 1,
            H2Role::Server => 2,
        };

        Self {
            role,
            conn_state,
            conn_send_window: DEFAULT_INITIAL_WINDOW_SIZE,
            conn_recv_window: DEFAULT_INITIAL_WINDOW_SIZE,
            remote_initial_window: DEFAULT_INITIAL_WINDOW_SIZE,
            local_initial_window: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_concurrent_streams: 100,
            next_stream_id,
            last_remote_stream_id: 0,
            streams: BTreeMap::new(),
            hpack_decoder: HpackDecoder::new(),
            hpack_encoder: HpackEncoder::new(),
            continuation_stream: None,
            continuation_buffer: Vec::new(),
            continuation_end_stream: false,
        }
    }

    /// Opens a new local stream and returns its assigned stream identifier.
    ///
    /// # Errors
    /// Returns [`H2Error::RefusedStream`] if concurrent stream limit is reached.
    pub fn open_stream(&mut self) -> Result<u32, H2Error> {
        let active_count = self
            .streams
            .values()
            .filter(|s| !matches!(s.state, H2StreamState::Closed | H2StreamState::Reset(_)))
            .count();

        if active_count >= self.max_concurrent_streams as usize {
            return Err(H2Error::RefusedStream);
        }

        let id = self.next_stream_id;
        self.next_stream_id += 2;

        let stream = H2Stream::new(
            id,
            self.remote_initial_window,
            self.local_initial_window,
            true,
        );
        self.streams.insert(id, stream);
        Ok(id)
    }

    /// Gets an immutable reference to a stream by identifier.
    #[must_use]
    pub fn stream(&self, id: u32) -> Option<&H2Stream> {
        self.streams.get(&id)
    }

    /// Gets a mutable reference to a stream by identifier.
    pub fn stream_mut(&mut self, id: u32) -> Option<&mut H2Stream> {
        self.streams.get_mut(&id)
    }

    /// Processes an incoming HTTP/2 frame, validating connection and stream state transitions.
    ///
    /// # Errors
    /// Returns an [`H2Error`] if protocol, flow control, or framing constraints are violated.
    #[allow(clippy::too_many_lines)]
    pub fn handle_frame(&mut self, frame: Frame) -> Result<Vec<H2Event>, H2Error> {
        // Enforce CONTINUATION atomicity (RFC 7540 §6.10)
        if let Some(c_sid) = self.continuation_stream {
            match frame {
                Frame::Continuation { stream_id, .. } if stream_id == c_sid => {}
                _ => return Err(H2Error::ProtocolError),
            }
        }

        let mut events = Vec::new();

        match frame {
            Frame::Data {
                flags,
                stream_id,
                data,
            } => {
                if stream_id == 0 {
                    return Err(H2Error::ProtocolError);
                }
                let end_stream = (flags & frame_flags::END_STREAM) != 0;

                let data_len_i32 =
                    i32::try_from(data.len()).map_err(|_| H2Error::FlowControlError)?;
                self.conn_recv_window = self.conn_recv_window.saturating_sub(data_len_i32);

                let stream = self
                    .streams
                    .get_mut(&stream_id)
                    .ok_or(H2Error::StreamClosed)?;
                stream.on_recv_data(data.len(), end_stream)?;

                events.push(H2Event::Data {
                    stream_id,
                    data,
                    end_stream,
                });
            }

            Frame::Headers {
                flags,
                stream_id,
                header_block,
            } => {
                if stream_id == 0 {
                    return Err(H2Error::ProtocolError);
                }
                let end_headers = (flags & frame_flags::END_HEADERS) != 0;
                let end_stream = (flags & frame_flags::END_STREAM) != 0;

                if end_headers {
                    let headers = self.hpack_decoder.decode(&header_block)?;
                    self.on_recv_stream_headers(stream_id, end_stream)?;
                    events.push(H2Event::Headers {
                        stream_id,
                        headers,
                        end_stream,
                    });
                } else {
                    self.continuation_stream = Some(stream_id);
                    self.continuation_buffer = header_block;
                    self.continuation_end_stream = end_stream;
                }
            }

            Frame::Continuation {
                flags,
                stream_id,
                header_block,
            } => {
                if stream_id == 0 {
                    return Err(H2Error::ProtocolError);
                }
                self.continuation_buffer.extend_from_slice(&header_block);
                let end_headers = (flags & frame_flags::END_HEADERS) != 0;

                if end_headers {
                    let block = std::mem::take(&mut self.continuation_buffer);
                    let end_stream = self.continuation_end_stream;
                    self.continuation_stream = None;

                    let headers = self.hpack_decoder.decode(&block)?;
                    self.on_recv_stream_headers(stream_id, end_stream)?;
                    events.push(H2Event::Headers {
                        stream_id,
                        headers,
                        end_stream,
                    });
                }
            }

            Frame::Settings { flags, settings } => {
                if (flags & frame_flags::ACK) != 0 {
                    events.push(H2Event::SettingsAck);
                } else {
                    for (param, val) in settings {
                        match param {
                            SettingsParameter::InitialWindowSize => {
                                let val_i32 =
                                    i32::try_from(val).map_err(|_| H2Error::FlowControlError)?;
                                if val_i32 < 0 {
                                    return Err(H2Error::FlowControlError);
                                }
                                let delta = val_i32 - self.remote_initial_window;
                                self.remote_initial_window = val_i32;
                                for s in self.streams.values_mut() {
                                    s.adjust_initial_window(delta)?;
                                }
                            }
                            SettingsParameter::MaxFrameSize => {
                                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&val) {
                                    return Err(H2Error::ProtocolError);
                                }
                                self.max_frame_size = val;
                            }
                            SettingsParameter::HeaderTableSize => {
                                self.hpack_decoder.set_max_allowed_table_size(val as usize);
                            }
                            SettingsParameter::MaxConcurrentStreams => {
                                self.max_concurrent_streams = val;
                            }
                            _ => {}
                        }
                    }
                    events.push(H2Event::SettingsUpdated);
                }
            }

            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                if increment == 0 {
                    return Err(H2Error::ProtocolError);
                }
                if stream_id == 0 {
                    let new_w = i64::from(self.conn_send_window) + i64::from(increment);
                    if new_w > i64::from(MAX_WINDOW_SIZE) {
                        return Err(H2Error::FlowControlError);
                    }
                    self.conn_send_window =
                        i32::try_from(new_w).map_err(|_| H2Error::FlowControlError)?;
                } else {
                    let stream = self
                        .streams
                        .get_mut(&stream_id)
                        .ok_or(H2Error::StreamClosed)?;
                    stream.update_send_window(increment)?;
                }
                events.push(H2Event::WindowUpdate {
                    stream_id,
                    increment,
                });
            }

            Frame::RstStream {
                stream_id,
                error_code,
            } => {
                if stream_id == 0 {
                    return Err(H2Error::ProtocolError);
                }
                if let Some(stream) = self.streams.get_mut(&stream_id) {
                    stream.on_rst(error_code);
                }
                events.push(H2Event::RstStream {
                    stream_id,
                    error_code,
                });
            }

            Frame::Ping { flags, opaque_data } => {
                let is_ack = (flags & frame_flags::ACK) != 0;
                events.push(H2Event::Ping {
                    opaque_data,
                    is_ack,
                });
            }

            Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                self.conn_state = H2ConnState::GoAwayReceived;
                events.push(H2Event::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                });
            }

            Frame::Priority { .. } | Frame::PushPromise { .. } | Frame::Unknown { .. } => {}
        }

        Ok(events)
    }

    fn on_recv_stream_headers(&mut self, stream_id: u32, end_stream: bool) -> Result<(), H2Error> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.on_recv_headers(end_stream)
        } else {
            // New remote stream initiated
            if stream_id <= self.last_remote_stream_id {
                return Err(H2Error::ProtocolError);
            }
            self.last_remote_stream_id = stream_id;

            let mut stream = H2Stream::new(
                stream_id,
                self.remote_initial_window,
                self.local_initial_window,
                false,
            );
            stream.on_recv_headers(end_stream)?;
            self.streams.insert(stream_id, stream);
            Ok(())
        }
    }

    /// Formats and emits HEADERS and optional CONTINUATION frames for a stream.
    ///
    /// # Errors
    /// Returns [`H2Error::StreamClosed`] if stream cannot send headers.
    pub fn send_headers(
        &mut self,
        stream_id: u32,
        headers: &[HeaderField],
        end_stream: bool,
    ) -> Result<Vec<Frame>, H2Error> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(H2Error::StreamClosed)?;
        stream.on_send_headers(end_stream)?;

        let block = self.hpack_encoder.encode(headers);
        let max_chunk = self.max_frame_size as usize;

        if block.len() <= max_chunk {
            let mut flags = frame_flags::END_HEADERS;
            if end_stream {
                flags |= frame_flags::END_STREAM;
            }
            Ok(vec![Frame::Headers {
                flags,
                stream_id,
                header_block: block,
            }])
        } else {
            let mut frames = Vec::new();
            let mut first = true;
            for chunk in block.chunks(max_chunk) {
                if first {
                    let mut flags = 0;
                    if end_stream {
                        flags |= frame_flags::END_STREAM;
                    }
                    frames.push(Frame::Headers {
                        flags,
                        stream_id,
                        header_block: chunk.to_vec(),
                    });
                    first = false;
                } else {
                    frames.push(Frame::Continuation {
                        flags: 0,
                        stream_id,
                        header_block: chunk.to_vec(),
                    });
                }
            }
            if let Some(Frame::Headers { flags, .. } | Frame::Continuation { flags, .. }) =
                frames.last_mut()
            {
                *flags |= frame_flags::END_HEADERS;
            }
            Ok(frames)
        }
    }

    /// Formats and emits DATA frames for a stream, obeying connection and stream flow control windows.
    ///
    /// # Errors
    /// Returns [`H2Error::FlowControlError`] if sending requires more window than available,
    /// or [`H2Error::StreamClosed`] if stream is closed.
    pub fn send_data(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> Result<Vec<Frame>, H2Error> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(H2Error::StreamClosed)?;

        let data_len = data.len();
        let conn_w = usize::try_from(self.conn_send_window.max(0)).unwrap_or(0);
        let stream_w = usize::try_from(stream.send_window.max(0)).unwrap_or(0);
        let avail_window = conn_w.min(stream_w);

        if data_len > avail_window {
            return Err(H2Error::FlowControlError);
        }

        stream.on_send_data(data_len, end_stream)?;
        let data_len_i32 = i32::try_from(data_len).map_err(|_| H2Error::FlowControlError)?;
        self.conn_send_window -= data_len_i32;

        let max_chunk = self.max_frame_size as usize;
        let mut frames = Vec::new();

        if data.is_empty() {
            let flags = if end_stream {
                frame_flags::END_STREAM
            } else {
                0
            };
            frames.push(Frame::Data {
                flags,
                stream_id,
                data: Vec::new(),
            });
            return Ok(frames);
        }

        let chunks: Vec<&[u8]> = data.chunks(max_chunk).collect();
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.into_iter().enumerate() {
            let is_last = i == num_chunks - 1;
            let mut flags = 0;
            if is_last && end_stream {
                flags |= frame_flags::END_STREAM;
            }
            frames.push(Frame::Data {
                flags,
                stream_id,
                data: chunk.to_vec(),
            });
        }

        Ok(frames)
    }

    /// Formats an outgoing `WINDOW_UPDATE` frame.
    ///
    /// # Errors
    /// Returns [`H2Error::ProtocolError`] if increment is 0.
    pub fn send_window_update(&mut self, stream_id: u32, increment: u32) -> Result<Frame, H2Error> {
        if increment == 0 {
            return Err(H2Error::ProtocolError);
        }
        let inc_i32 = i32::try_from(increment).map_err(|_| H2Error::FlowControlError)?;
        if stream_id == 0 {
            self.conn_recv_window = self.conn_recv_window.checked_add(inc_i32).ok_or(H2Error::FlowControlError)?;
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_window = stream.recv_window.checked_add(inc_i32).ok_or(H2Error::FlowControlError)?;
        }
        Ok(Frame::WindowUpdate {
            stream_id,
            increment,
        })
    }

    /// Emits a `RST_STREAM` frame and transitions stream to `Reset`.
    pub fn send_rst_stream(&mut self, stream_id: u32, error_code: H2Error) -> Frame {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.on_rst(error_code);
        }
        Frame::RstStream {
            stream_id,
            error_code,
        }
    }

    /// Emits a `GOAWAY` frame and marks connection as `GoAwaySent`.
    pub fn send_goaway(&mut self, error_code: H2Error, debug_data: &[u8]) -> Frame {
        self.conn_state = H2ConnState::GoAwaySent;
        Frame::GoAway {
            last_stream_id: self.last_remote_stream_id,
            error_code,
            debug_data: debug_data.to_vec(),
        }
    }

    /// Emits a `SETTINGS` frame.
    #[must_use]
    pub fn send_settings(&self, settings: Vec<(SettingsParameter, u32)>) -> Frame {
        Frame::Settings { flags: 0, settings }
    }

    /// Emits a `SETTINGS` ACK frame.
    #[must_use]
    pub fn send_settings_ack(&self) -> Frame {
        Frame::Settings {
            flags: frame_flags::ACK,
            settings: Vec::new(),
        }
    }

    /// Emits a `PING` frame.
    #[must_use]
    pub fn send_ping(&self, opaque_data: [u8; 8], ack: bool) -> Frame {
        let flags = if ack { frame_flags::ACK } else { 0 };
        Frame::Ping { flags, opaque_data }
    }
}

/// A request's fields as HTTP/2 decoded them that are malformed (RFC 9113 section 8.2):
/// the stream is reset PROTOCOL_ERROR and nothing reaches the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedFields;

/// The pseudo-headers `h2_str_to_phdr` knows: their name is checked from the second byte.
fn known_pseudo(name: &str) -> bool {
    matches!(name, ":method" | ":scheme" | ":authority" | ":path" | ":protocol" | ":status")
}

/// The name a field may have (`h2_make_htx_request`): tokens without uppercase, the colon
/// of a known pseudo-header excepted.
fn name_ok(name: &str) -> bool {
    let skip = usize::from(known_pseudo(name));
    !name.is_empty() && name.bytes().skip(skip).all(|b| !b.is_ascii_uppercase() && crate::h1::is_tchar(b))
}

/// `http_header_has_forbidden_char`: NUL, CR and LF are refused in any value, since an
/// HTTP/1 head written from it would carry them as line ends (RFC 9113 section 8.2.1).
fn value_ok(value: &str) -> bool {
    !value.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n'))
}

/// `http_path_has_forbidden_char`: a `:path` takes no control byte, space or `#`.
fn path_ok(value: &str) -> bool {
    !value.bytes().any(|b| b <= b' ' || b == b'#')
}

/// `http_validate_scheme`: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) (RFC 3986 3.1).
fn scheme_ok(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphabetic()) && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
}

/// The checks `HAProxy` makes of each field of a decoded HTTP/2 request
/// (`h2_make_htx_request`, `h2_prepare_htx_reqline`), before anything writes them into a
/// head: they hold for the HTX blocks and for a head written as HTTP/1.1 text alike.
///
/// `Err` is a malformed request (`RST_STREAM` PROTOCOL_ERROR): a name that is not a
/// lowercase token, NUL / CR / LF in a value, a `:path` with a control byte, space or `#`
/// or that is neither absolute nor `*`, an `:authority` or `host` that
/// `http_authority_has_forbidden_char` refuses, a connection-specific header, `te` other
/// than `trailers`. `Ok(true)` is a request `HAProxy` takes and answers 400
/// (`HTX_FL_PARSING_ERROR`): a method that is not a token, a scheme that is not one, a URI
/// with a blank or a control byte (DEL).
///
/// # Errors
/// [`MalformedFields`] as above.
///
/// `relaxed` is `option accept-unsafe-violations-in-http-request`: a `:path` is then
/// checked as any value (NUL / CR / LF refused), so a `#` passes and a blank or control
/// byte is a 400.
pub fn check_request_fields<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>, relaxed: bool) -> Result<bool, MalformedFields> {
    let mut bad_request = false;
    let lws_or_ctl = |s: &str| s.bytes().any(|b| b <= b' ' || b == 0x7f);
    for (name, value) in fields {
        if !name_ok(name) {
            return Err(MalformedFields);
        }
        let valid = match name {
            ":path" => (if relaxed { value_ok(value) } else { path_ok(value) }) && (value.is_empty() || value.starts_with('/') || value == "*"),
            ":authority" | "host" => value_ok(value) && !crate::authority::has_forbidden_char(value.as_bytes()),
            "connection" | "proxy-connection" | "keep-alive" | "upgrade" | "transfer-encoding" => false,
            "te" => value == "trailers",
            _ => value_ok(value),
        };
        if !valid {
            return Err(MalformedFields);
        }
        bad_request |= match name {
            ":method" => value.is_empty() || !value.bytes().all(crate::h1::is_tchar),
            ":scheme" => !scheme_ok(value),
            ":path" => lws_or_ctl(value),
            _ => false,
        };
    }
    Ok(bad_request)
}

/// The checks of `http_trailers_to_htx` on trailers: a name that is a lowercase token, not
/// a pseudo-header nor one of the fields a trailer may not carry, a value without NUL, CR or
/// LF.
///
/// # Errors
/// [`MalformedFields`] for any other.
pub fn check_trailer_fields<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<(), MalformedFields> {
    for (name, value) in fields {
        let forbidden = matches!(
            name,
            "host" | "content-length" | "connection" | "proxy-connection" | "keep-alive" | "upgrade" | "te" | "transfer-encoding"
        );
        if name.starts_with(':') || !name_ok(name) || forbidden || !value_ok(value) {
            return Err(MalformedFields);
        }
    }
    Ok(())
}

/// The checks of `h2_make_htx_response` on each field of a response: a lowercase token
/// name (a known pseudo-header from its second byte), a value without NUL, CR or LF.
///
/// # Errors
/// [`MalformedFields`] for any other.
pub fn check_response_fields<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<(), MalformedFields> {
    for (name, value) in fields {
        if !name_ok(name) || !value_ok(value) {
            return Err(MalformedFields);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T449: the field checks of `h2_make_htx_request` / `http_trailers_to_htx`, as measured
    /// on HAProxy 3.5-dev8 (`h2_field_validity` drives them through a running proxy).
    #[test]
    fn request_and_trailer_fields_are_checked_as_haproxy_checks_them() {
        let req = |f: &[(&'static str, &'static str)]| check_request_fields(f.iter().copied(), false);
        let base = [(":method", "GET"), (":scheme", "https"), (":path", "/a?b"), (":authority", "[::1]:8443")];
        assert_eq!(req(&base), Ok(false));
        assert_eq!(req(&[(":path", "*"), ("te", "trailers"), ("x-a", "a\t\x01\x7fb")]), Ok(false));
        for bad in [
            ("x-a", "b\r\nx-injected: 1"), ("x-a", "b\0"), ("x-a\r", "1"), ("X-a", "1"), ("", "1"), (":x", "1"),
            (":path", "/a b"), (":path", "/a#b"), (":path", "a"), (":authority", "u@x"), ("host", "x,y"),
            (":method", "GET\n"), ("connection", "close"), ("te", "gzip"), ("transfer-encoding", "chunked"),
        ] {
            assert_eq!(req(&[bad]), Err(MalformedFields), "{bad:?}");
        }
        for bad_request in [(":method", "GE T"), (":method", ""), (":scheme", "1http"), (":path", "/a\x7f")] {
            assert_eq!(req(&[bad_request]), Ok(true), "{bad_request:?}");
        }
        let trl = |f: &[(&'static str, &'static str)]| check_trailer_fields(f.iter().copied());
        assert_eq!(trl(&[("x-t", "1"), ("grpc-status", "0")]), Ok(()));
        for bad in [(":path", "/"), ("X-t", "1"), ("content-length", "1"), ("host", "x"), ("x-t", "a\rb")] {
            assert_eq!(trl(&[bad]), Err(MalformedFields), "{bad:?}");
        }
    }
    use proptest::prelude::*;

    #[test]
    fn test_preface_constant() {
        assert_eq!(H2_CONN_PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert_eq!(H2_CONN_PREFACE.len(), 24);
    }

    #[test]
    fn test_frame_header_codec() {
        let hdr = FrameHeader {
            length: 1234,
            frame_type: FrameType::Headers,
            flags: frame_flags::END_STREAM | frame_flags::END_HEADERS,
            stream_id: 17,
        };
        let encoded = hdr.encode();
        assert_eq!(encoded.len(), 9);
        let decoded = FrameHeader::decode(&encoded).expect("decode");
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn test_settings_frame_codec() {
        let frame = Frame::Settings {
            flags: 0,
            settings: vec![
                (SettingsParameter::MaxConcurrentStreams, 100),
                (SettingsParameter::InitialWindowSize, 1_048_576),
            ],
        };
        let bytes = frame.encode();
        let hdr = FrameHeader::decode(&bytes[..9]).unwrap();
        let decoded = Frame::decode(&hdr, &bytes[9..]).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_rst_stream_codec() {
        let frame = Frame::RstStream {
            stream_id: 3,
            error_code: H2Error::Cancel,
        };
        let bytes = frame.encode();
        let hdr = FrameHeader::decode(&bytes[..9]).unwrap();
        let decoded = Frame::decode(&hdr, &bytes[9..]).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_goaway_codec() {
        let frame = Frame::GoAway {
            last_stream_id: 9,
            error_code: H2Error::NoError,
            debug_data: b"graceful shutdown".to_vec(),
        };
        let bytes = frame.encode();
        let hdr = FrameHeader::decode(&bytes[..9]).unwrap();
        let decoded = Frame::decode(&hdr, &bytes[9..]).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_window_update_codec() {
        let frame = Frame::WindowUpdate {
            stream_id: 1,
            increment: 65535,
        };
        let bytes = frame.encode();
        let hdr = FrameHeader::decode(&bytes[..9]).unwrap();
        let decoded = Frame::decode(&hdr, &bytes[9..]).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn test_h2_frame_parser_streaming() {
        let parser = H2FrameParser::new();
        let frame = Frame::Ping {
            flags: frame_flags::ACK,
            opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let bytes = frame.encode();

        // Feed partial bytes
        assert!(parser.parse(&bytes[..5]).unwrap().is_none());
        assert!(parser.parse(&bytes[..12]).unwrap().is_none());

        // Full frame
        let (parsed, consumed) = parser.parse(&bytes).unwrap().unwrap();
        assert_eq!(parsed, frame);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn test_multiplexer_stream_lifecycle() {
        let mut mux = H2Multiplexer::new(H2Role::Server);
        assert_eq!(mux.conn_state, H2ConnState::ExpectPreface);

        // Server receives headers on stream 1
        let mut enc = HpackEncoder::new();
        let headers = vec![
            HeaderField {
                name: ":method".to_string(),
                value: "GET".to_string(),
            },
            HeaderField {
                name: ":path".to_string(),
                value: "/index.html".to_string(),
            },
        ];
        let block = enc.encode(&headers);

        let frame = Frame::Headers {
            flags: frame_flags::END_HEADERS,
            stream_id: 1,
            header_block: block,
        };

        let events = mux.handle_frame(frame).expect("handle headers");
        assert_eq!(events.len(), 1);
        let stream = mux.stream(1).expect("stream 1 created");
        assert_eq!(stream.state, H2StreamState::Open);

        // Remote sends DATA with END_STREAM
        let data_frame = Frame::Data {
            flags: frame_flags::END_STREAM,
            stream_id: 1,
            data: b"hello".to_vec(),
        };
        let events = mux.handle_frame(data_frame).expect("handle data");
        assert_eq!(events.len(), 1);
        let stream = mux.stream(1).expect("stream 1");
        assert_eq!(stream.state, H2StreamState::HalfClosedRemote);

        // Server replies with headers and data ending stream
        let res_headers = vec![HeaderField {
            name: ":status".to_string(),
            value: "200".to_string(),
        }];
        let out_headers = mux
            .send_headers(1, &res_headers, false)
            .expect("send res headers");
        assert!(!out_headers.is_empty());

        let out_data = mux.send_data(1, b"world", true).expect("send res data");
        assert!(!out_data.is_empty());

        // Stream is now fully Closed!
        assert_eq!(mux.stream(1).unwrap().state, H2StreamState::Closed);
    }

    #[test]
    fn test_multiplexer_flow_control() {
        let mut mux = H2Multiplexer::new(H2Role::Client);
        let sid = mux.open_stream().expect("open stream");

        // Initial windows should be 65,535
        assert_eq!(mux.conn_send_window, 65_535);
        assert_eq!(mux.stream(sid).unwrap().send_window, 65_535);

        // Transition stream to Open by sending headers
        let headers = vec![
            HeaderField {
                name: ":method".to_string(),
                value: "POST".to_string(),
            },
            HeaderField {
                name: ":path".to_string(),
                value: "/upload".to_string(),
            },
        ];
        mux.send_headers(sid, &headers, false)
            .expect("send headers");

        // Send 10,000 bytes
        let data = vec![0u8; 10_000];
        let frames = mux.send_data(sid, &data, false).expect("send data");
        assert!(!frames.is_empty());

        assert_eq!(mux.conn_send_window, 55_535);
        assert_eq!(mux.stream(sid).unwrap().send_window, 55_535);

        // Peer sends WINDOW_UPDATE on stream and connection
        let wu_conn = Frame::WindowUpdate {
            stream_id: 0,
            increment: 5_000,
        };
        mux.handle_frame(wu_conn).expect("wu conn");
        assert_eq!(mux.conn_send_window, 60_535);

        let wu_stream = Frame::WindowUpdate {
            stream_id: sid,
            increment: 5_000,
        };
        mux.handle_frame(wu_stream).expect("wu stream");
        assert_eq!(mux.stream(sid).unwrap().send_window, 60_535);

        // Test flow control overflow detection
        let wu_overflow = Frame::WindowUpdate {
            stream_id: sid,
            increment: 0x7fff_ffff,
        };
        assert_eq!(
            mux.handle_frame(wu_overflow),
            Err(H2Error::FlowControlError)
        );
    }

    /// A WINDOW_UPDATE that would push a window past 2^31-1 is a flow-control error, on the
    /// connection and on a stream (gate 48, covercheck of VV-4's checked_add).
    #[test]
    fn send_window_update_refuses_to_overflow_a_window() {
        let mut mux = H2Multiplexer::new(H2Role::Server);
        mux.handle_frame(Frame::Headers { flags: 0x4, stream_id: 1, header_block: vec![0x82] })
            .expect("headers");
        mux.conn_recv_window = i32::MAX - 5;
        assert_eq!(mux.send_window_update(0, 10), Err(H2Error::FlowControlError));
        mux.streams.get_mut(&1).expect("stream").recv_window = i32::MAX - 5;
        assert_eq!(mux.send_window_update(1, 10), Err(H2Error::FlowControlError));
        assert!(mux.send_window_update(1, 5).is_ok());
    }

    #[test]
    fn test_continuation_atomicity_enforcement() {
        let mut mux = H2Multiplexer::new(H2Role::Server);

        // HEADERS without END_HEADERS
        let headers_frame = Frame::Headers {
            flags: 0, // No END_HEADERS
            stream_id: 1,
            header_block: vec![0x82],
        };
        mux.handle_frame(headers_frame)
            .expect("headers without end");

        // An intervening PING frame MUST be rejected with PROTOCOL_ERROR
        let ping = Frame::Ping {
            flags: 0,
            opaque_data: [0; 8],
        };
        assert_eq!(mux.handle_frame(ping), Err(H2Error::ProtocolError));
    }

    proptest! {
        #[test]
        fn prop_frame_header_roundtrip(
            length in 0u32..=16_777_215,
            frame_type in 0u8..=9,
            flags in 0u8..=255,
            stream_id in 0u32..=0x7fff_ffff
        ) {
            let hdr = FrameHeader {
                length,
                frame_type: FrameType::from(frame_type),
                flags,
                stream_id,
            };
            let enc = hdr.encode();
            let dec = FrameHeader::decode(&enc).expect("decode header");
            prop_assert_eq!(dec, hdr);
        }

        #[test]
        fn prop_window_update_roundtrip(
            stream_id in 0u32..=0x7fff_ffff,
            increment in 1u32..=0x7fff_ffff
        ) {
            let frame = Frame::WindowUpdate {
                stream_id,
                increment,
            };
            let bytes = frame.encode();
            let hdr = FrameHeader::decode(&bytes[..9]).unwrap();
            let dec = Frame::decode(&hdr, &bytes[9..]).unwrap();
            prop_assert_eq!(dec, frame);
        }

        #[test]
        fn prop_settings_roundtrip(val1 in 0u32..=1_000_000, val2 in 16_384u32..=16_777_215) {
            let frame = Frame::Settings {
                flags: 0,
                settings: vec![
                    (SettingsParameter::InitialWindowSize, val1),
                    (SettingsParameter::MaxFrameSize, val2),
                ],
            };
            let bytes = frame.encode();
            let hdr = FrameHeader::decode(&bytes[..9]).unwrap();
            let dec = Frame::decode(&hdr, &bytes[9..]).unwrap();
            prop_assert_eq!(dec, frame);
        }
    }

    fn dec(kind: FrameType, flags: u8, sid: u32, payload: &[u8]) -> io::Result<Frame> {
        let h = FrameHeader { length: payload.len() as u32, frame_type: kind, flags, stream_id: sid };
        Frame::decode(&h, payload)
    }

    fn block_of(f: io::Result<Frame>) -> Vec<u8> {
        let Ok(Frame::Headers { header_block, .. }) = f else { panic!("not a decoded HEADERS: {f:?}") };
        header_block
    }

    /// RFC 9113 section 6.2, Chrome's request: PRIORITY set, the 5 bytes are not HPACK.
    #[test]
    fn headers_priority_field_is_not_part_of_the_block() {
        let flags = frame_flags::END_HEADERS | frame_flags::END_STREAM | frame_flags::PRIORITY;
        let got = block_of(dec(FrameType::Headers, flags, 1, &[0x80, 0, 0, 0, 0xff, 0x82, 0x87]));
        assert_eq!(got, [0x82, 0x87]);
    }

    #[test]
    fn headers_padding_is_stripped() {
        let flags = frame_flags::END_HEADERS | frame_flags::PADDED;
        let got = block_of(dec(FrameType::Headers, flags, 1, &[3, 0x82, 0x87, 0, 0, 0]));
        assert_eq!(got, [0x82, 0x87]);
    }

    #[test]
    fn headers_padded_and_priority_together() {
        let flags = frame_flags::END_HEADERS | frame_flags::PADDED | frame_flags::PRIORITY;
        let got = block_of(dec(FrameType::Headers, flags, 1, &[2, 0, 0, 0, 0, 16, 0x82, 0, 0]));
        assert_eq!(got, [0x82]);
        // A pad length of exactly what is left is fine: an empty block.
        let got = block_of(dec(FrameType::Headers, flags, 1, &[2, 0, 0, 0, 0, 16, 0, 0]));
        assert!(got.is_empty());
    }

    #[test]
    fn headers_pad_length_too_large_is_protocol_error() {
        let flags = frame_flags::END_HEADERS | frame_flags::PADDED;
        let e = dec(FrameType::Headers, flags, 1, &[3, 0x82, 0x87]).expect_err("pad > data");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // Pad length eating into the priority field.
        let flags = flags | frame_flags::PRIORITY;
        let e = dec(FrameType::Headers, flags, 1, &[1, 0, 0, 0, 0, 16]).expect_err("pad into priority");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    /// HAProxy answers FRAME_SIZE_ERROR (6) to these; InvalidInput is the marker for it.
    #[test]
    fn headers_truncated_fields_are_frame_size_errors() {
        let e = dec(FrameType::Headers, frame_frags_padded(), 1, &[]).expect_err("no pad length");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let e = dec(FrameType::Headers, frame_flags::PRIORITY, 1, &[0, 0]).expect_err("short priority");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    fn frame_frags_padded() -> u8 {
        frame_flags::PADDED
    }

    /// HAProxy: GOAWAY PROTOCOL_ERROR for a HEADERS that depends on its own stream.
    #[test]
    fn headers_depending_on_itself_is_protocol_error() {
        let e = dec(FrameType::Headers, frame_flags::PRIORITY, 5, &[0, 0, 0, 5, 16]).expect_err("self");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // The exclusive bit does not hide it.
        let e = dec(FrameType::Headers, frame_flags::PRIORITY, 5, &[0x80, 0, 0, 5, 16]).expect_err("self excl");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn data_padding_is_stripped_and_checked() {
        let f = dec(FrameType::Data, frame_flags::PADDED, 1, &[4, b'a', b'b', b'c', 0, 0, 0, 0]).expect("ok");
        assert!(matches!(f, Frame::Data { ref data, .. } if data == b"abc"));
        let f = dec(FrameType::Data, frame_flags::PADDED, 1, &[3, 0, 0, 0]).expect("all padding");
        assert!(matches!(f, Frame::Data { ref data, .. } if data.is_empty()));
        let e = dec(FrameType::Data, frame_flags::PADDED, 1, &[9, b'a']).expect_err("pad > data");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let e = dec(FrameType::Data, frame_flags::PADDED, 1, &[]).expect_err("no pad length");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn push_promise_too_short_is_frame_size_error() {
        let e = dec(FrameType::PushPromise, frame_flags::PADDED, 1, &[1, 0, 0, 2, 0]).expect_err("short");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "pad 1 leaves 3 of 4 id bytes");
        let e = dec(FrameType::PushPromise, 0, 1, &[0, 0, 2]).expect_err("short");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn push_promise_padding_is_stripped() {
        let f = dec(FrameType::PushPromise, frame_flags::PADDED | frame_flags::END_HEADERS, 1, &[2, 0, 0, 0, 2, 0x82, 0, 0])
            .expect("ok");
        assert!(matches!(f, Frame::PushPromise { promised_stream_id: 2, ref header_block, .. } if header_block == &[0x82]));
    }
}
