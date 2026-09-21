// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy doc/proxy-protocol.txt, include/haproxy/connection.h,
// include/haproxy/connection-t.h, and src/connection.c.
// Copyright (C) 2000-2026 Willy Tarreau <w@1wt.eu> and HAProxy contributors.
// See LICENSE in the repository root.

//! PROXY Protocol Versions 1 & 2 Parser, Encoder, and TLV Engine.
//!
//! This module provides a pure memory-safe, zero-allocation, strict implementation
//! of the `HAProxy` PROXY protocol (v1 text and v2 binary), as specified in
//! `doc/proxy-protocol.txt` and implemented in `HAProxy` 3.5.
//!
//! # Safety
//!
//! This implementation operates under strict `#![forbid(unsafe_code)]`. All parsing,
//! decoding, encoding, and TLV manipulation occur directly on bounded byte slices
//! without dynamic heap allocations on hot paths.
//!
//! # Protocol Overview
//!
//! - **Version 1**: Human-readable ASCII line format (`PROXY TCP4/TCP6/UNKNOWN ...\r\n`),
//!   bounded to a maximum of 107 characters (excluding terminating CRLF).
//! - **Version 2**: Binary format starting with the 12-byte signature
//!   `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`, followed by version/command,
//!   family/transport, 16-bit big-endian payload length, network-endian addresses,
//!   and arbitrary Type-Length-Value (TLV) extension vectors (e.g. ALPN, Authority/SNI,
//!   `CRC32c` checksum, Unique ID, SSL attributes and sub-TLVs, Netns).

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// 12-byte constant binary signature for PROXY protocol version 2.
pub const PP2_SIGNATURE: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

/// Initial ASCII prefix for PROXY protocol version 1.
pub const PP1_PREFIX: &[u8; 6] = b"PROXY ";

/// Maximum allowed length in bytes for a PROXY protocol version 1 header line (including CRLF).
pub const PP1_MAX_LINE_LEN: usize = 107;

/// Fixed header length in bytes for PROXY protocol version 2.
pub const PP2_HEADER_LEN: usize = 16;

/// Address length in bytes for `AF_INET` (IPv4) in PROXY protocol version 2 (4 + 4 + 2 + 2).
pub const PP2_ADDR_LEN_INET: usize = 12;

/// Address length in bytes for `AF_INET6` (IPv6) in PROXY protocol version 2 (16 + 16 + 2 + 2).
pub const PP2_ADDR_LEN_INET6: usize = 36;

/// Address length in bytes for `AF_UNIX` in PROXY protocol version 2 (108 + 108).
pub const PP2_ADDR_LEN_UNIX: usize = 216;

/// Registered TLV Types for PROXY protocol version 2.
pub mod tlv_types {
    /// Application-Layer Protocol Negotiation (ALPN) extension (RFC 7301).
    pub const PP2_TYPE_ALPN: u8 = 0x01;
    /// Authority / Server Name Indication (SNI) UTF-8 string (RFC 3546).
    pub const PP2_TYPE_AUTHORITY: u8 = 0x02;
    /// `CRC32c` checksum of the entire PROXY v2 header (RFC 4960 App B).
    pub const PP2_TYPE_CRC32C: u8 = 0x03;
    /// No-op padding / alignment vector.
    pub const PP2_TYPE_NOOP: u8 = 0x04;
    /// Opaque unique connection ID (up to 128 bytes).
    pub const PP2_TYPE_UNIQUE_ID: u8 = 0x05;
    /// SSL / TLS connection details container.
    pub const PP2_TYPE_SSL: u8 = 0x20;
    /// Sub-TLV: SSL version string (e.g., "TLSv1.3").
    pub const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21;
    /// Sub-TLV: SSL client certificate Common Name (CN).
    pub const PP2_SUBTYPE_SSL_CN: u8 = 0x22;
    /// Sub-TLV: SSL negotiated cipher suite name.
    pub const PP2_SUBTYPE_SSL_CIPHER: u8 = 0x23;
    /// Sub-TLV: SSL certificate signature algorithm name.
    pub const PP2_SUBTYPE_SSL_SIG_ALG: u8 = 0x24;
    /// Sub-TLV: SSL public key algorithm name.
    pub const PP2_SUBTYPE_SSL_KEY_ALG: u8 = 0x25;
    /// Sub-TLV: SSL key exchange group name (e.g. "secp256r1", "X25519").
    pub const PP2_SUBTYPE_SSL_GROUP: u8 = 0x26;
    /// Sub-TLV: SSL signature scheme name (e.g. "`rsa_pss_rsae_sha256`").
    pub const PP2_SUBTYPE_SSL_SIG_SCHEME: u8 = 0x27;
    /// Sub-TLV: Raw X.509 client certificate in ASN.1 DER encoding.
    pub const PP2_SUBTYPE_SSL_CLIENT_CERT: u8 = 0x28;
    /// Network namespace name string.
    pub const PP2_TYPE_NETNS: u8 = 0x30;

    /// Lower bound for custom application-specific TLV type range (0xE0..=0xEF).
    pub const PP2_TYPE_MIN_CUSTOM: u8 = 0xE0;
    /// Upper bound for custom application-specific TLV type range.
    pub const PP2_TYPE_MAX_CUSTOM: u8 = 0xEF;
    /// Lower bound for experimental TLV type range (0xF0..=0xF7).
    pub const PP2_TYPE_MIN_EXPERIMENT: u8 = 0xF0;
    /// Upper bound for experimental TLV type range.
    pub const PP2_TYPE_MAX_EXPERIMENT: u8 = 0xF7;
    /// Lower bound for future multi-byte type extension range (0xF8..=0xFF).
    pub const PP2_TYPE_MIN_FUTURE: u8 = 0xF8;
    /// Upper bound for future multi-byte type extension range.
    pub const PP2_TYPE_MAX_FUTURE: u8 = 0xFF;
}

/// Bit flags for the `client` field in `PP2_TYPE_SSL` TLVs.
pub mod ssl_client_flags {
    /// Client connected over SSL/TLS.
    pub const PP2_CLIENT_SSL: u8 = 0x01;
    /// Client provided a certificate over the current connection.
    pub const PP2_CLIENT_CERT_CONN: u8 = 0x02;
    /// Client provided a certificate at least once over this TLS session.
    pub const PP2_CLIENT_CERT_SESS: u8 = 0x04;
}

/// Lookup table for `CRC32c` (Castagnoli `0x1EDC6F41` reflected polynomial `0x82F63B78`),
/// compliant with RFC 4960 Appendix B and `HAProxy` 3.5.
const CRC32C_TABLE: [u32; 256] = [
    0x0000_0000,
    0xF26B_8303,
    0xE13B_70F7,
    0x1350_F3F4,
    0xC79A_971F,
    0x35F1_141C,
    0x26A1_E7E8,
    0xD4CA_64EB,
    0x8AD9_58CF,
    0x78B2_DBCC,
    0x6BE2_2838,
    0x9989_AB3B,
    0x4D43_CFD0,
    0xBF28_4CD3,
    0xAC78_BF27,
    0x5E13_3C24,
    0x105E_C76F,
    0xE235_446C,
    0xF165_B798,
    0x030E_349B,
    0xD7C4_5070,
    0x25AF_D373,
    0x36FF_2087,
    0xC494_A384,
    0x9A87_9FA0,
    0x68EC_1CA3,
    0x7BBC_EF57,
    0x89D7_6C54,
    0x5D1D_08BF,
    0xAF76_8BBC,
    0xBC26_7848,
    0x4E4D_FB4B,
    0x20BD_8EDE,
    0xD2D6_0DDD,
    0xC186_FE29,
    0x33ED_7D2A,
    0xE727_19C1,
    0x154C_9AC2,
    0x061C_6936,
    0xF477_EA35,
    0xAA64_D611,
    0x580F_5512,
    0x4B5F_A6E6,
    0xB934_25E5,
    0x6DFE_410E,
    0x9F95_C20D,
    0x8CC5_31F9,
    0x7EAE_B2FA,
    0x30E3_49B1,
    0xC288_CAB2,
    0xD1D8_3946,
    0x23B3_BA45,
    0xF779_DEAE,
    0x0512_5DAD,
    0x1642_AE59,
    0xE429_2D5A,
    0xBA3A_117E,
    0x4851_927D,
    0x5B01_6189,
    0xA96A_E28A,
    0x7DA0_8661,
    0x8FCB_0562,
    0x9C9B_F696,
    0x6EF0_7595,
    0x417B_1DBC,
    0xB310_9EBF,
    0xA040_6D4B,
    0x522B_EE48,
    0x86E1_8AA3,
    0x748A_09A0,
    0x67DA_FA54,
    0x95B1_7957,
    0xCBA2_4573,
    0x39C9_C670,
    0x2A99_3584,
    0xD8F2_B687,
    0x0C38_D26C,
    0xFE53_516F,
    0xED03_A29B,
    0x1F68_2198,
    0x5125_DAD3,
    0xA34E_59D0,
    0xB01E_AA24,
    0x4275_2927,
    0x96BF_4DCC,
    0x64D4_CECF,
    0x7784_3D3B,
    0x85EF_BE38,
    0xDBFC_821C,
    0x2997_011F,
    0x3AC7_F2EB,
    0xC8AC_71E8,
    0x1C66_1503,
    0xEE0D_9600,
    0xFD5D_65F4,
    0x0F36_E6F7,
    0x61C6_9362,
    0x93AD_1061,
    0x80FD_E395,
    0x7296_6096,
    0xA65C_047D,
    0x5437_877E,
    0x4767_748A,
    0xB50C_F789,
    0xEB1F_CBAD,
    0x1974_48AE,
    0x0A24_BB5A,
    0xF84F_3859,
    0x2C85_5CB2,
    0xDEEE_DFB1,
    0xCDBE_2C45,
    0x3FD5_AF46,
    0x7198_540D,
    0x83F3_D70E,
    0x90A3_24FA,
    0x62C8_A7F9,
    0xB602_C312,
    0x4469_4011,
    0x5739_B3E5,
    0xA552_30E6,
    0xFB41_0CC2,
    0x092A_8FC1,
    0x1A7A_7C35,
    0xE811_FF36,
    0x3CDB_9BDD,
    0xCEB0_18DE,
    0xDDE0_EB2A,
    0x2F8B_6829,
    0x82F6_3B78,
    0x709D_B87B,
    0x63CD_4B8F,
    0x91A6_C88C,
    0x456C_AC67,
    0xB707_2F64,
    0xA457_DC90,
    0x563C_5F93,
    0x082F_63B7,
    0xFA44_E0B4,
    0xE914_1340,
    0x1B7F_9043,
    0xCFB5_F4A8,
    0x3DDE_77AB,
    0x2E8E_845F,
    0xDCE5_075C,
    0x92A8_FC17,
    0x60C3_7F14,
    0x7393_8CE0,
    0x81F8_0FE3,
    0x5532_6B08,
    0xA759_E80B,
    0xB409_1BFF,
    0x4662_98FC,
    0x1871_A4D8,
    0xEA1A_27DB,
    0xF94A_D42F,
    0x0B21_572C,
    0xDFEB_33C7,
    0x2D80_B0C4,
    0x3ED0_4330,
    0xCCBB_C033,
    0xA24B_B5A6,
    0x5020_36A5,
    0x4370_C551,
    0xB11B_4652,
    0x65D1_22B9,
    0x97BA_A1BA,
    0x84EA_524E,
    0x7681_D14D,
    0x2892_ED69,
    0xDAF9_6E6A,
    0xC9A9_9D9E,
    0x3BC2_1E9D,
    0xEF08_7A76,
    0x1D63_F975,
    0x0E33_0A81,
    0xFC58_8982,
    0xB215_72C9,
    0x407E_F1CA,
    0x532E_023E,
    0xA145_813D,
    0x758F_E5D6,
    0x87E4_66D5,
    0x94B4_9521,
    0x66DF_1622,
    0x38CC_2A06,
    0xCAA7_A905,
    0xD9F7_5AF1,
    0x2B9C_D9F2,
    0xFF56_BD19,
    0x0D3D_3E1A,
    0x1E6D_CDEE,
    0xEC06_4EED,
    0xC38D_26C4,
    0x31E6_A5C7,
    0x22B6_5633,
    0xD0DD_D530,
    0x0417_B1DB,
    0xF67C_32D8,
    0xE52C_C12C,
    0x1747_422F,
    0x4954_7E0B,
    0xBB3F_FD08,
    0xA86F_0EFC,
    0x5A04_8DFF,
    0x8ECE_E914,
    0x7CA5_6A17,
    0x6FF5_99E3,
    0x9D9E_1AE0,
    0xD3D3_E1AB,
    0x21B8_62A8,
    0x32E8_915C,
    0xC083_125F,
    0x1449_76B4,
    0xE622_F5B7,
    0xF572_0643,
    0x0719_8540,
    0x590A_B964,
    0xAB61_3A67,
    0xB831_C993,
    0x4A5A_4A90,
    0x9E90_2E7B,
    0x6CFB_AD78,
    0x7FAB_5E8C,
    0x8DC0_DD8F,
    0xE330_A81A,
    0x115B_2B19,
    0x020B_D8ED,
    0xF060_5BEE,
    0x24AA_3F05,
    0xD6C1_BC06,
    0xC591_4FF2,
    0x37FA_CCF1,
    0x69E9_F0D5,
    0x9B82_73D6,
    0x88D2_8022,
    0x7AB9_0321,
    0xAE73_67CA,
    0x5C18_E4C9,
    0x4F48_173D,
    0xBD23_943E,
    0xF36E_6F75,
    0x0105_EC76,
    0x1255_1F82,
    0xE03E_9C81,
    0x34F4_F86A,
    0xC69F_7B69,
    0xD5CF_889D,
    0x27A4_0B9E,
    0x79B7_37BA,
    0x8BDC_B4B9,
    0x988C_474D,
    0x6AE7_C44E,
    0xBE2D_A0A5,
    0x4C46_23A6,
    0x5F16_D052,
    0xAD7D_5351,
];

/// Calculates the standard `CRC32c` checksum across a byte slice.
#[must_use]
pub fn calculate_crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc = (crc >> 8) ^ CRC32C_TABLE[((crc ^ u32::from(b)) & 0xff) as usize];
    }
    crc ^ 0xffff_ffff
}

/// PROXY protocol specification version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyVersion {
    /// Human-readable ASCII format (Version 1).
    V1,
    /// Binary format (Version 2).
    V2,
}

/// PROXY protocol command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyCommand {
    /// Connection established locally by proxy (e.g. health check).
    Local,
    /// Proxied connection on behalf of another node.
    Proxy,
}

/// Transport protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyTransport {
    /// Unspecified or unknown transport protocol.
    Unspec,
    /// Stream-oriented protocol (e.g., TCP or UNIX Stream).
    Stream,
    /// Datagram-oriented protocol (e.g., UDP or UNIX Datagram).
    Datagram,
}

/// Connection endpoint addresses carried in the PROXY protocol header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyAddress {
    /// Unspecified or unknown address family.
    Unspec,
    /// IPv4 connection addresses and 16-bit ports.
    Ipv4 {
        /// Layer 3 source IPv4 address.
        src_addr: Ipv4Addr,
        /// Layer 3 destination IPv4 address.
        dst_addr: Ipv4Addr,
        /// Layer 4 source port.
        src_port: u16,
        /// Layer 4 destination port.
        dst_port: u16,
    },
    /// IPv6 connection addresses and 16-bit ports.
    Ipv6 {
        /// Layer 3 source IPv6 address.
        src_addr: Ipv6Addr,
        /// Layer 3 destination IPv6 address.
        dst_addr: Ipv6Addr,
        /// Layer 4 source port.
        src_port: u16,
        /// Layer 4 destination port.
        dst_port: u16,
    },
    /// `AF_UNIX` socket addresses (up to 108 bytes each).
    Unix {
        /// Layer 3 source UNIX socket path bytes.
        src_addr: [u8; 108],
        /// Layer 3 destination UNIX socket path bytes.
        dst_addr: [u8; 108],
    },
}

impl ProxyAddress {
    /// Extracts the source address as a standard `SocketAddr` if IPv4 or IPv6.
    #[must_use]
    pub fn src_sockaddr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4 {
                src_addr, src_port, ..
            } => Some(SocketAddr::V4(SocketAddrV4::new(*src_addr, *src_port))),
            Self::Ipv6 {
                src_addr, src_port, ..
            } => Some(SocketAddr::V6(SocketAddrV6::new(
                *src_addr, *src_port, 0, 0,
            ))),
            Self::Unspec | Self::Unix { .. } => None,
        }
    }

    /// Extracts the destination address as a standard `SocketAddr` if IPv4 or IPv6.
    #[must_use]
    pub fn dst_sockaddr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ipv4 {
                dst_addr, dst_port, ..
            } => Some(SocketAddr::V4(SocketAddrV4::new(*dst_addr, *dst_port))),
            Self::Ipv6 {
                dst_addr, dst_port, ..
            } => Some(SocketAddr::V6(SocketAddrV6::new(
                *dst_addr, *dst_port, 0, 0,
            ))),
            Self::Unspec | Self::Unix { .. } => None,
        }
    }
}

/// Parsed or constructed PROXY protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHeader<'a> {
    /// Protocol version (V1 or V2).
    pub version: ProxyVersion,
    /// Protocol command (Local or Proxy).
    pub command: ProxyCommand,
    /// Transport layer protocol (Stream, Datagram, or Unspec).
    pub transport: ProxyTransport,
    /// Forwarded network addresses.
    pub address: ProxyAddress,
    /// Raw unparsed TLV vector slice for Version 2 headers.
    pub tlv_data: &'a [u8],
}

/// Errors returned during PROXY protocol header parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyParseError {
    /// Signature does not match either V1 (`"PROXY "`) or V2 (`PP2_SIGNATURE`).
    InvalidSignature,
    /// Header specifies an unsupported protocol version.
    UnsupportedVersion(u8),
    /// Header specifies an invalid command byte.
    InvalidCommand(u8),
    /// Header specifies an unrecognized address family.
    InvalidAddressFamily(u8),
    /// Header specifies an unrecognized transport protocol.
    InvalidTransport(u8),
    /// Header payload length is too small for the specified address family.
    InvalidLength {
        /// Expected minimum payload length in bytes.
        expected: usize,
        /// Actual payload length found in bytes.
        actual: usize,
    },
    /// Version 1 header exceeds 107 bytes without terminating CRLF.
    LineTooLong,
    /// Version 1 header is structurally malformed.
    InvalidV1Header,
    /// Invalid IP address string in Version 1 header.
    InvalidIpAddress,
    /// Invalid port integer in Version 1 header.
    InvalidPort,
    /// Unrecognized protocol keyword in Version 1 header (expected TCP4, TCP6, or UNKNOWN).
    InvalidProtocol,
    /// Incomplete 3-byte TLV header in TLV stream.
    TruncatedTlvHeader,
    /// TLV payload is shorter than the declared 16-bit length.
    TruncatedTlvValue {
        /// TLV type code.
        kind: u8,
        /// Expected length in bytes.
        expected: usize,
        /// Actual available bytes.
        available: usize,
    },
    /// TLV has an invalid length for its fixed schema.
    InvalidTlvLength {
        /// TLV type code.
        kind: u8,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length found.
        actual: usize,
    },
    /// String TLV contains invalid UTF-8 bytes.
    InvalidUtf8String {
        /// TLV type code.
        kind: u8,
    },
    /// `CRC32c` checksum validation failed.
    CrcMismatch {
        /// Expected checksum from TLV.
        expected: u32,
        /// Computed checksum over header.
        computed: u32,
    },
}

impl fmt::Display for ProxyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid PROXY protocol signature"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported PROXY protocol version: {v}"),
            Self::InvalidCommand(c) => write!(f, "invalid PROXY protocol command: {c:#04x}"),
            Self::InvalidAddressFamily(fam) => {
                write!(f, "invalid PROXY address family: {fam:#04x}")
            }
            Self::InvalidTransport(tr) => write!(f, "invalid PROXY transport protocol: {tr:#04x}"),
            Self::InvalidLength { expected, actual } => write!(
                f,
                "PROXY header length {actual} is smaller than required {expected}"
            ),
            Self::LineTooLong => write!(f, "PROXY v1 header line exceeds 107 bytes without CRLF"),
            Self::InvalidV1Header => write!(f, "malformed PROXY v1 header"),
            Self::InvalidIpAddress => write!(f, "invalid IP address in PROXY v1 header"),
            Self::InvalidPort => write!(f, "invalid port in PROXY v1 header"),
            Self::InvalidProtocol => write!(f, "invalid protocol keyword in PROXY v1 header"),
            Self::TruncatedTlvHeader => write!(f, "truncated TLV header in PROXY v2 stream"),
            Self::TruncatedTlvValue {
                kind,
                expected,
                available,
            } => write!(
                f,
                "truncated TLV type {kind:#04x}: expected {expected} bytes, got {available}"
            ),
            Self::InvalidTlvLength {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "invalid TLV length for type {kind:#04x}: expected {expected} bytes, got {actual}"
            ),
            Self::InvalidUtf8String { kind } => {
                write!(f, "invalid UTF-8 string in TLV type {kind:#04x}")
            }
            Self::CrcMismatch { expected, computed } => write!(
                f,
                "PROXY v2 CRC32c mismatch: expected {expected:#010x}, computed {computed:#010x}"
            ),
        }
    }
}

impl std::error::Error for ProxyParseError {}

/// Errors returned during PROXY protocol header encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEncodeError {
    /// Provided destination buffer is too small to hold the encoded header.
    BufferTooSmall {
        /// Needed bytes for serialization.
        needed: usize,
        /// Available buffer capacity.
        available: usize,
    },
    /// Total encoded header payload exceeds 65535 bytes (16-bit length overflow).
    LengthOverflow,
    /// Individual TLV value length exceeds 65535 bytes.
    TlvTooLarge {
        /// TLV type code.
        kind: u8,
        /// Attempted length in bytes.
        len: usize,
    },
    /// Address type cannot be represented in the chosen PROXY protocol version.
    InvalidAddressForVersion,
    /// `CRC32c` TLV was not found in buffer during CRC update.
    CrcNotFound,
}

impl fmt::Display for ProxyEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, available } => write!(
                f,
                "destination buffer too small: needed {needed} bytes, available {available}"
            ),
            Self::LengthOverflow => write!(f, "PROXY v2 header length exceeds 65535 bytes"),
            Self::TlvTooLarge { kind, len } => {
                write!(f, "TLV type {kind:#04x} length {len} exceeds 65535 bytes")
            }
            Self::InvalidAddressForVersion => write!(f, "incompatible address format for version"),
            Self::CrcNotFound => write!(f, "CRC32c TLV was not found in buffer"),
        }
    }
}

impl std::error::Error for ProxyEncodeError {}

impl<'a> ProxyHeader<'a> {
    /// Constructs a PROXY protocol Version 1 header with IPv4 endpoints.
    #[must_use]
    pub fn new_v1_ipv4(
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            version: ProxyVersion::V1,
            command: ProxyCommand::Proxy,
            transport: ProxyTransport::Stream,
            address: ProxyAddress::Ipv4 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            },
            tlv_data: &[],
        }
    }

    /// Constructs a PROXY protocol Version 1 header with IPv6 endpoints.
    #[must_use]
    pub fn new_v1_ipv6(
        src_addr: Ipv6Addr,
        dst_addr: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self {
            version: ProxyVersion::V1,
            command: ProxyCommand::Proxy,
            transport: ProxyTransport::Stream,
            address: ProxyAddress::Ipv6 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            },
            tlv_data: &[],
        }
    }

    /// Constructs a PROXY protocol Version 1 header representing an unknown/unspecified connection.
    #[must_use]
    pub fn new_v1_unknown() -> Self {
        Self {
            version: ProxyVersion::V1,
            command: ProxyCommand::Local,
            transport: ProxyTransport::Unspec,
            address: ProxyAddress::Unspec,
            tlv_data: &[],
        }
    }

    /// Constructs a PROXY protocol Version 2 header with IPv4 endpoints.
    #[must_use]
    pub fn new_v2_ipv4(
        command: ProxyCommand,
        transport: ProxyTransport,
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        tlv_data: &'a [u8],
    ) -> Self {
        Self {
            version: ProxyVersion::V2,
            command,
            transport,
            address: ProxyAddress::Ipv4 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            },
            tlv_data,
        }
    }

    /// Constructs a PROXY protocol Version 2 header with IPv6 endpoints.
    #[must_use]
    pub fn new_v2_ipv6(
        command: ProxyCommand,
        transport: ProxyTransport,
        src_addr: Ipv6Addr,
        dst_addr: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        tlv_data: &'a [u8],
    ) -> Self {
        Self {
            version: ProxyVersion::V2,
            command,
            transport,
            address: ProxyAddress::Ipv6 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            },
            tlv_data,
        }
    }

    /// Constructs a PROXY protocol Version 2 header with `AF_UNIX` endpoints.
    #[must_use]
    pub fn new_v2_unix(
        command: ProxyCommand,
        transport: ProxyTransport,
        src_addr: [u8; 108],
        dst_addr: [u8; 108],
        tlv_data: &'a [u8],
    ) -> Self {
        Self {
            version: ProxyVersion::V2,
            command,
            transport,
            address: ProxyAddress::Unix { src_addr, dst_addr },
            tlv_data,
        }
    }

    /// Constructs a PROXY protocol Version 2 header with unspecified endpoints.
    #[must_use]
    pub fn new_v2_unspec(
        command: ProxyCommand,
        transport: ProxyTransport,
        tlv_data: &'a [u8],
    ) -> Self {
        Self {
            version: ProxyVersion::V2,
            command,
            transport,
            address: ProxyAddress::Unspec,
            tlv_data,
        }
    }

    /// Constructs a PROXY protocol Version 2 LOCAL header (e.g. for health checks).
    #[must_use]
    pub fn new_v2_local() -> Self {
        Self {
            version: ProxyVersion::V2,
            command: ProxyCommand::Local,
            transport: ProxyTransport::Unspec,
            address: ProxyAddress::Unspec,
            tlv_data: &[],
        }
    }

    /// Parses a complete or partial PROXY protocol header from an immutable byte slice.
    ///
    /// # Return Value
    ///
    /// - `Ok(Some((header, bytes_consumed)))`: Header successfully parsed.
    /// - `Ok(None)`: Input buffer is incomplete (needs more data to finish parsing).
    /// - `Err(ProxyParseError)`: Input buffer is corrupt or invalid according to the specification.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyParseError`] if the buffer contains an invalid signature, unsupported version,
    /// corrupted address formatting, truncated TLVs, or a failing `CRC32c` checksum.
    pub fn parse(buf: &'a [u8]) -> Result<Option<(Self, usize)>, ProxyParseError> {
        if buf.is_empty() {
            return Ok(None);
        }

        // 1. Check for Version 2 binary signature
        if buf.len() >= 12 && &buf[..12] == PP2_SIGNATURE {
            return Self::parse_v2(buf);
        }

        // 2. Check for Version 1 text prefix
        if buf.len() >= 6 && &buf[..6] == PP1_PREFIX {
            return Self::parse_v1(buf);
        }

        // 3. Partial prefix checks: if buffer is shorter than full signatures, determine if valid prefix
        if buf.len() < 12 && PP2_SIGNATURE.starts_with(buf) {
            return Ok(None);
        }
        if buf.len() < 6 && PP1_PREFIX.starts_with(buf) {
            return Ok(None);
        }

        // Neither matches valid protocol prefix
        Err(ProxyParseError::InvalidSignature)
    }

    fn parse_v1(buf: &'a [u8]) -> Result<Option<(Self, usize)>, ProxyParseError> {
        let search_len = buf.len().min(PP1_MAX_LINE_LEN);
        let Some(crlf_pos) = find_crlf(&buf[..search_len]) else {
            if buf.len() >= PP1_MAX_LINE_LEN {
                return Err(ProxyParseError::LineTooLong);
            }
            return Ok(None);
        };

        let line = &buf[6..crlf_pos];
        let total_consumed = crlf_pos + 2;

        if line == b"UNKNOWN" || line.starts_with(b"UNKNOWN ") {
            return Ok(Some((
                Self {
                    version: ProxyVersion::V1,
                    command: ProxyCommand::Local,
                    transport: ProxyTransport::Unspec,
                    address: ProxyAddress::Unspec,
                    tlv_data: &[],
                },
                total_consumed,
            )));
        }

        if let Some(rest) = line.strip_prefix(b"TCP4 ") {
            let mut parts = rest.split(|&b| b == b' ');
            let src_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;
            let dst_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;
            let sport_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;
            let dport_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;

            if parts.next().is_some() {
                return Err(ProxyParseError::InvalidV1Header);
            }

            let src_addr = parse_v1_ipv4(src_s).ok_or(ProxyParseError::InvalidIpAddress)?;
            let dst_addr = parse_v1_ipv4(dst_s).ok_or(ProxyParseError::InvalidIpAddress)?;
            let src_port = parse_v1_port(sport_s).ok_or(ProxyParseError::InvalidPort)?;
            let dst_port = parse_v1_port(dport_s).ok_or(ProxyParseError::InvalidPort)?;

            return Ok(Some((
                Self {
                    version: ProxyVersion::V1,
                    command: ProxyCommand::Proxy,
                    transport: ProxyTransport::Stream,
                    address: ProxyAddress::Ipv4 {
                        src_addr,
                        dst_addr,
                        src_port,
                        dst_port,
                    },
                    tlv_data: &[],
                },
                total_consumed,
            )));
        }

        if let Some(rest) = line.strip_prefix(b"TCP6 ") {
            let mut parts = rest.split(|&b| b == b' ');
            let src_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;
            let dst_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;
            let sport_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;
            let dport_s = parts.next().ok_or(ProxyParseError::InvalidV1Header)?;

            if parts.next().is_some() {
                return Err(ProxyParseError::InvalidV1Header);
            }

            let src_addr = parse_v1_ipv6(src_s).ok_or(ProxyParseError::InvalidIpAddress)?;
            let dst_addr = parse_v1_ipv6(dst_s).ok_or(ProxyParseError::InvalidIpAddress)?;
            let src_port = parse_v1_port(sport_s).ok_or(ProxyParseError::InvalidPort)?;
            let dst_port = parse_v1_port(dport_s).ok_or(ProxyParseError::InvalidPort)?;

            return Ok(Some((
                Self {
                    version: ProxyVersion::V1,
                    command: ProxyCommand::Proxy,
                    transport: ProxyTransport::Stream,
                    address: ProxyAddress::Ipv6 {
                        src_addr,
                        dst_addr,
                        src_port,
                        dst_port,
                    },
                    tlv_data: &[],
                },
                total_consumed,
            )));
        }

        Err(ProxyParseError::InvalidProtocol)
    }

    fn parse_v2(buf: &'a [u8]) -> Result<Option<(Self, usize)>, ProxyParseError> {
        if buf.len() < PP2_HEADER_LEN {
            return Ok(None);
        }

        let ver_cmd = buf[12];
        let version_nibble = (ver_cmd & 0xF0) >> 4;
        if version_nibble != 0x02 {
            return Err(ProxyParseError::UnsupportedVersion(version_nibble));
        }

        let command = match ver_cmd & 0x0F {
            0x00 => ProxyCommand::Local,
            0x01 => ProxyCommand::Proxy,
            other => return Err(ProxyParseError::InvalidCommand(other)),
        };

        let fam_byte = buf[13];
        let fam_nibble = (fam_byte & 0xF0) >> 4;
        let trans_nibble = fam_byte & 0x0F;

        let transport = match trans_nibble {
            0x00 => ProxyTransport::Unspec,
            0x01 => ProxyTransport::Stream,
            0x02 => ProxyTransport::Datagram,
            other => return Err(ProxyParseError::InvalidTransport(other)),
        };

        let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        let total_v2_len = PP2_HEADER_LEN + len;

        if buf.len() < total_v2_len {
            return Ok(None);
        }

        let payload = &buf[PP2_HEADER_LEN..total_v2_len];
        let (address, tlv_data) = parse_v2_address(fam_nibble, payload)?;
        validate_v2_tlvs_and_crc(buf, payload.len() - tlv_data.len(), tlv_data, total_v2_len)?;

        Ok(Some((
            Self {
                version: ProxyVersion::V2,
                command,
                transport,
                address,
                tlv_data,
            },
            total_v2_len,
        )))
    }

    /// Encodes this PROXY header into a destination byte buffer without heap allocations.
    ///
    /// # Returns
    ///
    /// Number of bytes written to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError::BufferTooSmall`] if `out` lacks sufficient capacity.
    /// Returns [`ProxyEncodeError::LengthOverflow`] if the header exceeds 65535 payload bytes.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ProxyEncodeError> {
        match self.version {
            ProxyVersion::V1 => self.encode_v1(out),
            ProxyVersion::V2 => self.encode_v2(out),
        }
    }

    fn encode_v1(&self, out: &mut [u8]) -> Result<usize, ProxyEncodeError> {
        let available = out.len();
        let mut writer = SliceFormatter::new(out);
        match self.address {
            ProxyAddress::Ipv4 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            } => {
                if self.command == ProxyCommand::Local {
                    writer.write_str("PROXY UNKNOWN\r\n")?;
                } else {
                    use std::fmt::Write;
                    write!(
                        writer,
                        "PROXY TCP4 {src_addr} {dst_addr} {src_port} {dst_port}\r\n"
                    )
                    .map_err(|_| ProxyEncodeError::BufferTooSmall {
                        needed: 56,
                        available,
                    })?;
                }
            }
            ProxyAddress::Ipv6 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            } => {
                if self.command == ProxyCommand::Local {
                    writer.write_str("PROXY UNKNOWN\r\n")?;
                } else {
                    use std::fmt::Write;
                    write!(
                        writer,
                        "PROXY TCP6 {src_addr} {dst_addr} {src_port} {dst_port}\r\n"
                    )
                    .map_err(|_| ProxyEncodeError::BufferTooSmall {
                        needed: 104,
                        available,
                    })?;
                }
            }
            ProxyAddress::Unspec | ProxyAddress::Unix { .. } => {
                writer.write_str("PROXY UNKNOWN\r\n")?;
            }
        }
        Ok(writer.written())
    }

    fn encode_v2(&self, out: &mut [u8]) -> Result<usize, ProxyEncodeError> {
        let addr_len = match self.address {
            ProxyAddress::Unspec => 0,
            ProxyAddress::Ipv4 { .. } => PP2_ADDR_LEN_INET,
            ProxyAddress::Ipv6 { .. } => PP2_ADDR_LEN_INET6,
            ProxyAddress::Unix { .. } => PP2_ADDR_LEN_UNIX,
        };

        let total_payload_len = addr_len + self.tlv_data.len();
        let u16_len =
            u16::try_from(total_payload_len).map_err(|_| ProxyEncodeError::LengthOverflow)?;

        let needed = PP2_HEADER_LEN + total_payload_len;
        if out.len() < needed {
            return Err(ProxyEncodeError::BufferTooSmall {
                needed,
                available: out.len(),
            });
        }

        // 1. Signature
        out[..12].copy_from_slice(PP2_SIGNATURE);

        // 2. Version and Command
        let ver_cmd = 0x20
            | match self.command {
                ProxyCommand::Local => 0x00,
                ProxyCommand::Proxy => 0x01,
            };
        out[12] = ver_cmd;

        // 3. Family and Transport
        let fam_nibble = match self.address {
            ProxyAddress::Unspec => 0x00,
            ProxyAddress::Ipv4 { .. } => 0x01,
            ProxyAddress::Ipv6 { .. } => 0x02,
            ProxyAddress::Unix { .. } => 0x03,
        };
        let trans_nibble = match self.transport {
            ProxyTransport::Unspec => 0x00,
            ProxyTransport::Stream => 0x01,
            ProxyTransport::Datagram => 0x02,
        };
        out[13] = (fam_nibble << 4) | trans_nibble;

        // 4. Length
        let len_bytes = u16_len.to_be_bytes();
        out[14] = len_bytes[0];
        out[15] = len_bytes[1];

        // 5. Addresses
        let mut offset = PP2_HEADER_LEN;
        match self.address {
            ProxyAddress::Unspec => {}
            ProxyAddress::Ipv4 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            } => {
                out[offset..offset + 4].copy_from_slice(&src_addr.octets());
                out[offset + 4..offset + 8].copy_from_slice(&dst_addr.octets());
                out[offset + 8..offset + 10].copy_from_slice(&src_port.to_be_bytes());
                out[offset + 10..offset + 12].copy_from_slice(&dst_port.to_be_bytes());
                offset += PP2_ADDR_LEN_INET;
            }
            ProxyAddress::Ipv6 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
            } => {
                out[offset..offset + 16].copy_from_slice(&src_addr.octets());
                out[offset + 16..offset + 32].copy_from_slice(&dst_addr.octets());
                out[offset + 32..offset + 34].copy_from_slice(&src_port.to_be_bytes());
                out[offset + 34..offset + 36].copy_from_slice(&dst_port.to_be_bytes());
                offset += PP2_ADDR_LEN_INET6;
            }
            ProxyAddress::Unix { src_addr, dst_addr } => {
                out[offset..offset + 108].copy_from_slice(&src_addr);
                out[offset + 108..offset + 216].copy_from_slice(&dst_addr);
                offset += PP2_ADDR_LEN_UNIX;
            }
        }

        // 6. TLVs
        if !self.tlv_data.is_empty() {
            out[offset..offset + self.tlv_data.len()].copy_from_slice(self.tlv_data);
            offset += self.tlv_data.len();
        }

        Ok(offset)
    }

    /// Returns an iterator over all TLVs present in the header's TLV stream.
    #[must_use]
    pub const fn tlvs(&self) -> TlvIter<'a> {
        TlvIter::new(self.tlv_data)
    }

    /// Searches for the first TLV matching the specified type.
    #[must_use]
    pub fn find_tlv(&self, tlv_type: u8) -> Option<Result<Tlv<'a>, ProxyParseError>> {
        for res in self.tlvs() {
            match res {
                Ok(tlv) if tlv.kind == tlv_type => return Some(Ok(tlv)),
                Err(e) => return Some(Err(e)),
                _ => {}
            }
        }
        None
    }

    /// Extracts the ALPN protocol negotiation byte sequence (`PP2_TYPE_ALPN`).
    #[must_use]
    pub fn alpn(&self) -> Option<Result<&'a [u8], ProxyParseError>> {
        self.find_tlv(tlv_types::PP2_TYPE_ALPN)
            .map(|res| res.map(|tlv| tlv.value))
    }

    /// Extracts the Authority / SNI hostname string (`PP2_TYPE_AUTHORITY`).
    #[must_use]
    pub fn authority(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_tlv(tlv_types::PP2_TYPE_AUTHORITY).map(|res| {
            res.and_then(|tlv| {
                tlv.as_str()
                    .map_err(|_| ProxyParseError::InvalidUtf8String {
                        kind: tlv_types::PP2_TYPE_AUTHORITY,
                    })
            })
        })
    }

    /// Extracts the `CRC32c` 32-bit checksum value (`PP2_TYPE_CRC32C`).
    #[must_use]
    pub fn crc32c(&self) -> Option<Result<u32, ProxyParseError>> {
        self.find_tlv(tlv_types::PP2_TYPE_CRC32C)
            .map(|res| res.and_then(|tlv| tlv.as_u32()))
    }

    /// Extracts the Unique ID byte sequence (`PP2_TYPE_UNIQUE_ID`).
    #[must_use]
    pub fn unique_id(&self) -> Option<Result<&'a [u8], ProxyParseError>> {
        self.find_tlv(tlv_types::PP2_TYPE_UNIQUE_ID)
            .map(|res| res.map(|tlv| tlv.value))
    }

    /// Extracts the Network Namespace string (`PP2_TYPE_NETNS`).
    #[must_use]
    pub fn netns(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_tlv(tlv_types::PP2_TYPE_NETNS).map(|res| {
            res.and_then(|tlv| {
                tlv.as_str()
                    .map_err(|_| ProxyParseError::InvalidUtf8String {
                        kind: tlv_types::PP2_TYPE_NETNS,
                    })
            })
        })
    }

    /// Extracts and parses the SSL connection metadata (`PP2_TYPE_SSL`).
    #[must_use]
    pub fn ssl(&self) -> Option<Result<SslTlv<'a>, ProxyParseError>> {
        self.find_tlv(tlv_types::PP2_TYPE_SSL)
            .map(|res| res.and_then(|tlv| SslTlv::parse(tlv.value)))
    }
}

/// A parsed Type-Length-Value vector referencing an underlying slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// 8-bit TLV type code.
    pub kind: u8,
    /// Raw byte value of the TLV.
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Constructs a new `Tlv` instance.
    #[must_use]
    pub const fn new(kind: u8, value: &'a [u8]) -> Self {
        Self { kind, value }
    }

    /// Attempts to interpret the TLV value as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`core::str::Utf8Error`] if the bytes are not valid UTF-8.
    pub fn as_str(&self) -> Result<&'a str, core::str::Utf8Error> {
        core::str::from_utf8(self.value)
    }

    /// Attempts to interpret the TLV value as a 32-bit big-endian unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyParseError::InvalidTlvLength`] if the value is not exactly 4 bytes.
    pub fn as_u32(&self) -> Result<u32, ProxyParseError> {
        if self.value.len() == 4 {
            Ok(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            Err(ProxyParseError::InvalidTlvLength {
                kind: self.kind,
                expected: 4,
                actual: self.value.len(),
            })
        }
    }
}

/// Zero-allocation iterator over a sequence of contiguous TLVs.
#[derive(Debug, Clone)]
pub struct TlvIter<'a> {
    slice: &'a [u8],
    offset: usize,
}

impl<'a> TlvIter<'a> {
    /// Creates a new `TlvIter` starting at the beginning of the slice.
    #[must_use]
    pub const fn new(slice: &'a [u8]) -> Self {
        Self { slice, offset: 0 }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<Tlv<'a>, ProxyParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.slice.len() {
            return None;
        }

        let rem = &self.slice[self.offset..];
        if rem.len() < 3 {
            self.offset = self.slice.len();
            return Some(Err(ProxyParseError::TruncatedTlvHeader));
        }

        let kind = rem[0];
        let length = u16::from_be_bytes([rem[1], rem[2]]) as usize;

        if rem.len() < 3 + length {
            self.offset = self.slice.len();
            return Some(Err(ProxyParseError::TruncatedTlvValue {
                kind,
                expected: length,
                available: rem.len() - 3,
            }));
        }

        let value = &rem[3..3 + length];
        self.offset += 3 + length;
        Some(Ok(Tlv { kind, value }))
    }
}

/// Parsed SSL / TLS metadata container (`PP2_TYPE_SSL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SslTlv<'a> {
    /// Bitmask of client SSL flags (see `ssl_client_flags`).
    pub client: u8,
    /// 32-bit verify result (0 if verified successfully).
    pub verify: u32,
    /// Raw unparsed sub-TLVs byte slice.
    pub sub_tlvs: &'a [u8],
}

impl<'a> SslTlv<'a> {
    /// Parses an `SslTlv` structure from a `PP2_TYPE_SSL` TLV value.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyParseError::InvalidTlvLength`] if the value slice is smaller than 5 bytes.
    pub fn parse(value: &'a [u8]) -> Result<Self, ProxyParseError> {
        if value.len() < 5 {
            return Err(ProxyParseError::InvalidTlvLength {
                kind: tlv_types::PP2_TYPE_SSL,
                expected: 5,
                actual: value.len(),
            });
        }
        let client = value[0];
        let verify = u32::from_be_bytes([value[1], value[2], value[3], value[4]]);
        let sub_tlvs = &value[5..];
        Ok(Self {
            client,
            verify,
            sub_tlvs,
        })
    }

    /// Indicates whether the client connected over SSL/TLS (`PP2_CLIENT_SSL`).
    #[must_use]
    pub const fn is_ssl(&self) -> bool {
        (self.client & ssl_client_flags::PP2_CLIENT_SSL) != 0
    }

    /// Indicates whether the client provided a certificate over the current connection.
    #[must_use]
    pub const fn has_cert_conn(&self) -> bool {
        (self.client & ssl_client_flags::PP2_CLIENT_CERT_CONN) != 0
    }

    /// Indicates whether the client provided a certificate in this TLS session.
    #[must_use]
    pub const fn has_cert_sess(&self) -> bool {
        (self.client & ssl_client_flags::PP2_CLIENT_CERT_SESS) != 0
    }

    /// Indicates whether client certificate verification succeeded (`verify == 0`).
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.verify == 0
    }

    /// Returns an iterator over all sub-TLVs in this SSL container.
    #[must_use]
    pub const fn sub_tlvs_iter(&self) -> TlvIter<'a> {
        TlvIter::new(self.sub_tlvs)
    }

    /// Extracts the SSL TLS protocol version string (`PP2_SUBTYPE_SSL_VERSION`).
    #[must_use]
    pub fn version(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_sub_tlv_str(tlv_types::PP2_SUBTYPE_SSL_VERSION)
    }

    /// Extracts the client certificate Common Name (CN) string (`PP2_SUBTYPE_SSL_CN`).
    #[must_use]
    pub fn common_name(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_sub_tlv_str(tlv_types::PP2_SUBTYPE_SSL_CN)
    }

    /// Extracts the negotiated cipher suite name (`PP2_SUBTYPE_SSL_CIPHER`).
    #[must_use]
    pub fn cipher(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_sub_tlv_str(tlv_types::PP2_SUBTYPE_SSL_CIPHER)
    }

    /// Extracts the certificate signature algorithm name (`PP2_SUBTYPE_SSL_SIG_ALG`).
    #[must_use]
    pub fn sig_alg(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_sub_tlv_str(tlv_types::PP2_SUBTYPE_SSL_SIG_ALG)
    }

    /// Extracts the public key algorithm name (`PP2_SUBTYPE_SSL_KEY_ALG`).
    #[must_use]
    pub fn key_alg(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_sub_tlv_str(tlv_types::PP2_SUBTYPE_SSL_KEY_ALG)
    }

    /// Extracts the key exchange group name (`PP2_SUBTYPE_SSL_GROUP`).
    #[must_use]
    pub fn group(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_sub_tlv_str(tlv_types::PP2_SUBTYPE_SSL_GROUP)
    }

    /// Extracts the signature scheme name (`PP2_SUBTYPE_SSL_SIG_SCHEME`).
    #[must_use]
    pub fn sig_scheme(&self) -> Option<Result<&'a str, ProxyParseError>> {
        self.find_sub_tlv_str(tlv_types::PP2_SUBTYPE_SSL_SIG_SCHEME)
    }

    /// Extracts the raw X.509 client certificate bytes (`PP2_SUBTYPE_SSL_CLIENT_CERT`).
    #[must_use]
    pub fn client_cert(&self) -> Option<Result<&'a [u8], ProxyParseError>> {
        for res in self.sub_tlvs_iter() {
            match res {
                Ok(tlv) if tlv.kind == tlv_types::PP2_SUBTYPE_SSL_CLIENT_CERT => {
                    return Some(Ok(tlv.value));
                }
                Err(e) => return Some(Err(e)),
                _ => {}
            }
        }
        None
    }

    fn find_sub_tlv_str(&self, sub_type: u8) -> Option<Result<&'a str, ProxyParseError>> {
        for res in self.sub_tlvs_iter() {
            match res {
                Ok(tlv) if tlv.kind == sub_type => {
                    return Some(
                        tlv.as_str()
                            .map_err(|_| ProxyParseError::InvalidUtf8String { kind: sub_type }),
                    );
                }
                Err(e) => return Some(Err(e)),
                _ => {}
            }
        }
        None
    }
}

/// Zero-allocation builder for constructing TLV vectors in a mutable byte buffer.
pub struct TlvBuilder<'b> {
    buf: &'b mut [u8],
    offset: usize,
}

impl<'b> TlvBuilder<'b> {
    /// Creates a new `TlvBuilder` wrapping a mutable slice.
    #[must_use]
    pub fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// Number of bytes written into the buffer so far.
    #[must_use]
    pub const fn written(&self) -> usize {
        self.offset
    }

    /// Converts the builder into the written byte slice.
    #[must_use]
    pub fn into_slice(self) -> &'b [u8] {
        &self.buf[..self.offset]
    }

    /// Appends a generic TLV entry to the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError::TlvTooLarge`] if value exceeds 65535 bytes.
    /// Returns [`ProxyEncodeError::BufferTooSmall`] if capacity is insufficient.
    pub fn append_tlv(&mut self, kind: u8, value: &[u8]) -> Result<(), ProxyEncodeError> {
        let len_u16 = u16::try_from(value.len()).map_err(|_| ProxyEncodeError::TlvTooLarge {
            kind,
            len: value.len(),
        })?;
        let needed = 3 + value.len();
        if self.buf.len() - self.offset < needed {
            return Err(ProxyEncodeError::BufferTooSmall {
                needed,
                available: self.buf.len() - self.offset,
            });
        }

        self.buf[self.offset] = kind;
        let len_bytes = len_u16.to_be_bytes();
        self.buf[self.offset + 1] = len_bytes[0];
        self.buf[self.offset + 2] = len_bytes[1];
        self.buf[self.offset + 3..self.offset + 3 + value.len()].copy_from_slice(value);
        self.offset += needed;
        Ok(())
    }

    /// Appends an ALPN extension TLV (`PP2_TYPE_ALPN`).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError`] on buffer exhaustion or length overflow.
    pub fn append_alpn(&mut self, alpn: &[u8]) -> Result<(), ProxyEncodeError> {
        self.append_tlv(tlv_types::PP2_TYPE_ALPN, alpn)
    }

    /// Appends an Authority / SNI TLV (`PP2_TYPE_AUTHORITY`).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError`] on buffer exhaustion or length overflow.
    pub fn append_authority(&mut self, authority: &str) -> Result<(), ProxyEncodeError> {
        self.append_tlv(tlv_types::PP2_TYPE_AUTHORITY, authority.as_bytes())
    }

    /// Appends a 4-byte `CRC32c` placeholder TLV (`PP2_TYPE_CRC32C`).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError`] on buffer exhaustion.
    pub fn append_crc32c_placeholder(&mut self) -> Result<(), ProxyEncodeError> {
        self.append_tlv(tlv_types::PP2_TYPE_CRC32C, &[0, 0, 0, 0])
    }

    /// Appends a NOOP alignment / padding TLV of specified size (`PP2_TYPE_NOOP`).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError::TlvTooLarge`] if len exceeds 65535.
    /// Returns [`ProxyEncodeError::BufferTooSmall`] if capacity is insufficient.
    pub fn append_noop(&mut self, len: usize) -> Result<(), ProxyEncodeError> {
        let len_u16 = u16::try_from(len).map_err(|_| ProxyEncodeError::TlvTooLarge {
            kind: tlv_types::PP2_TYPE_NOOP,
            len,
        })?;
        let needed = 3 + len;
        if self.buf.len() - self.offset < needed {
            return Err(ProxyEncodeError::BufferTooSmall {
                needed,
                available: self.buf.len() - self.offset,
            });
        }
        self.buf[self.offset] = tlv_types::PP2_TYPE_NOOP;
        let len_bytes = len_u16.to_be_bytes();
        self.buf[self.offset + 1] = len_bytes[0];
        self.buf[self.offset + 2] = len_bytes[1];
        self.buf[self.offset + 3..self.offset + 3 + len].fill(0);
        self.offset += needed;
        Ok(())
    }

    /// Appends a Unique ID TLV (`PP2_TYPE_UNIQUE_ID`).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError`] on buffer exhaustion or length overflow.
    pub fn append_unique_id(&mut self, id: &[u8]) -> Result<(), ProxyEncodeError> {
        self.append_tlv(tlv_types::PP2_TYPE_UNIQUE_ID, id)
    }

    /// Appends a Network Namespace TLV (`PP2_TYPE_NETNS`).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError`] on buffer exhaustion or length overflow.
    pub fn append_netns(&mut self, netns: &str) -> Result<(), ProxyEncodeError> {
        self.append_tlv(tlv_types::PP2_TYPE_NETNS, netns.as_bytes())
    }

    /// Appends an SSL container TLV (`PP2_TYPE_SSL`) with sub-TLVs.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyEncodeError::TlvTooLarge`] if total SSL payload exceeds 65535 bytes.
    /// Returns [`ProxyEncodeError::BufferTooSmall`] if buffer capacity is insufficient.
    pub fn append_ssl(
        &mut self,
        client_flags: u8,
        verify: u32,
        sub_tlvs: &[u8],
    ) -> Result<(), ProxyEncodeError> {
        let total_val_len = 5 + sub_tlvs.len();
        let len_u16 = u16::try_from(total_val_len).map_err(|_| ProxyEncodeError::TlvTooLarge {
            kind: tlv_types::PP2_TYPE_SSL,
            len: total_val_len,
        })?;
        let needed = 3 + total_val_len;
        if self.buf.len() - self.offset < needed {
            return Err(ProxyEncodeError::BufferTooSmall {
                needed,
                available: self.buf.len() - self.offset,
            });
        }
        self.buf[self.offset] = tlv_types::PP2_TYPE_SSL;
        let len_bytes = len_u16.to_be_bytes();
        self.buf[self.offset + 1] = len_bytes[0];
        self.buf[self.offset + 2] = len_bytes[1];
        self.buf[self.offset + 3] = client_flags;
        let verify_bytes = verify.to_be_bytes();
        self.buf[self.offset + 4..self.offset + 8].copy_from_slice(&verify_bytes);
        if !sub_tlvs.is_empty() {
            self.buf[self.offset + 8..self.offset + 8 + sub_tlvs.len()].copy_from_slice(sub_tlvs);
        }
        self.offset += needed;
        Ok(())
    }
}

/// Updates and finalizes the `CRC32c` checksum in an encoded PROXY v2 header buffer.
///
/// Finds the `PP2_TYPE_CRC32C` TLV, sets its 4-byte value to 0, computes the Castagnoli
/// `CRC32c` over the whole header, and writes the calculated checksum in big-endian order.
///
/// # Errors
///
/// Returns [`ProxyEncodeError::CrcNotFound`] if no `PP2_TYPE_CRC32C` TLV is present.
pub fn update_crc32c_in_buffer(buf: &mut [u8]) -> Result<(), ProxyEncodeError> {
    if buf.len() < PP2_HEADER_LEN || !buf.starts_with(PP2_SIGNATURE) {
        return Err(ProxyEncodeError::CrcNotFound);
    }

    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total_v2_len = PP2_HEADER_LEN + len;
    if buf.len() < total_v2_len {
        return Err(ProxyEncodeError::CrcNotFound);
    }

    let fam_byte = buf[13];
    let fam_nibble = (fam_byte & 0xF0) >> 4;
    let addr_len = match fam_nibble {
        0x00 => 0,
        0x01 => PP2_ADDR_LEN_INET,
        0x02 => PP2_ADDR_LEN_INET6,
        0x03 => PP2_ADDR_LEN_UNIX,
        _ => return Err(ProxyEncodeError::CrcNotFound),
    };

    let tlv_start = PP2_HEADER_LEN + addr_len;
    let mut offset = tlv_start;
    let mut crc_val_offset = None;

    while offset < total_v2_len {
        if offset + 3 > total_v2_len {
            break;
        }
        let kind = buf[offset];
        let tlv_len = u16::from_be_bytes([buf[offset + 1], buf[offset + 2]]) as usize;
        if offset + 3 + tlv_len > total_v2_len {
            break;
        }

        if kind == tlv_types::PP2_TYPE_CRC32C && tlv_len == 4 {
            crc_val_offset = Some(offset + 3);
            break;
        }
        offset += 3 + tlv_len;
    }

    let crc_offset = crc_val_offset.ok_or(ProxyEncodeError::CrcNotFound)?;

    // Zero out CRC field
    buf[crc_offset..crc_offset + 4].fill(0);

    // Compute checksum
    let crc = calculate_crc32c(&buf[..total_v2_len]);

    // Store calculated checksum
    buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_be_bytes());

    Ok(())
}

/// Helper function to compute `CRC32c` with a specific 4-byte slice treated as zero.
fn calculate_header_crc32c_zeroed(header_slice: &[u8], zero_offset: usize) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for (i, &b) in header_slice.iter().enumerate() {
        let byte = if i >= zero_offset && i < zero_offset + 4 {
            0
        } else {
            b
        };
        crc = (crc >> 8) ^ CRC32C_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize];
    }
    crc ^ 0xffff_ffff
}

fn parse_v2_address(
    fam_nibble: u8,
    payload: &[u8],
) -> Result<(ProxyAddress, &[u8]), ProxyParseError> {
    match fam_nibble {
        0x00 => Ok((ProxyAddress::Unspec, payload)),
        0x01 => {
            if payload.len() < PP2_ADDR_LEN_INET {
                return Err(ProxyParseError::InvalidLength {
                    expected: PP2_ADDR_LEN_INET,
                    actual: payload.len(),
                });
            }
            let src_addr = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let dst_addr = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let src_port = u16::from_be_bytes([payload[8], payload[9]]);
            let dst_port = u16::from_be_bytes([payload[10], payload[11]]);
            Ok((
                ProxyAddress::Ipv4 {
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                },
                &payload[PP2_ADDR_LEN_INET..],
            ))
        }
        0x02 => {
            if payload.len() < PP2_ADDR_LEN_INET6 {
                return Err(ProxyParseError::InvalidLength {
                    expected: PP2_ADDR_LEN_INET6,
                    actual: payload.len(),
                });
            }
            let mut src_octets = [0u8; 16];
            let mut dst_octets = [0u8; 16];
            src_octets.copy_from_slice(&payload[0..16]);
            dst_octets.copy_from_slice(&payload[16..32]);
            let src_addr = Ipv6Addr::from(src_octets);
            let dst_addr = Ipv6Addr::from(dst_octets);
            let src_port = u16::from_be_bytes([payload[32], payload[33]]);
            let dst_port = u16::from_be_bytes([payload[34], payload[35]]);
            Ok((
                ProxyAddress::Ipv6 {
                    src_addr,
                    dst_addr,
                    src_port,
                    dst_port,
                },
                &payload[PP2_ADDR_LEN_INET6..],
            ))
        }
        0x03 => {
            if payload.len() < PP2_ADDR_LEN_UNIX {
                return Err(ProxyParseError::InvalidLength {
                    expected: PP2_ADDR_LEN_UNIX,
                    actual: payload.len(),
                });
            }
            let mut src_addr = [0u8; 108];
            let mut dst_addr = [0u8; 108];
            src_addr.copy_from_slice(&payload[0..108]);
            dst_addr.copy_from_slice(&payload[108..216]);
            Ok((
                ProxyAddress::Unix { src_addr, dst_addr },
                &payload[PP2_ADDR_LEN_UNIX..],
            ))
        }
        other => Err(ProxyParseError::InvalidAddressFamily(other)),
    }
}

fn validate_v2_tlvs_and_crc(
    buf: &[u8],
    addr_len: usize,
    tlv_data: &[u8],
    total_v2_len: usize,
) -> Result<(), ProxyParseError> {
    let mut tlv_offset = 0;
    let mut crc_val_offset = None;
    let mut expected_crc = None;

    while tlv_offset < tlv_data.len() {
        if tlv_offset + 3 > tlv_data.len() {
            return Err(ProxyParseError::TruncatedTlvHeader);
        }
        let tlv_type = tlv_data[tlv_offset];
        let tlv_len =
            u16::from_be_bytes([tlv_data[tlv_offset + 1], tlv_data[tlv_offset + 2]]) as usize;
        if tlv_offset + 3 + tlv_len > tlv_data.len() {
            return Err(ProxyParseError::TruncatedTlvValue {
                kind: tlv_type,
                expected: tlv_len,
                available: tlv_data.len() - (tlv_offset + 3),
            });
        }

        if tlv_type == tlv_types::PP2_TYPE_CRC32C {
            if tlv_len != 4 {
                return Err(ProxyParseError::InvalidTlvLength {
                    kind: tlv_types::PP2_TYPE_CRC32C,
                    expected: 4,
                    actual: tlv_len,
                });
            }
            let val_slice = &tlv_data[tlv_offset + 3..tlv_offset + 7];
            expected_crc = Some(u32::from_be_bytes([
                val_slice[0],
                val_slice[1],
                val_slice[2],
                val_slice[3],
            ]));
            crc_val_offset = Some(PP2_HEADER_LEN + addr_len + tlv_offset + 3);
        }

        tlv_offset += 3 + tlv_len;
    }

    if let (Some(expected), Some(crc_offset)) = (expected_crc, crc_val_offset) {
        let full_header_slice = &buf[..total_v2_len];
        let computed = calculate_header_crc32c_zeroed(full_header_slice, crc_offset);
        if computed != expected {
            return Err(ProxyParseError::CrcMismatch { expected, computed });
        }
    }

    Ok(())
}

/// Finds the `\r\n` line terminator within a byte slice.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    (0..buf.len() - 1).find(|&i| buf[i] == b'\r' && buf[i + 1] == b'\n')
}

/// Strict V1 decimal port parser without leading zeros (range 0..=65535).
fn parse_v1_port(s: &[u8]) -> Option<u16> {
    if s.is_empty() {
        return None;
    }
    if s.len() > 1 && s[0] == b'0' {
        return None;
    }
    let mut val: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
        if val > 65535 {
            return None;
        }
    }
    u16::try_from(val).ok()
}

/// Strict V1 decimal IPv4 parser without leading zeros in octets.
fn parse_v1_ipv4(s: &[u8]) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut count = 0;

    for part in s.split(|&b| b == b'.') {
        if count >= 4 || part.is_empty() {
            return None;
        }
        if part.len() > 1 && part[0] == b'0' {
            return None;
        }
        let mut val: u16 = 0;
        for &b in part {
            if !b.is_ascii_digit() {
                return None;
            }
            val = val.checked_mul(10)?.checked_add(u16::from(b - b'0'))?;
            if val > 255 {
                return None;
            }
        }
        octets[count] = u8::try_from(val).ok()?;
        count += 1;
    }

    if count == 4 {
        Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    } else {
        None
    }
}

/// Strict V1 IPv6 parser.
fn parse_v1_ipv6(s: &[u8]) -> Option<Ipv6Addr> {
    let utf8_str = core::str::from_utf8(s).ok()?;
    utf8_str.parse::<Ipv6Addr>().ok()
}

/// Zero-allocation write formatter for direct serialization into byte slices.
struct SliceFormatter<'a> {
    slice: &'a mut [u8],
    offset: usize,
}

impl<'a> SliceFormatter<'a> {
    fn new(slice: &'a mut [u8]) -> Self {
        Self { slice, offset: 0 }
    }

    const fn written(&self) -> usize {
        self.offset
    }

    fn write_str(&mut self, s: &str) -> Result<(), ProxyEncodeError> {
        let bytes = s.as_bytes();
        let needed = bytes.len();
        if self.slice.len() - self.offset < needed {
            return Err(ProxyEncodeError::BufferTooSmall {
                needed,
                available: self.slice.len() - self.offset,
            });
        }
        self.slice[self.offset..self.offset + needed].copy_from_slice(bytes);
        self.offset += needed;
        Ok(())
    }
}

impl fmt::Write for SliceFormatter<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.slice.len() - self.offset < bytes.len() {
            return Err(fmt::Error);
        }
        self.slice[self.offset..self.offset + bytes.len()].copy_from_slice(bytes);
        self.offset += bytes.len();
        Ok(())
    }
}

/// Owned representation of a parsed PROXY protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyInfo {
    pub version: ProxyVersion,
    pub command: ProxyCommand,
    pub transport: ProxyTransport,
    pub address: ProxyAddress,
    pub tlv_data: Vec<u8>,
}

impl ProxyInfo {
    #[must_use]
    pub fn as_header(&self) -> ProxyHeader<'_> {
        ProxyHeader {
            version: self.version,
            command: self.command,
            transport: self.transport,
            address: self.address,
            tlv_data: &self.tlv_data,
        }
    }

    #[must_use]
    pub fn src_sockaddr(&self) -> Option<SocketAddr> {
        self.address.src_sockaddr()
    }

    #[must_use]
    pub fn dst_sockaddr(&self) -> Option<SocketAddr> {
        self.address.dst_sockaddr()
    }

    #[must_use]
    pub fn alpn(&self) -> Option<Result<&[u8], ProxyParseError>> {
        self.as_header().alpn()
    }

    #[must_use]
    pub fn authority(&self) -> Option<Result<&str, ProxyParseError>> {
        self.as_header().authority()
    }

    #[must_use]
    pub fn unique_id(&self) -> Option<Result<&[u8], ProxyParseError>> {
        self.as_header().unique_id()
    }

    #[must_use]
    pub fn netns(&self) -> Option<Result<&str, ProxyParseError>> {
        self.as_header().netns()
    }

    #[must_use]
    pub fn ssl(&self) -> Option<Result<SslTlv<'_>, ProxyParseError>> {
        self.as_header().ssl()
    }
}

impl ProxyHeader<'_> {
    #[must_use]
    pub fn src_sockaddr(&self) -> Option<SocketAddr> {
        self.address.src_sockaddr()
    }

    #[must_use]
    pub fn dst_sockaddr(&self) -> Option<SocketAddr> {
        self.address.dst_sockaddr()
    }

    #[must_use]
    pub fn to_owned(&self) -> ProxyInfo {
        ProxyInfo {
            version: self.version,
            command: self.command,
            transport: self.transport,
            address: self.address,
            tlv_data: self.tlv_data.to_vec(),
        }
    }
}

/// Parses a PROXY protocol header from a byte slice.
///
/// # Errors
///
/// Returns [`ProxyParseError`] if the header is malformed or validation fails.
pub fn parse_proxy_header(buf: &[u8]) -> Result<Option<(ProxyHeader<'_>, usize)>, ProxyParseError> {
    ProxyHeader::parse(buf)
}

/// Encodes a PROXY protocol v1 text header into a newly allocated `Vec<u8>`.
#[must_use]
pub fn encode_proxy_v1(src: Option<SocketAddr>, dst: Option<SocketAddr>) -> Vec<u8> {
    let mut buf = [0u8; PP1_MAX_LINE_LEN];
    let hdr = match (src, dst) {
        (Some(SocketAddr::V4(s)), Some(SocketAddr::V4(d))) => {
            ProxyHeader::new_v1_ipv4(*s.ip(), *d.ip(), s.port(), d.port())
        }
        (Some(SocketAddr::V6(s)), Some(SocketAddr::V6(d))) => {
            ProxyHeader::new_v1_ipv6(*s.ip(), *d.ip(), s.port(), d.port())
        }
        _ => ProxyHeader::new_v1_unknown(),
    };
    let len = hdr.encode(&mut buf).unwrap_or(0);
    buf[..len].to_vec()
}

/// Encodes a PROXY protocol v2 binary header into a newly allocated `Vec<u8>`.
#[must_use]
pub fn encode_proxy_v2(
    command: ProxyCommand,
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
    tlv_data: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; PP2_HEADER_LEN + PP2_ADDR_LEN_INET6 + tlv_data.len() + 64];
    let hdr = match (src, dst) {
        (Some(SocketAddr::V4(s)), Some(SocketAddr::V4(d))) => ProxyHeader::new_v2_ipv4(
            command,
            ProxyTransport::Stream,
            *s.ip(),
            *d.ip(),
            s.port(),
            d.port(),
            tlv_data,
        ),
        (Some(SocketAddr::V6(s)), Some(SocketAddr::V6(d))) => ProxyHeader::new_v2_ipv6(
            command,
            ProxyTransport::Stream,
            *s.ip(),
            *d.ip(),
            s.port(),
            d.port(),
            tlv_data,
        ),
        _ => ProxyHeader::new_v2_unspec(command, ProxyTransport::Unspec, tlv_data),
    };
    let len = hdr.encode(&mut buf).unwrap_or(0);
    buf.truncate(len);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_crc32c_vectors() {
        assert_eq!(calculate_crc32c(b""), 0x0000_0000);
        assert_eq!(calculate_crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn test_v1_ipv4_parsing_and_encoding() {
        let wire = b"PROXY TCP4 192.168.0.1 10.0.0.1 56324 80\r\n";
        let res = ProxyHeader::parse(wire).expect("parse failed");
        let (hdr, len) = res.expect("need more data");
        assert_eq!(len, wire.len());
        assert_eq!(hdr.version, ProxyVersion::V1);
        assert_eq!(hdr.command, ProxyCommand::Proxy);
        assert_eq!(hdr.transport, ProxyTransport::Stream);
        assert_eq!(
            hdr.address,
            ProxyAddress::Ipv4 {
                src_addr: Ipv4Addr::new(192, 168, 0, 1),
                dst_addr: Ipv4Addr::new(10, 0, 0, 1),
                src_port: 56324,
                dst_port: 80,
            }
        );

        let mut out = [0u8; 128];
        let written = hdr.encode(&mut out).expect("encode failed");
        assert_eq!(&out[..written], wire);
    }

    #[test]
    fn test_v1_ipv6_parsing_and_encoding() {
        let wire = b"PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n";
        let res = ProxyHeader::parse(wire).expect("parse failed");
        let (hdr, len) = res.expect("need more data");
        assert_eq!(len, wire.len());
        assert_eq!(hdr.version, ProxyVersion::V1);
        assert_eq!(hdr.command, ProxyCommand::Proxy);
        assert_eq!(hdr.transport, ProxyTransport::Stream);

        let mut out = [0u8; 128];
        let written = hdr.encode(&mut out).expect("encode failed");
        assert_eq!(&out[..written], wire);
    }

    #[test]
    fn test_v1_unknown_parsing_and_encoding() {
        let wire = b"PROXY UNKNOWN\r\n";
        let res = ProxyHeader::parse(wire).expect("parse failed");
        let (hdr, len) = res.expect("need more data");
        assert_eq!(len, wire.len());
        assert_eq!(hdr.version, ProxyVersion::V1);
        assert_eq!(hdr.command, ProxyCommand::Local);
        assert_eq!(hdr.transport, ProxyTransport::Unspec);
        assert_eq!(hdr.address, ProxyAddress::Unspec);

        let mut out = [0u8; 64];
        let written = hdr.encode(&mut out).expect("encode failed");
        assert_eq!(&out[..written], wire);

        // Extended unknown format
        let wire_ext = b"PROXY UNKNOWN foo bar baz 1234 5678\r\n";
        let res_ext = ProxyHeader::parse(wire_ext).expect("parse failed");
        let (hdr_ext, len_ext) = res_ext.expect("need more data");
        assert_eq!(len_ext, wire_ext.len());
        assert_eq!(hdr_ext.address, ProxyAddress::Unspec);
    }

    #[test]
    fn test_v1_error_handling() {
        // Line too long (> 107 chars without CRLF)
        let mut long_buf = [b'A'; 110];
        long_buf[..6].copy_from_slice(b"PROXY ");
        assert_eq!(
            ProxyHeader::parse(&long_buf),
            Err(ProxyParseError::LineTooLong)
        );

        // Leading zero in IPv4 octet
        assert_eq!(
            ProxyHeader::parse(b"PROXY TCP4 01.2.3.4 5.6.7.8 80 80\r\n"),
            Err(ProxyParseError::InvalidIpAddress)
        );

        // Leading zero in port
        assert_eq!(
            ProxyHeader::parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 080 80\r\n"),
            Err(ProxyParseError::InvalidPort)
        );

        // Port > 65535
        assert_eq!(
            ProxyHeader::parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 70000 80\r\n"),
            Err(ProxyParseError::InvalidPort)
        );

        // Missing fields
        assert_eq!(
            ProxyHeader::parse(b"PROXY TCP4 1.2.3.4 5.6.7.8 80\r\n"),
            Err(ProxyParseError::InvalidV1Header)
        );

        // Invalid protocol keyword
        assert_eq!(
            ProxyHeader::parse(b"PROXY UDP4 1.2.3.4 5.6.7.8 80 80\r\n"),
            Err(ProxyParseError::InvalidProtocol)
        );
    }

    #[test]
    fn test_v2_ipv4_parsing_and_encoding() {
        let mut tlv_buf = [0u8; 128];
        let mut builder = TlvBuilder::new(&mut tlv_buf);
        builder.append_alpn(b"h2").expect("alpn failed");
        builder
            .append_authority("lb.internal.ibex")
            .expect("authority failed");
        let tlv_slice = builder.into_slice();

        let hdr = ProxyHeader::new_v2_ipv4(
            ProxyCommand::Proxy,
            ProxyTransport::Stream,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(10, 0, 0, 1),
            54321,
            443,
            tlv_slice,
        );

        let mut out = [0u8; 256];
        let written = hdr.encode(&mut out).expect("encode failed");
        assert_eq!(written, 16 + 12 + tlv_slice.len());

        let res = ProxyHeader::parse(&out[..written]).expect("parse failed");
        let (parsed, consumed) = res.expect("need more data");
        assert_eq!(consumed, written);
        assert_eq!(parsed.version, ProxyVersion::V2);
        assert_eq!(parsed.command, ProxyCommand::Proxy);
        assert_eq!(parsed.transport, ProxyTransport::Stream);
        assert_eq!(
            parsed.address,
            ProxyAddress::Ipv4 {
                src_addr: Ipv4Addr::new(192, 168, 1, 100),
                dst_addr: Ipv4Addr::new(10, 0, 0, 1),
                src_port: 54321,
                dst_port: 443,
            }
        );

        assert_eq!(parsed.alpn().unwrap().unwrap(), b"h2");
        assert_eq!(parsed.authority().unwrap().unwrap(), "lb.internal.ibex");
    }

    #[test]
    fn test_v2_ipv6_and_unix_headers() {
        let hdr_v6 = ProxyHeader::new_v2_ipv6(
            ProxyCommand::Proxy,
            ProxyTransport::Datagram,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            5000,
            5000,
            &[],
        );
        let mut out_v6 = [0u8; 128];
        let written_v6 = hdr_v6.encode(&mut out_v6).expect("encode v6 failed");
        assert_eq!(written_v6, 16 + 36);

        let (parsed_v6, len_v6) = ProxyHeader::parse(&out_v6[..written_v6]).unwrap().unwrap();
        assert_eq!(len_v6, written_v6);
        assert_eq!(parsed_v6.transport, ProxyTransport::Datagram);
        assert_eq!(parsed_v6.address, hdr_v6.address);

        let mut src_u = [0u8; 108];
        let mut dst_u = [0u8; 108];
        src_u[..11].copy_from_slice(b"/tmp/client");
        dst_u[..11].copy_from_slice(b"/tmp/server");
        let hdr_unx = ProxyHeader::new_v2_unix(
            ProxyCommand::Proxy,
            ProxyTransport::Stream,
            src_u,
            dst_u,
            &[],
        );
        let mut out_unx = [0u8; 300];
        let written_unx = hdr_unx.encode(&mut out_unx).expect("encode unix failed");
        assert_eq!(written_unx, 16 + 216);

        let (parsed_unx, len_unx) = ProxyHeader::parse(&out_unx[..written_unx])
            .unwrap()
            .unwrap();
        assert_eq!(len_unx, written_unx);
        assert_eq!(parsed_unx.address, hdr_unx.address);
    }

    #[test]
    fn test_v2_ssl_container_and_sub_tlvs() {
        let mut sub_buf = [0u8; 256];
        let mut sub_builder = TlvBuilder::new(&mut sub_buf);
        sub_builder
            .append_tlv(tlv_types::PP2_SUBTYPE_SSL_VERSION, b"TLSv1.3")
            .unwrap();
        sub_builder
            .append_tlv(tlv_types::PP2_SUBTYPE_SSL_CN, b"api.example.com")
            .unwrap();
        sub_builder
            .append_tlv(tlv_types::PP2_SUBTYPE_SSL_CIPHER, b"TLS_AES_256_GCM_SHA384")
            .unwrap();
        sub_builder
            .append_tlv(tlv_types::PP2_SUBTYPE_SSL_SIG_ALG, b"RSA-PSS-SHA256")
            .unwrap();
        sub_builder
            .append_tlv(tlv_types::PP2_SUBTYPE_SSL_KEY_ALG, b"RSA4096")
            .unwrap();
        sub_builder
            .append_tlv(tlv_types::PP2_SUBTYPE_SSL_GROUP, b"X25519")
            .unwrap();
        sub_builder
            .append_tlv(
                tlv_types::PP2_SUBTYPE_SSL_SIG_SCHEME,
                b"rsa_pss_rsae_sha256",
            )
            .unwrap();
        sub_builder
            .append_tlv(
                tlv_types::PP2_SUBTYPE_SSL_CLIENT_CERT,
                &[0x30, 0x82, 0x01, 0x0a],
            )
            .unwrap();
        let sub_slice = sub_builder.into_slice();

        let mut tlv_buf = [0u8; 512];
        let mut builder = TlvBuilder::new(&mut tlv_buf);
        builder
            .append_ssl(
                ssl_client_flags::PP2_CLIENT_SSL | ssl_client_flags::PP2_CLIENT_CERT_CONN,
                0,
                sub_slice,
            )
            .unwrap();
        builder.append_unique_id(b"unique-conn-9988").unwrap();
        builder.append_netns("tenant-red").unwrap();
        builder.append_noop(4).unwrap();
        let tlv_slice = builder.into_slice();

        let hdr = ProxyHeader::new_v2_ipv4(
            ProxyCommand::Proxy,
            ProxyTransport::Stream,
            Ipv4Addr::new(10, 10, 10, 1),
            Ipv4Addr::new(10, 10, 10, 2),
            44300,
            443,
            tlv_slice,
        );

        let mut out = [0u8; 1024];
        let written = hdr.encode(&mut out).unwrap();

        let (parsed, _) = ProxyHeader::parse(&out[..written]).unwrap().unwrap();
        assert_eq!(parsed.unique_id().unwrap().unwrap(), b"unique-conn-9988");
        assert_eq!(parsed.netns().unwrap().unwrap(), "tenant-red");

        let ssl = parsed.ssl().unwrap().unwrap();
        assert!(ssl.is_ssl());
        assert!(ssl.has_cert_conn());
        assert!(!ssl.has_cert_sess());
        assert!(ssl.is_verified());
        assert_eq!(ssl.version().unwrap().unwrap(), "TLSv1.3");
        assert_eq!(ssl.common_name().unwrap().unwrap(), "api.example.com");
        assert_eq!(ssl.cipher().unwrap().unwrap(), "TLS_AES_256_GCM_SHA384");
        assert_eq!(ssl.sig_alg().unwrap().unwrap(), "RSA-PSS-SHA256");
        assert_eq!(ssl.key_alg().unwrap().unwrap(), "RSA4096");
        assert_eq!(ssl.group().unwrap().unwrap(), "X25519");
        assert_eq!(ssl.sig_scheme().unwrap().unwrap(), "rsa_pss_rsae_sha256");
        assert_eq!(
            ssl.client_cert().unwrap().unwrap(),
            &[0x30, 0x82, 0x01, 0x0a]
        );
    }

    #[test]
    fn test_v2_crc32c_validation_and_tampering() {
        let mut tlv_buf = [0u8; 64];
        let mut builder = TlvBuilder::new(&mut tlv_buf);
        builder.append_alpn(b"http/1.1").unwrap();
        builder.append_crc32c_placeholder().unwrap();
        let tlv_slice = builder.into_slice();

        let hdr = ProxyHeader::new_v2_ipv4(
            ProxyCommand::Proxy,
            ProxyTransport::Stream,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            8080,
            80,
            tlv_slice,
        );

        let mut out = [0u8; 128];
        let written = hdr.encode(&mut out).unwrap();

        // Finalize CRC
        update_crc32c_in_buffer(&mut out[..written]).unwrap();

        // Parse: should succeed and verify CRC32c!
        let (parsed, _) = ProxyHeader::parse(&out[..written]).unwrap().unwrap();
        assert!(parsed.crc32c().is_some());

        // Tamper with IP address in wire buffer
        out[16] ^= 0xFF;

        // Parse should now fail with CrcMismatch
        let parse_err = ProxyHeader::parse(&out[..written]).unwrap_err();
        match parse_err {
            ProxyParseError::CrcMismatch { .. } => {}
            other => panic!("expected CrcMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_partial_buffer_streaming() {
        let wire = b"PROXY TCP4 1.1.1.1 2.2.2.2 1234 5678\r\n";
        for i in 0..wire.len() - 1 {
            let res = ProxyHeader::parse(&wire[..i]).unwrap();
            assert!(res.is_none(), "expected None for len {i}");
        }
        let res_full = ProxyHeader::parse(wire).unwrap();
        assert!(res_full.is_some());
    }

    #[test]
    fn test_trailing_payload() {
        let mut wire = Vec::new();
        wire.extend_from_slice(b"PROXY TCP4 10.0.0.1 10.0.0.2 8080 80\r\n");
        wire.extend_from_slice(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");

        let (hdr, consumed) = ProxyHeader::parse(&wire).unwrap().unwrap();
        assert_eq!(hdr.version, ProxyVersion::V1);
        assert_eq!(
            &wire[consumed..],
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
    }
}
