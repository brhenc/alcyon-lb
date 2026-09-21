//! HAProxy Peer Protocol (v2 / v2.1) Wire Framing & Serialization.

use bytes::{BufMut, BytesMut};
use ibex_core::error::{IbexError, IbexResult};
use std::net::{Ipv4Addr, Ipv6Addr};

/// HAProxy Peers protocol magic headers and versions
pub const PEER_PROTO_VERSION_20: u8 = 0x20;
pub const PEER_PROTO_VERSION_21: u8 = 0x21;

/// Peer Message Class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMsgClass {
    Control,
    StickTable,
    Unknown(u8),
}

/// Peer Message Type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMessage {
    Handshake {
        version: u8,
        peer_id: String,
    },
    Heartbeat,
    TableDefinition {
        table_name: String,
        table_id: u32,
    },
    TableUpdate {
        table_id: u32,
        key: PeerKey,
        conn_cnt: Option<u64>,
        conn_cur: Option<u32>,
        http_req_cnt: Option<u64>,
        server_id: Option<u32>,
    },
    Ack {
        sequence: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerKey {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Integer(u64),
    String(String),
}

/// Variable-length integer codec (HAProxy varint)
pub struct VarintCodec;

impl VarintCodec {
    /// Encodes a u64 into HAProxy-style varint bytes.
    pub fn encode_varint(mut val: u64, dst: &mut BytesMut) {
        loop {
            if val < 0x80 {
                dst.put_u8(val as u8);
                break;
            } else {
                dst.put_u8(((val & 0x7F) | 0x80) as u8);
                val >>= 7;
            }
        }
    }

    /// Decodes a u64 from bytes, returning (value, bytes_consumed).
    pub fn decode_varint(src: &mut &[u8]) -> IbexResult<u64> {
        let mut result: u64 = 0;
        let mut shift: usize = 0;

        for _ in 0..10 {
            if src.is_empty() {
                return Err(IbexError::Peers("Unexpected EOF decoding varint".into()));
            }
            let byte = src[0];
            *src = &src[1..];
            result |= ((byte & 0x7F) as u64) << shift;
            if (byte & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
        }

        Err(IbexError::Peers("Varint overflow".into()))
    }
}

/// Peer Protocol Frame Encoder & Decoder
pub struct PeerCodec;

impl PeerCodec {
    /// Encodes a PeerMessage into wire format.
    pub fn encode(msg: &PeerMessage, dst: &mut BytesMut) -> IbexResult<()> {
        match msg {
            PeerMessage::Handshake { version, peer_id } => {
                dst.put_u8(*version);
                VarintCodec::encode_varint(peer_id.len() as u64, dst);
                dst.put_slice(peer_id.as_bytes());
            }
            PeerMessage::Heartbeat => {
                dst.put_u8(0xFF); // Heartbeat opcode
            }
            PeerMessage::TableDefinition {
                table_name,
                table_id,
            } => {
                dst.put_u8(0x01); // Table definition opcode
                VarintCodec::encode_varint(*table_id as u64, dst);
                VarintCodec::encode_varint(table_name.len() as u64, dst);
                dst.put_slice(table_name.as_bytes());
            }
            PeerMessage::TableUpdate {
                table_id,
                key,
                conn_cnt,
                conn_cur,
                http_req_cnt,
                server_id,
            } => {
                dst.put_u8(0x02); // Table update opcode
                VarintCodec::encode_varint(*table_id as u64, dst);
                match key {
                    PeerKey::Ipv4(ip) => {
                        dst.put_u8(4);
                        dst.put_slice(&ip.octets());
                    }
                    PeerKey::Ipv6(ip) => {
                        dst.put_u8(6);
                        dst.put_slice(&ip.octets());
                    }
                    PeerKey::Integer(v) => {
                        dst.put_u8(8);
                        VarintCodec::encode_varint(*v, dst);
                    }
                    PeerKey::String(s) => {
                        dst.put_u8(1);
                        VarintCodec::encode_varint(s.len() as u64, dst);
                        dst.put_slice(s.as_bytes());
                    }
                }
                VarintCodec::encode_varint(conn_cnt.unwrap_or(0), dst);
                VarintCodec::encode_varint(conn_cur.unwrap_or(0) as u64, dst);
                VarintCodec::encode_varint(http_req_cnt.unwrap_or(0), dst);
                VarintCodec::encode_varint(server_id.unwrap_or(0) as u64, dst);
            }
            PeerMessage::Ack { sequence } => {
                dst.put_u8(0x03);
                VarintCodec::encode_varint(*sequence, dst);
            }
        }
        Ok(())
    }

    /// Decodes a PeerMessage from wire bytes.
    pub fn decode(src: &mut &[u8]) -> IbexResult<Option<PeerMessage>> {
        if src.is_empty() {
            return Ok(None);
        }

        let opcode = src[0];
        *src = &src[1..];

        match opcode {
            PEER_PROTO_VERSION_20 | PEER_PROTO_VERSION_21 => {
                let len = VarintCodec::decode_varint(src)? as usize;
                if src.len() < len {
                    return Err(IbexError::Peers("Incomplete handshake frame".into()));
                }
                let peer_id = String::from_utf8_lossy(&src[..len]).to_string();
                *src = &src[len..];
                Ok(Some(PeerMessage::Handshake {
                    version: opcode,
                    peer_id,
                }))
            }
            0xFF => Ok(Some(PeerMessage::Heartbeat)),
            0x01 => {
                let table_id = VarintCodec::decode_varint(src)? as u32;
                let name_len = VarintCodec::decode_varint(src)? as usize;
                if src.len() < name_len {
                    return Err(IbexError::Peers("Incomplete table definition".into()));
                }
                let table_name = String::from_utf8_lossy(&src[..name_len]).to_string();
                *src = &src[name_len..];
                Ok(Some(PeerMessage::TableDefinition {
                    table_name,
                    table_id,
                }))
            }
            0x02 => {
                let table_id = VarintCodec::decode_varint(src)? as u32;
                if src.is_empty() {
                    return Err(IbexError::Peers("Incomplete key type".into()));
                }
                let key_type = src[0];
                *src = &src[1..];

                let key = match key_type {
                    4 => {
                        if src.len() < 4 {
                            return Err(IbexError::Peers("Incomplete IPv4 key".into()));
                        }
                        let octets: [u8; 4] = [src[0], src[1], src[2], src[3]];
                        *src = &src[4..];
                        PeerKey::Ipv4(Ipv4Addr::from(octets))
                    }
                    6 => {
                        if src.len() < 16 {
                            return Err(IbexError::Peers("Incomplete IPv6 key".into()));
                        }
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&src[..16]);
                        *src = &src[16..];
                        PeerKey::Ipv6(Ipv6Addr::from(octets))
                    }
                    8 => {
                        let val = VarintCodec::decode_varint(src)?;
                        PeerKey::Integer(val)
                    }
                    1 => {
                        let len = VarintCodec::decode_varint(src)? as usize;
                        if src.len() < len {
                            return Err(IbexError::Peers("Incomplete string key".into()));
                        }
                        let s = String::from_utf8_lossy(&src[..len]).to_string();
                        *src = &src[len..];
                        PeerKey::String(s)
                    }
                    other => {
                        return Err(IbexError::Peers(format!("Unknown key type {other}")));
                    }
                };

                let conn_cnt = Some(VarintCodec::decode_varint(src)?);
                let conn_cur = Some(VarintCodec::decode_varint(src)? as u32);
                let http_req_cnt = Some(VarintCodec::decode_varint(src)?);
                let server_id = Some(VarintCodec::decode_varint(src)? as u32);

                Ok(Some(PeerMessage::TableUpdate {
                    table_id,
                    key,
                    conn_cnt,
                    conn_cur,
                    http_req_cnt,
                    server_id,
                }))
            }
            0x03 => {
                let seq = VarintCodec::decode_varint(src)?;
                Ok(Some(PeerMessage::Ack { sequence: seq }))
            }
            other => Err(IbexError::Peers(format!("Unknown opcode {other:#x}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let values = [0u64, 1, 127, 128, 255, 300, 16384, 1_000_000_000];
        for v in values {
            let mut buf = BytesMut::new();
            VarintCodec::encode_varint(v, &mut buf);
            let mut slice = &buf[..];
            let decoded = VarintCodec::decode_varint(&mut slice).expect("decode varint");
            assert_eq!(v, decoded);
            assert!(slice.is_empty());
        }
    }

    #[test]
    fn test_peer_message_handshake_roundtrip() {
        let msg = PeerMessage::Handshake {
            version: PEER_PROTO_VERSION_21,
            peer_id: "haproxy-node-1".to_string(),
        };
        let mut buf = BytesMut::new();
        PeerCodec::encode(&msg, &mut buf).expect("encode");

        let mut slice = &buf[..];
        let decoded = PeerCodec::decode(&mut slice).expect("decode").unwrap();
        assert_eq!(msg, decoded);
    }
}
