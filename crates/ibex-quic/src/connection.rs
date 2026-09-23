// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! Connection identity and stream descriptors for QUIC.

use std::fmt;

/// Maximum length of a QUIC Connection ID as specified in RFC 9000 §5.1 (20 bytes).
pub const MAX_CID_LEN: usize = 20;

/// A QUIC Connection ID, used as the primary lookup key in the connection table.
///
/// Under RFC 9000 §5.1, connection IDs are up to 20 bytes long. A QUIC connection
/// is identified by its Connection ID, allowing connections to survive client address
/// changes (NAT rebinding, mobile handover) without resetting the connection.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId {
    bytes: [u8; MAX_CID_LEN],
    len: u8,
}

impl ConnectionId {
    /// Creates a new `ConnectionId` from a byte slice.
    ///
    /// # Panics
    /// Truncates to 20 bytes if `bytes.len() > 20`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        let mut buf = [0u8; MAX_CID_LEN];
        let len = bytes.len().min(MAX_CID_LEN);
        buf[..len].copy_from_slice(&bytes[..len]);
        #[allow(clippy::cast_possible_truncation)]
        Self {
            bytes: buf,
            len: len as u8,
        }
    }

    /// Creates a `ConnectionId` from an array and length.
    #[must_use]
    pub const fn from_parts(bytes: [u8; MAX_CID_LEN], len: u8) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let actual_len = if (len as usize) > MAX_CID_LEN {
            MAX_CID_LEN as u8
        } else {
            len
        };
        Self {
            bytes,
            len: actual_len,
        }
    }

    /// Returns the bytes of this Connection ID.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Returns the length in bytes of this Connection ID.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` if this Connection ID is empty (0 bytes).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            write!(f, "<empty>")
        } else {
            for b in self.as_bytes() {
                write!(f, "{b:02x}")?;
            }
            Ok(())
        }
    }
}

impl From<quinn_proto::ConnectionId> for ConnectionId {
    fn from(cid: quinn_proto::ConnectionId) -> Self {
        Self::new(&cid)
    }
}

impl From<ConnectionId> for quinn_proto::ConnectionId {
    fn from(cid: ConnectionId) -> Self {
        quinn_proto::ConnectionId::new(cid.as_bytes())
    }
}

/// Identifies a QUIC stream within a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Creates a new `StreamId`.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw integer value of the Stream ID.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.0
    }

    /// Returns the directionality of this stream (Bidirectional or Unidirectional).
    #[must_use]
    pub const fn dir(&self) -> StreamDirection {
        if (self.0 & 0x02) == 0 {
            StreamDirection::Bidirectional
        } else {
            StreamDirection::Unidirectional
        }
    }

    /// Returns `true` if the stream was initiated by the client.
    #[must_use]
    pub const fn is_client_initiated(&self) -> bool {
        (self.0 & 0x01) == 0
    }

    /// Returns `true` if the stream was initiated by the server.
    #[must_use]
    pub const fn is_server_initiated(&self) -> bool {
        (self.0 & 0x01) != 0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Stream({})", self.0)
    }
}

impl From<quinn_proto::StreamId> for StreamId {
    fn from(id: quinn_proto::StreamId) -> Self {
        Self(id.into())
    }
}

impl From<StreamId> for quinn_proto::StreamId {
    fn from(id: StreamId) -> Self {
        quinn_proto::VarInt::from_u64(id.0)
            .map_or_else(|_| quinn_proto::StreamId::from(quinn_proto::VarInt::MAX), Self::from)
    }
}


/// QUIC stream directionality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamDirection {
    /// Bidirectional stream (both endpoints send and receive).
    Bidirectional,
    /// Unidirectional stream (initiator sends, peer receives).
    Unidirectional,
}

impl From<quinn_proto::Dir> for StreamDirection {
    fn from(dir: quinn_proto::Dir) -> Self {
        match dir {
            quinn_proto::Dir::Bi => Self::Bidirectional,
            quinn_proto::Dir::Uni => Self::Unidirectional,
        }
    }
}

impl From<StreamDirection> for quinn_proto::Dir {
    fn from(dir: StreamDirection) -> Self {
        match dir {
            StreamDirection::Bidirectional => Self::Bi,
            StreamDirection::Unidirectional => Self::Uni,
        }
    }
}

/// Result of reading from a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadStreamResult {
    /// Number of bytes read into the output buffer.
    pub bytes_read: usize,
    /// Whether the stream reached its end (FIN received).
    pub fin: bool,
}

/// Lifecycle state of a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicConnectionState {
    /// Connection handshake is currently in progress.
    Handshaking,
    /// Connection is fully established and authenticated.
    Connected,
    /// Connection is closing.
    Closing,
    /// Connection has been drained and is awaiting disposal.
    Drained,
    /// Connection is closed.
    Closed,
}
