// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC transport boundary trait and transport event definitions.
//!
//! This module defines the transport seam (`QuicTransport`) that isolates the sans-IO
//! QUIC state machine (`quinn-proto`) behind an abstract interface. Nothing above this
//! boundary depends on or names `quinn-proto`.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::connection::{ConnectionId, ReadStreamResult, StreamDirection, StreamId};
use crate::error::Result;

/// Explicit Congestion Notification (ECN) codepoints (RFC 3168).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcnCodepoint {
    /// ECN Capable Transport (ECT(0))
    Ect0,
    /// ECN Capable Transport (ECT(1))
    Ect1,
    /// Congestion Experienced (CE)
    Ce,
}

impl From<quinn_proto::EcnCodepoint> for EcnCodepoint {
    fn from(ecn: quinn_proto::EcnCodepoint) -> Self {
        match ecn {
            quinn_proto::EcnCodepoint::Ect0 => Self::Ect0,
            quinn_proto::EcnCodepoint::Ect1 => Self::Ect1,
            quinn_proto::EcnCodepoint::Ce => Self::Ce,
        }
    }
}

impl From<EcnCodepoint> for quinn_proto::EcnCodepoint {
    fn from(ecn: EcnCodepoint) -> Self {
        match ecn {
            EcnCodepoint::Ect0 => Self::Ect0,
            EcnCodepoint::Ect1 => Self::Ect1,
            EcnCodepoint::Ce => Self::Ce,
        }
    }
}

/// An outbound UDP datagram produced by the transport to be sent over the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// Destination socket address.
    pub destination: SocketAddr,
    /// Local source IP address to bind to (if required by `IP_PKTINFO`).
    pub src_ip: Option<IpAddr>,
    /// Size in bytes of the serialized packet data in the output buffer.
    pub size: usize,
    /// Segment size for Generic Segmentation Offload (GSO), if batched.
    pub segment_size: Option<usize>,
    /// Explicit Congestion Notification marking for the IP header.
    pub ecn: Option<EcnCodepoint>,
}

/// Events emitted by the QUIC transport to upper layers (e.g. the runtime and HTTP/3 stream layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// A new incoming QUIC connection has been accepted.
    NewConnection {
        /// Primary Connection ID of the new connection.
        conn_id: ConnectionId,
        /// Remote peer address.
        remote: SocketAddr,
    },
    /// TLS handshake completed successfully and ALPN was negotiated.
    HandshakeComplete {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Negotiated ALPN protocol (e.g. `b"h3"`).
        alpn: Option<Vec<u8>>,
        /// SNI server name if provided by the client.
        server_name: Option<String>,
    },
    /// A new stream was opened by the remote peer.
    StreamOpened {
        /// Connection ID.
        conn_id: ConnectionId,
        /// ID of the opened stream.
        stream_id: StreamId,
        /// Stream direction (Bidirectional or Unidirectional).
        dir: StreamDirection,
    },
    /// A stream has incoming bytes available to read.
    StreamReadable {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Stream ID.
        stream_id: StreamId,
    },
    /// A stream has capacity to accept more outbound write data.
    StreamWritable {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Stream ID.
        stream_id: StreamId,
    },
    /// The peer finished sending on a stream (FIN received).
    StreamFinished {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Stream ID.
        stream_id: StreamId,
    },
    /// A stream was reset by the peer with an application error code.
    StreamReset {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Stream ID.
        stream_id: StreamId,
        /// Application error code.
        error_code: u64,
    },
    /// A stream was stopped by the peer with an error code (`STOP_SENDING`).
    StreamStopped {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Stream ID.
        stream_id: StreamId,
        /// Application error code.
        error_code: u64,
    },
    /// An unreliable QUIC datagram frame was received on this connection.
    DatagramReceived {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Datagram payload.
        data: Vec<u8>,
    },
    /// The connection was closed.
    ConnectionClosed {
        /// Connection ID.
        conn_id: ConnectionId,
        /// Error code (0 for clean close).
        error_code: u64,
        /// Reason string / bytes.
        reason: Vec<u8>,
    },
}

/// The result of processing an incoming datagram at the transport boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramOutcome {
    /// Datagram initiated a new incoming connection.
    Accepted,
    /// Datagram was routed to an existing active connection.
    Routed,
    /// Datagram generated an immediate stateless response (e.g. Retry or Version Negotiation).
    StatelessResponse,
    /// Datagram was ignored (e.g. corrupt or invalid).
    Ignored,
}

/// Pure sans-IO QUIC transport seam.
///
/// Implementations receive datagrams and a clock, and emit datagrams, timer deadlines,
/// and stream/connection events.
pub trait QuicTransport {
    /// Feed an incoming datagram into the transport.
    ///
    /// # Errors
    /// Returns an error if datagram handling fails unrecoverably.
    fn handle_datagram(
        &mut self,
        now: Instant,
        from: SocketAddr,
        local_ip: Option<IpAddr>,
        buf: &[u8],
    ) -> Result<DatagramOutcome>;

    /// Poll for an outbound datagram to transmit over the UDP socket.
    ///
    /// The payload is written into `out`, and on success a `Transmit` metadata struct is returned.
    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<Transmit>;

    /// Poll for the earliest timer expiry deadline across all active connections.
    #[must_use]
    fn poll_timeout(&self) -> Option<Instant>;

    /// Advance the transport clock and process expired timers (loss recovery, pings, idle timeout).
    fn handle_timeout(&mut self, now: Instant);

    /// Poll for the next queued transport event.
    fn poll_event(&mut self) -> Option<TransportEvent>;

    /// Open a new stream on an active connection.
    ///
    /// # Errors
    /// Returns `QuicError::StreamLimit` if the peer's max streams limit has been reached,
    /// or `QuicError::ConnectionNotFound` if the connection does not exist.
    fn open_stream(&mut self, conn_id: ConnectionId, dir: StreamDirection) -> Result<StreamId>;

    /// Accept a stream opened by the peer on a connection.
    fn accept_stream(&mut self, conn_id: ConnectionId, dir: StreamDirection) -> Option<StreamId>;

    /// Read data from a stream into the provided buffer.
    ///
    /// # Errors
    /// Returns an error if the stream has been reset or does not exist.
    fn read_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        buf: &mut [u8],
    ) -> Result<ReadStreamResult>;

    /// Write data to a stream.
    ///
    /// # Errors
    /// Returns an error if the stream is closed or has been reset.
    fn write_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize>;

    /// Finish (close) the sending half of a stream.
    ///
    /// # Errors
    /// Returns an error if the connection or stream does not exist.
    fn finish_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) -> Result<()>;

    /// Close a connection with an application error code and reason phrase.
    fn close_connection(&mut self, conn_id: ConnectionId, error_code: u64, reason: &[u8]);

    /// Returns the number of currently active connections.
    #[must_use]
    fn connection_count(&self) -> usize;

    /// Returns the negotiated ALPN protocol for a connection, if available.
    #[must_use]
    fn alpn(&self, conn_id: ConnectionId) -> Option<Vec<u8>>;

    /// Returns the SNI server name for a connection, if provided.
    #[must_use]
    fn server_name(&self, conn_id: ConnectionId) -> Option<String>;
}
