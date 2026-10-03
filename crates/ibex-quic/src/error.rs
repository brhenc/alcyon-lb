// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Error types for `ibex-quic`.

use thiserror::Error;

/// Result type alias for `ibex-quic` operations.
pub type Result<T, E = QuicError> = std::result::Result<T, E>;

/// Errors produced during QUIC transport, endpoint, and stream operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum QuicError {
    /// TLS configuration or crypto provider error.
    #[error("TLS configuration error: {0}")]
    Tls(String),

    /// Endpoint configuration error.
    #[error("endpoint configuration error: {0}")]
    Config(String),

    /// A connection ID was not found in the connection table.
    #[error("connection not found: {0}")]
    ConnectionNotFound(String),

    /// The requested stream was not found or has been closed.
    #[error("stream {0} not found")]
    StreamNotFound(u64),

    /// Stream limit reached for this connection.
    #[error("stream limit reached")]
    StreamLimit,

    /// Stream closed.
    #[error("stream closed")]
    StreamClosed,

    /// Stream was reset by peer.
    #[error("stream reset with error code {0}")]
    StreamReset(u64),

    /// Stream was stopped by peer.
    #[error("stream stopped with error code {0}")]
    StreamStopped(u64),

    /// Buffer provided was too small.
    #[error("buffer too small: needed {needed}, available {available}")]
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes provided.
        available: usize,
    },

    /// Handshake failed.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    /// Connection closed.
    #[error("connection closed: {0}")]
    ConnectionClosed(String),

    /// General transport error.
    #[error("transport error: {0}")]
    Transport(String),

    /// I/O error description.
    #[error("I/O error: {0}")]
    Io(String),
}
