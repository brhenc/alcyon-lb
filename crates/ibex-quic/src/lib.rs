// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! # `ibex-quic`
//!
//! Pure memory-safe QUIC transport layer for Project Ibex.
//!
//! Features:
//! - Pure `#![forbid(unsafe_code)]` with `quinn-proto 0.11` and `rustls 0.23`.
//! - Pure sans-IO architecture: operates on datagram buffers and clocks without async runtimes.
//! - Transport seam: [`QuicTransport`] encapsulates the underlying state machine.
//! - Connection table keyed by Destination Connection ID (DCID), supporting client migration.
//! - ALPN `h3` negotiation and certificate loading with `ibex-tls`.
//! - Timer wheel integration via explicit timeout polling.

#![forbid(unsafe_code)]

pub mod config;
pub mod connection;
pub mod endpoint;
pub mod error;
pub mod listener;
pub mod table;
pub mod transport;

pub use quinn_proto;
pub use config::{load_pem_cert_and_key, QuicConfig, ALPN_H3};
pub use connection::{
    ConnectionId, QuicConnectionState, ReadStreamResult, StreamDirection, StreamId, MAX_CID_LEN,
};
pub use endpoint::QuicEndpoint;
pub use error::{QuicError, Result};
pub use listener::QuicListener;
pub use table::ConnectionTable;
pub use transport::{
    DatagramOutcome, EcnCodepoint, QuicTransport, TransportEvent, Transmit,
};
