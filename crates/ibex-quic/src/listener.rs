// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Standalone QUIC listener integrating UDP I/O with `QuicEndpoint`.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

use crate::config::QuicConfig;
use crate::endpoint::QuicEndpoint;
use crate::transport::{QuicTransport, TransportEvent};

/// A QUIC listener managing datagram I/O on a UDP socket and driving the QUIC transport.
pub struct QuicListener {
    socket: UdpSocket,
    endpoint: QuicEndpoint,
    addr: SocketAddr,
    recv_buf: Box<[u8]>,
    send_buf: Box<[u8]>,
}

impl QuicListener {
    /// Binds a UDP listening socket and initializes the `QuicEndpoint`.
    ///
    /// # Errors
    /// Returns an error if the UDP socket fails to bind or if endpoint configuration fails.
    pub fn bind(
        addr: SocketAddr,
        tls: &Arc<ibex_tls::tcp::BindTls>,
        quic_config: Option<QuicConfig>,
    ) -> io::Result<Self> {
        let config = quic_config.unwrap_or_default();
        let server_config = config
            .build_server_config(tls)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        // The whole config has to reach the endpoint, not just its TLS half. Routing through
        // `bind_with_server_config` dropped `require_retry` and `anti_amplification_factor` on
        // the floor, so a stricter factor an operator asked for was silently ignored.
        let endpoint = QuicEndpoint::with_configs_and_amplification(
            Arc::new(config.build_endpoint_config().map_err(|e| io::Error::other(e.to_string()))?),
            server_config,
            config.require_retry,
            config.anti_amplification_factor,
        );
        Self::from_endpoint(addr, endpoint)
    }

    /// Binds a UDP socket on `addr` and initializes with a pre-built `quinn_proto::ServerConfig`.
    ///
    /// # Errors
    /// Returns an error if the UDP socket cannot be bound or if endpoint initialization fails.
    pub fn bind_with_server_config(
        addr: SocketAddr,
        server_config: Arc<quinn_proto::ServerConfig>,
    ) -> io::Result<Self> {
        let endpoint = QuicEndpoint::with_server_config(server_config)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Self::from_endpoint(addr, endpoint)
    }

    /// Binds the UDP socket and wraps an already-configured endpoint.
    fn from_endpoint(addr: SocketAddr, endpoint: QuicEndpoint) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let bound_addr = socket.local_addr()?;

        Ok(Self {
            socket,
            endpoint,
            addr: bound_addr,
            recv_buf: vec![0u8; 65535].into_boxed_slice(),
            send_buf: vec![0u8; 65535].into_boxed_slice(),
        })
    }


    /// Returns the local bound address of the listener.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns a reference to the underlying `UdpSocket`.
    #[must_use]
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Receives incoming datagrams from the UDP socket and feeds them into the QUIC transport.
    ///
    /// # Errors
    /// Returns an error if a non-transient socket read error occurs.
    pub fn handle_read(&mut self, now: Instant) -> io::Result<usize> {
        let mut count = 0;

        loop {
            match self.socket.recv_from(&mut self.recv_buf) {
                Ok((bytes_read, peer_addr)) => {
                    let _ = self.endpoint.handle_datagram(
                        now,
                        peer_addr,
                        None,
                        &self.recv_buf[..bytes_read],
                    );
                    count += 1;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        Ok(count)
    }

    /// Drains outbound transmits from the QUIC transport and sends them over the UDP socket.
    ///
    /// # Errors
    /// Returns an error if a non-transient socket write error occurs.
    pub fn handle_write(&mut self, now: Instant) -> io::Result<usize> {
        let mut count = 0;

        while let Some(tx) = self.endpoint.poll_transmit(now, &mut self.send_buf) {
            match self.socket.send_to(&self.send_buf[..tx.size], tx.destination) {
                Ok(_) => {
                    count += 1;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        Ok(count)
    }

    /// Advances the transport timers (loss recovery, idle timeout).
    pub fn handle_timeout(&mut self, now: Instant) {
        self.endpoint.handle_timeout(now);
    }

    /// Returns the next earliest timer expiry instant.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.endpoint.poll_timeout()
    }

    /// Polls for the next queued transport event.
    pub fn poll_event(&mut self) -> Option<TransportEvent> {
        self.endpoint.poll_event()
    }

    /// Returns a reference to the transport interface.
    #[must_use]
    pub const fn transport(&self) -> &QuicEndpoint {
        &self.endpoint
    }

    /// Returns a mutable reference to the transport interface.
    pub fn transport_mut(&mut self) -> &mut QuicEndpoint {
        &mut self.endpoint
    }
}
