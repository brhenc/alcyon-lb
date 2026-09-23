// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! QUIC listening socket, integrating UDP datagram I/O (`DgramSocket`) with `ibex-quic`.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Instant;

use crate::dgram::{DgramBuf, DgramOut, DgramSocket};
use ibex_quic::quinn_proto;
use ibex_quic::{QuicConfig, QuicEndpoint, QuicTransport, TransportEvent};

/// Batch size for datagram I/O.
const BATCH_SIZE: usize = 32;
/// Buffer capacity per datagram (covers maximum standard Ethernet MTU and QUIC padding).
const DGRAM_BUF_SIZE: usize = 2048;
/// Control message buffer capacity per datagram for `IP_PKTINFO`.
const CMSG_BUF_SIZE: usize = 128;

/// A QUIC listener managing datagram I/O on a nonblocking UDP socket and driving the QUIC transport.
pub struct QuicListener {
    socket: DgramSocket,
    endpoint: QuicEndpoint,
    addr: SocketAddr,
    recv_raw_bufs: Vec<Vec<u8>>,
    recv_cmsg_bufs: Vec<Vec<u8>>,
    send_raw_bufs: Vec<Vec<u8>>,
}

impl QuicListener {
    /// Binds a UDP socket on `addr` and initializes the `ibex_quic::QuicEndpoint`.
    ///
    /// # Errors
    /// Returns an error if the UDP socket cannot be bound or if endpoint initialization fails.
    pub fn bind(
        addr: SocketAddr,
        tls_server_config: &rustls::ServerConfig,
        quic_config: Option<QuicConfig>,
    ) -> io::Result<Self> {
        let config = quic_config.unwrap_or_default();
        let server_config = config
            .build_server_config(tls_server_config)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Self::bind_with_server_config(addr, server_config)
    }

    /// Binds a UDP socket on `addr` and initializes with a pre-built `quinn_proto::ServerConfig`.
    ///
    /// # Errors
    /// Returns an error if the UDP socket cannot be bound or if endpoint initialization fails.
    pub fn bind_with_server_config(
        addr: SocketAddr,
        server_config: Arc<quinn_proto::ServerConfig>,
    ) -> io::Result<Self> {
        let socket = DgramSocket::bind(addr)?;
        let bound_addr = socket.local_addr().unwrap_or(addr);

        let endpoint = QuicEndpoint::with_server_config(server_config)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let recv_raw_bufs = vec![vec![0u8; DGRAM_BUF_SIZE]; BATCH_SIZE];
        let recv_cmsg_bufs = vec![vec![0u8; CMSG_BUF_SIZE]; BATCH_SIZE];
        let send_raw_bufs = vec![vec![0u8; DGRAM_BUF_SIZE]; BATCH_SIZE];

        Ok(Self {
            socket,
            endpoint,
            addr: bound_addr,
            recv_raw_bufs,
            recv_cmsg_bufs,
            send_raw_bufs,
        })
    }


    /// Returns the local bound address of the listener.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the raw file descriptor of the underlying socket for poller registration.
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// Receives a batch of incoming datagrams and passes them to the QUIC transport.
    ///
    /// # Errors
    /// Returns an error if a non-transient socket error occurs.
    pub fn recv_batch(&mut self, now: Instant) -> io::Result<usize> {
        let mut dgram_bufs: Vec<DgramBuf> = self
            .recv_raw_bufs
            .iter_mut()
            .zip(self.recv_cmsg_bufs.iter_mut())
            .map(|(buf, cmsg_buf)| DgramBuf::new(buf.as_mut_slice(), cmsg_buf.as_mut_slice()))
            .collect();

        let n = self.socket.recv_batch(&mut dgram_bufs)?;
        for item in dgram_bufs.iter().take(n) {
            if item.truncated {
                continue;
            }
            if let Some(src) = item.src_addr {
                let _ = self.endpoint.handle_datagram(
                    now,
                    src,
                    item.dst_addr,
                    &item.buf[..item.len],
                );
            }
        }

        Ok(n)
    }

    /// Drains outbound transmits from the QUIC transport and sends them in batch over the socket.
    ///
    /// # Errors
    /// Returns an error if a non-transient socket write error occurs.
    pub fn send_batch(&mut self, now: Instant) -> io::Result<usize> {
        let mut total_sent = 0;

        loop {
            let mut transmits = Vec::with_capacity(BATCH_SIZE);
            let mut send_msgs = Vec::with_capacity(BATCH_SIZE);

            for i in 0..BATCH_SIZE {
                if let Some(tx) = self.endpoint.poll_transmit(now, &mut self.send_raw_bufs[i]) {
                    transmits.push(tx);
                } else {
                    break;
                }
            }

            if transmits.is_empty() {
                break;
            }

            for (i, tx) in transmits.iter().enumerate() {
                let mut msg = DgramOut::new(&self.send_raw_bufs[i][..tx.size]);
                msg.dst_addr = Some(tx.destination);
                msg.src_addr = tx.src_ip;
                send_msgs.push(msg);
            }

            let sent = self.socket.send_batch(&send_msgs)?;
            total_sent += sent;
            if sent < transmits.len() {
                break;
            }
        }

        Ok(total_sent)
    }

    /// Advances the transport timers for loss recovery and idle timeout.
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
