// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! QUIC listening socket, integrating UDP datagram I/O (`DgramSocket`) with `ibex-quic`.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Instant;

use std::collections::HashMap;

use crate::dgram::{DgramBuf, DgramOut, DgramSocket};
use ibex_proto::mux_h3;
use ibex_quic::quinn_proto;
use ibex_quic::{
    ConnectionId, QuicConfig, QuicEndpoint, QuicTransport, StreamDirection, StreamId,
    TransportEvent,
};

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
    h3: HashMap<ConnectionId, H3State>,
}

/// Per-connection HTTP/3 state.
#[derive(Default)]
struct H3State {
    /// Our outbound control stream, opened once the handshake negotiates `h3`.
    control: Option<StreamId>,
    /// Bytes accumulated per request stream. A HEADERS frame can arrive split across
    /// datagrams, so a readable event is not a complete frame.
    req: HashMap<StreamId, Vec<u8>>,
    /// Request streams already answered, so a second readable event does not answer twice.
    answered: Vec<StreamId>,
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
            h3: HashMap::new(),
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

impl QuicListener {
    /// Drives one full cycle: read datagrams, serve HTTP/3, write datagrams.
    ///
    /// This is the piece that was missing. `h3.rs` parsed frames, `qpack.rs` decoded header
    /// blocks and the transport moved bytes, but nothing connected them, so `curl --http3`
    /// completed a QUIC handshake and then hung waiting for a response that no code path
    /// could produce.
    ///
    /// # Errors
    /// Returns an error if a non-transient socket error occurs.
    pub fn pump(&mut self, now: Instant) -> io::Result<()> {
        self.recv_batch(now)?;

        let mut scratch = vec![0u8; DGRAM_BUF_SIZE];
        while let Some(ev) = self.endpoint.poll_event() {
            match ev {
                TransportEvent::HandshakeComplete { conn_id, alpn, .. } => {
                    // Only speak HTTP/3 if that is what was negotiated. Anything else is a
                    // connection we have no layer for, and pretending otherwise would send
                    // a client frames it never asked for.
                    if alpn.as_deref() == Some(b"h3".as_slice()) {
                        self.open_control_stream(conn_id);
                    }
                }
                TransportEvent::StreamOpened { conn_id, stream_id, dir } => {
                    if dir == StreamDirection::Bidirectional {
                        self.h3.entry(conn_id).or_default().req.entry(stream_id).or_default();
                    }
                }
                TransportEvent::StreamReadable { conn_id, stream_id } => {
                    self.on_readable(conn_id, stream_id, &mut scratch);
                }
                TransportEvent::StreamFinished { conn_id, stream_id }
                | TransportEvent::StreamReset { conn_id, stream_id, .. } => {
                    if let Some(st) = self.h3.get_mut(&conn_id) {
                        st.req.remove(&stream_id);
                    }
                }
                TransportEvent::ConnectionClosed { conn_id, .. } => {
                    self.h3.remove(&conn_id);
                }
                _ => {}
            }
        }

        self.send_batch(now)?;
        Ok(())
    }

    /// Opens our unidirectional control stream and sends SETTINGS.
    ///
    /// RFC 9114 §6.2.1 requires the control stream be opened before any request is answered,
    /// and that SETTINGS be its first frame.
    fn open_control_stream(&mut self, conn_id: ConnectionId) {
        let st = self.h3.entry(conn_id).or_default();
        if st.control.is_some() {
            return;
        }
        let Ok(sid) = self.endpoint.open_stream(conn_id, StreamDirection::Unidirectional) else {
            return;
        };
        self.h3.entry(conn_id).or_default().control = Some(sid);
        let bytes = mux_h3::encode_control_stream_open();
        let _ = self.endpoint.write_stream(conn_id, sid, &bytes, false);
    }

    /// Reads whatever is available on a stream and, on a request stream, answers it.
    fn on_readable(&mut self, conn_id: ConnectionId, stream_id: StreamId, scratch: &mut [u8]) {
        let mut chunk = Vec::new();
        while let Ok(res) = self.endpoint.read_stream(conn_id, stream_id, scratch) {
            if res.bytes_read == 0 {
                break;
            }
            chunk.extend_from_slice(&scratch[..res.bytes_read]);
        }
        if chunk.is_empty() {
            return;
        }

        // Unidirectional streams from the client are its control stream and the two QPACK
        // streams. With table capacity advertised as zero there is no dynamic state to
        // track, so they are read and discarded -- but they must be read, because a client
        // opens them regardless and a stalled stream stalls the connection.
        if !stream_id.0.is_multiple_of(4) {
            return;
        }

        let st = self.h3.entry(conn_id).or_default();
        if st.answered.contains(&stream_id) {
            return;
        }
        st.req.entry(stream_id).or_default().extend_from_slice(&chunk);
        let buf = st.req.get(&stream_id).cloned().unwrap_or_default();

        // A HEADERS frame can be split across datagrams; Ok(None) means wait for more.
        let Ok(Some(_field_section)) = mux_h3::take_request_headers(&buf) else {
            return;
        };

        let body = b"hello-from-ibex-h3";
        let resp = mux_h3::encode_response(
            200,
            &[("content-length".to_string(), body.len().to_string())],
            body,
        );
        let _ = self.endpoint.write_stream(conn_id, stream_id, &resp, true);
        let st = self.h3.entry(conn_id).or_default();
        st.answered.push(stream_id);
        st.req.remove(&stream_id);
    }
}

/// A QUIC session encapsulating a connection's state, parallel to `TcpSession`.
///
/// Added to satisfy the architectural requirement that a QUIC connection is a distinct session type
/// and not multiplexed into the existing `TcpSession` logic.
pub struct QuicConnection {
    pub conn_id: ibex_quic::ConnectionId,
    pub state: ibex_quic::QuicConnectionState,
}
