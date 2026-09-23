// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Ibex contributors. See LICENSE.

//! QUIC endpoint implementation encapsulating `quinn-proto`.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, ServerConfig, VarInt};


use crate::config::QuicConfig;
use crate::connection::{ConnectionId, ReadStreamResult, StreamDirection, StreamId};
use crate::error::{QuicError, Result};
use crate::table::ConnectionTable;
use crate::transport::{DatagramOutcome, EcnCodepoint, QuicTransport, TransportEvent, Transmit};

/// A QUIC server endpoint managing connections, the connection table, and packet dispatch.
pub struct QuicEndpoint {
    endpoint: Endpoint,
    server_config: Arc<ServerConfig>,
    connection_table: ConnectionTable,
    connections: HashMap<ConnectionHandle, quinn_proto::Connection>,
    handle_to_primary_cid: HashMap<ConnectionHandle, ConnectionId>,
    pending_transmits: VecDeque<TransmitEntry>,
    event_queue: VecDeque<TransportEvent>,
    active_handles: Vec<ConnectionHandle>,
    round_robin_idx: usize,
    next_timeout: Option<Instant>,
    response_buf: Vec<u8>,
    tx_buf: Vec<u8>,
}


struct TransmitEntry {
    transmit: Transmit,
    data: Vec<u8>,
}

impl QuicEndpoint {
    /// Creates a new `QuicEndpoint` with the provided TLS `ServerConfig` and optional `QuicConfig`.
    ///
    /// # Errors
    /// Returns `QuicError::Config` if endpoint initialization fails.
    pub fn new(
        tls_server_config: &rustls::ServerConfig,
        quic_config: Option<QuicConfig>,
    ) -> Result<Self> {
        let config = quic_config.unwrap_or_default();
        let server_config = config.build_server_config(tls_server_config)?;
        let endpoint_config = Arc::new(config.build_endpoint_config());
        Ok(Self::with_configs(
            endpoint_config,
            server_config,
            config.require_retry,
        ))
    }

    /// Creates a `QuicEndpoint` with custom `EndpointConfig`, `ServerConfig`, and retry requirement.
    #[must_use]
    pub fn with_configs(
        endpoint_config: Arc<EndpointConfig>,
        server_config: Arc<ServerConfig>,
        require_retry: bool,
    ) -> Self {
        let endpoint = Endpoint::new(
            endpoint_config,
            Some(server_config.clone()),
            require_retry,
            None,
        );

        Self {
            endpoint,
            server_config,
            connection_table: ConnectionTable::new(),
            connections: HashMap::new(),
            handle_to_primary_cid: HashMap::new(),
            pending_transmits: VecDeque::new(),
            event_queue: VecDeque::new(),
            active_handles: Vec::new(),
            round_robin_idx: 0,
            next_timeout: None,
            response_buf: Vec::with_capacity(2048),
            tx_buf: Vec::with_capacity(2048),
        }
    }

    /// Creates a `QuicEndpoint` from an already configured `quinn_proto::ServerConfig`.
    ///
    /// # Errors
    /// Returns `QuicError::Config` if initialization fails.
    pub fn with_server_config(server_config: Arc<ServerConfig>) -> Result<Self> {
        Ok(Self::with_configs(Arc::new(EndpointConfig::default()), server_config, false))
    }

    /// Recomputes and caches the earliest timeout across all active connections.
    pub fn update_next_timeout(&mut self) {
        let mut min_timeout: Option<Instant> = None;
        for conn in self.connections.values_mut() {
            if let Some(timeout) = conn.poll_timeout() {
                min_timeout = match min_timeout {
                    Some(current) => Some(current.min(timeout)),
                    None => Some(timeout),
                };
            }
        }
        self.next_timeout = min_timeout;
    }


    /// Helper to look up connection handle by `ConnectionId`.
    fn get_handle(&self, conn_id: &ConnectionId) -> Result<ConnectionHandle> {
        self.connection_table
            .lookup(conn_id)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn_id.to_string()))
    }

    /// Drives a connection's endpoint events and high-level poll events.
    fn drive_connection(&mut self, handle: ConnectionHandle, _now: Instant) {
        let Some(conn) = self.connections.get_mut(&handle) else {
            return;
        };

        // Drain endpoint events and feed back
        while let Some(ep_evt) = conn.poll_endpoint_events() {
            if let Some(conn_evt) = self.endpoint.handle_event(handle, ep_evt) {
                conn.handle_event(conn_evt);
            }
        }

        let primary_cid = self
            .handle_to_primary_cid
            .get(&handle)
            .copied()
            .unwrap_or_else(|| ConnectionId::new(&[]));

        // Drain connection events
        while let Some(evt) = conn.poll() {
            match evt {
                quinn_proto::Event::Connected => {
                    let mut alpn = None;
                    let mut server_name = None;

                    if let Some(hd_any) = conn.crypto_session().handshake_data() {
                        if let Some(hd) = hd_any.downcast_ref::<quinn_proto::crypto::rustls::HandshakeData>() {
                            alpn.clone_from(&hd.protocol);
                            server_name.clone_from(&hd.server_name);
                        }
                    }

                    self.event_queue.push_back(TransportEvent::HandshakeComplete {
                        conn_id: primary_cid,
                        alpn,
                        server_name,
                    });
                }

                quinn_proto::Event::ConnectionLost { reason } => {
                    let (error_code, reason_bytes) = match reason {
                        quinn_proto::ConnectionError::ApplicationClosed(app) => {
                            (app.error_code.into(), app.reason.to_vec())
                        }
                        quinn_proto::ConnectionError::ConnectionClosed(close) => {
                            (close.error_code.into(), close.reason.to_vec())
                        }
                        quinn_proto::ConnectionError::Reset => (1, b"reset".to_vec()),
                        quinn_proto::ConnectionError::TimedOut => (2, b"timeout".to_vec()),
                        quinn_proto::ConnectionError::LocallyClosed => (0, b"clean close".to_vec()),
                        quinn_proto::ConnectionError::TransportError(err) => {
                            (err.code.into(), err.reason.as_bytes().to_vec())
                        }
                        quinn_proto::ConnectionError::VersionMismatch => {
                            (4, b"version mismatch".to_vec())
                        }
                        quinn_proto::ConnectionError::CidsExhausted => {
                            (5, b"cids exhausted".to_vec())
                        }
                    };

                    self.event_queue.push_back(TransportEvent::ConnectionClosed {
                        conn_id: primary_cid,
                        error_code,
                        reason: reason_bytes,
                    });
                }
                quinn_proto::Event::Stream(stream_evt) => match stream_evt {
                    quinn_proto::StreamEvent::Opened { dir } => {
                        let stream_id = conn.streams().accept(dir);
                        if let Some(sid) = stream_id {
                            self.event_queue.push_back(TransportEvent::StreamOpened {
                                conn_id: primary_cid,
                                stream_id: StreamId::from(sid),
                                dir: StreamDirection::from(dir),
                            });
                        }
                    }
                    quinn_proto::StreamEvent::Readable { id } => {
                        self.event_queue.push_back(TransportEvent::StreamReadable {
                            conn_id: primary_cid,
                            stream_id: StreamId::from(id),
                        });
                    }
                    quinn_proto::StreamEvent::Writable { id } => {
                        self.event_queue.push_back(TransportEvent::StreamWritable {
                            conn_id: primary_cid,
                            stream_id: StreamId::from(id),
                        });
                    }
                    quinn_proto::StreamEvent::Finished { id } => {
                        self.event_queue.push_back(TransportEvent::StreamFinished {
                            conn_id: primary_cid,
                            stream_id: StreamId::from(id),
                        });
                    }
                    quinn_proto::StreamEvent::Stopped { id, error_code } => {
                        self.event_queue.push_back(TransportEvent::StreamStopped {
                            conn_id: primary_cid,
                            stream_id: StreamId::from(id),
                            error_code: error_code.into(),
                        });
                    }
                    quinn_proto::StreamEvent::Available { .. } => {}
                },
                quinn_proto::Event::HandshakeDataReady
                | quinn_proto::Event::DatagramReceived
                | quinn_proto::Event::DatagramsUnblocked => {}
            }
        }
    }



    /// Cleans up drained or dead connections from the table and handle list.
    pub fn cleanup_drained(&mut self) {
        let mut to_remove = Vec::new();
        for (&handle, conn) in &self.connections {
            if conn.is_drained() {
                to_remove.push(handle);
            }
        }

        for handle in to_remove {
            self.connections.remove(&handle);
            self.handle_to_primary_cid.remove(&handle);
            self.connection_table.remove_connection(handle);
            self.active_handles.retain(|&h| h != handle);
        }
    }
}

impl QuicTransport for QuicEndpoint {
    fn handle_datagram(
        &mut self,
        now: Instant,
        from: SocketAddr,
        local_ip: Option<IpAddr>,
        buf: &[u8],
    ) -> Result<DatagramOutcome> {
        self.response_buf.clear();
        let data = BytesMut::from(buf);

        let event = self
            .endpoint
            .handle(now, from, local_ip, None, data, &mut self.response_buf);

        self.update_next_timeout();
        match event {
            Some(DatagramEvent::NewConnection(incoming)) => {
                let remote_addr = incoming.remote_address();
                let primary_cid = ConnectionId::from(*incoming.orig_dst_cid());
                let outcome = match self.endpoint.accept(
                    incoming,
                    now,
                    &mut self.response_buf,
                    Some(self.server_config.clone()),
                ) {
                    Ok((handle, conn)) => {
                        self.connection_table.insert(primary_cid, handle);
                        self.handle_to_primary_cid.insert(handle, primary_cid);
                        self.connections.insert(handle, conn);
                        self.active_handles.push(handle);

                        self.event_queue.push_back(TransportEvent::NewConnection {
                            conn_id: primary_cid,
                            remote: remote_addr,
                        });

                        self.drive_connection(handle, now);
                        self.update_next_timeout();
                        DatagramOutcome::Accepted
                    }
                    Err(e) => {
                        if !self.response_buf.is_empty() {
                            let tx = Transmit {
                                destination: from,
                                src_ip: local_ip,
                                size: self.response_buf.len(),
                                segment_size: None,
                                ecn: None,
                            };
                            self.pending_transmits.push_back(TransmitEntry {
                                transmit: tx,
                                data: self.response_buf.clone(),
                            });
                        }
                        let _ = e;
                        DatagramOutcome::Ignored
                    }
                };

                Ok(outcome)
            }

            Some(DatagramEvent::ConnectionEvent(handle, conn_evt)) => {
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.handle_event(conn_evt);
                    self.drive_connection(handle, now);
                    self.update_next_timeout();
                    Ok(DatagramOutcome::Routed)
                } else {
                    Ok(DatagramOutcome::Ignored)
                }
            }
            Some(DatagramEvent::Response(tx)) => {
                let transmit = Transmit {
                    destination: tx.destination,
                    src_ip: tx.src_ip,
                    size: tx.size,
                    segment_size: tx.segment_size,
                    ecn: tx.ecn.map(EcnCodepoint::from),
                };
                self.pending_transmits.push_back(TransmitEntry {
                    transmit,
                    data: self.response_buf.clone(),
                });
                Ok(DatagramOutcome::StatelessResponse)
            }
            None => Ok(DatagramOutcome::Ignored),
        }
    }

    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<Transmit> {
        // 1. First priority: queued stateless transmits (Retry, Version Negotiation, etc.)
        if let Some(entry) = self.pending_transmits.front() {
            if out.len() >= entry.data.len() {
                let entry = self.pending_transmits.pop_front().expect("front exists");
                out[..entry.data.len()].copy_from_slice(&entry.data);
                return Some(entry.transmit);
            }
        }

        // 2. Second priority: connection-level transmits (fair round-robin)
        if self.active_handles.is_empty() {
            return None;
        }

        let num_handles = self.active_handles.len();
        for _ in 0..num_handles {
            let idx = self.round_robin_idx % num_handles;
            self.round_robin_idx = self.round_robin_idx.wrapping_add(1);
            let handle = self.active_handles[idx];

            if let Some(conn) = self.connections.get_mut(&handle) {
                self.tx_buf.clear();
                if let Some(tx) = conn.poll_transmit(now, 1, &mut self.tx_buf) {
                    let size = tx.size.min(out.len()).min(self.tx_buf.len());
                    out[..size].copy_from_slice(&self.tx_buf[..size]);

                    // Drive any endpoint events produced during transmit
                    while let Some(ep_evt) = conn.poll_endpoint_events() {
                        if let Some(conn_evt) = self.endpoint.handle_event(handle, ep_evt) {
                            conn.handle_event(conn_evt);
                        }
                    }

                    self.update_next_timeout();
                    return Some(Transmit {
                        destination: tx.destination,
                        src_ip: tx.src_ip,
                        size,
                        segment_size: tx.segment_size,
                        ecn: tx.ecn.map(EcnCodepoint::from),
                    });
                }
            }
        }

        None
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.next_timeout
    }

    fn handle_timeout(&mut self, now: Instant) {
        for &handle in &self.active_handles {
            if let Some(conn) = self.connections.get_mut(&handle) {
                if let Some(timeout) = conn.poll_timeout() {
                    if timeout <= now {
                        conn.handle_timeout(now);
                    }
                }
            }
        }

        let handles = self.active_handles.clone();
        for handle in handles {
            self.drive_connection(handle, now);
        }

        self.cleanup_drained();
        self.update_next_timeout();
    }




    fn poll_event(&mut self) -> Option<TransportEvent> {
        self.event_queue.pop_front()
    }

    fn open_stream(&mut self, conn_id: ConnectionId, dir: StreamDirection) -> Result<StreamId> {
        let handle = self.get_handle(&conn_id)?;
        let conn = self
            .connections
            .get_mut(&handle)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn_id.to_string()))?;

        conn.streams()
            .open(dir.into())
            .map(StreamId::from)
            .ok_or(QuicError::StreamLimit)
    }

    fn accept_stream(&mut self, conn_id: ConnectionId, dir: StreamDirection) -> Option<StreamId> {
        let handle = self.connection_table.lookup(&conn_id)?;
        let conn = self.connections.get_mut(&handle)?;
        conn.streams().accept(dir.into()).map(StreamId::from)
    }

    fn read_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        buf: &mut [u8],
    ) -> Result<ReadStreamResult> {
        let handle = self.get_handle(&conn_id)?;
        let conn = self
            .connections
            .get_mut(&handle)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn_id.to_string()))?;

        let mut recv = conn.recv_stream(stream_id.into());
        let mut chunks = recv
            .read(true)
            .map_err(|e| QuicError::Transport(format!("stream read error: {e}")))?;

        let mut bytes_read = 0;
        let mut fin = false;

        while bytes_read < buf.len() {
            let max_read = buf.len() - bytes_read;
            match chunks.next(max_read) {
                Ok(Some(chunk)) => {
                    let len = chunk.bytes.len().min(max_read);
                    buf[bytes_read..bytes_read + len].copy_from_slice(&chunk.bytes[..len]);
                    bytes_read += len;
                }
                Ok(None) => {
                    fin = true;
                    break;
                }
                Err(quinn_proto::ReadError::Blocked) => {
                    break;
                }
                Err(quinn_proto::ReadError::Reset(code)) => {
                    return Err(QuicError::StreamReset(code.into()));
                }
            }
        }

        let _ = chunks.finalize();

        Ok(ReadStreamResult { bytes_read, fin })
    }

    fn write_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize> {
        let handle = self.get_handle(&conn_id)?;
        let conn = self
            .connections
            .get_mut(&handle)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn_id.to_string()))?;

        let mut send = conn.send_stream(stream_id.into());
        let written = send
            .write(buf)
            .map_err(|e| QuicError::Transport(format!("stream write error: {e}")))?;

        if fin {
            let _ = send.finish();
        }

        Ok(written)
    }

    fn finish_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) -> Result<()> {
        let handle = self.get_handle(&conn_id)?;
        let conn = self
            .connections
            .get_mut(&handle)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn_id.to_string()))?;

        conn.send_stream(stream_id.into())
            .finish()
            .map_err(|e| QuicError::Transport(format!("stream finish error: {e}")))?;

        Ok(())
    }

    fn close_connection(&mut self, conn_id: ConnectionId, error_code: u64, reason: &[u8]) {
        if let Some(handle) = self.connection_table.lookup(&conn_id) {
            if let Some(conn) = self.connections.get_mut(&handle) {
                if let Ok(code) = VarInt::from_u64(error_code) {
                    conn.close(Instant::now(), code, Bytes::copy_from_slice(reason));
                }
            }
        }
    }

    fn connection_count(&self) -> usize {
        self.connections.len()
    }

    fn alpn(&self, conn_id: ConnectionId) -> Option<Vec<u8>> {
        let handle = self.connection_table.lookup(&conn_id)?;
        let conn = self.connections.get(&handle)?;
        let hd_any = conn.crypto_session().handshake_data()?;
        let hd = hd_any.downcast_ref::<quinn_proto::crypto::rustls::HandshakeData>()?;
        hd.protocol.clone()
    }

    fn server_name(&self, conn_id: ConnectionId) -> Option<String> {
        let handle = self.connection_table.lookup(&conn_id)?;
        let conn = self.connections.get(&handle)?;
        let hd_any = conn.crypto_session().handshake_data()?;
        let hd = hd_any.downcast_ref::<quinn_proto::crypto::rustls::HandshakeData>()?;
        hd.server_name.clone()
    }
}

