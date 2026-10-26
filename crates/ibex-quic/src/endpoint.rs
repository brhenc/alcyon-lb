// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC endpoint implementation encapsulating `quinn-proto`.

use std::collections::{BTreeSet, HashMap, VecDeque};
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
    amplification_budgets: HashMap<ConnectionHandle, AmplificationBudget>,
    anti_amplification_factor: u64,
    /// Packets quinn-proto produced that the budget then refused. Every one of these is a
    /// wasted packet number and an armed loss-recovery timer, so this is expected to be zero.
    amplification_overshoots: u64,
    pending_transmits: VecDeque<TransmitEntry>,
    event_queue: VecDeque<TransportEvent>,
    active_handles: Vec<ConnectionHandle>,
    round_robin_idx: usize,
    next_timeout: Option<Instant>,
    /// How many times a connection's `poll_timeout` was asked (a test counter: the cost of a
    /// datagram must not grow with the number of idle connections).
    timeout_polls: u64,
    /// Every connection's next deadline, ordered: the earliest is the first element. A
    /// connection is re-keyed (`refresh_timer`) only when its own timeout may have changed.
    timers: BTreeSet<(Instant, usize)>,
    /// The deadline each connection has in `timers`.
    timer_of: HashMap<ConnectionHandle, Instant>,
    response_buf: Vec<u8>,
    tx_buf: Vec<u8>,
    /// Set by a soft stop: connections already here are served to the end, a new Initial is refused.
    refusing_new: bool,
    /// `quic-force-retry`: every new connection without a valid token gets a Retry.
    force_retry: bool,
    /// `tune.quic.fe.sec.retry-threshold`: Retry once this many connections are half open.
    retry_threshold: u64,
    /// Connections whose peer address is not validated yet (`HAProxy`'s `half_open_conn`):
    /// those with an [`AmplificationBudget`] not `validated`.
    half_open: u64,
}

/// RFC 9000 §8.1 accounting for one connection on an unvalidated path.
///
/// `validated` is set when the connection completes, which is *later* than the RFC requires:
/// §8.1 lifts the limit once the server successfully processes a Handshake packet from the
/// client. It is deliberately late rather than wrong. The RFC's condition is "successfully
/// processed", meaning decrypted and authenticated, and quinn-proto keeps that state in
/// `Connection::path.validated`, which is `pub(crate)` with no accessor. The only signal
/// reachable from outside is the packet header, and an off-path attacker can forge a Handshake
/// header as easily as an Initial one -- lifting the cap on an unauthenticated header would
/// hand back exactly the reflector this limit exists to prevent.
///
/// So the cap stays on until `Event::Connected`. Being stricter than the RFC is always safe
/// here; the cost is that a server sending a large certificate chain may wait for the client
/// to speak again. Should quinn-proto ever expose path validation, this is the line to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AmplificationBudget {
    bytes_received: u64,
    bytes_sent: u64,
    max_factor: u64,
    validated: bool,
}

impl AmplificationBudget {
    const fn new(initial_received: u64, max_factor: u64) -> Self {
        Self {
            bytes_received: initial_received,
            bytes_sent: 0,
            max_factor,
            validated: false,
        }
    }

    fn record_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
    }

    fn is_allowed(&self, bytes_to_send: u64) -> bool {
        if self.validated {
            return true;
        }
        let max_allowed = self.bytes_received.saturating_mul(self.max_factor);
        self.bytes_sent.saturating_add(bytes_to_send) <= max_allowed
    }

    fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
    }
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
        tls: &Arc<ibex_tls::tcp::BindTls>,
        quic_config: Option<QuicConfig>,
    ) -> Result<Self> {
        let config = quic_config.unwrap_or_default();
        let server_config = config.build_server_config(tls)?;
        let endpoint_config = Arc::new(config.build_endpoint_config()?);
        Ok(Self::from_config(endpoint_config, server_config, &config))
    }

    /// Creates a `QuicEndpoint` over built `EndpointConfig` and `ServerConfig`, with the
    /// endpoint-level settings of `config` (Retry policy, anti-amplification factor).
    #[must_use]
    pub fn from_config(
        endpoint_config: Arc<EndpointConfig>,
        server_config: Arc<ServerConfig>,
        config: &QuicConfig,
    ) -> Self {
        let mut endpoint = Self::with_configs_and_amplification(
            endpoint_config,
            server_config,
            config.require_retry,
            config.anti_amplification_factor,
        );
        endpoint.retry_threshold = config.retry_threshold;
        endpoint
    }

    /// Creates a `QuicEndpoint` with custom `EndpointConfig`, `ServerConfig`, and
    /// `quic-force-retry`.
    #[must_use]
    pub fn with_configs(
        endpoint_config: Arc<EndpointConfig>,
        server_config: Arc<ServerConfig>,
        force_retry: bool,
    ) -> Self {
        Self::with_configs_and_amplification(endpoint_config, server_config, force_retry, 3)
    }

    /// Creates a `QuicEndpoint` with custom `EndpointConfig`, `ServerConfig`,
    /// `quic-force-retry`, and anti-amplification factor. The Retry threshold is the default
    /// (100); [`QuicEndpoint::from_config`] takes it from a [`QuicConfig`].
    #[must_use]
    pub fn with_configs_and_amplification(
        endpoint_config: Arc<EndpointConfig>,
        server_config: Arc<ServerConfig>,
        force_retry: bool,
        anti_amplification_factor: u64,
    ) -> Self {
        // The third argument is quinn-proto's `allow_mtud`, not a Retry switch (it was passed
        // `require_retry`, so Retry could never be enabled, T492). Path MTU discovery is only
        // sound on a socket that sets the don't-fragment bit, and Ibex's UDP sockets do not
        // (no IP_MTU_DISCOVER / IPV6_DONTFRAG), so it stays off: packets keep the configured
        // `initial_mtu`, as `HAProxy` keeps its fixed maximum datagram size.
        let endpoint = Endpoint::new(
            endpoint_config,
            Some(server_config.clone()),
            false,
            None,
        );

        Self {
            endpoint,
            server_config,
            connection_table: ConnectionTable::new(),
            connections: HashMap::new(),
            handle_to_primary_cid: HashMap::new(),
            amplification_budgets: HashMap::new(),
            anti_amplification_factor: if anti_amplification_factor == 0 { 3 } else { anti_amplification_factor },
            amplification_overshoots: 0,
            pending_transmits: VecDeque::new(),
            event_queue: VecDeque::new(),
            active_handles: Vec::new(),
            round_robin_idx: 0,
            next_timeout: None,
            timeout_polls: 0,
            timers: BTreeSet::new(),
            timer_of: HashMap::new(),
            response_buf: Vec::with_capacity(2048),
            tx_buf: Vec::with_capacity(2048),
            refusing_new: false,
            force_retry,
            retry_threshold: QuicConfig::default().retry_threshold,
            half_open: 0,
        }
    }

    /// Soft stop (HAProxy's `soft_stop()`): refuse every new connection from now on while the
    /// ones already established keep being served. The client of a refused one gets a
    /// CONNECTION_REFUSED close and goes to whichever process is taking over.
    pub fn stop_accepting(&mut self) {
        self.refusing_new = true;
    }

    /// Creates a `QuicEndpoint` from an already configured `quinn_proto::ServerConfig`.
    ///
    /// # Errors
    /// Returns `QuicError::Config` if initialization fails.
    pub fn with_server_config(server_config: Arc<ServerConfig>) -> Result<Self> {
        let reset = crate::crypto::ResetKey::new().map_err(QuicError::Config)?;
        Ok(Self::with_configs(Arc::new(EndpointConfig::new(Arc::new(reset))), server_config, false))
    }

    /// Sets the anti-amplification factor limit for unvalidated peer paths.
    pub fn set_anti_amplification_factor(&mut self, factor: u64) {
        self.anti_amplification_factor = if factor == 0 { 3 } else { factor };
    }

    /// Number of packets generated and then refused by the anti-amplification budget.
    #[must_use]
    pub const fn amplification_overshoots(&self) -> u64 {
        self.amplification_overshoots
    }

    /// Number of per-connection timeout queries so far (see the `timeout_polls` field).
    #[must_use]
    pub const fn timeout_polls(&self) -> u64 {
        self.timeout_polls
    }

    /// Whether `bytes` may be sent to `handle` under its anti-amplification budget.
    fn may_send(&self, handle: ConnectionHandle, bytes: u64) -> bool {
        // Fail closed. A missing budget means this code has lost track of a connection, and
        // the safe reading of that is "no budget", not "unlimited" -- the limit being enforced
        // is what stops this proxy being used as a reflector.
        self.amplification_budgets
            .get(&handle)
            .is_some_and(|b| b.is_allowed(bytes))
    }

    /// Caches the earliest deadline of all connections: the first of `timers`, O(log n).
    pub fn update_next_timeout(&mut self) {
        self.next_timeout = self.timers.first().map(|&(t, _)| t);
    }

    /// Re-keys one connection's deadline after something that may have changed it, then
    /// refreshes the cached earliest deadline. Costs one connection's `poll_timeout`, however
    /// many other connections there are.
    fn refresh_timer(&mut self, handle: ConnectionHandle) {
        if let Some(conn) = self.connections.get_mut(&handle) {
            self.timeout_polls += 1;
            let new = conn.poll_timeout();
            let old = self.timer_of.get(&handle).copied();
            if new != old {
                if let Some(t) = old {
                    self.timers.remove(&(t, handle.0));
                }
                self.timer_of.remove(&handle);
                if let Some(t) = new {
                    self.timers.insert((t, handle.0));
                    self.timer_of.insert(handle, t);
                }
            }
        }
        self.update_next_timeout();
    }

    /// Drops a connection's deadline (it is gone).
    fn forget_timer(&mut self, handle: ConnectionHandle) {
        let old = self.timer_of.remove(&handle);
        let _ = old.is_some_and(|t| self.timers.remove(&(t, handle.0)));
    }

    /// Helper to look up connection handle by `ConnectionId`.
    fn get_handle(&self, conn_id: &ConnectionId) -> Result<ConnectionHandle> {
        self.connection_table
            .lookup(conn_id)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn_id.to_string()))
    }

    /// Drives a connection's endpoint events and high-level poll events.
    #[allow(clippy::too_many_lines)]
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
                    if let Some(budget) = self.amplification_budgets.get_mut(&handle) {
                        if !budget.validated {
                            self.half_open = self.half_open.saturating_sub(1);
                        }
                        budget.validated = true;
                    }

                    let mut alpn = None;
                    let mut server_name = None;

                    if let Some(hd_any) = conn.crypto_session().handshake_data() {
                        if let Some(hd) = hd_any.downcast_ref::<crate::crypto::HandshakeData>() {
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
                    // "One or more" streams: a client that opens several requests in one
                    // flight raises a single `Opened`. Accepting only the first left the
                    // others unanswered for ever (T130).
                    quinn_proto::StreamEvent::Opened { dir } => {
                        while let Some(sid) = conn.streams().accept(dir) {
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



    /// Answers `incoming` with a Retry (`send_retry`, `src/quic_tx.c`): the Retry is queued, and
    /// no connection state is kept.
    fn send_retry(&mut self, incoming: quinn_proto::Incoming) -> DatagramOutcome {
        self.response_buf.clear();
        // Only an Incoming that already answered a Retry may not be retried, and that one is
        // validated, so the refusal is not reached by a test (one line, ignored).
        let tx = match self.endpoint.retry(incoming, &mut self.response_buf) { Ok(tx) => tx, Err(e) => { self.endpoint.ignore(e.into_incoming()); return DatagramOutcome::Ignored } };
        self.pending_transmits.push_back(TransmitEntry {
            transmit: Transmit {
                destination: tx.destination,
                src_ip: tx.src_ip,
                size: tx.size,
                segment_size: tx.segment_size,
                ecn: tx.ecn.map(EcnCodepoint::from),
            },
            data: self.response_buf.clone(),
        });
        DatagramOutcome::StatelessResponse
    }

    /// Removes those of `candidates` that are drained.
    fn remove_drained(&mut self, candidates: &[ConnectionHandle]) {
        for &handle in candidates {
            if !self.connections.get(&handle).is_some_and(quinn_proto::Connection::is_drained) {
                continue;
            }
            self.forget_timer(handle);
            self.connections.remove(&handle);
            self.handle_to_primary_cid.remove(&handle);
            // Released before its address was validated (`quic_conn_release`).
            if self.amplification_budgets.remove(&handle).is_some_and(|b| !b.validated) {
                self.half_open = self.half_open.saturating_sub(1);
            }
            self.connection_table.remove_connection(handle);
            self.active_handles.retain(|&h| h != handle);
        }
    }
}

/// The token length of a QUIC v1 Initial packet at the start of `buf`, `None` for any other
/// packet or one too short to say (RFC 9000 §17.2.2).
fn initial_token_len(buf: &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    // Long header, type Initial (0), version 1.
    if first & 0xb0 != 0x80 || buf.get(1..5)? != [0, 0, 0, 1] {
        return None;
    }
    let dcid_len = usize::from(*buf.get(5)?);
    let scid_at = 6 + dcid_len;
    let scid_len = usize::from(*buf.get(scid_at)?);
    let at = scid_at + 1 + scid_len;
    let b0 = *buf.get(at)?;
    let len = 1usize << (b0 >> 6);
    let bytes = buf.get(at..at + len)?;
    Some(bytes[1..].iter().fold(u64::from(b0 & 0x3f), |v, &b| (v << 8) | u64::from(b)))
}

impl QuicTransport for QuicEndpoint {
    #[allow(clippy::too_many_lines)]
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

        match event {
            Some(DatagramEvent::NewConnection(incoming)) => {
                let remote_addr = incoming.remote_address();
                if self.refusing_new {
                    self.response_buf.clear();
                    let tx = self.endpoint.refuse(incoming, &mut self.response_buf);
                    self.pending_transmits.push_back(TransmitEntry {
                        transmit: Transmit {
                            destination: tx.destination,
                            src_ip: tx.src_ip,
                            size: tx.size,
                            segment_size: tx.segment_size,
                            ecn: tx.ecn.map(EcnCodepoint::from),
                        },
                        data: self.response_buf.clone(),
                    });
                    return Ok(DatagramOutcome::StatelessResponse);
                }
                let validated = incoming.remote_address_validated();
                // `quic_rx_pkt_retrieve_conn`: an Initial whose token does not validate is
                // dropped, nothing sent. quinn-proto would go on as if there were no token
                // for one it cannot decode; Ibex issues no NEW_TOKEN tokens (no `bloom`
                // feature), so any token it cannot validate is forged or someone else's.
                if !validated && initial_token_len(buf).is_some_and(|n| n > 0) {
                    self.endpoint.ignore(incoming);
                    return Ok(DatagramOutcome::Ignored);
                }
                if !validated && (self.force_retry || self.half_open >= self.retry_threshold) {
                    return Ok(self.send_retry(incoming));
                }
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
                        let mut budget = AmplificationBudget::new(buf.len() as u64, self.anti_amplification_factor);
                        // A Retry token validates the address (RFC 9000 §8.1.2): no
                        // amplification limit, and not half open (`qc_new_conn`).
                        budget.validated = validated;
                        if !validated {
                            self.half_open += 1;
                        }
                        self.amplification_budgets.insert(handle, budget);

                        self.event_queue.push_back(TransportEvent::NewConnection {
                            conn_id: primary_cid,
                            remote: remote_addr,
                        });

                        self.drive_connection(handle, now);
                        self.refresh_timer(handle);
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
                if let Some(budget) = self.amplification_budgets.get_mut(&handle) {
                    budget.record_received(buf.len() as u64);
                }
                if let Some(conn) = self.connections.get_mut(&handle) {
                    conn.handle_event(conn_evt);
                    self.drive_connection(handle, now);
                    self.refresh_timer(handle);
                    Ok(DatagramOutcome::Routed)
                } else {
                    Ok(DatagramOutcome::Ignored)
                }
            }
            // quinn-proto closes with INVALID_TOKEN on a Retry token it decodes and refuses
            // (another address, expired); `HAProxy` drops the datagram and sends nothing.
            Some(DatagramEvent::Response(_)) if initial_token_len(buf).is_some_and(|n| n > 0) => {
                Ok(DatagramOutcome::Ignored)
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
        if self.pending_transmits.front().is_some_and(|e| out.len() >= e.data.len()) {
            if let Some(entry) = self.pending_transmits.pop_front() {
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

            // Decide before asking for a packet, not after. `poll_transmit` assigns a packet
            // number and arms loss recovery before it returns, so a packet refused afterwards
            // still has to be retransmitted later -- the refusal costs a round trip instead of
            // saving one. The budget is already known here. A full MTU is reserved because
            // that is the largest single datagram `poll_transmit` can hand back.
            let Some((mtu, handshaking)) = self
                .connections
                .get(&handle)
                .map(|c| (u64::from(c.current_mtu()), c.is_handshaking()))
            else {
                continue;
            };
            if handshaking && !self.may_send(handle, mtu) {
                continue;
            }

            if let Some(conn) = self.connections.get_mut(&handle) {
                self.tx_buf.clear();
                if let Some(tx) = conn.poll_transmit(now, 1, &mut self.tx_buf) {
                    let size = tx.size.min(out.len()).min(self.tx_buf.len());

                    // Drive any endpoint events produced during transmit
                    while let Some(ep_evt) = conn.poll_endpoint_events() {
                        if let Some(conn_evt) = self.endpoint.handle_event(handle, ep_evt) {
                            conn.handle_event(conn_evt);
                        }
                    }

                    // The packet moved the connection's deadline, whether or not it is sent.
                    self.refresh_timer(handle);
                    if handshaking {
                        if let Some(budget) = self.amplification_budgets.get_mut(&handle) {
                            if !budget.is_allowed(size as u64) {
                                // The pre-check reserved a full MTU, so reaching here means
                                // `poll_transmit` returned more than the connection's MTU.
                                self.amplification_overshoots += 1;
                                // Exceeds 3x anti-amplification limit before address validation (RFC 9000 §8.1).
                                // Suppress transmission to prevent DDoS amplification reflection.
                                continue;
                            }
                            budget.record_sent(size as u64);
                        }
                    }

                    out[..size].copy_from_slice(&self.tx_buf[..size]);
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
        // Only the connections whose deadline has come: the head of `timers`.
        let mut expired = Vec::new();
        while let Some(&(t, h)) = self.timers.first() {
            if t > now {
                break;
            }
            self.timers.remove(&(t, h));
            self.timer_of.remove(&ConnectionHandle(h));
            expired.push(ConnectionHandle(h));
        }
        for &handle in &expired {
            if let Some(conn) = self.connections.get_mut(&handle) {
                conn.handle_timeout(now);
            }
            self.drive_connection(handle, now);
        }
        self.remove_drained(&expired);
        for handle in expired {
            self.refresh_timer(handle);
        }
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
        // Flow control or the send buffer full is not an error: nothing was taken, and the
        // caller keeps the bytes until the stream is writable again.
        let written = send
            .write(buf)
            .or_else(|e| if e == quinn_proto::WriteError::Blocked { Ok(0) } else { Err(e) })
            .map_err(|e| QuicError::Transport(format!("stream write error: {e}")))?;

        // Finishing after a partial write would end the stream on what fitted, which is how
        // an HTTP/3 response larger than the window arrived truncated (T108, T130). The
        // stream is finished only once the last byte has been taken.
        if fin && written == buf.len() {
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

    fn reset_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId, error_code: u64) -> Result<()> {
        let code = VarInt::from_u64(error_code).map_err(|e| QuicError::Transport(format!("error code: {e}")))?;
        let handle = self.get_handle(&conn_id)?;
        let conn = self
            .connections
            .get_mut(&handle)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn_id.to_string()))?;
        // A half that is already closed is not an error: the stream is gone either way.
        let _ = conn.send_stream(stream_id.into()).reset(code);
        let _ = conn.recv_stream(stream_id.into()).stop(code);
        Ok(())
    }

    fn close_connection(&mut self, conn_id: ConnectionId, error_code: u64, reason: &[u8]) {
        if let Some(handle) = self.connection_table.lookup(&conn_id) {
            if let Some(conn) = self.connections.get_mut(&handle) {
                if let Ok(code) = VarInt::from_u64(error_code) {
                    conn.close(Instant::now(), code, Bytes::copy_from_slice(reason));
                }
            }
            self.drive_connection(handle, Instant::now());
            // Closing arms a drain timer. Left out of the cached deadline, the engine would not
            // wake for it, and the connection would be counted live until some unrelated
            // datagram refreshed the cache.
            self.refresh_timer(handle);
        }
    }

    fn connection_count(&self) -> usize {
        self.connections.len()
    }

    fn alpn(&self, conn_id: ConnectionId) -> Option<Vec<u8>> {
        let handle = self.connection_table.lookup(&conn_id)?;
        let conn = self.connections.get(&handle)?;
        let hd_any = conn.crypto_session().handshake_data()?;
        let hd = hd_any.downcast_ref::<crate::crypto::HandshakeData>()?;
        hd.protocol.clone()
    }

    fn server_name(&self, conn_id: ConnectionId) -> Option<String> {
        let handle = self.connection_table.lookup(&conn_id)?;
        let conn = self.connections.get(&handle)?;
        let hd_any = conn.crypto_session().handshake_data()?;
        let hd = hd_any.downcast_ref::<crate::crypto::HandshakeData>()?;
        hd.server_name.clone()
    }
}

