// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC endpoint implementation encapsulating `quinn-proto`.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, ServerConfig, VarInt};


use crate::config::QuicConfig;
use crate::connection::{ConnHandle, ConnectionId, ReadStreamResult, StreamDirection, StreamId};
use crate::error::{QuicError, Result};
use crate::transport::{DatagramOutcome, EcnCodepoint, QuicTransport, TransportEvent, Transmit};

/// The receive block's size ([`CopyBlock`]): the listener's datagram buffer.
const RX_BLOCK: usize = 2048;
/// The STREAM write block's size ([`CopyBlock`]): a standard buffer.
const TX_BLOCK: usize = 16384;

/// A block that what quinn-proto takes as an owned `BytesMut`/`Bytes` (a received datagram,
/// STREAM data written) is copied into and cut from (T512). A new buffer for each was one or
/// two allocations (the bytes, then the shared header once quinn splits it); pieces cut from
/// one block share its header, and the block's space is used again once quinn has dropped
/// every piece (`try_reclaim`, which allocates nothing). While quinn still holds a piece past
/// the free space (stream data not read yet, data not acked, an `Incoming` not accepted),
/// [`CopyBlock::copy`] says no and the caller allocates as before (a new block for a datagram,
/// so a datagram quinn holds pins one block, as its own buffer did; quinn's own copy for a
/// STREAM write). Under `tune.ibex.zero-buffers`, what
/// the pieces left is wiped when the block starts over (quinn decrypts datagrams in place, so
/// it is plaintext either way).
struct CopyBlock {
    buf: BytesMut,
    /// Bytes written since the block last started over.
    fill: usize,
    size: usize,
}

impl CopyBlock {
    fn new(size: usize) -> Self {
        Self { buf: BytesMut::with_capacity(size), fill: 0, size }
    }

    /// `data` copied into the block, or `None`: empty or larger than a block, or the block's free space
    /// too small and a piece of it still held. `wipe`: `tune.ibex.zero-buffers`.
    fn copy(&mut self, data: &[u8], wipe: bool) -> Option<BytesMut> {
        let n = data.len();
        if n == 0 || n > self.size {
            return None;
        }
        if self.buf.capacity() < n {
            if !self.buf.try_reclaim(n) {
                return None;
            }
            // Back at the block's start: what the earlier pieces left is stale.
            if wipe {
                self.buf.resize(self.fill, 0);
                ibex_alloc::wipe_bytes(&mut self.buf);
                self.buf.clear();
            }
            self.fill = 0;
        }
        self.buf.extend_from_slice(data);
        self.fill += n;
        Some(self.buf.split())
    }

    /// A new block (the old one is freed when quinn drops its last piece).
    fn renew(&mut self) -> &mut Self {
        self.buf = BytesMut::with_capacity(self.size);
        self.fill = 0;
        self
    }
}

/// One connection's slot (Q1): indexed by quinn-proto's `ConnectionHandle`, which quinn
/// hands out dense from 0 and reuses once a connection is gone; `gen` moves on at each reuse,
/// so a [`ConnHandle`] of the connection before finds nothing.
#[derive(Default)]
struct Slot {
    gen: u32,
    live: Option<Live>,
}

/// A live connection and what the endpoint keeps of it.
struct Live {
    conn: quinn_proto::Connection,
    /// Its key in `show quic`: the destination CID of its first Initial.
    cid: ConnectionId,
    budget: AmplificationBudget,
    /// In `to_poll`.
    queued: bool,
    /// In `timer_stale`: its deadline is asked again at the next `poll_timeout`.
    timer_stale: bool,
    /// `ConnectionClosed` was queued for it. quinn raises `ConnectionLost` for an end the
    /// peer or the network caused, not for a `close()` of ours (T561).
    reported: bool,
}

/// A QUIC server endpoint: quinn-proto's endpoint, its connections by handle, packet dispatch.
pub struct QuicEndpoint {
    endpoint: Endpoint,
    server_config: Arc<ServerConfig>,
    /// The connections, by quinn's handle (Q1): no lookup by connection ID after routing.
    slots: Vec<Slot>,
    anti_amplification_factor: u64,
    /// Packets quinn-proto produced that the budget then refused. Every one of these is a
    /// wasted packet number and an armed loss-recovery timer, so this is expected to be zero.
    amplification_overshoots: u64,
    pending_transmits: VecDeque<TransmitEntry>,
    event_queue: VecDeque<TransportEvent>,
    /// The live connections' slot indices.
    active_handles: Vec<u32>,
    /// The earliest of `deadlines`, valid unless `rescan` is set.
    next_timeout: Option<Instant>,
    /// Each slot's deadline as quinn last told it, by slot index (apart from the slots, so the
    /// rare scan for the earliest touches one small array).
    deadlines: Vec<Option<Instant>>,
    /// Connections whose deadline may have changed since `poll_timeout` last asked them: a
    /// datagram, a packet sent, a stream call, a timer. Each is asked once (Q1); the
    /// per-event re-key it replaces asked ~3 times a request.
    timer_stale: Vec<u32>,
    /// The connection that held `next_timeout` moved later or went: the earliest is found
    /// again by a scan of `deadlines` at the next `poll_timeout`.
    rescan: bool,
    /// `handle_timeout`'s list of expired connections, kept between calls.
    expired: Vec<u32>,
    /// How many times a connection's `poll_timeout` was asked (a test counter: the cost of a
    /// datagram must not grow with the number of idle connections).
    timeout_polls: u64,
    /// How many times a connection was asked for a packet (a test counter, T543).
    transmit_polls: u64,
    /// How many times a connection was found by a connection ID (a test counter, Q1): once
    /// per datagram, by quinn's routing, and never after.
    cid_lookups: u64,
    /// The connections that may have a packet to send: something reached them (a datagram, a
    /// timer, a stream call, a close) since they last had none (T543). quinn-proto changes
    /// only through such calls, so a connection outside this queue has nothing to send, and
    /// `poll_transmit` does not ask it: its empty `poll_transmit` re-checks every space, path
    /// and queue, and the h3 listener drains transmits ~8 times a request.
    /// An entry whose generation is not its slot's any more is skipped.
    to_poll: VecDeque<ConnHandle>,
    response_buf: Vec<u8>,
    tx_buf: Vec<u8>,
    /// What each received datagram is copied into for quinn-proto, which takes it by value.
    rx: CopyBlock,
    /// What each STREAM write is copied into for quinn-proto, which keeps it until acked.
    tx: CopyBlock,
    /// Set by a soft stop: connections already here are served to the end, a new Initial is refused.
    refusing_new: bool,
    /// `quic-force-retry`: every new connection without a valid token gets a Retry.
    force_retry: bool,
    /// `tune.quic.fe.sec.retry-threshold`: Retry once this many connections are half open.
    retry_threshold: u64,
    /// Connections whose peer address is not validated yet (`HAProxy`'s `half_open_conn`),
    /// of every endpoint sharing the counter ([`QuicEndpoint::share_half_open`]): `HAProxy`
    /// keeps one per frontend and thread group, not per thread (T523).
    half_open: Arc<AtomicU64>,
    /// This endpoint's own part of `half_open`: those of its connections with an
    /// [`AmplificationBudget`] not `validated`. Given back when the endpoint is dropped.
    own_half_open: u64,
}

impl Drop for QuicEndpoint {
    fn drop(&mut self) {
        self.half_open.fetch_sub(self.own_half_open, Ordering::Relaxed);
    }
}

/// Where a connection is in its life, as `show quic` tells it (`HDSHK`, `ESTAB`, `CLOSE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnPhase {
    Handshake,
    Established,
    /// Closing or draining; quinn-proto does not tell the two apart.
    Closing,
}

/// One connection as [`QuicEndpoint::connection_infos`] reports it.
#[derive(Debug, Clone, Copy)]
pub struct ConnInfo {
    /// The connection's key in the endpoint: the destination CID of its first Initial.
    pub id: ConnectionId,
    pub remote: std::net::SocketAddr,
    /// The local address the client reached, when the kernel told.
    pub local_ip: Option<std::net::IpAddr>,
    pub state: ConnPhase,
    pub lost_packets: u64,
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
            slots: Vec::new(),
            anti_amplification_factor: if anti_amplification_factor == 0 { 3 } else { anti_amplification_factor },
            amplification_overshoots: 0,
            pending_transmits: VecDeque::new(),
            event_queue: VecDeque::new(),
            active_handles: Vec::new(),
            next_timeout: None,
            deadlines: Vec::new(),
            timer_stale: Vec::new(),
            rescan: false,
            expired: Vec::new(),
            timeout_polls: 0,
            transmit_polls: 0,
            cid_lookups: 0,
            to_poll: VecDeque::new(),
            response_buf: Vec::with_capacity(2048),
            rx: CopyBlock::new(RX_BLOCK),
            tx: CopyBlock::new(TX_BLOCK),
            tx_buf: Vec::with_capacity(2048),
            refusing_new: false,
            force_retry,
            retry_threshold: QuicConfig::default().retry_threshold,
            half_open: Arc::new(AtomicU64::new(0)),
            own_half_open: 0,
        }
    }

    /// Counts this endpoint's half-open connections in `shared`, with those of every other
    /// endpoint given the same counter, against the Retry threshold: the workers of one
    /// frontend's QUIC bind share one, as `HAProxy`'s threads share the frontend's
    /// `half_open_conn` (T523).
    pub fn share_half_open(&mut self, shared: Arc<AtomicU64>) {
        shared.fetch_add(self.own_half_open, Ordering::Relaxed);
        self.half_open.fetch_sub(self.own_half_open, Ordering::Relaxed);
        self.half_open = shared;
    }

    /// Soft stop (HAProxy's `soft_stop()`): refuse every new connection from now on while the
    /// ones already established keep being served. The client of a refused one gets a
    /// CONNECTION_REFUSED close and goes to whichever process is taking over.
    pub fn stop_accepting(&mut self) {
        self.refusing_new = true;
    }

    /// What `show quic` lists of each connection (T524): read-only, one entry per live
    /// connection, in no particular order.
    #[must_use]
    pub fn connection_infos(&self) -> Vec<ConnInfo> {
        self.slots
            .iter()
            .filter_map(|slot| {
                let live = slot.live.as_ref()?;
                let (c, id) = (&live.conn, live.cid);
                let state = if c.is_closed() {
                    ConnPhase::Closing
                } else if c.is_handshaking() {
                    ConnPhase::Handshake
                } else {
                    ConnPhase::Established
                };
                Some(ConnInfo {
                    id,
                    remote: c.remote_address(),
                    local_ip: c.local_ip(),
                    state,
                    lost_packets: c.stats().path.lost_packets,
                })
            })
            .collect()
    }

    /// Asks the peer to stop sending on a stream (`STOP_SENDING`, `HAProxy`'s
    /// `qcc_abort_stream_read`), the sending half left as it is. A stream or connection that
    /// is gone, or a code that is no varint, is nothing to do.
    pub fn stop_sending(&mut self, conn: ConnHandle, stream_id: StreamId, error_code: u64) {
        let Ok(code) = VarInt::from_u64(error_code) else { return };
        if let Some(live) = self.touch(conn) {
            let _ = live.conn.recv_stream(stream_id.into()).stop(code);
        }
    }

    /// The local address connection `conn`'s client reached, when the kernel told (a pinned
    /// socket on a wildcard bind is bound to it, T558).
    #[must_use]
    pub fn local_ip_of(&self, conn: ConnHandle) -> Option<std::net::IpAddr> {
        self.live(conn)?.conn.local_ip()
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

    /// The deadline quinn gave connection `conn` when last asked (after asking the ones
    /// something reached since), for tests to check `poll_timeout` against.
    #[doc(hidden)]
    pub fn deadline_of(&mut self, conn: ConnHandle) -> Option<Instant> {
        self.update_next_timeout();
        self.live(conn)?;
        self.deadlines.get(conn.index()).copied().flatten()
    }

    /// Number of connection lookups by connection ID (see the `cid_lookups` field).
    #[must_use]
    pub const fn cid_lookups(&self) -> u64 {
        self.cid_lookups
    }

    /// The live connection `conn` names, if its slot is still at that generation.
    fn live(&self, conn: ConnHandle) -> Option<&Live> {
        self.slots.get(conn.index()).filter(|s| s.gen == conn.generation())?.live.as_ref()
    }

    /// Something reaches connection `conn`: it is asked for packets (`to_poll`) and for its
    /// deadline (`timer_stale`) again. The connection, if it is live.
    fn touch(&mut self, conn: ConnHandle) -> Option<&mut Live> {
        Self::touch_in(&mut self.slots, &mut self.to_poll, &mut self.timer_stale, conn)
    }

    /// [`QuicEndpoint::touch`] on the fields it needs, so the caller keeps the others.
    fn touch_in<'a>(slots: &'a mut [Slot], to_poll: &mut VecDeque<ConnHandle>, timer_stale: &mut Vec<u32>, conn: ConnHandle) -> Option<&'a mut Live> {
        let slot = slots.get_mut(conn.index()).filter(|s| s.gen == conn.generation())?;
        let live = slot.live.as_mut()?;
        Self::mark_live(to_poll, timer_stale, conn, live);
        Some(live)
    }

    /// [`QuicEndpoint::touch`] on a connection already in hand.
    fn mark_live(to_poll: &mut VecDeque<ConnHandle>, timer_stale: &mut Vec<u32>, conn: ConnHandle, live: &mut Live) {
        if !live.queued {
            live.queued = true;
            to_poll.push_back(conn);
        }
        Self::stale_live(timer_stale, conn, live);
    }

    /// The connection's deadline may have moved: asked at the next `poll_timeout`.
    fn stale_live(timer_stale: &mut Vec<u32>, conn: ConnHandle, live: &mut Live) {
        if !live.timer_stale {
            live.timer_stale = true;
            #[allow(clippy::cast_possible_truncation)]
            timer_stale.push(conn.index() as u32);
        }
    }

    /// The handle of the connection in slot `idx` now.
    #[allow(clippy::cast_possible_truncation)]
    fn handle_at(&self, idx: usize) -> ConnHandle {
        ConnHandle::new(idx as u32, self.slots.get(idx).map_or(0, |s| s.gen))
    }

    /// Number of times a connection was asked for a packet (see the `transmit_polls` field).
    pub const fn transmit_polls(&self) -> u64 {
        self.transmit_polls
    }

    /// Asks each connection something reached since the last call for its deadline, once,
    /// and keeps the earliest of all of them (Q1). Costs one `poll_timeout` of quinn per such
    /// connection; a scan of the deadlines (no connection asked) only when the connection
    /// with the earliest one moved it later or went. A connection quinn has drained is
    /// forgotten here: whatever drained it (a datagram, a timer, a packet sent) touched it.
    pub fn update_next_timeout(&mut self) {
        let mut stale = std::mem::take(&mut self.timer_stale);
        for &idx in &stale {
            let i = idx as usize;
            let Some(live) = self.slots.get_mut(i).and_then(|s| s.live.as_mut()) else { continue };
            live.timer_stale = false;
            if live.conn.is_drained() {
                self.remove_slot(i);
                continue;
            }
            self.timeout_polls += 1;
            let new = live.conn.poll_timeout();
            let Some(slot) = self.deadlines.get_mut(i) else { continue };
            let old = std::mem::replace(slot, new);
            if old == new {
                continue;
            }
            match (new, self.next_timeout) {
                (Some(n), Some(t)) if n < t => self.next_timeout = Some(n),
                (Some(n), None) if !self.rescan => self.next_timeout = Some(n),
                _ => {}
            }
            // It held the earliest and moved it later, or has none any more.
            self.rescan |= old.is_some() && old == self.next_timeout;
        }
        stale.clear();
        self.timer_stale = stale;
        if std::mem::take(&mut self.rescan) {
            let deadlines = &self.deadlines;
            self.next_timeout = self.active_handles.iter().filter_map(|&i| deadlines.get(i as usize).copied().flatten()).min();
        }
    }

    /// Hands what the connection has for quinn's endpoint (new CIDs, retired ones, drained) to
    /// it, and the endpoint's answers back.
    fn forward_endpoint_events(endpoint: &mut Endpoint, handle: ConnectionHandle, conn: &mut quinn_proto::Connection) {
        while let Some(ep_evt) = conn.poll_endpoint_events() {
            if let Some(conn_evt) = endpoint.handle_event(handle, ep_evt) {
                conn.handle_event(conn_evt);
            }
        }
    }

    /// Drives a connection's endpoint events and high-level poll events.
    #[allow(clippy::too_many_lines)]
    fn drive_connection(&mut self, idx: usize, _now: Instant) {
        let conn_ref = self.handle_at(idx);
        let handle = ConnectionHandle(idx);
        // Every caller has just accepted, routed to or touched this connection: it is live.
        let live = self.slots.get_mut(idx).and_then(|s| s.live.as_mut());
        debug_assert!(live.is_some(), "drive_connection on slot {idx} without a connection");
        let Some(live) = live else { return };
        Self::forward_endpoint_events(&mut self.endpoint, handle, &mut live.conn);

        // Drain connection events
        while let Some(evt) = live.conn.poll() {
            match evt {
                quinn_proto::Event::Connected => {
                    let budget = &mut live.budget;
                    if !budget.validated && self.own_half_open > 0 {
                        self.own_half_open -= 1;
                        self.half_open.fetch_sub(1, Ordering::Relaxed);
                    }
                    budget.validated = true;

                    let mut alpn = None;
                    let mut server_name = None;

                    if let Some(hd_any) = live.conn.crypto_session().handshake_data() {
                        if let Some(hd) = hd_any.downcast_ref::<crate::crypto::HandshakeData>() {
                            alpn.clone_from(&hd.protocol);
                            server_name.clone_from(&hd.server_name);
                        }
                    }

                    self.event_queue.push_back(TransportEvent::HandshakeComplete {
                        conn: conn_ref,
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

                    live.reported = true;
                    self.event_queue.push_back(TransportEvent::ConnectionClosed {
                        conn: conn_ref,
                        error_code,
                        reason: reason_bytes,
                    });
                }
                quinn_proto::Event::Stream(stream_evt) => match stream_evt {
                    // "One or more" streams: a client that opens several requests in one
                    // flight raises a single `Opened`. Accepting only the first left the
                    // others unanswered for ever (T130).
                    quinn_proto::StreamEvent::Opened { dir } => {
                        while let Some(sid) = live.conn.streams().accept(dir) {
                            self.event_queue.push_back(TransportEvent::StreamOpened {
                                conn: conn_ref,
                                stream_id: StreamId::from(sid),
                                dir: StreamDirection::from(dir),
                            });
                        }
                    }
                    quinn_proto::StreamEvent::Readable { id } => {
                        self.event_queue.push_back(TransportEvent::StreamReadable {
                            conn: conn_ref,
                            stream_id: StreamId::from(id),
                        });
                    }
                    quinn_proto::StreamEvent::Writable { id } => {
                        self.event_queue.push_back(TransportEvent::StreamWritable {
                            conn: conn_ref,
                            stream_id: StreamId::from(id),
                        });
                    }
                    quinn_proto::StreamEvent::Finished { id } => {
                        self.event_queue.push_back(TransportEvent::StreamFinished {
                            conn: conn_ref,
                            stream_id: StreamId::from(id),
                        });
                    }
                    quinn_proto::StreamEvent::Stopped { id, error_code } => {
                        self.event_queue.push_back(TransportEvent::StreamStopped {
                            conn: conn_ref,
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

    /// One of this endpoint's half-open connections was validated or released.
    fn half_open_done(&mut self) {
        if self.own_half_open > 0 {
            self.own_half_open -= 1;
            self.half_open.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Forgets the connection in slot `idx`: its deadline, its half-open count, its place in
    /// `active_handles`. Its `to_poll` entry, if any, is skipped by its generation later.
    fn remove_slot(&mut self, idx: usize) {
        let handle = self.handle_at(idx);
        let Some(live) = self.slots.get_mut(idx).and_then(|s| s.live.take()) else { return };
        // Drained after a close of ours: quinn said nothing, so the end is reported here, the
        // one place every connection leaves by (T561).
        if !live.reported {
            self.event_queue.push_back(TransportEvent::ConnectionClosed {
                conn: handle,
                error_code: 0,
                reason: b"clean close".to_vec(),
            });
        }
        // Released before its address was validated (`quic_conn_release`).
        if !live.budget.validated {
            self.half_open_done();
        }
        if let Some(d) = self.deadlines.get_mut(idx) {
            // It held the earliest: found again at the next `poll_timeout`.
            self.rescan |= d.take().is_some_and(|t| Some(t) == self.next_timeout);
        }
        #[allow(clippy::cast_possible_truncation)]
        self.active_handles.retain(|&h| h as usize != idx);
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
        // quinn routes the datagram by its destination CID: the one lookup by ID it costs.
        self.cid_lookups += 1;
        let wipe = ibex_alloc::zero_buffers();
        let data = self.rx.copy(buf, wipe).or_else(|| self.rx.renew().copy(buf, wipe)).unwrap_or_else(|| BytesMut::from(buf));

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
                if !validated && (self.force_retry || self.half_open.load(Ordering::Relaxed) >= self.retry_threshold) {
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
                        let idx = handle.0;
                        if self.slots.len() <= idx {
                            self.slots.resize_with(idx + 1, Slot::default);
                            self.deadlines.resize(idx + 1, None);
                        }
                        // quinn hands out an index again only once its connection is gone;
                        // one this endpoint did not see drained is forgotten now.
                        self.remove_slot(idx);
                        let mut budget = AmplificationBudget::new(buf.len() as u64, self.anti_amplification_factor);
                        // A Retry token validates the address (RFC 9000 §8.1.2): no
                        // amplification limit, and not half open (`qc_new_conn`).
                        budget.validated = validated;
                        if !validated {
                            self.own_half_open += 1;
                            self.half_open.fetch_add(1, Ordering::Relaxed);
                        }
                        let slot = &mut self.slots[idx];
                        slot.gen = slot.gen.wrapping_add(1);
                        slot.live = Some(Live { conn, cid: primary_cid, budget, queued: false, timer_stale: false, reported: false });
                        let c = self.handle_at(idx);
                        #[allow(clippy::cast_possible_truncation)]
                        self.active_handles.push(idx as u32);
                        let _ = self.touch(c);

                        self.event_queue.push_back(TransportEvent::NewConnection {
                            conn: c,
                            id: primary_cid,
                            remote: remote_addr,
                        });

                        self.drive_connection(idx, now);
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
                let c = self.handle_at(handle.0);
                if let Some(live) = self.touch(c) {
                    live.budget.record_received(buf.len() as u64);
                    live.conn.handle_event(conn_evt);
                    self.drive_connection(handle.0, now);
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

        // 2. Second priority: connection-level transmits, round-robin over the connections
        // that may have one (`to_poll`, T543). One that hands a packet goes to the back of
        // the queue; one that has none leaves it until something reaches it again.
        for _ in 0..self.to_poll.len() {
            let Some(c) = self.to_poll.pop_front() else { break };
            let idx = c.index();
            // A connection gone since it was queued, or a slot used again since: skipped.
            let Some(live) = self.slots.get_mut(idx).filter(|s| s.gen == c.generation()).and_then(|s| s.live.as_mut()) else {
                continue;
            };

            // Decide before asking for a packet, not after. `poll_transmit` assigns a packet
            // number and arms loss recovery before it returns, so a packet refused afterwards
            // still has to be retransmitted later -- the refusal costs a round trip instead of
            // saving one. The budget is already known here. A full MTU is reserved because
            // that is the largest single datagram `poll_transmit` can hand back.
            let (mtu, handshaking) = (u64::from(live.conn.current_mtu()), live.conn.is_handshaking());
            if handshaking && !live.budget.is_allowed(mtu) {
                // No budget until the client sends more, which marks it again.
                live.queued = false;
                continue;
            }

            self.tx_buf.clear();
            self.transmit_polls += 1;
            if let Some(tx) = live.conn.poll_transmit(now, 1, &mut self.tx_buf) {
                self.to_poll.push_back(c);
                let size = tx.size.min(out.len()).min(self.tx_buf.len());

                // Drive any endpoint events produced during transmit
                Self::forward_endpoint_events(&mut self.endpoint, ConnectionHandle(idx), &mut live.conn);

                // The packet moved the connection's deadline, whether or not it is sent.
                Self::stale_live(&mut self.timer_stale, c, live);
                if handshaking {
                    if !live.budget.is_allowed(size as u64) {
                        // The pre-check reserved a full MTU, so reaching here means
                        // `poll_transmit` returned more than the connection's MTU.
                        self.amplification_overshoots += 1;
                        // Exceeds 3x anti-amplification limit before address validation (RFC 9000 §8.1).
                        // Suppress transmission to prevent DDoS amplification reflection.
                        continue;
                    }
                    live.budget.record_sent(size as u64);
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
            // Nothing to send: off the queue. An empty poll can still arm a timer (pacing),
            // which wakes it through `handle_timeout`.
            live.queued = false;
            Self::stale_live(&mut self.timer_stale, c, live);
        }

        None
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.update_next_timeout();
        self.next_timeout
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.update_next_timeout();
        if !self.next_timeout.is_some_and(|t| t <= now) {
            return;
        }
        // Only the connections whose deadline has come.
        let mut expired = std::mem::take(&mut self.expired);
        expired.clear();
        let deadlines = &self.deadlines;
        expired.extend(self.active_handles.iter().copied().filter(|&i| deadlines.get(i as usize).copied().flatten().is_some_and(|t| t <= now)));
        // The earliest is among them: found again at the next `poll_timeout`.
        self.rescan = true;
        // Their deadlines stay until `poll_timeout` asks them again (`touch`), and one drained
        // is forgotten then.
        for &i in &expired {
            let idx = i as usize;
            let c = self.handle_at(idx);
            if let Some(live) = self.touch(c) {
                live.conn.handle_timeout(now);
            }
            self.drive_connection(idx, now);
        }
        self.expired = expired;
    }

    fn poll_event(&mut self) -> Option<TransportEvent> {
        self.event_queue.pop_front()
    }

    fn open_stream(&mut self, conn: ConnHandle, dir: StreamDirection) -> Result<StreamId> {
        let live = self.touch(conn).ok_or_else(|| QuicError::ConnectionNotFound(conn.to_string()))?;
        live.conn
            .streams()
            .open(dir.into())
            .map(StreamId::from)
            .ok_or(QuicError::StreamLimit)
    }

    fn read_stream(
        &mut self,
        conn: ConnHandle,
        stream_id: StreamId,
        buf: &mut [u8],
    ) -> Result<ReadStreamResult> {
        let live = self.touch(conn).ok_or_else(|| QuicError::ConnectionNotFound(conn.to_string()))?;

        let mut recv = live.conn.recv_stream(stream_id.into());
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
        conn: ConnHandle,
        stream_id: StreamId,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize> {
        let live = Self::touch_in(&mut self.slots, &mut self.to_poll, &mut self.timer_stale, conn)
            .ok_or_else(|| QuicError::ConnectionNotFound(conn.to_string()))?;

        let mut send = live.conn.send_stream(stream_id.into());
        // Flow control or the send buffer full is not an error: nothing was taken, and the
        // caller keeps the bytes until the stream is writable again. The bytes go in as a
        // piece of `tx` (T512), else as quinn's own copy (`write`) as before; what quinn does
        // not take of a piece is dropped with it.
        let wrote = match self.tx.copy(buf, ibex_alloc::zero_buffers()) {
            Some(piece) => send.write_chunks(&mut [piece.freeze()]).map(|w| w.bytes),
            None => send.write(buf),
        };
        let written = wrote
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

    fn finish_stream(&mut self, conn: ConnHandle, stream_id: StreamId) -> Result<()> {
        let live = self.touch(conn).ok_or_else(|| QuicError::ConnectionNotFound(conn.to_string()))?;
        live.conn
            .send_stream(stream_id.into())
            .finish()
            .map_err(|e| QuicError::Transport(format!("stream finish error: {e}")))?;

        Ok(())
    }

    fn reset_stream(&mut self, conn: ConnHandle, stream_id: StreamId, error_code: u64) -> Result<()> {
        let code = VarInt::from_u64(error_code).map_err(|e| QuicError::Transport(format!("error code: {e}")))?;
        let live = self.touch(conn).ok_or_else(|| QuicError::ConnectionNotFound(conn.to_string()))?;
        // A half that is already closed is not an error: the stream is gone either way.
        let _ = live.conn.send_stream(stream_id.into()).reset(code);
        let _ = live.conn.recv_stream(stream_id.into()).stop(code);
        Ok(())
    }

    fn close_connection(&mut self, conn: ConnHandle, error_code: u64, reason: &[u8]) {
        let now = Instant::now();
        // Closing arms a drain timer: `touch` has the next `poll_timeout` ask for it. Left
        // out of the cached deadline, the engine would not wake for it, and the connection
        // would be counted live until some unrelated datagram refreshed the cache.
        let Some(live) = self.touch(conn) else { return };
        if let Ok(code) = VarInt::from_u64(error_code) {
            live.conn.close(now, code, Bytes::copy_from_slice(reason));
        }
        self.drive_connection(conn.index(), now);
    }

    fn connection_count(&self) -> usize {
        self.active_handles.len()
    }

    fn alpn(&self, conn: ConnHandle) -> Option<Vec<u8>> {
        let hd_any = self.live(conn)?.conn.crypto_session().handshake_data()?;
        let hd = hd_any.downcast_ref::<crate::crypto::HandshakeData>()?;
        hd.protocol.clone()
    }

    fn server_name(&self, conn: ConnHandle) -> Option<String> {
        let hd_any = self.live(conn)?.conn.crypto_session().handshake_data()?;
        let hd = hd_any.downcast_ref::<crate::crypto::HandshakeData>()?;
        hd.server_name.clone()
    }
}

#[cfg(test)]
mod copy_block_tests {
    use super::CopyBlock;

    /// T512: pieces share the block while it has room; once quinn has dropped them all the
    /// block starts over (wiped when asked) instead of a new buffer.
    #[test]
    fn a_block_is_reused_once_every_piece_is_dropped() {
        for wipe in [false, true] {
            let mut b = CopyBlock::new(8);
            let one = b.copy(b"abcde", wipe).expect("room");
            let two = b.copy(b"fg", wipe).expect("room");
            assert_eq!((&one[..], &two[..]), (&b"abcde"[..], &b"fg"[..]));
            // No room past the pieces, and a piece still held: no.
            assert!(b.copy(b"xyz", wipe).is_none());
            drop(one);
            assert!(b.copy(b"xyz", wipe).is_none(), "`two` still holds the block");
            drop(two);
            let three = b.copy(b"xyz", wipe).expect("the block starts over");
            assert_eq!(&three[..], b"xyz");
            assert_eq!(b.fill, 3);
        }
    }

    /// Empty, larger than a block: no; a new block takes what the held one cannot.
    #[test]
    fn what_a_block_cannot_take_is_refused() {
        let mut b = CopyBlock::new(4);
        assert!(b.copy(b"", false).is_none());
        assert!(b.copy(b"12345", false).is_none());
        let held = b.copy(b"1234", false).expect("room");
        assert!(b.copy(b"5", false).is_none());
        assert_eq!(&b.renew().copy(b"5", false).expect("a new block")[..], b"5");
        assert_eq!(&held[..], b"1234");
    }
}
