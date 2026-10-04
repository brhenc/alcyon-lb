// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC listening socket, integrating UDP datagram I/O (`DgramSocket`) with `ibex-quic`.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Instant;

use std::collections::HashMap;

use crate::dgram::{DgramBuf, DgramOut, DgramSocket};
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};

use ibex_proto::htx::{HtxBlock, HtxSlice};
use ibex_proto::mux_h3;
use ibex_proto::qpack;
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
/// H3_NO_ERROR (RFC 9114 section 8.1), the application error code of a graceful close.
const H3_NO_ERROR: u64 = 0x100;

/// A QUIC listener managing datagram I/O on a nonblocking UDP socket and driving the QUIC transport.
pub struct QuicListener {
    socket: DgramSocket,
    endpoint: QuicEndpoint,
    addr: SocketAddr,
    recv_raw_bufs: Vec<Vec<u8>>,
    recv_cmsg_bufs: Vec<Vec<u8>>,
    send_raw_bufs: Vec<Vec<u8>>,
    h3: HashMap<ConnectionId, H3State>,
    /// Where to proxy requests. Without one the listener answers directly, which is what
    /// the bring-up test used before there was a backend leg.
    backend: Option<SocketAddr>,
    /// Backend requests still in flight, one per answered request stream (standalone mode
    /// only, see [`QuicListener::set_backend`]).
    legs: Vec<BackendLeg>,
    /// Set by the engine: each request is handed to the frontend's stream engine.
    frontend: Option<usize>,
    /// Request streams handed to the engine, one per socket pair.
    relays: Vec<Relay>,
    /// Engine ends of socket pairs created since the engine last took them.
    accepted: Vec<AcceptedStream>,
    /// HTTP/3 bytes the stream has not taken yet, and whether the stream ends after them.
    /// Flow control may take a response a part at a time.
    outq: HashMap<(ConnectionId, StreamId), OutQ>,
    /// Read buffer of `pump`, kept between passes.
    scratch: Vec<u8>,
    /// Set by a soft stop: no new connection, and a connection is closed once it is idle.
    stopping: bool,
    /// Where each live connection's peer is, so a soft stop can pin its datagrams here.
    peers: HashMap<ConnectionId, SocketAddr>,
    /// Soft stop only: one connected UDP socket per peer still being served. See
    /// [`QuicListener::begin_soft_stop`].
    pinned: Vec<(SocketAddr, DgramSocket)>,
    /// Descriptors of backend legs and pinned sockets that were dropped, for the engine to
    /// forget: the number is free for the kernel to hand out again, and a stale table entry
    /// under it would keep the next socket to get it out of the poller.
    released: Vec<RawFd>,
}

/// One backend request in flight, driven without blocking the pump loop.
///
/// The first version did `TcpStream::connect` plus blocking reads inside `on_readable`, so a
/// single slow backend stalled every QUIC connection on the listener. Non-blocking from the
/// start now: `raw::connect` returns immediately with `EINPROGRESS`, and each `pump` advances
/// whatever legs are outstanding.
struct BackendLeg {
    fd: OwnedFd,
    conn_id: ConnectionId,
    stream_id: StreamId,
    connected: bool,
    request: Vec<u8>,
    written: usize,
    response: Vec<u8>,
}

/// A request stream handed to the stream engine over a socket pair (see `h3_relay`).
struct Relay {
    /// Our end of the socket pair.
    fd: OwnedFd,
    conn_id: ConnectionId,
    stream_id: StreamId,
    /// Frames from the client not yet converted.
    rx: Vec<u8>,
    body: crate::h3_relay::BodyState,
    /// The client finished its stream (all of `rx` there is).
    client_fin: bool,
    /// HTTP/1 bytes for the engine not yet written.
    to_engine: Vec<u8>,
    resp: crate::h3_relay::ResponseConv,
    /// Finished: the relay is dropped at the end of the pass.
    done: bool,
}

/// A request stream for the engine to adopt as a client connection of the frontend.
pub struct AcceptedStream {
    /// The engine's end of the socket pair.
    pub fd: OwnedFd,
    /// The QUIC peer, the stream's client address.
    pub peer: SocketAddr,
    /// The listener's address, the stream's destination.
    pub local: SocketAddr,
}

#[derive(Default)]
struct OutQ {
    buf: Vec<u8>,
    off: usize,
    fin: bool,
}

/// How much converted response may wait for the client before the engine side is no longer
/// read, and how much request body may wait for the engine before the stream is not read.
const RELAY_BACKLOG: usize = 256 * 1024;

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
    /// Responses written in full whose last byte the peer has not yet acknowledged. Closing
    /// the connection before then abandons them.
    unacked: Vec<StreamId>,
    /// One past the highest request stream seen: the GOAWAY identifier.
    next_request: u64,
    /// A GOAWAY went out, or the connection was closed.
    draining: bool,
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
        // The whole config has to reach the endpoint, not just its TLS half. Routing through
        // `bind_with_server_config` dropped `require_retry` and `anti_amplification_factor`,
        // so a stricter factor an operator asked for was silently ignored.
        let endpoint = QuicEndpoint::with_configs_and_amplification(
            Arc::new(config.build_endpoint_config()),
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
        let socket = DgramSocket::bind(addr)?;
        let bound_addr = socket.local_addr().unwrap_or(addr);

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
            backend: None,
            legs: Vec::new(),
            frontend: None,
            relays: Vec::new(),
            accepted: Vec::new(),
            outq: HashMap::new(),
            scratch: Vec::new(),
            stopping: false,
            peers: HashMap::new(),
            pinned: Vec::new(),
            released: Vec::new(),
        })
    }


    /// Sets the backend this listener proxies to, without the stream engine: the request
    /// goes straight to `addr`, with no rule, load balancing or log. For the standalone
    /// bring-up tests and `duress_target`; the engine uses [`QuicListener::set_frontend`].
    pub fn set_backend(&mut self, addr: SocketAddr) {
        self.backend = Some(addr);
    }

    /// Hands every request to the stream engine (T130): each one becomes a client
    /// connection of the frontend, collected with [`QuicListener::take_accepted`].
    pub fn set_frontend(&mut self, proxy_idx: usize) {
        self.frontend = Some(proxy_idx);
    }

    /// The frontend (proxy index) the requests are handed to, if any.
    #[must_use]
    pub const fn frontend(&self) -> Option<usize> {
        self.frontend
    }

    /// The request streams created since the last call, for the engine to adopt.
    pub fn take_accepted(&mut self) -> Vec<AcceptedStream> {
        std::mem::take(&mut self.accepted)
    }

    /// Descriptors this listener drives besides its UDP socket -- backend legs and request
    /// relays -- with the readiness each one waits for now. Write interest only while there
    /// is something to write: a socket is nearly always writable, so asking for it
    /// otherwise wakes the loop at once, every pass (the spin T108 found).
    #[must_use]
    pub fn io_fds(&self) -> Vec<(std::os::fd::BorrowedFd<'_>, bool, bool)> {
        let legs = self.legs.iter().map(|l| {
            let writing = !l.connected || l.written < l.request.len();
            (l.fd.as_fd(), !writing, writing)
        });
        let relays = self.relays.iter().map(|r| {
            let backlog = self.outq.get(&(r.conn_id, r.stream_id)).map_or(0, |q| q.buf.len() - q.off);
            (r.fd.as_fd(), !r.done && backlog < RELAY_BACKLOG, !r.to_engine.is_empty())
        });
        legs.chain(relays).collect()
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

    /// Borrows the UDP socket for poller registration, without `unsafe` at the call site.
    #[must_use]
    pub fn borrowed_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.borrowed_fd()
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
        Self::dispatch(&mut self.endpoint, now, &dgram_bufs, n);
        // Datagrams of the connections a soft stop pinned. A pinned socket is drained empty
        // each time, like the listening one, so level-triggered readiness cannot spin.
        let mut total = n;
        for (_, sock) in &self.pinned {
            loop {
                // WouldBlock is "drained"; any other error on a socket we may drop is too.
                let got = sock.recv_batch(&mut dgram_bufs).unwrap_or(0);
                if got == 0 {
                    break;
                }
                Self::dispatch(&mut self.endpoint, now, &dgram_bufs, got);
                total += got;
            }
        }
        Ok(total)
    }

    fn dispatch(endpoint: &mut QuicEndpoint, now: Instant, dgram_bufs: &[DgramBuf], n: usize) {
        for item in dgram_bufs.iter().take(n) {
            if item.truncated {
                continue;
            }
            if let Some(src) = item.src_addr {
                let _ = endpoint.handle_datagram(now, src, item.dst_addr, &item.buf[..item.len]);
            }
        }
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

        // Reused across passes: a relay reads the engine's response through it, 64 KB a time.
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.resize(64 * 1024, 0);
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
                TransportEvent::NewConnection { conn_id, remote } => {
                    self.peers.insert(conn_id, remote);
                }
                TransportEvent::StreamOpened { conn_id, stream_id, dir } => {
                    if dir == StreamDirection::Bidirectional {
                        let st = self.h3.entry(conn_id).or_default();
                        st.req.entry(stream_id).or_default();
                        st.next_request = st.next_request.max(stream_id.0 + 4);
                    }
                    // A stream whose first flight already carries the whole request is
                    // opened and readable at once, and quinn-proto raises no separate
                    // `Readable` for data that arrived before the stream was accepted.
                    // Waiting for one left such a request unanswered for ever.
                    self.on_readable(conn_id, stream_id, &mut scratch);
                }
                TransportEvent::StreamReadable { conn_id, stream_id } => {
                    self.on_readable(conn_id, stream_id, &mut scratch);
                }
                // A finished stream and a reset stream are both done with; the difference
                // matters to the peer, not to our buffer bookkeeping.
                TransportEvent::StreamFinished { conn_id, stream_id } => {
                    if let Some(st) = self.h3.get_mut(&conn_id) {
                        st.req.remove(&stream_id);
                        st.unacked.retain(|s| *s != stream_id);
                    }
                }
                // The client asked us to stop sending the response. (A reset of its request
                // arrives as a read error instead, in `on_readable`.)
                TransportEvent::StreamStopped { conn_id, stream_id, .. } => {
                    self.abandon_stream(conn_id, stream_id);
                }
                TransportEvent::ConnectionClosed { conn_id, .. } => {
                    self.h3.remove(&conn_id);
                    self.peers.remove(&conn_id);
                    for r in &mut self.relays {
                        if r.conn_id == conn_id {
                            r.done = true;
                        }
                    }
                    self.outq.retain(|(c, _), _| *c != conn_id);
                    self.release_pinned();
                }
                _ => {}
            }
        }

        self.advance_backends();
        self.advance_relays(&mut scratch);
        self.flush_out();
        if self.stopping {
            self.drain_idle_connections();
        }
        self.scratch = scratch;
        self.send_batch(now)?;
        Ok(())
    }

    /// Soft stop, HAProxy's `soft_stop()` for a QUIC listener: refuse new connections, tell
    /// every established HTTP/3 client with a GOAWAY that it will get no further request,
    /// and close each connection as soon as the responses it owes have been delivered.
    /// The UDP socket stays registered, because the datagrams of those connections arrive on it.
    pub fn begin_soft_stop(&mut self) {
        // Called once, by the engine, when the soft stop begins.
        self.stopping = true;
        self.endpoint.stop_accepting();
        self.pin_peers();
        for (conn_id, st) in &mut self.h3 {
            Self::send_goaway(&mut self.endpoint, *conn_id, st);
        }
        self.drain_idle_connections();
        // The GOAWAYs and closes go out now. Left for the next `pump`, they waited for an
        // unrelated wakeup -- and a closed connection's next wakeup is its drain timer, which
        // removes it before its CONNECTION_CLOSE was ever sent. That this used to work was
        // the backend legs' write interest waking the loop on every pass.
        let _ = self.send_batch(Instant::now());
    }

    /// Gives each remaining connection a UDP socket of its own, connected to its peer.
    ///
    /// The new process of a reload binds the same address with `SO_REUSEPORT`, and the kernel
    /// then hashes every datagram to one of the two listening sockets, so about half of what
    /// an old connection's client sends -- the acknowledgement of the response it was
    /// waiting for included -- would reach a process that has never heard of the connection
    /// and answers with a stateless reset. A connected socket is matched on the full four
    /// tuple before the reuseport group is consulted, which is what keeps those datagrams
    /// here. HAProxy does the same in `quic-socket connection` mode (`quic_sock.c`).
    fn pin_peers(&mut self) {
        let mut want: Vec<SocketAddr> = self.peers.values().copied().collect();
        want.sort();
        want.dedup();
        for peer in want {
            if let Ok(sock) = DgramSocket::bind(self.addr).and_then(|s| s.connect(peer).map(|()| s)) {
                self.pinned.push((peer, sock));
            }
        }
    }

    /// Drops the pinned socket of a peer with no connection left.
    fn release_pinned(&mut self) {
        let live: Vec<SocketAddr> = self.peers.values().copied().collect();
        let released = &mut self.released;
        self.pinned.retain(|(peer, sock)| {
            let keep = live.contains(peer);
            if !keep {
                released.push(sock.as_raw_fd());
            }
            keep
        });
    }

    /// The pinned sockets (see `begin_soft_stop`), for the engine's poller. Read-only
    /// interest: a UDP socket is always writable, so asking for that would spin the loop.
    #[must_use]
    pub fn pinned_borrowed_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
        self.pinned.iter().map(|(_, s)| s.borrowed_fd()).collect()
    }

    /// Descriptors of legs and pinned sockets dropped since the last call.
    pub fn take_released_fds(&mut self) -> Vec<RawFd> {
        std::mem::take(&mut self.released)
    }

    /// Whether this listener still has work a soft stop must wait for: a connection that has
    /// not yet finished closing, or a backend request in flight.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        !self.legs.is_empty() || !self.relays.is_empty() || self.endpoint.connection_count() > 0
    }

    /// Sends GOAWAY once on a connection's control stream.
    fn send_goaway(endpoint: &mut QuicEndpoint, conn_id: ConnectionId, st: &mut H3State) {
        if let (Some(control), false) = (st.control, std::mem::replace(&mut st.draining, true)) {
            let bytes = mux_h3::encode_goaway(st.next_request);
            let _ = endpoint.write_stream(conn_id, control, &bytes, false);
        }
    }

    /// Closes, with H3_NO_ERROR, every connection that owes no response.
    fn drain_idle_connections(&mut self) {
        let mut idle = Vec::new();
        for (conn_id, st) in &self.h3 {
            let owes = !st.unacked.is_empty()
                || st.req.values().any(|b| !b.is_empty())
                || self.legs.iter().any(|l| l.conn_id == *conn_id)
                || self.relays.iter().any(|r| r.conn_id == *conn_id)
                || self.outq.keys().any(|(c, _)| c == conn_id);
            if !owes {
                idle.push(*conn_id);
            }
        }
        for conn_id in idle {
            self.endpoint.close_connection(conn_id, H3_NO_ERROR, b"");
        }
    }

    /// Queues a whole response; [`QuicListener::flush_out`] writes it as flow control allows.
    fn respond(&mut self, conn_id: ConnectionId, stream_id: StreamId, resp: &[u8]) {
        self.queue_out(conn_id, stream_id, resp, true);
    }

    /// Queues HTTP/3 bytes for a stream, and its end when `fin`.
    fn queue_out(&mut self, conn_id: ConnectionId, stream_id: StreamId, bytes: &[u8], fin: bool) {
        let q = self.outq.entry((conn_id, stream_id)).or_default();
        if q.off > 0 && q.off == q.buf.len() {
            q.buf.clear();
            q.off = 0;
        }
        q.buf.extend_from_slice(bytes);
        q.fin |= fin;
    }

    /// Writes what the streams will take. A stream whose last byte and end went out is
    /// owed only its acknowledgement now (`unacked`, for the soft stop).
    fn flush_out(&mut self) {
        let mut finished = Vec::new();
        for (&(conn_id, stream_id), q) in &mut self.outq {
            // An error here is a stream the client stopped or a connection that is gone;
            // the event saying so (`StreamStopped`, `ConnectionClosed`) drops the queue.
            q.off += self.endpoint.write_stream(conn_id, stream_id, &q.buf[q.off..], q.fin).unwrap_or(0);
            if q.off == q.buf.len() && q.fin {
                finished.push((conn_id, stream_id));
            }
        }
        for (conn_id, stream_id) in finished {
            self.outq.remove(&(conn_id, stream_id));
            if let Some(st) = self.h3.get_mut(&conn_id) {
                st.unacked.push(stream_id);
            }
        }
    }

    /// Advances every in-flight backend leg by whatever it can do without blocking.
    fn advance_backends(&mut self) {
        let mut finished: Vec<(ConnectionId, StreamId, Vec<u8>)> = Vec::new();
        let mut still = Vec::with_capacity(self.legs.len());
        let before: Vec<RawFd> = self.legs.iter().map(|l| l.fd.as_raw_fd()).collect();

        for mut leg in std::mem::take(&mut self.legs) {
            if !leg.connected {
                if matches!(crate::raw::check_connect_error(leg.fd.as_fd()), Ok(None)) {
                    leg.connected = true;
                } else {
                    finished.push((leg.conn_id, leg.stream_id,
                                   mux_h3::encode_response(502, &[], b"")));
                    continue;
                }
            }

            while leg.written < leg.request.len() {
                match crate::raw::send(leg.fd.as_fd(), &leg.request[leg.written..]) {
                    Ok(crate::raw::Io::Done(n)) => leg.written += n,
                    Ok(crate::raw::Io::WouldBlock) => break,
                    _ => {
                        finished.push((leg.conn_id, leg.stream_id,
                                       mux_h3::encode_response(502, &[], b"")));
                        leg.written = usize::MAX;
                        break;
                    }
                }
            }
            if leg.written == usize::MAX {
                continue;
            }
            if leg.written < leg.request.len() {
                still.push(leg);
                continue;
            }

            let mut chunk = [0u8; 4096];
            let mut done = false;
            let mut failed = false;
            loop {
                match crate::raw::recv(leg.fd.as_fd(), &mut chunk) {
                    Ok(crate::raw::Io::Done(n)) => leg.response.extend_from_slice(&chunk[..n]),
                    Ok(crate::raw::Io::WouldBlock) => break,
                    Ok(crate::raw::Io::Eof) => {
                        done = true;
                        break;
                    }
                    _ => {
                        failed = true;
                        break;
                    }
                }
                if Self::try_split_response(&leg.response).is_some() {
                    done = true;
                    break;
                }
            }

            if failed && Self::try_split_response(&leg.response).is_none() {
                finished.push((leg.conn_id, leg.stream_id,
                               mux_h3::encode_response(502, &[], b"")));
                continue;
            }
            if done || Self::try_split_response(&leg.response).is_some() {
                let resp = match Self::try_split_response(&leg.response) {
                    Some((status, body)) => mux_h3::encode_response(
                        status,
                        &[("content-length".to_string(), body.len().to_string())],
                        &body,
                    ),
                    None => mux_h3::encode_response(502, &[], b""),
                };
                finished.push((leg.conn_id, leg.stream_id, resp));
                continue;
            }
            still.push(leg);
        }

        self.legs = still;
        for fd in before {
            if !self.legs.iter().any(|l| l.fd.as_raw_fd() == fd) {
                self.released.push(fd);
            }
        }
        for (conn_id, stream_id, resp) in finished {
            self.respond(conn_id, stream_id, &resp);
        }
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
        let relay = self.relays.iter().position(|r| r.conn_id == conn_id && r.stream_id == stream_id);
        // A request body the engine has not taken yet stays in the stream, so the client's
        // flow-control window, not our memory, holds the rest back. `advance_relays` reads
        // again once the engine has caught up.
        if relay.is_some_and(|i| self.relays[i].to_engine.len() >= RELAY_BACKLOG || self.relays[i].client_fin) {
            return;
        }
        let mut chunk = Vec::new();
        let mut fin = false;
        loop {
            match self.endpoint.read_stream(conn_id, stream_id, scratch) {
                Ok(res) => {
                    chunk.extend_from_slice(&scratch[..res.bytes_read]);
                    if res.fin {
                        fin = true;
                        break;
                    }
                    if res.bytes_read == 0 {
                        break;
                    }
                }
                // quinn reports a reset as a read error, not as an event: the endpoint never
                // raises `TransportEvent::StreamReset`. Missing it left the engine's stream of
                // a reset request open until its timeout.
                Err(ibex_quic::error::QuicError::StreamReset(_)) => {
                    self.abandon_stream(conn_id, stream_id);
                    return;
                }
                Err(_) => break,
            }
        }
        if chunk.is_empty() && !fin {
            return;
        }

        // Unidirectional streams from the client are its control stream and the two QPACK
        // streams. With table capacity advertised as zero there is no dynamic state to
        // track, so they are read and discarded -- but they must be read, because a client
        // opens them regardless and a stalled stream stalls the connection.
        if !stream_id.0.is_multiple_of(4) {
            return;
        }

        if let Some(i) = relay {
            let r = &mut self.relays[i];
            r.rx.extend_from_slice(&chunk);
            r.client_fin |= fin;
            if let Some(resp) = r.pump_request() {
                self.respond(conn_id, stream_id, &resp);
            }
            return;
        }

        let st = self.h3.entry(conn_id).or_default();
        if st.answered.contains(&stream_id) {
            return;
        }
        st.req.entry(stream_id).or_default().extend_from_slice(&chunk);
        let buf = st.req.get(&stream_id).cloned().unwrap_or_default();

        // A HEADERS frame can be split across datagrams; Ok(None) means wait for more.
        let Ok(Some(field_section)) = mux_h3::take_request_headers(&buf) else {
            return;
        };

        let st = self.h3.entry(conn_id).or_default();
        st.answered.push(stream_id);
        st.req.remove(&stream_id);

        if self.frontend.is_some() {
            self.start_relay(conn_id, stream_id, &buf, fin);
        } else if let Some(be) = self.backend {
            match Self::start_backend(be, conn_id, stream_id, &field_section) {
                Ok(leg) => self.legs.push(leg),
                Err(resp) => self.respond(conn_id, stream_id, &resp),
            }
        } else {
            let body = b"hello-from-ibex-h3".to_vec();
            let resp = mux_h3::encode_response(
                200,
                &[("content-length".to_string(), body.len().to_string())],
                &body,
            );
            self.respond(conn_id, stream_id, &resp);
        }
    }

    /// The client reset the request or asked us to stop sending the response: the engine's
    /// stream is cut, which it sees as the client going away.
    fn abandon_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let st = self.h3.entry(conn_id).or_default();
        st.req.remove(&stream_id);
        st.unacked.retain(|s| *s != stream_id);
        for r in &mut self.relays {
            if r.conn_id == conn_id && r.stream_id == stream_id {
                r.done = true;
            }
        }
        self.outq.remove(&(conn_id, stream_id));
    }

    /// Hands a request whose HEADERS arrived to the engine: converts it to its HTTP/1 head
    /// and opens the socket pair the engine adopts as a client connection.
    fn start_relay(&mut self, conn_id: ConnectionId, stream_id: StreamId, buf: &[u8], fin: bool) {
        let Ok(Some((section, after))) = crate::h3_relay::first_headers(buf) else {
            self.respond(conn_id, stream_id, &mux_h3::encode_response(400, &[], b""));
            return;
        };
        let rest = buf[after..].to_vec();
        let known = if fin { crate::h3_relay::complete_body_len(&rest) } else { None };
        let head = match crate::h3_relay::request_head(&section, known) {
            Ok(h) => h,
            Err(status) => {
                self.respond(conn_id, stream_id, &mux_h3::encode_response(status, &[], b""));
                return;
            }
        };
        let flags = rustix::net::SocketFlags::NONBLOCK | rustix::net::SocketFlags::CLOEXEC;
        let Ok((ours, theirs)) =
            rustix::net::socketpair(rustix::net::AddressFamily::UNIX, rustix::net::SocketType::STREAM, flags, None)
        else {
            self.respond(conn_id, stream_id, &mux_h3::encode_response(503, &[], b""));
            return;
        };
        let mut relay = Relay {
            fd: ours,
            conn_id,
            stream_id,
            rx: rest,
            body: crate::h3_relay::BodyState::new(head.body),
            client_fin: fin,
            to_engine: head.head,
            resp: crate::h3_relay::ResponseConv::new(head.method_head),
            done: false,
        };
        if let Some(resp) = relay.pump_request() {
            self.respond(conn_id, stream_id, &resp);
            return;
        }
        let peer = self.peers.get(&conn_id).copied().unwrap_or(self.addr);
        self.accepted.push(AcceptedStream { fd: theirs, peer, local: self.addr });
        self.relays.push(relay);
    }

    /// Moves request bytes to the engine and the engine's response to the client.
    fn advance_relays(&mut self, scratch: &mut [u8]) {
        // Request bodies held back by `on_readable` while the engine was behind.
        let waiting: Vec<(ConnectionId, StreamId)> = self
            .relays
            .iter()
            .filter(|r| !r.client_fin && !r.done && r.to_engine.len() < RELAY_BACKLOG)
            .map(|r| (r.conn_id, r.stream_id))
            .collect();
        for (c, sid) in waiting {
            self.on_readable(c, sid, scratch);
        }

        let mut out: Vec<(ConnectionId, StreamId, Vec<u8>, bool)> = Vec::new();
        for r in &mut self.relays {
            if r.done {
                continue;
            }
            while !r.to_engine.is_empty() {
                match crate::raw::send(r.fd.as_fd(), &r.to_engine) {
                    Ok(crate::raw::Io::Done(n)) if n > 0 => {
                        r.to_engine.drain(..n);
                    }
                    Ok(crate::raw::Io::WouldBlock) => break,
                    // The engine closed its side (it answered without reading the whole
                    // body, or gave up): the rest of the request has nowhere to go.
                    _ => {
                        r.to_engine.clear();
                        break;
                    }
                }
            }
            let backlog = self.outq.get(&(r.conn_id, r.stream_id)).map_or(0, |q| q.buf.len() - q.off);
            let mut frames = Vec::new();
            while backlog + frames.len() < RELAY_BACKLOG && !r.done {
                match crate::raw::recv(r.fd.as_fd(), scratch) {
                    Ok(crate::raw::Io::Done(n)) if n > 0 => {
                        if r.resp.feed(&scratch[..n], &mut frames).is_err() {
                            r.done = true;
                            if !r.resp.head_sent {
                                frames = mux_h3::encode_response(502, &[], b"");
                            }
                        }
                    }
                    Ok(crate::raw::Io::WouldBlock) => break,
                    _ => {
                        // End of the engine's side: a response delimited by the close ends
                        // here; one cut short gets a 502 if nothing of it went out yet.
                        r.done = true;
                        if r.resp.eof().is_err() && !r.resp.head_sent {
                            frames = mux_h3::encode_response(502, &[], b"");
                        }
                    }
                }
                if r.resp.is_done() {
                    r.done = true;
                }
            }
            if !frames.is_empty() || r.done {
                out.push((r.conn_id, r.stream_id, frames, r.done));
            }
        }
        for (c, sid, frames, fin) in out {
            self.queue_out(c, sid, &frames, fin);
        }
        let released = &mut self.released;
        self.relays.retain(|r| {
            if r.done {
                released.push(r.fd.as_raw_fd());
            }
            !r.done
        });
    }
}

impl Relay {
    /// Converts what the client sent since the head into HTTP/1 body bytes for the engine.
    /// Returns an HTTP/3 error response when the request turned out malformed before the
    /// engine answered anything; later, the relay is cut instead.
    fn pump_request(&mut self) -> Option<Vec<u8>> {
        let mut ok = self.body.take(&mut self.rx, &mut self.to_engine).is_ok();
        if ok && self.client_fin {
            ok = self.body.end(&self.rx, &mut self.to_engine).is_ok();
        }
        if ok {
            return None;
        }
        self.done = true;
        (!self.resp.head_sent).then(|| mux_h3::encode_response(400, &[], b""))
    }
}

impl QuicListener {
    /// Converts a decoded HTTP/3 request and starts a non-blocking backend connect.
    ///
    /// The conversion goes through `headers_to_htx`, the same `pseudo_headers_to_htx` the
    /// HTTP/2 mux uses: `:authority` becomes `Host`, `:scheme` is consumed, and no
    /// pseudo-header reaches the backend. Reimplementing that mapping here is how HTTP/3
    /// inherited the missing-`Host` defect in the first place.
    ///
    /// # Errors
    /// Returns an already-encoded HTTP/3 error response when the request cannot be converted
    /// or the socket cannot be created.
    fn start_backend(
        backend: SocketAddr,
        conn_id: ConnectionId,
        stream_id: StreamId,
        field_section: &[u8],
    ) -> Result<BackendLeg, Vec<u8>> {
        let fields = qpack::decode_qpack_static(field_section)
            .map_err(|_| mux_h3::encode_response(400, &[], b""))?;
        let blocks = ibex_proto::h3::headers_to_htx(fields)
            .map_err(|_| mux_h3::encode_response(400, &[], b""))?;

        let mut scratch = vec![0u8; 16384];
        let mut slice = HtxSlice::new(&mut scratch);
        for block in &blocks {
            let pushed = match block {
                HtxBlock::ReqLine(rl) => {
                    slice.push_req_line(rl.method.as_str(), &rl.uri, "HTTP/1.1")
                }
                HtxBlock::Header(h) => slice.push_header(&h.name, &h.value),
                HtxBlock::Eoh => slice.push_eoh(),
                _ => Ok(()),
            };
            if pushed.is_err() {
                return Err(mux_h3::encode_response(431, &[], b""));
            }
        }
        let request = slice.as_ref().to_h1_wire();

        let (fd, connected) = crate::raw::connect(backend)
            .map_err(|_| mux_h3::encode_response(502, &[], b""))?;

        Ok(BackendLeg {
            fd,
            conn_id,
            stream_id,
            connected,
            request,
            written: 0,
            response: Vec::new(),
        })
    }

    /// Parses a complete HTTP/1 response, or `None` if more bytes are needed.
    fn try_split_response(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
        let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let head = std::str::from_utf8(&raw[..head_end]).ok()?;
        let status: u16 = head.split_whitespace().nth(1)?.parse().ok()?;
        let content_length = head
            .lines()
            .find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.trim().eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let body = &raw[head_end..];
        if body.len() < content_length {
            return None;
        }
        Some((status, body[..content_length].to_vec()))
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
