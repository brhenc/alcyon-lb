// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC listening socket, integrating UDP datagram I/O (`DgramSocket`) with `ibex-quic`.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::Instant;

use std::collections::{HashMap, HashSet, VecDeque};

use crate::dgram::{DgramBuf, DgramOut, DgramSocket};
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};

use ibex_proto::h3::H3Error;
use ibex_proto::mux_h3;
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
/// Two eight-byte varints: the largest frame header, which a buffer may hold on top of a
/// frame at the cap.
const MAX_FRAME_HEADER: usize = 16;

/// The QUIC sockets bound by [`prebind`] before the workers start, one per worker and
/// address, each waiting for its worker to take it.
static PREBOUND: std::sync::Mutex<Vec<(SocketAddr, usize, DgramSocket)>> = std::sync::Mutex::new(Vec::new());

/// Binds every worker's `SO_REUSEPORT` socket on `addr` now, on the calling thread (T210).
///
/// The kernel hashes a datagram's four-tuple over the sockets in the reuseport group *at the
/// time it arrives*. Bound one by one from inside the worker threads, while the first workers
/// already served, the group grew under a client that came early: its first datagrams went
/// to one worker, its later ones to another that had never heard of the connection, and the
/// handshake stalled (`h3_many_threads.rs`: 9 of 20 at `nbthread 64`). HAProxy binds every
/// listener, QUIC included, in the startup path before the first thread is created
/// (strace: all `bind`s precede the first `clone3`).
///
/// # Errors
/// The first socket that cannot be bound; none of this address's sockets are kept then.
pub fn prebind(addr: SocketAddr, workers: usize) -> io::Result<()> {
    let mut socks = Vec::with_capacity(workers);
    for worker in 0..workers {
        socks.push((addr, worker, DgramSocket::bind(addr)?));
    }
    PREBOUND.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(socks);
    Ok(())
}

/// The socket [`prebind`] bound on `addr` for `worker`, if there is one.
fn take_prebound(addr: SocketAddr, worker: usize) -> Option<DgramSocket> {
    let mut all = PREBOUND.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let i = all.iter().position(|(a, w, _)| *a == addr && *w == worker)?;
    Some(all.swap_remove(i).2)
}

/// A QUIC listener managing datagram I/O on a nonblocking UDP socket and driving the QUIC transport.
pub struct QuicListener {
    /// The poller saw the socket readable this pass ([`QuicListener::mark_ready`]).
    ready: bool,
    socket: DgramSocket,
    endpoint: QuicEndpoint,
    addr: SocketAddr,
    recv_raw_bufs: Vec<Vec<u8>>,
    recv_cmsg_bufs: Vec<Vec<u8>>,
    send_raw_bufs: Vec<Vec<u8>>,
    h3: HashMap<ConnectionId, H3State>,
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
    /// Set by the engine (T504): an HTTP/3 connection is admitted to its frontend as a session
    /// before it is served. Without it (a listener driven alone) every connection is served
    /// at once.
    gated: bool,
    /// Connections whose handshake completed since the engine last counted them.
    handshaken: Vec<ConnectionId>,
    /// Counted by the engine, held by `maxconn` until it admits them, oldest first.
    waiting: VecDeque<ConnectionId>,
    /// `handshaken` and `waiting`: connections not served yet.
    pending: HashSet<ConnectionId>,
    /// Connections admitted as sessions.
    admitted: HashSet<ConnectionId>,
    /// Stream events of a connection that was not admitted yet, replayed when it is.
    held: HashMap<ConnectionId, Vec<(StreamId, bool)>>,
    /// Connections that ended since the engine last looked, and whether each was admitted.
    closed: Vec<(ConnectionId, bool)>,
    /// `tune.ibex.h3-path mux` (T509): an admitted connection is served by an owner session
    /// of the engine through the h3 mux, not by the relay.
    mux: bool,
    /// The connections owner sessions serve, by connection.
    owned: HashMap<ConnectionId, OwnedConn>,
    /// Connections admitted since the engine last took them, each to get its owner.
    new_owned: Vec<ConnectionId>,
    /// Owners with transport news since the engine last woke them.
    wake: Vec<ibex_sched::TaskRef>,
    /// An owner wrote to the transport since the last `send_batch`.
    dirty: bool,
}

/// A connection an owner session serves (T509): what the transport said of it since the
/// owner's last pass, for that pass to act on.
#[derive(Default)]
struct OwnedConn {
    /// The owner's entry and task, once the engine has made it.
    owner: Option<(u32, ibex_sched::TaskRef)>,
    /// Streams to read: opened or readable since, or held back by the mux (no room).
    read: Vec<u64>,
    /// `STOP_SENDING`s from the client: stream and code.
    stopped: Vec<(u64, u64)>,
    /// Our control stream is open.
    control: bool,
    /// The connection is gone.
    closed: bool,
    /// Request streams whose FIN is written and not yet acknowledged: a soft stop closes
    /// the connection only once this is empty, for quinn retransmits nothing after a close
    /// (T521; `HAProxy` keeps a stream until its FIN is acknowledged, `qcc_streams_sent_done`).
    unacked: Vec<u64>,
}

/// What an owner's read of its connection found ([`QuicListener::owner_recv`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerConn {
    Open,
    /// The connection is gone: the owner ends.
    Closed,
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
        tls: &Arc<ibex_tls::tcp::BindTls>,
        quic_config: Option<QuicConfig>,
    ) -> io::Result<Self> {
        Self::bind_for_worker(addr, tls, quic_config, None)
    }

    /// [`QuicListener::bind`] for a worker: it takes the socket [`prebind`] bound for it on
    /// `addr`, and binds one only if there is none (an engine built without `prebind`).
    ///
    /// # Errors
    /// As [`QuicListener::bind`].
    pub fn bind_for_worker(
        addr: SocketAddr,
        tls: &Arc<ibex_tls::tcp::BindTls>,
        quic_config: Option<QuicConfig>,
        worker: Option<usize>,
    ) -> io::Result<Self> {
        let config = quic_config.unwrap_or_default();
        let server_config = config
            .build_server_config(tls)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        // The whole config has to reach the endpoint, not just its TLS half. Routing through
        // `bind_with_server_config` dropped `require_retry`, the Retry threshold and
        // `anti_amplification_factor`, so a stricter factor an operator asked for was
        // silently ignored.
        let endpoint = QuicEndpoint::from_config(
            Arc::new(config.build_endpoint_config().map_err(|e| io::Error::other(e.to_string()))?),
            server_config,
            &config,
        );
        let socket = match worker.and_then(|w| take_prebound(addr, w)) {
            Some(s) => s,
            None => DgramSocket::bind(addr)?,
        };
        Ok(Self::from_socket(addr, socket, endpoint))
    }

    /// Wraps a bound UDP socket and an already-configured endpoint.
    fn from_socket(addr: SocketAddr, socket: DgramSocket, endpoint: QuicEndpoint) -> Self {
        let bound_addr = socket.local_addr().unwrap_or(addr);

        let recv_raw_bufs = vec![vec![0u8; DGRAM_BUF_SIZE]; BATCH_SIZE];
        let recv_cmsg_bufs = vec![vec![0u8; CMSG_BUF_SIZE]; BATCH_SIZE];
        let send_raw_bufs = vec![vec![0u8; DGRAM_BUF_SIZE]; BATCH_SIZE];

        Self {
            ready: false,
            socket,
            endpoint,
            addr: bound_addr,
            recv_raw_bufs,
            recv_cmsg_bufs,
            send_raw_bufs,
            h3: HashMap::new(),
            frontend: None,
            relays: Vec::new(),
            accepted: Vec::new(),
            outq: HashMap::new(),
            scratch: Vec::new(),
            stopping: false,
            peers: HashMap::new(),
            pinned: Vec::new(),
            released: Vec::new(),
            gated: false,
            handshaken: Vec::new(),
            waiting: VecDeque::new(),
            pending: HashSet::new(),
            admitted: HashSet::new(),
            held: HashMap::new(),
            closed: Vec::new(),
            mux: false,
            owned: HashMap::new(),
            new_owned: Vec::new(),
            wake: Vec::new(),
            dirty: false,
        }
    }

    /// `tune.ibex.h3-path mux` (T509): admitted connections are served by owner sessions
    /// ([`QuicListener::take_new_owned`]), not by the relay.
    pub fn serve_by_mux(&mut self) {
        self.mux = true;
    }

    /// Connections admitted since the last call, each for the engine to give an owner
    /// session ([`QuicListener::set_owner`]).
    pub fn take_new_owned(&mut self) -> Vec<ConnectionId> {
        std::mem::take(&mut self.new_owned)
    }

    /// The owner session of `conn_id` is entry `idx`, task `task`: it is woken with the
    /// transport's news of the connection.
    pub fn set_owner(&mut self, conn_id: ConnectionId, idx: u32, task: ibex_sched::TaskRef) {
        if let Some(oc) = self.owned.get_mut(&conn_id) {
            oc.owner = Some((idx, task));
            if !oc.read.is_empty() || oc.closed {
                self.wake.push(task);
            }
        }
    }

    /// The owners to wake for what the transport did since the last call.
    pub fn take_wake(&mut self, into: &mut Vec<ibex_sched::TaskRef>) {
        into.append(&mut self.wake);
    }

    /// The poller found the socket readable: the next [`QuicListener::take_ready`] is true.
    /// A flag rather than an index list the engine collects, so a pass allocates nothing (T512).
    pub fn mark_ready(&mut self) {
        self.ready = true;
    }

    /// Whether the socket was marked readable since the last call.
    pub fn take_ready(&mut self) -> bool {
        std::mem::replace(&mut self.ready, false)
    }

    /// Whether an owner wrote to the transport since the last call: its datagrams go out.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::replace(&mut self.dirty, false)
    }

    /// Whether the connection `conn_id` is owned and the listener is in a soft stop.
    #[must_use]
    pub fn is_stopping(&self) -> bool {
        self.stopping
    }

    /// The peer of a connection, or the listener's own address.
    #[must_use]
    pub fn peer_of(&self, conn_id: ConnectionId) -> SocketAddr {
        self.peers.get(&conn_id).copied().unwrap_or(self.addr)
    }

    /// The owner of `conn_id` reads what the client sent into its mux (T509): `STOP_SENDING`s,
    /// then each stream with news, as far as the mux has room for it (§2.3: the client's
    /// window holds the rest back). Our control stream is opened on the first pass.
    pub fn owner_recv(&mut self, conn_id: ConnectionId, mux: &mut mux_h3::H3MuxContext, now: u64) -> OwnerConn {
        let Some(oc) = self.owned.get_mut(&conn_id) else { return OwnerConn::Closed };
        if oc.closed {
            return OwnerConn::Closed;
        }
        if !oc.control {
            oc.control = true;
            if let Ok(sid) = self.endpoint.open_stream(conn_id, StreamDirection::Unidirectional) {
                mux.open_control(sid.0);
            }
        }
        for (id, code) in oc.stopped.drain(..) {
            let _ = mux.on_stop_sending(id, code);
        }
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.resize(64 * 1024, 0);
        let mut i = 0;
        while i < oc.read.len() {
            let id = oc.read[i];
            let mut keep = false;
            while mux.error.is_none() {
                let room = mux.rx_room(id).min(scratch.len());
                if room == 0 {
                    keep = true;
                    break;
                }
                match self.endpoint.read_stream(conn_id, StreamId(id), &mut scratch[..room]) {
                    Ok(r) => {
                        if r.bytes_read > 0 || r.fin {
                            let _ = mux.recv(id, &scratch[..r.bytes_read], r.fin, now);
                        }
                        if r.fin || r.bytes_read == 0 {
                            break;
                        }
                    }
                    Err(ibex_quic::error::QuicError::StreamReset(code)) => {
                        let _ = mux.on_reset(id, code);
                        break;
                    }
                    Err(_) => break,
                }
            }
            if keep {
                i += 1;
            } else {
                oc.read.swap_remove(i);
            }
        }
        self.scratch = scratch;
        OwnerConn::Open
    }

    /// The owner of `conn_id` writes what its mux framed (T509): the stream signals, a
    /// connection error as the close, then each stream's bytes and FIN round robin, as
    /// much as quinn takes. A stream whose FIN went out and that `done` says no child serves
    /// any more is let go.
    pub fn owner_send(&mut self, conn_id: ConnectionId, mux: &mut mux_h3::H3MuxContext, done: impl Fn(u64) -> bool) {
        if !self.owned.contains_key(&conn_id) {
            return;
        }
        self.dirty = true;
        while let Some(sig) = mux.take_signal() {
            match sig {
                mux_h3::H3Signal::StopSending { id, code } => self.endpoint.stop_sending(conn_id, StreamId(id), code),
                mux_h3::H3Signal::ResetStream { id, code } => {
                    let _ = self.endpoint.reset_stream(conn_id, StreamId(id), code);
                }
            }
        }
        if let Some(e) = mux.error {
            self.endpoint.close_connection(conn_id, e as u64, b"");
            return;
        }
        for _ in 0..256 {
            let Some(id) = mux.next_tx() else { break };
            let bytes = mux.tx_bytes(id);
            let n = if bytes.is_empty() { 0 } else { self.endpoint.write_stream(conn_id, StreamId(id), bytes, false).unwrap_or(0) };
            mux.tx_written(id, n);
            if mux.fin_due(id) {
                if self.endpoint.finish_stream(conn_id, StreamId(id)).is_ok() {
                    if let Some(oc) = self.owned.get_mut(&conn_id) {
                        oc.unacked.push(id);
                    }
                }
                mux.fin_written(id);
                if done(id) {
                    mux.release(id);
                }
            } else if n == 0 {
                break;
            }
        }
    }

    /// Whether a FIN written on connection `conn_id` waits for its acknowledgement.
    #[must_use]
    pub fn owner_unacked(&self, conn_id: ConnectionId) -> bool {
        self.owned.get(&conn_id).is_some_and(|oc| !oc.unacked.is_empty())
    }

    /// Stream `id` of an owned connection needs no acknowledgement any more (its FIN was, or
    /// the client stopped it): whether it was waiting for one.
    fn acked(oc: &mut OwnedConn, id: u64) -> bool {
        let Some(i) = oc.unacked.iter().position(|s| *s == id) else { return false };
        oc.unacked.swap_remove(i);
        true
    }

    /// Closes connection `conn_id`, its owner gone or ending it (`H3_NO_ERROR`).
    pub fn owner_close(&mut self, conn_id: ConnectionId) {
        if self.owned.remove(&conn_id).is_some_and(|oc| !oc.closed) {
            self.endpoint.close_connection(conn_id, H3_NO_ERROR, b"");
            self.dirty = true;
        }
    }

    /// Records transport news of an owned connection for its owner, and wakes it.
    fn owned_news(&mut self, conn_id: ConnectionId, read: Option<u64>, stopped: Option<(u64, u64)>) -> bool {
        let Some(oc) = self.owned.get_mut(&conn_id) else { return false };
        if let Some(id) = read.filter(|id| !oc.read.contains(id)) {
            oc.read.push(id);
        }
        if let Some(st) = stopped {
            oc.stopped.push(st);
        }
        if let Some((_, task)) = oc.owner {
            self.wake.push(task);
        }
        true
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

    /// Bytes of request streams held for parsing, over every connection (for tests).
    #[doc(hidden)]
    #[must_use]
    pub fn pending_request_bytes(&self) -> usize {
        self.h3.values().flat_map(|st| st.req.values()).map(Vec::len).sum()
    }

    /// Makes the engine decide, per connection, when it is served (T504): a connection that
    /// completes its HTTP/3 handshake waits until [`QuicListener::admit_next`] says so.
    pub fn gate_connections(&mut self) {
        self.gated = true;
    }

    /// Connections that completed their handshake since the last call, now waiting for
    /// admission, for the engine to count (or [`QuicListener::refuse`]).
    pub fn take_handshaken(&mut self) -> Vec<ConnectionId> {
        let new = std::mem::take(&mut self.handshaken);
        self.waiting.extend(new.iter().copied());
        new
    }

    /// Closes a connection the engine will not count (`global maxconn` is reached, as
    /// `HAProxy`'s listener refuses it).
    pub fn refuse(&mut self, conn_id: ConnectionId) {
        self.pending.remove(&conn_id);
        self.held.remove(&conn_id);
        self.waiting.retain(|c| *c != conn_id);
        self.endpoint.close_connection(conn_id, H3_NO_ERROR, b"");
    }

    /// Whether a connection waits for admission.
    #[must_use]
    pub fn has_waiting(&self) -> bool {
        !self.waiting.is_empty()
    }

    /// Serves the oldest waiting connection: its control stream, and the streams it opened
    /// while it waited.
    pub fn admit_next(&mut self) {
        let Some(conn_id) = self.waiting.pop_front() else { return };
        self.pending.remove(&conn_id);
        self.admitted.insert(conn_id);
        if self.mux {
            // Its owner reads the streams it opened while it waited (T509).
            let mut oc = OwnedConn::default();
            for (stream_id, _) in self.held.remove(&conn_id).unwrap_or_default() {
                if !oc.read.contains(&stream_id.0) {
                    oc.read.push(stream_id.0);
                }
            }
            self.owned.insert(conn_id, oc);
            self.new_owned.push(conn_id);
            return;
        }
        self.open_control_stream(conn_id);
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.resize(64 * 1024, 0);
        for (stream_id, opened) in self.held.remove(&conn_id).unwrap_or_default() {
            self.stream_event(conn_id, stream_id, opened, &mut scratch);
        }
        self.scratch = scratch;
        self.flush_out();
        let _ = self.send_batch(Instant::now());
    }

    /// Connections that ended since the last call, with whether each had been admitted.
    pub fn take_closed(&mut self) -> Vec<(ConnectionId, bool)> {
        std::mem::take(&mut self.closed)
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
        let relays = self.relays.iter().map(|r| {
            let backlog = self.outq.get(&(r.conn_id, r.stream_id)).map_or(0, |q| q.buf.len() - q.off);
            (r.fd.as_fd(), !r.done && backlog < RELAY_BACKLOG, !r.to_engine.is_empty())
        });
        relays.collect()
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
        // On the stack, not a `Vec` per call (T512: one allocation a pass). Both lists hold
        // `BATCH_SIZE` buffers, so the empty fallback is never used.
        let mut lent = self.recv_raw_bufs.iter_mut().zip(self.recv_cmsg_bufs.iter_mut());
        let mut dgram_bufs: [DgramBuf; BATCH_SIZE] = std::array::from_fn(|_| {
            lent.next().map_or_else(|| DgramBuf::new(&mut [], &mut []), |(buf, cmsg_buf)| DgramBuf::new(buf.as_mut_slice(), cmsg_buf.as_mut_slice()))
        });

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
            // What each datagram needs once its bytes are in `send_raw_bufs[i]`: on the stack,
            // not two `Vec`s per round (T512: they were half of an h3 request's allocations).
            let mut heads: [Option<(usize, SocketAddr, Option<std::net::IpAddr>)>; BATCH_SIZE] = [None; BATCH_SIZE];
            let mut count = 0;
            for (head, buf) in heads.iter_mut().zip(self.send_raw_bufs.iter_mut()) {
                let Some(tx) = self.endpoint.poll_transmit(now, buf) else { break };
                *head = Some((tx.size, tx.destination, tx.src_ip));
                count += 1;
            }

            if count == 0 {
                break;
            }

            let bufs = &self.send_raw_bufs;
            let send_msgs: [DgramOut; BATCH_SIZE] = std::array::from_fn(|i| match (heads[i], bufs.get(i)) {
                (Some((size, dst, src)), Some(buf)) => {
                    let mut msg = DgramOut::new(&buf[..size]);
                    msg.dst_addr = Some(dst);
                    msg.src_addr = src;
                    msg
                }
                _ => DgramOut::new(&[]),
            });

            let sent = self.socket.send_batch(&send_msgs[..count])?;
            total_sent += sent;
            if sent < count {
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
        // Every request goes to a frontend's stream engine (T463): a listener without one
        // is a bug in whoever built it, and answering anyway would hide it.
        if self.frontend.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "QUIC listener has no frontend"));
        }
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
                        // `HAProxy` accepts a QUIC connection once, after its handshake
                        // (`quic_accept_push_qc` -> `listener_accept`): one connection and
                        // one session however many request streams it carries.
                        crate::engine::count_global_conn();
                        if self.gated {
                            self.handshaken.push(conn_id);
                            self.pending.insert(conn_id);
                        } else {
                            crate::engine::count_global_sess();
                            self.open_control_stream(conn_id);
                        }
                    }
                }
                TransportEvent::NewConnection { conn_id, remote } => {
                    self.peers.insert(conn_id, remote);
                }
                TransportEvent::StreamOpened { conn_id, stream_id, dir } => {
                    self.stream_event(conn_id, stream_id, dir == StreamDirection::Bidirectional, &mut scratch);
                }
                TransportEvent::StreamReadable { conn_id, stream_id } => {
                    self.stream_event(conn_id, stream_id, false, &mut scratch);
                }
                // A finished stream and a reset stream are both done with; the difference
                // matters to the peer, not to our buffer bookkeeping.
                TransportEvent::StreamFinished { conn_id, stream_id } => {
                    if self.owned.get_mut(&conn_id).is_some_and(|oc| Self::acked(oc, stream_id.0)) {
                        self.owned_news(conn_id, None, None);
                    }
                    if let Some(st) = self.h3.get_mut(&conn_id) {
                        st.req.remove(&stream_id);
                        st.unacked.retain(|s| *s != stream_id);
                    }
                }
                // The client asked us to stop sending the response. (A reset of its request
                // arrives as a read error instead, in `on_readable`.)
                TransportEvent::StreamStopped { conn_id, stream_id, error_code } => {
                    if let Some(oc) = self.owned.get_mut(&conn_id) {
                        Self::acked(oc, stream_id.0);
                    }
                    if !self.owned_news(conn_id, None, Some((stream_id.0, error_code))) {
                        self.abandon_stream(conn_id, stream_id);
                    }
                }
                // Room on a stream an owner writes: it writes the rest (T509).
                TransportEvent::StreamWritable { conn_id, .. } => {
                    self.owned_news(conn_id, None, None);
                }
                TransportEvent::ConnectionClosed { conn_id, .. } => {
                    if let Some(oc) = self.owned.get_mut(&conn_id) {
                        oc.closed = true;
                        if let Some((_, task)) = oc.owner {
                            self.wake.push(task);
                        }
                    }
                    if self.admitted.remove(&conn_id) {
                        self.closed.push((conn_id, true));
                    } else if self.pending.remove(&conn_id) {
                        self.held.remove(&conn_id);
                        if let Some(i) = self.waiting.iter().position(|c| *c == conn_id) {
                            self.waiting.remove(i);
                            self.closed.push((conn_id, false));
                        } else {
                            self.handshaken.retain(|c| *c != conn_id);
                        }
                    }
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
        // Each owner (the mux path) sends its own GOAWAY and closes when idle: woken now, or
        // one whose client went quiet sleeps through the stop until quinn's idle timeout (T511).
        self.wake.extend(self.owned.values().filter_map(|oc| oc.owner.map(|(_, task)| task)));
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
        !self.relays.is_empty() || self.endpoint.connection_count() > 0
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

    /// A stream opened (`opened`) or became readable. On a connection the engine has not
    /// admitted yet it is kept until it is: nothing is read, so the client's flow control
    /// holds the request back.
    fn stream_event(&mut self, conn_id: ConnectionId, stream_id: StreamId, opened: bool, scratch: &mut [u8]) {
        if self.pending.contains(&conn_id) {
            self.held.entry(conn_id).or_default().push((stream_id, opened));
            return;
        }
        if self.owned_news(conn_id, Some(stream_id.0), None) {
            return;
        }
        if opened {
            let st = self.h3.entry(conn_id).or_default();
            st.req.entry(stream_id).or_default();
            st.next_request = st.next_request.max(stream_id.0 + 4);
        }
        // A stream whose first flight already carries the whole request is opened and readable
        // at once, and quinn-proto raises no separate `Readable` for data that arrived before
        // the stream was accepted. Waiting for one left such a request unanswered for ever.
        self.on_readable(conn_id, stream_id, scratch);
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
        let held = st.req.entry(stream_id).or_default();
        held.extend_from_slice(&chunk);

        // HAProxy's per-stream receive buffer is `tune.bufsize` less its 4-byte reserve
        // (`qcm_stream_rx_bufsz`), and a non-DATA frame longer than that is H3_EXCESSIVE_LOAD
        // (`h3.c` `h3_rcv_buf`). A HEADERS frame can be split across datagrams, so
        // `Ok(None)` means wait for more -- but never for more than one buffer of it.
        let cap = crate::buf::get_bufsize().saturating_sub(4);
        match mux_h3::take_request_headers(held, cap) {
            Ok(Some(_)) => {}
            Ok(None) if held.len() <= cap + MAX_FRAME_HEADER => return,
            _ => {
                st.req.remove(&stream_id);
                self.endpoint.close_connection(conn_id, H3Error::ExcessiveLoad as u64, b"");
                return;
            }
        }

        st.answered.push(stream_id);
        let buf = st.req.remove(&stream_id).unwrap_or_default();

        self.start_relay(conn_id, stream_id, &buf, fin);
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
            Err(crate::h3_relay::HeadError::Decompression) => {
                self.endpoint.close_connection(conn_id, H3Error::QpackDecompressionFailed as u64, b"");
                return;
            }
            Err(crate::h3_relay::HeadError::Message) => {
                // A malformed request is a stream error (RFC 9114 section 4.1.2): the
                // stream is aborted and the connection and its other streams go on.
                let _ = self.endpoint.reset_stream(conn_id, stream_id, H3Error::MessageError as u64);
                self.outq.remove(&(conn_id, stream_id));
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
                match crate::raw::send_uncounted(r.fd.as_fd(), &r.to_engine) {
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

/// A QUIC session encapsulating a connection's state, parallel to `TcpSession`.
///
/// Added to satisfy the architectural requirement that a QUIC connection is a distinct session type
/// and not multiplexed into the existing `TcpSession` logic.
pub struct QuicConnection {
    pub conn_id: ibex_quic::ConnectionId,
    pub state: ibex_quic::QuicConnectionState,
}
