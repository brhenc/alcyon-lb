// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! QUIC listening socket, integrating UDP datagram I/O (`DgramSocket`) with `ibex-quic`.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::collections::{HashMap, VecDeque};

use crate::dgram::{DgramBuf, DgramOut, DgramSocket};
use std::os::fd::{AsFd, AsRawFd as _, OwnedFd};

use ibex_proto::h3::H3Error;
use ibex_proto::mux_h3;
use ibex_quic::{
    ConnHandle, QuicConfig, QuicEndpoint, QuicTransport, StreamDirection, StreamId,
    TransportEvent,
};

/// Batch size for datagram I/O.
const BATCH_SIZE: usize = 32;
/// Buffer capacity per datagram (covers maximum standard Ethernet MTU and QUIC padding).
const DGRAM_BUF_SIZE: usize = 2048;
/// Control message buffer capacity per datagram for `IP_PKTINFO`.
const CMSG_BUF_SIZE: usize = 128;
/// How long a soft stop waits for the first request of a connection that has sent none
/// (T558); the mux path's is `engine::H3_STOP_FIRST_REQUEST_MS`.
const STOP_FIRST_REQUEST: Duration = Duration::from_millis(crate::engine::H3_STOP_FIRST_REQUEST_MS as u64);

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
    // The old process's sockets first (`-x`, T558): the reuseport group stays as it was, and
    // the old process stops reading them at its soft stop. More of them than workers (fewer
    // threads now): the rest are closed here, and the old process's copies leave the group
    // when it exits.
    let mut inherited = crate::handover::take_inherited_all(crate::handover::Kind::Quic, addr).into_iter();
    let mut socks = Vec::with_capacity(workers);
    for worker in 0..workers {
        let sock = match inherited.next() {
            Some(fd) => DgramSocket::from_inherited(fd),
            None => DgramSocket::bind(addr)?,
        };
        crate::handover::expose_kind(crate::handover::Kind::Quic, addr, sock.borrowed_fd())?;
        socks.push((addr, worker, sock));
    }
    PREBOUND.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(socks);
    Ok(())
}

/// The half-open connection count the workers' endpoints on `addr` share (T523): `HAProxy`
/// counts `half_open_conn` per frontend and thread group, so its Retry threshold weighs the
/// half-open connections of every thread. One per address, made by the first worker that
/// asks; kept for the process's life (one `u64` per QUIC bind).
static HALF_OPEN: std::sync::Mutex<Vec<(SocketAddr, Arc<std::sync::atomic::AtomicU64>)>> = std::sync::Mutex::new(Vec::new());

fn shared_half_open(addr: SocketAddr) -> Arc<std::sync::atomic::AtomicU64> {
    let mut all = HALF_OPEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, c)) = all.iter().find(|(a, _)| *a == addr) {
        return Arc::clone(c);
    }
    let c = Arc::new(std::sync::atomic::AtomicU64::new(0));
    all.push((addr, Arc::clone(&c)));
    c
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
    /// Each connection's state, in the slot of its handle's index (Q1, design
    /// `quic-transport-2026-11-01.md` §5 (i)): no hashing on the request path. A slot whose
    /// handle has another generation belongs to a connection that is gone.
    conns: Vec<Option<ConnSlot>>,
    /// Set by the engine: each request is handed to the frontend's stream engine.
    frontend: Option<usize>,
    /// Request streams handed to the engine, one per socket pair.
    relays: Vec<Relay>,
    /// Engine ends of socket pairs created since the engine last took them.
    accepted: Vec<AcceptedStream>,
    /// HTTP/3 bytes the stream has not taken yet, and whether the stream ends after them.
    /// Flow control may take a response a part at a time.
    outq: HashMap<(ConnHandle, StreamId), OutQ>,
    /// Read buffer of `pump`, kept between passes.
    scratch: Vec<u8>,
    /// Set by a soft stop: no new connection, and a connection is closed once it is idle.
    stopping: bool,
    /// The listening socket is the next process's now (handed over, T558): not read.
    deaf: bool,
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
    handshaken: Vec<ConnHandle>,
    /// Counted by the engine, held by `maxconn` until it admits them, oldest first.
    waiting: VecDeque<ConnHandle>,
    /// Connections that ended since the engine last looked, and whether each was admitted.
    closed: Vec<(ConnHandle, bool)>,
    /// `tune.ibex.h3-path mux` (T509): an admitted connection is served by an owner session
    /// of the engine through the h3 mux, not by the relay.
    mux: bool,
    /// `tune.quic.fe.stream.max-total` (T525): the request streams one connection carries
    /// before it is closed; 0 is no limit.
    stream_max_total: u32,
    /// Connections admitted since the engine last took them, each to get its owner.
    new_owned: Vec<ConnHandle>,
    /// Owners with transport news since the engine last woke them.
    wake: Vec<ibex_sched::TaskRef>,
    /// An owner wrote to the transport since the last `send_batch`.
    dirty: bool,
}

/// What the listener keeps of one connection (Q1: the maps by connection ID it replaces).
struct ConnSlot {
    conn: ConnHandle,
    /// Where its peer is, so a soft stop can pin its datagrams here.
    peer: Option<SocketAddr>,
    /// The relay path's HTTP/3 state.
    h3: Option<H3State>,
    /// Handshaken or waiting: not served yet.
    pending: bool,
    /// Admitted as a session.
    admitted: bool,
    /// Stream events while it was not admitted yet, replayed when it is.
    held: Vec<(StreamId, bool)>,
    /// Request streams done (their response acknowledged), counted only when
    /// `stream_max_total` is set.
    streams_done: u32,
    /// Served by an owner session.
    owned: Option<OwnedConn>,
}

impl ConnSlot {
    const fn new(conn: ConnHandle) -> Self {
        Self { conn, peer: None, h3: None, pending: false, admitted: false, held: Vec::new(), streams_done: 0, owned: None }
    }
}

/// The slot of `conn`, if it is that connection's.
fn slot_of(conns: &mut [Option<ConnSlot>], conn: ConnHandle) -> Option<&mut ConnSlot> {
    conns.get_mut(conn.index())?.as_mut().filter(|s| s.conn == conn)
}

/// The relay path's HTTP/3 state of `conn`, made if it has none; `None` once the connection
/// is gone (its slot is made at `NewConnection` only).
fn h3_of(conns: &mut [Option<ConnSlot>], conn: ConnHandle) -> Option<&mut H3State> {
    Some(slot_of(conns, conn)?.h3.get_or_insert_with(H3State::default))
}

/// The owned state of `conn`, if an owner session serves it.
fn owned_of(conns: &mut [Option<ConnSlot>], conn: ConnHandle) -> Option<&mut OwnedConn> {
    slot_of(conns, conn)?.owned.as_mut()
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
    conn: ConnHandle,
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
    /// Soft stop: until when a connection with no request yet waits for its first (T558).
    fresh_until: Option<Instant>,
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
        let mut endpoint = QuicEndpoint::from_config(
            Arc::new(config.build_endpoint_config().map_err(|e| io::Error::other(e.to_string()))?),
            server_config,
            &config,
        );
        if worker.is_some() {
            endpoint.share_half_open(shared_half_open(addr));
        }
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
            conns: Vec::new(),
            frontend: None,
            relays: Vec::new(),
            accepted: Vec::new(),
            outq: HashMap::new(),
            scratch: Vec::new(),
            stopping: false,
            deaf: false,
            pinned: Vec::new(),
            released: Vec::new(),
            gated: false,
            handshaken: Vec::new(),
            waiting: VecDeque::new(),
            closed: Vec::new(),
            mux: false,
            stream_max_total: 0,
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

    /// `tune.quic.fe.stream.max-total` (T525): a connection that has finished this many request
    /// streams is closed with `H3_NO_ERROR` (`HAProxy` stops granting stream credit at that
    /// number and ends the connection when they are done). 0 is no limit.
    pub fn set_stream_max_total(&mut self, n: u32) {
        self.stream_max_total = n;
    }

    /// Connections admitted since the last call, each for the engine to give an owner
    /// session ([`QuicListener::set_owner`]).
    pub fn take_new_owned(&mut self) -> Vec<ConnHandle> {
        std::mem::take(&mut self.new_owned)
    }

    /// The owner session of `conn_id` is entry `idx`, task `task`: it is woken with the
    /// transport's news of the connection.
    pub fn set_owner(&mut self, conn: ConnHandle, idx: u32, task: ibex_sched::TaskRef) {
        if let Some(oc) = owned_of(&mut self.conns, conn) {
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
    pub fn peer_of(&self, conn: ConnHandle) -> SocketAddr {
        self.conns.get(conn.index()).and_then(Option::as_ref).filter(|s| s.conn == conn).and_then(|s| s.peer).unwrap_or(self.addr)
    }

    /// The owner of `conn_id` reads what the client sent into its mux (T509): `STOP_SENDING`s,
    /// then each stream with news, as far as the mux has room for it (§2.3: the client's
    /// window holds the rest back). Our control stream is opened on the first pass.
    pub fn owner_recv(&mut self, conn_id: ConnHandle, mux: &mut mux_h3::H3MuxContext, now: u64) -> OwnerConn {
        let Some(oc) = owned_of(&mut self.conns, conn_id) else { return OwnerConn::Closed };
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
    pub fn owner_send(&mut self, conn_id: ConnHandle, mux: &mut mux_h3::H3MuxContext, done: impl Fn(u64) -> bool) {
        if owned_of(&mut self.conns, conn_id).is_none() {
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
                    if let Some(oc) = owned_of(&mut self.conns, conn_id) {
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
    pub fn owner_unacked(&self, conn_id: ConnHandle) -> bool {
        self.conns
            .get(conn_id.index())
            .and_then(Option::as_ref)
            .filter(|s| s.conn == conn_id)
            .and_then(|s| s.owned.as_ref())
            .is_some_and(|oc| !oc.unacked.is_empty())
    }

    /// Stream `id` of an owned connection needs no acknowledgement any more (its FIN was, or
    /// the client stopped it): whether it was waiting for one.
    fn acked(oc: &mut OwnedConn, id: u64) -> bool {
        let Some(i) = oc.unacked.iter().position(|s| *s == id) else { return false };
        oc.unacked.swap_remove(i);
        true
    }

    /// Closes connection `conn_id`, its owner gone or ending it (`H3_NO_ERROR`).
    pub fn owner_close(&mut self, conn_id: ConnHandle) {
        let Some(oc) = slot_of(&mut self.conns, conn_id).and_then(|s| s.owned.take()) else { return };
        if oc.closed {
            // The connection had ended: its slot was kept for the owner only.
            self.conns[conn_id.index()] = None;
        } else {
            self.endpoint.close_connection(conn_id, H3_NO_ERROR, b"");
            self.dirty = true;
        }
    }

    /// Records transport news of an owned connection for its owner, and wakes it.
    fn owned_news(&mut self, conn_id: ConnHandle, read: Option<u64>, stopped: Option<(u64, u64)>) -> bool {
        let Some(oc) = owned_of(&mut self.conns, conn_id) else { return false };
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
        self.conns.iter().flatten().filter_map(|c| c.h3.as_ref()).flat_map(|st| st.req.values()).map(Vec::len).sum()
    }

    /// The connections for `show quic` (T524), read-only. The local address is the listener's
    /// port with the IP the client reached when the kernel said so.
    #[must_use]
    pub fn show_infos(&self, worker: usize) -> Vec<crate::mailbox::QuicSnap> {
        self.endpoint
            .connection_infos()
            .into_iter()
            .map(|i| crate::mailbox::QuicSnap {
                worker,
                fe: self.frontend,
                id: i.id,
                phase: i.state,
                local: SocketAddr::new(i.local_ip.unwrap_or(self.addr.ip()), self.addr.port()),
                peer: i.remote,
                lost_packets: i.lost_packets,
            })
            .collect()
    }

    /// Makes the engine decide, per connection, when it is served (T504): a connection that
    /// completes its HTTP/3 handshake waits until [`QuicListener::admit_next`] says so.
    pub fn gate_connections(&mut self) {
        self.gated = true;
    }

    /// Connections that completed their handshake since the last call, now waiting for
    /// admission, for the engine to count (or [`QuicListener::refuse`]).
    pub fn take_handshaken(&mut self) -> Vec<ConnHandle> {
        let new = std::mem::take(&mut self.handshaken);
        self.waiting.extend(new.iter().copied());
        new
    }

    /// Closes a connection the engine will not count (`global maxconn` is reached, as
    /// `HAProxy`'s listener refuses it).
    pub fn refuse(&mut self, conn_id: ConnHandle) {
        if let Some(slot) = slot_of(&mut self.conns, conn_id) {
            slot.pending = false;
            slot.held = Vec::new();
        }
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
        // A connection that ended while it waited left `waiting` then.
        let Some(slot) = slot_of(&mut self.conns, conn_id) else { return };
        slot.pending = false;
        slot.admitted = true;
        let held = std::mem::take(&mut slot.held);
        if self.mux {
            // Its owner reads the streams it opened while it waited (T509).
            let mut oc = OwnedConn::default();
            for (stream_id, _) in held {
                if !oc.read.contains(&stream_id.0) {
                    oc.read.push(stream_id.0);
                }
            }
            slot.owned = Some(oc);
            self.new_owned.push(conn_id);
            return;
        }
        self.open_control_stream(conn_id);
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.resize(64 * 1024, 0);
        for (stream_id, opened) in held {
            self.stream_event(conn_id, stream_id, opened, &mut scratch);
        }
        self.scratch = scratch;
        self.flush_out();
        // Sent with the rest of the pass's datagrams (Q1: one send per pass).
        self.dirty = true;
    }

    /// Connections that ended since the last call, with whether each had been admitted.
    pub fn take_closed(&mut self) -> Vec<(ConnHandle, bool)> {
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
            let backlog = self.outq.get(&(r.conn, r.stream_id)).map_or(0, |q| q.buf.len() - q.off);
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

        let n = if self.deaf { 0 } else { self.socket.recv_batch(&mut dgram_bufs)? };
        Self::dispatch(&mut self.endpoint, now, &dgram_bufs, n);
        // Datagrams of the connections a soft stop pinned. A pinned socket is drained empty
        // each time, like the listening one, so level-triggered readiness cannot spin.
        let mut total = n;
        for (peer, sock) in &self.pinned {
            loop {
                // WouldBlock is "drained"; any other error on a socket we may drop is too.
                let got = sock.recv_batch(&mut dgram_bufs).unwrap_or(0);
                if got == 0 {
                    break;
                }
                // Between its bind and its connect, a pinned socket was an unconnected member
                // of the reuseport group: a datagram of another client queued on it then is
                // not ours to answer (refused, it would be a lost request). Its client
                // retransmits to the socket it belongs to.
                for d in dgram_bufs.iter_mut().take(got) {
                    if d.src_addr != Some(*peer) {
                        d.truncated = true;
                    }
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
        // HAProxy's `quic_lstnr_may_set_src`: the source address goes with each datagram only
        // on a wildcard bind, where the kernel would otherwise pick the route's source and a
        // client that reached another local address drops the reply (T552, VV-27). A bind to
        // one address sends no control message.
        let wildcard = self.addr.ip().is_unspecified();

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
                    msg.src_addr = if wildcard { src } else { None };
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
        // A connection this timer drained (after a close of ours) is forgotten, and its
        // `ConnectionClosed` queued, now: left to the next `poll_timeout`, no `serve` followed
        // it and the event waited for an unrelated datagram, the slot and its counters with it
        // (T562: an idle h3 connection closed at `timeout client`).
        self.endpoint.update_next_timeout();
    }

    /// Returns the next earliest timer expiry instant: the connections something reached since
    /// the last call are asked for theirs now, once each (Q1).
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let t = self.endpoint.poll_timeout();
        if !self.stopping {
            return t;
        }
        // The end of a fresh connection's wait for its first request (T558).
        let fresh = self.conns.iter().flatten().filter_map(|s| s.h3.as_ref()).filter(|st| st.next_request == 0).filter_map(|st| st.fresh_until).min();
        match (t, fresh) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
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
        self.serve(now)?;
        self.send_batch(now)?;
        Ok(())
    }

    /// [`QuicListener::pump`] without the send: the engine sends once a pass, after the owner
    /// sessions ran (Q1), so what they wrote and the acknowledgements of what was read leave
    /// together. [`QuicListener::take_dirty`] is true after it.
    ///
    /// # Errors
    /// As [`QuicListener::pump`].
    #[allow(clippy::too_many_lines)]
    pub fn serve(&mut self, now: Instant) -> io::Result<()> {
        // Every request goes to a frontend's stream engine (T463): a listener without one
        // is a bug in whoever built it, and answering anyway would hide it.
        if self.frontend.is_none() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "QUIC listener has no frontend"));
        }
        self.recv_batch(now)?;
        self.dirty = true;

        // Reused across passes: a relay reads the engine's response through it, 64 KB a time.
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.resize(64 * 1024, 0);
        while let Some(ev) = self.endpoint.poll_event() {
            match ev {
                TransportEvent::HandshakeComplete { conn, alpn, .. } => {
                    // Only speak HTTP/3 if that is what was negotiated. Anything else is a
                    // connection we have no layer for, and pretending otherwise would send
                    // a client frames it never asked for.
                    if alpn.as_deref() == Some(b"h3".as_slice()) {
                        // `HAProxy` accepts a QUIC connection once, after its handshake
                        // (`quic_accept_push_qc` -> `listener_accept`): one connection and
                        // one session however many request streams it carries.
                        crate::engine::count_global_conn();
                        if self.gated {
                            self.handshaken.push(conn);
                            if let Some(slot) = slot_of(&mut self.conns, conn) {
                                slot.pending = true;
                            }
                        } else {
                            crate::engine::count_global_sess();
                            self.open_control_stream(conn);
                        }
                    }
                }
                TransportEvent::NewConnection { conn, remote, .. } => {
                    // A new connection in this slot: what a gone one left there goes.
                    let i = conn.index();
                    if self.conns.len() <= i {
                        self.conns.resize_with(i + 1, || None);
                    }
                    let mut slot = ConnSlot::new(conn);
                    slot.peer = Some(remote);
                    self.conns[i] = Some(slot);
                    // One the stop did not know of (none is accepted after it, but an Initial
                    // read before it may surface here): pinned too, or its datagrams may be
                    // hashed to the next process.
                    if self.stopping && !self.pinned.iter().any(|(p, _)| *p == remote) {
                        let local = self.endpoint.local_ip_of(conn);
                        self.pin(remote, local);
                    }
                }
                TransportEvent::StreamOpened { conn, stream_id, dir } => {
                    self.stream_event(conn, stream_id, dir == StreamDirection::Bidirectional, &mut scratch);
                }
                TransportEvent::StreamReadable { conn, stream_id } => {
                    self.stream_event(conn, stream_id, false, &mut scratch);
                }
                // A finished stream and a reset stream are both done with; the difference
                // matters to the peer, not to our buffer bookkeeping.
                TransportEvent::StreamFinished { conn, stream_id } => {
                    let Some(slot) = slot_of(&mut self.conns, conn) else { continue };
                    // A client-initiated bidirectional stream (a request) is done once its
                    // response is acknowledged: the last one the limit allows ends the connection.
                    let mut close = false;
                    if self.stream_max_total != 0 && stream_id.0.trailing_zeros() >= 2 {
                        slot.streams_done += 1;
                        close = slot.streams_done >= self.stream_max_total;
                    }
                    let acked = slot.owned.as_mut().is_some_and(|oc| Self::acked(oc, stream_id.0));
                    if let Some(st) = slot.h3.as_mut() {
                        st.req.remove(&stream_id);
                        st.unacked.retain(|s| *s != stream_id);
                    }
                    if close {
                        self.endpoint.close_connection(conn, H3_NO_ERROR, b"");
                    }
                    if acked {
                        self.owned_news(conn, None, None);
                    }
                }
                // The client asked us to stop sending the response. (A reset of its request
                // arrives as a read error instead, in `on_readable`.)
                TransportEvent::StreamStopped { conn, stream_id, error_code } => {
                    if let Some(oc) = owned_of(&mut self.conns, conn) {
                        Self::acked(oc, stream_id.0);
                    }
                    if !self.owned_news(conn, None, Some((stream_id.0, error_code))) {
                        self.abandon_stream(conn, stream_id);
                    }
                }
                // Room on a stream an owner writes: it writes the rest (T509).
                TransportEvent::StreamWritable { conn, .. } => {
                    self.owned_news(conn, None, None);
                }
                TransportEvent::ConnectionClosed { conn, .. } => {
                    let i = conn.index();
                    if let Some(slot) = slot_of(&mut self.conns, conn) {
                        if let Some(oc) = slot.owned.as_mut() {
                            oc.closed = true;
                            if let Some((_, task)) = oc.owner {
                                self.wake.push(task);
                            }
                        }
                        if std::mem::take(&mut slot.admitted) {
                            self.closed.push((conn, true));
                        } else if std::mem::take(&mut slot.pending) {
                            slot.held = Vec::new();
                            if let Some(i) = self.waiting.iter().position(|c| *c == conn) {
                                self.waiting.remove(i);
                                self.closed.push((conn, false));
                            } else {
                                self.handshaken.retain(|c| *c != conn);
                            }
                        }
                        // Its owner, if any, still has to see it closed (`owner_close`
                        // frees the slot then).
                        if slot.owned.is_some() {
                            slot.h3 = None;
                            slot.peer = None;
                            slot.streams_done = 0;
                        } else {
                            self.conns[i] = None;
                        }
                    }
                    for r in &mut self.relays {
                        if r.conn == conn {
                            r.done = true;
                        }
                    }
                    if !self.outq.is_empty() {
                        self.outq.retain(|(c, _), _| *c != conn);
                    }
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
        Ok(())
    }

    /// Soft stop, HAProxy's `soft_stop()` for a QUIC listener: refuse new connections, tell
    /// every established HTTP/3 client with a GOAWAY that it will get no further request,
    /// and close each connection as soon as the responses it owes have been delivered.
    /// The UDP socket stays registered, because the datagrams of those connections arrive on it.
    pub fn begin_soft_stop(&mut self) {
        // Called once, by the engine, when the soft stop begins.
        self.stopping = true;
        // Handed over, the listening socket is the next process's from now on: its datagrams,
        // new connections' Initials included, are for that process to read (T558). The engine
        // takes it out of its poller. This process's own connections are pinned below.
        self.deaf = crate::handover::handed_over();
        self.endpoint.stop_accepting();
        self.pin_peers();
        // A connection with no request yet gets its GOAWAY after its first one, or at the end
        // of its grace (`drain_idle_connections`, T558).
        let fresh_until = Instant::now() + STOP_FIRST_REQUEST;
        for slot in self.conns.iter_mut().flatten() {
            if let Some(st) = slot.h3.as_mut() {
                if st.next_request == 0 {
                    st.fresh_until = Some(fresh_until);
                } else {
                    Self::send_goaway(&mut self.endpoint, slot.conn, st);
                }
            }
        }
        // Each owner (the mux path) sends its own GOAWAY and closes when idle: woken now, or
        // one whose client went quiet sleeps through the stop until quinn's idle timeout (T511).
        self.wake.extend(self.conns.iter().flatten().filter_map(|s| s.owned.as_ref()?.owner.map(|(_, task)| task)));
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
        let endpoint = &self.endpoint;
        let mut want: Vec<(SocketAddr, Option<std::net::IpAddr>)> =
            self.conns.iter().flatten().filter_map(|s| Some((s.peer?, endpoint.local_ip_of(s.conn)))).collect();
        want.sort();
        want.dedup_by_key(|w| w.0);
        for (peer, local) in want {
            self.pin(peer, local);
        }
    }

    /// One connected socket for `peer`, bound to the address the client reached (`local`) on a
    /// wildcard bind, as `HAProxy`'s `qc_alloc_fd` binds the connection's local address: bound
    /// to the wildcard, the kernel gives it the route's source address, and a client of
    /// another local address does not match it (T552 note, VV-27).
    fn pin(&mut self, peer: SocketAddr, local: Option<std::net::IpAddr>) {
        self.pin_with(peer, local, |_| {});
    }

    /// [`QuicListener::pin`] with `between` run after the bind and before the connect, given
    /// the address bound: tests use it to queue another client's datagram on the socket
    /// while it is an unconnected member of the group, the race `recv_batch` filters (T558).
    #[doc(hidden)]
    pub fn pin_with(&mut self, peer: SocketAddr, local: Option<std::net::IpAddr>, between: impl FnOnce(SocketAddr)) {
        let at = match local {
            Some(ip) if self.addr.ip().is_unspecified() => SocketAddr::new(ip, self.addr.port()),
            _ => self.addr,
        };
        let Ok(sock) = DgramSocket::bind(at) else { return };
        between(at);
        if sock.connect(peer).is_ok() {
            self.pinned.push((peer, sock));
        }
    }

    /// Drops the pinned socket of a peer with no connection left.
    fn release_pinned(&mut self) {
        if self.pinned.is_empty() {
            return;
        }
        let live: Vec<SocketAddr> = self.conns.iter().flatten().filter_map(|s| s.peer).collect();
        let released = &mut self.released;
        self.pinned.retain(|(peer, sock)| {
            let keep = live.contains(peer);
            if !keep {
                released.push(sock.as_raw_fd());
            }
            keep
        });
    }

    /// Whether the listening socket is no longer read (handed over, soft stop; T558).
    #[must_use]
    pub const fn is_deaf(&self) -> bool {
        self.deaf
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
    fn send_goaway(endpoint: &mut QuicEndpoint, conn_id: ConnHandle, st: &mut H3State) {
        if let (Some(control), false) = (st.control, std::mem::replace(&mut st.draining, true)) {
            let bytes = mux_h3::encode_goaway(st.next_request);
            let _ = endpoint.write_stream(conn_id, control, &bytes, false);
        }
    }

    /// Closes, with `H3_NO_ERROR`, every connection that owes no response, after its GOAWAY.
    /// One that has sent no request yet waits for its first, until its `fresh_until` (T558).
    fn drain_idle_connections(&mut self) {
        let mut idle = Vec::new();
        let now = Instant::now();
        for slot in self.conns.iter_mut().flatten() {
            let Some(st) = slot.h3.as_mut() else { continue };
            if st.next_request == 0 && st.fresh_until.is_some_and(|t| now < t) {
                continue;
            }
            // Its wait is over (a request came, or the time is up): no timer for it any more.
            st.fresh_until = None;
            Self::send_goaway(&mut self.endpoint, slot.conn, st);
        }
        for slot in self.conns.iter().flatten() {
            let Some(st) = slot.h3.as_ref() else { continue };
            if st.fresh_until.is_some() {
                continue;
            }
            let conn_id = slot.conn;
            let owes = !st.unacked.is_empty()
                || st.req.values().any(|b| !b.is_empty())
                || self.relays.iter().any(|r| r.conn == conn_id)
                || self.outq.keys().any(|(c, _)| *c == conn_id);
            if !owes {
                idle.push(conn_id);
            }
        }
        for conn_id in idle {
            self.endpoint.close_connection(conn_id, H3_NO_ERROR, b"");
        }
    }

    /// Queues a whole response; [`QuicListener::flush_out`] writes it as flow control allows.
    fn respond(&mut self, conn_id: ConnHandle, stream_id: StreamId, resp: &[u8]) {
        self.queue_out(conn_id, stream_id, resp, true);
    }

    /// Queues HTTP/3 bytes for a stream, and its end when `fin`.
    fn queue_out(&mut self, conn_id: ConnHandle, stream_id: StreamId, bytes: &[u8], fin: bool) {
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
            if let Some(st) = slot_of(&mut self.conns, conn_id).and_then(|s| s.h3.as_mut()) {
                st.unacked.push(stream_id);
            }
        }
    }

    /// Opens our unidirectional control stream and sends SETTINGS.
    ///
    /// RFC 9114 §6.2.1 requires the control stream be opened before any request is answered,
    /// and that SETTINGS be its first frame.
    fn open_control_stream(&mut self, conn_id: ConnHandle) {
        let Some(st) = h3_of(&mut self.conns, conn_id) else { return };
        if st.control.is_some() {
            return;
        }
        let Ok(sid) = self.endpoint.open_stream(conn_id, StreamDirection::Unidirectional) else {
            return;
        };
        let stopping = self.stopping;
        if let Some(st) = h3_of(&mut self.conns, conn_id) {
            st.control = Some(sid);
            // Its handshake ended during a soft stop: it waits for its first request (T558).
            if stopping {
                st.fresh_until = Some(Instant::now() + STOP_FIRST_REQUEST);
            }
        }
        let bytes = mux_h3::encode_control_stream_open();
        let _ = self.endpoint.write_stream(conn_id, sid, &bytes, false);
    }

    /// A stream opened (`opened`) or became readable. On a connection the engine has not
    /// admitted yet it is kept until it is: nothing is read, so the client's flow control
    /// holds the request back.
    fn stream_event(&mut self, conn_id: ConnHandle, stream_id: StreamId, opened: bool, scratch: &mut [u8]) {
        if let Some(slot) = slot_of(&mut self.conns, conn_id).filter(|s| s.pending) {
            slot.held.push((stream_id, opened));
            return;
        }
        if self.owned_news(conn_id, Some(stream_id.0), None) {
            return;
        }
        let Some(st) = h3_of(&mut self.conns, conn_id) else { return };
        if opened {
            st.req.entry(stream_id).or_default();
            st.next_request = st.next_request.max(stream_id.0 + 4);
        }
        // A stream whose first flight already carries the whole request is opened and readable
        // at once, and quinn-proto raises no separate `Readable` for data that arrived before
        // the stream was accepted. Waiting for one left such a request unanswered for ever.
        self.on_readable(conn_id, stream_id, scratch);
    }

    /// Reads whatever is available on a stream and, on a request stream, answers it.
    fn on_readable(&mut self, conn_id: ConnHandle, stream_id: StreamId, scratch: &mut [u8]) {
        let relay = self.relays.iter().position(|r| r.conn == conn_id && r.stream_id == stream_id);
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

        let Some(st) = h3_of(&mut self.conns, conn_id) else { return };
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
    fn abandon_stream(&mut self, conn_id: ConnHandle, stream_id: StreamId) {
        // Its request and its wait for an acknowledgement go (a connection the relay never
        // gave HTTP/3 state has neither). One expression: there is no other branch to take.
        let st = slot_of(&mut self.conns, conn_id).and_then(|s| s.h3.as_mut());
        st.map(|st| (st.req.remove(&stream_id), st.unacked.retain(|s| *s != stream_id)));
        for r in &mut self.relays {
            if r.conn == conn_id && r.stream_id == stream_id {
                r.done = true;
            }
        }
        self.outq.remove(&(conn_id, stream_id));
    }

    /// Hands a request whose HEADERS arrived to the engine: converts it to its HTTP/1 head
    /// and opens the socket pair the engine adopts as a client connection.
    fn start_relay(&mut self, conn_id: ConnHandle, stream_id: StreamId, buf: &[u8], fin: bool) {
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
            conn: conn_id,
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
        let peer = self.peer_of(conn_id);
        self.accepted.push(AcceptedStream { fd: theirs, peer, local: self.addr });
        self.relays.push(relay);
    }

    /// Moves request bytes to the engine and the engine's response to the client.
    fn advance_relays(&mut self, scratch: &mut [u8]) {
        // Request bodies held back by `on_readable` while the engine was behind.
        let waiting: Vec<(ConnHandle, StreamId)> = self
            .relays
            .iter()
            .filter(|r| !r.client_fin && !r.done && r.to_engine.len() < RELAY_BACKLOG)
            .map(|r| (r.conn, r.stream_id))
            .collect();
        for (c, sid) in waiting {
            self.on_readable(c, sid, scratch);
        }

        let mut out: Vec<(ConnHandle, StreamId, Vec<u8>, bool)> = Vec::new();
        let mut cancelled: Vec<(ConnHandle, StreamId)> = Vec::new();
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
            let backlog = self.outq.get(&(r.conn, r.stream_id)).map_or(0, |q| q.buf.len() - q.off);
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
                        // here. One that never started is the request the engine dropped (a
                        // reused server connection that closed under it, T517/T523): the
                        // stream is reset with H3_REQUEST_CANCELLED, as the mux path resets
                        // a stream that ends without its response and as `HAProxy` does.
                        r.done = true;
                        if r.resp.eof().is_err() && !r.resp.head_sent {
                            cancelled.push((r.conn, r.stream_id));
                        }
                    }
                }
                if r.resp.is_done() {
                    r.done = true;
                }
            }
            if (!frames.is_empty() || r.done) && !cancelled.last().is_some_and(|&(c, sid)| c == r.conn && sid == r.stream_id) {
                out.push((r.conn, r.stream_id, frames, r.done));
            }
        }
        for (c, sid, frames, fin) in out {
            self.queue_out(c, sid, &frames, fin);
        }
        for (c, sid) in cancelled {
            let _ = self.endpoint.reset_stream(c, sid, H3Error::RequestCancelled as u64);
            self.outq.remove(&(c, sid));
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
