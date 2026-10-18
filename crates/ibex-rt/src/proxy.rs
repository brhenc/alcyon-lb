// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy 1.0.2 process_cli(), process_srv() and process_task()
// (haproxy.c), and from mainline's src/stream.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The stream engine for `mode tcp`.
//!
//! `HAProxy` 1.0.2's `process_cli()` and `process_srv()` are the specification. Each
//! inspects both sides, advances at most one state, and returns whether anything
//! changed; `process_task()` runs them until neither does. That "iterate to quiescence"
//! shape is preserved here, because it is what makes the two directions compose without
//! either needing to know the other's internals.
//!
//! The mux layer is absent by design, not by omission: in `mode tcp` `HAProxy` uses
//! `mux_pt`, the passthrough mux, which adds no framing. The seam is real ([`Mux`] in
//! `ibex-proto`), and an H1 mux slots in at exactly the point where this module moves
//! bytes between [`Buf`]s.
//!
//! [`Mux`]: ibex_proto::Mux

use std::sync::Arc;
use crate::buf::Buf;
use crate::raw::{self, Io};
use crate::txn::{self, HttpTxn};
use crate::xprt::{ClientXprt, ServerXprt};
use ibex_proto::parser::ParserKind;
use ibex_config::Mode;
use ibex_proto::endpoint::ScState;
use ibex_proto::htx::HtxBlock;
use ibex_proto::h2::H2_CONN_PREFACE;
use ibex_proto::mux::Mux;
use ibex_proto::mux_h2::{H2MuxContext, MuxH2};
use ibex_proto::{rewrite_header_block, CompiledExp};
use ibex_sample::{Expr, Registry, SampleContext};
use ibex_sched::Tick;
use ibex_stick_table::StickKey;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Instant;

/// Why a connection that was to carry a PROXY header did not get one past the parser:
/// `HAProxy`'s `CO_ER_PRX_*` codes, with the texts of `conn_err_code_str`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProxyHdrError {
    /// The client closed before sending a byte (`CO_ER_PRX_EMPTY`).
    Empty,
    /// The read failed, as on a reset (`CO_ER_PRX_ABORT`).
    Abort,
    /// `timeout client` expired with no header (`CO_ER_PRX_TIMEOUT`).
    Timeout,
    /// Some of a header, and `HAProxy` does not wait for the rest (`CO_ER_PRX_TRUNCATED`).
    Truncated,
    /// Neither a v1 line nor a v2 signature (`CO_ER_PRX_NOT_HDR`).
    NotHdr,
    /// A header that does not hold together (`CO_ER_PRX_BAD_HDR`).
    BadHdr,
    /// A v1 protocol that is not `TCP4`, `TCP6` or `UNKNOWN` (`CO_ER_PRX_BAD_PROTO`).
    BadProto,
    /// The header was good, and the `tcp-request session` rules it let run refused the
    /// connection (T157). `conn_complete_session` fails with no error code
    /// (`CO_ER_NONE`), so `session_kill_embryonic` logs its text, "Success" (measured:
    /// "10.1.2.3:42 [...] fe/1: Success"), and nothing under `option dontlognull`.
    SessionRefused,
}

impl ProxyHdrError {
    /// The text `HAProxy` logs after `fe/<listener>: `.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Empty => "Connection closed while waiting for PROXY protocol header",
            Self::Abort => "Connection error while waiting for PROXY protocol header",
            Self::Timeout => "Timeout while waiting for PROXY protocol header",
            Self::Truncated => "Truncated PROXY protocol header received",
            Self::NotHdr => "Received something which does not look like a PROXY protocol header",
            Self::BadHdr => "Received an invalid PROXY protocol header",
            Self::BadProto => "Received an unhandled protocol in the PROXY protocol header",
            Self::SessionRefused => "Success",
        }
    }

    /// `conn->err_code` (`CO_ER_*`): what `fc_err` reads. A refusal by a `tcp-request session`
    /// rule has none.
    #[must_use]
    pub const fn code(self) -> i64 {
        match self {
            Self::Empty => 11,
            Self::Abort => 12,
            Self::Timeout => 13,
            Self::Truncated => 14,
            Self::NotHdr => 15,
            Self::BadHdr => 16,
            Self::BadProto => 17,
            Self::SessionRefused => 0,
        }
    }

    /// `conn_err_code_name`: what `fc_err_name` reads.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Empty => "PRX_EMPTY",
            Self::Abort => "PRX_ABORT",
            Self::Timeout => "PRX_TIMEOUT",
            Self::Truncated => "PRX_TRUNCATED",
            Self::NotHdr => "PRX_NOT_HDR",
            Self::BadHdr => "PRX_BAD_HDR",
            Self::BadProto => "PRX_BAD_PROTO",
            Self::SessionRefused => "",
        }
    }

    /// The code for a parser error, as `conn_recv_proxy` picks it.
    #[must_use]
    pub fn from_parse(e: &ibex_proto::ProxyParseError) -> Self {
        use ibex_proto::ProxyParseError as E;
        match e {
            E::InvalidSignature | E::UnsupportedVersion(_) => Self::NotHdr,
            E::InvalidProtocol => Self::BadProto,
            _ => Self::BadHdr,
        }
    }

    /// `option dontlognull` drops the lines of a client that sent nothing (`session_kill_embryonic`
    /// checks the code before a timeout has been given one, so that is silent too), and
    /// that of a connection its session rules refused (no error code at all).
    #[must_use]
    pub fn is_null(self) -> bool {
        matches!(self, Self::Empty | Self::Abort | Self::Timeout | Self::SessionRefused)
    }
}

/// Why a session ended. Reported to logs and to `show sess`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Ending {
    /// Both directions completed normally.
    Complete,
    /// The client went away.
    ClientAbort,
    /// The server went away.
    ServerAbort,
    /// No server could be reached after exhausting retries.
    ConnectFailed,
    /// A timeout fired. Carries which one, for the log.
    Timeout(Which),
    /// An unexpected I/O error.
    Error,
}

/// Which side a timeout belongs to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Which {
    Client,
    Server,
    Connect,
}

/// What a side wants from the poller next.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Want {
    pub read: bool,
    pub write: bool,
}

/// Timeouts, in milliseconds. Zero means "not set", matching 1.0's config semantics.
#[derive(Copy, Clone, Debug, Default)]
pub struct Timeouts {
    pub client: u32,
    pub server: u32,
    pub connect: u32,
}

/// The timeouts `set-timeout` gave one stream (`stream_set_timeout`, src/stream.c).
#[derive(Clone, Copy, Debug)]
pub struct TimeoutsSet {
    /// What each rule set, in ms, indexed by [`ibex_sample::TimeoutKind`]; 0: not set.
    pub ms: [u32; 6],
    /// The session's timeouts before the first rule changed them: the next stream starts
    /// from these, as a new stream in `HAProxy` starts from its proxies'.
    pub before: Timeouts,
}

/// A request waiting in its backend's queue because every server is at its `maxconn`
/// (`pendconn`, src/queue.c). It leaves the queue when it is given a slot, when `deadline`
/// (`timeout queue`) passes (`503`, `sQ`), or with the session; dropping it is leaving.
pub struct QueueWait {
    /// When `timeout queue` ends (`ETERNITY`: it does not).
    pub deadline: Tick,
    /// The backend's queue length, this request in it, for `%bq` in the log.
    pub pos: u32,
    task: ibex_sched::TaskRef,
    stats: Arc<Vec<crate::engine::ProxyStats>>,
    be_idx: usize,
}

thread_local! {
    /// The requests queued on this thread, oldest first, with the backend each waits for:
    /// what `Engine::wake_queued` hands slots to. (A session never leaves its thread.)
    static QUEUED: std::cell::RefCell<Vec<(ibex_sched::TaskRef, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl QueueWait {
    /// Puts the request of `task` in the queue of backend `be_idx`; `stats` are the
    /// backend's, where `qcur` and `qmax` are kept.
    #[must_use]
    pub fn enter(task: ibex_sched::TaskRef, be_idx: usize, stats: Arc<Vec<crate::engine::ProxyStats>>, deadline: Tick) -> Box<QueueWait> {
        let st = &stats[0];
        let pos = st.queue_cur.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        st.queue_max.fetch_max(pos, std::sync::atomic::Ordering::Relaxed);
        QUEUED.with(|q| q.borrow_mut().push((task, be_idx)));
        Box::new(QueueWait { deadline, pos, task, stats, be_idx })
    }

    /// Whether anything is queued on this thread.
    #[must_use]
    pub fn any() -> bool {
        QUEUED.with(|q| !q.borrow().is_empty())
    }

    /// The tasks to wake: for each backend, the oldest `free(be)` of those waiting on it.
    pub fn take_due(mut free: impl FnMut(usize) -> usize) -> Vec<ibex_sched::TaskRef> {
        QUEUED.with(|q| {
            let q = q.borrow();
            let mut left: Vec<(usize, usize)> = Vec::new();
            let mut due = Vec::new();
            for &(task, be) in q.iter() {
                let slot = if let Some(i) = left.iter().position(|(b, _)| *b == be) {
                    i
                } else {
                    left.push((be, free(be)));
                    left.len() - 1
                };
                if left[slot].1 > 0 {
                    left[slot].1 -= 1;
                    due.push(task);
                }
            }
            due
        })
    }
}

impl Drop for QueueWait {
    fn drop(&mut self) {
        self.stats[0].queue_cur.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let (task, be) = (self.task, self.be_idx);
        let _ = QUEUED.try_with(|q| q.borrow_mut().retain(|&(t, b)| !(t == task && b == be)));
    }
}

/// The client side of a session: its socket, or, for a stream of an HTTP/2 connection
/// (T280), none of its own -- the connection's owner entry reads and writes the socket, and
/// what the stream does to "its" client connection (a FIN, a reset) is done by the owner
/// ([`H2Child::conn_end`]).
pub enum ClientSide {
    Fd(OwnedFd),
    H2Child,
}

impl ClientSide {
    #[inline]
    fn fd(&self) -> Option<BorrowedFd<'_>> {
        match self {
            ClientSide::Fd(f) => Some(f.as_fd()),
            ClientSide::H2Child => None,
        }
    }

    /// A read from the socket; nothing for a stream of an HTTP/2 connection.
    fn recv(&self, xprt: &mut ClientXprt, dst: &mut [u8]) -> io::Result<Io> {
        match self {
            ClientSide::Fd(f) => xprt.recv(f.as_fd(), dst),
            ClientSide::H2Child => Ok(Io::WouldBlock),
        }
    }

    /// A write to the socket; nothing for a stream of an HTTP/2 connection.
    fn send(&self, xprt: &mut ClientXprt, src: &[u8]) -> io::Result<Io> {
        match self {
            ClientSide::Fd(f) => xprt.send(f.as_fd(), src),
            ClientSide::H2Child => Ok(Io::WouldBlock),
        }
    }

    fn shutdown_read(&self) {
        if let ClientSide::Fd(f) = self {
            raw::shutdown_read(f.as_fd());
        }
    }
}

/// A session's part in an HTTP/2 connection (T280): `HAProxy`'s `h2c` (the owner, the entry
/// that accepted the socket: the mux, the socket, the connection's timers) and its `h2s` +
/// `struct stream` (a child: one entry per stream being served, with its own transaction,
/// server connection and log line).
pub enum H2Role {
    Owner(H2Owner),
    Child(H2Child),
}

/// The owner's side: its children.
#[derive(Default)]
pub struct H2Owner {
    /// The entries serving the connection's streams, at most [`TcpSession::h2_max_children`].
    pub children: Vec<H2ChildLink>,
    /// The client's TLS session as the `ssl_fc*` fetches of every stream read it: one copy
    /// for the connection, shared.
    pub tls: Option<Arc<ibex_tls::RustlsTlsInfo>>,
    /// Where the next pass that moves the streams' bytes starts: after the stream that sent
    /// DATA last, so that one with a big body cannot take the connection's window from the
    /// others pass after pass (`HAProxy`'s `send_list`, round robin).
    pub next_child: usize,
}

/// A child of an owner, as the owner knows it. The arena reuses indices and task slots: a
/// link is removed when its child is freed, and a child forgets its owner when the owner
/// is ([`H2Child::owner`]), so neither ever names an entry that is not its own.
#[derive(Clone, Copy, Debug)]
pub struct H2ChildLink {
    pub idx: u32,
    pub task: ibex_sched::TaskRef,
    pub stream_id: u32,
}

/// What a child asks of its owner's client connection when it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnEnd {
    /// `shutw_cli`: a FIN.
    Shutw,
    /// `shutdown_both`.
    ShutBoth,
    /// `abort_with_rst`.
    Abort,
    /// `silent_drop`: IPv6 or not, and the TTL of the RST.
    SilentDrop(bool, u8),
}

/// The child's side: the stream it serves and its owner.
#[allow(clippy::struct_excessive_bools)]
pub struct H2Child {
    /// The owner's entry and task; `None` once the owner is gone.
    pub owner: Option<(u32, ibex_sched::TaskRef)>,
    pub stream: H2ActiveStream,
    /// The client (or the mux) reset the stream.
    pub reset: bool,
    /// The transaction ended through `end_txn` and the connection goes on: the entry is
    /// freed, and a server connection it kept goes to the owner for the next stream.
    pub finished: bool,
    /// What the transaction did to the client connection, done by the owner.
    pub conn_end: Option<ConnEnd>,
    /// The owner has frames for the client it has not written yet (they were part of
    /// "output pending" when the stream was the connection's own).
    pub owner_tx_pending: bool,
    /// The `RST_STREAM` the owner sends when the stream is let go with its connection
    /// kept: `CANCEL` for a stream whose `timeout client` ran out (T300).
    pub rst: Option<ibex_proto::h2::H2Error>,
    /// The `GOAWAY` the owner sends with that `RST_STREAM`: `http-request reject`'s, which
    /// ends the connection's usefulness while the other streams finish.
    pub goaway: Option<ibex_proto::h2::H2Error>,
    pub tls: Option<Arc<ibex_tls::RustlsTlsInfo>>,
    /// The connection's session variables as the stream got them: what it changed of them
    /// goes back to the connection, and only that, as other streams may have set others.
    pub sess_vars_at_start: ibex_sample::VarMap,
}

impl H2Child {
    /// Records what the stream does to the client connection; a reset outweighs a FIN.
    fn end_conn(&mut self, how: ConnEnd) {
        if !matches!(self.conn_end, Some(ConnEnd::Abort | ConnEnd::SilentDrop(..))) {
            self.conn_end = Some(how);
        }
    }
}

/// What the `ssl_fc*` fetches of a session read, from its fields (so that a caller may
/// hold it beside others): the client's TLS session, a stream's that of its connection.
#[must_use]
pub fn ssl_fc<'a>(xprt: &'a ClientXprt, role: Option<&'a H2Role>) -> ibex_sample::SslFacts<'a> {
    match role {
        Some(H2Role::Child(H2Child { tls: Some(info), .. })) => crate::xprt::facts_of(info),
        _ => xprt.ssl_facts(),
    }
}

/// A backend connection's `conn->err_code` (`CO_ER_*`, numbered as in
/// `include/haproxy/connection-t.h`), named and worded as `conn_err_code_name` and
/// `conn_err_code_str` do: what `bc_err` and `bc_err_str` read.
const fn bc_err(code: i64, name: &'static str, text: &'static str) -> ibex_sample::ConnErr<'static> {
    ibex_sample::ConnErr { code, text, name, tls: false, ssl_code: 0, ssl_text: None }
}

/// `CO_ER_NONE`: the connection is established.
pub const BC_CONNECTED: ibex_sample::ConnErr<'static> = bc_err(0, "", "Success");

/// The error of a server connect the kernel refused once under way, as `sock_conn_check`
/// records it (`conn_set_errno`).
#[must_use]
pub fn bc_connect_errno(e: &io::Error) -> &'static ibex_sample::ConnErr<'static> {
    use rustix::io::Errno;
    let errno = e.raw_os_error().map(Errno::from_raw_os_error);
    match errno {
        Some(Errno::CONNREFUSED) => const { &bc_err(47, "EREFUSED", "ECONNREFUSED returned by OS") },
        Some(Errno::CONNRESET) => const { &bc_err(48, "ERESET", "ECONNRESET returned by OS") },
        Some(Errno::HOSTUNREACH | Errno::NETUNREACH) => const { &bc_err(49, "EUNREACH", "ENETUNREACH returned by OS") },
        Some(Errno::NOMEM) => const { &bc_err(50, "ENOMEM", "ENOMEM returned by OS") },
        Some(Errno::BADF) => const { &bc_err(51, "EBADF", "EBADF returned by OS") },
        Some(Errno::FAULT) => const { &bc_err(52, "EFAULT", "EFAULT returned by OS") },
        Some(Errno::INVAL) => const { &bc_err(53, "EINVAL", "EINVAL returned by OS") },
        Some(Errno::NOTCONN) => const { &bc_err(54, "ENCONN", "ENCONN returned by OS") },
        Some(Errno::NOTSOCK) => const { &bc_err(55, "ENSOCK", "ENSOCK returned by OS") },
        Some(Errno::NOBUFS) => const { &bc_err(56, "ENOBUFS", "ENOBUFS returned by OS") },
        Some(Errno::PIPE) => const { &bc_err(57, "EPIPE", "EPIPE returned by OS") },
        _ => const { &bc_err(6, "SOCK_ERR", "General socket error") },
    }
}

/// The error of a server `connect()` that failed at once, as `tcp_connect_server` records it.
#[must_use]
pub fn bc_connect_now_errno(e: &io::Error) -> &'static ibex_sample::ConnErr<'static> {
    use rustix::io::Errno;
    match e.raw_os_error().map(Errno::from_raw_os_error) {
        Some(Errno::AGAIN | Errno::ADDRNOTAVAIL) => const { &bc_err(9, "FREE_PORTS", "Out of local source ports on the system") },
        Some(Errno::ADDRINUSE) => const { &bc_err(10, "ADDR_INUSE", "Local source address already in use") },
        _ => const { &bc_err(6, "SOCK_ERR", "General socket error") },
    }
}

/// One TCP / HTTP session: two connections, two buffers, two state machines.
#[allow(clippy::struct_excessive_bools)]
/// What waits to go into a session's `rep`.
pub enum PendingOut {
    /// The rest of a local reply, and how much of it is in `rep`.
    Raw(Vec<u8>, usize),
    /// A Prometheus scrape being produced.
    Scrape(crate::promex::Cursor),
}

impl PendingOut {
    fn has_output(&self) -> bool {
        match self {
            PendingOut::Raw(d, o) => *o < d.len(),
            PendingOut::Scrape(_) => true,
        }
    }
}

thread_local! {
    /// Boxes for [`PendingOut::Scrape`], made by `promex::prewarm`.
    static SCRAPE_BOXES: std::cell::RefCell<Vec<Box<PendingOut>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Makes room for `n` scrape boxes on this thread (start-up, when the config has the rule).
pub fn reserve_scrape_boxes(n: usize) {
    SCRAPE_BOXES.with(|l| {
        let mut l = l.borrow_mut();
        l.reserve_exact(n);
        while l.len() < n {
            l.push(Box::new(PendingOut::Scrape(crate::promex::Cursor::start())));
        }
    });
}

pub struct TcpSession {
    /// The client's socket, none for a stream of an HTTP/2 connection (T280). Outside this
    /// module it is reached through `cli_fd` only.
    cli: ClientSide,
    /// Which HTTP parser validates this connection's request heads.
    ///
    /// A `ParserKind` rather than a `Box<dyn HttpStream>`: it is `Copy`, so the session
    /// carries two bytes instead of a trait object, and the stream is built only when
    /// there is a head to check.
    pub parser_kind: ParserKind,
    /// The transport under the client socket: plaintext, or TLS over the same fd.
    ///
    /// `ClientXprt::Plain` is what every session had implicitly before this existed and
    /// compiles to the same `raw::recv`/`raw::send` calls.
    pub cli_xprt: ClientXprt,
    pub srv: Option<OwnedFd>,
    /// The transport under the backend server socket: plaintext, or TLS over the same fd.
    pub srv_xprt: ServerXprt,
    pub mode: Mode,
    pub client_addr: Option<SocketAddr>,
    /// The name of the bind that accepted this connection (`so_name`).
    pub so_name: Option<Arc<str>>,
    /// The id of the bind that accepted this connection (`so_id`).
    pub so_id: Option<u32>,
    /// Set when the PROXY header was refused: the connection logs that, not a request.
    pub proxy_hdr_err: Option<ProxyHdrError>,
    pub cliexp: Vec<CompiledExp>,
    pub srvexp: Vec<CompiledExp>,
    pub req_uri: Option<String>,
    pub req_method: Option<String>,
    pub req_headers: Option<Vec<(String, String)>>,
    pub htx_buf: Buf,
    pub htx_tail: usize,
    pub htx_blocks: usize,
    pub has_htx: bool,
    pub htx_modified: bool,
    /// What the request in flight asked for of a websocket upgrade, for its response
    /// (`crate::websocket`); `None` for one that asked for no upgrade.
    pub req_ws: Option<Box<crate::websocket::ReqWs>>,
    pub cli_state: ScState,
    pub srv_state: ScState,
    /// Client to server.
    pub req: Buf,
    /// Server to client.
    pub rep: Buf,
    pub timeouts: Timeouts,
    /// What `http-request set-timeout` set for the stream in progress; `None` until a rule
    /// sets one, so a stream that sets none allocates nothing.
    pub timeouts_set: Option<Box<TimeoutsSet>>,
    /// The chosen backend's `timeout tunnel` and `timeout queue`, in ms (0: none). The queue
    /// one is `timeout connect` where the backend has no `timeout queue` of its own (the
    /// value `HAProxy` is configured with). What `set-timeout` set for the stream is in
    /// `timeouts_set` and wins; see [`TcpSession::tunnel_ms`] and [`TcpSession::queue_ms`].
    pub be_tunnel_ms: u32,
    pub be_queue_ms: u32,
    /// The request waits for a server slot (`maxconn`): see [`QueueWait`].
    pub queue: Option<Box<QueueWait>>,
    /// Connect attempts left before giving up.
    pub conn_retries: u16,
    /// The retry budget this stream started with, `s->max_retries` in HAProxy: what
    /// `cur_max_retries` reports while `conn_retries` counts down.
    pub max_retries: u16,
    /// Deadline for the operation currently in flight on each side.
    pub cli_exp: Tick,
    /// `timeout http-request`, in ms (0: none), and when it ends for the request head now
    /// being received: from the connection for its first request, from the first byte of
    /// a later one. It ends with the head, and does not move with the client's progress.
    pub http_request_ms: u32,
    /// `timeout http-keep-alive`, in ms (0: none): the wait between a response and the next
    /// request's first byte. Without it that wait is `timeout http-request`, then
    /// `timeout client`.
    pub keep_alive_ms: u32,
    /// `option httpclose` in the frontend: each response closes the client connection.
    pub close_client: bool,
    /// `req_exp` is the idle wait, not a request head's.
    pub req_idle: bool,
    pub req_exp: Tick,
    pub srv_exp: Tick,
    pub conn_exp: Tick,
    /// Earliest tick at which a failed connect may be retried.
    ///
    /// `HAProxy` calls this the turn-around state (`SC_ST_TAR`). After an asynchronous
    /// connect failure it waits `MIN(1s, timeout connect)` before retrying the *same*
    /// server, because an instant retry almost always reproduces the same error and
    /// just burns the retry budget. See `src/backend.c:2890`.
    pub retry_after: Tick,
    /// When the server connection kept after a response goes back to the server's lists
    /// if no next request has taken it (T187; unset while none is kept).
    pub srv_park_exp: Tick,
    /// The backend retries a failed connection (`retry-on conn-failure`, the default).
    pub retry_conn: bool,
    /// The stream was redispatched (`SF_REDISP`): what `txn.redispatched` reads.
    pub redispatched: bool,
    /// The configured address of the server the stream is connected, or connecting, to
    /// (`%si` and the stats read it); `None` while it has none. Set when a connect is
    /// made, cleared when the server is released, and moved with the server connection.
    /// The socket's own destination, `bc_dst`, is derived from it: [`Self::bc_dst`].
    pub target_addr: Option<SocketAddr>,
    /// The server connection's `conn->err_code`: [`BC_CONNECTED`] once connected, the
    /// failure of a connect, `None` while there is none or it is connecting: `bc_err`.
    pub bc_err: Option<&'static ibex_sample::ConnErr<'static>>,
    /// The load balancer picked the stream's server (`assign_server`'s balancing branch),
    /// where `use-server`, a persistence cookie or `stick match` did not (`SF_DIRECT`):
    /// only a pick counts in `lbtot` (T225).
    pub lb_picked: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// What the stick-table entries this session tracks have been credited of `bytes_in`
    /// (`flush_stick_bytes`).
    pub stick_acct_in: u64,
    /// The HTTP/2 glitches already credited to the tracked entries (`glitch_cnt`).
    pub glitches_credited: u64,
    /// What the servers sent in the requests that are over and not credited yet.
    pub stick_out_pending: u64,
    pub ending: Option<Ending>,
    pub accept_proxy: bool,
    pub accept_proxy_v2: bool,
    pub proxy_handshake_done: bool,
    /// The `tcp-request session` rules wait for the PROXY header (T157): `HAProxy` runs
    /// them in `conn_complete_session`, after the handshake, so `src` and `fc_pp_tlv`
    /// read the header.
    pub session_rules_pending: bool,
    pub proxy_info: Option<Box<ibex_proto::ProxyInfo>>,
    pub server_addr: Option<SocketAddr>,
    pub send_proxy_prepended: bool,
    /// The PROXY header the server connection opened with, if any: a later request reuses
    /// that connection only if it would send the same one.
    pub send_proxy_header: Vec<u8>,
    /// The HTTP transaction in progress: `None` between requests, and always in `mode
    /// tcp`. What may be forwarded in each direction is decided by its message states.
    pub txn: Option<HttpTxn>,
    /// The server socket is drained, so it is not read again until the poller reports it
    /// readable (`HAProxy`'s `fd_cant_recv`): set by a read that returned `EAGAIN` or
    /// fewer bytes than asked for (`src/raw_sock.c`). HTTP over plain sockets only: those
    /// sessions are always driven by the engine, which clears it on a readiness event; a
    /// TCP session may be driven without a poller and keeps reading speculatively, and
    /// TLS may hold decrypted bytes the socket no longer shows.
    pub srv_cant_recv: bool,
    /// The same for the client socket. Without it every pass over the session read the
    /// client again, eight `EAGAIN` reads per keep-alive request (`performance.md`).
    pub cli_cant_recv: bool,
    /// The last [`Self::advance`] stopped at its bound with its passes still making
    /// progress: there is more to do, and maybe no socket event to say so.
    pub passes_ran_out: bool,
    /// The client connection failed (a TLS record that does not decrypt, a socket error),
    /// as opposed to the client closing or resetting it: an HTTP/2 connection that ends so
    /// before its preface is not logged (`HAProxy` only logs a read0 there, T272).
    pub cli_failed: bool,
    pub created_at: Instant,
    /// Output still to go into `rep`: the overflow of a local reply, or a Prometheus scrape
    /// produced chunk by chunk (`crate::promex::pump`). One pointer for both, so that only
    /// the sessions that have one pay for it.
    pub pending_resp: Option<Box<PendingOut>>,
    pub fc_src: Option<SocketAddr>,
    pub fc_dst: Option<SocketAddr>,
    pub tcp_inspect_done: bool,
    pub inspect_exp: Option<Tick>,
    /// The backend's `tcp-request content` rules are waiting (TCP mode): `inspect_exp` is
    /// their delay, and the backend is chosen again when it is over.
    pub be_inspect: bool,
    /// TCP mode, `tcp-response content` rules still deciding: the response is held from
    /// the client (no write, no shutdown) until they accept or reject it.
    pub res_inspect_pending: bool,
    /// When `tcp-response inspect-delay` runs out and the rules decide on what they have.
    pub res_inspect_exp: Option<Tick>,
    /// The backend has `tcp-response content` rules for this stream: they start, with
    /// this inspect-delay, once the server connection is up (`server_connected`).
    pub res_inspect_armed: Option<Option<u32>>,
    pub sess_vars: ibex_sample::VarMap,
    pub req_vars: ibex_sample::VarMap,
    /// What this stream measured for its log line, and its captures and unique ID.
    pub log: crate::txnlog::StreamLog,
    pub tracked_sc: [Option<(usize, StickKey)>; 3],
    /// The keys `stick on` and `stick store-request` took from the request, each with the
    /// proxy whose table keeps it: stored with the server that answers.
    pub stick_stores: Vec<(usize, StickKey)>,
    pub bufsize: usize,
    pub maxrewrite: usize,
    pub h2_ctx: Option<Box<H2MuxContext>>,
    /// The first GOAWAY of an HTTP/2 `timeout client` has gone: the next expiry closes.
    pub h2_idle_goaway: bool,
    /// `idle_start` of an HTTP/2 connection (`struct h2c`): when it last went idle (no
    /// stream, nothing to send), or when the request now being received began. The idle
    /// timeouts count from here, not from the last byte.
    pub h2_idle_start: Tick,
    /// Output was waiting for the client the last time the connection's timer was set
    /// (`H2_CF_MBUF_HAS_DATA`): when it has gone, the connection is idle from then.
    pub h2_out_waited: bool,
    /// A request head was partly received the last time the timer was set.
    pub h2_head_partial: bool,
    /// The session's part in an HTTP/2 connection (T280): the owner of the connection, with
    /// its streams' entries, or one of those streams. Boxed, as most sessions are neither.
    pub h2_role: Option<Box<H2Role>>,
    pub h2_flood_config: ibex_proto::H2FloodConfig,
    pub is_first_req: bool,
    /// The client's reset was reported with the first bytes of its request, before any
    /// transaction: it left while its connection waited to be accepted.
    pub reset_with_request: bool,
    /// Keep each request line for the log (`txn->uri`): set when a format of the
    /// frontend reads it, so a frontend that does not log it does not pay for a copy.
    pub keep_request_line: bool,
    /// `option accept-unsafe-violations-in-http-request` on the frontend.
    pub accept_unsafe_request: bool,
    /// The client is an HTTP/3 request stream relayed by a QUIC listener (T130): one
    /// request, over TLS, logged as `HTTP/3.0` with the URI `HAProxy` builds from
    /// `:scheme` and `:authority`.
    pub h3: bool,
}

/// The HTTP/2 stream a session is serving: its id, how much of its request body has been
/// written to `req`, and whether the head forwarded for it has to carry
/// `transfer-encoding: chunked` (no length was given; it is added when the head is written,
/// not in the HTX the rules see).
#[derive(Clone, Copy, Debug)]
pub struct H2ActiveStream {
    pub id: u32,
    pub body: H2ReqBody,
    pub chunk_out: bool,
}

/// Where the body of an HTTP/2 request has got to on its way into `req`: the next block of
/// the stream's message, how far into it, whether it goes out chunked (no length was
/// given), and whether the end has been written.
#[derive(Clone, Copy, Debug, Default)]
pub struct H2ReqBody {
    pub cursor: usize,
    pub off: usize,
    pub chunked: bool,
    pub done: bool,
    /// The last chunk has been written with trailers after it.
    pub trailing: bool,
    /// What the trailers add to `%U`: each name and value, and the byte of their end.
    pub trailer_bytes: u64,
    /// DATA bytes moved into the server-bound buffer, and how many of them the client has
    /// been given stream window for (T195: the window is granted as the body is consumed).
    pub consumed: u64,
    pub credited: u64,
}

impl TcpSession {
    /// The client's socket; `None` for a stream of an HTTP/2 connection, whose socket is
    /// its owner's (T280).
    #[must_use]
    #[inline]
    pub fn cli_fd(&self) -> Option<BorrowedFd<'_>> {
        self.cli.fd()
    }

    /// Whether the session speaks HTTP/2 to its client: the connection's owner, or one of
    /// its streams.
    #[must_use]
    #[inline]
    pub fn is_h2(&self) -> bool {
        self.h2_ctx.is_some() || self.is_h2_child()
    }

    /// T326: `fc_http_major` (`smp_fetch_fc_http_major`, `src/connection.c`): the client
    /// connection's mux, 2 for HTTP/2 (TLS ALPN, `proto h2` or a detected preface), 1 for
    /// HTTP/1, none in TCP mode, whose mux is raw.
    #[must_use]
    pub fn fc_http_major(&self) -> Option<u8> {
        (self.mode == Mode::Http).then(|| if self.is_h2() { 2 } else { 1 })
    }

    /// T326: `bc_http_major`: 1 on an HTTP server connection, the only one Ibex makes (it has
    /// no HTTP/2 mux towards servers and refuses `server ... proto h2`); none before there is
    /// a server connection, or in TCP mode.
    #[must_use]
    pub fn bc_http_major(&self) -> Option<u8> {
        (self.mode == Mode::Http && self.srv.is_some()).then_some(1)
    }

    /// `bc_dst`: where the server connection was made, or is being made, to -- the
    /// server's address with the destination filling in what it leaves unset
    /// (`connect_addr`, as the connect computed it). Derived rather than stored, which
    /// would cost a `SessionEntry` 32 bytes or a box per connect. It reads `server_addr`
    /// as it is now, which is the value the connect used: `set-dst` runs before the
    /// connect, and a server that takes the destination's address or port is never
    /// reused for a later request (its kept connection is replaced, `set_target` again).
    /// Only that later request's own rules, before its connect, could see the old
    /// connection with the new destination.
    #[must_use]
    pub fn bc_dst(&self) -> Option<SocketAddr> {
        self.target_addr.map(|t| crate::engine::connect_addr(t, self.server_addr))
    }

    /// Whether the session is a stream of an HTTP/2 connection (T280).
    #[must_use]
    #[inline]
    pub fn is_h2_child(&self) -> bool {
        matches!(self.cli, ClientSide::H2Child)
    }

    #[must_use]
    pub fn h2_child(&self) -> Option<&H2Child> {
        match self.h2_role.as_deref() {
            Some(H2Role::Child(c)) => Some(c),
            _ => None,
        }
    }

    pub fn h2_child_mut(&mut self) -> Option<&mut H2Child> {
        match self.h2_role.as_deref_mut() {
            Some(H2Role::Child(c)) => Some(c),
            _ => None,
        }
    }

    #[must_use]
    pub fn h2_owner(&self) -> Option<&H2Owner> {
        match self.h2_role.as_deref() {
            Some(H2Role::Owner(o)) => Some(o),
            _ => None,
        }
    }

    /// The owner's side of an HTTP/2 connection, made on first use (one `Box` a connection).
    pub fn h2_owner_mut(&mut self) -> Option<&mut H2Owner> {
        self.h2_ctx.as_ref()?;
        // A child has no `h2_ctx`: the role is an owner's.
        let H2Role::Owner(o) = self.h2_role.get_or_insert_with(|| Box::new(H2Role::Owner(H2Owner::default()))).as_mut() else { return None };
        Some(o)
    }

    /// The HTTP/2 stream this session serves, for a child.
    #[must_use]
    pub fn h2_active(&self) -> Option<&H2ActiveStream> {
        self.h2_child().map(|c| &c.stream)
    }

    /// Whether the client connection is TLS (`ssl_fc`, the `~` of `%ft`), a stream's that
    /// of its connection.
    #[must_use]
    pub fn cli_is_tls(&self) -> bool {
        self.cli_xprt.is_tls() || self.h2_child().is_some_and(|c| c.tls.is_some())
    }

    /// Resets the client connection (`abort_with_rst`); a stream's, through its owner.
    pub fn abort_client(&mut self) {
        match self.cli.fd() {
            Some(fd) => raw::abort_with_rst(fd),
            None => {
                if let Some(c) = self.h2_child_mut() {
                    c.end_conn(ConnEnd::Abort);
                }
            }
        }
    }

    /// `silent-drop` on the client connection; a stream's, through its owner.
    pub fn silent_drop_client(&mut self, is_ipv6: bool, ttl: u8) {
        match self.cli.fd() {
            Some(fd) => raw::silent_drop(fd, is_ipv6, ttl),
            None => {
                if let Some(c) = self.h2_child_mut() {
                    c.end_conn(ConnEnd::SilentDrop(is_ipv6, ttl));
                }
            }
        }
    }

    /// `http-request reject` (`silent` false) and `silent-drop` on a request, with no
    /// response. On HTTP/1 `reject` is a close with a FIN (the caller closes) and
    /// `silent-drop` the connection vanishing; on a stream of an HTTP/2 connection,
    /// measured on `HAProxy` 3.5-dev8, `reject` resets the stream with `ENHANCE_YOUR_CALM`
    /// and sends a `GOAWAY` with the same code, `silent-drop` only resets the stream
    /// (`REFUSED_STREAM`) and the connection goes on.
    pub fn refuse_request(&mut self, silent: bool, is_ipv6: bool, ttl: u8) {
        use ibex_proto::h2::H2Error;
        if let Some(c) = self.h2_child_mut() {
            c.rst = Some(if silent { H2Error::RefusedStream } else { H2Error::EnhanceYourCalm });
            c.goaway = (!silent).then_some(H2Error::EnhanceYourCalm);
            c.finished = true;
        } else if silent {
            self.silent_drop_client(is_ipv6, ttl);
        }
    }

    /// Shuts both directions of the client connection; a stream's, through its owner.
    pub fn shutdown_both_client(&mut self) {
        match self.cli.fd() {
            Some(fd) => raw::shutdown_both(fd),
            None => {
                if let Some(c) = self.h2_child_mut() {
                    c.end_conn(ConnEnd::ShutBoth);
                }
            }
        }
    }

    /// A session for stream `stream` of the HTTP/2 connection `owner` serves, entry
    /// `owner_ref` (T280): what the stream reads of its connection (addresses, listener,
    /// TLS session, PROXY header, session variables and counters, the log started for the
    /// next stream) is copied from the owner, the rest starts as a new session's. Its
    /// client side is the owner's; its client timer is its own, armed when the stream
    /// starts (T300). [`Self::h2_child_done`] gives back what the stream changed.
    #[must_use]
    pub fn h2_child_of(owner: &mut TcpSession, owner_ref: (u32, ibex_sched::TaskRef), stream: H2ActiveStream) -> TcpSession {
        let tls = owner.h2_owner_mut().and_then(|o| o.tls.clone());
        let tls = tls.or_else(|| {
            let info = Arc::new(owner.cli_xprt.tls_info()?.clone());
            if let Some(o) = owner.h2_owner_mut() {
                o.tls = Some(Arc::clone(&info));
            }
            Some(info)
        });
        let mut c = TcpSession::new_with_mode(ClientSide::H2Child, owner.mode, Vec::new(), Vec::new(), owner.timeouts, owner.max_retries, Tick::ETERNITY);
        c.cli_exp = Tick::ETERNITY;
        c.parser_kind = owner.parser_kind;
        c.client_addr = owner.client_addr;
        c.so_name.clone_from(&owner.so_name);
        c.so_id = owner.so_id;
        c.http_request_ms = owner.http_request_ms;
        c.keep_alive_ms = owner.keep_alive_ms;
        c.close_client = owner.close_client;
        c.bytes_in = owner.bytes_in;
        c.bytes_out = owner.bytes_out;
        // The bytes not credited yet are the stream's to credit (with its request): the
        // connection's accounting moves past them, so a stream served beside it does not
        // credit them again.
        c.stick_acct_in = owner.stick_acct_in;
        c.stick_out_pending = std::mem::take(&mut owner.stick_out_pending);
        owner.stick_acct_in = owner.stick_acct_in.max(owner.log.bytes_in_at_start);
        c.accept_proxy = owner.accept_proxy;
        c.accept_proxy_v2 = owner.accept_proxy_v2;
        c.proxy_handshake_done = owner.proxy_handshake_done;
        c.proxy_info.clone_from(&owner.proxy_info);
        c.server_addr = owner.server_addr;
        c.fc_src = owner.fc_src;
        c.fc_dst = owner.fc_dst;
        c.created_at = Instant::now();
        c.bufsize = owner.bufsize;
        c.maxrewrite = owner.maxrewrite;
        // The `tcp-request content` rules the owner armed for the next request run on this
        // one (`end_txn` armed them for the next request of the connection).
        c.tcp_inspect_done = std::mem::replace(&mut owner.tcp_inspect_done, true);
        c.inspect_exp = owner.inspect_exp.take();
        c.sess_vars.clone_from(&owner.sess_vars);
        c.log = owner.log.clone();
        c.tracked_sc.clone_from(&owner.tracked_sc);
        c.h2_flood_config = owner.h2_flood_config;
        c.is_first_req = owner.is_first_req;
        c.reset_with_request = owner.reset_with_request;
        c.keep_request_line = owner.keep_request_line;
        c.accept_unsafe_request = owner.accept_unsafe_request;
        c.h2_role = Some(Box::new(H2Role::Child(H2Child {
            owner: Some(owner_ref),
            stream,
            reset: false,
            finished: false,
            conn_end: None,
            owner_tx_pending: false,
            rst: None,
            goaway: None,
            tls,
            sess_vars_at_start: owner.sess_vars.clone(),
        })));
        c
    }

    /// The stream `child` is over: what it changed of the connection's state comes back to
    /// the owner, which then waits for its next stream as the session did after `end_txn`
    /// (`reset_for_next_request`). `inspect`: the frontend's `tcp-request content` rules
    /// are armed again for the next request, with this deadline.
    pub fn h2_child_done(&mut self, child: &mut TcpSession, inspect: Option<Option<Tick>>) {
        // Other streams may be served beside this one: what it changed is merged in, the
        // rest of the connection's state is left as they made it.
        let at_start = child.h2_child_mut().map(|c| std::mem::take(&mut c.sess_vars_at_start)).unwrap_or_default();
        for k in at_start.keys().filter(|k| !child.sess_vars.contains_key(*k)) {
            self.sess_vars.remove(k);
        }
        for (k, v) in child.sess_vars.drain() {
            if at_start.get(&k) != Some(&v) {
                self.sess_vars.insert(k, v);
            }
        }
        for (mine, theirs) in self.tracked_sc.iter_mut().zip(&mut child.tracked_sc) {
            if mine.is_none() {
                *mine = theirs.take();
            }
        }
        self.stick_acct_in = self.stick_acct_in.max(child.stick_acct_in);
        self.stick_out_pending += child.stick_out_pending + child.log.bytes_from_server;
        self.log = crate::txnlog::StreamLog::start(self.bytes_in, self.bytes_out);
        self.is_first_req = false;
        self.ending = None;
        if let Some(exp) = inspect {
            self.tcp_inspect_done = false;
            self.inspect_exp = exp;
        }
        // The streams that are over are let go, as `HAProxy` frees a stream when it closes
        // (`h2s_destroy`). Kept, each held its request for the life of the connection and
        // every request walked all of them: 88% of the CPU of an h2 request (T186).
        // A stream another entry still serves is kept until that one is over.
        let (Some(H2Role::Owner(o)), Some(h2)) = (self.h2_role.as_deref(), self.h2_ctx.as_mut()) else { return };
        h2.streams.retain(|id, s| o.children.iter().any(|l| l.stream_id == *id) || !matches!(s.state, ibex_proto::H2StreamState::Closed | ibex_proto::H2StreamState::Reset(_)));
    }

    /// Whether the client connection is TLS and its handshake is not done yet.
    #[must_use]
    pub fn cli_tls_handshaking(&self) -> bool {
        matches!(&self.cli_xprt, ClientXprt::Tls(t) if !t.handshake_done())
    }

    /// Whether the server connection is TLS and its handshake is not done yet.
    #[must_use]
    pub fn srv_tls_handshaking(&self) -> bool {
        matches!(&self.srv_xprt, ServerXprt::Tls(t) if !t.handshake_done())
    }

    /// The end of the session: whatever TLS connection is still open says `close_notify` before
    /// its socket is closed, as `HAProxy`'s `ssl_sock_shutw` does on every close, so an HTTP/2
    /// connection that ended after its GOAWAY, or a backend connection that ended, is a finished
    /// stream and not a cut one. Already sent, or a failed socket: nothing.
    pub fn close_notify_both(&mut self) {
        if let Some(fd) = self.cli.fd().filter(|_| !self.cli_failed && matches!(&self.cli_xprt, ClientXprt::Tls(t) if t.handshake_done())) {
            self.cli_xprt.send_close_notify(fd);
        }
        if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
            self.srv_xprt.send_close_notify(sfd);
        }
    }

    /// Ends what is sent to the client: `close_notify` first on a TLS connection whose
    /// handshake is done, then the FIN. `HAProxy` sends it on every clean shutdown
    /// (`ssl_sock_shutw`); without it an OpenSSL client reads the FIN as "unexpected eof"
    /// and drops its session as not resumable, so every reconnect paid a full handshake
    /// (T283, MY-2).
    pub fn shutw_cli(&mut self) {
        let Some(fd) = self.cli.fd() else {
            // A stream's FIN is its connection's: the owner sends it (T280).
            if let Some(c) = self.h2_child_mut() {
                c.end_conn(ConnEnd::Shutw);
            }
            return;
        };
        if matches!(&self.cli_xprt, ClientXprt::Tls(t) if t.handshake_done()) {
            self.cli_xprt.send_close_notify(fd);
        }
        raw::shutdown_write(fd);
    }

    #[must_use]
    pub fn new(cli: OwnedFd, timeouts: Timeouts, retries: u16, now: Tick) -> Self {
        Self::new_with_mode(
            ClientSide::Fd(cli),
            Mode::Tcp,
            Vec::new(),
            Vec::new(),
            timeouts,
            retries,
            now,
        )
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_mode(
        cli: ClientSide,
        mode: Mode,
        cliexp: Vec<CompiledExp>,
        srvexp: Vec<CompiledExp>,
        timeouts: Timeouts,
        retries: u16,
        now: Tick,
    ) -> Self {
        let cli_state = if mode == Mode::Http {
            ScState::Ready
        } else {
            ScState::Established
        };
        let mut s = TcpSession {
            cli,
            parser_kind: ParserKind::H1,
            cli_xprt: ClientXprt::Plain,
            srv: None,
            srv_xprt: ServerXprt::Plain,
            mode,
            client_addr: None,
            so_name: None,
            so_id: None,
            proxy_hdr_err: None,
            cliexp,
            srvexp,
            req_uri: None,
            req_method: None,
            req_headers: None,
            htx_buf: Buf::unallocated(crate::buf::BufClass::Standard),
            htx_tail: 0,
            htx_blocks: 0,
            has_htx: false,
            htx_modified: false,
            req_ws: None,
            cli_state,
            srv_state: ScState::Init,
            req: Buf::unallocated(crate::buf::BufClass::Standard),
            rep: Buf::unallocated(crate::buf::BufClass::Standard),
            timeouts,
            timeouts_set: None,
            be_tunnel_ms: 0,
            be_queue_ms: 0,
            queue: None,
            conn_retries: retries,
            max_retries: retries,
            retry_after: Tick::ETERNITY,
            srv_park_exp: Tick::ETERNITY,
            retry_conn: true,
            redispatched: false,
            target_addr: None,
            bc_err: None,
            lb_picked: false,
            cli_exp: Tick::ETERNITY,
            http_request_ms: 0,
            keep_alive_ms: 0,
            close_client: false,
            req_idle: false,
            req_exp: Tick::ETERNITY,
            srv_exp: Tick::ETERNITY,
            conn_exp: Tick::ETERNITY,
            bytes_in: 0,
            bytes_out: 0,
            stick_acct_in: 0,
            glitches_credited: 0,
            stick_out_pending: 0,
            ending: None,
            accept_proxy: false,
            accept_proxy_v2: false,
            proxy_handshake_done: false,
            session_rules_pending: false,
            proxy_info: None,
            server_addr: None,
            send_proxy_prepended: false,
            send_proxy_header: Vec::new(),
            txn: None,
            srv_cant_recv: false,
            cli_cant_recv: false,
            passes_ran_out: false,
            cli_failed: false,
            created_at: Instant::now(),
            bufsize: crate::buf::get_bufsize(),
            maxrewrite: 1024,
            pending_resp: None,
            fc_src: None,
            fc_dst: None,
            tcp_inspect_done: true,
            inspect_exp: None,
            be_inspect: false,
            res_inspect_pending: false,
            res_inspect_exp: None,
            res_inspect_armed: None,
            sess_vars: HashMap::new(),
            req_vars: HashMap::new(),
            log: crate::txnlog::StreamLog::start(0, 0),
            tracked_sc: [None, None, None],
            stick_stores: Vec::new(),
            h2_ctx: None,
            h2_idle_goaway: false,
            h2_idle_start: now,
            h2_out_waited: false,
            h2_head_partial: false,
            h2_role: None,
            h2_flood_config: ibex_proto::H2FloodConfig::default(),
            is_first_req: true,
            reset_with_request: false,
            keep_request_line: false,
            accept_unsafe_request: false,
            h3: false,
        };
        s.arm_client(now);
        s
    }

    /// The version the client spoke (`req.ver`): where it is not HTTP/1.x, or after the HTX is gone: the HTX start line of
    /// an h2 or h3 request is rewritten to HTTP/1.1 for the server leg, but `HAProxy` reads the
    /// version of the message the client sent (`2.0`, `3.0`).
    #[must_use]
    pub fn client_version(&self) -> Option<&'static str> {
        if self.h3 {
            Some("HTTP/3.0")
        } else if self.is_h2() {
            Some("HTTP/2.0")
        } else if self.has_htx {
            None
        } else {
            // The head's HTX is gone once it is forwarded: the version is kept apart.
            self.txn.as_ref().and_then(|t| txn::version_text(t.req_version))
        }
    }

    #[must_use]
    pub fn htx_slice(&self) -> Option<ibex_proto::htx::HtxSliceRef<'_>> {
        if self.has_htx {
            Some(ibex_proto::htx::HtxSliceRef::new(
                self.htx_buf.raw_slice(),
                self.htx_blocks,
            ))
        } else {
            None
        }
    }

    pub fn with_htx_mut<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut ibex_proto::htx::HtxSlice<'_>) -> R,
    {
        if !self.has_htx {
            return None;
        }
        let tail = self.htx_tail;
        let blocks = self.htx_blocks;
        let mut slice = ibex_proto::htx::HtxSlice::with_offsets(
            self.htx_buf.raw_slice_mut(),
            tail,
            blocks,
        );
        let res = f(&mut slice);
        self.htx_tail = slice.tail_addr();
        self.htx_blocks = slice.num_blocks();
        self.htx_modified = true;
        Some(res)
    }

    /// Makes sure the HTX holds `bytes` more of header (and its descriptor). This HTX is
    /// laid out with 16-byte block descriptors where `HAProxy`'s are 8, so a request that
    /// still has room in the message `HAProxy` would hold may have none in this buffer: the
    /// buffer is then replaced by a larger one, the data kept at the front and the
    /// descriptors at the end, as they were.
    pub fn htx_reserve(&mut self, bytes: usize) {
        use ibex_proto::htx::HTX_DESC_SIZE;
        self.htx_buf.alloc_if_needed();
        let len = self.htx_buf.raw_slice().len();
        let descs = self.htx_blocks * HTX_DESC_SIZE;
        let free = len.saturating_sub(descs).saturating_sub(self.htx_tail);
        let needed = bytes + HTX_DESC_SIZE;
        if free >= needed {
            return;
        }
        let new_len = len + (needed - free) + 4096;
        let mut bigger = Buf::with_capacity(new_len);
        let old = self.htx_buf.raw_slice();
        let new = bigger.raw_slice_mut();
        new[..self.htx_tail].copy_from_slice(&old[..self.htx_tail]);
        new[new_len - descs..].copy_from_slice(&old[len - descs..]);
        self.htx_buf = bigger;
    }

    pub fn clear_htx(&mut self) {
        self.has_htx = false;
        self.htx_tail = 0;
        self.htx_blocks = 0;
        self.htx_modified = false;
    }

    /// Whether there is output the client may be sent now: response bytes inside the
    /// current response's window (a response still waiting for its head to be processed
    /// is not output yet), the overflow of a local reply, or HTTP/2 frames.
    #[must_use]
    pub fn has_pending_output(&self) -> bool {
        self.rep_window() > 0
            || self.pending_resp.as_deref().is_some_and(PendingOut::has_output)
            || self.h2_ctx.as_ref().is_some_and(|h| h.tx_consumed < h.tx_buf.len())
            || self.h2_child().is_some_and(|c| c.owner_tx_pending)
    }

    /// Whether the session must be run again with no socket event to wake it.
    ///
    /// A TLS handshake with the server that failed in a pass after the engine's check for
    /// it (`process` runs again in the content and HTTP steps) is retried on the next pass.
    /// The server's FIN behind its alert used to be that wakeup, through an EPOLLRDHUP
    /// armed with no read interest; since T226 it is not, and the retry waited for
    /// `timeout connect`.
    #[must_use]
    pub fn wants_rerun(&self) -> bool {
        self.passes_ran_out
            || self.has_undispatched_h2_streams()
            || (self.srv_state == ScState::Error && self.srv_xprt.handshake_failed())
    }

    /// How many streams of an HTTP/2 connection are served at once (T280): as many as the
    /// connection advertised it takes (`SETTINGS_MAX_CONCURRENT_STREAMS`), each by an entry
    /// of its own; the mux refuses those over it.
    #[must_use]
    pub fn h2_max_children(&self) -> usize {
        self.h2_ctx.as_ref().map_or(0, |h| h.max_concurrent_streams as usize)
    }

    /// A stream with its request in, waiting for its turn, and the turn free: as many
    /// streams are served at once as [`Self::h2_max_children`], so while that many are the others
    /// wait for one's end (the child's release runs the owner again then). Counting them
    /// while one was at the server had the session requeue itself on every pass, a busy
    /// loop as long as the server took (T186).
    #[must_use]
    pub fn has_undispatched_h2_streams(&self) -> bool {
        if self.h2_owner().is_some_and(|o| o.children.len() >= self.h2_max_children()) || self.txn.is_some() {
            return false;
        }
        if let Some(ref h2) = self.h2_ctx {
            h2.streams.values().any(|st| {
                !st.dispatched
                    && st.state != ibex_proto::H2StreamState::Closed
                    && !matches!(st.state, ibex_proto::H2StreamState::Reset(_))
                    && st.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Eoh))
            })
        } else {
            false
        }
    }

    pub fn enable_accept_proxy(&mut self, require_v2: bool) {
        self.accept_proxy = true;
        self.accept_proxy_v2 = require_v2;
        self.proxy_handshake_done = false;
        self.cli_state = ScState::Ready;
        // The header's first read waits for the poller (T157). `conn_recv_proxy` starts
        // with `if (!fd_recv_ready(fd)) goto not_ready;`, and a new connection's fd is not
        // ready until the poller reports it, a loop after the accept. That read is the
        // only one the header gets (a part of it is refused as truncated), so reading at
        // accept, before the client's writes are all in, refused headers `HAProxy` takes.
        self.cli_cant_recv = true;
    }

    pub(crate) fn arm_client(&mut self, now: Tick) {
        if self.h2_ctx.is_some() {
            self.arm_h2_connection(now);
            return;
        }
        // A stream of an HTTP/2 connection has a timer of its own, as `HAProxy`'s streams
        // have, its connection none while streams are attached (`h2c_may_expire`, T300).
        let ms = self.tunnel_ms().unwrap_or(self.timeouts.client);
        self.cli_exp = if ms == 0 { Tick::ETERNITY } else { now.add(ms) };
    }

    /// The deadline of an HTTP/2 connection (`h2c_update_timeout`, `src/mux_h2.c`). With a
    /// stream attached it has none (each stream has its own). With output waiting it is
    /// `timeout client` from now. Idle, and the GOAWAY not yet sent: `idle_start` plus
    /// `timeout http-keep-alive` if a stream has been seen and no part of the next request
    /// is buffered, else plus `timeout http-request`, else (neither set) `timeout client`
    /// from now. After the idle GOAWAY the deadline set at its sending stands (it is the
    /// `client-fin` or `client` wait).
    fn arm_h2_connection(&mut self, now: Tick) {
        let Some(h2) = self.h2_ctx.as_deref() else { return };
        let client = if self.timeouts.client == 0 { Tick::ETERNITY } else { now.add(self.timeouts.client) };
        if self.h2_owner().is_some_and(|o| !o.children.is_empty()) {
            self.cli_exp = Tick::ETERNITY;
            return;
        }
        if h2.tx_consumed < h2.tx_buf.len() {
            self.h2_out_waited = true;
            self.cli_exp = client;
            return;
        }
        if std::mem::take(&mut self.h2_out_waited) {
            self.h2_idle_start = now;
        }
        if self.h2_idle_goaway {
            // The GOAWAY queued its own output wait (above), which stands; never eternity here.
            self.cli_exp = if self.cli_exp.is_set() { self.cli_exp } else { client };
            return;
        }
        // A HEADERS frame starting ends the keep-alive wait and starts the http-request one.
        let partial = !h2.rx_buf.is_empty() || h2.continuation_stream.is_some();
        if partial && !self.h2_head_partial && (h2.continuation_stream.is_some() || h2.rx_buf.get(3) == Some(&1)) {
            self.h2_idle_start = now;
        }
        self.h2_head_partial = partial;
        let to = if h2.last_client_stream_id > 0 && !partial && self.keep_alive_ms != 0 { self.keep_alive_ms } else { self.http_request_ms };
        self.cli_exp = if to != 0 { self.h2_idle_start.add(to) } else { client };
    }

    /// `timeout tunnel` for this stream, the backend's or the one `set-timeout tunnel` gave
    /// it (`s->tunnel_timeout`), while it is a tunnel: a TCP stream once its server is
    /// connected, an HTTP one once both its request and its response are one (a `101`, or
    /// a `2xx` to `CONNECT`). Then it replaces `timeout client` and `timeout server` on both
    /// sides; without it those two go on.
    #[must_use]
    pub fn tunnel_ms(&self) -> Option<u32> {
        let set = self.timeouts_set.as_ref().map_or(0, |s| s.ms[ibex_sample::TimeoutKind::Tunnel as usize]);
        let ms = if set != 0 { set } else { self.be_tunnel_ms };
        let on = match self.mode {
            Mode::Tcp => self.srv_state == ScState::Established,
            _ => self.mode == Mode::Http && self.txn.as_ref().is_some_and(|t| t.rsp == txn::MsgState::Tunnel && t.req == txn::MsgState::Tunnel),
        };
        (ms != 0 && on).then_some(ms)
    }

    /// The chosen backend's `timeout tunnel` and `timeout queue` apply from here (`stream_set_backend`).
    pub fn set_backend_timeouts(&mut self, be: &crate::engine::Proxy) {
        let t = &be.stats_config.raw_timeouts;
        let ms = |d: std::time::Duration| u32::try_from(d.as_millis()).unwrap_or(u32::MAX);
        self.be_tunnel_ms = t.tunnel.map_or(0, ms);
        self.be_queue_ms = t.queue.or(t.connect).map_or(0, ms);
    }

    /// `timeout queue` for this stream, in ms (0: none).
    #[must_use]
    pub fn queue_ms(&self) -> u32 {
        let set = self.timeouts_set.as_ref().map_or(0, |s| s.ms[ibex_sample::TimeoutKind::Queue as usize]);
        if set != 0 { set } else { self.be_queue_ms }
    }

    /// Whether the request head is still being received: no transaction yet, and either
    /// the connection is new or part of a request is here.
    fn head_pending(&self) -> bool {
        self.mode == Mode::Http
            && self.txn.is_none()
            && (self.is_first_req || !self.req.is_empty())
            // An HTTP/2 connection serving a stream has its request head (T280).
            && self.h2_owner().is_none_or(|o| o.children.is_empty())
    }

    /// Whether the connection waits for the first byte of its next request: a response has
    /// gone, nothing has come.
    fn idle_wait(&self) -> bool {
        self.mode == Mode::Http && !self.is_h2() && self.txn.is_none() && !self.is_first_req && self.req.is_empty()
    }

    /// Starts `timeout http-request` when a request head starts, and ends it when the head
    /// is complete. Between requests the wait is `timeout http-keep-alive`, else
    /// `timeout http-request`; a request's first byte ends it.
    pub fn arm_request(&mut self, now: Tick) {
        // An HTTP/2 connection's idle waits are its own (`arm_h2_connection`).
        if self.http_request_ms == 0 && self.keep_alive_ms == 0 || self.h2_ctx.is_some() {
            return;
        }
        if self.head_pending() {
            if self.req_idle {
                self.req_idle = false;
                self.req_exp = Tick::ETERNITY;
            }
            if self.http_request_ms != 0 && !self.req_exp.is_set() {
                self.req_exp = now.add(self.http_request_ms);
            }
        } else if self.idle_wait() {
            let ms = if self.keep_alive_ms != 0 { self.keep_alive_ms } else { self.http_request_ms };
            if !self.req_exp.is_set() {
                self.req_exp = now.add(ms);
                self.req_idle = true;
            }
        } else {
            self.req_exp = Tick::ETERNITY;
            self.req_idle = false;
        }
    }

    fn arm_server(&mut self, now: Tick) {
        let ms = self.tunnel_ms().unwrap_or(self.timeouts.server);
        self.srv_exp = if ms == 0 { Tick::ETERNITY } else { now.add(ms) };
    }

    /// Attaches a server-side connection that is still connecting.
    pub fn attach_server(&mut self, fd: OwnedFd, now: Tick) {
        self.attach_server_with_xprt(fd, ServerXprt::Plain, now);
    }

    /// Attaches a server-side connection with a specific transport (`ServerXprt`).
    pub fn attach_server_with_xprt(&mut self, fd: OwnedFd, xprt: ServerXprt, now: Tick) {
        self.log.queue.get_or_insert_with(crate::txnlog::loop_now);
        self.srv = Some(fd);
        self.srv_xprt = xprt;
        self.srv_cant_recv = false;
        self.srv_state = ScState::Connecting;
        self.bc_err = None;
        self.conn_exp = if self.timeouts.connect == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.connect)
        };
    }

    /// The server connection completed.
    pub fn server_connected(&mut self, now: Tick) {
        self.bc_err = Some(&BC_CONNECTED);
        self.srv_state = if self.mode == Mode::Http {
            ScState::Ready
        } else {
            ScState::Established
        };
        // A TLS handshake still to run stays under `timeout connect` (see `process_srv_io`).
        if self.srv_xprt.is_ready() {
            self.conn_exp = Tick::ETERNITY;
        }
        self.arm_server(now);
        // A TCP stream is a tunnel from here: the client's timer, armed at accept, restarts.
        if self.mode == Mode::Tcp && self.tunnel_ms().is_some() {
            self.arm_client(now);
        }
        self.log.connect = Some(crate::txnlog::loop_now());
        // `AN_RES_INSPECT` runs from here, before any of the response has arrived.
        if let Some(delay) = self.res_inspect_armed.take() {
            self.res_inspect_pending = true;
            self.res_inspect_exp = delay.map(|ms| now.add(ms));
        }
    }

    /// Gives the stream a retry budget of `n`, before any connect attempt: a new request,
    /// a backend switch, or `set-retries`.
    pub fn set_retries(&mut self, n: u16) {
        self.conn_retries = n;
        self.max_retries = n;
        self.redispatched = false;
    }

    /// A retry on the server's answer (`do_l7_retry`): one retry is spent, the server
    /// connection is dropped and the request goes out again from `Init`.
    pub fn l7_retried(&mut self) {
        self.conn_retries = self.conn_retries.saturating_sub(1);
        self.srv = None;
        self.conn_exp = Tick::ETERNITY;
        self.srv_exp = Tick::ETERNITY;
        self.srv_state = ScState::Init;
        self.retry_after = Tick::ETERNITY;
    }

    /// The server connection failed. Returns `true` if a retry remains.
    ///
    /// `same_server` says whether the next attempt will target the server that just
    /// failed. When it does, a turn-around delay is armed; on redispatch to a different
    /// server there is nothing to wait for, so the retry is immediate.
    pub fn server_failed_at(&mut self, now: Tick, same_server: bool) -> bool {
        self.srv = None;
        self.conn_exp = Tick::ETERNITY;
        if self.conn_retries > 0 && self.retry_conn {
            self.conn_retries -= 1;
            self.srv_state = ScState::Init;
            self.retry_after = if same_server {
                now.add(self.retry_delay_ms())
            } else {
                Tick::ETERNITY
            };
            true
        } else {
            self.srv_state = ScState::Error;
            self.retry_after = Tick::ETERNITY;
            self.ending.get_or_insert(Ending::ConnectFailed);
            false
        }
    }

    /// Turn-around delay: `MIN(1s, timeout connect)`, matching `src/backend.c:2898`.
    #[must_use]
    pub fn retry_delay_ms(&self) -> u32 {
        const DEFAULT_TURNAROUND_MS: u32 = 1000;
        if self.timeouts.connect != 0 && self.timeouts.connect < DEFAULT_TURNAROUND_MS {
            self.timeouts.connect
        } else {
            DEFAULT_TURNAROUND_MS
        }
    }

    /// Whether a retry is still waiting out its turn-around delay.
    ///
    /// The caller must not open a new server connection while this is true; doing so
    /// is exactly the back-to-back retry storm the delay exists to prevent.
    #[must_use]
    pub fn retry_pending(&self, now: Tick) -> bool {
        self.retry_after.is_set() && !self.retry_after.is_expired(now)
    }

    /// Backwards-compatible immediate-retry form. Prefer [`Self::server_failed_at`],
    /// which can arm the turn-around delay.
    pub fn server_failed(&mut self) -> bool {
        let now = Tick::ETERNITY;
        let _ = now;
        self.server_failed_at(Tick(1), false)
    }

    /// Injects or updates an HTTP header in the request buffer.
    pub fn inject_req_header(&mut self, name: &str, value: &str) -> bool {
        self.req.inject_http_header(name, value)
    }

    /// Removes all occurrences of an HTTP header from the request buffer.
    pub fn remove_req_header(&mut self, name: &str) -> bool {
        self.req.remove_http_header(name)
    }

    /// Injects or updates an HTTP header in the response buffer.
    pub fn inject_rep_header(&mut self, name: &str, value: &str) -> bool {
        self.rep.inject_http_header(name, value)
    }

    /// Removes all occurrences of an HTTP header from the response buffer.
    pub fn remove_rep_header(&mut self, name: &str) -> bool {
        self.rep.remove_http_header(name)
    }

    /// How much of `rep` may be written to the client now: in HTTP, the bytes of the
    /// response in flight, and none of a response whose head the engine has not yet
    /// processed. That hold is what lets `http-response` rules see every response: the
    /// byte layer reads the server and writes the client in one call.
    #[must_use]
    pub fn rep_window(&self) -> usize {
        let data = self.rep.readable();
        match &self.txn {
            Some(t) if self.mode == Mode::Http && t.rsp.holds_trailer(data, self.bufsize) => 0,
            Some(t) if self.mode == Mode::Http => t.client_window(data),
            _ => data.len(),
        }
    }

    /// Rewrites the framing of a chunked request body in `req` as `HAProxy` forwards it,
    /// before any of it is: each trailer line ended by a lone LF ends by CRLF
    /// ([`txn::MsgState::trailer_bare_lf`]), each chunk-size line loses its extension
    /// ([`txn::MsgState::canonical_chunk_lines`]).
    fn rewrite_req_chunk_framing(&mut self) {
        self.end_req_trailer_lines_with_crlf();
        if self.mode != Mode::Http {
            return;
        }
        let Some(t) = &self.txn else { return };
        let n = t.req.canonical_chunk_lines(self.req.readable_mut());
        self.req.cut(n, self.req.len());
    }

    /// [`Self::rewrite_req_chunk_framing`] for a chunked response body in `rep`, once its
    /// head has been processed: each chunk-size line loses its extension.
    pub fn rewrite_rep_chunk_framing(&mut self) {
        if self.mode != Mode::Http {
            return;
        }
        let Some(t) = &self.txn else { return };
        let n = t.rsp.canonical_chunk_lines(self.rep.readable_mut());
        self.rep.cut(n, self.rep.len());
    }

    /// Rewrites each trailer line of the request in `req` ended by a lone LF to end by
    /// CRLF, before any of it is forwarded (see [`txn::MsgState::trailer_bare_lf`]).
    fn end_req_trailer_lines_with_crlf(&mut self) {
        if self.mode != Mode::Http {
            return;
        }
        let Some(t) = &self.txn else { return };
        while let Some(at) = t.req.trailer_bare_lf(self.req.readable()) {
            let mut fixed = Vec::with_capacity(at + 2);
            fixed.extend_from_slice(&self.req.readable()[..at]);
            fixed.extend_from_slice(b"\r\n");
            self.req.replace_prefix(at + 1, &fixed);
        }
    }

    /// How much of `req` may go to the server now: in HTTP, the current request and
    /// nothing after it. A pipelined request waits in `req` for this transaction to end,
    /// and is then routed on its own.
    #[must_use]
    pub fn req_window(&self) -> usize {
        let data = self.req.readable();
        if self.mode != Mode::Http {
            return data.len();
        }
        match &self.txn {
            // Not before its rules have run: a server connection kept from the last
            // transaction is ready to take bytes the moment a head is parsed, and the
            // request would reach it unfiltered and unrewritten.
            Some(t) if t.req.holds_trailer(data, self.bufsize) => 0,
            Some(t) if t.req_rules_done && !t.local && t.error.is_none() => t.req.window(data),
            _ => 0,
        }
    }

    /// Whether the server side may be read: always, except while the proxy writes its own
    /// reply into `rep`. A kept connection is read between transactions too: that is how
    /// its close is noticed, without probing it, and it keeps the poller's read interest
    /// from flipping off and on with every transaction. Bytes outside a response are the
    /// engine's to judge (`end_txn`, `http_step`).
    fn reads_server(&self) -> bool {
        self.mode != Mode::Http || self.txn.as_ref().is_none_or(|t| !t.local && t.error.is_none())
    }

    /// Whether the client side keeps `cli_cant_recv` (see `srv_cant_recv` for the rule).
    /// Over TLS too, since T186: the transport knows whether its socket was emptied
    /// ([`crate::xprt::ClientXprt::drained`]).
    fn polls_cli(&self) -> bool {
        self.mode == Mode::Http
    }

    /// Writes `raw` to the client once, best effort, on a connection about to be closed:
    /// what is not taken by the socket at once is dropped, as the connection is.
    ///
    /// `raw` is HTTP/1 text, so on an HTTP/2 connection nothing is sent: the h2 mux has
    /// no 408 for an idle client (it closes), and a `100 Continue` is not its to send.
    pub fn send_before_close(&mut self, raw: &[u8]) {
        if self.is_h2() {
            return;
        }
        if let Some(fd) = self.cli.fd() {
            let _ = self.cli_xprt.send(fd, raw);
        }
    }

    /// Answers the current request with `raw`, a complete response the proxy built
    /// itself. `HAProxy`'s `http_reply_message`: the rest of the request is dropped, the
    /// response replaces anything in `rep`, and the transaction ends when it has been
    /// sent.
    ///
    /// The request is dropped through its framing, so its body is never read as the next
    /// request. A body not yet all here is drained as it arrives (`drain_request`) and the
    /// connection then kept, as `HAProxy` 3.5 does, bounded by `timeout client` -- also
    /// for a client that sent `Expect: 100-continue` and was not invited to send its body
    /// (`HAProxy` 3.5 keeps that connection too, and answers the next request once the
    /// body has come). The connection closes after an empty reply (the `errorfile
    /// /dev/null` idiom) and one that says `Connection: close`.
    pub fn write_reply(&mut self, raw: &[u8]) {
        self.write_reply_with(raw, true);
    }

    /// [`Self::write_reply`], `announce_close` telling whether a reply that closes the
    /// connection says so (`Connection: close`) when the page does not. HAProxy's 431 for
    /// an oversized request head does not (measured on 3.5-dev8, `tasks/T87`).
    pub fn write_reply_with(&mut self, raw: &[u8], announce_close: bool) {
        let h2 = self.is_h2();
        let txn = self.txn.get_or_insert_with(|| HttpTxn::new(txn::Framing::None, false));
        let data = self.req.readable();
        let n = txn.req.window(data);
        txn.request_consumed(data, n);
        self.req.consume(n);
        let head_len = find_eoh(raw).map_or(raw.len(), |(h, e)| h + e);
        let head = String::from_utf8_lossy(&raw[..head_len]);
        txn.local = true;
        txn.srv_reusable = false;
        txn.rsp_interim = false;
        txn.status = txn::status_of(&head);
        if raw.is_empty() || txn::head_wants_close(&head) {
            txn.close_after = true;
        }
        // On an HTTP/2 connection the reply is a response like a server's: its head
        // goes out as HEADERS and its body as DATA on the request's stream
        // (`h2_forward_response`), so it is queued as a head with its framing, not as
        // an opaque run of bytes, and says nothing about `Connection`.
        // The answer to a HEAD is the head alone, on either protocol (T296).
        let raw = if txn.client_head { &raw[..head_len.min(raw.len())] } else { raw };
        let mut out;
        let raw = if announce_close && !h2 && txn.close_after && !raw.is_empty() && !has_header(&head, "connection") {
            // The client is told, as for a server's response: last in the head, as
            // `inject_connection_close_header_zero_alloc` places it.
            let at = find_eoh(raw).map_or(0, |(h, e)| h + e / 2);
            out = Vec::with_capacity(raw.len() + 19);
            out.extend_from_slice(&raw[..at]);
            out.extend_from_slice(b"connection: close\r\n");
            out.extend_from_slice(&raw[at..]);
            out.as_slice()
        } else {
            raw
        };
        txn.rsp = if raw.is_empty() {
            txn::MsgState::Done
        } else if h2 {
            let body = raw.len() - head_len.min(raw.len());
            let bodyless = body == 0 || matches!(txn.status, 100..=199 | 204 | 304);
            txn::MsgState::head(if bodyless { txn::Framing::None } else { txn::Framing::Length(body as u64) })
        } else if txn.client_head {
            // The body is not sent: the head, and the message is over, with the length the
            // head announced for a body that is not there. Held as a body, a HEAD's reply
            // was dropped whole (`skip_head_body`) and the client got nothing.
            // `raw` is the head alone by now, with `connection: close` in it when that was added.
            txn::MsgState::Head { left: raw.len(), body: txn::Framing::None }
        } else {
            txn::MsgState::Body(txn::Body::Length(raw.len() as u64))
        };
        self.rep.clear();
        let w = self.rep.writable();
        let n = raw.len().min(w.len());
        w[..n].copy_from_slice(&raw[..n]);
        self.rep.commit(n);
        self.pending_resp = (n < raw.len()).then(|| Box::new(PendingOut::Raw(raw.to_vec(), n)));
    }

    /// The scrape being produced, if any.
    #[must_use]
    pub fn scrape(&self) -> Option<crate::promex::Cursor> {
        match self.pending_resp.as_deref() {
            Some(PendingOut::Scrape(c)) => Some(*c),
            _ => None,
        }
    }

    /// Sets (or ends) the scrape. The box comes from, and goes back to, a per-thread free
    /// list, so a scrape allocates no more than a response does.
    pub fn set_scrape(&mut self, c: Option<crate::promex::Cursor>) {
        match (c, self.pending_resp.as_deref_mut()) {
            (Some(c), Some(PendingOut::Scrape(slot))) => *slot = c,
            (Some(c), _) => {
                let b = SCRAPE_BOXES.try_with(|l| l.borrow_mut().pop()).ok().flatten();
                self.pending_resp = Some(match b {
                    Some(mut b) => {
                        *b = PendingOut::Scrape(c);
                        b
                    }
                    None => Box::new(PendingOut::Scrape(c)),
                });
            }
            (None, Some(PendingOut::Scrape(_))) => {
                if let Some(b) = self.pending_resp.take() {
                    let _ = SCRAPE_BOXES.try_with(|l| {
                        let mut l = l.borrow_mut();
                        if l.len() < l.capacity() {
                            l.push(b);
                        }
                    });
                }
            }
            (None, _) => {}
        }
    }

    /// Answers a Prometheus scrape: the head now, the body as [`crate::promex::pump`] fills
    /// `rep` (chunked, like a server's response relayed). A `HEAD` gets the head alone.
    pub fn start_scrape(&mut self) {
        self.write_reply_with(crate::promex::REPLY_HEAD, true);
        let head_only = self.txn.as_ref().is_some_and(|t| t.client_head);
        if !head_only {
            if let Some(t) = self.txn.as_mut() {
                t.rsp = txn::MsgState::head(txn::Framing::Chunked);
            }
            self.set_scrape(Some(crate::promex::Cursor::start()));
        }
    }

    /// Clears what belonged to the transaction that just ended, so the next request on
    /// this connection starts from nothing. The one place that list lives.
    pub fn reset_for_next_request(&mut self) {
        self.stick_out_pending += self.log.bytes_from_server;
        self.log = crate::txnlog::StreamLog::start(self.bytes_in, self.bytes_out);
        self.txn = None;
        self.req_method = None;
        self.req_uri = None;
        self.set_scrape(None);
        self.req_headers = None;
        self.clear_htx();
        self.req_vars.clear();
        if let Some(set) = self.timeouts_set.take() {
            self.timeouts = set.before;
        }
        // The stream is running, so its variables are in the thread's map
        // (`engine::with_stream_vars`): the transaction's go from there too.
        ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().retain(|k, _| k.starts_with("sess.")));
        self.stick_stores.clear();
        self.is_first_req = false;
        // How the last transaction ended is not how the next one will: a 503 after refused
        // connects left `ConnectFailed`, and the next request's client leaving was then
        // taken for a stream already over, not aborted (T227, devtest7).
        self.ending = None;
        self.cli_state = ScState::Ready;
        self.release_idle_buffers();
    }

    /// Gives back the buffers that hold nothing (`h1_release_buf`): a connection waiting
    /// for its next request holds no buffer (T183). An HTX grown past its class goes too;
    /// the next message starts from a pooled one.
    pub fn release_idle_buffers(&mut self) {
        self.req.release();
        self.rep.release();
        if !self.has_htx {
            if self.htx_buf.class() == crate::buf::BufClass::Custom {
                self.htx_buf = Buf::unallocated(crate::buf::BufClass::Standard);
            } else {
                self.htx_buf.release();
            }
        }
    }

    /// The request head is on the wire to the server: the parsed HTX has no reader left, and a
    /// request whose body is still arriving would pin its 16 KiB for as long as the client
    /// takes (`HAProxy` empties the channel buffer once the head is forwarded). What later
    /// stages read of the request is kept apart from it: the method, URI and request line
    /// (`%r`, `%HU`, `%HM`), the header captures (`log.req_captures`), the retry snapshot of
    /// `retry-on` (`L7Retry::Saved`) and `req_headers`. Nothing reads the HTX of a request
    /// after this point (`req.hdr` is refused in response rules and logs, as in `HAProxy`);
    /// the next request parses a new one.
    fn release_forwarded_head(&mut self) {
        if self.has_htx {
            self.clear_htx();
            self.release_idle_buffers();
        }
    }

    /// Discards the body of a request the proxy has already answered, as it arrives, up
    /// to its end; what follows it is the next request.
    fn drain_request(&mut self) {
        if let Some(t) = self.txn.as_mut().filter(|t| t.local && !t.req.is_done() && !t.close_after) {
            let data = self.req.readable();
            let n = t.req.window(data);
            t.request_consumed(data, n);
            self.req.consume(n);
        }
    }

    /// The request cannot be parsed. It is answered with `status` -- by the engine, which
    /// has the error pages -- and the connection closes; nothing more is read from it.
    fn fail_request(&mut self, status: u16) {
        self.log.term = Some(*b"PR");
        self.req.clear();
        self.txn = Some(HttpTxn::failed(status));
        self.cli_state = ScState::ShutR;
        self.ending.get_or_insert(Ending::Error);
    }

    /// Runs the configured parser over a complete request head.
    ///
    /// # Errors
    /// A framing violation: a malformed `Content-Length` / `Transfer-Encoding`, a bare CR as a line terminator, an invalid header name, or a
    /// malformed chunk size. Each of these is a way for two intermediaries to read the
    /// same bytes as different requests.
    fn validate_request_head(&mut self, head_len: usize) -> io::Result<bool> {
        // The built-in parser is a value on this frame: a `Box<dyn HttpStream>` per request
        // head was an allocation per request (Z2, 56 bytes). Nothing sets `parser_kind` to
        // another parser (the other kinds are not built into this crate: `build` refuses them,
        // and the FFI one needs a feature `ibex-rt` does not have), so a boxed one would be a
        // branch no run can take; a kind added later must come with its way in.
        debug_assert_eq!(self.parser_kind, ibex_proto::parser::ParserKind::H1, "only the built-in parser is wired");
        let mut h1_parser = ibex_proto::H1Parser::new(false);
        let stream: &mut dyn ibex_proto::parser::HttpStream = &mut h1_parser;
        stream.set_accept_unsafe_request(self.accept_unsafe_request);
        // The head HAProxy holds in `tune.bufsize` may not fit this HTX, whose descriptors
        // are twice as large: the buffer is made large enough for the head and one
        // descriptor per line (and the two of the start line and the end of the head).
        self.htx_tail = 0;
        self.htx_blocks = 0;
        let lines = self.req.readable()[..head_len].iter().filter(|&&b| b == b'\n').count();
        // One more line for a `Sec-WebSocket-Key` the proxy may write.
        self.htx_reserve(head_len + 64 + ibex_proto::htx::HTX_DESC_SIZE * (lines + 3));
        let raw = self.htx_buf.raw_slice_mut();
        let mut slice = ibex_proto::htx::HtxSlice::new(raw);
        stream.parse(&self.req.readable()[..head_len], &mut slice)?;
        let mut close = stream.connection_close();
        // `Content-Length` beside `Transfer-Encoding`: forwarded as HAProxy does
        // (`src/h1.c`, `h1_parse_msg_hdrs`, "T-E + C-L: force close and remove C-L"). The
        // chunked encoding frames the body, the `Content-Length` is removed so no next hop
        // can frame it by the length instead -- the smuggling this would otherwise be --
        // and the connection closes after the response (RFC 9112 section 6.3, rule 3).
        // tasks/T89; the user chose to follow HAProxy over refusing.
        let conflict = stream.framing_conflict();
        if conflict {
            slice.remove_header("content-length");
            close = true;
        }
        // The websocket handshake, for the response (T281): a key written when the request
        // has none and the frontend accepts that (`h1_process_mux`).
        let (ws, written) = crate::websocket::ReqWs::of(
            slice.as_ref().header_blocks_where(crate::websocket::ReqWs::reads).map(|(_, n, v)| (n, v)),
            self.accept_unsafe_request,
        );
        let key_written = written.is_some_and(|k| slice.add_header("sec-websocket-key", &k).is_ok());
        self.req_ws = (ws != crate::websocket::ReqWs::default()).then(|| Box::new(ws));
        self.htx_tail = slice.tail_addr();
        self.htx_blocks = slice.num_blocks();
        self.has_htx = true;
        // Modified, so the head forwarded is regenerated from the HTX, without it. So
        // too when the parser normalised the authority and `Host` (tasks/T93).
        self.htx_modified = conflict || key_written || stream.head_rewritten();
        Ok(close)
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        (matches!(self.cli_state, ScState::Closed | ScState::Error) && matches!(self.srv_state, ScState::Closed | ScState::Error))
            // A stream of an HTTP/2 connection whose transaction ended: its entry goes, and
            // a server connection it kept goes to its owner (T280).
            || self.h2_child().is_some_and(|c| c.finished)
    }

    // ---- the two state machines --------------------------------------------------

    /// Why the client's TLS handshake failed, if it did: the session ends without a
    /// transaction and logs the connection error, not a request (`session_kill_embryonic`,
    /// T262). Read from the transport, which keeps it for the session's life, so the
    /// per-connection session does not carry a copy (struct_sizes).
    #[must_use]
    pub fn hs_fail(&self) -> Option<&crate::xprt::HsFail> {
        self.cli_xprt.failure()
    }

    /// Advances the client side. Returns `true` if anything changed.
    fn process_cli(&mut self) -> bool {
        // Every error here is the client connection's: a TLS handshake that failed or
        // that the client left (T259), a TLS record that does not decrypt after it, a
        // socket error the transport does not map. It ends the client side now, as a
        // reset does, and as HAProxy does (EOF at once; `CR`, `CD` or `PR` by what was
        // under way, measured). Propagated, it ended nothing: the engine dropped it and
        // the session waited out a timeout (T261).
        let changed_io = self.process_cli_io().unwrap_or_else(|_| {
            self.client_conn_failed();
            true
        });
        let changed_trans = self.process_cli_transitions();
        changed_io || changed_trans
    }

    /// The client negotiated HTTP/2 (ALPN `h2`) and its preface is not all in yet: the
    /// connection is `HAProxy`'s h2 mux's, waiting for the preface, not an HTTP/1 one.
    #[must_use]
    pub fn h2_preface_pending(&self) -> bool {
        self.h2_ctx.is_none() && self.cli_xprt.alpn() == Some(b"h2".as_slice())
    }

    /// The client connection failed: it is closed, as one the client reset.
    fn client_conn_failed(&mut self) {
        self.cli_failed = true;
        if !matches!(self.cli_state, ScState::Closed | ScState::Error) {
            self.cli_state = ScState::Closed;
        }
        self.ending.get_or_insert(Ending::ClientAbort);
    }

    /// The server connection failed. A TLS handshake that failed, wherever it was driven
    /// from, is a connect failure: `Error`, which the engine retries (`handshake_failed`).
    /// Anything else is the server hanging up, as a reset is.
    fn server_conn_failed(&mut self) {
        if matches!(self.srv_state, ScState::Closed | ScState::Error) {
            return;
        }
        if self.srv_xprt.handshake_failed() {
            self.srv_state = ScState::Error;
        } else {
            self.srv_state = ScState::Closed;
            self.ending.get_or_insert(Ending::ServerAbort);
        }
    }

    /// Takes a parsed PROXY header as the connection's: the addresses it carries, its
    /// TLVs, and the state that lets the request through. `false` when `accept-proxy`
    /// was told to insist on v2 and this is not (the caller ends the connection).
    fn apply_proxy_header(&mut self, info: ibex_proto::ProxyInfo, is_v2: bool) -> bool {
        if self.accept_proxy_v2 && !is_v2 {
            return false;
        }
        if let Some(src) = info.src_sockaddr() {
            self.client_addr = Some(src);
        }
        if let Some(dst) = info.dst_sockaddr() {
            self.server_addr = Some(dst);
        }
        self.proxy_info = Some(Box::new(info));
        self.proxy_handshake_done = true;
        self.cli_state = if self.mode == Mode::Http { ScState::Ready } else { ScState::Established };
        true
    }

    /// `accept-proxy` is on and nothing of the header has been taken in yet.
    fn awaiting_proxy_header(&self) -> bool {
        self.accept_proxy && !self.proxy_handshake_done && self.proxy_hdr_err.is_none() && self.req.is_empty()
    }

    /// Ends the connection for a PROXY header that was not accepted, and remembers why.
    fn refuse_proxy_header(&mut self, why: ProxyHdrError) {
        self.proxy_hdr_err = Some(why);
        self.cli_state = ScState::Error;
        self.ending = Some(Ending::Error);
    }

    /// `accept-proxy` on a TLS bind: the PROXY header comes in plaintext, ahead of the
    /// ClientHello (`HAProxy` reads it in `conn_recv_proxy` before `ssl_sock` sees a
    /// byte; a `send-proxy ... ssl` server writes it from `xprt_handshake` under TLS).
    /// So it is read off the socket raw -- peeked, parsed, then taken to exactly its
    /// length -- before the transport's handshake consumes anything. `Ok(true)` once the
    /// header is in, `Ok(false)` while it is still arriving.
    fn read_proxy_header_before_tls(&mut self) -> io::Result<bool> {
        // Not before the poller reports the socket readable (`enable_accept_proxy`).
        if self.cli_cant_recv {
            return Ok(false);
        }
        let Some(fd) = self.cli.fd() else { return Ok(false) };
        let mut peek = [0u8; 16384];
        let n = match raw::peek(fd, &mut peek)? {
            Io::Done(n) => n,
            Io::WouldBlock => return Ok(false),
            r @ (Io::Eof | Io::Closed) => {
                self.refuse_proxy_header(if matches!(r, Io::Eof) { ProxyHdrError::Empty } else { ProxyHdrError::Abort });
                return Ok(false);
            }
        };
        match ibex_proto::parse_proxy_header(&peek[..n]) {
            Ok(Some((hdr, consumed))) => {
                let (info, is_v2) = (hdr.to_owned(), hdr.version == ibex_proto::ProxyVersion::V2);
                // The header is in `peek` already; this read only takes it off the socket.
                let mut sink = vec![0u8; consumed];
                // What the peek showed is on the socket, so one read takes all of it.
                let taken = if let Io::Done(k) = raw::recv(fd, &mut sink)? { k } else { 0 };
                if taken == consumed && self.apply_proxy_header(info, is_v2) {
                    return Ok(true);
                }
                self.refuse_proxy_header(if taken == consumed { ProxyHdrError::NotHdr } else { ProxyHdrError::Abort });
                Ok(false)
            }
            // Not all of it yet; a header this buffer cannot hold is not one.
            // `HAProxy` peeks once: what it did not get in that read it does not wait for.
            Ok(None) => {
                self.refuse_proxy_header(ProxyHdrError::Truncated);
                Ok(false)
            }
            Err(e) => {
                self.refuse_proxy_header(ProxyHdrError::from_parse(&e));
                Ok(false)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn process_cli_io(&mut self) -> io::Result<bool> {
        // A stream of an HTTP/2 connection has no socket: its owner moves its bytes (T280).
        if self.is_h2_child() {
            return Ok(false);
        }
        let mut changed = false;

        // A PROXY header to a TLS bind precedes the handshake: read it before the
        // transport reads anything.
        if self.accept_proxy && !self.proxy_handshake_done && self.cli_xprt.is_tls() {
            if !self.read_proxy_header_before_tls()? {
                return Ok(matches!(self.cli_state, ScState::Error | ScState::Closed));
            }
            changed = true;
        }

        // Read from the client.
        // For H2 connections (negotiated via ALPN or active H2 context), decrypted bytes
        // are fed directly into the H2 mux so they do not contaminate `self.req` (which
        // holds the HTTP/1 wire request forwarded to the backend server).
        // The H2 context is created when the client's preface is seen (below), as `HAProxy`
        // starts its mux with it: after ALPN `h2`, a client that has sent nothing is sent
        // nothing either (measured). The creation on ALPN alone that stood here no test could
        // reach, and it changed nothing a client could see (T217).
        let is_h2 = self.h2_ctx.is_some();
        if is_h2 {
            // Not while the demux is held (`H2MuxContext::wants_input`): what the client
            // sends then waits in the socket, as with `HAProxy` (T235).
            if self.cli_state.can_read() && !self.cli_cant_recv && self.h2_ctx.as_ref().is_some_and(|h| h.wants_input()) {
                let mut raw_buf = [0u8; 16384];
                let r = self.cli.recv(&mut self.cli_xprt, &mut raw_buf)?;
                self.cli_cant_recv = self.polls_cli() && self.cli_xprt.drained(r, raw_buf.len());
                match r {
                    Io::Eof => {
                        self.cli.shutdown_read();
                        self.cli_state = match self.cli_state {
                            ScState::Ready | ScState::Established => ScState::ShutR,
                            ScState::ShutW => ScState::Closed,
                            other => other,
                        };
                        changed = true;
                    }
                    Io::Closed => {
                        self.cli_state = ScState::Closed;
                        self.ending.get_or_insert(Ending::ClientAbort);
                        changed = true;
                    }
                    Io::Done(n) if n > 0 => {
                        let h2 = self.h2_ctx.as_mut().unwrap();
                        // A connection error leaves its GOAWAY queued; it is flushed and the
                        // connection closed below, as HAProxy does, not dropped unsent.
                        let _ = MuxH2.parse(h2, &raw_buf[..n]).map_err(|_| h2.ensure_goaway());
                        self.bytes_in += n as u64;
                        self.log.first_byte_now();
                        changed = true;
                    }
                    Io::Done(_) | Io::WouldBlock => {}
                }
            }
        } else {
            // Read from the client into the request buffer while reading is permitted
            // and buffer space exists. Backpressure stops reads when full.
            if self.cli_state.can_read() && !self.req.is_full() && !self.cli_cant_recv {
                let dst = self.req.writable();
                let asked = dst.len();
                let r = self.cli.recv(&mut self.cli_xprt, dst)?;
                self.cli_cant_recv = self.polls_cli() && self.cli_xprt.drained(r, asked);
                match r {
                    // The client left before a byte of the PROXY header.
                    Io::Eof if self.awaiting_proxy_header() => self.refuse_proxy_header(ProxyHdrError::Empty),
                    Io::Closed if self.awaiting_proxy_header() => self.refuse_proxy_header(ProxyHdrError::Abort),
                    Io::Eof => {
                        self.cli.shutdown_read();
                        self.cli_state = match self.cli_state {
                            ScState::Ready | ScState::Established => ScState::ShutR,
                            ScState::ShutW => ScState::Closed,
                            other => other,
                        };
                        changed = true;
                    }
                    Io::Closed => {
                        self.cli_state = ScState::Closed;
                        self.ending.get_or_insert(Ending::ClientAbort);
                        changed = true;
                    }
                    Io::Done(n) if n > 0 => {
                        self.req.commit(n);
                        self.rewrite_req_chunk_framing();
                        self.bytes_in += n as u64;
                        self.log.first_byte_now();
                        changed = true;
                    }
                    // Nothing came: the buffer taken for the read goes back
                    // (`h1_release_buf`), so a connection that has sent nothing yet holds none.
                    Io::Done(_) | Io::WouldBlock => self.req.release(),
                }
            }

            // Check for cleartext H2 preface in self.req
            if self.req.readable().starts_with(H2_CONN_PREFACE) {
                let mut h2 = H2MuxContext::new(ibex_proto::conn::ConnId(0), true);
                h2.flood_config = self.h2_flood_config;
                if let Some(m) = self.h2_flood_config.max_concurrent_streams {
                    h2.max_concurrent_streams = m;
                }
                let to_parse = self.req.readable().to_vec();
                let _ = MuxH2.parse(&mut h2, &to_parse).map_err(|_| h2.ensure_goaway());
                self.req.clear();
                self.h2_ctx = Some(Box::new(h2));
                changed = true;
            } else if self.h2_preface_pending() && !self.req.is_empty() && !H2_CONN_PREFACE.starts_with(self.req.readable()) {
                // ALPN `h2` and not the preface: `HAProxy`'s h2 mux fails the connection
                // ("invalid preface received"), logs it and closes, sending nothing (the
                // GOAWAY may be omitted); it is no HTTP/1 request. The mux holds the error,
                // as one it raised itself, for the log (T272).
                self.req.clear();
                let mut h2 = H2MuxContext::new(ibex_proto::conn::ConnId(0), true);
                h2.goaway_sent = Some((0, ibex_proto::h2::H2Error::ProtocolError));
                self.h2_ctx = Some(Box::new(h2));
                self.cli_state = ScState::Closed;
                self.ending.get_or_insert(Ending::ClientAbort);
                changed = true;
            }
        }

        if self.mode == Mode::Http {
            self.drain_request();
        }

        // Parse PROXY protocol header if accept-proxy is configured
        if self.accept_proxy && !self.proxy_handshake_done {
            if !self.req.is_empty() {
                match ibex_proto::parse_proxy_header(self.req.readable()) {
                    Ok(Some((hdr, consumed))) => {
                        let (info, is_v2) = (hdr.to_owned(), hdr.version == ibex_proto::ProxyVersion::V2);
                        if !self.apply_proxy_header(info, is_v2) {
                            self.refuse_proxy_header(ProxyHdrError::NotHdr);
                            return Ok(true);
                        }
                        self.req.consume(consumed);
                        changed = true;
                    }
                    Ok(None) => {
                        // Not all of it in the first read: `HAProxy` does not wait for the rest.
                        self.refuse_proxy_header(ProxyHdrError::Truncated);
                        return Ok(true);
                    }
                    Err(e) => {
                        // Invalid signature, malformed header, or CRC mismatch: reject immediately
                        self.refuse_proxy_header(ProxyHdrError::from_parse(&e));
                        return Ok(true);
                    }
                }
            }
            if !self.proxy_handshake_done {
                return Ok(changed);
            }
        }

        // The streams are dispatched to their own entries, and their bytes moved, by the
        // engine (`h2_owner_pass`, T280): the owner only reads and writes the socket.
        if let Some(ref mut h2) = self.h2_ctx {
            // Flush pending frames to client socket
            let pending = h2.tx_buf.len() - h2.tx_consumed;
            if pending > 0 {
                match self.cli.send(&mut self.cli_xprt, &h2.tx_buf[h2.tx_consumed..])? {
                    Io::Done(n) if n > 0 => {
                        MuxH2.consume_output(h2, n);
                        // Room for replies again: a demux held on a full output goes on.
                        h2.resume();
                        self.bytes_out += n as u64;
                        changed = true;
                    }
                    Io::Closed => {
                        self.cli_state = ScState::Closed;
                        self.ending.get_or_insert(Ending::ClientAbort);
                        changed = true;
                    }
                    _ => {}
                }
            }
            if h2.conn_state == ibex_proto::H2ConnState::GoAwaySent && h2.tx_consumed >= h2.tx_buf.len() {
                self.cli_state = ScState::Closed;
                self.ending.get_or_insert(Ending::Error);
                changed = true;
            }
        }

        // Parse HTTP request headers if in Ready state
        if !self.is_h2() && self.cli_state == ScState::Ready {
            // Empty lines before a request line are skipped (RFC 9112 section 2.2), as
            // HAProxy's parser does in `H1_MSG_RQBEFORE`.
            // A CR there must be followed by an LF (`H1_MSG_RQBEFORE_CR`): one that is not is
            // left for the request-line check to refuse (T291).
            let (data, mut blank) = (self.req.readable(), 0);
            while let Some(&b) = data.get(blank) {
                match (b, data.get(blank + 1)) {
                    (b'\n', _) => blank += 1,
                    (b'\r', Some(b'\n')) => blank += 2,
                    _ => break,
                }
            }
            self.req.consume(blank);
            let threshold = self.bufsize.saturating_sub(self.maxrewrite);
            let req_data = self.req.readable();
            if !req_data.is_empty() {
                let first_byte = req_data[0];
                let is_valid_method_char = first_byte.is_ascii_alphanumeric()
                    || matches!(first_byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' | b'\r' | b'\n');
                if !is_valid_method_char {
                    self.fail_request(400);
                    return Ok(true);
                }
            }
            // A request line with a byte HAProxy refuses is a 400 as soon as the byte is in,
            // whatever else is wrong, and so is a version that is not `HTTP/<digit>.<digit>`
            // (T286, T291).
            if self.req.readable() != b"\r"
                && ibex_proto::h1::scan_request_line(self.req.readable(), self.accept_unsafe_request) == ibex_proto::h1::ReqLineScan::Invalid
            {
                self.fail_request(400);
                return Ok(true);
            }
            // A request line the buffer cannot hold is a 414, whatever follows it (T282).
            if txn::request_line_too_long(self.req.readable(), self.bufsize) {
                self.fail_request(414);
                return Ok(true);
            }
            if let Some((hdr_len, eoh_len)) = find_eoh(self.req.readable()) {
                let total_hdr_len = hdr_len + eoh_len;

                // The head, parsed into HTX, has to fit in tune.bufsize - tune.maxrewrite:
                // HAProxy answers 431 (tasks/T87; `txn::htx_head_cost_and_size`).
                // What `%U` counts of this head: the message as received, whatever the
                // rules make of it afterwards.
                let (cost, req_htx) = txn::htx_head_cost_and_size(&self.req.readable()[..total_hdr_len]);
                if cost > threshold {
                    self.fail_request(431);
                    return Ok(true);
                }

                // Validate the head through the selected parser before anything below
                // reads it.
                //
                // What follows is a `from_utf8_lossy` and a `split_whitespace`, which
                // will parse almost anything and forwards the headers verbatim. That is
                // how a request carrying both `Content-Length` and `Transfer-Encoding`
                // reached a backend with both headers intact and a second request behind
                // them -- textbook CL.TE smuggling. Such a request is now forwarded the
                // way HAProxy forwards it: chunked, without the `Content-Length`, closing
                // after (see `validate_request_head`, tasks/T89).
                //
                // The head is already buffered, so this is a complete message and the
                // stream needs no state across calls. One allocation per request head
                // for the trait object; it buys the framing rules and the seam that lets
                // the parser be swapped.
                let mut close = match self.validate_request_head(total_hdr_len) {
                    Ok(close) => close,
                    Err(e) => {
                        // 400, or the 413 / 422 HAProxy answers to some heads (T276).
                        self.fail_request(ibex_proto::h1::Refusal::status_of(&e));
                        if ibex_proto::h1::Refusal::is_quiet(&e) {
                            if let Some(t) = self.txn.as_mut() {
                                t.quiet = true;
                            }
                        }
                        return Ok(true);
                    }
                };
                if self.has_htx {
                    let (req_m, req_u, conn_close, wire_replacement) = {
                        let htx = ibex_proto::htx::HtxSliceRef::new(
                            self.htx_buf.raw_slice(),
                            self.htx_blocks,
                        );
                        let mut req_m = None;
                        let mut req_u = None;
                        let mut conn_close = false;
                        if let Some(req) = htx.req_line() {
                            req_m = Some(req.method.to_string());
                            req_u = Some(req.uri.to_string());
                            if req.version == "HTTP/1.0"
                                && !htx.headers().any(|(k, v)| k.eq_ignore_ascii_case("connection") && txn::connection_has(v, "keep-alive"))
                            {
                                conn_close = true;
                            }
                        }
                        if htx.headers().any(|(k, v)| k.eq_ignore_ascii_case("connection") && txn::connection_has(v, "close")) {
                            conn_close = true;
                        }
                        let wire_replacement = if self.htx_modified {
                            // Sized to the head, not a fixed buffer (tasks/T101).
                            Some(htx.write_h1_wire_vec())
                        } else {
                            None
                        };
                        (req_m, req_u, conn_close, wire_replacement)
                    };
                    if let Some(m) = req_m {
                        self.req_method = Some(m);
                    }
                    if let Some(u) = req_u {
                        self.req_uri = Some(u);
                    }
                    close |= conn_close;
                    // Only regenerate wire buffer if HTX was actually modified
                    if let Some(wire) = wire_replacement {
                        self.req.replace_prefix(total_hdr_len, &wire);
                    }
                } else {
                    let hdr_bytes = &self.req.readable()[..total_hdr_len];
                    let hdr_str = String::from_utf8_lossy(hdr_bytes).to_string();
                    let (first_line, rest_headers) =
                        if let Some((fl, rest)) = hdr_str.split_once("\r\n") {
                            (fl, rest)
                        } else if let Some((fl, rest)) = hdr_str.split_once('\n') {
                            (fl, rest)
                        } else if let Some((fl, rest)) = hdr_str.split_once('\r') {
                            (fl, rest)
                        } else {
                            (hdr_str.as_ref(), "")
                        };

                    let mut parts = first_line.split_whitespace();
                    if let Some(m) = parts.next() {
                        self.req_method = Some(m.to_string());
                    }
                    if let Some(u) = parts.next() {
                        self.req_uri = Some(u.to_string());
                    }
                    let mut hdrs: Vec<(String, String)> = Vec::new();
                    for line in rest_headers.lines() {
                        let trimmed = line.trim_end_matches(['\r', '\n']);
                        if trimmed.is_empty() {
                            continue;
                        }
                        if trimmed.starts_with(' ') || trimmed.starts_with('\t') {
                            if let Some(last) = hdrs.last_mut() {
                                last.1.push(' ');
                                last.1.push_str(trimmed.trim());
                            }
                        } else if let Some((k, v)) = trimmed.split_once(':') {
                            hdrs.push((k.trim().to_string(), v.trim().to_string()));
                        }
                    }
                    if hdrs.iter().any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close")) {
                        close = true;
                    }
                    if first_line.contains("HTTP/1.0") && !hdrs.iter().any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("keep-alive")) {
                        close = true;
                    }
                    self.req_headers = Some(hdrs);
                }

                // `txn->uri`: the request line once the parser has normalised the authority
                // (`HAProxy` takes it from the HTX start line), before any rule rewrites it
                // (and keeps its first `tune.http.logurilen`, 1024, bytes). The head forwarded
                // may have been regenerated just above, so its length is read again.
                self.log.request = Some(crate::txnlog::loop_now());
                if self.keep_request_line {
                    let head = self.req.readable();
                    let line_end = head.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(head.len());
                    let mut line = String::from_utf8_lossy(&head[..line_end.min(1024)]).into_owned();
                    if self.h3 {
                        let host = self.htx_slice().and_then(|h| {
                            h.headers().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.to_string())
                        });
                        line = h3_log_line(&line, host.as_deref());
                    }
                    self.log.request_line = Some(line);
                }

                if !self.cliexp.is_empty() {
                    let hdr_bytes = &self.req.readable()[..total_hdr_len];
                    let hdr_str = String::from_utf8_lossy(hdr_bytes);
                    let rewritten = rewrite_header_block(&hdr_str, &self.cliexp);
                    self.req.replace_prefix(total_hdr_len, rewritten.as_bytes());
                }

                // The head may have been rewritten above; its framing is read from what
                // will be forwarded.
                let framing = find_eoh(self.req.readable())
                    .map_or(txn::Framing::None, |(h, e)| txn::request_framing(&self.req.readable()[..h + e]));
                // The chunked body already received with the head is checked before any of
                // the request is forwarded: HAProxy parses what is in its buffer into HTX
                // first, and answers a malformed chunk with 400 without contacting the
                // server. Forwarded, the bytes Ibex refuses mid-body reached the server
                // verbatim (tasks/T276, V&V VV-2).
                // A trailer section past its cap is refused too, but `HAProxy` writes nothing
                // back then: it logs a 400 `PR` and closes (3.5-dev8, T281).
                if framing == txn::Framing::Chunked {
                    match txn::MsgState::head(framing).check_body(self.req.readable()) {
                        txn::BodyCheck::Broken | txn::BodyCheck::TooLarge { trailer: false } => {
                            self.fail_request(400);
                            return Ok(true);
                        }
                        txn::BodyCheck::TooLarge { trailer: true } => {
                            self.fail_request(400);
                            if let Some(t) = self.txn.as_mut() {
                                t.quiet = true;
                            }
                            return Ok(true);
                        }
                        txn::BodyCheck::Held { trailer: true, .. } if self.req.len() >= self.bufsize => {
                            // Held whole until the section is (`MsgState::holds_trailer`).
                            self.req.grow_capacity(2 * self.bufsize);
                        }
                        txn::BodyCheck::Fine | txn::BodyCheck::Held { .. } => {}
                    }
                }
                let mut txn = HttpTxn::new(framing, close || self.close_client);
                txn.req_htx = req_htx;
                let line = self.req.readable().split(|&b| b == b'\n').next().map_or(&[][..], <[u8]>::trim_ascii_end);
                let ver = &line[line.len().saturating_sub(8)..];
                txn.req_http11 = ibex_proto::h1::version_is_11(ver);
                txn.req_version = txn::version_digits(ver).unwrap_or(txn.req_version);
                // The client's own method: rules that rewrite it have not run yet.
                txn.client_head = self.req_method.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("HEAD"));
                self.txn = Some(txn);
                self.rewrite_req_chunk_framing();
                self.cli_state = ScState::Established;
                changed = true;
            } else if match ibex_proto::h1::scan_request_line(self.req.readable(), self.accept_unsafe_request) {
                ibex_proto::h1::ReqLineScan::Complete(l) => ibex_proto::h1::header_lines_invalid(self.req.readable(), l.eol + l.eol_len, self.accept_unsafe_request),
                _ => false,
            } {
                // A head not yet whole with a byte HAProxy refuses in a header line: 400 at
                // that byte, not a 408 later (T291).
                self.fail_request(400);
                return Ok(true);
            } else if let early @ (ibex_proto::h1::ClEarly::Bad | ibex_proto::h1::ClEarly::Conflict) = match ibex_proto::h1::scan_request_line(self.req.readable(), self.accept_unsafe_request) {
                ibex_proto::h1::ReqLineScan::Complete(l) => ibex_proto::h1::content_length_early(self.req.readable(), l.eol + l.eol_len),
                _ => ibex_proto::h1::ClEarly::Fine,
            } {
                // A head not yet whole with a bad `Content-Length` line, refused when the
                // line completes as HAProxy does: a 400, or for a value that differs from an
                // earlier line's a close with nothing written (T315).
                self.fail_request(400);
                if early == ibex_proto::h1::ClEarly::Conflict {
                    if let Some(t) = self.txn.as_mut() {
                        t.quiet = true;
                    }
                }
                return Ok(true);
            } else if self.req.readable().len() + 56 >= self.bufsize {
                // No end of head and the buffer is full: 431 as well. Measured on 3.5-dev8,
                // a partial head draws it from `bufsize - 56` bytes on (the 40 of `struct
                // htx` and two blocks), whatever `tune.maxrewrite` is.
                self.fail_request(431);
                return Ok(true);
            }
        }

        // Drain pending synthetic response into rep if space is available
        if let Some(PendingOut::Raw(ref data, ref mut offset)) = self.pending_resp.as_deref_mut() {
            if self.rep.writable().is_empty() && self.rep.len() < self.rep.capacity() {
                self.rep.compact();
            }
            let space = self.rep.writable().len();
            if space > 0 && *offset < data.len() {
                let to_copy = space.min(data.len() - *offset);
                self.rep.writable()[..to_copy].copy_from_slice(&data[*offset..*offset + to_copy]);
                self.rep.commit(to_copy);
                *offset += to_copy;
                changed = true;
            }
            if *offset >= data.len() && self.rep.is_empty() {
                self.pending_resp = None;
            }
        }

        // A response to a HEAD that carries a body anyway (the server answered a GET):
        // the body is read to its end and dropped.
        if self.mode == Mode::Http && !self.is_h2() {
            if let Some(t) = self.txn.as_mut() {
                let n = t.skip_head_body(self.rep.readable());
                if n > 0 {
                    self.rep.consume(n);
                    changed = true;
                }
            }
        }

        // Write response data back to the client while writing is permitted: in HTTP, the
        // current response's bytes and no more.
        let window = self.rep_window();
        if !self.is_h2() && self.cli_state.can_write() && window > 0 && !self.res_inspect_pending {
            match self.cli.send(&mut self.cli_xprt, &self.rep.readable()[..window])? {
                Io::Done(n) if n > 0 => {
                    if self.mode == Mode::Http {
                        if let Some(t) = self.txn.as_mut() {
                            t.response_sent(self.rep.readable(), n);
                        }
                    }
                    self.rep.consume(n);
                    self.bytes_out += n as u64;
                    changed = true;
                }
                Io::Closed => {
                    self.cli_state = ScState::Closed;
                    self.ending.get_or_insert(Ending::ClientAbort);
                    changed = true;
                }
                Io::Done(_) | Io::WouldBlock | Io::Eof => {}
            }
        }

        Ok(changed)
    }

    fn process_cli_transitions(&mut self) -> bool {
        // An HTTP connection's life is decided per transaction, by the engine
        // (`end_txn`): a server closing ends a response, not the client connection.
        if self.is_h2() || self.mode == Mode::Http {
            return false;
        }

        let mut changed = false;

        match self.cli_state {
            ScState::Ready | ScState::Established => {
                let srv_done_sending = matches!(
                    self.srv_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if srv_done_sending && self.rep.is_empty() && self.pending_resp.is_none() && !self.res_inspect_pending {
                    self.shutw_cli();
                    self.cli_state = ScState::ShutW;
                    self.ending
                        .get_or_insert(if self.srv_state == ScState::Error {
                            Ending::ServerAbort
                        } else {
                            Ending::Complete
                        });
                    changed = true;
                } else {
                    let srv_done_receiving = matches!(
                        self.srv_state,
                        ScState::ShutW | ScState::Closed | ScState::Error
                    );
                    if srv_done_receiving {
                        self.cli.shutdown_read();
                        self.cli_state = ScState::ShutR;
                        changed = true;
                    }
                }
            }
            ScState::ShutR => {
                let srv_done_sending = matches!(
                    self.srv_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if srv_done_sending && self.rep.is_empty() && self.pending_resp.is_none() && !self.res_inspect_pending {
                    self.shutw_cli();
                    self.cli_state = ScState::Closed;
                    self.srv_state = ScState::Closed;
                    self.ending
                        .get_or_insert(if self.srv_state == ScState::Error {
                            Ending::ServerAbort
                        } else {
                            Ending::Complete
                        });
                    changed = true;
                }
            }
            ScState::ShutW => {
                let srv_done_receiving = matches!(
                    self.srv_state,
                    ScState::ShutW | ScState::Closed | ScState::Error
                );
                if srv_done_receiving {
                    self.cli_state = ScState::Closed;
                    changed = true;
                }
            }
            _ => {}
        }

        changed
    }

    /// Advances the server side. Returns `true` if anything changed.
    ///
    /// Mirrors 1.0's `process_srv()`.
    fn process_srv(&mut self) -> io::Result<bool> {
        match self.srv_state {
            ScState::Init if self.mode == Mode::Http => Ok(false),
            ScState::Init => {
                // While idle, give up if the client is gone. A client that only shut its
                // sending side (`ShutR` here) with nothing to forward still gets its first
                // connect: `HAProxy` forwards the close and relays a server that speaks
                // first (measured on 3.5-dev8, T305 item 6), as Ibex's own connect at
                // accept does. Only its retries are dropped (`--`, one retry counted).
                let cli_done = matches!(self.cli_state, ScState::Closed | ScState::Error | ScState::ShutW)
                    || (self.cli_state == ScState::ShutR && self.req.is_empty() && self.conn_retries < self.max_retries);
                if cli_done {
                    self.srv_state = ScState::Closed;
                    return Ok(true);
                }
                Ok(false)
            }
            ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW => {
                if self.srv.is_none() {
                    self.srv_state = ScState::Error;
                    return Ok(true);
                }
                self.process_srv_active()
            }
            _ => Ok(false),
        }
    }

    fn process_srv_active(&mut self) -> io::Result<bool> {
        let changed_io = self.process_srv_io()?;

        let changed_trans = self.process_srv_transitions();
        Ok(changed_io || changed_trans)
    }

    fn process_srv_io(&mut self) -> io::Result<bool> {
        let mut changed = false;

        if self.srv_xprt.is_tls() && !self.srv_xprt.is_ready() {
            let sfd = self
                .srv
                .as_ref()
                .map(AsFd::as_fd)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
            match self.srv_xprt.handshake(sfd) {
                Ok(true) => {
                    // The connection is established only now: `timeout connect` covered
                    // the handshake (HAProxy: a TLS handshake that hangs is a connect
                    // timeout), and the server timer starts here.
                    self.conn_exp = Tick::ETERNITY;
                    changed = true;
                }
                Ok(false) => {}
                Err(e) => {
                    // A connect failure, which the engine retries (`srv_xprt.handshake_failed`).
                    self.srv_state = ScState::Error;
                    return Err(e);
                }
            }
        }

        let window = self.req_window();
        // `retry-on <status>`: the request is copied the first time it is sent, whole, so
        // that it can be sent again when the answer is one to retry on.
        if window > 0 && self.srv_state.can_write() && self.mode == Mode::Http {
            if let Some(t) = self.txn.as_mut().filter(|t| matches!(t.l7, txn::L7Retry::Armed)) {
                let data = &self.req.readable()[..window];
                let mut after = t.req;
                after.advance(data);
                t.l7 = if after.is_done() && window <= self.bufsize {
                    txn::L7Retry::Saved(Box::new(txn::L7Snapshot { bytes: data.to_vec(), req_state: t.req }))
                } else {
                    txn::L7Retry::Dead
                };
            }
        }
        let mut head_gone = false;
        if self.srv_state.can_write() && (window > 0 || self.srv_xprt.wants_write()) {
            let r = {
                let sfd = self
                    .srv
                    .as_ref()
                    .map(AsFd::as_fd)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
                match self.srv_xprt.send(sfd, &self.req.readable()[..window]) {
                    Err(e) if e.kind() == io::ErrorKind::InvalidData && self.srv_xprt.is_ready() => Io::Closed,
                    r => r?,
                }
            };
            match r {
                Io::Done(n) if n > 0 => {
                    if self.mode == Mode::Http {
                        if let Some(t) = self.txn.as_mut() {
                            t.request_consumed(self.req.readable(), n);
                            head_gone = !matches!(t.req, txn::MsgState::Head { .. });
                        }
                    }
                    self.req.consume(n);
                    if head_gone {
                        self.release_forwarded_head();
                    }
                    changed = true;
                }
                Io::Closed => {
                    self.srv_state = ScState::Closed;
                    self.ending.get_or_insert(Ending::ServerAbort);
                    changed = true;
                }
                Io::Done(_) | Io::WouldBlock | Io::Eof => {}
            }
        }

        if self.srv_state.can_read() && !self.rep.is_full() && self.reads_server() && !self.srv_cant_recv {
            let r = {
                let sfd = self
                    .srv
                    .as_ref()
                    .map(AsFd::as_fd)
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
                let dst = self.rep.writable();
                let asked = dst.len();
                // A TLS protocol error *after* the handshake (a post-handshake alert,
                // such as a server that wanted a client certificate and the TLS 1.3
                // handshake completed on our side first) is the server hanging up:
                // HAProxy logs `SH` and answers 502. A failure *during* the handshake is
                // a connect failure instead, which the engine retries (`handshake_failed`),
                // so it is left to propagate.
                let r = match self.srv_xprt.recv(sfd, dst) {
                    Err(e) if e.kind() == io::ErrorKind::InvalidData && self.srv_xprt.is_ready() => Io::Closed,
                    r => r?,
                };
                self.srv_cant_recv = self.mode == Mode::Http && !self.srv_xprt.is_tls() && drained(r, asked);
                r
            };
            match r {
                Io::Eof => {
                    if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                        self.srv_xprt.send_close_notify(sfd);
                        raw::shutdown_read(sfd);
                    }
                    self.srv_state = match self.srv_state {
                        ScState::Ready | ScState::Established => ScState::ShutR,
                        ScState::ShutW => ScState::Closed,
                        other => other,
                    };
                    changed = true;
                }
                Io::Closed => {
                    self.srv_state = ScState::Closed;
                    self.ending.get_or_insert(Ending::ServerAbort);
                    changed = true;
                }
                Io::Done(n) if n > 0 => {
                    self.rep.commit(n);
                    self.rewrite_rep_chunk_framing();
                    self.log.bytes_from_server += n as u64;
                    changed = true;
                }
                Io::Done(_) | Io::WouldBlock => {}
            }
        }

        Ok(changed)
    }

    fn process_srv_transitions(&mut self) -> bool {
        if self.mode == Mode::Http {
            return false;
        }
        let mut changed = false;

        match self.srv_state {
            ScState::Ready | ScState::Established => {
                let cli_done_sending = matches!(
                    self.cli_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if cli_done_sending && self.req.is_empty() {
                    if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                        self.srv_xprt.send_close_notify(sfd);
                        raw::shutdown_write(sfd);
                    }
                    self.srv_state = ScState::ShutW;
                    changed = true;
                } else {
                    let cli_done_receiving = matches!(
                        self.cli_state,
                        ScState::ShutW | ScState::Closed | ScState::Error
                    );
                    if cli_done_receiving {
                        if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                            raw::shutdown_read(sfd);
                        }
                        self.srv_state = ScState::ShutR;
                        changed = true;
                    }
                }
            }
            ScState::ShutR => {
                let cli_done_sending = matches!(
                    self.cli_state,
                    ScState::ShutR | ScState::Closed | ScState::Error
                );
                if cli_done_sending && self.req.is_empty() {
                    if let Some(sfd) = self.srv.as_ref().map(AsFd::as_fd) {
                        self.srv_xprt.send_close_notify(sfd);
                        raw::shutdown_write(sfd);
                    }
                    self.srv_state = ScState::Closed;
                    changed = true;
                }
            }
            ScState::ShutW => {
                let cli_done_receiving = matches!(
                    self.cli_state,
                    ScState::ShutW | ScState::Closed | ScState::Error
                );
                if cli_done_receiving {
                    self.srv_state = ScState::Closed;
                    changed = true;
                }
            }
            _ => {}
        }

        changed
    }

    /// Runs both sides until neither changes state.
    ///
    /// Mirrors 1.0's `process_task()`. The iteration bound is not decoration: each pass
    /// is driven by data the peer controls, so an unbounded loop here is a
    /// denial-of-service primitive. On exhaustion we return normally and the engine
    /// requeues us ([`Self::wants_rerun`]), which costs a little latency and cannot hang the
    /// thread. The requeue is needed: what a pass would have moved on next may wait on no
    /// socket event at all, an HTTP/2 request body held in its stream's message with the
    /// server-bound buffer emptied and the client's socket drained (T221).
    ///
    /// An error on either connection ends that side here (its state and `ending`), for the
    /// engine's close paths to act on in the same pass: nothing is returned for a caller to
    /// drop. The engine dropped every error `process` returned, and an error ended nothing
    /// until a timeout fired (T261).
    pub fn advance(&mut self, now: Tick) {
        self.passes_ran_out = false;
        for pass in 0..16 {
            let a = self.process_cli();
            let b = self.process_srv().unwrap_or_else(|_| {
                self.server_conn_failed();
                true
            });
            if !a && !b {
                break;
            }
            self.passes_ran_out = pass == 15;
            // A stream of an HTTP/2 connection waits on its client alone: what its owner
            // moves for it re-arms its timer (`h2_bridge_moves`), its server's bytes do not
            // (`HAProxy` times out a stream whose response the client's window holds while
            // the server still sends, T300).
            if !self.is_h2_child()
                && matches!(
                    self.cli_state,
                    ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
                )
            {
                self.arm_client(now);
            }
            if matches!(
                self.srv_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            ) {
                self.arm_server(now);
            }
        }
        self.arm_request(now);
    }

    /// [`Self::advance`], for callers written when it returned an error.
    ///
    /// # Errors
    /// None: an error ends its side of the session instead (T261).
    pub fn process(&mut self, now: Tick) -> io::Result<()> {
        self.advance(now);
        Ok(())
    }

    /// Applies whichever timeout has fired, if any. A timer that has expired but no
    /// longer applies (the server side released, or idle between transactions; the client
    /// while its response is awaited) is disarmed, as `HAProxy` sets a timer it does not
    /// need to `TICK_ETERNITY`: left armed and expired, it is the session's next expiry
    /// and wakes it at once, every pass. Progress, or a new server connection, re-arms it.
    pub fn check_timeouts(&mut self, now: Tick) -> bool {
        if self.conn_exp.is_expired(now) {
            self.conn_exp = Tick::ETERNITY;
            if self.conn_timer_live() {
                self.srv_state = ScState::Error;
                self.ending.get_or_insert(Ending::Timeout(Which::Connect));
                return true;
            }
        }
        if self.cli_exp.is_expired(now) {
            if self.cli_timer_live() {
                // An HTTP/2 connection that is idle gets a GOAWAY (`NO_ERROR`, the last
                // stream it opened) at the end of `timeout client`, and the same again,
                // with the close, at the end of the next one (measured on HAProxy 3.5,
                // `h2c_timeout` in `src/mux_h2.c`).
                if let Some(h2) = self.h2_ctx.as_mut() {
                    let last = h2.last_client_stream_id;
                    if self.h2_idle_goaway {
                        // The second expiry: the GOAWAY is written if the socket takes it at
                        // once, and the connection is let go, as `h2_timeout_task` does ("try
                        // to send but no need to insist", then `h2_release`). Left to close
                        // when its output drained, a client that reads nothing was kept, and
                        // this timer, still expired, fired on every pass: a core spinning and
                        // a GOAWAY more queued each time (T288, MY-3).
                        h2.send_goaway(last, ibex_proto::h2::H2Error::NoError, &[]);
                        if let Ok(Io::Done(n)) = self.cli.send(&mut self.cli_xprt, &h2.tx_buf[h2.tx_consumed..]) {
                            MuxH2.consume_output(h2, n);
                            self.bytes_out += n as u64;
                        }
                        self.cli_state = ScState::Closed;
                        self.cli_exp = Tick::ETERNITY;
                    } else {
                        h2.enqueue_frame(&ibex_proto::h2::Frame::GoAway { last_stream_id: last, error_code: ibex_proto::h2::H2Error::NoError, debug_data: Vec::new() });
                        self.h2_idle_goaway = true;
                        self.cli_exp = Tick::ETERNITY;
                        self.arm_client(now);
                    }
                    self.ending.get_or_insert(Ending::Timeout(Which::Client));
                    return true;
                }
                self.cli_state = ScState::Error;
                self.ending.get_or_insert(Ending::Timeout(Which::Client));
                return true;
            }
            self.cli_exp = Tick::ETERNITY;
        }
        if self.req_exp.is_expired(now) && self.expire_request() {
            return true;
        }
        if self.srv_exp.is_expired(now) {
            if self.srv_timer_live() {
                self.srv_state = ScState::Error;
                self.ending.get_or_insert(Ending::Timeout(Which::Server));
                return true;
            }
            self.srv_exp = Tick::ETERNITY;
        }
        false
    }

    /// `timeout http-request` is over: if the head is still not complete, that is the
    /// client's timeout, `408` and all. Whether it fired.
    fn expire_request(&mut self) -> bool {
        self.req_exp = Tick::ETERNITY;
        // Armed before the connection was known to be HTTP/2: its waits are its own now.
        if self.h2_ctx.is_some() {
            return false;
        }
        let live = (self.head_pending() || self.idle_wait()) && self.cli_timer_live();
        self.req_idle = false;
        live.then(|| {
            self.cli_state = ScState::Error;
            self.ending.get_or_insert(Ending::Timeout(Which::Client));
        })
        .is_some()
    }

    fn conn_timer_live(&self) -> bool {
        self.srv_state == ScState::Connecting
            || (matches!(self.srv_state, ScState::Ready | ScState::Established) && self.srv_xprt.is_tls() && !self.srv_xprt.is_ready())
    }

    fn cli_timer_live(&self) -> bool {
        // A tarpitted request is held for `timeout tarpit` alone.
        if self.txn.as_ref().is_some_and(|t| t.body_wait.is_some_and(|w| w.tarpit)) {
            return false;
        }
        // An HTTP/2 connection has no timer of its own while streams are attached: each
        // stream has its own (`h2c_may_expire`, T300).
        if self.h2_owner().is_some_and(|o| !o.children.is_empty()) {
            return false;
        }
        // Once an HTTP request is complete the client owes nothing until its response
        // starts: the wait belongs to `timeout server`, as in HAProxy.
        let awaiting_server = self.mode == Mode::Http
            && self.txn.as_ref().is_some_and(|t| t.req.is_done() && !t.local && t.error.is_none())
            && !self.has_pending_output();
        // So is the turnaround before a retry (`SC_ST_TAR`).
        !awaiting_server
            && !self.retry_after.is_set()
            && matches!(
                self.cli_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            )
    }

    fn srv_timer_live(&self) -> bool {
        // A server connection kept idle between HTTP transactions owes nothing.
        let srv_idle = self.mode == Mode::Http && self.txn.is_none();
        // Nor one whose request is still coming, with nothing of it waiting for the server
        // to take: the wait is the client's (`SE_FL_EXP_NO_DATA` until the request's end,
        // `sc_rcv_may_expire`). A stalled upload ends at `timeout client`, not at a shorter
        // `timeout server` (T305 item 2). A send the server does not take still times out.
        let awaiting_client = self.mode == Mode::Http
            && self.req.readable().is_empty()
            && self.txn.as_ref().is_some_and(|t| !matches!(t.req, txn::MsgState::Done | txn::MsgState::Tunnel));
        !srv_idle
            && !awaiting_client
            && matches!(
                self.srv_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            )
    }

    /// The earliest deadline across both sides, for the scheduler's wait queue.
    #[must_use]
    pub fn next_expiry(&self) -> Tick {
        let mut exp = self.cli_exp.earliest(self.req_exp).earliest(self.srv_exp).earliest(self.conn_exp).earliest(self.retry_after).earliest(self.srv_park_exp);
        if let Some(q) = self.queue.as_ref() {
            exp = exp.earliest(q.deadline);
        }
        if let Some(i_exp) = self.inspect_exp {
            if !self.tcp_inspect_done || self.be_inspect {
                exp = exp.earliest(i_exp);
            }
        }
        if let (true, Some(r_exp)) = (self.res_inspect_pending, self.res_inspect_exp) {
            exp = exp.earliest(r_exp);
        }
        // A request held for its body (`wait-for-body`) answers 408 when the time is up.
        if let Some(wait) = self.txn.as_ref().and_then(|t| t.body_wait) {
            exp = exp.earliest(wait.deadline);
        }
        // So is a response, held for its body: `504`.
        if let Some(wait) = self.txn.as_ref().and_then(|t| t.rsp_wait) {
            exp = exp.earliest(wait.deadline);
        }
        exp
    }

    /// What each side needs from the poller.
    ///
    /// Derived from buffer occupancy, which is what makes backpressure work: a full
    /// request buffer stops us asking for client readability, the client's socket
    /// buffer fills, and TCP slows the sender.
    #[must_use]
    pub fn interests(&self) -> (Want, Want) {
        // An HTTP/2 client is written only what is framed in `tx_buf`: the response in
        // `rep` goes there as the flow-control windows allow (`h2_forward_response`), and
        // what they hold back cannot be written. Counting it asked the level-triggered
        // poller for writability with nothing to write, and a client whose window stayed
        // at 0 had a core spin on EPOLLOUT (T248). A `WINDOW_UPDATE` arrives as a read.
        let has_pending = if self.h2_ctx.is_some() {
            self.pending_resp.as_deref().is_some_and(PendingOut::has_output)
                || self.h2_ctx.as_ref().is_some_and(|h| h.tx_consumed < h.tx_buf.len())
        } else {
            self.has_pending_output()
        };
        // `cli_xprt.wants_write()` is the TLS term. A handshake is mostly the server
        // talking, and the condition below it -- "we have a response queued" -- is false
        // throughout one, so without this the connection is never polled for writability
        // and the handshake never finishes. It is always false for a plaintext session.
        let cli = Want {
            // An HTTP/2 demux that is held reads nothing (`H2MuxContext::wants_input`): asked
            // for readability then, the level-triggered poller woke the session for the
            // bytes left in the socket over and over, a core spinning (T235).
            read: self.cli_state.can_read() && !self.req.is_full() && self.h2_ctx.as_ref().is_none_or(|h| h.wants_input()),
            write: self.cli_state.can_write() && (has_pending || self.cli_xprt.wants_write()),
        };
        let srv = match self.srv_state {
            ScState::Connecting => Want {
                read: false,
                write: true,
            },
            ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW => Want {
                read: self.srv_state.can_read() && !self.rep.is_full() && self.reads_server(),
                write: self.srv_state.can_write() && (self.req_window() > 0 || self.srv_xprt.wants_write()),
            },
            _ => Want::default(),
        };
        (cli, srv)
    }
}

/// Whether a read that asked for `asked` bytes and got `r` left the socket drained, so
/// that reading it again before the poller reports it readable would only return
/// `EAGAIN`. A short read is enough: `HAProxy` stops there too (`raw_sock_to_buf`), and an
/// EOF behind the data is announced by `EPOLLRDHUP`.
fn drained(r: Io, asked: usize) -> bool {
    match r {
        Io::WouldBlock => true,
        Io::Done(n) => n < asked,
        Io::Eof | Io::Closed => false,
    }
}

fn has_header(head: &str, name: &str) -> bool {
    head.split('\n')
        .skip(1)
        .any(|l| l.split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name)))
}

#[must_use]
pub fn find_eoh(buf: &[u8]) -> Option<(usize, usize)> {
    // Each end starts with a CR or an LF: the bytes before the next one are passed over.
    let mut i = 0;
    while let Some(n) = buf[i..].iter().position(|&b| b == b'\r' || b == b'\n') {
        i += n;
        let rest = &buf[i..];
        if rest.starts_with(b"\r\n\r\n") {
            return Some((i, 4));
        }
        // A line ended by a bare LF, then the blank line as CRLF: HAProxy ends the head
        // there, and what follows is the next request (T291).
        if rest.starts_with(b"\n\r\n") {
            return Some((i, 3));
        }
        if rest.starts_with(b"\n\n") || rest.starts_with(b"\r\r") {
            return Some((i, 2));
        }
        i += 1;
    }
    None
}

/// [`find_eoh`] a byte at a time.
#[cfg(test)]
fn find_eoh_bytewise(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len() {
        if i + 4 <= buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, 4));
        }
        if i + 3 <= buf.len() && &buf[i..i + 3] == b"\n\r\n" {
            return Some((i, 3));
        }
        if i + 2 <= buf.len() && &buf[i..i + 2] == b"\n\n" {
            return Some((i, 2));
        }
        if i + 2 <= buf.len() && &buf[i..i + 2] == b"\r\r" {
            return Some((i, 2));
        }
    }
    None
}

#[must_use]
pub fn format_log_fmt(fmt: &str, client_addr: Option<SocketAddr>, elapsed_ms: u64) -> String {
    let mut out = String::with_capacity(fmt.len() + 16);
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            if let Some(&next) = chars.peek() {
                match next {
                    'c' => {
                        chars.next();
                        if let Some(&sub) = chars.peek() {
                            if sub == 'i' {
                                chars.next();
                                if let Some(sa) = client_addr {
                                    out.push_str(&sa.ip().to_string());
                                }
                            } else if sub == 'p' {
                                chars.next();
                                if let Some(sa) = client_addr {
                                    out.push_str(&sa.port().to_string());
                                }
                            } else {
                                out.push('%');
                                out.push('c');
                            }
                        } else {
                            out.push('%');
                            out.push('c');
                        }
                    }
                    'T' => {
                        chars.next();
                        if let Some(&sub) = chars.peek() {
                            if sub == 'r' {
                                chars.next();
                                out.push_str(&elapsed_ms.to_string());
                            } else {
                                out.push('%');
                                out.push('T');
                            }
                        } else {
                            out.push('%');
                            out.push('T');
                        }
                    }
                    '%' => {
                        chars.next();
                        out.push('%');
                    }
                    other => {
                        out.push('%');
                        chars.next();
                        out.push(other);
                    }
                }
            } else {
                out.push('%');
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn modify_http_headers<F>(hdr_str: &str, mut transform: F) -> String
where
    F: FnMut(&str, &mut Vec<(String, String)>),
{
    let use_crlf = hdr_str.contains("\r\n");
    let line_sep = if use_crlf { "\r\n" } else { "\n" };

    let (first_line, rest) = match hdr_str.split_once(line_sep) {
        Some((fl, r)) => (fl, r),
        None => (hdr_str, ""),
    };

    let mut headers = Vec::new();
    for line in rest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    transform(first_line, &mut headers);

    let mut out = String::with_capacity(hdr_str.len() + 64);
    out.push_str(first_line);
    out.push_str("\r\n");
    for (k, v) in headers {
        out.push_str(&k);
        out.push_str(": ");
        out.push_str(&v);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

#[must_use]
pub fn apply_set_header(hdr_str: &str, name: &str, val: &str) -> String {
    modify_http_headers(hdr_str, |_first_line, headers| {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        headers.push((name.to_string(), val.to_string()));
    })
}

#[must_use]
pub fn apply_add_header(hdr_str: &str, name: &str, val: &str) -> String {
    modify_http_headers(hdr_str, |_first_line, headers| {
        headers.push((name.to_string(), val.to_string()));
    })
}

#[must_use]
pub fn apply_del_header(hdr_str: &str, name: &str) -> String {
    modify_http_headers(hdr_str, |_first_line, headers| {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    })
}

#[must_use]
pub fn eval_acl_term(
    term: &ibex_config::AclTerm,
    acls: &ibex_sample::Acls,
    registry: &Registry,
    ctx: &SampleContext,
) -> bool {
    let res = if let Some(expr) = acls.get(&term.name) {
        expr.eval(registry, ctx)
    } else if let Ok(expr) = Expr::cached(&term.name) {
        expr.eval(registry, ctx)
    } else {
        false
    };
    if term.negated {
        !res
    } else {
        res
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclEvalResult {
    Matched,
    NotMatched,
    MissingData,
}

#[must_use]
pub fn eval_acl_term_extended(
    term: &ibex_config::AclTerm,
    acls: &ibex_sample::Acls,
    registry: &Registry,
    ctx: &SampleContext,
    req_bytes: &[u8],
    can_wait: bool,
) -> AclEvalResult {
    let expr_opt = acls.get(&term.name);
    let parsed_expr;
    let expr = if let Some(e) = expr_opt {
        e
    } else if let Ok(e) = Expr::cached(&term.name) {
        parsed_expr = e;
        &*parsed_expr
    } else {
        return if term.negated {
            AclEvalResult::Matched
        } else {
            AclEvalResult::NotMatched
        };
    };

    if can_wait {
        if expr.fetch_name == "wait_end" {
            // `smp_fetch_wait_end`: no sample until the rules cannot wait any longer.
            return AclEvalResult::MissingData;
        } else if expr.fetch_name == "req.payload" || expr.fetch_name == "payload" {
            let offset = expr
                .fetch_args
                .first()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let len = expr
                .fetch_args
                .get(1)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(0);
            let min_needed = if len > 0 {
                offset.saturating_add(len)
            } else {
                let pat_len = expr.matcher.as_ref().map_or(1, ibex_sample::Matcher::min_pattern_len);
                offset.saturating_add(pat_len)
            };
            if req_bytes.len() < min_needed {
                return AclEvalResult::MissingData;
            }
        } else if expr.fetch_name == "req.len" {
            if req_bytes.is_empty() {
                return AclEvalResult::MissingData;
            }
        }
    }

    let is_match = expr.eval(registry, ctx);
    // The raw-buffer fetches (`src/payload.c`) say themselves whether more data could still give them one
    // (`SMP_F_MAY_CHANGE`): a miss then is not final.
    let may_change = ctx.raw_req.is_some() && ibex_sample::raw_may_change(&expr.fetch_name, &expr.fetch_args, req_bytes) == Some(true);
    if can_wait && !is_match && may_change {
        return AclEvalResult::MissingData;
    }
    if can_wait && !is_match && (expr.fetch_name == "req.payload" || expr.fetch_name == "payload") {
        let len = expr
            .fetch_args
            .get(1)
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);
        // A non-match is not final while the payload can still grow, for an unanchored
        // substring unless a line delimiter says the message has ended, and for a suffix
        // or a regex whatever the payload ends with.
        if len == 0
            && expr
                .matcher
                .as_ref()
                .is_some_and(|m| m.may_match_later(req_bytes.ends_with(b"\n")))
        {
            return AclEvalResult::MissingData;
        }
    }
    let effective = if term.negated { !is_match } else { is_match };
    if effective {
        AclEvalResult::Matched
    } else {
        AclEvalResult::NotMatched
    }
}

#[must_use]
pub fn eval_acl_condition_extended(
    cond: &ibex_config::AclCondition,
    acls: &ibex_sample::Acls,
    registry: &Registry,
    ctx: &SampleContext,
    req_bytes: &[u8],
    can_wait: bool,
) -> AclEvalResult {
    combine_condition(cond, |term| eval_acl_term_extended(term, acls, registry, ctx, req_bytes, can_wait))
}

/// `acl_exec_cond` (src/acl.c): within an alternative a failing term fails it and a
/// missing one makes it a miss; across alternatives a passing one passes and a miss
/// leaves the condition a miss. `unless` inverts pass and fail; a miss stays a miss.
pub fn combine_condition(
    cond: &ibex_config::AclCondition,
    mut term: impl FnMut(&ibex_config::AclTerm) -> AclEvalResult,
) -> AclEvalResult {
    let mut any_missing = false;
    let mut passed = false;
    // An alternative with no term in it (`if` and nothing, `if !`, a trailing `||`) is not
    // one: `HAProxy` builds no suite for it, so `if` is false and `unless` true when none
    // is left (measured: `http-request deny if` lets the request through).
    for suite in cond.suites().filter(|s| !s.is_empty()) {
        let mut suite_res = AclEvalResult::Matched;
        for t in suite {
            match term(t) {
                AclEvalResult::NotMatched => {
                    suite_res = AclEvalResult::NotMatched;
                    break;
                }
                AclEvalResult::MissingData => suite_res = AclEvalResult::MissingData,
                AclEvalResult::Matched => {}
            }
        }
        match suite_res {
            AclEvalResult::Matched => {
                passed = true;
                break;
            }
            AclEvalResult::MissingData => any_missing = true,
            AclEvalResult::NotMatched => {}
        }
    }
    if passed {
        if cond.is_if { AclEvalResult::Matched } else { AclEvalResult::NotMatched }
    } else if any_missing {
        AclEvalResult::MissingData
    } else if cond.is_if {
        AclEvalResult::NotMatched
    } else {
        AclEvalResult::Matched
    }
}

#[must_use]
pub fn eval_acl_condition(
    cond: &ibex_config::AclCondition,
    acls: &ibex_sample::Acls,
    registry: &Registry,
    ctx: &SampleContext,
) -> bool {
    combine_condition(cond, |term| {
        if eval_acl_term(term, acls, registry, ctx) {
            AclEvalResult::Matched
        } else {
            AclEvalResult::NotMatched
        }
    }) == AclEvalResult::Matched
}

/// The request line an HTTP/3 request is logged with: `HAProxy` keeps the absolute URI the
/// `:scheme` and `:authority` pseudo-headers make, and the version `HTTP/3.0`
/// (`"GET https://localhost:8443/ HTTP/3.0"`). The relay hands the engine an origin-form
/// HTTP/1.1 line, with `:authority` as `host`.
fn h3_log_line(line: &str, host: Option<&str>) -> String {
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(uri)) = (parts.next(), parts.next()) else {
        return line.to_string();
    };
    match host {
        Some(host) if uri.starts_with('/') => format!("{method} https://{host}{uri} HTTP/3.0"),
        _ => format!("{method} {uri} HTTP/3.0"),
    }
}

#[cfg(test)]
mod tests {

    /// `bc_err` builds the `bc_err`/`bc_err_str` pair the oracle prints for a plain
    /// (non-TLS) connection. Runtime call: the table in `proxy.rs` evaluates it at compile
    /// time, where no coverage is counted. No oracle value: the arguments are made up here (the real
    /// table is pinned by the bc_err tests of the integration suite).
    #[test]
    fn bc_err_builds_a_plain_connection_error() {
        let e = super::bc_err(47, "EREFUSED", "ECONNREFUSED returned by OS");
        assert_eq!((e.code, e.name, e.text), (47, "EREFUSED", "ECONNREFUSED returned by OS"));
        assert!(!e.tls && e.ssl_code == 0 && e.ssl_text.is_none());
        assert_eq!(super::BC_CONNECTED.text, "Success");
    }

    /// A stream of an HTTP/2 connection has no socket of its own (T280): reads and writes
    /// on its client side find nothing to do, its owner moves its bytes.
    #[test]
    fn an_h2_streams_client_side_reads_and_writes_nothing() {
        let (mut x, side) = (super::ClientXprt::Plain, super::ClientSide::H2Child);
        assert!(matches!(side.recv(&mut x, &mut [0u8; 8]), Ok(super::Io::WouldBlock)));
        assert!(matches!(side.send(&mut x, b"x"), Ok(super::Io::WouldBlock)));
        side.shutdown_read();
    }

    /// Every string of up to eight bytes out of `a`, CR and LF.
    #[test]
    fn find_eoh_skips_to_line_ends_and_finds_the_same_end() {
        for len in 0..=8u32 {
            for mut code in 0..3usize.pow(len) {
                let mut buf = Vec::new();
                for _ in 0..len {
                    buf.push(b"a\r\n"[code % 3]);
                    code /= 3;
                }
                assert_eq!(super::find_eoh(&buf), super::find_eoh_bytewise(&buf), "{buf:?}");
            }
        }
    }
    use super::{h3_log_line, H2ReqBody};
    use crate::h2_bridge::pump_h2_body;
    use crate::buf::Buf;
    use ibex_proto::htx::{Htx, HtxBlock};

    /// Pumps until the body is done, taking out what each pass wrote.
    fn pump_all(msg: &mut Htx, st: &mut H2ReqBody, req: &mut Buf, out: &mut Vec<u8>) {
        for _ in 0..64 {
            if st.done {
                break;
            }
            pump_h2_body(msg, st, req);
            out.extend_from_slice(req.readable());
            let n = req.readable().len();
            req.consume(n);
        }
        assert!(st.done, "the body never finished: {st:?}");
    }

    /// A chunk's size in upper-case hex, as `HAProxy` writes it (`1E` for a 30-byte body
    /// from an HTTP/2 client with no length, 3.5-dev8; T302).
    #[test]
    fn an_h2_request_chunk_size_is_upper_case_hex() {
        let mut msg = Htx::new();
        msg.push(HtxBlock::Eoh);
        msg.push(HtxBlock::Data(b"0123456789abcdefghij0123456789".to_vec()));
        msg.push(HtxBlock::Eom);
        let mut st = H2ReqBody { chunked: true, ..H2ReqBody::default() };
        let mut req = Buf::with_capacity(64);
        let mut out = Vec::new();
        pump_all(&mut msg, &mut st, &mut req, &mut out);
        assert_eq!(out, b"1E\r\n0123456789abcdefghij0123456789\r\n0\r\n\r\n");
    }

    /// A body bigger than the room left goes out a piece at a time, as chunks when there
    /// is no length; empty DATA frames and blocks that are not body are passed over, and the
    /// last chunk waits until it fits.
    #[test]
    fn an_h2_request_body_is_pumped_in_pieces_that_fit() {
        let mut msg = Htx::new();
        msg.push(HtxBlock::Eoh);
        msg.push(HtxBlock::Data(Vec::new()));
        msg.push(HtxBlock::Data(b"abcdefghij".to_vec()));
        msg.push(HtxBlock::Eom);

        let mut st = H2ReqBody { chunked: true, ..H2ReqBody::default() };
        let mut req = Buf::with_capacity(16);
        let mut out = Vec::new();
        pump_all(&mut msg.clone(), &mut st, &mut req, &mut out);
        assert_eq!(out, b"4\r\nabcd\r\n4\r\nefgh\r\n2\r\nij\r\n0\r\n\r\n");

        let mut st = H2ReqBody::default();
        let mut req = Buf::with_capacity(4);
        let mut out = Vec::new();
        pump_all(&mut msg.clone(), &mut st, &mut req, &mut out);
        assert_eq!(out, b"abcdefghij");
    }

    /// T221: `process` stops after 16 passes, so a pass cannot be driven forever by a peer.
    /// An HTTP/2 request body held in the stream's message is moved on only by a pass; when
    /// the passes run out with body still held, the server-bound buffer emptied and the
    /// client's socket drained, no socket event is coming, and the session must ask to be
    /// run again. It did not: the upload stalled until `timeout client` (1 in ~150 runs of
    /// `h2_large_request_body` under load). Since each stream has an entry of its own
    /// (T280), the connection's owner moves the body into the stream's `req` once per run
    /// and runs the stream when it did; the stream runs its owner after each of its runs.
    /// Neither may be left with body held and nothing to run either.
    #[test]
    fn an_h2_body_left_when_the_passes_run_out_runs_the_session_again() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let frame = |kind: u8, flags: u8, sid: u32, pl: &[u8]| {
            let len = pl.len() as u32;
            let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
            f.extend_from_slice(&sid.to_be_bytes());
            f.extend_from_slice(pl);
            f
        };
        let body_len = 1_000_000usize;
        let mut head = Vec::new();
        for (n, v) in [(":method", "POST"), (":scheme", "http"), (":authority", "x"), (":path", "/up"), ("content-length", &body_len.to_string())] {
            head.extend_from_slice(&[0, n.len() as u8]);
            head.extend_from_slice(n.as_bytes());
            head.push(v.len() as u8);
            head.extend_from_slice(v.as_bytes());
        }
        let (cli, mut client) = UnixStream::pair().expect("pair");
        cli.set_nonblocking(true).expect("nonblocking");
        client.write_all(super::H2_CONN_PREFACE).expect("preface");
        client.write_all(&frame(4, 0, 0, &[])).expect("settings");
        client.write_all(&frame(1, 4, 1, &head)).expect("headers");
        let mut o = super::TcpSession::new_with_mode(super::ClientSide::Fd(cli.into()), super::Mode::Http, Vec::new(), Vec::new(), super::Timeouts::default(), 0, ibex_sched::Tick(1000));
        o.cli_cant_recv = false;
        o.process(ibex_sched::Tick(1000)).expect("process");
        let d = crate::h2_bridge::dispatch_next(o.h2_ctx.as_deref_mut().expect("h2"), false).expect("the request is dispatched");
        let mut s = super::TcpSession::h2_child_of(&mut o, (0, ibex_sched::TaskRef::NONE), d.stream);
        crate::h2_bridge::start_request(&mut s, d);
        assert_eq!(s.h2_active().map(|a| a.id), Some(1), "the stream is the child's");
        s.txn.as_mut().expect("txn").req_rules_done = true;

        // The body, as the mux would have stored it from DATA frames: more than 16 passes
        // move on (one buffer each), so the passes run out before it is all gone.
        let h2 = o.h2_ctx.as_mut().expect("h2");
        let st = h2.streams.get_mut(&1).expect("stream");
        for _ in 0..body_len / 10_000 {
            st.rx_htx.push(HtxBlock::Data(vec![b'b'; 10_000]));
        }
        st.rx_htx.push(HtxBlock::Eom);

        // A server that reads everything at once.
        let (srv, mut server) = UnixStream::pair().expect("pair");
        srv.set_nonblocking(true).expect("nonblocking");
        let reader = std::thread::spawn(move || {
            let mut got = 0usize;
            let mut buf = vec![0u8; 1 << 16];
            while let Ok(n) = server.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got += n;
            }
            got
        });
        s.attach_server(srv.into(), ibex_sched::Tick(1000));
        s.server_connected(ibex_sched::Tick(1000));

        // Run the two as the engine does: the stream, then its owner, which every run of the
        // stream wakes (it moves the body on into the room the run made); then the stream
        // again only if the owner moved something, on a socket event (the server writable
        // while `req` holds bytes; the client has nothing more to send) or when it asks to
        // be. (The owner's pass was modelled before the stream's run, not after it: a run
        // that drained a `req` the pass had found full ended with nothing "to run it", while
        // the engine runs the owner after it -- 1 in ~8 runs failed, T300.)
        //
        // The socket event is the engine's: write interest as `interests` gives it
        // (`update_interests` registers it), and the run it brings comes when the server's
        // socket can take bytes, not at once. Running the stream again at once while the
        // reader thread had not drained the socket spun the 1000 runs through `EAGAIN`
        // with the body still held (1 in ~10 runs of the whole lib, most on busy cores).
        let done = |s: &super::TcpSession| s.h2_active().expect("served").body.done;
        for run in 0..1000 {
            s.process(ibex_sched::Tick(1000)).expect("process");
            let moved = {
                let Some(super::H2Role::Child(ch)) = s.h2_role.as_deref_mut() else { panic!("a child") };
                crate::h2_bridge::pump_request_body(o.h2_ctx.as_deref_mut().expect("h2"), &mut ch.stream, &mut s.req).0
            };
            if done(&s) && s.req.is_empty() {
                break;
            }
            let srv_write_wanted = s.interests().1.write;
            let woken = moved || srv_write_wanted || s.wants_rerun();
            assert!(woken, "run {run}: {} body bytes moved on, the rest held with nothing to run the session again", s.h2_active().expect("served").body.consumed);
            // The socket event runs it: wait for the server's socket to take bytes, as the
            // poller does (at once when it can; the reader thread drains it).
            use rustix::event::{poll, PollFd, PollFlags};
            let mut fds = [PollFd::new(s.srv.as_ref().expect("the server's socket"), PollFlags::OUT)];
            assert_eq!(poll(&mut fds, 10_000).expect("poll"), 1, "run {run}: the server's socket never became writable");
        }
        assert!(done(&s), "the body was moved on whole");
        drop(s);
        assert!(reader.join().expect("reader") > body_len, "the server got the head and the body");
    }

    /// Found by T195: the DATA of an HTTP/2 request stayed in the stream's message after it
    /// was written towards the server, so a 50 MB upload was held whole until the stream
    /// ended. A block written out is released; what is still to go stays.
    #[test]
    fn a_forwarded_h2_body_is_released() {
        let mut msg = Htx::new();
        msg.push(HtxBlock::Eoh);
        msg.push(HtxBlock::Data(vec![b'x'; 100]));
        msg.push(HtxBlock::Data(vec![b'y'; 100]));
        let held = |m: &Htx| -> usize { m.blocks().iter().map(|b| if let HtxBlock::Data(d) = b { d.len() } else { 0 }).sum() };
        let mut st = H2ReqBody { cursor: 1, ..H2ReqBody::default() };
        let mut req = Buf::with_capacity(150);
        assert!(pump_h2_body(&mut msg, &mut st, &mut req));
        assert_eq!(req.readable().len(), 150);
        assert_eq!(held(&msg), 100, "the first block went out whole, the second in part");
        req.consume(150);
        assert!(pump_h2_body(&mut msg, &mut st, &mut req));
        assert_eq!(req.readable(), [b'y'; 50]);
        assert_eq!(held(&msg), 0);
    }

    /// An HTX grown past its class for a large request head is replaced, once the
    /// transaction is over, by an unallocated pooled one (T183): it does not stay at its
    /// size for the connection's idle time.
    #[test]
    fn a_grown_htx_is_released_with_the_transaction() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut s = super::TcpSession::new(std::os::fd::OwnedFd::from(a), Default::default(), 0, ibex_sched::Tick::ETERNITY);
        s.htx_reserve(20_000);
        assert_eq!(s.htx_buf.class(), crate::buf::BufClass::Custom);
        s.release_idle_buffers();
        assert_eq!(s.htx_buf.class(), crate::buf::BufClass::Standard);
        assert!(s.htx_buf.raw_slice().is_empty(), "the replacement holds no memory");
        // a pooled one that was used is emptied in place and keeps its class
        s.htx_buf.alloc_if_needed();
        assert!(!s.htx_buf.raw_slice().is_empty());
        s.release_idle_buffers();
        assert!(s.htx_buf.raw_slice().is_empty());
        assert_eq!(s.htx_buf.class(), crate::buf::BufClass::Standard);
        // an HTX still holding a message is kept
        s.htx_buf.alloc_if_needed();
        s.has_htx = true;
        s.release_idle_buffers();
        assert!(!s.htx_buf.raw_slice().is_empty());
    }

    /// The last chunk is not split: with less than its five bytes of room, nothing is
    /// written and the body is not done.
    #[test]
    fn the_last_chunk_waits_for_room() {
        let mut msg = Htx::new();
        msg.push(HtxBlock::Eom);
        let mut st = H2ReqBody { chunked: true, ..H2ReqBody::default() };
        let mut req = Buf::with_capacity(4);
        assert!(!pump_h2_body(&mut msg, &mut st, &mut req));
        assert!(!st.done);
        let mut req = Buf::with_capacity(16);
        assert!(pump_h2_body(&mut msg, &mut st, &mut req));
        assert_eq!(req.readable(), b"0\r\n\r\n");
    }

    /// Trailers follow the last chunk as `name: value` lines and a blank one, each written
    /// only when it fits; with a length they are dropped, and counted either way.
    #[test]
    fn trailers_are_written_when_they_fit_and_counted_either_way() {
        use ibex_proto::htx::HeaderField;
        let mut msg = Htx::new();
        msg.push(HtxBlock::Eoh);
        msg.push(HtxBlock::Data(b"ab".to_vec()));
        msg.push(HtxBlock::Trailer(HeaderField { name: "x".into(), value: "y".into() }));
        msg.push(HtxBlock::Eot);
        msg.push(HtxBlock::Eom);
        for (cap, passes) in [(15, 2), (17, 2), (64, 1)] {
            let mut st = H2ReqBody { chunked: true, ..H2ReqBody::default() };
            let mut msg = msg.clone();
            let mut req = Buf::with_capacity(cap);
            let mut out = Vec::new();
            let mut n = 0;
            while !st.done {
                pump_h2_body(&mut msg, &mut st, &mut req);
                n += 1;
                out.extend_from_slice(req.readable());
                let len = req.readable().len();
                req.consume(len);
                assert!(n <= 5, "{st:?}");
            }
            assert_eq!(out, b"2\r\nab\r\n0\r\nx: y\r\n\r\n", "capacity {cap}");
            assert_eq!(n, passes, "capacity {cap}");
            assert_eq!(st.trailer_bytes, 3);
        }
        let mut st = H2ReqBody::default();
        let mut req = Buf::with_capacity(64);
        let mut out = Vec::new();
        pump_all(&mut msg.clone(), &mut st, &mut req, &mut out);
        assert_eq!(out, b"ab");
        assert_eq!(st.trailer_bytes, 3);
    }

    #[test]
    fn the_h3_log_line_is_absolute_when_it_can_be() {
        assert_eq!(h3_log_line("GET /a?b HTTP/1.1", Some("h:1")), "GET https://h:1/a?b HTTP/3.0");
        assert_eq!(h3_log_line("GET /a HTTP/1.1", None), "GET /a HTTP/3.0");
        assert_eq!(h3_log_line("OPTIONS * HTTP/1.1", Some("h")), "OPTIONS * HTTP/3.0");
        assert_eq!(h3_log_line("garbage", Some("h")), "garbage");
    }
}
