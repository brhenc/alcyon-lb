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
use std::os::fd::{AsFd, OwnedFd};
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

/// One TCP / HTTP session: two connections, two buffers, two state machines.
#[allow(clippy::struct_excessive_bools)]
pub struct TcpSession {
    pub cli: OwnedFd,
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
    pub created_at: Instant,
    pub pending_resp: Option<Box<(Vec<u8>, usize)>>,
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
    pub sess_vars: HashMap<String, String>,
    pub req_vars: HashMap<String, String>,
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
    pub h2_active_stream_id: Option<u32>,
    /// How much of the active HTTP/2 stream's request body has been written to `req`.
    pub h2_body: H2ReqBody,
    /// The head forwarded for the HTTP/2 request in flight has to carry `transfer-encoding:
    /// chunked` (no length was given); it is added when the head is written, not in the HTX
    /// the rules see.
    pub h2_chunk_out: bool,
    pub h2_flood_config: ibex_proto::H2FloodConfig,
    pub is_first_req: bool,
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

/// What `%U` counts of an HTTP/2 request's head (`HAProxy`'s HTX: 20 bytes for the start
/// line, its three strings -- the target is `scheme://authority` and the path when the
/// request had both -- and each header's name and value, then the end of the headers).
fn h2_head_size(msg: &ibex_proto::htx::Htx, abs_prefix: Option<&str>) -> u64 {
    let Some(r) = msg.req_line() else { return 0 };
    let mut size = 20 + (r.method.as_str().len() + abs_prefix.map_or(0, str::len) + r.uri.len() + "HTTP/2.0".len()) as u64 + 1;
    for h in msg.headers() {
        size += (h.name.len() + h.value.len()) as u64;
    }
    size
}

/// Writes what has come of an HTTP/2 request's body into `req`, as much as there is room
/// for: each DATA frame as it is, or as a chunk when the request has no length, and the
/// end as the last chunk. True if anything was written. A DATA block written out whole
/// is released: the stream holds only what is still to go (T195's 50 MB upload was held
/// until the stream ended).
fn pump_h2_body(msg: &mut ibex_proto::htx::Htx, st: &mut H2ReqBody, req: &mut Buf) -> bool {
    let blocks = msg.blocks_mut();
    let mut wrote = false;
    while !st.done && st.cursor < blocks.len() {
        match &blocks[st.cursor] {
            HtxBlock::Data(d) | HtxBlock::RawData(d) => {
                let rest = &d[st.off.min(d.len())..];
                if rest.is_empty() {
                    st.cursor += 1;
                    st.off = 0;
                    continue;
                }
                // A chunk's size line takes at most 8 bytes, with its two CRLFs.
                let framing = if st.chunked { 12 } else { 0 };
                let room = req.writable();
                if room.len() <= framing {
                    break;
                }
                let n = rest.len().min(room.len() - framing);
                let at = if st.chunked {
                    let size = format!("{n:x}\r\n");
                    room[..size.len()].copy_from_slice(size.as_bytes());
                    size.len()
                } else {
                    0
                };
                room[at..at + n].copy_from_slice(&rest[..n]);
                let mut len = at + n;
                if st.chunked {
                    room[len..len + 2].copy_from_slice(b"\r\n");
                    len += 2;
                }
                req.commit(len);
                wrote = true;
                st.off += n;
                st.consumed += n as u64;
                if st.off >= d.len() {
                    if let HtxBlock::Data(d) | HtxBlock::RawData(d) = &mut blocks[st.cursor] {
                        *d = Vec::new();
                    }
                    st.cursor += 1;
                    st.off = 0;
                }
            }
            HtxBlock::Trailer(h) => {
                // Trailers can follow only a chunked body: with a length they are dropped.
                if st.chunked {
                    let mut line = Vec::with_capacity(h.name.len() + h.value.len() + 7);
                    if !st.trailing {
                        line.extend_from_slice(b"0\r\n");
                    }
                    line.extend_from_slice(h.name.as_bytes());
                    line.extend_from_slice(b": ");
                    line.extend_from_slice(h.value.as_bytes());
                    line.extend_from_slice(b"\r\n");
                    let room = req.writable();
                    if room.len() < line.len() {
                        break;
                    }
                    room[..line.len()].copy_from_slice(&line);
                    req.commit(line.len());
                    wrote = true;
                    st.trailing = true;
                }
                // Dropped or forwarded, `HAProxy` counts them.
                st.trailer_bytes += (h.name.len() + h.value.len()) as u64;
                st.cursor += 1;
            }
            HtxBlock::Eot => {
                if st.chunked && st.trailing {
                    let room = req.writable();
                    if room.len() < 2 {
                        break;
                    }
                    room[..2].copy_from_slice(b"\r\n");
                    req.commit(2);
                    wrote = true;
                }
                st.trailer_bytes += 1;
                st.cursor += 1;
            }
            HtxBlock::Eom => {
                if st.chunked && !st.trailing {
                    let room = req.writable();
                    if room.len() < 5 {
                        break;
                    }
                    room[..5].copy_from_slice(b"0\r\n\r\n");
                    req.commit(5);
                    wrote = true;
                }
                st.done = true;
            }
            _ => st.cursor += 1,
        }
    }
    wrote
}

impl TcpSession {
    #[must_use]
    pub fn new(cli: OwnedFd, timeouts: Timeouts, retries: u16, now: Tick) -> Self {
        Self::new_with_mode(
            cli,
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
        cli: OwnedFd,
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
            h2_active_stream_id: None,
            h2_body: H2ReqBody::default(),
            h2_chunk_out: false,
            h2_flood_config: ibex_proto::H2FloodConfig::default(),
            is_first_req: true,
            keep_request_line: false,
            accept_unsafe_request: false,
            h3: false,
        };
        s.arm_client(now);
        s
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
            || self.pending_resp.as_deref().is_some_and(|(d, o)| *o < d.len())
            || self.h2_ctx.as_ref().is_some_and(|h| h.tx_consumed < h.tx_buf.len())
    }

    /// A stream with its request in, waiting for its turn, and the turn free: streams
    /// go one at a time, so while one is served the others wait for its end (`end_txn`
    /// runs the session again then). Counting them while one was at the server had the
    /// session requeue itself on every pass, a busy loop as long as the server took (T186).
    #[must_use]
    pub fn has_undispatched_h2_streams(&self) -> bool {
        if self.h2_active_stream_id.is_some() || self.txn.is_some() {
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

    fn arm_client(&mut self, now: Tick) {
        let ms = self.tunnel_ms().unwrap_or(self.timeouts.client);
        self.cli_exp = if ms == 0 { Tick::ETERNITY } else { now.add(ms) };
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
        self.mode == Mode::Http && self.txn.is_none() && (self.is_first_req || !self.req.is_empty())
    }

    /// Whether the connection waits for the first byte of its next request: a response has
    /// gone, nothing has come.
    fn idle_wait(&self) -> bool {
        self.mode == Mode::Http && self.h2_ctx.is_none() && self.txn.is_none() && !self.is_first_req && self.req.is_empty()
    }

    /// Starts `timeout http-request` when a request head starts, and ends it when the head
    /// is complete. Between requests the wait is `timeout http-keep-alive`, else
    /// `timeout http-request`; a request's first byte ends it.
    pub fn arm_request(&mut self, now: Tick) {
        if self.http_request_ms == 0 && self.keep_alive_ms == 0 {
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
        self.log.queue.get_or_insert_with(std::time::Instant::now);
        self.srv = Some(fd);
        self.srv_xprt = xprt;
        self.srv_cant_recv = false;
        self.srv_state = ScState::Connecting;
        self.conn_exp = if self.timeouts.connect == 0 {
            Tick::ETERNITY
        } else {
            now.add(self.timeouts.connect)
        };
    }

    /// The server connection completed.
    pub fn server_connected(&mut self, now: Tick) {
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
        self.log.connect = Some(std::time::Instant::now());
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
            Some(t) if self.mode == Mode::Http => t.client_window(data),
            _ => data.len(),
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
        if self.h2_ctx.is_some() {
            return;
        }
        let _ = self.cli_xprt.send(self.cli.as_fd(), raw);
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
        let h2 = self.h2_ctx.is_some();
        // On an HTTP/2 connection the reply is a response like a server's: its head
        // goes out as HEADERS and its body as DATA on the request's stream
        // (`h2_forward_response`), so it is queued as a head with its framing, not as
        // an opaque run of bytes, and says nothing about `Connection`.
        let raw = if h2 && txn.client_head { &raw[..head_len.min(raw.len())] } else { raw };
        let mut out;
        let raw = if announce_close && !h2 && txn.close_after && !raw.is_empty() && !has_header(&head, "connection") {
            // The client is told, as for a server's response: last in the head, as
            // `inject_connection_close_header_zero_alloc` places it.
            let at = find_eoh(raw).map_or(0, |(h, e)| h + e / 2);
            out = Vec::with_capacity(raw.len() + 19);
            out.extend_from_slice(&raw[..at]);
            out.extend_from_slice(b"Connection: close\r\n");
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
        } else {
            txn::MsgState::Body(txn::Body::Length(raw.len() as u64))
        };
        self.rep.clear();
        let w = self.rep.writable();
        let n = raw.len().min(w.len());
        w[..n].copy_from_slice(&raw[..n]);
        self.rep.commit(n);
        self.pending_resp = (n < raw.len()).then(|| Box::new((raw.to_vec(), n)));
    }

    /// Clears what belonged to the transaction that just ended, so the next request on
    /// this connection starts from nothing. The one place that list lives.
    pub fn reset_for_next_request(&mut self) {
        self.stick_out_pending += self.log.bytes_from_server;
        self.log = crate::txnlog::StreamLog::start(self.bytes_in, self.bytes_out);
        self.txn = None;
        self.req_method = None;
        self.req_uri = None;
        self.req_headers = None;
        self.clear_htx();
        // The streams that are over are let go, as `HAProxy` frees a stream when it closes
        // (`h2s_destroy`). Kept, each held its request for the life of the connection and
        // every request walked all of them: 88% of the CPU of an h2 request (T186).
        if let Some(h2) = self.h2_ctx.as_mut() {
            h2.streams.retain(|_, s| !matches!(s.state, ibex_proto::H2StreamState::Closed | ibex_proto::H2StreamState::Reset(_)));
        }
        self.h2_active_stream_id = None;
        self.h2_body = H2ReqBody::default();
        self.h2_chunk_out = false;
        self.req_vars.clear();
        if let Some(set) = self.timeouts_set.take() {
            self.timeouts = set.before;
        }
        // The stream is running, so its variables are in the thread's map
        // (`engine::with_stream_vars`): the transaction's go from there too.
        ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().retain(|k, _| k.starts_with("sess.")));
        self.stick_stores.clear();
        self.is_first_req = false;
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
        let parser = ibex_proto::parser::build(self.parser_kind)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut stream = parser.stream(false);
        stream.set_accept_unsafe_request(self.accept_unsafe_request);
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
        self.htx_tail = slice.tail_addr();
        self.htx_blocks = slice.num_blocks();
        self.has_htx = true;
        // Modified, so the head forwarded is regenerated from the HTX, without it. So
        // too when the parser normalised the authority and `Host` (tasks/T93).
        self.htx_modified = conflict || stream.head_rewritten();
        Ok(close)
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self.cli_state, ScState::Closed | ScState::Error)
            && matches!(self.srv_state, ScState::Closed | ScState::Error)
    }

    // ---- the two state machines --------------------------------------------------

    /// Advances the client side. Returns `true` if anything changed.
    fn process_cli(&mut self) -> io::Result<bool> {
        let changed_io = self.process_cli_io()?;
        let changed_trans = self.process_cli_transitions();
        Ok(changed_io || changed_trans)
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
        let fd = self.cli.as_fd();
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
        let is_h2 = self.h2_ctx.is_some() || self.cli_xprt.alpn() == Some(b"h2");
        if is_h2 {
            if self.h2_ctx.is_none() {
                let mut h2 = H2MuxContext::new(ibex_proto::conn::ConnId(0), true);
                h2.flood_config = self.h2_flood_config;
                self.h2_ctx = Some(Box::new(h2));
            }
            if self.cli_state.can_read() && !self.cli_cant_recv {
                let mut raw_buf = [0u8; 16384];
                let r = self.cli_xprt.recv(self.cli.as_fd(), &mut raw_buf)?;
                self.cli_cant_recv = self.polls_cli() && self.cli_xprt.drained(r, raw_buf.len());
                match r {
                    Io::Eof => {
                        raw::shutdown_read(self.cli.as_fd());
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
                let r = self.cli_xprt.recv(self.cli.as_fd(), dst)?;
                self.cli_cant_recv = self.polls_cli() && self.cli_xprt.drained(r, asked);
                match r {
                    // The client left before a byte of the PROXY header.
                    Io::Eof if self.awaiting_proxy_header() => self.refuse_proxy_header(ProxyHdrError::Empty),
                    Io::Closed if self.awaiting_proxy_header() => self.refuse_proxy_header(ProxyHdrError::Abort),
                    Io::Eof => {
                        raw::shutdown_read(self.cli.as_fd());
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
                let to_parse = self.req.readable().to_vec();
                let _ = MuxH2.parse(&mut h2, &to_parse).map_err(|_| h2.ensure_goaway());
                self.req.clear();
                self.h2_ctx = Some(Box::new(h2));
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

        if let Some(ref mut h2) = self.h2_ctx {
            // Check if any stream has arrived with a complete request
            if (self.cli_state == ScState::Ready || self.cli_state == ScState::Established)
                && self.h2_active_stream_id.is_none()
                && self.req_headers.is_none()
                && !self.has_htx
                && self.req.is_empty()
            {
                if let Some(&stream_id) = h2.streams.keys().find(|&&id| {
                        if let Some(st) = h2.streams.get(&id) {
                            !st.dispatched
                                && st.state != ibex_proto::H2StreamState::Closed
                                && !matches!(st.state, ibex_proto::H2StreamState::Reset(_))
                                && st.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Eoh))
                        } else {
                            false
                        }
                    }) {
                        self.h2_active_stream_id = Some(stream_id);
                        if let Some(stream) = h2.streams.get_mut(&stream_id) {
                            stream.dispatched = true;
                            // The head goes to the server as HTTP/1.1, and the body follows
                            // as the DATA frames come (`pump_h2_body`): with the length the
                            // client gave, else chunked, as `HAProxy` writes it.
                            let has_data = stream.rx_htx.blocks().iter().any(|b| matches!(b, HtxBlock::Data(_) | HtxBlock::RawData(_) | HtxBlock::Trailer(_)));
                            let chunked = stream.rx_htx.get_header("content-length").is_none() && (has_data || !stream.rx_htx.is_eom());
                            let first_body = stream.rx_htx.blocks().iter().position(|b| matches!(b, HtxBlock::Eoh)).map_or(stream.rx_htx.blocks().len(), |i| i + 1);
                            self.h2_body = H2ReqBody { cursor: first_body, off: 0, chunked, ..H2ReqBody::default() };
                            // `%U`, and the line `%r` prints, are those of the message the
                            // client sent: `transfer-encoding: chunked` is added on output only,
                            // so the rules do not see it either (only the forwarded head has it).
                            // The chunked end the forwarded body is counted with (+1 when it is
                            // consumed) is not in `HAProxy`'s message unless trailers precede it.
                            let req_htx = h2_head_size(&stream.rx_htx, stream.abs_prefix.as_deref()).saturating_sub(u64::from(chunked));
                            if self.keep_request_line {
                                self.log.request_line = stream.rx_htx.req_line().map(|r| {
                                    format!("{} {}{} HTTP/2.0", r.method.as_str(), stream.abs_prefix.as_deref().unwrap_or(""), r.uri)
                                });
                            }
                            self.log.request = Some(std::time::Instant::now());
                            let full_req = stream.rx_htx.to_h1_wire();
                            let head_only = find_eoh(&full_req).map_or(&full_req[..], |(h, e)| &full_req[..h + e]);
                            let wire_req_buf: Vec<u8>;
                            let wire_req: &[u8] = if chunked {
                                let at = find_eoh(head_only).map_or(head_only.len(), |(h, _)| h);
                                let mut v = head_only[..at].to_vec();
                                v.extend_from_slice(b"\r\ntransfer-encoding: chunked");
                                v.extend_from_slice(&head_only[at..]);
                                wire_req_buf = v;
                                &wire_req_buf
                            } else {
                                head_only
                            };
                            self.h2_chunk_out = chunked;
                            if let Ok(parser) = ibex_proto::parser::build(ibex_proto::parser::ParserKind::H1) {
                                let mut p_stream = parser.stream(false);
                                let raw = self.htx_buf.raw_slice_mut();
                                let mut slice = ibex_proto::htx::HtxSlice::new(raw);
                                if p_stream.parse(head_only, &mut slice).is_ok() {
                                    self.htx_tail = slice.tail_addr();
                                    self.htx_blocks = slice.num_blocks();
                                    self.has_htx = true;
                                    self.htx_modified = false;
                                }
                            }
                            self.req_method = stream.rx_htx.req_line().map(|r| r.method.as_str().to_string());
                            self.req_uri = stream.rx_htx.req_line().map(|r| r.uri.clone());
                            self.req_headers = Some(
                                stream.rx_htx.headers().map(|h| (h.name.clone(), h.value.clone())).collect(),
                            );
                            self.req.clear();
                            let w = self.req.writable();
                            let n = wire_req.len().min(w.len());
                            w[..n].copy_from_slice(&wire_req[..n]);
                            self.req.commit(n);
                            let framing = find_eoh(wire_req)
                                .map_or(txn::Framing::None, |(h, e)| txn::request_framing(&wire_req[..h + e]));
                            let mut txn = HttpTxn::new(framing, false);
                            txn.req_htx = Some(req_htx);
                            self.txn = Some(txn);
                            self.cli_state = ScState::Established;
                            changed = true;
                        }
                    }
                }
                // The DATA frames of the request being served that have come since.
                if let Some(stream) = self.h2_active_stream_id.and_then(|id| h2.streams.get_mut(&id)) {
                    let before = self.h2_body.trailer_bytes;
                    if pump_h2_body(&mut stream.rx_htx, &mut self.h2_body, &mut self.req) {
                        changed = true;
                    }
                    // The client may send as much again as has moved on towards the server:
                    // a backed-up server stops the grants, and so the client.
                    let pending = self.h2_body.consumed - self.h2_body.credited;
                    if pending >= 16384 && !self.h2_body.done {
                        if let Some(id) = self.h2_active_stream_id {
                            self.h2_body.credited += pending;
                            h2.send_window_update(id, pending as u32);
                            changed = true;
                        }
                    }
                    // What the trailers add to `%U`.
                    let added = self.h2_body.trailer_bytes - before;
                    if let Some(t) = self.txn.as_mut().and_then(|t| t.req_htx.as_mut()) {
                        *t += added;
                    }
                }

            // Flush pending frames to client socket
            let pending = h2.tx_buf.len() - h2.tx_consumed;
            if pending > 0 {
                match self.cli_xprt.send(self.cli.as_fd(), &h2.tx_buf[h2.tx_consumed..])? {
                    Io::Done(n) if n > 0 => {
                        MuxH2.consume_output(h2, n);
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
        if self.h2_ctx.is_none() && self.cli_state == ScState::Ready {
            // Empty lines before a request line are skipped (RFC 9112 section 2.2), as
            // HAProxy's parser does in `H1_MSG_RQBEFORE`.
            let blank = self.req.readable().iter().take_while(|b| matches!(b, b'\r' | b'\n')).count();
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
            if let Some((hdr_len, eoh_len)) = find_eoh(self.req.readable()) {
                let total_hdr_len = hdr_len + eoh_len;

                // The head, parsed into HTX, has to fit in tune.bufsize - tune.maxrewrite:
                // HAProxy answers 431 (tasks/T87; `txn::htx_head_cost`).
                if txn::htx_head_cost(&self.req.readable()[..total_hdr_len]) > threshold {
                    self.fail_request(431);
                    return Ok(true);
                }

                // What `%U` counts of this head: the message as received, whatever the
                // rules make of it afterwards.
                let req_htx = txn::htx_head_size(&self.req.readable()[..total_hdr_len], true);

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
                let Ok(mut close) = self.validate_request_head(total_hdr_len) else {
                    self.fail_request(400);
                    return Ok(true);
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
                self.log.request = Some(std::time::Instant::now());
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
                let mut txn = HttpTxn::new(framing, close || self.close_client);
                txn.req_htx = req_htx;
                txn.req_http11 = self.req.readable().split(|&b| b == b'\n').next().is_some_and(|l| l.trim_ascii_end().ends_with(b"HTTP/1.1"));
                // The client's own method: rules that rewrite it have not run yet.
                txn.client_head = self.req_method.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("HEAD"));
                self.txn = Some(txn);
                self.cli_state = ScState::Established;
                changed = true;
            } else if self.req.readable().len() + 56 >= self.bufsize {
                // No end of head and the buffer is full: 431 as well. Measured on 3.5-dev8,
                // a partial head draws it from `bufsize - 56` bytes on (the 40 of `struct
                // htx` and two blocks), whatever `tune.maxrewrite` is.
                self.fail_request(431);
                return Ok(true);
            }
        }

        // Drain pending synthetic response into rep if space is available
        if let Some((ref data, ref mut offset)) = self.pending_resp.as_deref_mut() {
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
        if self.mode == Mode::Http && self.h2_ctx.is_none() {
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
        if self.h2_ctx.is_none() && self.cli_state.can_write() && window > 0 && !self.res_inspect_pending {
            match self.cli_xprt.send(self.cli.as_fd(), &self.rep.readable()[..window])? {
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
        if self.h2_ctx.is_some() || self.mode == Mode::Http {
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
                    raw::shutdown_write(self.cli.as_fd());
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
                        raw::shutdown_read(self.cli.as_fd());
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
                    raw::shutdown_write(self.cli.as_fd());
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
                // 1.0: while idle, give up if the client is gone and has left nothing
                // behind. Connecting to a server for a client that has already
                // vanished is pure waste, and under a connection flood it is the
                // difference between absorbing the flood and amplifying it.
                let cli_done = matches!(
                    self.cli_state,
                    ScState::Closed | ScState::Error | ScState::ShutW
                ) || (self.cli_state == ScState::ShutR && self.req.is_empty());
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
                        }
                    }
                    self.req.consume(n);
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
    /// denial-of-service primitive. On exhaustion we return normally and the scheduler
    /// re-queues us, which costs a little latency and cannot hang the thread.
    ///
    /// # Errors
    /// Propagates unexpected I/O failures.
    pub fn process(&mut self, now: Tick) -> io::Result<()> {
        for _ in 0..16 {
            let a = self.process_cli()?;
            let b = self.process_srv()?;
            if !a && !b {
                break;
            }
            if matches!(
                self.cli_state,
                ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW
            ) {
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
                        h2.send_goaway(last, ibex_proto::h2::H2Error::NoError, &[]);
                    } else {
                        h2.enqueue_frame(&ibex_proto::h2::Frame::GoAway { last_stream_id: last, error_code: ibex_proto::h2::H2Error::NoError, debug_data: Vec::new() });
                        self.h2_idle_goaway = true;
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
        !srv_idle
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
        let has_pending = self.has_pending_output();
        // `cli_xprt.wants_write()` is the TLS term. A handshake is mostly the server
        // talking, and the condition below it -- "we have a response queued" -- is false
        // throughout one, so without this the connection is never polled for writability
        // and the handshake never finishes. It is always false for a plaintext session.
        let cli = Want {
            read: self.cli_state.can_read() && !self.req.is_full(),
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
    for i in 0..buf.len() {
        if i + 4 <= buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, 4));
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
    use super::{h3_log_line, pump_h2_body, H2ReqBody};
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
