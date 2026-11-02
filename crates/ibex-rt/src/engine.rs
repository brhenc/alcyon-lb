// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/haproxy.c (run_poll_loop, process_task), src/listener.c,
// and src/stream.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The integrated runtime engine: listeners, connections, poller, scheduler, and proxies.
//!
//! Connects [`Listener`], [`Poller`], [`FdTab`], [`Scheduler`], and [`TcpSession`]
//! into the single-threaded soft-realtime execution loop described in `design/008-tcp-first.md`.

// `assigning_clones` fires on the CURRENT_RES_HEADERS thread-local writes below.
// Those sites mix owned and borrowed `hdrs`, so a uniform `clone_from()` does not
// typecheck, and varying it per-site is churn for no measurable gain.
#![allow(clippy::assigning_clones)]
#![allow(clippy::wildcard_enum_match_arm)]

use crate::applet::{AppletArena, AppletContext, CliApplet};
use crate::check::{self, ServerCheckConfig, ServerCheckState, ServerStatus};
use crate::fdtab::{FdState, FdTab, Interest};
use crate::listener::Listener;
use crate::poller::Poller;
use crate::proxy_state::{ProxiesView, StickView};
use crate::syslog::SyslogTarget;
use ibex_config::LogLevel;
use crate::txn::MsgState;
use crate::proxy::{TcpSession, Timeouts};
use crate::raw;
use ibex_config::{BalanceAlgorithm, Config, Mode, StickRule, UseBackendRule};
use ibex_proto::endpoint::ScState;
use ibex_sample::{Expr, Registry, Sample, SampleContext};
use ibex_sched::task::{state, Kind, TaskRef, WorkKind};
use ibex_sched::{Class, Dispatch, Outcome, Scheduler, Tick};
use ibex_stick_table::{Gpc, GpcOp, KeyType, StickKey, StickTable, StickTableConfig};
use std::cell::Cell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use std::time::{Duration, Instant};

// These four are the *same* thread-locals the sample fetches read. They used to be
// declared again here, so `set-var` wrote one map and `var` read another; the only
// reason it worked was that engine re-registered `var` against its own copy. Sharing
// them makes the split impossible to reintroduce by accident.
//
// Note `CURRENT_RES_STATUS` starts at 0, not 200: ibex-sample treats 0 as "no response
// yet" and renders `-`, where the old engine-local default reported a 200 that had
// never been sent.
use ibex_sample::registry::{
    TimeoutKind, CURRENT_RES_HEADERS, CURRENT_RES_STATUS, CURRENT_RES_TR, CURRENT_SRV_STATUS, CURRENT_TIMEOUTS,
};
use ibex_sample::vars::VarStore;

thread_local! {
    pub static WORKER_ID: Cell<usize> = const { Cell::new(0) };
    static STRICT_MODE: Cell<bool> = const { Cell::new(true) };
    /// The request rules are editing the head of the request they run for: the head is written
    /// out of the HTX into the request buffer once, when they are done (or before a rule that
    /// reads the buffer), not after each edit ([`hold_req_rebuild`]). `.1`: an edit was made
    /// since, the buffer's head is not the HTX's yet. A rule pass runs to its end for one
    /// session before the thread does anything else.
    static REQ_REBUILD: Cell<(bool, bool)> = const { Cell::new((false, false)) };
    /// The line of the `http-response` rule that last ended the rules (`allow`, `deny`,
    /// `redirect`), left by `run_res_rules` for its caller to take.
    static LAST_RULE: Cell<Option<u32>> = const { Cell::new(None) };
    /// The response being rewritten by `http-response`/`http-after-response`, as the HTX
    /// message `HAProxy` holds it in: (bytes in use, size). See [`res_htx_init`].
    static RES_HTX: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

/// What an idle server connection is pooled under. `HAProxy` keeps idle connections per
/// server (`srv->per_thr[tid]`) and finds one by a hash of what shaped it
/// (`be_calculate_conn_hash`): the server, the destination address and the connection's
/// name, which for TLS is the SNI, so a connection opened for one name never carries a
/// request for another. Two backends naming one address do not share connections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdleKey {
    /// `(backend, server)`.
    pub srv: (usize, usize),
    pub addr: SocketAddr,
    /// The SNI of a TLS connection.
    pub name: Option<String>,
}

/// An idle server connection: its socket and, for TLS, its session.
#[derive(Debug)]
pub struct IdleConn {
    pub fd: OwnedFd,
    pub xprt: crate::xprt::ServerXprt,
    /// Its local address (`%bi`/`%bp`), read when it was opened: the stream that takes it
    /// again has it without a `getsockname` (T550 Q8).
    pub src: Option<SocketAddr>,
}

impl IdleConn {
    fn close(mut self) {
        self.xprt.send_close_notify(self.fd.as_fd());
    }
}

/// A server's idle connection settings: `pool-max-conn` (-1: no limit), `pool-low-conn`,
/// `pool-purge-delay` in milliseconds (0: nothing is kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrvPoolCfg {
    pub max_conn: i32,
    pub low_conn: u32,
    pub purge_delay_ms: u32,
    /// `proto h2` in `mode http`: the server's connections speak h2 (T540). Here, with the
    /// other per-connection settings, because `Proxy`'s size is bounded (`struct_sizes.rs`).
    pub h2: bool,
    /// `max-reuse`: an h2 connection is reused this many times (-1: no limit).
    pub max_reuse: i32,
}

impl SrvPoolCfg {
    pub const DEFAULT: Self = Self { max_conn: -1, low_conn: 0, purge_delay_ms: 5000, h2: false, max_reuse: -1 };

    /// Whether the server keeps idle connections at all.
    fn keeps_any(self) -> bool {
        self.max_conn != 0 && self.purge_delay_ms != 0
    }
}

#[derive(Debug)]
struct Pooled {
    addr: SocketAddr,
    name: Option<String>,
    safe: bool,
    conn: IdleConn,
}

/// The size of one entry of a server's idle list, the memory its first kept connection asks
/// for (a test refuses it, T465).
#[doc(hidden)]
#[must_use]
pub const fn idle_entry_size() -> usize {
    std::mem::size_of::<Pooled>()
}

/// The fds in use and the two counts they are weighed against (`ha_used_fds`,
/// `tune.pool_low_count`, `tune.pool_high_count`).
#[derive(Clone, Copy, Debug)]
struct FdUse {
    used: usize,
    low: usize,
    high: usize,
}

impl FdUse {
    #[cfg(test)]
    const UNLIMITED: Self = Self { used: 0, low: usize::MAX, high: usize::MAX };
}

/// Flat index of `[backend][server]`: backend `b`'s servers start at `offs[b]`.
#[derive(Clone, Debug, Default)]
struct DenseIdx {
    offs: Box<[u32]>,
}

impl DenseIdx {
    fn new(servers: &[usize]) -> Self {
        let mut n = 0u32;
        let offs = std::iter::once(0)
            .chain(servers.iter().map(|&c| {
                n = n.saturating_add(u32::try_from(c).unwrap_or(u32::MAX));
                n
            }))
            .collect();
        Self { offs }
    }

    fn total(&self) -> usize {
        self.offs.last().map_or(0, |&n| n as usize)
    }

    /// The flat index of server `srv`, if it is covered.
    #[inline]
    fn at(&self, srv: (usize, usize)) -> Option<usize> {
        let b = *self.offs.get(srv.0)? as usize;
        let e = *self.offs.get(srv.0 + 1)? as usize;
        (srv.1 < e - b).then_some(b + srv.1)
    }
}

/// What a server keeps idle in one worker. `HAProxy` has two lists: a connection that has
/// carried one request waits in `idle`, one that has carried two or more in `safe` (it
/// proved the server reuses connections); both are also on `idle_conn_list`, oldest first,
/// which is the order here. `max_used` and `est_need` are `srv->max_used_conns` and
/// `srv->est_need_conns`.
#[derive(Debug, Default)]
struct SrvIdle {
    conns: std::collections::VecDeque<Pooled>,
    safe: usize,
    max_used: u32,
    est_need: u32,
    /// When the purge next looks at this server: armed when a connection goes idle while
    /// none was scheduled, re-armed while connections remain (`idle_conn_srv`).
    purge_at: Option<Instant>,
    purge_delay: Duration,
}

/// Server `srv`'s idle lists, made if it has none; `None` when the map cannot grow for it (T465).
fn server_entry(servers: &mut HashMap<(usize, usize), SrvIdle>, srv: (usize, usize)) -> Option<&mut SrvIdle> {
    let room = servers.len() < servers.capacity() || servers.contains_key(&srv) || servers.try_reserve(1).is_ok();
    room.then(|| servers.entry(srv).or_default())
}

/// The idle server connections of a worker, per server (`srv->per_thr[tid]`). Shared with
/// the other workers through [`IdlePools`].
#[derive(Debug, Default)]
struct WorkerPool {
    servers: HashMap<(usize, usize), SrvIdle>,
    /// Where the servers the pool was sized for are ([`IdlePool::size`]); `servers` holds any
    /// other.
    dense: Option<Arc<DenseIdx>>,
    /// Per covered server, the position of its lists in `slab` (`u32::MAX`: none yet).
    slot: Vec<u32>,
    /// The lists of the covered servers that have had a connection, made on first use.
    slab: Vec<((usize, usize), SrvIdle)>,
    /// Connections in all lists: a session whose server connection has the pool to itself
    /// (the usual keep-alive case) never looks the server up.
    conns: usize,
    /// The earliest `purge_at` of all servers.
    next_purge: Option<Instant>,
    /// The worker's epoll descriptor (shared with its poller): its idle connections stay registered
    /// there for reads, and another worker that takes one takes it out first (T434). None
    /// for a worker that shares its pool with none ([`Engine::share_idle_pools`] sets it),
    /// and in the pools of the unit tests below, whose connections are registered nowhere.
    epfd: Option<Arc<OwnedFd>>,
}

impl WorkerPool {
    /// Server `srv`'s lists, if it has any: by index, hashed only for a server the pool was
    /// not sized for.
    fn srv_mut(&mut self, srv: (usize, usize)) -> Option<&mut SrvIdle> {
        if let Some(i) = self.dense.as_ref().and_then(|d| d.at(srv)) {
            let k = *self.slot.get(i)?;
            return self.slab.get_mut(k as usize).map(|e| &mut e.1);
        }
        ibex_sample::work::note(ibex_sample::work::Op::IdleHash, 1);
        self.servers.get_mut(&srv)
    }

    /// Server `srv`'s lists, made if it has none ([`server_entry`]).
    fn srv_entry(&mut self, srv: (usize, usize)) -> Option<&mut SrvIdle> {
        if let Some(i) = self.dense.as_ref().and_then(|d| d.at(srv)) {
            let k = *self.slot.get(i)?;
            if k != u32::MAX {
                return self.slab.get_mut(k as usize).map(|e| &mut e.1);
            }
            // Bounded like `server_entry`: no list when the memory is not there.
            self.slab.try_reserve(1).ok()?;
            self.slot[i] = u32::try_from(self.slab.len()).ok()?;
            self.slab.push((srv, SrvIdle::default()));
            return self.slab.last_mut().map(|e| &mut e.1);
        }
        ibex_sample::work::note(ibex_sample::work::Op::IdleHash, 1);
        server_entry(&mut self.servers, srv)
    }

    /// The server and position of the idle connection on `fd`.
    fn find_fd(&self, fd: std::os::fd::RawFd) -> Option<((usize, usize), usize)> {
        let at = |s: &SrvIdle| s.conns.iter().position(|p| p.conn.fd.as_raw_fd() == fd);
        self.slab.iter().map(|(k, s)| (*k, s)).chain(self.servers.iter().map(|(&k, s)| (k, s))).find_map(|(k, s)| at(s).map(|i| (k, i)))
    }

    /// When [`WorkerPool::purge`] next has work.
    fn next_purge(&self) -> Option<Instant> {
        self.next_purge
    }

    /// `srv_add_to_idle_list`: the server keeps a released connection if it keeps any
    /// (`pool-purge-delay` not 0), the process holds fewer fds than `pool_high_count`,
    /// `pool-max-conn` allows, and its safe list is empty and the connection is itself safe
    /// or its idle list is empty, or -- under `pool_low_count` fds -- the server is not
    /// keeping more than it was seen to need plus `pool-low-conn` (`used` is the server's
    /// connections in use, this one included). Otherwise it is given back for closing.
    #[cfg(test)]
    fn keep(&mut self, key: IdleKey, conn: IdleConn, is_safe: bool, cfg: SrvPoolCfg, used: u32, now: Instant) -> Result<(), IdleConn> {
        self.keep_with(key, conn, is_safe, cfg, used, (0, used), FdUse::UNLIMITED, now).map_err(|(conn, _)| conn)
    }

    /// [`WorkerPool::keep`], with what the other workers know of the server: its idle
    /// connections on them, and the most connections it was seen to use at once on any
    /// (`srv->curr_idle_conns`, `srv->max_used_conns`: server-wide in `HAProxy`; only the
    /// empty-lists clause is this worker's own, `srv->per_thr[tid]`).
    #[allow(clippy::too_many_arguments)]
    fn keep_with(&mut self, key: IdleKey, conn: IdleConn, is_safe: bool, cfg: SrvPoolCfg, used: u32, (others, peak): (usize, u32), fds: FdUse, now: Instant) -> Result<(), (IdleConn, IdleKey)> {
        if cfg.purge_delay_ms == 0 || fds.used >= fds.high {
            return Err((conn, key));
        }
        let Some(s) = self.srv_entry(key.srv) else { return Err((conn, key)) };
        // `srv_use_conn` raises both with every connection in use; seen from here, the
        // peak is at least the connections in use at a release.
        s.max_used = s.max_used.max(used).max(peak);
        s.est_need = s.est_need.max(used).max(peak);
        let curr_idle = s.conns.len();
        let all_idle = curr_idle + others;
        if usize::try_from(cfg.max_conn).is_ok_and(|m| m <= all_idle) {
            return Err((conn, key));
        }
        let idle_empty = curr_idle == s.safe;
        let curr = u32::try_from(all_idle).unwrap_or(u32::MAX);
        if !((s.safe == 0 && (is_safe || idle_empty)) || (fds.used < fds.low && used.saturating_add(curr) <= used.max(s.est_need).saturating_add(cfg.low_conn))) {
            return Err((conn, key));
        }
        // `HAProxy`'s idle lists are intrusive; ours closes the connection when the list cannot
        // grow (T465: an abort under `RLIMIT_DATA`).
        if s.conns.try_reserve(1).is_err() {
            return Err((conn, key));
        }
        s.conns.push_back(Pooled { addr: key.addr, name: key.name, safe: is_safe, conn });
        s.safe += usize::from(is_safe);
        let mut armed = None;
        if s.purge_at.is_none() {
            s.purge_delay = Duration::from_millis(u64::from(cfg.purge_delay_ms));
            let at = now + s.purge_delay;
            s.purge_at = Some(at);
            armed = Some(at);
        }
        self.conns += 1;
        if let Some(at) = armed {
            self.next_purge = Some(self.next_purge.map_or(at, |n| n.min(at)));
        }
        Ok(())
    }

    /// `be_reuse_connection`: the connection a request may take, and whether it was a safe
    /// one. A request that is not the first of its client connection takes an idle
    /// connection, then a safe one; a first request takes nothing under `safe`, a safe
    /// connection under `aggressive`, a safe then an idle one under `always`. The oldest
    /// that matches is taken, without a probe (`conn_backend_get`): one whose server closed
    /// it has left the lists at that event ([`IdlePool::idle_event`], T434), and one that
    /// closes as the request goes out is `abort_keep_alive`'s.
    fn take(&mut self, key: &IdleKey, first_req: bool, mode: ibex_config::HttpReuse) -> Option<(IdleConn, bool)> {
        use ibex_config::HttpReuse::{Aggressive, Always, Never, Safe};
        let s = self.srv_mut(key.srv)?;
        let order: &[bool] = match (first_req, mode) {
            (_, Never) | (true, Safe) => &[],
            (false, _) => &[false, true],
            (true, Aggressive) => &[true],
            (true, Always) => &[true, false],
        };
        for &safe in order {
            if let Some(pos) = s.conns.iter().position(|p| p.safe == safe && p.addr == key.addr && p.name == key.name) {
                let p = s.conns.remove(pos)?;
                s.safe -= usize::from(safe);
                self.conns -= 1;
                return Some((p.conn, safe));
            }
        }
        None
    }

    /// Closes server `srv`'s oldest idle connection, safe or not (`idle_conn_list`'s head).
    fn close_oldest(&mut self, srv: (usize, usize)) -> bool {
        let Some(s) = self.srv_mut(srv) else { return false };
        let Some(p) = s.conns.pop_front() else { return false };
        s.safe -= usize::from(p.safe);
        self.conns -= 1;
        p.conn.close();
        true
    }

    /// `srv_cleanup_idle_conns`, for every server whose purge is due at `now`: half the
    /// idle connections beyond what the server needs, rounded up, plus one, are closed,
    /// oldest first; the estimate of the need moves halfway to the peak seen since the last
    /// purge (never below it), and the peak restarts from the connections in use (`used`).
    #[cfg(test)]
    fn purge(&mut self, now: Instant, used: impl Fn((usize, usize)) -> u32) {
        self.purge_with(now, |srv, s| {
            let curr_idle = s.conns.len();
            if curr_idle == 0 {
                return 0;
            }
            let (to_kill, est_need) = srv_purge_step(used(srv), curr_idle, s.max_used, s.est_need);
            s.est_need = est_need;
            s.max_used = used(srv);
            to_kill.map_or(0, |k| k.saturating_add(1).min(curr_idle))
        });
    }

    /// The purge of every server due at `now`: `to_close` weighs the server and says how
    /// many of its oldest idle connections in this pool to close.
    fn purge_with(&mut self, now: Instant, mut to_close: impl FnMut((usize, usize), &mut SrvIdle) -> usize) {
        if self.next_purge.is_none_or(|t| t > now) {
            return;
        }
        let mut next: Option<Instant> = None;
        let mut closed = 0;
        for (srv, s) in self.slab.iter_mut().map(|(k, s)| (*k, s)).chain(self.servers.iter_mut().map(|(&k, s)| (k, s))) {
            let Some(at) = s.purge_at else { continue };
            if at <= now {
                let n = to_close(srv, s).min(s.conns.len());
                if n > 0 {
                    for p in s.conns.drain(..n) {
                        s.safe -= usize::from(p.safe);
                        p.conn.close();
                    }
                    closed += n;
                }
                s.purge_at = (!s.conns.is_empty()).then(|| now + s.purge_delay);
            }
            if let Some(t) = s.purge_at {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        self.conns -= closed;
        self.next_purge = next;
    }
}

/// One step of `srv_cleanup_idle_conns` for a server with `in_use` connections in use and
/// `curr_idle` idle, its peak since the last purge `max_used` and its estimated need
/// `est_need`: how many to kill (half the idle connections beyond the need, rounded up;
/// `None` when there are none), and the new estimate, moved halfway to the peak and never
/// below it. The peak then restarts from `in_use`.
fn srv_purge_step(in_use: u32, curr_idle: usize, max_used: u32, est_need: u32) -> (Option<usize>, u32) {
    let exceed = i64::from(in_use) + i64::try_from(curr_idle).unwrap_or(i64::MAX) - i64::from(max_used.max(est_need));
    let exceed = exceed / 2 + (exceed & 1);
    let est = est_need.midpoint(max_used).max(max_used);
    ((exceed > 0).then(|| usize::try_from(exceed).unwrap_or(usize::MAX)), est)
}

/// One worker's idle connections as the other workers see them (`idle_conns[tid]`): the
/// lists behind their lock and how many they hold (`srv->curr_idle_thr[tid]`, summed over
/// servers), read without it.
#[derive(Debug, Default)]
#[repr(align(64))]
struct IdleSlot {
    pool: std::sync::Mutex<WorkerPool>,
    conns: AtomicUsize,
}

/// The idle server connections of every worker. Each worker keeps its released connections
/// in its own slot and purges them; one whose own slot holds nothing for a server takes
/// another worker's (`conn_backend_get`), unless `tune.idle-pool.shared off`. The socket
/// stays in its worker's epoll set while idle, for reads (`FdState::Idle`); a taker on
/// another worker takes it out of that set under the slot's lock and adds it to its own.
#[derive(Debug)]
pub struct IdlePools {
    slots: Box<[IdleSlot]>,
    /// `tune.idle-pool.shared` is not `off` (`GTUNE_IDLE_POOL_SHARED`).
    shared: bool,
    /// The slot the next takeover starts from (`srv->per_tgrp[].next_takeover`, here one for
    /// all servers).
    next_takeover: AtomicUsize,
    /// Each server's idle connections in all slots (`srv->curr_idle_conns`).
    srv_idle: std::sync::RwLock<HashMap<(usize, usize), SrvIdleCount>>,
    /// The same counts by `[backend][server]` for the servers the engine sized the pool for
    /// ([`IdlePool::size`]): read without a lock or a hash. A server it does not cover
    /// (the unit tests' keys) uses `srv_idle`.
    dense: std::sync::OnceLock<(Arc<DenseIdx>, Box<[SrvIdleCount]>)>,
    /// `tune.pool_low_count`: past these fds in use, a server keeps no more idle
    /// connections than it was seen to need, and a worker takes another's even when the
    /// server has few (`tune.pool-low-fd-ratio` of `maxsock`).
    pool_low: usize,
    /// `tune.pool_high_count`: past these, no released connection is kept, and a new one
    /// closes an idle one first (`tune.pool-high-fd-ratio` of `maxsock`).
    pool_high: usize,
}

/// A server's idle connections in all slots, the most it was seen to use at once since a
/// purge last looked at it, and the connections it is estimated to need.
#[derive(Debug, Default)]
struct SrvIdleCount {
    idle: AtomicUsize,
    peak: std::sync::atomic::AtomicU32,
    /// `srv->est_need_conns`: raised with the connections in use, moved halfway to the
    /// peak by every worker's purge of the server.
    est_need: std::sync::atomic::AtomicU32,
}

impl IdlePools {
    /// The pools of `workers` workers, `tune.idle-pool.shared` read from `config`, with
    /// `tune.pool-low-fd-ratio` and `tune.pool-high-fd-ratio` of the `maxsock` the
    /// configuration gives (`global maxconn` as [`crate::globalconn`] settled it).
    #[must_use]
    pub fn new(workers: usize, config: &Config) -> Arc<Self> {
        let g = config.global.as_ref();
        let unshared = g.is_some_and(|g| g.idle_pool_unshared);
        let maxsock = config_maxsock(config, workers);
        let low = crate::globalconn::pool_count(maxsock, g.and_then(|g| g.pool_low_fd_ratio).unwrap_or(20));
        let high = crate::globalconn::pool_count(maxsock, g.and_then(|g| g.pool_high_fd_ratio).unwrap_or(25));
        Self::with_counts(workers, !unshared, low, high)
    }

    /// No limit from the fds in use.
    fn with(workers: usize, shared: bool) -> Arc<Self> {
        Self::with_counts(workers, shared, usize::MAX, usize::MAX)
    }

    fn with_counts(workers: usize, shared: bool, pool_low: usize, pool_high: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: (0..workers.max(1)).map(|_| IdleSlot::default()).collect(),
            shared,
            next_takeover: AtomicUsize::new(0),
            srv_idle: std::sync::RwLock::default(),
            dense: std::sync::OnceLock::new(),
            pool_low,
            pool_high,
        })
    }

    /// `ha_used_fds`: the fds in the workers' tables, and the idle connections, which leave
    /// their worker's table when they go idle.
    fn fds_used(&self) -> usize {
        crate::fdtab::used().saturating_add(self.slots.iter().map(|s| s.conns.load(Ordering::Relaxed)).sum::<usize>())
    }

    /// Runs `f` on server `srv`'s counts, made on first use.
    fn with_count<R>(&self, srv: (usize, usize), f: impl Fn(&SrvIdleCount) -> R) -> R {
        if let Some(n) = self.dense.get().and_then(|(ix, counts)| counts.get(ix.at(srv)?)) {
            return f(n);
        }
        ibex_sample::work::note(ibex_sample::work::Op::IdleLock, 1);
        if let Some(n) = self.srv_idle.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(&srv) {
            return f(n);
        }
        f(self.srv_idle.write().unwrap_or_else(std::sync::PoisonError::into_inner).entry(srv).or_default())
    }

    /// Server `srv`'s idle connections in every slot, and its peak of connections in use
    /// raised to `used`.
    fn srv_seen(&self, srv: (usize, usize), used: u32) -> (usize, u32) {
        let (idle, peak, _) = self.srv_need(srv, used);
        (idle, peak)
    }

    /// [`IdlePools::srv_seen`], with the server's estimated need, also raised to `used`
    /// (`srv_use_conn`).
    fn srv_need(&self, srv: (usize, usize), used: u32) -> (usize, u32, u32) {
        self.with_count(srv, |n| {
            let peak = n.peak.fetch_max(used, Ordering::Relaxed).max(used);
            let est = n.est_need.fetch_max(used, Ordering::Relaxed).max(used);
            (n.idle.load(Ordering::Relaxed), peak, est)
        })
    }

    /// Counts `added` connections into server `srv`'s idle ones and `removed` out.
    fn count_idle(&self, srv: (usize, usize), added: usize, removed: usize) {
        if added == removed {
            return;
        }
        self.with_count(srv, |n| {
            n.idle.fetch_add(added, Ordering::Relaxed);
            let _ = n.idle.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(removed)));
        });
    }

    /// Worker `wid`'s handle.
    #[must_use]
    pub fn worker(self: &Arc<Self>, wid: usize) -> IdlePool {
        IdlePool { pools: Arc::clone(self), wid: wid % self.slots.len(), next_purge: None, sized: false }
    }

    fn lock(slot: &IdleSlot) -> std::sync::MutexGuard<'_, WorkerPool> {
        slot.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}


/// The engine's upkeep, one `Kind::Housekeeping` task per concern (L1): each runs when its
/// timer expires, as `HAProxy`'s `srv_cleanup_idle_conns` and `process_table_expire` tasks,
/// not on every loop pass. A periodic concern stays armed while the thread is busy (a task ran
/// since its last run) and for [`hk::TAIL`] runs after, then sleeps until work comes back.
mod hk {
    /// The heap trim after a burst of fresh buffers (`buf::trim_idle`): it notes when the
    /// allocations last moved, every 100 ms (the poll's own bound) while the thread works and
    /// for 600 ms after, and trims once they have been still for 500 ms.
    pub const BUF_TRIM: usize = 0;
    /// The expired entries of the stick tables, while there is a table (none, no timer).
    pub const STICK: usize = 1;
    /// The idle server connections beyond need (`pool-purge-delay`): at the pool's own time.
    pub const IDLE_PURGE: usize = 2;
    pub const N: usize = 3;
    /// The period of each periodic concern, in ms (`IDLE_PURGE` has none: the pool says).
    pub const PERIOD_MS: [u32; N] = [100, 250, 0];
    /// Runs a periodic concern makes with no work since its last before its timer stops (an
    /// idle worker sleeps until something is due): the trim's 600 ms; the stick tables' expiry is
    /// armed as long as a table exists.
    pub const TAIL: [u8; N] = [6, u8::MAX, 0];
}

/// The housekeeping tasks and what decides their timers.
#[derive(Debug)]
struct Housekeeping {
    tasks: [TaskRef; hk::N],
    /// Concerns whose task has a timer queued.
    armed: u8,
    /// The scheduler's `tasks_run` at each concern's last run: activity since is "busy".
    seen_runs: [u64; hk::N],
    /// Idle runs since each concern last saw activity.
    idle_runs: [u8; hk::N],
    /// The idle pool's purge instant the `IDLE_PURGE` timer is queued for.
    purge_at: Option<Instant>,
    /// Concern runs so far: the scheduler counts them among its tasks run, which are not the
    /// thread's work.
    own_runs: u64,
}

impl Housekeeping {
    /// The tasks, none armed but the stick tables' expiry when `stick` (a table exists):
    /// the others arm with the thread's first work.
    fn new(scheduler: &mut Scheduler, now: Tick, stick: bool) -> Self {
        let mut tasks = [TaskRef::NONE; hk::N];
        let mut armed = 0u8;
        for (i, t) in tasks.iter_mut().enumerate() {
            let Some(task) = scheduler.create(WorkKind::new(Kind::Housekeeping, u32::try_from(i).unwrap_or(0))) else { continue };
            *t = task;
            if i == hk::STICK && stick {
                scheduler.queue_timer(task, now.add(hk::PERIOD_MS[i]));
                armed |= 1 << i;
            }
        }
        // Without a table the expiry counts as armed: nothing ever arms it.
        let armed = if stick { armed } else { armed | (1 << hk::STICK) };
        Housekeeping { tasks, armed, seen_runs: [0; hk::N], idle_runs: [0; hk::N], purge_at: None, own_runs: 0 }
    }
}

/// A worker's handle on [`IdlePools`]: what the engine keeps, takes and purges through.
#[derive(Debug)]
pub struct IdlePool {
    pools: Arc<IdlePools>,
    wid: usize,
    /// When this worker's purge next has work: kept here so that a step with nothing to purge
    /// does not take the lock.
    next_purge: Option<Instant>,
    /// [`IdlePool::ensure_sized`] has run: done when the first connection goes idle, so that a
    /// worker that never keeps one holds no table.
    sized: bool,
}

impl IdlePool {
    /// Whether a panic unwound through a change of the idle connection lists of any worker
    /// (T447).
    fn poisoned(&self) -> bool {
        self.pools.srv_idle.is_poisoned() || self.pools.slots.iter().any(|s| s.pool.is_poisoned())
    }
}

impl Default for IdlePool {
    /// A worker alone.
    fn default() -> Self {
        IdlePools::with(1, true).worker(0)
    }
}

impl IdlePool {
    fn slot(&self) -> &IdleSlot {
        &self.pools.slots[self.wid]
    }

    /// The most servers the pool is sized for.
    const DENSE_MAX: usize = 16384;

    /// Sizes the pool for backends with `servers[b]` servers each, so that their lists and
    /// counts are found by index (O2). Called before the engine runs; the first worker to
    /// call fixes the counts' table, which every worker's engine builds alike.
    fn ensure_sized(&mut self, proxies: &[Proxy]) {
        if !self.sized {
            self.sized = true;
            let counts: Vec<usize> = proxies.iter().map(|p| p.servers.len()).collect();
            self.size(&counts);
        }
    }

    /// Sizes the pool for backends with `servers[b]` servers each (see [`IdlePool::ensure_sized`]).
    pub fn size(&mut self, servers: &[usize]) {
        // The tables cost ~24 bytes a server in all (a configuration of 60k backends is held to
        // a memory bound the tables would break): past this many, the hashed path serves.
        if servers.iter().sum::<usize>() > Self::DENSE_MAX {
            return;
        }
        let (ix, counts) = self.pools.dense.get_or_init(|| {
            let ix = DenseIdx::new(servers);
            let counts = (0..ix.total()).map(|_| SrvIdleCount::default()).collect();
            (Arc::new(ix), counts)
        });
        let mut pool = IdlePools::lock(self.slot());
        if pool.dense.is_none() && pool.conns == 0 {
            pool.slot = vec![u32::MAX; counts.len()];
            pool.dense = Some(Arc::clone(ix));
        }
    }

    /// Whether this worker holds no idle connection.
    fn is_empty(&self) -> bool {
        self.slot().conns.load(Ordering::Relaxed) == 0
    }

    /// Whether a request of this worker may find an idle connection: its own, or with
    /// sharing on another worker's.
    fn may_find(&self) -> bool {
        !self.is_empty() || (self.pools.shared && self.pools.slots.iter().any(|s| s.conns.load(Ordering::Relaxed) != 0))
    }

    /// When [`IdlePool::purge`] next has work.
    #[must_use]
    pub fn next_purge(&self) -> Option<Instant> {
        self.next_purge
    }

    /// See [`WorkerPool::keep`]; into this worker's slot.
    fn keep(&mut self, key: IdleKey, conn: IdleConn, is_safe: bool, cfg: SrvPoolCfg, used: u32, now: Instant) -> Result<(), IdleConn> {
        let srv = key.srv;
        let slot = &self.pools.slots[self.wid];
        let mut pool = IdlePools::lock(slot);
        let (all, peak, est) = self.pools.srv_need(srv, used);
        // The server's need is server-wide and every worker's purge moves it: this worker's
        // copy starts from it, which `keep_with` raises to what it sees.
        let Some(s) = pool.srv_entry(srv) else { return Err(conn) };
        let own = s.conns.len();
        (s.max_used, s.est_need) = (peak, est);
        // `HAProxy` weighs a connection it may keep with its fd still counted; this one has
        // left the worker's table already.
        let fds = FdUse { used: self.pools.fds_used().saturating_add(1), low: self.pools.pool_low, high: self.pools.pool_high };
        let others = all.saturating_sub(own);
        // A connection its server closed is not weighed: it left the lists at that event
        // (`IdlePool::idle_event`), as `HAProxy` drops one (T301: a dead one weighed made
        // the lists refuse the next client's fresh connection; T434: no probe).
        let r = pool.keep_with(key, conn, is_safe, cfg, used, (others, peak), fds, now);
        slot.conns.store(pool.conns, Ordering::Relaxed);
        self.next_purge = pool.next_purge();
        drop(pool);
        if r.is_ok() {
            self.pools.count_idle(srv, 1, 0);
        }
        r.map_err(|(conn, _)| conn)
    }

    /// `conn_backend_get`: this worker's lists first; when they hold nothing that matches,
    /// with sharing on and unless the server keeps fewer idle connections than its
    /// `pool-low-conn` (`steal` false), every other worker's, from the one after the last
    /// taken from (waiting for a busy one, where `HAProxy` skips it: see below).
    ///
    /// The third member says whether the connection is still registered in this worker's
    /// epoll set, for reads: one of its own is; one taken from another worker has been taken
    /// out of that worker's set, under its lock, and is registered nowhere (T434).
    fn take(&mut self, key: &IdleKey, first_req: bool, mode: ibex_config::HttpReuse, steal: bool) -> Option<(IdleConn, bool, bool)> {
        let pools = &*self.pools;
        let own = &pools.slots[self.wid];
        if own.conns.load(Ordering::Relaxed) != 0 {
            let mut pool = IdlePools::lock(own);
            let before = pool.conns;
            let found = pool.take(key, first_req, mode);
            own.conns.store(pool.conns, Ordering::Relaxed);
            self.next_purge = pool.next_purge();
            pools.count_idle(key.srv, 0, before - pool.conns);
            if let Some((conn, safe)) = found {
                return Some((conn, safe, true));
            }
        }
        let n = pools.slots.len();
        if !pools.shared || !steal || n == 1 {
            return None;
        }
        let start = pools.next_takeover.load(Ordering::Relaxed) % n;
        for i in (start..n).chain(0..start) {
            let slot = &pools.slots[i];
            if i == self.wid || slot.conns.load(Ordering::Relaxed) == 0 {
                continue;
            }
            // `HAProxy` skips a busy list (`HA_SPIN_TRYLOCK`), held there for a few
            // instructions; this lock is also held by the owner's purge and its reads of
            // an idle connection's event, and skipping it opened a connection while the
            // slot held idle ones (T224, when the owner's sweep peeked at every idle
            // connection under it: a ninth where eight serve, 8 in 72 runs under load; 1
            // in 72 waiting).
            // No worker holds its own slot while it locks another's: no lock order to break.
            let mut pool = IdlePools::lock(slot);
            let before = pool.conns;
            let found = pool.take(key, first_req, mode);
            slot.conns.store(pool.conns, Ordering::Relaxed);
            let removed = before - pool.conns;
            // `fd_takeover`: out of the owner's epoll set while its lock is held, so that
            // the owner, which finds its idle connections' events under that lock, never
            // sees this one again. One that cannot be taken out is closed, not used.
            let found = found.and_then(|(conn, safe)| match pool.epfd.as_ref().map(|ep| Poller::forget_in(ep.as_fd(), conn.fd.as_fd())) {
                Some(Err(_)) => {
                    conn.close();
                    None
                }
                _ => Some((conn, safe, false)),
            });
            drop(pool);
            pools.count_idle(key.srv, 0, removed);
            if found.is_some() {
                pools.next_takeover.store(i + 1, Ordering::Relaxed);
                return found;
            }
        }
        None
    }

    /// Gives this worker's slot its epoll descriptor, for the workers that take its idle
    /// connections to take them out of it.
    pub fn attach_poller(&mut self, epfd: Arc<OwnedFd>) {
        IdlePools::lock(self.slot()).epfd = Some(epfd);
    }

    /// An event on `fd`, one of this worker's idle connections ([`FdState::Idle`]): its
    /// server closed or reset it, or sent something (`h1_io_cb` on an idle connection, then
    /// `h1_process`). What is there is read; anything but nothing to read (`close_notify`,
    /// EOF, an error, bytes nobody asked for) closes it and takes it out of the lists and
    /// the server's count. A TLS record without data (a session ticket) leaves it idle.
    /// Whether it is still idle here: false also when another worker took it after the
    /// event was reported (it is no longer in this worker's epoll set).
    pub fn idle_event(&mut self, fd: std::os::fd::RawFd) -> bool {
        let slot = &self.pools.slots[self.wid];
        let mut pool = IdlePools::lock(slot);
        let Some((srv, pos)) = pool.find_fd(fd) else {
            return false;
        };
        let Some(s) = pool.srv_mut(srv) else { return false };
        let mut buf = [0u8; 4096];
        let quiet = s.conns.get_mut(pos).is_some_and(|p| matches!(p.conn.xprt.recv(p.conn.fd.as_fd(), &mut buf), Ok(raw::Io::WouldBlock)));
        if quiet {
            return true;
        }
        let Some(p) = s.conns.remove(pos) else { return false };
        s.safe -= usize::from(p.safe);
        pool.conns -= 1;
        slot.conns.store(pool.conns, Ordering::Relaxed);
        self.next_purge = pool.next_purge();
        drop(pool);
        p.conn.close();
        self.pools.count_idle(srv, 0, 1);
        false
    }

    /// Idle connections in every worker's slot.
    fn total(&self) -> usize {
        self.pools.slots.iter().map(|s| s.conns.load(Ordering::Relaxed)).sum()
    }

    /// `conn_backend_get`: whether a worker may take server `srv`'s idle connections from
    /// another worker. Not while the server keeps fewer than its `pool-low-conn` (`low`)
    /// and the process holds fewer fds than `pool_low_count`: a new connection is cheap then.
    fn may_steal(&self, srv: (usize, usize), low: u32) -> bool {
        let idle = self.pools.with_count(srv, |n| n.idle.load(Ordering::Relaxed));
        !(idle < usize::try_from(low).unwrap_or(usize::MAX) && self.pools.fds_used() < self.pools.pool_low)
    }

    /// `connect_server`: past `pool_high_count` fds in use, closes server `srv`'s oldest idle
    /// connection, this worker's first, then another's whose lock is free (with sharing on;
    /// off, only the next worker is tried, as `HAProxy` stops after one).
    fn close_one_over_high(&mut self, srv: (usize, usize)) {
        let pools = &*self.pools;
        if pools.fds_used() <= pools.pool_high {
            return;
        }
        let n = pools.slots.len();
        for i in (self.wid..n).chain(0..self.wid) {
            let slot = &pools.slots[i];
            if slot.conns.load(Ordering::Relaxed) == 0 {
                if i != self.wid && !pools.shared {
                    break;
                }
                continue;
            }
            let pool = if i == self.wid { Some(IdlePools::lock(slot)) } else { slot.pool.try_lock().ok() };
            let Some(mut pool) = pool else { continue };
            let closed = pool.close_oldest(srv);
            slot.conns.store(pool.conns, Ordering::Relaxed);
            if i == self.wid {
                self.next_purge = pool.next_purge();
            }
            drop(pool);
            if closed {
                pools.count_idle(srv, 0, 1);
                return;
            }
            if i != self.wid && !pools.shared {
                break;
            }
        }
    }

    /// Raises server `srv`'s peak of connections in use to `used`.
    fn note_used(&self, srv: (usize, usize), used: u32) {
        let _ = self.pools.srv_seen(srv, used);
    }

    /// See [`WorkerPool::purge`]; this worker's slot, when its purge is due.
    pub fn purge(&mut self, now: Instant, used: impl Fn((usize, usize)) -> u32) {
        if self.next_purge.is_none_or(|t| t > now) {
            return;
        }
        let slot = &self.pools.slots[self.wid];
        let mut pool = IdlePools::lock(slot);
        let pools = &*self.pools;
        // `srv_cleanup_idle_conns`: the server's idle connections, peak and need are
        // server-wide, and this worker closes its share of the excess (T270: weighed per
        // worker, each worker's few idle connections stood against the whole server's peak
        // and a burst's connections outlived it by tens of seconds).
        pool.purge_with(now, |srv, s| {
            let own = s.conns.len();
            let (all, max_used, est) = pools.with_count(srv, |c| {
                (c.idle.load(Ordering::Relaxed), c.peak.load(Ordering::Relaxed), c.est_need.load(Ordering::Relaxed))
            });
            let all = all.max(own);
            if all == 0 {
                return 0;
            }
            let in_use = used(srv);
            let (to_kill, est) = srv_purge_step(in_use, all, max_used, est);
            pools.with_count(srv, |c| {
                c.est_need.store(est, Ordering::Relaxed);
                // The peak restarts from the connections in use with each purge of the server.
                c.peak.store(in_use, Ordering::Relaxed);
            });
            (s.max_used, s.est_need) = (in_use, est);
            let n = to_kill.map_or(0, |k| (k.saturating_mul(own) / all).saturating_add(1).min(own));
            // Counted here, as the counts above are: no list of what was closed, whose memory
            // could fail (T465).
            pools.count_idle(srv, 0, n);
            n
        });
        slot.conns.store(pool.conns, Ordering::Relaxed);
        self.next_purge = pool.next_purge();
    }
}

#[cfg(test)]
mod shared_pool_tests {
    use super::*;

    fn alive() -> (IdleConn, std::os::unix::net::UnixStream) {
        let (a, b) = std::os::unix::net::UnixStream::pair().expect("pair");
        // Non-blocking, as every server socket is: an event's read must not wait.
        a.set_nonblocking(true).expect("nonblocking");
        (IdleConn { fd: OwnedFd::from(a), xprt: crate::xprt::ServerXprt::Plain, src: None }, b)
    }

    fn key() -> IdleKey {
        IdleKey { srv: (0, 0), addr: "127.0.0.1:1".parse().unwrap(), name: None }
    }

    const CFG: SrvPoolCfg = SrvPoolCfg { max_conn: -1, low_conn: 0, purge_delay_ms: 500, h2: false, max_reuse: -1 };

    /// A connection worker 0 released is taken by worker 1 when shared, not when not, nor
    /// when `pool-low-conn` forbids it; worker 0's lock held a while is waited for (T224).
    #[test]
    fn another_worker_takes_an_idle_connection_only_when_shared() {
        use ibex_config::HttpReuse::Always;
        let t0 = Instant::now();
        for shared in [true, false] {
            let pools = IdlePools::with(2, shared);
            let (mut w0, mut w1) = (pools.worker(0), pools.worker(1));
            let (c, _peer) = alive();
            assert!(w0.keep(key(), c, false, CFG, 1, t0).is_ok());
            assert!(!w1.is_empty() || w1.may_find() == shared);
            assert_eq!(w1.total(), 1);
            assert!(w1.take(&key(), true, Always, false).is_none());
            let (tx, rx) = std::sync::mpsc::channel();
            let p = Arc::clone(&pools);
            let holder = std::thread::spawn(move || {
                let _held = IdlePools::lock(&p.slots[0]);
                tx.send(()).expect("signal");
                std::thread::sleep(Duration::from_millis(100));
            });
            rx.recv().expect("the lock is held");
            let asked = Instant::now();
            let took = w1.take(&key(), true, Always, true).is_some();
            holder.join().expect("holder");
            assert_eq!(took, shared);
            if shared {
                assert!(asked.elapsed() >= Duration::from_millis(50), "the busy slot was skipped");
            }
            assert_eq!(w0.is_empty(), shared);
            // The worker the connection was taken from purges nothing and is unscheduled;
            // one that still holds it purges again later.
            w0.purge(t0 + Duration::from_secs(1), |_| 0);
            assert_eq!(w0.next_purge().is_none(), shared);
        }
    }

    /// Past `pool_high_count` fds no released connection is kept; past `pool_low_count` only
    /// the one an empty list takes (`srv_add_to_idle_list`).
    #[test]
    fn the_fds_in_use_limit_what_is_kept() {
        let t0 = Instant::now();
        let fds = |used| FdUse { used, low: 5, high: 20 };
        for (used, first, second) in [(3, true, true), (10, true, false), (20, false, false)] {
            let mut pool = WorkerPool::default();
            let (c0, _p0) = alive();
            let (c1, _p1) = alive();
            assert_eq!(pool.keep_with(key(), c0, false, CFG, 2, (0, 2), fds(used), t0).is_ok(), first, "{used} fds, the first");
            assert_eq!(pool.keep_with(key(), c1, false, CFG, 1, (0, 2), fds(used), t0).is_ok(), second, "{used} fds, the second");
        }
    }

    /// Past `pool_high_count` a new connection closes the server's oldest idle one: this
    /// worker's, else another's while sharing; unshared, only the next worker is looked at.
    #[test]
    fn over_the_high_count_a_connect_closes_an_idle_connection() {
        use std::io::Read;
        let t0 = Instant::now();
        // (sharing, the worker holding server (0, 0)'s connection, `pool_high_count`,
        // whether worker 1 holds one of another server's, whether (0, 0)'s is closed)
        let cases = [
            (true, 0, 0, false, true),
            (false, 0, 0, false, true),
            (true, 2, 0, false, true),
            (false, 2, 0, false, false),
            (true, 2, 0, true, true),
            (false, 2, 0, true, false),
            (true, 0, usize::MAX, false, false),
        ];
        for (shared, holder, high, other_on_1, closed) in cases {
            let pools = IdlePools::with_counts(3, shared, usize::MAX, high);
            let (c, mut peer) = alive();
            let (c_other, _peer_other) = alive();
            let other = IdleKey { srv: (0, 1), ..key() };
            for (wid, k, conn) in [(holder, key(), Some(c)), (1, other, other_on_1.then_some(c_other))] {
                let Some(conn) = conn else { continue };
                let mut pool = IdlePools::lock(&pools.slots[wid]);
                assert!(pool.keep(k.clone(), conn, false, CFG, 1, t0).is_ok());
                pools.slots[wid].conns.store(pool.conns, Ordering::Relaxed);
                pools.count_idle(k.srv, 1, 0);
            }
            pools.worker(0).close_one_over_high(key().srv);
            peer.set_nonblocking(true).expect("nonblocking");
            let eof = matches!(peer.read(&mut [0u8; 1]), Ok(0));
            assert_eq!(eof, closed, "shared {shared}, held by worker {holder}, high {high}, another server's on worker 1 {other_on_1}");
            assert_eq!(pools.slots[holder].conns.load(Ordering::Relaxed) == 0, closed);
        }
    }

    /// Another worker's idle connection is not taken while the server keeps fewer than its
    /// `pool-low-conn` and the fds in use are under `pool_low_count`.
    #[test]
    fn under_the_low_count_a_server_with_few_idle_connections_is_not_stolen_from() {
        let w = IdlePools::with_counts(1, true, usize::MAX, usize::MAX).worker(0);
        assert!(w.may_steal(key().srv, 0));
        assert!(!w.may_steal(key().srv, 2));
        let w = IdlePools::with_counts(1, true, 0, usize::MAX).worker(0);
        assert!(w.may_steal(key().srv, 2));
    }

    /// The purge of a server restarts its peak of connections in use from the connections in
    /// use at that moment (`srv->max_used_conns = srv->curr_used_conns`).
    #[test]
    fn a_purge_restarts_the_servers_peak_from_the_connections_in_use() {
        let t0 = Instant::now();
        let pools = IdlePools::with(1, true);
        let mut w = pools.worker(0);
        let (c, _p) = alive();
        assert!(w.keep(key(), c, false, CFG, 5, t0).is_ok());
        assert_eq!(pools.srv_seen(key().srv, 0).1, 5);
        // A second server, kept later, is not due at that purge: its peak stays.
        let (c2, _p2) = alive();
        let other = IdleKey { srv: (0, 1), ..key() };
        assert!(w.keep(other.clone(), c2, false, CFG, 7, t0 + Duration::from_millis(300)).is_ok());
        w.purge(t0 + Duration::from_millis(500), |_| 2);
        assert_eq!(pools.srv_seen(key().srv, 0).1, 2);
        assert_eq!(pools.srv_seen(other.srv, 0).1, 7);
    }

    /// T270: after a burst of 32 connections spread over four workers, eight idle on each,
    /// the server's need and peak are server-wide (`srv->est_need_conns`,
    /// `srv->max_used_conns`, `srv->curr_idle_conns`) and every worker's purge moves them, so
    /// the idle connections are gone after four purge periods, as `HAProxy` drains them
    /// (each purge closes its share, `to_kill * curr_idle_thr / curr_idle + 1`). Weighed per
    /// worker, each worker's eight stood against the whole server's peak of 32 and outlived a
    /// header storm by more than 45 s with the default `pool-purge-delay 5s`.
    #[test]
    fn every_workers_purge_moves_the_servers_need() {
        let t0 = Instant::now();
        let pools = IdlePools::with(4, true);
        let mut ws: Vec<IdlePool> = (0..4).map(|w| pools.worker(w)).collect();
        let mut peers = Vec::new();
        for (w, wk) in (0..4u32).zip(ws.iter_mut()) {
            let at = t0 + Duration::from_millis(100 * u64::from(w));
            for k in 0..8u32 {
                let (c, p) = alive();
                peers.push(p);
                assert!(wk.keep(key(), c, false, CFG, 32 - 8 * w - k, at).is_ok());
            }
        }
        assert_eq!(ws[0].total(), 32);
        // Purges as `HAProxy` would run them: (worker, ms after t0, idle left on it).
        let steps = [
            (0, 500, 8), (1, 600, 8), (2, 700, 5), (3, 800, 4),
            (0, 1000, 4), (1, 1100, 4), (2, 1200, 2), (3, 1300, 1),
            (0, 1500, 1), (1, 1600, 1), (2, 1700, 0), (3, 1800, 0),
            (0, 2000, 0), (1, 2100, 0),
        ];
        for (w, ms, left) in steps {
            ws[w].purge(t0 + Duration::from_millis(ms), |_| 0);
            assert_eq!(ws[w].slot().conns.load(Ordering::Relaxed), left, "worker {w} at {ms} ms");
        }
        assert_eq!(ws[0].total(), 0);
    }

    /// An event on an idle connection closes it when its peer closed it, or sent bytes, and
    /// keeps it when there is nothing to read; the counts the pool and the servers hold
    /// follow (T434: what the sweep's peeks did every 50 ms).
    #[test]
    fn an_idle_event_closes_the_connections_the_peer_closed() {
        use std::io::Write;
        let t0 = Instant::now();
        let pools = IdlePools::with(1, true);
        let mut w = pools.worker(0);
        let (c0, p0) = alive();
        let (c1, mut p1) = alive();
        let (c2, _p2) = alive();
        let fds = [c0.fd.as_raw_fd(), c1.fd.as_raw_fd(), c2.fd.as_raw_fd()];
        assert!(w.keep(key(), c0, false, CFG, 3, t0).is_ok());
        assert!(w.keep(IdleKey { srv: (0, 1), ..key() }, c1, false, CFG, 3, t0).is_ok());
        assert!(w.keep(IdleKey { srv: (0, 2), ..key() }, c2, false, CFG, 3, t0).is_ok());
        drop(p0);
        p1.write_all(b"x").expect("unexpected bytes");
        assert!(!w.idle_event(fds[0]), "closed by its peer");
        assert!(!w.idle_event(fds[1]), "bytes nobody asked for");
        assert!(w.idle_event(fds[2]), "nothing to read: still idle");
        assert!(!w.idle_event(fds[0]), "no longer in the lists");
        assert_eq!(w.total(), 1);
        for srv in [(0, 0), (0, 1), (0, 2)] {
            assert_eq!(pools.with_count(srv, |n| n.idle.load(Ordering::Relaxed)), usize::from(srv.1 == 2));
        }
    }

    /// Past `DENSE_MAX` servers the pool is not sized, and keeps and takes through the hashed
    /// path as an unsized pool does.
    #[test]
    fn a_pool_too_large_to_size_still_keeps_and_takes() {
        let t0 = Instant::now();
        let pools = IdlePools::with(1, true);
        let mut w = pools.worker(0);
        w.size(&[IdlePool::DENSE_MAX + 1]);
        assert!(pools.dense.get().is_none(), "not sized");
        let (c, _p) = alive();
        assert!(w.keep(key(), c, false, CFG, 1, t0).is_ok());
        assert_eq!(w.total(), 1);
        assert!(w.take(&key(), false, ibex_config::HttpReuse::Always, true).is_some());
    }

    /// A connection whose server closed it while idle does not make the lists refuse the
    /// next one (T301): with it alive, a second connection that carried one request is
    /// refused (the idle list is not empty); once its peer's close was its event, the
    /// second is kept in its place, and the server's count holds one.
    #[test]
    fn a_dead_idle_connection_does_not_make_the_lists_refuse() {
        let t0 = Instant::now();
        let pools = IdlePools::with(1, true);
        let mut w = pools.worker(0);
        let (c0, _p0) = alive();
        let (c1, _p1) = alive();
        assert!(w.keep(key(), c0, false, CFG, 1, t0).is_ok());
        assert!(w.keep(key(), c1, false, CFG, 1, t0).is_err(), "the idle list holds a live one");
        let (c2, _p2) = alive();
        let (c3, p3) = alive();
        let pools = IdlePools::with(1, true);
        let mut w = pools.worker(0);
        let fd3 = c3.fd.as_raw_fd();
        assert!(w.keep(key(), c3, false, CFG, 1, t0).is_ok());
        drop(p3);
        assert!(!w.idle_event(fd3));
        assert!(w.keep(key(), c2, false, CFG, 1, t0).is_ok(), "the dead one is not weighed");
        assert_eq!(w.total(), 1);
        assert_eq!(pools.with_count((0, 0), |n| n.idle.load(Ordering::Relaxed)), 1);
    }

    /// Another worker's dead idle connections do not make the lists refuse either (T301
    /// item 3): `pool-max-conn` and the need estimate count the server's idle connections
    /// on every worker. Worker 0, on its own thread, keeps a connection whose peer then
    /// closes, which is an event on worker 0; worker 1 keeps one under `pool-max-conn 1`,
    /// and one more beside a live one of its own under `pool-low-conn 1`, each refused
    /// while worker 0's was alive.
    #[test]
    fn another_workers_dead_idle_connection_does_not_make_the_lists_refuse() {
        let t0 = Instant::now();
        let one = SrvPoolCfg { max_conn: 1, ..CFG };
        let low = SrvPoolCfg { low_conn: 1, ..CFG };
        for (cfg, own_live) in [(one, false), (low, true)] {
            let pools = IdlePools::with(2, true);
            let (mut w0, mut w1) = (pools.worker(0), pools.worker(1));
            let (c0, p0) = alive();
            let fd0 = c0.fd.as_raw_fd();
            std::thread::scope(|t| {
                t.spawn(|| assert!(w0.keep(key(), c0, false, cfg, 1, t0).is_ok()));
            });
            let _own = own_live.then(|| {
                let (c, p) = alive();
                assert!(w1.keep(key(), c, false, CFG, 1, t0).is_ok());
                p
            });
            let (c1, _p1) = alive();
            assert!(w1.keep(key(), c1, false, cfg, 1, t0).is_err(), "worker 0's is alive");
            drop(p0);
            std::thread::scope(|t| {
                t.spawn(|| assert!(!w0.idle_event(fd0)));
            });
            assert!(w0.is_empty(), "worker 0's dead one is dropped");
            let (c2, _p2) = alive();
            assert!(w1.keep(key(), c2, false, cfg, 1, t0).is_ok(), "worker 0's is dead");
            assert_eq!(pools.with_count((0, 0), |n| n.idle.load(Ordering::Relaxed)), 1 + usize::from(own_live));
        }
    }

    /// Another worker's connection to another server is not taken; the search goes on to
    /// the next worker.
    #[test]
    fn a_takeover_matches_the_server() {
        use ibex_config::HttpReuse::Always;
        let t0 = Instant::now();
        let pools = IdlePools::with(3, true);
        let (mut w0, mut w1, mut w2) = (pools.worker(0), pools.worker(1), pools.worker(2));
        let other = IdleKey { srv: (0, 1), ..key() };
        let (c0, _p0) = alive();
        let (c1, _p1) = alive();
        assert!(w0.keep(other, c0, false, CFG, 1, t0).is_ok());
        assert!(w1.keep(key(), c1, false, CFG, 1, t0).is_ok());
        assert!(w2.take(&key(), true, Always, true).is_some());
        assert!(w1.is_empty() && !w0.is_empty());
        assert!(w2.take(&key(), true, Always, true).is_none());
    }

    /// `srv_add_to_idle_list` compares `pool-max-conn` and the need estimate with the
    /// server's idle connections on every thread (`srv->curr_idle_conns`), not this
    /// worker's: with `pool-max-conn 1` and one idle on worker 0, worker 1 keeps none
    /// (`http_reuse_safe.vtc` at `nbthread 64`: c2's second request gets c1's
    /// connection). Taking or purging one counts it out again.
    #[test]
    fn pool_max_conn_counts_the_idle_connections_of_every_worker() {
        use ibex_config::HttpReuse::Always;
        let t0 = Instant::now();
        let one = SrvPoolCfg { max_conn: 1, ..CFG };
        let pools = IdlePools::with(2, true);
        let (mut w0, mut w1) = (pools.worker(0), pools.worker(1));
        let (c0, _p0) = alive();
        let (c1, _p1) = alive();
        let (c2, _p2) = alive();
        assert!(w0.keep(key(), c0, true, one, 1, t0).is_ok());
        assert!(w1.keep(key(), c1, true, one, 1, t0).is_err(), "a second idle connection on another worker");
        assert!(w1.take(&key(), false, Always, true).is_some());
        assert!(w1.keep(key(), c2, true, one, 1, t0).is_ok(), "the one idle connection was taken");
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    fn conn() -> IdleConn {
        IdleConn { fd: OwnedFd::from(std::fs::File::open("/dev/null").expect("open")), xprt: crate::xprt::ServerXprt::Plain, src: None }
    }

    fn key() -> IdleKey {
        IdleKey { srv: (0, 0), addr: "127.0.0.1:1".parse().unwrap(), name: None }
    }

    const CFG: SrvPoolCfg = SrvPoolCfg { max_conn: -1, low_conn: 0, purge_delay_ms: 500, h2: false, max_reuse: -1 };

    /// HAProxy, eight connections idle after a burst of eight, `pool-purge-delay 500`:
    /// nothing is closed at the first two purges, then 3, 3 and 2 (the estimate 8, 8, 4, 2,
    /// 1, 0).
    #[test]
    fn each_purge_closes_half_the_excess_plus_one() {
        let t0 = Instant::now();
        let mut pool = WorkerPool::default();
        for used in (1..=8).rev() {
            assert!(pool.keep(key(), conn(), false, CFG, used, t0).is_ok());
        }
        assert_eq!(pool.next_purge(), Some(t0 + Duration::from_millis(500)));
        let mut left = Vec::new();
        for k in 1..=6 {
            let now = t0 + Duration::from_millis(500 * k);
            pool.purge(now - Duration::from_millis(1), |_| 0);
            assert_eq!(pool.conns, left.last().copied().unwrap_or(8), "not due yet at purge {k}");
            pool.purge(now, |_| 0);
            left.push(pool.conns);
        }
        assert_eq!(left, [8, 8, 5, 2, 0, 0]);
        assert_eq!(pool.next_purge(), None);
    }

    /// `pool-purge-delay 0` keeps nothing; `pool-low-conn` keeps that many beyond the need.
    #[test]
    fn purge_delay_zero_and_low_conn() {
        let t0 = Instant::now();
        let mut pool = WorkerPool::default();
        assert!(pool.keep(key(), conn(), false, SrvPoolCfg { purge_delay_ms: 0, ..CFG }, 1, t0).is_err());
        let low = SrvPoolCfg { low_conn: 1, ..CFG };
        assert!(pool.keep(key(), conn(), false, low, 1, t0).is_ok());
        assert!(pool.keep(key(), conn(), false, low, 1, t0).is_ok());
        assert!(pool.keep(key(), conn(), false, low, 1, t0).is_err());
        assert!(pool.keep(key(), conn(), false, CFG, 1, t0).is_err());
    }

    /// A server whose idle connections were all taken before its purge is unscheduled
    /// (`srv_cleanup_idle_conns`: `curr_idle == 0`), its estimate untouched.
    #[test]
    fn a_purge_with_nothing_idle_unschedules_the_server() {
        let t0 = Instant::now();
        let mut pool = WorkerPool::default();
        // A socket pair: the idle connection must look alive to be taken.
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let c = IdleConn { fd: OwnedFd::from(a), xprt: crate::xprt::ServerXprt::Plain, src: None };
        assert!(pool.keep(key(), c, false, CFG, 3, t0).is_ok());
        assert!(pool.take(&key(), false, ibex_config::HttpReuse::Safe).is_some());
        pool.purge(t0 + Duration::from_millis(500), |_| 0);
        assert_eq!(pool.next_purge(), None);
        assert_eq!(pool.servers[&(0, 0)].est_need, 3);
    }
}

/// The idle connection settings of each server of a proxy, and its `proto h2` in `mode http`
/// (`mode_http`); empty when all are the defaults.
fn pool_cfgs(servers: &[ibex_config::Server], mode_http: bool) -> Vec<SrvPoolCfg> {
    let cfg = |s: &ibex_config::Server| {
        let p = s.pool.as_deref().copied().unwrap_or_default();
        SrvPoolCfg { max_conn: p.max_conn, low_conn: p.low_conn, purge_delay_ms: p.purge_delay, h2: mode_http && s.proto_h2, max_reuse: p.max_reuse }
    };
    if servers.iter().all(|s| cfg(s) == SrvPoolCfg::DEFAULT) {
        Vec::new()
    } else {
        servers.iter().map(cfg).collect()
    }
}

/// Attaches the freshly connected `srv_fd` to `sess` with the transport the server line
/// `proxies[be_idx].servers.at(s_idx)` asks for: plaintext, or TLS with the SNI its
/// expression gives over this stream. This is where `server ... ssl` reaches the data
/// path (T113). A TLS session that cannot be set up is a connect failure.
fn attach_server_to(
    sess: &mut TcpSession,
    proxies: &[Proxy],
    fe_idx: usize,
    be_idx: usize,
    s_idx: Option<usize>,
    srv_fd: OwnedFd,
    now: Tick,
) {
    let tls = s_idx.and_then(|i| proxies.get(be_idx).and_then(|p| p.server_tls.get(i)).and_then(Option::as_ref));
    // `proto h2`: h2 from the first byte, over TLS whatever ALPN selects (T540).
    let h2 = s_idx.is_some_and(|i| proxies.get(be_idx).is_some_and(|p| p.ids.server_pool(i).h2));
    let Some(tls) = tls else {
        if h2 {
            attach_h2(sess, srv_fd, crate::xprt::ServerXprt::Plain, now);
        } else {
            sess.attach_server(srv_fd, now);
        }
        return;
    };
    let (fe, be) = (&proxies[fe_idx], &proxies[be_idx]);
    let stick = StickView::new(proxies, &sess.tracked_sc);
    let ip = s_idx.and_then(|i| be.servers.get(i)).map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |a| a.ip());
    let mut xprt = tls.with_sni(sample_registry(), &stream_sample_ctx(sess, fe, be, &ProxiesView(proxies), &stick), |sni| {
        tls.connect(&srv_fd, sni, ip)
    });
    // A PROXY header (`send-proxy*`) was put at the head of the request; to a TLS
    // server it goes on the wire in plaintext, before the ClientHello, as
    // HAProxy's xprt_handshake layer sends it and the peer's `accept-proxy`
    // reads it. So it leaves the stream for the transport's prefix.
    let n = sess.send_proxy_header.len();
    if let (true, crate::xprt::ServerXprt::Tls(t)) = (
        sess.send_proxy_prepended && n > 0 && sess.req.readable().get(..n) == Some(&sess.send_proxy_header[..]),
        &mut xprt,
    ) {
        t.set_plain_prefix(sess.req.readable()[..n].to_vec());
        sess.req.consume(n);
        sess.txn.iter_mut().for_each(|t| {
            if let MsgState::Head { left, body } = t.req {
                t.req = MsgState::Head { left: left.saturating_sub(n), body };
            }
        });
    }
    if h2 {
        attach_h2(sess, srv_fd, xprt, now);
        return;
    }
    sess.attach_server_with_xprt(srv_fd, xprt, now);
}

/// What the HTTP/1.1 text of an h2 server's response head `head` holds that `HAProxy`'s HTX of
/// it does not, for `%B`: the reason phrase (h2 has none: measured 49 bytes logged where an
/// h1 server's same response logs 51) and, for the `transfer-encoding: chunked` the codec
/// adds to a response without a length, 25 bytes (measured: nghttpd `--no-content-length`,
/// 19, 1000 and 40000-byte bodies, `HAProxy` logs 25 bytes fewer than Ibex counts with the
/// field in). An h2 server cannot send that field (the codec refuses it), so one in the text
/// is the codec's.
fn h2_htx_overcount(head: &[u8]) -> u64 {
    let first = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let reason = first.splitn(3, |&b| b == b' ').nth(2).map_or(0, |r| r.strip_suffix(b"\r").unwrap_or(r).len());
    let te = if head.windows(28).any(|w| w == b"\ntransfer-encoding: chunked\r") { 25 } else { 0 };
    reason as u64 + te
}

/// Attaches a `proto h2` connection: `xprt` under the h2 layer. Without memory for its codec
/// the connection fails as a connect failure does.
fn attach_h2(sess: &mut TcpSession, srv_fd: OwnedFd, xprt: crate::xprt::ServerXprt, now: Tick) {
    match xprt.into_h2() {
        Ok(x) => sess.attach_server_with_xprt(srv_fd, x, now),
        Err(_) => {
            sess.attach_server(srv_fd, now);
            sess.srv_state = ScState::Error;
        }
    }
}

/// The SNI a request on `sess` would send to `proxies[be_idx].servers.at(s_idx)`, for the
/// idle pool's key and for deciding whether the connection in hand can carry it.
fn server_sni(sess: &TcpSession, proxies: &[Proxy], fe_idx: usize, be_idx: usize, s_idx: Option<usize>) -> Option<String> {
    with_server_sni(sess, proxies, fe_idx, be_idx, s_idx, |sni| sni.map(str::to_string))
}

/// `f` of [`server_sni`], the name lent rather than copied: what the check of the kept
/// connection, made for every request, uses (T440: 3 allocations per request otherwise).
fn with_server_sni<R>(
    sess: &TcpSession,
    proxies: &[Proxy],
    fe_idx: usize,
    be_idx: usize,
    s_idx: Option<usize>,
    f: impl FnOnce(Option<&str>) -> R,
) -> R {
    let Some(tls) = s_idx.and_then(|i| proxies.get(be_idx).and_then(|p| p.server_tls.get(i)).and_then(Option::as_ref)) else {
        return f(None);
    };
    let stick = StickView::new(proxies, &sess.tracked_sc);
    tls.with_sni(sample_registry(), &stream_sample_ctx(sess, &proxies[fe_idx], &proxies[be_idx], &ProxiesView(proxies), &stick), f)
}

/// The pool key of a connection to `addr` for server `s_idx` of backend `be_idx`, opened
/// with `sni` (a plaintext connection has none); none without a server.
fn idle_key(addr: SocketAddr, be_idx: usize, s_idx: Option<usize>, sni: Option<String>) -> Option<IdleKey> {
    Some(IdleKey { srv: (be_idx, s_idx?), addr, name: sni })
}

/// Builds the TLS of every server of `proxy` from its section (`servers`). Done once per
/// proxy at load, as `ssl_sock_prepare_srv_ctx` is, so a missing `ca-file` or `crt` is
/// a load error and `ibex -c` reports it.
fn attach_server_tls(proxy: &mut Proxy, servers: &[ibex_config::Server], mode_http: bool, section: &str) -> io::Result<()> {
    proxy.server_tls.clear();
    proxy.server_check_tls.clear();
    // A backend with no TLS server anywhere keeps both maps empty; indexing is by
    // `.get(i)`, which reads an empty map as "all plaintext". So 60,000 plaintext
    // servers cost nothing here -- the memory-bound tests stay where they were.
    if !servers.iter().any(|s| s.ssl.as_deref().is_some_and(|x| x.ssl || x.check_uses_tls(s.check_port))) {
        return Ok(());
    }
    proxy.server_tls.resize_with(servers.len(), || None);
    proxy.server_check_tls.resize_with(servers.len(), || None);
    for (i, s) in servers.iter().enumerate() {
        if !s.ssl.as_deref().is_some_and(|x| x.ssl || x.check_uses_tls(s.check_port)) {
            continue;
        }
        let who = format!("'server {}/{}'", section, s.id);
        proxy.server_tls[i] = crate::srv_tls::ServerTls::from_server(s, mode_http, &who)?.map(Arc::new);
        proxy.server_check_tls[i] = crate::srv_tls::CheckTls::from_server(s, &who)?.map(Arc::new);
    }
    Ok(())
}

#[inline]
fn millis_to_u32(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

#[inline]
pub(crate) fn usize_to_u32(idx: usize) -> u32 {
    u32::try_from(idx).unwrap_or(u32::MAX)
}

#[inline]
fn raw_fd_to_u64(fd: RawFd) -> u64 {
    u64::try_from(fd).unwrap_or(0)
}

/// A count of events over the last second, as `HAProxy`'s frequency counters
/// (`read_freq_ctr`) give it: the window starts at the first event after a quiet spell, and
/// the part of the previous window that has not yet slid out still counts.
///
/// Sixteen bytes, because a configuration of sixty thousand backends keeps one per proxy and
/// per server. One thread counts into it (each worker has its own set); the others only read.
#[derive(Default, Debug)]
pub struct RateCtr {
    /// The start of the current window in milliseconds since [`RateCtr::now`]'s epoch (0:
    /// nothing counted yet), over the events counted in it.
    head: AtomicU64,
    /// The events of the window before.
    prev: AtomicU32,
}

#[allow(clippy::cast_possible_truncation)]
impl RateCtr {
    const PERIOD_MS: u32 = 1000;

    /// A zeroed counter, for a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self { head: AtomicU64::new(0), prev: AtomicU32::new(0) }
    }

    /// Milliseconds since the first call; never 0, which marks a counter nothing was counted in.
    fn now() -> u32 {
        // Wraps after 49 days, as `HAProxy`'s ticks do; every comparison is a wrapping difference.
        Self::at(crate::statcnt::now_ms())
    }

    /// The tick for a [`crate::statcnt::now_ms`] reading, so one clock read serves a whole stream's accounting.
    pub fn at(now_ms: u64) -> u32 {
        (now_ms as u32).max(1)
    }

    pub fn tick(&self) {
        self.tick_at(Self::now());
    }

    pub fn tick_at(&self, now: u32) {
        let head = self.head.load(Ordering::Relaxed);
        let (start, mut cur) = ((head >> 32) as u32, head as u32);
        let mut prev = self.prev.load(Ordering::Relaxed);
        let mut start_new = start;
        let elapsed = now.wrapping_sub(start);
        if start == 0 || elapsed >= 2 * Self::PERIOD_MS {
            (prev, cur, start_new) = (0, 0, now);
        } else if elapsed >= Self::PERIOD_MS {
            (prev, cur, start_new) = (cur, 0, now);
        }
        self.prev.store(prev, Ordering::Relaxed);
        self.head.store((u64::from(start_new) << 32) | u64::from(cur.saturating_add(1)), Ordering::Relaxed);
    }

    /// Takes back one event just counted, for a session that turned out not to be one
    /// (a client whose TLS handshake failed: `HAProxy` creates the session after it).
    pub fn untick(&self) {
        let head = self.head.load(Ordering::Relaxed);
        if head as u32 > 0 {
            self.head.store(head - 1, Ordering::Relaxed);
        } else {
            let _ = self.prev.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |p| p.checked_sub(1));
        }
    }

    /// The events over the last second.
    #[must_use]
    pub fn rate(&self) -> u64 {
        self.rate_at(Self::now())
    }

    pub fn rate_at(&self, now: u32) -> u64 {
        let head = self.head.load(Ordering::Relaxed);
        let (start, cur) = ((head >> 32) as u32, u64::from(head as u32));
        if start == 0 {
            return 0;
        }
        let elapsed = u64::from(now.wrapping_sub(start));
        let period = u64::from(Self::PERIOD_MS);
        if elapsed >= 2 * period {
            0
        } else if elapsed >= period {
            cur * (2 * period - elapsed) / period
        } else {
            cur + u64::from(self.prev.load(Ordering::Relaxed)) * (period - elapsed) / period
        }
    }
}

/// One engine thread's share of the process-wide `show info` rates. Only its owner thread
/// writes it; `show info` sums the registered shares on read (AGENTS.md §8: no shared write
/// per accepted connection). The peak is that thread's own, so `MaxConnRate` is the sum of the
/// threads' peaks: exact with one thread, an upper bound when the peaks are not simultaneous.
struct ThreadRates {
    conn: RateCtr,
    sess: RateCtr,
    max_conn: AtomicU32,
    max_sess: AtomicU32,
    /// The `CLEAR_EPOCH` the maxima belong to; a share from before the last `clear counters` reads as 0.
    epoch: AtomicU32,
}

static THREAD_RATES: std::sync::Mutex<Vec<&'static ThreadRates>> = std::sync::Mutex::new(Vec::new());
/// Bumped by `clear counters`; each thread zeroes its own maxima when it next counts.
static CLEAR_EPOCH: AtomicU32 = AtomicU32::new(0);

thread_local! {
    static LOCAL_RATES: &'static ThreadRates = {
        let r: &'static ThreadRates = Box::leak(Box::new(ThreadRates {
            conn: RateCtr::new(),
            sess: RateCtr::new(),
            max_conn: AtomicU32::new(0),
            max_sess: AtomicU32::new(0),
            epoch: AtomicU32::new(CLEAR_EPOCH.load(Ordering::Relaxed)),
        }));
        THREAD_RATES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(r);
        r
    };
}

fn tick_local(pick: impl Fn(&ThreadRates) -> (&RateCtr, &AtomicU32)) {
    LOCAL_RATES.with(|r| {
        let epoch = CLEAR_EPOCH.load(Ordering::Relaxed);
        if r.epoch.load(Ordering::Relaxed) != epoch {
            r.max_conn.store(0, Ordering::Relaxed);
            r.max_sess.store(0, Ordering::Relaxed);
            r.epoch.store(epoch, Ordering::Relaxed);
        }
        let (ctr, max) = pick(r);
        ctr.tick();
        let rate = u32::try_from(ctr.rate()).unwrap_or(u32::MAX);
        if rate > max.load(Ordering::Relaxed) {
            max.store(rate, Ordering::Relaxed);
        }
    });
}

fn sum_rates(f: impl Fn(&ThreadRates) -> u64) -> u64 {
    THREAD_RATES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().map(|r| f(r)).sum()
}

fn sum_max(f: impl Fn(&ThreadRates) -> &AtomicU32) -> u64 {
    let epoch = CLEAR_EPOCH.load(Ordering::Relaxed);
    sum_rates(|r| if r.epoch.load(Ordering::Relaxed) == epoch { u64::from(f(r).load(Ordering::Relaxed)) } else { 0 })
}

/// `ConnRate`: connections accepted over the last second, all threads.
#[must_use]
pub fn global_conn_rate() -> u64 {
    sum_rates(|r| r.conn.rate())
}

/// `SessRate`: sessions created over the last second, all threads.
#[must_use]
pub fn global_sess_rate() -> u64 {
    sum_rates(|r| r.sess.rate())
}

/// `MaxConnRate` since start or the last `clear counters`.
#[must_use]
pub fn max_conn_rate() -> u64 {
    sum_max(|r| &r.max_conn)
}

/// `MaxSessRate` since start or the last `clear counters`.
#[must_use]
pub fn max_sess_rate() -> u64 {
    sum_max(|r| &r.max_sess)
}

/// `clear counters`: forget the maxima (each thread zeroes its own share when it next counts).
pub fn clear_rate_maxima() {
    CLEAR_EPOCH.fetch_add(1, Ordering::Relaxed);
}

/// One accepted client connection, counted before `tcp-request connection` rules run
/// (`listener_accept`: rejected and silently dropped connections are in `ConnRate`).
/// Not for the CLI, which `HAProxy` binds unlimited (`BC_O_UNLIMITED`).
pub(crate) fn count_global_conn() {
    tick_local(|r| (&r.conn, &r.max_conn));
}

/// One session, counted once the connection survived the `tcp-request connection` rules.
pub(crate) fn count_global_sess() {
    tick_local(|r| (&r.sess, &r.max_sess));
}

/// Accumulated statistics per proxy.
#[derive(Default, Debug)]
pub struct ProxyStats {
    /// Sessions accepted by the frontend per second (`fe_sess_rate`).
    pub fe_sess_rate: RateCtr,
    /// Connections accepted by the frontend per second (`conn_rate`): the sessions, and the
    /// connections whose TLS handshake failed before there was one.
    pub fe_conn_rate: RateCtr,
    /// HTTP requests received by the frontend per second (`fe_req_rate`).
    pub fe_req_rate: RateCtr,
    /// Streams switched to the backend per second (`be_sess_rate`).
    pub be_sess_rate: RateCtr,
    pub cum_conn: AtomicU64,
    /// Client TLS handshakes that failed (`ssl_failed_handshake`).
    pub ssl_failed_hs: AtomicU64,
    pub act_conn: AtomicU32,
    /// Streams the backend has been given and not finished with (`beconn`, `%bc`).
    pub be_streams: AtomicU32,
    pub max_conn: AtomicU32,
    /// Requests waiting for a server slot (`qcur`) and the most there were (`qmax`).
    pub queue_cur: AtomicU32,
    pub queue_max: AtomicU32,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub retries_count: AtomicU64,
    pub redispatches: AtomicU64,
    pub failed_conn: AtomicU64,
    pub srv_err: AtomicU64,
    pub cli_err: AtomicU64,
    pub denied_conn: AtomicU64,
    pub denied_req: AtomicU64,
    pub denied_resp: AtomicU64,
}

impl Proxy {
    /// The proxy's transaction counters, made when first needed.
    pub fn txn_counters(&self) -> &crate::statcnt::ProxyCounters {
        self.ids.tc.get_or_init(|| Arc::new(crate::statcnt::ProxyCounters::new(self.servers.len())))
    }
}

impl ProxyStats {
    /// `clear counters` without `all`: the maxima fall back to what is current now.
    pub fn clear_max(&self) {
        let act = self.act_conn.load(Ordering::Relaxed);
        self.max_conn.store(act, Ordering::Relaxed);
        self.queue_max.store(self.queue_cur.load(Ordering::Relaxed), Ordering::Relaxed);
        // The failed-handshake count goes with the maxima, `conn_tot` does not (measured).
        self.ssl_failed_hs.store(0, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.cum_conn.store(0, Ordering::Relaxed);
        self.ssl_failed_hs.store(0, Ordering::Relaxed);
        let act = self.act_conn.load(Ordering::Relaxed);
        self.max_conn.store(act, Ordering::Relaxed);
        self.queue_max.store(self.queue_cur.load(Ordering::Relaxed), Ordering::Relaxed);
        self.bytes_in.store(0, Ordering::Relaxed);
        self.bytes_out.store(0, Ordering::Relaxed);
        self.retries_count.store(0, Ordering::Relaxed);
        self.redispatches.store(0, Ordering::Relaxed);
        self.failed_conn.store(0, Ordering::Relaxed);
        self.srv_err.store(0, Ordering::Relaxed);
        self.cli_err.store(0, Ordering::Relaxed);
        self.denied_conn.store(0, Ordering::Relaxed);
        self.denied_req.store(0, Ordering::Relaxed);
        self.denied_resp.store(0, Ordering::Relaxed);
    }
}




/// Links each proxy to the one written after it ([`ProxyIdInfo::next_decl`]). The list is
/// built listens, backends, frontends; `show stat` lists them as they were written.
pub(crate) fn link_declaration_order(proxies: &mut [Proxy]) {
    let mut order: Vec<usize> = (0..proxies.len()).collect();
    order.sort_by_key(|&i| proxies[i].ids.decl);
    for w in order.windows(2) {
        proxies[w[0]].ids.next_decl = usize_to_u32(w[1] + 1);
    }
    if let Some(&last) = order.last() {
        proxies[last].ids.next_decl = 0;
    }
}

/// What [`Proxy::ids`] holds.
#[derive(Debug, Clone, Default)]
pub struct ProxyIdInfo {
    /// The proxy's `timeout client`, `server`, `connect`, `queue`, `tunnel`, `tarpit` in ms
    /// (0 unset), as the `*_timeout` fetches report them: converted once, not a stream run
    /// (L3, [`stream_timeouts`]). Here, in the box, because `Proxy` is held to its size.
    pub timeout_ms: [u32; 6],
    /// The transaction counters `show stat` prints (T165), made on first use. Here, in the
    /// box, because `Proxy` is held to its size.
    pub tc: std::sync::OnceLock<Arc<crate::statcnt::ProxyCounters>>,
    /// The proxy's numeric id (`uuid`): `iid` in `show stat`, `be_id` in `show servers
    /// state`, what `fe_id` and `be_id` read. Numbered in the order the sections were
    /// written, from 2, around the ones that asked for an `id` (`Config::proxy_ids`).
    pub iid: u32,
    /// Where the section was written among the proxies: `show stat` lists them in that order.
    pub decl: u32,
    /// The proxy written after this one, as its index plus one; 0 for the last: `show stat`
    /// walks the proxies in declaration order a row at a time without sorting them (T572).
    /// Set once the list is built ([`link_declaration_order`]).
    pub next_decl: u32,
    /// The section has an `id` of its own (`bk_f_forced_id`).
    pub forced_id: bool,
    /// Each server's numeric id in this proxy (`puid`), what `srv_id`, the `sid` column of
    /// `show stat` and `show servers state` report, and where the server's points on a
    /// consistent-hash ring come from. Empty when no server has an `id` of its own: they are
    /// then 1, 2, 3...; read it with [`Proxy::server_puid`].
    pub server_puids: Vec<u32>,
    /// Whether each server has an `id` of its own (`srv_f_forced_id`); empty when none does
    /// (see [`Proxy::server_forced_id`]).
    pub server_forced_ids: Vec<bool>,
    /// What `show servers state` reports as each server's `srv_check_health` while no check
    /// runs on it; empty when that is 0 for all (see [`Proxy::server_init_health`]).
    pub server_init_health: Vec<u32>,
    /// Which servers the configuration disabled (`SRV_ADMF_CMAINT`, 4 in `show servers state`
    /// whatever the CLI does afterwards); empty when none (see [`Proxy::server_cmaint`]).
    pub server_cmaint: Vec<bool>,
    /// Which servers have no address (`init-addr none` after a name did not resolve, or a
    /// resolver took it: `SRV_ADMF_RMAINT`, 32 in `show servers state`, `MAINT
    /// (resolution)`), and the operator's admin state kept under it (`SRV_ADMF_FMAINT`,
    /// `SRV_ADMF_FDRAIN`): 0 none, else 1 + that [`ServerStatus`]; empty when no server's
    /// address is a name (see [`Proxy::server_rmaint`], [`Proxy::server_rmaint_kept`]).
    pub server_rmaint: Arc<Vec<std::sync::atomic::AtomicU8>>,
    /// The name each server's address was written as (`srv_fqdn`); empty when no server's
    /// was (see [`Proxy::server_fqdn`]).
    pub server_fqdns: Vec<Option<Box<str>>>,
    /// Which servers' `srv_fqdn` the server-state file had changed from the CLI
    /// (`SRV_ADMF_FQDN_CHANGED`, 64 in `srv_admin_state`; T490); empty when none.
    pub server_fqdn_changed: Vec<bool>,
    /// The slots of the servers whose name is an SRV record (`srvrecord`, T487): the target
    /// each took and `SRV_ADMF_FQDN_CHANGED`; `None` when no server's name is one.
    pub server_srv: Option<Arc<crate::resolvers::SrvSlots>>,
    /// Each server's `port` (`check port`, `default-server port`): `srv_agent_port`, and
    /// `srv_check_port` of a server with no check; empty when no server has one.
    pub server_check_ports: Vec<u16>,
    /// Each server's `econ`: the requests whose connection attempts all failed, the last
    /// attempt having been to that server (see [`count_connect_failure`]).
    /// Each listener's numeric id (`luid`) by `bind` line, as `so_id` reads it.
    pub listener_ids: Vec<u32>,
    /// `pool-max-conn`, `pool-low-conn` and `pool-purge-delay` per server; empty when every
    /// server has the defaults (read it with [`ProxyIdInfo::server_pool`]). Read when a
    /// server connection is released, so it lives here, off `Proxy`'s inline size
    /// (`struct_sizes.rs`).
    pub server_pool: Vec<SrvPoolCfg>,
    /// `option http-server-close`: the server connection carries one request. Read when a
    /// request goes to a server and when its response ends.
    pub http_mode: ibex_config::ast::HttpMode,
    /// `option persist`: a server named by a cookie or a stick table is used when it is down.
    pub persist: bool,
    /// `option checkcache`: a cacheable response that sets a cookie is answered 502
    /// (`http_process_res_common`).
    pub checkcache: bool,
    /// `retry-on`, as the `ibex_config::RE_*` bits: what a failed attempt is retried on.
    pub retry_on: u32,
    /// What the server-state file gave each server (T490, [`crate::server_state`]): read
    /// by `init_checks` and by the `lastchg` columns; empty when no file was applied.
    pub server_restored: Vec<Option<crate::server_state::Restored>>,
}

impl ProxyIdInfo {
    /// What the server-state file gave server `i`, if anything.
    #[must_use]
    pub fn restored(&self, i: usize) -> Option<&crate::server_state::Restored> {
        self.server_restored.get(i).and_then(Option::as_ref)
    }

    /// Seconds since server `i` last changed state (`lastchg`, `srv_time_since_last_change`):
    /// from its last change, or else from the start plus the age the server-state file gave.
    #[must_use]
    pub fn server_lastchg(&self, i: usize, last_chg: u64) -> u64 {
        crate::statcnt::TxnCounters::since_secs(last_chg)
            .unwrap_or_else(|| crate::statcnt::now_ms() / 1000 + self.restored(i).map_or(0, |r| r.age_s))
    }

    /// The idle connection settings of server `i`.
    #[must_use]
    pub fn server_pool(&self, i: usize) -> SrvPoolCfg {
        self.server_pool.get(i).copied().unwrap_or(SrvPoolCfg::DEFAULT)
    }
}

/// The proxies, built once by [`Engine::build_shared_state`] and shared by every worker,
/// as `HAProxy`'s threads share one `struct proxy` (T160). Each worker used to hold a clone
/// of every `Proxy`, about 14 KB per backend per worker.
///
/// What the workers change at run time is behind the `Arc`s and atomics inside each
/// `Proxy`; nothing takes it mutably. The CLI and the stats page write the same way
/// (weights, addresses, `maxconn`: `crate::srv_rt`), so every worker sees the change on
/// its next connection (T177). There is deliberately no `make_mut`: it used to give the
/// worker that served a CLI command its own copy, and the other workers never saw it.
#[derive(Debug, Clone, Default)]
pub struct Proxies(Arc<Vec<Proxy>>);

impl Proxies {
    #[must_use]
    pub fn new(proxies: Vec<Proxy>) -> Self {
        Self(Arc::new(proxies))
    }
}

impl std::ops::Deref for Proxies {
    type Target = [Proxy];
    fn deref(&self) -> &[Proxy] {
        &self.0
    }
}

/// A proxy's `monitor-uri` and the `monitor fail` conditions that turn its answer into a 503.
#[derive(Debug, Clone)]
pub struct Monitor {
    pub uri: Box<str>,
    pub fail: Vec<ibex_config::AclCondition>,
}

impl Monitor {
    /// `None` without a `monitor-uri`: `monitor fail` acts on that request only.
    fn boxed(uri: Option<&str>, fail: &[ibex_config::AclCondition]) -> Option<Box<Self>> {
        uri.map(|uri| Box::new(Self { uri: uri.into(), fail: fail.to_vec() }))
    }
}

/// A configured proxy instance.
#[derive(Debug, Clone)]
// More than three bools, and they are genuinely independent switches rather than a state
// machine: PROXY protocol on accept, v2 on accept, and the two logging options. Grouping
// them into an enum would model a relationship that does not exist.
#[allow(clippy::struct_excessive_bools)]
pub struct Proxy {
    /// The proxy's index in the engine's list, which the engine addresses it by. Not the
    /// number `HAProxy` shows for it: that is [`Proxy::iid`].
    pub id: u32,
    /// The ids of the proxy, its servers and its listeners: cold (the CLI, `show stat` and the
    /// id fetches read them), so boxed, as every proxy pays for the struct.
    pub ids: Box<ProxyIdInfo>,
    pub name: String,
    /// A `frontend` or a `listen`: what `fe_exists` looks for.
    pub has_frontend: bool,
    /// A `backend` or a `listen`: what the server-state fetches' backend arguments name.
    pub has_backend: bool,
    pub addr: SocketAddr,
    pub mode: Mode,
    pub balance: BalanceAlgorithm,
    /// A `balance` line was given; `show stat`'s `algo` is `unknown` without one.
    pub balance_set: bool,
    pub timeouts: Timeouts,
    pub retries: u16,
    pub redisp: bool,
    /// `option redispatch <interval>` (`redispatch_after`), see [`crate::lb::redispatch_due`].
    pub redisp_after: i32,
    /// `maxconn`: shared by every worker and by the proxy's listeners, which stop
    /// accepting at it, so `set maxconn frontend` reaches all of them (T177).
    pub maxconn: crate::srv_rt::ConnLimit,
    pub dispatch: Option<SocketAddr>,
    /// The `cookie` line (`ck_opts`, `cookie_*`): persistence by a cookie. Only a backend
    /// (or a `listen`) has one.
    pub cookie: Option<ibex_config::CookieConfig>,
    pub cliexp: Vec<ibex_proto::CompiledExp>,
    pub srvexp: Vec<ibex_proto::CompiledExp>,
    /// Each server's address, shared by every worker: `set server ... addr` changes it
    /// in place (T177).
    pub servers: crate::srv_rt::ServerAddrs,
    pub server_ids: Vec<String>,
    /// Each server's persistence cookie value (`server ... cookie <value>`). A server
    /// without one is never chosen by a cookie, not even by its name.
    pub server_cookies: Vec<Option<Box<str>>>,
    pub server_statuses: Arc<Vec<AtomicU8>>,
    /// `track` of each server (`None` for one that tracks nothing; empty when none does).
    pub server_track: Option<Arc<Vec<Option<crate::track::Track>>>>,
    /// Each server's current weight and its configured one (`iweight`: what `set server
    /// ... weight <n>%` is a share of, and the `initial` of `get weight`), shared by every
    /// worker: `set weight` changes it in place (T177).
    pub server_weights: crate::srv_rt::ServerWeights,
    pub next_server_idx: Arc<AtomicUsize>,
    /// The proxy's counters: one set, which every worker counts into, as `HAProxy`'s
    /// threads count into their thread group's (`fe_counters_shared.tg[]`; one group by
    /// default). Read with [`Proxy::counters`]. One set per worker cost 152 bytes per
    /// proxy per thread, 23 MB for 10,000 backends at `nbthread 16` (T160). A `Vec`, and
    /// summed by its readers, so thread groups can slot in.
    pub stats: Arc<Vec<ProxyStats>>,
    pub stats_config: ibex_config::StatsConfig,
    /// The section's `description`, shown on the stats page.
    pub desc: Option<Box<str>>,
    pub default_backend: Option<String>,
    pub use_backends: Vec<UseBackendRule>,
    /// `use-server` rules (backends and listens), in order.
    pub use_servers: Vec<ibex_config::UseServerRule>,
    /// `force-be-switch` conditions (frontends and listens).
    pub force_be_switch: Vec<ibex_config::AclCondition>,
    /// The names of the backends and listens the configuration disables: they are not
    /// instantiated, and only `force-be-switch` lets a rule choose one (then it has no
    /// server to give).
    pub disabled_backends: Arc<Vec<String>>,
    /// `monitor-uri` and its `monitor fail` conditions (frontends and listens); boxed, as
    /// `Proxy` is paid for per backend.
    pub monitor: Option<Box<Monitor>>,
    pub acls: ibex_sample::Acls,
    pub stick_table: Option<Arc<StickTable>>,
    pub stick_rules: Vec<StickRule>,
    pub server_send_proxy: Vec<bool>,
    /// `tfo` per server, in `servers` order.
    pub server_tfo: Vec<bool>,
    pub server_send_proxy_v2: Vec<bool>,
    /// `proxy-v2-options unique-id`, per server.
    pub server_pp_unique_id: Vec<bool>,
    pub server_backups: Vec<bool>,
    /// Each server's `maxconn`, shared by every worker: `set maxconn server` changes it in
    /// place (T177).
    pub server_maxconn: crate::srv_rt::ServerMaxconns,
    pub server_actconn: Arc<Vec<AtomicU32>>,
    /// Per server `(wretr, wredis, econ)`: retries on it, redispatches away from it, and
    /// streams whose last connect attempt, out of retries, failed on it.
    pub server_retr: Arc<std::sync::Mutex<std::collections::HashMap<usize, (u64, u64, u64)>>>,
    /// Streams assigned to each server per second (`srv_sess_rate`).
    pub server_sess_rates: Arc<Vec<RateCtr>>,
    /// Each server's check parameters, `None` for a server without `check`. The servers
    /// whose parameters are the same share one (T304: 60,000 servers of a backend hold one).
    pub server_check_configs: Vec<Option<Arc<ServerCheckConfig>>>,
    /// Each server's TLS (`server ... ssl`), `None` for a plaintext one (T113).
    pub server_tls: Vec<Option<Arc<crate::srv_tls::ServerTls>>>,
    /// Each server's health-check TLS (`check-ssl`, or `ssl` inherited), `None` for
    /// plaintext checks.
    pub server_check_tls: Vec<Option<Arc<crate::srv_tls::CheckTls>>>,
    pub tcp_req_conn_rules: Vec<ibex_config::TcpReqConnRule>,
    pub tcp_req_session_rules: Vec<ibex_config::TcpReqSessionRule>,
    pub tcp_req_content_rules: Vec<ibex_config::TcpReqContentRule>,
    pub tcp_req_inspect_delay: Option<Duration>,
    pub tcp_res_content_rules: Vec<ibex_config::TcpResContentRule>,
    pub tcp_res_inspect_delay: Option<Duration>,
    pub http_req_rules: Vec<ibex_config::HttpReqRule>,
    pub http_res_rules: Vec<ibex_config::HttpResRule>,
    pub http_after_res_rules: Vec<ibex_config::HttpAfterResRule>,
    /// The three HTTP rule lists' conditions, expressions (`capture`, `set-var`) and formats,
    /// compiled when the proxy is built.
    pub rules: Box<crate::rule_compiled::Rules>,
    /// Indices into [`Engine::log_targets`]. Held as indices rather than targets because
    /// `Proxy` is `Clone` and a `SyslogTarget` owns a socket; the sockets live once, on
    /// the engine, and every proxy points at the ones its section resolved to.
    pub log_target_idx: Vec<usize>,
    /// `option log-health-checks`: log every check whose health counter moved, not only
    /// the UP/DOWN transitions.
    pub log_health_checks: bool,
    /// HTTP connection reuse strategy (`http-reuse`).
    pub http_reuse: ibex_config::HttpReuse,
    /// Whether a client that leaves aborts its request at the server, in the queue or while
    /// connecting (`option abortonclose`, on for HTTP unless `no option abortonclose`). A
    /// backend's: the stream's backend decides, as `proxy_abrt_close(s->be)`.
    pub abortonclose: bool,
    /// `option h1-case-adjust-bogus-client` / `-server` ([`ibex_config::H1_ADJ_CLIENT`], `_SERVER`).
    pub h1_adjust: u8,
    /// The global `h1-case-adjust` table: lower-case name to the name to write. Set on every
    /// proxy that has a bit in `h1_adjust`; empty otherwise.
    pub h1_case: Arc<std::collections::HashMap<String, String>>,
    /// `tune.ibex.h1-lowercase-headers on` (global, X5, D-E): the header names of a head this
    /// proxy forwards go in lower case, as `HAProxy` writes them; off, in the case they came in.
    pub h1_lower: bool,
    /// Custom error pages (`errorfile`/`errorfiles`), keyed by status code.
    pub error_files: HashMap<u16, Vec<u8>>,
    /// `http-error` overrides, keyed by status code; consulted before `error_files`.
    pub error_replies: HashMap<u16, ibex_config::ErrorPageSource>,
    /// `log-tag`, as sent: the tag followed by `[pid]`, which `HAProxy` adds whichever
    /// tag a line carries (`__send_log`, `src/log.c`). `None` sends the global tag.
    pub log_tag: Option<Arc<str>>,
    /// The per-transaction log line's format (`log-format`, `option httplog`/`tcplog`);
    /// frontends and listens only, as in `HAProxy`.
    pub log_format: Option<Arc<crate::logfmt::LogFormat>>,
    /// `error-log-format` and `log-format-sd`, which few frontends have: boxed together, as
    /// `Proxy` is paid for per backend (T303).
    pub extra_log: Option<Box<ExtraLogFormats>>,
    /// `option dontlognull`: a connection that carried nothing logs nothing.
    pub dont_log_null: bool,
    /// `option http-ignore-probes`: a connection that sends nothing before it closes or
    /// times out is sent nothing and neither logged nor counted (T272).
    pub ignore_probes: bool,
    /// `option dontlog-normal`, `option log-separate-errors`, `option logasap`: the
    /// `ibex_config::LOG_OPT_*` bits.
    pub log_opts: u8,
    /// `unique-id-format`, compiled.
    pub unique_id_format: Option<Arc<crate::logfmt::LogFormat>>,
    /// `unique-id-header`: the request header the unique ID is sent to the server in (a
    /// `Box<str>`: `Proxy` is paid for per backend, T296).
    pub unique_id_header: Option<Box<str>>,
    /// Request capture slots as (header name, length): a `capture request header`'s name is
    /// the header, an empty name is a slot only a rule fills (`declare capture request`, or
    /// an `http-request capture` rule's own, which has the rule's `len`).
    pub req_capture_slots: Arc<[(String, usize)]>,
    /// `capture response header`, by slot.
    pub res_capture_slots: Arc<[(String, usize)]>,
    /// `%lc`: the lines this proxy has logged, shared by the workers.
    pub log_count: Arc<AtomicU64>,
    /// One sampling cursor per entry of `log_target_idx` (`syslog::sample_admits`).
    /// Per proxy because `HAProxy` copies each logger into every proxy that uses it, and
    /// behind an `Arc` so the workers, which each clone the proxies, share them as
    /// `HAProxy`'s threads share a logger.
    pub log_cursors: Arc<Vec<AtomicU64>>,
    /// Hashing method for hash-based balancing algorithms (`hash-type`).
    pub hash_type: ibex_config::HashType,
    /// Affinity-preservation mode for hash-based algorithms (`hash-preserve-affinity`).
    pub hash_preserve_affinity: ibex_config::HashPreserveAffinity,
    /// The `hash-type consistent` ring, built on first use and shared by the workers.
    pub chash: Arc<crate::lb::ChashRing>,
    /// `balance roundrobin`'s weighted order, shared by the workers.
    pub fwrr: Arc<crate::lb::Fwrr>,
}

impl Proxy {
    /// Whether server `tfo` applies to the server at `addr`.
    fn server_tfo_of(&self, addr: SocketAddr) -> bool {
        self.servers.iter().position(|s| s == addr).and_then(|i| self.server_tfo.get(i).copied()).unwrap_or(false)
    }

    /// The counters this worker counts into (see [`Proxy::stats`]).
    #[inline]
    #[must_use]
    pub fn counters(&self) -> &ProxyStats {
        &self.stats[0]
    }

    /// `srv_check_health` of the server at `idx` while no check runs on it.
    #[must_use]
    pub fn server_init_health(&self, idx: usize) -> u32 {
        self.ids.server_init_health.get(idx).copied().unwrap_or(0)
    }

    /// The numeric id of the server at `idx` (`puid`).
    #[must_use]
    pub fn server_puid(&self, idx: usize) -> u32 {
        self.ids.server_puids.get(idx).copied().unwrap_or_else(|| u32::try_from(idx + 1).unwrap_or(u32::MAX))
    }

    /// Whether the configuration disabled the server at `idx` (`SRV_ADMF_CMAINT`).
    #[must_use]
    pub fn server_cmaint(&self, idx: usize) -> bool {
        self.ids.server_cmaint.get(idx).copied().unwrap_or(false)
    }

    /// Whether the server at `idx` has no address (`SRV_ADMF_RMAINT`): it stays in
    /// maintenance whatever the CLI asks, until its resolver gives it one (`crate::resolvers`).
    #[must_use]
    pub fn server_rmaint(&self, idx: usize) -> bool {
        self.ids.server_rmaint.get(idx).is_some_and(|f| f.load(Ordering::Relaxed) != 0)
    }

    /// The admin state the operator (or `disabled`) gave the server at `idx` while it is in
    /// `SRV_ADMF_RMAINT`: `Maint`, `Drain` or `Up`, the one it takes back when its name
    /// resolves again. `Up` when it is not in `RMAINT`.
    #[must_use]
    pub fn server_rmaint_kept(&self, idx: usize) -> ServerStatus {
        match self.ids.server_rmaint.get(idx).map_or(0, |f| f.load(Ordering::Relaxed)) {
            0 => ServerStatus::Up,
            v => ServerStatus::from(v - 1),
        }
    }

    /// Puts the server at `idx` in `SRV_ADMF_RMAINT`, keeping the admin state `kept`, or takes
    /// it out with `None` (a server whose address is a name: the others have no flag).
    pub fn set_server_rmaint(&self, idx: usize, kept: Option<ServerStatus>) {
        if let Some(f) = self.ids.server_rmaint.get(idx) {
            f.store(kept.map_or(0, |k| k as u8 + 1), Ordering::Relaxed);
        }
    }

    /// The name the address of the server at `idx` was written as, if it was one.
    #[must_use]
    pub fn server_fqdn(&self, idx: usize) -> Option<&str> {
        self.ids.server_fqdns.get(idx).and_then(Option::as_deref)
    }

    /// Whether the server-state file kept `SRV_ADMF_FQDN_CHANGED` for the server at `idx`.
    #[must_use]
    pub fn server_fqdn_changed(&self, idx: usize) -> bool {
        self.ids.server_fqdn_changed.get(idx).copied().unwrap_or(false)
            || self.ids.server_srv.as_ref().is_some_and(|v| v.changed.get(idx).is_some_and(|c| c.load(Ordering::Relaxed)))
    }

    /// The SRV record the server at `idx` is a slot of (`srvrecord`), if any.
    #[must_use]
    pub fn server_srv_record(&self, idx: usize) -> Option<&str> {
        self.ids.server_srv.as_ref().and_then(|v| v.record.get(idx)).and_then(Option::as_deref)
    }

    /// The target the SRV slot at `idx` took (`srv->hostname`), if it took one.
    #[must_use]
    pub fn server_srv_fqdn(&self, idx: usize) -> Option<Box<str>> {
        self.ids.server_srv.as_ref().and_then(|v| v.fqdn(idx))
    }

    /// Sets (or clears) the target of the SRV slot at `idx`; setting one raises
    /// `SRV_ADMF_FQDN_CHANGED`. A server that is no slot has no target to set.
    pub fn set_server_srv_fqdn(&self, idx: usize, v: Option<&str>) {
        if let Some(slots) = &self.ids.server_srv {
            slots.set_fqdn(idx, v);
        }
    }

    /// The `resolvers` section the server at `idx` names, if any (`srv->resolvers`).
    #[must_use]
    pub fn server_resolvers(&self, idx: usize) -> Option<&str> {
        self.ids.server_srv.as_ref().and_then(|v| v.section.get(idx)).and_then(Option::as_deref)
    }

    /// The name the server at `idx` resolves now (`srv->hostname`): the one `set server fqdn`
    /// or an SRV record gave it, else the configuration's.
    #[must_use]
    pub fn server_hostname(&self, idx: usize) -> Option<Box<str>> {
        self.server_srv_fqdn(idx).or_else(|| self.server_fqdn(idx).map(Box::from))
    }

    /// `set server fqdn`: the name `srv_fqdn` shows from now on (no flag yet).
    pub fn set_server_hostname(&self, idx: usize, v: &str) {
        if let Some(slots) = &self.ids.server_srv {
            slots.set_name(idx, Some(v));
        }
    }

    /// Raises `SRV_ADMF_FQDN_CHANGED` for the server at `idx`.
    pub fn mark_server_fqdn_changed(&self, idx: usize) {
        if let Some(c) = self.ids.server_srv.as_ref().and_then(|v| v.changed.get(idx)) {
            c.store(true, Ordering::Relaxed);
        }
    }

    /// The `port` keyword of the server at `idx`, 0 without one (`srv_agent_port`).
    #[must_use]
    pub fn server_check_port(&self, idx: usize) -> u16 {
        self.ids.server_check_ports.get(idx).copied().unwrap_or(0)
    }

    /// Whether the server at `idx` has an `id` of its own (`SRV_F_FORCED_ID`).
    #[must_use]
    pub fn server_forced_id(&self, idx: usize) -> bool {
        self.ids.server_forced_ids.get(idx).copied().unwrap_or(false)
    }

    /// Returns the indices of eligible servers for request routing.
    ///
    /// Active (non-backup) servers that are UP and not saturated (actconn < maxconn) are prioritized.
    /// If at least one active server is available, only active servers are returned (backup servers receive 0 traffic).
    /// If all active servers are DOWN (or saturated), returns the first available backup alone.
    /// If no servers are available, returns an empty vector.
    #[must_use]
    pub fn eligible_server_indices(&self) -> Vec<usize> {
        let n = self.eligible_count();
        (0..n).filter_map(|k| self.eligible_nth(k)).collect()
    }

    /// Whether server `idx` is an active server that takes balanced traffic.
    fn is_eligible_active(&self, idx: usize) -> bool {
        let is_backup = self.server_backups.get(idx).copied().unwrap_or(false);
        // A weight of 0 (`set server ... weight 0`) takes no balanced traffic.
        !is_backup && crate::lb::is_server_available(self, idx) && self.server_weights.get(idx).unwrap_or(1) > 0
    }

    /// How many servers [`Proxy::eligible_server_indices`] lists, without listing them.
    fn eligible_count(&self) -> usize {
        let active = (0..self.servers.len()).filter(|&i| self.is_eligible_active(i)).count();
        if active > 0 { active } else { usize::from(crate::lb::first_backup(self).is_some()) }
    }

    /// The `k`th of [`Proxy::eligible_server_indices`], without listing them.
    fn eligible_nth(&self, k: usize) -> Option<usize> {
        let mut it = (0..self.servers.len()).filter(|&i| self.is_eligible_active(i));
        it.nth(k).or_else(|| crate::lb::first_backup(self).filter(|_| k == 0))
    }

    /// Whether no server can take a connection only because each one that is UP is at its
    /// `maxconn`: the request is queued then, not refused.
    #[must_use]
    pub fn all_servers_full(&self) -> bool {
        self.dispatch.is_none() && crate::lb::any_full(self) && self.eligible_server_indices().is_empty()
    }

    /// How many queued requests the servers can take now (`usize::MAX`: no limit).
    #[must_use]
    pub fn queue_headroom(&self) -> usize {
        self.eligible_server_indices().into_iter().fold(0usize, |free, i| {
            let room = self.server_maxconn.get(i).filter(|&mc| mc > 0).map_or(usize::MAX, |mc| {
                mc.saturating_sub(self.server_actconn.get(i).map_or(0, |a| a.load(Ordering::Relaxed))) as usize
            });
            free.saturating_add(room)
        })
    }

    /// Takes one of server `idx`'s connection slots: in one step with the check against its
    /// `maxconn`, so that two workers never both take its last one (T590). `HAProxy` checks
    /// `srv->served < srv_dynamic_maxconn(srv)` and counts the stream under the server's
    /// lock (`assign_server_and_queue`, `pendconn_dequeue`). `None`: the server is full.
    /// Without a `maxconn` the slot is always there, and counted only with `count_unlimited`
    /// (`Some(false)`: the caller counts it when the connection is in use, T224).
    #[must_use]
    pub fn take_server_slot(&self, idx: usize, count_unlimited: bool) -> Option<bool> {
        let Some(cur) = self.server_actconn.get(idx) else { return Some(false) };
        match self.server_maxconn.get(idx).filter(|&mc| mc > 0) {
            None => {
                if count_unlimited {
                    cur.fetch_add(1, Ordering::Relaxed);
                }
                Some(count_unlimited)
            }
            Some(mc) => cur.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| (c < mc).then_some(c + 1)).ok().map(|_| true),
        }
    }

    /// A server `pick` gives, with its slot taken ([`Proxy::take_server_slot`]; the `bool`:
    /// counted). A server another worker filled since `pick` saw room in it is passed over
    /// and `pick` asked again: it no longer offers that one while it is full. `None` when
    /// every pick was full (the request queues then: [`Proxy::all_servers_full`]) or there
    /// is no server; the dispatch address takes no slot.
    pub fn pick_and_take(
        &self,
        count_unlimited: bool,
        mut pick: impl FnMut() -> Option<(Option<usize>, SocketAddr)>,
    ) -> Option<((Option<usize>, SocketAddr), bool)> {
        (0..=self.servers.len())
            .find_map(|_| match pick() {
                Some((Some(i), addr)) => self.take_server_slot(i, count_unlimited).map(|counted| Some(((Some(i), addr), counted))),
                other => Some(other.map(|t| (t, false))),
            })
            .flatten()
    }

    /// Selects the target backend server using the configured load balancing algorithm,
    /// preferring primary servers over backup servers,
    /// or falls back to the dispatch address if all servers are down or absent.
    #[must_use]
    pub fn select_server(&self) -> Option<SocketAddr> {
        self.select_server_idx().map(|(_, a)| a)
    }

    /// [`Proxy::select_server`], with the index of the server picked.
    #[must_use]
    pub fn select_server_idx(&self) -> Option<(Option<usize>, SocketAddr)> {
        if self.servers.is_empty() {
            return self.dispatch.map(|a| (None, a));
        }
        let picked = match self.balance {
            BalanceAlgorithm::Leastconn => crate::lb::leastconn(self),
            BalanceAlgorithm::StaticRr => crate::lb::static_rr(self),
            BalanceAlgorithm::First => crate::lb::first(self),
            BalanceAlgorithm::Random(draws) => crate::lb::random(self, draws),
            BalanceAlgorithm::RoundRobin => crate::lb::round_robin(self),
            _ => self.eligible_count().checked_sub(1).and_then(|last| self.eligible_nth(self.next_server_idx.fetch_add(1, Ordering::Relaxed) % (last + 1))),
        };
        picked.map(|idx| (Some(idx), self.servers.at(idx))).or(self.dispatch.map(|a| (None, a)))
    }

    /// Selects the target backend server with load balancing algorithm (Source IP hash or round-robin),
    /// respecting backup failover and connection limits.
    #[must_use]
    pub fn select_server_with_key(&self, source_ip: Option<IpAddr>, uri: Option<&str>) -> Option<SocketAddr> {
        self.select_server_with_key_idx(source_ip, uri).map(|(_, a)| a)
    }

    /// [`Proxy::select_server_with_key`], with the index of the server picked (`None`: the
    /// dispatch address), so that the caller does not look the address up again.
    #[must_use]
    pub fn select_server_with_key_idx(&self, source_ip: Option<IpAddr>, uri: Option<&str>) -> Option<(Option<usize>, SocketAddr)> {
        if self.servers.is_empty() {
            return self.dispatch.map(|a| (None, a));
        }
        match self.balance {
            BalanceAlgorithm::Source if self.hash_type == ibex_config::HashType::Consistent && source_ip.is_some() => {
                let ip = source_ip?;
                crate::lb::balance_source_consistent(self, ip).map(|idx| (Some(idx), self.servers.at(idx))).or(self.dispatch.map(|a| (None, a)))
            }
            BalanceAlgorithm::Source => {
                let n = self.eligible_count();
                let slot = match source_ip {
                    // The sum of the address bytes (v6) or the address (v4), modulo the servers.
                    Some(IpAddr::V4(v4)) => u32::from(v4) as usize,
                    Some(IpAddr::V6(v6)) => v6.octets().iter().fold(0usize, |acc, &b| acc.wrapping_add(b as usize)),
                    None => self.next_server_idx.fetch_add(1, Ordering::Relaxed),
                };
                let picked = n.checked_sub(1).and_then(|last| self.eligible_nth(slot % (last + 1)));
                picked.map(|idx| (Some(idx), self.servers.at(idx))).or(self.dispatch.map(|a| (None, a)))
            }
            BalanceAlgorithm::Uri => {
                let u = uri.unwrap_or("/");
                if let Some(idx) = crate::lb::balance_uri(self, u) {
                    Some((Some(idx), self.servers.at(idx)))
                } else {
                    self.select_server_idx()
                }
            }
            _ => self.select_server_idx(),
        }
    }

}

/// A session registered in the runtime engine.
pub struct SessionEntry {
    pub sess: TcpSession,
    pub task: TaskRef,
    pub proxy_idx: usize,
    /// The backend of the transaction in progress (the frontend until one is chosen).
    pub backend_idx: usize,
    /// The backend the attached server connection belongs to; `target_server_idx` indexes
    /// its servers. Separate from `backend_idx` because a connection kept between
    /// transactions outlives the routing of the one that opened it.
    pub srv_backend_idx: usize,
    pub target_server_idx: Option<usize>,
    pub cli_raw_fd: RawFd,
    pub srv_raw_fd: Option<RawFd>,
    pub cli_interest: Interest,
    pub srv_interest: Interest,
    pub actconn_reclaimed: bool,
    /// The stream's counters were added to `show stat`'s (once per transaction).
    pub stats_done: bool,
    /// The backend whose `be_streams` count this stream (`stream_set_backend`), [`NO_BACKEND`] for none.
    pub be_counted: std::cell::Cell<u32>,
    /// The `Connect from` line of a frontend with no `log-format` is still to be sent: it goes
    /// once the connection has its PROXY header and TLS handshake behind it.
    pub connect_log_due: bool,
    /// The frontend's `rate_max` is still to be raised for this session: it is, once the TLS
    /// handshake is behind it (a connection whose handshake fails is no session).
    pub rate_max_due: bool,
    /// Requests the server connection has carried (saturating at 2): from the second it is
    /// kept in the server's safe list (`http-reuse`).
    pub srv_served: u8,
    /// A finished transaction's log line, waiting to be sent to its frontend's targets.
    pub log_line: Option<Vec<u8>>,
    /// `log_line` is a failed stream's: `option log-separate-errors` sends it at `err`.
    pub log_err: bool,
    /// The first `log_sd` bytes of `log_line` are its STRUCTURED-DATA (`log-format-sd`).
    pub log_sd: u32,
    /// Its place in the buffer wait queue (S6, [`crate::buf_wait`]).
    pub buf_wait: crate::buf_wait::WaitState,
}

/// Whether the soft stop has asked for its `pool_gc` (one request for every worker).
static SOFT_STOP_GC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Slots of every worker's [`SessionArena`], for `show pools` (pool `session`).
pub static SESSION_POOL: ibex_alloc::ArenaStats = ibex_alloc::ArenaStats::new(
    "session",
    std::mem::size_of::<Option<SessionEntry>>(),
    std::mem::align_of::<Option<SessionEntry>>(),
    file!(),
    line!(),
);

/// Compactions of every worker's session arena skipped for want of memory (T453).
#[must_use]
pub fn session_trims_skipped() -> usize {
    SESSION_POOL.compactions_skipped()
}

/// `show pools` provider for the `session` pool: the slots ever created, those in use.
#[allow(clippy::unnecessary_wraps)]
pub fn session_pool_stats() -> Option<ibex_alloc::PoolHead> {
    Some(SESSION_POOL.head())
}

/// Per-thread storage for active sessions: an [`ibex_alloc::Arena`] (design 3.7). A close
/// frees the slot and nothing more; the burst capacity goes back only in `pool_gc`
/// ([`Arena::compact`](ibex_alloc::Arena::compact)).
pub struct SessionArena {
    entries: Vec<Option<SessionEntry>>,
    free: Vec<u32>,
    live: usize,
    /// The capacity it was created with (`maxconn`'s pre-size): never given back, since
    /// untouched capacity costs no resident memory and growing it again is a `realloc` on
    /// the request path.
    floor: usize,
    /// The most slots it has held since its memory was last made fresh.
    peak: usize,
    /// `tune.memory.prealloc` made its slots: `pool_gc` does not compact it.
    presized: bool,
    published: ibex_alloc::arena::Published,
}

impl Drop for SessionArena {
    fn drop(&mut self) {
        SESSION_POOL.retire(&mut self.published);
    }
}

impl SessionArena {
    /// Pre-sized for `cap` sessions; short of memory (a small `-m`), empty instead, growing on
    /// use as `HAProxy`'s pools do: never an abort at the start (T511: under `-m 6` the
    /// instrumented build's larger footprint left no room for the 272000 bytes asked here).
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        let (mut entries, mut free) = (Vec::new(), Vec::new());
        let cap = if entries.try_reserve_exact(cap).is_ok() && free.try_reserve_exact(cap).is_ok() {
            cap
        } else {
            (entries, free) = (Vec::new(), Vec::new());
            0
        };
        SessionArena {
            entries,
            free,
            live: 0,
            floor: cap,
            peak: 0,
            presized: false,
            published: ibex_alloc::arena::Published::default(),
        }
    }

    /// Slots the arena can hold before it grows.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    /// Adds this arena's change since the last pass to `show pools` (once per loop pass).
    #[inline]
    pub fn publish(&mut self) {
        let mut last = self.published;
        SESSION_POOL.publish_arena::<SessionEntry>(&mut last, self);
        self.published = last;
    }

    /// `tune.memory.prealloc` (T468): `n` slots made now (free, resident), and kept as the
    /// floor. False when memory is short.
    pub fn prealloc(&mut self, n: usize) -> bool {
        let more = n.saturating_sub(self.entries.len());
        if self.entries.try_reserve_exact(more).is_err() || self.free.try_reserve_exact(more).is_err() {
            return false;
        }
        while self.entries.len() < n {
            let Ok(idx) = u32::try_from(self.entries.len()) else { return false };
            self.entries.push(None);
            self.free.push(idx);
        }
        // Lowest index first, as a fresh arena hands them out.
        self.free.reverse();
        self.presized = true;
        self.floor = self.floor.max(self.entries.capacity());
        self.peak = self.peak.max(self.entries.len());
        true
    }

    /// A slot for `entry`, or `None` (the entry is dropped) when the arena is full and the
    /// allocator refuses to grow it: the caller refuses the connection (`session.c`).
    pub fn alloc(&mut self, entry: SessionEntry) -> Option<u32> {
        // A trimmed tail leaves stale indices in `free`, and a regrown slot can be listed twice:
        // only a slot that exists and is empty is reused.
        while let Some(idx) = self.free.pop() {
            if let Some(slot @ None) = self.entries.get_mut(idx as usize) {
                *slot = Some(entry);
                self.live += 1;
                return Some(idx);
            }
        }
        let idx = u32::try_from(self.entries.len()).ok()?;
        if !ibex_alloc::arena::grow_for_one(&mut self.entries, &mut self.free) {
            SESSION_POOL.failed();
            return None;
        }
        self.live += 1;
        self.entries.push(Some(entry));
        self.peak = self.peak.max(self.entries.len());
        Some(idx)
    }

    #[must_use]
    pub fn get(&self, idx: u32) -> Option<&SessionEntry> {
        self.entries.get(idx as usize)?.as_ref()
    }

    pub fn get_mut(&mut self, idx: u32) -> Option<&mut SessionEntry> {
        self.entries.get_mut(idx as usize)?.as_mut()
    }

    /// Two distinct entries at once: an HTTP/2 connection's owner and one of its streams,
    /// whose bytes the owner moves (T280). `None` if `a == b` or either is free.
    pub fn get2_mut(&mut self, a: u32, b: u32) -> Option<(&mut SessionEntry, &mut SessionEntry)> {
        let (ai, bi) = (a as usize, b as usize);
        if ai == bi || ai.max(bi) >= self.entries.len() {
            return None;
        }
        let (lo, hi) = (ai.min(bi), ai.max(bi));
        let (left, right) = self.entries.split_at_mut(hi);
        let (x, y) = (left[lo].as_mut()?, right[0].as_mut()?);
        Some(if ai < bi { (x, y) } else { (y, x) })
    }

    pub fn free(&mut self, idx: u32) -> Option<SessionEntry> {
        let mut entry = self.entries.get_mut(idx as usize)?.take();
        if let Some(e) = entry.as_mut() {
            // A scrape or stats page cut short (the client left, its HTTP/2 stream was reset)
            // gives its box back to the pool, which does not count it while it is out (T580).
            e.sess.end_dump();
            self.live -= 1;
            self.free.push(idx);
        }
        entry
    }

    #[must_use]
    pub const fn live(&self) -> usize {
        self.live
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u32, &mut SessionEntry)> {
        self.entries
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, opt)| {
                let id = u32::try_from(idx).ok()?;
                opt.as_mut().map(|entry| (id, entry))
            })
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, &SessionEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(idx, opt)| {
                let id = u32::try_from(idx).ok()?;
                opt.as_ref().map(|entry| (id, entry))
            })
    }
}

impl Engine {
    /// The arenas' part of `pool_gc` (design 3.4, 3.7): the session, applet and task arenas
    /// give back the burst capacity (the free slots after the last one in use, the capacity
    /// above the pre-size). A close never does; only this does.
    fn compact_arenas(&mut self) {
        use ibex_alloc::Arena;
        let released = self.sessions.compact() + self.applets.compact() + self.scheduler.tasks.compact();
        if released > 0 {
            let _ = ibex_alloc::trim_heap();
        }
    }
}

impl ibex_alloc::Arena<SessionEntry> for SessionArena {
    fn slots(&self) -> usize {
        self.entries.len()
    }

    fn live(&self) -> usize {
        self.live
    }

    fn compact(&mut self) -> usize {
        // `tune.memory.prealloc`'s slots stay made: sized once, at start (T468).
        if self.presized {
            return 0;
        }
        ibex_alloc::arena::compact_slots(&mut self.entries, &mut self.free, self.live, self.floor, &mut self.peak, &SESSION_POOL)
    }
}

#[inline]
pub fn worker_id() -> usize {
    WORKER_ID.with(|id| id.get())
}

pub struct Engine {
    pub poller: Poller,
    pub scheduler: Scheduler,
    pub fdtab: FdTab,
    pub listeners: Vec<Listener>,
    /// QUIC listeners, driven by the engine like any other readiness source.
    pub quic_listeners: Vec<crate::quic_listener::QuicListener>,
    /// Every proxy, shared by the workers (T160). Runtime changes go through the atomics
    /// inside each `Proxy` (T177).
    pub proxies: Proxies,
    pub checks: Vec<ServerCheckState>,
    /// The `resolvers` sections the servers use, on worker 0 with the checks they change
    /// (`crate::resolvers`); empty elsewhere.
    resolvers: Vec<crate::resolvers::Section>,
    pub sessions: SessionArena,
    pub applets: AppletArena,
    pub cli_listener: Option<crate::cli_listener::CliListener>,
    /// The first CLI socket's file, unlinked on exit; `None` for TCP and abstract sockets.
    pub cli_socket_path: Option<PathBuf>,
    /// The first CLI socket's name for `show cli sockets` (`unix@/p`, `ipv4@a:p`, ...).
    cli_socket_name: Option<String>,
    /// The `stats socket` lines after the first, each with its own level (`HAProxy` binds
    /// them all).
    extra_cli: Vec<ExtraCli>,
    /// The abstract stats sockets given up on `SIGTTOU`: which one (`None` the first) and
    /// the name as bound. One a `SIGTTIN` could not bind back (still held) stays here for
    /// the next `SIGTTIN`.
    paused_abns: Vec<(Option<usize>, Vec<u8>)>,
    /// The TCP stats sockets `SIGTTOU` took out of the listening state, out of the poller
    /// until `SIGTTIN` (`None` the first).
    paused_tcp_cli: Vec<(Option<usize>, crate::cli_listener::CliListener)>,
    /// `SIGTTOU` paused the listeners and no `SIGTTIN` has resumed them yet: no limit
    /// (`global maxconn`, a frontend's) re-arms them meanwhile.
    sig_paused: bool,
    /// The listeners were stopped because `global maxconn` was reached (`globalconn`).
    global_paused: bool,
    /// `accept` failed for want of a resource (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`):
    /// the listeners are stopped as for `global maxconn` until this instant, or until a
    /// client connection of the process closes (the `actconn` recorded here drops), as
    /// `HAProxy`'s `CO_AC_PAUSE` puts the listener in the global listener queue for 100 ms
    /// (`listener_accept`, `transient_error`). Without it the level-triggered listener
    /// reported ready again at once: a CPU spent in `accept4` (T237).
    accept_limited: Option<(Instant, u32)>,
    /// A listener stopped polling because its frontend reached `maxconn`: the limit is shared
    /// by every worker, so a slot freed or a limit raised elsewhere is noticed by looking.
    fe_paused: bool,
    /// Connections may have waited in a listener's backlog, for it was stopped at a
    /// `maxconn` and has not been drained since: their clients may have left (T231).
    backlog_waits: bool,
    /// The `level` of the stats socket (`stats socket ... level`): what each new CLI connection
    /// may do. Unset means admin, as before the level was honoured.
    pub cli_level: crate::applet::CliLevel,
    /// `stats timeout`, in ms: how long a CLI connection may stay idle.
    pub cli_timeout_ms: u32,
    /// `stats maxconn`: CLI connections served at once; the listeners stop accepting at it.
    cli_maxconn: usize,
    /// The CLI listeners are out of the poller because `cli_maxconn` was reached.
    cli_paused: bool,
    /// `accept` on a CLI socket failed for want of a resource (`EMFILE`, `ENFILE`,
    /// `ENOBUFS`, `ENOMEM`): the CLI listeners stay stopped until this instant, as
    /// `HAProxy`'s `CO_AC_PAUSE` stops a listener for 100 ms. Left armed, the
    /// level-triggered listener was ready again at once and the worker spun (T246).
    cli_accept_retry: Option<Instant>,
    pub start_time: Instant,
    /// This process's id, read once: `std::process::id()` is a `getpid` syscall, and the
    /// dispatcher wants it on every step. Nothing forks after an engine is built (`-D`
    /// re-executes before any is).
    pid: u32,
    pub now: Tick,
    pub is_running: bool,
    pub worker_id: usize,
    events: Vec<crate::poller::Event>,
    timer_updates: Vec<(TaskRef, Tick)>,
    /// The tasks a pass wakes and the HTTP/2 connections whose streams it spawns, kept
    /// from one pass to the next, as `timer_updates` (T437: a `Vec` each pass allocated as
    /// soon as anything was pushed).
    wake_scratch: Vec<TaskRef>,
    /// The dispatcher's `wake_now` between passes (L2), empty.
    wake_now_scratch: Vec<TaskRef>,
    h2_spawn_scratch: Vec<(u32, TaskRef)>,
    /// Every syslog target the config declared, global and per-proxy. Proxies reference
    /// these by index through `Proxy::log_target_idx`.
    log_targets: Vec<SyslogTarget>,
    /// Value for the syslog TAG field. `HAProxy` uses the program name.
    log_tag: String,
    /// Global `tune.bufsize` value, stored per-engine to avoid races in tests that run
    /// multiple engines in the same process against the global `BUFSIZE_STANDARD` atomic.
    global_bufsize: usize,
    /// Global `tune.maxrewrite` value, stored per-engine for the same reason.
    global_maxrewrite: usize,
    /// `tune.ssl.capture-buffer-size`: the `ClientHello` bytes each TLS client connection keeps
    /// for the `ssl_fc_cipherlist_*` fetches; 0 keeps none.
    ssl_capture_size: usize,
    ssl_ja4_spec: bool,
    /// `tune.maxaccept`: how many connections one listener wakeup accepts in a row before
    /// the pass goes on to its other work (`listener_accept`: `for (; max_accept;
    /// max_accept--)`); the rest of the backlog is found by the next pass, the listener
    /// being polled level-triggered. `u32::MAX` is no limit (`-1`, and the default:
    /// `docs/differences.md`).
    maxaccept: u32,
    /// Global HTTP/2 flood mitigation configuration.
    pub global_h2_flood_config: ibex_proto::H2FloodConfig,
    /// Shared idle backend connection pool across sessions (`http-reuse`).
    pub idle_backend_pool: IdlePool,
    /// The upkeep tasks (L1).
    housekeeping: Housekeeping,
    /// Stop requests from signals, shared by every worker. `None` in tests and embeddings
    /// that drive the engine directly and stop it with [`Engine::stop`].
    lifecycle: Option<crate::lifecycle::Lifecycle>,
    /// Set once a soft stop has begun: listeners are closed and the loop is draining.
    stopping: bool,
    /// `global hard-stop-after`: how long a soft stop may drain before the loop ends anyway.
    hard_stop_after: Option<Duration>,
    /// When the current soft stop gives up draining, from `hard_stop_after`.
    stop_deadline: Option<Instant>,
    /// The identity (device, inode) of the CLI socket file this engine created, so that on
    /// exit it only unlinks a path that is still its own. See the `Drop` impl.
    cli_socket_ident: Option<(u64, u64)>,
    /// Requests from the other workers, and this one's way to ask them (`show sess`).
    mailboxes: Arc<crate::mailbox::Mailboxes>,
    /// This engine's mailbox among `mailboxes`: its worker id once `share_mailboxes` ran.
    mailbox_wid: usize,
}

/// A `stats socket` beyond the first: the first one keeps its fields on [`Engine`].
struct ExtraCli {
    /// `None` once the engine stops accepting (soft stop); the path stays for the unlink.
    listener: Option<crate::cli_listener::CliListener>,
    /// The socket file, unlinked on exit; `None` for TCP and abstract sockets.
    path: Option<PathBuf>,
    /// For `show cli sockets`.
    name: String,
    ident: Option<(u64, u64)>,
    level: crate::applet::CliLevel,
}

impl Engine {
    /// `SIGTTOU`: pauses every listener, as `HAProxy`'s `sig_pause` (`pause_proxies`):
    /// a frontend's TCP sockets leave the listening state, so a connect is refused
    /// ([`Listener::pause`]), unless `_getsocks` handed them to a successor, which serves
    /// on them: those are only no longer polled. The stats sockets: an abstract one lets go
    /// of its name (T354), a TCP one stops listening, a socket file is still served (all
    /// measured on 3.5-dev8-885761-29). Connections already accepted go on. QUIC listeners
    /// are not paused: an Ibex QUIC connection lives on the listening socket, which
    /// `HAProxy`'s `udp_suspend_receiver` connects to itself (its connections have sockets
    /// of their own); `docs/differences.md`.
    fn pause_on_signal(&mut self) {
        let shared = crate::handover::handed_over();
        for l in &self.listeners {
            // One that cannot be disconnected (it cannot fail on a listening socket) is
            // still no longer polled, as a shared one.
            if !shared {
                let _ = l.pause();
            }
            let lfd = l.raw_fd();
            let _ = self.poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), false, false);
            self.fdtab.set_interest(lfd, Interest::NONE);
        }
        self.sig_paused = true;
        self.pause_cli_on_signal();
        self.log_pause_or_resume("Paused", true);
    }

    /// `SIGTTIN`: undoes [`Self::pause_on_signal`]. A listener a limit stops meanwhile
    /// (`global maxconn`, its frontend's `maxconn`) is left to the limit's own resume.
    fn resume_on_signal(&mut self) {
        let shared = crate::handover::handed_over();
        self.sig_paused = false;
        let full = self.global_paused || self.accept_limited.is_some();
        for l in &self.listeners {
            // One that cannot listen again is not polled: a socket that is not listening
            // would be reported ready for ever.
            let listening = shared || l.resume().is_ok();
            if !listening || full {
                continue;
            }
            if l.is_full() {
                self.fe_paused = true;
                continue;
            }
            let lfd = l.raw_fd();
            let _ = self.poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), true, false);
            self.fdtab.set_interest(lfd, Interest::READ);
        }
        // Shared, they were only no longer polled: connections waited in their queues.
        self.backlog_waits |= shared;
        // The proxies are reported before the stats sockets are bound back, so a name
        // refused is reported after them, as on `HAProxy` (measured).
        self.log_pause_or_resume("Resumed", false);
        self.resume_cli_again();
    }

    /// The stats sockets' part of a `SIGTTIN`, and all of one after a resume an abstract
    /// name refused (still held): that name is tried again (T370), and only `GLOBAL` is
    /// reported.
    fn resume_cli_again(&mut self) {
        if self.resume_cli_on_signal() {
            Self::log_refused_resume(self.pid);
        } else {
            self.log_global("Resumed");
        }
    }

    /// `Paused frontend fe.` (`Paused proxy li.` for a `listen`), once a proxy with a
    /// listener, in the order of the configuration, then `frontend GLOBAL` when there is a
    /// stats socket: once a process (worker 0 says it), not once a thread (T456).
    fn log_pause_or_resume(&self, what: &str, global: bool) {
        if self.worker_id != 0 {
            return;
        }
        let mut idx: Vec<usize> = self.listeners.iter().map(|l| l.proxy as usize).collect();
        idx.sort_unstable_by_key(|&i| self.proxies[i].ids.decl);
        idx.dedup();
        for i in idx {
            let p = &self.proxies[i];
            let kind = if p.has_backend { "proxy" } else { "frontend" };
            crate::stderr_line!("[WARNING]  ({}) : {what} {kind} {}.", self.pid, p.name);
        }
        if global {
            self.log_global(what);
        }
    }

    /// `Paused frontend GLOBAL.` (`Resumed`), from worker 0, when there is a stats socket.
    fn log_global(&self, what: &str) {
        if self.worker_id == 0 && (self.cli_socket_name.is_some() || !self.extra_cli.is_empty()) {
            crate::stderr_line!("[WARNING]  ({}) : {what} frontend GLOBAL.", self.pid);
        }
    }

    fn log_refused_resume(pid: u32) {
        crate::stderr_line!(
            "[WARNING]  ({pid}) : Some proxies refused to resume, probably due to a conflict on a listening port. You may want to try again after the conflicting application is stopped, otherwise a restart might be needed to resume safe operations."
        );
    }

    /// The stats sockets' part of [`Self::pause_on_signal`]: the abstract ones let go of
    /// their names, whose successor started with `-sf` cannot share them; it sends this
    /// when its bind finds one in use, as `HAProxy`'s does (T354). The TCP ones stop
    /// listening (unless handed over). Both leave the poller until `SIGTTIN`.
    fn pause_cli_on_signal(&mut self) {
        use std::os::linux::net::SocketAddrExt;
        let abstract_name = |l: &crate::cli_listener::CliListener| -> Option<Vec<u8>> {
            match l {
                crate::cli_listener::CliListener::Unix(u) => {
                    u.local_addr().ok()?.as_abstract_name().map(<[u8]>::to_vec)
                }
                crate::cli_listener::CliListener::Tcp(_) => None,
            }
        };
        let shared = crate::handover::handed_over();
        let first = std::iter::once((None, &mut self.cli_listener));
        let extra = self.extra_cli.iter_mut().enumerate().map(|(i, x)| (Some(i), &mut x.listener));
        for (which, slot) in first.chain(extra) {
            let Some(l) = slot.take_if(|l| abstract_name(l).is_some() || (l.is_tcp() && !shared)) else {
                continue;
            };
            self.fdtab.remove(l.as_raw_fd());
            let _ = self.poller.delete(l.as_fd());
            if let Some(name) = abstract_name(&l) {
                self.paused_abns.push((which, name));
            } else {
                let _ = l.pause_tcp();
                self.paused_tcp_cli.push((which, l));
            }
        }
    }

    /// Puts a stats socket back in the poller and in its slot.
    fn rearm_cli(&mut self, which: Option<usize>, l: crate::cli_listener::CliListener) {
        let fd = l.as_raw_fd();
        let state = match which {
            None => FdState::CliListener,
            Some(i) => FdState::CliExtra(u32::try_from(i).unwrap_or(u32::MAX)),
        };
        let added = self.poller.add(l.as_fd(), raw_fd_to_u64(fd), !self.cli_paused, false).ok();
        let _ = added.map(|()| {
            self.fdtab.insert(fd, state, Interest::READ);
            match which {
                None => self.cli_listener = Some(l),
                Some(i) => self.extra_cli[i].listener = Some(l),
            }
        });
    }

    /// The stats sockets' part of [`Self::resume_on_signal`]; whether an abstract name could
    /// not be bound back.
    fn resume_cli_on_signal(&mut self) -> bool {
        // One that cannot listen again stays out of the poller, for the next `SIGTTIN`.
        let (back, still): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.paused_tcp_cli).into_iter().partition(|(_, l)| l.resume_tcp().is_ok());
        self.paused_tcp_cli = still;
        for (which, l) in back {
            self.rearm_cli(which, l);
        }
        self.resume_abns_cli()
    }

    /// `SIGTTIN` (T354): the successor did not start; binds the names given up again, each
    /// tried once, as `HAProxy`'s `protocol_resume_all` does (src/protocol.c:453). An Ibex
    /// successor closes its sockets before it signals (T370), so a name it held is free
    /// here; one something else holds is reported with `HAProxy`'s lines (measured on
    /// 3.5-dev8-885761-29) and kept for the next `SIGTTIN`:
    ///
    /// ```text
    /// [ALERT]    (pid) : Resuming listener: protocol abns_stream: cannot bind UNIX socket (already in use) [abns@NAME].
    /// [WARNING]  (pid) : Some proxies refused to resume, probably due to a conflict on a listening port. You may want to try again after the conflicting application is stopped, otherwise a restart might be needed to resume safe operations.
    /// ```
    fn resume_abns_cli(&mut self) -> bool {
        use std::os::linux::net::SocketAddrExt;
        let mut refused = false;
        for (which, bytes) in std::mem::take(&mut self.paused_abns) {
            let bound = std::os::unix::net::SocketAddr::from_abstract_name(&bytes)
                .and_then(|a| std::os::unix::net::UnixListener::bind_addr(&a))
                .and_then(|l| l.set_nonblocking(true).map(|()| l));
            let l = match bound {
                Ok(l) => l,
                Err(err) => {
                    // `abns@` is bound zero-padded to the whole `sun_path`; `abnsz@` is not.
                    let proto = if bytes.len() == 107 { "abns_stream" } else { "abnsz_stream" };
                    let shown = String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string();
                    let why = if err.kind() == std::io::ErrorKind::AddrInUse { "already in use".to_string() } else { err.to_string() };
                    crate::stderr_line!(
                        "[ALERT]    ({}) : Resuming listener: protocol {proto}: cannot bind UNIX socket ({why}) [abns@{shown}].",
                        std::process::id()
                    );
                    refused = true;
                    self.paused_abns.push((which, bytes));
                    continue;
                }
            };
            self.rearm_cli(which, crate::cli_listener::CliListener::from(l));
        }
        refused
    }

    /// The lines of `show cli sockets`: every CLI socket, in configuration order, with the
    /// level it was bound at (T354).
    fn cli_sockets_text(&self) -> String {
        let mut out = String::new();
        if let Some(n) = &self.cli_socket_name {
            out.push_str(&format!("{n} {} all", self.cli_level.name()));
        }
        for x in &self.extra_cli {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("{} {} all", x.name, x.level.name()));
        }
        out
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Whatever the other workers still ask of this one is answered empty.
        self.mailboxes.close(self.mailbox_wid);
        for x in &self.extra_cli {
            if let Some(path) = x.path.as_ref() {
                if x.ident.is_some() && socket_file_ident(path) == x.ident {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        // Unlink the CLI socket only if the path still names the socket this engine
        // created. During a reload the new process binds the same path before the old one
        // exits; an unconditional unlink here deleted the new process's stats socket, so
        // every reload silently took the CLI away.
        if let (Some(ref path), Some(ident)) = (&self.cli_socket_path, self.cli_socket_ident) {
            if socket_file_ident(path) == Some(ident) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// The listening sockets for one bind on one worker: whatever the previous process handed
/// over through `-x` (see [`crate::handover`]), or one freshly bound socket if nothing was.
/// Each is registered for `_getsocks`, so the *next* reload can take it over in turn.
fn listeners_for(
    worker_id: usize,
    addr: SocketAddr,
    proxy: u32,
    tuning: &ibex_config::ast::SocketTuning,
    backlog: i32,
) -> io::Result<Vec<Listener>> {
    let mut out = Vec::new();
    for fd in crate::handover::take_inherited(worker_id, addr) {
        match Listener::adopt(fd, addr, proxy, tuning) {
            // The backlog it keeps is its first process's; a resume after SIGTTOU
            // `listen()`s with this configuration's, as `tcp_resume_receiver` does.
            Ok(mut l) => {
                l.backlog = backlog;
                out.push(l);
            }
            Err(e) => crate::stderr_line!("[WARNING] {e}; binding a fresh socket instead"),
        }
    }
    if out.is_empty() {
        out.push(Listener::bind_tuned(addr, backlog, proxy, tuning)?);
    }
    for l in &out {
        crate::handover::expose(l.addr(), l.borrowed_fd())?;
    }
    Ok(out)
}

fn socket_file_ident(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// A proxy's ACLs by name: its own, then the predefined ones, shared by every proxy
/// (`find_acl_by_name` is searched before `find_acl_default`, so an ACL of the same name
/// replaces one). T175: compiling the predefined ACLs into each proxy took 20 KB a backend.
fn compile_acls(acl_rules: &[ibex_config::AclRule]) -> ibex_sample::Acls {
    ibex_sample::Acls::compile(acl_rules.iter().map(|r| (r.name.as_str(), r.expr.as_str())))
}

fn init_stick_table(ast: &ibex_config::StickTableConfigAst, name: &str) -> StickTable {
    let key_type = match ast.key_type.as_str() {
        "ipv6" => KeyType::Ipv6,
        "integer" => KeyType::Integer,
        "string" => KeyType::String,
        "binary" => KeyType::Binary,
        _ => KeyType::Ip,
    };

    let mut track_conn_rate_ms = None;
    let mut track_http_req_rate_ms = None;
    let mut track_http_err_rate_ms = None;
    let mut extra = ibex_stick_table::table::StickExtra::default();
    // What the table stores (`store`): the fetches that read a data type it does not store
    // give no sample, as they do in `HAProxy`.
    let mut flags = ibex_stick_table::table::TrackFlags {
        conn_cnt: false,
        conn_cur: false,
        sess_cnt: false,
        http_req_cnt: false,
        http_err_cnt: false,
        bytes_in_cnt: false,
        bytes_out_cnt: false,
        gpc0: false,
        gpc1: false,
        gpt0: false,
        http_fail_cnt: false,
        glitch_cnt: false,
        server_id: false,
    };

    for field in &ast.store_fields {
        let (name, args) = field.split_once('(').map_or((field.as_str(), ""), |(n, a)| (n, a.trim_end_matches(')')));
        // The period of a rate: `<name>(<period>)`, in milliseconds.
        let period = |a: &str| Some(u64::from(parse_timeout_val(a)));
        match name {
            "conn_cnt" => flags.conn_cnt = true,
            "conn_cur" => flags.conn_cur = true,
            "sess_cnt" => flags.sess_cnt = true,
            "http_req_cnt" => flags.http_req_cnt = true,
            "http_err_cnt" => flags.http_err_cnt = true,
            "http_fail_cnt" => flags.http_fail_cnt = true,
            "bytes_in_cnt" => flags.bytes_in_cnt = true,
            "bytes_out_cnt" => flags.bytes_out_cnt = true,
            "glitch_cnt" => flags.glitch_cnt = true,
            "server_id" => flags.server_id = true,
            "gpc0" => flags.gpc0 = true,
            "gpc1" => flags.gpc1 = true,
            "gpt0" => flags.gpt0 = true,
            "conn_rate" => track_conn_rate_ms = period(args),
            "http_req_rate" => track_http_req_rate_ms = period(args),
            "http_err_rate" => track_http_err_rate_ms = period(args),
            "sess_rate" => extra.sess_rate_ms = period(args),
            "http_fail_rate" => extra.http_fail_rate_ms = period(args),
            "bytes_in_rate" => extra.bytes_in_rate_ms = period(args),
            "bytes_out_rate" => extra.bytes_out_rate_ms = period(args),
            "glitch_rate" => extra.glitch_rate_ms = period(args),
            "gpc0_rate" => extra.gpc0_rate_ms = period(args),
            "gpc1_rate" => extra.gpc1_rate_ms = period(args),
            "gpc" => extra.gpc_n = args.parse().unwrap_or(0),
            "gpt" => extra.gpt_n = args.parse().unwrap_or(0),
            "gpc_rate" => {
                let (n, p) = args.split_once(',').unwrap_or((args, ""));
                extra.gpc_rate_n = n.trim().parse().unwrap_or(0);
                extra.gpc_rate_ms = u64::from(parse_timeout_val(p));
            }
            _ => {}
        }
    }

    let config = StickTableConfig {
        name: name.to_string(),
        key_type,
        max_size: ast.size,
        expire: ast.expire,
        flags,
        track_conn_rate_ms,
        track_http_req_rate_ms,
        track_http_err_rate_ms,
        extra,
    };

    // `len` of a `string` or `binary` table, 32 where the configuration does not say.
    StickTable::new(config).with_key_len(ast.key_len.unwrap_or(32))
}


/// The local hostname for the syslog HOSTNAME field.
///
/// Read once at startup. RFC 3164 wants a hostname with no domain part and no spaces;
/// anything unreadable becomes "-", which is what a collector expects for "unknown"
/// rather than an empty field that would shift every following token.
fn hostname() -> String {
    // uname(2), as HAProxy's gethostname(): a file under /proc is not there in a chroot,
    // and this is first read when the first line is logged, after the chroot (T240).
    Some(rustix::system::uname().nodename().to_string_lossy().into_owned())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty() && !h.contains(' '))
        .map_or_else(|| "-".to_string(), |h| {
            h.split('.').next().unwrap_or("-").to_string()
        })
}

/// A syslog tag as sent: `tag[pid]`. Built once per proxy, after `-D` has re-executed,
/// so the pid is the one that sends.
/// A format already checked by [`crate::rule_exprs::validate_config`].
fn compile_unique_id_format(fmt: &str) -> Option<Arc<crate::logfmt::LogFormat>> {
    crate::logfmt::LogFormat::compile_unique_id(fmt, sample_registry()).ok().map(Arc::new)
}

fn compile_format(fmt: &str) -> Option<Arc<crate::logfmt::LogFormat>> {
    crate::logfmt::LogFormat::compile(fmt, sample_registry()).ok().map(Arc::new)
}

fn compile_log_format(spec: Option<&ibex_config::LogFormatSpec>, mode_http: bool) -> Option<Arc<crate::logfmt::LogFormat>> {
    compile_format(crate::logfmt::format_string(spec?, mode_http))
}

/// The proxy's request capture slots, and the slot each `http-request capture` rule
/// without `id` writes: `HAProxy` numbers both in declaration order, and the header
/// captures recorded theirs, so the rules take the rest in order. A rule's slot is as long
/// as the rule's `len`, which a later rule writing it by `id` is cut to.
/// `option http-buffer-request` is a `wait-for-body` ahead of the proxy's request rules
/// (`time` unset: the wait `wait_for_request_body` gives it).
fn with_buffered_request(rules: &mut Vec<ibex_config::HttpReqRule>, on: bool) {
    if on {
        let action = ibex_config::HttpReqAction::WaitForBody { time_ms: None, at_least: 0 };
        rules.insert(0, ibex_config::HttpReqRule { action, cond: None, line: 0 });
    }
}

fn capture_slots(
    headers: &[ibex_config::HeaderCapture],
    rules: &mut [ibex_config::HttpReqRule],
    tcp_rules: &mut [ibex_config::TcpReqContentRule],
) -> Arc<[(String, usize)]> {
    let rule_slots = rules
        .iter()
        .filter(|r| matches!(r.action, ibex_config::HttpReqAction::Capture { id: None, .. }))
        .count()
        + tcp_rules.iter().filter(|r| matches!(r.action, ibex_config::TcpReqContentAction::Capture { .. })).count();
    let mut slots: Vec<Option<(String, usize)>> = vec![None; headers.len() + rule_slots];
    for h in headers {
        if let Some(s) = slots.get_mut(h.slot) {
            *s = Some((h.name.clone(), h.len));
        }
    }
    let mut free = (0..slots.len()).filter(|&i| slots[i].is_none()).collect::<Vec<_>>().into_iter();
    for r in rules.iter_mut() {
        if let ibex_config::HttpReqAction::Capture { id: id @ None, len, .. } = &mut r.action {
            *id = free.next();
            if let Some(slot) = id.and_then(|i| slots.get_mut(i)) {
                *slot = Some((String::new(), len.unwrap_or(usize::MAX)));
            }
        }
    }
    // `tcp-request content capture` rules take the slots after the `http-request` ones.
    for r in tcp_rules.iter_mut() {
        if let ibex_config::TcpReqContentAction::Capture { len, id, .. } = &mut r.action {
            *id = free.next();
            if let Some(slot) = id.and_then(|i| slots.get_mut(i)) {
                *slot = Some((String::new(), *len));
            }
        }
    }
    slots.into_iter().map(Option::unwrap_or_default).collect()
}

/// The `http-request capture` expressions of `rules`, parsed once, parallel to the rules.
/// `Expr::parse` was running on every request; an expression that does not parse was
/// refused when the configuration loaded.
/// The host name, read once: `%H`.
pub(crate) fn log_hostname() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(hostname)
}

/// `s` cut to at most `len` bytes: a capture is bytes, and one that ends inside a
/// character keeps the byte it cut at, as in `HAProxy`.
fn cut_at(s: &str, len: usize) -> std::borrow::Cow<'_, [u8]> {
    match ibex_regex::bytetext::text_to_bytes(s) {
        std::borrow::Cow::Borrowed(b) => std::borrow::Cow::Borrowed(&b[..len.min(b.len())]),
        std::borrow::Cow::Owned(mut b) => {
            b.truncate(len);
            std::borrow::Cow::Owned(b)
        }
    }
}

/// A new HTTP transaction's request is in: its header captures and unique ID, before any
/// rule can read them, and the ID sent on in `unique-id-header` (`http_process_request`).
fn begin_http_stream(entry: &mut SessionEntry, proxies: &[Proxy], fe_idx: usize, pid: u32) {
    let fe = &proxies[fe_idx];
    if !fe.req_capture_slots.is_empty() {
        // Into the slots' memory of the connection's previous request (T437): taken out
        // while the HTX is read, put back.
        let mut caps = std::mem::take(&mut entry.sess.log.req_captures);
        // What `tcp-request content capture` wrote before the request was parsed is in the
        // slots of its own (no header name), which nothing here fills.
        let tcp_captures = fe.tcp_req_content_rules.iter().any(|r| matches!(r.action, ibex_config::TcpReqContentAction::Capture { .. }));
        let keep_tcp = tcp_captures && caps.len() == fe.req_capture_slots.len();
        if !keep_tcp {
            crate::txnlog::reset_captures(&mut caps, fe.req_capture_slots.len());
        }
        // A request that reached here was parsed into HTX (H1 and H2 alike).
        let htx = entry.sess.htx_slice();
        for (slot, (name, len)) in caps.iter_mut().zip(fe.req_capture_slots.iter()) {
            // A slot no header fills (`declare capture`, a rule's) has no name.
            if name.is_empty() {
                continue;
            }
            // The last header of the name, as bytes: a value is text holding any escaped byte
            // of a header that is not UTF-8 (T286), captured as the client sent it.
            let found = htx.as_ref().and_then(|h| h.headers().filter(|(k, _)| k.as_bytes().trim_ascii().eq_ignore_ascii_case(name.as_bytes())).last());
            match found {
                Some((_, v)) => {
                    let v = ibex_regex::bytetext::text_to_bytes(v);
                    let v = v.trim_ascii();
                    crate::txnlog::set_capture(slot, &v[..(*len).min(v.len())]);
                }
                None => crate::txnlog::clear_capture(slot),
            }
        }
        entry.sess.log.req_captures = caps;
    }
    // The response's slots exist from here on, empty until a response fills them: `%hs`
    // is `{}` for a transaction the server never answered, and nothing for a request
    // that never parsed.
    crate::txnlog::reset_captures(&mut entry.sess.log.res_captures, fe.res_capture_slots.len());
    // T331: what the `capture-req` and `capture-res` converters cut at.
    // The run that parsed the request has started already, with no slots to give.
    let _ = ibex_sample::capture_write::enter_shared(&fe.req_capture_slots, &fe.res_capture_slots);
    // `HAProxy` builds the ID on first use (`stream_generate_unique_id`); built here, once,
    // it is the same value for every reader, from the request as received.
    if let Some(fmt) = fe.unique_id_format.as_ref() {
        let id = {
            let data = stream_log_data(entry, std::slice::from_ref(fe), 0, pid);
            let view = ProxiesView(proxies);
            let stick = StickView::new(proxies, &entry.sess.tracked_sc);
            let ctx = stream_sample_ctx(&entry.sess, fe, fe, &view, &stick);
            fmt.render(&data, sample_registry(), &ctx)
        };
        if let Some(h) = fe.unique_id_header.as_deref() {
            // Into the HTX too: the head is written again from it whenever a later step edits a header.
            add_req_header(&mut entry.sess, &h.to_ascii_lowercase(), &id);
        }
        entry.sess.log.unique_id = Some(id);
    }
}

static CONFIG_FILES: std::sync::OnceLock<Vec<(u32, String)>> = std::sync::OnceLock::new();

/// Records the configuration files as they were read into one text: each file's path and
/// the line of that text it starts at (the first is 1), so a rule's line can be told as
/// `file:line` for `last_rule_file` and `last_rule_line`.
pub fn set_config_files(files: Vec<(u32, String)>) {
    let _ = CONFIG_FILES.set(files);
}

/// `last_rule`, a line of the configuration text, as the file it is in and its line there.
fn last_rule_at(line: Option<u32>) -> Option<(&'static str, u32)> {
    let line = line?;
    let files = CONFIG_FILES.get()?;
    let (first, path) = files.iter().rev().find(|(first, _)| *first <= line)?;
    Some((path.as_str(), line - first + 1))
}

/// Notes `line` as the last rule that ended a rule set for the request: `0`, a rule the
/// proxy made up, is not one.
fn note_last_rule(sess: &mut TcpSession, line: u32) {
    if line != 0 {
        sess.log.last_rule = Some(line);
    }
}

/// What `when()` reads of a stream (`sample_conv_when`): an error is a 5xx status; a
/// connection attempt, once made, counts as forwarded. A connection retry (`retried`) is an
/// error too (`conn_retries` with no error flag); a redispatch is one retry, so it is
/// covered.
fn stream_facts(sess: &TcpSession, status: Option<u16>, timers: bool) -> ibex_sample::StreamFacts {
    let log = &sess.log;
    let used = sess.max_retries.saturating_sub(sess.conn_retries);
    ibex_sample::StreamFacts {
        error: used > 0 || status.is_some_and(|s| s >= 500),
        forwarded: log.queue.is_some() || log.connect.is_some(),
        toapplet: log.applet,
        retries: u32::from(used),
        redispatched: sess.redispatched,
        // Only for a rule whose format prints them: five clock reads are not free (T455).
        timers: timers.then(|| [log.ms(log.first_byte), log.ms(log.request), log.ms(log.queue), log.ms(log.connect), log.ms(log.data)]),
    }
}

/// `request_date`: the accept date plus the idle time before the request's first byte
/// (`accept_date + t_idle + t_handshake`, `tcp_sample.c`), as unix seconds and
/// milliseconds; the accept date while no byte has come.
fn request_date(log: &crate::txnlog::StreamLog) -> (i64, u32) {
    let date = log.date();
    let Some(fb) = log.first_byte else { return date };
    let d = fb.saturating_duration_since(log.start);
    let ms = date.1 + d.subsec_millis();
    let secs = date.0.saturating_add(i64::try_from(d.as_secs()).unwrap_or(i64::MAX)).saturating_add(i64::from(ms / 1000));
    (secs, ms % 1000)
}

/// The sample context a log line's `%[...]` reads.
fn stream_sample_ctx<'a>(s: &'a TcpSession, fe: &'a Proxy, be: &'a Proxy, view: &'a ProxiesView<'a>, stick: &'a StickView<'a>) -> SampleContext<'a> {
    SampleContext {
        proxies: Some(view),
        stick: Some(stick),
        client_addr: s.client_addr,
        server_addr: s.server_addr,
        fc_src: s.fc_src(),
        fc_dst: s.fc_dst(),
        is_first_req: s.is_first_req,
        proxy_tlvs: s.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: crate::proxy::ssl_fc(&s.cli_xprt, s.h2_role.as_deref()),
        quic_acks: s.quic_facts(),
        fc_http_major: s.fc_http_major(),
        bc_http_major: s.bc_http_major(),
        req_version: s.client_version(),
        ssl_bc: s.srv_xprt.ssl_facts(),
        htx_slice: s.htx_slice(),
        req_uri: s.req_uri.as_deref(),
        req_method: s.req_method.as_deref(),
        req_headers: s.req_headers.as_deref(),
        fe_name: Some(&fe.name),
        fe_id: Some(fe.ids.iid),
        be_name: Some(&be.name),
        be_id: Some(be.ids.iid),
        so_name: s.so_name.as_deref(),
        so_id: s.so_id,
        captures_req_hdr: Some(&s.log.req_captures),
        captures_res_hdr: Some(&s.log.res_captures),
        unique_id: s.log.unique_id.as_deref(),
        accept_date: Some(s.log.date()),
        request_date: Some(request_date(&s.log)),
        last_rule: last_rule_at(s.log.last_rule),
        prio: (s.log.prio_class, s.log.prio_offset),
        bc_err: s.bc_err.copied(),
        bc_reused: Some(s.txn.as_ref().is_some_and(|t| t.srv_reused)),
        term_state: Some(sess_term_state(s)),
        bc_dst: s.bc_dst(),
        bc_src: s.bc_src(),
        ..Default::default()
    }
}

/// `%ts` (`StreamLog::term_state`).
fn term_state(entry: &SessionEntry) -> [u8; 2] {
    sess_term_state(&entry.sess)
}

/// The termination state of a stream as it is now (`txn.sess_term_state` reads the flags
/// when it is evaluated).
fn sess_term_state(s: &TcpSession) -> [u8; 2] {
    s.log.term_state(s.ending, s.mode == Mode::Http, s.txn.as_ref().is_some_and(|t| t.rsp.is_done()))
}

/// What the stream measured, for its log line and `unique-id-format`. `proxies` holds the
/// frontend at `entry.proxy_idx`, or is the frontend alone (`proxy_idx` then 0).
fn stream_log_data<'a>(entry: &'a SessionEntry, proxies: &'a [Proxy], proxy_idx: usize, pid: u32) -> crate::logfmt::LogData<'a> {
    let fe = &proxies[proxy_idx];
    let be = proxies.get(entry.backend_idx).filter(|_| proxies.len() > 1).unwrap_or(fe);
    crate::logfmt::LogData {
        server_addr: entry.sess.bc_dst(),
        backend_addr: entry.sess.bc_src(),
        server: entry
            .target_server_idx
            .or_else(|| entry.sess.log.server.map(|i| i.get() as usize - 1))
            .and_then(|i| proxies.get(entry.srv_backend_idx)?.server_ids.get(i))
            .map(String::as_str),
        term_state: term_state(entry),
        // The stream has let go of its backend when the line is made: only the others count.
        beconn: {
            let own = counted_backend(entry).and_then(|i| proxies.get(i)).is_some_and(|p| std::ptr::eq(p, be));
            be.stats.iter().map(|st| u64::from(st.be_streams.load(Ordering::Relaxed))).sum::<u64>().saturating_sub(u64::from(own))
        },
        srvconn: entry
            .target_server_idx
            .and_then(|i| proxies.get(entry.srv_backend_idx)?.server_actconn.get(i))
            .map_or(0, |a| u64::from(a.load(Ordering::Relaxed))),
        ..session_log_data(&entry.sess, fe, be, pid)
    }
}

/// `%[req.hdr(host)]`, the host a `redirect scheme` rule uses, compiled once.
fn host_format() -> &'static crate::rule_compiled::Format {
    static F: std::sync::LazyLock<crate::rule_compiled::Format> = std::sync::LazyLock::new(|| crate::rule_compiled::Format::compile("%[req.hdr(host)]", false));
    &F
}

/// A rule's compiled format, rendered from `ctx` alone: what a rule that has no session in
/// reach (a `tcp-request` one) writes.
fn render_rule_fmt(rc: &crate::rule_compiled::Rule, ctx: &SampleContext, registry: &Registry) -> String {
    let mut out = String::new();
    rc.fmt.iter().for_each(|f| f.render_into(&mut out, ctx, registry, None));
    out
}

/// A response rule's compiled format rendered: `%ST` is the status the response has now.
fn render_res_format(f: &crate::rule_compiled::Format, out: &mut String, ctx: &SampleContext, registry: &Registry, status: u16) {
    if f.needs_stream() {
        let data = crate::logfmt::LogData { status: i64::from(status), ..crate::logfmt::LogData::of_context(ctx) };
        f.render_into(out, ctx, registry, Some(&data));
    } else {
        f.render_into(out, ctx, registry, None);
    }
}

/// The request line as the access log keeps it, from what a context holds of the request
/// (`%r`, `%HM`, ... in a rule's format).
fn request_line_of(ctx: &SampleContext) -> String {
    format!("{} {} {}", ctx.req_method.unwrap_or_default(), ctx.req_uri.unwrap_or_default(), ctx.req_version.unwrap_or("HTTP/1.1"))
}

/// What the session measured, for a rule's format that reads it ([`session_log_data`]); `None`
/// where the proxies the context names are not there.
fn stream_data<'a>(sess: &'a TcpSession, proxies: &'a [Proxy], ctx: &SampleContext, request_line: Option<&'a str>) -> Option<crate::logfmt::LogData<'a>> {
    let named = |name: Option<&str>, frontend: bool| name.and_then(|n| proxies.iter().find(|p| p.name == n && if frontend { p.has_frontend } else { p.has_backend }));
    let fe = named(ctx.fe_name, true)?;
    let be = named(ctx.be_name, false).unwrap_or(fe);
    let mut data = session_log_data(sess, fe, be, std::process::id());
    data.request_line = request_line;
    // A request rule runs before the request is counted as received: `TR` and `Tq` are -1 and
    // `U` is 0 (measured on 3.5-dev8), and the termination state is the one the rule just set.
    data.t_request = -1;
    data.bytes_in = 0;
    data.term_state = sess_term_state(sess);
    Some(data)
}

/// A request rule's compiled format rendered. A format that reads the stream's measures (the
/// timers, `%ST`, `%B`, the counters, ...) is given the session's, as the access log is
/// (`session_log_data`); one that reads names, addresses and samples reads them from `ctx`.
fn render_rule_format(f: &crate::rule_compiled::Format, out: &mut String, ctx: &SampleContext, registry: &Registry, sess: &TcpSession, proxies: &[Proxy]) {
    if f.needs_stream() {
        let line = f.uses_request_line().then(|| request_line_of(ctx));
        if let Some(data) = stream_data(sess, proxies, ctx, line.as_deref()) {
            f.render_into(out, ctx, registry, Some(&data));
            return;
        }
    }
    f.render_into(out, ctx, registry, None);
}

/// `%ST`: -1 for a transaction that has no status (`txn->status` starts at -1), as one the
/// client left before it reached a server (`CQ`, `CC`).
fn stream_status(s: &TcpSession) -> i64 {
    s.txn.as_ref().map(|t| t.status).filter(|&st| st > 0).or(s.log.status).map_or(-1, i64::from)
}

/// The HTX messages `HAProxy` parsed, where they were measured; the bytes that crossed
/// the wire otherwise (an HTTP/2 client's request, a response the server did not make).
fn stream_bytes_out(s: &TcpSession) -> u64 {
    let l = &s.log;
    s.txn.as_ref().and_then(|t| t.rsp_htx).filter(|_| l.bytes_from_server > 0).unwrap_or(l.bytes_from_server)
}

/// A request that never parsed counts nothing (`HAProxy`: `U=0` with `<BADREQ>`).
fn stream_bytes_in(s: &TcpSession) -> u64 {
    let l = &s.log;
    if s.mode == Mode::Http && l.request.is_none() {
        0
    } else {
        s.txn.as_ref().and_then(|t| t.req_htx).unwrap_or_else(|| s.bytes_in.saturating_sub(l.bytes_in_at_start))
    }
}

/// What the session alone knows, before (or without) a server: what `unique-id-format`
/// reads when a TCP stream's PROXY header is built at connect.
fn session_log_data<'a>(s: &'a TcpSession, fe: &'a Proxy, be: &'a Proxy, pid: u32) -> crate::logfmt::LogData<'a> {
    let l = &s.log;
    let sum = |p: &Proxy| p.stats.iter().map(|st| u64::from(st.act_conn.load(Ordering::Relaxed))).sum::<u64>();
    crate::logfmt::LogData {
        client: s.client_addr,
        frontend_addr: s.server_addr,
        frontend: &fe.name,
        // QUIC is TLS, though the relayed stream the engine reads is not (T130).
        frontend_ssl: s.cli_is_tls() || s.h3,
        ssl_cipher: crate::proxy::ssl_fc(&s.cli_xprt, s.h2_role.as_deref()).cipher,
        ssl_version: crate::proxy::ssl_fc(&s.cli_xprt, s.h2_role.as_deref()).protocol,
        backend: &be.name,
        backend_http: be.mode == Mode::Http,
        accept_date: l.date(),
        t_handshake: 0,
        t_idle: l.ms(l.first_byte),
        t_request: l.ms(l.request),
        t_queue: l.ms(l.queue),
        t_connect: l.ms(l.connect),
        t_data: l.ms(l.data),
        t_close: if l.asap_done || fe.log_opts & ibex_config::LOG_OPT_ASAP != 0 { l.ms(l.data.or(Some(crate::txnlog::loop_now()))) } else { l.ms(Some(crate::txnlog::loop_now())) },
        plus: fe.log_opts & ibex_config::LOG_OPT_ASAP != 0,
        status: stream_status(s),
        bytes_out: stream_bytes_out(s),
        bytes_in: stream_bytes_in(s),
        // `%tsc`'s cookie characters: only a backend with a cookie mode shows them.
        cookie_state: match (&be.cookie, s.txn.as_ref()) {
            (Some(c), Some(t)) if c.rewrite || c.indirect || c.insert || c.prefix => t.ck.log_chars(),
            _ => *b"--",
        },
        actconn: u64::from(crate::globalconn::current()),
        feconn: sum(fe),
        retries: i64::from(s.max_retries.saturating_sub(s.conn_retries)),
        redispatched: s.log.redispatched,
        uniq_id: l.uniq_id,
        be_queue: u64::from(l.be_queue),
        log_counter: fe.log_count.load(Ordering::Relaxed),
        pid,
        hostname: log_hostname(),
        request_line: l.request_line.as_deref(),
        req_captures: (!fe.req_capture_slots.is_empty()).then_some(l.req_captures.as_slice()),
        res_captures: (!fe.res_capture_slots.is_empty()).then_some(l.res_captures.as_slice()),
        unique_id: l.unique_id.as_deref(),
        ..crate::logfmt::LogData::default()
    }
}

/// Adds a finished stream to the counters `show stat` prints (T165), once. Called where the
/// stream's log line is made, whether or not it logs: the frontend counts every request it
/// took (the one it could not parse included), the backend the ones routed to it, and the
/// server the ones it was given.
fn account_stream(entry: &mut SessionEntry, proxies: &[Proxy]) {
    if entry.stats_done {
        return;
    }
    entry.stats_done = true;
    let http = entry.sess.mode == Mode::Http;
    // `show info` `CumStreams`: `HAProxy` makes a stream for a TCP session at once, and for
    // HTTP only once a request was parsed (`stream_new`); a probe, an unparsable request,
    // a 408 or garbage to an h2 bind never had one.
    if !http || entry.sess.log.request.is_some() {
        crate::statcnt::add(&crate::stats::CUM_STREAMS, 1);
    }
    // Only what the counters need of the log line's data: the whole `LogData` costs a
    // measurable share of a request (T172).
    let s = &entry.sess;
    let l = &s.log;
    let term = term_state(entry);
    let routed = !http || (l.request.is_some() && !matches!(&term, b"PR" | b"LR"));
    let status = stream_status(s);
    // A request lost on a kept server connection has status 0 in `HAProxy`, which counts
    // no response for it, and no backend request (`stream.c`, at the stream's end).
    let keepalive_lost = s.txn.as_ref().is_some_and(|t| t.keepalive_lost);
    let client_reset = s.ending == Some(crate::proxy::Ending::ClientAbort);
    let (bin, bout) = (stream_bytes_in(s), stream_bytes_out(s));
    let (t_queue, t_connect, t_data) = (l.ms(l.queue), l.ms(l.connect), l.ms(l.data));
    let t_request = l.ms(l.request).max(0);
    let tw = if t_queue >= 0 { t_queue - t_request } else { -1 };
    let tc = if t_connect >= 0 { t_connect - t_queue } else { -1 };
    let tr = if t_data >= 0 { t_data - t_connect } else { -1 };
    let ta = l.ms(Some(crate::txnlog::loop_now()));
    let answered = entry.sess.log.data.is_some();
    let srv_idx = entry.target_server_idx.filter(|_| routed);
    let be_idx = entry.backend_idx;
    let srv_be = entry.srv_backend_idx;

    let fe = &proxies[entry.proxy_idx].txn_counters().fe;
    if http {
        crate::statcnt::add(&fe.req_tot, 1);
        if !keepalive_lost {
            fe.count_status(status);
        }
        if entry.sess.log.request.is_none() {
            crate::statcnt::add(&fe.ereq, 1);
        }
    }
    crate::statcnt::add_nz(&fe.bin, bin);
    crate::statcnt::add_nz(&fe.bout, bout);

    if !routed {
        return;
    }
    let now_ms = crate::statcnt::now_ms();
    let now = RateCtr::at(now_ms);
    // A server counts each attempt made on it where it is made (`srv_inc_sess_ctr`): the
    // retries that failed on other servers, or on this one, were counted there already
    // ([`count_failed_attempt`]); this is the last attempt.
    let one = |c: &crate::statcnt::TxnCounters, server: bool| {
        crate::statcnt::add(&c.stot, 1);
        crate::statcnt::add_nz(&c.bin, bin);
        crate::statcnt::add_nz(&c.bout, bout);
        if http && (!server || answered) && !keepalive_lost {
            crate::statcnt::add(&c.req_tot, 1);
            c.count_status(status);
        }
        // Which side's fault, as `HAProxy`'s termination code counts it (measured on
        // 3.5-dev8-885761-29: `SH` adds two to `eresp`, `sH` one, `SD` one to `eresp` and
        // one to `srv_abrt`, `sD` one to `srv_abrt`, `PH` two to `eresp`). A client that
        // leaves (T227): `CC` and a closed `CQ` count nothing, a reset `CQ` one; a reset
        // while the response head was awaited (`CD` 400) counts twice, once by the request
        // analyser and once by the response's.
        // A request lost on a kept server connection, closed or reset alike: one of each.
        let (abrt_cli, abrt_srv, eresp) = match &term {
            _ if keepalive_lost => (0, 1, 1),
            b"SH" | b"PH" => (0, 0, 2),
            b"sH" => (0, 0, 1),
            b"SD" => (0, 1, 1),
            b"sD" => (0, 1, 0),
            b"CC" => (0, 0, 0),
            b"CQ" => (u64::from(client_reset), 0, 0),
            b"CD" | b"CL" if status == 400 => (2, 0, 0),
            [b'C', _] => (1, 0, 0),
            _ => (0, 0, 0),
        };
        // Most streams end cleanly: skip the locked add of a zero.
        if abrt_cli != 0 {
            crate::statcnt::add(&c.cli_abrt, abrt_cli);
        }
        if abrt_srv != 0 {
            crate::statcnt::add(&c.srv_abrt, abrt_srv);
        }
        if eresp != 0 {
            crate::statcnt::add(&c.eresp, eresp);
        }
        // `econ` is counted where the last connect fails (`server_connect_failed`), as
        // `HAProxy` counts it in `back_handle_st_cer`, whatever the termination code.
        // Timings count once the connection is made and the response head has come
        // (`stream_update_time_stats`).
        if tc >= 0 && (tr >= 0 || !http) {
            let ms = |v: i64| u64::try_from(v).unwrap_or(0);
            let counted = if http { c.req_tot.load(Ordering::Relaxed) } else { c.lbtot.load(Ordering::Relaxed) };
            c.qtime.add(ms(tw), counted);
            c.ctime.add(ms(tc), counted);
            c.rtime.add(if http { ms(tr) } else { 0 }, counted);
            c.ttime.add(ms(ta), counted);
        }
        c.last_sess.store(now_ms, Ordering::Relaxed);
        c.sess_rate.tick_at(now);
        let rate = u32::try_from(c.sess_rate.rate_at(now)).unwrap_or(u32::MAX);
        if rate > c.rate_max.load(Ordering::Relaxed) {
            crate::statcnt::max(&c.rate_max, rate);
        }
    };
    let be = &proxies[be_idx];
    let c = &be.txn_counters().be;
    let picked = srv_idx.is_some() && entry.sess.lb_picked;
    if picked {
        crate::statcnt::add(&c.lbtot, 1);
    }
    one(c, false);
    let srv = srv_idx.and_then(|i| Some((i, proxies[srv_be].txn_counters().srv.get(i)?)));
    for (i, c) in srv {
        if picked {
            crate::statcnt::add(&c.lbtot, 1);
        }
        one(c, true);
        let now_on = proxies[srv_be].server_actconn.get(i).map_or(0, |a| a.load(Ordering::Relaxed));
        crate::statcnt::max(&c.smax, now_on);
    }
}

/// A frontend's `error-log-format` and `log-format-sd`, compiled once with the configuration.
#[derive(Debug, Clone, Default)]
pub struct ExtraLogFormats {
    /// The line for a connection that fails before a stream exists, in place of `HAProxy`'s
    /// plain error line (a TLS handshake, a PROXY header) or of `log_format` (a request the
    /// mux refuses).
    pub error: Option<Arc<crate::logfmt::LogFormat>>,
    /// The STRUCTURED-DATA of the frontend's stream and error lines. Kept only while one of
    /// its log targets writes an rfc5424 header ([`resolve_log_targets`]), so it is rendered
    /// only for a line that has somewhere to carry it.
    pub sd: Option<Arc<crate::logfmt::LogFormat>>,
}

/// `None` when the section has neither.
fn extra_log_formats(error: Option<&str>, sd: Option<&str>) -> Option<Box<ExtraLogFormats>> {
    let (error, sd) = (error.and_then(compile_format), sd.and_then(compile_format));
    (error.is_some() || sd.is_some()).then(|| Box::new(ExtraLogFormats { error, sd }))
}

impl Proxy {
    /// `error-log-format`.
    #[must_use]
    pub fn error_log_format(&self) -> Option<&crate::logfmt::LogFormat> {
        self.extra_log.as_ref()?.error.as_deref()
    }

    /// `log-format-sd`, when one of the proxy's targets writes it.
    #[must_use]
    pub fn log_format_sd(&self) -> Option<&crate::logfmt::LogFormat> {
        self.extra_log.as_ref()?.sd.as_deref()
    }
}

/// The stream's log line, when its frontend logs (`HAProxy` logs nothing without a
/// `log` target).
///
/// With it, whether the stream failed (`strm_log`'s `err`): a redispatch or a retry, a
/// termination state that names a fault (anything but `-` and `L`), or a 5xx status. A
/// stream that did not fail has no line under `option dontlog-normal`.
fn stream_log_line(entry: &SessionEntry, proxies: &[Proxy], pid: u32) -> Option<(Vec<u8>, u32, bool)> {
    let fe = &proxies[entry.proxy_idx];
    // A request the mux refused (400, 408, 501: `<BADREQ>`) never became a stream, and
    // `HAProxy` logs it with `error-log-format` when there is one (`_sess_log`, not
    // embryonic), whatever the `log-format`.
    let refused = entry.sess.mode == Mode::Http && entry.sess.log.request.is_none();
    let fmt = fe.error_log_format().filter(|_| refused).or(fe.log_format.as_deref())?;
    if fe.log_target_idx.is_empty() || entry.sess.log.asap_done {
        return None;
    }
    // `abort_keep_alive` clears the stream's log (`logwait`, `level`): the client retries,
    // and the retry is the request that gets logged (T229).
    if entry.sess.txn.as_ref().is_some_and(|t| t.keepalive_lost) {
        return None;
    }
    let be = proxies.get(entry.backend_idx).unwrap_or(fe);
    // `status` is the transaction's (`txn->status`, as `%ST`), not whatever response the
    // thread rewrote last (T152).
    // A stream that never had a transaction (an aborted or timed-out connection, a bad
    // request) has no status for a fetch: `%[status]` and `%[txn.status]` are empty there,
    // while `%ST` still reports the 400 or 408.
    let txn_status = entry.sess.txn.as_ref().map(|t| t.status).filter(|&s| s > 0);
    let status = txn_status.or(entry.sess.log.status.filter(|&s| s > 0));
    let term = term_state(entry);
    let err = (term[0] != b'-' && term[0] != b'L')
        || (term[0] == b'-' && entry.sess.max_retries > entry.sess.conn_retries)
        || (entry.sess.mode == Mode::Http && status.is_some_and(|s| s >= 500));
    if !err && fe.log_opts & ibex_config::LOG_OPT_DONTLOG_NORMAL != 0 {
        return None;
    }
    // `%sc` counts the other streams on the server: `HAProxy` logs after this one has
    // let go of it (measured: `1/1/0/0/0` for a lone request on a one-server backend).
    let mut data = stream_log_data(entry, proxies, entry.proxy_idx, pid);
    if entry.target_server_idx.is_some() && !entry.actconn_reclaimed {
        data.srvconn = data.srvconn.saturating_sub(1);
    }
    let (view, stick) = (ProxiesView(proxies), StickView::new(proxies, &entry.sess.tracked_sc));
    // The thread-locals hold whatever response this thread handled last, a sibling stream's
    // included (T467): this stream's own status and Tr are the ones the fetches give.
    CURRENT_SRV_STATUS.set(entry.sess.log.srv_status);
    let tr = entry.sess.log.data.zip(entry.sess.log.connect).map(|(d, c)| d.saturating_duration_since(c).as_millis());
    CURRENT_RES_TR.set(tr.map_or(-1, |ms| i64::try_from(ms).unwrap_or(i64::MAX)));
    let ctx = SampleContext { at_log: true, res_status: txn_status, ..stream_sample_ctx(&entry.sess, fe, be, &view, &stick) };
    let (line, sd) = with_sd(fe.log_format_sd(), fmt, &data, &ctx);
    fe.log_count.fetch_add(1, Ordering::Relaxed);
    Some((line, sd, err))
}

/// `fmt` rendered, after the frontend's `log-format-sd` when it has one to send: one buffer,
/// the STRUCTURED-DATA its first `sd_len` bytes (`send_log` splits it).
fn with_sd(sd: Option<&crate::logfmt::LogFormat>, fmt: &crate::logfmt::LogFormat, data: &crate::logfmt::LogData, ctx: &SampleContext) -> (Vec<u8>, u32) {
    let Some(sd) = sd else {
        return (fmt.render_line(data, sample_registry(), ctx), 0);
    };
    let mut line = sd.render_line(data, sample_registry(), ctx);
    let sd_len = u32::try_from(line.len()).unwrap_or(0);
    fmt.render_append(&mut line, data, sample_registry(), ctx);
    (line, sd_len)
}

/// Queues the stream's log line, with the level it goes out at, on `entry`.
fn set_stream_log(entry: &mut SessionEntry, proxies: &[Proxy], pid: u32) {
    account_stream(entry, proxies);
    // `option logasap` sent this stream's line with its response head; it may not have gone
    // out yet, and nothing replaces it.
    if entry.sess.log.asap_done {
        return;
    }
    match stream_log_line(entry, proxies, pid) {
        Some((line, sd, err)) => (entry.log_line, entry.log_sd, entry.log_err) = (Some(line), sd, err),
        None => entry.log_line = None,
    }
    leave_backend(entry, proxies);
}

/// How an HTTP/2 connection that ends without ever opening a stream is logged, as
/// `HAProxy`'s h2 mux logs it (`h2_sess_log_conn`, `src/mux_h2.c`, measured in
/// `tests/h2_connection_end_log.rs`): `None` for any other connection, `Some(true)` for a
/// `0 PR--` line, `Some(false)` for none.
///
/// After the preface, only a connection error the mux raised is logged (Ibex's GOAWAY with
/// an error code: a malformed SETTINGS, HEADERS on an even stream; a bad preface after ALPN
/// `h2`, which `process_cli_io` records the same way); a close, a reset, a failed TLS
/// record or `timeout client` is not. `HAProxy` logs most of its connection errors, not all
/// (not a zero `WINDOW_UPDATE` increment); Ibex logs every one. Before the whole preface (ALPN
/// `h2`): a close or reset is logged, except with nothing received under `option
/// dontlognull` or `option http-ignore-probes`; a failed connection or a timeout is not.
/// The length of the empty lines (CRLF or LF) at the start of `buf`.
fn leading_empty_lines(buf: &[u8]) -> usize {
    let mut i = 0;
    loop {
        match buf.get(i..) {
            Some([b'\n', ..]) => i += 1,
            Some([b'\r', b'\n', ..]) => i += 2,
            _ => return i,
        }
    }
}

fn h2_no_stream_end(s: &TcpSession, fe: &Proxy) -> Option<bool> {
    if let Some(h2) = s.h2_ctx.as_ref() {
        if h2.highest_opened != 0 || !h2.streams.is_empty() {
            return None;
        }
        return Some(h2.goaway_sent.is_some_and(|(_, e)| e != ibex_proto::h2::H2Error::NoError));
    }
    if !s.h2_preface_pending() {
        return None;
    }
    let read0 = !s.cli_failed && matches!(s.ending, None | Some(crate::proxy::Ending::ClientAbort));
    Some(read0 && !(s.req.is_empty() && (fe.dont_log_null || fe.ignore_probes)))
}

/// Why a connection that was to open with a PROXY header did not get past it, if that is
/// what happened: the parser's refusal, or the client closing, resetting or timing out
/// before sending one.
fn proxy_header_failure(s: &TcpSession) -> Option<crate::proxy::ProxyHdrError> {
    use crate::proxy::{Ending, ProxyHdrError};
    if s.proxy_hdr_err.is_some() {
        return s.proxy_hdr_err;
    }
    if !s.accept_proxy || s.proxy_handshake_done {
        return None;
    }
    // The header's reads end in `proxy_hdr_err` themselves; what is left is the timer.
    matches!(s.ending?, Ending::Timeout(crate::proxy::Which::Client)).then_some(ProxyHdrError::Timeout)
}

/// Why a connection ended before a session began: the message of `HAProxy`'s line, whether
/// `option dontlognull` drops it, and what `fc_err` and the like read in an
/// `error-log-format`.
struct EmbryonicFailure {
    message: String,
    null: bool,
    code: i64,
    name: &'static str,
    text: &'static str,
    tls: bool,
    ssl: Option<(i64, String)>,
}

impl EmbryonicFailure {
    fn conn_err(&self) -> ibex_sample::ConnErr<'_> {
        ibex_sample::ConnErr {
            code: self.code,
            text: self.text,
            name: self.name,
            tls: self.tls,
            ssl_code: self.ssl.as_ref().map_or(0, |(c, _)| *c),
            ssl_text: self.ssl.as_ref().map(|(_, t)| t.as_str()),
        }
    }
}

/// Why a connection ended before a session began, if that is what happened: a bad PROXY
/// header, or a TLS handshake that failed.
fn embryonic_failure(s: &TcpSession) -> Option<EmbryonicFailure> {
    if let Some(why) = proxy_header_failure(s) {
        return Some(EmbryonicFailure {
            message: why.message().to_string(),
            null: why.is_null(),
            code: why.code(),
            name: why.name(),
            text: why.message(),
            tls: false,
            ssl: None,
        });
    }
    s.hs_fail().map(|f| EmbryonicFailure {
        message: f.message(),
        null: f.is_null(),
        code: f.code(),
        name: f.name(),
        text: f.text(),
        tls: true,
        ssl: f.openssl_error().map(|(c, t)| (c, t.to_string())),
    })
}

/// `HAProxy`'s own line for a connection that failed before its session began
/// (`session_kill_embryonic`): only for a frontend that logs, and not for the empty cases
/// under `option dontlognull`. Its text is `error-log-format` when the frontend has one
/// (compiled at load, rendered here with what the connection knows), else the plain
/// `<src>:<port> [<date>] <fe>/<listener>: <message>`, never the frontend's `log-format`.
/// A frontend logs it when it has any format: a `log-format`, an `error-log-format` or a
/// `log-format-sd`, its own or the default of an rfc5424 target (measured: with `log` and
/// none of them, a line only on an rfc5424 target).
fn proxy_header_error_line(entry: &SessionEntry, proxies: &[Proxy], pid: u32) -> Option<(Vec<u8>, u32)> {
    let failure = embryonic_failure(&entry.sess)?;
    let fe = &proxies[entry.proxy_idx];
    if fe.log_target_idx.is_empty() || (fe.dont_log_null && failure.null) {
        return None;
    }
    // `to_log` (`session_kill_embryonic`): set by every format the frontend compiles,
    // `log-format-sd` and the default one an rfc5424 target brings included.
    if fe.log_format.is_none() && fe.extra_log.is_none() {
        return None;
    }
    let s = &entry.sess;
    let data = crate::logfmt::LogData {
        term_state: *b"PR",
        status: 0,
        t_idle: 0,
        ..session_log_data(s, fe, fe, pid)
    };
    let (view, stick) = (ProxiesView(proxies), StickView::new(proxies, &s.tracked_sc));
    // No stream, so no backend either: `be_name` has no value in `HAProxy`'s line.
    let ctx = SampleContext { at_log: true, conn_err: Some(failure.conn_err()), be_name: None, be_id: None, ..stream_sample_ctx(s, fe, fe, &view, &stick) };
    let line = match fe.error_log_format() {
        Some(elf) => with_sd(fe.log_format_sd(), elf, &data, &ctx),
        None => {
            // The plain line has the frontend's `log-format-sd` in front of it too.
            let mut line = fe.log_format_sd().map_or_else(Vec::new, |sd| sd.render_bytes(&data, sample_registry(), &ctx));
            let sd_len = u32::try_from(line.len()).unwrap_or(0);
            let listener = s.so_name.as_deref().map_or_else(|| s.so_id.unwrap_or(0).to_string(), str::to_string);
            line.extend_from_slice(crate::logfmt::connection_error_line(s.client_addr, s.log.date(), &fe.name, &listener, &failure.message).as_bytes());
            (line, sd_len)
        }
    };
    fe.log_count.fetch_add(1, Ordering::Relaxed);
    Some(line)
}

fn syslog_tag(tag: &str) -> Arc<str> {
    format!("{tag}[{}]", std::process::id()).into()
}

/// Builds the syslog targets and points every proxy at the ones its section resolved to.
///
/// `HAProxy` resolves logging per proxy: a section's own `log <addr>` lines apply, `log
/// global` adds whatever the `global` section declared, and a section that says nothing
/// inherits `defaults`. Resolution has to happen after every section is parsed, because
/// `log global` names a section that may be read later, which is why the proxy
/// constructors leave `log_target_idx` empty.
///
/// Targets are deduplicated by address and facility so two sections pointing at the same
/// collector share one socket rather than opening one each -- at 60k backends that
/// distinction is the difference between one fd and thousands.
fn resolve_log_targets(config: &Config, proxies: &mut [Proxy]) -> Vec<SyslogTarget> {
    let mut targets: Vec<SyslogTarget> = Vec::new();
    let intern = |cfg: &ibex_config::LogConfig, targets: &mut Vec<SyslogTarget>| -> usize {
        // Interned by target and facility, so two sections naming the same collector
        // share one socket. `stdout` and `stderr` intern too: a descriptor written from
        // two places interleaves partial lines.
        if let Some(i) = targets
            .iter()
            .position(|t| t.same_logger(cfg))
        {
            return i;
        }
        targets.push(SyslogTarget::new(cfg));
        targets.len() - 1
    };

    let global: Vec<usize> = config
        .global
        .iter()
        .flat_map(|g| g.logs.iter())
        .map(|c| intern(c, &mut targets))
        .collect();
    let defaults_log_health = config
        .defaults
        .as_ref()
        .is_some_and(|d| d.log_health_checks);

    // A section's own directives, in config order.
    let mut own: Vec<(String, Vec<usize>, bool)> = Vec::new();
    for l in &config.listens {
        let idx = l.logs.iter().map(|c| intern(c, &mut targets)).collect();
        own.push((l.name.clone(), idx, l.log_global));
    }
    for f in &config.frontends {
        let idx = f.logs.iter().map(|c| intern(c, &mut targets)).collect();
        own.push((f.name.clone(), idx, f.log_global));
    }
    for b in &config.backends {
        let idx = b.logs.iter().map(|c| intern(c, &mut targets)).collect();
        own.push((b.name.clone(), idx, b.log_global));
    }

    // First section of a name wins, as the linear `find` this replaces did: sorting by
    // (name, position) puts it first among equals.
    let mut by_name: Vec<(&str, usize)> = own.iter().enumerate().map(|(i, (n, _, _))| (n.as_str(), i)).collect();
    by_name.sort_unstable();
    for proxy in proxies.iter_mut() {
        let at = by_name.partition_point(|&(n, _)| n < proxy.name.as_str());
        let Some((_, idx, log_global)) = by_name
            .get(at)
            .filter(|&&(n, _)| n == proxy.name.as_str())
            .map(|&(_, i)| &own[i])
        else {
            continue;
        };
        let mut resolved = idx.clone();
        if *log_global {
            resolved.extend_from_slice(&global);
        }
        // The parser copied `defaults`' `log` lines into the section (and `no log` cleared
        // them), so nothing is inherited here.
        resolved.sort_unstable();
        resolved.dedup();
        // Kept when already there, so the cursors stay the ones every user shares.
        if proxy.log_cursors.len() != resolved.len() {
            proxy.log_cursors = Arc::new(resolved.iter().map(|_| AtomicU64::new(0)).collect());
        }
        proxy.log_target_idx = resolved;
        // `log-format-sd` fills only an rfc5424 header's STRUCTURED-DATA: a proxy none of
        // whose targets writes one never renders it. A frontend with such a target and no
        // `log-format-sd` gets `HAProxy`'s default one (`- `, which Ibex writes as an empty
        // field), and with it a line for a connection that fails before its session
        // (`to_log`, see [`proxy_header_error_line`]).
        if proxy.log_target_idx.iter().any(|&i| targets[i].writes_sd()) {
            if proxy.has_frontend {
                proxy.extra_log.get_or_insert_with(Box::default);
            }
        } else if let Some(extra) = proxy.extra_log.as_mut() {
            extra.sd = None;
        }

        if defaults_log_health {
            proxy.log_health_checks = true;
        }
    }

    targets
}

/// Loads every TLS bind in the config without binding a port.
///
/// `-c` used to return "Configuration file is valid" without ever touching the
/// certificates, because it exits before `Engine::new`. A missing or unreadable `crt`
/// then passed validation in CI and failed at startup in production, which is the worst
/// place to find out. `HAProxy`'s `-c` loads them, so this does too.
///
/// # Errors
///
/// The first bind whose certificates cannot be loaded, with the frontend and address
/// named.
pub fn validate_tls(config: &Config) -> io::Result<()> {
    crate::logfwd::check_debug_sinks(config)?;
    crate::crypto_provider::apply(config)?;
    for fe in &config.frontends {
        if fe.disabled {
            continue;
        }
        for bind in fe.binds.iter().filter(|b| b.ssl) {
            if bind.quic {
                bind_tls_quic(&fe.name, &fe.binds, bind.addr)?;
            } else {
                bind_tls(&fe.name, &fe.binds, bind.addr)?;
            }
        }
    }
    // A `disabled` listen is checked too: `HAProxy` loads its certificates at parse time.
    for l in &config.listens {
        for bind in l.binds.iter().filter(|b| b.ssl) {
            if bind.quic {
                bind_tls_quic(&l.name, &l.binds, bind.addr)?;
            } else {
                bind_tls(&l.name, &l.binds, bind.addr)?;
            }
        }
    }
    // Servers: `ca-file`, `crl-file` and `crt` are opened, and the `sni` expression
    // parsed, as `ssl_sock_prepare_srv_ctx` does at load.
    let servers = config
        .listens
        .iter()
        .map(|l| (&l.name, &l.servers, l.mode))
        .chain(config.backends.iter().map(|b| (&b.name, &b.servers, b.mode)));
    for (name, servers, mode) in servers {
        for s in servers {
            let who = format!("'server {}/{}'", name, s.id);
            crate::srv_tls::ServerTls::from_server(s, mode == Mode::Http, &who)?;
            crate::srv_tls::CheckTls::from_server(s, &who)?;
        }
    }
    Ok(())
}

/// Builds the TLS configuration for one bind, or `None` when it is plaintext.
///
/// # Errors
///
/// Every failure here is fatal by design, and the reason is the whole point of this
/// function: an operator who wrote `ssl` on a bind believes that port is encrypted. If a
/// certificate is missing, unreadable, or has no key, the only two things we can do are
/// refuse to start or listen on :443 and serve cleartext to clients that think they
/// negotiated TLS. The second is worse than being down -- it is being down while looking
/// fine, with credentials going over the wire in the clear -- so this returns an error
/// and `Engine::new` propagates it.
///
/// `ssl` with no `crt` is the same class of mistake and is refused for the same reason.
fn bind_tls(
    section: &str,
    binds: &[ibex_config::ast::BindConfig],
    addr: SocketAddr,
) -> io::Result<Option<Arc<ibex_tls::tcp::BindTls>>> {
    bind_tls_with(section, binds, addr, false, ibex_tls::tcp::from_bind_config)
}

/// [`bind_tls`] for a QUIC bind: the same rustls 0.24 configuration as TCP's, TLS 1.3 only
/// (`BindPlan::versions` of a `quic` bind), on the provider a swap makes current (T461).
fn bind_tls_quic(
    section: &str,
    binds: &[ibex_config::ast::BindConfig],
    addr: SocketAddr,
) -> io::Result<Option<Arc<ibex_tls::tcp::BindTls>>> {
    bind_tls_with(section, binds, addr, true, ibex_tls::tcp::from_bind_config)
}

/// Opens one `quic` bind of a frontend or a `listen` (T530): this worker's UDP socket, handed to
/// the proxy's stream engine, in the poller. The proxy index is what `ql.set_frontend` reads.
#[allow(clippy::too_many_arguments)]
fn open_quic_bind(
    config: &Config,
    worker_id: usize,
    bufsize: usize,
    b: &ibex_config::ast::BindConfig,
    tls: &Arc<ibex_tls::tcp::BindTls>,
    proxy_idx: usize,
    quic_listeners: &mut Vec<crate::quic_listener::QuicListener>,
    fdtab: &mut FdTab,
    poller: &Poller,
) -> io::Result<()> {
    // `tune.quic.listen off`: `protocol_may_bind_quic` is false, a QUIC bind gets no socket
    // (T525), for a `listen` as for a frontend; the proxy's other binds are served.
    if config.global.as_ref().and_then(|g| g.quic_listen) == Some(false) {
        return Ok(());
    }

    // Each request is handed to this frontend's stream engine (T130). It
    // used to go straight to the first server of the default backend, and
    // no rule, `use_backend`, balancing or log line ever saw it.
    // `quic-force-retry` and `tune.quic.fe.sec.retry-threshold` (T492); windows from
    // `tune.bufsize`, as HAProxy's (h3-engine design 2.3): 100 streams of `bufsize - 4`,
    // 90 % of it for one (T504).
    let mut qc = ibex_quic::QuicConfig::new().with_flow_windows(bufsize, 100, 90);
    qc.require_retry = b.sock.as_ref().is_some_and(|s| s.quic_force_retry);
    if let Some(n) = config.global.as_ref().and_then(|g| g.quic_retry_threshold) {
        qc.retry_threshold = n;
    }
    // T525: the transport parameters sent to a client. `max_streams_bidi` is the
    // smaller of `max-concurrent` and `max-total` (`quic_transport_params_init`).
    let g = config.global.as_ref();
    if let Some(ms) = g.and_then(|g| g.quic_max_idle_timeout) {
        // 0 sends no parameter: no transport idle timeout.
        qc.max_idle_timeout = (ms != 0).then(|| Duration::from_millis(u64::from(ms)));
    }
    // Q0: `tune.ibex.quic-ack-frequency` and its two parameters (default off, 2, 25 ms) reach
    // `QuicConfig::ack_frequency`, then `TransportConfig::ack_frequency_config`.
    crate::stats::QUIC_ACK_FREQUENCY_ON.store(g.and_then(|g| g.quic_ack_frequency) == Some(true), Ordering::Relaxed);
    if g.and_then(|g| g.quic_ack_frequency) == Some(true) {
        let threshold = g.and_then(|g| g.quic_ack_frequency_threshold).unwrap_or(2);
        let delay = g.and_then(|g| g.quic_ack_frequency_max_delay_ms).unwrap_or(25);
        qc.ack_frequency = Some((threshold, Duration::from_millis(u64::from(delay))));
    }
    let total = g.and_then(|g| g.quic_stream_max_total).unwrap_or(0);
    let mut streams = g.and_then(|g| g.quic_stream_max_concurrent).unwrap_or(100);
    if total != 0 {
        streams = streams.min(total);
    }
    qc.max_concurrent_bidi_streams = u64::from(streams);
    let mut ql = crate::quic_listener::QuicListener::bind_for_worker(b.addr, tls, Some(qc), Some(worker_id))?;
    ql.set_frontend(proxy_idx);
    ql.gate_connections();
    ql.set_stream_max_total(total);
    if h3_mux(config.global.as_ref().and_then(|g| g.h3_mux)) {
        ql.serve_by_mux();
    }

    let l_idx = quic_listeners.len();
    let lfd = ql.raw_fd();
    fdtab.insert(
        lfd,
        FdState::QuicListener { listener: usize_to_u32(l_idx) },
        Interest::READ,
    );
    poller.add(ql.borrowed_fd(), raw_fd_to_u64(lfd), true, false)?;
    quic_listeners.push(ql);
    Ok(())
}

/// The `ssl` bind at `addr` of the given transport: a TCP and a `quic` bind may share an
/// ip:port, each with its own certificates, ALPN and TLS versions (T494).
fn bind_tls_with<T>(
    section: &str,
    binds: &[ibex_config::ast::BindConfig],
    addr: SocketAddr,
    quic: bool,
    build: fn(&ibex_config::ast::BindConfig) -> Result<T, String>,
) -> io::Result<Option<T>> {
    let Some(bind) = binds.iter().find(|b| b.addr == addr && b.ssl && b.quic == quic) else {
        return Ok(None);
    };

    if bind.crt.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "'{section}': bind {addr} has 'ssl' but no 'crt'; refusing to start \
                 rather than serve cleartext on a port configured for TLS"
            ),
        ));
    }
    let cfg = build(bind).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{section}': bind {addr} ssl: {e}"),
        )
    })?;
    Ok(Some(cfg))
}

/// A section's timeouts. Its own `timeout` lines are in `own`; the legacy fields carry
/// only what `defaults` said when the section opened (or what a test built in code), so
/// they are the fallback. Read the other way round, `defaults` overrode the section's own
/// `timeout server`.
fn section_timeouts(
    own: &ibex_config::TimeoutConfig,
    client: Option<Duration>,
    server: Option<Duration>,
    connect: Option<Duration>,
) -> Timeouts {
    Timeouts {
        client: own.client.or(client).map_or(0, millis_to_u32),
        server: own.server.or(server).map_or(0, millis_to_u32),
        connect: own.connect.or(connect).map_or(0, millis_to_u32),
    }
}

#[allow(clippy::too_many_lines)] // a field-by-field mirror of the section
/// The state a server starts in: `disabled` is maintenance, which the CLI's `enable
/// server` ends.
fn initial_status(s: &ibex_config::Server, unresolved: bool) -> u8 {
    // A server whose name did not resolve (`init-addr none`) has no address to send to.
    if s.disabled || unresolved { ServerStatus::Maint as u8 } else { ServerStatus::Up as u8 }
}

/// The `bind` lines of a frontend, as the engine opens them: the `bind` shorthand of a
/// section built in code first, when no line has its address.
/// Binds the QUIC sockets of all `workers` for every enabled frontend's `quic` bind, before any
/// worker is started; each worker's `Engine::new_worker` then takes its own
/// ([`crate::quic_listener::prebind`] says why).
///
/// # Errors
/// The first address that cannot be bound.
pub fn prebind_quic(config: &Config, workers: usize) -> io::Result<()> {
    // `tune.quic.listen off`: no QUIC socket at all (T525).
    if config.global.as_ref().and_then(|g| g.quic_listen) == Some(false) {
        return Ok(());
    }
    let listens = config.listens.iter().filter(|l| !l.disabled).map(|l| ("listen", &l.name, l.binds.clone()));
    let frontends = config.frontends.iter().filter(|f| !f.disabled).map(|f| ("frontend", &f.name, frontend_binds(f)));
    for (kind, name, binds) in listens.chain(frontends) {
        for b in binds.iter().filter(|b| b.quic) {
            crate::quic_listener::prebind(b.addr, workers).map_err(|e| {
                // HAProxy's alert (`protocol_bind_all`: proxy type, then name), without its `[file:line]`.
                let why = e.to_string();
                let why = why.split(" (os error").next().unwrap_or(&why).to_string();
                let proto = if b.addr.is_ipv4() { "quic4" } else { "quic6" };
                io::Error::new(
                    e.kind(),
                    format!("Binding for {kind} {name}: protocol {proto}: cannot bind socket ({why}) for [{}].", b.addr),
                )
            })?;
        }
    }
    Ok(())
}

/// `-m <megs>` as `HAProxy` applies it (`compute_ideal_maxconn`, src/limits.c): the budget
/// is recorded for `show info` and `/metrics`, and sizes `global maxconn` when the
/// configuration has none; a configured one that leaves no room for TLS is refused.
/// `RLIMIT_DATA` is set apart, by `globalconn::apply_memmax_rlimit` (T465, tradeoff.md 6.25).
///
/// # Errors
/// The alert text `HAProxy` exits 1 with.
pub fn apply_memmax(config: &mut Config) -> Result<(), String> {
    let Some(g) = config.global.as_mut() else { return Ok(()) };
    let Some(megs) = g.memmax_mb else { return Ok(()) };
    crate::globalconn::set_memmax_mb(megs);
    let bind_ssl = config.listens.iter().any(|l| l.binds.iter().any(|b| b.ssl))
        || config.frontends.iter().any(|f| frontend_binds(f).iter().any(|b| b.ssl));
    let server_ssl = config.backends.iter().flat_map(|b| &b.servers).chain(config.listens.iter().flat_map(|l| &l.servers)).any(|s| s.ssl.as_ref().is_some_and(|x| x.ssl));
    let sides = u64::from(bind_ssl) + u64::from(server_ssl);
    let bufsize = g.bufsize.map_or(16384, |b| b as u64);
    // `tune.ssl.cachesize` is not configurable in Ibex: SSLCACHESIZE (defaults.h:515).
    let maxconn = crate::globalconn::memmax_maxconn(megs, g.maxconn, sides, bufsize, 20000)?;
    g.maxconn = Some(maxconn);
    Ok(())
}

/// Settles `global maxconn` for `config` ([`crate::globalconn::configure`]), leaving room for
/// its listeners. Startup calls it before [`config_maxsock`] raises the file descriptor
/// limit, which `build_shared_state` now follows (it binds the `log-forward` sockets after
/// the old process handed them over); `build_shared_state` calls it again for a reload.
pub fn configure_maxconn(config: &Config) {
    let (listeners, stats_socket) = listener_count(config);
    crate::globalconn::configure(config.global.as_ref().and_then(|g| g.maxconn), listeners, stats_socket);
}

/// The listeners a configuration opens, stats sockets included, and whether it has a stats
/// socket: what `maxconn` and `maxsock` leave room for.
/// `global.maxsock` for `config` run by `workers` threads, `global maxconn` as
/// [`crate::globalconn::configure`] settled it.
#[must_use]
pub fn config_maxsock(config: &Config, workers: usize) -> usize {
    let (listeners, stats_socket) = listener_count(config);
    let checks = config.backends.iter().flat_map(|b| &b.servers).chain(config.listens.iter().flat_map(|l| &l.servers)).filter(|s| s.check).count();
    crate::globalconn::maxsock(crate::globalconn::hard(), listeners, stats_socket, checks, workers.max(1))
}

fn listener_count(config: &Config) -> (usize, bool) {
    let stats_sockets = config.global.as_ref().map_or(0, |g| usize::from(g.stats_socket.is_some()) + g.extra_stats_sockets.len());
    let listeners = stats_sockets
        + config.listens.iter().map(|l| l.binds.len()).sum::<usize>()
        + config.frontends.iter().map(|f| frontend_binds(f).len()).sum::<usize>();
    (listeners, stats_sockets > 0)
}

fn frontend_binds(frontend: &ibex_config::FrontendSection) -> Vec<ibex_config::ast::BindConfig> {
    let mut all_binds = frontend.binds.clone();
    if let Some(ba) = frontend.bind {
        if !all_binds.iter().any(|b| b.addr == ba) {
            all_binds.insert(0, ibex_config::ast::BindConfig {
                sock: None,
                line: 0,
                addr: ba,
                quic: false,
                ssl: false,
                crt: vec![],
                alpn: vec![],
                proto: None,
                accept_proxy: frontend.accept_proxy,
                accept_proxy_v2: frontend.accept_proxy_v2,
                name: None,
                id: None,
                min_ver: None,
                max_ver: None,
            });
        }
    }
    all_binds
}

/// The ids of the servers for [`Proxy::server_puids`]: empty when none asked for one.
fn server_puids(count: usize, extras: &ibex_config::ast::ServerExtras) -> Vec<u32> {
    if extras.puid.is_empty() { Vec::new() } else { ibex_config::ast::server_puids(count, &extras.puid) }
}

/// The values for [`Proxy::server_init_health`]: empty when all are 0.
fn server_init_health(count: usize, extras: &ibex_config::ast::ServerExtras) -> Vec<u32> {
    let mut health = Vec::new();
    for &(i, h) in &extras.init_health {
        health.resize(count, 0);
        if let Some(slot) = health.get_mut(i as usize) {
            *slot = h;
        }
    }
    health
}

/// The flags for [`Proxy::server_cmaint`]: empty when no server is `disabled` in the file.
fn server_cmaint(servers: &[ibex_config::Server]) -> Vec<bool> {
    if servers.iter().any(|s| s.disabled) { servers.iter().map(|s| s.disabled).collect() } else { Vec::new() }
}

/// The flags for [`Proxy::server_rmaint`]: one per server when an address was written as a
/// name (a resolver may take it away at run time), else empty. A `disabled` server keeps
/// `Maint` under it.
fn server_rmaint(servers: &[ibex_config::Server], extras: &ibex_config::ast::ServerExtras) -> Arc<Vec<std::sync::atomic::AtomicU8>> {
    if extras.names.is_empty() {
        Arc::default()
    } else {
        let kept = |i: usize| if servers.get(i).is_some_and(|s| s.disabled) { ServerStatus::Maint } else { ServerStatus::Up };
        Arc::new((0..servers.len()).map(|i| std::sync::atomic::AtomicU8::new(if extras.unresolved(i) { kept(i) as u8 + 1 } else { 0 })).collect())
    }
}

/// The names for [`Proxy::server_fqdn`]: empty when no address was written as one.
/// An SRV record's name is no `srv_fqdn`: the slot's target is (see [`Proxy::server_srv_fqdn`]).
fn server_fqdns(count: usize, extras: &ibex_config::ast::ServerExtras) -> Vec<Option<Box<str>>> {
    if extras.names.is_empty() { Vec::new() } else { (0..count).map(|i| extras.fqdn(i).filter(|f| !f.starts_with('_')).map(Box::from)).collect() }
}

/// [`ProxyIdInfo::server_fqdn_changed`].
fn server_fqdn_changed(count: usize, extras: &ibex_config::ast::ServerExtras) -> Vec<bool> {
    let mut out = Vec::new();
    for n in extras.names.iter().filter(|n| n.fqdn_changed) {
        out.resize(count, false);
        if let Some(slot) = out.get_mut(n.index as usize) {
            *slot = true;
        }
    }
    out
}

/// [`ProxyIdInfo::server_check_ports`].
fn server_check_ports(servers: &[ibex_config::ast::Server]) -> Vec<u16> {
    if servers.iter().all(|s| s.check_port.is_none()) {
        return Vec::new();
    }
    servers.iter().map(|s| s.check_port.unwrap_or(0)).collect()
}

/// The flags for [`Proxy::server_forced_ids`]: empty when none asked for an id.
fn server_forced_ids(count: usize, extras: &ibex_config::ast::ServerExtras) -> Vec<bool> {
    let mut forced = Vec::new();
    for &(i, _) in &extras.puid {
        forced.resize(count, false);
        if let Some(slot) = forced.get_mut(i as usize) {
            *slot = true;
        }
    }
    forced
}

fn init_proxy_from_listen(proxy_idx: usize, ids: ibex_config::ast::ProxyId, listen: &ibex_config::ListenSection) -> Proxy {
    let mut http_req_rules = listen.http_req_rules.clone();
    with_buffered_request(&mut http_req_rules, listen.buffer_request);
    let mut tcp_req_content_rules = listen.tcp_req_content_rules.clone();
    let req_capture_slots = capture_slots(&listen.req_header_captures, &mut http_req_rules, &mut tcp_req_content_rules);
    let timeouts = section_timeouts(&listen.timeouts, listen.clitimeout, listen.srvtimeout, listen.contimeout);

    let retries = u16::try_from(listen.retries).unwrap_or(u16::MAX);

    let mut cliexp = Vec::new();
    for exp in &listen.cliexp {
        if let Ok(c) = ibex_proto::CompiledExp::new(&exp.regex, &exp.replacement) {
            cliexp.push(c);
        }
    }
    let mut srvexp = Vec::new();
    for exp in &listen.srvexp {
        if let Ok(c) = ibex_proto::CompiledExp::new(&exp.regex, &exp.replacement) {
            srvexp.push(c);
        }
    }

    let stick_table = listen
        .stick_table
        .as_ref()
        .map(|ast| Arc::new(init_stick_table(ast, &listen.name)));

    let server_count = listen.servers.len();
    let server_check_configs = server_check_configs(&listen.servers, listen.timeouts.check);

    let acls = compile_acls(&listen.acls);
    let rules = Box::new(crate::rule_compiled::Rules {
        http_req: crate::rule_compiled::http_req(&http_req_rules, &acls),
        http_res: crate::rule_compiled::http_res(&listen.http_res_rules, &acls),
        http_after_res: crate::rule_compiled::http_after_res(&listen.http_after_res_rules, &acls),
        tcp_req_conn: crate::rule_compiled::tcp_req_conn(&listen.tcp_req_conn_rules, &acls),
        tcp_req_session: crate::rule_compiled::tcp_req_session(&listen.tcp_req_session_rules, &acls),
        tcp_req_content: crate::rule_compiled::tcp_req_content(&tcp_req_content_rules, &acls),
        tcp_res_content: crate::rule_compiled::tcp_res_content(&listen.tcp_res_content_rules, &acls),
        stick: crate::rule_compiled::stick(&listen.stick_rules, &acls),
        use_backend: crate::rule_compiled::use_backend(&listen.use_backends, &acls),
        use_server: crate::rule_compiled::use_server(&listen.use_servers, &acls),
        force_be: crate::rule_compiled::force_be(&listen.force_be_switch, &acls),
        reply_pages: crate::rule_compiled::reply_pages(&listen.error_replies),
        res_stream: false,
    }.finish());
    Proxy {
        id: usize_to_u32(proxy_idx),
        ids: Box::new(ProxyIdInfo {
            timeout_ms: timeouts_ms(&listen.timeouts),
            iid: ids.iid,
            decl: ids.decl,
            next_decl: 0,
            forced_id: ids.forced,
            server_puids: server_puids(listen.servers.len(), &listen.server_extras),
            server_forced_ids: server_forced_ids(listen.servers.len(), &listen.server_extras),
            server_init_health: server_init_health(listen.servers.len(), &listen.server_extras),
            server_cmaint: server_cmaint(&listen.servers),
            server_rmaint: server_rmaint(&listen.servers, &listen.server_extras),
            server_fqdns: server_fqdns(listen.servers.len(), &listen.server_extras),
            server_fqdn_changed: server_fqdn_changed(listen.servers.len(), &listen.server_extras),
            server_srv: crate::resolvers::SrvSlots::new(listen.servers.len(), &listen.server_extras),
            server_check_ports: server_check_ports(&listen.servers),
            listener_ids: ibex_config::ast::listener_ids(&listen.binds),
            server_pool: pool_cfgs(&listen.servers, listen.mode == Mode::Http),
            http_mode: listen.http_mode,
            persist: listen.persist,
            checkcache: listen.checkcache,
            retry_on: listen.retry_on,
            ..ProxyIdInfo::default()
        }),
        name: listen.name.clone(),
        has_frontend: true,
        has_backend: true,
        log_target_idx: Vec::new(),
        log_health_checks: listen.log_health_checks,
        addr: listen.addr,
        mode: listen.mode,
        balance: listen.balance,
        balance_set: listen.balance_set,
        timeouts,
        retries,
        redisp: listen.redisp,
        redisp_after: listen.redisp_after,
        maxconn: effective_fe_maxconn(listen.maxconn).into(),
        dispatch: listen.dispatch,
        cookie: listen.cookie.clone(),
        cliexp,
        srvexp,
        servers: listen.servers.iter().map(|s| s.addr).collect(),
        server_ids: listen.servers.iter().map(|s| s.id.clone()).collect(),
        server_cookies: listen.servers.iter().map(|s| s.cookie.as_deref().map(Box::from)).collect(),
        server_statuses: Arc::new(listen.servers.iter().enumerate().map(|(i, s)| AtomicU8::new(initial_status(s, listen.server_extras.unresolved(i)))).collect()),
        server_track: None,
        server_weights: listen
            .servers
            .iter()
            .map(|s| s.weight.unwrap_or(1))
            .collect(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new(vec![ProxyStats::default()]),
        desc: listen.description.as_deref().map(Box::from),
        stats_config: {
            let mut sc = listen.stats.clone();
            sc.raw_timeouts = listen.timeouts;
            sc.forwardfor.clone_from(&listen.forwardfor);
            sc.forwardfor_if_none = listen.forwardfor_if_none;
            sc.forwarded.clone_from(&listen.forwarded);
            sc.originalto.clone_from(&listen.originalto);
            sc
        },
        default_backend: listen.default_backend.clone(),
        use_backends: listen.use_backends.clone(),
        use_servers: listen.use_servers.clone(),
        force_be_switch: listen.force_be_switch.clone(),
        disabled_backends: Arc::default(),
        monitor: Monitor::boxed(listen.monitor_uri.as_deref(), &listen.monitor_fail),
        acls,
        stick_table,
        stick_rules: listen.stick_rules.clone(),
        server_send_proxy: listen.servers.iter().map(|s| s.send_proxy).collect(),
        server_tfo: listen.servers.iter().map(|s| s.tfo).collect(),
        server_send_proxy_v2: listen.servers.iter().map(|s| s.send_proxy_v2).collect(),
        server_pp_unique_id: listen.servers.iter().map(|s| s.proxy_v2_unique_id).collect(),
        server_backups: listen.servers.iter().map(|s| s.backup).collect(),
        server_maxconn: listen.servers.iter().map(|s| s.maxconn).collect(),
        server_actconn: Arc::new((0..server_count).map(|_| AtomicU32::new(0)).collect()),
        server_retr: Arc::default(),
        server_sess_rates: Arc::new((0..server_count).map(|_| RateCtr::default()).collect()),
        server_check_configs,
        server_tls: Vec::new(),
        server_check_tls: Vec::new(),
        tcp_req_conn_rules: listen.tcp_req_conn_rules.clone(),
        tcp_req_session_rules: listen.tcp_req_session_rules.clone(),
        tcp_req_content_rules,
        tcp_req_inspect_delay: listen.tcp_req_inspect_delay,
        tcp_res_content_rules: listen.tcp_res_content_rules.clone(),
        tcp_res_inspect_delay: listen.tcp_res_inspect_delay,
        rules,
        http_req_rules,
        http_res_rules: listen.http_res_rules.clone(),
        http_after_res_rules: listen.http_after_res_rules.clone(),
        http_reuse: listen.http_reuse.unwrap_or_default(),
        abortonclose: listen.abortonclose.unwrap_or(true),
        h1_adjust: listen.h1_adjust,
        h1_case: Arc::default(),
        h1_lower: false,
        error_files: listen.error_files.clone(),
        error_replies: listen.error_replies.clone(),
        log_tag: listen.log_tag.as_deref().map(syslog_tag),
        log_format: compile_log_format(listen.log_format.as_ref(), listen.mode == Mode::Http),
        dont_log_null: listen.dontlognull,
        ignore_probes: listen.http_ignore_probes,
        log_opts: listen.log_opts,
        unique_id_format: listen.unique_id_format.as_deref().and_then(compile_unique_id_format),
        extra_log: extra_log_formats(listen.error_log_format.as_deref(), listen.log_format_sd.as_deref()),
        unique_id_header: listen.unique_id_header.as_deref().map(Box::from),
        req_capture_slots,
        res_capture_slots: listen.res_header_captures.iter().map(|c| (c.name.clone(), c.len)).collect(),
        log_count: Arc::default(),
        log_cursors: Arc::default(),
        hash_type: listen.hash_type.unwrap_or_default(),
        hash_preserve_affinity: listen.hash_preserve_affinity.unwrap_or_default(),
        chash: Arc::default(),
        fwrr: Arc::default(),
    }
}

fn init_proxy_from_frontend(proxy_idx: usize, ids: ibex_config::ast::ProxyId, fe: &ibex_config::FrontendSection) -> Proxy {
    let mut http_req_rules = fe.http_req_rules.clone();
    with_buffered_request(&mut http_req_rules, fe.buffer_request);
    let mut tcp_req_content_rules = fe.tcp_req_content_rules.clone();
    let req_capture_slots = capture_slots(&fe.req_header_captures, &mut http_req_rules, &mut tcp_req_content_rules);
    let timeouts = section_timeouts(&fe.timeouts, fe.clitimeout, None, None);

    let mut cliexp = Vec::new();
    for exp in &fe.cliexp {
        if let Ok(c) = ibex_proto::CompiledExp::new(&exp.regex, &exp.replacement) {
            cliexp.push(c);
        }
    }

    let stick_table = fe
        .stick_table
        .as_ref()
        .map(|ast| Arc::new(init_stick_table(ast, &fe.name)));

    let acls = compile_acls(&fe.acls);
    let rules = Box::new(crate::rule_compiled::Rules {
        http_req: crate::rule_compiled::http_req(&http_req_rules, &acls),
        http_res: crate::rule_compiled::http_res(&fe.http_res_rules, &acls),
        http_after_res: crate::rule_compiled::http_after_res(&fe.http_after_res_rules, &acls),
        tcp_req_conn: crate::rule_compiled::tcp_req_conn(&fe.tcp_req_conn_rules, &acls),
        tcp_req_session: crate::rule_compiled::tcp_req_session(&fe.tcp_req_session_rules, &acls),
        tcp_req_content: crate::rule_compiled::tcp_req_content(&tcp_req_content_rules, &acls),
        tcp_res_content: crate::rule_compiled::tcp_res_content(&[], &acls),
        stick: crate::rule_compiled::stick(&fe.stick_rules, &acls),
        use_backend: crate::rule_compiled::use_backend(&fe.use_backends, &acls),
        use_server: crate::rule_compiled::use_server(&[], &acls),
        force_be: crate::rule_compiled::force_be(&fe.force_be_switch, &acls),
        reply_pages: crate::rule_compiled::reply_pages(&fe.error_replies),
        res_stream: false,
    }.finish());
    Proxy {
        id: usize_to_u32(proxy_idx),
        ids: Box::new(ProxyIdInfo {
            timeout_ms: timeouts_ms(&fe.timeouts),
            iid: ids.iid,
            decl: ids.decl,
            next_decl: 0,
            forced_id: ids.forced,
            server_puids: Vec::new(),
            server_forced_ids: Vec::new(),
            server_init_health: Vec::new(),
            listener_ids: ibex_config::ast::listener_ids(&frontend_binds(fe)),
            http_mode: fe.http_mode,
            retry_on: ibex_config::RE_CONN_FAILED,
            ..ProxyIdInfo::default()
        }),
        name: fe.name.clone(),
        has_frontend: true,
        has_backend: false,
        log_target_idx: Vec::new(),
        log_health_checks: fe.log_health_checks,
        addr: fe.bind.unwrap_or(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
        )),
        mode: fe.mode,
        balance: BalanceAlgorithm::RoundRobin,
        balance_set: false,
        timeouts,
        retries: 3,
        redisp: false,
        redisp_after: -1,
        maxconn: effective_fe_maxconn(fe.maxconn).into(),
        dispatch: None,
        cookie: None,
        cliexp,
        srvexp: Vec::new(),
        servers: Vec::new().into(),
        server_ids: Vec::new(),
        server_cookies: Vec::new(),
        server_statuses: std::sync::Arc::new(Vec::new()),
        server_track: None,
        server_weights: std::iter::empty().collect(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new(vec![ProxyStats::default()]),
        desc: fe.description.as_deref().map(Box::from),
        stats_config: {
            let mut sc = fe.stats.clone();
            sc.raw_timeouts = fe.timeouts;
            sc.forwardfor.clone_from(&fe.forwardfor);
            sc.forwardfor_if_none = fe.forwardfor_if_none;
            sc.originalto.clone_from(&fe.originalto);
            sc
        },
        default_backend: fe.default_backend.clone(),
        use_backends: fe.use_backends.clone(),
        use_servers: Vec::new(),
        force_be_switch: fe.force_be_switch.clone(),
        disabled_backends: Arc::default(),
        monitor: Monitor::boxed(fe.monitor_uri.as_deref(), &fe.monitor_fail),
        acls,
        stick_table,
        stick_rules: fe.stick_rules.clone(),
        server_send_proxy: Vec::new(),
        server_tfo: Vec::new(),
        server_send_proxy_v2: Vec::new(),
        server_pp_unique_id: Vec::new(),
        server_backups: Vec::new(),
        server_maxconn: std::iter::empty().collect(),
        server_actconn: std::sync::Arc::new(Vec::new()),
        server_retr: Arc::default(),
        server_sess_rates: std::sync::Arc::new(Vec::new()),
        server_check_configs: Vec::new(),
        server_tls: Vec::new(),
        server_check_tls: Vec::new(),
        tcp_req_conn_rules: fe.tcp_req_conn_rules.clone(),
        tcp_req_session_rules: fe.tcp_req_session_rules.clone(),
        tcp_req_content_rules,
        tcp_req_inspect_delay: fe.tcp_req_inspect_delay,
        tcp_res_content_rules: Vec::new(),
        tcp_res_inspect_delay: None,
        rules,
        http_req_rules,
        http_res_rules: fe.http_res_rules.clone(),
        http_after_res_rules: fe.http_after_res_rules.clone(),
        http_reuse: ibex_config::HttpReuse::default(),
        abortonclose: true,
        h1_adjust: fe.h1_adjust,
        h1_case: Arc::default(),
        h1_lower: false,
        error_files: fe.error_files.clone(),
        error_replies: fe.error_replies.clone(),
        log_tag: fe.log_tag.as_deref().map(syslog_tag),
        log_format: compile_log_format(fe.log_format.as_ref(), fe.mode == Mode::Http),
        dont_log_null: fe.dontlognull,
        ignore_probes: fe.http_ignore_probes,
        log_opts: fe.log_opts,
        unique_id_format: fe.unique_id_format.as_deref().and_then(compile_unique_id_format),
        extra_log: extra_log_formats(fe.error_log_format.as_deref(), fe.log_format_sd.as_deref()),
        unique_id_header: fe.unique_id_header.as_deref().map(Box::from),
        req_capture_slots,
        res_capture_slots: fe.res_header_captures.iter().map(|c| (c.name.clone(), c.len)).collect(),
        log_count: Arc::default(),
        log_cursors: Arc::default(),
        hash_type: ibex_config::HashType::default(),
        hash_preserve_affinity: ibex_config::HashPreserveAffinity::default(),
        chash: Arc::default(),
        fwrr: Arc::default(),
    }
}

fn init_proxy_from_backend(proxy_idx: usize, ids: ibex_config::ast::ProxyId, be: &ibex_config::BackendSection) -> Proxy {
    let mut http_req_rules = be.http_req_rules.clone();
    with_buffered_request(&mut http_req_rules, be.buffer_request);
    let timeouts = section_timeouts(&be.timeouts, None, be.srvtimeout, be.contimeout);

    let retries = u16::try_from(be.retries).unwrap_or(u16::MAX);

    let mut srvexp = Vec::new();
    for exp in &be.srvexp {
        if let Ok(c) = ibex_proto::CompiledExp::new(&exp.regex, &exp.replacement) {
            srvexp.push(c);
        }
    }

    let stick_table = be
        .stick_table
        .as_ref()
        .map(|ast| Arc::new(init_stick_table(ast, &be.name)));

    let server_count = be.servers.len();
    let server_check_configs = server_check_configs(&be.servers, be.timeouts.check);

    let acls = compile_acls(&be.acls);
    let rules = Box::new(crate::rule_compiled::Rules {
        http_req: crate::rule_compiled::http_req(&http_req_rules, &acls),
        http_res: crate::rule_compiled::http_res(&be.http_res_rules, &acls),
        http_after_res: crate::rule_compiled::http_after_res(&be.http_after_res_rules, &acls),
        tcp_req_conn: crate::rule_compiled::tcp_req_conn(&[], &acls),
        tcp_req_session: crate::rule_compiled::tcp_req_session(&[], &acls),
        tcp_req_content: crate::rule_compiled::tcp_req_content(&be.tcp_req_content_rules, &acls),
        tcp_res_content: crate::rule_compiled::tcp_res_content(&be.tcp_res_content_rules, &acls),
        stick: crate::rule_compiled::stick(&be.stick_rules, &acls),
        use_backend: crate::rule_compiled::use_backend(&[], &acls),
        use_server: crate::rule_compiled::use_server(&be.use_servers, &acls),
        force_be: crate::rule_compiled::force_be(&[], &acls),
        reply_pages: crate::rule_compiled::reply_pages(&be.error_replies),
        res_stream: false,
    }.finish());
    Proxy {
        id: usize_to_u32(proxy_idx),
        ids: Box::new(ProxyIdInfo {
            timeout_ms: timeouts_ms(&be.timeouts),
            iid: ids.iid,
            decl: ids.decl,
            next_decl: 0,
            forced_id: ids.forced,
            server_puids: server_puids(be.servers.len(), &be.server_extras),
            server_forced_ids: server_forced_ids(be.servers.len(), &be.server_extras),
            server_init_health: server_init_health(be.servers.len(), &be.server_extras),
            server_cmaint: server_cmaint(&be.servers),
            server_rmaint: server_rmaint(&be.servers, &be.server_extras),
            server_fqdns: server_fqdns(be.servers.len(), &be.server_extras),
            server_fqdn_changed: server_fqdn_changed(be.servers.len(), &be.server_extras),
            server_srv: crate::resolvers::SrvSlots::new(be.servers.len(), &be.server_extras),
            server_check_ports: server_check_ports(&be.servers),
            listener_ids: Vec::new(),
            server_pool: pool_cfgs(&be.servers, be.mode == Mode::Http),
            http_mode: be.http_mode,
            persist: be.persist,
            checkcache: be.checkcache,
            retry_on: be.retry_on,
            ..ProxyIdInfo::default()
        }),
        name: be.name.clone(),
        has_frontend: false,
        has_backend: true,
        log_target_idx: Vec::new(),
        log_health_checks: be.log_health_checks,
        addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
        mode: be.mode,
        balance: be.balance,
        balance_set: be.balance_set,
        timeouts,
        retries,
        redisp: be.redisp,
        redisp_after: be.redisp_after,
        maxconn: 2000.into(),
        dispatch: be.dispatch,
        cookie: be.cookie.clone(),
        cliexp: Vec::new(),
        srvexp,
        servers: be.servers.iter().map(|s| s.addr).collect(),
        server_ids: be.servers.iter().map(|s| s.id.clone()).collect(),
        server_cookies: be.servers.iter().map(|s| s.cookie.as_deref().map(Box::from)).collect(),
        server_statuses: Arc::new(be.servers.iter().enumerate().map(|(i, s)| AtomicU8::new(initial_status(s, be.server_extras.unresolved(i)))).collect()),
        server_track: None,
        server_weights: be.servers.iter().map(|s| s.weight.unwrap_or(1)).collect(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new(vec![ProxyStats::default()]),
        desc: be.description.as_deref().map(Box::from),
        stats_config: {
            let mut sc = be.stats.clone();
            sc.raw_timeouts = be.timeouts;
            sc.forwardfor.clone_from(&be.forwardfor);
            sc.forwardfor_if_none = be.forwardfor_if_none;
            sc.forwarded.clone_from(&be.forwarded);
            sc.originalto.clone_from(&be.originalto);
            sc
        },
        default_backend: None,
        use_backends: Vec::new(),
        use_servers: be.use_servers.clone(),
        force_be_switch: Vec::new(),
        disabled_backends: Arc::default(),
        monitor: None,
        acls,
        stick_table,
        stick_rules: be.stick_rules.clone(),
        server_send_proxy: be.servers.iter().map(|s| s.send_proxy).collect(),
        server_tfo: be.servers.iter().map(|s| s.tfo).collect(),
        server_send_proxy_v2: be.servers.iter().map(|s| s.send_proxy_v2).collect(),
        server_pp_unique_id: be.servers.iter().map(|s| s.proxy_v2_unique_id).collect(),
        server_backups: be.servers.iter().map(|s| s.backup).collect(),
        server_maxconn: be.servers.iter().map(|s| s.maxconn).collect(),
        server_actconn: Arc::new((0..server_count).map(|_| AtomicU32::new(0)).collect()),
        server_retr: Arc::default(),
        server_sess_rates: Arc::new((0..server_count).map(|_| RateCtr::default()).collect()),
        server_check_configs,
        server_tls: Vec::new(),
        server_check_tls: Vec::new(),
        tcp_req_conn_rules: Vec::new(),
        tcp_req_session_rules: Vec::new(),
        tcp_req_content_rules: be.tcp_req_content_rules.clone(),
        tcp_req_inspect_delay: be.tcp_req_inspect_delay,
        tcp_res_content_rules: be.tcp_res_content_rules.clone(),
        tcp_res_inspect_delay: be.tcp_res_inspect_delay,
        rules,
        http_req_rules,
        http_res_rules: be.http_res_rules.clone(),
        http_after_res_rules: be.http_after_res_rules.clone(),
        http_reuse: be.http_reuse.unwrap_or_default(),
        abortonclose: be.abortonclose.unwrap_or(true),
        h1_adjust: be.h1_adjust,
        h1_case: Arc::default(),
        h1_lower: false,
        error_files: be.error_files.clone(),
        error_replies: be.error_replies.clone(),
        log_tag: be.log_tag.as_deref().map(syslog_tag),
        log_format: None,
        extra_log: None,
        dont_log_null: false,
        ignore_probes: false,
        log_opts: 0,
        unique_id_format: be.unique_id_format.as_deref().and_then(compile_unique_id_format),
        unique_id_header: be.unique_id_header.as_deref().map(Box::from),
        req_capture_slots: Arc::from([]),
        res_capture_slots: Arc::from([]),
        log_count: Arc::default(),
        log_cursors: Arc::default(),
        hash_type: be.hash_type.unwrap_or_default(),
        hash_preserve_affinity: be.hash_preserve_affinity.unwrap_or_default(),
        chash: Arc::default(),
        fwrr: Arc::default(),
    }
}

/// The check parameters of each server of a section (`inter`, `fastinter`, `downinter`,
/// `rise`, `fall`, and `timeout check` or else `inter`): one shared copy for each run of
/// servers that have the same, which is every server of a backend whose `server` lines
/// differ only by name and address.
fn server_check_configs(servers: &[ibex_config::ast::Server], check_timeout: Option<Duration>) -> Vec<Option<Arc<ServerCheckConfig>>> {
    let mut last: Option<Arc<ServerCheckConfig>> = None;
    servers
        .iter()
        .map(|s| {
            if !s.check {
                return None;
            }
            let mut cfg = ServerCheckConfig::default();
            if let Some(inter) = s.inter {
                cfg.inter = inter;
            }
            cfg.check_port = s.check_port;
            cfg.h2 = s.check_proto.map_or(s.proto_h2, |p| p == "h2");
            cfg.fastinter_ms = s.fastinter_ms();
            cfg.downinter_ms = s.downinter_ms();
            if let Some(fall) = s.fall {
                cfg.fall = fall;
            }
            if let Some(rise) = s.rise {
                cfg.rise = rise;
            }
            if let Some(chk_timeout) = check_timeout {
                cfg.timeout = chk_timeout;
            } else if let Some(inter) = s.inter {
                cfg.timeout = inter;
            }
            let shared = match last.take() {
                Some(prev) if *prev == cfg => prev,
                _ => Arc::new(cfg),
            };
            last = Some(Arc::clone(&shared));
            Some(shared)
        })
        .collect()
}

fn init_checks(proxies: &[Proxy], scheduler: &mut Scheduler, now: Tick) -> Vec<ServerCheckState> {
    let mut checks = Vec::with_capacity(proxies.iter().map(|p| p.server_check_configs.iter().flatten().count()).sum());
    // One task and one timer per check.
    scheduler.reserve(checks.capacity());
    for (proxy_idx, proxy) in proxies.iter().enumerate() {
        for (server_idx, srv_addr) in proxy.servers.iter().enumerate() {
            let Some(check_cfg) = proxy.server_check_configs.get(server_idx).and_then(Clone::clone) else {
                continue;
            };
            let mut check = ServerCheckState::new(proxy_idx, server_idx, srv_addr, check_cfg, now);
            check.tls = proxy.server_check_tls.get(server_idx).cloned().flatten();
            if let Some(r) = proxy.ids.restored(server_idx) {
                // What the server-state file said (T490), already in `server_statuses`.
                let published = proxy.server_statuses.get(server_idx).map_or(0, |s| s.load(Ordering::Relaxed));
                check.status = if published == crate::check::DRAIN_DOWN { ServerStatus::Down } else { ServerStatus::from(published) };
                check.admin = r.admin;
                check.health = r.health;
                check.enabled = !r.check_disabled;
                if let Some((code, desc)) = r.check_code {
                    check.last_status_code = code;
                    check.last_status_desc = desc;
                }
            } else if proxy.server_statuses.get(server_idx).is_some_and(|s| s.load(Ordering::Relaxed) == ServerStatus::Maint as u8) {
                // A `disabled` server stays in maintenance whatever its checks find.
                check.set_admin_status(ServerStatus::Maint);
            }
            let check_idx = usize_to_u32(checks.len());
            if let Some(task_ref) = scheduler.create(WorkKind::new(Kind::Check, check_idx)) {
                check.task = task_ref;
                let initial_delay = 50u32.saturating_add(check_idx.saturating_mul(50));
                scheduler.queue_timer(task_ref, now.add(initial_delay));
            }
            checks.push(check);
        }
    }
    checks
}

thread_local! {
    /// `http-err-codes` and `http-fail-codes` (`global`), the statuses that count in the
    /// `http_err_cnt` and `http_fail_cnt` of the tracked entries.
    static HTTP_ERR_CODES: std::cell::Cell<ibex_config::StatusCodeSet> = const { std::cell::Cell::new(ibex_config::StatusCodeSet::EMPTY) };
    static HTTP_FAIL_CODES: std::cell::Cell<ibex_config::StatusCodeSet> = const { std::cell::Cell::new(ibex_config::StatusCodeSet::EMPTY) };
}

/// Whether a response with `status` is an error and/or a failure, per `http-err-codes` and
/// `http-fail-codes` (the defaults: 400 to 499, and 500 to 599 but 501 and 505).
fn response_class(status: u16) -> (bool, bool) {
    (HTTP_ERR_CODES.with(|c| c.get().contains(status)), HTTP_FAIL_CODES.with(|c| c.get().contains(status)))
}

/// The address of a `Forwarded` node: an IPv4 address as it is, an IPv6 one in brackets.
fn node_text(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format!("[{a}]"),
    }
}

/// The element `option forwarded` adds: `proto`, `host`, `by` and `for`, in that order, each
/// from its sample expression or from the connection.
fn forwarded_element(fwd: &ibex_config::Forwarded, sess: &TcpSession, ctx: &SampleContext) -> String {
    use ibex_config::ForwardedValue::{Default as Plain, Expr as Expression, Off};
    use ibex_sample::rfc7239::{node_from_sample, port_from_sample, valid_host};
    let registry = sample_registry();
    let eval = |e: &str| Expr::cached(e).ok().and_then(|e| e.eval_sample(registry, ctx));
    let mut parts: Vec<String> = Vec::new();
    if fwd.proto {
        parts.push(format!("proto={}", if sess.cli_is_tls() { "https" } else { "http" }));
    }
    match &fwd.host {
        Off => {}
        v => {
            let host = match v {
                Expression(e) => eval(e).map(|s| sample_to_string(&s)),
                _ => sess.htx_slice().and_then(|h| h.get_header("host")).map(str::to_string),
            };
            parts.push(format!("host=\"{}\"", host.filter(|h| valid_host(h)).unwrap_or_default()));
        }
    }
    // The address of the stream (`set-src`/`set-dst` change it), and the port of the connection.
    let src = sess.client_addr.map(|a| (a.ip(), if a.port() == 0 { sess.fc_src().map_or(0, |c| c.port()) } else { a.port() }));
    let dst_port = sess.fc_dst().map_or(0, |c| c.port());
    let dst = sess.server_addr.map(|a| a.ip()).or(sess.fc_dst().map(|a| a.ip())).map(|ip| (ip, dst_port));
    for (name, node, port, addr) in [("by", &fwd.by, &fwd.by_port, dst), ("for", &fwd.for_, &fwd.for_port, src)] {
        if *node == Off {
            continue;
        }
        let name_text = match node {
            Expression(e) => node_from_sample(eval(e).as_ref()),
            _ => addr.map_or_else(|| "unknown".to_string(), |(ip, _)| node_text(ip)),
        };
        let port_text = match port {
            Off => None,
            Plain => addr.map(|(_, p)| p).filter(|p| *p != 0).map(|p| p.to_string()),
            Expression(e) => port_from_sample(eval(e).as_ref()),
        };
        let quoted = *port != Off || name_text.contains([':', '[']);
        let value = port_text.map_or_else(|| name_text.clone(), |p| format!("{name_text}:{p}"));
        parts.push(if quoted { format!("{name}=\"{value}\"") } else { format!("{name}={value}") });
    }
    parts.join(";")
}

/// Adds `element` at the end of the request's last `Forwarded` header, or as a header of its
/// own when it has none. False, nothing changed, when it does not fit ([`add_req_header_fit`]).
fn append_forwarded_element(sess: &mut TcpSession, element: &str) -> bool {
    let existing: Vec<String> = sess
        .htx_slice()
        .map(|s| s.headers().filter(|(n, _)| n.eq_ignore_ascii_case("forwarded")).map(|(_, v)| v.to_string()).collect())
        .unwrap_or_default();
    match existing.as_slice() {
        [] => return add_req_header_fit(sess, "forwarded", element),
        [only] => {
            if !res_htx_resize(0, element.len() + 1) {
                return false;
            }
            sess.htx_reserve(element.len() + 1);
            set_req_header(sess, "forwarded", &format!("{only},{element}"));
        }
        many => {
            if !res_htx_resize(0, element.len() + 1) {
                return false;
            }
            sess.htx_reserve(element.len() + 1);
            let last = many.len() - 1;
            let values: Vec<String> = many.iter().enumerate().map(|(i, v)| if i == last { format!("{v},{element}") } else { v.clone() }).collect();
            sess.with_htx_mut(|htx| {
                htx.remove_header("forwarded");
                for v in &values {
                    let _ = htx.add_header("forwarded", v);
                }
            });
            let mut hdrs = sess.req_headers.take().unwrap_or_default();
            hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case("forwarded"));
            hdrs.extend(values.into_iter().map(|v| ("forwarded".to_string(), v)));
            sess.req_headers = Some(hdrs);
            rebuild_req_buffer(sess);
        }
    }
    true
}

/// `reply`, a whole response, with `header` as the last header line of its head
/// (`http_action_auth` adds `www-authenticate` after the page's own headers).
fn with_header_at_end_of_head(reply: &[u8], header: &str) -> Vec<u8> {
    let at = reply.windows(4).position(|w| w == b"\r\n\r\n").map_or(reply.len(), |p| p + 2);
    let mut out = Vec::with_capacity(reply.len() + header.len() + 2);
    out.extend_from_slice(&reply[..at]);
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&reply[at..]);
    out
}

/// A sample as an integer, as a string converts to one: its leading digits, 0 when it has none.
fn sample_as_sint(smp: &ibex_sample::Sample) -> i64 {
    let text = sample_to_string(smp);
    let t = text.trim_start();
    let (neg, digits) = t.strip_prefix('-').map_or((false, t.strip_prefix('+').unwrap_or(t)), |d| (true, d));
    let n = digits.bytes().take_while(u8::is_ascii_digit).fold(0i64, |n, d| n.saturating_mul(10).saturating_add(i64::from(d - b'0')));
    if neg { -n } else { n }
}

fn init_global_vars(global: Option<&ibex_config::GlobalSection>) {
    if let Some(global) = global {
        let sample_reg = sample_registry();
        let sample_ctx = SampleContext::default();
        for set_var in &global.set_vars {
            // `set-var` keeps the sample's type, `set-var-fmt` stores a string (T364).
            let val = if set_var.is_fmt {
                Sample::Str(format_sample_string(&set_var.expr, &sample_ctx, sample_reg))
            } else {
                // The expression was checked when the configuration loaded.
                Expr::cached(&set_var.expr).ok().and_then(|e| e.eval_sample(sample_reg, &sample_ctx)).unwrap_or_else(|| Sample::Str(set_var.expr.clone()))
            };
            ibex_sample::vars::set_proc(&set_var.name, val);
        }
    }
}

impl Engine {
    /// Constructs an `Engine` configured from the given parsed config.
    ///
    /// # Errors
    /// Returns an error if epoll creation or binding any listener fails, or if a rule
    /// action's sample expression names an unknown fetch or converter
    /// ([`crate::rule_exprs::validate_rule_exprs`]).
    #[allow(clippy::too_many_lines)]
    pub fn build_shared_state(config: &Config) -> io::Result<Proxies> {
    // T460: before any TLS configuration (server lines here, binds in `new_worker`) is built.
    crate::crypto_provider::apply(config)?;
    // Expressions and ACL files compiled for a previous configuration are not reused.
    ibex_sample::expr::new_generation();
    // The clock of `lastchg` and `lastsess` (`show stat`) starts with the proxies.
    let _ = crate::statcnt::now_ms();
    configure_maxconn(config);
    // `global` `set-var` lines: once per process, before any worker serves. Run again in each
    // worker, a `set-var-fmt` reading its own variable saw what the others had appended.
    init_global_vars(config.global.as_ref());
    crate::crash::set_fault(config.global.as_ref().and_then(|g| g.debug_panic.clone()));
    // An action naming a fetch or converter the registry lacks would load and then do
    // nothing on every request; `HAProxy` refuses the configuration instead.
    crate::rule_exprs::validate_config(config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // Exactly the proxies built below: a doubling Vec of 1.6 KB proxies left up to half of
    // it unused, 2.7 KB a backend at 10,000 (T175).
    let mut proxies = Vec::with_capacity(
        config.listens.iter().filter(|l| !l.disabled).count()
            + config.backends.iter().filter(|b| !b.disabled).count()
            + config.frontends.iter().filter(|f| !f.disabled).count(),
    );
    let ids = config.proxy_ids();
    for (i, listen) in config.listens.iter().enumerate().filter(|(_, l)| !l.disabled) {
        let mut p = init_proxy_from_listen(proxies.len(), ids.listens[i], listen);
        attach_server_tls(&mut p, &listen.servers, listen.mode == Mode::Http, &listen.name)?;
        proxies.push(p);
    }
    for (i, backend) in config.backends.iter().enumerate() {
        if !backend.disabled {
            let mut p = init_proxy_from_backend(proxies.len(), ids.backends[i], backend);
            attach_server_tls(&mut p, &backend.servers, backend.mode == Mode::Http, &backend.name)?;
            proxies.push(p);
        }
    }
    for (i, frontend) in config.frontends.iter().enumerate() {
        if !frontend.disabled { proxies.push(init_proxy_from_frontend(proxies.len(), ids.frontends[i], frontend)); }
    }
    // T490: the servers start where the server-state file says, before any check or request.
    crate::server_state::apply(config, &mut proxies);
    let disabled: Arc<Vec<String>> = Arc::new(
        config.listens.iter().map(|l| (l.disabled, &l.name))
            .chain(config.backends.iter().map(|b| (b.disabled, &b.name)))
            .filter(|(d, _)| *d)
            .map(|(_, n)| n.clone())
            .collect(),
    );
    for p in &mut proxies {
        p.disabled_backends = Arc::clone(&disabled);
    }
    // `h1-case-adjust`, `h1-case-adjust-file` (global): the table the proxies with a
    // `h1-case-adjust-bogus-*` option write names from (`h1_get_hdrs_map`).
    let h1_table: Arc<std::collections::HashMap<String, String>> =
        Arc::new(config.global.iter().flat_map(|g| g.h1_case_adjust.iter().cloned()).collect());
    for p in proxies.iter_mut().filter(|p| p.h1_adjust & (ibex_config::H1_ADJ_CLIENT | ibex_config::H1_ADJ_SERVER) != 0) {
        p.h1_case = Arc::clone(&h1_table);
    }
    // `tune.ibex.h1-lowercase-headers` (X5): read where a forwarded head's names are written.
    let h1_lower = config.global.as_ref().and_then(|g| g.h1_lowercase_headers).unwrap_or(false);
    for p in &mut proxies {
        p.h1_lower = h1_lower;
    }
    crate::track::attach(&mut proxies, config);
    link_declaration_order(&mut proxies);
    crate::logfwd::start(config)?;
    let _ = resolve_log_targets(config, &mut proxies);
    Ok(Proxies::new(proxies))
}

pub fn new(config: &Config, capacity: usize) -> io::Result<Self> {
        let proxies = Self::build_shared_state(config)?;
        Self::new_worker(config, capacity, 0, proxies)
    }

    pub fn new_worker(config: &Config, capacity: usize, worker_id: usize, proxies: Proxies) -> io::Result<Self> {
        WORKER_ID.with(|id| id.set(worker_id));
        ibex_sample::THREAD_ID.with(|t| t.set(worker_id));
        let _ = ibex_sample::CPU_USAGE_SOURCE.set(crate::cpu::get_usage_pct);
        let poller = Poller::new(capacity)?;
        let mut scheduler = Scheduler::with_capacity(capacity);
        let mut fdtab = FdTab::with_capacity(capacity * 2);
        let mut sessions = SessionArena::with_capacity(capacity);
        // The buffer wait queues, for as many streams as the arena is sized for (S6b §3): a
        // stream queued at `tune.buffers.limit` allocates nothing. Short of memory, they grow
        // on use instead.
        let _ = crate::buf_wait::presize(capacity);
        let applets = AppletArena::with_capacity(capacity);

        ibex_sample::set_userlists(
            config
                .userlists
                .iter()
                .map(|l| ibex_sample::AuthUserlist {
                    name: l.name.clone(),
                    users: l
                        .users
                        .iter()
                        .map(|u| ibex_sample::AuthUser {
                            name: u.name.clone(),
                            password: u.password.clone(),
                            // The parser checked the hash; this is the verifier `http_auth` runs.
                            crypt: u.password.as_deref().filter(|_| u.password_is_hash).and_then(|h| ibex_sample::CryptHash::parse(h).ok()),
                            groups: u.groups.clone(),
                        })
                        .collect(),
                })
                .collect(),
        );
        HTTP_ERR_CODES.set(config.global.as_ref().and_then(|g| g.http_err_codes).unwrap_or_else(ibex_config::StatusCodeSet::default_err));
        HTTP_FAIL_CODES.set(config.global.as_ref().and_then(|g| g.http_fail_codes).unwrap_or_else(ibex_config::StatusCodeSet::default_fail));
        ibex_alloc::set_trim_disabled(config.global.as_ref().is_some_and(|g| g.no_memory_trimming));
        // Both off unless configured (the user, 2026-10-24: comparisons with HAProxy stay fair).
        ibex_alloc::set_zero_buffers(config.global.as_ref().and_then(|g| g.zero_buffers).unwrap_or(false));
        ibex_alloc::set_ssl_zero_on_free(config.global.as_ref().is_some_and(|g| g.ssl_zero_on_free));
        ibex_alloc::set_ssl_zero_buffers(config.global.as_ref().and_then(|g| g.ssl_zero_buffers).unwrap_or(true));
        ibex_alloc::set_zero_spares(config.global.as_ref().and_then(|g| g.zero_spares).unwrap_or(false));
        // `tune.ibex.zero-on-free` (T459, off unless configured): read by the binary's allocator
        // on every free (`ibex_alloc::IbexAllocator`), the quarantine emptied by the pass below.
        ibex_alloc::zero_on_free::set_zero_on_free(match config.global.as_ref().and_then(|g| g.zero_on_free) {
            Some(ibex_config::ast::ZeroOnFree::Soft) => ibex_alloc::ZeroOnFree::Soft,
            Some(ibex_config::ast::ZeroOnFree::Hard) => ibex_alloc::ZeroOnFree::Hard,
            Some(ibex_config::ast::ZeroOnFree::Off) | None => ibex_alloc::ZeroOnFree::Off,
        });
        ibex_alloc::set_hot_size(config.global.as_ref().and_then(|g| g.hot_size).unwrap_or(ibex_alloc::HOT_SIZE_DEFAULT));
        // `tune.buffers.limit`, `tune.fail-alloc` under `-dMfail` (S5): read by the pools' miss
        // paths (`buf::take_mem`, `Pool::miss`) and the accept (`register_new_session`).
        // `tune.buffers.reserve` (S6b): each thread's emergency buffers raise the limit. Default
        // `RESERVED_BUFS` (4), as HAProxy, but only with a limit: without one the pool refuses
        // only when memory is short, where Ibex fails the stream (S5).
        let limit = config.global.as_ref().and_then(|g| g.buffers_limit).unwrap_or(0);
        let reserve = config.global.as_ref().and_then(|g| g.buffers_reserve).unwrap_or(if limit == 0 { 0 } else { crate::buf::RESERVED_BUFS });
        let nbthread = crate::stats::NBTHREAD.load(Ordering::Relaxed) as usize;
        crate::buf::set_buffers_limit(crate::buf::limit_with_reserve(limit, reserve, nbthread));
        ibex_alloc::pool::set_fail_alloc(ibex_alloc::pool::effective_fail_alloc(config.global.as_ref().and_then(|g| g.fail_alloc)));
        // A variable whose memory is refused collects and retries once (T445).
        ibex_sample::vars::set_alloc_failure_hook(crate::pool_gc::pool_gc);
        let bufsize = config.global.as_ref().and_then(|g| g.bufsize).unwrap_or(16384);
        let bufsize_small = config.global.as_ref().and_then(|g| g.bufsize_small).unwrap_or(1024);
        let bufsize_large = config.global.as_ref().and_then(|g| g.bufsize_large);
        crate::buf::init_buffer_sizes(bufsize, bufsize_small, bufsize_large);
        let vl = config.global.as_ref().map(|g| g.vars_limits).unwrap_or_default();
        ibex_sample::vars::set_limits(vl.global, vl.proc_, vl.sess, vl.txn, vl.reqres, vl.check);
        if bufsize_large.is_some() {
            crate::buf::preallocate_large_buffers();
        }
        if !crate::buf::fill_emergency(reserve) {
            return Err(io::Error::other(format!("tune.buffers.reserve: cannot allocate {reserve} emergency buffers")));
        }
        // `tune.memory.prealloc` (T468): this thread's buffers and session slots, from `maxconn`.
        if let Some(plan) = crate::prealloc::plan(config) {
            crate::buf::set_buffers_limit(crate::buf::limit_with_reserve(plan.buffers_limit, reserve, nbthread));
            if !crate::buf::prealloc_standard(plan.buffers) || !sessions.prealloc(plan.sessions) {
                return Err(io::Error::other(format!(
                    "tune.memory.prealloc: cannot allocate {} buffers and {} session slots",
                    plan.buffers, plan.sessions
                )));
            }
        }

        let mut quic_listeners: Vec<crate::quic_listener::QuicListener> = Vec::new();
        let mut listeners: Vec<crate::listener::Listener> = Vec::new();
        let mut proxy_idx = 0;
        for listen in &config.listens {
            if listen.disabled { continue; }
            // A section built in code with `addr` alone is one plaintext bind on it.
            let binds = if listen.binds.is_empty() {
                vec![ibex_config::ast::BindConfig {
                    sock: None,
                    line: 0,
                    addr: listen.addr,
                    quic: false,
                    ssl: false,
                    crt: vec![],
                    alpn: vec![],
                    proto: None,
                    accept_proxy: listen.accept_proxy,
                    accept_proxy_v2: listen.accept_proxy_v2,
                    name: None,
                    id: None,
                    min_ver: None,
                    max_ver: None,
                }]
            } else {
                listen.binds.clone()
            };
            for (bind_idx, b) in binds.iter().enumerate() {
                if b.quic {
                    let tls = bind_tls_quic(&listen.name, &binds, b.addr)?.expect("QUIC requires TLS");
                    open_quic_bind(config, worker_id, bufsize, b, &tls, proxy_idx, &mut quic_listeners, &mut fdtab, &poller)?;
                    continue;
                }
                let tls = bind_tls(&listen.name, &binds, b.addr)?;
                for mut listener in listeners_for(worker_id, b.addr, usize_to_u32(proxy_idx), b.sock.as_deref().unwrap_or(&ibex_config::ast::SocketTuning::default()), crate::listener::listener_backlog(b.sock.as_deref().and_then(|s| s.backlog), listen.backlog, listen.maxconn))? {
                    listener.luid = proxies[proxy_idx].ids.listener_ids.get(bind_idx).copied().unwrap_or(0);
                    listener.maxconn = proxies[proxy_idx].maxconn.clone();
                    listener.name = b.name.as_deref().map(Into::into);
                    listener.accept_proxy = b.accept_proxy || b.accept_proxy_v2;
                    listener.accept_proxy_v2 = b.accept_proxy_v2;
                    listener.proto_h2 = b.proto.as_deref() == Some("h2");
                    listener.tls.clone_from(&tls);
                    let l_idx = listeners.len();
                    let lfd = listener.raw_fd();
                    fdtab.insert(lfd, FdState::Listener { listener: usize_to_u32(l_idx) }, Interest::READ);
                    poller.add(listener.borrowed_fd(), raw_fd_to_u64(lfd), true, false)?;
                    listeners.push(listener);
                }
            }
            proxy_idx += 1;
        }
        for backend in &config.backends {
            if backend.disabled { continue; }
            proxy_idx += 1;
        }
        for frontend in &config.frontends {
            if frontend.disabled { continue; }
            let all_binds = frontend_binds(frontend);
            for (bind_idx, b) in all_binds.iter().enumerate() {
                let bind_addr = b.addr;
                if b.quic {
                    // `tune.quic.listen off`: `protocol_may_bind_quic` is false, a QUIC bind gets
                    // no socket (T525); the frontend's other binds are served.
                    if config.global.as_ref().and_then(|g| g.quic_listen) == Some(false) {
                        continue;
                    }
                    let tls = bind_tls_quic(&frontend.name, &frontend.binds, bind_addr)?.expect("QUIC requires TLS");
                    open_quic_bind(config, worker_id, bufsize, b, &tls, proxy_idx, &mut quic_listeners, &mut fdtab, &poller)?;
                } else {
                    let tls = bind_tls(&frontend.name, &frontend.binds, bind_addr)?;
                    for mut listener in listeners_for(worker_id, bind_addr, usize_to_u32(proxy_idx), b.sock.as_deref().unwrap_or(&ibex_config::ast::SocketTuning::default()), crate::listener::listener_backlog(b.sock.as_deref().and_then(|s| s.backlog), frontend.backlog, frontend.maxconn))? {
                        listener.luid = proxies[proxy_idx].ids.listener_ids.get(bind_idx).copied().unwrap_or(0);
                        listener.maxconn = proxies[proxy_idx].maxconn.clone();
                        listener.name = b.name.as_deref().map(Into::into);
                    listener.accept_proxy = b.accept_proxy || b.accept_proxy_v2;
                    listener.accept_proxy_v2 = b.accept_proxy_v2;
                    listener.proto_h2 = b.proto.as_deref() == Some("h2");
                        listener.tls.clone_from(&tls);
                        let l_idx = listeners.len();
                        let lfd = listener.raw_fd();
                        fdtab.insert(lfd, FdState::Listener { listener: usize_to_u32(l_idx) }, Interest::READ);
                        poller.add(listener.borrowed_fd(), raw_fd_to_u64(lfd), true, false)?;
                        listeners.push(listener);
                    }
                }
            }
            proxy_idx += 1;
        }

        crate::logfwd::start(config)?;
        // The sockets are this worker's; the proxies' indices into them were resolved once,
        // by `build_shared_state`, and interning gives the same order here.
        let log_targets = resolve_log_targets(config, &mut []);

        let start_time = Instant::now();
        crate::stats::note_process_start(start_time);
        let now = Tick(1);
        let housekeeping = Housekeeping::new(&mut scheduler, now, proxies.iter().any(|p| p.stick_table.is_some()));
        
        let checks = if worker_id == 0 {
            init_checks(&proxies, &mut scheduler, now)
        } else {
            Vec::new()
        };
        // Where a server's `resolvers` reaches the data path: its section's task and sockets.
        let resolvers = if worker_id == 0 {
            crate::resolvers::build(config, &proxies, &mut scheduler, &mut fdtab, &poller, now)?
        } else {
            Vec::new()
        };


        // A worker on its own answers itself; `share_mailboxes` joins it to the others.
        let mailboxes = crate::mailbox::Mailboxes::new(1)?;
        crate::resolvers::dr_set_mailboxes(&mailboxes);
        let mb_fd = mailboxes.fd(0).as_raw_fd();
        fdtab.insert(mb_fd, FdState::Mailbox, Interest::READ);
        poller.add(mailboxes.fd(0), raw_fd_to_u64(mb_fd), true, false)?;

        // A configured Prometheus exporter gets its scratch here, on this thread, sized without rendering.
        if proxies.iter().any(|p| p.http_req_rules.iter().any(|r| matches!(r.action, ibex_config::HttpReqAction::UseServicePrometheus))) {
            crate::promex::prewarm();
        }

        let mut engine = Engine {
            quic_listeners,
            poller,
            scheduler,
            fdtab,
            listeners,
            proxies,
            checks,
            resolvers,
            sessions,
            applets,
            cli_listener: None,
            cli_socket_path: None,
            cli_socket_name: None,
            extra_cli: Vec::new(),
            paused_abns: Vec::new(),
            paused_tcp_cli: Vec::new(),
            sig_paused: false,
            global_paused: false,
            accept_limited: None,
            fe_paused: false,
            backlog_waits: false,
            cli_level: crate::applet::CliLevel::Admin,
            cli_timeout_ms: crate::applet::DEFAULT_CLI_TIMEOUT_MS,
            cli_maxconn: crate::applet::DEFAULT_CLI_MAXCONN,
            cli_paused: false,
            cli_accept_retry: None,
            start_time,
            pid: std::process::id(),
            now,
            is_running: true,
            worker_id,
            events: Vec::with_capacity(capacity * 2),
            timer_updates: Vec::with_capacity(capacity * 2),
            wake_scratch: Vec::new(),
            wake_now_scratch: Vec::new(),
            h2_spawn_scratch: Vec::new(),
            log_targets,
            log_tag: syslog_tag(config.global.as_ref().and_then(|g| g.log_tag.as_deref()).unwrap_or("haproxy")).to_string(),
            global_bufsize: bufsize,
            ssl_capture_size: config.global.as_ref().map_or(0, |g| g.tune_ssl_capture_buffer_size),
            ssl_ja4_spec: config.global.as_ref().is_some_and(|g| g.ibex_ja4_compat_spec),
            global_maxrewrite: config
                .global
                .as_ref()
                .and_then(|g| g.maxrewrite)
                .unwrap_or(1024)
                // haproxy.c: `if (maxrewrite >= bufsize / 2) maxrewrite = bufsize / 2;`
                .min(bufsize / 2),
            maxaccept: config
                .global
                .as_ref()
                .and_then(|g| g.maxaccept)
                .filter(|&n| n > 0)
                .map_or(u32::MAX, |n| n.unsigned_abs()),
            global_h2_flood_config: ibex_proto::H2FloodConfig {
                // HAProxy's `h2c_max_concurrent_streams`: the frontend value when not 0,
                // else the global one (default 100, and 0 when set to 0).
                max_concurrent_streams: config.global.as_ref().and_then(|g| {
                    g.h2_fe_max_concurrent_streams.filter(|&v| v != 0).or(g.h2_max_concurrent_streams)
                }),
                max_total_streams: config
                    .global
                    .as_ref()
                    .and_then(|g| g.h2_max_total_streams)
                    .unwrap_or(0),
                glitches_threshold: config
                    .global
                    .as_ref()
                    .and_then(|g| g.h2_glitches_threshold)
                    .unwrap_or(0),
                rxbuf: config.global.as_ref().and_then(|g| g.h2_fe_rxbuf).unwrap_or(0),
            },
            idle_backend_pool: IdlePool::default(),
            housekeeping,
            lifecycle: None,
            stopping: false,
            hard_stop_after: config.global.as_ref().and_then(|g| g.hard_stop_after),
            stop_deadline: None,
            cli_socket_ident: None,
            mailboxes,
            mailbox_wid: 0,
        };
        Ok(engine)
    }

    /// Binds a Unix domain socket for CLI / `hatop` inspection.
    ///
    /// # Errors
    /// Returns an error if binding or setting non-blocking mode fails.
    pub fn bind_cli_socket<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let (listener, path_buf) = bind_unix_listener(path.as_ref())?;
        self.adopt_cli_listener(listener, path_buf)
    }

    /// Serves the CLI on `listener`, already bound (by the main thread, before any worker
    /// served: T220).
    ///
    /// # Errors
    /// Returns an error if registering with the poller fails.
    pub fn adopt_cli_listener(&mut self, listener: UnixListener, path_buf: PathBuf) -> io::Result<()> {
        let name = format!("unix@{}", path_buf.display());
        self.adopt_cli(listener.into(), name, Some(path_buf))
    }

    /// Serves the CLI on `listener` of any kind (T246), already bound. `name` is what `show
    /// cli sockets` prints; `file` the socket file to unlink on exit, if it is one.
    ///
    /// # Errors
    /// Returns an error if registering with the poller fails.
    pub fn adopt_cli(&mut self, listener: crate::cli_listener::CliListener, name: String, file: Option<PathBuf>) -> io::Result<()> {
        let raw_fd = listener.as_raw_fd();
        self.fdtab
            .insert(raw_fd, FdState::CliListener, Interest::READ);
        self.poller
            .add(listener.as_fd(), raw_fd_to_u64(raw_fd), true, false)?;
        self.cli_listener = Some(listener);
        self.cli_socket_ident = file.as_deref().and_then(socket_file_ident);
        self.cli_socket_path = file;
        self.cli_socket_name = Some(name);
        Ok(())
    }

    /// Serves one more CLI socket of any kind (see `adopt_cli`).
    ///
    /// # Errors
    /// Returns an error if registering with the poller fails.
    pub fn adopt_extra_cli(
        &mut self,
        listener: crate::cli_listener::CliListener,
        name: String,
        file: Option<PathBuf>,
        level: crate::applet::CliLevel,
    ) -> io::Result<()> {
        let raw_fd = listener.as_raw_fd();
        let idx = u32::try_from(self.extra_cli.len()).unwrap_or(u32::MAX);
        self.fdtab.insert(raw_fd, FdState::CliExtra(idx), Interest::READ);
        self.poller.add(listener.as_fd(), raw_fd_to_u64(raw_fd), true, false)?;
        let ident = file.as_deref().and_then(socket_file_ident);
        self.extra_cli.push(ExtraCli { listener: Some(listener), path: file, name, ident, level });
        Ok(())
    }

    /// Sets the level new CLI connections start at (`stats socket ... level`).
    pub fn set_cli_level(&mut self, level: crate::applet::CliLevel) {
        self.cli_level = level;
    }

    /// `stats timeout`, for every CLI connection this worker accepts from now on.
    pub fn set_cli_timeout(&mut self, timeout: std::time::Duration) {
        self.cli_timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    }

    /// `stats maxconn`: with that many CLI connections open, the stats sockets are not
    /// accepted from until one closes (the others wait in the kernel's backlog, as in HAProxy).
    pub fn set_cli_maxconn(&mut self, n: usize) {
        self.cli_maxconn = n.max(1);
    }

    /// Arms (`on`) or disarms the CLI listeners in the poller.
    fn set_cli_listening(&mut self, on: bool) {
        for l in self.cli_listener.iter().chain(self.extra_cli.iter().filter_map(|x| x.listener.as_ref())) {
            let fd = l.as_raw_fd();
            let _ = self.poller.modify(l.as_fd(), raw_fd_to_u64(fd), on, false);
        }
        self.cli_paused = !on;
    }

    /// Re-arms the CLI listeners once a connection closed below `stats maxconn`.
    fn resume_cli_after_close(&mut self) {
        if self.cli_paused && self.cli_accept_retry.is_none() && self.applets.live() < self.cli_maxconn {
            self.set_cli_listening(true);
        }
    }

    /// Makes this engine worker `wid` of `pools`, the idle server connections all workers
    /// share (`tune.idle-pool.shared`). Called before the engine runs: a worker alone keeps
    /// a pool of its own. Its slot shares its epoll descriptor, which a worker that takes
    /// one of its idle connections takes it out of (T434).
    pub fn share_idle_pools(&mut self, pools: &Arc<IdlePools>, wid: usize) {
        self.idle_backend_pool = pools.worker(wid);
        self.idle_backend_pool.attach_poller(self.poller.shared_epfd());
    }

    /// Makes this engine worker `wid` of `boxes`, the mailboxes every worker shares: `show
    /// sess` and `shutdown session(s)` reach the streams of all of them. Called before the
    /// engine runs.
    ///
    /// # Errors
    /// `epoll_ctl` failure.
    pub fn share_mailboxes(&mut self, boxes: &Arc<crate::mailbox::Mailboxes>, wid: usize) -> io::Result<()> {
        let old = self.mailboxes.fd(self.mailbox_wid);
        let _ = self.poller.delete(old);
        self.fdtab.remove(old.as_raw_fd());
        self.mailboxes.close(self.mailbox_wid);
        let fd = boxes.fd(wid);
        self.fdtab.insert(fd.as_raw_fd(), FdState::Mailbox, Interest::READ);
        self.poller.add(fd, raw_fd_to_u64(fd.as_raw_fd()), true, false)?;
        self.mailboxes = Arc::clone(boxes);
        self.mailbox_wid = wid;
        crate::buf_wait::join(boxes, wid);
        crate::resolvers::dr_set_mailboxes(boxes);
        Ok(())
    }

    /// Answers what the other workers asked: a snapshot of this worker's streams, a shutdown
    /// of some of them, or the wakeup of a task whose request they all answered.
    fn serve_mailbox(&mut self) {
        let wid = self.mailbox_wid;
        for msg in self.mailboxes.take(wid) {
            match msg {
                crate::mailbox::Msg::ShowSess(g) => g.reply(wid, self.snapshot_streams()),
                crate::mailbox::Msg::ShowQuic(g) => {
                    g.reply(wid, self.quic_listeners.iter().flat_map(|ql| ql.show_infos(wid)).collect());
                }
                crate::mailbox::Msg::Shutdown(f, g) => {
                    let mut wake = Vec::new();
                    let n = self.shutdown_filtered(*f, &mut wake);
                    for t in wake {
                        if self.scheduler.is_live(t) {
                            self.scheduler.tasklet_wakeup(t, Class::Urgent, state::WOKEN_IO);
                        }
                    }
                    g.reply(wid, n);
                }
                crate::mailbox::Msg::Wake(t) => {
                    if self.scheduler.is_live(t) {
                        self.scheduler.tasklet_wakeup(t, Class::Urgent, state::WOKEN_IO);
                    }
                }
                // T489: worker 0 answers a `do-resolve` miss now, or its section asks.
                crate::mailbox::Msg::DoResolve(mut m) => {
                    let done = if let Some(sec) = self.resolvers.iter_mut().find(|s| s.config_index() == m.section) {
                        let done = sec.do_resolve(m);
                        if done.is_none() {
                            self.scheduler.tasklet_wakeup(sec.task, Class::Urgent, state::WOKEN_IO);
                        }
                        done
                    } else {
                        m.answer = None;
                        m.hold = std::time::Duration::ZERO;
                        Some(m)
                    };
                    if let Some(m) = done {
                        self.mailboxes.post(m.wid, crate::mailbox::Msg::DoResolved(m));
                    }
                }
                crate::mailbox::Msg::DoResolved(m) => {
                    let t = crate::resolvers::dr_answered(&m);
                    drop(m);
                    if self.scheduler.is_live(t) {
                        self.scheduler.tasklet_wakeup(t, Class::Urgent, state::WOKEN_IO);
                    }
                }
            }
        }
        let sig = self.mailboxes.take_signals(wid);
        if sig != 0 {
            self.serve_buffer_signals(sig);
        }
    }

    /// S6b: another thread waits for a buffer (this one's cached buffers go on the shelf, unless
    /// it waits too), or put buffers on the shelf (this thread's waiters are offered them).
    #[cold]
    #[inline(never)]
    fn serve_buffer_signals(&mut self, sig: u8) {
        use crate::mailbox::Signal;
        if sig & Signal::ShelveBuffers as u8 != 0 && !crate::buf_wait::has_waiters() {
            let _ = crate::buf::shelve_standard();
        }
        if sig & Signal::BuffersShelved as u8 != 0 {
            crate::buf_wait::offer_shelved();
            self.wake_buffer_waiters();
        }
    }

    /// Shuts down this worker's streams `f` names; how many.
    fn shutdown_filtered(&mut self, f: crate::mailbox::SessFilter, wake: &mut Vec<TaskRef>) -> usize {
        use crate::mailbox::SessFilter;
        let wid = self.mailbox_wid;
        let proxies = &self.proxies;
        let mut n = 0;
        for (idx, e) in self.sessions.iter_mut() {
            let hit = match f {
                SessFilter::Server { be, srv } => e.srv_backend_idx == be && e.target_server_idx == Some(srv),
                SessFilter::Backend(be) => e.srv_backend_idx == be,
                SessFilter::Id(id) => crate::mailbox::sess_id(wid, idx) == id,
            };
            if hit {
                shutdown_session_entry(e, proxies, wake);
                n += 1;
            }
        }
        n
    }

    /// This worker's streams as `show sess` lists them, and its CLI connections (`HAProxy`
    /// lists the CLI's own stream too).
    fn snapshot_streams(&self) -> Vec<crate::mailbox::SessSnap> {
        use crate::mailbox::SessSnap;
        let now = self.current_tick();
        let rel = |t: Tick| t.is_set().then(|| i64::from(t.0.wrapping_sub(now.0).cast_signed()));
        let wid = self.mailbox_wid;
        let mut out = Vec::new();
        for (idx, e) in self.sessions.iter() {
            let s = &e.sess;
            let http = matches!(s.mode, Mode::Http);
            // HTTP/1 creates no stream before a request (`HAProxy` lists none for an idle
            // connection).
            // Nor for a request whose head is not complete.
            if http && s.txn.is_none() && s.h2_ctx.is_none() {
                continue;
            }
            // An HTTP/2 connection is no stream: its streams are, each its own entry, which
            // shows the connection's descriptor (`HAProxy` lists none for an idle `h2c`, and
            // one per stream with the connection's fd, measured on 3.5-dev8; T280).
            if s.h2_ctx.is_some() && e.sess.h2_owner().is_some_and(|o| !o.children.is_empty()) {
                continue;
            }
            let fe = self.proxies.get(e.proxy_idx);
            let be = self.proxies.get(e.backend_idx).filter(|p| p.has_backend).map(|_| e.backend_idx);
            let srv = e.target_server_idx.filter(|_| e.srv_backend_idx == e.backend_idx);
            // What each side's timer means (`sc_ep_rcv_ex` / `sc_ep_snd_ex`): a receive timer
            // while that side may still send us data, a send timer while ours to it is
            // blocked. An HTTP/1 request in hand is not read from the client any more (the
            // client's timer waits only for a body or, once the response flows, for its
            // reader), and the server is not read while the response backs up or the request
            // has not been sent whole.
            let (cli_rex, cli_wex, srv_rex) = match s.txn.as_ref().filter(|_| http && !s.is_h2()) {
                Some(t) => {
                    let pending = s.has_pending_output();
                    let cli = if s.cli_exp.is_set() { s.cli_exp } else { Tick::ETERNITY };
                    // Received whole: forwarded already, or all of it waits in the buffer.
                    let req_done = {
                        let mut m = t.req;
                        m.advance(s.req.readable());
                        m.is_done()
                    };
                    (
                        if req_done || pending { Tick::ETERNITY } else { cli },
                        if pending { cli } else { Tick::ETERNITY },
                        if req_done && !pending { s.srv_exp } else { Tick::ETERNITY },
                    )
                }
                None => (if s.cli_exp.is_set() { s.cli_exp } else { s.req_exp }, Tick::ETERNITY, s.srv_exp),
            };
            let timers = [cli_rex, cli_wex, srv_rex, s.conn_exp];
            let exp = timers.iter().copied().filter(|t| t.is_set()).reduce(Tick::earliest);
            out.push(SessSnap {
                id: crate::mailbox::sess_id(wid, idx),
                created: s.created_at,
                since: if http { s.log.first_byte.unwrap_or(s.log.start) } else { s.log.start },
                // The listener's protocol in HAProxy; a stream here is TCP over the client's family.
                proto: if s.client_addr.is_some_and(|a| a.is_ipv6()) { "tcpv6" } else { "tcpv4" },
                src: s.client_addr,
                fe: fe.map(|_| e.proxy_idx),
                be,
                srv,
                req_in: s.req.len(),
                rep_in: s.rep.len(),
                cli_fd: e.cli_raw_fd,
                srv_fd: e.srv_raw_fd.unwrap_or(-1),
                cli_rex: rel(cli_rex),
                srv_rex: rel(srv_rex),
                cli_wex: rel(cli_wex),
                exp: exp.and_then(rel),
                c_exp: rel(s.conn_exp),
                retries: s.max_retries.saturating_sub(s.conn_retries),
                uri: s.txn.as_ref().and(s.req_uri.as_deref().map(str::to_owned)),
            });
        }
        for (aidx, a) in self.applets.iter() {
            let exp = rel(a.last_activity.add(a.timeout_ms));
            out.push(SessSnap {
                id: crate::mailbox::sess_id(wid, 0x8000_0000 | aidx),
                created: a.created,
                since: a.created,
                proto: "unix_stream",
                src: None,
                fe: None,
                be: None,
                srv: None,
                req_in: 0,
                rep_in: 0,
                cli_fd: a.raw_fd,
                srv_fd: -1,
                cli_rex: exp,
                srv_rex: None,
                cli_wex: None,
                exp,
                c_exp: None,
                retries: 0,
                uri: None,
            });
        }
        out.sort_by_key(|x| x.created);
        out
    }

    /// Computes the current monotonic tick.
    #[must_use]
    pub fn current_tick(&self) -> Tick {
        self.tick_at(Instant::now())
    }

    /// The tick of an instant already read (the loop's clock for the pass).
    fn tick_at(&self, at: Instant) -> Tick {
        let elapsed = at.saturating_duration_since(self.start_time);
        let ms = u32::try_from(elapsed.as_millis() & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        Tick(if ms == 0 { 1 } else { ms })
    }

    /// Formats runtime statistics string.
    #[must_use]
    pub fn format_stats_info(&self) -> String {
        let pid = std::process::id();
        // `actconn`: the QUIC connections `maxconn` holds are in it, not in any `scur` (T504).
        let active_conns = crate::globalconn::current();
        let max_conns: u32 = self.proxies.iter().map(|p| p.maxconn.get()).sum();
        let cum_conns: u64 = self.proxies.iter().map(|p| p.stats.iter().map(|s| s.cum_conn.load(Ordering::Relaxed)).sum::<u64>()).sum();
        let cum_reqs: u64 = self.proxies.iter().filter_map(|p| p.ids.tc.get()).map(|c| c.fe.req_tot.load(Ordering::Relaxed)).sum();
        crate::stats::format_show_info_counts(
            self.start_time,
            pid,
            self.scheduler.live_tasks(),
            self.scheduler.run_queue_len(),
            active_conns,
            max_conns,
            cum_conns,
            cum_reqs,
        )
    }

    /// Formats 146-column CSV stats output.
    #[must_use]
    pub fn format_stats_stat(&self) -> String {
        let pid = std::process::id();
        crate::stats::format_show_stat(&self.proxies, &self.checks, pid)
    }

    /// Formats CSV stats output with the given PID.
    #[must_use]
    pub fn stats_csv(&self, pid: u32) -> String {
        crate::stats::format_show_stat(&self.proxies, &self.checks, pid)
    }

    /// Runs a single iteration of the engine using the current tick.
    ///
    /// # Errors
    /// Returns an error if polling epoll fails.
    pub fn run_once(&mut self) -> io::Result<usize> {
        let at = crate::txnlog::loop_now();
        self.step_at(self.tick_at(at), at)
    }

    /// Registers any backend socket a QUIC listener has opened since the last pass.
    ///
    /// The listener creates these when a request arrives, so the engine learns about them
    /// after the fact rather than up front. Registering them is what lets a slow backend
    /// wake the loop instead of being noticed on the next unrelated event.
    fn sync_quic_backend_fds(&mut self) {
        // Backend legs and pinned sockets that have been dropped: the kernel took them out of
        // the poller when it closed them, but their table slots are still ours. A slot left
        // behind makes the next socket given that descriptor number look already registered,
        // so it is never polled and its leg waits for an unrelated wakeup.
        for ql in &mut self.quic_listeners {
            forget_quic_fds(&mut self.fdtab, ql.take_released_fds());
        }
        // Sockets pinned to connections by a soft stop: readable interest only.
        let mut pinned_add: Vec<(usize, RawFd)> = Vec::new();
        for (idx, ql) in self.quic_listeners.iter().enumerate() {
            for b in ql.pinned_borrowed_fds() {
                if self.fdtab.is_free(b.as_raw_fd()) {
                    pinned_add.push((idx, b.as_raw_fd()));
                }
            }
        }
        for (idx, fd) in pinned_add {
            let Some(ql) = self.quic_listeners.get(idx) else { continue };
            let Some(b) = ql.pinned_borrowed_fds().into_iter().find(|b| b.as_raw_fd() == fd) else { continue };
            sync_quic_fd(&mut self.fdtab, &self.poller, idx, b, Interest::READ, false);
        }
        // Backend legs and request relays, with the interest each one has now: write only
        // while it has bytes to write. Registering them all for writing made a slow leg
        // wake the loop on every pass until it answered (T108).
        for (idx, ql) in self.quic_listeners.iter().enumerate() {
            for (b, readable, writable) in ql.io_fds() {
                sync_quic_fd(&mut self.fdtab, &self.poller, idx, b, Interest { readable, writable }, true);
            }
        }
    }

    /// A QUIC connection is a session of its frontend (T504; HAProxy's `quic_accept_push_qc` ->
    /// `listener_accept` -> `session_new`). At its handshake it is a connection (`CurrConns`,
    /// `CurrSslConns`/`CumSslConns`, held by `global maxconn` as every connection is); once
    /// the frontend's `maxconn` has room it is a session (`scur`, `stot`, `conn_tot`,
    /// `CumConns`), served, oldest first. Its request streams count in `req_tot` only.
    fn admit_quic_connections(&mut self) {
        for q_idx in 0..self.quic_listeners.len() {
            let Some(proxy_idx) = self.quic_listeners[q_idx].frontend() else { continue };
            let ql = &mut self.quic_listeners[q_idx];
            for (_, admitted) in ql.take_closed() {
                crate::globalconn::release();
                crate::stats::SSL_CURR.fetch_sub(1, Ordering::Relaxed);
                if admitted {
                    let proxy = &self.proxies[proxy_idx];
                    proxy.counters().act_conn.fetch_sub(1, Ordering::Relaxed);
                    proxy.maxconn.dec();
                }
            }
            for conn_id in ql.take_handshaken() {
                // `global maxconn` is reached: HAProxy's listener does not accept it, and it
                // is in no counter.
                if !crate::globalconn::try_acquire() {
                    ql.refuse(conn_id);
                    continue;
                }
                crate::stats::SSL_CURR.fetch_add(1, Ordering::Relaxed);
                crate::stats::SSL_CUM.fetch_add(1, Ordering::Relaxed);
            }
            while ql.has_waiting() {
                let proxy = &self.proxies[proxy_idx];
                if !proxy.maxconn.try_inc() {
                    break;
                }
                let c = proxy.counters();
                c.cum_conn.fetch_add(1, Ordering::Relaxed);
                c.fe_sess_rate.tick();
                c.fe_conn_rate.tick();
                count_global_sess();
                let conn_rate = c.fe_conn_rate.rate();
                proxy.txn_counters().fe.conn_rate_max.fetch_max(u32::try_from(conn_rate).unwrap_or(u32::MAX), Ordering::Relaxed);
                let act = c.act_conn.fetch_add(1, Ordering::Relaxed) + 1;
                c.max_conn.fetch_max(act, Ordering::Relaxed);
                ql.admit_next();
            }
        }
    }

    /// The HTTP/3 connections admitted since the last pass get their owner sessions
    /// (`tune.ibex.h3-path mux`, T509; design 2.2): an entry of the frontend with the
    /// connection's mux, whose request streams are its children as an h2 connection's are.
    /// The connection was counted at its admission (`admit_quic_connections`); its
    /// `tcp-request connection` rules run here, once per connection as `HAProxy`'s.
    fn adopt_quic_owners(&mut self) {
        for q_idx in 0..self.quic_listeners.len() {
            let Some(proxy_idx) = self.quic_listeners[q_idx].frontend() else { continue };
            for conn in self.quic_listeners[q_idx].take_new_owned() {
                let ql = &mut self.quic_listeners[q_idx];
                let (peer, local) = (ql.peer_of(conn), ql.addr());
                let tracked: [Option<(usize, StickKey)>; 3] = [None, None, None];
                let (client_addr, server_addr, fc_src, fc_dst) =
                    match eval_tcp_req_conn_rules(&self.proxies[proxy_idx], &self.proxies, sample_registry(), peer, local, &tracked) {
                        ConnEvalOutcome::Accept(c, s, fs, fd, _) => (c, s, fs, fd),
                        ConnEvalOutcome::Reject | ConnEvalOutcome::SilentDrop(_) => {
                            self.proxies[proxy_idx].counters().denied_conn.fetch_add(1, Ordering::Relaxed);
                            ql.owner_close(conn);
                            continue;
                        }
                    };
                let Some(mut mux) = ibex_proto::mux_h3::H3MuxContext::take() else {
                    ql.owner_close(conn);
                    continue;
                };
                mux.relaxed_path = self.proxies[proxy_idx].stats_config.accept_unsafe_request;
                let raw_fd = ql.raw_fd();
                let Some((mut sess, _, _)) = init_client_session(
                    &self.proxies,
                    proxy_idx,
                    crate::proxy::ClientSide::Quic,
                    self.now,
                    peer,
                    client_addr,
                    server_addr,
                    fc_src,
                    fc_dst,
                    None,
                    0,
                    false,
                    tracked,
                    self.global_bufsize,
                    self.global_maxrewrite,
                    self.global_h2_flood_config,
                    false,
                    (false, false),
                ) else {
                    self.quic_listeners[q_idx].owner_close(conn);
                    continue;
                };
                sess.h3 = true;
                // Admitted during a soft stop (its handshake ended after it began, T558): its
                // streams are served as those of the sessions the stop found (`begin_soft_stop`),
                // their server connections not kept for a request that will not come.
                if self.stopping {
                    sess.stopping = true;
                    sess.close_client = true;
                }
                sess.cli_state = ScState::Established;
                sess.cli_exp = Tick::ETERNITY;
                sess.req_exp = Tick::ETERNITY;
                // Its role, which keeps its children and its mux, is made now (two `Box`es a
                // connection).
                sess.h2_role = Some(Box::new(crate::proxy::H2Role::Owner(crate::proxy::H2Owner {
                    h3: Some(Box::new(crate::proxy::H3Owner { mux, listener: usize_to_u32(q_idx), conn, body_scratch: Vec::new(), idle_start: self.now, closing: false, stop_grace: None, stop_read: false })),
                    ..Default::default()
                })));
                let entry = SessionEntry {
                    sess,
                    task: TaskRef::NONE,
                    proxy_idx,
                    backend_idx: proxy_idx,
                    srv_backend_idx: proxy_idx,
                    target_server_idx: None,
                    // The listener's socket, which `show sess` shows; never polled through
                    // this entry.
                    cli_raw_fd: raw_fd,
                    srv_raw_fd: None,
                    cli_interest: Interest::NONE,
                    srv_interest: Interest::NONE,
                    actconn_reclaimed: true,
                    stats_done: false,
                    be_counted: std::cell::Cell::new(NO_BACKEND),
                    connect_log_due: false,
                    rate_max_due: false,
                    srv_served: 0,
                    log_line: None,
                    log_err: false,
                    log_sd: 0,
                    buf_wait: crate::buf_wait::WaitState::default(),
                };
                let Some(idx) = self.sessions.alloc(entry) else {
                    self.quic_listeners[q_idx].owner_close(conn);
                    continue;
                };
                let Some(task) = self.scheduler.create(WorkKind::new(Kind::Stream, idx)) else {
                    self.sessions.free(idx);
                    self.quic_listeners[q_idx].owner_close(conn);
                    continue;
                };
                if let Some(e) = self.sessions.get_mut(idx) {
                    e.task = task;
                }
                self.quic_listeners[q_idx].set_owner(conn, idx, task);
                self.scheduler.tasklet_wakeup(task, Class::Urgent, state::WOKEN_IO);
            }
        }
    }

    /// Adopts the HTTP/3 request streams the QUIC listeners opened since the last pass, each
    /// as a client connection of its frontend (T130). From here an HTTP/3 request is an
    /// ordinary stream: rules, backend choice, balancing, server connection and log line.
    fn adopt_quic_streams(&mut self) {
        for q_idx in 0..self.quic_listeners.len() {
            let Some(proxy_idx) = self.quic_listeners[q_idx].frontend() else { continue };
            for st in self.quic_listeners[q_idx].take_accepted() {
                let src = crate::proxy::QuicAckSrc { listener: usize_to_u32(q_idx), conn: st.conn, facts: st.acks };
                self.admit_connection(proxy_idx, None, st.fd, st.peer, st.local, Some(src));
            }
        }
    }

    /// Wakes the requests waiting in a backend's queue for as many slots as it has free,
    /// oldest first (`process_srv_queue`). A slot another thread frees is seen here too.
    fn wake_queued(&mut self) {
        if !crate::proxy::QueueWait::any() {
            return;
        }
        // At most one wake per millisecond: a queued request that cannot take the slot the
        // headroom count promised (a server the balancing passes over) must not spin the loop.
        thread_local! {
            static LAST_WAKE: std::cell::Cell<Option<Tick>> = const { std::cell::Cell::new(None) };
        }
        if LAST_WAKE.get() == Some(self.now) {
            return;
        }
        let proxies = &self.proxies;
        let due = crate::proxy::QueueWait::take_due(|be| proxies.get(be).map_or(0, Proxy::queue_headroom));
        if !due.is_empty() {
            LAST_WAKE.set(Some(self.now));
        }
        for t in due {
            if self.scheduler.is_live(t) {
                self.scheduler.tasklet_wakeup(t, Class::Urgent, state::WOKEN_IO);
            }
        }
    }

    /// Drops the expired entries of every stick table, every 250 ms from the
    /// `hk::STICK` housekeeping task (the expire task of `HAProxy`'s tables): without it an entry stays, and counts as used,
    /// until the table is full.
    fn purge_stick_tables(&mut self) {
        let mut purged = 0;
        for p in self.proxies.iter() {
            if let Some(t) = p.stick_table.as_ref() {
                purged += t.purge_expired().unwrap_or(0);
            }
        }
        // A stopping process gives back what the purge freed at once (`src/proxy.c:3715`).
        if self.stopping && purged > 0 {
            crate::pool_gc::request();
        }
    }

    /// Wakes a stream waiting for a buffer for each standard buffer given back on this thread
    /// since the last pass (`offer_buffers`, S6): most critical queue first, oldest first.
    #[cold]
    #[inline(never)]
    fn wake_buffer_waiters(&mut self) {
        while let Some((task, idx)) = crate::buf_wait::next_offered() {
            match self.sessions.get_mut(idx) {
                Some(e) if e.task == task && e.buf_wait.queued() && self.scheduler.is_live(task) => {
                    e.buf_wait.dequeued();
                    e.buf_wait.set_offered(true);
                    self.scheduler.tasklet_wakeup(task, Class::Urgent, state::WOKEN_IO);
                }
                // Gone or reused: the buffer is the next waiter's.
                _ => crate::buf_wait::reoffer(),
            }
        }
    }

    /// The accept limits' per-pass part, while one is in force: `global maxconn`'s pause
    /// expiring, the listeners it or a frontend's `maxconn` stopped resuming, the CLI's
    /// accept retry. Returns the poll timeout, shortened to the retry's instant.
    #[cold]
    #[inline(never)]
    fn limits_pass(&mut self, now_inst: Instant, poll_timeout: Duration) -> Duration {
        if let Some((until, actconn)) = self.accept_limited {
            if now_inst >= until || crate::globalconn::current() < actconn {
                self.accept_limited = None;
            }
        }
        self.resume_paused_listeners();
        match self.cli_accept_retry {
            Some(t) if t <= now_inst => {
                self.cli_accept_retry = None;
                self.resume_cli_after_close();
                poll_timeout
            }
            Some(t) => poll_timeout.min(t.saturating_duration_since(now_inst)),
            None => poll_timeout,
        }
    }

    /// Whether a housekeeping timer is to be queued after a pass that ran tasks: a periodic
    /// concern asleep, or the idle pool's purge instant moved.
    #[inline]
    fn housekeeping_rearm_wanted(&self) -> bool {
        const PERIODIC: u8 = (1 << hk::BUF_TRIM) | (1 << hk::STICK);
        self.housekeeping.armed & PERIODIC != PERIODIC || self.idle_backend_pool.next_purge() != self.housekeeping.purge_at
    }

    /// Runs the housekeeping concerns whose timers fired this pass (`due`), and queues the
    /// timers again: a periodic one while the thread is busy and [`hk::TAIL`] runs after, the
    /// purge at the idle pool's next purge.
    #[cold]
    #[inline(never)]
    fn run_housekeeping(&mut self, due: u8, inst: Instant) {
        let now = self.now;
        let activity = self.scheduler.stats().tasks_run.wrapping_sub(self.housekeeping.own_runs);
        for i in 0..hk::N {
            if due & (1 << i) == 0 {
                continue;
            }
            self.housekeeping.armed &= !(1 << i);
            self.housekeeping.own_runs += 1;
            #[cfg(debug_assertions)]
            ibex_sample::work::note(ibex_sample::work::Op::Housekeeping, 1);
            match i {
                hk::BUF_TRIM => crate::buf::trim_idle(inst),
                hk::STICK => self.purge_stick_tables(),
                _ => {
                    // The idle server connections beyond what their servers need are purged
                    // every `pool-purge-delay` (`srv_cleanup_idle_conns`): this is where that
                    // keyword acts.
                    let proxies = &self.proxies;
                    self.idle_backend_pool.purge(inst, |(be, s)| {
                        proxies.get(be).and_then(|p| p.server_actconn.get(s)).map_or(0, |a| a.load(Ordering::Relaxed))
                    });
                    self.housekeeping.purge_at = None;
                    continue;
                }
            }
            let h = &mut self.housekeeping;
            if activity == h.seen_runs[i] {
                h.idle_runs[i] = h.idle_runs[i].saturating_add(1);
            } else {
                h.seen_runs[i] = activity;
                h.idle_runs[i] = 0;
            }
            if h.idle_runs[i] < hk::TAIL[i] {
                self.scheduler.queue_timer(h.tasks[i], now.add(hk::PERIOD_MS[i]));
                h.armed |= 1 << i;
            }
        }
        // A periodic concern asleep wakes with the thread's work.
        for i in 0..hk::N {
            let h = &mut self.housekeeping;
            if hk::PERIOD_MS[i] != 0 && h.armed & (1 << i) == 0 && activity != h.seen_runs[i] && self.scheduler.is_live(h.tasks[i]) {
                h.idle_runs[i] = 0;
                self.scheduler.queue_timer(h.tasks[i], now.add(hk::PERIOD_MS[i]));
                h.armed |= 1 << i;
            }
        }
        let next = self.idle_backend_pool.next_purge();
        if next != self.housekeeping.purge_at {
            let task = self.housekeeping.tasks[hk::IDLE_PURGE];
            if let Some(t) = next.filter(|_| self.scheduler.is_live(task)) {
                // A millisecond late rather than early: a tick is the instant rounded down.
                self.scheduler.queue_timer(task, self.tick_at(t).add(1));
            }
            self.housekeeping.purge_at = next;
        }
    }

    pub fn step(&mut self, now: Tick) -> io::Result<usize> {
        self.step_at(now, Instant::now())
    }

    /// [`Self::step`] with the clock already read: `now_inst` is the instant `now` was taken
    /// from, what the deadlines before the poller are measured against.
    fn step_at(&mut self, now: Tick, now_inst: Instant) -> io::Result<usize> {
        #[cfg(debug_assertions)]
        ibex_sample::work::note(ibex_sample::work::Op::Pass, 1);
        self.now = now;
        crate::watchdog::progress();
        crate::watchdog::set_streams(self.sessions.live());
        self.wake_queued();
        if crate::buf_wait::pending() {
            self.wake_buffer_waiters();
        }

        // 1. Expire scheduler timers
        self.scheduler.set_now(now);
        let _ = self.scheduler.wake_expired_tasks();

        // 2. Determine epoll wait timeout based on scheduler. Queued tasklets count: a
        // session woken without a socket event -- the next pipelined request already in
        // its buffer -- otherwise waited for the poll timeout, 100 ms per request.
        // `runnable()` is the timer run queue only.
        let poll_timeout = if self.scheduler.run_queue_len() > 0 {
            Duration::from_millis(0)
        } else {
            let next_timer = self.scheduler.next_expiry();
            // A slot freed by another thread wakes nothing here: while requests queue,
            // look again soon.
            let cap = if crate::proxy::QueueWait::any() { 2 } else { 100 };
            if let Some(remain_ms) = next_timer.remaining(now) {
                Duration::from_millis(u64::from(remain_ms.min(cap)))
            } else {
                Duration::from_millis(cap.into())
            }
        };

        // While the listeners are stopped for `global maxconn`, a connection closed by
        // another worker is only noticed by looking: do not sleep through it.
        let poll_timeout = if self.global_paused || self.fe_paused { poll_timeout.min(Duration::from_millis(5)) } else { poll_timeout };

        // A QUIC transport's next deadline can be sooner than the scheduler's. Waiting past
        // it would delay loss recovery; the shortest of the two wins.
        let poll_timeout = if self.quic_listeners.is_empty() {
            poll_timeout
        } else {
            let poll_timeout = self
                .quic_listeners
                .iter_mut()
                .filter_map(crate::quic_listener::QuicListener::poll_timeout)
                .fold(poll_timeout, |acc, deadline| acc.min(deadline.saturating_duration_since(now_inst)));
            // Datagrams read and not served yet (a pass serves `RX_PER_PASS`, T560): the socket
            // may be empty and wake nothing, so look again at once. The listener is marked ready.
            if self.quic_listeners.iter().any(crate::quic_listener::QuicListener::has_backlog) {
                Duration::ZERO
            } else {
                poll_timeout
            }
        };

        // The idle server connections beyond what their servers need are purged every
        // `pool-purge-delay` (`srv_cleanup_idle_conns`): this is where that keyword acts.
        // A `pool_gc` was asked for (a signal, the stop path, a failed allocation on any
        // thread): this thread empties its caches, and the engine its own scratch lists.
        if crate::pool_gc::poll() {
            self.compact_arenas();
            self.wake_now_scratch = Vec::new();
            if self.wake_scratch.is_empty() {
                self.wake_scratch = Vec::new();
            }
            if self.h2_spawn_scratch.is_empty() {
                self.h2_spawn_scratch = Vec::new();
            }
        }
        // The pools' per-pass work stays (a load and two compares: the settings copy, and the
        // `show pools` counts at most every 10 ms, as every pass of a busy thread saw them);
        // the idle purge, the buffer trim and the stick-table expiry are the housekeeping
        // tasks (L1). Published from a timer, a burst's counts lagged the scrape that followed.
        ibex_alloc::pool::pass(now_inst);
        // The arenas' counts stay per pass: a compare each, and `show pools` and the scrape read
        // a stream's slot as soon as its pass made it.
        self.sessions.publish();
        self.applets.publish();
        self.scheduler.tasks.publish();
        // The accept limits: one test when none is in force.
        let poll_timeout = if self.accept_limited.is_some() || self.global_paused || self.fe_paused || self.cli_accept_retry.is_some() {
            self.limits_pass(now_inst, poll_timeout)
        } else {
            poll_timeout
        };

        // 3. Poll readiness events
        let mut events = std::mem::take(&mut self.events);
        events.clear();
        crate::watchdog::sleeping(true);
        let polled = self.poller.poll(Some(poll_timeout), |ev| events.push(ev));
        crate::watchdog::sleeping(false);
        crate::watchdog::progress();
        polled?;

        // The time now, not the time the pass started: everything below arms its timers from
        // `now`, and a connection accepted or a request read after the poller waited would
        // otherwise have its deadlines early by the time the engine was idle (up to the 100
        // ms poll bound). One clock read per loop pass, as HAProxy's `tv_update_date` after
        // its poller. The timers that expired during the wait are woken by it too.
        crate::probe::clock_read();
        let pass_start = Instant::now();
        // `tune.ibex.zero-on-free soft`: this thread's quarantine, emptied when the poller found
        // nothing to do, else what passed the age bound and a small budget. One load when off.
        ibex_alloc::zero_on_free::pass(pass_start, events.is_empty());
        crate::txnlog::set_loop_now(pass_start);
        let now = self.tick_at(pass_start);
        self.now = now;
        self.scheduler.set_now(now);
        let _ = self.scheduler.wake_expired_tasks();

        // 4. Process polled readiness events
        let mut mail = false;
        for &ev in &events {
            // A descriptor handled keeps the thread from being killed, not from being
            // reported: `fd_update_events` clears `TH_FL_STUCK` (src/fd.c:685), only a
            // task run clears `sched_stuck`.
            crate::watchdog::under_control();
            match self.fdtab.state(ev.fd) {
                FdState::Listener { listener: l_idx } => {
                    let l_idx = l_idx as usize;
                    if l_idx < self.listeners.len() {
                        self.accept_from_listener(l_idx);
                    }
                }
                FdState::CliListener => {
                    self.accept_from_cli_listener(None);
                }
                FdState::CliExtra(i) => {
                    self.accept_from_cli_listener(Some(i as usize));
                }
                FdState::Conn { task, conn: _ } => {
                    // A hang-up or error is news for a reader too: the read that finds it
                    // must not be skipped by a socket marked drained (`cli_cant_recv`).
                    self.fdtab.set_ready(ev.fd, ev.readable || ev.closed, ev.writable);
                    // The handshake is over: the connection leaves `Heavy` (`ssl_sock_io_cb`
                    // clears `TASK_HEAVY` once `CO_FL_SSL_WAIT_HS` is gone).
                    if self.scheduler.is_heavy(task) {
                        let kind = self.scheduler.tasks.get(task).kind;
                        let done = kind.kind() != Some(Kind::Stream)
                            || self
                                .sessions
                                .get(kind.index())
                                .is_none_or(|e| !e.sess.cli_tls_handshaking() && !e.sess.srv_tls_handshaking());
                        if done {
                            self.scheduler.set_heavy(task, false);
                        }
                    }
                    self.scheduler
                        .tasklet_wakeup(task, Class::Urgent, state::WOKEN_IO);
                }
                FdState::QuicListener { listener: q_idx }
                | FdState::QuicBackend { listener: q_idx } => {
                    // A QUIC connection is not a descriptor, so there is nothing to accept
                    // and no task to wake: the listener demultiplexes by connection ID.
                    // Both the UDP socket and any backend socket it opened drive the same
                    // listener, which is why they share an arm.
                    if let Some(ql) = self.quic_listeners.get_mut(q_idx as usize) {
                        ql.mark_ready();
                    }
                }
                FdState::Mailbox => mail = true,
                FdState::Resolver { section } => {
                    if let Some(sec) = self.resolvers.get(section as usize) {
                        self.scheduler.tasklet_wakeup(sec.task, Class::Normal, state::WOKEN_IO);
                    }
                }
                // One of this worker's idle server connections: its server closed it, or
                // sent what nobody asked for (T434).
                FdState::Idle => {
                    if !self.idle_backend_pool.idle_event(ev.fd) {
                        self.fdtab.remove(ev.fd);
                    }
                }
                FdState::Closed => {}
            }
        }
        self.events = events;
        if mail {
            self.serve_mailbox();
        }

        // Drive every QUIC listener that had readiness, and every one whose transport timer
        // has expired. `poll_timeout` is asked rather than calling `handle_timeout` on each
        // wakeup, because a transport told the time has advanced when it has not will arm and
        // fire loss-recovery timers that are not due.
        // The pass's clock: read once after the poller, as everything since.
        let inst = pass_start;
        if !self.quic_listeners.is_empty() {
            for ql in &mut self.quic_listeners {
                let timer_due = ql.poll_timeout().is_some_and(|d| d <= inst);
                if timer_due {
                    ql.handle_timeout(inst);
                }
                // Sent at the end of the pass, with what the owner sessions write (Q1).
                if ql.take_ready() || timer_due {
                    let _ = ql.serve(inst);
                }
            }
            self.admit_quic_connections();
            self.adopt_quic_owners();
            self.adopt_quic_streams();
            self.sync_quic_backend_fds();
            let mut quic_wake = std::mem::take(&mut self.wake_scratch);
            for ql in &mut self.quic_listeners {
                ql.take_wake(&mut quic_wake);
            }
            for t in quic_wake.drain(..) {
                if self.scheduler.is_live(t) {
                    self.scheduler.tasklet_wakeup(t, Class::Urgent, state::WOKEN_IO);
                }
            }
            self.wake_scratch = quic_wake;
        }

        // 5. Run runnable tasks through Dispatch
        let pid = self.pid;
        let total_tasks = self.scheduler.live_tasks();
        let run_queue_len = self.scheduler.run_queue_len();
        crate::stats::note_sched(total_tasks, run_queue_len);

        let mut timer_updates = std::mem::take(&mut self.timer_updates);
        timer_updates.clear();

        let mut dispatcher = EngineDispatcher {
            sessions: &mut self.sessions,
            applets: &mut self.applets,
            proxies: &mut self.proxies,
            checks: &mut self.checks,
            resolvers: &mut self.resolvers,
            fdtab: &mut self.fdtab,
            poller: &mut self.poller,
            listeners: &mut self.listeners,
            start_time: self.start_time,
            pid,
            total_tasks,
            run_queue_len,
            now,
            timer_updates,
            wake_queue: std::mem::take(&mut self.wake_scratch),
            heavy: Vec::new(),
            h2_spawn: std::mem::take(&mut self.h2_spawn_scratch),
            log_targets: &self.log_targets,
            log_tag: &self.log_tag,
            idle_backend_pool: &mut self.idle_backend_pool,
            mailboxes: &self.mailboxes,
            worker_id: self.mailbox_wid,
            quic_listeners: &mut self.quic_listeners,
            hk_due: 0,
            wake_now: std::mem::take(&mut self.wake_now_scratch),
        };

        let tasks_run = self.scheduler.process_runnable_tasks(&mut dispatcher);
        let hk_due = dispatcher.hk_due;
        self.wake_now_scratch = std::mem::take(&mut dispatcher.wake_now);
        // What the other workers changed on the servers whose checks run here (T593).
        crate::track::adopt_pending(dispatcher.proxies, dispatcher.checks);
        // The server state changes the pass made (a check, the CLI, the stats page).
        if crate::srvlog::pending() {
            let proxies = dispatcher.proxies.clone();
            crate::srvlog::drain(&proxies, |proxy, level, msg| dispatcher.send_log(proxy, level, b"", msg.as_bytes()));
        }
        // A task recorded here may have ended later in the same pass (a session shut down
        // by the CLI, then run to `Outcome::Done`), and the scheduler has freed it. Its
        // slot must not be queued: it is handed to the next connection, and the stale
        // membership corrupted the tasklet lists (T100). No task is allocated during the
        // pass, so a live reference here still names the task it was recorded for.
        for &(task_ref, expiry) in &dispatcher.timer_updates {
            if self.scheduler.is_live(task_ref) {
                self.scheduler.queue_timer(task_ref, expiry);
            }
        }
        for &task_ref in &dispatcher.heavy {
            if self.scheduler.is_live(task_ref) {
                self.scheduler.set_heavy(task_ref, true);
            }
        }
        let mut h2_spawn = std::mem::take(&mut dispatcher.h2_spawn);
        let mut wake_queue = std::mem::take(&mut dispatcher.wake_queue);
        self.timer_updates = dispatcher.timer_updates;
        for (owner_idx, owner_task) in h2_spawn.drain(..) {
            self.spawn_h2_children(owner_idx, owner_task, &mut wake_queue);
        }
        // What the owners of HTTP/3 connections wrote goes out now (T509), with what the
        // listener's own pass (`serve`) left to send: one send a pass (Q1). The clock is read
        // only when there is one: once per pass is a fifth of an h1 request's added cost otherwise.
        for ql in &mut self.quic_listeners {
            if ql.take_dirty() {
                let _ = ql.send_batch(Instant::now());
            }
            ql.take_wake(&mut wake_queue);
        }
        for task_ref in wake_queue.drain(..) {
            if self.scheduler.is_live(task_ref) {
                self.scheduler
                    .tasklet_wakeup(task_ref, Class::Urgent, state::WOKEN_IO);
            }
        }
        self.h2_spawn_scratch = h2_spawn;
        self.wake_scratch = wake_queue;
        if hk_due != 0 || (tasks_run > 0 && self.housekeeping_rearm_wanted()) {
            self.run_housekeeping(hk_due, inst);
        }
        // Slots this pass freed go to the queue now, not on the next poll's timeout.
        self.wake_queued();
        self.resume_cli_after_close();
        Ok(tasks_run)
    }

    /// The streams of HTTP/2 connection `owner_idx` whose request heads are in get entries of
    /// their own (T280), as many as [`TcpSession::h2_max_children`] at once: a child
    /// session that starts the stream's transaction, with a task of its own, run with its
    /// owner (which moves the request's body).
    fn spawn_h2_children(&mut self, owner_idx: u32, owner_task: TaskRef, wake_queue: &mut Vec<TaskRef>) {
        let now = self.now;
        loop {
            let Some(owner) = self.sessions.get_mut(owner_idx).filter(|o| o.task == owner_task) else { return };
            if owner.sess.is_done()
                || !matches!(owner.sess.cli_state, ScState::Ready | ScState::Established)
                || owner.sess.h2_owner().is_none_or(|o| o.children.len() >= owner.sess.h2_max_children())
            {
                return;
            }
            let keep = owner.sess.keep_request_line;
            let d = match owner.sess.h3_owner_mut() {
                Some(h3) => crate::h2_bridge::dispatch_mux(&mut *h3.mux, keep, "HTTP/3.0"),
                None => owner.sess.h2_ctx.as_deref_mut().and_then(|h2| crate::h2_bridge::dispatch_next(h2, keep)),
            };
            let Some(d) = d else { return };
            let stream_id = d.stream.id;
            let mut sess = TcpSession::h2_child_of(&mut owner.sess, (owner_idx, owner_task), d.stream);
            sess.h3 = owner.sess.h3;
            // T569: the connection's acknowledgement counts as this request found them.
            if let Some(h3) = owner.sess.h3_owner() {
                let facts = self.quic_listeners.get(h3.listener as usize).and_then(|ql| ql.ack_facts(h3.conn));
                if let Some(c) = sess.h2_child_mut() {
                    c.quic_ack = Some(crate::proxy::QuicAckSrc { listener: h3.listener, conn: h3.conn, facts });
                }
            }
            // An HTTP/2 owner stamps the first byte of each stream as it reads it; an HTTP/3
            // one reads no bytes of its own. The stream's request head is in, which is where
            // its idle time (`Ti`, since the connection's previous stream ended) stops and
            // its own `TR` and `Ta` start (T529). Left unset, `TR` and `Ta` held the idle gap.
            if owner.sess.h3 {
                sess.log.first_byte_now();
            }
            let entry = SessionEntry {
                sess,
                task: TaskRef::NONE,
                proxy_idx: owner.proxy_idx,
                backend_idx: owner.proxy_idx,
                srv_backend_idx: owner.proxy_idx,
                target_server_idx: None,
                // The connection's, which `show sess` shows; never polled through this entry.
                cli_raw_fd: owner.cli_raw_fd,
                srv_raw_fd: None,
                cli_interest: Interest::NONE,
                srv_interest: Interest::NONE,
                actconn_reclaimed: false,
                stats_done: false,
                be_counted: std::cell::Cell::new(NO_BACKEND),
                connect_log_due: false,
                rate_max_due: false,
                srv_served: 0,
                log_line: None,
                log_err: false,
                log_sd: 0,
                buf_wait: crate::buf_wait::WaitState::default(),
            };
            // Neither fails before the `u32` indices run out.
            let Some(child_idx) = self.sessions.alloc(entry) else { return };
            let Some(task) = self.scheduler.create(WorkKind::new(Kind::Stream, child_idx)) else { self.sessions.free(child_idx); return };
            let Some((owner, child)) = self.sessions.get2_mut(owner_idx, child_idx) else { return };
            child.task = task;
            // A server connection the last stream kept goes to this one, as the session
            // kept it for its next request.
            move_server(owner, child, &mut self.fdtab);
            // It is not this stream's until a request takes it (`bc_idle`, T491).
            child.sess.bc_idle = child.sess.srv.is_some();
            let head = crate::h2_bridge::start_request(&mut child.sess, d);
            if let Some(h2) = owner.sess.h2_ctx.as_deref_mut() {
                h2.give_back_head(head);
            } else if let Some(h3) = owner.sess.h3_owner_mut() {
                ibex_proto::htx_mux::HtxMux::give_back_head(&mut *h3.mux, head);
            }
            // The stream's own `timeout client` starts with it (T300).
            child.sess.arm_client(now);
            if let Some(o) = owner.sess.h2_owner_mut() {
                o.children.push(crate::proxy::H2ChildLink { idx: child_idx, task, stream_id });
            }
            wake_queue.push(task);
            wake_queue.push(owner_task);
        }
    }

    /// Accepts on the first CLI socket (`which` is `None`) or on the `which`th further one.
    fn accept_from_cli_listener(&mut self, which: Option<usize>) {
        // `tune.maxaccept` applies to a stats socket as to any listener (`bind_conf->maxaccept`).
        let mut left = self.maxaccept;
        loop {
            if left == 0 {
                return;
            }
            left -= 1;
            if self.applets.live() >= self.cli_maxconn {
                self.set_cli_listening(false);
                return;
            }
            let (listener, level, name) = match which {
                None => (self.cli_listener.as_ref(), self.cli_level, self.cli_socket_name.as_ref()),
                // `FdState::CliExtra(i)` is registered by `adopt_extra_cli` with `i` its index.
                Some(i) => (self.extra_cli[i].listener.as_ref(), self.extra_cli[i].level, Some(&self.extra_cli[i].name)),
            };
            let Some(listener) = listener else {
                return;
            };
            match listener.accept() {
                Ok(stream) => {
                    crate::globalconn::note_accept();
                    let mut applet = CliApplet::new(stream, self.now);
                    // T320: count each CLI connection.
                    crate::stats::CUM_STREAMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    applet.timeout_ms = self.cli_timeout_ms;
                    applet.level = level;
                    applet.socket_name = name.cloned();
                    applet.socket_list = self.cli_sockets_text();
                    let raw_fd = applet.raw_fd;

                    let Some(applet_idx) = self.applets.alloc(applet) else {
                        break;
                    };

                    let Some(task_ref) = self
                        .scheduler
                        .create(WorkKind::new(Kind::Applet, applet_idx))
                    else {
                        self.applets.free(applet_idx);
                        break;
                    };

                    let Some(entry) = self.applets.get_mut(applet_idx) else {
                        break;
                    };
                    entry.task = task_ref;

                    {
                        self.fdtab.insert(
                            raw_fd,
                            FdState::Conn {
                                task: task_ref,
                                conn: 0,
                            },
                            Interest::READ,
                        );
                        if let Some(ref stream) = entry.stream {
                            let _ = self.poller.add(stream.as_fd(), raw_fd_to_u64(raw_fd), true, false);
                        }
                    }

                    self.scheduler.queue_timer(task_ref, self.now.add(60_000));
                    self.scheduler
                        .tasklet_wakeup(task_ref, Class::Urgent, state::WOKEN_IO);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    use rustix::io::Errno;
                    let out_of = [Errno::MFILE, Errno::NFILE, Errno::NOBUFS, Errno::NOMEM].map(Errno::raw_os_error);
                    if e.raw_os_error().is_some_and(|n| out_of.contains(&n)) {
                        self.set_cli_listening(false);
                        self.cli_accept_retry = Some(Instant::now() + Duration::from_millis(100));
                    }
                    break;
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn accept_from_listener(&mut self, l_idx: usize) {
        let proxy_idx = self.listeners[l_idx].proxy as usize;
        if proxy_idx >= self.proxies.len() {
            return;
        }

        if crate::globalconn::full() {
            self.pause_listeners_for_global();
            return;
        }

        let lfd = self.listeners[l_idx].raw_fd();
        if self.listeners[l_idx].is_full() {
            let _ = self.poller.modify(
                self.listeners[l_idx].borrowed_fd(),
                raw_fd_to_u64(lfd),
                false,
                false,
            );
            self.fdtab.set_interest(lfd, Interest::NONE);
            self.fe_paused = true;
            self.backlog_waits = true;
            return;
        }

        // The slot of `global maxconn` is taken before accepting, atomically: workers
        // checking `full()` and then counting would overshoot it by up to one each. The
        // connection's slot is then `admit_connection`'s to release if it refuses it.
        // The frontend's `maxconn` slot is taken the same way (`ConnLimit::try_inc`).
        // `tune.maxaccept` reaches the data path here: at most that many accepts per wakeup.
        let mut left = self.maxaccept;
        while left > 0 && self.listeners[l_idx].maxconn.try_inc() {
            left -= 1;
            if !crate::globalconn::try_acquire() {
                self.listeners[l_idx].maxconn.dec();
                break;
            }
            let accept_res = self.listeners[l_idx].accept();
            let Some((cli_fd, peer_addr)) = (match accept_res {
                Ok(Some(pair)) => Some(pair),
                Ok(None) => None,
                Err(_) => {
                    crate::globalconn::release();
                    self.listeners[l_idx].maxconn.dec();
                    self.pause_listeners_for_accept_error();
                    return;
                }
            }) else {
                crate::globalconn::release();
                self.listeners[l_idx].maxconn.dec();
                // The backlog is drained: what is accepted next has not waited.
                self.backlog_waits &= self.fe_paused || self.global_paused;
                break;
            };
            crate::globalconn::note_accept();
            let local_addr = self.listeners[l_idx].addr();
            self.admit_connection(proxy_idx, Some(l_idx), cli_fd, peer_addr, local_addr, None);
        }
    }

    /// `accept` failed other than with an empty queue -- out of fds or memory: stop polling
    /// every listener for 100 ms, or until a client connection closes (`accept_limited`).
    fn pause_listeners_for_accept_error(&mut self) {
        self.accept_limited = Some((Instant::now() + Duration::from_millis(100), crate::globalconn::current()));
        self.pause_listeners_for_global();
    }

    /// `global maxconn` is reached: stop polling every listener. The connections wait in
    /// the backlog; `step` resumes the listeners once the count is back under the limit.
    fn pause_listeners_for_global(&mut self) {
        for l in &self.listeners {
            let lfd = l.raw_fd();
            let _ = self.poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), false, false);
            self.fdtab.set_interest(lfd, Interest::NONE);
        }
        self.global_paused = true;
        self.backlog_waits = true;
    }

    /// Re-arms the listeners stopped at their frontend's `maxconn` whose frontend has room
    /// again (a connection closed on another worker, or `set maxconn frontend` raised it).
    fn resume_listeners_after_frontend_limit(&mut self) {
        let mut still_full = false;
        for l in &self.listeners {
            let lfd = l.raw_fd();
            if !self.fdtab.interest(lfd).is_none() {
                continue;
            }
            if l.is_full() {
                still_full = true;
            } else {
                let _ = self.poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), true, false);
                self.fdtab.set_interest(lfd, Interest::READ);
            }
        }
        self.fe_paused = still_full;
    }

    /// Re-arms the listeners a limit stopped, once the limit has room again: `global maxconn`
    /// ([`Self::resume_listeners_after_global`]) and a frontend's own `maxconn`
    /// ([`Self::resume_listeners_after_frontend_limit`]). Called on every pass of `step`.
    fn resume_paused_listeners(&mut self) {
        // Paused by SIGTTOU: SIGTTIN re-arms them ([`Self::resume_on_signal`]).
        if self.sig_paused {
            return;
        }
        if self.global_paused && self.accept_limited.is_none() && !crate::globalconn::full() {
            self.resume_listeners_after_global();
        }
        if self.fe_paused && !self.global_paused {
            self.resume_listeners_after_frontend_limit();
        }
    }

    /// Undoes [`Self::pause_listeners_for_global`] for the listeners that have room of
    /// their own.
    fn resume_listeners_after_global(&mut self) {
        self.global_paused = false;
        for l in &self.listeners {
            let lfd = l.raw_fd();
            if self.fdtab.interest(lfd).is_none() {
                if l.is_full() {
                    // Still stopped, by its frontend's limit now: `fe_paused` is what makes
                    // `step` look at that limit again (T430 row 33).
                    self.fe_paused = true;
                } else {
                    let _ = self.poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), true, false);
                    self.fdtab.set_interest(lfd, Interest::READ);
                }
            }
        }
    }

    /// Admits a client connection to frontend `proxy_idx`: stick and `tcp-request
    /// connection` rules, counters, then the session. `l_idx` is the TCP listener that
    /// accepted it; `None` for an HTTP/3 request stream (`adopt_quic_streams`), which has
    /// no listener slot of its own to count against.
    fn admit_connection(
        &mut self,
        proxy_idx: usize,
        l_idx: Option<usize>,
        cli_fd: std::os::fd::OwnedFd,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        quic_ack: Option<crate::proxy::QuicAckSrc>,
    ) {
        if l_idx.is_some() {
            count_global_conn();
        }
        {
            let mut tracked_sc: [Option<(usize, StickKey)>; 3] = [None, None, None];

            let sample_ctx = SampleContext {
                proxies: Some(&ProxiesView(&self.proxies)),
                client_addr: Some(peer_addr),
                server_addr: Some(local_addr),
                fc_src: Some(peer_addr),
                fc_dst: Some(local_addr),
                act_conn: self.proxies[proxy_idx].counters().act_conn.load(Ordering::Relaxed),
                ..Default::default()
            };

            // 1. Process stick_rules (e.g. `track-sc0 src` from frontend/listen)
            for (srule, rc) in self.proxies[proxy_idx].stick_rules.iter().zip(&self.proxies[proxy_idx].rules.stick) {
                let slot = match srule.rule_type {
                    ibex_config::StickRuleType::TrackSc0 => Some(0),
                    ibex_config::StickRuleType::TrackSc1 => Some(1),
                    ibex_config::StickRuleType::TrackSc2 => Some(2),
                    _ => None,
                };
                if let Some(slot) = slot {
                    if let Some(key) = resolve_stick_key(rc.expr.as_ref(), sample_registry(), &sample_ctx, self.proxies[proxy_idx].stick_table.as_ref()) {
                        if let Some(ref tbl) = self.proxies[proxy_idx].stick_table {
                            if tracked_sc[slot].is_none() {
                                let _ = tbl.update_entry(&key, |data| data.track(true));
                                tracked_sc[slot] = Some((proxy_idx, key));
                            }
                        }
                    }
                }
            }

            // 2. Process tcp_req_conn_rules (e.g. `tcp-request connection track-sc0 ...`)
            for (rule, rc) in self.proxies[proxy_idx].tcp_req_conn_rules.iter().zip(&self.proxies[proxy_idx].rules.tcp_req_conn) {
                let matches = rc.cond.as_ref().is_none_or(|c| c.eval(&sample_ctx, &self.proxies[proxy_idx].acls, sample_registry()));
                if !matches {
                    continue;
                }
                match &rule.action {
                    ibex_config::TcpReqConnAction::TrackSc0 { table, expr: _ } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_stick_key(rc.expr.as_ref(), sample_registry(), &sample_ctx, self.proxies[t_idx].stick_table.as_ref()) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                if tracked_sc[0].is_none() {
                                    let _ = tbl.update_entry(&key, |data| data.track(true));
                                    tracked_sc[0] = Some((t_idx, key));
                                }
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc1 { table, expr: _ } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_stick_key(rc.expr.as_ref(), sample_registry(), &sample_ctx, self.proxies[t_idx].stick_table.as_ref()) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                if tracked_sc[1].is_none() {
                                    let _ = tbl.update_entry(&key, |data| data.track(true));
                                    tracked_sc[1] = Some((t_idx, key));
                                }
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc2 { table, expr: _ } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_stick_key(rc.expr.as_ref(), sample_registry(), &sample_ctx, self.proxies[t_idx].stick_table.as_ref()) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                if tracked_sc[2].is_none() {
                                    let _ = tbl.update_entry(&key, |data| data.track(true));
                                    tracked_sc[2] = Some((t_idx, key));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            let (client_addr, server_addr, fc_src, fc_dst, expect_proxy) = match eval_tcp_req_conn_rules(
                &self.proxies[proxy_idx],
                &self.proxies,
                sample_registry(),
                peer_addr,
                local_addr,
                &tracked_sc,
            ) {
                ConnEvalOutcome::Accept(c, s, fs, fd, ep) => (c, s, fs, fd, ep),
                ConnEvalOutcome::Reject => {
                    raw::abort_with_rst(cli_fd.as_fd());
                    self.proxies[proxy_idx].counters().denied_conn.fetch_add(1, Ordering::Relaxed);
                    for (t_idx, ref key) in tracked_sc.iter().flatten() {
                        if let Some(ref tbl) = self.proxies[*t_idx].stick_table {
                            let _ = tbl.update_entry(key, |data| {
                                data.untrack();
                            });
                        }
                    }
                    drop(cli_fd);
                    if let Some(l_idx) = l_idx {
                        crate::globalconn::release();
                        self.listeners[l_idx].maxconn.dec();
                    }
                    return;
                }
                ConnEvalOutcome::SilentDrop(ttl) => {
                    raw::silent_drop(cli_fd.as_fd(), peer_addr.is_ipv6(), ttl);
                    self.proxies[proxy_idx].counters().denied_conn.fetch_add(1, Ordering::Relaxed);
                    for (t_idx, ref key) in tracked_sc.iter().flatten() {
                        if let Some(ref tbl) = self.proxies[*t_idx].stick_table {
                            let _ = tbl.update_entry(key, |data| {
                                data.untrack();
                            });
                        }
                    }
                    drop(cli_fd);
                    if let Some(l_idx) = l_idx {
                        crate::globalconn::release();
                        self.listeners[l_idx].maxconn.dec();
                    }
                    return;
                }
            };

            let proxy = &self.proxies[proxy_idx];
            // An HTTP/3 request stream (`l_idx` is `None`) is a stream of its QUIC connection,
            // which `admit_quic_connections` counted as the session: no connection counter.
            if l_idx.is_some() {
                proxy.counters().cum_conn.fetch_add(1, Ordering::Relaxed);
                proxy.counters().fe_sess_rate.tick();
                proxy.counters().fe_conn_rate.tick();
            }
            // Once per TCP connection; a QUIC connection is counted by the QUIC listener,
            // not per HTTP/3 request stream (`l_idx` is `None` for those).
            if l_idx.is_some() {
                count_global_sess();
            }
            // `rate_max` counts sessions: it is raised once the TLS handshake is done, not here.
            // An HTTP/3 request stream takes no connection slot (`admit_quic_connections`).
            if l_idx.is_some() {
                let conn_rate = proxy.counters().fe_conn_rate.rate();
                proxy.txn_counters().fe.conn_rate_max.fetch_max(u32::try_from(conn_rate).unwrap_or(u32::MAX), Ordering::Relaxed);
                proxy.counters().act_conn.fetch_add(1, Ordering::Relaxed);
                // From the accept loop the slot of `global maxconn` is already taken (`try_acquire`).
                if proxy.counters().act_conn.load(Ordering::Relaxed) > proxy.counters().max_conn.load(Ordering::Relaxed) {
                    proxy.counters().max_conn.store(proxy.counters().act_conn.load(Ordering::Relaxed), Ordering::Relaxed);
                }
            }

            if let Some(l_idx) = l_idx.filter(|&i| self.listeners[i].is_full()) {
                let lfd = self.listeners[l_idx].raw_fd();
                let _ = self.poller.modify(
                    self.listeners[l_idx].borrowed_fd(),
                    raw_fd_to_u64(lfd),
                    false,
                    false,
                );
                self.fdtab.set_interest(lfd, Interest::NONE);
                self.fe_paused = true;
                self.backlog_waits = true;
            }

            register_new_session(
                self,
                proxy_idx,
                l_idx,
                cli_fd,
                peer_addr,
                client_addr,
                server_addr,
                fc_src,
                fc_dst,
                tracked_sc,
                expect_proxy,
                quic_ack,
            );
        }
    }

    /// Runs the engine loop until `is_running` is set to false.
    ///
    /// # Errors
    /// Propagates polling errors.
    pub fn run_loop(&mut self) -> io::Result<()> {
        // Whether the last step found nothing to run. HAProxy closes the idle front
        // connections of a stopping process only when a thread has nothing left to do
        // (`run_poll_loop`, `src/haproxy.c`, wakes `mux_stopping_data`). Under constant
        // keep-alive load that moment rarely comes, so a client is answered with
        // `Connection: close` instead of having its connection closed between two
        // requests -- the race it can only survive by retrying. Closing them at once, on
        // every turn of the loop, made 311 requests in 100 reloads hit a closed connection
        // where HAProxy has 23 (T166, `tools/measure/reload_under_load.py`).
        let mut quiet = true;
        while self.is_running {
            if !self.stopping
                && self
                    .lifecycle
                    .as_ref()
                    .is_some_and(crate::lifecycle::Lifecycle::soft_stop_requested)
            {
                self.begin_soft_stop();
            }
            // SIGQUIT (`dump`): every worker empties its caches at its next pass (T445).
            if self.lifecycle.as_ref().is_some_and(crate::lifecycle::Lifecycle::take_flush_request) {
                crate::pool_gc::request();
            }
            let want = self.lifecycle.as_ref().map_or(self.sig_paused, crate::lifecycle::Lifecycle::pause_requested);
            // A SIGTTIN after a resume that was refused (the name still held) tries again.
            let again = !want && !self.paused_abns.is_empty() && self.lifecycle.as_ref().is_some_and(crate::lifecycle::Lifecycle::take_resume);
            if !self.stopping {
                if want != self.sig_paused {
                    if want {
                        self.pause_on_signal();
                    } else {
                        self.resume_on_signal();
                    }
                } else if again {
                    self.resume_cli_again();
                }
            }
            if self.stopping {
                if quiet {
                    self.close_idle_http_sessions();
                }
                // A CLI session open is waited for too, as `HAProxy`'s stopping thread
                // waits for its last stream, applets included (T456: worker 0, which
                // serves the CLI, left as soon as it had no client session, and dropped
                // the CLI sessions open on it).
                if self.sessions.live() == 0
                    && self.applets.live() == 0
                    && !self.quic_listeners.iter().any(crate::quic_listener::QuicListener::is_busy)
                {
                    // Done; the workers leave together (`Mailboxes::all_done`).
                    self.mailboxes.mark_done(self.mailbox_wid);
                    if self.mailboxes.all_done() {
                        break;
                    }
                }
                if self.stop_deadline.is_some_and(|d| Instant::now() >= d) {
                    self.linger_close_sessions();
                    break;
                }
            }
            // One clock read a pass, after the poller (`pass_start`): the deadlines the poller
            // waits for are measured from the previous pass's, as HAProxy's `now_ms` is (T579, C2).
            let at = crate::txnlog::loop_now();
            let ran = self.step_at(self.tick_at(at), at)?;
            quiet = ran == 0 && self.scheduler.run_queue_len() == 0;
        }
        Ok(())
    }

    /// Attaches the process lifecycle, so the run loop observes `SIGUSR1`.
    pub fn set_lifecycle(&mut self, lifecycle: crate::lifecycle::Lifecycle) {
        self.lifecycle = Some(lifecycle);
    }

    /// HAProxy's `soft_stop()` (`src/proxy.c:3961`): stop accepting, keep serving what is
    /// in flight, and exit once it has drained or `hard-stop-after` expires.
    ///
    /// QUIC listeners are deliberately left open. A QUIC connection lives on the listening
    /// UDP socket itself, so closing it would cut every in-flight HTTP/3 request, which is
    /// the opposite of a soft stop. Each one stops taking new connections and drains
    /// (`QuicListener::begin_soft_stop`); the loop waits for it like it waits for sessions.
    pub fn begin_soft_stop(&mut self) {
        if self.stopping {
            return;
        }
        self.stopping = true;
        ibex_sample::STOPPING.store(true, Ordering::Relaxed);
        // `sig_soft_stop` ends with `pool_gc(NULL)`: once for the process, not once a worker.
        if !SOFT_STOP_GC.swap(true, Ordering::Relaxed) {
            crate::pool_gc::request();
        }
        self.stop_deadline = self.hard_stop_after.map(|d| Instant::now() + d);
        crate::systemd::notify_stopping_once();

        // Listener indices live in the fd table, so entries cannot be removed one at a
        // time; every listener goes at once. Session teardown looks listeners up with
        // `find`, which is a no-op on an empty vector.
        for l in self.listeners.drain(..) {
            self.fdtab.remove(l.raw_fd());
            let _ = self.poller.delete(l.borrowed_fd());
        }
        // The `_getsocks` registry holds duplicates of those sockets. Left in place they
        // would keep each socket open -- and queueing connections -- after its listener
        // is gone. By now the new process has taken what it needs.
        crate::handover::withdraw_all();
        crate::logfwd::soft_stop();
        for ql in &mut self.quic_listeners {
            ql.begin_soft_stop();
            // Handed over: the socket stays open (this process still sends on it) but is the
            // next process's to read (T558).
            if ql.is_deaf() {
                let _ = self.poller.delete(ql.borrowed_fd());
            }
        }
        if let Some(cli) = self.cli_listener.take() {
            self.fdtab.remove(cli.as_raw_fd());
            let _ = self.poller.delete(cli.as_fd());
        }
        for x in &mut self.extra_cli {
            if let Some(l) = x.listener.take() {
                self.fdtab.remove(l.as_raw_fd());
                let _ = self.poller.delete(l.as_fd());
            }
        }

        // An HTTP session finishes the transaction it is in and then closes, instead of
        // waiting for another request that this process will not be around to serve.
        for (_, e) in self.sessions.iter_mut() {
            if e.sess.mode == Mode::Http {
                if let Some(t) = e.sess.txn.as_mut() {
                    t.close_after = true;
                    t.close_opt = false;
                }
                e.sess.stopping = true;
                // And so does every transaction it starts from here on: a request read
                // after the stop is answered with `Connection: close`, as HAProxy switches
                // a keep-alive stream to close mode once its frontend is stopping
                // (`src/mux_h1.c`, `h1_set_cli_conn_mode`). Without it the client is told
                // to reuse a connection the next loop closes under it (T166).
                e.sess.close_client = true;
                if let Some(ref mut h2_ctx) = e.sess.h2_ctx {
                    h2_ctx.send_graceful_goaway();
                    // Wake up the task so the mux can flush the frame. No liveness check:
                    // a task is freed only when its run returns `Outcome::Done`, and that
                    // run frees its session first (`self.sessions.free`), so a session still
                    // in the table names a live task, and no task runs during this loop.
                    debug_assert!(self.scheduler.is_live(e.task), "a session in the table names a freed task");
                    self.scheduler
                        .tasklet_wakeup(e.task, Class::Urgent, state::WOKEN_IO);
                }
            }
        }
    }

    /// Closes HTTP sessions that are between requests. They hold no work, and keeping
    /// them would let every idle keep-alive client hold a stopping process open until
    /// `timeout client`. A request already on the wire but not yet read is lost with the
    /// connection; clients retry that case, and HAProxy has the same window. An idle
    /// HTTP/2 connection is told first, with a graceful GOAWAY, and closed once that has
    /// been written (`src/mux_h2.c:5501`).
    /// The end of `hard-stop-after`: every connection still open gets a FIN, then what its
    /// peer is still sending is read and discarded until the peer closes or 200 ms pass.
    /// Leaving with bytes unread in a socket makes the kernel answer the close with a RST,
    /// which a client that kept sending through a WebSocket saw as a reset, not an EOF.
    fn linger_close_sessions(&mut self) {
        use std::os::fd::AsFd;
        for (_, e) in self.sessions.iter_mut() {
            e.sess.shutw_cli();
            if let Some(srv) = e.sess.srv.as_ref() {
                raw::shutdown_write(srv.as_fd());
            }
        }
        let end = Instant::now() + Duration::from_millis(200);
        let mut buf = [0u8; 16384];
        let mut done: std::collections::HashSet<std::os::fd::RawFd> = std::collections::HashSet::new();
        loop {
            let mut pending = 0usize;
            for (_, e) in self.sessions.iter_mut() {
                for fd in e.sess.cli_fd().into_iter().chain(e.sess.srv.as_ref().map(|s| s.as_fd())) {
                    if done.contains(&std::os::fd::AsRawFd::as_raw_fd(&fd)) {
                        continue;
                    }
                    // Whatever is queued is read away; EOF or an error ends this one.
                    let mut rounds = 0;
                    loop {
                        match raw::recv(fd, &mut buf) {
                            Ok(raw::Io::Done(_)) if rounds < 64 => rounds += 1,
                            Ok(raw::Io::WouldBlock | raw::Io::Done(_)) => {
                                pending += 1;
                                break;
                            }
                            _ => {
                                done.insert(std::os::fd::AsRawFd::as_raw_fd(&fd));
                                break;
                            }
                        }
                    }
                }
            }
            if pending == 0 || Instant::now() >= end {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn close_idle_http_sessions(&mut self) {
        use ibex_proto::h2::H2StreamState;
        use ibex_proto::mux::Mux;
        let mut wake = Vec::new();
        for (_, e) in self.sessions.iter_mut() {
            let idle = e.sess.mode == Mode::Http
                && e.sess.txn.is_none()
                && e.sess.req.is_empty()
                && e.sess.rep.is_empty()
                && e.sess.req_headers.is_none()
                && !e.sess.has_htx
                // Between requests a keep-alive client sits in `Ready`, not `Established`:
                // T71 keeps it there across transactions. Matching only `Established` meant
                // this closed nothing, and an idle client held the soft stop open until
                // `timeout client` -- which a test missed for as long as the client
                // connection was being closed after its first response anyway.
                && matches!(e.sess.cli_state, ScState::Established | ScState::Ready)
                // A connection that has not sent its first request yet is not between
                // requests: its request may already be in the socket, unread. HAProxy
                // releases only a connection waiting for its *next* request
                // (`H1C_F_WAIT_NEXT_REQ`, `src/mux_h1.c`) and serves the first one with
                // `connection: close`; closing it lost requests on every reload under
                // load (T252). An HTTP/2 connection is told with a GOAWAY either way.
                && (!e.sess.is_first_req || e.sess.h2_ctx.is_some())
                // An HTTP/2 connection serving a stream is not idle (the stream is its child,
                // T280).
                && e.sess.h2_owner().is_none_or(|o| o.children.is_empty())
                // An HTTP/3 connection drains itself (`step_h3_owner`): it closes once its
                // FINs are acknowledged; shut here, it lost the response not yet received
                // (T521).
                && e.sess.h3_owner().is_none();
            if !idle {
                continue;
            }
            match e.sess.h2_ctx.as_mut() {
                None => shutdown_session_entry(e, &mut self.proxies, &mut wake),
                Some(h2) => {
                    let no_open_streams = h2.streams.values().all(|s| {
                        matches!(s.state, H2StreamState::Closed | H2StreamState::Reset(_))
                    });
                    if !no_open_streams {
                        continue;
                    }
                    h2.send_graceful_goaway();
                    if ibex_proto::mux_h2::MuxH2.pending_output(h2).is_empty() {
                        shutdown_session_entry(e, &mut self.proxies, &mut wake);
                    } else {
                        wake.push(e.task);
                    }
                }
            }
        }
        // No liveness check: every task in `wake` was taken from a session in the table just
        // above, and a task is freed only when its run returns `Outcome::Done`, which frees
        // its session first. Nothing between the loop and here runs a task.
        for task in wake {
            debug_assert!(self.scheduler.is_live(task), "a session in the table names a freed task");
            self.scheduler.tasklet_wakeup(task, Class::Urgent, state::WOKEN_IO);
        }
    }

    /// Stops the engine loop.
    pub fn stop(&mut self) {
        self.is_running = false;
    }

    /// Dynamically terminates all active TCP and HTTP client/server sessions attached to a specific server
    /// or whole backend, reclaiming active connection counts immediately.
    pub fn shutdown_sessions(
        &mut self,
        backend_name: Option<&str>,
        server_id: Option<&str>,
    ) -> usize {
        let mut wake_queue = Vec::new();
        let count = shutdown_matching_sessions(
            self.sessions.iter_mut().map(|(_, e)| e),
            &mut self.proxies,
            backend_name,
            server_id,
            &mut wake_queue,
        );
        for task in wake_queue {
            self.scheduler
                .tasklet_wakeup(task, Class::Urgent, state::WOKEN_IO);
        }
        count
    }

    /// Dynamically enables active health checking for a server.
    pub fn enable_health(&mut self, backend_name: &str, server_id: &str) -> bool {
        set_health_check_enabled(
            &mut self.checks,
            &self.proxies,
            backend_name,
            server_id,
            true,
            self.now,
        )
    }

    /// Dynamically disables active health checking for a server.
    pub fn disable_health(&mut self, backend_name: &str, server_id: &str) -> bool {
        set_health_check_enabled(
            &mut self.checks,
            &self.proxies,
            backend_name,
            server_id,
            false,
            self.now,
        )
    }

    /// Clears traffic and error counters for a specific proxy, or all proxies if `target` is `None`.
    pub fn clear_counters(&mut self, target: Option<&str>) -> bool {
        clear_proxy_counters(&self.proxies, target)
    }

    /// Dynamically tunes maxconn on a proxy or a server.
    pub fn set_maxconn(&mut self, px_name: &str, sv_name: Option<&str>, maxconn: u32) -> bool {
        set_proxy_maxconn(&self.proxies, px_name, sv_name, maxconn)
    }
}

/// The value of a `set-src-port`/`set-dst-port` expression: an integer, cut to 16 bits as
/// `htons(smp->data.u.sint)` does (`tcp_action_req_set_src_port`, src/tcp_act.c). `None`
/// when the sample cannot be fetched: the rule then changes nothing.
fn eval_port_expr(expr: Option<&Expr>, registry: &Registry, ctx: &SampleContext<'_>) -> Option<u16> {
    let smp = expr?.eval_sample(registry, ctx)?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let port = |n: i64| n as u16;
    ibex_sample::cast::cast(smp, ibex_sample::SampleType::Sint).and_then(|s| if let ibex_sample::Sample::Sint(n) = s { Some(port(n)) } else { None })
}

/// `addr` with its port replaced and its address kept; with no address, `0.0.0.0` (HAProxy
/// forces AF_INET "0.0.0.0" when the family was neither inet nor inet6).
fn with_port(addr: Option<SocketAddr>, port: u16) -> SocketAddr {
    let ip = addr.map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |a| a.ip());
    SocketAddr::new(ip, port)
}

#[derive(Debug)]
enum ConnEvalOutcome {
    /// Client, server, `fc_src`, `fc_dst`, and whether `expect-proxy` matched.
    Accept(SocketAddr, SocketAddr, SocketAddr, SocketAddr, bool),
    Reject,
    /// `silent-drop`; the TTL of the RST (`rst-ttl`, 0 without it: `TCP_REPAIR` first, then 1).
    SilentDrop(u8),
}

#[derive(Debug, PartialEq, Eq)]
enum SessionEvalOutcome {
    Accept,
    Reject,
    SilentDrop(u8),
}

/// `tcp-request session` rules of a connection that opened with a PROXY header, once the
/// header is in (T157): `HAProxy` runs them in `conn_complete_session`, after the
/// handshake, so `src` and `fc_pp_tlv` read the header's values. Ibex ran them at accept,
/// before a byte of it. Runs inside the stream's run (`step_stream`), where its variables
/// and timeouts are. A refusal has the connection-error line of a bad header, with the
/// text "Success" (`ProxyHdrError::SessionRefused`).
fn run_deferred_session_rules(proxy_idx: usize, proxies: &[Proxy], sess: &mut TcpSession) {
    if !sess.session_rules_pending || !sess.proxy_handshake_done || sess.is_done() {
        return;
    }
    sess.session_rules_pending = false;
    match eval_tcp_req_session_rules(&proxies[proxy_idx], proxies, sample_registry(), sess) {
        SessionEvalOutcome::Accept => return,
        SessionEvalOutcome::Reject => sess.abort_client(),
        SessionEvalOutcome::SilentDrop(ttl) => {
            let is_ipv6 = sess.fc_src().or(sess.client_addr).is_some_and(|a| a.is_ipv6());
            sess.silent_drop_client(is_ipv6, ttl);
        }
    }
    proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
    sess.proxy_hdr_err = Some(crate::proxy::ProxyHdrError::SessionRefused);
    sess.cli_state = ScState::Closed;
    sess.srv_state = ScState::Closed;
    sess.tcp_inspect_done = true;
}

#[allow(clippy::too_many_lines)]
fn eval_tcp_req_conn_rules(
    proxy: &Proxy,
    proxies: &[Proxy],
    registry: &Registry,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    tracked: &[Option<(usize, StickKey)>; 3],
) -> ConnEvalOutcome {
    let mut client_addr = peer_addr;
    let mut server_addr = local_addr;
    let mut fc_src = peer_addr;
    let mut fc_dst = local_addr;
    let mut expect_proxy = false;

    let stick = StickView::new(proxies, tracked);
    let mut ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        stick: Some(&stick),
        client_addr: Some(client_addr),
        server_addr: Some(server_addr),
        fc_src: Some(fc_src),
        fc_dst: Some(fc_dst),
        act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
        ..Default::default()
    };

    for (rule, rc) in proxy.tcp_req_conn_rules.iter().zip(&proxy.rules.tcp_req_conn) {
        let matches = rc.cond.as_ref().is_none_or(|c| c.eval(&ctx, &proxy.acls, registry));
        if !matches {
            continue;
        }
        match &rule.action {
            ibex_config::TcpReqConnAction::SilentDrop => {
                return ConnEvalOutcome::SilentDrop(0);
            }
            ibex_config::TcpReqConnAction::SilentDropTtl(ttl) => {
                return ConnEvalOutcome::SilentDrop(*ttl);
            }
            ibex_config::TcpReqConnAction::Reject => {
                return ConnEvalOutcome::Reject;
            }
            ibex_config::TcpReqConnAction::Accept => {
                break;
            }
            ibex_config::TcpReqConnAction::ExpectProxy => {
                expect_proxy = true;
            }
            ibex_config::TcpReqConnAction::SetSrcPort { expr: _ } => {
                if let Some(port) = eval_port_expr(rc.expr.as_ref(), registry, &ctx) {
                    client_addr = with_port(Some(client_addr), port);
                    fc_src = client_addr;
                    ctx.client_addr = Some(client_addr);
                    ctx.fc_src = Some(fc_src);
                }
            }
            ibex_config::TcpReqConnAction::SetDstPort { expr: _ } => {
                if let Some(port) = eval_port_expr(rc.expr.as_ref(), registry, &ctx) {
                    server_addr = with_port(Some(server_addr), port);
                    fc_dst = server_addr;
                    ctx.server_addr = Some(server_addr);
                    ctx.fc_dst = Some(fc_dst);
                }
            }
            ibex_config::TcpReqConnAction::SetSrc { expr: _ } => {
                let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                if let Ok(ip) = val.parse::<IpAddr>() {
                    client_addr = SocketAddr::new(ip, client_addr.port());
                    ctx.client_addr = Some(client_addr);
                    fc_src = client_addr;
                    ctx.fc_src = Some(fc_src);
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    client_addr = sa;
                    ctx.client_addr = Some(client_addr);
                    fc_src = client_addr;
                    ctx.fc_src = Some(fc_src);
                }
            }
            ibex_config::TcpReqConnAction::SetDst { expr: _ } => {
                let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                if let Ok(ip) = val.parse::<IpAddr>() {
                    server_addr = SocketAddr::new(ip, server_addr.port());
                    ctx.server_addr = Some(server_addr);
                    fc_dst = server_addr;
                    ctx.fc_dst = Some(fc_dst);
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    server_addr = sa;
                    ctx.server_addr = Some(server_addr);
                    fc_dst = server_addr;
                    ctx.fc_dst = Some(fc_dst);
                }
            }
            _ => {}
        }
    }
    ConnEvalOutcome::Accept(client_addr, server_addr, fc_src, fc_dst, expect_proxy)
}

#[allow(clippy::too_many_lines)]
fn eval_tcp_req_session_rules(
    proxy: &Proxy,
    proxies: &[Proxy],
    registry: &Registry,
    sess: &mut TcpSession,
) -> SessionEvalOutcome {
    let stick = StickView::new(proxies, &sess.tracked_sc);
    let mut ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        stick: Some(&stick),
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src(),
        so_name: sess.so_name.as_deref(),
        so_id: sess.so_id,
        fe_id: Some(proxy.ids.iid),
        fc_dst: sess.fc_dst(),
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: crate::proxy::ssl_fc(&sess.cli_xprt, sess.h2_role.as_deref()),
        quic_acks: sess.quic_facts(),
        req_version: sess.client_version(),
        ssl_bc: sess.srv_xprt.ssl_facts(),
        act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        accept_date: Some(sess.log.date()),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };

    for (rule, rc) in proxy.tcp_req_session_rules.iter().zip(&proxy.rules.tcp_req_session) {
        let matches = rc.cond.as_ref().is_none_or(|c| c.eval(&ctx, &proxy.acls, registry));
        if !matches {
            continue;
        }
        match &rule.action {
            ibex_config::TcpReqSessionAction::SilentDrop => {
                return SessionEvalOutcome::SilentDrop(0);
            }
            ibex_config::TcpReqSessionAction::SilentDropTtl(ttl) => {
                return SessionEvalOutcome::SilentDrop(*ttl);
            }
            ibex_config::TcpReqSessionAction::Reject => {
                return SessionEvalOutcome::Reject;
            }
            ibex_config::TcpReqSessionAction::Accept => {
                break;
            }
            ibex_config::TcpReqSessionAction::TrackSc0 { table, expr: _ } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        // A slot that tracks an entry already keeps it (`stream_track_stkctr` is not called again).
                        if sess.tracked_sc[0].is_none() {
                            let _ = tbl.update_entry(&key, |data| data.track(true));
                            stick.track(0, t_idx, &key);
                            sess.tracked_sc[0] = Some((t_idx, key));
                        }
                    }
                }
            }
            ibex_config::TcpReqSessionAction::TrackSc1 { table, expr: _ } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        // A slot that tracks an entry already keeps it (`stream_track_stkctr` is not called again).
                        if sess.tracked_sc[1].is_none() {
                            let _ = tbl.update_entry(&key, |data| data.track(true));
                            stick.track(1, t_idx, &key);
                            sess.tracked_sc[1] = Some((t_idx, key));
                        }
                    }
                }
            }
            ibex_config::TcpReqSessionAction::TrackSc2 { table, expr: _ } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        // A slot that tracks an entry already keeps it (`stream_track_stkctr` is not called again).
                        if sess.tracked_sc[2].is_none() {
                            let _ = tbl.update_entry(&key, |data| data.track(true));
                            stick.track(2, t_idx, &key);
                            sess.tracked_sc[2] = Some((t_idx, key));
                        }
                    }
                }
            }
            ibex_config::TcpReqSessionAction::SetSrc { expr: _ } => {
                let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                if let Ok(ip) = val.parse::<IpAddr>() {
                    let port = sess.client_addr.map_or(0, |a| a.port());
                    let new_addr = SocketAddr::new(ip, port);
                    sess.client_addr = Some(new_addr);
                    ctx.client_addr = Some(new_addr);
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    sess.client_addr = Some(sa);
                    ctx.client_addr = Some(sa);
                }
            }
            ibex_config::TcpReqSessionAction::SetDst { expr: _ } => {
                let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                if let Ok(ip) = val.parse::<IpAddr>() {
                    let port = sess.server_addr.map_or(0, |a| a.port());
                    let new_addr = SocketAddr::new(ip, port);
                    sess.server_addr = Some(new_addr);
                    ctx.server_addr = Some(new_addr);
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    sess.server_addr = Some(sa);
                    ctx.server_addr = Some(sa);
                }
            }
            ibex_config::TcpReqSessionAction::SetSrcPort { expr: _ } => {
                if let Some(port) = eval_port_expr(rc.expr.as_ref(), registry, &ctx) {
                    let new_addr = with_port(sess.client_addr, port);
                    sess.client_addr = Some(new_addr);
                    ctx.client_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqSessionAction::SetDstPort { expr: _ } => {
                if let Some(port) = eval_port_expr(rc.expr.as_ref(), registry, &ctx) {
                    let new_addr = with_port(sess.server_addr, port);
                    sess.server_addr = Some(new_addr);
                    ctx.server_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqSessionAction::SetVar { var_name, expr: _ } => {
                // A sample that cannot be fetched sets nothing (`action_store`, src/vars.c).
                // The expression is a sample fetch, checked at load; one that cannot be parsed or
                // fetched sets nothing.
                // A constant (`str(hello)`) is copied in, with no allocation (T364 S6).
                let e = rc.expr.as_ref();
                if let Some(c) = e.and_then(|e| e.constant(registry)) {
                    store_var_in(&mut sess.vars, &rc.var(var_name), ibex_sample::vars::In::Ref(c));
                } else if let Some(val) = e.and_then(|e| e.eval_sample(registry, &ctx)) {
                    store_var_smp(&mut sess.vars, &rc.var(var_name), val);
                }
            }
            ibex_config::TcpReqSessionAction::SetVarFmt { var_name, fmt: _ } => {
                let val = render_rule_fmt(rc, &ctx, registry);
                store_var(&mut sess.vars, &rc.var(var_name), val);
            }
            ibex_config::TcpReqSessionAction::UnsetVar { var_name } => {
                unset_var(&mut sess.vars, &rc.var(var_name));
            }
            ibex_config::TcpReqSessionAction::ScIncGpc0 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::Inc),
            ibex_config::TcpReqSessionAction::ScIncGpc1 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::One, GpcOp::Inc),
            ibex_config::TcpReqSessionAction::ScSetGpt0 { sc, expr } => {
                let val = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::SetTag(val));
            }
            ibex_config::TcpReqSessionAction::ScIncGpc { idx, sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Inc),
            ibex_config::TcpReqSessionAction::ScAddGpc { idx, sc, expr } => {
                let n = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Add(u64::from(n)));
            }
            ibex_config::TcpReqSessionAction::ScSetGpt { idx, sc, expr } => {
                let val = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::SetTag(val));
            }
            _ => {}
        }
    }
    SessionEvalOutcome::Accept
}

#[derive(Debug, PartialEq, Eq)]
enum ContentEvalResult {
    Done,
    Waiting,
    Reject,
    SilentDrop(u8),
}

#[allow(clippy::too_many_lines)]
fn eval_tcp_req_content_rules(
    proxy: &Proxy,
    fe_idx: usize,
    proxies: &[Proxy],
    registry: &Registry,
    sess: &mut TcpSession,
    now: Tick,
    start: usize,
) -> ContentEvalResult {
    if proxy.tcp_req_content_rules.is_empty() {
        return ContentEvalResult::Done;
    }

    let req_bytes = sess.req.readable();
    let has_content = !req_bytes.is_empty();
    // A kept-alive connection closed by the client with no next request has no stream to
    // inspect: HAProxy runs nothing for it.
    if sess.mode == Mode::Http
        && !sess.is_first_req
        && !sess.has_htx
        && !has_content
        && matches!(sess.cli_state, ScState::ShutR | ScState::Closed)
    {
        return ContentEvalResult::Done;
    }
    let expired = sess.inspect_exp.is_some_and(|exp| exp.is_expired(now));
    let client_closed = sess.cli_state == ScState::ShutR || sess.cli_state == ScState::Closed;
    let can_wait = sess.inspect_exp.is_some() && !expired && !client_closed;

    if !has_content && (can_wait || (sess.mode == Mode::Http && !client_closed)) {
        return ContentEvalResult::Waiting;
    }

    let stick = StickView::new(proxies, &sess.tracked_sc);
    let mut ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        stick: Some(&stick),
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src(),
        so_name: sess.so_name.as_deref(),
        so_id: sess.so_id,
        fc_dst: sess.fc_dst(),
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: crate::proxy::ssl_fc(&sess.cli_xprt, sess.h2_role.as_deref()),
        quic_acks: sess.quic_facts(),
        fc_http_major: sess.fc_http_major(),
        bc_http_major: sess.bc_http_major(),
        req_version: sess.client_version(),
        ssl_bc: sess.srv_xprt.ssl_facts(),
        req_body: if has_content { Some(req_bytes) } else { None },
        raw_req: (sess.mode == Mode::Tcp).then_some(req_bytes),
        // In HTTP mode the request is parsed by the time these rules run, and `path`,
        // `hdr()` and the like read it, as they do in `HAProxy`. Built from the fields: the
        // rules change `vars` while this borrows.
        htx_slice: sess.has_htx.then(|| ibex_proto::htx::HtxSliceRef::new(sess.htx_buf.raw_slice(), sess.htx_blocks)),
        req_uri: sess.req_uri.as_deref(),
        req_method: sess.req_method.as_deref(),
        req_headers: sess.req_headers.as_deref(),
        act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        accept_date: Some(sess.log.date()),
        last_rule: last_rule_at(sess.log.last_rule),
        prio: (sess.log.prio_class, sess.log.prio_offset),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };

    let mut has_missing_data = false;
    for (rule_idx, (rule, rc)) in proxy.tcp_req_content_rules.iter().zip(&proxy.rules.tcp_req_content).enumerate().skip(start) {
        let cond_res = rc.cond.as_ref().map_or(crate::proxy::AclEvalResult::Matched, |c| c.eval_extended(&ctx, &proxy.acls, registry, req_bytes, can_wait));
        match cond_res {
            crate::proxy::AclEvalResult::MissingData => {
                has_missing_data = true;
                break;
            }
            crate::proxy::AclEvalResult::NotMatched => {
                continue;
            }
            crate::proxy::AclEvalResult::Matched => {}
        }
        match &rule.action {
            ibex_config::TcpReqContentAction::SilentDrop => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::SilentDrop(0);
            }
            ibex_config::TcpReqContentAction::SilentDropTtl(ttl) => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::SilentDrop(*ttl);
            }
            ibex_config::TcpReqContentAction::Reject => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::Reject;
            }
            ibex_config::TcpReqContentAction::Accept => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::Done;
            }
            ibex_config::TcpReqContentAction::TrackSc0 { table, expr: _ } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        // A slot that tracks an entry already keeps it (`stream_track_stkctr` is not called again).
                        if sess.tracked_sc[0].is_none() {
                            let _ = tbl.update_entry(&key, |data| data.track(false));
                            stick.track(0, t_idx, &key);
                            sess.tracked_sc[0] = Some((t_idx, key));
                        }
                    }
                }
            }
            ibex_config::TcpReqContentAction::TrackSc1 { table, expr: _ } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        // A slot that tracks an entry already keeps it (`stream_track_stkctr` is not called again).
                        if sess.tracked_sc[1].is_none() {
                            let _ = tbl.update_entry(&key, |data| data.track(false));
                            stick.track(1, t_idx, &key);
                            sess.tracked_sc[1] = Some((t_idx, key));
                        }
                    }
                }
            }
            ibex_config::TcpReqContentAction::TrackSc2 { table, expr: _ } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        // A slot that tracks an entry already keeps it (`stream_track_stkctr` is not called again).
                        if sess.tracked_sc[2].is_none() {
                            let _ = tbl.update_entry(&key, |data| data.track(false));
                            stick.track(2, t_idx, &key);
                            sess.tracked_sc[2] = Some((t_idx, key));
                        }
                    }
                }
            }
            ibex_config::TcpReqContentAction::SetSrc { expr: _ } => {
                let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                if let Ok(ip) = val.parse::<IpAddr>() {
                    let port = sess.client_addr.map_or(0, |a| a.port());
                    let new_addr = SocketAddr::new(ip, port);
                    sess.client_addr = Some(new_addr);
                    ctx.client_addr = Some(new_addr);
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    sess.client_addr = Some(sa);
                    ctx.client_addr = Some(sa);
                }
            }
            ibex_config::TcpReqContentAction::Capture { expr: _, len, id } => {
                // The slot is the holding proxy's own; a stream from another frontend has
                // none and the rule is ignored (`tcp_action_capture`: `px != strm_fe(s)`).
                if std::ptr::eq(proxy, &proxies[fe_idx]) {
                    let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| sample_to_string(&smp));
                    if let (Some(id), Some(val)) = (id, val) {
                        // The context borrows the slots: the rules after this one run on a new
                        // pass, over the written slots, in place of this one.
                        if let Some(slot) = sess.log.req_captures.get_mut(*id) {
                            *slot = Some(cut_at(&val, *len).into_owned());
                        }
                        return eval_tcp_req_content_rules(proxy, fe_idx, proxies, registry, sess, now, rule_idx + 1);
                    }
                }
            }
            ibex_config::TcpReqContentAction::SetDst { expr: _ } => {
                let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                if let Ok(ip) = val.parse::<IpAddr>() {
                    let port = sess.server_addr.map_or(0, |a| a.port());
                    let new_addr = SocketAddr::new(ip, port);
                    sess.server_addr = Some(new_addr);
                    ctx.server_addr = Some(new_addr);
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    sess.server_addr = Some(sa);
                    ctx.server_addr = Some(sa);
                }
            }
            ibex_config::TcpReqContentAction::SetSrcPort { expr: _ } => {
                if let Some(port) = eval_port_expr(rc.expr.as_ref(), registry, &ctx) {
                    let new_addr = with_port(sess.client_addr, port);
                    sess.client_addr = Some(new_addr);
                    ctx.client_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqContentAction::SetDstPort { expr: _ } => {
                if let Some(port) = eval_port_expr(rc.expr.as_ref(), registry, &ctx) {
                    let new_addr = with_port(sess.server_addr, port);
                    sess.server_addr = Some(new_addr);
                    ctx.server_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqContentAction::SetVar { var_name, expr: _ } => {
                // A sample that cannot be fetched sets nothing (`action_store`, src/vars.c).
                // The expression is a sample fetch, checked at load; one that cannot be parsed or
                // fetched sets nothing.
                // A constant (`str(hello)`) is copied in, with no allocation (T364 S6).
                let e = rc.expr.as_ref();
                if let Some(c) = e.and_then(|e| e.constant(registry)) {
                    store_var_in(&mut sess.vars, &rc.var(var_name), ibex_sample::vars::In::Ref(c));
                } else if let Some(val) = e.and_then(|e| e.eval_sample(registry, &ctx)) {
                    store_var_smp(&mut sess.vars, &rc.var(var_name), val);
                }
            }
            ibex_config::TcpReqContentAction::DoResolve(d) => {
                // T489: as `http-request do-resolve`, within the `inspect-delay`: at its end
                // (or without one, `ACT_OPT_FINAL`) the rule gives up and nothing is asked.
                // The rules run again from the first while they wait.
                let held = crate::resolvers::dr_wait_unpack(sess.dr_wait).filter(|w| w.0 == rule_idx);
                if can_wait {
                    let task = crate::resolvers::dr_task();
                    let step = with_rule_name(rc.expr.as_ref(), registry, &ctx, |name| match held {
                        Some((_, asked)) => crate::resolvers::dr_poll(d.section_idx, d.prefer_ipv4, name, asked).map_or(crate::resolvers::DrStep::Wait, crate::resolvers::DrStep::Done),
                        None => crate::resolvers::dr_start(d.section_idx, d.prefer_ipv4, name, task, std::time::Instant::now()),
                    });
                    match step {
                        crate::resolvers::DrStep::Wait => {
                            if held.is_none() {
                                sess.dr_wait = crate::resolvers::dr_wait_pack(rule_idx, crate::resolvers::dr_mark());
                            }
                            return ContentEvalResult::Waiting;
                        }
                        crate::resolvers::DrStep::Done(ip) => {
                            if let Some(ip) = ip {
                                ibex_sample::vars::store_by_name(&mut sess.vars, &d.var_name, ibex_sample::vars::In::Owned(ip_sample(ip)));
                            }
                        }
                    }
                }
                if held.is_some() {
                    sess.dr_wait = 0;
                }
            }
            ibex_config::TcpReqContentAction::SetVarFmt { var_name, fmt: _ } => {
                let val = render_rule_fmt(rc, &ctx, registry);
                store_var(&mut sess.vars, &rc.var(var_name), val);
            }
            ibex_config::TcpReqContentAction::UnsetVar { var_name } => {
                unset_var(&mut sess.vars, &rc.var(var_name));
            }
            ibex_config::TcpReqContentAction::ScIncGpc0 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::Inc),
            ibex_config::TcpReqContentAction::ScIncGpc1 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::One, GpcOp::Inc),
            ibex_config::TcpReqContentAction::ScSetGpt0 { sc, expr } => {
                let val = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::SetTag(val));
            }
            ibex_config::TcpReqContentAction::ScIncGpc { idx, sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Inc),
            ibex_config::TcpReqContentAction::ScAddGpc { idx, sc, expr } => {
                let n = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Add(u64::from(n)));
            }
            ibex_config::TcpReqContentAction::ScSetGpt { idx, sc, expr } => {
                let val = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::SetTag(val));
            }
            ibex_config::TcpReqContentAction::SwitchModeHttp { .. } => {
                sess.mode = Mode::Http;
                sess.cli_state = ScState::Ready;
            }
            _ => {}
        }
    }

    if has_missing_data {
        ContentEvalResult::Waiting
    } else {
        ContentEvalResult::Done
    }
}

/// Whether a sample of the response may still change while more of it can arrive
/// (`SMP_F_MAY_CHANGE`): `smp_fetch_payload` sets it with no length or not enough bytes
/// yet, `smp_fetch_len` always (src/payload.c). The FIX converters decide it themselves
/// from the message (`sample_conv_fix_is_valid`, `sample_conv_fix_tag_value`): only a
/// message that needs more data may change.
fn res_sample_may_change(expr: &Expr, rep: &[u8]) -> bool {
    if expr.fetch_name == "res.len" {
        return true;
    }
    if let Some(wait) = ibex_sample::raw_may_change(&expr.fetch_name, &expr.fetch_args, rep) {
        return wait;
    }
    if expr.fetch_name != "res.payload" {
        return false;
    }
    let arg = |i: usize| expr.fetch_args.get(i).and_then(|a| a.trim().parse::<usize>().ok()).unwrap_or(0);
    let (off, len) = (arg(0), arg(1));
    if off.saturating_add(len) > rep.len() {
        // `too_short`: the fetch itself fails, and may succeed with more data.
        return true;
    }
    let payload = if len == 0 { &rep[off..] } else { &rep[off..off + len] };
    match expr.converters.first().map(|(name, args)| (name.as_str(), args)) {
        Some(("fix_is_valid", _)) => {
            ibex_sample::fix::validate_message(payload) == ibex_sample::fix::Validity::NeedMoreData
        }
        Some(("fix_tag_value", args)) => {
            let id = args.first().and_then(|a| ibex_sample::fix::tag_id(a.trim()));
            id.is_some_and(|id| ibex_sample::fix::tag_value(payload, id) == ibex_sample::fix::TagValue::NeedMoreData)
        }
        _ => len == 0,
    }
}

/// `tcp-response content` rules in TCP mode, as `tcp_inspect_response` (`src/tcp_rules.c`)
/// runs them over the response received so far. They decide once a rule accepts or
/// rejects, or all have run; a condition on response data that may still grow and does
/// not hold yet makes them wait, until the server closes, the buffer fills, or
/// `tcp-response inspect-delay` runs out, when they decide on what is there.
fn eval_tcp_res_content_rules(proxy: &Proxy, proxies: &[Proxy], registry: &Registry, sess: &mut TcpSession, now: Tick) -> ContentEvalResult {
    let server_closed = matches!(sess.srv_state, ScState::ShutR | ScState::Closed | ScState::Error);
    let expired = sess.res_inspect_exp.is_none_or(|exp| exp.is_expired(now));
    let final_ = server_closed || sess.rep.is_full() || expired;
    let rep_bytes = sess.rep.readable();
    let stick = StickView::new(proxies, &sess.tracked_sc);
    let ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        stick: Some(&stick),
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src(),
        so_name: sess.so_name.as_deref(),
        so_id: sess.so_id,
        fc_dst: sess.fc_dst(),
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: crate::proxy::ssl_fc(&sess.cli_xprt, sess.h2_role.as_deref()),
        quic_acks: sess.quic_facts(),
        fc_http_major: sess.fc_http_major(),
        bc_http_major: sess.bc_http_major(),
        req_version: sess.client_version(),
        ssl_bc: sess.srv_xprt.ssl_facts(),
        res_body: Some(rep_bytes),
        raw_res: Some(rep_bytes),
        act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        accept_date: Some(sess.log.date()),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        bc_err: sess.bc_err.copied(),
        bc_reused: Some(sess.txn.as_ref().is_some_and(|t| t.srv_reused)),
        term_state: Some(sess_term_state(sess)),
        bc_dst: sess.bc_dst(),
        bc_src: sess.bc_src(),
        ..Default::default()
    };
    for (rule, rc) in proxy.tcp_res_content_rules.iter().zip(&proxy.rules.tcp_res_content) {
        if let Some(cond) = &rc.cond {
            // `acl_exec_cond`: a sample that may change and does not match is a miss.
            let res = cond.eval_terms(&proxy.acls, |expr, negated| {
                if expr.fetch_name == "wait_end" && !final_ {
                    return crate::proxy::AclEvalResult::MissingData;
                }
                let matched = expr.eval(registry, &ctx);
                if !matched && !final_ && res_sample_may_change(expr, rep_bytes) {
                    crate::proxy::AclEvalResult::MissingData
                } else if matched != negated {
                    crate::proxy::AclEvalResult::Matched
                } else {
                    crate::proxy::AclEvalResult::NotMatched
                }
            });
            match res {
                crate::proxy::AclEvalResult::MissingData => return ContentEvalResult::Waiting,
                crate::proxy::AclEvalResult::NotMatched => continue,
                crate::proxy::AclEvalResult::Matched => {}
            }
        }
        match &rule.action {
            ibex_config::TcpResAction::Accept => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::Done;
            }
            ibex_config::TcpResAction::Reject => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::Reject;
            }
            ibex_config::TcpResAction::SilentDrop => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::SilentDrop(0);
            }
            ibex_config::TcpResAction::SetVar { var_name, expr: _ } => {
                set_var_from(&mut sess.vars, &rc.var(var_name), rc.expr.as_ref(), &ctx, registry);
            }
            ibex_config::TcpResAction::SetVarFmt { var_name, fmt: _ } => {
                store_var(&mut sess.vars, &rc.var(var_name), render_rule_fmt(rc, &ctx, registry));
            }
            ibex_config::TcpResAction::UnsetVar { var_name } => unset_var(&mut sess.vars, &rc.var(var_name)),
        }
    }
    ContentEvalResult::Done
}

/// `set-var(<name>) <expr>`: `action_store` (src/vars.c) -- a sample that cannot be
/// fetched sets nothing. A constant expression (`str(hello)`, `int(5)`) is evaluated once and
/// copied into the variable: no allocation (T364 S6).
fn set_var_from(vars: &mut VarStore, name: &ibex_sample::vars::VarRef, e: Option<&Expr>, ctx: &SampleContext, registry: &Registry) {
    let Some(e) = e else { return };
    if let Some(c) = e.constant(registry) {
        store_var_in(vars, name, ibex_sample::vars::In::Ref(c));
    } else if let Some(val) = e.eval_sample(registry, ctx) {
        store_var_smp(vars, name, val);
    }
}

/// `unset-var(<name>)`, from the scope it lives in.
fn unset_var(vars: &mut VarStore, var: &ibex_sample::vars::VarRef) {
    var.unset(vars);
}

/// Stores a variable where its scope lives, and where the rules after it read it.
///
/// `set-var-fmt(<name>) <fmt>`: the format is built in a trash chunk, so the value is cut
/// at `tune.bufsize - 1` bytes (T251).
/// The value is a `str`, as `HAProxy`'s `SMP_T_STR` (T364).
fn store_var(vars: &mut VarStore, name: &ibex_sample::vars::VarRef, mut val: String) {
    ibex_sample::registry::truncate_to_trash(&mut val);
    store_var_smp(vars, name, Sample::Str(val));
}

/// `name[,<cond>...]` of `set-var(...)`: the variable is set only when every condition holds
/// (`var_set`, src/vars.c). `ifexists`/`ifset` and their negations look at the variable
/// (a process variable always exists, as the configuration declares it, but is set only
/// once it has a value), `ifempty`/`ifnotempty` at the new sample, `ifgt`/`iflt` compare the
/// stored and the new value when both are `sint`.
///
/// The variable keeps the sample's type (T364): `var()` gives back this `Sample`.
/// How long a stream waits for a `do-resolve` answer at most (T489): worker 0 always answers
/// once the resolution ends (`resolve_retries` x `timeout retry`); this only bounds a lost one.
const DO_RESOLVE_WAIT_MS: u32 = 30_000;

/// The name a `do-resolve` expression gives, to `f`: a constant string without a copy, else
/// the sample cast to a string, as `resolv_action_do_resolve` takes it
/// (`sample_fetch_as_type(..., SMP_T_STR)`: `int(1)` asks `1`, `src` its address). No name
/// (the fetch failed, no cast to a string): `Done(None)`.
fn with_rule_name(e: Option<&ibex_sample::Expr>, registry: &ibex_sample::Registry, ctx: &SampleContext, f: impl FnOnce(&[u8]) -> crate::resolvers::DrStep) -> crate::resolvers::DrStep {
    let none = crate::resolvers::DrStep::Done(None);
    let Some(e) = e else { return none };
    let smp = match e.constant(registry) {
        Some(Sample::Str(s)) => return f(s.as_bytes()),
        Some(Sample::Bin(b)) => return f(b),
        Some(c) => Some(c.clone()),
        None => e.eval_sample(registry, ctx),
    };
    match smp.and_then(|v| if matches!(v, Sample::Bin(_)) { Some(v) } else { ibex_sample::cast(v, ibex_sample::SampleType::Str) }) {
        Some(Sample::Str(s)) => f(s.as_bytes()),
        Some(Sample::Bin(b)) => f(&b),
        _ => none,
    }
}

/// An address as a variable holds it (`SMP_T_IPV4` / `SMP_T_IPV6`).
fn ip_sample(ip: IpAddr) -> Sample {
    match ip {
        IpAddr::V4(v4) => Sample::Ipv4(v4),
        IpAddr::V6(v6) => Sample::Ipv6(v6),
    }
}

fn store_var_smp(vars: &mut VarStore, spec: &ibex_sample::vars::VarRef, val: Sample) {
    store_var_in(vars, spec, ibex_sample::vars::In::Owned(val));
}

/// [`store_var_smp`] of a sample to keep or to copy. `vars` is the session's store; while the
/// stream runs its variables are the thread's (`ibex_sample::vars::with_stream`).
fn store_var_in(vars: &mut VarStore, var: &ibex_sample::vars::VarRef, val: ibex_sample::vars::In<'_>) {
    var.store(vars, val);
}

/// Runs `f` with `sess`'s variables in the thread's `CURRENT_VARS`, where the fetches and
/// converters read them, and puts them back in the session after (T152).
///
/// `CURRENT_VARS` is one store per thread, and every stream on the thread runs through it in
/// turn: a stream that waits (for its server, its body, a tarpit) leaves the thread to the
/// others, so the store holds a stream's variables only while that stream runs. It is filled
/// here, for the length of one run and never across a wait, and emptied after, so a
/// stream reads its own variables or none -- never those of the stream that ran last.
///
/// The store is swapped, not copied (`ibex_sample::vars::enter`/`leave`): the session's is the
/// thread's empty one while `f` runs, and every write lands in the thread's. No allocation,
/// whatever the number of variables (T364 S6).
fn with_stream_vars<R>(sess: &mut TcpSession, fe: &Proxy, f: impl FnOnce(&mut TcpSession) -> R) -> R {
    stream_vars_enter(sess, fe);
    let out = f(sess);
    stream_vars_leave(Some(sess));
    out
}

/// The start of [`with_stream_vars`].
fn stream_vars_enter(sess: &mut TcpSession, fe: &Proxy) {
    ibex_sample::vars::enter(&mut sess.vars);
    // T331: the slots' lengths, for the converters that write them. The thread keeps the
    // last frontend's tables: no `Arc` clone a run (L3, Q6).
    let taken = ibex_sample::capture_write::enter_shared(&fe.req_capture_slots, &fe.res_capture_slots);
    if cfg!(debug_assertions) && taken {
        ibex_sample::work::note(ibex_sample::work::Op::RunSetup, 1);
    }
}

/// The end of [`with_stream_vars`]: the thread's store goes back to `sess`, or is emptied
/// with a stream that is gone.
fn stream_vars_leave(sess: Option<&mut TcpSession>) {
    // T331: what `capture-req` and `capture-res` wrote goes into the slots; a stream that is
    // gone has none to take it.
    let writes = ibex_sample::capture_write::leave_kept();
    let Some(sess) = sess else {
        ibex_sample::vars::leave(None);
        return;
    };
    ibex_sample::vars::leave(Some(&mut sess.vars));
    for (res, id, val) in writes {
        let slots = if res { &mut sess.log.res_captures } else { &mut sess.log.req_captures };
        if let Some(slot) = slots.get_mut(id) {
            *slot = Some(val);
        }
    }
}

/// The timeouts the `*_timeout` fetches report for a stream of frontend `fe` on backend
/// `be` (the frontend until one is chosen), with what its `set-timeout` rules set (T156).
///
/// `cur_*` is the backend's timeout, the client's the frontend's, unless a rule set it,
/// as `smp_fetch_cur_*_timeout` (src/stream.c) read the stream's own timers.
fn stream_timeouts(fe: &Proxy, be: &Proxy, set: Option<&crate::proxy::TimeoutsSet>) -> ibex_sample::StreamTimeouts {
    let fe_ms = fe.ids.timeout_ms;
    let mut be_ms = be.ids.timeout_ms;
    be_ms[TimeoutKind::Client as usize] = fe_ms[TimeoutKind::Client as usize];
    let mut cur = be_ms;
    if let Some(set) = set {
        for (c, s) in cur.iter_mut().zip(set.ms) {
            if s != 0 {
                *c = s;
            }
        }
    }
    ibex_sample::StreamTimeouts { fe: fe_ms, be: be_ms, cur }
}

/// [`Proxy::timeout_ms`] of a proxy's `timeouts`.
fn timeouts_ms(t: &ibex_config::TimeoutConfig) -> [u32; 6] {
    #[cfg(debug_assertions)]
    ibex_sample::work::note(ibex_sample::work::Op::RunSetup, 1);
    [t.client, t.server, t.connect, t.queue, t.tunnel, t.tarpit].map(|v| v.map_or(0, millis_to_u32))
}

/// Puts the timeouts of the stream that runs now where its fetches read them
/// ([`stream_timeouts`]). Like the variables ([`with_stream_vars`]) they are the thread's
/// for one run of one stream only: `None` outside a run.
fn stream_timeouts_enter(proxies: &[Proxy], fe_idx: usize, be_idx: usize, sess: &TcpSession) {
    let pair = proxies.get(fe_idx).zip(proxies.get(be_idx));
    CURRENT_TIMEOUTS.set(pair.map(|(fe, be)| stream_timeouts(fe, be, sess.timeouts_set.as_deref())));
}

/// Readies a TCP-mode stream for `proxy`'s `tcp-response content` rules, if it has any
/// (`AN_RES_INSPECT`, set with the backend); they start when the server connects.
fn arm_res_inspect(proxy: &Proxy, sess: &mut TcpSession) {
    sess.res_inspect_armed = (sess.mode == Mode::Tcp && !proxy.tcp_res_content_rules.is_empty())
        .then(|| proxy.tcp_res_inspect_delay.map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)));
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
/// `tune.ibex.h3-path` (T509, Ibex-only until the relay is removed): `mux` serves HTTP/3
/// request streams through the h3 mux and the bridge, `relay` through the HTTP/1 relay.
/// Unset, the environment variable `IBEX_H3_PATH` (`mux` or `relay`) decides, so that the h3
/// tests run on both paths without a configuration of their own; else the mux (the default
/// since T536).
/// How long a soft stop waits for the first request of an HTTP/3 connection that has sent
/// none (T558): long enough for a client's request lost on its way (sent while the reuseport
/// group was changing, before the connection was pinned) to be retransmitted -- quinn's and
/// ngtcp2's probe timeouts are tens of milliseconds on a short path, doubling -- and short
/// enough that a connection opened and left idle does not keep the old process long.
pub const H3_STOP_FIRST_REQUEST_MS: u32 = 1000;

fn h3_mux(keyword: Option<bool>) -> bool {
    keyword.unwrap_or_else(|| std::env::var("IBEX_H3_PATH").map_or(true, |v| v != "relay"))
}

fn register_new_session(
    engine: &mut Engine,
    proxy_idx: usize,
    listener_idx: Option<usize>,
    cli_fd: std::os::fd::OwnedFd,
    peer_addr: SocketAddr,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    fc_src: SocketAddr,
    fc_dst: SocketAddr,
    tracked_sc: [Option<(usize, StickKey)>; 3],
    expect_proxy: bool,
    quic_ack: Option<crate::proxy::QuicAckSrc>,
) {
    // Cloned out before `proxies` is borrowed mutably. TLS belongs to the bind that
    // accepted, not to the proxy, so it is read from the listener.
    let tls = listener_idx
        .and_then(|i| engine.listeners.get(i))
        .and_then(|l| l.tls.clone());
    let cli_raw_fd = cli_fd.as_raw_fd();
    // A client that reset while its connection waited at `maxconn`: `HAProxy` finds the
    // reset with the request, and the stream's state tells it (`client_left`, T231).
    let reset_pending = engine.backlog_waits && crate::raw::reset_pending(cli_fd.as_fd());
    let Some((mut sess, target_addr, srv_raw_fd)) = init_client_session(
        &mut engine.proxies,
        proxy_idx,
        crate::proxy::ClientSide::Fd(cli_fd),
        engine.now,
        peer_addr,
        client_addr,
        server_addr,
        fc_src,
        fc_dst,
        tls.as_ref(),
        engine.ssl_capture_size,
        engine.ssl_ja4_spec,
        tracked_sc,
        engine.global_bufsize,
        engine.global_maxrewrite,
        engine.global_h2_flood_config,
        expect_proxy,
        listener_idx
            .and_then(|i| engine.listeners.get(i))
            .map_or((false, false), |l| (l.accept_proxy, l.accept_proxy_v2)),
    ) else {
        // TLS setup failed; the fd is dropped with the session and the connection closes.
        return;
    };
    // Without a listener, the client is an HTTP/3 request stream (`adopt_quic_streams`).
    sess.reset_with_request = reset_pending;
    sess.h3 = listener_idx.is_none();
    if let Some(q) = quic_ack {
        sess.h2_role = Some(crate::proxy::relay_role(q));
    }
    sess.proto_h2 = listener_idx.and_then(|i| engine.listeners.get(i)).is_some_and(|l| l.proto_h2);
    sess.so_name = listener_idx.and_then(|i| engine.listeners.get(i)).and_then(|l| l.name.clone());
    sess.so_id = listener_idx.and_then(|i| engine.listeners.get(i)).map(|l| l.luid).filter(|&id| id != 0);

    let proxy = &engine.proxies[proxy_idx];

    let target_server_idx = target_addr.and_then(|t| proxy.servers.iter().position(|s| s == t));
    if target_addr.is_some() {
        count_connect(&engine.proxies, proxy_idx, target_server_idx, false);
    }
    // A balanced pick counted its server when it took the slot (`init_client_session`).
    if let Some(idx) = target_server_idx.filter(|_| !sess.lb_picked) {
        if idx < proxy.server_actconn.len() {
            proxy.server_actconn[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    sess.log.server = target_server_idx.and_then(crate::txnlog::server_slot);
    let (cli_want, srv_want) = sess.interests();
    let cli_interest = Interest {
        readable: cli_want.read,
        writable: cli_want.write,
    };

    // `-dMfail` (`tune.fail-alloc`): a session `HAProxy`'s `pool_alloc` refuses in `session_new`;
    // the connection is closed, as when the arena cannot grow.
    let refused = ibex_alloc::pool::inject_failure();
    if refused {
        SESSION_POOL.failed();
    }
    let Some(session_idx) = (!refused).then_some(()).and_then(|()| engine.sessions.alloc(SessionEntry {
        sess,
        task: TaskRef::NONE,
        proxy_idx,
        backend_idx: proxy_idx,
        srv_backend_idx: proxy_idx,
        target_server_idx,
        cli_raw_fd,
        srv_raw_fd,
        cli_interest,
        srv_interest: Interest::NONE,
        actconn_reclaimed: false,
        stats_done: false,
        be_counted: std::cell::Cell::new(NO_BACKEND),
        connect_log_due: proxy.log_format.is_none() && !proxy.log_target_idx.is_empty(),
        rate_max_due: true,
        srv_served: 0,
        log_line: None,
        log_err: false,
        log_sd: 0,
        buf_wait: crate::buf_wait::WaitState::default(),
    })) else {
        if let Some(idx) = target_server_idx {
            if idx < proxy.server_actconn.len() {
                proxy.server_actconn[idx].fetch_sub(1, Ordering::Relaxed);
            }
        }
        return;
    };

    let Some(task_ref) = engine
        .scheduler
        .create(WorkKind::new(Kind::Stream, session_idx))
    else {
        if let Some(idx) = target_server_idx {
            if idx < proxy.server_actconn.len() {
                proxy.server_actconn[idx].fetch_sub(1, Ordering::Relaxed);
            }
        }
        engine.sessions.free(session_idx);
        return;
    };

    let Some(entry) = engine.sessions.get_mut(session_idx) else {
        return;
    };
    entry.task = task_ref;

    {
        engine.fdtab.insert(
            cli_raw_fd,
            FdState::Conn {
                task: task_ref,
                conn: 0,
            },
            cli_interest,
        );
        let Some(cfd) = entry.sess.cli_fd() else { return };
        let _ = engine.poller.add(
            cfd,
            raw_fd_to_u64(cli_raw_fd),
            cli_interest.readable,
            cli_interest.writable,
        );
    }

    if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.as_ref(), srv_raw_fd) {
        let init_srv_interest = if entry.sess.srv_state == ScState::Connecting {
            Interest::WRITE
        } else {
            Interest {
                readable: srv_want.read,
                writable: srv_want.write,
            }
        };
        entry.srv_interest = init_srv_interest;
        {
            engine.fdtab.insert(
                sfd,
                FdState::Conn {
                    task: task_ref,
                    conn: 1,
                },
                init_srv_interest,
            );
            let _ = engine.poller.add(
                srv_fd.as_fd(),
                raw_fd_to_u64(sfd),
                init_srv_interest.readable,
                init_srv_interest.writable,
            );
        }
    }

    engine
        .scheduler
        .queue_timer(task_ref, entry.sess.next_expiry());
    // A TLS client's handshake is the heavy part of its life: until it is done, its task
    // runs in `Heavy`, one per pass, and the established connections of this thread are
    // served between two handshakes (`HAProxy`'s `TASK_HEAVY`, T283). Cleared in `step`.
    if entry.sess.cli_tls_handshaking() {
        engine.scheduler.set_heavy(task_ref, true);
    }
    engine
        .scheduler
        .tasklet_wakeup(task_ref, Class::Urgent, state::WOKEN_IO);
}

/// Whether a server written without a port, or without an address, takes them from the
/// stream's destination (`SRV_F_MAPPORTS` in `HAProxy`).
fn maps_destination(server: SocketAddr) -> bool {
    server.port() == 0 || server.ip().is_unspecified()
}

/// The address a connection to `server` goes to: `alloc_dst_address` (src/backend.c). A
/// server without an address connects to the destination's, and one without a port to
/// the destination port -- which `set-dst-port` may have rewritten. The server keeps its
/// configured address as its identity (selection, `actconn`, stats); only the socket
/// sees this one.
pub(crate) fn connect_addr(server: SocketAddr, dst: Option<SocketAddr>) -> SocketAddr {
    let Some(dst) = dst else { return server };
    let ip = if server.ip().is_unspecified() { dst.ip() } else { server.ip() };
    let port = if server.port() == 0 { dst.port() } else { server.port() };
    SocketAddr::new(ip, port)
}

/// The stream connects to `target` now: `%si` and the stats read the configured address,
/// `bc_dst` the one the socket connects to.
fn set_target(entry: &mut SessionEntry, target: SocketAddr) {
    entry.sess.target_addr = Some(target);
    entry.sess.bc_idle = false;
}

fn maybe_prepend_send_proxy(fe: &Proxy, proxy: &Proxy, proxies: &[Proxy], sess: &mut TcpSession, target_addr: SocketAddr) {
    if sess.send_proxy_prepended {
        return;
    }
    let before = sess.req.len();
    prepend_send_proxy(fe, proxy, proxies, sess, target_addr);
    // The header goes out ahead of the request, so it is counted as part of the request's
    // head. Measured by the scanner it would not be: a v2 header opens with the bytes
    // `\r\n\r\n`, which read as the end of a head four bytes in.
    let added = sess.req.len() - before;
    if added > 0 {
        if let Some(t) = sess.txn.as_mut() {
            if let MsgState::Head { left: 0, body } = t.req {
                let head = crate::proxy::find_eoh(&sess.req.readable()[added..]).map_or(0, |(h, e)| h + e);
                t.req = MsgState::Head { left: added + head, body };
            }
        }
    }
}

fn prepend_send_proxy(fe: &Proxy, proxy: &Proxy, proxies: &[Proxy], sess: &mut TcpSession, target_addr: SocketAddr) {
    if let Some(hdr) = proxy_header(fe, proxy, proxies, sess, target_addr) {
        sess.req.replace_prefix(0, &hdr);
        sess.send_proxy_prepended = true;
        sess.send_proxy_header = hdr;
    }
}

/// The PROXY header this stream sends ahead of its request to `target_addr`, if that
/// server line asks for one.
fn proxy_header(fe: &Proxy, proxy: &Proxy, proxies: &[Proxy], sess: &mut TcpSession, target_addr: SocketAddr) -> Option<Vec<u8>> {
    let idx = proxy.servers.iter().position(|s| s == target_addr)?;
    let send_v2 = proxy
        .server_send_proxy_v2
        .get(idx)
        .copied()
        .unwrap_or(false);
    let send_v1 = proxy.server_send_proxy.get(idx).copied().unwrap_or(false);

    if send_v2 {
        let src = sess.client_addr;
        let dst = sess.server_addr.or(Some(proxy.addr));
        let mut tlv_data = sess.proxy_info.as_ref().map_or_else(Vec::new, |p| p.tlv_data.clone());
        if proxy.server_pp_unique_id.get(idx).copied().unwrap_or(false) {
            // `PP2_TYPE_UNIQUE_ID`: the stream's ID, built now if nothing has yet (a TCP
            // stream), from the frontend's format; without one, an empty TLV
            // (`stream_generate_unique_id`, `make_proxy_line_v2`).
            if sess.log.unique_id.is_none() {
                if let Some(fmt) = fe.unique_id_format.as_ref() {
                    let id = fmt.render(&session_log_data(sess, fe, proxy, std::process::id()), sample_registry(), &stream_sample_ctx(sess, fe, proxy, &ProxiesView(proxies), &StickView::new(proxies, &sess.tracked_sc)));
                    sess.log.unique_id = Some(id);
                }
            }
            let id = sess.log.unique_id.as_deref().unwrap_or("").as_bytes();
            let id = &id[..id.len().min(usize::from(u16::MAX))];
            tlv_data.push(0x05);
            tlv_data.extend_from_slice(&u16::try_from(id.len()).unwrap_or(u16::MAX).to_be_bytes());
            tlv_data.extend_from_slice(id);
        }
        Some(ibex_proto::encode_proxy_v2(ibex_proto::ProxyCommand::Proxy, src, dst, &tlv_data))
    } else if send_v1 {
        let src = sess.client_addr;
        let dst = sess.server_addr.or(Some(proxy.addr));
        Some(ibex_proto::encode_proxy_v1(src, dst))
    } else {
        None
    }
}

#[allow(clippy::too_many_arguments)]
fn init_client_session(
    proxies: &[Proxy],
    proxy_idx: usize,
    cli: crate::proxy::ClientSide,
    now: Tick,
    peer_addr: SocketAddr,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    fc_src: SocketAddr,
    fc_dst: SocketAddr,
    tls: Option<&Arc<ibex_tls::tcp::BindTls>>,
    ssl_capture_size: usize,
    ssl_ja4_spec: bool,
    tracked_sc: [Option<(usize, StickKey)>; 3],
    global_bufsize: usize,
    global_maxrewrite: usize,
    global_h2_flood_config: ibex_proto::H2FloodConfig,
    expect_proxy: bool,
    bind_proxy: (bool, bool),
) -> Option<(TcpSession, Option<SocketAddr>, Option<RawFd>)> {
    let mode = proxies[proxy_idx].mode;
    let timeouts = proxies[proxy_idx].timeouts;
    let retries = proxies[proxy_idx].retries;
    let cliexp = proxies[proxy_idx].cliexp.clone();
    let srvexp = proxies[proxy_idx].srvexp.clone();
    // The TLS transport is built on the accepted socket before the session owns it, so
    // there is no session without a client socket to account for (T342).
    let tls_xprt = match (&cli, tls) {
        (crate::proxy::ClientSide::Fd(fd), Some(cfg)) => Some(crate::xprt::accept_tls_capturing(fd, Arc::clone(cfg), ssl_capture_size, ssl_ja4_spec)),
        _ => None,
    };

    let mut sess = TcpSession::new_with_mode(
        cli,
        mode,
        cliexp,
        srvexp,
        timeouts,
        retries,
        now,
    );
    sess.client_addr = Some(client_addr);
    sess.server_addr = Some(server_addr);
    sess.fc_src = Some(fc_src);
    sess.fc_dst = Some(fc_dst);
    sess.tracked_sc = tracked_sc;
    sess.h2_flood_config = global_h2_flood_config;
    let fe = &proxies[proxy_idx];
    sess.accept_unsafe_request = fe.stats_config.accept_unsafe_request;
    sess.http_request_ms = fe.stats_config.raw_timeouts.http_request.map_or(0, millis_to_u32);
    sess.keep_alive_ms = fe.stats_config.raw_timeouts.http_keep_alive.map_or(0, millis_to_u32);
    sess.close_client = client_close(proxies, proxy_idx);
    sess.drop_rsp_trailers = fe.h1_adjust & ibex_config::H1_DROP_RES_TRAILERS != 0;
    sess.arm_request(now);
    sess.keep_request_line = (!fe.log_target_idx.is_empty() && fe.log_format.as_ref().is_some_and(|f| f.uses_request_line()))
        || fe.unique_id_format.as_ref().is_some_and(|f| f.uses_request_line());
    // Use per-engine values rather than the global `BUFSIZE_STANDARD` atomic so that
    // multiple Engine instances running in the same process (e.g. parallel tests) do not
    // race each other's configuration.
    sess.bufsize = global_bufsize;
    sess.maxrewrite = proxies[proxy_idx]
        .stats_config
        .maxrewrite
        .unwrap_or(global_maxrewrite)
        .min(global_bufsize / 2);

    // A TLS bind's connection is TLS from its first byte and never falls back to cleartext
    // (the downgrade `bind_tls` refuses to start with); a failed handshake closes it.
    if let Some(xprt) = tls_xprt {
        sess.cli_xprt = xprt;
        // T320: `SslRate`; `CurrSslConns` and `CumSslConns` are the transport's own.
        crate::stats::ssl_conn_accepted();
    }
    // `accept-proxy` belongs to the bind that accepted, not to the frontend.
    if bind_proxy.0 {
        sess.enable_accept_proxy(bind_proxy.1);
    } else if expect_proxy {
        // `tcp-request connection expect-proxy layer4` matched: v1 or v2, as `accept-proxy`.
        sess.enable_accept_proxy(false);
    }

    let registry = sample_registry();
    // With a PROXY header to come, the rules wait for it (`run_deferred_session_rules`).
    let session_rules = if sess.accept_proxy {
        sess.session_rules_pending = true;
        SessionEvalOutcome::Accept
    } else {
        stream_timeouts_enter(proxies, proxy_idx, proxy_idx, &sess);
        let out = with_stream_vars(&mut sess, &proxies[proxy_idx], |sess| eval_tcp_req_session_rules(&proxies[proxy_idx], proxies, registry, sess));
        CURRENT_TIMEOUTS.set(None);
        out
    };
    match session_rules {
        SessionEvalOutcome::Accept => {}
        SessionEvalOutcome::Reject => {
            sess.abort_client();
            proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SessionEvalOutcome::SilentDrop(ttl) => {
            let is_ipv6 = peer_addr.is_ipv6();
            sess.silent_drop_client(is_ipv6, ttl);
            proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    }

    // `use-server` of a proxy that serves directly (a TCP `listen`).
    let use_server = EngineDispatcher::use_server(&sess, proxy_idx, proxies);
    // `stick match` of a TCP `listen` that connects right here (`stick` rules wait for the
    // inspection of the request otherwise: `connect_tcp_backend`).
    let use_server = use_server.or_else(|| {
        let p = &proxies[proxy_idx];
        let direct = mode == Mode::Tcp
            && !sess.accept_proxy
            && p.tcp_req_inspect_delay.is_none()
            && p.tcp_req_content_rules.is_empty()
            && p.use_backends.is_empty()
            && p.default_backend.is_none();
        direct.then(|| EngineDispatcher::sticking_rules(&mut sess, proxy_idx, proxies, false)).flatten()
    });
    let proxy = &proxies[proxy_idx];

    let has_inspect = proxy.tcp_req_inspect_delay.is_some() || !proxy.tcp_req_content_rules.is_empty();
    if has_inspect {
        sess.tcp_inspect_done = false;
        if let Some(delay) = proxy.tcp_req_inspect_delay {
            let ms = u32::try_from(delay.as_millis()).unwrap_or(u32::MAX);
            sess.inspect_exp = Some(now.add(ms));
        }
    }

    let mut target_addr = None;
    let mut srv_raw_fd = None;

    if mode == Mode::Health {
        let w = sess.rep.writable();
        let msg = b"OK\n";
        let n = w.len().min(msg.len());
        w[..n].copy_from_slice(&msg[..n]);
        sess.rep.commit(n);
        sess.cli_state = ScState::ShutR;
        sess.srv_state = ScState::Closed;
    } else if mode == Mode::Tcp
        && !sess.accept_proxy
        && sess.tcp_inspect_done
        // A proxy that routes (`use_backend`, `default_backend`) connects once the backend
        // is resolved (`connect_tcp_backend`): its own server list is not the one to use.
        && proxy.use_backends.is_empty()
        && proxy.default_backend.is_none()
    {
        sess.lb_picked = use_server.is_none();
        // A balanced pick takes its server's slot with it (T590), on the index the session
        // is counted on (`register_new_session`); `use-server` is counted there.
        target_addr = match use_server {
            Some(i) => Some(proxy.servers.at(i)),
            None => proxy
                .pick_and_take(true, || {
                    let a = proxy.select_server_with_key(sess.client_addr.map(|a| a.ip()), sess.req_uri.as_deref())?;
                    Some((proxy.servers.iter().position(|s| s == a), a))
                })
                .map(|((_, a), _)| a),
        };
        if let Some(target) = target_addr {
            let proxies: &[Proxy] = proxies;
            let proxy = &proxies[proxy_idx];
            maybe_prepend_send_proxy(proxy, proxy, proxies, &mut sess, target);
            arm_res_inspect(proxy, &mut sess);
            sess.set_backend_timeouts(proxy);

            sess.target_addr = Some(target);
            let connected = raw::connect_opts(connect_addr(target, sess.server_addr), proxy.server_tfo_of(target))
                .inspect_err(|e| sess.bc_err = Some(crate::proxy::bc_connect_now_errno(e)));
            if let Ok((srv_fd, immediate)) = connected {
                let sfd = srv_fd.as_raw_fd();
                let s_idx = proxy.servers.iter().position(|s| s == target);
                attach_server_to(&mut sess, proxies, proxy_idx, proxy_idx, s_idx, srv_fd, now);
                srv_raw_fd = Some(sfd);
                if immediate {
                    sess.server_connected(now);
                }
            } else if !sess.server_failed() {
                // Out of retries already: `econ` counts this one (`server_connect_failed`
                // counts the failures of the retries).
                proxy.counters().failed_conn.fetch_add(1, Ordering::Relaxed);
                if let Some(i) = proxy.servers.iter().position(|s| s == target) {
                    proxy.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(i).or_default().2 += 1;
                }
                sess.srv_state = ScState::Error;
            }
        } else {
            sess.srv_state = ScState::Error;
        }
    }
    // In Mode::Http (or Mode::Tcp when accept_proxy is true or has_inspect is true), target connect is deferred
    Some((sess, target_addr, srv_raw_fd))
}

/// Gracefully shuts down a session entry, closing its sockets, reclaiming active connection counters,
/// and enqueuing its tasklet for wakeup.
pub fn shutdown_session_entry(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    wake_queue: &mut Vec<TaskRef>,
) {
    entry.sess.cli_state = ScState::Closed;
    entry.sess.srv_state = ScState::Closed;
    entry.sess.shutdown_both_client();
    if let Some(ref srv) = entry.sess.srv {
        raw::shutdown_both(srv.as_fd());
    }
    leave_backend(entry, proxies);
    if !entry.actconn_reclaimed {
        entry.actconn_reclaimed = true;
        let proxy_idx = entry.proxy_idx;
        // A stream of an HTTP/2 connection holds no connection slot (T280).
        // ... nor does an HTTP/3 request stream (T504): its connection does.
        if proxy_idx < proxies.len() && !entry.sess.is_h2_child() && !entry.sess.h3 {
            proxies[proxy_idx].counters().act_conn.fetch_sub(1, Ordering::Relaxed);
            crate::globalconn::release();
        }
        if let Some(s_idx) = entry.target_server_idx.filter(|_| !entry.sess.srv_park_exp.is_set()) {
            let be_idx = entry.srv_backend_idx;
            if be_idx < proxies.len() && s_idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[s_idx].fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    wake_queue.push(entry.task);
}

/// Shuts down active sessions matching an optional backend name and optional server ID.
pub fn shutdown_matching_sessions<'a>(
    sessions: impl IntoIterator<Item = &'a mut SessionEntry>,
    proxies: &[Proxy],
    backend_name: Option<&str>,
    server_id: Option<&str>,
    wake_queue: &mut Vec<TaskRef>,
) -> usize {
    let mut count = 0;
    for entry in sessions {
        let be_idx = entry.srv_backend_idx;
        if be_idx >= proxies.len() {
            continue;
        }
        if let Some(b_name) = backend_name {
            if proxies[be_idx].name != b_name {
                continue;
            }
        }
        if let Some(s_id) = server_id {
            let matches_server = entry
                .target_server_idx
                .and_then(|idx| proxies[be_idx].server_ids.get(idx))
                .is_some_and(|sid| sid == s_id);
            if !matches_server {
                continue;
            }
        }
        shutdown_session_entry(entry, proxies, wake_queue);
        count += 1;
    }
    count
}

fn clear_one(p: &Proxy) {
    p.stats.iter().for_each(|s| s.clear());
    if let Some(c) = p.ids.tc.get() {
        c.fe.clear();
        c.be.clear();
        c.srv.iter().for_each(crate::statcnt::TxnCounters::clear);
    }
    p.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
}

/// `clear counters server`: the counters of server `idx` of `p`, and no other.
pub fn clear_server_counters(p: &Proxy, idx: usize) {
    p.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&idx);
}

/// `clear counters` without `all`: the maxima of every proxy, nothing else.
pub fn clear_proxy_maxima(proxies: &[Proxy]) {
    for p in proxies {
        p.stats.iter().for_each(ProxyStats::clear_max);
        if let Some(c) = p.ids.tc.get() {
            c.fe.clear_max();
            c.be.clear_max();
            c.srv.iter().for_each(crate::statcnt::TxnCounters::clear_max);
        }
    }
}

/// Clears traffic and error counters for a specific proxy, or all proxies if `target` is `None` or `"all"`.
pub fn clear_proxy_counters(proxies: &[Proxy], target: Option<&str>) -> bool {
    let all = target.is_none_or(|n| n.eq_ignore_ascii_case("all"));
    let mut found = false;
    for p in proxies.iter().filter(|p| all || Some(p.name.as_str()) == target) {
        clear_one(p);
        found = true;
    }
    found || all
}

/// Dynamically enables or disables health checks for a server.
pub fn set_health_check_enabled(
    checks: &mut [ServerCheckState],
    proxies: &[Proxy],
    px_name: &str,
    sv_name: &str,
    enabled: bool,
    now: Tick,
) -> bool {
    let Some(proxy_idx) = proxies.iter().position(|p| p.name == px_name) else {
        return false;
    };
    let Some(server_idx) = proxies[proxy_idx]
        .server_ids
        .iter()
        .position(|sid| sid == sv_name)
    else {
        return false;
    };
    crate::track::set_check_enabled(proxies, checks, proxy_idx, server_idx, enabled, now)
}

/// A frontend without a `maxconn` (0 in the parsed configuration) is limited by the global
/// one, as in `HAProxy` (`show stat` `slim` of such a frontend is `Maxconn` of `show info`).
fn effective_fe_maxconn(configured: u32) -> u32 {
    if configured == 0 { crate::globalconn::hard() } else { configured }
}

/// Dynamically configures `maxconn` on a proxy or a specific server within a proxy.
pub fn set_proxy_maxconn(
    proxies: &[Proxy],
    px_name: &str,
    sv_name: Option<&str>,
    val: u32,
) -> bool {
    let Some(proxy) = proxies.iter().find(|p| p.name == px_name) else {
        return false;
    };
    if let Some(sv) = sv_name {
        let Some(s_idx) = proxy.server_ids.iter().position(|sid| sid == sv) else {
            return false;
        };
        proxy.server_maxconn.set(s_idx, Some(val))
    } else {
        // The listeners of the frontend read the same value (`Listener::is_full`).
        proxy.maxconn.set(val);
        true
    }
}

/// A check of server `s` of proxy `p` ended in a layer-4 timeout: its resolutions may be due
/// now (`resolvers::Section::trigger`). Out of line: kept off the dispatcher's code.
#[cold]
#[inline(never)]
fn trigger_resolutions(resolvers: &mut [crate::resolvers::Section], timers: &mut Vec<(TaskRef, Tick)>, now: Tick, p: usize, s: usize) {
    for sec in resolvers.iter_mut() {
        if sec.trigger(p, s) {
            timers.push((sec.task, now));
        }
    }
}

/// Internal dispatcher executing scheduler tasks against runtime sessions and health checks.
struct EngineDispatcher<'a> {
    sessions: &'a mut SessionArena,
    applets: &'a mut AppletArena,
    proxies: &'a mut Proxies,
    checks: &'a mut [ServerCheckState],
    resolvers: &'a mut [crate::resolvers::Section],
    fdtab: &'a mut FdTab,
    poller: &'a mut Poller,
    listeners: &'a mut [Listener],
    start_time: Instant,
    pid: u32,
    total_tasks: usize,
    run_queue_len: usize,
    now: Tick,
    timer_updates: Vec<(TaskRef, Tick)>,
    wake_queue: Vec<TaskRef>,
    /// The housekeeping concerns whose timers fired this pass (bit per `hk::*`), run by the
    /// engine after the pass.
    hk_due: u8,
    /// Tasks the current run woke for this pass (L2): the owner of an h2/h3 connection and
    /// its streams, a stream that wants another run. The scheduler takes them after the run
    /// (`Dispatch::pop_wake_now`); `wake_queue` is for what waits for the next pass.
    wake_now: Vec<TaskRef>,
    /// Streams whose server connection is in its TLS handshake after this pass: marked
    /// heavy after it, one per pass from then on, as the client side is at admission
    /// (T283; `ssl_sock_init` sets `TASK_HEAVY` for a server connection too). T295.
    heavy: Vec<TaskRef>,
    /// HTTP/2 connections (owner entry, task) with a stream to dispatch to an entry of its
    /// own: tasks are made after the pass, not during it (T280).
    h2_spawn: Vec<(u32, TaskRef)>,
    /// Shared read-only: the sockets live on the `Engine`, proxies index into this.
    log_targets: &'a [SyslogTarget],
    log_tag: &'a str,
    idle_backend_pool: &'a mut IdlePool,
    mailboxes: &'a Arc<crate::mailbox::Mailboxes>,
    worker_id: usize,
    /// The QUIC listeners, which the owners of HTTP/3 connections read and write (T509).
    quic_listeners: &'a mut [crate::quic_listener::QuicListener],
}

/// Answers the current request with the page for `status`, chosen as HAProxy's
/// `http_error_message` chooses it: the backend's `http-error`/`errorfile`, then the
/// frontend's, then the built-in page. Every error the proxy generates on a stream goes
/// through here, and through the `http-after-response` rules.
fn reply_error(entry: &mut SessionEntry, proxies: &[Proxy], status: u16) {
    // A server that fails to answer (502) or in time (504) is a failure of the request.
    if matches!(status, 502 | 504) {
        for_tracked(proxies, &entry.sess, |data| data.count_fail());
    }
    let be_idx = if entry.backend_idx < proxies.len() { entry.backend_idx } else { entry.proxy_idx };
    let page = proxy_error_response(&entry.sess, &proxies[be_idx], &proxies[entry.proxy_idx], proxies, status);
    send_proxy_reply(&mut entry.sess, proxies, entry.proxy_idx, be_idx, &page);
}

/// An `http_reply` with neither body nor headers: the status line and `content-length: 0`
/// (`http_reply_to_htx`, `src/http_htx.c`), through the `http-after-response` rules.
fn reply_empty(entry: &mut SessionEntry, proxies: &[Proxy], status: u16) {
    let be_idx = if entry.backend_idx < proxies.len() { entry.backend_idx } else { entry.proxy_idx };
    let reply = format!("HTTP/1.1 {status} {}\r\ncontent-length: 0\r\n\r\n", status_reason(status));
    send_proxy_reply(&mut entry.sess, proxies, entry.proxy_idx, be_idx, reply.as_bytes());
}

/// The answer to a request that could not be parsed. `HAProxy`'s H1 mux sends it before
/// there is a stream, so no rule runs on it -- `http-after-response` included.
fn reply_parse_error(entry: &mut SessionEntry, proxies: &[Proxy], status: u16) {
    let be = proxies.get(entry.backend_idx).unwrap_or(&proxies[entry.proxy_idx]);
    let mut page = proxy_error_response(&entry.sess, be, &proxies[entry.proxy_idx], proxies, status);
    // The H1 mux's own error reply goes through HTX, which writes the header names in lower
    // case (measured on 3.5-dev8: `content-length: 105`, `cache-control: ...`).
    rewrite_header_names(&mut page, client_case_table(&proxies[entry.proxy_idx]));
    // The page goes out as it is: HAProxy adds no `Connection: close` to the 413, 414, 422 and
    // 431 it closes after, nor to an `errorfile` 400 without one (T430 row 3).
    entry.sess.write_reply_with(&page, false);
    count_parse_error(entry, proxies, status);
}

/// The request that could not be parsed counts as a request and as the error or failure its
/// status is (measured: `http_req_cnt=1 http_err_cnt=1` for a 400).
fn count_parse_error(entry: &SessionEntry, proxies: &[Proxy], status: u16) {
    let (is_err, is_fail) = response_class(status);
    for_tracked(proxies, &entry.sess, |data| {
        data.count_request();
        if is_err {
            data.count_err();
        }
        if is_fail {
            data.count_fail();
        }
    });
}

/// Counts the session's server connection into (`add`) or out of its server's connections
/// in use.
fn server_actconn_add(entry: &SessionEntry, proxies: &[Proxy], add: bool) {
    if entry.actconn_reclaimed {
        return;
    }
    if let Some(a) = entry.target_server_idx.and_then(|i| proxies.get(entry.srv_backend_idx)?.server_actconn.get(i)) {
        if add {
            a.fetch_add(1, Ordering::Relaxed);
        } else {
            a.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// How long a server connection stays on its session after a response, for that client's
/// next request, before it goes to the server's lists (ms).
const SRV_PARK_MS: u32 = 100;

/// Detaches the server connection from the session: into the idle pool when it can carry
/// another request, closed otherwise. The server slot it held is released either way.
fn release_server(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    idle_pool: &mut IdlePool,
    reusable: bool,
) {
    // A parked connection has already left the server's count of connections in use.
    let parked = entry.sess.srv_park_exp.is_set();
    let mut actconn_released = false;
    if let Some(srv_fd) = entry.sess.srv.take() {
        let sfd = srv_fd.as_raw_fd();
        entry.srv_raw_fd = None;
        let reusable = reusable
            && matches!(entry.sess.srv_state, ScState::Ready | ScState::Established)
            // A connection that opened with a PROXY header speaks for this client only.
            && !entry.sess.send_proxy_prepended
            // A TLS session goes to the pool with its socket, once it is established.
            && entry.sess.srv_xprt.is_ready()
            // An h2 connection with no stream open and no GOAWAY (T540).
            && entry.sess.srv_xprt.reusable()
            && proxies.get(entry.srv_backend_idx).is_some_and(|p| {
                p.http_reuse != ibex_config::HttpReuse::Never
                    // An h2 connection is its session's under `safe` (T540, `session_add_conn`).
                    && !(p.http_reuse == ibex_config::HttpReuse::Safe && entry.sess.srv_xprt.is_h2())
            });
        // Whether the server closes it later is an event on it while it is idle
        // (`IdlePool::idle_event`): nothing is probed, here or when it is taken (T434).
        // The pool is keyed by server; a server that maps the destination may have been
        // connected anywhere, so its connections are not pooled.
        let xprt = std::mem::replace(&mut entry.sess.srv_xprt, crate::xprt::ServerXprt::Plain);
        // Only a server's connections are pooled (`srv_add_to_idle_list` needs one).
        let key = entry
            .sess
            .target_addr
            .filter(|&a| reusable && !maps_destination(a))
            .and_then(|addr| idle_key(addr, entry.srv_backend_idx, entry.target_server_idx, xprt.sni().map(str::to_string)));
        if let (Some(key), Some(be)) = (key, proxies.get(entry.srv_backend_idx)) {
            let cfg = be.ids.server_pool(key.srv.1);
            let used = be.server_actconn.get(key.srv.1).map_or(0, |a| a.load(Ordering::Relaxed)) + u32::from(parked);
            // Out of use before it counts as idle (`srv_add_to_idle_list` moves it from one
            // count to the other at once): in use and idle at the same time, another worker
            // weighing a release saw one connection more than there were and closed one the
            // next burst needed (T224). `used` above still counts it, as `HAProxy`'s does.
            release_server_actconn(entry, proxies, parked);
            actconn_released = true;
            // Idle, it stays in this worker's epoll set, for reads only (`h1_detach`
            // subscribing it `SUB_RETRY_RECV`): its server's close is an event on it
            // (`IdlePool::idle_event`), and the request that takes it again from this
            // worker's lists registers nothing (T434). After a response it waits for reads
            // already: no `epoll_ctl`.
            if entry.srv_interest != Interest::READ {
                let _ = poller.modify(srv_fd.as_fd(), raw_fd_to_u64(sfd), true, false);
            }
            entry.srv_interest = Interest::NONE;
            fdtab.set_idle(sfd);
            // An h2 connection is one a first request may take under `aggressive` from its
            // first response on: `HAProxy` keeps it in the server's available list (A.3 row 7,
            // 1 connection for 5 clients one after the other; T540).
            let safe = entry.srv_served >= 2 || xprt.is_h2();
            idle_pool.ensure_sized(proxies);
            if let Err(conn) = idle_pool.keep(key, IdleConn { fd: srv_fd, xprt, src: entry.sess.bc_src }, safe, cfg, used, crate::txnlog::loop_now()) {
                // Closing its only descriptor takes it out of the epoll set.
                fdtab.remove(sfd);
                conn.close();
            }
        } else {
            let _ = poller.delete(srv_fd.as_fd());
            fdtab.remove(sfd);
            entry.srv_interest = Interest::NONE;
            let mut xprt = xprt;
            xprt.send_close_notify(srv_fd.as_fd());
        }
    }
    entry.srv_raw_fd = None;
    entry.sess.srv_park_exp = Tick::ETERNITY;
    entry.sess.srv_xprt = crate::xprt::ServerXprt::Plain;
    if !actconn_released {
        release_server_actconn(entry, proxies, parked);
    }
    entry.target_server_idx = None;
    entry.sess.target_addr = None;
    entry.sess.bc_src = None;
    entry.sess.bc_err = None;
    entry.srv_served = 0;
    entry.sess.srv_state = ScState::Init;
    // The next server connection is a new one and gets its own PROXY header.
    if entry.sess.mode == Mode::Http {
        entry.sess.send_proxy_prepended = false;
    }
}

/// The stream no longer uses its server: out of the server's connections in use (a parked
/// connection left them already, and a reclaimed stream was taken out by the CLI).
fn release_server_actconn(entry: &SessionEntry, proxies: &[Proxy], parked: bool) {
    let be = entry.srv_backend_idx;
    if let Some(s_idx) = entry.target_server_idx {
        if !entry.actconn_reclaimed && !parked && be < proxies.len() && s_idx < proxies[be].server_actconn.len() {
            proxies[be].server_actconn[s_idx].fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// A server connection goes from one entry to another with everything that describes it:
/// from a stream of an HTTP/2 connection that kept it after its response to the
/// connection's owner, which keeps it for the next stream as the session kept it between
/// requests, and from the owner to that next stream (T280). Its descriptor wakes the task
/// it now belongs to.
fn move_server(from: &mut SessionEntry, to: &mut SessionEntry, fdtab: &mut FdTab) {
    let Some(fd) = from.sess.srv.take() else { return };
    let (f, t) = (&mut from.sess, &mut to.sess);
    t.srv = Some(fd);
    t.srv_xprt = std::mem::replace(&mut f.srv_xprt, crate::xprt::ServerXprt::Plain);
    t.srv_state = std::mem::replace(&mut f.srv_state, ScState::Init);
    t.srv_park_exp = std::mem::replace(&mut f.srv_park_exp, Tick::ETERNITY);
    t.srv_exp = std::mem::replace(&mut f.srv_exp, Tick::ETERNITY);
    t.conn_exp = std::mem::replace(&mut f.conn_exp, Tick::ETERNITY);
    t.srv_cant_recv = f.srv_cant_recv;
    t.send_proxy_prepended = std::mem::take(&mut f.send_proxy_prepended);
    t.send_proxy_header = std::mem::take(&mut f.send_proxy_header);
    t.target_addr = f.target_addr.take();
    t.bc_src = f.bc_src.take();
    t.bc_err = f.bc_err.take();
    to.srv_raw_fd = from.srv_raw_fd.take();
    to.srv_interest = std::mem::replace(&mut from.srv_interest, Interest::NONE);
    to.srv_backend_idx = from.srv_backend_idx;
    to.target_server_idx = from.target_server_idx.take();
    to.srv_served = std::mem::take(&mut from.srv_served);
    if let Some(sfd) = to.srv_raw_fd {
        fdtab.set_task(sfd, to.task);
    }
}

/// The bytes an HTTP/2 connection's owner moves for one of its streams (T280): the DATA
/// that came for its request into its `req`, and its response out of `rep` as frames.
/// `true` when the stream has something new to work on. Nothing on a stream the client
/// reset: its child ends it ([`h2_bridge_state`]).
fn h2_bridge_moves(o: &mut SessionEntry, c: &mut SessionEntry, now: Tick) -> bool {
    let (os, cs) = (&mut o.sess, &mut c.sess);
    let Some(h2) = os.h2_ctx.as_deref_mut() else { return false };
    let Some(crate::proxy::H2Role::Child(ch)) = cs.h2_role.as_deref_mut() else { return false };
    if ch.reset || crate::h2_bridge::stream_is_reset(h2, ch.stream.id) {
        return false;
    }
    ch.stream.body.drop_trailers = cs.drop_req_trailers;
    let (mut moved, trailers) = crate::h2_bridge::pump_request_body(h2, &mut ch.stream, &mut cs.req);
    // A stream's entry has its transaction until it is freed.
    let Some(t) = cs.txn.as_mut() else { return moved };
    // What the trailers add to `%U`.
    if let Some(u) = t.req_htx.as_mut() {
        *u += trailers;
    }
    // The client's END_STREAM on an extended CONNECT's tunnel ends what the server is sent,
    // once what came before has gone: its FIN, as `HAProxy` sends it, and the stream ends
    // when the server closes (T505).
    if t.req == MsgState::Tunnel && ch.stream.body.done && cs.req.is_empty() && matches!(cs.srv_state, ScState::Ready | ScState::Established) {
        if let Some(sfd) = cs.srv.as_ref().map(std::os::fd::AsFd::as_fd) {
            cs.srv_xprt.send_close_notify(sfd);
            crate::raw::shutdown_write(sfd);
        }
        cs.srv_state = ScState::ShutW;
        t.close_after = true;
        moved = true;
    }
    let before = (cs.rep.len(), t.rsp);
    let srv_gone = matches!(cs.srv_state, ScState::ShutR | ScState::Closed | ScState::Error);
    if crate::h2_bridge::forward_response(h2, ch.stream.id, t, &mut cs.rep, srv_gone, &mut ch.late_trailers, &mut ch.rsp_head) {
        cs.log.term = Some(*b"SD");
        moved = true;
    }
    moved |= before != (cs.rep.len(), t.rsp);
    // Progress on the stream re-arms its own client timer, as `HAProxy`'s stream channels
    // see the bytes the mux takes and gives (T300).
    if moved && matches!(os.cli_state, ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW) {
        cs.arm_client(now);
    }
    // A body the rules left without framing is dropped as it comes (T442).
    cs.drain_request();
    moved
}

/// What the owner of an HTTP/2 connection tells one of its streams after its pass (T280):
/// the client reset the stream, left, or the connection timed out or failed (its state and
/// ending, which were the session's); whether frames are still unwritten (the stream's
/// "output pending"); and the glitches the connection counted, credited to the counters
/// the stream tracks. `true` when the stream has something new to see.
fn h2_bridge_state(o: &mut SessionEntry, c: &mut SessionEntry, proxies: &[Proxy]) -> bool {
    let (os, cs) = (&mut o.sess, &mut c.sess);
    let Some(h2) = os.h2_ctx.as_deref() else { return false };
    let reset = crate::h2_bridge::stream_is_reset(h2, cs.h2_active().map_or(0, |a| a.id));
    let tx_pending = h2.tx_consumed < h2.tx_buf.len();
    let glitches = h2.glitch_count as u64;
    let Some(crate::proxy::H2Role::Child(ch)) = cs.h2_role.as_deref_mut() else { return false };
    let mut wake = false;
    if reset && !ch.reset {
        ch.reset = true;
        wake = true;
    }
    if ch.owner_tx_pending != tx_pending {
        ch.owner_tx_pending = tx_pending;
        wake = true;
    }
    if !matches!(os.cli_state, ScState::Ready | ScState::Established)
        && matches!(cs.cli_state, ScState::Ready | ScState::Established | ScState::ShutR)
        && cs.cli_state != os.cli_state
    {
        cs.cli_state = os.cli_state;
        wake = true;
    }
    if let (Some(e), None) = (os.ending, cs.ending) {
        cs.ending = Some(e);
        wake = true;
    }
    if glitches > os.glitches_credited {
        let due = glitches - os.glitches_credited;
        os.glitches_credited = glitches;
        for_tracked(proxies, cs, |data| data.add_glitches(due));
    }
    wake
}

/// [`h2_bridge_moves`] for a stream of an HTTP/3 connection (T509).
fn h3_bridge_moves(o: &mut SessionEntry, c: &mut SessionEntry, now: Tick) -> bool {
    let (os, cs) = (&mut o.sess, &mut c.sess);
    let Some(h3) = os.h3_owner_mut() else { return false };
    let Some(crate::proxy::H2Role::Child(ch)) = cs.h2_role.as_deref_mut() else { return false };
    let mux = &mut *h3.mux;
    if ch.reset || ibex_proto::htx_mux::HtxMux::is_reset(mux, u64::from(ch.stream.id)) {
        return false;
    }
    ch.stream.body.drop_trailers = cs.drop_req_trailers;
    let (mut moved, trailers) = crate::h2_bridge::pump_request_body_mux(mux, &mut ch.stream, &mut cs.req);
    let Some(t) = cs.txn.as_mut() else { return moved };
    if let Some(u) = t.req_htx.as_mut() {
        *u += trailers;
    }
    let before = (cs.rep.len(), t.rsp);
    let srv_gone = matches!(cs.srv_state, ScState::ShutR | ScState::Closed | ScState::Error);
    if crate::h2_bridge::forward_response_mux(mux, ch.stream.id, t, &mut cs.rep, srv_gone, &mut h3.body_scratch, &mut ch.late_trailers, &mut ch.rsp_head) {
        cs.log.term = Some(*b"SD");
        moved = true;
    }
    moved |= before != (cs.rep.len(), t.rsp);
    if moved {
        cs.arm_client(now);
    }
    cs.drain_request();
    moved
}

/// [`h2_bridge_state`] for a stream of an HTTP/3 connection (T509): its reset, and the
/// connection failing (`failed`: the mux's connection error, which closes it).
/// The deadline of an HTTP/3 connection's owner (`qcc_refresh_timeout`, `src/mux_quic.c`),
/// T521 (RV-16). A stream served, or one whose head is in and waits for its child: none (each
/// stream has its own timers). Output waiting: `timeout client` from now. A stream with a
/// partial head: `timeout http-request` from that stream's start, the oldest one's
/// (`qcc->opening_list`); no request yet: `http-request` from the connection's start; else
/// `http-keep-alive` (or `http-request`) from the end of the last stream. Neither set:
/// `timeout client` from now.
fn h3_owner_deadline(s: &crate::proxy::TcpSession, now: Tick) -> Tick {
    use ibex_proto::htx_mux::HtxMux;
    let Some(h3) = s.h3_owner() else { return Tick::ETERNITY };
    let mux = &*h3.mux;
    let client = if s.timeouts.client == 0 { Tick::ETERNITY } else { now.add(s.timeouts.client) };
    if s.h2_owner().is_some_and(|o| !o.children.is_empty()) || mux.next_dispatch().is_some() {
        return Tick::ETERNITY;
    }
    if mux.tx_pending() {
        return client;
    }
    let (base, ms) = match (mux.head_partial(), mux.last_client_stream_id) {
        // The mux keeps the owner's tick (`now.0`) as the stream's start.
        (Some(start), _) => (Tick(u32::try_from(start).unwrap_or(now.0)), s.http_request_ms),
        (None, None) => (h3.idle_start, s.http_request_ms),
        (None, Some(_)) => (h3.idle_start, if s.keep_alive_ms != 0 { s.keep_alive_ms } else { s.http_request_ms }),
    };
    if ms == 0 {
        // `timeout client` as the fallback (T562): HAProxy computes it from `now` only when the
        // mux is woken by a stream event, so on a quiet connection (PINGs wake no mux) it runs
        // out. Recomputed from `now` at every owner step it would slide for ever; anchor it at
        // `idle_start` unless a stream's head is in progress.
        if mux.head_partial().is_none() && s.timeouts.client != 0 {
            h3.idle_start.add(s.timeouts.client)
        } else {
            client
        }
    } else {
        base.add(ms)
    }
}

fn h3_bridge_state(o: &mut SessionEntry, c: &mut SessionEntry, failed: bool) -> bool {
    let (os, cs) = (&mut o.sess, &mut c.sess);
    let Some(h3) = os.h3_owner() else { return false };
    let tx_pending = ibex_proto::htx_mux::HtxMux::tx_pending(&*h3.mux);
    let reset = cs.h2_active().is_some_and(|a| ibex_proto::htx_mux::HtxMux::is_reset(&*h3.mux, u64::from(a.id)));
    let Some(crate::proxy::H2Role::Child(ch)) = cs.h2_role.as_deref_mut() else { return false };
    let mut wake = false;
    if reset && !ch.reset {
        ch.reset = true;
        wake = true;
    }
    if ch.owner_tx_pending != tx_pending {
        ch.owner_tx_pending = tx_pending;
        wake = true;
    }
    if failed && matches!(cs.cli_state, ScState::Ready | ScState::Established | ScState::ShutR) {
        cs.cli_state = ScState::Closed;
        cs.ending.get_or_insert(crate::proxy::Ending::ClientAbort);
        wake = true;
    }
    wake
}

/// A stream of an HTTP/2 connection whose request went whole to the server (its length
/// is in) but which the client has not ended yet: trailers, or an empty `END_STREAM`, may
/// still come. `HAProxy` holds the stream until they do (measured on 3.5-dev8: trailers
/// sent after the whole response are counted in `%U`, the line is logged then, and nothing
/// more is sent on the stream); ended here, the line went out without them, the stream was
/// reset, and the trailers that came after were a `GOAWAY` for a frame on a closed stream.
/// So too an extended CONNECT's tunnel the server ended first (T505).
fn h2_request_open(sess: &TcpSession, txn: &crate::txn::HttpTxn) -> bool {
    (txn.req.is_done() || txn.req == MsgState::Tunnel) && !txn.local && sess.h2_active().is_some_and(|a| !a.body.done)
}

/// A stream of an HTTP/2 connection whose reply the proxy made itself (`http-request
/// return`, `deny`, ...) is over while the client's request is not: it ends there, and
/// `h2_child_released` resets it with `NO_ERROR` so the client stops sending, as `HAProxy`
/// does (measured on 3.5-dev8, T314). A response from a server does not do this: `HAProxy`
/// leaves such a stream open until the request ends.
fn h2_local_reply_over_open_request(sess: &TcpSession, txn: &crate::txn::HttpTxn) -> bool {
    txn.local && txn.rsp.is_done() && sess.h2_active().is_some_and(|a| !a.body.done)
}

/// Ends the HTTP session: the server connection is pooled if `reusable`, the client
/// connection closed.
fn close_http_session(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    idle_pool: &mut IdlePool,
    reusable: bool,
) {
    // A transaction that ends with its connection, not through `end_txn` (cut short by
    // either side), logs here, while its request and response are still known.
    if entry.sess.txn.is_some() && entry.log_line.is_none() {
        set_stream_log(entry, proxies, std::process::id());
    }
    release_server(entry, proxies, fdtab, poller, idle_pool, reusable);
    if matches!(entry.sess.cli_state, ScState::Ready | ScState::Established | ScState::ShutR) {
        entry.sess.shutw_cli();
    }
    entry.sess.txn = None;
    entry.sess.cli_state = ScState::Closed;
    entry.sess.srv_state = ScState::Closed;
    entry.sess.ending.get_or_insert(crate::proxy::Ending::Complete);
}

/// `srv_inc_sess_ctr`: a stream was assigned to the server at `addr` of backend `be_idx`,
/// whether it then reuses a connection to it or opens one (`srv_sess_rate`).
fn count_server_session(proxies: &[Proxy], be_idx: usize, idx: Option<usize>) {
    let px = &proxies[be_idx];
    idx.and_then(|idx| px.server_sess_rates.get(idx)).inspect(|rate| rate.tick());
}

/// `SessionEntry::be_counted` of a stream no backend counts.
const NO_BACKEND: u32 = u32::MAX;

/// The index of the backend counting the stream.
fn counted_backend(entry: &SessionEntry) -> Option<usize> {
    Some(entry.be_counted.get()).filter(|&i| i != NO_BACKEND).map(|i| i as usize)
}

/// The stream belongs to backend `be_idx` (`stream_set_backend`: `beconn` counts it).
fn enter_backend(entry: &SessionEntry, proxies: &[Proxy], be_idx: usize) {
    if counted_backend(entry) == Some(be_idx) {
        return;
    }
    leave_backend(entry, proxies);
    if let Some(p) = proxies.get(be_idx) {
        // `stream_set_backend`: `conn_max` follows `beconn`, the backend's smax, at the one
        // place a stream joins it (O(1); no sum over the servers per request).
        let beconn = p.counters().be_streams.fetch_add(1, Ordering::Relaxed) + 1;
        crate::statcnt::max(&p.txn_counters().be.smax, beconn);
        entry.be_counted.set(u32::try_from(be_idx).unwrap_or(NO_BACKEND));
    }
}

/// The stream is done with its backend (`stream_free`): when its transaction is logged, or
/// the session ends.
fn leave_backend(entry: &SessionEntry, proxies: &[Proxy]) {
    if let Some(p) = counted_backend(entry).and_then(|i| proxies.get(i)) {
        entry.be_counted.set(NO_BACKEND);
        let _ = p.counters().be_streams.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| Some(c.saturating_sub(1)));
    }
}

/// `connect_server`: an attempt to reach the server counts in `reuse` on the server and the
/// backend when the stream uses a connection that exists already, in `connect` when it makes
/// one (failed attempts included).
fn count_connect(proxies: &[Proxy], be_idx: usize, srv_idx: Option<usize>, reused: bool) {
    let Some(px) = proxies.get(be_idx) else { return };
    let tc = px.txn_counters();
    let pick = |c: &crate::statcnt::TxnCounters| if reused { c.reuse.fetch_add(1, Ordering::Relaxed) } else { c.connect.fetch_add(1, Ordering::Relaxed) };
    pick(&tc.be);
    if let Some(c) = srv_idx.and_then(|i| tc.srv.get(i)) {
        pick(c);
    }
}

/// `srv_inc_sess_ctr` for a connect attempt that failed: the server's `stot` and session
/// rate count it, as they count the attempt that ends the stream ([`account_stream`]).
fn count_failed_attempt(proxies: &[Proxy], be_idx: usize, srv_idx: usize) {
    if let Some(c) = proxies.get(be_idx).and_then(|p| p.txn_counters().srv.get(srv_idx)) {
        c.stot.fetch_add(1, Ordering::Relaxed);
        c.sess_rate.tick_at(RateCtr::at(crate::statcnt::now_ms()));
    }
}

/// A connect attempt to the stream's server failed (`back_handle_st_cer`): while retries
/// remain, connect again -- after the turnaround (`SC_ST_TAR`) when `wait`, an asynchronous
/// connect error, and the server is the same one; at once after a connect refused at once.
/// Out of retries, the failure counts in `econ` on the backend and on the server tried
/// last (once per stream, not per attempt: measured on `HAProxy`, `retries 2` shows
/// `wretr` 2, `econ` 1) and the stream ends, with a 503 in HTTP.
fn server_connect_failed(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    mut wait: bool,
) {
    loop {
        // The failed socket leaves the poller and the fd table before `server_failed`
        // closes it, as `HAProxy`'s `fd_delete` does (T443). A close takes it out of the
        // epoll set only if it was the last reference (a `fork` in progress holds one), and
        // the entry left behind woke this task's slot once it was freed.
        release_failed_server(entry, fdtab, poller);
        if !entry.sess.server_failed() {
            let be = &proxies[entry.srv_backend_idx];
            be.counters().failed_conn.fetch_add(1, Ordering::Relaxed);
            if let Some(i) = entry.target_server_idx {
                be.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entry(i).or_default().2 += 1;
            }
            entry.sess.srv_state = ScState::Error;
            if entry.sess.mode == Mode::Http {
                reply_error(entry, proxies, 503);
            }
            return;
        }
        if !retry_server_connect(entry, proxies, fdtab, poller, now, wait) {
            return;
        }
        wait = false;
    }
}

/// Takes a failed server connection out of the poller and the fd table, its socket kept
/// for the caller to close: an fd-table entry must not outlive the socket it names (T443).
fn release_failed_server(entry: &mut SessionEntry, fdtab: &mut FdTab, poller: &mut Poller) {
    if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.as_ref(), entry.srv_raw_fd.take()) {
        let _ = poller.delete(srv_fd.as_fd());
        fdtab.remove(sfd);
    }
}

/// Connects again now, the retry of a connect that failed (a turnaround over, or the
/// connect made at accept refused at once); a refusal at once is the next failure.
fn retry_now(entry: &mut SessionEntry, proxies: &[Proxy], fdtab: &mut FdTab, poller: &mut Poller, now: Tick) {
    if retry_server_connect(entry, proxies, fdtab, poller, now, false) {
        server_connect_failed(entry, proxies, fdtab, poller, now, false);
    }
}

/// Connects the stream again after a failed attempt, to the same server or, redispatched,
/// another. Returns `true` when this connect is refused at once, which the caller handles
/// as the next failure ([`server_connect_failed`]); a turnaround armed or a connect under
/// way returns `false`.
fn retry_server_connect(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
    wait: bool,
) -> bool {
    release_failed_server(entry, fdtab, poller);
    entry.sess.srv = None;

    let old_idx = entry.target_server_idx.take();
    if let Some(old_idx) = old_idx {
        let old_be = entry.srv_backend_idx;
        if old_be < proxies.len() && old_idx < proxies[old_be].server_actconn.len() {
            proxies[old_be].server_actconn[old_idx].fetch_sub(1, Ordering::Relaxed);
        }
    }

    let be_idx = EngineDispatcher::resolve_backend(entry, proxies).unwrap_or(entry.proxy_idx);
    entry.backend_idx = be_idx;
    let source_ip = entry.sess.client_addr.map(|a| a.ip());
    let be = &proxies[be_idx];
    // `stream_choose_redispatch`: with `option redispatch` the retry may be balanced anew.
    // A retry that waited out its turnaround (`SC_ST_TAR`) resumes here: the server was
    // chosen, and counted, when the wait began.
    let resuming = entry.sess.retry_after.is_set();
    entry.sess.retry_after = Tick::ETERNITY;
    // The attempt that failed counts on the server it was made on, once (a turnaround that
    // resumes is the same attempt's retry).
    if !resuming {
        if let Some(i) = old_idx {
            count_failed_attempt(proxies, entry.srv_backend_idx, i);
        }
    }
    let redispatch = !resuming && be.redisp && {
        let status_of = |i: usize| be.server_statuses.get(i).map(|s| s.load(Ordering::Relaxed));
        let running = old_idx.is_none_or(|i| {
            status_of(i).is_some_and(|s| s == ServerStatus::Up as u8 || s == ServerStatus::Drain as u8)
        });
        let active = (0..be.servers.len())
            .filter(|&i| !be.server_backups.get(i).copied().unwrap_or(false) && status_of(i) == Some(ServerStatus::Up as u8))
            .count();
        let hash = matches!(be.balance, BalanceAlgorithm::Source | BalanceAlgorithm::Uri);
        let direct = entry.sess.txn.as_ref().is_some_and(|t| t.ck.direct);
        crate::lb::redispatch_due(
            be.redisp_after,
            entry.sess.max_retries,
            entry.sess.max_retries.saturating_sub(entry.sess.conn_retries),
            running,
            direct,
            active,
            hash,
        )
    };
    let target = if resuming {
        entry.sess.target_addr
    } else if redispatch {
        // A consistent ring walks past the server to avoid; a map-based hash cannot.
        let hash = matches!(proxies[be_idx].balance, BalanceAlgorithm::Source | BalanceAlgorithm::Uri)
            && proxies[be_idx].hash_type != ibex_config::HashType::Consistent;
        // The balancing algorithm is asked to avoid the server that just failed, unless it
        // is the only one left (`fwrr_get_next_server(.., prev_srv)` and the like).
        // Only another active server counts: a backup is not a way out of the one active
        // server, which is then asked again.
        let others = proxies[be_idx].eligible_server_indices().len() > 1;
        let be = &proxies[be_idx];
        crate::lb::with_avoided(be, if hash || !others { None } else { old_idx }, || {
            be.select_server_with_key(source_ip, entry.sess.req_uri.as_deref())
        })
    } else {
        entry
            .sess
            .target_addr
            .or_else(|| proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref()))
    };
    // A different server is a redispatch (`wredis`), the same one a retry (`wretr`); the
    // client's persistence cookie no longer holds (`SF_DIRECT` cleared, `TX_CK_DOWN`).
    let moved = target.is_some() && entry.sess.target_addr.is_some() && target != entry.sess.target_addr;
    let stats = &proxies[be_idx].counters();
    let count_on_server = |redispatch: bool| {
        let mut m = proxies[be_idx].server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        old_idx.into_iter().for_each(|i| {
            let c = m.entry(i).or_default();
            c.0 += u64::from(!redispatch);
            c.1 += u64::from(redispatch);
        });
    };
    // `SF_REDISP` is set when the server changed, not when a redispatch was due and the
    // balancer gave the same one again (`assign_server_and_queue`).
    if !resuming && moved {
        entry.sess.log.redispatched = true;
        entry.sess.redispatched = true;
        count_on_server(true);
        stats.redispatches.fetch_add(1, Ordering::Relaxed);
        // The server left was a pick too, if the balancer made it (`cum_lbconn` counts each
        // pick of a server other than the last); the next one is the balancer's.
        if entry.sess.lb_picked {
            proxies[be_idx].txn_counters().be.lbtot.fetch_add(1, Ordering::Relaxed);
            if let Some(c) = old_idx.and_then(|i| proxies[entry.srv_backend_idx].txn_counters().srv.get(i)) {
                c.lbtot.fetch_add(1, Ordering::Relaxed);
            }
        }
        entry.sess.lb_picked = true;
        entry.sess.txn.iter_mut().for_each(|txn| {
            txn.ck.direct = false;
            // TX_CK_VALID (3) becomes TX_CK_DOWN (2).
            txn.ck.ck = if txn.ck.ck == 3 { 2 } else { txn.ck.ck };
        });
    } else if !resuming {
        count_on_server(false);
        stats.retries_count.fetch_add(1, Ordering::Relaxed);
    }

    let Some(target_addr) = target else {
        entry.sess.srv_state = ScState::Error;
        return false;
    };

    // The same server again after an asynchronous connect error: wait `MIN(1s, timeout
    // connect)` first (`SC_ST_TAR`, `src/backend.c`). `check_timeouts_and_retry` resumes the
    // connect when it is over. A connect refused at once is retried at once.
    if wait && !resuming && entry.sess.target_addr == Some(target_addr) {
        entry.sess.retry_after = now.add(entry.sess.retry_delay_ms());
        return false;
    }

    let s_idx = proxies[be_idx]
        .servers
        .iter()
        .position(|s| s == target_addr);
    if let Some(idx) = s_idx {
        if idx < proxies[be_idx].server_actconn.len() {
            proxies[be_idx].server_actconn[idx].fetch_add(1, Ordering::Relaxed);
        }
    }
    entry.target_server_idx = s_idx;
    entry.srv_backend_idx = be_idx;
    entry.sess.log.server = s_idx.and_then(crate::txnlog::server_slot);
    count_connect(proxies, be_idx, s_idx, false);

    maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

    set_target(entry, target_addr);
    if let Ok((srv_fd, immediate)) = raw::connect_opts(connect_addr(target_addr, entry.sess.server_addr), proxies[be_idx].server_tfo_of(target_addr))
        .inspect_err(|e| entry.sess.bc_err = Some(crate::proxy::bc_connect_now_errno(e)))
    {
        let sfd = srv_fd.as_raw_fd();
        attach_server_to(&mut entry.sess, proxies, entry.proxy_idx, be_idx, s_idx, srv_fd, now);
        entry.srv_raw_fd = Some(sfd);
        if immediate {
            entry.sess.server_connected(now);
            let (_, srv_want) = entry.sess.interests();
            let new_interest = Interest {
                readable: srv_want.read,
                writable: srv_want.write,
            };
            entry.srv_interest = new_interest;
            fdtab.insert(
                sfd,
                FdState::Conn {
                    task: entry.task,
                    conn: 1,
                },
                new_interest,
            );
            if let Some(ref srv) = entry.sess.srv {
                let _ = poller.add(
                    srv.as_fd(),
                    raw_fd_to_u64(sfd),
                    new_interest.readable,
                    new_interest.writable,
                );
            }
        } else {
            entry.srv_interest = Interest::WRITE;
            fdtab.insert(
                sfd,
                FdState::Conn {
                    task: entry.task,
                    conn: 1,
                },
                Interest::WRITE,
            );
            if let Some(ref srv) = entry.sess.srv {
                let _ = poller.add(srv.as_fd(), raw_fd_to_u64(sfd), false, true);
            }
        }
    } else {
        return true;
    }
    false
}

fn check_srv_connect(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
) {
    if entry.sess.srv_state == ScState::Connecting {
        if let Some(sfd) = entry.srv_raw_fd {
            if fdtab.ready(sfd).writable {
                let conn_err = entry.sess.srv.as_ref().map_or(
                    Ok(Some(io::Error::from(io::ErrorKind::NotConnected))),
                    |sock| raw::check_connect_error(sock.as_fd()),
                );

                if let Ok(None) = conn_err {
                    entry.sess.server_connected(now);
                    let (_, srv_want) = entry.sess.interests();
                    let new_interest = Interest {
                        readable: srv_want.read,
                        writable: srv_want.write,
                    };
                    if new_interest != entry.srv_interest {
                        if let Some(srv_fd) = entry.sess.srv.as_ref() {
                            let _ = poller.modify(
                                srv_fd.as_fd(),
                                raw_fd_to_u64(sfd),
                                new_interest.readable,
                                new_interest.writable,
                            );
                        }
                        fdtab.set_interest(sfd, new_interest);
                        entry.srv_interest = new_interest;
                    }
                } else {
                    if let Ok(Some(e)) = &conn_err {
                        entry.sess.bc_err = Some(crate::proxy::bc_connect_errno(e));
                    }
                    server_connect_failed(entry, proxies, fdtab, poller, now, true);
                }
            }
        }
    }
}

fn update_interests(entry: &mut SessionEntry, fdtab: &mut FdTab, poller: &mut Poller) {
    let (mut cli_want, mut srv_want) = entry.sess.interests();
    // Waiting for a buffer to read into (S6): that side is not polled for reading until the
    // stream is woken, or its unread bytes would wake it on every loop.
    if entry.buf_wait.queued() {
        cli_want.read &= !entry.buf_wait.mutes_cli();
        srv_want.read &= !entry.buf_wait.mutes_srv();
    }
    let new_cli_interest = Interest {
        readable: cli_want.read,
        writable: cli_want.write,
    };
    // A stream of an HTTP/2 connection polls no client socket: its owner does (T280).
    if let Some(cfd) = entry.sess.cli_fd().filter(|_| new_cli_interest != entry.cli_interest) {
        let _ = poller.modify(
            cfd,
            raw_fd_to_u64(entry.cli_raw_fd),
            new_cli_interest.readable,
            new_cli_interest.writable,
        );
        fdtab.set_interest(entry.cli_raw_fd, new_cli_interest);
        entry.cli_interest = new_cli_interest;
    }

    if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.as_ref(), entry.srv_raw_fd) {
        if entry.sess.srv_state != ScState::Connecting {
            let new_srv_interest = Interest {
                readable: srv_want.read,
                writable: srv_want.write,
            };
            if new_srv_interest != entry.srv_interest {
                let _ = poller.modify(
                    srv_fd.as_fd(),
                    raw_fd_to_u64(sfd),
                    new_srv_interest.readable,
                    new_srv_interest.writable,
                );
                fdtab.set_interest(sfd, new_srv_interest);
                entry.srv_interest = new_srv_interest;
            }
        }
    }
}

fn cleanup_done(
    entry: &SessionEntry,
    proxies: &[Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    listeners: &mut [Listener],
) {
    if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.as_ref(), entry.srv_raw_fd) {
        let _ = poller.delete(srv_fd.as_fd());
        fdtab.remove(sfd);
    }
    leave_backend(entry, proxies);

    // A stream of an HTTP/2 connection is no connection: the socket, its bytes, its slot
    // in `maxconn` and its tracked counters are its owner's, which settles them when it
    // ends. Only its server connection is its own (T280).
    let Some(cfd) = entry.sess.cli_fd() else {
        if let Some(s_idx) = entry.target_server_idx.filter(|_| !entry.actconn_reclaimed && !entry.sess.srv_park_exp.is_set()) {
            let be_idx = entry.srv_backend_idx;
            if be_idx < proxies.len() && s_idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[s_idx].fetch_sub(1, Ordering::Relaxed);
            }
        }
        return;
    };
    let _ = poller.delete(cfd);
    fdtab.remove(entry.cli_raw_fd);
    let proxy_idx = entry.proxy_idx;
    proxies[proxy_idx].counters().bytes_in.fetch_add(entry.sess.bytes_in, Ordering::Relaxed);
    proxies[proxy_idx].counters().bytes_out.fetch_add(entry.sess.bytes_out, Ordering::Relaxed);
    if !entry.actconn_reclaimed && !entry.sess.h3 {
        proxies[proxy_idx].counters().act_conn.fetch_sub(1, Ordering::Relaxed);
        crate::globalconn::release();

        if let Some(s_idx) = entry.target_server_idx.filter(|_| !entry.sess.srv_park_exp.is_set()) {
            let be_idx = entry.srv_backend_idx;
            if be_idx < proxies.len() && s_idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[s_idx].fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    let (din, dout) = stick_bytes_due(&entry.sess, true);
    for_tracked(proxies, &entry.sess, |data| {
        data.add_bytes(din, dout);
        data.untrack();
    });

    // An HTTP/3 request stream took no listener slot (`admit_connection`).
    if let Some(l) = listeners.iter_mut().filter(|_| !entry.sess.h3).find(|l| l.proxy == usize_to_u32(proxy_idx)) {
        l.maxconn.dec();
        let lfd = l.raw_fd();
        if !l.is_full() && fdtab.interest(lfd).is_none() {
            let _ = poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), true, false);
            fdtab.set_interest(lfd, Interest::READ);
        }
    }
}

/// `HAProxy`'s `monitor-uri` answer; the connection stays open after it.
const MONITOR_URI_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 58\r\n\
cache-control: no-cache\r\ncontent-type: text/html\r\n\r\n\
<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n";

/// Adds `Connection: <token>` as the last header of the head at the front of `buf`, with the
/// line ends the head has. The head is copied through the stack (no allocation) when it fits.
/// `canonical`: the head is one [`ibex_proto::response_head::RspHead`] indexes (CRLF line
/// ends, names in lower case), and the line goes in as `connection: <token>\r\n`. The length
/// of the line put in, `None` when it went in another way.
fn inject_connection_token_zero_alloc(buf: &mut crate::buf::Buf, token: &str, canonical: bool) -> Option<usize> {
    let (eoh_pos, eoh_len) = buf.eoh()?;
    let crlf = canonical || {
        ibex_proto::response_head::count_head_scan();
        buf.readable()[..eoh_pos + eoh_len].windows(2).any(|w| w == b"\r\n")
    };
    // `token` is `close` or `keep-alive`: the line is 24 bytes at most.
    let mut line = [0u8; 40];
    let mut n = 0;
    let name: &[u8] = if canonical { b"connection: " } else { b"Connection: " };
    for part in [name, token.as_bytes(), if crlf { b"\r\n" } else { b"\n" }] {
        line[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    let inject = &line[..n];
    // The usual head ends in CRLF CRLF: the line goes in where it is (no scratch copy).
    if crlf && eoh_len == 4 && buf.insert_last_header(inject) {
        return Some(inject.len());
    }
    let total_old = eoh_pos + eoh_len;
    let total_new = total_old + inject.len();
    // `find_eoh` points at the start of the blank-line pair; the last header's own
    // line terminator is its first half. The new header goes after that, not before.
    let at = eoh_pos + eoh_len / 2;
    if total_new <= 4096 {
        let mut stack_hdr = [0u8; 4096];
        let readable = buf.readable();
        stack_hdr[..at].copy_from_slice(&readable[..at]);
        stack_hdr[at..at + inject.len()].copy_from_slice(inject);
        stack_hdr[at + inject.len()..total_new].copy_from_slice(&readable[at..total_old]);
        buf.replace_prefix(total_old, &stack_hdr[..total_new]);
        Some(inject.len())
    } else {
        buf.inject_http_header(if canonical { "connection" } else { "Connection" }, token);
        None
    }
}

impl EngineDispatcher<'_> {
    /// What the sample fetches of a request rule see: the session, the proxy whose rules
    /// run (for its counters), and the proxies' state.
    fn request_ctx<'a>(sess: &'a TcpSession, proxy: &Proxy, view: &'a ProxiesView<'a>, stick: &'a StickView<'a>) -> SampleContext<'a> {
        SampleContext {
            proxies: Some(view),
            stick: Some(stick),
            client_addr: sess.client_addr,
            server_addr: sess.server_addr,
            fc_src: sess.fc_src(),
            so_name: sess.so_name.as_deref(),
            so_id: sess.so_id,
            fc_dst: sess.fc_dst(),
            is_first_req: sess.is_first_req,
            proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: crate::proxy::ssl_fc(&sess.cli_xprt, sess.h2_role.as_deref()),
            quic_acks: sess.quic_facts(),
            fc_http_major: sess.fc_http_major(),
            bc_http_major: sess.bc_http_major(),
            req_version: sess.client_version(),
            ssl_bc: sess.srv_xprt.ssl_facts(),
            // The body a `wait-for-body` saw; otherwise the bytes in the buffer.
            req_body: match sess.txn.as_ref().and_then(|t| t.req_body.as_deref()) {
                Some(body) => Some(body),
                None if sess.req.readable().is_empty() => None,
                None => Some(sess.req.readable()),
            },
            raw_req: (sess.mode == Mode::Tcp).then(|| sess.req.readable()),
            htx: None,
            htx_slice: sess.htx_slice(),
            req_uri: sess.req_uri.as_deref(),
            req_method: sess.req_method.as_deref(),
            req_headers: sess.req_headers.as_deref(),
            act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
            unique_id: sess.log.unique_id.as_deref(),
            accept_date: Some(sess.log.date()),
            captures_req_hdr: Some(&sess.log.req_captures),
            captures_res_hdr: Some(&sess.log.res_captures),
            ..Default::default()
        }
    }

    /// The backend a request goes to: the first `use_backend` rule that holds and names a
    /// backend that is enabled, else the default backend, else the proxy itself.
    ///
    /// `None` is a request that `force-be-switch` sent to a backend the configuration
    /// disables (`process_switching_rules`, `src/stream.c`): `HAProxy` runs the request
    /// in that backend, which has no server to give.
    fn resolve_backend(entry: &SessionEntry, proxies: &[Proxy]) -> Option<usize> {
        let proxy_idx = entry.proxy_idx;
        let proxy = &proxies[proxy_idx];

        if proxy.use_backends.is_empty() && proxy.default_backend.is_none() {
            return Some(proxy_idx);
        }

        let view = ProxiesView(proxies);
        let stick = StickView::new(proxies, &entry.sess.tracked_sc);
        let ctx = Self::request_ctx(&entry.sess, proxy, &view, &stick);
        let registry = sample_registry();
        // `lookup_fe_persist_rules`: the frontend's `force-be-switch` conditions.
        let forced = || {
            proxy.rules.force_be.iter().any(|c| c.eval(&ctx, &proxy.acls, registry))
        };

        for (rule, rc) in proxy.use_backends.iter().zip(&proxy.rules.use_backend) {
            let matches = rc.cond.as_ref().is_none_or(|cond| cond.eval(&ctx, &proxy.acls, registry));
            if matches {
                if let Some(idx) = proxies.iter().position(|p| p.name == rule.backend) {
                    return Some(idx);
                }
                if proxy.disabled_backends.contains(&rule.backend) && forced() {
                    return None;
                }
            }
        }

        if let Some(ref def_name) = proxy.default_backend {
            if let Some(idx) = proxies.iter().position(|p| p.name == *def_name) {
                return Some(idx);
            }
            if proxy.disabled_backends.contains(def_name) && forced() {
                return None;
            }
        }

        Some(proxy_idx)
    }

    /// `process_server_rules` (`src/stream.c`): the server a `use-server` rule of backend
    /// `be_idx` picks for this request, bypassing the balance algorithm. The first rule
    /// whose condition holds and whose server is not stopped (down or in maintenance; a
    /// draining one is still picked) wins; a stopped server's rule is skipped for the next.
    fn use_server(sess: &TcpSession, be_idx: usize, proxies: &[Proxy]) -> Option<usize> {
        let be = &proxies[be_idx];
        if be.use_servers.is_empty() {
            return None;
        }
        let view = ProxiesView(proxies);
        let stick = StickView::new(proxies, &sess.tracked_sc);
        let ctx = Self::request_ctx(sess, be, &view, &stick);
        let registry = sample_registry();
        for (rule, rc) in be.use_servers.iter().zip(&be.rules.use_server) {
            if !rc.cond.as_ref().is_some_and(|cond| cond.eval(&ctx, &be.acls, registry)) {
                continue;
            }
            let Some(i) = be.server_ids.iter().position(|s| *s == rule.server) else { continue };
            let st = be.server_statuses.get(i).map_or(ServerStatus::Down, |s| ServerStatus::from(s.load(Ordering::Relaxed)));
            if !matches!(st, ServerStatus::Down | ServerStatus::Maint) {
                return Some(i);
            }
        }
        None
    }

    /// `process_sticking_rules` (`src/stream.c`): the backend's `stick` rules on a request.
    /// The server a `stick match` finds for the request is returned, unless `assigned`
    /// (`use-server` or a persistence cookie chose already). The keys of `stick on` and
    /// `stick store-request` are queued to be stored with the server that answers
    /// ([`commit_stick_stores`]); the first of them for a table wins, and a rule that stores
    /// for a table that has one is skipped whole, its match included.
    fn sticking_rules(sess: &mut TcpSession, be_idx: usize, proxies: &[Proxy], mut assigned: bool) -> Option<usize> {
        use ibex_config::StickRuleType::{StickMatch, StickOn, StickStoreRequest};
        let be = &proxies[be_idx];
        if be.stick_rules.is_empty() {
            return None;
        }
        let view = ProxiesView(proxies);
        let stick = StickView::new(proxies, &sess.tracked_sc);
        let ctx = Self::request_ctx(sess, be, &view, &stick);
        let registry = sample_registry();
        let mut found = None;
        let mut stores: Vec<(usize, StickKey)> = Vec::new();
        for (rule, rc) in be.stick_rules.iter().zip(&be.rules.stick) {
            let is_store = matches!(rule.rule_type, StickOn | StickStoreRequest);
            let is_match = matches!(rule.rule_type, StickOn | StickMatch);
            if !is_store && !is_match {
                continue;
            }
            let t_idx = match &rule.table {
                Some(name) => proxies.iter().position(|p| p.name == *name),
                None => Some(be_idx),
            };
            let Some((t_idx, tbl)) = t_idx.and_then(|i| Some((i, proxies[i].stick_table.as_ref()?))) else {
                continue;
            };
            if is_store && sess.stick_stores.iter().chain(stores.iter()).any(|(t, _)| *t == t_idx) {
                continue;
            }
            if rc.cond.as_ref().is_some_and(|c| !c.eval(&ctx, &be.acls, registry)) {
                continue;
            }
            let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, Some(tbl)) else {
                continue;
            };
            if is_match {
                if let Ok(Some(entry)) = tbl.get_entry(&key) {
                    if !assigned {
                        // The server stored by its id, if it is still there and not stopped.
                        let i = entry.server_id.and_then(|id| (0..be.servers.len()).find(|&i| be.server_puid(i) == id));
                        let up = |i: usize| be.server_statuses.get(i).is_none_or(|s| !matches!(ServerStatus::from(s.load(Ordering::Relaxed)), ServerStatus::Down | ServerStatus::Maint));
                        if let Some(i) = i.filter(|&i| be.ids.persist || up(i)) {
                            found = Some(i);
                            assigned = true;
                        }
                    }
                    // `stktable_touch_local`: the entry lives on.
                    let _ = tbl.update_entry(&key, |_| {});
                }
            }
            if is_store && stores.len() + sess.stick_stores.len() < 8 {
                stores.push((t_idx, key));
            }
        }
        sess.stick_stores.extend(stores);
        found
    }

    /// One pass over the HTTP transaction, after the byte layer has run: the reply owed
    /// for an unparsable request, request rules and routing (once per transaction), the
    /// response head, how each side ended, and the end of the transaction.
    #[allow(clippy::too_many_arguments)]
    fn http_step(
        entry: &mut SessionEntry,
        proxies: &mut Proxies,
        checks: &mut [ServerCheckState],
        pid: u32,
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
        wake_queue: &mut Vec<TaskRef>,
        now: Tick,
    ) -> Option<crate::stats_html::AdminAction> {
        // An HTTP/2 connection serving a stream is not between requests: the stream is its
        // child's, which ends it (T280).
        if entry.sess.h2_owner().is_some_and(|o| !o.children.is_empty()) {
            return None;
        }
        let Some(txn) = entry.sess.txn.as_mut() else {
            // Between requests. A client that goes away here ends the session; a server
            // connection kept from the last transaction goes back to the pool.
            if !matches!(entry.sess.cli_state, ScState::Ready | ScState::Established) {
                // A TLS handshake that failed is no request, bad or not: it logs its own
                // line when the session ends, and counts no 400 (T262).
                if entry.sess.hs_fail().is_some() {
                    close_http_session(entry, proxies, fdtab, poller, idle_pool, true);
                    return None;
                }
                // An HTTP/2 connection that never opened a stream has no stream to log or
                // count: only the protocol errors `HAProxy` logs give a line (T272).
                if let Some(log) = h2_no_stream_end(&entry.sess, &proxies[entry.proxy_idx]) {
                    if log {
                        entry.sess.log.status = Some(0);
                        entry.sess.log.term = Some(*b"PR");
                        // No stream: no request, no status counted (measured).
                        entry.stats_done = true;
                        set_stream_log(entry, proxies, pid);
                    }
                    close_http_session(entry, proxies, fdtab, poller, idle_pool, true);
                    return None;
                }
                // `option http-ignore-probes` (`PR_O_IGNORE_PRB`): a new connection that sent
                // nothing and closes or times out is a probe, sent nothing, not logged and
                // not counted (`h1_process`, `h1_handle_req_tout`, T272).
                if proxies[entry.proxy_idx].ignore_probes && entry.sess.is_first_req && entry.sess.req.is_empty() {
                    close_http_session(entry, proxies, fdtab, poller, idle_pool, true);
                    return None;
                }
                // `option dontlognull`: a connection that sent nothing is not logged, whether
                // the client left or `timeout client` ran out.
                let mut quiet = false;
                // `timeout client` before a request head is complete: HAProxy answers 408
                // (`h1_handle_req_tout`, `src/mux_h1.c`) from the frontend's pages, also on
                // a new connection that sent nothing. Only a keep-alive connection waiting
                // for its next request, with nothing of one on it, closes silently.
                if entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Client))
                    && (!entry.sess.req.is_empty() || entry.sess.is_first_req)
                {
                    let fe = &proxies[entry.proxy_idx];
                    let mut page = proxy_error_response(&entry.sess, fe, fe, proxies, 408);
                    rewrite_header_names(&mut page, client_case_table(fe));
                    entry.sess.send_before_close(&page);
                    entry.sess.log.status = Some(408);
                    entry.sess.log.term = Some(*b"cR");
                    quiet = entry.sess.req.is_empty() && proxies[entry.proxy_idx].dont_log_null;
                } else if !entry.sess.req.is_empty()
                    || (entry.sess.is_first_req && matches!(entry.sess.ending, None | Some(crate::proxy::Ending::ClientAbort)))
                {
                    // Part of a request, or a new connection closed before its first byte,
                    // then the client left: `HAProxy` logs it as a 400 the client aborted
                    // (`CR`).
                    entry.sess.log.status = Some(400);
                    entry.sess.log.term = Some(*b"CR");
                    quiet = entry.sess.req.is_empty() && proxies[entry.proxy_idx].dont_log_null;
                }
                if entry.sess.log.status.is_some() {
                    if quiet {
                        account_stream(entry, proxies);
                    } else {
                        set_stream_log(entry, proxies, pid);
                    }
                }
                close_http_session(entry, proxies, fdtab, poller, idle_pool, true);
            } else if entry.sess.srv.is_some()
                && (!entry.sess.rep.is_empty()
                    || !matches!(entry.sess.srv_state, ScState::Ready | ScState::Established))
            {
                // The kept connection closed, failed, or spoke out of turn: it is done.
                entry.sess.rep.clear();
                release_server(entry, proxies, fdtab, poller, idle_pool, false);
            }
            return None;
        };

        if let Some(status) = txn.error.take() {
            if txn.quiet {
                // Nothing is written back; the empty reply ends the transaction and closes.
                entry.sess.write_reply_with(b"", false);
                entry.sess.log.status = Some(status);
                count_parse_error(entry, proxies, status);
            } else {
                reply_parse_error(entry, proxies, status);
            }
        }

        if Self::request_body_broken(entry, proxies, fdtab, poller, idle_pool) {
            return None;
        }

        // `timeout client` while the request is held for its body: the 408 the wait's own
        // time-out gives.
        if entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Client))
            && entry.sess.txn.as_ref().is_some_and(|t| t.body_wait.is_some_and(|w| !w.tarpit && !w.inspect))
        {
            let fe = &proxies[entry.proxy_idx];
            let mut page = proxy_error_response(&entry.sess, fe, fe, proxies, 408);
            rewrite_header_names(&mut page, client_case_table(fe));
            entry.sess.send_before_close(&page);
            entry.sess.log.status = Some(408);
            entry.sess.log.term = Some(*b"cR");
            entry.sess.log.request = None;
            set_stream_log(entry, proxies, pid);
            close_http_session(entry, proxies, fdtab, poller, idle_pool, true);
            return None;
        }

        if Self::h2_stream_reset(entry, proxies, fdtab, poller, idle_pool, wake_queue, now, pid) {
            return None;
        }

        let mut admin = None;
        // A request in the queue goes on when a slot is free, or ends when its time is up.
        if entry.sess.queue.is_some() {
            let be_idx = entry.backend_idx;
            admin = Self::route_to_server(entry, proxies, fdtab, poller, idle_pool, now, be_idx, None);
        }
        if entry.sess.txn.as_ref().is_some_and(|t| !t.req_rules_done) && entry.sess.tcp_inspect_done {
            if let Some(t) = entry.sess.txn.as_mut() {
                t.req_rules_done = true;
            }
            admin = Self::connect_http_backend(entry, proxies, checks, pid, fdtab, poller, idle_pool, now);
            let sess = &mut entry.sess;
            if let Some(t) = sess.txn.as_mut() {
                if t.body_wait.is_some() {
                    // Held for the body: the rules go on from the wait when it is here.
                    t.req_rules_done = false;
                } else {
                    // The rules have had their way with the head; it is final now.
                    t.req.measure_head_by(|| sess.req.eoh());
                }
            }
        }

        // The response head, then whatever this pass made ready to move: a request the
        // rules just released, a response head they just processed, a reply, or the final
        // head queued behind an interim one. It moves now rather than on the next poller
        // round. Bounded, and it stops as soon as a byte pass makes no progress (a full
        // socket), so it cannot spin. If it is still moving when the bound runs out (a run
        // of interim heads in one read: each takes a turn), the session is run again at once
        // (`wants_rerun`): nothing else wakes it, as everything is already read, and the
        // heads behind waited for `timeout server`, or for ever (T248).
        let mut ran_out = true;
        let snapshot = |entry: &SessionEntry| {
            (entry.sess.req.len(), entry.sess.rep.len(), entry.sess.txn.as_ref().map(|t| (t.req, t.rsp)))
        };
        for _ in 0..4 {
            let top = snapshot(entry);
            if entry.sess.txn.as_ref().is_some_and(|t| t.rsp == MsgState::Waiting && t.reads_server())
                && !entry.sess.rep.is_empty()
            {
                if Self::l7_retry(entry, proxies, fdtab, poller, now) {
                    continue;
                }
                if !Self::apply_http_response_rules(entry, proxies, now) {
                    Self::write_response_head_names(entry, proxies);
                }
            }
            if Self::l7_retry_failure(entry, proxies, fdtab, poller, now) {
                continue;
            }
            // An HTTP/2 stream's response goes to the client through its connection's owner
            // (`h2_bridge::forward_response` in `h2_owner_pass`, T280), which drops an
            // interim response and runs the stream again for the head behind it.
            Self::http_server_side(entry, proxies);
            let next_head = entry.sess.txn.as_ref().is_some_and(|t| t.rsp == MsgState::Waiting)
                && !entry.sess.rep.is_empty()
                && snapshot(entry) != top;
            let movable = entry.sess.has_pending_output() || entry.sess.req_window() > 0;
            if entry.sess.is_done() || (!movable && !next_head) {
                ran_out = false;
                break;
            }
            if !movable {
                continue;
            }
            let before = snapshot(entry);
            entry.sess.advance(now);
            if before == snapshot(entry) {
                ran_out = false;
                break;
            }
        }
        if ran_out {
            entry.sess.passes_ran_out = true;
        }

        if Self::client_left(entry, proxies, fdtab, poller, idle_pool) {
            return admin;
        }
        let abortonclose = proxies.get(entry.backend_idx).is_none_or(|p| p.abortonclose);
        let Some(txn) = entry.sess.txn.as_mut() else {
            return admin;
        };
        match entry.sess.cli_state {
            ScState::Ready | ScState::Established => {}
            // The client finished sending. A complete request is still answered; one cut
            // short cannot be.
            // A tunnel has no end of its own: either side closing ends it, once what is
            // in flight has been delivered.
            ScState::ShutR if txn.req == MsgState::Tunnel => {
                txn.close_after = true;
                txn.aborted = true;
            }
            ScState::ShutR if txn.req.is_done() || txn.local => {
                txn.close_after = true;
            }
            // `no option abortonclose`: a whole request still queued or connecting goes on
            // to the server.
            ScState::ShutR if !abortonclose && matches!(txn.req, MsgState::Head { body: crate::txn::Framing::None, .. }) => {
                txn.close_after = true;
            }
            _ => {
                close_http_session(entry, proxies, fdtab, poller, idle_pool, false);
                return admin;
            }
        }

        let drained = !entry.sess.has_pending_output();
        let Some(txn) = entry.sess.txn.as_ref() else {
            return admin;
        };
        if drained && txn.aborted {
            close_http_session(entry, proxies, fdtab, poller, idle_pool, false);
        } else if drained && (txn.finished() || h2_local_reply_over_open_request(&entry.sess, txn)) && !h2_request_open(&entry.sess, txn) {
            Self::end_txn(entry, proxies, fdtab, poller, idle_pool, wake_queue, now, pid);
        }
        admin
    }

    /// The client left before its response was complete: what `abortonclose` does with the
    /// request (`proxy_abrt_close`, T227). `true` when the session is closed.
    ///
    /// Measured on `HAProxy` 3.5-dev8 (`tests/abortonclose.rs`): with the option, on by
    /// default in HTTP, a client's FIN resets the server connection; waiting for the
    /// response head, the client is sent a 400 (`CH`); during the body, the response stops
    /// (`CD`); queued or connecting, the request is dropped (`CQ`, `CC`, status -1). A
    /// client's reset does all that whatever the option (`CD` 400 waiting for the head).
    /// Without the option, a FIN changes nothing until the response is complete.
    fn client_left(
        entry: &mut SessionEntry,
        proxies: &[Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
    ) -> bool {
        if entry.sess.is_h2() {
            return Self::h2_client_left(entry, proxies, fdtab, poller, idle_pool);
        }
        if matches!(entry.sess.cli_state, ScState::Ready | ScState::Established) {
            return false;
        }
        // Not a transaction a client's leaving can abort: none, a reply of the proxy's own,
        // one already ending, a tunnel, or a response that is all in.
        let Some(txn) = entry.sess.txn.as_ref().filter(|t| !(t.local || t.aborted || t.req == MsgState::Tunnel || t.rsp.is_done())) else {
            return false;
        };
        // A FIN leaves no ending, a reset `ClientAbort`; any other ending (a timeout, an
        // error) already decided how the stream ends.
        let reset = match entry.sess.ending {
            None => false,
            Some(crate::proxy::Ending::ClientAbort) => true,
            Some(_) => return false,
        };
        if !reset && !proxies.get(entry.backend_idx).is_none_or(|p| p.abortonclose) {
            return false;
        }
        if !txn.req.is_done() {
            // Not at the server yet: queued, or connecting. Only a whole request; one whose
            // body was still coming is cut short, as before.
            if !matches!(txn.req, MsgState::Head { body: crate::txn::Framing::None, .. }) {
                return false;
            }
            let queued = entry.sess.queue.leave();
            if queued {
                entry.sess.log.queue.get_or_insert_with(crate::txnlog::loop_now);
            }
            entry.sess.log.term = Some([b'C', if queued { b'Q' } else { b'C' }]);
            if let Some(srv) = entry.sess.srv.as_ref() {
                raw::abort_with_rst(srv.as_fd());
            }
            close_http_session(entry, proxies, fdtab, poller, idle_pool, false);
            return true;
        }
        let waiting = txn.rsp == MsgState::Waiting;
        // `SC_FL_NOLINGER`: the server connection is reset when it is closed, with the
        // session, which keeps it until then for the log and the server's counters.
        if let Some(srv) = entry.sess.srv.as_ref() {
            raw::abort_with_rst(srv.as_fd());
        }
        if waiting {
            // A reset that came with the request (the client left while its connection
            // waited to be accepted, at `maxconn`) is the last phase for `HAProxy`: the 400
            // it answers is a whole response (`CL`, T231).
            let phase = if entry.sess.reset_with_request { b'L' } else { b'D' };
            entry.sess.log.term = Some(if reset { [b'C', phase] } else { *b"CH" });
            // Nothing more is read from the server, nor sent to it.
            entry.sess.srv_state = ScState::Closed;
            entry.sess.rep.clear();
            reply_error(entry, proxies, 400);
            // A half-closed client is sent it, as a local reply; a reset one is closed below.
            return false;
        }
        entry.sess.log.term = Some(*b"CD");
        close_http_session(entry, proxies, fdtab, poller, idle_pool, false);
        true
    }

    /// An HTTP/2 client's FIN ends every stream on its connection, whatever
    /// `abortonclose` says: `HAProxy`'s H2 mux reports the read0 to each stream as an
    /// error (`h2_wake_some_streams`). Measured on 3.5-dev8 with the stream's window at 0
    /// and a 10 MB body behind it: `CD--`, `Tt` the FIN's time, the server connection let
    /// go; waiting for the response head, `400 ... CH--` with nothing sent. The
    /// connection, with nothing left it could carry, is closed at once (`HAProxy` closes an
    /// idle one at once too; after an aborted stream it waits for `timeout client`).
    /// Kept instead, the stream held its server connection for `timeout client`, then
    /// the connection a second one after its GOAWAY (T269).
    fn h2_client_left(
        entry: &mut SessionEntry,
        proxies: &[Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
    ) -> bool {
        if entry.sess.cli_state != ScState::ShutR || !crate::h2_bridge::abort_on_client_left(&mut entry.sess) {
            return false;
        }
        close_http_session(entry, proxies, fdtab, poller, idle_pool, false);
        true
    }

    /// An HTTP/1 request whose chunked body breaks its framing after its head was taken: a
    /// malformed chunk, a trailer section refused or past its cap, or a trailer section held
    /// back that fills the buffer. `HAProxy` 3.5-dev8 sends the server nothing more of it (not the
    /// last-chunk line before a refused trailer section), answers the client nothing, closes
    /// both, and logs `400 ... PH--` (T281). Ibex stopped forwarding at the error and waited:
    /// the server, holding a request with no end, answered or timed out, and that answer
    /// reached the client. `true` when the transaction ended here.
    fn request_body_broken(
        entry: &mut SessionEntry,
        proxies: &[Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
    ) -> bool {
        if entry.sess.is_h2() || entry.sess.h3 {
            return false;
        }
        let Some(txn) = entry.sess.txn.as_ref().filter(|t| {
            !t.local
                && !t.aborted
                && t.error.is_none()
                && t.req_rules_done
                && t.rsp == MsgState::Waiting
                && matches!(
                    t.req,
                    MsgState::Body(crate::txn::Body::Chunked(_)) | MsgState::Head { body: crate::txn::Framing::Chunked, .. }
                )
        }) else {
            return false;
        };
        if !txn.req.check_body(entry.sess.req.readable()).stuck(entry.sess.req.len(), entry.sess.bufsize) {
            return false;
        }
        if let Some(srv) = entry.sess.srv.as_ref() {
            raw::abort_with_rst(srv.as_fd());
        }
        // Nothing of it forwarded yet (held whole, `MsgState::holds_trailer`): `HAProxy` never
        // made it a request (`PR`, as `<BADREQ>`).
        let term = if matches!(txn.req, MsgState::Head { .. }) { *b"PR" } else { *b"PH" };
        entry.sess.log.status = Some(400);
        entry.sess.log.term = Some(term);
        entry.sess.req.clear();
        entry.sess.rep.clear();
        close_http_session(entry, proxies, fdtab, poller, idle_pool, false);
        true
    }

    /// The HTTP/2 stream being served was reset, by the client's `RST_STREAM` or by the mux
    /// for a stream error in the rest of its request (trailers without `END_STREAM`, say):
    /// the transaction ends here and the connection's next stream goes on. `true` when it
    /// ended.
    ///
    /// Measured on `HAProxy` 3.5-dev8 (`tests/h2_no_frames_after_rst.rs`): nothing more is
    /// sent on the stream, the server connection is reset at once, and the log reads
    /// `400 ... CH--` waiting for the response head, `CD--` during the body. Left to run,
    /// the transaction sent the server's HEADERS on the reset stream (a frame on a closed
    /// stream, RFC 9113 5.1), held the server connection until `timeout server`, and the
    /// connection's next stream waited behind it (T273 B).
    #[allow(clippy::too_many_arguments)]
    fn h2_stream_reset(
        entry: &mut SessionEntry,
        proxies: &[Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
        wake_queue: &mut Vec<TaskRef>,
        now: Tick,
        pid: u32,
    ) -> bool {
        let sess = &mut entry.sess;
        // The owner saw the reset (`h2_owner_pass`) and told the stream's entry.
        let reset = sess.h2_child().is_some_and(|c| c.reset);
        if !reset || !crate::h2_bridge::abort_reset_stream(sess) {
            return false;
        }
        Self::end_txn(entry, proxies, fdtab, poller, idle_pool, wake_queue, now, pid);
        true
    }

    /// `timeout client` ran out under a transaction (T300). An upload cut short whose
    /// response has not started is answered 400 from the error pages and logged `cH--`
    /// (`HAProxy`'s `return_cli_abort` in `http_request_forward_body`): on HTTP/1 the page
    /// is written and the connection closed; on a stream of an HTTP/2 connection the page
    /// is the stream's response, and the stream is reset `NO_ERROR` once it is out
    /// (`h2_child_released`), the connection and its other streams going on. Any other
    /// stream of an HTTP/2 connection is aborted alone: its server connection reset, its
    /// log `cD--` (or as the phase reads), `RST_STREAM CANCEL`; one whose response went out
    /// whole before its upload stalled (the server answered early) logs `cL--`, its server
    /// connection closed, and is reset `NO_ERROR` (T305 item 2). Measured on `HAProxy`
    /// 3.5-dev8 (`tests/it/h2_stream_timers.rs`). `cli_before`: the client side's state
    /// before the timeout, which a stream keeps (the connection is its owner's).
    #[allow(clippy::too_many_arguments)]
    fn client_timed_out(
        entry: &mut SessionEntry,
        proxies: &[Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
        wake_queue: &mut Vec<TaskRef>,
        now: Tick,
        pid: u32,
        cli_before: ScState,
    ) {
        let child = entry.sess.is_h2_child();
        let Some(txn) = entry.sess.txn.as_mut() else { return };
        if !txn.req.is_done() && !txn.local && txn.rsp == MsgState::Waiting && txn.body_wait.is_none() && entry.sess.rep.is_empty() {
            txn.srv_reusable = false;
            // The server connection still being made: the client gave up during the connect
            // (`cC--`), not while the server waited for the rest of the body (`cH--`).
            entry.sess.log.term = Some(if entry.sess.srv_state == ScState::Connecting { *b"cC" } else { *b"cH" });
            entry.sess.log.status = Some(400);
            if child {
                entry.sess.cli_state = cli_before;
                entry.sess.ending = None;
                reply_error(entry, proxies, 400);
                // The rest of the upload is not waited for: the stream is reset behind the page.
                if let Some(t) = entry.sess.txn.as_mut() {
                    t.req = MsgState::Done;
                }
                entry.sess.req.clear();
                return;
            }
            let fe = &proxies[entry.proxy_idx];
            let be = proxies.get(entry.backend_idx).unwrap_or(fe);
            let mut page = proxy_error_response(&entry.sess, be, fe, proxies, 400);
            rewrite_header_names(&mut page, client_case_table(fe));
            entry.sess.send_before_close(&page);
            // The connection is not closed with the page: the client side waits one more
            // `timeout client`, whatever arrives restarting it, and a FIN ends it (T501,
            // VV-9; measured on HAProxy 3.5-dev8: 400 at T, close at 2T). The stream is over
            // and logged now; the server side is let go.
            if entry.sess.timeouts.client != 0 && entry.sess.cli_state == ScState::Error {
                set_stream_log(entry, proxies, std::process::id());
                release_server(entry, proxies, fdtab, poller, idle_pool, false);
                entry.sess.txn = None;
                entry.sess.srv_state = ScState::Closed;
                entry.sess.cli_state = ScState::Ready;
                entry.sess.ending = None;
                entry.sess.cli_linger = true;
                entry.sess.req.clear();
                entry.sess.arm_client(now);
                return;
            }
            close_http_session(entry, proxies, fdtab, poller, idle_pool, false);
            return;
        }
        if !child {
            return;
        }
        // A response delivered whole before its upload ended (the server answered early):
        // `cL--`, the server connection closed, not reset, and the stream reset `NO_ERROR`.
        let answered = txn.rsp == MsgState::Done && entry.sess.rep.is_empty();
        let term = if txn.rsp == MsgState::Waiting { *b"cH" } else if answered { *b"cL" } else { *b"cD" };
        txn.srv_reusable = false;
        txn.rsp = MsgState::Done;
        entry.sess.log.term.get_or_insert(term);
        if let (false, Some(srv)) = (answered, entry.sess.srv.as_ref()) {
            raw::abort_with_rst(srv.as_fd());
        }
        entry.sess.rep.clear();
        entry.sess.req.clear();
        entry.sess.srv_state = ScState::Closed;
        entry.sess.cli_state = cli_before;
        if let Some(c) = entry.sess.h2_child_mut() {
            c.rst = Some(if answered { ibex_proto::h2::H2Error::NoError } else { ibex_proto::h2::H2Error::Cancel });
        }
        Self::end_txn(entry, proxies, fdtab, poller, idle_pool, wake_queue, now, pid);
    }

    /// How the server side ended, if it has, for a response the server is sending.
    fn http_server_side(entry: &mut SessionEntry, proxies: &[Proxy]) {
        let srv_eof = matches!(entry.sess.srv_state, ScState::ShutR | ScState::Closed);
        let srv_err = entry.sess.srv_state == ScState::Error;
        let h2_child = entry.sess.is_h2_child();
        let Some(txn) = entry.sess.txn.as_mut() else {
            return;
        };
        // A response body that breaks its framing, or a chunk extension or trailer section
        // past its cap: what came before the violation is delivered and nothing after it.
        // The rest is never going to be relayed, so waiting for more of it (`timeout server`,
        // or for ever against a server that keeps talking) is pointless; the server is let
        // go now and the client connection closed behind the valid bytes. `HAProxy` 3.5-dev8
        // closes at once on a trailer flood and logs `PH` (T248).
        // So is a trailer section held back that fills the buffer (`tune.bufsize` below its
        // cap): the end it waits for has no room to arrive.
        // A response held whole behind its trailer section (`MsgState::holds_trailer`) that
        // is refused is a 502, as when it arrives all at once: nothing of it has gone.
        // Held means none of it has gone: the head is all still here.
        let unsent = match txn.rsp {
            MsgState::Head { left, body: crate::txn::Framing::Chunked } => {
                entry.sess.rep.eoh().is_some_and(|(h, e)| h + e == left)
            }
            _ => false,
        };
        if unsent && !txn.local && !txn.aborted && entry.sess.rep.len() >= entry.sess.bufsize {
            let check = txn.rsp.check_body(entry.sess.rep.readable());
            let refused = match check {
                crate::txn::BodyCheck::Broken | crate::txn::BodyCheck::TooLarge { .. } => true,
                crate::txn::BodyCheck::Held { trailer, .. } => trailer && (srv_eof || srv_err),
                crate::txn::BodyCheck::Fine => false,
            };
            if refused {
                txn.srv_reusable = false;
                entry.sess.rep.clear();
                entry.sess.log.term = Some(*b"PH");
                entry.sess.log.bytes_from_server = 0;
                reply_error(entry, proxies, 502);
                return;
            }
        }
        // (Not on a stream of an HTTP/2 connection: its owner resets the stream when the body
        // breaks, T280, as the session did when it moved the response before looking here.)
        if !(srv_eof || srv_err) && !txn.local && !txn.aborted && matches!(txn.rsp, MsgState::Body(_)) && !h2_child {
            let check = txn.rsp.check_body(entry.sess.rep.readable());
            if check.stuck(entry.sess.rep.len(), entry.sess.bufsize) {
                txn.srv_reusable = false;
                txn.close_after = true;
                txn.aborted = true;
                entry.sess.srv_state = ScState::Error;
                entry.sess.ending.get_or_insert(crate::proxy::Ending::ServerAbort);
                entry.sess.log.term = Some(*b"PH");
                for_tracked(proxies, &entry.sess, |data| data.count_fail());
                return;
            }
        }
        // A response held by its rules (`WAIT_END`, `wait-for-body`) is here, and one they
        // rejected is not owed; the server closing behind either changes nothing.
        if !(srv_eof || srv_err) || !txn.req_rules_done || txn.local || txn.rsp.is_done() || txn.rsp_wait.is_some() || txn.aborted {
            return;
        }
        // A stream of an HTTP/2 connection whose server ended during the body: what came is
        // delivered by its owner, which then ends the stream (`h2_bridge::forward_response`:
        // the body's end for one that lasts until the close, else `RST_STREAM`, `SD`), as the
        // session did when it moved the response itself before looking here (T280).
        if h2_child && !matches!(txn.rsp, MsgState::Waiting) {
            return;
        }
        match txn.rsp {
            MsgState::Waiting => {
                // No response, or a partial head: HAProxy answers 502, or 504 when it gave
                // up waiting, or 503 when the connection never completed.
                let status = match entry.sess.ending {
                    Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Server)) => 504,
                    Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Connect)) => 503,
                    _ => 502,
                };
                // An h2 server's malformed response is the server's fault, not a lost
                // connection: `PH--` whether or not it was reused (T540).
                let bad = entry.sess.srv_xprt.bad_response();
                if status == 502 && txn.srv_reused && entry.sess.rep.is_empty() && !bad {
                    // `abort_keep_alive`: a keep-alive request lost to a network error,
                    // nothing of a response received. The client retries only if it
                    // sees the connection close unanswered.
                    txn.close_after = true;
                    txn.aborted = true;
                    txn.keepalive_lost = true;
                    // On HTTP/2 that is the stream alone, reset `REFUSED_STREAM` (the
                    // client may retry it), and the connection and its other streams go
                    // on: measured on `HAProxy` 3.5-dev8 (T324). Its client side is done,
                    // so the close that follows sends no FIN for the whole connection.
                    if let Some(c) = entry.sess.h2_child_mut() {
                        c.rst = Some(ibex_proto::h2::H2Error::RefusedStream);
                        c.finished = true;
                        entry.sess.cli_state = ScState::Closed;
                    }
                    return;
                }
                if status == 502 {
                    // The server ended the connection before its response head: `SH`; an h2
                    // server's malformed head: `PH`, as `HAProxy` logs it.
                    entry.sess.log.term = Some(if bad { *b"PH" } else { *b"SH" });
                }
                entry.sess.rep.clear();
                reply_error(entry, proxies, status);
            }
            MsgState::Body(crate::txn::Body::UntilClose) | MsgState::Head { body: crate::txn::Framing::UntilClose, .. }
                if srv_eof =>
            {
                // The close is the end of this body; the client learns it the same way.
                txn.close_after = true;
                if entry.sess.rep.is_empty() {
                    txn.rsp = MsgState::Done;
                }
            }
            _ => {
                // A server closing after its response is all here has finished that
                // response, not cut it short; it is delivered and the connection kept.
                let mut probe = txn.rsp;
                probe.advance(entry.sess.rep.readable());
                if probe.is_done() {
                    txn.srv_reusable = false;
                } else {
                    // Cut short: what arrived is delivered, then the client connection
                    // closes, the only way left to tell it the response is incomplete.
                    txn.close_after = true;
                    txn.aborted = true;
                    // `sD` when the server stopped sending and `timeout server` ran out,
                    // `SD` when it closed.
                    let timed_out = entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Server));
                    entry.sess.log.term = Some(if timed_out { *b"sD" } else { *b"SD" });
                    // A response cut short is one failed request (`http_fail_cnt`).
                    for_tracked(proxies, &entry.sess, |data| data.count_fail());
                }
            }
        }
    }

    /// HTTP/2: the response of the active stream, as HEADERS then DATA frames, as much as
    /// the client's flow-control windows take. One stream at a time until each stream has
    /// its own transaction (design 010 step 5).
    /// The transaction is over: both messages complete and the response delivered.
    /// `HAProxy`'s `http_end_request`/`http_end_response` meeting at `DONE`. The server
    /// connection goes back to the pool if it can carry another request; the client
    /// connection either closes or waits for its next request.
    #[allow(clippy::too_many_arguments)]
    fn end_txn(
        entry: &mut SessionEntry,
        proxies: &[Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
        wake_queue: &mut Vec<TaskRef>,
        now: Tick,
        pid: u32,
    ) {
        // The transaction's line, while its request and response are still here.
        if entry.sess.txn.is_some() {
            set_stream_log(entry, proxies, pid);
        }
        let Some(txn) = entry.sess.txn.take() else {
            return;
        };
        // Bytes after the end of the response are not the next response: the server broke
        // framing (a body after a HEAD answer, say), and its connection is not reused.
        let leftover = !entry.sess.rep.is_empty() && !txn.local;
        if leftover {
            entry.sess.rep.clear();
        }
        // An h2 connection only with no stream open and no GOAWAY (T540).
        let reusable = (txn.srv_reusable || txn.keeps_srv)
            && (!txn.local || txn.keeps_srv)
            && !leftover
            && txn.req.is_done()
            && txn.rsp.is_done()
            && entry.sess.srv_xprt.reusable()
            // `max-reuse`, on h2 only (`HAProxy`: 2 gives connections of 3 streams; ignored on h1).
            && entry.sess.srv_xprt.h2_streams().is_none_or(|n| {
                let max = entry.target_server_idx.and_then(|i| proxies.get(entry.srv_backend_idx).map(|p| p.ids.server_pool(i).max_reuse));
                max.is_none_or(|m| m < 0 || i64::from(n) <= i64::from(m))
            });
        if reusable {
            entry.srv_served = (entry.srv_served + 1).min(2);
        }
        let close = if entry.sess.is_h2() {
            !matches!(entry.sess.cli_state, ScState::Ready | ScState::Established)
        } else {
            txn.close_after || !matches!(entry.sess.cli_state, ScState::Ready | ScState::Established)
        };
        if close {
            close_http_session(entry, proxies, fdtab, poller, idle_pool, reusable);
            return;
        }
        // The server connection leaves the session with the response (`h1_detach`): into
        // the server's lists, which may close it (`srv_add_to_idle_list`), so a client that
        // idles holds no server connection (T187: 10 idle clients, one backend connection
        // in HAProxy). A next request already in the buffer keeps it: it is not a first
        // request, and the pool would hand it straight back (`connect_http_backend`).
        // While the lists hold nothing, and the server keeps idle connections at all, it
        // would be kept there and be the one the client's next request takes: it stays
        // parked on the session for `SRV_PARK_MS` instead, so a keep-alive client that asks
        // again at once takes it back without the pool round trip (two `epoll_ctl` and a
        // peek per request before T434: -25% requests/s at 50 clients), and one that idles has given
        // it back before another request could tell.
        // Under `http-reuse never` the connection is the session's own (`session_add_conn`)
        // and stays on it; so does one opened with a PROXY header, whose reuse key is the
        // header (it names this client's addresses), which the pool does not key by.
        // So is an h2 server connection under `safe` (`MX_FL_HOL_RISK` -> `session_add_conn`,
        // `backend.c`: measured, 26 server connections for 26 client sessions, T533).
        let private = entry.sess.send_proxy_prepended
            || proxies.get(entry.srv_backend_idx).is_some_and(|p| {
                p.http_reuse == ibex_config::HttpReuse::Never || (p.http_reuse == ibex_config::HttpReuse::Safe && entry.sess.srv_xprt.is_h2())
            });
        // A request the proxy answered itself never took the connection attached to the
        // session (`bc_idle`, set at the previous transaction's end and cleared where a request
        // connects or takes it back): HAProxy leaves it where it is, parked or in the idle
        // lists, for the next request (T491).
        let untouched = txn.local && entry.sess.bc_idle && entry.sess.srv.is_some();
        if !untouched && !reusable {
            release_server(entry, proxies, fdtab, poller, idle_pool, false);
        } else if !untouched && entry.sess.req.is_empty() && !private {
            let keeps = entry.target_server_idx.is_some_and(|i| proxies.get(entry.srv_backend_idx).is_some_and(|p| p.ids.server_pool(i).keeps_any()));
            // An HTTP/3 request relayed over a socket pair is its session's only one: there is
            // no next request to keep the connection for, and parked it is no other stream's
            // (T523: 150 server connections for a burst of 200 where HAProxy opened 115).
            let relayed = entry.sess.h3 && !entry.sess.is_h2_child();
            if keeps && idle_pool.total() == 0 && entry.sess.srv.is_some() && !relayed {
                entry.sess.srv_park_exp = now.add(SRV_PARK_MS);
                // Idle, it is not one of the server's connections in use (`scur`, and
                // what the lists' rule weighs); the peak in use is noted first, as the
                // lists would have (`srv_add_to_idle_list` raising `max_used_conns`).
                // (`keeps` above holds only with a server, so there is one.)
                let i = entry.target_server_idx.unwrap_or_default();
                let used = proxies.get(entry.srv_backend_idx).and_then(|p| p.server_actconn.get(i)).map_or(0, |a| a.load(Ordering::Relaxed));
                idle_pool.ensure_sized(proxies);
                idle_pool.note_used((entry.srv_backend_idx, i), used);
                server_actconn_add(entry, proxies, false);
            } else {
                release_server(entry, proxies, fdtab, poller, idle_pool, true);
            }
        }
        // A stream of an HTTP/2 connection ends with its transaction: its entry is freed, and
        // a server connection it kept here goes to its owner for the next stream, with what
        // the stream changed of the connection's state (`h2_child_released`, T280).
        if let Some(c) = entry.sess.h2_child_mut() {
            c.finished = true;
            return;
        }
        entry.sess.reset_for_next_request();
        entry.stats_done = false;
        // The wait for the next request starts with the response's end
        // (`timeout http-keep-alive`).
        entry.sess.arm_request(now);
        // A next request already in the buffer has no socket event left to announce it:
        // run once more straight away. (Without one, the poller wakes the session.)
        if !entry.sess.req.is_empty() {
            wake_queue.push(entry.task);
        }
        // `tcp-request content` rules run again for every request of a kept-alive connection
        // (a request is a stream in HAProxy): arm them for the next one, and the stream step
        // runs them once its head is in. Their result for a request that has not arrived
        // yet used to be thrown away here, and they never ran again after the first request.
        let proxy = &proxies[entry.proxy_idx];
        if !proxy.tcp_req_content_rules.is_empty() {
            entry.sess.tcp_inspect_done = false;
            entry.sess.inspect_exp = proxy
                .tcp_req_inspect_delay
                .map(|d| now.add(u32::try_from(d.as_millis()).unwrap_or(u32::MAX)));
        }
    }

    /// The owner of an HTTP/2 connection moves its streams' bytes (T280): each stream's
    /// request DATA into its child's `req`, its child's response from `rep` out as HEADERS
    /// and DATA (written in the same pass: one write a response, T186), and what happened
    /// to the connection or the stream (a reset, the client leaving, a timeout) to the
    /// child. A child that got something to work on is run. A stream with its head in and
    /// a free place gets an entry after the pass (`h2_spawn`). The streams take the
    /// connection's window in turns: the pass starts after the one that sent DATA last.
    fn h2_owner_pass(&mut self, owner_idx: u32, now: Tick) {
        let (n, first) = self.sessions.get(owner_idx).and_then(|e| e.sess.h2_owner()).map_or((0, 0), |o| (o.children.len(), o.next_child));
        let mut sent_last = None;
        for k in 0..n {
            let i = (first + k) % n;
            let Some(link) = self.sessions.get(owner_idx).and_then(|e| e.sess.h2_owner()).and_then(|o| o.children.get(i).copied()) else { break };
            let Some((o, c)) = self.sessions.get2_mut(owner_idx, link.idx).filter(|(_, c)| c.task == link.task) else { continue };
            let window = |o: &SessionEntry| o.sess.h2_ctx.as_ref().map_or(0, |h| h.conn_send_window);
            let before = window(o);
            if h2_bridge_moves(o, c, now) {
                self.wake_now.push(link.task);
            }
            if window(o) < before {
                sent_last = Some(i);
            }
        }
        if let Some((i, o)) = sent_last.zip(self.sessions.get_mut(owner_idx).and_then(|e| e.sess.h2_owner_mut())) {
            o.next_child = i + 1;
        }
        // What the moves framed goes out now.
        if let Some(o) = self.sessions.get_mut(owner_idx).filter(|o| !o.sess.is_done() && o.sess.h2_ctx.as_ref().is_some_and(|h| h.tx_consumed < h.tx_buf.len())) {
            o.sess.advance(now);
        }
        for i in 0..n {
            let Some(link) = self.sessions.get(owner_idx).and_then(|e| e.sess.h2_owner()).and_then(|o| o.children.get(i).copied()) else { break };
            let Some((o, c)) = self.sessions.get2_mut(owner_idx, link.idx).filter(|(_, c)| c.task == link.task) else { continue };
            if h2_bridge_state(o, c, self.proxies) {
                self.wake_now.push(link.task);
            }
        }
        if let Some(o) = self.sessions.get(owner_idx).filter(|o| !o.sess.is_done() && matches!(o.sess.cli_state, ScState::Ready | ScState::Established) && o.sess.has_undispatched_h2_streams()) {
            self.h2_spawn.push((owner_idx, o.task));
        }
    }

    /// One run of the owner of an HTTP/3 connection (T509, design 2.2): what the client sent
    /// into the mux, its streams' bytes moved both ways (`h3_bridge_moves`, the h2 owner's
    /// `h2_bridge_moves` over the h3 mux), the mux's frames to quinn, what happened to the
    /// connection to the children, and the streams with their heads in dispatched after the
    /// pass (`h2_spawn`). The connection gone, the owner ends and its children with it.
    fn step_h3_owner(&mut self, owner_idx: u32, now: Tick) -> Outcome {
        let Some(e) = self.sessions.get_mut(owner_idx) else { return Outcome::Done };
        let task = e.task;
        let Some(h3) = e.sess.h3_owner_mut() else { return Outcome::Done };
        let (q_idx, conn) = (h3.listener as usize, h3.conn);
        let Some(ql) = self.quic_listeners.get_mut(q_idx) else { return Outcome::Done };
        if ql.owner_recv(conn, &mut h3.mux, u64::from(now.0)) == crate::quic_listener::OwnerConn::Closed {
            ql.owner_close(conn);
            e.sess.cli_state = ScState::Closed;
            e.sess.ending.get_or_insert(crate::proxy::Ending::ClientAbort);
            return Outcome::Done;
        }
        let children = e.sess.h2_owner().map_or(0, |o| o.children.len());
        let mut moved = false;
        for i in 0..children {
            let Some(link) = self.sessions.get(owner_idx).and_then(|e| e.sess.h2_owner()).and_then(|o| o.children.get(i).copied()) else { break };
            let Some((o, c)) = self.sessions.get2_mut(owner_idx, link.idx).filter(|(_, c)| c.task == link.task) else { continue };
            if h3_bridge_moves(o, c, now) {
                moved = true;
                self.wake_now.push(link.task);
            }
        }
        let Some(e) = self.sessions.get_mut(owner_idx) else { return Outcome::Done };
        let Some(crate::proxy::H2Role::Owner(crate::proxy::H2Owner { children: served_by, h3: Some(h3), .. })) = e.sess.h2_role.as_deref_mut() else { return Outcome::Done };
        let served = |id: u64| served_by.iter().any(|l| u64::from(l.stream_id) == id);
        let ql = &mut self.quic_listeners[q_idx];
        // A connection that has sent no request yet when the soft stop reaches it -- one the
        // client opened to send one, whose request may be on the wire, or one whose handshake
        // ends during the stop -- waits for that first request, at most
        // `H3_STOP_FIRST_REQUEST_MS`; it is then served and drained as any other (T558,
        // VV-30). `HAProxy` sends GOAWAY(0) and closes it at once, and the request is lost.
        let stopping = ql.is_stopping();
        let grace = if stopping { *h3.stop_grace.get_or_insert(now.add(H3_STOP_FIRST_REQUEST_MS)) } else { Tick::ETERNITY };
        // Its grace over, the connection is judged on what its sockets hold, not on what was
        // read when its timer fired: a pass whose poller was interrupted (a signal, a stopped
        // or starved process) runs the expired timers with nothing read, and the request its
        // client sent meanwhile waits in the socket. The listener reads them all in the next
        // pass, and the owner looks again after it (T564: GOAWAY(0) and a close with the
        // request unread, curl `ERR_DRAINING`).
        if stopping && h3.mux.last_client_stream_id.is_none() && grace.is_expired(now) && !h3.stop_read {
            h3.stop_read = true;
            ql.mark_ready();
            self.wake_queue.push(task);
            return Outcome::Keep;
        }
        let fresh = stopping && h3.mux.last_client_stream_id.is_none() && !grace.is_expired(now);
        // The GOAWAY of a soft stop goes out in this pass: framed after the write, it was
        // what kept an idle owner from closing, nothing waking it to write it (T511).
        let goaway_before = h3.mux.goaway_sent.is_some();
        if stopping && !fresh {
            h3.mux.send_goaway();
        }
        ql.owner_send(conn, &mut h3.mux, |id| !served(id));
        let idle = children == 0 && !ibex_proto::htx_mux::HtxMux::tx_pending(&*h3.mux);
        // A request whose head is still arriving is in flight too: the drain waits for it.
        // Read only in a stop: `head_partial` walks the streams, every pass of every request.
        let in_flight = stopping && (ibex_proto::htx_mux::HtxMux::next_dispatch(&*h3.mux).is_some() || h3.mux.head_partial().is_some());
        let failed = h3.mux.error.is_some();
        for i in 0..children {
            let Some(link) = self.sessions.get(owner_idx).and_then(|e| e.sess.h2_owner()).and_then(|o| o.children.get(i).copied()) else { break };
            let Some((o, c)) = self.sessions.get2_mut(owner_idx, link.idx).filter(|(_, c)| c.task == link.task) else { continue };
            if h3_bridge_state(o, c, failed) {
                self.wake_now.push(link.task);
            }
        }
        let Some(e) = self.sessions.get_mut(owner_idx) else { return Outcome::Done };
        // A stream ended the connection (`http-request reject`, a silent drop), the mux
        // failed it, its timer expired (the GOAWAY went out in the last pass), or a soft stop
        // finds it idle with every FIN acknowledged -- quinn retransmits nothing after a
        // close, so closing once the last FIN was written lost the response whose datagrams
        // the client had not received yet (T521): it closes.
        let ended = !matches!(e.sess.cli_state, ScState::Ready | ScState::Established);
        let ql = &self.quic_listeners[q_idx];
        let drained = stopping && idle && !fresh && !in_flight && !ql.owner_unacked(conn);
        // Its GOAWAY was framed in this pass: the close waits for the next one, as a timer's
        // does, or quinn drops the GOAWAY with the close (T558: the client of a connection
        // idle at the stop saw only CONNECTION_CLOSE).
        if drained && !goaway_before && !ended && !failed {
            if let Some(h3) = e.sess.h3_owner_mut() {
                h3.closing = true;
            }
            self.wake_queue.push(task);
            return Outcome::Keep;
        }
        if ended || failed || drained || e.sess.h3_owner().is_some_and(|h| h.closing) {
            if !failed {
                self.quic_listeners[q_idx].owner_close(conn);
            }
            e.sess.cli_state = ScState::Closed;
            return Outcome::Done;
        }
        let max = e.sess.h2_max_children();
        if e.sess.h2_owner().map_or(0, |o| o.children.len()) < max
            && e.sess.h3_owner().is_some_and(|h| ibex_proto::htx_mux::HtxMux::next_dispatch(&*h.mux).is_some())
        {
            self.h2_spawn.push((owner_idx, task));
        }
        // More of a response may be framed now that quinn took the last.
        if moved {
            self.wake_queue.push(task);
        }
        let exp = h3_owner_deadline(&e.sess, now);
        let exp = if fresh { exp.earliest(grace) } else { exp };
        if exp.is_expired(now) {
            // `qcc_timeout_task` -> `qcc_shutdown`: a GOAWAY now, the close in the next
            // pass, once the GOAWAY is out (quinn sends no stream data after a close).
            if let Some(h3) = e.sess.h3_owner_mut() {
                h3.mux.send_goaway();
                h3.closing = true;
                self.quic_listeners[q_idx].owner_send(conn, &mut h3.mux, |_| true);
            }
            self.wake_queue.push(task);
            return Outcome::Keep;
        }
        e.sess.cli_exp = exp;
        self.timer_updates.push((task, exp));
        Outcome::Keep
    }

    /// A stream of an HTTP/2 connection is freed: its owner learns it, takes back what the
    /// stream changed of the connection (and a server connection it kept, as the session
    /// kept it between requests), and goes on to its next stream; or, when the stream ended
    /// the connection as the session's transaction would have, closes it (T280).
    fn h2_child_released(&mut self, child: &mut SessionEntry, now: Tick) {
        // The bytes before the stream that were its to credit at its http rules (the
        // connection's accounting moved past them when it started): a stream that ended
        // before its rules ran (refused, reset) credits them now, or nothing would (T300).
        let due = child.sess.log.bytes_in_at_start.saturating_sub(child.sess.stick_acct_in);
        child.sess.stick_acct_in += due;
        let (finished, conn_end) = child.sess.h2_child().map_or((false, None), |c| (c.finished, c.conn_end));
        let owner = child.sess.h2_child().and_then(|c| c.owner).and_then(|(idx, task)| self.sessions.get_mut(idx).filter(|o| o.task == task));
        // Its server's bytes go to its connection, which credits them with its next request
        // or at its end; a stream that outlives its connection (freed first, its final
        // count done), or ends it, credits them itself (T300: under load, the second of two
        // streams was often freed after its connection and its bytes were lost).
        let kept = finished && conn_end.is_none() && owner.is_some();
        let out = if kept { 0 } else { std::mem::take(&mut child.sess.stick_out_pending) + child.sess.log.bytes_from_server };
        if due > 0 || out > 0 {
            for_tracked(self.proxies, &child.sess, |data| data.add_bytes(due, out));
        }
        let Some(owner) = owner else { return };
        let owner_task = owner.task;
        // An HTTP/3 owner runs in this pass too (L2): its own closes (a GOAWAY framed, then
        // `closing`) still wait for the next pass (`step_h3_owner`, T558), so a second run
        // in this one closes on nothing quinn has not written.
        owner.sess.h2_owner_mut().into_iter().for_each(|o| o.children.retain(|l| l.task != child.task));
        // An HTTP/3 stream whose response is all framed is let go once its FIN is out
        // (`QuicListener::owner_send`); one that ends without it is reset and let go now.
        let none_left = owner.sess.h2_owner().is_some_and(|o| o.children.is_empty());
        if let Some(h3) = owner.sess.h3_owner_mut() {
            // Its idle timers run from here (`qcc->idle_start`, T521).
            if none_left {
                h3.idle_start = now;
            }
            let id = child.sess.h2_child().map_or(0, |c| u64::from(c.stream.id));
            let mux = &mut *h3.mux;
            match mux.streams.get(&id).map(|st| (st.tx_fin, st.fin_sent)) {
                Some((_, true)) => mux.release(id),
                Some((false, _)) => {
                    ibex_proto::htx_mux::HtxMux::reset(mux, id, ibex_proto::htx_mux::MuxReset::Cancel);
                    mux.release(id);
                }
                _ => {}
            }
        }
        if finished && conn_end.is_none() {
            // A stream let go before the client ended its side is reset (T300): `NO_ERROR`
            // after a whole response (`HAProxy`'s 400 to an upload its `timeout client` cut
            // short), or the code the stream asked for (`CANCEL` when it timed out).
            let (id, rst) = child.sess.h2_child().map_or((0, None), |c| (c.stream.id, c.rst));
            let h2 = owner.sess.h2_ctx.as_deref_mut();
            let code = h2.as_ref().and_then(|h2| h2.streams.get(&id)).and_then(|st| match st.state {
                ibex_proto::H2StreamState::HalfClosedLocal => Some(rst.unwrap_or(ibex_proto::h2::H2Error::NoError)),
                ibex_proto::H2StreamState::Open | ibex_proto::H2StreamState::HalfClosedRemote => rst,
                _ => None,
            });
            if let (Some(h2), Some(code)) = (h2, code) {
                h2.send_rst_stream(id, code);
                if let Some(goaway) = child.sess.h2_child().and_then(|c| c.goaway) {
                    h2.send_goaway(h2.last_client_stream_id, goaway, b"");
                }
            }
            if owner.sess.srv.is_some() || owner.sess.h3_owner().is_some() {
                // Another stream already gave one back: this one goes to the pool, as
                // `HAProxy`'s streams each release theirs. The owner of an HTTP/3
                // connection keeps none: it polls no server socket (T509).
                release_server(child, self.proxies, self.fdtab, self.poller, self.idle_backend_pool, true);
            }
            move_server(child, owner, self.fdtab);
            let fe = &self.proxies[owner.proxy_idx];
            let inspect = (!fe.tcp_req_content_rules.is_empty()).then(|| fe.tcp_req_inspect_delay.map(|d| now.add(u32::try_from(d.as_millis()).unwrap_or(u32::MAX))));
            owner.sess.h2_child_done(&mut child.sess, inspect);
            owner.sess.arm_request(now);
            // The connection's own timer runs again once no stream is attached (T300).
            if owner.sess.h2_owner().is_some_and(|o| o.children.is_empty()) && matches!(owner.sess.cli_state, ScState::Ready | ScState::Established | ScState::ShutR | ScState::ShutW) {
                // The connection is idle from the end of its last stream (`idle_start`).
                if owner.sess.h2_ctx.as_ref().is_some_and(|h| h.tx_consumed >= h.tx_buf.len()) {
                    owner.sess.h2_idle_start = now;
                }
                owner.sess.arm_client(now);
            }
        } else {
            // The connection ends with the stream, as the session did with its transaction.
            match conn_end {
                Some(crate::proxy::ConnEnd::Shutw) => {
                    if matches!(owner.sess.cli_state, ScState::Ready | ScState::Established | ScState::ShutR) {
                        owner.sess.shutw_cli();
                    }
                }
                Some(crate::proxy::ConnEnd::ShutBoth) => owner.sess.shutdown_both_client(),
                Some(crate::proxy::ConnEnd::Abort) => owner.sess.abort_client(),
                Some(crate::proxy::ConnEnd::SilentDrop(v6, ttl)) => owner.sess.silent_drop_client(v6, ttl),
                None => {}
            }
            if owner.sess.srv.is_some() {
                release_server(owner, self.proxies, self.fdtab, self.poller, self.idle_backend_pool, false);
            }
            owner.sess.cli_state = ScState::Closed;
            owner.sess.srv_state = ScState::Closed;
            owner.sess.ending.get_or_insert(child.sess.ending.unwrap_or(crate::proxy::Ending::Complete));
        }
        self.wake_now.push(owner_task);
    }

    /// An HTTP/2 connection is freed with streams still served: each forgets it (its index
    /// and task may be reused) and ends as when its client leaves (T280).
    fn h2_owner_released(&mut self, owner: &mut SessionEntry) {
        let links = owner.sess.h2_owner_mut().map(|o| std::mem::take(&mut o.children)).unwrap_or_default();
        for link in links {
            let Some(c) = self.sessions.get_mut(link.idx).filter(|c| c.task == link.task) else { continue };
            if let Some(ch) = c.sess.h2_child_mut() {
                ch.owner = None;
            }
            // (Its owner's pass has usually told it the connection is closed already.)
            if c.sess.cli_state != ScState::Error {
                c.sess.cli_state = ScState::Closed;
            }
            c.sess.ending.get_or_insert(crate::proxy::Ending::ClientAbort);
            self.wake_queue.push(link.task);
        }
    }

    /// One run of a stream, with its variables where its rules read them
    /// ([`with_stream_vars`]): everything a stream evaluates happens inside a run, and a
    /// run never waits -- a stream that waits ends its run and is woken for another.
    /// `timer`: a timer woke it (`WOKEN_TIMER`): the run looks at its timers (L3).
    fn step_stream(&mut self, session_idx: u32, timer: bool) -> Outcome {
        if let Some(entry) = self.sessions.get_mut(session_idx) {
            stream_vars_enter(&mut entry.sess, &self.proxies[entry.proxy_idx]);
            stream_timeouts_enter(self.proxies, entry.proxy_idx, entry.backend_idx, &entry.sess);
        }
        let out = self.step_stream_run(session_idx, timer);
        // Refused a buffer at `tune.buffers.limit` in this run: it waits for one (S6).
        if crate::buf_wait::wanted() {
            match self.sessions.get_mut(session_idx) {
                Some(entry) => {
                    if buf_wait_enter(entry, session_idx) {
                        self.wake_queue.push(entry.task);
                    }
                    update_interests(entry, self.fdtab, self.poller);
                }
                None => drop(crate::buf_wait::take_want()),
            }
        }
        stream_vars_leave(self.sessions.get_mut(session_idx).map(|e| &mut e.sess));
        CURRENT_TIMEOUTS.set(None);
        out
    }

    #[allow(clippy::too_many_lines)] // one dispatch chain; splitting it would obscure the order
    fn step_stream_run(&mut self, session_idx: u32, timer: bool) -> Outcome {
        // The time now, not the time the pass started: `step` takes its tick before it waits
        // in the poller, so a stream woken by a request after an idle second would arm a
        // `wait-for-body` of 300 ms from a second ago.
        let now = self.now;
        let (is_h2_owner, is_h3_owner) = self.sessions.get(session_idx).map_or((false, false), |e| (e.sess.h2_ctx.is_some(), e.sess.h3_owner().is_some()));
        if is_h3_owner {
            let out = self.step_h3_owner(session_idx, now);
            if matches!(out, Outcome::Done) {
                self.end_stream(session_idx, now, false);
            }
            return out;
        }
        let mut connect_line: Option<(usize, String)> = None;
        let mut owner_wake: Option<TaskRef> = None;
        {
            let Some(entry) = self.sessions.get_mut(session_idx) else {
                return Outcome::Done;
            };

            // A frontend that logs and has no `log-format` (no `option httplog`, `tcplog`) says
            // only that it took the connection, once, and nothing when the request or the
            // connection ends (`frontend_accept`, `frontend.c`): after the PROXY header and
            // the TLS handshake, which a connection that fails never gets past.
            if entry.connect_log_due && (!entry.sess.accept_proxy || entry.sess.proxy_handshake_done) && entry.sess.cli_xprt.is_ready() {
                entry.connect_log_due = false;
                let fe = &self.proxies[entry.proxy_idx];
                let unknown = SocketAddr::from(([0, 0, 0, 0], 0));
                let (src, dst) = (entry.sess.client_addr.unwrap_or(unknown), entry.sess.server_addr.unwrap_or(unknown));
                let line = format!(
                    "Connect from {}:{} to {}:{} ({}/{})",
                    src.ip(),
                    src.port(),
                    dst.ip(),
                    dst.port(),
                    fe.name,
                    if fe.mode == Mode::Http { "HTTP" } else { "TCP" }
                );
                connect_line = Some((entry.proxy_idx, line));
            }

            if entry.rate_max_due && entry.sess.cli_xprt.is_ready() {
                entry.rate_max_due = false;
                let rate = self.proxies[entry.proxy_idx].counters().fe_sess_rate.rate();
                self.proxies[entry.proxy_idx].txn_counters().fe.rate_max.fetch_max(u32::try_from(rate).unwrap_or(u32::MAX), Ordering::Relaxed);
            }

            // Step 1: Server connect check if connecting
            check_srv_connect(entry, self.proxies, self.fdtab, self.poller, now);

            // A readiness event on either socket: reading it may make progress again.
            if let Some(sfd) = entry.srv_raw_fd {
                if self.fdtab.ready(sfd).readable {
                    entry.sess.srv_cant_recv = false;
                    self.fdtab.clear_ready(sfd, true, false);
                }
            }
            if let Some(cfd) = entry.sess.cli_fd().map(|fd| fd.as_raw_fd()) {
                if self.fdtab.ready(cfd).readable {
                    entry.sess.cli_cant_recv = false;
                    self.fdtab.clear_ready(cfd, true, false);
                }
            }

            // Step 2: Check timeouts -- in a run a timer woke (L3): every deadline the stream
            // has is its task's timer (`next_expiry`, step 5), so one that passed while the
            // stream ran for I/O wakes it in the next pass, `WOKEN_TIMER`
            // (`process_stream` reads `TASK_WOKEN_TIMER` the same way).
            if timer {
                let cli_before = entry.sess.cli_state;
                #[cfg(debug_assertions)]
                ibex_sample::work::note(ibex_sample::work::Op::TimeoutCheck, 1);
                let timed_out = entry.sess.check_timeouts(now);
                if timed_out && entry.sess.mode == Mode::Http && entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Client)) {
                    Self::client_timed_out(entry, self.proxies, self.fdtab, self.poller, self.idle_backend_pool, &mut self.wake_queue, now, self.pid, cli_before);
                }
                // `timeout connect` expired: a failed connect like any other (`back_handle_st_cer`),
                // retried at once -- no turnaround, which only follows an asynchronous error --
                // and counted in `econ` once the retries are spent.
                if timed_out
                    && matches!(entry.sess.ending, Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Connect)))
                    && entry.srv_raw_fd.is_some()
                    && !entry.sess.is_done()
                {
                    entry.sess.ending = None;
                    server_connect_failed(entry, self.proxies, self.fdtab, self.poller, now, false);
                    // The last attempt ran out of time, not out of luck: a server-side timeout
                    // (`sC--`), where a refusal is `SC--` (T496, VV-23).
                    if entry.sess.ending == Some(crate::proxy::Ending::ConnectFailed) {
                        entry.sess.ending = Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Connect));
                    }
                }
                // A retry that waited out its turnaround connects now.
                if entry.sess.retry_after.is_set() && entry.sess.retry_after.is_expired(now) && !entry.sess.is_done() {
                    retry_now(entry, self.proxies, self.fdtab, self.poller, now);
                }
            }

            // Step 3: Stream engine process pass
            if !entry.sess.is_done() {
                entry.sess.advance(now);
            }
            #[cfg(debug_assertions)]
            crate::crash::fault_point(false, entry.sess.req_uri.as_deref().filter(|_| entry.sess.txn.is_some()));
        }
        // Step 3.05: an HTTP/2 connection's streams, each served by an entry of its own: the
        // next ones dispatched, their request bodies and responses moved (T280).
        if is_h2_owner {
            self.h2_owner_pass(session_idx, now);
        }
        let (is_done, pending_admin, log_line, checkcache_alert) = {
            let Some(entry) = self.sessions.get_mut(session_idx) else { return Outcome::Done };
            // The glitches the HTTP/2 connection counted since the last pass go to the entries
            // its stream counters track (`glitch_cnt`, `glitch_rate`); while a stream is served,
            // the owner pass credits them, to the counters as the stream tracks them.
            if let Some(n) = entry.sess.h2_ctx.as_ref().map(|h| h.glitch_count as u64).filter(|&n| n > entry.sess.glitches_credited && entry.sess.h2_owner().is_none_or(|o| o.children.is_empty())) {
                let due = n - entry.sess.glitches_credited;
                entry.sess.glitches_credited = n;
                for_tracked(self.proxies, &entry.sess, |data| data.add_glitches(due));
            }
            // A TCP stream stores what its `stick` rules took once the server has accepted
            // the connection (`AN_RES_STORE_RULES` runs on the first event of the response
            // side); a server that refused stores nothing.
            if !entry.sess.stick_stores.is_empty()
                && entry.sess.mode == Mode::Tcp
                && entry.sess.log.connect.is_some()
            {
                let stores = std::mem::take(&mut entry.sess.stick_stores);
                commit_stick_stores(stores.into_iter(), self.proxies, entry.srv_backend_idx, entry.target_server_idx);
            }

            // Step 3.1: a TLS handshake with the server that failed (certificate refused,
            // a peer not speaking TLS) is a connect failure: `HAProxy` retries it and,
            // out of retries, answers 503 `SC` (measured: `ssl verify required` against
            // a certificate the SNI does not match, "0/0/-1/-1/1 503 ... SC-- ... /3").
            if entry.sess.srv_xprt.handshake_failed() && entry.sess.srv_state == ScState::Error {
                if let (Some(fd), Some(sfd)) = (entry.sess.srv.as_ref(), entry.srv_raw_fd.take()) {
                    let _ = self.poller.delete(fd.as_fd());
                    self.fdtab.remove(sfd);
                }
                entry.sess.srv_xprt = crate::xprt::ServerXprt::Plain;
                entry.sess.ending = None;
                // `HAProxy` records a `CO_ER_SSL_*` code here, which Ibex does not tell
                // apart yet: no `bc_err` rather than the 0 of the TCP connect.
                entry.sess.bc_err = None;
                server_connect_failed(entry, self.proxies, self.fdtab, self.poller, now, true);
            }

            // Step 3.3: `tcp-request session` rules that waited for the PROXY header.
            run_deferred_session_rules(entry.proxy_idx, self.proxies, &mut entry.sess);

            // Step 3.4: Content inspection for TCP rules (or before HTTP request parsing)
            if !entry.sess.tcp_inspect_done && !entry.sess.is_done() {
                let proxy_idx = entry.proxy_idx;
                // The request's capture slots exist from the first rule that can fill one:
                // `begin_http_stream` keeps what these rules wrote in the slots no header fills.
                if self.proxies[proxy_idx].tcp_req_content_rules.iter().any(|r| matches!(r.action, ibex_config::TcpReqContentAction::Capture { .. })) {
                    entry.sess.log.req_captures.clear();
                    entry.sess.log.req_captures.resize(self.proxies[proxy_idx].req_capture_slots.len(), None);
                }
                crate::resolvers::dr_set_task(entry.task);
                match eval_tcp_req_content_rules(
                    &self.proxies[proxy_idx],
                    proxy_idx,
                    self.proxies,
                    sample_registry(),
                    &mut entry.sess,
                    now,
                    0,
                ) {
                    ContentEvalResult::Done => {
                        entry.sess.tcp_inspect_done = true;
                        entry.sess.inspect_exp = None;
                        // `switch-mode http` made the first request's head a thing to wait
                        // for: `timeout http-request` starts now, not at the next event.
                        entry.sess.arm_request(now);
                    }
                    ContentEvalResult::Reject => {
                        entry.sess.abort_client();
                        self.proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                        entry.sess.cli_state = ScState::Closed;
                        entry.sess.srv_state = ScState::Closed;
                        entry.sess.tcp_inspect_done = true;
                    }
                    ContentEvalResult::SilentDrop(ttl) => {
                        let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                        entry.sess.silent_drop_client(is_ipv6, ttl);
                        self.proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                        entry.sess.cli_state = ScState::Closed;
                        entry.sess.srv_state = ScState::Closed;
                        entry.sess.tcp_inspect_done = true;
                    }
                    ContentEvalResult::Waiting => {}
                }
            }

            // Step 3.45: TCP mode, `tcp-response content` rules over the response so far.
            if entry.sess.res_inspect_pending && !entry.sess.is_done() {
                let be_idx = entry.backend_idx;
                let res = eval_tcp_res_content_rules(&self.proxies[be_idx], &self.proxies, sample_registry(), &mut entry.sess, now);
                if res != ContentEvalResult::Waiting {
                    entry.sess.res_inspect_pending = false;
                    entry.sess.res_inspect_exp = None;
                }
                match res {
                    ContentEvalResult::Waiting => {}
                    // Released: forward what was held.
                    ContentEvalResult::Done => {
                        entry.sess.advance(now);
                    }
                    // `reject` (src/tcp_rules.c): the server connection is killed, the
                    // client's closed with nothing forwarded.
                    ContentEvalResult::Reject => {
                        if let Some(srv_fd) = entry.sess.srv.as_ref() {
                            raw::abort_with_rst(srv_fd.as_fd());
                        }
                        entry.sess.rep.clear();
                        self.proxies[be_idx].counters().denied_resp.fetch_add(1, Ordering::Relaxed);
                        entry.sess.cli_state = ScState::Closed;
                        entry.sess.srv_state = ScState::Closed;
                    }
                    ContentEvalResult::SilentDrop(ttl) => {
                        let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                        entry.sess.silent_drop_client(is_ipv6, ttl);
                        if let Some(srv_fd) = entry.sess.srv.as_ref() {
                            raw::abort_with_rst(srv_fd.as_fd());
                        }
                        entry.sess.rep.clear();
                        self.proxies[be_idx].counters().denied_resp.fetch_add(1, Ordering::Relaxed);
                        entry.sess.cli_state = ScState::Closed;
                        entry.sess.srv_state = ScState::Closed;
                    }
                }
            }

            // Step 3.5: the HTTP transaction -- rules, routing, the response head, and its end.
            let mut pending_admin = None;
            // A Prometheus scrape or a stats page being produced: one test for both.
            match entry.sess.pending_resp.as_deref() {
                Some(crate::proxy::PendingOut::Scrape(_)) => crate::promex::pump(&mut entry.sess, self.proxies, self.checks, self.pid),
                Some(crate::proxy::PendingOut::Stats(d)) => {
                    let d = *d;
                    stats_pump(&mut entry.sess, d, self.proxies, self.checks, self.pid);
                }
                // A local reply larger than one buffer, on an HTTP/2 stream (T589): the rest
                // of it follows as the stream's buffer empties.
                Some(crate::proxy::PendingOut::Raw(..)) if entry.sess.is_h2_child() => {
                    entry.sess.drain_pending_raw_h2();
                }
                _ => {}
            }
            // T587: an HTTP/3 stream's response head is in: the response rules and the log see the
            // packets sent and received since its request head, not the counts it found then.
            if !entry.sess.rep.is_empty() && entry.sess.txn.as_ref().is_some_and(|t| t.rsp == MsgState::Waiting) {
                if let Some(q) = entry.sess.quic_ack_mut() {
                    if let Some(f) = self.quic_listeners.get(q.listener as usize).and_then(|ql| ql.ack_facts(q.conn)) {
                        q.facts = Some(f);
                    }
                }
            }
            if entry.sess.mode == Mode::Http && !entry.sess.is_done() {
                pending_admin = Self::http_step(
                    entry,
                    self.proxies,
                    self.checks,
                    self.pid,
                    self.fdtab,
                    self.poller,
                    self.idle_backend_pool,
                    &mut self.wake_queue,
                    now,
                );
            }

            let log_line = entry.log_line.take().filter(|_| embryonic_failure(&entry.sess).is_none()).map(|l| (l, entry.log_sd, entry.log_err));
            // `option checkcache` blocked a response: the alert goes to the backend's loggers,
            // before the stream's own line (rare: the message is built here, not on the path).
            let checkcache_alert = std::mem::take(&mut entry.sess.log.checkcache_blocked).then(|| {
                let srv_idx = entry.target_server_idx.or_else(|| entry.sess.log.server.map(|i| i.get() as usize - 1));
                let srv = srv_idx.and_then(|i| self.proxies.get(entry.srv_backend_idx)?.server_ids.get(i)).map_or("<dispatch>", String::as_str);
                let be = self.proxies.get(entry.backend_idx).map_or("", |p| p.name.as_str());
                (entry.backend_idx, format!("Blocking cacheable cookie in response from instance {be}, server {srv}."))
            });

            // Step 3.6: If in TCP mode and server not yet connected (e.g. deferred on accept-proxy or inspect), connect once ready
            if entry.sess.mode == Mode::Tcp
                && entry.sess.srv_state == ScState::Init
                && (!entry.sess.accept_proxy || entry.sess.proxy_handshake_done)
                && entry.sess.tcp_inspect_done
                && !entry.sess.is_done()
                // A retry waiting out its turnaround connects in step 2 when it is over.
                && !entry.sess.retry_after.is_set()
            {
                if entry.sess.target_addr.is_some() {
                    // The connect made at accept was refused at once, retries remain: this
                    // is the retry (`wretr`, or `wredis` redispatched), at once.
                    retry_now(entry, self.proxies, self.fdtab, self.poller, now);
                } else {
                    Self::connect_tcp_backend(entry, self.proxies, self.fdtab, self.poller, now);
                }
            }

            // A server connection parked after a response that no request has taken back
            // goes to the server's lists (`end_txn`).
            if entry.sess.srv_park_exp.is_expired(now) {
                release_server(entry, self.proxies, self.fdtab, self.poller, self.idle_backend_pool, true);
            }

            // Step 4: Update interests
            update_interests(entry, self.fdtab, self.poller);
            // A direction with nothing in transit holds no buffer between two runs
            // (`h1_release_buf` after each send/recv): a forwarded request's buffer goes
            // back while its answer is stuck behind a slow client (T184).
            entry.sess.req.release();
            entry.sess.rep.release();

            // Step 4b: undispatched H2 streams have no socket event to wake them; run again.
            // Pending output needs no requeue: Step 4 asked the (level-triggered) poller
            // for writability, and requeueing it here spun a CPU against a client that
            // reads slowly.
            // In this pass for an h2 owner with streams to dispatch (L2); a run that spent its
            // budget (a scrape, a body) waits for the next one, as a self-wake does: run twice
            // a pass, the scrape counted its own response buffers in the pool figures.
            if entry.sess.wants_rerun() && !entry.sess.is_done() {
                if entry.sess.has_undispatched_h2_streams() {
                    self.wake_now.push(entry.task);
                } else {
                    self.wake_queue.push(entry.task);
                }
            }
            // A stream of an HTTP/2 connection has its owner run after it: the owner moves
            // what it produced (its response, room for more of its request) and sees how it
            // ended (T280).
            // An HTTP/3 owner too (L2): its second run in a pass sends what this one moved.
            if let Some((_, owner_task)) = entry.sess.h2_child().and_then(|c| c.owner) {
                owner_wake = Some(owner_task);
            }

            // Step 5: Update timer. Not for a stream that has ended: its task is freed when
            // this returns `Outcome::Done`, and a timer queued on it after the pass was
            // T100's crash.
            if !entry.sess.is_done() {
                self.timer_updates
                    .push((entry.task, entry.sess.next_expiry()));
                // A server TLS handshake started (or still runs) in this step: its next
                // wakeups go to `Heavy`. Cleared in `step` once it is done, as the
                // client's.
                if entry.sess.srv_tls_handshaking() {
                    self.heavy.push(entry.task);
                }
            }

            (entry.sess.is_done(), pending_admin, log_line, checkcache_alert)
        };

        if let Some(owner_task) = owner_wake {
            self.wake_now.push(owner_task);
        }
        if let Some((fe, line)) = connect_line {
            self.send_log_line(fe, line.as_bytes());
        }
        if let Some((be, msg)) = checkcache_alert {
            self.send_log(be, LogLevel::Alert, b"", msg.as_bytes());
        }
        if let Some((line, sd, err)) = log_line {
            let fe = self.sessions.get(session_idx).map_or(0, |e| e.proxy_idx);
            self.send_stream_log(fe, err, &line, sd);
            crate::logfmt::recycle_line(line);
        }

        if let Some(cmd) = pending_admin {
            if cmd.action == "kill_sessions" || cmd.action == "shutdown_sessions" {
                let be_name = cmd.backend.as_deref();
                let sv_id = cmd.server.as_deref();
                let _ = shutdown_matching_sessions(
                    self.sessions
                        .iter_mut()
                        .filter_map(|(idx, e)| if idx == session_idx { None } else { Some(e) }),
                    self.proxies,
                    be_name,
                    sv_id,
                    &mut self.wake_queue,
                );
            }
        }

        // Step 6: Completion cleanup
        if is_done {
            self.end_stream(session_idx, now, true);
            Outcome::Done
        } else {
            Outcome::Keep
        }
    }

    /// A stream that ended: its log line, then its entry freed and everything it held
    /// released (`close_notify`: a TLS client is told, which a stream a panic ended skips:
    /// its TLS state may be mid-record).
    fn end_stream(&mut self, session_idx: u32, now: Tick, close_notify: bool) {
        // A TCP connection's line, and an HTTP transaction's that ended with the
        // connection rather than through `end_txn` (aborted, timed out).
        let line = self.sessions.get_mut(session_idx).and_then(|e| {
            // A refused PROXY header has its own line, never the frontend's format.
            if embryonic_failure(&e.sess).is_some() {
                e.log_line = None;
                if e.sess.hs_fail().is_some() {
                    // `HAProxy` builds the session after the handshake: this connection
                    // is a `conn_tot` and a `ssl_failed_handshake`, not an `stot` or a `rate`.
                    let c = self.proxies[e.proxy_idx].counters();
                    c.ssl_failed_hs.fetch_add(1, Ordering::Relaxed);
                    c.fe_sess_rate.untick();
                }
                // `session_kill_embryonic`: `err` with `log-separate-errors`, else `info`.
                let err = self.proxies[e.proxy_idx].log_opts & ibex_config::LOG_OPT_SEPARATE_ERRORS != 0;
                return proxy_header_error_line(e, self.proxies, self.pid).map(|(l, sd)| (e.proxy_idx, l, sd, err));
            }
            if e.sess.mode == Mode::Tcp || e.sess.txn.is_some() {
                account_stream(e, self.proxies);
            }
            let queued = e.log_line.take().map(|l| (l, e.log_sd, e.log_err));
            queued
                .or_else(|| (e.sess.mode == Mode::Tcp || e.sess.txn.is_some()).then(|| stream_log_line(e, self.proxies, self.pid)).flatten())
                .map(|(l, sd, err)| (e.proxy_idx, l, sd, err))
        });
        if let Some((fe, line, sd, err)) = line {
            self.send_stream_log(fe, err, &line, sd);
            crate::logfmt::recycle_line(line);
        }
        if let Some(mut entry) = self.sessions.free(session_idx) {
            if entry.buf_wait.queued() {
                crate::buf_wait::leave(session_idx);
            }
            if entry.sess.is_h2_child() {
                // The stream is freed in its own run: its variables are in the run's map
                // until they go back to it here, for its connection's.
                stream_vars_leave(Some(&mut entry.sess));
                self.h2_child_released(&mut entry, now);
            } else if entry.sess.h2_owner().is_some_and(|o| !o.children.is_empty()) {
                self.h2_owner_released(&mut entry);
            }
            if close_notify {
                entry.sess.close_notify_both();
            }
            cleanup_done(
                &entry,
                self.proxies,
                self.fdtab,
                self.poller,
                self.listeners,
            );
            crate::proxy::give_relay_role(&mut entry.sess);
        }
    }

    /// A stream's run panicked ([`crate::crash::contain`], T447): the stream is closed as one
    /// that met an internal error (`%ts` `I`, `eint`), without an answer, as `HAProxy` closes a
    /// connection whose stream it could not allocate, and the worker serves on. Unless the
    /// panic left shared state half-changed, or this panics too: then the process aborts, as
    /// for any other panic. Design and the state it resets: `tasks/T447-progress.md`.
    #[cold]
    #[inline(never)]
    fn stream_panicked(&mut self, session_idx: u32) -> Outcome {
        // What the run had put in the thread's context, as `step_stream` takes it back. The
        // variables are dropped: no other stream may see them.
        stream_vars_leave(None);
        CURRENT_TIMEOUTS.set(None);
        crate::lb::clear_avoided();
        if let Some(what) = self.shared_state_poisoned() {
            crate::crash::abort_uncontained(&format!("left {what} half-changed"));
        }
        let now = self.now;
        let ended = crate::crash::contain(|| {
            let Some(entry) = self.sessions.get_mut(session_idx) else { return };
            // The task is destroyed when this returns: nothing queued during the pass may
            // name it any more (T100).
            let task = entry.task;
            self.timer_updates.retain(|(t, _)| *t != task);
            self.wake_queue.retain(|t| *t != task);
            self.wake_now.retain(|t| *t != task);
            self.heavy.retain(|t| *t != task);
            self.h2_spawn.retain(|(idx, _)| *idx != session_idx);
            entry.sess.ending = Some(crate::proxy::Ending::Error);
            // An HTTP stream that has no server yet failed in its request (`IR`, as
            // `HAProxy`'s `return_int_err` sets `SF_FINST_R`); otherwise the phase it reached.
            let in_request = entry.sess.mode == Mode::Http && entry.target_server_idx.is_none() && entry.srv_raw_fd.is_none();
            entry.sess.log.term = in_request.then_some(*b"IR");
            let fe = &self.proxies[entry.proxy_idx];
            fe.txn_counters().fe.eint.fetch_add(1, Ordering::Relaxed);
            // The backend once the stream has one (`SF_BE_ASSIGNED`), as `HAProxy` counts.
            if let Some(be) = counted_backend(entry).and_then(|i| self.proxies.get(i)) {
                be.txn_counters().be.eint.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(srv) = entry.target_server_idx.and_then(|i| self.proxies.get(entry.srv_backend_idx)?.txn_counters().srv.get(i)) {
                srv.eint.fetch_add(1, Ordering::Relaxed);
            }
            let client = entry.sess.client_addr.map_or_else(String::new, |a| format!(", client {a}"));
            crate::stderr_line!("[ALERT] ibex: a stream of frontend '{}'{client} panicked; it was closed, the process serves on", fe.name);
            self.end_stream(session_idx, now, false);
        });
        if ended.is_err() { crate::crash::abort_uncontained("closing it panicked too") }
        Outcome::Done
    }

    /// The shared state a panic can have left half-changed, if any (T447): a lock the
    /// panicking thread held is poisoned. Every lock a stream's run takes on structured data
    /// is here; the others hold rate estimates only (`tasks/T447-progress.md`).
    fn shared_state_poisoned(&self) -> Option<&'static str> {
        let per_proxy = self.proxies.iter().find_map(|p| {
            p.stick_table.as_ref().is_some_and(|t| t.is_poisoned()).then_some("a stick table")
                .or_else(|| crate::lb::lb_poisoned(&p.fwrr, &p.chash).then_some("a load balancer"))
                .or_else(|| p.server_retr.is_poisoned().then_some("server retry counters"))
        });
        per_proxy
            .or_else(|| self.idle_backend_pool.poisoned().then_some("the idle server connections"))
            .or_else(|| crate::ring::poisoned().then_some("a ring"))
            .or_else(|| crate::crash::fault_poisoned().then_some("the ibex.debug.panic lock"))
            .or_else(ibex_sample::shared_state_poisoned)
    }

    /// `retry-on <status>` and `junk-response`: the server's final answer carries a status
    /// the backend retries on (or a status line that is none), the request was copied whole
    /// when it was sent, and a retry is left: the answer is dropped and the request sent
    /// again (`l7_replay`). `true` when it was.
    fn l7_retry(entry: &mut SessionEntry, proxies: &[Proxy], fdtab: &mut FdTab, poller: &mut Poller, now: Tick) -> bool {
        let retry_on = proxies[entry.backend_idx].ids.retry_on;
        if retry_on & (ibex_config::RE_STATUS_MASK | ibex_config::RE_JUNK_RESPONSE) == 0 {
            return false;
        }
        let Some((h, e)) = entry.sess.rep.eoh() else {
            return false;
        };
        let status = crate::txn::status_of(&String::from_utf8_lossy(&entry.sess.rep.readable()[..h + e]));
        let due = if status < 100 {
            retry_on & ibex_config::RE_JUNK_RESPONSE != 0
        } else {
            ibex_config::RE_STATUSES.iter().any(|&(s, bit)| s == status && retry_on & bit != 0)
        };
        due && Self::l7_replay(entry, proxies, fdtab, poller, now)
    }

    /// `retry-on empty-response`, `response-timeout` and `junk-response`: the server ended
    /// the connection, or `timeout server` ran out, before a response head, and the backend
    /// retries on that.
    fn l7_retry_failure(entry: &mut SessionEntry, proxies: &[Proxy], fdtab: &mut FdTab, poller: &mut Poller, now: Tick) -> bool {
        let retry_on = proxies[entry.backend_idx].ids.retry_on;
        let timeout = entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Server));
        let srv_eof = matches!(entry.sess.srv_state, ScState::ShutR | ScState::Closed);
        let waiting = entry.sess.txn.as_ref().is_some_and(|t| {
            t.rsp == MsgState::Waiting && t.req_rules_done && !t.local && t.rsp_wait.is_none() && !t.aborted
        });
        if !waiting || !(srv_eof || timeout) || entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Connect)) {
            return false;
        }
        let kind = if timeout {
            ibex_config::RE_TIMEOUT
        } else if entry.sess.rep.is_empty() {
            ibex_config::RE_DISCONNECTED
        } else {
            ibex_config::RE_JUNK_RESPONSE
        };
        retry_on & kind != 0 && Self::l7_replay(entry, proxies, fdtab, poller, now)
    }

    /// `do_l7_retry`: one retry is spent, the answer so far dropped, the server connection
    /// closed, and the request, as it was sent, put back to go out again to the server the
    /// balancing picks (redispatching under `option redispatch`). `false` when no retry is
    /// left or the request was not kept.
    fn l7_replay(entry: &mut SessionEntry, proxies: &[Proxy], fdtab: &mut FdTab, poller: &mut Poller, now: Tick) -> bool {
        if entry.sess.conn_retries == 0 {
            return false;
        }
        let sess = &mut entry.sess;
        let Some(t) = sess.txn.as_mut() else { return false };
        let crate::txn::L7Retry::Saved(snap) = &t.l7 else { return false };
        sess.rep.clear();
        sess.req.replace_prefix(0, snap.bytes.readable());
        let req_state = snap.req_state;
        {
            t.req = req_state;
            t.rsp = MsgState::Waiting;
            t.rsp_interim = false;
            t.status = 0;
        }
        if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.take(), entry.srv_raw_fd.take()) {
            let _ = poller.delete(srv_fd.as_fd());
            fdtab.remove(sfd);
        }
        entry.sess.srv_xprt = crate::xprt::ServerXprt::Plain;
        entry.sess.ending = None;
        entry.sess.l7_retried();
        // The last retry is spent: the copy goes back to the pool now, not with the transaction.
        if entry.sess.conn_retries == 0 {
            if let Some(t) = entry.sess.txn.as_mut() {
                t.l7 = crate::txn::L7Retry::Dead;
            }
        }
        // The connect that follows is any other retry's: a refusal at once is the next
        // failure (`server_connect_failed`: `econ` once, retries without turnaround).
        retry_now(entry, proxies, fdtab, poller, now);
        true
    }

    /// The response head `apply_http_response_rules` has just settled goes to the client with
    /// its header names in lower case (`HAProxy` writes what went through HTX so), in the case
    /// of the `h1-case-adjust` table for a frontend with `option h1-case-adjust-bogus-client`.
    /// The rewrite is idempotent, so a pass that leaves the head for the next one is harmless.
    fn write_response_head_names(entry: &mut SessionEntry, proxies: &[Proxy]) {
        if entry.sess.txn.as_ref().is_none_or(|t| t.rsp == MsgState::Waiting) {
            return;
        }
        let table = client_case_table(&proxies[entry.proxy_idx]);
        let lower = names_lower(&entry.sess, &proxies[entry.proxy_idx]);
        if !lower && table.is_none() {
            return;
        }
        ibex_proto::response_head::count_head_scan();
        entry.sess.rep.edit_keeping_lines(|head, eoh| rewrite_header_names_before(head, eoh, table, lower));
    }

    /// The response head's rules, framing and `Connection`. True when the head's names are
    /// in lower case already, from its index (E2), and [`Self::write_response_head_names`]
    /// has nothing to do.
    fn apply_http_response_rules(entry: &mut SessionEntry, proxies: &[Proxy], now: Tick) -> bool {
        if let Some(c) = entry.sess.h2_child_mut() {
            c.rsp_head = None;
        }
        let mut lowered = false;
        Self::apply_http_response_rules_in(entry, proxies, now, &mut lowered);
        lowered
    }

    #[allow(clippy::too_many_lines)]
    fn apply_http_response_rules_in(entry: &mut SessionEntry, proxies: &[Proxy], now: Tick, lowered: &mut bool) {
        let threshold = entry.sess.bufsize.saturating_sub(entry.sess.maxrewrite);
        // Empty lines ahead of a status line are skipped (`H1_MSG_RPBEFORE`), so that the
        // end of the head is not looked for in them (T275).
        let blank = leading_empty_lines(entry.sess.rep.readable());
        if blank > 0 {
            entry.sess.rep.replace_prefix(blank, b"");
        }
        #[cfg(debug_assertions)]
        if entry.sess.rep.eoh().is_some() {
            crate::crash::fault_point(true, entry.sess.req_uri.as_deref());
        }
        let Some((hdr_len, eoh_len)) = entry.sess.rep.eoh() else {
            // No end of head and no room for more: as for a request, from `bufsize - 56`
            // (T265).
            if entry.sess.rep.readable().len() > threshold || entry.sess.rep.readable().len() + 56 >= entry.sess.bufsize {
                entry.sess.rep.clear();
                reply_error(entry, proxies, 502);
            }
            return;
        };
        let be_idx = entry.backend_idx;
        let fe_idx = entry.proxy_idx;

        let mut total_hdr_len = hdr_len + eoh_len;
        // The head as `HAProxy` parses it (T275): refused with a 502 (`PH`), or written again
        // as `HAProxy` writes what it parsed. `option accept-unsafe-violations-in-http-response`
        // of the backend relaxes what it relaxes. A head back from a wait was checked when it
        // arrived, and the rules have edited it since.
        let mut close_server = false;
        // What `%B` counts of the head: what HTX holds of it.
        let mut held: Option<Vec<u8>> = None;
        // The head as parsed, while nothing has edited it (E2).
        let mut index: Option<ibex_proto::response_head::RspHead> = None;
        // The facts of an indexed head, read in the check's pass over it (X3).
        let mut checked_facts = None;
        if entry.sess.txn.as_ref().is_some_and(|t| t.rsp_wait.is_none()) {
            let accept = proxies[be_idx].stats_config.accept_unsafe_response;
            let head = &entry.sess.rep.readable()[..total_hdr_len];
            let mut facts = crate::txn::ResponseFacts::default();
            let checked = ibex_proto::response_head::check_response_head_with(head, accept, |at, colon, end| facts.field(head, at, colon, end));
            if let ibex_proto::response_head::ResponseHead::Valid { rewrite: None, index: Some(ix), .. } = &checked {
                checked_facts = facts.finish(head, ix.start as usize);
            }
            match checked {
                ibex_proto::response_head::ResponseHead::Invalid => {
                    entry.sess.rep.clear();
                    entry.sess.log.term.get_or_insert(*b"PH");
                    entry.sess.log.bytes_from_server = 0;
                    reply_error(entry, proxies, 502);
                    return;
                }
                ibex_proto::response_head::ResponseHead::Valid { status, rewrite, close_server: close, index: ix } => {
                    close_server = close;
                    index = ix;
                    if let Some(r) = rewrite {
                        note_response_head_write();
                        entry.sess.rep.replace_prefix(total_hdr_len, &r.head);
                        total_hdr_len = r.head.len();
                        held = Some(r.held);
                    }
                    // The websocket handshake against what the request asked for (T281):
                    // nothing to read in a head with no `Upgrade` field but a `101`.
                    let req_ws = entry.sess.req_ws.as_deref().copied().unwrap_or_default();
                    let verdict = match &index {
                        Some(ix) if status != 101 && !ix.upgrade => crate::websocket::Verdict::Keep,
                        _ => crate::websocket::check_response(&entry.sess.rep.readable()[..total_hdr_len], status, &req_ws, accept),
                    };
                    #[cfg(debug_assertions)]
                    if index.is_some() {
                        debug_assert_eq!(verdict, crate::websocket::check_response_uncounted(&entry.sess.rep.readable()[..total_hdr_len], status, &req_ws, accept));
                    }
                    if !matches!(verdict, crate::websocket::Verdict::Keep) {
                        index = None;
                    }
                    match verdict {
                        crate::websocket::Verdict::Keep => {}
                        crate::websocket::Verdict::Refuse => {
                            entry.sess.rep.clear();
                            entry.sess.log.term.get_or_insert(*b"PH");
                            entry.sess.log.bytes_from_server = 0;
                            reply_error(entry, proxies, 502);
                            return;
                        }
                        crate::websocket::Verdict::Rewrite(new) => {
                            note_response_head_write();
                            entry.sess.rep.replace_prefix(total_hdr_len, &new);
                            total_hdr_len = new.len();
                        }
                    }
                }
            }
        }
        // Read in place: the head is borrowed from `rep` (no copy for a UTF-8 head, which is
        // every head on the fast path) and the borrow ends before `rep` is edited.
        // One pass over the head for what follows reads of it (T436); a head the facts are not
        // read from is read the old way, a pass for each.
        let rsp_facts = match (&index, checked_facts) {
            (Some(_), Some(f)) => Some(f),
            _ => crate::txn::HeadFacts::scan(&entry.sess.rep.readable()[..total_hdr_len], false),
        };
        let (status, framing, srv_has_close, srv_http11) = {
            let raw = &entry.sess.rep.readable()[..total_hdr_len];
            let method = entry.sess.req_method.as_deref();
            if let Some(f) = rsp_facts {
                let (status, http11) = match &index {
                    Some(ix) => (ix.status, ix.http11),
                    None => (crate::txn::status_of_line(&raw[..memchr::memchr(b'\n', raw).unwrap_or(raw.len())]), ibex_proto::response_head::is_http11(raw)),
                };
                #[cfg(debug_assertions)]
                debug_assert_eq!((status, http11), (crate::txn::status_of_line(&raw[..memchr::memchr(b'\n', raw).unwrap_or(raw.len())]), ibex_proto::response_head::is_http11(raw)));
                let framing = f.response_framing(method, status).unwrap_or_else(|| crate::txn::response_framing(&String::from_utf8_lossy(raw), method, status));
                (status, framing, f.wants_close(), http11)
            } else {
                let head = String::from_utf8_lossy(raw);
                let status = crate::txn::status_of(&head);
                let framing = crate::txn::response_framing(&head, method, status);
                (status, framing, crate::txn::head_wants_close(&head), ibex_proto::response_head::is_http11(head.as_bytes()))
            }
        };
        // The head counts what its HTX holds (T265): the data, 40 bytes and 8 per block, not the
        // wire length.
        // Read with the HTX size of the head, which `%B` counts below: the head is not edited in
        // between.
        let (cost, rsp_htx) = match rsp_facts {
            Some(f) => (f.cost(), Some(f.size)),
            None => crate::txn::htx_response_head_cost_and_size(&entry.sess.rep.readable()[..total_hdr_len]),
        };
        if cost > threshold {
            entry.sess.rep.clear();
            // A response that is not HTTP: `PH`, and nothing of it counts as sent.
            entry.sess.log.term.get_or_insert(*b"PH");
            entry.sess.log.bytes_from_server = 0;
            reply_error(entry, proxies, 502);
            return;
        }
        // The chunked body that arrived with the head is parsed with it, as `HAProxy` parses
        // what is in its buffer into HTX before the stream sees the head: a malformed chunk,
        // or a trailer section past its cap, makes the whole response a 502 (`PH`), and none
        // of it is relayed. Ibex relayed the head and the body up to the error (T281, V&V
        // chunked_diff). Once the head has gone, an error closes the client connection
        // behind what was relayed (`http_server_side`).
        if framing == crate::txn::Framing::Chunked && entry.sess.txn.as_ref().is_some_and(|t| t.rsp_wait.is_none()) {
            let check = MsgState::head(framing).check_body(entry.sess.rep.readable());
            if matches!(check, crate::txn::BodyCheck::Held { trailer: true, .. }) && entry.sess.rep.len() >= entry.sess.bufsize {
                // Held whole until the section is (`MsgState::holds_trailer`); refused in
                // `http_server_side` if it is not. No memory for it: this stream fails (S5).
                if !entry.sess.rep.grow_capacity(2 * entry.sess.bufsize) {
                    entry.sess.rep.clear();
                    entry.sess.ending = Some(crate::proxy::Ending::Error);
                    entry.sess.log.bytes_from_server = 0;
                    if let Some(t) = entry.sess.txn.as_mut() {
                        t.srv_reusable = false;
                    }
                    reply_error(entry, proxies, 500);
                    return;
                }
            }
            if matches!(check, crate::txn::BodyCheck::Broken | crate::txn::BodyCheck::TooLarge { .. }) {
                entry.sess.rep.clear();
                entry.sess.log.term.get_or_insert(*b"PH");
                entry.sess.log.bytes_from_server = 0;
                if let Some(t) = entry.sess.txn.as_mut() {
                    t.srv_reusable = false;
                }
                reply_error(entry, proxies, 502);
                return;
            }
        }
        let h2_less = if entry.sess.srv_xprt.is_h2() { h2_htx_overcount(&entry.sess.rep.readable()[..total_hdr_len]) } else { 0 };
        let Some(txn) = entry.sess.txn.as_mut() else {
            return;
        };
        if (100..200).contains(&status) && status != 101 {
            // Interim: forwarded as it is, and the final response follows.
            txn.rsp = MsgState::head(crate::txn::Framing::None);
            txn.rsp_interim = true;
            return;
        }
        // A response held for its body (`wait-for-body`) comes back here with its head as
        // the rules before the wait left it, and goes on from the wait.
        let wait = txn.rsp_wait.take();
        // Held by `tcp-response content` (`WAIT_END`): the rules start over, with the delay
        // already running.
        let inspect_wait = wait.filter(|w| w.inspect);
        let resume = wait.filter(|w| !w.inspect);
        // The final response head: `t_data`, and `capture response header`.
        if wait.is_none() {
            entry.sess.log.data = Some(crate::txnlog::loop_now());
            // What `%B` counts of this head: the message as the server sent it.
            txn.rsp_htx = held.as_deref().map_or(rsp_htx, |h| crate::txn::htx_head_size(h, false)).map(|n| n.saturating_sub(h2_less));
        }
        let fe_caps = &proxies[fe_idx].res_capture_slots;
        if wait.is_none() && !fe_caps.is_empty() {
            // From the bytes of the head, not a lossy copy of them.
            let head = &entry.sess.rep.readable()[..total_hdr_len];
            // T331: a slot whose header the response lacks keeps what a converter wrote to it.
            // A slot no header fills (a rule's) has no name. The value goes into the slot's
            // memory of the previous response (T437).
            for (slot, (name, len)) in entry.sess.log.res_captures.iter_mut().zip(fe_caps.iter()) {
                if name.is_empty() {
                    continue;
                }
                let found = head
                    .split(|&b| b == b'\n')
                    .skip(1)
                    .filter_map(|l| {
                        let colon = l.iter().position(|&b| b == b':')?;
                        Some((&l[..colon], l[colon + 1..].strip_suffix(b"\r").unwrap_or(&l[colon + 1..])))
                    })
                    .filter(|(k, _)| k.trim_ascii().eq_ignore_ascii_case(name.as_bytes()))
                    .last();
                if let Some((_, v)) = found {
                    let v = v.trim_ascii();
                    crate::txnlog::set_capture(slot, &v[..(*len).min(v.len())]);
                }
            }
        }
        txn.status = status;
        // A head back from a `wait-for-body` has lost the server's `close` (T439): what was
        // read of the head the server sent stands.
        txn.srv_reusable = (resume.is_none() || txn.srv_reusable)
            && !srv_has_close
            && !close_server
            && (txn.srv_kal_rule || !server_close(proxies, entry.proxy_idx, entry.backend_idx))
            && !txn.req_len_long
            && !matches!(framing, crate::txn::Framing::UntilClose | crate::txn::Framing::Tunnel);
        if framing == crate::txn::Framing::UntilClose {
            // The server's close is the only end the client can see.
            txn.close_after = true;
            txn.close_opt = false;
        }
        // `Transfer-Encoding` in an HTTP/1.0 response ends the message there (`H1_MF_CONN_CLO`,
        // whatever `Connection` says): the client connection too, with no `Connection` header
        // for it (measured on 3.5-dev8; T296).
        if close_server && !srv_http11 {
            txn.close_after = true;
            txn.close_opt = false;
        }
        let client_close = txn.close_after;
        let req_http11 = txn.req_http11;
        let cookie_txn = txn.ck;
        // Only an error changes a counter: a response that is not one costs the tracked entries no update.
        let (is_err, is_fail) = response_class(status);
        if resume.is_none() && (is_err || is_fail) {
            for_tracked(proxies, &entry.sess, |data| {
                if is_err {
                    data.count_err();
                }
                if is_fail {
                    data.count_fail();
                }
            });
        }

        let tunnel = framing == crate::txn::Framing::Tunnel;
        let set_rsp = |entry: &mut SessionEntry| {
            let sess = &mut entry.sess;
            let mut head_left = 0;
            if let Some(txn) = sess.txn.as_mut() {
                // One whose chunk framing comes off goes as a body that lasts until the close
                // until its end is seen (`TcpSession::dechunk_rep`).
                txn.rsp = MsgState::head(if txn.rsp_dechunk.is_some() { crate::txn::Framing::UntilClose } else { framing });
                txn.rsp.measure_head_by(|| sess.rep.eoh());
                if let MsgState::Head { left, .. } = txn.rsp {
                    head_left = left;
                }
                if framing == crate::txn::Framing::Tunnel && txn.req.is_done() {
                    txn.req = MsgState::Tunnel;
                }
            }
            sess.dechunk_rep(head_left);
            // The body that came with the head: its chunk lines as HAProxy writes them.
            sess.rewrite_rep_chunk_framing();
            // `option logasap`: the line goes out with the response head (`http_process_res_common`),
            // with what has come from the server so far, and the end of the stream logs nothing.
            if proxies[fe_idx].log_opts & ibex_config::LOG_OPT_ASAP != 0 && !entry.sess.log.asap_done {
                set_stream_log(entry, proxies, std::process::id());
                entry.sess.log.asap_done = true;
            }
        };

        // `stick store-response` reads the response head: it takes the slow path below, where
        // the response's fetches are set up. Without one, the keys of the request are stored
        // here, with the server that answered.
        let store_rsp = wait.is_none()
            && proxies[be_idx].stick_rules.iter().any(|r| r.rule_type == ibex_config::StickRuleType::StickStoreResponse);
        if wait.is_none() && !store_rsp && !entry.sess.stick_stores.is_empty() {
            let stores = std::mem::take(&mut entry.sess.stick_stores);
            commit_stick_stores(stores.into_iter(), proxies, entry.srv_backend_idx, entry.target_server_idx);
        }

        let has_rules = store_rsp
            || !proxies[be_idx].http_res_rules.is_empty()
            || !proxies[be_idx].http_after_res_rules.is_empty()
            || !proxies[fe_idx].http_res_rules.is_empty()
            || !proxies[fe_idx].http_after_res_rules.is_empty()
            || !proxies[be_idx].tcp_res_content_rules.is_empty()
            || proxies[be_idx].cookie.is_some()
            || proxies[be_idx].ids.checkcache
            || !proxies[be_idx].srvexp.is_empty();

        if !has_rules {
            // The names in lower case, as `HAProxy` writes what went through HTX, from the
            // index: nothing has edited the head since it was made (E2). With an
            // `h1-case-adjust` table for the client, `write_response_head_names` does it.
            let mut index = index.filter(|ix| ix.len as usize == total_hdr_len && client_case_table(&proxies[fe_idx]).is_none());
            // Off (`tune.ibex.h1-lowercase-headers`, the default), the names stay as they came:
            // nothing to write, and nothing left for `write_response_head_names` either.
            if let Some(ix) = &index {
                if names_lower(&entry.sess, &proxies[fe_idx]) {
                    entry.sess.rep.edit_keeping_lines(|head, _| {
                        for f in ix.fields() {
                            head[f.at as usize..f.colon as usize].make_ascii_lowercase();
                        }
                    });
                }
                *lowered = true;
            }
            // `keep-alive` and `close` out of the server's `Connection`, the one this
            // connection's state calls for in (`h1_update_res_conn_value`).
            let (h, e) = entry.sess.rep.eoh().unwrap_or_default();
            // Without rules nothing has edited the head since its facts were read.
            let scan = match rsp_facts {
                Some(f) if h + e == total_hdr_len => f.conn,
                _ => crate::txn::scan_connection(&entry.sess.rep.readable()[..h + e]),
            };
            debug_assert_eq!(scan, crate::txn::scan_connection(&entry.sess.rep.readable()[..h + e]), "stale response head facts");
            // Under 200, `HAProxy` writes no `Connection` (`H1S_F_HAVE_O_CONN`), also for a
            // final status under 100.
            let token = if tunnel || status < 100 {
                None
            } else {
                crate::txn::response_connection_token(client_close, srv_http11, req_http11, false)
            };
            if scan.count == 0 || (scan.count == 1 && scan.plain) {
                // The usual response: no `Connection`, or one that is all `keep-alive` and
                // `close`; the head is edited where it is, with no copy.
                if scan.count == 1 {
                    entry.sess.rep.cut(scan.first.0, scan.first.1);
                    if let Some(ix) = index.as_mut() {
                        ix.cut_line(scan.first.0, scan.first.1);
                    }
                }
                if let Some(tok) = token {
                    // A head the index holds ends with CRLF, and its names are lower case. A
                    // line put in another way (a head past 4096 bytes) leaves the index of the
                    // head before it, which the client side then reads again (its length).
                    let line = inject_connection_token_zero_alloc(&mut entry.sess.rep, tok, index.is_some());
                    if let (Some(ix), Some(l)) = (index.as_mut(), line) {
                        ix.add_line("connection".len(), l);
                    }
                }
            } else {
                let head = ibex_regex::bytetext::bytes_to_text(&entry.sess.rep.readable()[..h + e]);
                if let Some(new) = crate::txn::rewrite_response_connection(&head, client_close, req_http11, tunnel) {
                    note_response_head_write();
                    entry.sess.rep.replace_prefix(h + e, &ibex_regex::bytetext::text_to_bytes(&new));
                    index = None;
                    *lowered = false;
                }
            }
            // What an HTTP/2 or HTTP/3 client's HEADERS are written from.
            if let Some(c) = entry.sess.h2_child_mut() {
                c.rsp_head = index;
            }
            set_rsp(entry);
            return;
        }

        // The whole head, blank line included: it is replaced by one that carries its own.
        // Replacing only up to the blank line left the old one in front of the body, so
        // every response through these rules arrived with four bytes more than its
        // `Content-Length`.
        let total_hdr_len = match entry.sess.rep.eoh() {
            Some((h, e)) => h + e,
            None => return,
        };
        let hdr_bytes = &entry.sess.rep.readable()[..total_hdr_len];
        // The head as text, the status line's parts and the header list are per-thread strings
        // given back at the end (T437).
        let mut hdr_str = crate::reuse::PString::new();
        match std::str::from_utf8(hdr_bytes) {
            Ok(t) if !ibex_regex::bytetext::has_escapes(t) => hdr_str.push_str(t),
            _ => hdr_str.push_str(&ibex_regex::bytetext::bytes_to_text(hdr_bytes)),
        }

        // Bare-LF line ends are a head too (`find_eoh` accepts them, as HAProxy's parser
        // does); split only on CRLF, such a head skipped every rule.
        let Some((first_line, rest_headers)) = hdr_str.split_once("\r\n").or_else(|| hdr_str.split_once('\n')) else {
            set_rsp(entry);
            return;
        };

        let mut status: u16 = 200;
        let mut proto_version = crate::reuse::PString::of("HTTP/1.1");
        let mut status_msg = crate::reuse::PString::of("OK");
        let mut parts = first_line.split_whitespace();
        if let (Some(p0), Some(p1)) = (parts.next(), parts.next()) {
            proto_version.clear();
            proto_version.push_str(p0);
            if let Ok(st) = p1.parse::<u16>() {
                status = st;
            }
            // The reason's words, one space between each.
            if let Some(w) = parts.next() {
                status_msg.clear();
                status_msg.push_str(w);
                for w in parts {
                    status_msg.push(' ');
                    status_msg.push_str(w);
                }
            }
        }

        // The headers the rules edit are the list the response fetches read (X3): built once
        // where they read it, edited there, and written out from it, with no copy of it per
        // rule or per list.
        with_res_hdrs(|hdrs| {
            crate::reuse::clear_pairs(hdrs);
            for line in rest_headers.lines() {
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    hdrs.push((crate::reuse::string_from(k.trim()), crate::reuse::string_from(v.trim())));
                }
            }
        });
        // T439: the rules do not see the server's `close` and `keep-alive` (`HAProxy` takes
        // them out as it parses the head), and what framed the response is kept for after
        // them. A head back from a `wait-for-body` is the one the rules left: done then.
        if resume.is_none() {
            let len_hdrs = with_res_hdrs(|hdrs| {
                crate::txn::strip_connection_tokens(hdrs);
                crate::txn::LenHdrs::of_response(hdrs)
            });
            if let Some(t) = entry.sess.txn.as_mut() {
                t.rsp_len_hdrs = len_hdrs;
            }
        }

        CURRENT_RES_STATUS.set(status);
        CURRENT_SRV_STATUS.set(status);
        entry.sess.log.srv_status = status;
        // `t_data - t_connect` (`smp_fetch_reX_timers`).
        let tr = entry.sess.log.data.zip(entry.sess.log.connect).map(|(d, c)| d.saturating_duration_since(c).as_millis());
        CURRENT_RES_TR.set(tr.map_or(-1, |ms| i64::try_from(ms).unwrap_or(i64::MAX)));
        // `HAProxy` caps `tune.maxrewrite` at half the buffer (`src/haproxy.c`).
        let reserve = entry.sess.maxrewrite.min(entry.sess.bufsize / 2);
        let body_in_buf = entry.sess.rep.readable().len().saturating_sub(total_hdr_len);
        with_res_hdrs(|hdrs| res_htx_init(entry.sess.bufsize, Some(reserve), &proto_version, &status_msg, hdrs, body_in_buf));

        let registry = sample_registry();

        // The response capture slots the `http-response capture` rules write, and that the
        // context reads (as they were when the response came in).
        let mut res_caps = entry.sess.log.res_captures.clone();
        let res_caps_in = res_caps.clone();

        let htx_slice = if entry.sess.has_htx {
            Some(ibex_proto::htx::HtxSliceRef::new(
                entry.sess.htx_buf.raw_slice(),
                entry.sess.htx_blocks,
            ))
        } else {
            None
        };

        // The rules of a proxy that waits for the response body read what is in the buffer
        // as `res.body`, as `HAProxy` gives them: the rules after a `wait-for-body` the whole
        // of it (or what the wait settled for).
        let order: &[usize] = if fe_idx == be_idx { &[be_idx] } else { &[be_idx, fe_idx] };
        let has_wait = order.iter().any(|&px| {
            proxies[px].http_res_rules.iter().any(|r| matches!(r.action, ibex_config::HttpResAction::WaitForBody { .. }))
        });
        let limit = entry.sess.bufsize.saturating_sub(entry.sess.maxrewrite);
        let mut res_body = Vec::new();
        let body_progress = if has_wait {
            let data = entry.sess.rep.readable();
            let progress = crate::txn::read_body(framing, &data[total_hdr_len..], &mut res_body);
            res_body.truncate(limit.saturating_sub(total_hdr_len));
            progress
        } else {
            crate::txn::BodyProgress::Complete
        };
        let rep_full = entry.sess.rep.len() >= limit;
        let srv_ended = matches!(entry.sess.srv_state, ScState::ShutR | ScState::Closed | ScState::Error);
        let srv_timed_out = entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Server));

        // The keys of the request, and the response's own, wait for the server's id.
        let mut stick_stores = std::mem::take(&mut entry.sess.stick_stores);
        let stick = StickView::new(proxies, &entry.sess.tracked_sc);
        let mut ctx = SampleContext {
            proxies: Some(&ProxiesView(proxies)),
            stick: Some(&stick),
            client_addr: entry.sess.client_addr,
            server_addr: entry.sess.server_addr,
            fc_src: entry.sess.fc_src(),
            so_name: entry.sess.so_name.as_deref(),
            so_id: entry.sess.so_id,
            fc_dst: entry.sess.fc_dst(),
            is_first_req: entry.sess.is_first_req,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: crate::proxy::ssl_fc(&entry.sess.cli_xprt, entry.sess.h2_role.as_deref()),
            quic_acks: entry.sess.quic_facts(),
            fc_http_major: entry.sess.fc_http_major(),
            bc_http_major: entry.sess.bc_http_major(),
            req_version: entry.sess.client_version(),
            ssl_bc: entry.sess.srv_xprt.ssl_facts(),
            htx: None,
            htx_slice,
            req_uri: entry.sess.req_uri.as_deref(),
            req_method: entry.sess.req_method.as_deref(),
            req_headers: entry.sess.req_headers.as_deref(),
            fe_name: Some(&proxies[fe_idx].name),
            fe_id: Some(proxies[fe_idx].ids.iid),
            be_name: Some(&proxies[be_idx].name),
            be_id: Some(proxies[be_idx].ids.iid),
            be_max_retries: Some(proxies[be_idx].retries),
            cur_max_retries: Some(entry.sess.max_retries),
            res_version: Some(&proto_version),
            res_body: has_wait.then_some(res_body.as_slice()),
            unique_id: entry.sess.log.unique_id.as_deref(),
            accept_date: Some(entry.sess.log.date()),
            stream: Some(stream_facts(&entry.sess, Some(status), order.iter().any(|&px| proxies[px].rules.res_stream))),
            bc_err: entry.sess.bc_err.copied(),
            bc_reused: Some(entry.sess.txn.as_ref().is_some_and(|t| t.srv_reused)),
            term_state: Some(sess_term_state(&entry.sess)),
            bc_dst: entry.sess.bc_dst(),
            bc_src: entry.sess.bc_src(),
            last_rule: last_rule_at(entry.sess.log.last_rule),
            prio: (entry.sess.log.prio_class, entry.sess.log.prio_offset),
            captures_req_hdr: Some(&entry.sess.log.req_captures),
            captures_res_hdr: Some(&res_caps_in),
            // The server that answered, for `srv_id` and `srv_name`.
            srv_id: entry.target_server_idx.and_then(|i| u32::try_from(i + 1).ok()),
            srv_name: entry
                .target_server_idx
                .and_then(|i| proxies.get(entry.srv_backend_idx)?.server_ids.get(i))
                .map(String::as_str),
            ..Default::default()
        };

        // `process_store_rules`: `stick store-response` takes a key from the response (the
        // first per table, none where the request already stored one), and every key queued
        // is stored with the server that sent it, ahead of the `http-response` rules.
        if store_rsp {
            let be = &proxies[be_idx];
            let from_request = stick_stores.len();
            for (rule, rc) in be.stick_rules.iter().zip(&be.rules.stick).filter(|(r, _)| r.rule_type == ibex_config::StickRuleType::StickStoreResponse) {
                let t_idx = match &rule.table {
                    Some(name) => proxies.iter().position(|p| p.name == *name),
                    None => Some(be_idx),
                };
                let Some((t_idx, tbl)) = t_idx.and_then(|i| Some((i, proxies[i].stick_table.as_ref()?))) else {
                    continue;
                };
                if stick_stores[from_request..].iter().any(|(t, _)| *t == t_idx) || stick_stores.len() >= 8 {
                    continue;
                }
                if rc.cond.as_ref().is_some_and(|c| !c.eval(&ctx, &be.acls, registry)) {
                    continue;
                }
                if let Some(key) = resolve_stick_key(rc.expr.as_ref(), registry, &ctx, Some(tbl)) {
                    stick_stores.push((t_idx, key));
                }
            }
        }
        commit_stick_stores(stick_stores.drain(..), proxies, entry.srv_backend_idx, entry.target_server_idx);

        // `tcp-response content reject`: the response is dropped and the client connection
        // closed with nothing sent, as HAProxy does -- not answered with a 502.
        let mut rejected = false;
        // Where a `wait-for-body` holds the response: the list and the rule, and until when.
        let mut held: Option<crate::txn::RspWait> = None;
        let mut timed_out = false;
        let mut malformed = false;
        let failed: Option<ResStop> = 'rules: {
            // 0. Apply be.tcp_res_content_rules. They run before the response is analysed
            // as HTTP (`AN_RES_INSPECT` ahead of `AN_RES_WAIT_HTTP`), so its status and
            // headers are not there to fetch until they are done.
            CURRENT_RES_STATUS.set(0);
            // The headers, out of the fetches' sight while the `tcp-response` rules run, and
            // back whatever ends them.
            let hidden = with_res_hdrs(std::mem::take);
            let tcp_stop = 'tcp: {
            // Copied only for a backend that has the rules (S7: a copy per response).
            let tcp_ctx = (resume.is_none() && !proxies[be_idx].tcp_res_content_rules.is_empty()).then(|| SampleContext { res_version: None, ..ctx.clone() });
            // `tcp-response inspect-delay` runs from the first pass over the head; with none,
            // the rules cannot wait (`tcp_inspect_response`).
            let inspect_exp = inspect_wait.map(|w| w.deadline).or_else(|| {
                proxies[be_idx].tcp_res_inspect_delay.map(|d| now.add(u32::try_from(d.as_millis()).unwrap_or(u32::MAX)))
            });
            // A server that closed after its response does not end the wait: measured, the
            // response still waits for the whole delay.
            let inspect_final = rep_full || srv_timed_out || inspect_exp.is_none_or(|exp| exp.is_expired(now));
            for (rule, rc, tcp_ctx) in tcp_ctx.iter().flat_map(|c| proxies[be_idx].tcp_res_content_rules.iter().zip(&proxies[be_idx].rules.tcp_res_content).map(move |(r, rc)| (r, rc, c))) {
                let matches = match &rc.cond {
                    None => true,
                    Some(cond) => {
                        let res = cond.eval_terms(&proxies[be_idx].acls, |expr, negated| {
                            if expr.fetch_name == "wait_end" && !inspect_final {
                                crate::proxy::AclEvalResult::MissingData
                            } else if expr.eval(registry, tcp_ctx) != negated {
                                crate::proxy::AclEvalResult::Matched
                            } else {
                                crate::proxy::AclEvalResult::NotMatched
                            }
                        });
                        if res == crate::proxy::AclEvalResult::MissingData {
                            // Held until the delay is over: the rules start again then.
                            held = Some(crate::txn::RspWait { list: 0, rule: 0, deadline: inspect_exp.unwrap_or(Tick::ETERNITY), inspect: true });
                            break 'tcp true;
                        }
                        res == crate::proxy::AclEvalResult::Matched
                    }
                };
                if !matches {
                    continue;
                }
                match &rule.action {
                    ibex_config::TcpResAction::Accept => {
                        entry.sess.log.last_rule = Some(rule.line);
                        break;
                    }
                    ibex_config::TcpResAction::Reject | ibex_config::TcpResAction::SilentDrop => {
                        entry.sess.log.last_rule = Some(rule.line);
                        rejected = true;
                        break 'tcp true;
                    }
                    ibex_config::TcpResAction::SetVar { var_name, expr: _ } => {
                        set_var_from(&mut entry.sess.vars, &rc.var(var_name), rc.expr.as_ref(), tcp_ctx, registry);
                    }
                    ibex_config::TcpResAction::SetVarFmt { var_name, fmt: _ } => {
                        let val = render_rule_fmt(rc, tcp_ctx, registry);
                        store_var(&mut entry.sess.vars, &rc.var(var_name), val);
                    }
                    ibex_config::TcpResAction::UnsetVar { var_name } => {
                        unset_var(&mut entry.sess.vars, &rc.var(var_name));
                    }
                }
            }
            false
            };
            with_res_hdrs(|hdrs| *hdrs = hidden);
            if tcp_stop {
                break 'rules None;
            }
            CURRENT_RES_STATUS.set(status);

            // 1. The backend's `http-response` rules, then the frontend's when it is another
            // proxy; an `allow` ends only its own list.
            // `http-response capture` writes the frontend's slots, whichever proxy the rule is in.
            // The response side starts with the request's `req.*` variables gone.
            ibex_sample::vars::with_stream(&mut entry.sess.vars, |m| m.clear_scope(ibex_sample::VarScope::Req));
            let fe_res_slots = &proxies[fe_idx].res_capture_slots;
            let mut stopped = None;
            LAST_RULE.set(None);
            for (list, &px) in order.iter().enumerate() {
                if resume.is_some_and(|w| list < w.list) {
                    continue;
                }
                let start = resume.filter(|w| w.list == list).map_or(0, |w| w.rule);
                let rules = proxies[px].http_res_rules.iter().zip(&proxies[px].rules.http_res).map(|(r, rc)| (ResOp::of_res(&r.action, rc), rc.cond.as_ref(), r.line));
                let caps = (!fe_res_slots.is_empty()).then_some((&mut res_caps, &fe_res_slots[..]));
                let mut check = |rule: usize, time_ms: u32, at_least: u32| -> BodyWait {
                    let here = resume.filter(|w| w.list == list && w.rule == rule);
                    if at_least == PAUSE_RULE {
                        // `pause`: the deadline is set once, and the body is not waited for.
                        let deadline = here.map_or_else(|| now.add(time_ms), |w| w.deadline);
                        if (here.is_none() && time_ms == 0) || deadline.is_expired(now) {
                            return BodyWait::Ready;
                        }
                        held = Some(crate::txn::RspWait { list, rule, deadline, inspect: false });
                        return BodyWait::Pending;
                    }
                    let deadline = here.map_or_else(
                        || if time_ms > 0 { now.add(time_ms) } else { Tick::ETERNITY },
                        |w| w.deadline,
                    );
                    let enough = at_least > 0 && res_body.len() >= at_least as usize;
                    let outcome = if body_progress == crate::txn::BodyProgress::Error {
                        BodyWait::Malformed
                    } else if body_progress == crate::txn::BodyProgress::Complete || enough || rep_full {
                        BodyWait::Ready
                    } else if srv_timed_out || (!srv_ended && deadline.is_expired(now)) {
                        BodyWait::TimedOut
                    } else if srv_ended {
                        // Cut short: what is here goes on, and the forwarding tells the
                        // client the response is incomplete.
                        BodyWait::Ready
                    } else {
                        BodyWait::Pending
                    };
                    match outcome {
                        BodyWait::Pending => held = Some(crate::txn::RspWait { list, rule, deadline, inspect: false }),
                        BodyWait::TimedOut => timed_out = true,
                        BodyWait::Malformed => malformed = true,
                        _ => {}
                    }
                    outcome
                };
                match run_res_rules(
                    rules,
                    &proxies[px].acls,
                    (&mut status, &mut status_msg),
                    &mut ctx,
                    caps,
                    registry,
                    &mut entry.sess.vars,
                    Some(ResWait { start, check: &mut check }),
                ) {
                    Err(stop) => {
                        stopped = Some(stop);
                        break;
                    }
                    Ok(Some(_)) => break,
                    Ok(None) => {}
                }
            }
            if let Some(line) = LAST_RULE.take() {
                entry.sess.log.last_rule = Some(line);
            }
            // What the rules captured is what the log line shows, and what the rules after
            // them (`http-after-response`) read.
            entry.sess.log.res_captures.clone_from(&res_caps);
            if stopped.is_some() {
                break 'rules stopped;
            }

            // The backend's `cookie` line: the server's own cookie edited, the persistence
            // cookie inserted (`http_manage_server_side_cookies` and the insertion in
            // `http_process_res_common`), between the `http-response` and the
            // `http-after-response` rules.
            if let Some(cfg) = &proxies[be_idx].cookie {
                let be = &proxies[be_idx];
                let target = entry.target_server_idx.filter(|_| entry.srv_backend_idx == be_idx).map(|i| crate::cookie::Target {
                    value: be.server_cookies.get(i).and_then(Option::as_deref).map(str::as_bytes),
                });
                let method = entry.sess.req_method.as_deref().unwrap_or("");
                let req = crate::cookie::ReqKind {
                    safe_method: matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE"),
                    post: method == "POST",
                };
                let sck = with_res_hdrs(|hdrs| crate::cookie::process_response(cfg, target, &cookie_txn, req, status, unix_now(), hdrs));
                if let Some(txn) = entry.sess.txn.as_mut() {
                    txn.ck.sck = sck;
                }
            }

            // `option checkcache`: a response that may be stored by a cache and sets a cookie is
            // blocked (`http_process_res_common`). The fetches in the rules above may have
            // changed the headers, so this reads them as they now are.
            if proxies[be_idx].ids.checkcache
                && with_res_hdrs(|hdrs| hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("set-cookie")))
                && {
                    let req = crate::cookie::ReqKind {
                        safe_method: matches!(entry.sess.req_method.as_deref().unwrap_or(""), "GET" | "HEAD" | "OPTIONS" | "TRACE"),
                        post: entry.sess.req_method.as_deref() == Some("POST"),
                    };
                    let (cacheable, cook) = with_res_hdrs(|hdrs| crate::cookie::response_cache_flags(req, status, hdrs));
                    cacheable && cook
                }
            {
                let srv = ctx.srv_name.unwrap_or("<dispatch>");
                crate::stderr_line!("[ALERT] Blocking cacheable cookie in response from instance {}, server {}.", proxies[be_idx].name, srv);
                entry.sess.log.checkcache_blocked = true;
                break 'rules Some(ResStop::Page(502));
            }

            // 2. and 3. `http-after-response`, the backend's then the frontend's.
            let after = eval_after_res_rules(
                proxies,
                fe_idx,
                be_idx,
                (&mut status, &mut status_msg),
                &mut ctx,
                Some(&mut res_caps),
                registry,
                &mut entry.sess.vars,
            );
            entry.sess.log.res_captures.clone_from(&res_caps);
            if let Err(stop) = after {
                break 'rules Some(stop);
            }
            None
        };
        if rejected {
            entry.sess.rep.clear();
            if let Some(txn) = entry.sess.txn.as_mut() {
                txn.close_after = true;
                txn.aborted = true;
            }
            return;
        }
        if let Some(wait) = held {
            // Held for the body: the head as the rules so far left it goes back into the
            // buffer, and the rules go on from the wait when the body is here.
            let mut new_hdr = format!("{proto_version} {status} {status_msg}\r\n");
            with_res_hdrs(|hdrs| push_header_lines(&mut new_hdr, hdrs));
            new_hdr.push_str("\r\n");
            note_response_head_write();
            entry.sess.rep.replace_prefix(total_hdr_len, &ibex_regex::bytetext::text_to_bytes(&new_hdr));
            entry.sess.log.res_captures.clone_from(&res_caps);
            if let Some(txn) = entry.sess.txn.as_mut() {
                txn.rsp_wait = Some(wait);
            }
            return;
        }
        if timed_out {
            entry.sess.log.term.get_or_insert(*b"sH");
        }
        if malformed {
            entry.sess.log.term.get_or_insert(*b"PH");
        }
        if let Some(stop) = failed {
            // A rule refused or could not rewrite the server's response: `PH`.
            entry.sess.log.term.get_or_insert(*b"PH");
            // `%B` stays the server's message as it was received: its head and the body
            // that came with it (measured: 51 for `200`, `content-length: 2`, `ok`), not
            // the reply that replaces it (`HttpTxn::response_sent` skips a local one).
            let mut pay = 0;
            // Whether the server's response was all here and its connection fit for another
            // request: a reply that replaces it leaves the connection to the pool then (the
            // rest of a larger response is not read, and the connection is closed).
            let mut srv_msg = MsgState::head(framing);
            let used = srv_msg.advance_counted(entry.sess.rep.readable(), &mut pay);
            let srv_complete = srv_msg.is_done() && used == entry.sess.rep.readable().len() && entry.sess.txn.as_ref().is_some_and(|t| t.srv_reusable);
            if let Some(t) = entry.sess.txn.as_mut().and_then(|t| t.rsp_htx.as_mut()) {
                *t += pay;
            }
            entry.sess.rep.clear();
            match stop {
                ResStop::Page(st) => reply_error(entry, proxies, st),
                ResStop::Empty(st) => reply_empty(entry, proxies, st),
                ResStop::Reply(raw) => {
                    // A redirect is the proxy's own answer, not a refusal: `LH` (measured).
                    entry.sess.log.term = Some(*b"LH");
                    let be_idx = if entry.backend_idx < proxies.len() { entry.backend_idx } else { entry.proxy_idx };
                    send_proxy_reply(&mut entry.sess, proxies, entry.proxy_idx, be_idx, &raw);
                }
                ResStop::Return { status, content_type, reply, page, error_page } => {
                    // The server's response is already truncated when the reply is built
                    // (`http_reply_message`): its status and headers fetch as nothing.
                    CURRENT_RES_STATUS.set(0);
                    CURRENT_RES_HEADERS.with(|h| crate::reuse::clear_pairs(&mut h.borrow_mut()));
                    let res_ctx = SampleContext { res_version: None, ..ctx.clone() };
                    let be_idx = if entry.backend_idx < proxies.len() { entry.backend_idx } else { entry.proxy_idx };
                    let raw: Vec<u8> = match resolve_error_body(&proxies[be_idx], &proxies[entry.proxy_idx], status, error_page.as_ref(), content_type.as_ref(), reply.as_deref(), page.as_deref()) {
                        ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                        ResolvedErrorBody::Custom { content_type, reply } => build_templated_error_response(status, content_type, reply, None, &res_ctx, registry),
                    };
                    // The proxy's own answer, not a refusal: `LH`.
                    entry.sess.log.term = Some(*b"LH");
                    send_proxy_reply(&mut entry.sess, proxies, entry.proxy_idx, be_idx, &raw);
                    if let Some(t) = entry.sess.txn.as_mut() {
                        t.keeps_srv = srv_complete;
                    }
                }
                // The response is read and counted (its status is the log's) but never sent:
                // `PR`, `dreq` on the frontend and the backend (measured).
                ResStop::SilentDrop => {
                    entry.sess.log.term = Some(*b"PR");
                    proxies[entry.proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    proxies[entry.backend_idx.min(proxies.len() - 1)].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                    entry.sess.refuse_request(true, is_ipv6, 0);
                    if let Some(txn) = entry.sess.txn.as_mut() {
                        txn.close_after = true;
                        txn.aborted = true;
                    }
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                }
            }
            return;
        }

        // What the rules did to the framing and to `Connection`, read again as `HAProxy` reads
        // it when it writes the head out (`h1_make_eoh`, `src/mux_h1.c`; T439): a response
        // left with no length, or a `close` a rule wrote, closes the client connection.
        let was = entry.sess.txn.as_ref().map_or_else(Default::default, |t| t.rsp_len_hdrs);
        // A `keep-alive` a rule wrote keeps the connection `option httpclose` alone would close
        // (`h1_set_cli_conn_mode`, T442).
        let (rule_close, rule_kal) = with_res_hdrs(|hdrs| crate::txn::reread_response_after_rules(hdrs, was, status));
        let client_close = if rule_close && !tunnel {
            if let Some(t) = entry.sess.txn.as_mut() {
                t.close_after = true;
            }
            true
        } else if rule_kal && !tunnel && entry.sess.txn.as_ref().is_some_and(|t| t.close_opt) {
            if let Some(t) = entry.sess.txn.as_mut() {
                t.close_after = false;
            }
            false
        } else {
            client_close
        };
        // A chunked body whose `Transfer-Encoding` the rules removed goes without its chunk
        // framing, until the end of the message (`h1_process_emit_headers`, T442).
        if framing == crate::txn::Framing::Chunked && was.chnk && !with_res_hdrs(|hdrs| hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))) {
            if let Some(t) = entry.sess.txn.as_mut() {
                t.rsp_dechunk = Some(Box::new(crate::txn::Chunk::START));
            }
        }
        // The same `Connection` handling as without rules, on the headers the rules left.
        // The head written again into the string it was read from, from the list the
        // fetches read (left there for the ones after, the log's).
        let mut new_hdr = hdr_str;
        new_hdr.clear();
        new_hdr.push_str(&proto_version);
        new_hdr.push(' ');
        push_status(&mut new_hdr, status);
        new_hdr.push(' ');
        new_hdr.push_str(&status_msg);
        new_hdr.push_str("\r\n");
        with_res_hdrs(|hdrs| {
            crate::txn::apply_response_connection(hdrs, srv_http11, client_close, req_http11, tunnel || status < 100);
            push_header_lines(&mut new_hdr, hdrs);
        });
        new_hdr.push_str("\r\n");

        note_response_head_write();
        entry.sess.rep.replace_prefix(total_hdr_len, &ibex_regex::bytetext::text_to_bytes(&new_hdr));
        set_rsp(entry);
    }

    /// `stats_check_uri`: only GET, HEAD and POST reach the stats applet; any other method
    /// is an ordinary request (a PUT to the stats URI goes to the backend).
    fn stats_method_ok(sess: &TcpSession) -> bool {
        matches!(sess.req_method.as_deref(), Some("GET" | "HEAD" | "POST"))
    }

    fn is_stats_request(req_uri: &str, configured_uri: Option<&str>) -> bool {
        match configured_uri {
            Some(uri) => {
                if uri.contains('?') {
                    req_uri == uri
                        || req_uri.starts_with(&format!("{uri}/"))
                        || req_uri.starts_with(&format!("{uri};"))
                        || req_uri.starts_with(&format!("{uri}&"))
                        || req_uri.starts_with(&format!("{uri}?"))
                } else {
                    let trimmed_uri = uri.trim_end_matches('/');
                    let base = if trimmed_uri.is_empty() {
                        "/"
                    } else {
                        trimmed_uri
                    };
                    if base == "/" {
                        req_uri == "/"
                            || req_uri.starts_with("/;csv")
                            || req_uri.starts_with("/api/data")
                    } else {
                        req_uri == base
                            || req_uri.starts_with(&format!("{base}/"))
                            || req_uri.starts_with(&format!("{base};"))
                            || req_uri.starts_with(&format!("{base}?"))
                    }
                }
            }
            None => {
                req_uri == "/stats"
                    || req_uri.starts_with("/stats/")
                    || req_uri.starts_with("/stats;")
                    || req_uri.starts_with("/stats?")
                    || req_uri == "/haproxy?stats"
                    || req_uri.starts_with("/haproxy?stats/")
                    || req_uri.starts_with("/haproxy?stats;")
                    || req_uri.starts_with("/haproxy?stats&")
            }
        }
    }

    /// What a `stats` rule's condition and its `http-error` template see of the stream: the
    /// request line, headers, addresses, and the proxy as frontend and backend.
    fn stats_ctx<'a>(sess: &'a crate::proxy::TcpSession, view: &'a ProxiesView<'a>, serving: usize) -> SampleContext<'a> {
        let proxies = view.0;
        let name = proxies[serving].name.as_str();
        SampleContext {
            proxies: Some(view),
            client_addr: sess.client_addr,
            server_addr: sess.server_addr,
            fc_src: sess.fc_src(),
            fc_dst: sess.fc_dst(),
            is_first_req: sess.is_first_req,
            ssl_fc: crate::proxy::ssl_fc(&sess.cli_xprt, sess.h2_role.as_deref()),
            quic_acks: sess.quic_facts(),
            fc_http_major: sess.fc_http_major(),
            req_version: sess.client_version(),
            req_uri: sess.req_uri.as_deref(),
            req_method: sess.req_method.as_deref(),
            htx_slice: sess.htx_slice(),
            req_headers: sess.req_headers.as_deref(),
            fe_name: Some(name),
            fe_id: Some(proxies[serving].ids.iid),
            be_name: Some(name),
            be_id: Some(proxies[serving].ids.iid),
            acls: Some(&proxies[serving].acls),
            ..Default::default()
        }
    }

    /// Whether a `stats` rule's condition holds for the request (no condition: always). The
    /// condition sees the request line, headers and addresses of the stream.
    fn stats_cond_holds(sess: &crate::proxy::TcpSession, proxies: &Proxies, serving: usize, cond: Option<&ibex_config::AclCondition>) -> bool {
        let registry = sample_registry();
        let Some(cond) = cond else { return true };
        let view = ProxiesView(proxies);
        let ctx = Self::stats_ctx(sess, &view, serving);
        eval_condition(cond, &ctx, &proxies[serving].acls, registry)
    }

    /// `stats http-request` (and the rule `stats auth` became): the first rule whose condition
    /// holds answers. `allow` serves the page, `deny` and `auth` reply and return true; no
    /// rule matching serves it (`http_req_get_intercept_rule` over `uri_auth->http_req_rules`).
    /// The condition sees the request line, headers and addresses of the stream.
    fn stats_rules_reply(entry: &mut SessionEntry, proxies: &Proxies, serving: usize) -> bool {
        let rules = proxies[serving].stats_config.http_req_rules();
        if rules.is_empty() {
            return false;
        }
        let registry = sample_registry();
        let sess = &mut entry.sess;
        for rule in rules {
            let matches = Self::stats_cond_holds(sess, proxies, serving, rule.cond.as_ref());
            if !matches {
                continue;
            }
            let (status, realm) = match &rule.action {
                ibex_config::HttpReqAction::Deny { deny_status, .. } => {
                    proxies[serving].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    (deny_status.unwrap_or(403), None)
                }
                ibex_config::HttpReqAction::Auth { realm } => (401, Some(realm.as_deref().unwrap_or("HAProxy Statistics"))),
                // `allow` (the parser lets nothing else in): the page follows.
                _ => return false,
            };
            let mut resp: Vec<u8> = match resolve_error_body(&proxies[serving], &proxies[serving], status, Some(&ibex_config::ErrorPageSource::DefaultErrorfiles), None, None, None) {
                ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                // An `http-error` template, rendered for the stream (T450).
                ResolvedErrorBody::Custom { content_type, reply } => {
                    {
                        // `%s` is `<STATS>` for a stream the stats applet serves.
                        let view = ProxiesView(proxies);
                        let ctx = Self::stats_ctx(sess, &view, serving);
                        let data = crate::logfmt::LogData { server: Some("<STATS>"), ..crate::logfmt::LogData::of_context(&ctx) };
                        build_templated_error_response(status, content_type, reply, Some(&data), &ctx, registry)
                    }
                }
            };
            if let Some(realm) = realm {
                resp = with_header_at_end_of_head(&resp, &format!("www-authenticate: Basic realm=\"{realm}\""));
            }
            send_proxy_reply(sess, &proxies[..], serving, serving, &resp);
            return true;
        }
        false
    }

    /// `stats admin`: the page is administrable when a `stats admin` line has no condition or
    /// its condition holds (`uri_auth->admin_rules`, `http_handle_stats`).
    fn stats_admin_allowed(sess: &crate::proxy::TcpSession, proxies: &Proxies, serving: usize) -> bool {
        let cfg = &proxies[serving].stats_config;
        // No rule recorded (a configuration built without the parser) is `stats admin` alone.
        cfg.admin && (cfg.admin_rules.is_empty() || cfg.admin_rules.iter().any(|c| Self::stats_cond_holds(sess, proxies, serving, c.as_ref())))
    }

    /// The stats page's URI prefix as the redirect and the banner's link name it, with the
    /// flags of the request that stay (`;up`, and `;norefresh` when the page refreshes).
    fn stats_self_link(proxies: &[Proxy], serving: usize, req_uri: &str) -> String {
        let cfg = &proxies[serving].stats_config;
        let prefix = cfg.uri.as_deref().unwrap_or("/haproxy?stats");
        let rest = req_uri.get(prefix.len()..).unwrap_or("");
        let mut link = String::from(prefix);
        if rest.contains(";up") {
            link.push_str(";up");
        }
        if cfg.refresh.is_some() && rest.contains(";norefresh") {
            link.push_str(";norefresh");
        }
        link
    }

    /// `stats_send_http_redirect`: the answer to an admin POST, whatever came of it.
    fn stats_redirect(entry: &mut SessionEntry, proxies: &Proxies, serving: usize, code: crate::stats_post::StCode) {
        let req_uri = entry.sess.req_uri.as_deref().unwrap_or("/");
        let cfg = &proxies[serving].stats_config;
        let prefix = cfg.uri.as_deref().unwrap_or("/haproxy?stats");
        let rest = req_uri.get(prefix.len()..).unwrap_or("");
        let mut loc = format!("{prefix};st={}", code.name());
        if rest.contains(";up") {
            loc.push_str(";up");
        }
        if cfg.refresh.is_some() && rest.contains(";norefresh") {
            loc.push_str(";norefresh");
        }
        let resp = format!(
            "HTTP/1.1 303 See Other\r\ncache-control: no-cache\r\ncontent-type: text/plain\r\ncontent-length: 0\r\nlocation: {loc}\r\nconnection: close\r\n\r\n"
        );
        stats_write_reply(entry, proxies, resp.as_bytes());
    }

    /// The banner a `;st=<CODE>` in the URI asks the HTML page for.
    fn stats_st_code(proxies: &Proxies, serving: usize, req_uri: &str) -> Option<crate::stats_post::StCode> {
        let prefix = proxies[serving].stats_config.uri.as_deref().unwrap_or("/haproxy?stats");
        crate::stats_post::StCode::from_uri(req_uri.get(prefix.len()..).unwrap_or(""))
    }

    /// The text of that banner, linking back to the page as the request asked for it.
    pub(crate) fn stats_banner(proxies: &[Proxy], serving: usize, req_uri: &str, code: crate::stats_post::StCode) -> String {
        code.banner(&Self::stats_self_link(proxies, serving, req_uri))
    }

    /// The request's header lines, from the HTX message or, without one, the parsed list.
    fn stats_req_headers(sess: &crate::proxy::TcpSession) -> Vec<(&str, &str)> {
        match (sess.htx_slice(), sess.req_headers.as_deref()) {
            (Some(htx), _) => htx.headers().collect(),
            (None, Some(h)) => h.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
            (None, None) => Vec::new(),
        }
    }

    /// An admin POST as `stats_process_http_post` handles it; the code is the answer.
    fn stats_admin_post(
        entry: &SessionEntry,
        proxies: &Proxies,
        checks: &mut [ServerCheckState],
        now: Tick,
        body: &str,
        nhdr: usize,
        head_len: usize,
        declared: usize,
    ) -> crate::stats_post::StCode {
        use crate::stats_post::{process_post, StCode, Verb};
        if !crate::stats_post::fits_buffer(entry.sess.bufsize, head_len, nhdr, body.len().max(declared)) {
            return StCode::Excd;
        }
        let mut backend = |name: &str| proxies.iter().position(|p| p.has_backend && p.name == name);
        let mut apply = |p: usize, verb: Verb, name: &str| -> Option<bool> {
            let s = proxies[p].server_ids.iter().position(|id| id == name)?;
            let cur = proxies[p].server_statuses.get(s).map_or(0, |a| a.load(Ordering::Relaxed));
            let maint = ServerStatus::from(cur) == ServerStatus::Maint;
            let drain = cur == check::DRAIN_DOWN || cur == ServerStatus::Drain as u8;
            let set = |to: ServerStatus, cause: crate::srvlog::Cause<'_>, checks: &mut [ServerCheckState]| {
                crate::track::apply_admin(proxies, checks, p, s, to, cause);
                true
            };
            use crate::srvlog::Cause as C;
            Some(match verb {
                Verb::Ready => set(ServerStatus::Up, C::Web, checks),
                Verb::Drain => set(ServerStatus::Drain, C::Web, checks),
                Verb::Maint => set(ServerStatus::Maint, C::Web, checks),
                Verb::Disable => !maint && set(ServerStatus::Maint, C::WebDisable, checks),
                Verb::Enable => maint && set(ServerStatus::Up, C::Web, checks),
                // A server in maintenance keeps its state: Ibex has one admin state, HAProxy
                // two flags (the drain flag is set under the maintenance one).
                Verb::Stop => !drain && (maint || set(ServerStatus::Drain, C::WebStop, checks)),
                Verb::Start => drain && set(ServerStatus::Up, C::Web, checks),
                Verb::Dhlth => set_health_check_enabled(checks, proxies, &proxies[p].name, name, false, now),
                Verb::Ehlth => set_health_check_enabled(checks, proxies, &proxies[p].name, name, true, now),
                Verb::Hrunn | Verb::Hdown => {
                    if crate::track::is_tracking(proxies, p, s) {
                        false
                    } else {
                        crate::track::apply_health(proxies, checks, p, s, verb == Verb::Hrunn, C::Web);
                        true
                    }
                }
            })
        };
        process_post(body, &mut backend, &mut apply)
    }

    #[allow(clippy::too_many_lines)]
    fn handle_stats_request(
        entry: &mut SessionEntry,
        proxies: &mut Proxies,
        checks: &mut [ServerCheckState],
        pid: u32,
        now: Tick,
        serving: usize,
    ) -> Option<crate::stats_html::AdminAction> {
        entry.sess.log.applet = true;
        if Self::stats_rules_reply(entry, proxies, serving) {
            return None;
        }
        // The page, the redirect and the banner are the applet's answers: `LR`.
        entry.sess.log.term.get_or_insert(*b"LR");
        let req_uri = entry.sess.req_uri.as_deref().unwrap_or("/");

        // `stats refresh`: HAProxy sends `Refresh: <seconds, rounded up>` unless the URI carries
        // `;norefresh` (stats-html.c, uri->refresh).
        let refresh = match proxies[serving].stats_config.refresh {
            Some(d) if !d.is_zero() && !req_uri.contains(";norefresh") => {
                format!("refresh: {}\r\n", d.as_millis().div_ceil(1000))
            }
            _ => String::new(),
        };

        // An admin POST: refused unless the page is administrable and the request is not a
        // cross-site one; the form's own verbs are `stats_process_http_post`'s, answered by a
        // redirect to the page. The dashboard's script (JSON requests) and the verbs only Ibex
        // has (weight, maxconn, counters, sessions) go on below.
        let is_post = entry.sess.req_method.as_deref() == Some("POST");
        let admin_ok = is_post && Self::stats_admin_allowed(&entry.sess, proxies, serving);
        if is_post {
            let hdrs = Self::stats_req_headers(&entry.sess);
            let same_origin = crate::stats_post::same_origin(&hdrs);
            if !admin_ok || !same_origin {
                Self::stats_redirect(entry, proxies, serving, crate::stats_post::StCode::Deny);
                return None;
            }
            let body = entry.sess.req.eoh()
                .map(|(h, e)| String::from_utf8_lossy(entry.sess.req.readable().get(h + e..).unwrap_or(&[])).into_owned())
                .unwrap_or_default();
            let legacy = body.trim().starts_with('{')
                || crate::stats_post::uses_ibex_keys(&body)
                || req_uri.contains("/api/")
                || hdrs.iter().any(|(k, v)| {
                    (k.eq_ignore_ascii_case("accept") || k.eq_ignore_ascii_case("content-type")) && v.contains("application/json")
                })
                || crate::stats_html::parse_admin_action("", &body).is_some_and(|c| {
                    matches!(
                        c.action.as_str(),
                        "weight" | "maxconn" | "clear_counters" | "kill_sessions" | "shutdown_sessions" | "enable_health" | "disable_health"
                    )
                });
            if !legacy {
                let code = {
                    let head_len = entry.sess.req.eoh().map_or(0, |(h, e)| h + e);
                    // The body that fits counts as the whole of it: what the client declares is the size.
                    let declared = hdrs
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    Self::stats_admin_post(entry, proxies, checks, now, &body, hdrs.len(), head_len, declared)
                };
                Self::stats_redirect(entry, proxies, serving, code);
                return None;
            }
        }

        // 0. `;json-schema` and `;json` (`stats-json.c`): the CLI's `show stat json` rows, and
        // the schema that describes them. Looked at before `;csv`, as `HAProxy` does.
        if req_uri.contains(";json-schema") {
            let page = crate::stats_stream::Page::Text(include_str!("stats_json_schema.json"), false);
            stats_stream_page(entry, proxies, checks, pid, serving, "application/json", &refresh, page);
            return None;
        }
        if req_uri.contains(";json") {
            let page = crate::stats_stream::Page::Rows(crate::stats::StatCursor::page(crate::stats::StatFormat::Json, proxies[serving].stats_config.show_legends));
            stats_stream_page(entry, proxies, checks, pid, serving, "application/json", &refresh, page);
            return None;
        }

        // `;typed` (`stats-html.c`): the CLI's `show stat typed` rows; after `;json`, before `;csv`.
        if req_uri.contains(";typed") {
            let page = crate::stats_stream::Page::Rows(crate::stats::StatCursor::page(crate::stats::StatFormat::Typed, proxies[serving].stats_config.show_legends));
            stats_stream_page(entry, proxies, checks, pid, serving, "text/plain", &refresh, page);
            return None;
        }

        // 1. CSV telemetry
        if req_uri.contains(";csv") || req_uri.ends_with("/csv") {
            let page = crate::stats_stream::Page::Rows(crate::stats::StatCursor::page(crate::stats::StatFormat::Csv, proxies[serving].stats_config.show_legends));
            stats_stream_page(entry, proxies, checks, pid, serving, "text/plain", &refresh, page);
            return None;
        }

        // 2. JSON API data for live auto-refresh
        if req_uri.contains("/api/data") || req_uri.ends_with("/data") {
            let page = crate::stats_stream::Page::Json(crate::stats_html::JsonCursor::new());
            stats_stream_page(entry, proxies, checks, pid, serving, "application/json", &refresh, page);
            return None;
        }

        // 3. Admin mutations
        let body_str =
            if let Some((hdr_len, eoh_len)) = entry.sess.req.eoh() {
                let total = hdr_len + eoh_len;
                if entry.sess.req.readable().len() > total {
                    String::from_utf8_lossy(&entry.sess.req.readable()[total..]).to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

        let query_str = req_uri.split_once('?').map_or("", |x| x.1);
        let admin_cmd = crate::stats_html::parse_admin_action(query_str, &body_str).filter(|_| admin_ok && is_post);

        if let Some(cmd) = admin_cmd {
            let is_json_req = req_uri.contains("/api/")
                || body_str.trim().starts_with('{')
                || entry.sess.req_headers.as_ref().is_some_and(|hdrs| {
                    hdrs.iter().any(|(k, v)| {
                        (k.eq_ignore_ascii_case("accept") || k.eq_ignore_ascii_case("content-type"))
                            && v.contains("application/json")
                    })
                });

            match cmd.action.as_str() {
                "clear_counters" => {
                    let target = cmd.backend.as_deref().or(cmd.server.as_deref());
                    let _ = clear_proxy_counters(proxies, target);
                }
                "enable_health" => {
                    if let Some(be) = cmd.backend.as_deref() {
                        if let Some(sv) = cmd.server.as_deref() {
                            let _ = set_health_check_enabled(checks, proxies, be, sv, true, now);
                        }
                    }
                }
                "disable_health" => {
                    if let Some(be) = cmd.backend.as_deref() {
                        if let Some(sv) = cmd.server.as_deref() {
                            let _ = set_health_check_enabled(checks, proxies, be, sv, false, now);
                        }
                    }
                }
                "maxconn" => {
                    if let Some(mc) = cmd.maxconn {
                        if let Some(be) = cmd.backend.as_deref() {
                            let _ = set_proxy_maxconn(proxies, be, cmd.server.as_deref(), mc);
                        }
                    }
                }
                "kill_sessions" | "shutdown_sessions" => {
                    // Deferred to caller
                }
                _ => {
                    let target_backend = cmd.backend.as_deref();
                    let target_server = cmd.server.as_deref();

                    let mut status_changes = Vec::new();
                    // The stats page's admin form: it writes the shared proxies, which
                    // every worker reads (T177).
                    for (p_idx, proxy) in proxies.iter().enumerate() {
                        if target_backend.is_none() || target_backend == Some(proxy.name.as_str()) {
                            let mut weight_changes = Vec::new();
                            for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                                if target_server.is_none() || target_server == Some(sid.as_str()) {
                                    let new_status = match cmd.action.as_str() {
                                        "ready" | "up" | "enable" => Some(ServerStatus::Up),
                                        "drain" => Some(ServerStatus::Drain),
                                        "maint" | "down" | "disable" => Some(ServerStatus::Maint),
                                        _ => None,
                                    };
                                    if let Some(st) = new_status {
                                        status_changes.push((p_idx, s_idx, st));
                                    }
                                    if let Some(w) = cmd.weight {
                                        weight_changes.push((s_idx, w));
                                    }
                                    if let Some(mc) = cmd.maxconn {
                                        proxy.server_maxconn.set(s_idx, Some(mc));
                                    }
                                }
                            }
                            for (s_idx, w) in weight_changes {
                                proxy.set_weight(s_idx, w);
                            }
                        }
                    }
                    for (p_idx, s_idx, st) in status_changes {
                        crate::track::apply_admin(proxies, checks, p_idx, s_idx, st, crate::srvlog::Cause::Web);
                    }
                }
            }

            if is_json_req {
                let body = r#"{"status":"ok","message":"Admin action applied"}"#;
                stats_write_page(entry, proxies, "application/json", &refresh, body.as_bytes());
                return Some(cmd);
            }

            let page = crate::stats_stream::Page::Html(crate::stats_html::HtmlCursor::new(), Self::stats_st_code(proxies, serving, req_uri));
            stats_stream_page(entry, proxies, checks, pid, serving, "text/html", &refresh, page);
            return Some(cmd);
        }

        // 4. Default: Render full HTML dashboard
        let page = crate::stats_stream::Page::Html(crate::stats_html::HtmlCursor::new(), Self::stats_st_code(proxies, serving, req_uri));
        stats_stream_page(entry, proxies, checks, pid, serving, "text/html", &refresh, page);
        None
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
    fn connect_http_backend(
        entry: &mut SessionEntry,
        proxies: &mut Proxies,
        checks: &mut [ServerCheckState],
        pid: u32,
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
        now: Tick,
    ) -> Option<crate::stats_html::AdminAction> {
        let proxy_idx = entry.proxy_idx;
        // A request held for its body (`wait-for-body`) comes back here when the body is
        // here, and goes on from the rule it stopped at: what ran before it (routing the
        // request, counting it, the rules ahead of the wait) is not run again.
        let resume = entry.sess.txn.as_ref().and_then(|t| t.body_wait);
        let resume_be = resume.is_some_and(|w| w.backend);
        if resume.is_none() {
            // Until a backend is chosen the frontend stands in for it, as `s->be` does in
            // HAProxy: an error page picked before routing comes from the frontend.
            entry.backend_idx = proxy_idx;
            // Each request is a new stream in HAProxy, with the retry budget of its proxy
            // (`stream_new`); what the last request spent or `set-retries` does not carry over.
            entry.sess.set_retries(proxies[proxy_idx].retries);
        }
        // `proxy_inc_fe_req_ctr`: the request counts for the frontend before any rule sees it.
        if resume.is_none() {
            proxies[proxy_idx].counters().fe_req_rate.tick();
            let rate = proxies[proxy_idx].counters().fe_req_rate.rate();
            proxies[proxy_idx].txn_counters().fe.req_rate_max.fetch_max(u32::try_from(rate).unwrap_or(u32::MAX), Ordering::Relaxed);
        }

        // The stream's variables are in `CURRENT_VARS` for this whole run (`step_stream`).
        if resume.is_none() {
            begin_http_stream(entry, proxies, proxy_idx, pid);
        }
        // Until a backend is chosen the frontend's timeouts are the backend's too.
        stream_timeouts_enter(proxies, proxy_idx, entry.backend_idx, &entry.sess);
        STRICT_MODE.set(true);

        // `monitor-uri`: answer the probe here, before any rule or backend sees it. The
        // response is HAProxy's, byte for byte (`src/http_ana.c`), and matches the path of
        // an absolute-form request too.
        if let Some(mon) = proxies[proxy_idx].monitor.as_deref().filter(|_| resume.is_none()) {
            let m_uri = &*mon.uri;
            let req_uri = entry.sess.req_uri.as_deref().unwrap_or("/");
            let path = if m_uri.starts_with('/') && req_uri.contains("://") {
                split_uri(req_uri).1
            } else {
                req_uri
            };
            if path == m_uri {
                // `monitor fail if|unless <cond>` (`http_wait_for_request`): any condition that
                // holds makes the answer a 503, which goes through the proxy's error page
                // (`errorfile`, `errorloc`) like any error the proxy generates.
                let failed = !mon.fail.is_empty() && {
                    let proxy = &proxies[proxy_idx];
                    let view = ProxiesView(proxies);
                    let stick = StickView::new(proxies, &entry.sess.tracked_sc);
                    let ctx = Self::request_ctx(&entry.sess, proxy, &view, &stick);
                    let registry = sample_registry();
                    mon.fail.iter().any(|c| crate::proxy::eval_acl_condition(c, &proxy.acls, registry, &ctx))
                };
                if failed {
                    reply_error(entry, proxies, 503);
                } else {
                    send_proxy_reply(&mut entry.sess, proxies, proxy_idx, proxy_idx, MONITOR_URI_RESPONSE);
                }
                return None;
            }
        }

        let registry = sample_registry();

        // 1. Stick table tracking from http_req_rules

        // Only the `track-sc` rules read it: a proxy without one builds none (T584).
        let has_track = resume.is_none()
            && proxies[proxy_idx].http_req_rules.iter().any(|r| {
                matches!(r.action, ibex_config::HttpReqAction::TrackSc0 { .. } | ibex_config::HttpReqAction::TrackSc1 { .. } | ibex_config::HttpReqAction::TrackSc2 { .. })
            });
        let track_view = ProxiesView(proxies);
        let http_sample_ctx = if has_track {
            if cfg!(debug_assertions) {
                ibex_sample::work::note(ibex_sample::work::Op::TrackCtx, 1);
            }
            Some(SampleContext {
            proxies: Some(&track_view),
            client_addr: entry.sess.client_addr,
            server_addr: entry.sess.server_addr,
            fc_src: entry.sess.fc_src(),
            so_name: entry.sess.so_name.as_deref(),
            so_id: entry.sess.so_id,
            fc_dst: entry.sess.fc_dst(),
            is_first_req: entry.sess.is_first_req,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: crate::proxy::ssl_fc(&entry.sess.cli_xprt, entry.sess.h2_role.as_deref()),
            quic_acks: entry.sess.quic_facts(),
            fc_http_major: entry.sess.fc_http_major(),
            bc_http_major: entry.sess.bc_http_major(),
            req_version: entry.sess.client_version(),
            ssl_bc: entry.sess.srv_xprt.ssl_facts(),
            req_uri: entry.sess.req_uri.as_deref(),
            req_method: entry.sess.req_method.as_deref(),
            req_headers: entry.sess.req_headers.as_deref(),
            // `track-sc0 req.hdr(x-key)` reads the request's HTX. Built from the fields
            // rather than by `htx_slice()`, which would borrow the whole session while the
            // rules below set its `tracked_sc`.
            htx_slice: entry.sess.has_htx.then(|| ibex_proto::htx::HtxSliceRef::new(entry.sess.htx_buf.raw_slice(), entry.sess.htx_blocks)),
            fe_name: Some(&proxies[proxy_idx].name),
            fe_id: Some(proxies[proxy_idx].ids.iid),
            act_conn: proxies[proxy_idx].counters().act_conn.load(Ordering::Relaxed),
            unique_id: entry.sess.log.unique_id.as_deref(),
            accept_date: Some(entry.sess.log.date()),
            captures_req_hdr: Some(&entry.sess.log.req_captures),
            captures_res_hdr: Some(&entry.sess.log.res_captures),
            ..Default::default()
            })
        } else {
            None
        };

        // Only the `track-sc` rules: the condition of any other is evaluated once, in its turn
        // below (S7: each was evaluated twice per request, its ACLs looked up by name).
        let track_rules = proxies[proxy_idx].http_req_rules.iter().zip(&proxies[proxy_idx].rules.http_req).filter(|(r, _)| {
            resume.is_none() && matches!(r.action, ibex_config::HttpReqAction::TrackSc0 { .. } | ibex_config::HttpReqAction::TrackSc1 { .. } | ibex_config::HttpReqAction::TrackSc2 { .. })
        });
        for (rule, rc) in track_rules {
            let Some(http_sample_ctx) = http_sample_ctx.as_ref() else { break };
            if !rc.cond.as_ref().is_none_or(|cond| cond.eval(http_sample_ctx, &proxies[proxy_idx].acls, registry)) {
                continue;
            }
            match &rule.action {
                ibex_config::HttpReqAction::TrackSc0 { table, expr: _ } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_stick_key(rc.expr.as_ref(), registry, http_sample_ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                        track_http_slot(proxies, &mut entry.sess.tracked_sc, 0, t_idx, k);
                    }
                }
                ibex_config::HttpReqAction::TrackSc1 { table, expr: _ } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_stick_key(rc.expr.as_ref(), registry, http_sample_ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                        track_http_slot(proxies, &mut entry.sess.tracked_sc, 1, t_idx, k);
                    }
                }
                ibex_config::HttpReqAction::TrackSc2 { table, expr: _ } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_stick_key(rc.expr.as_ref(), registry, http_sample_ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                        track_http_slot(proxies, &mut entry.sess.tracked_sc, 2, t_idx, k);
                    }
                }
                _ => {}
            }
        }

        // Count HTTP request into all active tracked slots, and credit them the bytes of the
        // requests that are over.
        if resume.is_none() {
            // One update per slot: the request, and the bytes of the ones that are over.
            let (din, dout) = stick_bytes_due(&entry.sess, false);
            entry.sess.stick_acct_in += din;
            entry.sess.stick_out_pending = 0;
            for_tracked(proxies, &entry.sess, |data| {
                data.count_request();
                data.add_bytes(din, dout);
            });
        }

        let stick = StickView::new(proxies, &entry.sess.tracked_sc);
        let act_conn = proxies[proxy_idx].counters().act_conn.load(Ordering::Relaxed);
        // The stream a `do-resolve` wakes (T489).
        let my_task = entry.task;
        let eval_http_rules_held = |rules: &[ibex_config::HttpReqRule], compiled: &[crate::rule_compiled::Rule], acls: &ibex_sample::Acls, sess: &mut TcpSession, be_retries: u16, fe_name: Option<&str>, be_name: Option<&str>, pages_idx: usize, be_stage: bool, start: usize| -> Result<RuleFlow, u16> {
            macro_rules! make_ctx {
                ($s:expr) => {
                    SampleContext {
                        proxies: Some(&ProxiesView(proxies)),
                        client_addr: $s.client_addr,
                        server_addr: $s.server_addr,
                        fc_src: $s.fc_src(),
                        so_name: $s.so_name.as_deref(),
                        so_id: $s.so_id,
                        fc_dst: $s.fc_dst(),
                        is_first_req: $s.is_first_req,
                        proxy_tlvs: $s.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
                        ssl_fc: crate::proxy::ssl_fc(&$s.cli_xprt, $s.h2_role.as_deref()),
                        quic_acks: $s.quic_facts(),
                        fc_http_major: $s.fc_http_major(),
                        bc_http_major: $s.bc_http_major(),
                        req_version: $s.client_version(),
                        ssl_bc: $s.srv_xprt.ssl_facts(),
                        htx: None,
                        htx_slice: $s.htx_slice(),
                        req_uri: $s.req_uri.as_deref(),
                        req_method: $s.req_method.as_deref(),
                        req_headers: $s.req_headers.as_deref(),
                        req_body: $s.txn.as_ref().and_then(|t| t.req_body.as_deref()),
                        fe_name,
                        be_name,
                        fe_id: fe_name.and_then(|n| proxies.iter().find(|p| p.has_frontend && p.name == n)).map(|p| p.ids.iid),
                        be_id: be_name.and_then(|n| proxies.iter().find(|p| p.has_backend && p.name == n)).map(|p| p.ids.iid),
                        captures_req_hdr: Some(&$s.log.req_captures),
                        unique_id: $s.log.unique_id.as_deref(),
                        accept_date: Some($s.log.date()),
                        request_date: Some(request_date(&$s.log)),
                        last_rule: last_rule_at($s.log.last_rule),
                        prio: ($s.log.prio_class, $s.log.prio_offset),
                        be_max_retries: Some(be_retries),
                        term_state: Some(sess_term_state(&$s)),
                        cur_max_retries: Some($s.max_retries),
                        acls: Some(acls),
                        act_conn,
                        stick: Some(&stick),
                        ..Default::default()
                    }
                };
            }

            // Each list starts strict (`http_req_get_intercept_rule` clears
            // `HTTP_MSGF_SOFT_RW`) and sizes the request as it is now.
            STRICT_MODE.set(true);
            req_htx_init(sess);
            for (rule_idx, (rule, rc)) in rules.iter().zip(compiled).enumerate().skip(start) {
                // Compiled with the proxy (S7): nothing is looked up by its text.
                let matches = rc.cond.as_ref().is_none_or(|cond| cond.eval(&make_ctx!(sess), acls, registry));
                if !matches {
                    continue;
                }
                if matches!(
                    rule.action,
                    ibex_config::HttpReqAction::Return { .. }
                        | ibex_config::HttpReqAction::UseServicePrometheus
                        | ibex_config::HttpReqAction::Deny { .. }
                        | ibex_config::HttpReqAction::Allow
                        | ibex_config::HttpReqAction::Auth { .. }
                        | ibex_config::HttpReqAction::Redirect { .. }
                        | ibex_config::HttpReqAction::Tarpit { .. }
                        | ibex_config::HttpReqAction::Reject
                        | ibex_config::HttpReqAction::SilentDrop
                        | ibex_config::HttpReqAction::SilentDropTtl(_)
                ) {
                    note_last_rule(sess, rule.line);
                }

                // Only the edits that read nothing of the request buffer go on holding its head.
                let edit_only = matches!(
                    rule.action,
                    ibex_config::HttpReqAction::SetHeader { .. }
                        | ibex_config::HttpReqAction::AddHeader { .. }
                        | ibex_config::HttpReqAction::DelHeader { .. }
                        | ibex_config::HttpReqAction::ReplaceHeader { .. }
                        | ibex_config::HttpReqAction::ReplaceValue { .. }
                        | ibex_config::HttpReqAction::SetVar { .. }
                        | ibex_config::HttpReqAction::DoResolve(_)
                        | ibex_config::HttpReqAction::SetVarFmt { .. }
                        | ibex_config::HttpReqAction::UnsetVar { .. }
                );
                if !edit_only {
                    flush_req_rebuild(sess, true);
                }

                match &rule.action {
                    ibex_config::HttpReqAction::Return {
                        status,
                        content_type,
                        lf_string: _,
                        error_page,
                    } => {
                        // The flags are set before the reply is formatted: a `hdr` of it that
                        // reads `txn.sess_term_state` sees `LR`.
                        sess.log.term.get_or_insert(*b"LR");
                        let body = resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], *status, error_page.as_ref(), content_type.as_ref(), rc.reply.as_deref(), rc.page.as_deref());
                        // Built in a per-thread buffer that is reused (T437).
                        crate::reuse::with_bytes(|full_resp| {
                            match body {
                                ResolvedErrorBody::Raw(bytes) => send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, bytes),
                                ResolvedErrorBody::Custom { content_type, reply } => {
                                    let ctx = make_ctx!(sess);
                                    let line = reply.is_some_and(crate::rule_compiled::Reply::uses_request_line).then(|| request_line_of(&ctx));
                                    let data = reply.filter(|r| r.needs_stream()).and_then(|_| stream_data(sess, proxies, &ctx, line.as_deref()));
                                    build_templated_error_response_into(full_resp, *status, content_type, reply, data.as_ref(), &ctx, registry);
                                    send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, full_resp);
                                }
                            }
                        });
                        return Ok(RuleFlow::Replied);
                    }
                    // `use-service prometheus-exporter`: the metrics page answers the request and
                    // no later rule runs (`ACT_RET_STOP`). This is where the configuration
                    // keyword reaches `promex::scrape_reply`.
                    ibex_config::HttpReqAction::UseServicePrometheus => {
                        sess.log.applet = true;
                        if sess.req_uri.as_deref().is_some_and(|u| !crate::promex::query_ok(u)) {
                            send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, crate::promex::BAD_QUERY);
                        } else {
                            // The body is produced into the response buffer by
                            // `promex::pump` on every pass over the session.
                            sess.start_scrape();
                            crate::promex::pump(sess, &proxies[..], &*checks, pid);
                        }
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Deny {
                        deny_status,
                        content_type,
                        lf_string: _,
                        error_page,
                    } => {
                        let status_code = deny_status.unwrap_or(403);
                        // Denied by the proxy: `PR`, not a rule's answer (`LR`). Set before the
                        // reply is formatted, for a `hdr` that reads `txn.sess_term_state`.
                        sess.log.term = Some(*b"PR");
                        let body = resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], status_code, error_page.as_ref(), content_type.as_ref(), rc.reply.as_deref(), rc.page.as_deref());
                        let resp: Vec<u8> = match body {
                            ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                            ResolvedErrorBody::Custom { content_type, reply } => {
                                let ctx = make_ctx!(sess);
                                let line = reply.is_some_and(crate::rule_compiled::Reply::uses_request_line).then(|| request_line_of(&ctx));
                                let data = reply.filter(|r| r.needs_stream()).and_then(|_| stream_data(sess, proxies, &ctx, line.as_deref()));
                                build_templated_error_response(status_code, content_type, reply, data.as_ref(), &ctx, registry)
                            }
                        };
                        // `dreq` of the proxy whose rule denied (`http_req_get_intercept_rule`).
                        proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                        for_tracked(proxies, sess, |data| data.count_err());
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, &resp);
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Tarpit { deny_status, content_type, lf_string: _, error_page } => {
                        // The request is held until `timeout tarpit` (`timeout connect` when
                        // unset) has passed, then answered like a `deny` with status 500.
                        let held = sess.txn.as_ref().and_then(|t| t.body_wait).filter(|w| w.tarpit && w.backend == be_stage && w.rule == rule_idx);
                        let deadline = held.map_or_else(
                            || {
                                let t = &proxies[proxy_idx].stats_config.raw_timeouts;
                                // `http-request set-timeout tarpit` of this stream wins.
                                let set = sess.timeouts_set.as_ref().map(|s| s.ms[TimeoutKind::Tarpit as usize]).filter(|&ms| ms != 0);
                                let ms = set.unwrap_or_else(|| t.tarpit.or(t.connect).map_or(0, millis_to_u32));
                                now.add(ms)
                            },
                            |w| w.deadline,
                        );
                        if !deadline.is_expired(now) {
                            if let Some(t) = sess.txn.as_mut() {
                                t.body_wait = Some(crate::txn::BodyWait { backend: be_stage, rule: rule_idx, deadline, tarpit: true, inspect: false, resolve: false });
                            }
                            return Ok(RuleFlow::Suspend);
                        }
                        if let Some(t) = sess.txn.as_mut() {
                            t.body_wait = None;
                        }
                        let status_code = deny_status.unwrap_or(500);
                        sess.log.term = Some(*b"PT");
                        let body = resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], status_code, error_page.as_ref(), content_type.as_ref(), rc.reply.as_deref(), rc.page.as_deref());
                        let resp: Vec<u8> = match body {
                            ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                            ResolvedErrorBody::Custom { content_type, reply } => {
                                let ctx = make_ctx!(sess);
                                let line = reply.is_some_and(crate::rule_compiled::Reply::uses_request_line).then(|| request_line_of(&ctx));
                                let data = reply.filter(|r| r.needs_stream()).and_then(|_| stream_data(sess, proxies, &ctx, line.as_deref()));
                                build_templated_error_response(status_code, content_type, reply, data.as_ref(), &ctx, registry)
                            }
                        };
                        for_tracked(proxies, sess, |data| data.count_err());
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, &resp);
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Allow => {
                        return Ok(RuleFlow::Next);
                    }
                    // `reject` closes the client connection, `silent-drop` makes it vanish;
                    // either way no response is made and the server is not contacted. The
                    // `tcp-request content` versions end the same way (above).
                    ibex_config::HttpReqAction::Reject
                    | ibex_config::HttpReqAction::SilentDrop
                    | ibex_config::HttpReqAction::SilentDropTtl(_) => {
                        sess.log.term = Some(*b"PR");
                        proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                        for_tracked(proxies, sess, |data| data.count_err());
                        let is_ipv6 = sess.client_addr.is_some_and(|a| a.is_ipv6());
                        let (silent, ttl) = match rule.action {
                            ibex_config::HttpReqAction::SilentDrop => (true, 0),
                            ibex_config::HttpReqAction::SilentDropTtl(ttl) => (true, ttl),
                            _ => (false, 1),
                        };
                        sess.refuse_request(silent, is_ipv6, ttl);
                        // No response is owed, and the server's absence is no 502.
                        if let Some(t) = sess.txn.as_mut() {
                            t.close_after = true;
                            t.aborted = true;
                        }
                        sess.cli_state = ScState::Closed;
                        sess.srv_state = ScState::Closed;
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Auth { realm } => {
                        // The 401 page of the proxy with `WWW-Authenticate` added; with no
                        // realm, the name of the proxy the rule is in (`http_action_auth`).
                        let realm = realm.as_deref().or(if be_stage { be_name } else { fe_name }).unwrap_or_default();
                        let page = match resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], 401, Some(&ibex_config::ErrorPageSource::DefaultErrorfiles), None, None, None) {
                            ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                            ResolvedErrorBody::Custom { content_type, reply } => {
                                build_templated_error_response(401, content_type, reply, None, &make_ctx!(sess), registry)
                            }
                        };
                        let resp = with_header_at_end_of_head(&page, &format!("www-authenticate: Basic realm=\"{realm}\""));
                        for_tracked(proxies, sess, |data| data.count_err());
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, &resp);
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Redirect(r) => {
                        // `http_apply_redirect_rule` (src/http_ana.c).
                        let ctx = make_ctx!(sess);
                        let target = render_rule_fmt(rc, &ctx, registry);
                        let uri = sess.req_uri.as_deref().unwrap_or("/");
                        let (pfx, path, query) = split_uri(uri);
                        let query_part = if query.is_empty() { String::new() } else { format!("?{query}") };
                        let mut loc = match r.kind {
                            ibex_config::RedirectKind::Location => {
                                let mut l = target;
                                if r.keep_query && !query.is_empty() {
                                    l.push(if l.contains('?') { '&' } else { '?' });
                                    l.push_str(query);
                                }
                                l
                            }
                            ibex_config::RedirectKind::Prefix => {
                                format!("{target}{path}{}", if r.drop_query { "" } else { &query_part })
                            }
                            ibex_config::RedirectKind::Scheme => {
                                let mut host = String::new();
                                host_format().render_into(&mut host, &ctx, registry, None);
                                if host.is_empty() {
                                    host = pfx.split_once("://").map(|(_, a)| a.to_string()).unwrap_or_default();
                                }
                                format!("{target}://{host}{path}{}", if r.drop_query { "" } else { &query_part })
                            }
                        };
                        if r.append_slash && r.kind != ibex_config::RedirectKind::Location && !loc.ends_with('/') {
                            loc.push('/');
                        }
                        if loc.is_empty() && r.ignore_empty {
                            continue;
                        }
                        let mut reply = format!(
                            "HTTP/1.1 {} {}\r\ncontent-length: 0\r\nlocation: {loc}\r\n",
                            r.code,
                            status_reason(r.code)
                        );
                        if matches!(r.code, 302 | 303 | 307) {
                            reply.push_str("cache-control: no-cache\r\n");
                        }
                        match &r.cookie {
                            Some(ibex_config::RedirectCookie::Set(c)) => reply.push_str(&format!("set-cookie: {c}; path=/;\r\n")),
                            Some(ibex_config::RedirectCookie::SetFmt(_)) => {
                                let mut cookie = String::new();
                                rc.fmt2.iter().for_each(|f| f.render_into(&mut cookie, &ctx, registry, None));
                                let _ = write!(reply, "set-cookie: {cookie}; path=/;\r\n");
                            }
                            Some(ibex_config::RedirectCookie::Clear(n)) => reply.push_str(&format!("set-cookie: {n}; path=/; Max-Age=0;\r\n")),
                            None => {}
                        }
                        reply.push_str("\r\n");
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, reply.as_bytes());
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::SetPath { fmt: _ } => {
                        let new_path = render_rule_fmt(rc, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, _, query) = split_uri(current_uri);
                            rebuild_uri(pfx, &new_path, query)
                        };
                        if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::ReplacePath { regex, .. } => {
                        let step = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            // A target with no path (`*`, `http://h?q=1`) is left alone.
                            target_parts(current_uri).filter(|(_, path, _)| !path.is_empty()).and_then(|(pfx, path, query)| {
                                replace_uri_part(path, regex, rc.fmt.as_ref(), &make_ctx!(sess), registry)
                                    .map(|r| r.map(|new_path| rebuild_uri(pfx, &new_path, query)))
                            })
                        };
                        match step {
                            None => {}
                            Some(Err(())) => return Err(500),
                            Some(Ok(rebuilt)) => {
                                if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                                    return Err(500);
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::SetPathq { fmt: _ } => {
                        let new_pathq = render_rule_fmt(rc, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, _, _) = split_uri(current_uri);
                            format!("{pfx}{new_pathq}")
                        };
                        if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::ReplacePathq { regex, .. } => {
                        let step = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            target_parts(current_uri).and_then(|(pfx, path, query)| {
                                let pathq = if query.is_empty() { path.to_string() } else { format!("{path}?{query}") };
                                replace_uri_part(&pathq, regex, rc.fmt.as_ref(), &make_ctx!(sess), registry).map(|r| r.map(|n| format!("{pfx}{n}")))
                            })
                        };
                        match step {
                            None => {}
                            Some(Err(())) => return Err(500),
                            Some(Ok(rebuilt)) => {
                                if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                                    return Err(500);
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::ReplaceUri { regex, .. } => {
                        // The whole target, scheme and authority included.
                        let step = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            replace_uri_part(current_uri, regex, rc.fmt.as_ref(), &make_ctx!(sess), registry)
                        };
                        match step {
                            None => {}
                            Some(Err(())) => return Err(500),
                            Some(Ok(rebuilt)) => {
                                if !(req_set_uri(sess, rebuilt) && req_update_host(sess)) && STRICT_MODE.get() {
                                    return Err(500);
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::SetQuery { fmt: _ } => {
                        let new_query = render_rule_fmt(rc, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, path, _) = split_uri(current_uri);
                            rebuild_uri(pfx, path, &new_query)
                        };
                        if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::SetUri { fmt: _ } => {
                        let new_uri = render_rule_fmt(rc, &make_ctx!(sess), registry);
                        if !(req_set_uri(sess, new_uri) && req_update_host(sess)) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::SetMethod { fmt: _ } => {
                        let new_method = render_rule_fmt(rc, &make_ctx!(sess), registry);
                        if !req_set_method(sess, new_method) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::SetSrc { expr: _ } => {
                        let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &make_ctx!(sess))).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                        // The address changes, the port stays (`tcp_action_req_set_src`).
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            let port = sess.client_addr.map_or(0, |a| a.port());
                            sess.client_addr = Some(SocketAddr::new(ip, port));
                        }
                    }
                    ibex_config::HttpReqAction::SetSrcPort { expr: _ } => {
                        if let Some(port) = eval_port_expr(rc.expr.as_ref(), registry, &make_ctx!(sess)) {
                            sess.client_addr = Some(with_port(sess.client_addr, port));
                        }
                    }
                    ibex_config::HttpReqAction::SetPriorityClass { .. } | ibex_config::HttpReqAction::SetPriorityOffset { .. } => {
                        // `http_action_set_priority` (src/http_act.c): the sample as an
                        // integer (a string that is not a number is 0), clamped; a sample that
                        // cannot be fetched changes nothing.
                        let value = rc.expr.as_ref()
                            .and_then(|e| e.eval_sample(registry, &make_ctx!(sess)))
                            .map(|smp| sample_as_sint(&smp));
                        if let Some(v) = value {
                            if matches!(rule.action, ibex_config::HttpReqAction::SetPriorityClass { .. }) {
                                sess.log.prio_class = v.clamp(-2047, 2047) as i32;
                            } else {
                                sess.log.prio_offset = v.clamp(-524_287, 524_287) as i32;
                            }
                        }
                    }
                    ibex_config::HttpReqAction::SetDstPort { expr: _ } => {
                        // `tcp_action_req_set_dst_port` (src/tcp_act.c): the value as an
                        // integer, truncated to 16 bits, on the stream's destination; an
                        // address of another family becomes 0.0.0.0.
                        let port = rc.expr.as_ref()
                            .and_then(|e| e.eval_sample(registry, &make_ctx!(sess)))
                            .and_then(|smp| ibex_sample::cast::cast(smp, ibex_sample::SampleType::Sint));
                        if let Some(ibex_sample::Sample::Sint(n)) = port {
                            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                            let port = n as u16;
                            let ip = sess.server_addr.map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |a| a.ip());
                            sess.server_addr = Some(SocketAddr::new(ip, port));
                        }
                    }
                    ibex_config::HttpReqAction::SetRetries { value } => {
                        // `stream_action_set_retries` (src/stream.c): an expression's value
                        // is used only in 0..=100. A backend switch afterwards resets it.
                        match value {
                            ibex_config::RetriesValue::Fixed(n) => sess.set_retries(*n),
                            ibex_config::RetriesValue::Expr(_) => {
                                let n = rc.expr.as_ref()
                                    .and_then(|e| e.eval_sample(registry, &make_ctx!(sess)))
                                    .and_then(|smp| ibex_sample::cast::cast(smp, ibex_sample::SampleType::Sint));
                                if let Some(ibex_sample::Sample::Sint(n @ 0..=100)) = n {
                                    sess.set_retries(u16::try_from(n).unwrap_or(0));
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::SetDst { expr: _ } => {
                        let val = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &make_ctx!(sess))).map(|smp| sample_to_string(&smp)).unwrap_or_default();
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            let port = sess.server_addr.map_or(0, |a| a.port());
                            sess.server_addr = Some(SocketAddr::new(ip, port));
                        }
                    }
                    ibex_config::HttpReqAction::DoResolve(d) => {
                        // `resolv_action_do_resolve` (T489): the stream waits for the answer (its
                        // `body_wait` holds the rule), then the address goes into the variable;
                        // no answer (an error, an invalid name, the deadline) sets nothing.
                        // The cache mark it asked at is in `TcpSession::dr_wait` (shared with `tcp-request
                        // content do-resolve`: a stream waits on one rule at a time), not in the
                        // `BodyWait`, which would grow every session by 8 (`struct_sizes`).
                        let held = sess.txn.as_ref().and_then(|t| t.body_wait).filter(|w| w.resolve && w.backend == be_stage && w.rule == rule_idx);
                        let asked = held.and(crate::resolvers::dr_wait_unpack(sess.dr_wait)).filter(|w| w.0 == rule_idx).map(|w| w.1);
                        let step = with_rule_name(rc.expr.as_ref(), registry, &make_ctx!(sess), |name| match asked {
                            Some(asked) => crate::resolvers::dr_poll(d.section_idx, d.prefer_ipv4, name, asked).map_or(crate::resolvers::DrStep::Wait, crate::resolvers::DrStep::Done),
                            None => crate::resolvers::dr_start(d.section_idx, d.prefer_ipv4, name, my_task, std::time::Instant::now()),
                        });
                        match step {
                            crate::resolvers::DrStep::Wait if held.is_none_or(|w| !w.deadline.is_expired(now)) => {
                                if held.is_none() {
                                    if let Some(t) = sess.txn.as_mut() {
                                        t.body_wait = Some(crate::txn::BodyWait { backend: be_stage, rule: rule_idx, deadline: now.add(DO_RESOLVE_WAIT_MS), tarpit: false, inspect: false, resolve: true });
                                    }
                                    sess.dr_wait = crate::resolvers::dr_wait_pack(rule_idx, crate::resolvers::dr_mark());
                                }
                                return Ok(RuleFlow::Suspend);
                            }
                            // A wait past its bound goes on with no address, like an empty answer.
                            crate::resolvers::DrStep::Wait | crate::resolvers::DrStep::Done(None) => {}
                            crate::resolvers::DrStep::Done(Some(ip)) => ibex_sample::vars::store_by_name(&mut sess.vars, &d.var_name, ibex_sample::vars::In::Owned(ip_sample(ip))),
                        }
                        if held.is_some() {
                            if let Some(t) = sess.txn.as_mut() {
                                t.body_wait = None;
                            }
                            sess.dr_wait = 0;
                        }
                    }
                    ibex_config::HttpReqAction::SetVar { var_name, .. } => {
                        // A sample that cannot be fetched sets nothing (`action_store`, src/vars.c).
                        // The expression is a sample fetch, checked at load; one that cannot be parsed or
                        // fetched sets nothing.
                        // A constant (`str(hello)`) is copied in, with no allocation (T364 S6).
                        let e = rc.expr.as_ref();
                        if let Some(c) = e.and_then(|e| e.constant(registry)) {
                            store_var_in(&mut sess.vars, &rc.var(var_name), ibex_sample::vars::In::Ref(c));
                        } else if let Some(val) = e.and_then(|e| e.eval_sample(registry, &make_ctx!(sess))) {
                            store_var_smp(&mut sess.vars, &rc.var(var_name), val);
                        }
                    }
                    ibex_config::HttpReqAction::SetVarFmt { var_name, fmt } => {
                        let mut val = String::with_capacity(fmt.len());
                        rc.fmt.iter().for_each(|f| render_rule_format(f, &mut val, &make_ctx!(sess), registry, sess, proxies));
                        store_var(&mut sess.vars, &rc.var(var_name), val);
                    }
                    ibex_config::HttpReqAction::UnsetVar { var_name } => {
                        unset_var(&mut sess.vars, &rc.var(var_name));
                    }
                    ibex_config::HttpReqAction::StrictMode { on } => {
                        STRICT_MODE.set(*on);
                    }
                    ibex_config::HttpReqAction::DisableL7Retry => {
                        if let Some(t) = sess.txn.as_mut() {
                            t.l7_off = true;
                            t.l7 = crate::txn::L7Retry::Off;
                        }
                    }
                    ibex_config::HttpReqAction::SetTimeout { timeout_type, timeout_val } => {
                        let ms = match rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &make_ctx!(sess))) {
                            // The sample is cast to an integer of milliseconds (no units) and
                            // truncated to 32 bits, as `http_action_set_timeout` does.
                            Some(Sample::Sint(n)) => n as u32,
                            Some(Sample::Str(ref s)) => str_to_sint(s) as u32,
                            _ => parse_timeout_val(timeout_val),
                        };
                        // `stream_set_timeout` (src/stream.c): the stream runs on it from here,
                        // and `cur_*_timeout` reports it. 0 is applied too (no timeout) for
                        // client, server and connect; for queue, tunnel and tarpit `timeouts_set`
                        // holds 0 for "not set", so 0 leaves those as they were (not measured).
                        if let Some(kind) = TimeoutKind::from_name(timeout_type)
                            .filter(|k| ms != 0 || matches!(k, TimeoutKind::Client | TimeoutKind::Server | TimeoutKind::Connect))
                        {
                            let before = sess.timeouts;
                            sess.timeouts_set.get_or_insert_with(|| Box::new(crate::proxy::TimeoutsSet { ms: [0; 6], before })).ms[kind as usize] = ms;
                            match kind {
                                TimeoutKind::Client => sess.timeouts.client = ms,
                                TimeoutKind::Server => sess.timeouts.server = ms,
                                TimeoutKind::Connect => sess.timeouts.connect = ms,
                                // Queue and tunnel are read from `timeouts_set` when the request
                                // is queued (`TcpSession::queue_ms`) and while it is a tunnel
                                // (`TcpSession::tunnel_ms`); so is the tarpit.
                                TimeoutKind::Queue | TimeoutKind::Tunnel | TimeoutKind::Tarpit => {}
                            }
                            if let Some(mut t) = CURRENT_TIMEOUTS.get() {
                                t.cur[kind as usize] = ms;
                                CURRENT_TIMEOUTS.set(Some(t));
                            }
                        }
                    }
                    ibex_config::HttpReqAction::NormalizeUri { normalizer, full, strict } => {
                        let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                        if let Ok(new_uri) = apply_normalize_uri(current_uri, normalizer, *full, *strict) {
                            // Through the HTX message, as `set-uri` does: setting only
                            // `req_uri` left the request that went out unchanged.
                            if !req_set_uri(sess, new_uri) && STRICT_MODE.get() {
                                return Err(500);
                            }
                        } else {
                            return Err(400);
                        }
                    }
                    ibex_config::HttpReqAction::SetHeader { name, .. } => {
                        // A header that does not fit fails the request in strict mode and is
                        // skipped otherwise (`fail_rewrite`).
                        // The value is rendered into a per-thread string (T437).
                        let fits = crate::reuse::with_string(|val| {
                            rc.fmt.iter().for_each(|f| render_rule_format(f, val, &make_ctx!(sess), registry, sess, proxies));
                            req_rule_header(sess, name, val, true)
                        });
                        if !fits && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::AddHeader { name, .. } => {
                        let fits = crate::reuse::with_string(|val| {
                            rc.fmt.iter().for_each(|f| render_rule_format(f, val, &make_ctx!(sess), registry, sess, proxies));
                            req_rule_header(sess, name, val, false)
                        });
                        if !fits && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::DelHeader { name } => {
                        let freed = req_hdr_bytes(sess, name);
                        del_req_header(sess, name);
                        res_htx_resize(freed, 0);
                    }
                    ibex_config::HttpReqAction::HeadersBin { op, prefix, .. } => {
                        // A list that cannot be fetched changes nothing (`sample_fetch_as_type`).
                        let bin = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, &make_ctx!(sess))).map(sample_to_bin);
                        if let Some(bin) = bin {
                            match req_headers_bin(sess, *op, prefix, &bin) {
                                crate::hdrs_bin::Walk::Done => {}
                                crate::hdrs_bin::Walk::Rewrite if !STRICT_MODE.get() => {}
                                crate::hdrs_bin::Walk::Rewrite | crate::hdrs_bin::Walk::Invalid => return Err(500),
                            }
                        }
                    }
                    ibex_config::HttpReqAction::ReplaceHeader { name, regex, .. } => {
                        let mut repl = crate::reuse::string();
                        rc.fmt.iter().for_each(|f| f.render_into(&mut repl, &make_ctx!(sess), registry, None));
                        let failed = replace_req_header(sess, name, regex, &repl).is_err();
                        crate::reuse::give(repl);
                        if failed {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::ReplaceValue { name, regex, .. } => {
                        let mut repl = crate::reuse::string();
                        rc.fmt.iter().for_each(|f| f.render_into(&mut repl, &make_ctx!(sess), registry, None));
                        let failed = replace_req_value(sess, name, regex, &repl).is_err();
                        crate::reuse::give(repl);
                        if failed {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::ScIncGpc0 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::Inc),
                    ibex_config::HttpReqAction::ScIncGpc1 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::One, GpcOp::Inc),
                    ibex_config::HttpReqAction::ScSetGpt0 { sc, expr } => {
                        let val = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &make_ctx!(sess));
                        sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::SetTag(val));
                    }
                    ibex_config::HttpReqAction::ScIncGpc { idx, sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Inc),
                    ibex_config::HttpReqAction::ScAddGpc { idx, sc, expr } => {
                        let n = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &make_ctx!(sess));
                        sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Add(u64::from(n)));
                    }
                    ibex_config::HttpReqAction::ScSetGpt { idx, sc, expr } => {
                        let val = resolve_gpt0_val(expr, rc.expr.as_ref(), registry, &make_ctx!(sess));
                        sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::SetTag(val));
                    }
                    ibex_config::HttpReqAction::Pause { time_ms, expr: _ } => {
                        // `http_action_pause`: the wait starts once (the stream's `body_wait`
                        // holds its deadline across the yields, as a tarpit's does), and the
                        // rules go on when it has passed. No value, or one not above 0, is no
                        // wait.
                        let held = sess.txn.as_ref().and_then(|t| t.body_wait).filter(|w| w.tarpit && w.backend == be_stage && w.rule == rule_idx);
                        let deadline = if let Some(w) = held {
                            Some(w.deadline)
                        } else {
                            let ms = pause_ms(*time_ms, rc.expr.as_ref(), registry, &make_ctx!(sess));
                            (ms > 0).then(|| now.add(ms))
                        };
                        if let Some(deadline) = deadline.filter(|d| !d.is_expired(now)) {
                            if let Some(t) = sess.txn.as_mut() {
                                t.body_wait = Some(crate::txn::BodyWait { backend: be_stage, rule: rule_idx, deadline, tarpit: true, inspect: false, resolve: false });
                            }
                            return Ok(RuleFlow::Suspend);
                        }
                        if let Some(t) = sess.txn.as_mut() {
                            t.body_wait = None;
                        }
                    }
                    ibex_config::HttpReqAction::WaitForBody { time_ms, at_least } => {
                        match wait_for_request_body(sess, &proxies[pages_idx], be_stage, rule_idx, *time_ms, *at_least, now) {
                            BodyWait::Ready => {}
                            BodyWait::Pending => return Ok(RuleFlow::Suspend),
                            BodyWait::TimedOut => {
                                sess.log.term.get_or_insert(*b"cR");
                                return Err(408);
                            }
                            BodyWait::ClientGone => {
                                sess.log.term.get_or_insert(*b"CR");
                                return Err(400);
                            }
                            BodyWait::Malformed => return Err(400),
                        }
                    }
                    ibex_config::HttpReqAction::Capture { len, id, .. } => {
                        // No sample, no capture: the slot stays empty (`-` in `%hrl`).
                        // The expression was checked when the configuration loaded.
                        let val = rc
                            .expr
                            .as_ref()
                            .and_then(|e| e.eval_sample(registry, &make_ctx!(sess)))
                            .map(|smp| sample_to_string(&smp));
                        // `id` names one of the frontend's slots (a backend's rule too); without
                        // it the rule's own, which the engine assigned when the proxy was built.
                        // An `id` past the frontend's slots captures nothing.
                        // A rule with its own slot (`len`) belongs to the proxy that holds it; a
                        // stream coming from another frontend has no such slot (`px != strm_fe`).
                        let foreign = len.is_some() && pages_idx != proxy_idx;
                        if let (Some(target_id), Some(val), false) = (id, val, foreign) {
                            // With `id`, the length is the declared slot's.
                            let max = len.or_else(|| proxies[proxy_idx].req_capture_slots.get(*target_id).map(|(_, l)| *l));
                            if let Some(slot) = sess.log.req_captures.get_mut(*target_id) {
                                ibex_sample::capture_write::discard(false, *target_id);
                                crate::txnlog::set_capture(slot, &cut_at(&val, max.unwrap_or(usize::MAX)));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(RuleFlow::Next)
        };
        // A pass over a rule list writes the head it edited once, when it ends however it ends.
        let eval_http_rules = |rules: &[ibex_config::HttpReqRule], compiled: &[crate::rule_compiled::Rule], acls: &ibex_sample::Acls, sess: &mut TcpSession, be_retries: u16, fe_name: Option<&str>, be_name: Option<&str>, pages_idx: usize, be_stage: bool, start: usize| -> Result<RuleFlow, u16> {
            hold_req_rebuild();
            let flow = eval_http_rules_held(rules, compiled, acls, sess, be_retries, fe_name, be_name, pages_idx, be_stage, start);
            release_req_rebuild(sess);
            flow
        };

        // Execute frontend rules
        if !resume_be && !proxies[proxy_idx].http_req_rules.is_empty() {
            let fe_rules = &proxies[proxy_idx].http_req_rules;
            let fe_acls = &proxies[proxy_idx].acls;
            let start = resume.map_or(0, |w| w.rule);
            match eval_http_rules(fe_rules, &proxies[proxy_idx].rules.http_req, fe_acls, &mut entry.sess, proxies[proxy_idx].retries, Some(&proxies[proxy_idx].name), None, proxy_idx, false, start) {
                Ok(RuleFlow::Replied) => {
                    entry.sess.log.term.get_or_insert(*b"LR");
                    return None;
                }
                Err(status) => {
                    entry.sess.log.term.get_or_insert(*b"PR");
                    reply_error(entry, proxies, status);
                    return None;
                }
                // Held for the body: back here when it is.
                Ok(RuleFlow::Suspend) => return None,
                Ok(RuleFlow::Next) => {}
            }
        }

        // Serve the stats page once the frontend's `http-request` rules have accepted the
        // request, as `http_process_req_common` does (a `deny` blocks the page, a `set-path`
        // moves the request onto or off the stats URI); before any backend is chosen.
        //
        // This dispatch was dropped when the action-rule engine was wired in, leaving
        // `is_stats_request` and `handle_stats_request` orphaned -- clippy flagged both
        // as never used. The effect was that every request to `stats uri` fell through
        // to normal backend routing and returned 503, so the stats page and the whole
        // web admin stopped working.
        if !resume_be
            && (proxies[proxy_idx].stats_config.enable
                || proxies[proxy_idx].stats_config.uri.is_some()
                || proxies[proxy_idx].stats_config.admin)
        {
            let req_uri = entry.sess.req_uri.as_deref().unwrap_or("/");
            let configured_uri = proxies[proxy_idx].stats_config.uri.as_deref();
            if Self::stats_method_ok(&entry.sess) && Self::is_stats_request(req_uri, configured_uri) {
                // An admin POST is read whole before it acts (`AN_REQ_HTTP_BODY`): held here
                // until its body is, then back past the rules that already ran.
                if entry.sess.req_method.as_deref() == Some("POST") && Self::stats_admin_allowed(&entry.sess, proxies, proxy_idx) {
                    let at = proxies[proxy_idx].http_req_rules.len();
                    match wait_for_request_body(&mut entry.sess, &proxies[proxy_idx], false, at, None, 0, now) {
                        BodyWait::Ready => {}
                        BodyWait::Pending => return None,
                        // The applet is the one that answers (measured: `LR`) a body that does
                        // not come in time or is cut short; a body that is not one is a bad request.
                        BodyWait::TimedOut => {
                            entry.sess.log.term.get_or_insert(*b"LR");
                            reply_error(entry, proxies, 408);
                            return None;
                        }
                        BodyWait::ClientGone => {
                            entry.sess.log.term.get_or_insert(*b"LR");
                            reply_error(entry, proxies, 400);
                            return None;
                        }
                        BodyWait::Malformed => {
                            // Cut off with no answer, logged 400 (measured): the applet gets a
                            // body that is not one after it started, the mux's 400 is for the head.
                            entry.sess.log.status = Some(400);
                            entry.sess.log.term = Some(*b"LR");
                            if let Some(txn) = entry.sess.txn.as_mut() {
                                txn.close_after = true;
                                txn.aborted = true;
                            }
                            entry.sess.cli_state = ScState::Closed;
                            entry.sess.srv_state = ScState::Closed;
                            return None;
                        }
                    }
                }
                return Self::handle_stats_request(entry, proxies, checks, pid, now, proxy_idx);
            }
        }

        // 3. Resolve backend and server
        let be_idx = if resume_be {
            entry.backend_idx
        } else if let Some(idx) = Self::resolve_backend(entry, proxies) {
            idx
        } else {
            // `force-be-switch` sent the request to a disabled backend: no server.
            entry.backend_idx = proxy_idx;
            proxies[proxy_idx].counters().failed_conn.fetch_add(1, Ordering::Relaxed);
            reply_error(entry, proxies, 503);
            return None;
        };
        entry.backend_idx = be_idx;
        enter_backend(entry, proxies, be_idx);
        entry.sess.retry_conn = proxies[be_idx].ids.retry_on & ibex_config::RE_CONN_FAILED != 0;
        // `option http-drop-request-trailers` is the backend's (`h1_snd_buf`, on the server connection).
        entry.sess.set_drop_req_trailers(proxies[be_idx].h1_adjust & ibex_config::H1_DROP_REQ_TRAILERS != 0);
        // `stream_set_backend` counts the stream for the backend (`proxy_inc_be_ctr`).
        proxies[be_idx].counters().be_sess_rate.tick();
        // `stream_set_backend` (src/stream.c): switching to a backend takes its retry
        // budget, whatever a frontend-side `set-retries` set.
        if be_idx != proxy_idx && !resume_be {
            entry.sess.set_retries(proxies[be_idx].retries);
        }
        // The server side runs on the backend's timeouts, as in HAProxy: `stream_set_backend`
        // drops what a frontend-side `set-timeout` set for it (the client's and the
        // tarpit's stay). Not again on a stream resumed in the backend, whose own rules may
        // have set them since.
        if be_idx != proxy_idx && !resume_be {
            let t = proxies[be_idx].timeouts;
            entry.sess.timeouts.server = t.server;
            entry.sess.timeouts.connect = t.connect;
            if let Some(set) = entry.sess.timeouts_set.as_mut() {
                for k in [TimeoutKind::Server, TimeoutKind::Connect, TimeoutKind::Queue, TimeoutKind::Tunnel] {
                    set.ms[k as usize] = 0;
                }
            }
        }
        entry.sess.set_backend_timeouts(&proxies[be_idx]);
        stream_timeouts_enter(proxies, proxy_idx, be_idx, &entry.sess);

        // Evaluate backend tcp-request content rules
        let inspect_wait = resume.filter(|w| w.inspect);
        if (!resume_be || inspect_wait.is_some()) && !proxies[be_idx].tcp_req_content_rules.is_empty() {
            // The backend's own `inspect-delay`, from the first pass over its rules.
            let deadline = inspect_wait.map(|w| w.deadline).or_else(|| {
                proxies[be_idx].tcp_req_inspect_delay.map(|d| now.add(u32::try_from(d.as_millis()).unwrap_or(u32::MAX)))
            });
            entry.sess.inspect_exp = deadline;
            crate::resolvers::dr_set_task(entry.task);
            let res = eval_tcp_req_content_rules(
                &proxies[be_idx],
                proxy_idx,
                proxies,
                sample_registry(),
                &mut entry.sess,
                now,
                0,
            );
            entry.sess.inspect_exp = None;
            let wait = (res == ContentEvalResult::Waiting).then(|| crate::txn::BodyWait {
                backend: true,
                rule: 0,
                deadline: deadline.unwrap_or(Tick::ETERNITY),
                tarpit: false,
                inspect: true,
                resolve: false,
            });
            entry.sess.txn.iter_mut().for_each(|txn| txn.body_wait = wait);
            if res == ContentEvalResult::Waiting {
                // Held until the delay is over: back here then, past the rules and the
                // routing that already ran.
                return None;
            }
            match res {
                ContentEvalResult::Reject => {
                    entry.sess.abort_client();
                    proxies[be_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return None;
                }
                ContentEvalResult::SilentDrop(ttl) => {
                    let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                    entry.sess.silent_drop_client(is_ipv6, ttl);
                    proxies[be_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return None;
                }
                ContentEvalResult::Done | ContentEvalResult::Waiting => {}
            }
        }

        // If be_idx != proxy_idx, execute backend rules
        if be_idx != proxy_idx && !proxies[be_idx].http_req_rules.is_empty() {
            let be_rules = &proxies[be_idx].http_req_rules;
            let be_acls = &proxies[be_idx].acls;
            let start = resume.filter(|w| w.backend).map_or(0, |w| w.rule);
            match eval_http_rules(be_rules, &proxies[be_idx].rules.http_req, be_acls, &mut entry.sess, proxies[be_idx].retries, Some(&proxies[proxy_idx].name), Some(&proxies[be_idx].name), be_idx, true, start) {
                Ok(RuleFlow::Replied) => {
                    entry.sess.log.term.get_or_insert(*b"LR");
                    return None;
                }
                Err(status) => {
                    entry.sess.log.term.get_or_insert(*b"PR");
                    reply_error(entry, proxies, status);
                    return None;
                }
                Ok(RuleFlow::Suspend) => return None,
                Ok(RuleFlow::Next) => {}
            }
        }

        // `retry-on <status>`: the request is kept, once it is sent, to be sent again on an
        // answer the backend retries on (`TX_L7_RETRY`, set when a connection is requested
        // unless `http-request disable-l7-retry` ran). It reaches the data path in
        // `process_srv_io` (the copy) and `l7_retry` (the replay).
        if !resume_be && proxies[be_idx].ids.retry_on & !ibex_config::RE_CONN_FAILED != 0 {
            if let Some(t) = entry.sess.txn.as_mut().filter(|t| !t.l7_off && matches!(t.l7, crate::txn::L7Retry::Off)) {
                t.l7 = crate::txn::L7Retry::Armed;
            }
        }

        // A backend's `stats enable` / `stats uri`: the stats applet answers a request for
        // its URI after the backend's own rules (the frontend's was served above).
        if be_idx != proxy_idx
            && (proxies[be_idx].stats_config.enable || proxies[be_idx].stats_config.uri.is_some() || proxies[be_idx].stats_config.admin)
            && Self::stats_method_ok(&entry.sess)
            && Self::is_stats_request(entry.sess.req_uri.as_deref().unwrap_or("/"), proxies[be_idx].stats_config.uri.as_deref())
        {
            return Self::handle_stats_request(entry, proxies, checks, pid, now, be_idx);
        }

        // Apply forwardfor & originalto header injection. As in HAProxy
        // (`http_handle_xff_header`), the option applies when the frontend or the backend
        // sets it, and it is not applied to an address in the `except` network of any
        // proxy that sets it.
        let fe_be = [proxy_idx, be_idx];
        // These headers are added to the request as it stands after the rules; one that does
        // not fit fails the request (`http_process_request`, `return_int_err`).
        req_htx_init(&entry.sess);
        let xff_excepts: Vec<&str> = fe_be.iter().filter_map(|&i| proxies[i].stats_config.forwardfor.as_deref()).collect();
        if !xff_excepts.is_empty() {
            // `if-none` only counts when no proxy that sets the option leaves it out
            // (`PR_O_FF_ALWAYS`): then a header the client sent is kept as the only one.
            let always = fe_be.iter().any(|&i| {
                let sc = &proxies[i].stats_config;
                sc.forwardfor.is_some() && !sc.forwardfor_if_none
            });
            let has_own = entry.sess.htx_slice().is_some_and(|s| s.get_header("x-forwarded-for").is_some());
            let client_ip = entry.sess.client_addr.map(|a| a.ip());
            if let Some(ip) = client_ip.filter(|_| always || !has_own) {
                let in_except = xff_excepts.iter().any(|e| !e.is_empty() && ip_in_cidr(ip, e));
                if !in_except {
                    let ip_str = ip.to_string();
                    // A new line after the client's own, as `HAProxy` writes it.
                    if !add_req_header_fit(&mut entry.sess, "X-Forwarded-For", &ip_str) {
                        return Self::request_no_room(entry, proxies);
                    }
                }
            }
        }

        let xot_excepts: Vec<&str> = fe_be.iter().filter_map(|&i| proxies[i].stats_config.originalto.as_deref()).collect();
        if !xot_excepts.is_empty() {
            let dst_ip = entry.sess.server_addr.or(entry.sess.target_addr).map(|a| a.ip());
            if let Some(ip) = dst_ip {
                let in_except = xot_excepts.iter().any(|e| !e.is_empty() && ip_in_cidr(ip, e));
                if !in_except {
                    let ip_str = ip.to_string();
                    if !add_req_header_fit(&mut entry.sess, "X-Original-To", &ip_str) {
                        return Self::request_no_room(entry, proxies);
                    }
                }
            }
        }

        // `option forwarded` (`http_handle_7239_header`): the backend's, as one more element
        // at the end of the last `Forwarded` header.
        if let Some(fwd) = proxies[be_idx].stats_config.forwarded.clone() {
            let stick = StickView::new(proxies, &entry.sess.tracked_sc);
            let element = forwarded_element(&fwd, &entry.sess, &stream_sample_ctx(&entry.sess, &proxies[proxy_idx], &proxies[be_idx], &ProxiesView(proxies), &stick));
            if !append_forwarded_element(&mut entry.sess, &element) {
                return Self::request_no_room(entry, proxies);
            }
        }

        // `option http-server-close` (frontend or backend): this request has the server
        // connection to itself, and the server is asked to close it. A request that asks
        // for an upgrade keeps its `Connection` header.
        if (!proxies[proxy_idx].http_req_rules.is_empty() || !proxies[be_idx].http_req_rules.is_empty()) && !reread_request_framing(&mut entry.sess) {
            // A length the rules made shorter than the body: `HAProxy`'s mux fails the
            // request (500, `IH`) rather than send the rest as the next request (T442).
            entry.sess.log.term = Some(*b"IH");
            reply_error(entry, proxies, 500);
            return None;
        }
        rewrite_request_connection(&mut entry.sess, server_close(proxies, proxy_idx, be_idx));

        // The backend's `cookie` line: the client's cookies are cut and may name the server.
        let cookie_server = manage_client_cookies(&mut entry.sess, &proxies[be_idx]);
        // `use-server` comes first: a server it picked (SF_ASSIGNED) is not overridden by
        // the cookie, which is still cut as above.
        let cookie_server = Self::use_server(&entry.sess, be_idx, proxies).or(cookie_server);
        // `stick match` after those (`SF_ASSIGNED`); the keys to store are queued either way.
        let assigned = cookie_server.is_some();
        let cookie_server = cookie_server.or(Self::sticking_rules(&mut entry.sess, be_idx, proxies, assigned));
        // The head is final: its header names go to the server in lower case, as `HAProxy`
        // writes them (HTX). The request line and the values are the client's.
        let srv_table = (proxies[be_idx].h1_adjust & ibex_config::H1_ADJ_SERVER != 0).then(|| &*proxies[be_idx].h1_case);
        // In the case they came in when `tune.ibex.h1-lowercase-headers` is off (D-E, X5).
        let lower = proxies[be_idx].h1_lower;
        if lower || srv_table.is_some() {
            entry.sess.req.edit_keeping_lines(|head, eoh| rewrite_header_names_before(head, eoh, srv_table, lower));
        }
        Self::route_to_server(entry, proxies, fdtab, poller, idle_pool, now, be_idx, cookie_server)
    }

    /// A header `HAProxy` fails the request over (`return_int_err`) did not fit: the 500.
    fn request_no_room<T>(entry: &mut SessionEntry, proxies: &[Proxy]) -> Option<T> {
        entry.sess.log.term.get_or_insert(*b"PR");
        reply_error(entry, proxies, 500);
        None
    }

    /// Picks the server for the request and connects to it. When every server is at its
    /// `maxconn` the request waits in the backend's queue (`pendconn_add`), and this runs
    /// again each time a slot frees up (`Engine::wake_queued`) and when `timeout queue`
    /// ends: `503`, `sQ`. `cookie_server` is the server persistence picked, if any.
    #[allow(clippy::too_many_arguments)]
    fn route_to_server(
        entry: &mut SessionEntry,
        proxies: &mut Proxies,
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut IdlePool,
        now: Tick,
        be_idx: usize,
        cookie_server: Option<usize>,
    ) -> Option<crate::stats_html::AdminAction> {
        let source_ip = entry.sess.client_addr.map(|a| a.ip());
        entry.sess.lb_picked = cookie_server.is_none();
        // The server's slot is taken with the pick (T590): checked apart, two workers both
        // took a `maxconn 1` server's last one. A server persistence names takes it whether
        // or not it is full, as before.
        // Only a server with a `maxconn` is counted here; the others are counted once their
        // connection is in use, below (T224). `counted`: the slot is counted already.
        let be = &proxies[be_idx];
        let pick = || be.pick_and_take(false, || be.select_server_with_key_idx(source_ip, entry.sess.req_uri.as_deref()));
        let mut full = false;
        let target = if let Some(idx) = cookie_server {
            Some(((Some(idx), be.servers.at(idx)), false))
        } else {
            // No pick while a server looked full, and no longer full when asked, is a slot
            // another worker freed in between: asked again rather than refused (`SRV_STATUS_FULL`
            // is decided under the lock in `HAProxy`). The verdict that queues is the one seen
            // here, not one read again later.
            let limited = || (0..be.servers.len()).any(|i| be.server_maxconn.get(i).is_some_and(|m| m > 0));
            let mut tries = 0..3;
            loop {
                let t = pick();
                full = t.is_none() && be.all_servers_full();
                if t.is_some() || full || tries.next().is_none() || !limited() { break t; }
            }
        };

        let Some(((picked_idx, target_addr), counted)) = target else {
            if full {
                return Self::wait_in_queue(entry, proxies, now, be_idx);
            }
            proxies[be_idx].counters().failed_conn.fetch_add(1, Ordering::Relaxed);
            // No server to connect to: `SC`, whatever the stream's progress.
            entry.sess.log.term = Some(*b"SC");
            reply_error(entry, proxies, 503);
            return None;
        };
        // Given a slot: out of the queue.
        entry.sess.queue.leave();
        count_server_session(proxies, be_idx, picked_idx);

        // The connection kept from this session's last transaction, if this request goes
        // to the same server: no new connection, no pool round trip. Otherwise it goes to
        // the pool (or is closed) and the request is routed as usual.
        if entry.sess.srv.is_some() {
            // A server that maps the destination may have been reached at another
            // address than this request's destination names; it is not kept.
            let same = entry.srv_backend_idx == be_idx
                && entry.sess.target_addr == Some(target_addr)
                && !maps_destination(target_addr)
                // A TLS connection carries the name it was opened with; a request whose
                // SNI differs (another Host, under the automatic SNI) needs its own.
                && (!entry.sess.srv_xprt.is_tls()
                    || with_server_sni(&entry.sess, proxies, entry.proxy_idx, be_idx, entry.target_server_idx, |sni| {
                        sni == entry.sess.srv_xprt.sni()
                    }))
                // A connection opened with a PROXY header carries only requests that would
                // send that same header: HAProxy hashes it into the reuse key, so a
                // per-request unique-id TLV gets a connection of its own.
                && (!entry.sess.send_proxy_prepended
                    || proxy_header(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr)
                        .is_some_and(|h| h == entry.sess.send_proxy_header));
            // Under `http-reuse` other than `never` the connection goes back to the server's
            // lists after each response and the next request takes one by the mode's rules;
            // while the lists hold nothing else, and the server keeps idle connections at
            // all (`pool-max-conn`, `pool-purge-delay`), that is this one, and the round trip is skipped.
            // An h2 connection under `safe` is the session's own, as under `never` (T540).
            let alone = proxies[be_idx].http_reuse == ibex_config::HttpReuse::Never
                || (proxies[be_idx].http_reuse == ibex_config::HttpReuse::Safe && entry.sess.srv_xprt.is_h2())
                || (idle_pool.is_empty()
                    && cookie_server
                        .or(entry.target_server_idx)
                        .is_none_or(|i| proxies[be_idx].ids.server_pool(i).keeps_any()));
            if same
                && alone
                && matches!(entry.sess.srv_state, ScState::Ready | ScState::Established)
                && entry.sess.rep.is_empty()
            {
                // Its server timer is the last transaction's; this one starts its own.
                // The connection is already there, so `%Tw` and `%Tc` are both 0, not
                // -1 and the time from the request to now.
                entry.sess.log.queue.get_or_insert_with(crate::txnlog::loop_now);
                // A parked connection is in use again: the slot taken with the pick, or one
                // counted now. One that was not parked holds its own, and the pick's goes back.
                if entry.sess.srv_park_exp.is_set() {
                    entry.sess.srv_park_exp = Tick::ETERNITY;
                    if !counted {
                        server_actconn_add(entry, proxies, true);
                    }
                } else if counted {
                    if let Some(a) = picked_idx.and_then(|i| proxies[be_idx].server_actconn.get(i)) {
                        a.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                entry.sess.server_connected(now);
                entry.sess.bc_idle = false;
                if let Some(txn) = entry.sess.txn.as_mut() {
                    txn.srv_reused = true;
                }
                count_connect(proxies, be_idx, entry.target_server_idx, true);
                return None;
            }
            release_server(entry, proxies, fdtab, poller, idle_pool, true);
        }

        let s_idx = picked_idx;
        entry.target_server_idx = s_idx;
        entry.srv_backend_idx = be_idx;
        entry.sess.log.server = s_idx.and_then(crate::txnlog::server_slot);

        maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

        set_target(entry, target_addr);

        let mut reused = None;
        entry.srv_served = 0;
        idle_pool.ensure_sized(proxies);
        if proxies[be_idx].http_reuse != ibex_config::HttpReuse::Never && idle_pool.may_find() {
            let sni = server_sni(&entry.sess, proxies, entry.proxy_idx, be_idx, s_idx);
            let key = idle_key(target_addr, be_idx, s_idx, sni);
            // `conn_backend_get` takes none of another thread's while the server keeps fewer
            // idle connections than its `pool-low-conn` and few fds are in use.
            let low = s_idx.map_or(0, |i| proxies[be_idx].ids.server_pool(i).low_conn);
            let steal = key.as_ref().is_none_or(|k| idle_pool.may_steal(k.srv, low));
            let srv = key.as_ref().map(|k| k.srv);
            // Every stream of an HTTP/2 frontend is "not the first request" (`SE_FL_NOT_FIRST`, `mux_h2.c`),
            // and so is every HTTP/3 request, the relay's included (`qcs_new`, `mux_quic.c`): one
            // server connection per HTTP/3 request overflowed a small server's accept queue
            // under a burst of 200 (T523).
            let first_req = entry.sess.is_first_req && !entry.sess.is_h2_child() && !entry.sess.h3;
            if let Some((conn, safe, registered)) = key.and_then(|k| idle_pool.take(&k, first_req, proxies[be_idx].http_reuse, steal)) {
                entry.srv_served = if safe { 2 } else { 1 };
                reused = Some((conn, registered));
            }
            // `connect_server`: past `pool_high_count` fds, one of the server's idle
            // connections is closed, whether or not one was reused.
            if let Some(srv) = srv {
                idle_pool.close_one_over_high(srv);
            }
        }
        // In use from here (`srv_use_conn`, after the takeover): counted before the take, a
        // connection taken from the pool was in use and idle at once, and another worker
        // weighing a release (`srv_add_to_idle_list`) saw one more than there were and closed
        // a connection the next burst needed (T224: 9 server connections where 8 serve).
        // A server with a `maxconn` was counted with the pick (T590).
        if let Some(idx) = s_idx.filter(|_| !counted) {
            if idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[idx].fetch_add(1, Ordering::Relaxed);
            }
        }

        count_connect(proxies, be_idx, s_idx, reused.is_some());
        if let Some((IdleConn { fd: srv_fd, xprt, src }, registered)) = reused {
            let sfd = srv_fd.as_raw_fd();
            entry.srv_raw_fd = Some(sfd);
            entry.sess.attach_server_from(srv_fd, xprt, src, now);
            entry.sess.server_connected(now);
            if let Some(txn) = entry.sess.txn.as_mut() {
                txn.srv_reused = true;
            }
            if registered {
                // From this worker's lists: still in its epoll set, for reads. The request
                // is written without waiting for writability, and the pass's
                // `update_interests` asks for it only if that write could not finish.
                entry.srv_interest = Interest::READ;
                fdtab.insert(sfd, FdState::Conn { task: entry.task, conn: 1 }, Interest::READ);
                return None;
            }
            let (_, srv_want) = entry.sess.interests();
            let new_interest = Interest {
                readable: srv_want.read,
                writable: srv_want.write,
            };
            entry.srv_interest = new_interest;
            fdtab.insert(
                sfd,
                FdState::Conn {
                    task: entry.task,
                    conn: 1,
                },
                new_interest,
            );
            if let Some(ref srv) = entry.sess.srv {
                let _ = poller.add(
                    srv.as_fd(),
                    raw_fd_to_u64(sfd),
                    new_interest.readable,
                    new_interest.writable,
                );
            }
        } else if let Ok((srv_fd, immediate)) = raw::connect_opts(connect_addr(target_addr, entry.sess.server_addr), proxies[be_idx].server_tfo_of(target_addr))
        .inspect_err(|e| entry.sess.bc_err = Some(crate::proxy::bc_connect_now_errno(e)))
    {
            let sfd = srv_fd.as_raw_fd();
            attach_server_to(&mut entry.sess, proxies, entry.proxy_idx, be_idx, s_idx, srv_fd, now);
            entry.srv_raw_fd = Some(sfd);
            if immediate {
                entry.sess.server_connected(now);
                let (_, srv_want) = entry.sess.interests();
                let new_interest = Interest {
                    readable: srv_want.read,
                    writable: srv_want.write,
                };
                entry.srv_interest = new_interest;
                fdtab.insert(
                    sfd,
                    FdState::Conn {
                        task: entry.task,
                        conn: 1,
                    },
                    new_interest,
                );
                if let Some(ref srv) = entry.sess.srv {
                    let _ = poller.add(
                        srv.as_fd(),
                        raw_fd_to_u64(sfd),
                        new_interest.readable,
                        new_interest.writable,
                    );
                }
            } else {
                entry.srv_interest = Interest::WRITE;
                fdtab.insert(
                    sfd,
                    FdState::Conn {
                        task: entry.task,
                        conn: 1,
                    },
                    Interest::WRITE,
                );
                if let Some(ref srv) = entry.sess.srv {
                    let _ = poller.add(srv.as_fd(), raw_fd_to_u64(sfd), false, true);
                }
            }
        } else {
            server_connect_failed(entry, proxies, fdtab, poller, now, false);
        }
        None
    }

    /// The request found every server full: it waits for a slot, or, once there, gives up
    /// when `timeout queue` is over (`503`, `sQ`; `econ` counts it, as for a failed connect).
    fn wait_in_queue(entry: &mut SessionEntry, proxies: &Proxies, now: Tick, be_idx: usize) -> Option<crate::stats_html::AdminAction> {
        if let Some(deadline) = entry.sess.queue.deadline() {
            if deadline.is_expired(now) {
                entry.sess.queue.leave();
                proxies[be_idx].counters().failed_conn.fetch_add(1, Ordering::Relaxed);
                entry.sess.log.term = Some(*b"sQ");
                entry.sess.log.queue.get_or_insert_with(crate::txnlog::loop_now);
                reply_error(entry, proxies, 503);
            }
            return None;
        }
        let ms = entry.sess.queue_ms();
        let deadline = if ms == 0 { Tick::ETERNITY } else { now.add(ms) };
        entry.sess.log.be_queue = entry.sess.queue.enter(entry.task, be_idx, proxies[be_idx].stats.clone(), deadline);
        None
    }

    fn connect_tcp_backend(
        entry: &mut SessionEntry,
        proxies: &[Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        now: Tick,
    ) {
        let Some(be_idx) = Self::resolve_backend(entry, proxies) else {
            // `force-be-switch` sent the connection to a disabled backend: no server.
            entry.sess.srv_state = ScState::Error;
            return;
        };
        // Back here after the backend's `tcp-request content` rules waited: the stream is
        // already counted for the backend.
        let resumed = entry.sess.be_inspect;
        entry.backend_idx = be_idx;
        enter_backend(entry, proxies, be_idx);
        entry.sess.retry_conn = proxies[be_idx].ids.retry_on & ibex_config::RE_CONN_FAILED != 0;
        entry.sess.set_backend_timeouts(&proxies[be_idx]);
        stream_timeouts_enter(proxies, entry.proxy_idx, be_idx, &entry.sess);
        if !resumed {
            // `stream_set_backend` counts the stream for the backend (`proxy_inc_be_ctr`).
            proxies[be_idx].counters().be_sess_rate.tick();
            if be_idx != entry.proxy_idx {
                entry.sess.set_retries(proxies[be_idx].retries);
            }
        }
        arm_res_inspect(&proxies[be_idx], &mut entry.sess);

        if !proxies[be_idx].tcp_req_content_rules.is_empty() {
            if !resumed {
                // The backend's own `inspect-delay`, from the first pass over its rules
                // (`stream_set_backend` clears the analyser's expiry).
                entry.sess.inspect_exp = proxies[be_idx]
                    .tcp_req_inspect_delay
                    .map(|d| now.add(u32::try_from(d.as_millis()).unwrap_or(u32::MAX)));
            }
            crate::resolvers::dr_set_task(entry.task);
            let res = eval_tcp_req_content_rules(
                &proxies[be_idx],
                entry.proxy_idx,
                proxies,
                sample_registry(),
                &mut entry.sess,
                now,
                0,
            );
            if res == ContentEvalResult::Waiting {
                // Held until the delay is over, or the request says more: the server is
                // not connected, and this runs again.
                entry.sess.be_inspect = true;
                return;
            }
            entry.sess.be_inspect = false;
            entry.sess.inspect_exp = None;
            match res {
                ContentEvalResult::Reject => {
                    entry.sess.abort_client();
                    proxies[be_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return;
                }
                ContentEvalResult::SilentDrop(ttl) => {
                    let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                    entry.sess.silent_drop_client(is_ipv6, ttl);
                    proxies[be_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return;
                }
                ContentEvalResult::Done | ContentEvalResult::Waiting => {}
            }
        }

        let source_ip = entry.sess.client_addr.map(|a| a.ip());
        let chosen = Self::use_server(&entry.sess, be_idx, proxies);
        let assigned = chosen.is_some();
        let direct = chosen.or(Self::sticking_rules(&mut entry.sess, be_idx, proxies, assigned));
        entry.sess.lb_picked = direct.is_none();
        // The slot is taken with the pick (T590); a server persistence names is counted
        // whether or not it is full, as before.
        let be = &proxies[be_idx];
        let target = match direct {
            Some(i) => Some(((Some(i), be.servers.at(i)), false)),
            None => be.pick_and_take(true, || be.select_server_with_key_idx(source_ip, entry.sess.req_uri.as_deref())),
        };

        let Some(((s_idx, target_addr), counted)) = target else {
            entry.sess.srv_state = ScState::Error;
            return;
        };

        count_server_session(proxies, be_idx, s_idx);

        if let Some(idx) = s_idx.filter(|_| !counted) {
            if idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
        count_connect(proxies, be_idx, s_idx, false);
        entry.target_server_idx = s_idx;
        entry.srv_backend_idx = be_idx;

        maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

        set_target(entry, target_addr);
        // A connect that completed at once (`connect()` returning 0, which a TCP socket on
        // Linux never does: it is EINPROGRESS even on loopback) takes the same path: the
        // socket is reported writable on the next poll and completes there. Only INET
        // servers exist (`unix@` is refused at parse time), so no test could reach a
        // separate branch for it.
        if let Ok((srv_fd, _immediate)) = raw::connect_opts(connect_addr(target_addr, entry.sess.server_addr), proxies[be_idx].server_tfo_of(target_addr))
        .inspect_err(|e| entry.sess.bc_err = Some(crate::proxy::bc_connect_now_errno(e)))
    {
            let sfd = srv_fd.as_raw_fd();
            attach_server_to(&mut entry.sess, proxies, entry.proxy_idx, be_idx, s_idx, srv_fd, now);
            entry.srv_raw_fd = Some(sfd);
            {
                entry.srv_interest = Interest::WRITE;
                fdtab.insert(
                    sfd,
                    FdState::Conn {
                        task: entry.task,
                        conn: 1,
                    },
                    Interest::WRITE,
                );
                if let Some(ref srv) = entry.sess.srv {
                    let _ = poller.add(srv.as_fd(), raw_fd_to_u64(sfd), false, true);
                }
            }
        } else {
            server_connect_failed(entry, proxies, fdtab, poller, now, false);
        }
    }

    fn step_check(&mut self, check_idx: usize) -> Outcome {
        if check_idx < self.checks.len() {
            let check = &mut self.checks[check_idx];
            let now = self.now;
            crate::track::adopt_for(self.proxies, check);
            let step = check::step_check(check, self.fdtab, self.poller, now, self.proxies);

            let proxy_idx = check.proxy();
            let server_idx = check.server();
            if crate::resolvers::take_l4_timeout() {
                trigger_resolutions(self.resolvers, &mut self.timer_updates, now, proxy_idx, server_idx);
            }
            crate::track::publish_check(self.proxies, check);

            // The message is built while `check` is still borrowed, then the borrow ends
            // so the targets (which live behind `&self`) can be read to send it.
            let pending = (
                check.task,
                step.as_ref()
                    .ok()
                    .and_then(|s| s.next)
                    .unwrap_or(check.next_check),
            );
            let log = step.ok().and_then(|s| s.event).and_then(|event| {
                let proxy = self.proxies.get(proxy_idx)?;
                // HAProxy logs "Health check for server ..." only under `option
                // log-health-checks` (src/check.c, PR_O2_LOGHCHKS), a transition too; the
                // transition has its own line, "Server ... is DOWN" (`crate::srvlog`).
                // Without that gate a one-second check interval fills a collector with a
                // line per server per second.
                if !proxy.log_health_checks {
                    return None;
                }
                let server = proxy
                    .server_ids
                    .get(server_idx)
                    .map_or("?", String::as_str);
                Some(check.log_line(&proxy.name, server, event))
            });

            if let Some(msg) = log {
                self.send_log(proxy_idx, LogLevel::Notice, b"", msg.as_bytes());
            }

            self.timer_updates.push(pending);
            Outcome::Keep
        } else {
            Outcome::Done
        }
    }

    /// Runs `resolvers` section `idx` (`crate::resolvers`): its log lines go to the servers'
    /// proxies and to stderr, as `HAProxy`'s `send_log` and `ha_warning`. Out of line: kept off
    /// the stream path's code.
    #[cold]
    #[inline(never)]
    fn step_resolver(&mut self, idx: usize) -> Outcome {
        let Some(sec) = self.resolvers.get_mut(idx) else { return Outcome::Done };
        // Lines are rare (a change of a server's address or state): a `Vec` per change.
        let mut lines: Vec<(usize, LogLevel, String, bool)> = Vec::new();
        let wait = sec.step(self.proxies, self.checks, &mut |p, level, msg, stderr| lines.push((p, level, msg.to_string(), stderr)), &mut self.fdtab, &self.poller);
        let task = sec.task;
        // T489: the `do-resolve` answers back to the workers that asked.
        for m in sec.take_dr_answers() {
            self.mailboxes.post(m.wid, crate::mailbox::Msg::DoResolved(m));
        }
        for (p, level, msg, stderr) in lines {
            if stderr {
                crate::stderr_line!("[WARNING]  ({}) : {msg}", self.pid);
            }
            self.send_log(p, level, b"", msg.as_bytes());
        }
        let ms = u32::try_from(wait.as_micros().div_ceil(1000)).unwrap_or(u32::MAX).max(1);
        self.timer_updates.push((task, self.now.add(ms)));
        Outcome::Keep
    }

    /// Emits one line to every syslog target the given proxy resolved to.
    ///
    /// Silent when the proxy has no targets, which is the common case: `HAProxy` logs
    /// nothing unless a `log` directive says where to.
    /// A transaction's or connection's log line, at `info` as `HAProxy` sends them.
    fn send_log_line(&self, proxy_idx: usize, line: &[u8]) {
        self.send_log(proxy_idx, LogLevel::Info, b"", line);
    }

    /// A stream's line: `info`, or `err` when it failed and the frontend has `option
    /// log-separate-errors` (`strm_log`).
    /// The first `sd` bytes of `line` are its STRUCTURED-DATA (`log-format-sd`).
    fn send_stream_log(&self, proxy_idx: usize, err: bool, line: &[u8], sd: u32) {
        let separate = self.proxies.get(proxy_idx).is_some_and(|p| p.log_opts & ibex_config::LOG_OPT_SEPARATE_ERRORS != 0);
        let (sd, line) = line.split_at(usize::try_from(sd).unwrap_or(0).min(line.len()));
        self.send_log(proxy_idx, if err && separate { LogLevel::Err } else { LogLevel::Info }, sd, line);
    }

    /// `sd` is the line's STRUCTURED-DATA, which only an rfc5424 target writes (`-` when
    /// empty, as for every line `HAProxy` sends through `send_log`).
    fn send_log(&self, proxy_idx: usize, level: LogLevel, sd: &[u8], msg: &[u8]) {
        let Some(proxy) = self.proxies.get(proxy_idx) else {
            return;
        };
        for (k, &i) in proxy.log_target_idx.iter().enumerate() {
            let Some(target) = self.log_targets.get(i) else {
                continue;
            };
            // Level first: a line the logger filters out does not take a sampling slot.
            if !target.accepts(level) {
                continue;
            }
            if let (Some(sample), Some(cursor)) = (target.sample(), proxy.log_cursors.get(k)) {
                if !crate::syslog::sample_admits(sample, cursor) {
                    continue;
                }
            }
            let tag = proxy.log_tag.as_deref().unwrap_or(self.log_tag);
            // Discarded deliberately: syslog over UDP is fire-and-forget, and a
            // collector that is down must not slow or fail the data path.
            // No hostname in the header: `HAProxy` sends one only with
            // `log-send-hostname`, which Ibex does not have.
            let _ = target.send_sd(level, tag, "", sd, msg);
        }
    }

    fn step_applet(&mut self, applet_idx: usize) -> Outcome {
        let applet_id = usize_to_u32(applet_idx);
        let Some(applet) = self.applets.get_mut(applet_id) else {
            return Outcome::Done;
        };

        if applet.is_finished() {
            if let Some(applet) = self.applets.free(applet_id) {
                if let Some(ref stream) = applet.stream {
                    let _ = self.poller.delete(stream.as_fd());
                }
                self.fdtab.remove(applet.raw_fd);
            }
            return Outcome::Done;
        }

        let now = self.now;
        if applet.interest.readable && self.fdtab.ready(applet.raw_fd).readable {
            let had = applet.in_buf.len();
            applet.read_input();
            if applet.in_buf.len() > had {
                applet.last_activity = now;
            }
        }

        let mut applet_ctx = AppletContext {
            proxies: self.proxies,
            checks: self.checks,
            sessions: Some(self.sessions),
            wake_queue: Some(&mut self.wake_queue),
            start_time: self.start_time,
            pid: self.pid,
            total_tasks: self.total_tasks,
            run_queue_len: self.run_queue_len,
            now,
            mailboxes: self.mailboxes,
            worker_id: self.worker_id,
            task: applet.task,
        };

        applet.process_commands(&mut applet_ctx);
        while applet.table_pending() {
            let left = applet.out_buf.len() - applet.out_offset;
            applet.pump_table(&applet_ctx);
            if applet.out_buf.len() - applet.out_offset < left || applet.out_buf.is_empty() {
                applet.last_activity = now;
            }
            if applet.table_pending() {
                break;
            }
            // The table is out: the commands that came after it in `prompt` mode run now.
            applet.process_commands(&mut applet_ctx);
        }

        if !applet.out_buf.is_empty() {
            let left = applet.out_buf.len() - applet.out_offset;
            applet.write_output();
            // A long answer read slowly is activity, as `HAProxy`'s `timeout client` on
            // the CLI stream sees it.
            if applet.out_buf.len() - applet.out_offset < left {
                applet.last_activity = now;
            }
        }

        // Ended once its answer is out, not on the client's EOF nor before the workers
        // have answered; and at `stats timeout` when it sends nothing or reads nothing of
        // what is queued (`HAProxy` closes it then too), so a forgotten connection does not
        // hold its descriptor for ever (T226).
        if applet.is_finished() || applet.last_activity.add(applet.timeout_ms).is_expired(now) {
            if let Some(applet) = self.applets.free(applet_id) {
                if let Some(ref stream) = applet.stream {
                    let _ = self.poller.delete(stream.as_fd());
                }
                self.fdtab.remove(applet.raw_fd);
            }
            return Outcome::Done;
        }

        let new_interest = applet.wants();

        if new_interest != applet.interest {
            applet.interest = new_interest;
            self.fdtab.set_interest(applet.raw_fd, new_interest);
            if let Some(ref stream) = applet.stream {
                let _ = self.poller.modify(
                    stream.as_fd(),
                    raw_fd_to_u64(applet.raw_fd),
                    new_interest.readable,
                    new_interest.writable,
                );
            }
        }

        // A `show table` that stopped for its budget with the socket still taking data is
        // due again now; one blocked on the socket waits for it.
        let due = if applet.table_pending() && applet.out_buf.is_empty() { now } else { applet.last_activity.add(applet.timeout_ms) };
        self.timer_updates.push((applet.task, due));
        Outcome::Keep
    }
}

impl Dispatch for EngineDispatcher<'_> {
    fn run(&mut self, kind: WorkKind, woken: u32) -> Outcome {
        let outcome = self.run_task(kind, woken);
        // `sched_stuck = 0` after every task (src/task.c:681): one store, no syscall.
        crate::watchdog::progress();
        outcome
    }

    #[inline]
    fn pop_wake_now(&mut self) -> Option<TaskRef> {
        self.wake_now.pop()
    }
}

impl EngineDispatcher<'_> {
    fn run_task(&mut self, kind: WorkKind, woken: u32) -> Outcome {
        match kind.kind() {
            Some(Kind::Stream) => {
                let session_idx = kind.index();
                // A panic in the run closes this stream, not the process (T447).
                crate::crash::contain(|| self.step_stream(session_idx, woken & state::WOKEN_TIMER != 0)).unwrap_or_else(|()| self.stream_panicked(session_idx))
            }
            Some(Kind::Check) => {
                let check_idx = kind.index() as usize;
                self.step_check(check_idx)
            }
            Some(Kind::Resolver) => self.step_resolver(kind.index() as usize),
            // Its timer fired: the engine runs the concern after the pass (L1).
            Some(Kind::Housekeeping) => {
                self.hk_due |= 1u8 << (kind.index() & 7);
                Outcome::Keep
            }
            Some(Kind::Applet) => {
                let applet_idx = kind.index() as usize;
                self.step_applet(applet_idx)
            }
            _ => Outcome::Done,
        }
    }
}

/// The engine's sample registry. Every fetch and converter lives in `ibex-sample`.
///
/// This used to re-register 29 of them here, and because `Registry::register_*` is a
/// `HashMap` insert, the copies silently won: the `ibex-sample` implementations were
/// unreachable, testable in their own crate but never actually run. They had also
/// drifted -- engine's `map` handled one match type where `ibex-sample` handles eleven,
/// and engine's `var` read an engine-local `CURRENT_VARS`, so anything added to
/// `ibex-sample` that touched vars read a map that was permanently empty.
///
/// Nothing is registered here now. The function stays because it is the one place the
/// engine builds a registry: if map files ever need preloading from the parsed config,
/// that belongs here, and `registry_tests` asserts nothing else creeps back in.
static SAMPLE_REGISTRY: std::sync::LazyLock<Registry> = std::sync::LazyLock::new(Registry::new);

pub(crate) fn sample_registry() -> &'static Registry {
    &SAMPLE_REGISTRY
}

#[cfg(test)]
pub(crate) fn build_sample_registry() -> Registry {
    Registry::new()
}

pub(crate) fn sample_to_string(smp: &Sample) -> String {
    match smp {
        Sample::Str(s) => s.clone(),
        Sample::Sint(n) => n.to_string(),
        Sample::Bool(b) => if *b { "1".to_string() } else { "0".to_string() },
        Sample::Ipv4(ip) => ip.to_string(),
        Sample::Ipv6(ip) => ip.to_string(),
        // T363a: the bytes as bytetext, so a variable gives them back (lossy UTF-8 replaced every
        // byte from 0x80 up with U+FFFD).
        Sample::Bin(b) => ibex_regex::bytetext::bytes_to_text(b),
        Sample::Meth(m) => m.as_str().to_string(),
    }
}

pub(crate) fn resolve_gpt0_val(
    expr_str: &str,
    compiled: Option<&Expr>,
    registry: &Registry,
    ctx: &SampleContext,
) -> u32 {
    let trimmed = expr_str.trim().trim_matches('"').trim_matches('\'');
    if let Ok(n) = trimmed.parse::<u32>() {
        return n;
    }
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            return n;
        }
    }
    if let Some(e) = compiled {
        if let Some(smp) = e.eval_sample(registry, ctx) {
            return match smp {
                Sample::Sint(n) => u32::try_from(n).unwrap_or(0),
                Sample::Str(ref s) => s.parse::<u32>().unwrap_or(0),
                _ => 0,
            };
        }
    }
    0
}

/// The stick-table key `expr` stands for, converted to the type of the table `table`
/// that will hold it ([`ibex_stick_table::StickTable::coerce_key`]); `None` where the
/// expression yields nothing to track, or something the table's key type cannot be made
/// of. Tracking and lookups (`in_table`, `src_*`) build their keys the same way.
/// The expression is compiled at load (T455).
pub(crate) fn resolve_stick_key(
    expr: Option<&Expr>,
    registry: &Registry,
    ctx: &SampleContext,
    table: Option<&Arc<ibex_stick_table::StickTable>>,
) -> Option<StickKey> {
    // An expression that gives no sample (a header that is absent) tracks nothing.
    let smp = expr?.eval_sample(registry, ctx)?;
    let key = crate::proxy_state::sample_stick_key(smp);
    table.map_or(Some(key.clone()), |t| t.coerce_key(key))
}

fn split_uri(uri: &str) -> (&str, &str, &str) {
    let (prefix, rest) = if let Some(stripped) = uri.strip_prefix("http://") {
        if let Some(idx) = stripped.find('/') {
            let p = &uri[..7 + idx];
            let r = &stripped[idx..];
            (p, r)
        } else {
            (uri, "/")
        }
    } else if let Some(stripped) = uri.strip_prefix("https://") {
        if let Some(idx) = stripped.find('/') {
            let p = &uri[..8 + idx];
            let r = &stripped[idx..];
            (p, r)
        } else {
            (uri, "/")
        }
    } else {
        ("", uri)
    };

    let (path, query) = if let Some((p, q)) = rest.split_once('?') {
        (p, q)
    } else {
        (rest, "")
    };

    (prefix, path, query)
}

/// A request target as (scheme and authority, path, query), for the rules that rewrite the
/// path. `None` for `*` (`OPTIONS *` has no path). The path is empty for `http://h?q=1`
/// and is `/` for `http://h`, as `HAProxy` normalizes it.
fn target_parts(uri: &str) -> Option<(&str, &str, &str)> {
    if uri == "*" {
        return None;
    }
    let after_scheme = uri.find("://").map(|i| i + 3);
    let (pfx, rest) = match after_scheme {
        Some(i) => {
            let end = uri[i..].find(['/', '?']).map_or(uri.len(), |e| i + e);
            (&uri[..end], &uri[end..])
        }
        None => ("", uri),
    };
    let rest = if after_scheme.is_some() && rest.is_empty() { "/" } else { rest };
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    Some((pfx, path, query))
}

fn rebuild_uri(prefix: &str, path: &str, query: &str) -> String {
    let mut res = String::new();
    res.push_str(prefix);
    if path.is_empty() {
        res.push('/');
    } else {
        res.push_str(path);
    }
    if !query.is_empty() {
        res.push('?');
        res.push_str(query);
    }
    res
}

pub(crate) fn format_sample_string(fmt: &str, ctx: &SampleContext, registry: &Registry) -> String {
    render_sample_format(fmt, ctx, registry, false)
}

/// [`format_sample_string`] for a format `HAProxy` parses with `LOG_OPT_HTTP` (a header
/// value, the request line parts, a redirect): each sample value has the bytes of
/// `http_encode_map` written `%XX`, so that a CR LF in it cannot end the header or the
/// line (`lf_encode_chunk`, `src/log.c`). The text of the format itself is left alone.
pub(crate) fn format_http_string(fmt: &str, ctx: &SampleContext, registry: &Registry) -> String {
    render_sample_format(fmt, ctx, registry, true)
}

/// `http_encode_map` (`init_log`, `src/log.c`): the bytes a header value cannot carry --
/// 0x00-0x08, 0x0a-0x1f and DEL. TAB, `%` and bytes from 0x80 (obs-text) pass.
pub(crate) fn http_encoded(b: u8) -> bool {
    b <= 0x08 || (0x0a..=0x1f).contains(&b) || b == 0x7f
}

/// Appends `v` (text in [`ibex_regex::bytetext`] form) with the bytes [`http_encoded`]
/// selects written `%XX`.
pub(crate) fn push_http_encoded(out: &mut String, v: &str) {
    if !v.bytes().any(http_encoded) {
        out.push_str(v);
        return;
    }
    let bytes = ibex_regex::bytetext::text_to_bytes(v);
    let mut enc = Vec::with_capacity(bytes.len() + 8);
    for &b in bytes.iter() {
        if http_encoded(b) {
            enc.extend_from_slice(format!("%{b:02X}").as_bytes());
        } else {
            enc.push(b);
        }
    }
    out.push_str(&ibex_regex::bytetext::bytes_to_text(&enc));
}

fn render_sample_format(fmt: &str, ctx: &SampleContext, registry: &Registry, http: bool) -> String {
    let mut out = String::with_capacity(fmt.len());
    render_sample_format_into(&mut out, fmt, ctx, registry, http);
    out
}

/// [`format_http_string`] appended to `out`, which a caller reuses (T437: nothing allocated
/// for a format whose samples are numbers, addresses or text).
pub(crate) fn format_http_into(out: &mut String, fmt: &str, ctx: &SampleContext, registry: &Registry) {
    render_sample_format_into(out, fmt, ctx, registry, true);
}

/// [`format_sample_string`] appended to `out`.
pub(crate) fn format_sample_into(out: &mut String, fmt: &str, ctx: &SampleContext, registry: &Registry) {
    render_sample_format_into(out, fmt, ctx, registry, false);
}

/// `smp` as a format writes it, appended to `out` through `push`, with no string of its own
/// for a number, an address or a method.
pub(crate) fn push_sample(out: &mut String, smp: &Sample, push: &dyn Fn(&mut String, &str)) {
    use std::fmt::Write as _;
    match smp {
        Sample::Str(s) => push(out, s),
        // Numbers, addresses and methods have no byte to encode.
        Sample::Sint(n) => {
            let _ = write!(out, "{n}");
        }
        Sample::Bool(b) => out.push(if *b { '1' } else { '0' }),
        Sample::Ipv4(ip) => {
            let _ = write!(out, "{ip}");
        }
        Sample::Ipv6(ip) => {
            let _ = write!(out, "{ip}");
        }
        Sample::Meth(m) => out.push_str(m.as_str()),
        // Written as text, a binary is cast with `c_bin2str`: it ends at the first NUL.
        Sample::Bin(b) => {
            let b = &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())];
            match std::str::from_utf8(b) {
                Ok(t) if !ibex_regex::bytetext::has_escapes(t) => push(out, t),
                _ => push(out, &ibex_regex::bytetext::bytes_to_text(b)),
            }
        }
    }
}

/// The alias `%<name>` of a format rendered without the access log's data, from what the
/// stream gives `ctx`: its addresses and the names of its proxies and server. An address the
/// stream has no connection for prints nothing (measured on `HAProxy` 3.5-dev8). An alias
/// with nothing here to read stays text.
pub(crate) fn push_alias(out: &mut String, name: &str, ctx: &SampleContext, push: &dyn Fn(&mut String, &str)) {
    use std::fmt::Write as _;
    let addr = |out: &mut String, a: Option<SocketAddr>| {
        if let Some(a) = a {
            let _ = write!(out, "{}", a.ip());
        }
    };
    let port = |out: &mut String, a: Option<SocketAddr>| {
        if let Some(a) = a {
            let _ = write!(out, "{}", a.port());
        }
    };
    match name {
        "ci" => addr(out, ctx.client_addr),
        "cp" => port(out, ctx.client_addr),
        "fi" => addr(out, ctx.server_addr),
        "fp" => port(out, ctx.server_addr),
        "si" => addr(out, ctx.bc_dst),
        "sp" => port(out, ctx.bc_dst),
        "f" => push(out, ctx.fe_name.unwrap_or_default()),
        // Until a backend is chosen the stream's backend is its frontend (`s->be`).
        "b" => push(out, ctx.be_name.or(ctx.fe_name).unwrap_or_default()),
        "s" => push(out, ctx.srv_name.unwrap_or("<NOSRV>")),
        "Tr" => out.push_str("0ms"),
        _ => {
            out.push('%');
            out.push_str(name);
        }
    }
}

pub(crate) fn render_sample_format_into(out: &mut String, fmt: &str, ctx: &SampleContext, registry: &Registry, http: bool) {
    let push = |out: &mut String, v: &str| if http { push_http_encoded(out, v) } else { out.push_str(v) };
    let mut chars = fmt.char_indices().peekable();

    while let Some((_, c)) = chars.next() {
        if c == '%' {
            if chars.peek().map(|p| p.1) == Some('[') {
                chars.next(); // consume '['
                // The expression is the text up to the matching `]`, borrowed from the format.
                let start = chars.peek().map_or(fmt.len(), |p| p.0);
                let mut end = fmt.len();
                let mut depth = 1;
                for (i, ec) in chars.by_ref() {
                    if ec == '[' {
                        depth += 1;
                    } else if ec == ']' {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                }
                let expr_str = &fmt[start..end];
                if let Ok(expr) = Expr::cached(expr_str) {
                    if let Some(smp) = expr.eval_sample(registry, ctx) {
                        push_sample(out, &smp, &push);
                        ibex_sample::spare::give_sample(smp);
                    }
                }
            } else if chars.peek().is_some_and(|p| p.1.is_ascii_alphanumeric()) {
                // An alias: the name is the letters and digits that follow (`parse_logformat_string`).
                let start = chars.peek().map_or(fmt.len(), |p| p.0);
                let mut end = fmt.len();
                while let Some(&(i, ac)) = chars.peek() {
                    if !ac.is_ascii_alphanumeric() {
                        end = i;
                        break;
                    }
                    chars.next();
                }
                push_alias(out, &fmt[start..end], ctx, &push);
            } else if chars.peek().map(|p| p.1) == Some('%') {
                chars.next();
                out.push('%');
            } else {
                out.push('%');
            }
        } else {
            out.push(c);
        }
    }
}

/// The wait of a `pause` rule, in ms: its fixed time, or what its expression gives (cast to
/// an integer; no value, or one not above 0, is 0), at most 2147483647.
fn pause_ms(time_ms: u32, expr: Option<&Expr>, registry: &Registry, ctx: &SampleContext) -> u32 {
    let Some(expr) = expr else { return time_ms };
    let n = expr.eval_sample(registry, ctx)
        .and_then(|smp| ibex_sample::cast::cast(smp, ibex_sample::SampleType::Sint));
    match n {
        Some(Sample::Sint(n)) => u32::try_from(n.clamp(0, 0x7fff_ffff)).unwrap_or(0),
        _ => 0,
    }
}

/// A string cast to an integer: an optional sign and the leading digits, 0 when there are none.
fn str_to_sint(s: &str) -> i64 {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = digits.bytes().take_while(u8::is_ascii_digit).fold(0i64, |a, d| a.wrapping_mul(10).wrapping_add(i64::from(d - b'0')));
    if neg { n.wrapping_neg() } else { n }
}

fn parse_timeout_val(s: &str) -> u32 {
    let s = s.trim();
    let (num_str, factor) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, 1u32)
    } else if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1000u32)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60_000u32)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3_600_000u32)
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 86_400_000u32)
    } else {
        (s, 1u32)
    };
    num_str.parse::<u32>().unwrap_or(0).saturating_mul(factor)
}

fn header_name_matches(header_key: &str, pattern: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("\0m:") {
        if let Some((meth, pat)) = rest.split_once(':') {
            match meth {
                "beg" => header_key.to_lowercase().starts_with(&pat.to_lowercase()),
                "end" => header_key.to_lowercase().ends_with(&pat.to_lowercase()),
                "sub" => header_key.to_lowercase().contains(&pat.to_lowercase()),
                "reg" => ibex_regex::UserRegex::cached(pat).is_ok_and(|re| re.is_match(header_key)),
                _ => header_key.eq_ignore_ascii_case(pat),
            }
        } else {
            header_key.eq_ignore_ascii_case(rest)
        }
    } else {
        header_key.eq_ignore_ascii_case(pattern)
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let v4_u32 = u32::from(v4);
            if let Some((net_str, mask_str)) = cidr.split_once('/') {
                if let (Ok(net_ip), Ok(prefix)) = (net_str.parse::<std::net::Ipv4Addr>(), mask_str.parse::<u32>()) {
                    let mask = if prefix == 0 { 0 } else if prefix >= 32 { u32::MAX } else { !((1u32 << (32 - prefix)) - 1) };
                    (v4_u32 & mask) == (u32::from(net_ip) & mask)
                } else {
                    false
                }
            } else if let Ok(target_ip) = cidr.parse::<std::net::Ipv4Addr>() {
                v4 == target_ip
            } else {
                false
            }
        }
        IpAddr::V6(v6) => {
            let v6_u128 = u128::from(v6);
            if let Some((net_str, mask_str)) = cidr.split_once('/') {
                if let (Ok(net_ip), Ok(prefix)) = (net_str.parse::<std::net::Ipv6Addr>(), mask_str.parse::<u32>()) {
                    let mask = if prefix == 0 { 0 } else if prefix >= 128 { u128::MAX } else { !((1u128 << (128 - prefix)) - 1) };
                    (v6_u128 & mask) == (u128::from(net_ip) & mask)
                } else {
                    false
                }
            } else if let Ok(target_ip) = cidr.parse::<std::net::Ipv6Addr>() {
                v6 == target_ip
            } else {
                false
            }
        }
    }
}

// One arm per HAProxy normalizer; a flat dispatch table reads better than
// scattering the arms across helpers.
#[allow(clippy::too_many_lines)]
fn apply_normalize_uri(
    uri: &str,
    normalizer: &str,
    full: bool,
    strict: bool,
) -> Result<String, ()> {
    let (prefix, path, query) = split_uri(uri);

    match normalizer {
        "path-merge-slashes" => {
            let mut merged_path = String::with_capacity(path.len());
            let mut last_was_slash = false;
            for c in path.chars() {
                if c == '/' {
                    if !last_was_slash {
                        merged_path.push(c);
                        last_was_slash = true;
                    }
                } else {
                    merged_path.push(c);
                    last_was_slash = false;
                }
            }
            if merged_path.is_empty() {
                merged_path.push('/');
            }
            Ok(rebuild_uri(prefix, &merged_path, query))
        }
        // T359: ports of `uri_normalizer_path_dot` and `uri_normalizer_path_dotdot`
        // (src/uri_normalizer.c). They keep empty segments (`//`) and the trailing slash, and
        // dot-dot walks the path from the end as the C does; the rest of the target (`?` and the
        // query, even an empty one) is kept as `http_replace_req_path` keeps it.
        "path-strip-dotdot" | "path-strip-dot" => {
            let p = path.as_bytes();
            let mut out: Vec<u8> = Vec::with_capacity(p.len());
            if normalizer == "path-strip-dot" {
                let mut rest = p;
                while !rest.is_empty() {
                    let (seg, more, slash) = match rest.iter().position(|&c| c == b'/') {
                        Some(i) => (rest.get(..i).unwrap_or(&[]), rest.get(i + 1..).unwrap_or(&[]), true),
                        None => (rest, &[][..], false),
                    };
                    if seg != b"." {
                        out.extend_from_slice(seg);
                        if slash {
                            out.push(b'/');
                        }
                    }
                    rest = more;
                }
            } else {
                let at = |i: isize| usize::try_from(i).ok().and_then(|i| p.get(i).copied());
                let is = |i: isize, pat: &[u8]| usize::try_from(i).ok().and_then(|i| p.get(i..i + pat.len())) == Some(pat);
                let mut off = isize::try_from(p.len()).unwrap_or(0) - 1;
                let mut up = 0;
                if off >= 2 && is(off - 2, b"/..") {
                    up += 1;
                    off -= 2;
                }
                while off >= 0 {
                    if off >= 3 && is(off - 3, b"/../") {
                        up += 1;
                        off -= 3;
                        continue;
                    }
                    if up > 0 {
                        off -= 1;
                        if off >= 0 {
                            up -= 1;
                            while off >= 0 && at(off) != Some(b'/') {
                                off -= 1;
                            }
                        }
                    } else {
                        out.extend(at(off));
                        off -= 1;
                        while off >= 0 && at(off) != Some(b'/') {
                            out.extend(at(off));
                            off -= 1;
                        }
                    }
                }
                if up > 0 {
                    out.push(b'/');
                    if !full {
                        while up > 0 {
                            out.extend_from_slice(b"../");
                            up -= 1;
                        }
                    }
                }
                out.reverse();
            }
            let new_path = String::from_utf8(out).map_err(|_| ())?;
            let tail = uri.get(prefix.len() + path.len()..).unwrap_or("");
            Ok(format!("{prefix}{new_path}{tail}"))
        }
        "query-sort-by-name" => {
            if query.is_empty() {
                return Ok(uri.to_string());
            }
            let mut pairs: Vec<&str> = query.split('&').collect();
            pairs.sort_by(|a, b| {
                let ka = a.split_once('=').map_or(*a, |(k, _)| k);
                let kb = b.split_once('=').map_or(*b, |(k, _)| k);
                ka.cmp(kb)
            });
            let new_query = pairs.join("&");
            Ok(rebuild_uri(prefix, path, &new_query))
        }
        // Both work on bytes and copy every byte they do not rewrite, so a multibyte
        // character after a `%` stays whole (T358 #1: slicing the `str` at `i + 1..i + 3`
        // panicked off a char boundary). `HAProxy` leaves a `%` that is not followed by two
        // hex digits as it is (measured, 3.5-dev8), or refuses it with `strict`.
        "percent-to-uppercase" | "percent-decode-unreserved" => {
            let decode = normalizer == "percent-decode-unreserved";
            let mut res: Vec<u8> = Vec::with_capacity(uri.len());
            let bytes = uri.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] != b'%' {
                    res.push(bytes[i]);
                    i += 1;
                    continue;
                }
                let hex = bytes.get(i + 1..i + 3).filter(|h| h.iter().all(u8::is_ascii_hexdigit));
                let Some(hex) = hex else {
                    if strict {
                        return Err(());
                    }
                    res.push(b'%');
                    i += 1;
                    continue;
                };
                let nib = |c: u8| u8::try_from(char::from(c).to_digit(16).unwrap_or(0)).unwrap_or(0);
                let value = nib(hex[0]) << 4 | nib(hex[1]);
                if decode && (value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~')) {
                    res.push(value);
                } else if decode {
                    res.extend_from_slice(&bytes[i..i + 3]);
                } else {
                    res.push(b'%');
                    res.push(hex[0].to_ascii_uppercase());
                    res.push(hex[1].to_ascii_uppercase());
                }
                i += 3;
            }
            // Only ASCII bytes were replaced by ASCII bytes: still valid UTF-8.
            String::from_utf8(res).map_err(|_| ())
        }
        "fragment-strip" => {
            let cleaned = uri.split_once('#').map_or(uri, |(u, _)| u);
            Ok(cleaned.to_string())
        }
        "fragment-encode" => {
            let encoded = uri.replace('#', "%23");
            Ok(encoded)
        }
        _ => Ok(uri.to_string()),
    }
}

/// `process_store_rules`: each key queued for a table is stored there with the id of the
/// server of backend `be_idx` that answered (`server_idx`); with no server, they are dropped.
fn commit_stick_stores(stores: impl Iterator<Item = (usize, StickKey)>, proxies: &[Proxy], be_idx: usize, server_idx: Option<usize>) {
    let id = server_idx.map(|i| proxies[be_idx].server_puid(i));
    for (t_idx, key) in stores {
        let table = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref());
        table.zip(id).into_iter().for_each(|(tbl, id)| drop(tbl.update_entry(&key, |d| d.server_id = Some(id))));
    }
}

/// Whether the server is asked to close after this request: `option http-server-close` in
/// the frontend, or `http-server-close` or `httpclose` in the backend (measured on HAProxy:
/// a frontend's `httpclose` alone leaves the server connection alone).
fn server_close(proxies: &[Proxy], fe_idx: usize, be_idx: usize) -> bool {
    use ibex_config::ast::HttpMode;
    proxies.get(fe_idx).is_some_and(|p| p.ids.http_mode == HttpMode::ServerClose)
        || proxies.get(be_idx).is_some_and(|p| p.ids.http_mode != HttpMode::KeepAlive)
}

/// `option httpclose` in the frontend: the client connection closes after each response.
fn client_close(proxies: &[Proxy], fe_idx: usize) -> bool {
    proxies.get(fe_idx).is_some_and(|p| p.ids.http_mode == ibex_config::ast::HttpMode::Close)
}

/// The request's `Connection` headers as `HAProxy` forwards them to a server: `keep-alive`
/// and `close` taken out, an `upgrade` too when there is no `Upgrade` header, and the token
/// the server connection's state calls for added (`close` when it is not to be reused,
/// `keep-alive` for an HTTP/1.0 request that keeps it; [`crate::txn::request_connection_token`]).
///
/// `opt_close` is the option's (`server_close`): a `keep-alive` a rule wrote, without a
/// `close`, cancels it, and the server connection is kept (`h1_set_srv_conn_mode`: no
/// `H1_MF_CONN_KAL`, T442; [`crate::txn::HttpTxn::srv_kal_rule`]).
fn rewrite_request_connection(sess: &mut TcpSession, opt_close: bool) {
    let http11 = sess.txn.as_ref().is_none_or(|t| t.req_http11);
    // An HTTP/1.0 request with a chunked body is sent without a `Connection` token at all:
    // `keep-alive` would be wrong for a message that ends with its connection (T430 row 2).
    let forced = !http11
        && sess.req.eoh().is_some_and(|(h, e)| crate::txn::request_framing(&sess.req.readable()[..h + e]) == crate::txn::Framing::Chunked);
    let kept = |sess: &mut TcpSession, rule_close: bool, rule_kal: bool| {
        let kal = opt_close && rule_kal && !rule_close && !forced;
        if let Some(t) = sess.txn.as_mut() {
            t.srv_kal_rule = kal;
        }
        forced || rule_close || (opt_close && !kal)
    };
    // One look at the head, no copy. The usual request has no `Connection`, or one that is
    // all `keep-alive` and `close` and goes whole, cut out of the head where it is.
    let scan = sess.req.eoh().map(|(h, e)| crate::txn::scan_connection(&sess.req.readable()[..h + e]));
    let scan = scan.unwrap_or_default();
    if scan.count == 0 || (scan.count == 1 && scan.plain) {
        if scan.count == 1 {
            // The client's `close` went before the rules (`strip_request_connection`): one
            // here is a rule's, and the server is asked to close (`h1_set_srv_conn_mode`, T439).
            let v = sess.htx_slice().and_then(|h| h.get_header("connection"));
            let (rule_close, rule_kal) = (v.is_some_and(|v| crate::txn::connection_has(v, "close")), v.is_some_and(|v| crate::txn::connection_has(v, "keep-alive")));
            let close = kept(sess, rule_close, rule_kal);
            sess.with_htx_mut(|htx| {
                let _ = htx.remove_header("connection");
            });
            if let Some(hdrs) = sess.req_headers.as_mut() {
                hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
            }
            sess.req.cut(scan.first.0, scan.first.1);
            if let Some(tok) = crate::txn::request_connection_token(close, http11, false) {
                add_req_header(sess, "Connection", tok);
            }
            return;
        }
        let close = kept(sess, false, false);
        if let Some(tok) = crate::txn::request_connection_token(close, http11, false) {
            add_req_connection(sess, tok);
        }
        return;
    }
    let hdrs: Vec<(String, String)> =
        sess.htx_slice().map_or_else(Vec::new, |h| h.headers().map(|(k, v)| (k.to_string(), v.to_string())).collect());
    let has_upgrade = hdrs.iter().any(|(k, _)| k.eq_ignore_ascii_case("upgrade"));
    let mut tokens = crate::txn::ConnTokens::default();
    let old: Vec<&str> = hdrs.iter().filter(|(k, _)| k.eq_ignore_ascii_case("connection")).map(|(_, v)| v.trim()).collect();
    let new: Vec<String> = old.iter().filter_map(|v| crate::txn::clean_connection_value(v, !has_upgrade, &mut tokens)).collect();
    let unchanged = new.len() == old.len() && new.iter().zip(&old).all(|(a, b)| a == b);
    if !unchanged {
        if let ([_], [value]) = (old.as_slice(), new.as_slice()) {
            set_req_header(sess, "Connection", value);
        } else {
            del_req_header(sess, "Connection");
            if !new.is_empty() {
                add_req_header(sess, "Connection", &new.join(","));
            }
        }
    }
    let close = kept(sess, tokens.close, tokens.keep_alive);
    if let Some(tok) = crate::txn::request_connection_token(close, http11, tokens.upgrade) {
        add_req_header(sess, "Connection", tok);
    }
}

/// The request's `Content-Length` and `Transfer-Encoding` after its rules, as `HAProxy`
/// writes them out (`h1_process_emit_headers`, `src/mux_h1.c`, T439): one the request was
/// not framed by when it was parsed (`H1_MF_CLEN`, `H1_MF_CHNK`) is not written, and of
/// the `Content-Length` it was, only the first (T442). False when that length is not a
/// number or is shorter than the body: the request cannot be sent.
fn reread_request_framing(sess: &mut TcpSession) -> bool {
    // Every request that reaches its rules has what it was framed by (`TcpSession` and
    // `h2_bridge` set it); without it, both count as framed and nothing is dropped.
    let was = sess.txn.as_ref().and_then(|t| t.req_len_hdrs).unwrap_or(crate::txn::LenHdrs { clen: true, chnk: true });
    for (name, framed) in [("content-length", was.clen), ("transfer-encoding", was.chnk)] {
        if framed || sess.htx_slice().and_then(|h| h.get_header_bytes(name.as_bytes())).is_none() {
            continue;
        }
        sess.with_htx_mut(|htx| {
            let _ = htx.remove_header(name);
        });
        // The copy of the headers, when the session keeps one (the rules that edit a header
        // make it; a head nothing has edited does not have one).
        sess.req_headers.as_mut().into_iter().for_each(|hdrs| hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case(name)));
        rebuild_req_buffer(sess);
    }
    // Framed when it was parsed and by nothing now (a rule removed the header): `HAProxy`
    // writes `content-length: 0` and skips the payload (`h1_make_eoh`, T442). With no
    // length, the server would read the body as the next request.
    let framed_now = sess.htx_slice().map(|h| ["content-length", "transfer-encoding"].iter().any(|n| h.get_header_bytes(n.as_bytes()).is_some()));
    if (was.clen || was.chnk) && framed_now == Some(false) {
        add_req_header(sess, "content-length", "0");
        if let Some(t) = sess.txn.as_mut() {
            t.req_body_dropped = true;
        }
        return true;
    }
    if was.clen {
        return reread_request_length(sess);
    }
    true
}

/// The `Content-Length` a request framed by its length has after its rules, as
/// `h1_process_emit_headers` and `h1_make_eoh` write it (T442): the first only; a length
/// given to a request with no body closes the server connection after it ("C-L without
/// data"); false for one that is not a number or is shorter than the body.
fn reread_request_length(sess: &mut TcpSession) -> bool {
    let body = match sess.txn.as_ref().map(|t| t.req) {
        Some(crate::txn::MsgState::Head { body: crate::txn::Framing::Length(n), .. }) => n,
        _ => 0,
    };
    let (mut count, mut first) = (0usize, None);
    for (_, v) in sess.htx_slice().into_iter().flat_map(|h| h.headers()).filter(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        count += 1;
        first = first.or(Some(v.trim().parse::<u64>().ok()));
    }
    let Some(len) = first else { return true };
    let Some(len) = len.filter(|&l| body == 0 || l >= body) else {
        return false;
    };
    if count > 1 {
        let value = sess.htx_slice().and_then(|h| h.get_header_bytes(b"content-length")).map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
        sess.with_htx_mut(|htx| {
            let _ = htx.set_header("content-length", &value);
        });
        if let Some(hdrs) = sess.req_headers.as_mut() {
            let mut seen = false;
            hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") || !std::mem::replace(&mut seen, true));
        }
        rebuild_req_buffer(sess);
    }
    if len > body {
        if let Some(t) = sess.txn.as_mut() {
            t.req_len_long = true;
        }
    }
    if body == 0 && len > 0 {
        add_req_header(sess, "Connection", "close");
    }
    true
}

fn set_req_header(sess: &mut TcpSession, name: &str, val: &str) {
    sess.with_htx_mut(|htx| {
        let _ = htx.set_header(name, val);
    });
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case(name)) {
        hdrs[pos].1 = val.to_string();
    } else {
        hdrs.push((name.to_string(), val.to_string()));
    }
    sess.req_headers = Some(hdrs);
    rebuild_req_buffer(sess);
}

/// [`add_req_header`] for a header `HAProxy` adds with `http_add_header` and fails the request
/// over when it does not fit (`return_int_err`: `X-Forwarded-For`, `X-Original-To`,
/// `Forwarded`): false, nothing added, when the request as it is now (the model of
/// [`req_htx_init`]) has no room for it.
fn add_req_header_fit(sess: &mut TcpSession, name: &str, val: &str) -> bool {
    if !htx_hdr_add(name, val) {
        return false;
    }
    sess.htx_reserve(name.len() + val.len());
    add_req_header(sess, name, val);
    true
}

/// `Connection: <tok>` as the last header of the request, for the token the server connection's
/// state calls for (`h1_make_headers` writes it from the connection-mode flags, `HAProxy`'s
/// `H1_MF_CONN_KAL`/`H1_MF_CONN_CLO`). The head the client sent is in the request buffer as it
/// is (the client's own tokens went at the parse, [`crate::proxy`]'s `strip_request_connection`),
/// so the line goes in where it belongs, with the HTX block; nothing is written out again. A
/// request that edits go through [`add_req_header`].
fn add_req_connection(sess: &mut TcpSession, tok: &str) {
    let plain_h1 = !REQ_REBUILD.get().0 && sess.has_htx && sess.req_headers.is_none() && sess.h2_active().is_none() && !sess.h3;
    let mut line = [0u8; 40];
    let parts: [&[u8]; 3] = [b"connection: ", tok.as_bytes(), b"\r\n"];
    let mut n = 0;
    for p in parts {
        line[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    // In place when the head is the HTX alone, ends in CRLF and has room; otherwise (an HTTP/2
    // request, a copy of the headers, a head held for edits) the HTX and the head are written out.
    let in_place = plain_h1 && sess.req.insert_last_header(&line[..n]);
    if in_place {
        let _ = sess.with_htx_mut(|htx| htx.add_header("Connection", tok));
    } else {
        add_req_header(sess, "Connection", tok);
    }
}

fn add_req_header(sess: &mut TcpSession, name: &str, val: &str) {
    sess.with_htx_mut(|htx| {
        let _ = htx.add_header(name, val);
    });
    if mirrors_req_headers(sess) {
        let mut hdrs = sess.req_headers.take().unwrap_or_default();
        hdrs.push((name.to_string(), val.to_string()));
        sess.req_headers = Some(hdrs);
    }
    rebuild_req_buffer(sess);
}

/// Whether the request's parsed header list (`req_headers`) follows its edits: when there is
/// one (HTTP/2, or a rule that copied it out), or no HTX to edit. An HTTP/1 request that
/// has its HTX is read and written from that alone, so its edits copy nothing (T437).
fn mirrors_req_headers(sess: &TcpSession) -> bool {
    sess.req_headers.is_some() || !sess.has_htx
}

/// What a pass over a list of `http-request` rules came to.
#[derive(Debug, PartialEq, Eq)]
enum RuleFlow {
    /// Every rule ran; go on to what follows.
    Next,
    /// A rule answered the request itself.
    Replied,
    /// A `wait-for-body` holds the request: the pass resumes at it when the body is here.
    Suspend,
}

/// Where a `wait-for-body` stands.
enum BodyWait {
    /// The body is here (or enough of it, or the buffer is full): the rules go on.
    Ready,
    /// Not yet; `txn.body_wait` says where to resume and until when.
    Pending,
    /// The time ran out: `408`, as `http_wait_for_msg_body` does.
    TimedOut,
    /// The client closed before the end of the request: `400`, flagged `CR`.
    ClientGone,
    /// The body does not follow its framing.
    Malformed,
}

/// `http-request wait-for-body time <t> [at-least <bytes>]`, or the wait `option
/// http-buffer-request` stands for (`time_ms` unset: the `timeout http-request` of the proxy
/// whose rules these are, as `s->be->timeout.httpreq`; unset, no deadline of its own: the
/// `timeout client` read timer applies), reached at rule `rule` of the frontend's list or, with
/// `backend`, the backend's.
///
/// The request stays in `req` until its rules are done, so the body arrives there and is
/// read in place: the wait is over when the body is complete, `at_least` bytes of it are
/// here, or `req` is as full as `HAProxy` lets a request get (`tune.bufsize` less
/// `tune.maxrewrite`); then `req.body` is what is there, chunk framing removed.
fn wait_for_request_body(
    sess: &mut TcpSession,
    fe: &Proxy,
    backend: bool,
    rule: usize,
    time_ms: Option<u32>,
    at_least: u32,
    now: Tick,
) -> BodyWait {
    // The request is in `Head` until its rules are done, which is where this runs.
    let framing = sess.txn.as_ref().map_or(crate::txn::Framing::None, |t| {
        if let MsgState::Head { body, .. } = t.req { body } else { crate::txn::Framing::None }
    });
    let held = sess.txn.as_ref().and_then(|t| t.body_wait).filter(|w| w.backend == backend && w.rule == rule);
    let deadline = match held {
        Some(w) => w.deadline,
        None => {
            // `Expect: 100-continue`: the client is invited to send its body now, and the
            // server, which was not asked, is not told to.
            let asks = |name: &str, value: &str| name.eq_ignore_ascii_case("expect") && value.trim().eq_ignore_ascii_case("100-continue");
            let expects = sess.htx_slice().is_some_and(|htx| htx.headers().any(|(name, value)| asks(name, value)));
            if expects {
                // (An HTTP/2 client is not sent the interim response: raw bytes would be no
                // HTTP/2.)
                if !sess.is_h2() {
                    sess.send_before_close(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                del_req_header(sess, "expect");
            }
            let timeouts = &fe.stats_config.raw_timeouts;
            let wait_ms = time_ms.or_else(|| timeouts.http_request.map(millis_to_u32));
            wait_ms.filter(|ms| *ms > 0).map_or(Tick::ETERNITY, |ms| now.add(ms))
        }
    };
    let data = sess.req.readable();
    let head = crate::proxy::find_eoh(data).map_or(data.len(), |(h, e)| h + e);
    let mut body = Vec::new();
    let progress = crate::txn::read_body(framing, &data[head..], &mut body);
    // The buffer is full when `tune.maxrewrite` is all that is left of it, and what a rule
    // sees of the body is what fits before that.
    let limit = sess.bufsize.saturating_sub(sess.maxrewrite);
    let full = sess.req.len() >= limit;
    body.truncate(limit.saturating_sub(head));
    let enough = at_least > 0 && body.len() >= at_least as usize;
    let outcome = if progress == crate::txn::BodyProgress::Error {
        BodyWait::Malformed
    } else if progress == crate::txn::BodyProgress::Complete || enough || full {
        BodyWait::Ready
    } else if !matches!(sess.cli_state, ScState::Ready | ScState::Established) {
        BodyWait::ClientGone
    } else if deadline.is_expired(now) {
        BodyWait::TimedOut
    } else {
        BodyWait::Pending
    };
    // The request is complete for the log when its body is here (`Tq`), and never was when
    // the wait ends otherwise.
    match outcome {
        BodyWait::Ready if held.is_some() => sess.log.request = Some(crate::txnlog::loop_now()),
        BodyWait::TimedOut | BodyWait::ClientGone | BodyWait::Malformed => sess.log.request = None,
        _ => {}
    }
    let pending = matches!(outcome, BodyWait::Pending);
    let ready = matches!(outcome, BodyWait::Ready);
    for txn in sess.txn.as_mut() {
        txn.body_wait = pending.then_some(crate::txn::BodyWait { backend, rule, deadline, tarpit: false, inspect: false, resolve: false });
        if ready {
            txn.req_body = Some(std::mem::take(&mut body));
        }
    }
    outcome
}

fn del_req_header(sess: &mut TcpSession, name: &str) {
    // `-m beg|end|sub|reg` names a set of headers: remove each that matches.
    if name.starts_with('\0') {
        let names: Vec<String> =
            sess.htx_slice().map_or_else(Vec::new, |h| h.headers().map(|(k, _)| k.to_string()).filter(|k| header_name_matches(k, name)).collect());
        sess.with_htx_mut(|htx| {
            for n in &names {
                let _ = htx.remove_header(n);
            }
        });
    } else {
        sess.with_htx_mut(|htx| {
            let _ = htx.remove_header(name);
        });
    }
    if mirrors_req_headers(sess) {
        let mut hdrs = sess.req_headers.take().unwrap_or_default();
        hdrs.retain(|(k, _)| !header_name_matches(k, name));
        sess.req_headers = Some(hdrs);
    }
    rebuild_req_buffer(sess);
}

/// Sizes the HTX message the `http-request` rules rewrite, as `HAProxy` holds the request
/// (the same model as [`res_htx_init`]'s, in the same cell): a buffer of `tune.bufsize` less
/// the 40-byte `struct htx`, holding the request line (an 8-byte block, 20 bytes of `htx_sl`
/// and the method, the target and the version), each header ([`htx_hdr_size`]), the 9-byte
/// end-of-headers, and the body bytes already in the buffer (an 8-byte block and the data),
/// of which only what fits before the `tune.maxrewrite` reserve was read.
///
/// Measured on `HAProxy` 3.5-dev8 (2026-10-04, `tests/request_rule_actions.rs`): `GET /`
/// with `Host: x` and an `x` header of `n` bytes takes a `set-header` of the same `n` bytes
/// up to `n` = 8131. It is computed from the request as it is now, so the rewrites of the
/// rules before it count and a header a rule removed gives its room back.
fn req_htx_init(sess: &TcpSession) {
    let size = sess.bufsize.saturating_sub(40);
    let hdrs: usize = sess.htx_slice().map_or(0, |h| h.headers().map(|(k, v)| htx_hdr_size(k, v)).sum());
    let data = sess.req.readable();
    let head_len = crate::proxy::find_eoh(data).map_or(data.len(), |(h, e)| h + e);
    let body = data.len().saturating_sub(head_len);
    let line = 8 + 20 + sess.req_method.as_deref().map_or(3, str::len) + sess.req_uri.as_deref().map_or(1, str::len) + 8;
    let head = line + hdrs + 9;
    let reserve = sess.maxrewrite.min(sess.bufsize / 2);
    // The body is clamped once, against the head as it was read; a rewrite after that has
    // the reserve to itself and does not shrink the body again.
    let body = match sess.req_body_htx.get() {
        Some(b) => b,
        None => {
            let b = if body == 0 { 0 } else { (8 + body).min(size.saturating_sub(reserve).saturating_sub(head)) };
            sess.req_body_htx.set(Some(b));
            b
        }
    };
    RES_HTX.set((head + body, size));
}

/// Puts `uri` in the request line when it fits the message `HAProxy` would hold
/// ([`req_htx_init`]'s model: the target takes what its length changes); false, and the
/// line as it was, when it does not (`http_replace_req_uri`, `http_req_replace_stline`
/// failing). The caller fails the request in strict mode and goes on otherwise.
fn req_set_uri(sess: &mut TcpSession, uri: String) -> bool {
    let old = sess.req_uri.as_deref().map_or(1, str::len);
    if !res_htx_resize(old, uri.len()) {
        return false;
    }
    sess.htx_reserve(old + uri.len() + 16);
    sess.with_htx_mut(|htx| {
        let _ = htx.set_uri(&uri);
    });
    sess.req_uri.set(&uri);
    rebuild_req_buffer(sess);
    true
}

/// [`req_set_uri`] for the method.
fn req_set_method(sess: &mut TcpSession, method: String) -> bool {
    let old = sess.req_method.as_deref().map_or(3, str::len);
    if !res_htx_resize(old, method.len()) {
        return false;
    }
    sess.htx_reserve(old + method.len() + 16);
    sess.with_htx_mut(|htx| {
        let _ = htx.set_method(&method);
    });
    sess.req_method.set(&method);
    rebuild_req_buffer(sess);
    true
}

/// The bytes the request's headers named `name` take in the HTX message.
fn req_hdr_bytes(sess: &TcpSession, name: &str) -> usize {
    sess.htx_slice().map_or(0, |h| h.header_blocks_where(|k| k.eq_ignore_ascii_case(name.as_bytes())).map(|(_, k, v)| htx_hdr_size(k, v)).sum())
}

/// `add-header` (`replace` false) and `set-header` (`replace` true: every occurrence goes
/// first, as `http_action_set_header` removes them before it adds) on the request. False
/// when the header does not fit; what was removed stays removed.
fn req_rule_header(sess: &mut TcpSession, name: &str, val: &str, replace: bool) -> bool {
    if replace {
        let freed = req_hdr_bytes(sess, name);
        del_req_header(sess, name);
        res_htx_resize(freed, 0);
    }
    if !htx_hdr_add(name, val) {
        return false;
    }
    sess.htx_reserve(name.len() + val.len());
    add_req_header(sess, name, val);
    // `http_add_header(.., update_authority = 1)`.
    !name.eq_ignore_ascii_case("host") || req_update_authority(sess, val)
}

/// Where the authority sits in a request target, as `http_parse_authority` finds it with
/// `no_userinfo`: after the scheme and `//`, after any user information, up to the first of
/// `/`, `?` and `#`. `scheme_required` is `http_update_authority`'s case, a target that
/// carries an authority (absolute-form, or `CONNECT`'s authority-form, which has no scheme);
/// without it a target with no scheme is read as an authority, as `http_update_host` does.
fn uri_authority_span(uri: &str, connect: bool, scheme_required: bool) -> Option<(usize, usize)> {
    let b = uri.as_bytes();
    let mut start = 0;
    if !connect {
        // `http_parse_scheme`: a letter, then letters, digits, `+`, `-`, `.`, then `://`.
        let n = b.iter().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')).count();
        if n > 0 && b[0].is_ascii_alphabetic() && b[n..].starts_with(b"://") {
            start = n + 3;
        } else if scheme_required {
            return None;
        }
    }
    let end = start + b[start..].iter().position(|c| matches!(c, b'/' | b'?' | b'#')).unwrap_or(b.len() - start);
    if let Some(at) = b[start..end].iter().rposition(|c| *c == b'@') {
        start += at + 1;
    }
    (start < end).then_some((start, end))
}

/// A `Host` header was rewritten to `host`: the authority of the request target follows
/// (`http_update_authority`). False when the new target does not fit.
fn req_update_authority(sess: &mut TcpSession, host: &str) -> bool {
    let connect = sess.req_method.as_deref() == Some("CONNECT");
    let Some(uri) = sess.req_uri.as_deref() else { return true };
    let Some((a, e)) = uri_authority_span(uri, connect, true) else { return true };
    if &uri[a..e] == host {
        return true;
    }
    let mut new = String::with_capacity(uri.len() - (e - a) + host.len());
    new.push_str(&uri[..a]);
    new.push_str(host);
    new.push_str(&uri[e..]);
    req_set_uri(sess, new)
}

/// The target was replaced by `set-uri` or `replace-uri`: every `Host` header takes its
/// authority (`http_update_host`); an origin-form or `*` target leaves them alone. False when
/// a value does not fit.
fn req_update_host(sess: &mut TcpSession) -> bool {
    let connect = sess.req_method.as_deref() == Some("CONNECT");
    let Some(uri) = sess.req_uri.as_deref() else { return true };
    if uri.is_empty() || uri.starts_with('/') || uri == "*" {
        return true;
    }
    let Some((a, e)) = uri_authority_span(uri, connect, false) else { return true };
    let auth = uri[a..e].to_string();
    let hosts: Vec<(usize, String)> = sess
        .htx_slice()
        .map_or_else(Vec::new, |h| h.header_blocks().filter(|(_, k, _)| k.eq_ignore_ascii_case("host")).map(|(i, _, v)| (i, v.to_string())).collect());
    let mut ok = true;
    let mut edits: Vec<usize> = Vec::new();
    for (i, v) in &hosts {
        if *v == auth {
            continue;
        }
        if !res_htx_resize(htx_hdr_size("host", v), htx_hdr_size("host", &auth)) {
            ok = false;
            break;
        }
        edits.push(*i);
    }
    if edits.is_empty() {
        return ok;
    }
    sess.htx_reserve(edits.len() * (auth.len() + 64));
    sess.with_htx_mut(|htx| {
        for i in &edits {
            let _ = htx.replace_block_value(*i, auth.as_bytes());
        }
    });
    sess.req_headers = sess.htx_slice().map(|h| h.headers().map(|(k, v)| (k.to_string(), v.to_string())).collect());
    rebuild_req_buffer(sess);
    ok
}

/// The bytes of a sample as `sample_fetch_as_type(.., SMP_T_BIN)` gives them.
fn sample_to_bin(smp: Sample) -> Vec<u8> {
    match smp {
        Sample::Bin(b) => b,
        Sample::Str(s) => s.into_bytes(),
        // `c_int2bin` and `c_bool2bin`: eight bytes, big-endian; `c_addr2bin`: the address.
        Sample::Sint(n) => n.to_be_bytes().to_vec(),
        Sample::Bool(b) => i64::from(b).to_be_bytes().to_vec(),
        Sample::Ipv4(ip) => ip.octets().to_vec(),
        Sample::Ipv6(ip) => ip.octets().to_vec(),
        Sample::Meth(m) => m.as_str().as_bytes().to_vec(),
    }
}

/// The pattern `header_name_matches` takes for a `del-headers-bin` name: the name itself for
/// `-m str`, `"\0m:<method>:<name>"` for the others.
fn hdrs_bin_del_pattern(op: ibex_config::HeadersBinOp, name: &str) -> std::borrow::Cow<'_, str> {
    use ibex_config::HeadersBinOp as Op;
    let method = match op {
        Op::DelBeg => "beg",
        Op::DelEnd => "end",
        Op::DelSub => "sub",
        _ => return std::borrow::Cow::Borrowed(name),
    };
    std::borrow::Cow::Owned(format!("\0m:{method}:{name}"))
}

/// `add-headers-bin`, `set-headers-bin` and `del-headers-bin` on the request, whose list is
/// `bin` (T382, `http_action_set_headers_bin` and `http_action_del_headers_bin`): each entry
/// is an `add-header`, `set-header` or `del-header` (`-m` as the action says), through the
/// same paths as those rules, so the HTX room they take is the one those rules take.
fn req_headers_bin(sess: &mut TcpSession, op: ibex_config::HeadersBinOp, prefix: &str, bin: &[u8]) -> crate::hdrs_bin::Walk {
    use ibex_config::HeadersBinOp as Op;
    match op {
        Op::Set | Op::Add => crate::hdrs_bin::walk_set(bin, prefix, &mut |n, v| req_rule_header(sess, n, v, op == Op::Set)),
        _ => crate::hdrs_bin::walk_del(bin, &mut |n| {
            let pat = hdrs_bin_del_pattern(op, n);
            let freed = sess.htx_slice().map_or(0, |h| h.headers().filter(|(k, _)| header_name_matches(k, &pat)).map(|(k, v)| htx_hdr_size(k, v)).sum());
            del_req_header(sess, &pat);
            res_htx_resize(freed, 0);
        }),
    }
}

fn replace_req_header(sess: &mut TcpSession, name: &str, regex: &str, repl: &str) -> Result<(), ()> {
    rewrite_req_header_values(sess, name, regex, repl, false)
}

fn replace_req_value(sess: &mut TcpSession, name: &str, regex: &str, repl: &str) -> Result<(), ()> {
    rewrite_req_header_values(sess, name, regex, repl, true)
}

/// `replace-header` (`per_value` false: the whole value, `repl` from the first match) and
/// `replace-value` (`per_value` true: each comma-separated value that matches, with the
/// blanks around it) on the request, `repl` read as `exp_replace` reads it
/// ([`replace_each_value`], as the response rules do). `Err` when a value does not fit or
/// `repl` is cut short and the request is in strict mode: header by header, the ones
/// before it stay rewritten.
fn rewrite_req_header_values(sess: &mut TcpSession, name: &str, regex: &str, repl: &str, per_value: bool) -> Result<(), ()> {
    let re = ibex_regex::UserRegex::cached(regex).map_err(|_| ())?;
    // Block index, name and value of each header: a value is written back by its block, never
    // turned into a pattern (it is the client's text, and a compiled pattern is kept).
    let headers: Vec<(usize, String, String)> = sess.htx_slice().map_or_else(Vec::new, |h| {
        h.header_blocks().filter(|(_, k, _)| k.eq_ignore_ascii_case(name)).map(|(i, k, v)| (i, k.to_string(), v.to_string())).collect()
    });
    let mut edits: Vec<(usize, String, String)> = Vec::new();
    let mut failed = false;
    for (i, k, v) in &headers {
        let new = if per_value {
            replace_each_value(v, &re, repl)
        } else {
            match re.captures(v) {
                Some(caps) => exp_replace(repl, &caps),
                None => continue,
            }
        };
        match new {
            Some(n) if n == *v => {}
            Some(n) if n.len() <= HTX_HDR_VALUE_MAX_LEN && res_htx_resize(htx_hdr_size(k, v), htx_hdr_size(k, &n)) => edits.push((*i, v.clone(), n)),
            _ => {
                failed = true;
                break;
            }
        }
    }
    // Each value is written at the end of the HTX, the old ones staying where they were until
    // the message is defragmented.
    sess.htx_reserve(edits.iter().map(|(_, old, new)| old.len() + new.len() + 64).sum());
    sess.with_htx_mut(|htx| {
        for (i, _, new) in &edits {
            let _ = htx.replace_block_value(*i, new.as_bytes());
        }
    });
    rebuild_req_buffer(sess);
    // `http_replace_header(_value)(.., update_authority = 1)`: the last value written.
    if name.eq_ignore_ascii_case("host") {
        if let Some((_, _, last)) = edits.last() {
            failed |= !req_update_authority(sess, last);
        }
    }
    if failed && STRICT_MODE.get() {
        Err(())
    } else {
        Ok(())
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `http_manage_client_side_cookies`: the backend's `cookie` line applied to the request's
/// `Cookie` headers, which are cut in place (`indirect`, `prefix`) and may name the server
/// (`server ... cookie <value>`). Returns that server's index. What the response needs
/// goes to the transaction (`HttpTxn::ck`).
fn manage_client_cookies(sess: &mut TcpSession, be: &Proxy) -> Option<usize> {
    let cfg = be.cookie.as_ref()?;
    // `cur_state != SRV_ST_STOPPED`: a draining server still takes its clients.
    let servers: Vec<crate::cookie::SrvCookie<'_>> = (0..be.servers.len())
        .map(|i| crate::cookie::SrvCookie {
            value: be.server_cookies.get(i).and_then(Option::as_deref).map(str::as_bytes),
            persistent: be.ids.persist,
            usable: be
                .server_statuses
                .get(i)
                .map(|s| s.load(Ordering::Relaxed))
                .is_some_and(|s| s == ServerStatus::Up as u8 || s == ServerStatus::Drain as u8),
        })
        .collect();
    // The HTX head: its block indices stay valid while others are replaced or removed.
    let blocks: Vec<(usize, Vec<u8>)> = sess.htx_slice().map(|h| {
        h.header_blocks().filter(|(_, k, _)| k.eq_ignore_ascii_case("cookie")).map(|(i, _, v)| (i, v.as_bytes().to_vec())).collect()
    })?;
    if blocks.is_empty() {
        return None;
    }
    let values: Vec<Vec<u8>> = blocks.iter().map(|(_, v)| v.clone()).collect();
    let (srv, st, edits) = crate::cookie::client_side(cfg, unix_now(), &servers, &values);
    if let Some(txn) = sess.txn.as_mut() {
        txn.ck = st;
    }
    if edits.iter().all(|e| *e == crate::cookie::HeaderEdit::Keep) {
        return srv;
    }
    sess.with_htx_mut(|htx| {
        for ((idx, _), e) in blocks.iter().zip(&edits) {
            match e {
                crate::cookie::HeaderEdit::Keep => {}
                crate::cookie::HeaderEdit::Set(v) => {
                    let _ = htx.replace_block_value(*idx, v);
                }
                crate::cookie::HeaderEdit::Remove => htx.remove_block(*idx),
            }
        }
    });
    // The parsed list is what `req.hdr` fetches read: it follows the head.
    sess.req_headers = sess.htx_slice().map(|h| h.headers().map(|(k, v)| (k.to_string(), v.to_string())).collect());
    rebuild_req_buffer(sess);
    srv
}

/// Writes the request head out of its HTX into the request buffer, or, while the rules hold it
/// ([`hold_req_rebuild`]), notes that it is due: a run of header edits writes the head once.
fn rebuild_req_buffer(sess: &mut TcpSession) {
    if REQ_REBUILD.get().0 {
        REQ_REBUILD.set((true, true));
        return;
    }
    write_req_head(sess);
}

/// From here to [`release_req_rebuild`], the head edits only change the HTX (S7: five header
/// rules were five rebuilds, each an 8 KiB `memset`, a `memmove` and the request line split
/// again).
fn hold_req_rebuild() {
    REQ_REBUILD.set((true, false));
}

/// The head written out if an edit is due, before anything reads the request buffer; `hold`
/// to go on holding after.
fn flush_req_rebuild(sess: &mut TcpSession, hold: bool) {
    let (_, due) = REQ_REBUILD.replace((false, false));
    if due {
        write_req_head(sess);
    }
    REQ_REBUILD.set((hold, false));
}

/// [`flush_req_rebuild`], and no more holding.
fn release_req_rebuild(sess: &mut TcpSession) {
    flush_req_rebuild(sess, false);
}

fn write_req_head(sess: &mut TcpSession) {
    let Some((hdr_len, eoh_len)) = sess.req.eoh() else {
        return;
    };
    ibex_sample::work::note(ibex_sample::work::Op::ReqRebuild, 1);
    if let Some(htx) = sess.htx_slice() {
        if sess.h2_active().is_some_and(|a| a.chunk_out) {
            let mut wire = htx.write_h1_wire_vec();
            // An HTTP/2 request without a length goes out chunked: the header is written with
            // the head, after the rules, which never saw it.
            if !wire.is_empty() {
                if let Some((h, _)) = crate::proxy::find_eoh(&wire) {
                    wire = crate::h2_bridge::chunked_head(&wire, h);
                }
            }
            sess.req.replace_prefix(hdr_len + eoh_len, &wire);
        } else {
            // Through the stack when the head fits; the head is only larger than this with a
            // Vec (`write_h1_wire_vec` grows until it fits).
            let mut stack = [0u8; 8192];
            match htx.write_h1_wire(&mut stack) {
                Ok(n) => sess.req.replace_prefix(hdr_len + eoh_len, &stack[..n]),
                Err(_) => sess.req.replace_prefix(hdr_len + eoh_len, &htx.write_h1_wire_vec()),
            }
        }
    } else {
        let method = sess.req_method.as_deref().unwrap_or("GET");
        let uri = sess.req_uri.as_deref().unwrap_or("/");
        let mut new_hdr = format!("{method} {uri} HTTP/1.1\r\n");
        if let Some(ref hdrs) = sess.req_headers {
            for (k, v) in hdrs {
                let _ = write!(new_hdr, "{k}: {v}\r\n");
            }
        }
        new_hdr.push_str("\r\n");
        sess.req
            .replace_prefix(hdr_len + eoh_len, new_hdr.as_bytes());
    }
}

pub(crate) fn eval_condition(
    cond: &ibex_config::AclCondition,
    ctx: &SampleContext,
    acls: &ibex_sample::Acls,
    registry: &Registry,
) -> bool {
    crate::proxy::combine_condition(cond, |term| {
        let term_res = if term.name == "always_true" {
            true
        } else if term.name == "always_false" {
            false
        } else if let Some(expr) = acls.get(&term.name) {
            expr.eval(registry, ctx)
        } else if let Ok(expr) = Expr::cached(&term.name) {
            expr.eval(registry, ctx)
        } else {
            false
        };
        if term.negated ^ term_res {
            crate::proxy::AclEvalResult::Matched
        } else {
            crate::proxy::AclEvalResult::NotMatched
        }
    }) == crate::proxy::AclEvalResult::Matched
}

const fn status_reason(status: u16) -> &'static str {
    ibex_proto::status_reason_phrase(status)
}

/// HAProxy's built-in error pages, transcribed byte-for-byte from `http_err_msgs` in
/// `src/http.c` (3.5-dev7): status code paired with the full raw response HAProxy sends
/// when nothing -- no `errorfile`, `errorfiles`, or `http-error` -- customises that code.
/// This is the last fallback `default-errorfiles` (explicit, or implied by a bare `deny`)
/// resolves to, and it is why, for example, an unconfigured 403 has `Content-length: 93`.
const BUILTIN_ERROR_PAGES: &[(u16, &str)] = &[
    (200, "HTTP/1.1 200 OK\r\nContent-length: 58\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n"),
    (400, "HTTP/1.1 400 Bad request\r\nContent-length: 90\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n"),
    (401, "HTTP/1.1 401 Unauthorized\r\nContent-length: 112\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>401 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n"),
    (403, "HTTP/1.1 403 Forbidden\r\nContent-length: 93\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>\n"),
    (404, "HTTP/1.1 404 Not Found\r\nContent-length: 83\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>404 Not Found</h1>\nThe resource could not be found.\n</body></html>\n"),
    (405, "HTTP/1.1 405 Method Not Allowed\r\nContent-length: 147\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>405 Method Not Allowed</h1>\nA request was made of a resource using a request method not supported by that resource.\n</body></html>\n"),
    (407, "HTTP/1.1 407 Unauthorized\r\nContent-length: 112\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>407 Unauthorized</h1>\nYou need a valid user and password to access this content.\n</body></html>\n"),
    (408, "HTTP/1.1 408 Request Time-out\r\nContent-length: 110\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>408 Request Time-out</h1>\nYour browser didn't send a complete request in time.\n</body></html>\n"),
    (410, "HTTP/1.1 410 Gone\r\nContent-length: 114\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>410 Gone</h1>\nThe resource is no longer available and will not be available again.\n</body></html>\n"),
    (413, "HTTP/1.1 413 Payload Too Large\r\nContent-length: 106\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>413 Payload Too Large</h1>\nThe request entity exceeds the maximum allowed.\n</body></html>\n"),
    (414, "HTTP/1.1 414 URI Too Long\r\nContent-length: 110\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>414 URI Too Long</h1>\nThe URI provided was too long for the server to process.\n</body></html>\n"),
    (421, "HTTP/1.1 421 Misdirected Request\r\nContent-length: 104\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>421 Misdirected Request</h1>\nRequest sent to a non-authoritative server.\n</body></html>\n"),
    (422, "HTTP/1.1 422 Unprocessable Content\r\nContent-length: 116\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>422 Unprocessable Content</h1>\nThe server cannot process the contained instructions.\n</body></html>\n"),
    (425, "HTTP/1.1 425 Too Early\r\nContent-length: 80\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>425 Too Early</h1>\nYour browser sent early data.\n</body></html>\n"),
    (429, "HTTP/1.1 429 Too Many Requests\r\nContent-length: 117\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>429 Too Many Requests</h1>\nYou have sent too many requests in a given amount of time.\n</body></html>\n"),
    (431, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-length: 105\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>431 Request Header Fields Too Large</h1>\nRequest Header Fields Too Large.\n</body></html>\n"),
    (500, "HTTP/1.1 500 Internal Server Error\r\nContent-length: 97\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>500 Internal Server Error</h1>\nAn internal server error occurred.\n</body></html>\n"),
    (501, "HTTP/1.1 501 Not Implemented\r\nContent-length: 135\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>501 Not Implemented</h1>\nThe server does not support the functionality required to fulfill the request.\n</body></html>\n"),
    (502, "HTTP/1.1 502 Bad Gateway\r\nContent-length: 107\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>502 Bad Gateway</h1>\nThe server returned an invalid or incomplete response.\n</body></html>\n"),
    (503, "HTTP/1.1 503 Service Unavailable\r\nContent-length: 107\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n</body></html>\n"),
    (504, "HTTP/1.1 504 Gateway Time-out\r\nContent-length: 92\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\n\r\n<html><body><h1>504 Gateway Time-out</h1>\nThe server didn't respond in time.\n</body></html>\n"),
];

/// What ends the response rules early: the reply that goes out in place of the response.
/// `Page` is the proxy's page for the status (`deny`, `deny deny_status <code>`, a rewrite
/// that fails in strict mode), `Empty` the status line and `content-length: 0` alone
/// (`deny status <code>`, an `http_reply` with no body, `src/http_htx.c`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum ResStop {
    Page(u16),
    Empty(u16),
    /// A whole reply the rule made (`http-response redirect`).
    Reply(Vec<u8>),
    /// `http-response return`: the reply is built from the rule's arguments once the
    /// server's response is gone (`http_action_return`), as `http-request return` builds it.
    Return { status: u16, content_type: Option<String>, reply: Option<std::sync::Arc<crate::rule_compiled::Reply>>, page: Option<std::sync::Arc<crate::rule_compiled::Reply>>, error_page: Option<ibex_config::ErrorPageSource> },
    /// `http-response silent-drop`: nothing goes to the client, which is not told.
    SilentDrop,
}

/// One `http-response` or `http-after-response` action, whichever list it comes from.
/// The configuration encodes the actions that are not header edits as a `SetHeader` (or,
/// for `unset-var`, a `DelHeader`) whose name starts with a NUL (`rules_http.rs`).
#[derive(Clone, Copy)]
enum ResOp<'a> {
    /// The name, the format (or what the name says it is), and what the rule compiled of it.
    Set(&'a str, &'a str, &'a crate::rule_compiled::Rule),
    /// The name, and the rule's compiled format.
    Add(&'a str, &'a crate::rule_compiled::Rule),
    Del(&'a str),
    Status(u16, Option<&'a str>),
    /// `http-response redirect location <fmt> code <c> [cookie]`.
    Redirect(u16, Option<&'a ibex_config::RedirectCookie>, &'a crate::rule_compiled::Rule),
    /// `http-response return`: status, content type, formatted body, error page.
    Return(u16, Option<&'a str>, Option<&'a ibex_config::ErrorPageSource>, &'a crate::rule_compiled::Rule),
}

/// The `wait-for-body` of a response rule list: the rule the pass starts at, and the check a
/// `wait-for-body` rule (its index in the list, `time` in ms, `at-least`) is put to.
struct ResWait<'a> {
    start: usize,
    check: &'a mut dyn FnMut(usize, u32, u32) -> BodyWait,
}

/// An entry of a response rule list: a [`ResOp`] on the response head, or -- `capture` only
/// being in `http-response` -- a sample (a fetch expression) written to a capture slot.
#[derive(Clone, Copy)]
enum ResRule<'a> {
    Op(ResOp<'a>),
    Capture(Option<&'a Expr>, usize),
    /// `wait-for-body time <ms> at-least <bytes>`.
    Wait(u32, u32),
    /// `pause <time|expr>`: the time, the expression.
    Pause(u32, Option<&'a Expr>),
}

/// The `at_least` a [`ResWait`] check is called with for a `pause` rule: its `time_ms` is
/// then the pause, and the check says whether it is still running.
const PAUSE_RULE: u32 = u32::MAX;

impl<'a> ResOp<'a> {
    fn of_res(a: &'a ibex_config::HttpResAction, rc: &'a crate::rule_compiled::Rule) -> ResRule<'a> {
        ResRule::Op(match a {
            ibex_config::HttpResAction::SetHeader { name, fmt } => Self::Set(name, fmt, rc),
            ibex_config::HttpResAction::AddHeader { name, .. } => Self::Add(name, rc),
            ibex_config::HttpResAction::DelHeader { name } => Self::Del(name),
            ibex_config::HttpResAction::SetStatus { status, reason } => Self::Status(*status, reason.as_deref()),
            ibex_config::HttpResAction::Redirect { code, cookie, .. } => Self::Redirect(*code, cookie.as_ref(), rc),
            ibex_config::HttpResAction::Return { status, content_type, error_page, .. } => {
                Self::Return(*status, content_type.as_deref(), error_page.as_ref(), rc)
            }
            ibex_config::HttpResAction::Capture { id, .. } => return ResRule::Capture(rc.expr.as_ref(), *id),
            ibex_config::HttpResAction::WaitForBody { time_ms, at_least } => return ResRule::Wait(*time_ms, *at_least),
            ibex_config::HttpResAction::Pause { time_ms, .. } => return ResRule::Pause(*time_ms, rc.expr.as_ref()),
        })
    }

    fn of_after_res(a: &'a ibex_config::HttpAfterResAction, rc: &'a crate::rule_compiled::Rule) -> ResRule<'a> {
        ResRule::Op(match a {
            ibex_config::HttpAfterResAction::Capture { id, .. } => return ResRule::Capture(rc.expr.as_ref(), *id),
            ibex_config::HttpAfterResAction::SetHeader { name, fmt } => Self::Set(name, fmt, rc),
            ibex_config::HttpAfterResAction::AddHeader { name, .. } => Self::Add(name, rc),
            ibex_config::HttpAfterResAction::DelHeader { name } => Self::Del(name),
        })
    }
}

#[cfg(debug_assertions)]
thread_local! {
    static RSP_HEAD_WRITES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// A server's response head was written again in the response buffer (debug builds).
#[inline]
fn note_response_head_write() {
    #[cfg(debug_assertions)]
    RSP_HEAD_WRITES.with(|c| c.set(c.get() + 1));
}

/// The writes [`note_response_head_write`] counted on this thread (0 in release builds): a
/// test pins one a response with rules and none without (X3).
#[must_use]
pub fn response_head_writes() -> u64 {
    #[cfg(debug_assertions)]
    return RSP_HEAD_WRITES.with(std::cell::Cell::get);
    #[cfg(not(debug_assertions))]
    0
}

/// `f` on the response headers the rules edit, which are the ones the response fetches read
/// (`CURRENT_RES_HEADERS`, X3): no copy of them per rule. Nothing `f` does may evaluate a
/// fetch (the list is borrowed for it): a rule's format and condition are evaluated before.
fn with_res_hdrs<R>(f: impl FnOnce(&mut Vec<(String, String)>) -> R) -> R {
    CURRENT_RES_HEADERS.with(|h| f(&mut h.borrow_mut()))
}

/// `name: value\r\n` for each header, without the formatting machinery.
fn push_header_lines(out: &mut String, hdrs: &[(String, String)]) {
    for (k, v) in hdrs {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
}

/// `status` in decimal.
fn push_status(out: &mut String, status: u16) {
    let mut digits = [0u8; 5];
    let mut i = digits.len();
    let mut n = status;
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    digits[i..].iter().for_each(|&d| out.push(char::from(d)));
}

/// [`req_headers_bin`] for the response headers `hdrs`.
fn res_headers_bin(op: ibex_config::HeadersBinOp, prefix: &str, bin: &[u8], hdrs: &mut Vec<(String, String)>) -> crate::hdrs_bin::Walk {
    use ibex_config::HeadersBinOp as Op;
    match op {
        Op::Set | Op::Add => crate::hdrs_bin::walk_set(bin, prefix, &mut |n, v| {
            if op == Op::Set {
                let freed: usize = hdrs.iter().filter(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(k, v)| htx_hdr_size(k, v)).sum();
                hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case(n));
                res_htx_resize(freed, 0);
            }
            if !res_htx_resize(0, htx_hdr_size(n, v)) {
                return false;
            }
            hdrs.push((n.to_string(), v.to_string()));
            true
        }),
        _ => crate::hdrs_bin::walk_del(bin, &mut |n| {
            let pat = hdrs_bin_del_pattern(op, n);
            let freed: usize = hdrs.iter().filter(|(k, _)| header_name_matches(k, &pat)).map(|(k, v)| htx_hdr_size(k, v)).sum();
            hdrs.retain(|(k, _)| !header_name_matches(k, &pat));
            res_htx_resize(freed, 0);
        }),
    }
}

/// Bytes an HTX header block takes: the 8-byte block descriptor, the name and the value
/// (`htx_add_header`, `include/haproxy/htx.h`).
fn htx_hdr_size(name: &str, value: &str) -> usize {
    8 + name.len() + value.len()
}

/// Sizes the HTX message the rules rewrite (`RES_HTX`), as `HAProxy` holds the response: a
/// buffer of `tune.bufsize` less the 40-byte `struct htx`, holding the status line (an
/// 8-byte block, 20 bytes of `htx_sl` and the three strings), each header
/// ([`htx_hdr_size`]), the 9-byte end-of-headers, and the body bytes already in the buffer
/// (an 8-byte block and the data).
///
/// A rewrite fails when what it adds does not fit (`htx_reserve_nxblk`): `tune.maxrewrite`
/// plays no part in it except that a response is read into the buffer only up to
/// `tune.bufsize - tune.maxrewrite`, so that much stays free when the body would have
/// filled it -- `reserve`, `None` for a reply the proxy wrote whole.
///
/// Measured on `HAProxy` 3.5-dev8 (2026-10-03, `tests/response_rule_actions.rs`): with the
/// default buffer, a server's `HTTP/1.1 200 OK` and `Content-Length: 0` alone, two
/// `set-header` of `n`-byte values on two-letter names fit up to `n` = 8125 and fail at
/// 8126; each further header, or body byte, takes the bytes above from that room.
fn res_htx_init(bufsize: usize, reserve: Option<usize>, version: &str, reason: &str, hdrs: &[(String, String)], body: usize) {
    let size = bufsize.saturating_sub(40);
    let head = 8 + 20 + version.len() + 3 + reason.len() + hdrs.iter().map(|(k, v)| htx_hdr_size(k, v)).sum::<usize>() + 9;
    let mut body = if body == 0 { 0 } else { 8 + body };
    if let Some(reserve) = reserve {
        body = body.min(size.saturating_sub(reserve).saturating_sub(head));
    }
    RES_HTX.set((head + body, size));
}

/// The longest header value an HTX block holds (`HTX_HDR_VALUE_MAX_LEN`, `include/haproxy/htx-t.h`):
/// a rewrite that would make a longer one fails whatever room the buffer has (measured on
/// `HAProxy` 3.5-dev8: 1048575 bytes fit, 1048576 give a 500).
const HTX_HDR_VALUE_MAX_LEN: usize = 1_048_575;

/// Adds a header of `name` and `value` to the sized HTX message: false, the message left as
/// it was, when the value is past [`HTX_HDR_VALUE_MAX_LEN`] or the header does not fit.
fn htx_hdr_add(name: &str, value: &str) -> bool {
    value.len() <= HTX_HDR_VALUE_MAX_LEN && res_htx_resize(0, htx_hdr_size(name, value))
}

/// Replaces `free` bytes of the HTX message by `take` bytes: false, the message left as it
/// was, when they do not fit.
fn res_htx_resize(free: usize, take: usize) -> bool {
    let (used, size) = RES_HTX.get();
    let used = used.saturating_sub(free) + take;
    if used > size {
        return false;
    }
    RES_HTX.set((used, size));
    true
}

/// `http_action_replace_uri` (`src/http_act.c`) on `part` (the path, the path and query, or
/// the whole target): `None` when `part` is empty or the regex does not match it; otherwise
/// the replacement, a log-format string, expanded by [`exp_replace`] -- *all* of `part`
/// becomes that, not only the matched text. `Err` for a replacement `exp_replace` cannot
/// expand (a backslash cut short).
fn replace_uri_part(
    part: &str,
    regex: &str,
    repl: Option<&crate::rule_compiled::Format>,
    ctx: &SampleContext,
    registry: &Registry,
) -> Option<Result<String, ()>> {
    let re = ibex_regex::UserRegex::cached(regex).ok()?;
    let caps = re.captures(part)?;
    let mut fmt = crate::reuse::string();
    repl.iter().for_each(|f| f.render_into(&mut fmt, ctx, registry, None));
    let out = exp_replace(&fmt, &caps).ok_or(());
    crate::reuse::give(fmt);
    Some(out)
}

/// `exp_replace` (`src/regex.c`): `repl` with `\0`..`\9` replaced by that group of the
/// match (nothing for a group that did not take part), `\xHH` by that byte -- computed as
/// `HAProxy` computes it, which takes any two characters -- and a backslash before
/// anything else dropped. `None`, a failed rewrite, for a backslash or `\x` cut short.
fn exp_replace(repl: &str, caps: &ibex_regex::Captures<'_>) -> Option<String> {
    let nibble = |c: u8| {
        let n = c.to_ascii_uppercase().wrapping_sub(b'0');
        if n > 9 { n.wrapping_sub(b'A' - b'9' - 1) } else { n }
    };
    let mut out = Vec::with_capacity(repl.len());
    let mut s = repl.as_bytes();
    while let Some((&c, rest)) = s.split_first() {
        s = rest;
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let (&e, rest) = s.split_first()?;
        s = rest;
        if e.is_ascii_digit() {
            if let Some(m) = caps.get(usize::from(e - b'0')) {
                out.extend_from_slice(m.as_bytes());
            }
        } else if e == b'x' {
            let (&[h1, h2], rest) = s.split_first_chunk::<2>()?;
            out.push((nibble(h1) << 4).wrapping_add(nibble(h2)));
            s = rest;
        } else {
            out.push(e);
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Where the header value starting `v` ends: the first comma outside a quoted string
/// (`http_find_hdr_value_end`, `src/http.c`).
fn hdr_value_end(v: &str) -> usize {
    let b = v.as_bytes();
    let mut i = 0;
    let mut quoted = false;
    while i < b.len() {
        match b[i] {
            b'\\' if quoted => i += 1,
            b'"' => quoted = !quoted,
            b',' if !quoted => return i,
            _ => {}
        }
        i += 1;
    }
    b.len()
}

/// `replace-value`'s rewrite of one header line: each comma-separated value that `re`
/// matches is replaced, with the blanks around it, by [`exp_replace`]'s output; the
/// commas and the values it does not match stay as they were (`http_replace_hdrs` with
/// `full` unset, `http_replace_header_value`). `None` when [`exp_replace`] fails.
fn replace_each_value(v: &str, re: &ibex_regex::UserRegex, repl: &str) -> Option<String> {
    let mut out = String::with_capacity(v.len());
    let mut rest = v;
    loop {
        let before = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        let end = before + hdr_value_end(&rest[before..]);
        let value = rest[before..end].trim_end_matches([' ', '\t']);
        match re.captures(value) {
            Some(caps) => out.push_str(&exp_replace(repl, &caps)?),
            None => out.push_str(&rest[..end]),
        }
        let Some(next) = rest[end..].strip_prefix(',') else { break };
        out.push(',');
        rest = next;
    }
    Some(out)
}

/// One `http-response`/`http-after-response` action on the response head being rewritten:
/// `Ok(true)` to go on, `Ok(false)` for `allow` (the rest of this rule list is skipped),
/// `Err` when the response is refused or a rewrite does not fit in strict mode.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn res_action(
    op: ResOp<'_>,
    status: &mut u16,
    status_msg: &mut String,
    ctx: &SampleContext,
    registry: &Registry,
    vars: &mut VarStore,
) -> Result<bool, ResStop> {
    // A rewrite that does not fit: the response fails in strict mode, and the rule is
    // skipped otherwise (`fail_rewrite`, `src/http_act.c`).
    let failed = || if STRICT_MODE.get() { Err(ResStop::Page(500)) } else { Ok(true) };
    let (act_name, act_fmt, rc) = match op {
        ResOp::Return(status, content_type, error_page, rc) => {
            return Err(ResStop::Return {
                status,
                content_type: content_type.map(str::to_string),
                reply: rc.reply.clone(),
                page: rc.page.clone(),
                error_page: error_page.cloned(),
            });
        }
        ResOp::Redirect(code, cookie, rc) => {
            // `http_apply_redirect_rule` (src/http_ana.c) for a `location` redirect: the
            // answer to the client is the redirect, and the server's response is dropped.
            let mut reply = format!("HTTP/1.1 {code} {}\r\ncontent-length: 0\r\nlocation: {}\r\n", status_reason(code), render_rule_fmt(rc, ctx, registry));
            if matches!(code, 302 | 303 | 307) {
                reply.push_str("cache-control: no-cache\r\n");
            }
            match cookie {
                Some(ibex_config::RedirectCookie::Set(c)) => reply.push_str(&format!("set-cookie: {c}; path=/;\r\n")),
                Some(ibex_config::RedirectCookie::SetFmt(_)) => {
                    let mut cookie = String::new();
                    rc.fmt2.iter().for_each(|f| f.render_into(&mut cookie, ctx, registry, None));
                    let _ = write!(reply, "set-cookie: {cookie}; path=/;\r\n");
                }
                Some(ibex_config::RedirectCookie::Clear(n)) => reply.push_str(&format!("set-cookie: {n}; path=/; Max-Age=0;\r\n")),
                None => {}
            }
            reply.push_str("\r\n");
            return Err(ResStop::Reply(reply.into_bytes()));
        }
        ResOp::Status(st, custom) => {
            let reason = custom.unwrap_or_else(|| status_reason(st));
            if !res_htx_resize(status_msg.len(), reason.len()) {
                return failed();
            }
            *status = st;
            *status_msg = reason.to_string();
            CURRENT_RES_STATUS.set(st);
            return Ok(true);
        }
        ResOp::Del(name) => {
            if let Some(var_name) = name.strip_prefix("\0unset-var:") {
                ibex_sample::vars::unset_in(vars, var_name);
                return Ok(true);
            }
            with_res_hdrs(|hdrs| {
                let freed: usize = hdrs.iter().filter(|(k, _)| header_name_matches(k, name)).map(|(k, v)| htx_hdr_size(k, v)).sum();
                crate::reuse::retain_pairs(hdrs, |(k, _)| !header_name_matches(k, name));
                res_htx_resize(freed, 0);
            });
            return Ok(true);
        }
        ResOp::Add(name, rc) => {
            let mut val = crate::reuse::string();
            rc.fmt.iter().for_each(|f| render_res_format(f, &mut val, ctx, registry, *status));
            if !htx_hdr_add(name, &val) {
                crate::reuse::give(val);
                return failed();
            }
            with_res_hdrs(|hdrs| hdrs.push((crate::reuse::string_from(name), val)));
            return Ok(true);
        }
        ResOp::Set(name, fmt, rc) => (name, fmt, rc),
    };
    if act_name == "\0allow" {
        return Ok(false);
    }
    if act_name == "\0silent-drop" {
        return Err(ResStop::SilentDrop);
    }
    if act_name == "\0deny" {
        // `http-response deny` with no status is a 502 in HAProxy (the
        // server's response is what was refused); 403 is the request side's.
        return Err(match act_fmt.strip_suffix(":empty") {
            Some(st) => ResStop::Empty(st.parse().unwrap_or(502)),
            None => ResStop::Page(act_fmt.parse().unwrap_or(502)),
        });
    }
    if act_name == "\0set-status" {
        // `http-after-response set-status` is stored as `<code>` or `<code>\0<reason>`.
        let (code, reason) = match act_fmt.split_once('\0') {
            Some((c, r)) => (c, Some(r)),
            None => (act_fmt, None),
        };
        return res_action(ResOp::Status(code.parse().unwrap_or(*status), reason), status, status_msg, ctx, registry, vars);
    }
    if let Some(var_name) = act_name.strip_prefix("\0set-var:") {
        // A fetch that finds nothing leaves the variable as it was (`action_store`).
        set_var_from(vars, &rc.var(var_name), rc.expr.as_ref(), ctx, registry);
        return Ok(true);
    }
    if let Some(var_name) = act_name.strip_prefix("\0set-var-fmt:") {
        let mut val = String::with_capacity(act_fmt.len());
        rc.fmt.iter().for_each(|f| render_res_format(f, &mut val, ctx, registry, *status));
        store_var(vars, &rc.var(var_name), val);
        return Ok(true);
    }
    if act_name == "\0strict-mode" {
        STRICT_MODE.set(act_fmt == "on");
        return Ok(true);
    }
    if let Some((op, prefix)) = ibex_config::HeadersBinOp::decode_name(act_name) {
        // `add-headers-bin`, `set-headers-bin` and `del-headers-bin` (T382). A list that cannot
        // be fetched changes nothing.
        let Some(smp) = rc.expr.as_ref().and_then(|e| e.eval_sample(registry, ctx)) else { return Ok(true) };
        let bin = sample_to_bin(smp);
        let walk = with_res_hdrs(|hdrs| res_headers_bin(op, prefix, &bin, hdrs));
        return match walk {
            crate::hdrs_bin::Walk::Done => Ok(true),
            crate::hdrs_bin::Walk::Rewrite => failed(),
            crate::hdrs_bin::Walk::Invalid => Err(ResStop::Page(500)),
        };
    }
    let replace = act_name
        .strip_prefix("\0replace-header:")
        .map(|n| (n, true))
        .or_else(|| act_name.strip_prefix("\0replace-value:").map(|n| (n, false)));
    if let Some((hdr_name, full)) = replace {
        // `http_replace_hdrs`: header by header, the first that does not fit failing the
        // action with the ones before it rewritten.
        let Some((re_str, _)) = act_fmt.split_once('\t') else { return Ok(true) };
        let Ok(re) = ibex_regex::UserRegex::cached(re_str) else { return Ok(true) };
        let mut repl_text = crate::reuse::string();
        rc.fmt.iter().for_each(|f| render_res_format(f, &mut repl_text, ctx, registry, *status));
        let repl = repl_text.as_str();
        let mut result = Ok(true);
        with_res_hdrs(|hdrs| {
            for (k, v) in hdrs.iter_mut().filter(|(k, _)| k.eq_ignore_ascii_case(hdr_name)) {
                let new_v = if full {
                    match re.captures(v) {
                        Some(caps) => exp_replace(repl, &caps),
                        None => continue,
                    }
                } else {
                    replace_each_value(v, &re, repl)
                };
                match new_v {
                    Some(n) if n.len() <= HTX_HDR_VALUE_MAX_LEN && res_htx_resize(htx_hdr_size(k, v), htx_hdr_size(k, &n)) => *v = n,
                    _ => {
                        result = failed();
                        break;
                    }
                }
            }
        });
        crate::reuse::give(repl_text);
        return result;
    }

    // `set-header`: every occurrence goes, then one is added at the end
    // (`http_action_set_header`) -- the removal stays when the addition does not fit.
    let mut val = crate::reuse::string();
    rc.fmt.iter().for_each(|f| render_res_format(f, &mut val, ctx, registry, *status));
    let fits = with_res_hdrs(|hdrs| {
        let freed: usize = hdrs.iter().filter(|(k, _)| k.eq_ignore_ascii_case(act_name)).map(|(k, v)| htx_hdr_size(k, v)).sum();
        crate::reuse::retain_pairs(hdrs, |(k, _)| !k.eq_ignore_ascii_case(act_name));
        res_htx_resize(freed, 0);
        htx_hdr_add(act_name, &val)
    });
    if fits {
        with_res_hdrs(|hdrs| hdrs.push((crate::reuse::string_from(act_name), val)));
    } else {
        crate::reuse::give(val);
    }
    if fits {
        Ok(true)
    } else {
        failed()
    }
}

/// The response capture slots a rule list writes, with their lengths ([`run_res_rules`]).
type ResCaps<'x> = Option<(&'x mut Vec<Option<Vec<u8>>>, &'x [(String, usize)])>;

/// Runs one rule list (`http_res_get_intercept_rule`): each rule whose condition holds,
/// until `allow` ends the list or an action stops the response. Every list starts in
/// strict mode, and a `strict-mode off` in it lasts to its end only.
///
/// `caps` is the response capture slots with their lengths, for the lists that have
/// `http-response capture`: a rule writes its slot there, and the rules after it (and the
/// caller, once the list is done) read what it wrote.
///
/// The rules see the proxy's ACLs (`when(acl,<name>)`) in `ctx`, which is the caller's again
/// when they are done.
#[allow(clippy::too_many_arguments)]
fn run_res_rules<'a, 'c>(
    rules: impl Iterator<Item = (ResRule<'a>, Option<&'a crate::rule_compiled::Cond>, u32)>,
    acls: &'c ibex_sample::Acls,
    head: (&mut u16, &mut String),
    ctx: &mut SampleContext<'c>,
    caps: ResCaps<'_>,
    registry: &Registry,
    vars: &mut VarStore,
    wait: Option<ResWait<'_>>,
) -> Result<Option<usize>, ResStop> {
    // In place, not a copy of the context per rule (S7).
    let prev = ctx.acls.replace(acls);
    let flow = run_res_rules_in(rules, acls, head, ctx, caps, registry, vars, wait);
    ctx.acls = prev;
    flow
}

#[allow(clippy::too_many_arguments)]
fn run_res_rules_in<'a>(
    rules: impl Iterator<Item = (ResRule<'a>, Option<&'a crate::rule_compiled::Cond>, u32)>,
    acls: &ibex_sample::Acls,
    head: (&mut u16, &mut String),
    ctx: &SampleContext,
    mut caps: ResCaps<'_>,
    registry: &Registry,
    vars: &mut VarStore,
    mut wait: Option<ResWait<'_>>,
) -> Result<Option<usize>, ResStop> {
    let (status, status_msg) = head;
    STRICT_MODE.set(true);
    let mut result = Ok(None);
    let start = wait.as_ref().map_or(0, |w| w.start);
    let outer = ctx;
    for (idx, (op, cond, line)) in rules.enumerate().skip(start) {
        // The slots as the earlier rules left them, for `capture.res.hdr`: a copy of the
        // context per rule, for the lists that capture.
        let with_caps;
        let ctx = match caps.as_ref() {
            Some((slots, _)) => {
                with_caps = SampleContext { captures_res_hdr: Some(slots.as_slice()), ..outer.clone() };
                &with_caps
            }
            None => outer,
        };
        if cond.is_some_and(|c| !c.eval(ctx, acls, registry)) {
            continue;
        }
        let op = match op {
            ResRule::Op(op) => op,
            ResRule::Capture(expr, id) => {
                // No sample, no capture (the slot keeps what it had); an `id` past the frontend's
                // slots captures nothing (`http_action_res_capture_by_id`: `id >= fe->nb_rsp_cap`).
                let val = expr.and_then(|e| e.eval_sample(registry, ctx)).map(|smp| sample_to_string(&smp));
                if let (Some(val), Some((slots, lens))) = (val, caps.as_mut()) {
                    if let (Some(slot), Some((_, len))) = (slots.get_mut(id), lens.get(id)) {
                        ibex_sample::capture_write::discard(true, id);
                        *slot = Some(cut_at(&val, *len).into_owned());
                    }
                }
                continue;
            }
            ResRule::Pause(time_ms, expr) => {
                let Some(w) = wait.as_mut() else { continue };
                let ms = pause_ms(time_ms, expr, registry, ctx);
                match (w.check)(idx, ms, PAUSE_RULE) {
                    // Held: the pass resumes at this rule when the pause is over.
                    BodyWait::Pending => {
                        STRICT_MODE.set(true);
                        return Ok(Some(idx));
                    }
                    _ => continue,
                }
            }
            ResRule::Wait(time_ms, at_least) => {
                let Some(w) = wait.as_mut() else { continue };
                match (w.check)(idx, time_ms, at_least) {
                    BodyWait::Ready => continue,
                    // Held: the pass resumes at this rule.
                    BodyWait::Pending => {
                        STRICT_MODE.set(true);
                        return Ok(Some(idx));
                    }
                    BodyWait::TimedOut => result = Err(ResStop::Page(504)),
                    BodyWait::Malformed | BodyWait::ClientGone => result = Err(ResStop::Page(502)),
                }
                break;
            }
        };
        // `allow`, `deny` and `redirect` end the rules: they are the last rule (`LAST_RULE`).
        if line != 0 && matches!(op, ResOp::Redirect(..) | ResOp::Return(..) | ResOp::Set("\0allow" | "\0deny" | "\0silent-drop", ..)) {
            LAST_RULE.set(Some(line));
        }
        match res_action(op, status, status_msg, ctx, registry, vars) {
            Ok(true) => {}
            Ok(false) => break,
            Err(stop) => {
                result = Err(stop);
                break;
            }
        }
    }
    STRICT_MODE.set(true);
    result
}

/// `http_eval_after_res_rules` (`src/http_ana.c`): the backend's `http-after-response`
/// rules, then the frontend's when it is another proxy -- a `listen` section's run once,
/// and a reply made before routing (the frontend still `s->be`) runs the frontend's once.
/// The response side starts with the request's `req.*` variables pruned. `head` is the
/// response's headers, status and reason, rewritten in place.
#[allow(clippy::too_many_arguments)]
fn eval_after_res_rules<'c>(
    proxies: &'c [Proxy],
    fe_idx: usize,
    be_idx: usize,
    head: (&mut u16, &mut String),
    ctx: &mut SampleContext<'c>,
    mut res_caps: Option<&mut Vec<Option<Vec<u8>>>>,
    registry: &Registry,
    vars: &mut VarStore,
) -> Result<(), ResStop> {
    let (status, status_msg) = head;
    ibex_sample::vars::with_stream(vars, |m| m.clear_scope(ibex_sample::VarScope::Req));
    let order: &[usize] = if fe_idx == be_idx { &[be_idx] } else { &[be_idx, fe_idx] };
    for &px in order {
        let rules = proxies[px].http_after_res_rules.iter().zip(&proxies[px].rules.http_after_res).map(|(r, rc)| (ResOp::of_after_res(&r.action, rc), rc.cond.as_ref(), 0));
        // `http-after-response capture` writes the frontend's slots, whichever proxy the rule is in.
        let fe_slots = &proxies[fe_idx].res_capture_slots;
        let caps = res_caps.as_deref_mut().filter(|_| !fe_slots.is_empty()).map(|c| (c, &fe_slots[..]));
        run_res_rules(rules, &proxies[px].acls, (&mut *status, &mut *status_msg), ctx, caps, registry, vars, None)?;
    }
    Ok(())
}

/// `http-request track-sc<slot>` on `key` in the table of proxy `t_idx`: the entry is counted as a
/// connection (not a session) and tracked once more. `HAProxy` leaves a slot that already
/// tracks something alone; Ibex moves it to a different key, releasing the old entry -- it tracks
/// a connection with the peer's address when it accepts it, before a PROXY header gives the
/// source (T139: `canonical_haproxy_35_e2e` relies on the move).
fn track_http_slot(proxies: &[Proxy], tracked: &mut [Option<(usize, StickKey)>; 3], slot: usize, t_idx: usize, key: StickKey) {
    if tracked[slot].as_ref().is_some_and(|(old_idx, old_key)| *old_idx == t_idx && *old_key == key) {
        return;
    }
    if let Some((old_idx, old_key)) = tracked[slot].take() {
        proxies.get(old_idx).and_then(|p| p.stick_table.as_ref()).into_iter().for_each(|t| {
            let _ = t.update_entry(&old_key, |data| data.untrack());
        });
    }
    proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()).into_iter().for_each(|t| {
        let _ = t.update_entry(&key, |data| data.track(false));
    });
    tracked[slot] = Some((t_idx, key));
}

/// What a `sc-inc-gpc*`, `sc-add-gpc` or `sc-set-gpt*` rule does to the entry tracked in slot
/// `sc`: nothing if none is, or if its table does not store the counter
/// (`action_inc_gpc` and its siblings, `src/stick_table.c`).
fn sc_gpc_rule(
    proxies: &[Proxy],
    tracked: &[Option<(usize, StickKey)>; 3],
    sc: u8,
    which: Gpc,
    op: GpcOp,
) {
    tracked.get(usize::from(sc)).into_iter().flatten().for_each(|(t_idx, key)| {
        proxies.get(*t_idx).and_then(|p| p.stick_table.as_ref()).into_iter().for_each(|table| {
            let _ = table.gpc_op(key, true, which, op);
        });
    });
}

/// Applies `f` to the entry each stick counter of `sess` tracks.
fn for_tracked(proxies: &[Proxy], sess: &TcpSession, f: impl Fn(&mut ibex_stick_table::StickEntryData)) {
    sess.tracked_sc.iter().flatten().for_each(|(t_idx, key)| {
        proxies.get(*t_idx).and_then(|p| p.stick_table.as_ref()).into_iter().for_each(|table| {
            let _ = table.update_entry(key, |data| f(data));
        });
    });
}

/// The bytes `sess` has exchanged that its tracked entries are not credited yet, in and out:
/// those of the requests that are over (`last`: all of them, the session ends). It is what
/// `HAProxy` credits once it has produced a response: the bytes the client sent, and the ones
/// the server sent -- a reply the proxy makes itself sends none.
fn stick_bytes_due(sess: &TcpSession, last: bool) -> (u64, u64) {
    let http = sess.mode == Mode::Http;
    let upto = if last || !http { sess.bytes_in } else { sess.log.bytes_in_at_start };
    // `last` is 0 or 1: the current request's server bytes and a tcp session's are only the last ones.
    let end = u64::from(last);
    let dout = if http { sess.stick_out_pending + sess.log.bytes_from_server * end } else { sess.bytes_out * end };
    (upto.saturating_sub(sess.stick_acct_in), dout)
}

/// Sends a reply the proxy made itself -- `return`, `deny`, `redirect`, `auth`, an error
/// page -- through the `http-after-response` rules first, as `http_forward_proxy_resp`
/// does for every one of them. `be_idx` is the proxy standing as `s->be`: the frontend
/// until a backend is chosen.
///
/// A rule that fails turns the reply into the 500 page, which goes through the rules once
/// more; if they fail on that too, or the failed reply was already a 500, the 500 goes out
/// without them (`http_reply_and_close`, `TX_CONST_REPLY`).
/// Sends a stats answer built whole (the admin API's JSON reply, a page to an HTTP/2 client
/// or to a HEAD; the pages themselves are streamed by [`stats_stream_page`]) framed as
/// HAProxy's applet frames the page (T566, measured on 3.5-dev8): to an HTTP/1.1 client it is
/// `transfer-encoding: chunked`, here one chunk, and the connection stays open (the generic response logic adds `connection: close` when the client
/// asked for it); to an HTTP/1.0 client it has no length, says `connection: close` and the
/// connection is closed after the body.
fn stats_write_page(entry: &mut SessionEntry, proxies: &[Proxy], content_type: &str, refresh: &str, body: &[u8]) {
    let http11 = entry.sess.txn.as_ref().is_none_or(|t| t.req_http11);
    let mut out = format!("HTTP/1.1 200 OK\r\ncache-control: no-cache\r\ncontent-type: {content_type}\r\n{refresh}").into_bytes();
    if entry.sess.is_h2() {
        // HTTP/2 frames the body itself (DATA, then END_STREAM): no chunks, no `connection`.
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
    } else if http11 {
        out.extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
        if !body.is_empty() {
            out.extend_from_slice(format!("{:X}\r\n", body.len()).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
    } else {
        out.extend_from_slice(b"connection: close\r\n\r\n");
        out.extend_from_slice(body);
    }
    stats_write_reply(entry, proxies, &out);
}

/// Sends a stats page (HTML, CSV, JSON) as HAProxy's stats applet does (T572): the head
/// now, framed as [`stats_write_page`] frames it, and the body a buffer at a time from
/// `page`, by [`stats_pump`] on every pass over the session while the client reads. The page
/// is never built whole, over HTTP/2 and HTTP/3 neither (T580). A HEAD gets the head alone.
#[allow(clippy::too_many_arguments)]
fn stats_stream_page(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    checks: &[ServerCheckState],
    pid: u32,
    serving: usize,
    content_type: &str,
    refresh: &str,
    page: crate::stats_stream::Page,
) {
    let head_only = entry.sess.txn.as_ref().is_some_and(|t| t.client_head);
    let uri = entry.sess.req_uri.as_deref().unwrap_or("").to_string();
    let banner = |c: crate::stats_post::StCode| EngineDispatcher::stats_banner(proxies, serving, &uri, c);
    let ctx = crate::stats_stream::Ctx { proxies, checks, pid, cfg: &proxies[serving].stats_config, banner: &banner };
    if head_only {
        stats_write_page(entry, proxies, content_type, refresh, b"");
        return;
    }
    // An HTTP/2 stream's body is chunked in `rep` as a server's is, and the forwarder turns
    // the chunks into DATA frames as the windows take them (T580); the head says nothing of
    // the framing, which is the protocol's. (An HTTP/3 stream is not `is_h2()`: it takes the
    // HTTP/1.1 head, whose `transfer-encoding` its mux drops, and the same chunks.)
    let h2 = entry.sess.is_h2();
    let http11 = h2 || entry.sess.txn.as_ref().is_none_or(|t| t.req_http11);
    let framing = if h2 { "" } else if http11 { "transfer-encoding: chunked\r\n" } else { "connection: close\r\n" };
    let head = format!("HTTP/1.1 200 OK\r\ncache-control: no-cache\r\ncontent-type: {content_type}\r\n{refresh}{framing}\r\n");
    if !stats_write_reply(entry, proxies, head.as_bytes()) {
        return;
    }
    let sess = &mut entry.sess;
    let mut d = crate::stats_stream::Dump::new(page, http11, u32::try_from(serving).unwrap_or(0));
    if let Some(crate::proxy::PendingOut::Raw(v, off)) = sess.pending_resp.as_deref_mut() {
        // The head is waiting for a buffer (`tune.buffers.limit`): the body joins it, built
        // whole, as any other reply waits.
        let mut buf = vec![0u8; 1 << 16];
        while !d.finished {
            let n = crate::stats_stream::fill(&mut d, &ctx, &mut buf);
            v.extend_from_slice(&buf[..n]);
        }
        let left = (v.len() - *off + sess.rep.readable().len()) as u64;
        let rsp = if http11 { crate::txn::MsgState::head(crate::txn::Framing::Chunked) } else { crate::txn::MsgState::Body(crate::txn::Body::Length(left)) };
        if let Some(t) = sess.txn.as_mut() { t.rsp = rsp; }
        return;
    }
    let rsp = crate::txn::MsgState::head(if http11 { crate::txn::Framing::Chunked } else { crate::txn::Framing::UntilClose });
    if let Some(t) = sess.txn.as_mut() { t.rsp = rsp; }
    stats_pump(sess, d, proxies, checks, pid);
}

/// Fills the session's response buffer with the next part of its stats page, if the buffer
/// has room; called on every pass over the session while it has one. An unframed page (to
/// an HTTP/1.0 client) ends with the bytes still in the buffer once the last is written.
fn stats_pump(sess: &mut crate::proxy::TcpSession, mut d: crate::stats_stream::Dump, proxies: &[Proxy], checks: &[ServerCheckState], pid: u32) {
    // `serving` is the index of the proxy that took the request: the list never changes.
    let serving = d.serving as usize;
    let uri = sess.req_uri.as_deref().unwrap_or("");
    let banner = |c: crate::stats_post::StCode| EngineDispatcher::stats_banner(proxies, serving, uri, c);
    let ctx = crate::stats_stream::Ctx { proxies, checks, pid, cfg: &proxies[serving].stats_config, banner: &banner };
    // `writable` compacts a buffer whose consumed head leaves the tail exhausted.
    let n = crate::stats_stream::fill(&mut d, &ctx, sess.rep.writable());
    sess.rep.commit(n);
    if !d.finished {
        sess.set_stats_dump(d);
        return;
    }
    if !d.chunked() {
        let left = sess.rep.readable().len() as u64;
        let rsp = if left == 0 { crate::txn::MsgState::Done } else { crate::txn::MsgState::Body(crate::txn::Body::Length(left)) };
        if let Some(t) = sess.txn.as_mut() { t.rsp = rsp; }
    }
    sess.end_dump();
}

/// A stats page answer, with the `http-after-response` rules of its frontend and backend
/// applied as they are to any other response. `false` when a rule failed and the 500 page
/// went instead.
fn stats_write_reply(entry: &mut SessionEntry, proxies: &[Proxy], raw: &[u8]) -> bool {
    let (fe, be) = (entry.proxy_idx, entry.backend_idx);
    // The page is streamed by the applet, not held in the HTX message the rules edit: they
    // see the head alone.
    let head_len = crate::proxy::find_eoh(raw).map_or(raw.len(), |(h, e)| h + e);
    match after_res_on_reply(&mut entry.sess, proxies, fe, be, &raw[..head_len]) {
        Ok(head) => {
            let mut out = head.into_owned();
            out.extend_from_slice(&raw[head_len..]);
            entry.sess.write_reply(&out);
            true
        }
        // A rule that fails (strict mode, a rewrite that does not fit) makes the reply the 500
        // page, as it does any other (`http_reply_and_close`).
        Err(()) => {
            reply_error(entry, proxies, 500);
            false
        }
    }
}

/// The header names of the response or request head at the start of `buf` in lower case, as
/// `HAProxy` writes anything that went through HTX (measured on 3.5-dev8). Values, the first
/// line and the body are left as they are.
fn lowercase_header_names(buf: &mut [u8]) {
    rewrite_header_names(buf, None);
}

/// [`lowercase_header_names`], and then each name found in `table` (`h1-case-adjust`) in the
/// case the table gives. `from` and `to` differ in case only, so the head keeps its length.
fn rewrite_header_names(buf: &mut [u8], table: Option<&std::collections::HashMap<String, String>>) {
    let eoh = crate::proxy::find_eoh(buf);
    rewrite_header_names_before(buf, eoh, table, true);
}

/// [`rewrite_header_names`] of a head whose end is `eoh` (`find_eoh` of `buf`). Only the
/// case of name bytes changes: no line end moves. Without `lower`
/// (`tune.ibex.h1-lowercase-headers off`) only the names `table` holds are written, the
/// others left in the case they came in.
fn rewrite_header_names_before(buf: &mut [u8], eoh: Option<(usize, usize)>, table: Option<&std::collections::HashMap<String, String>>, lower: bool) {
    let head = eoh.map_or(0, |(h, _)| h);
    let mut at = memchr::memchr(b'\n', &buf[..head]).map_or(head, |i| i + 1);
    while at < head {
        let end = memchr::memchr(b'\n', &buf[at..head]).map_or(head, |i| at + i + 1);
        // A folded line has no name of its own: nothing of it is lower-cased.
        let folded = matches!(buf[at], b' ' | b'\t');
        let colon = memchr::memchr(b':', &buf[at..end]).filter(|_| !folded).map_or(at, |i| at + i);
        let to = if lower {
            buf[at..colon].make_ascii_lowercase();
            // The name is read as text only when there is a table to look it up in (T433).
            table.and_then(|t| t.get(std::str::from_utf8(&buf[at..colon]).ok()?))
        } else {
            let name = &buf[at..colon];
            table.and_then(|t| t.iter().find(|(k, _)| k.as_bytes().eq_ignore_ascii_case(name)).map(|(_, v)| v))
        };
        if let Some(to) = to {
            if to.len() == colon - at {
                buf[at..colon].copy_from_slice(to.as_bytes());
            }
        }
        at = end;
    }
}

/// The response's names go to the client in lower case: `tune.ibex.h1-lowercase-headers on`,
/// or a client that is not HTTP/1 (an h2/h3 stream's child: HTTP/2 and HTTP/3 names are lower
/// case, and the mux reads them from the head so, `indexed_fields`).
fn names_lower(sess: &TcpSession, fe: &Proxy) -> bool {
    fe.h1_lower || sess.is_h2_child()
}

/// The table to write the names of a message for the client from: the frontend has
/// `option h1-case-adjust-bogus-client`.
fn client_case_table(fe: &Proxy) -> Option<&std::collections::HashMap<String, String>> {
    (fe.h1_adjust & ibex_config::H1_ADJ_CLIENT != 0).then_some(&*fe.h1_case)
}

/// The reply the proxy generates as `HAProxy` sends it: header names in lower case, and the
/// built-in 400 and 408 pages with `connection: close` after their other headers (a page
/// from `errorfile` keeps the order of its file; the request-parsing path has its own).
/// Written into `out` (empty), which the caller reuses.
fn htx_reply_into(raw: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(raw);
    let status = crate::txn::status_of(&String::from_utf8_lossy(&raw[..crate::proxy::find_eoh(raw).map_or(raw.len(), |(h, _)| h)]));
    if matches!(status, 400 | 408) && builtin_error_page(status) == Some(raw) {
        const CLOSE: &[u8] = b"Connection: close\r\n";
        // The built-in page has the header; the position is always there.
        let at = out.windows(CLOSE.len()).position(|w| w == CLOSE);
        at.into_iter().for_each(|i| {
            out.drain(i..i + CLOSE.len());
            let h = crate::proxy::find_eoh(&out).map_or(out.len(), |(h, _)| h);
            out.splice(h..h, b"\r\nConnection: close".iter().copied());
        });
    }
    lowercase_header_names(out);
}

fn send_proxy_reply(sess: &mut TcpSession, proxies: &[Proxy], fe_idx: usize, be_idx: usize, raw: &[u8]) {
    // Written in a per-thread buffer, reused from one reply to the next (T437).
    crate::reuse::with_bytes2(|buf| send_proxy_reply_in(sess, proxies, fe_idx, be_idx, raw, buf));
}

fn send_proxy_reply_in(sess: &mut TcpSession, proxies: &[Proxy], fe_idx: usize, be_idx: usize, raw: &[u8], buf: &mut Vec<u8>) {
    htx_reply_into(raw, buf);
    rewrite_header_names(buf, client_case_table(&proxies[fe_idx]));
    let raw = &buf[..];
    if let Ok(out) = after_res_on_reply(sess, proxies, fe_idx, be_idx, raw) {
        // The headers the `http-after-response` rules added are HTX names too: lower case
        // (row 6 of T455, measured on 3.5-dev8: `set-header X-B` on a deny sends `x-b`).
        match out {
            std::borrow::Cow::Owned(mut o) => {
                rewrite_header_names(&mut o, client_case_table(&proxies[fe_idx]));
                sess.write_reply(&o);
            }
            std::borrow::Cow::Borrowed(b) => sess.write_reply(b),
        }
        return;
    }
    let page = proxy_error_response(sess, &proxies[be_idx], &proxies[fe_idx], proxies, 500);
    let head_len = crate::proxy::find_eoh(raw).map_or(raw.len(), |(h, _)| h);
    if crate::txn::status_of(&String::from_utf8_lossy(&raw[..head_len])) != 500 {
        if let Ok(out) = after_res_on_reply(sess, proxies, fe_idx, be_idx, &page) {
            sess.write_reply(&out);
            return;
        }
    }
    sess.write_reply(&page);
}

/// `raw`, a whole reply, with the `http-after-response` rules applied to its head; `Err`
/// when one of them fails. The rules see what the server-response path gives them: the
/// session's variables, the request, and this reply's status and headers.
fn after_res_on_reply<'r>(
    sess: &mut TcpSession,
    proxies: &[Proxy],
    fe_idx: usize,
    be_idx: usize,
    raw: &'r [u8],
) -> Result<std::borrow::Cow<'r, [u8]>, ()> {
    use std::borrow::Cow;
    if proxies[be_idx].http_after_res_rules.is_empty() && proxies[fe_idx].http_after_res_rules.is_empty() {
        return Ok(Cow::Borrowed(raw));
    }
    // The one reply with no head is an empty errorfile (`/dev/null`, the documented way to
    // send nothing): it goes out as it is, nothing. Every other one has a head with a
    // status -- the built-in pages and the replies Ibex builds, and errorfiles, which are
    // refused at load when they are not an HTTP response (`load_errorfile_bytes`).
    let parsed = crate::proxy::find_eoh(raw).and_then(|(hdr_end, eoh_len)| {
        let head = String::from_utf8_lossy(&raw[..hdr_end]);
        let (first, rest) = head.split_once('\n').unwrap_or((&head, ""));
        let mut parts = first.trim_end_matches('\r').splitn(3, ' ');
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();
        let status = parts.next()?.parse::<u16>().ok()?;
        let reason = parts.next().unwrap_or_default().to_string();
        let hdrs: Vec<(String, String)> = rest
            .split('\n')
            .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
            .collect();
        Some((hdr_end, eoh_len, version, status, reason, hdrs))
    });
    let Some((hdr_end, eoh_len, version, mut status, mut reason, hdrs)) = parsed else {
        return Ok(Cow::Borrowed(raw));
    };

    CURRENT_RES_STATUS.set(status);
    // A reply Ibex built has no server status and no Tr (HAProxy: 0 and -1), whatever response
    // this thread handled before.
    CURRENT_SRV_STATUS.set(0);
    CURRENT_RES_TR.set(-1);
    res_htx_init(sess.bufsize, None, &version, &reason, &hdrs, raw.len() - hdr_end - eoh_len);
    // The rules edit the list the fetches read (X3).
    with_res_hdrs(|h| *h = hdrs);
    // The variables are the session's own, in `CURRENT_VARS` for the run that makes the
    // reply (`step_stream`).
    let mut vars = std::mem::take(&mut sess.vars);
    let mut res_caps = std::mem::take(&mut sess.log.res_captures);
    let res_caps_in = res_caps.clone();
    let result = {
        // The reply is the proxy's own, and the rules read the same state they read on a server's.
        let view = ProxiesView(proxies);
        let stick = StickView::new(proxies, &sess.tracked_sc);
        let mut ctx = SampleContext {
            proxies: Some(&view),
            stick: Some(&stick),
            prio: (sess.log.prio_class, sess.log.prio_offset),
            client_addr: sess.client_addr,
            server_addr: sess.server_addr,
            fc_src: sess.fc_src(),
            so_name: sess.so_name.as_deref(),
            so_id: sess.so_id,
            fc_dst: sess.fc_dst(),
            is_first_req: sess.is_first_req,
            proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: crate::proxy::ssl_fc(&sess.cli_xprt, sess.h2_role.as_deref()),
            quic_acks: sess.quic_facts(),
            fc_http_major: sess.fc_http_major(),
            bc_http_major: sess.bc_http_major(),
            req_version: sess.client_version(),
            ssl_bc: sess.srv_xprt.ssl_facts(),
            htx_slice: sess.htx_slice(),
            req_uri: sess.req_uri.as_deref(),
            req_method: sess.req_method.as_deref(),
            req_headers: sess.req_headers.as_deref(),
            fe_name: Some(&proxies[fe_idx].name),
            fe_id: Some(proxies[fe_idx].ids.iid),
            be_name: Some(&proxies[be_idx].name),
            be_id: Some(proxies[be_idx].ids.iid),
            be_max_retries: Some(proxies[be_idx].retries),
            cur_max_retries: Some(sess.max_retries),
            res_version: Some(&version),
            unique_id: sess.log.unique_id.as_deref(),
            accept_date: Some(sess.log.date()),
            stream: Some(stream_facts(sess, Some(status), true)),
            captures_req_hdr: Some(&sess.log.req_captures),
            captures_res_hdr: Some(&res_caps_in),
            bc_err: sess.bc_err.copied(),
            bc_reused: Some(sess.txn.as_ref().is_some_and(|t| t.srv_reused)),
            term_state: Some(sess_term_state(sess)),
            bc_dst: sess.bc_dst(),
            bc_src: sess.bc_src(),
            ..Default::default()
        };
        eval_after_res_rules(
            proxies,
            fe_idx,
            be_idx,
            (&mut status, &mut reason),
            &mut ctx,
            Some(&mut res_caps),
            sample_registry(),
            &mut vars,
        )
    };
    sess.vars = vars;
    sess.log.res_captures = res_caps;
    CURRENT_RES_STATUS.set(0);
    CURRENT_SRV_STATUS.set(0);
    CURRENT_RES_TR.set(-1);
    let hdrs = with_res_hdrs(std::mem::take);
    result.map_err(|_| ())?;

    let mut out = format!("{version} {status} {reason}\r\n");
    push_header_lines(&mut out, &hdrs);
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&raw[hdr_end + eoh_len..]);
    Ok(Cow::Owned(bytes))
}

/// The response for an error the proxy generates itself (no server, connect failed), as
/// HAProxy's `http_error_message` picks it: the backend's `http-error`/`errorfile` for
/// `status`, then the frontend's, then the built-in page.
fn proxy_error_response(sess: &TcpSession, be: &Proxy, fe: &Proxy, proxies: &[Proxy], status: u16) -> Vec<u8> {
    let own = |proxy: &Proxy| -> Option<Vec<u8>> {
        match proxy.error_replies.get(&status) {
            Some(ibex_config::ErrorPageSource::Raw(bytes)) => return Some(copy_page(bytes)),
            Some(ibex_config::ErrorPageSource::Custom { content_type, .. }) => {
                let ctx = SampleContext {
                    proxies: Some(&ProxiesView(proxies)),
                    client_addr: sess.client_addr,
                    fc_src: sess.fc_src(),
                    proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
                    so_name: sess.so_name.as_deref(),
                    so_id: sess.so_id,
                    fc_dst: sess.fc_dst(),
                    is_first_req: sess.is_first_req,
                    ssl_fc: crate::proxy::ssl_fc(&sess.cli_xprt, sess.h2_role.as_deref()),
                    quic_acks: sess.quic_facts(),
                    fc_http_major: sess.fc_http_major(),
                    bc_http_major: sess.bc_http_major(),
                    req_version: sess.client_version(),
                    ssl_bc: sess.srv_xprt.ssl_facts(),
                    htx_slice: sess.htx_slice(),
                    req_uri: sess.req_uri.as_deref(),
                    req_method: sess.req_method.as_deref(),
                    req_headers: sess.req_headers.as_deref(),
                    fe_name: Some(fe.name.as_str()),
                    fe_id: Some(fe.ids.iid),
                    be_name: Some(be.name.as_str()),
                    be_id: Some(be.ids.iid),
                    ..Default::default()
                };
                return Some(build_templated_error_response(
                    status,
                    content_type.as_deref(),
                    proxy.rules.reply_pages.get(&status).map(AsRef::as_ref),
                    None,
                    &ctx,
                    sample_registry(),
                ));
            }
            Some(ibex_config::ErrorPageSource::DefaultErrorfiles) | None => {}
        }
        proxy.error_files.get(&status).map(|page| copy_page(page))
    };
    own(be)
        .or_else(|| own(fe))
        .or_else(|| builtin_error_page(status).map(copy_page))
        .unwrap_or_else(|| ibex_proto::build_synthetic_response(status, None, None))
}

/// A copy of an error page, or an empty page -- nothing is sent and the connection closes, as
/// for an empty `errorfile` -- when the memory for it cannot be had (T465: an abort under
/// `RLIMIT_DATA`).
fn copy_page(page: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    if v.try_reserve_exact(page.len()).is_ok() {
        v.extend_from_slice(page);
    }
    v
}

fn builtin_error_page(status: u16) -> Option<&'static [u8]> {
    BUILTIN_ERROR_PAGES
        .iter()
        .find(|(code, _)| *code == status)
        .map(|(_, msg)| msg.as_bytes())
}

/// What `deny`/`return` will actually send for a given status, once `error_page` (and, for
/// `default-errorfiles`, the proxy's own `error_replies`/`error_files` tables) has been
/// resolved.
enum ResolvedErrorBody<'a> {
    /// A full response, taken verbatim from an `errorfile`, an `errorfiles` section entry,
    /// or HAProxy's built-in page. An empty slice is a deliberately empty errorfile (the
    /// documented `/dev/null` idiom): nothing is written, and the connection just closes.
    Raw(&'a [u8]),
    /// A response to build from `content-type`/`hdr`/`string`/`lf-string`, exactly as
    /// `http-request return` already does.
    Custom {
        content_type: Option<&'a str>,
        reply: Option<&'a crate::rule_compiled::Reply>,
    },
}

/// Resolves `deny`/`return`'s `error_page` argument (and, transitively, `http-error`'s
/// per-proxy overrides and `errorfile`/`errorfiles`'s per-proxy table) to what should
/// actually be sent for `status`.
///
/// The data path this closes: a denied request whose proxy configured `errorfile 403
/// site.http` used to always get Ibex's hardcoded 403 body; this is the line where it
/// picks up the operator's file instead.
///
/// `be` is the proxy whose rule is answering (the frontend itself before a backend is
/// chosen) and `fe` the frontend: the proxy's own page wins, then the frontend's, as
/// `http_error_message` picks `s->be` then `strm_fe(s)`.
fn resolve_error_body<'a>(
    be: &'a Proxy,
    fe: &'a Proxy,
    status: u16,
    error_page: Option<&'a ibex_config::ErrorPageSource>,
    content_type: Option<&'a String>,
    reply: Option<&'a crate::rule_compiled::Reply>,
    page: Option<&'a crate::rule_compiled::Reply>,
) -> ResolvedErrorBody<'a> {
    match error_page {
        None => ResolvedErrorBody::Custom { content_type: content_type.map(String::as_str), reply },
        Some(ibex_config::ErrorPageSource::Raw(bytes)) => ResolvedErrorBody::Raw(bytes.as_slice()),
        Some(ibex_config::ErrorPageSource::Custom { content_type, .. }) => ResolvedErrorBody::Custom { content_type: content_type.as_deref(), reply: page },
        Some(ibex_config::ErrorPageSource::DefaultErrorfiles) => {
            for proxy in [be, fe] {
                match proxy.error_replies.get(&status) {
                    Some(ibex_config::ErrorPageSource::Raw(bytes)) => return ResolvedErrorBody::Raw(bytes.as_slice()),
                    Some(ibex_config::ErrorPageSource::Custom { content_type, .. }) => {
                        return ResolvedErrorBody::Custom { content_type: content_type.as_deref(), reply: proxy.rules.reply_pages.get(&status).map(AsRef::as_ref) };
                    }
                    Some(ibex_config::ErrorPageSource::DefaultErrorfiles) | None => {}
                }
                if let Some(bytes) = proxy.error_files.get(&status) {
                    return ResolvedErrorBody::Raw(bytes.as_slice());
                }
            }
            if let Some(builtin) = builtin_error_page(status) {
                return ResolvedErrorBody::Raw(builtin);
            }
            ResolvedErrorBody::Custom { content_type: None, reply: None }
        }
    }
}

/// Builds a full raw HTTP response from `http-request return`/`deny`'s templated body
/// arguments: an optional `content-type`, and the `\0HDR:`/`\0BODY:`-encoded custom
/// headers and payload the parser already produces for `string`/`lf-string`/`file`/
/// `lf-file`/`hdr`. Shared by `Return`'s dummy/templated body, `Deny`'s equivalent
/// arguments, and an `http-error`'s inline template resolved through
/// `ErrorPageSource::Custom`.
fn build_templated_error_response(
    status: u16,
    content_type: Option<&str>,
    reply: Option<&crate::rule_compiled::Reply>,
    data: Option<&crate::logfmt::LogData>,
    ctx: &SampleContext,
    registry: &Registry,
) -> Vec<u8> {
    let mut out = Vec::new();
    build_templated_error_response_into(&mut out, status, content_type, reply, data, ctx, registry);
    out
}

/// [`build_templated_error_response`] appended to `out`: the template is read where it is,
/// and its formats rendered into per-thread scratch strings, so a reply built into a reused
/// buffer allocates nothing (T437).
fn build_templated_error_response_into(
    out: &mut Vec<u8>,
    status: u16,
    content_type: Option<&str>,
    reply: Option<&crate::rule_compiled::Reply>,
    data: Option<&crate::logfmt::LogData>,
    ctx: &SampleContext,
    registry: &Registry,
) {
    use std::fmt::Write as _;
    // The `hdr` lines as text (`name: value\r\n`, an empty value leaving its line out), then
    // the body, in that order, as the formats are evaluated.
    crate::reuse::with_string(|head| {
        crate::reuse::with_string2(|body_str| {
            if let Some(r) = reply {
                r.render(head, body_str, ctx, registry, status, data);
            }
            // The config's escapes were decoded once, when it was read (`parse_line`); a second
            // pass would turn a literal `\\n` into a newline, which `HAProxy` does not.
            let body = ibex_regex::bytetext::text_to_bytes(body_str);
            // The status line goes in front of the `hdr` lines: the head is written to `out`
            // from text, in one piece.
            let hdrs_len = head.len();
            let _ = write!(head, "HTTP/1.1 {status} {}\r\n", status_reason(status));
            let line = &head[hdrs_len..];
            out.extend_from_slice(&ibex_regex::bytetext::text_to_bytes(line));
            out.extend_from_slice(&ibex_regex::bytetext::text_to_bytes(&head[..hdrs_len]));
            head.truncate(hdrs_len);
            head.clear();
            // `content-length` before `content-type` (measured on 3.5-dev8), after the `hdr` lines.
            let _ = write!(head, "Content-Length: {}\r\n", body.len());
            if let Some(ct) = content_type {
                let _ = write!(head, "Content-Type: {ct}\r\n");
            }
            head.push_str("\r\n");
            out.extend_from_slice(&ibex_regex::bytetext::text_to_bytes(head));
            out.extend_from_slice(&body);
        });
    });
}

#[cfg(test)]
mod arena_tests {
    use super::SessionArena;

    /// T468: `tune.memory.prealloc`'s slots are made at start and `pool_gc` does not compact
    /// them; a size the allocator cannot reserve is refused and leaves the arena as it was.
    #[test]
    fn a_presized_session_arena_keeps_its_slots_and_refuses_what_cannot_be_reserved() {
        use ibex_alloc::Arena;
        let mut a = SessionArena::with_capacity(0);
        assert!(a.prealloc(8));
        assert_eq!((a.slots(), a.live()), (8, 0));
        assert_eq!(a.compact(), 0, "no slot released");
        assert_eq!(a.slots(), 8);
        let mut b = SessionArena::with_capacity(0);
        assert!(!b.prealloc(usize::MAX), "a reservation past the address space");
        assert_eq!(b.slots(), 0);
    }

    /// Two entries at once are two distinct, live ones (T280): the same index twice, or one
    /// past the end, is none.
    #[test]
    fn get2_mut_is_none_for_one_entry_twice_or_a_missing_one() {
        let mut a = SessionArena::with_capacity(2);
        assert!(a.get2_mut(0, 0).is_none());
        assert!(a.get2_mut(0, 1).is_none());
    }
}

#[cfg(test)]
mod cut_at_tests {
    use super::cut_at;

    /// A capture is cut in bytes: an escaped stray byte counts as one (T286).
    #[test]
    fn a_capture_is_cut_in_bytes_of_what_the_text_stands_for() {
        let t = ibex_regex::bytetext::bytes_to_text(b"caf\xe9s");
        assert_eq!(cut_at(&t, 4).as_ref(), b"caf\xe9");
        assert_eq!(cut_at(&t, 99).as_ref(), b"caf\xe9s");
        assert_eq!(cut_at("abc", 2).as_ref(), b"ab");
    }
}

#[cfg(test)]
mod registry_tests {
    use super::{
        build_sample_registry,
        CURRENT_RES_STATUS,
    };
    use ibex_sample::CURRENT_VARS;
    use ibex_sample::{Expr, Sample, SampleContext};

    /// The engine's registry must read the *same* thread-locals the engine writes.
    ///
    /// This is the regression test for the two-registry bug. `engine.rs` declared its own
    /// `CURRENT_VARS` and re-registered `var` against it, while `ibex-sample` had a second
    /// one that its own `var` read. Both halves worked in isolation and the whole thing
    /// looked fine, because the engine's registration shadowed ibex-sample's in the
    /// `HashMap`. Anything added to ibex-sample that touched vars read an empty map.
    ///
    /// So this writes through the engine's handle and reads through the registry: before
    /// the merge it returned `None`, because those were two different maps.
    #[test]
    fn engine_var_writes_are_visible_to_the_sample_registry() {
        CURRENT_VARS.with(|v| {
            v.borrow_mut().insert("txn.probe", Sample::Str("seen".to_string()))
        });

        let reg = build_sample_registry();
        let ctx = SampleContext::default();
        let expr = Expr::parse("var(txn.probe)").expect("var() must parse");

        assert_eq!(
            expr.eval_sample(&reg, &ctx),
            Some(Sample::Str("seen".to_string())),
            "the engine wrote a var the sample registry could not see -- the two \
             CURRENT_VARS thread-locals have diverged again"
        );

        CURRENT_VARS.with(|v| v.borrow_mut().clear());
    }

    /// `build_sample_registry` must not re-register what `ibex-sample` already provides.
    ///
    /// `register_fetch` is a `HashMap` insert, so a duplicate here silently wins and the
    /// ibex-sample implementation becomes unreachable -- testable in its own crate, but
    /// never actually run. That is how engine's single-match-type `map` came to shadow
    /// ibex-sample's eleven.
    #[test]
    fn engine_registers_only_what_ibex_sample_cannot() {
        let base = ibex_sample::Registry::new();
        let engine = build_sample_registry();

        let base_convs = base.converter_names();
        let added: Vec<&str> = engine
            .converter_names()
            .into_iter()
            .filter(|n| !base_convs.contains(n))
            .collect();

        assert!(
            added.is_empty(),
            "engine.rs registered converters of its own: {added:?} -- these shadow \
             ibex-sample by HashMap insert, so its versions become dead code that \
             still passes its own tests"
        );
        assert_eq!(
            engine.fetch_names().len(),
            base.fetch_names().len(),
            "engine.rs must add no fetches of its own"
        );
    }

    #[test]
    fn a_connection_token_goes_in_as_the_last_header_whatever_the_head_and_its_line_ends() {
        let put = |raw: &[u8], tok: &str| {
            let mut b = crate::buf::Buf::standard();
            b.writable()[..raw.len()].copy_from_slice(raw);
            b.commit(raw.len());
            super::inject_connection_token_zero_alloc(&mut b, tok, false);
            String::from_utf8(b.readable().to_vec()).unwrap()
        };
        assert_eq!(
            put(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", "close"),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );
        assert_eq!(
            put(b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok", "keep-alive"),
            "HTTP/1.1 200 OK\nContent-Length: 2\nConnection: keep-alive\n\nok"
        );
        // A head too big for the stack copy.
        let big = format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\n\r\n", "a".repeat(4200));
        let out = put(big.as_bytes(), "close");
        assert!(out.to_ascii_lowercase().contains("connection: close"), "{}", &out[out.len() - 40..]);
        // No end of head: nothing is added.
        assert_eq!(put(b"HTTP/1.1 200 OK\r\nContent-Le", "close"), "HTTP/1.1 200 OK\r\nContent-Le");
    }

    /// The shared `CURRENT_RES_STATUS` starts at 0, meaning "no response yet".
    ///
    /// The engine's old private copy defaulted to 200, so `status` reported a response
    /// that had never been sent. ibex-sample treats 0 as absent and renders `-`.
    #[test]
    fn status_is_absent_before_a_response_exists() {
        CURRENT_RES_STATUS.set(0);
        let reg = build_sample_registry();
        let ctx = SampleContext::default();
        let expr = Expr::parse("status").expect("status must parse");
        assert_eq!(expr.eval_sample(&reg, &ctx), None);
    }
}

/// Registers backend socket `b` of QUIC listener `idx` for `want` when its slot is free
/// ([`FdTab::is_free`]: an `Idle` entry at a live QUIC socket's number is stale); with `retune`, one already registered whose interest changed is modified.
fn sync_quic_fd(fdtab: &mut FdTab, poller: &Poller, idx: usize, b: std::os::fd::BorrowedFd<'_>, want: Interest, retune: bool) {
    let fd = b.as_raw_fd();
    if fdtab.is_free(fd) {
        fdtab.insert(fd, FdState::QuicBackend { listener: usize_to_u32(idx) }, want);
        let _ = poller.add(b, raw_fd_to_u64(fd), want.readable, want.writable);
    } else if retune && fdtab.interest(fd) != want {
        fdtab.set_interest(fd, want);
        let _ = poller.modify(b, raw_fd_to_u64(fd), want.readable, want.writable);
    }
}

/// Takes the table slots of descriptors a QUIC listener closed. The listener reports them a
/// pass after closing them, and the number may have been given to another socket in between
/// (an accepted client, a server connection): that socket's slot is not ours to clear.
fn forget_quic_fds(fdtab: &mut FdTab, fds: Vec<RawFd>) {
    for fd in fds {
        if matches!(fdtab.state(fd), FdState::QuicBackend { .. }) {
            fdtab.remove(fd);
        }
    }
}

#[cfg(test)]
mod quic_fd_reuse_tests {
    use super::*;

    #[test]
    fn a_closed_quic_fd_reused_by_another_socket_keeps_its_slot() {
        let mut t = FdTab::with_capacity(64);
        let conn = FdState::Conn { task: ibex_sched::TaskRef(7), conn: 1 };
        t.insert(40, FdState::QuicBackend { listener: 0 }, Interest::READ);
        t.insert(41, conn, Interest::READ);
        forget_quic_fds(&mut t, vec![40, 41, 42]);
        assert!(matches!(t.state(40), FdState::Closed), "a QUIC leg's slot is cleared");
        assert!(matches!(t.state(41), FdState::Conn { .. }), "a slot another socket took over is kept");
        assert!(matches!(t.state(42), FdState::Closed));
    }

    /// A QUIC backend socket given the number of an idle server connection that left its
    /// worker's lists without an event (taken by another worker, purged, closed over
    /// `pool-high-conn`) is polled: the stale `Idle` entry at that number is a free slot,
    /// like a `Closed` one (T434). Before, it read as registered and the leg waited for an
    /// unrelated wakeup.
    #[test]
    fn a_quic_leg_on_a_stale_idle_slot_is_registered() {
        let poller = Poller::new(16).expect("poller");
        let mut t = FdTab::with_capacity(64);
        for (want, retune) in [(Interest::READ, true), (Interest::WRITE, true), (Interest::READ, false)] {
            let leg = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
            t.set_idle(leg.as_raw_fd());
            sync_quic_fd(&mut t, &poller, 0, leg.as_fd(), want, retune);
            assert!(poller.is_registered(leg.as_fd()), "a leg for {want:?} on a stale idle slot is not polled");
            assert!(matches!(t.state(leg.as_raw_fd()), FdState::QuicBackend { listener: 0 }));
            assert_eq!(t.interest(leg.as_raw_fd()), want);
            t.remove(leg.as_raw_fd());
        }
    }
}

#[cfg(test)]
mod rate_ctr_tests {
    use super::RateCtr;

    /// `RateCtr::new()` is a zeroed counter that counts as the default one does. The statics
    /// that use it evaluate it at compile time (no coverage), so call it at run time. No
    /// oracle value: a fresh counter's rate is 0 by construction.
    #[test]
    fn a_new_rate_counter_is_zero_and_counts() {
        let r = RateCtr::new();
        assert_eq!(r.rate_at(100), 0);
        r.tick_at(1000);
        assert_eq!(r.rate_at(1000), 1);
    }

    /// `read_freq_ctr` over a period of one second: the window starts at the first event
    /// after a quiet spell, and the part of the previous window that has not slid out counts.
    #[test]
    fn a_rate_counts_the_last_second_with_the_previous_window_sliding_out() {
        let r = RateCtr::default();
        assert_eq!(r.rate_at(100), 0, "nothing counted yet");
        for _ in 0..4 {
            r.tick_at(1000);
        }
        assert_eq!(r.rate_at(1000), 4);
        assert_eq!(r.rate_at(1999), 4, "still inside the window the first event opened");
        // The window ended: the 4 slide out over the next second, and a new event opens a window.
        assert_eq!(r.rate_at(2500), 2, "halfway through the next second, half of the 4 remain");
        // The window restarts at the event, not at the end of the old one (`HAProxy`: 3 events,
        // 1.2 s of quiet, one more: 4), so the previous window counts in full again.
        r.tick_at(2500);
        assert_eq!(r.rate_at(2500), 5, "1 new + the previous window's 4");
        assert_eq!(r.rate_at(3499), 1, "the old 4 have all slid out, the new one is in its window");
        // A rate nobody reads or ticks for two periods is 0, and a tick after that starts afresh.
        assert_eq!(r.rate_at(5000), 0);
        r.tick_at(9000);
        assert_eq!(r.rate_at(9000), 1, "the quiet spell dropped both windows");
    }

    /// An event taken back (a TLS handshake that failed) leaves the current window, then the
    /// previous one when the current is empty, and never goes below nothing.
    #[test]
    fn an_event_taken_back_leaves_the_window_it_was_counted_in() {
        let r = RateCtr::default();
        r.untick();
        assert_eq!(r.rate_at(1000), 0, "nothing to take back");
        for _ in 0..4 {
            r.tick_at(1000);
        }
        r.tick_at(2500);
        assert_eq!(r.rate_at(2500), 5);
        r.untick();
        assert_eq!(r.rate_at(2500), 4, "the new window's event");
        r.untick();
        assert_eq!(r.rate_at(2500), 3, "the new window is empty: one of the previous window's");
    }
}

#[cfg(test)]
mod actconn_tests {
    use super::*;
    use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// A response ends: the server connection is parked on its session and leaves the
    /// server's connections in use; a session whose count was already reclaimed (shut down)
    /// is counted neither out nor in again.
    #[test]
    fn a_parked_connection_leaves_the_servers_count_and_a_reclaimed_session_is_not_counted_again() {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let srv = l.local_addr().expect("addr");
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                std::thread::spawn(move || {
                    let mut b = [0u8; 1024];
                    while s.read(&mut b).is_ok_and(|n| n > 0) {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                    }
                });
            }
        });
        let fe = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
        let config = Config {
            frontends: vec![FrontendSection {
                name: "fe".into(),
                bind: Some(fe),
                mode: Mode::Http,
                default_backend: Some("be".into()),
                ..Default::default()
            }],
            backends: vec![BackendSection { name: "be".into(), mode: Mode::Http, servers: vec![Server::new("s1", srv)], ..Default::default() }],
            ..Default::default()
        };
        let mut engine = Engine::new(&config, 1024).expect("Engine::new");
        let mut c = TcpStream::connect(fe).expect("connect");
        c.set_nonblocking(true).expect("nonblocking");
        let _ = engine.run_once();
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        let start = Instant::now();
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        while !got.ends_with(b"ok") {
            assert!(start.elapsed() < Duration::from_secs(5), "no answer");
            let _ = engine.run_once();
            if let Ok(n) = c.read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
        }
        let proxies = &engine.proxies;
        let in_use = |p: &[Proxy]| p.iter().map(|p| p.server_actconn.iter().map(|a| a.load(Ordering::Relaxed)).sum::<u32>()).sum::<u32>();
        let (_, entry) = engine.sessions.iter_mut().find(|(_, e)| e.sess.srv_park_exp.is_set()).expect("a parked connection");
        assert_eq!(in_use(proxies), 0, "parked: out of the connections in use");
        server_actconn_add(entry, proxies, true);
        assert_eq!(in_use(proxies), 1);
        server_actconn_add(entry, proxies, false);
        assert_eq!(in_use(proxies), 0);
        entry.actconn_reclaimed = false;
        let idx = entry.target_server_idx.take();
        server_actconn_add(entry, proxies, true);
        assert_eq!(in_use(proxies), 0, "no server, nothing to count");
        entry.target_server_idx = idx;
        entry.actconn_reclaimed = true;
        server_actconn_add(entry, proxies, true);
        assert_eq!(in_use(proxies), 0, "a reclaimed session adds nothing");
    }
}

/// Idle server connections stay in their worker's epoll set, watched for reads (T434).
#[cfg(test)]
mod idle_poll_tests {
    use super::*;
    use ibex_config::ast::{BackendSection, Config, FrontendSection, Mode, Server};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc;

    /// A server that answers every request `200 ok` and hands the test each connection it
    /// accepted, for the test to close.
    fn backend() -> (SocketAddr, mpsc::Receiver<TcpStream>) {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let _ = tx.send(s.try_clone().expect("clone"));
                std::thread::spawn(move || {
                    let mut got = Vec::new();
                    let mut b = [0u8; 1024];
                    loop {
                        let n = match s.read(&mut b) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        got.extend_from_slice(&b[..n]);
                        while let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                            got.drain(..end + 4);
                            let Ok(()) = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") else { return };
                        }
                    }
                });
            }
        });
        (addr, rx)
    }

    fn engine(srv: SocketAddr) -> (Engine, SocketAddr) {
        engine_with(srv, None)
    }

    fn engine_with(srv: SocketAddr, http_reuse: Option<ibex_config::HttpReuse>) -> (Engine, SocketAddr) {
        let fe = TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr");
        let config = Config {
            frontends: vec![FrontendSection { name: "fe".into(), bind: Some(fe), mode: Mode::Http, default_backend: Some("be".into()), ..Default::default() }],
            backends: vec![BackendSection { name: "be".into(), mode: Mode::Http, servers: vec![Server::new("s1", srv)], http_reuse, ..Default::default() }],
            ..Default::default()
        };
        (Engine::new(&config, 1024).expect("Engine::new"), fe)
    }

    fn client(e: &mut Engine, fe: SocketAddr) -> TcpStream {
        let c = TcpStream::connect(fe).expect("connect");
        c.set_nonblocking(true).expect("nonblocking");
        let _ = e.run_once();
        c
    }

    /// One request on each of `cs` at once, `e` run until every answer is in.
    fn exchange_all(e: &mut Engine, cs: &mut [&mut TcpStream]) {
        for c in cs.iter_mut() {
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        }
        let start = Instant::now();
        let mut got = vec![Vec::new(); cs.len()];
        let mut buf = [0u8; 512];
        while !got.iter().all(|g| g.ends_with(b"ok")) {
            assert!(start.elapsed() < Duration::from_secs(5), "no answer: {got:?}");
            let _ = e.run_once();
            for (c, g) in cs.iter_mut().zip(got.iter_mut()) {
                if let Ok(n) = c.read(&mut buf) {
                    g.extend_from_slice(&buf[..n]);
                }
            }
        }
    }

    /// One request on `c`, `e` run until its answer is in.
    fn exchange(e: &mut Engine, c: &mut TcpStream) {
        exchange_all(e, &mut [c]);
    }

    fn drive_until(e: &mut Engine, mut done: impl FnMut(&Engine) -> bool) -> bool {
        let start = Instant::now();
        while !done(e) && start.elapsed() < Duration::from_secs(5) {
            let _ = e.run_once();
        }
        done(e)
    }

    fn idle_count(p: &IdlePool) -> usize {
        p.pools.with_count((0, 0), |n| n.idle.load(Ordering::Relaxed))
    }

    /// A keep-alive client whose requests take a connection from the server's lists and
    /// give it back makes no `epoll_ctl`: the connection stays registered for reads while
    /// it is idle, and the request is written without asking for writability (`HAProxy`:
    /// 0.008 `epoll_ctl` per request at 50 connections; Ibex before: 2, a DEL at the release
    /// and an ADD at the reuse).
    #[test]
    fn a_connection_reused_from_the_lists_makes_no_epoll_ctl() {
        let (srv, _conns) = backend();
        let (mut e, fe) = engine(srv);
        let (mut c1, mut c2) = (client(&mut e, fe), client(&mut e, fe));
        // Two at once: the server is seen to need two, and the lists keep both
        // (`srv_add_to_idle_list`), once they have been parked on their sessions.
        exchange_all(&mut e, &mut [&mut c1, &mut c2]);
        assert!(drive_until(&mut e, |e| e.idle_backend_pool.total() == 2), "two idle connections");
        let before = e.poller.ctl_calls();
        for _ in 0..10 {
            exchange(&mut e, &mut c1);
        }
        assert_eq!(e.idle_backend_pool.total(), 2);
        assert_eq!(e.poller.ctl_calls() - before, 0, "epoll_ctl calls for 10 requests through the lists");
    }

    /// An HTTP/3 request relayed over a socket pair (a session with no listener, T130) gives
    /// its server connection to the server's lists with its response, also while the lists
    /// are empty: its session carries no other request, and a connection parked on it for
    /// `SRV_PARK_MS` is no other stream's (T523: in a burst of 200 HTTP/3 connections, 150
    /// server connections where `HAProxy`, whose h3 stream ends with its response, opened 115).
    #[test]
    fn a_relayed_h3_request_parks_no_server_connection() {
        let (srv, _conns) = backend();
        let (mut e, _fe) = engine(srv);
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        ours.set_nonblocking(true).expect("nonblocking");
        let local: SocketAddr = "127.0.0.1:443".parse().expect("addr");
        e.admit_connection(0, None, theirs.into(), "127.0.0.1:50000".parse().expect("addr"), local, None);
        ours.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").expect("send");
        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        let start = Instant::now();
        while !got.ends_with(b"ok") {
            assert!(start.elapsed() < Duration::from_secs(5), "no answer: {got:?}");
            let _ = e.run_once();
            if let Ok(n) = ours.read(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
        }
        // The relay keeps its side open. Parked, the connection reaches the lists only when
        // its park ends (`SRV_PARK_MS`, 100 ms: the next `run_once` sleeps until then).
        let answered = Instant::now();
        assert!(drive_until(&mut e, |e| e.idle_backend_pool.total() == 1), "never reached the lists");
        let took = answered.elapsed();
        assert!(took < Duration::from_millis(50), "the server connection stayed on the relayed session for {took:?}");
    }

    /// A server that closes a connection while it is in its lists: the close is an event
    /// on the connection, which leaves the lists and the server's idle count with it,
    /// before any request could take it (`h1_io_cb` on an idle connection). Before, it
    /// stayed until the 50 ms sweep peeked at it, or a request did.
    #[test]
    fn a_pooled_connection_its_server_closes_leaves_the_lists_at_the_event() {
        // Up to five tries, for a loaded host; the last one must see the close at once.
        let mut took: Vec<Duration> = Vec::new();
        while took.len() < 5 && took.last().is_none_or(|t| *t >= Duration::from_millis(30)) {
            let (srv, conns) = backend();
            let (mut e, fe) = engine(srv);
            let mut c = client(&mut e, fe);
            exchange(&mut e, &mut c);
            assert!(drive_until(&mut e, |e| e.idle_backend_pool.total() == 1), "an idle connection");
            assert_eq!(idle_count(&e.idle_backend_pool), 1);
            let s = conns.recv_timeout(Duration::from_secs(1)).expect("the server's connection");
            s.shutdown(std::net::Shutdown::Both).expect("shutdown");
            let closed = Instant::now();
            assert!(drive_until(&mut e, |e| e.idle_backend_pool.total() == 0), "never left the lists");
            assert_eq!(idle_count(&e.idle_backend_pool), 0, "the server's idle count");
            took.push(closed.elapsed());
        }
        assert!(took.last().is_some_and(|t| *t < Duration::from_millis(30)), "the closed connection left the lists only after {took:?}, not at its event");
    }

    /// Nothing looks at the idle connections between their events: a worker holding one,
    /// and nothing else to do, sleeps until its next timer (at most 100 ms, the poll's
    /// bound), not every 50 ms to peek at it (the sweep before T434: a `recvfrom(MSG_PEEK)`
    /// per idle connection per wakeup, on top of one per take).
    #[test]
    fn an_idle_connection_does_not_wake_its_worker() {
        let (srv, _conns) = backend();
        let (mut e, fe) = engine(srv);
        let mut c = client(&mut e, fe);
        exchange(&mut e, &mut c);
        drop(c);
        assert!(drive_until(&mut e, |e| e.idle_backend_pool.total() == 1 && e.sessions.live() == 0), "an idle connection, no session");
        let (start, before) = (Instant::now(), e.poller.wait_calls());
        while start.elapsed() < Duration::from_millis(400) {
            let _ = e.run_once();
        }
        let waits = e.poller.wait_calls() - before;
        assert_eq!(e.idle_backend_pool.total(), 1);
        assert!(waits <= 5, "{waits} waits in 400 ms");
    }

    /// A connection another worker takes leaves its owner's epoll set under the owner's
    /// lock (`fd_takeover`): its events go to the taker, which answers with it; it goes back
    /// to the taker's lists, and its server's close is the taker's event.
    #[test]
    fn a_connection_another_worker_takes_leaves_its_owners_epoll() {
        let (srv, conns) = backend();
        let pools = IdlePools::with(2, true);
        // `always`: the other worker's client takes it with its first request.
        let (mut a, fe_a) = engine_with(srv, Some(ibex_config::HttpReuse::Always));
        let (mut b, fe_b) = engine_with(srv, Some(ibex_config::HttpReuse::Always));
        a.share_idle_pools(&pools, 0);
        b.share_idle_pools(&pools, 1);
        let mut ca = client(&mut a, fe_a);
        exchange(&mut a, &mut ca);
        assert!(drive_until(&mut a, |a| a.idle_backend_pool.total() == 1), "idle on worker 0");
        let raw = {
            let pool = IdlePools::lock(&pools.slots[0]);
            let p = pool.slab.iter().map(|e| &e.1).chain(pool.servers.values()).find_map(|s| s.conns.front()).expect("the idle connection");
            assert!(a.poller.is_registered(p.conn.fd.as_fd()), "an idle connection stays in its worker's epoll set");
            p.conn.fd.as_raw_fd()
        };
        assert_eq!(a.fdtab.state(raw), FdState::Idle);
        let mut cb = client(&mut b, fe_b);
        exchange(&mut b, &mut cb);
        assert!(conns.try_recv().is_ok() && conns.try_recv().is_err(), "one server connection, reused");
        let (_, entry) = b.sessions.iter_mut().find(|(_, e)| e.sess.srv.is_some()).expect("worker 1 holds it");
        let fd = entry.sess.srv.as_ref().expect("srv").as_fd();
        assert_eq!(fd.as_raw_fd(), raw);
        assert!(!a.poller.is_registered(fd), "still in its former owner's epoll set");
        assert!(b.poller.is_registered(fd));
        // The former owner runs on, its stale entry inert.
        let _ = a.run_once();
        assert!(drive_until(&mut b, |b| b.idle_backend_pool.total() == 1 && IdlePools::lock(&pools.slots[1]).conns == 1), "idle on worker 1");
        exchange(&mut b, &mut cb);
        assert!(conns.try_recv().is_err(), "still the one server connection");
    }

    /// A connection its owner's epoll set cannot be made to forget (`EPOLL_CTL_DEL` fails)
    /// is closed, not used: the taker opens its own, and the closed one leaves the owner's
    /// slot and its server's idle count.
    #[test]
    fn a_connection_that_cannot_leave_its_owners_epoll_is_closed_not_taken() {
        let (srv, conns) = backend();
        let pools = IdlePools::with(2, true);
        let (mut a, fe_a) = engine_with(srv, Some(ibex_config::HttpReuse::Always));
        let (mut b, fe_b) = engine_with(srv, Some(ibex_config::HttpReuse::Always));
        a.share_idle_pools(&pools, 0);
        b.share_idle_pools(&pools, 1);
        let mut ca = client(&mut a, fe_a);
        exchange(&mut a, &mut ca);
        assert!(drive_until(&mut a, |a| a.idle_backend_pool.total() == 1), "idle on worker 0");
        // Worker 0's slot names a descriptor that is not an epoll set.
        let (not_epoll, _peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        IdlePools::lock(&pools.slots[0]).epfd = Some(Arc::new(OwnedFd::from(not_epoll)));
        let mut cb = client(&mut b, fe_b);
        exchange(&mut b, &mut cb);
        assert!(conns.try_recv().is_ok() && conns.try_recv().is_ok(), "worker 1 opened its own server connection");
        assert_eq!(IdlePools::lock(&pools.slots[0]).conns, 0, "the closed one left worker 0's slot");
        assert!(drive_until(&mut b, |b| idle_count(&b.idle_backend_pool) == 1), "the server counts only worker 1's");
    }
}

/// Binds a non-blocking CLI listener at `path`, replacing a stale socket file.
///
/// # Errors
/// Returns an error if binding or setting non-blocking mode fails.
pub fn bind_unix_listener(path: &Path) -> io::Result<(UnixListener, PathBuf)> {
    let path_buf = path.to_path_buf();
    let _ = std::fs::remove_file(&path_buf);
    let listener = UnixListener::bind(&path_buf)?;
    listener.set_nonblocking(true)?;
    Ok((listener, path_buf))
}

#[cfg(test)]
mod inherited_socket_tests {
    use super::*;

    /// T342: an inherited descriptor that is not a listening stream socket for its address
    /// is reported on stderr (through `stderr_line!`) and a fresh socket is bound instead.
    #[test]
    fn a_mismatched_inherited_socket_falls_back_to_a_fresh_bind() {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp");
        let addr = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).expect("free port");
        let fd = rustix::io::dup(&udp).expect("dup");
        crate::handover::distribute(vec![(crate::handover::Kind::Tcp, addr, fd)], 1);
        let got = listeners_for(0, addr, 3, &ibex_config::ast::SocketTuning::default(), 128).expect("listeners");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].addr(), addr);
    }
}

#[cfg(test)]
mod sample_to_bin_tests {
    use super::*;

    /// `sample_casts[*][SMP_T_BIN]` (src/sample.c): `c_int2bin` and `c_bool2bin` make eight bytes
    /// big-endian, `c_addr2bin` the address, `c_meth2str` the method; a string or a binary keeps
    /// its bytes. The integer case against `haproxy`: `set-headers-bin int(5)` changes nothing
    /// (its first byte is the 0 that ends the list).
    #[test]
    fn a_sample_is_cast_to_binary_as_haproxy_casts_it() {
        assert_eq!(sample_to_bin(Sample::Sint(5)), [0, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(sample_to_bin(Sample::Sint(-1)), [0xff; 8]);
        assert_eq!(sample_to_bin(Sample::Bool(true)), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(sample_to_bin(Sample::Bool(false)), [0; 8]);
        assert_eq!(sample_to_bin(Sample::Ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4))), [1, 2, 3, 4]);
        assert_eq!(sample_to_bin(Sample::Ipv6(std::net::Ipv6Addr::LOCALHOST)).len(), 16);
        assert_eq!(sample_to_bin(Sample::Meth(ibex_proto::htx::HttpMethod::Get)), b"GET");
        assert_eq!(sample_to_bin(Sample::Str("ab".into())), b"ab");
        assert_eq!(sample_to_bin(Sample::Bin(vec![0, 1])), [0, 1]);
    }
}

#[cfg(test)]
mod accept_pause_tests {
    use super::*;

    /// T430 row 33: a listener stopped for `global maxconn` while its frontend's `maxconn` is
    /// reached too stayed stopped for good. A connection closes by releasing its global slot
    /// and, later in the same function, its frontend's; a worker looking in between found the
    /// global limit free and the frontend's still full, re-armed nothing, and cleared
    /// `global_paused` without setting `fe_paused`, the flag that makes `step` look at the
    /// frontend limit again. The connection waiting in the kernel's accept queue was never
    /// accepted (about 1 run in 80 of `maxconn_client_left` under load).
    #[test]
    fn a_listener_stopped_by_both_limits_is_rearmed_when_the_frontend_has_room() {
        let mut fe = ibex_config::ast::FrontendSection::default();
        fe.bind = Some("127.0.0.1:0".parse().expect("addr"));
        let config = Config { frontends: vec![fe], ..Default::default() };
        let mut engine = Engine::new(&config, 64).expect("Engine::new");
        let lfd = engine.listeners[0].raw_fd();
        engine.listeners[0].maxconn.set(1);
        engine.listeners[0].maxconn.inc();
        // The worker is told the process is full: it stops its listeners.
        engine.pause_listeners_for_global();
        assert!(engine.fdtab.interest(lfd).is_none());
        // The global slot is back, the frontend's is not yet: nothing to re-arm.
        engine.resume_paused_listeners();
        assert!(engine.fdtab.interest(lfd).is_none(), "the frontend is still full");
        // The frontend's slot comes back: the next pass must re-arm the listener.
        engine.listeners[0].maxconn.dec();
        engine.resume_paused_listeners();
        assert!(!engine.fdtab.interest(lfd).is_none(), "the listener must be polled again");
    }
}

#[cfg(test)]
mod add_req_connection_tests {
    use super::*;

    /// A request that keeps a copy of its headers (`req_headers`) is not edited in place: the
    /// token goes into the copy and the head is written out of it.
    #[test]
    fn the_token_of_a_request_with_a_header_copy_is_written_out_with_it() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut s = TcpSession::new(OwnedFd::from(a), Default::default(), 0, Tick::ETERNITY);
        s.req.replace_prefix(0, b"GET / HTTP/1.0\r\nHost: a\r\n\r\n");
        s.req_headers = Some(vec![("Host".to_string(), "a".to_string())]);
        add_req_connection(&mut s, "keep-alive");
        assert_eq!(s.req_headers.as_ref().map(Vec::len), Some(2));
        assert_eq!(s.req.readable(), b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n");
    }
}

#[cfg(test)]
mod stats_req_headers_tests {
    use super::*;

    /// The headers the stats POST checks come from the HTX message, else the parsed list
    /// (an HTTP/2 stream), else there are none.
    #[test]
    fn stats_req_headers_falls_back_to_the_parsed_list() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("pair");
        let mut s = TcpSession::new(OwnedFd::from(a), Default::default(), 0, Tick::ETERNITY);
        assert!(EngineDispatcher::stats_req_headers(&s).is_empty());
        s.req_headers = Some(vec![("Origin".to_string(), "http://evil".to_string())]);
        assert_eq!(EngineDispatcher::stats_req_headers(&s), [("Origin", "http://evil")]);
    }
}

/// Puts a stream refused a buffer at `tune.buffers.limit` in its class's wait queue (S6,
/// [`crate::buf_wait`]); a stream woken for a buffer and refused again goes back to the front.
/// The queue cannot grow: the stream fails, as in S5, and `true` says it must run again (its
/// failure's answer is written in its next run; nothing else would wake it: T473).
#[cold]
#[inline(never)]
fn buf_wait_enter(entry: &mut SessionEntry, session_idx: u32) -> bool {
    let Some(class) = crate::buf_wait::take_want() else { return false };
    let front = entry.buf_wait.take_offered();
    if entry.buf_wait.queued() {
        return false;
    }
    if crate::buf_wait::enter(entry.task, session_idx, class, front) {
        entry.buf_wait.enqueued(class);
        // A buffer given back on this thread after the refusal, before the stream was queued
        // (the stream's own empty request buffer, released as it waits for a TLS read: S6b)
        // was offered to nobody: it is the waiter's now.
        if crate::buf::cached_standard() > 0 {
            crate::buf_wait::reoffer();
        }
        false
    } else {
        entry.sess.fail_alloc();
        true
    }
}
