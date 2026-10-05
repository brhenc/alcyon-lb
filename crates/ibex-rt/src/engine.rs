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
    set_proc_var, TimeoutKind, CURRENT_RES_HEADERS, CURRENT_RES_STATUS, CURRENT_TIMEOUTS, CURRENT_VARS,
};

thread_local! {
    pub static WORKER_ID: Cell<usize> = const { Cell::new(0) };
    static STRICT_MODE: Cell<bool> = const { Cell::new(true) };
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
}

impl SrvPoolCfg {
    pub const DEFAULT: Self = Self { max_conn: -1, low_conn: 0, purge_delay_ms: 5000 };

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

/// The idle server connections of a worker, per server (`srv->per_thr[tid]`). Shared with
/// the other workers through [`IdlePools`].
#[derive(Debug, Default)]
struct WorkerPool {
    servers: HashMap<(usize, usize), SrvIdle>,
    /// Connections in all lists: a session whose server connection has the pool to itself
    /// (the usual keep-alive case) never looks the server up.
    conns: usize,
    /// The earliest `purge_at` of all servers.
    next_purge: Option<Instant>,
}

impl WorkerPool {
    /// When [`WorkerPool::purge`] next has work.
    fn next_purge(&self) -> Option<Instant> {
        self.next_purge
    }

    /// `srv_add_to_idle_list`: the server keeps a released connection if it keeps any
    /// (`pool-purge-delay` not 0), `pool-max-conn` allows, and its safe list is empty and
    /// the connection is itself safe or its idle list is empty, or the server is not keeping
    /// more than it was seen to need plus `pool-low-conn` (`used` is the server's
    /// connections in use, this one included). Otherwise it is given back for closing.
    #[cfg(test)]
    fn keep(&mut self, key: IdleKey, conn: IdleConn, is_safe: bool, cfg: SrvPoolCfg, used: u32, now: Instant) -> Result<(), IdleConn> {
        self.keep_with(key, conn, is_safe, cfg, used, (0, used), now)
    }

    /// [`WorkerPool::keep`], with what the other workers know of the server: its idle
    /// connections on them, and the most connections it was seen to use at once on any
    /// (`srv->curr_idle_conns`, `srv->max_used_conns`: server-wide in `HAProxy`; only the
    /// empty-lists clause is this worker's own, `srv->per_thr[tid]`).
    #[allow(clippy::too_many_arguments)]
    fn keep_with(&mut self, key: IdleKey, conn: IdleConn, is_safe: bool, cfg: SrvPoolCfg, used: u32, (others, peak): (usize, u32), now: Instant) -> Result<(), IdleConn> {
        if cfg.purge_delay_ms == 0 {
            return Err(conn);
        }
        let s = self.servers.entry(key.srv).or_default();
        // `srv_use_conn` raises both with every connection in use; seen from here, the
        // peak is at least the connections in use at a release.
        s.max_used = s.max_used.max(used).max(peak);
        s.est_need = s.est_need.max(used).max(peak);
        let curr_idle = s.conns.len();
        let all_idle = curr_idle + others;
        if usize::try_from(cfg.max_conn).is_ok_and(|m| m <= all_idle) {
            return Err(conn);
        }
        let idle_empty = curr_idle == s.safe;
        let curr = u32::try_from(all_idle).unwrap_or(u32::MAX);
        if !((s.safe == 0 && (is_safe || idle_empty)) || used.saturating_add(curr) <= used.max(s.est_need).saturating_add(cfg.low_conn)) {
            return Err(conn);
        }
        s.conns.push_back(Pooled { addr: key.addr, name: key.name, safe: is_safe, conn });
        s.safe += usize::from(is_safe);
        self.conns += 1;
        if s.purge_at.is_none() {
            s.purge_delay = Duration::from_millis(u64::from(cfg.purge_delay_ms));
            let at = now + s.purge_delay;
            s.purge_at = Some(at);
            self.next_purge = Some(self.next_purge.map_or(at, |n| n.min(at)));
        }
        Ok(())
    }

    /// `be_reuse_connection`: the connection a request may take, and whether it was a safe
    /// one. A request that is not the first of its client connection takes an idle
    /// connection, then a safe one; a first request takes nothing under `safe`, a safe
    /// connection under `aggressive`, a safe then an idle one under `always`. The oldest
    /// that matches is taken; one whose peer has closed is dropped on the way.
    fn take(&mut self, key: &IdleKey, first_req: bool, mode: ibex_config::HttpReuse) -> Option<(IdleConn, bool)> {
        use ibex_config::HttpReuse::{Aggressive, Always, Never, Safe};
        let s = self.servers.get_mut(&key.srv)?;
        let order: &[bool] = match (first_req, mode) {
            (_, Never) | (true, Safe) => &[],
            (false, _) => &[false, true],
            (true, Aggressive) => &[true],
            (true, Always) => &[true, false],
        };
        for &safe in order {
            while let Some(pos) = s.conns.iter().position(|p| p.safe == safe && p.addr == key.addr && p.name == key.name) {
                let Some(p) = s.conns.remove(pos) else { break };
                s.safe -= usize::from(safe);
                self.conns -= 1;
                if raw::is_idle_conn_alive(p.conn.fd.as_fd()) {
                    return Some((p.conn, safe));
                }
            }
        }
        None
    }

    /// Closes every idle connection whose peer has gone: EOF, a reset, or bytes nobody asked
    /// for (`HAProxy` subscribes an idle connection for reads and closes it on any of them).
    /// Reports the number closed per server to `gone`: nothing is allocated.
    fn drop_dead(&mut self, mut gone: impl FnMut((usize, usize), usize)) {
        for (&srv, s) in &mut self.servers {
            let before = s.conns.len();
            s.conns.retain(|p| {
                let alive = raw::is_idle_conn_alive(p.conn.fd.as_fd());
                if !alive {
                    s.safe -= usize::from(p.safe);
                }
                alive
            });
            let n = before - s.conns.len();
            if n > 0 {
                self.conns -= n;
                gone(srv, n);
            }
        }
    }

    /// `srv_cleanup_idle_conns`, for every server whose purge is due at `now`: half the
    /// idle connections beyond what the server needs, rounded up, plus one, are closed,
    /// oldest first; the estimate of the need moves halfway to the peak seen since the last
    /// purge (never below it), and the peak restarts from the connections in use (`used`).
    fn purge(&mut self, now: Instant, used: impl Fn((usize, usize)) -> u32) {
        if self.next_purge.is_none_or(|t| t > now) {
            return;
        }
        let mut next: Option<Instant> = None;
        for (&srv, s) in &mut self.servers {
            let Some(at) = s.purge_at else { continue };
            if at <= now {
                let curr_idle = s.conns.len();
                if curr_idle > 0 {
                    let in_use = used(srv);
                    let exceed = i64::from(in_use) + i64::try_from(curr_idle).unwrap_or(i64::MAX) - i64::from(s.max_used.max(s.est_need));
                    let exceed = exceed / 2 + (exceed & 1);
                    let avg = (u64::from(s.est_need) + u64::from(s.max_used)) / 2;
                    s.est_need = u32::try_from(avg).unwrap_or(u32::MAX).max(s.max_used);
                    s.max_used = in_use;
                    if exceed > 0 {
                        let n = usize::try_from(exceed + 1).unwrap_or(usize::MAX).min(curr_idle);
                        for p in s.conns.drain(..n) {
                            s.safe -= usize::from(p.safe);
                            p.conn.close();
                        }
                        self.conns -= n;
                    }
                }
                s.purge_at = (!s.conns.is_empty()).then(|| now + s.purge_delay);
            }
            if let Some(t) = s.purge_at {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        self.next_purge = next;
    }
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
/// another worker's (`conn_backend_get`), unless `tune.idle-pool.shared off`. The socket was
/// taken off its worker's poller when it went idle and joins the taker's.
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
}

/// A server's idle connections in all slots, and the most it was seen to use at once
/// since a purge last looked at it.
#[derive(Debug, Default)]
struct SrvIdleCount {
    idle: AtomicUsize,
    peak: std::sync::atomic::AtomicU32,
}

impl IdlePools {
    /// The pools of `workers` workers, `tune.idle-pool.shared` read from `config`.
    #[must_use]
    pub fn new(workers: usize, config: &Config) -> Arc<Self> {
        let unshared = config.global.as_ref().is_some_and(|g| g.idle_pool_unshared);
        Self::with(workers, !unshared)
    }

    fn with(workers: usize, shared: bool) -> Arc<Self> {
        Arc::new(Self {
            slots: (0..workers.max(1)).map(|_| IdleSlot::default()).collect(),
            shared,
            next_takeover: AtomicUsize::new(0),
            srv_idle: std::sync::RwLock::default(),
        })
    }

    /// Runs `f` on server `srv`'s counts, made on first use.
    fn with_count<R>(&self, srv: (usize, usize), f: impl Fn(&SrvIdleCount) -> R) -> R {
        if let Some(n) = self.srv_idle.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(&srv) {
            return f(n);
        }
        f(self.srv_idle.write().unwrap_or_else(std::sync::PoisonError::into_inner).entry(srv).or_default())
    }

    /// Server `srv`'s idle connections in every slot, and its peak of connections in use
    /// raised to `used`.
    fn srv_seen(&self, srv: (usize, usize), used: u32) -> (usize, u32) {
        self.with_count(srv, |n| (n.idle.load(Ordering::Relaxed), n.peak.fetch_max(used, Ordering::Relaxed).max(used)))
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
        IdlePool { pools: Arc::clone(self), wid: wid % self.slots.len(), next_purge: None, next_sweep: None }
    }

    fn lock(slot: &IdleSlot) -> std::sync::MutexGuard<'_, WorkerPool> {
        slot.pool.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How often a worker looks for idle server connections their server has closed.
const IDLE_SWEEP: Duration = Duration::from_millis(50);

/// A worker's handle on [`IdlePools`]: what the engine keeps, takes and purges through.
#[derive(Debug)]
pub struct IdlePool {
    pools: Arc<IdlePools>,
    wid: usize,
    /// When this worker's purge next has work: kept here so that a step with nothing to purge
    /// does not take the lock.
    next_purge: Option<Instant>,
    /// When this worker next looks for idle connections their server has closed.
    next_sweep: Option<Instant>,
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

    /// When [`IdlePool::sweep`] next has work: none while this worker holds no idle connection.
    #[must_use]
    pub fn next_sweep(&self) -> Option<Instant> {
        self.next_sweep
    }

    /// Closes this worker's idle connections whose server has closed or reset them, or sent
    /// data, at most every [`IDLE_SWEEP`]. A peek on each: the cost is per idle connection per
    /// interval, none on the request path.
    pub fn sweep(&mut self, now: Instant) {
        if self.next_sweep.is_none_or(|t| t > now) {
            return;
        }
        let slot = &self.pools.slots[self.wid];
        let mut pool = IdlePools::lock(slot);
        pool.drop_dead(|srv, n| self.pools.count_idle(srv, 0, n));
        slot.conns.store(pool.conns, Ordering::Relaxed);
        self.next_purge = pool.next_purge();
        self.next_sweep = (pool.conns != 0).then(|| now + IDLE_SWEEP);
    }

    /// See [`WorkerPool::keep`]; into this worker's slot.
    fn keep(&mut self, key: IdleKey, conn: IdleConn, is_safe: bool, cfg: SrvPoolCfg, used: u32, now: Instant) -> Result<(), IdleConn> {
        let srv = key.srv;
        let slot = &self.pools.slots[self.wid];
        let mut pool = IdlePools::lock(slot);
        let own = pool.servers.get(&srv).map_or(0, |s| s.conns.len());
        let (all, peak) = self.pools.srv_seen(srv, used);
        let r = pool.keep_with(key, conn, is_safe, cfg, used, (all.saturating_sub(own), peak), now);
        slot.conns.store(pool.conns, Ordering::Relaxed);
        self.next_purge = pool.next_purge();
        drop(pool);
        if r.is_ok() {
            self.next_sweep.get_or_insert(now + IDLE_SWEEP);
            self.pools.count_idle(srv, 1, 0);
        }
        r
    }

    /// `conn_backend_get`: this worker's lists first; when they hold nothing that matches,
    /// with sharing on and unless the server keeps fewer idle connections than its
    /// `pool-low-conn` (`steal` false), every other worker's whose lock is free, from the
    /// one after the last taken from (`HA_SPIN_TRYLOCK`: a busy one is skipped).
    fn take(&mut self, key: &IdleKey, first_req: bool, mode: ibex_config::HttpReuse, steal: bool) -> Option<(IdleConn, bool)> {
        let pools = &*self.pools;
        let own = &pools.slots[self.wid];
        if own.conns.load(Ordering::Relaxed) != 0 {
            let mut pool = IdlePools::lock(own);
            let before = pool.conns;
            let found = pool.take(key, first_req, mode);
            own.conns.store(pool.conns, Ordering::Relaxed);
            self.next_purge = pool.next_purge();
            pools.count_idle(key.srv, 0, before - pool.conns);
            if found.is_some() {
                return found;
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
            // A busy slot is skipped, and so is a poisoned one: its worker panicked.
            let Ok(mut pool) = slot.pool.try_lock() else { continue };
            let before = pool.conns;
            let found = pool.take(key, first_req, mode);
            slot.conns.store(pool.conns, Ordering::Relaxed);
            let removed = before - pool.conns;
            drop(pool);
            pools.count_idle(key.srv, 0, removed);
            if found.is_some() {
                pools.next_takeover.store(i + 1, Ordering::Relaxed);
                return found;
            }
        }
        None
    }

    /// Idle connections in every worker's slot: what `pool-low-conn` is compared with
    /// before taking another worker's (`srv->curr_idle_conns`, here for all servers).
    fn total(&self) -> usize {
        self.pools.slots.iter().map(|s| s.conns.load(Ordering::Relaxed)).sum()
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
        let before: Vec<((usize, usize), usize, Option<Instant>)> = pool.servers.iter().map(|(&k, s)| (k, s.conns.len(), s.purge_at)).collect();
        pool.purge(now, &used);
        slot.conns.store(pool.conns, Ordering::Relaxed);
        for (srv, n, at) in before {
            let after = pool.servers.get(&srv).map_or(0, |s| s.conns.len());
            self.pools.count_idle(srv, 0, n.saturating_sub(after));
            // The peak restarts from the connections in use with each purge of the server.
            if at.is_some_and(|t| t <= now) {
                let in_use = used(srv);
                self.pools.with_count(srv, |c| c.peak.store(in_use, Ordering::Relaxed));
            }
        }
        self.next_purge = pool.next_purge();
    }
}

#[cfg(test)]
mod shared_pool_tests {
    use super::*;

    fn alive() -> (IdleConn, std::os::unix::net::UnixStream) {
        let (a, b) = std::os::unix::net::UnixStream::pair().expect("pair");
        (IdleConn { fd: OwnedFd::from(a), xprt: crate::xprt::ServerXprt::Plain }, b)
    }

    fn key() -> IdleKey {
        IdleKey { srv: (0, 0), addr: "127.0.0.1:1".parse().unwrap(), name: None }
    }

    const CFG: SrvPoolCfg = SrvPoolCfg { max_conn: -1, low_conn: 0, purge_delay_ms: 500 };

    /// A connection worker 0 released is taken by worker 1 when shared, not when not, nor
    /// when the lock is held, nor when `pool-low-conn` forbids it.
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
            {
                let _held = IdlePools::lock(&pools.slots[0]);
                assert!(w1.take(&key(), true, Always, true).is_none());
            }
            assert_eq!(w1.take(&key(), true, Always, true).is_some(), shared);
            assert_eq!(w0.is_empty(), shared);
            // The worker the connection was taken from purges nothing and is unscheduled;
            // one that still holds it purges again later.
            w0.purge(t0 + Duration::from_secs(1), |_| 0);
            assert_eq!(w0.next_purge().is_none(), shared);
        }
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

    /// A sweep closes the idle connections whose peer closed, or sent bytes, and keeps the
    /// rest; the counts the pool and the servers hold follow, and with nothing left the
    /// sweep is no longer scheduled.
    #[test]
    fn a_sweep_closes_the_idle_connections_the_peer_closed() {
        use std::io::Write;
        let t0 = Instant::now();
        let pools = IdlePools::with(1, true);
        let mut w = pools.worker(0);
        let (c0, p0) = alive();
        let (c1, mut p1) = alive();
        let (c2, _p2) = alive();
        assert!(w.keep(key(), c0, false, CFG, 3, t0).is_ok());
        assert!(w.keep(IdleKey { srv: (0, 1), ..key() }, c1, false, CFG, 3, t0).is_ok());
        assert!(w.keep(IdleKey { srv: (0, 2), ..key() }, c2, false, CFG, 3, t0).is_ok());
        assert_eq!(w.next_sweep(), Some(t0 + IDLE_SWEEP));
        w.sweep(t0);
        assert_eq!(w.total(), 3, "not due yet");
        drop(p0);
        p1.write_all(b"x").expect("unexpected bytes");
        w.sweep(t0 + IDLE_SWEEP);
        assert_eq!(w.total(), 1);
        assert_eq!(w.next_sweep(), Some(t0 + IDLE_SWEEP * 2));
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
        IdleConn { fd: OwnedFd::from(std::fs::File::open("/dev/null").expect("open")), xprt: crate::xprt::ServerXprt::Plain }
    }

    fn key() -> IdleKey {
        IdleKey { srv: (0, 0), addr: "127.0.0.1:1".parse().unwrap(), name: None }
    }

    const CFG: SrvPoolCfg = SrvPoolCfg { max_conn: -1, low_conn: 0, purge_delay_ms: 500 };

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
        let c = IdleConn { fd: OwnedFd::from(a), xprt: crate::xprt::ServerXprt::Plain };
        assert!(pool.keep(key(), c, false, CFG, 3, t0).is_ok());
        assert!(pool.take(&key(), false, ibex_config::HttpReuse::Safe).is_some());
        pool.purge(t0 + Duration::from_millis(500), |_| 0);
        assert_eq!(pool.next_purge(), None);
        assert_eq!(pool.servers[&(0, 0)].est_need, 3);
    }
}

/// The idle connection settings of each server of a proxy; empty when all are the defaults.
fn pool_cfgs(servers: &[ibex_config::Server]) -> Vec<SrvPoolCfg> {
    let cfg = |s: &ibex_config::Server| {
        let p = s.pool.as_deref().copied().unwrap_or_default();
        SrvPoolCfg { max_conn: p.max_conn, low_conn: p.low_conn, purge_delay_ms: p.purge_delay }
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
    let Some(tls) = tls else {
        sess.attach_server(srv_fd, now);
        return;
    };
    let (fe, be) = (&proxies[fe_idx], &proxies[be_idx]);
    let stick = StickView::new(proxies, &sess.tracked_sc);
    let sni = tls.sni(sample_registry(), &stream_sample_ctx(sess, fe, be, &ProxiesView(proxies), &stick));
    let ip = s_idx.and_then(|i| be.servers.get(i)).map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |a| a.ip());
    let mut xprt = tls.connect(&srv_fd, sni.as_deref(), ip);
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
    sess.attach_server_with_xprt(srv_fd, xprt, now);
}

/// The SNI a request on `sess` would send to `proxies[be_idx].servers.at(s_idx)`, for the
/// idle pool's key and for deciding whether the connection in hand can carry it.
fn server_sni(sess: &TcpSession, proxies: &[Proxy], fe_idx: usize, be_idx: usize, s_idx: Option<usize>) -> Option<String> {
    let tls = s_idx.and_then(|i| proxies.get(be_idx).and_then(|p| p.server_tls.get(i)).and_then(Option::as_ref))?;
    let stick = StickView::new(proxies, &sess.tracked_sc);
    tls.sni(sample_registry(), &stream_sample_ctx(sess, &proxies[fe_idx], &proxies[be_idx], &ProxiesView(proxies), &stick))
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
fn usize_to_u32(idx: usize) -> u32 {
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

/// Accumulated statistics per proxy.
#[derive(Default, Debug)]
pub struct ProxyStats {
    /// Sessions accepted by the frontend per second (`fe_sess_rate`).
    pub fe_sess_rate: RateCtr,
    /// HTTP requests received by the frontend per second (`fe_req_rate`).
    pub fe_req_rate: RateCtr,
    /// Streams switched to the backend per second (`be_sess_rate`).
    pub be_sess_rate: RateCtr,
    pub cum_conn: AtomicU64,
    pub act_conn: AtomicU32,
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
    }

    pub fn clear(&self) {
        self.cum_conn.store(0, Ordering::Relaxed);
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




/// What [`Proxy::ids`] holds.
#[derive(Debug, Clone, Default)]
pub struct ProxyIdInfo {
    /// The transaction counters `show stat` prints (T165), made on first use. Here, in the
    /// box, because `Proxy` is held to its size.
    pub tc: std::sync::OnceLock<Arc<crate::statcnt::ProxyCounters>>,
    /// The proxy's numeric id (`uuid`): `iid` in `show stat`, `be_id` in `show servers
    /// state`, what `fe_id` and `be_id` read. Numbered in the order the sections were
    /// written, from 2, around the ones that asked for an `id` (`Config::proxy_ids`).
    pub iid: u32,
    /// Where the section was written among the proxies: `show stat` lists them in that order.
    pub decl: u32,
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
    /// `retry-on`, as the `ibex_config::RE_*` bits: what a failed attempt is retried on.
    pub retry_on: u32,
}

impl ProxyIdInfo {
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
    pub monitor_uri: Option<Box<str>>,
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
    pub server_check_configs: Vec<Option<Box<ServerCheckConfig>>>,
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
    /// `http_req_rules`' `capture` expressions, compiled when the proxy is built: one entry
    /// per rule, `None` for any other action.
    pub http_req_capture_exprs: Vec<Option<Expr>>,
    pub http_res_rules: Vec<ibex_config::HttpResRule>,
    pub http_after_res_rules: Vec<ibex_config::HttpAfterResRule>,
    /// Indices into [`Engine::log_targets`]. Held as indices rather than targets because
    /// `Proxy` is `Clone` and a `SyslogTarget` owns a socket; the sockets live once, on
    /// the engine, and every proxy points at the ones its section resolved to.
    pub log_target_idx: Vec<usize>,
    /// `option log-health-checks`: log every check whose health counter moved, not only
    /// the UP/DOWN transitions.
    pub log_health_checks: bool,
    /// HTTP connection reuse strategy (`http-reuse`).
    pub http_reuse: ibex_config::HttpReuse,
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
    /// `option dontlognull`: a connection that carried nothing logs nothing.
    pub dont_log_null: bool,
    /// `option dontlog-normal`, `option log-separate-errors`, `option logasap`: the
    /// `ibex_config::LOG_OPT_*` bits.
    pub log_opts: u8,
    /// `unique-id-format`, compiled.
    pub unique_id_format: Option<Arc<crate::logfmt::LogFormat>>,
    /// `unique-id-header`: the request header the unique ID is sent to the server in.
    pub unique_id_header: Option<String>,
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
        let is_server_available = |idx: usize| -> bool {
            if idx >= self.servers.len() || crate::lb::avoided(self, idx) {
                return false;
            }
            if let Some(status) = self.server_statuses.get(idx) {
                if status.load(Ordering::Relaxed) != ServerStatus::Up as u8 {
                    return false;
                }
            } else {
                return false;
            }
            if let Some(mc) = self.server_maxconn.get(idx) {
                if mc > 0 {
                    let act = self.server_actconn.get(idx).map(|a| a.load(Ordering::Relaxed)).unwrap_or(0);
                    if act >= mc {
                        return false;
                    }
                }
            }
            true
        };

        // 1. Check active (non-backup) servers first
        let active_up: Vec<usize> = (0..self.servers.len())
            .filter(|&idx| {
                let is_backup = self.server_backups.get(idx).copied().unwrap_or(false);
                // A weight of 0 (`set server ... weight 0`) takes no balanced traffic.
                !is_backup && is_server_available(idx) && self.server_weights.get(idx).unwrap_or(1) > 0
            })
            .collect();

        if !active_up.is_empty() {
            return active_up;
        }

        // 2. No active server: the first usable backup alone (`lbprm.fbck`).
        crate::lb::first_backup(self).into_iter().collect()
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

    /// Selects the target backend server using the configured load balancing algorithm,
    /// preferring primary servers over backup servers,
    /// or falls back to the dispatch address if all servers are down or absent.
    #[must_use]
    pub fn select_server(&self) -> Option<SocketAddr> {
        if self.servers.is_empty() {
            return self.dispatch;
        }
        match self.balance {
            BalanceAlgorithm::Leastconn => {
                if let Some(idx) = crate::lb::leastconn(self) {
                    Some(self.servers.at(idx))
                } else {
                    self.dispatch
                }
            }
            BalanceAlgorithm::StaticRr => {
                if let Some(idx) = crate::lb::static_rr(self) {
                    Some(self.servers.at(idx))
                } else {
                    self.dispatch
                }
            }
            BalanceAlgorithm::First => {
                if let Some(idx) = crate::lb::first(self) {
                    Some(self.servers.at(idx))
                } else {
                    self.dispatch
                }
            }
            BalanceAlgorithm::Random(draws) => {
                if let Some(idx) = crate::lb::random(self, draws) {
                    Some(self.servers.at(idx))
                } else {
                    self.dispatch
                }
            }
            BalanceAlgorithm::RoundRobin => {
                if let Some(idx) = crate::lb::round_robin(self) {
                    Some(self.servers.at(idx))
                } else {
                    self.dispatch
                }
            }
            _ => {
                let eligible = self.eligible_server_indices();
                if eligible.is_empty() {
                    return self.dispatch;
                }
                let chosen_idx = eligible[self.next_server_idx.fetch_add(1, Ordering::Relaxed) % eligible.len()];
                Some(self.servers.at(chosen_idx))
            }
        }
    }

    /// Selects the target backend server with load balancing algorithm (Source IP hash or round-robin),
    /// respecting backup failover and connection limits.
    #[must_use]
    pub fn select_server_with_key(&self, source_ip: Option<IpAddr>, uri: Option<&str>) -> Option<SocketAddr> {
        if self.servers.is_empty() {
            return self.dispatch;
        }
        match self.balance {
            BalanceAlgorithm::Source if self.hash_type == ibex_config::HashType::Consistent && source_ip.is_some() => {
                let ip = source_ip?;
                crate::lb::balance_source_consistent(self, ip).map(|idx| self.servers.at(idx)).or(self.dispatch)
            }
            BalanceAlgorithm::Source => {
                let eligible = self.eligible_server_indices();
                if eligible.is_empty() {
                    return self.dispatch;
                }
                if let Some(ip) = source_ip {
                    let hash: usize = match ip {
                        IpAddr::V4(v4) => u32::from(v4) as usize,
                        IpAddr::V6(v6) => v6
                            .octets()
                            .iter()
                            .fold(0usize, |acc, &b| acc.wrapping_add(b as usize)),
                    };
                    let chosen_idx = eligible[hash % eligible.len()];
                    return Some(self.servers.at(chosen_idx));
                }
                let chosen_idx = eligible[self.next_server_idx.fetch_add(1, Ordering::Relaxed) % eligible.len()];
                Some(self.servers.at(chosen_idx))
            }
            BalanceAlgorithm::Uri => {
                let u = uri.unwrap_or("/");
                if let Some(idx) = crate::lb::balance_uri(self, u) {
                    Some(self.servers.at(idx))
                } else {
                    self.select_server()
                }
            }
            _ => self.select_server(),
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
    pub target_addr: Option<SocketAddr>,
    pub cli_raw_fd: RawFd,
    pub srv_raw_fd: Option<RawFd>,
    pub cli_interest: Interest,
    pub srv_interest: Interest,
    pub actconn_reclaimed: bool,
    /// The stream's counters were added to `show stat`'s (once per transaction).
    pub stats_done: bool,
    /// The `Connect from` line of a frontend with no `log-format` is still to be sent: it goes
    /// once the connection has its PROXY header and TLS handshake behind it.
    pub connect_log_due: bool,
    /// Requests the server connection has carried (saturating at 2): from the second it is
    /// kept in the server's safe list (`http-reuse`).
    pub srv_served: u8,
    /// A finished transaction's log line, waiting to be sent to its frontend's targets.
    pub log_line: Option<Vec<u8>>,
    /// `log_line` is a failed stream's: `option log-separate-errors` sends it at `err`.
    pub log_err: bool,
}

/// Per-thread storage for active sessions.
pub struct SessionArena {
    entries: Vec<Option<SessionEntry>>,
    free: Vec<u32>,
    live: usize,
}

impl SessionArena {
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        SessionArena {
            entries: Vec::with_capacity(cap),
            free: Vec::with_capacity(cap),
            live: 0,
        }
    }

    pub fn alloc(&mut self, entry: SessionEntry) -> Option<u32> {
        self.live += 1;
        if let Some(idx) = self.free.pop() {
            self.entries[idx as usize] = Some(entry);
            Some(idx)
        } else {
            let idx = u32::try_from(self.entries.len()).ok()?;
            self.entries.push(Some(entry));
            Some(idx)
        }
    }

    #[must_use]
    pub fn get(&self, idx: u32) -> Option<&SessionEntry> {
        self.entries.get(idx as usize)?.as_ref()
    }

    pub fn get_mut(&mut self, idx: u32) -> Option<&mut SessionEntry> {
        self.entries.get_mut(idx as usize)?.as_mut()
    }

    pub fn free(&mut self, idx: u32) -> Option<SessionEntry> {
        let entry = self.entries.get_mut(idx as usize)?.take();
        if entry.is_some() {
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
    pub sessions: SessionArena,
    pub applets: AppletArena,
    pub cli_listener: Option<UnixListener>,
    pub cli_socket_path: Option<PathBuf>,
    /// The `stats socket` lines after the first, each with its own level (`HAProxy` binds
    /// them all).
    extra_cli: Vec<ExtraCli>,
    /// The listeners were stopped because `global maxconn` was reached (`globalconn`).
    global_paused: bool,
    /// A listener stopped polling because its frontend reached `maxconn`: the limit is shared
    /// by every worker, so a slot freed or a limit raised elsewhere is noticed by looking.
    fe_paused: bool,
    /// The `level` of the stats socket (`stats socket ... level`): what each new CLI connection
    /// may do. Unset means admin, as before the level was honoured.
    pub cli_level: crate::applet::CliLevel,
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
    /// Global HTTP/2 flood mitigation configuration.
    pub global_h2_flood_config: ibex_proto::H2FloodConfig,
    /// Shared idle backend connection pool across sessions (`http-reuse`).
    pub idle_backend_pool: IdlePool,
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
    listener: Option<UnixListener>,
    path: PathBuf,
    ident: Option<(u64, u64)>,
    level: crate::applet::CliLevel,
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Whatever the other workers still ask of this one is answered empty.
        self.mailboxes.close(self.mailbox_wid);
        for x in &self.extra_cli {
            if socket_file_ident(&x.path) == x.ident {
                let _ = std::fs::remove_file(&x.path);
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
) -> io::Result<Vec<Listener>> {
    let mut out = Vec::new();
    for fd in crate::handover::take_inherited(worker_id, addr) {
        match Listener::adopt(fd, addr, 128, proxy, tuning) {
            Ok(l) => out.push(l),
            Err(e) => eprintln!("[WARNING] {e}; binding a fresh socket instead"),
        }
    }
    if out.is_empty() {
        out.push(Listener::bind_tuned(addr, 128, proxy, tuning)?);
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
        "integer" | "int" => KeyType::Integer,
        "string" | "str" => KeyType::String,
        "binary" | "bin" => KeyType::Binary,
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

    StickTable::new(config)
}


/// The local hostname for the syslog HOSTNAME field.
///
/// Read once at startup. RFC 3164 wants a hostname with no domain part and no spaces;
/// anything unreadable becomes "-", which is what a collector expects for "unknown"
/// rather than an empty field that would shift every following token.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
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
) -> Arc<[(String, usize)]> {
    let rule_slots = rules
        .iter()
        .filter(|r| matches!(r.action, ibex_config::HttpReqAction::Capture { id: None, .. }))
        .count();
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
    slots.into_iter().map(Option::unwrap_or_default).collect()
}

/// The `http-request capture` expressions of `rules`, parsed once, parallel to the rules.
/// `Expr::parse` was running on every request; an expression that does not parse was
/// refused when the configuration loaded.
fn compile_capture_exprs(rules: &[ibex_config::HttpReqRule]) -> Vec<Option<Expr>> {
    rules
        .iter()
        .map(|r| match &r.action {
            ibex_config::HttpReqAction::Capture { expr, .. } => Expr::parse(expr).ok(),
            _ => None,
        })
        .collect()
}

/// The host name, read once: `%H`.
pub(crate) fn log_hostname() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(hostname)
}

/// The values of `slots` (`None` for a slot a rule fills) in a message head: the last
/// occurrence of each header, cut to its length (`capture_headers`, src/http_ana.c).
fn capture_values<'a>(slots: impl Iterator<Item = (&'a str, usize)>, headers: &[(&[u8], &[u8])]) -> Vec<Option<Vec<u8>>> {
    slots
        .map(|(name, len)| {
            // A slot no header fills (`declare capture`, a rule's) has no name.
            if name.is_empty() {
                return None;
            }
            // Bytes, not text: a header that is not UTF-8 is captured as the server sent it.
            headers.iter().rev().find(|(k, _)| k.trim_ascii().eq_ignore_ascii_case(name.as_bytes())).map(|(_, v)| {
                let v = v.trim_ascii();
                v[..len.min(v.len())].to_vec()
            })
        })
        .collect()
}

/// `s` cut to at most `len` bytes: a capture is bytes, and one that ends inside a
/// character keeps the byte it cut at, as in `HAProxy`.
fn cut_at(s: &str, len: usize) -> &[u8] {
    &s.as_bytes()[..len.min(s.len())]
}

/// A new HTTP transaction's request is in: its header captures and unique ID, before any
/// rule can read them, and the ID sent on in `unique-id-header` (`http_process_request`).
fn begin_http_stream(entry: &mut SessionEntry, proxies: &[Proxy], fe_idx: usize, pid: u32) {
    let fe = &proxies[fe_idx];
    if !fe.req_capture_slots.is_empty() {
        // A request that reached here was parsed into HTX (H1 and H2 alike).
        let headers: Vec<(&[u8], &[u8])> =
            entry.sess.htx_slice().map(|htx| htx.headers().map(|(k, v)| (k.as_bytes(), v.as_bytes())).collect()).unwrap_or_default();
        entry.sess.log.req_captures = capture_values(fe.req_capture_slots.iter().map(|(n, l)| (n.as_str(), *l)), &headers);
    }
    // The response's slots exist from here on, empty until a response fills them: `%hs`
    // is `{}` for a transaction the server never answered, and nothing for a request
    // that never parsed.
    entry.sess.log.res_captures = vec![None; fe.res_capture_slots.len()];
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
fn stream_facts(sess: &TcpSession, status: Option<u16>) -> ibex_sample::StreamFacts {
    let log = &sess.log;
    let used = sess.max_retries.saturating_sub(sess.conn_retries);
    ibex_sample::StreamFacts {
        error: used > 0 || status.is_some_and(|s| s >= 500),
        forwarded: log.queue.is_some() || log.connect.is_some(),
        toapplet: log.applet,
        retries: u32::from(used),
        redispatched: sess.redispatched,
    }
}

/// The sample context a log line's `%[...]` reads.
fn stream_sample_ctx<'a>(s: &'a TcpSession, fe: &'a Proxy, be: &'a Proxy, view: &'a ProxiesView<'a>, stick: &'a StickView<'a>) -> SampleContext<'a> {
    SampleContext {
        proxies: Some(view),
        stick: Some(stick),
        client_addr: s.client_addr,
        server_addr: s.server_addr,
        fc_src: s.fc_src,
        fc_dst: s.fc_dst,
        is_first_req: s.is_first_req,
        proxy_tlvs: s.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: s.cli_xprt.ssl_facts(),
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
        accept_date: Some(s.log.date),
        last_rule: last_rule_at(s.log.last_rule),
        prio: (s.log.prio_class, s.log.prio_offset),
        ..Default::default()
    }
}

/// `%ts` (`StreamLog::term_state`).
fn term_state(entry: &SessionEntry) -> [u8; 2] {
    let s = &entry.sess;
    s.log.term_state(s.ending, s.mode == Mode::Http, s.txn.as_ref().is_some_and(|t| t.rsp.is_done()))
}

/// What the stream measured, for its log line and `unique-id-format`. `proxies` holds the
/// frontend at `entry.proxy_idx`, or is the frontend alone (`proxy_idx` then 0).
fn stream_log_data<'a>(entry: &'a SessionEntry, proxies: &'a [Proxy], proxy_idx: usize, pid: u32) -> crate::logfmt::LogData<'a> {
    let fe = &proxies[proxy_idx];
    let be = proxies.get(entry.backend_idx).filter(|_| proxies.len() > 1).unwrap_or(fe);
    let sum = |p: &Proxy| p.stats.iter().map(|st| u64::from(st.act_conn.load(Ordering::Relaxed))).sum::<u64>();
    crate::logfmt::LogData {
        server_addr: entry.target_addr.map(|t| connect_addr(t, entry.sess.server_addr)),
        server: entry.target_server_idx.and_then(|i| proxies.get(entry.srv_backend_idx)?.server_ids.get(i)).map(String::as_str),
        term_state: term_state(entry),
        beconn: if std::ptr::eq(be, fe) { 0 } else { sum(be) },
        srvconn: entry
            .target_server_idx
            .and_then(|i| proxies.get(entry.srv_backend_idx)?.server_actconn.get(i))
            .map_or(0, |a| u64::from(a.load(Ordering::Relaxed))),
        ..session_log_data(&entry.sess, fe, be, pid)
    }
}

fn stream_status(s: &TcpSession) -> i64 {
    s.txn.as_ref().map(|t| t.status).or(s.log.status).map_or(-1, i64::from)
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
        frontend_ssl: s.cli_xprt.is_tls() || s.h3,
        ssl_cipher: s.cli_xprt.ssl_facts().cipher,
        ssl_version: s.cli_xprt.ssl_facts().protocol,
        backend: &be.name,
        backend_http: be.mode == Mode::Http,
        accept_date: l.date,
        t_handshake: 0,
        t_idle: l.ms(l.first_byte),
        t_request: l.ms(l.request),
        t_queue: l.ms(l.queue),
        t_connect: l.ms(l.connect),
        t_data: l.ms(l.data),
        t_close: if l.asap_done || fe.log_opts & ibex_config::LOG_OPT_ASAP != 0 { l.ms(l.data.or(Some(std::time::Instant::now()))) } else { l.ms(Some(std::time::Instant::now())) },
        plus: fe.log_opts & ibex_config::LOG_OPT_ASAP != 0,
        status: stream_status(s),
        bytes_out: stream_bytes_out(s),
        bytes_in: stream_bytes_in(s),
        // `%tsc`'s cookie characters: only a backend with a cookie mode shows them.
        cookie_state: match (&be.cookie, s.txn.as_ref()) {
            (Some(c), Some(t)) if c.rewrite || c.indirect || c.insert || c.prefix => t.ck.log_chars(),
            _ => *b"--",
        },
        actconn: sum(fe),
        feconn: sum(fe),
        retries: i64::from(s.max_retries.saturating_sub(s.conn_retries)),
        redispatched: s.log.redispatched,
        uniq_id: l.uniq_id,
        be_queue: l.be_queue,
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
    // Only what the counters need of the log line's data: the whole `LogData` costs a
    // measurable share of a request (T172).
    let s = &entry.sess;
    let l = &s.log;
    let term = term_state(entry);
    let routed = !http || (l.request.is_some() && !matches!(&term, b"PR" | b"LR"));
    let status = stream_status(s);
    let (bin, bout) = (stream_bytes_in(s), stream_bytes_out(s));
    let (t_queue, t_connect, t_data) = (l.ms(l.queue), l.ms(l.connect), l.ms(l.data));
    let t_request = l.ms(l.request).max(0);
    let tw = if t_queue >= 0 { t_queue - t_request } else { -1 };
    let tc = if t_connect >= 0 { t_connect - t_queue } else { -1 };
    let tr = if t_data >= 0 { t_data - t_connect } else { -1 };
    let ta = l.ms(Some(std::time::Instant::now()));
    let retries = u64::from(s.max_retries.saturating_sub(s.conn_retries));
    let answered = entry.sess.log.data.is_some();
    let srv_idx = entry.target_server_idx.filter(|_| routed);
    let be_idx = entry.backend_idx;
    let srv_be = entry.srv_backend_idx;

    let fe = &proxies[entry.proxy_idx].txn_counters().fe;
    if http {
        fe.req_tot.fetch_add(1, Ordering::Relaxed);
        fe.count_status(status);
        if entry.sess.log.request.is_none() {
            fe.ereq.fetch_add(1, Ordering::Relaxed);
        }
    }
    fe.bin.fetch_add(bin, Ordering::Relaxed);
    fe.bout.fetch_add(bout, Ordering::Relaxed);

    if !routed {
        return;
    }
    let now_ms = crate::statcnt::now_ms();
    let now = RateCtr::at(now_ms);
    let one = |c: &crate::statcnt::TxnCounters, server: bool| {
        c.stot.fetch_add(if server { 1 + retries } else { 1 }, Ordering::Relaxed);
        c.bin.fetch_add(bin, Ordering::Relaxed);
        c.bout.fetch_add(bout, Ordering::Relaxed);
        if http && (!server || answered) {
            c.req_tot.fetch_add(1, Ordering::Relaxed);
            c.count_status(status);
        }
        // Which side's fault, as `HAProxy`'s termination code counts it (measured on
        // 3.5-dev8-885761-29: `SH` adds two to `eresp`, `sH` one, `SD` one to `eresp` and
        // one to `srv_abrt`, `sD` one to `srv_abrt`, `PH` two to `eresp`).
        let (abrt_cli, abrt_srv, eresp) = match &term {
            b"SH" | b"PH" => (0, 0, 2),
            b"sH" => (0, 0, 1),
            b"SD" => (0, 1, 1),
            b"sD" => (0, 1, 0),
            [b'C', _] => (1, 0, 0),
            _ => (0, 0, 0),
        };
        // Most streams end cleanly: skip the locked add of a zero.
        if abrt_cli != 0 {
            c.cli_abrt.fetch_add(abrt_cli, Ordering::Relaxed);
        }
        if abrt_srv != 0 {
            c.srv_abrt.fetch_add(abrt_srv, Ordering::Relaxed);
        }
        if eresp != 0 {
            c.eresp.fetch_add(eresp, Ordering::Relaxed);
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
        // A server's rate counts the connections tried, retries included.
        for _ in 0..(if server { 1 + retries } else { 1 }) {
            c.sess_rate.tick_at(now);
        }
        let rate = u32::try_from(c.sess_rate.rate_at(now)).unwrap_or(u32::MAX);
        if rate > c.rate_max.load(Ordering::Relaxed) {
            c.rate_max.fetch_max(rate, Ordering::Relaxed);
        }
    };
    let be = &proxies[be_idx];
    let c = &be.txn_counters().be;
    if srv_idx.is_some() {
        c.lbtot.fetch_add(1, Ordering::Relaxed);
    }
    one(c, false);
    let on_server: u32 = be.server_actconn.iter().map(|a| a.load(Ordering::Relaxed)).sum();
    c.smax.fetch_max(on_server, Ordering::Relaxed);
    let srv = srv_idx.and_then(|i| Some((i, proxies[srv_be].txn_counters().srv.get(i)?)));
    for (i, c) in srv {
        c.lbtot.fetch_add(1, Ordering::Relaxed);
        one(c, true);
        let now_on = proxies[srv_be].server_actconn.get(i).map_or(0, |a| a.load(Ordering::Relaxed));
        c.smax.fetch_max(now_on, Ordering::Relaxed);
    }
}

/// The stream's log line, when its frontend logs (`HAProxy` logs nothing without a
/// `log` target).
///
/// With it, whether the stream failed (`strm_log`'s `err`): a redispatch or a retry, a
/// termination state that names a fault (anything but `-` and `L`), or a 5xx status. A
/// stream that did not fail has no line under `option dontlog-normal`.
fn stream_log_line(entry: &SessionEntry, proxies: &[Proxy], pid: u32) -> Option<(Vec<u8>, bool)> {
    let fe = &proxies[entry.proxy_idx];
    let fmt = fe.log_format.as_ref()?;
    if fe.log_target_idx.is_empty() || entry.sess.log.asap_done {
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
    let line = fmt.render_bytes(&data, sample_registry(), &SampleContext { at_log: true, res_status: txn_status, ..stream_sample_ctx(&entry.sess, fe, be, &ProxiesView(proxies), &StickView::new(proxies, &entry.sess.tracked_sc)) });
    fe.log_count.fetch_add(1, Ordering::Relaxed);
    Some((line, err))
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
        Some((line, err)) => (entry.log_line, entry.log_err) = (Some(line), err),
        None => entry.log_line = None,
    }
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

/// `HAProxy`'s own line for a bad PROXY header (`session_kill_embryonic`): only for a
/// frontend that logs, not in its log-format, and not for the empty cases under `option
/// dontlognull`.
fn proxy_header_error_line(entry: &SessionEntry, proxies: &[Proxy]) -> Option<String> {
    let why = proxy_header_failure(&entry.sess)?;
    let fe = &proxies[entry.proxy_idx];
    if fe.log_format.is_none() || fe.log_target_idx.is_empty() || (fe.dont_log_null && why.is_null()) {
        return None;
    }
    let s = &entry.sess;
    let listener = s.so_name.as_deref().map_or_else(|| s.so_id.unwrap_or(0).to_string(), str::to_string);
    fe.log_count.fetch_add(1, Ordering::Relaxed);
    Some(crate::logfmt::connection_error_line(s.client_addr, s.log.date, &fe.name, &listener, why.message()))
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
    for fe in &config.frontends {
        if fe.disabled {
            continue;
        }
        for bind in fe.binds.iter().filter(|b| b.ssl) {
            bind_tls(&fe.name, &fe.binds, bind.addr)?;
        }
    }
    // A `disabled` listen is checked too: `HAProxy` loads its certificates at parse time.
    for l in &config.listens {
        for bind in l.binds.iter().filter(|b| b.ssl) {
            bind_tls(&l.name, &l.binds, bind.addr)?;
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
) -> io::Result<Option<Arc<rustls::ServerConfig>>> {
    let Some(bind) = binds.iter().find(|b| b.addr == addr && b.ssl) else {
        return Ok(None);
    };

    // Chosen explicitly rather than inferred from crate features. rustls picks a default
    // provider only when exactly one of `ring` and `aws-lc-rs` is enabled, and any
    // dependency anywhere in the graph that turns on the other makes that ambiguous --
    // at which point `ServerConfig::builder()` panics. It panicked here under
    // `cargo test --workspace`, where a dev-dependency pulled the second provider in.
    // Relying on feature arithmetic to decide whether the proxy can start is not a
    // property worth having; this is idempotent and costs one atomic on the first bind.
    ibex_tls::install_default_crypto_provider();
    if bind.crt.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "'{section}': bind {addr} has 'ssl' but no 'crt'; refusing to start \
                 rather than serve cleartext on a port configured for TLS"
            ),
        ));
    }
    let cfg = ibex_tls::TlsConfig::from_bind_config(bind).map_err(|e| {
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
fn initial_status(s: &ibex_config::Server) -> u8 {
    if s.disabled { ServerStatus::Maint as u8 } else { ServerStatus::Up as u8 }
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
    for frontend in config.frontends.iter().filter(|f| !f.disabled) {
        for b in frontend_binds(frontend).iter().filter(|b| b.quic) {
            crate::quic_listener::prebind(b.addr, workers).map_err(|e| {
                // HAProxy's alert (`protocol_bind_all`), without its `[file:line]`.
                let why = e.to_string();
                let why = why.split(" (os error").next().unwrap_or(&why).to_string();
                let proto = if b.addr.is_ipv4() { "quic4" } else { "quic6" };
                io::Error::new(
                    e.kind(),
                    format!("Binding for frontend {}: protocol {proto}: cannot bind socket ({why}) for [{}].", frontend.name, b.addr),
                )
            })?;
        }
    }
    Ok(())
}

fn frontend_binds(frontend: &ibex_config::FrontendSection) -> Vec<ibex_config::ast::BindConfig> {
    let mut all_binds = frontend.binds.clone();
    if let Some(ba) = frontend.bind {
        if !all_binds.iter().any(|b| b.addr == ba) {
            all_binds.insert(0, ibex_config::ast::BindConfig {
                sock: None,
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
    let req_capture_slots = capture_slots(&listen.req_header_captures, &mut http_req_rules);
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
    let mut server_check_configs = Vec::with_capacity(server_count);
    for s in &listen.servers {
        if s.check {
            let mut cfg = ServerCheckConfig::default();
            if let Some(inter) = s.inter {
                cfg.inter = inter;
            }
            cfg.fastinter_ms = s.fastinter_ms();
            cfg.downinter_ms = s.downinter_ms();
            if let Some(fall) = s.fall {
                cfg.fall = fall;
            }
            if let Some(rise) = s.rise {
                cfg.rise = rise;
            }
            if let Some(chk_timeout) = listen.timeouts.check {
                cfg.timeout = chk_timeout;
            } else if let Some(inter) = s.inter {
                cfg.timeout = inter;
            }
            server_check_configs.push(Some(Box::new(cfg)));
        } else {
            server_check_configs.push(None);
        }
    }

    Proxy {
        id: usize_to_u32(proxy_idx),
        ids: Box::new(ProxyIdInfo {
            iid: ids.iid,
            decl: ids.decl,
            forced_id: ids.forced,
            server_puids: server_puids(listen.servers.len(), &listen.server_extras),
            server_forced_ids: server_forced_ids(listen.servers.len(), &listen.server_extras),
            server_init_health: server_init_health(listen.servers.len(), &listen.server_extras),
            server_cmaint: server_cmaint(&listen.servers),
            listener_ids: ibex_config::ast::listener_ids(&listen.binds),
            server_pool: pool_cfgs(&listen.servers),
            http_mode: listen.http_mode,
            persist: listen.persist,
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
        server_statuses: Arc::new(listen.servers.iter().map(|s| AtomicU8::new(initial_status(s))).collect()),
        server_track: None,
        server_weights: listen
            .servers
            .iter()
            .map(|s| s.weight.unwrap_or(1))
            .collect(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new(vec![ProxyStats::default()]),
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
        monitor_uri: listen.monitor_uri.as_deref().map(Into::into),
        acls: compile_acls(&listen.acls),
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
        tcp_req_content_rules: listen.tcp_req_content_rules.clone(),
        tcp_req_inspect_delay: listen.tcp_req_inspect_delay,
        tcp_res_content_rules: listen.tcp_res_content_rules.clone(),
        tcp_res_inspect_delay: listen.tcp_res_inspect_delay,
        http_req_capture_exprs: compile_capture_exprs(&http_req_rules),
        http_req_rules,
        http_res_rules: listen.http_res_rules.clone(),
        http_after_res_rules: listen.http_after_res_rules.clone(),
        http_reuse: listen.http_reuse.unwrap_or_default(),
        error_files: listen.error_files.clone(),
        error_replies: listen.error_replies.clone(),
        log_tag: listen.log_tag.as_deref().map(syslog_tag),
        log_format: compile_log_format(listen.log_format.as_ref(), listen.mode == Mode::Http),
        dont_log_null: listen.dontlognull,
        log_opts: listen.log_opts,
        unique_id_format: listen.unique_id_format.as_deref().and_then(compile_unique_id_format),
        unique_id_header: listen.unique_id_header.clone(),
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
    let req_capture_slots = capture_slots(&fe.req_header_captures, &mut http_req_rules);
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

    Proxy {
        id: usize_to_u32(proxy_idx),
        ids: Box::new(ProxyIdInfo {
            iid: ids.iid,
            decl: ids.decl,
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
        monitor_uri: fe.monitor_uri.as_deref().map(Into::into),
        acls: compile_acls(&fe.acls),
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
        tcp_req_content_rules: fe.tcp_req_content_rules.clone(),
        tcp_req_inspect_delay: fe.tcp_req_inspect_delay,
        tcp_res_content_rules: Vec::new(),
        tcp_res_inspect_delay: None,
        http_req_capture_exprs: compile_capture_exprs(&http_req_rules),
        http_req_rules,
        http_res_rules: fe.http_res_rules.clone(),
        http_after_res_rules: fe.http_after_res_rules.clone(),
        http_reuse: ibex_config::HttpReuse::default(),
        error_files: fe.error_files.clone(),
        error_replies: fe.error_replies.clone(),
        log_tag: fe.log_tag.as_deref().map(syslog_tag),
        log_format: compile_log_format(fe.log_format.as_ref(), fe.mode == Mode::Http),
        dont_log_null: fe.dontlognull,
        log_opts: fe.log_opts,
        unique_id_format: fe.unique_id_format.as_deref().and_then(compile_unique_id_format),
        unique_id_header: fe.unique_id_header.clone(),
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
    let mut server_check_configs = Vec::with_capacity(server_count);
    for s in &be.servers {
        if s.check {
            let mut cfg = ServerCheckConfig::default();
            if let Some(inter) = s.inter {
                cfg.inter = inter;
            }
            cfg.fastinter_ms = s.fastinter_ms();
            cfg.downinter_ms = s.downinter_ms();
            if let Some(fall) = s.fall {
                cfg.fall = fall;
            }
            if let Some(rise) = s.rise {
                cfg.rise = rise;
            }
            if let Some(chk_timeout) = be.timeouts.check {
                cfg.timeout = chk_timeout;
            } else if let Some(inter) = s.inter {
                cfg.timeout = inter;
            }
            server_check_configs.push(Some(Box::new(cfg)));
        } else {
            server_check_configs.push(None);
        }
    }

    Proxy {
        id: usize_to_u32(proxy_idx),
        ids: Box::new(ProxyIdInfo {
            iid: ids.iid,
            decl: ids.decl,
            forced_id: ids.forced,
            server_puids: server_puids(be.servers.len(), &be.server_extras),
            server_forced_ids: server_forced_ids(be.servers.len(), &be.server_extras),
            server_init_health: server_init_health(be.servers.len(), &be.server_extras),
            server_cmaint: server_cmaint(&be.servers),
            listener_ids: Vec::new(),
            server_pool: pool_cfgs(&be.servers),
            http_mode: be.http_mode,
            persist: be.persist,
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
        server_statuses: Arc::new(be.servers.iter().map(|s| AtomicU8::new(initial_status(s))).collect()),
        server_track: None,
        server_weights: be.servers.iter().map(|s| s.weight.unwrap_or(1)).collect(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new(vec![ProxyStats::default()]),
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
        monitor_uri: None,
        acls: compile_acls(&be.acls),
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
        http_req_capture_exprs: compile_capture_exprs(&http_req_rules),
        http_req_rules,
        http_res_rules: be.http_res_rules.clone(),
        http_after_res_rules: be.http_after_res_rules.clone(),
        http_reuse: be.http_reuse.unwrap_or_default(),
        error_files: be.error_files.clone(),
        error_replies: be.error_replies.clone(),
        log_tag: be.log_tag.as_deref().map(syslog_tag),
        log_format: None,
        dont_log_null: false,
        log_opts: 0,
        unique_id_format: be.unique_id_format.as_deref().and_then(compile_unique_id_format),
        unique_id_header: be.unique_id_header.clone(),
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

fn init_checks(proxies: &[Proxy], scheduler: &mut Scheduler, now: Tick) -> Vec<ServerCheckState> {
    let mut checks = Vec::with_capacity(proxies.iter().map(|p| p.server_check_configs.iter().flatten().count()).sum());
    for (proxy_idx, proxy) in proxies.iter().enumerate() {
        for (server_idx, srv_addr) in proxy.servers.iter().enumerate() {
            let Some(check_cfg) = proxy
                .server_check_configs
                .get(server_idx)
                .and_then(|c| c.as_deref().cloned())
            else {
                continue;
            };
            let mut check = ServerCheckState::new(proxy_idx, server_idx, srv_addr, check_cfg, now);
            check.tls = proxy.server_check_tls.get(server_idx).cloned().flatten();
            // A `disabled` server stays in maintenance whatever its checks find.
            if proxy.server_statuses.get(server_idx).is_some_and(|s| s.load(Ordering::Relaxed) == ServerStatus::Maint as u8) {
                check.status = ServerStatus::Maint;
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
        parts.push(format!("proto={}", if sess.cli_xprt.is_tls() { "https" } else { "http" }));
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
    let src = sess.client_addr.map(|a| (a.ip(), if a.port() == 0 { sess.fc_src.map_or(0, |c| c.port()) } else { a.port() }));
    let dst_port = sess.fc_dst.map_or(0, |c| c.port());
    let dst = sess.server_addr.map(|a| a.ip()).or(sess.fc_dst.map(|a| a.ip())).map(|ip| (ip, dst_port));
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
/// own when it has none.
fn append_forwarded_element(sess: &mut TcpSession, element: &str) {
    let existing: Vec<String> = sess
        .htx_slice()
        .map(|s| s.headers().filter(|(n, _)| n.eq_ignore_ascii_case("forwarded")).map(|(_, v)| v.to_string()).collect())
        .unwrap_or_default();
    match existing.as_slice() {
        [] => add_req_header(sess, "forwarded", element),
        [only] => set_req_header(sess, "forwarded", &format!("{only},{element}")),
        many => {
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
            let val = if set_var.is_fmt {
                format_sample_string(&set_var.expr, &sample_ctx, sample_reg)
            } else if let Ok(e) = Expr::cached(&set_var.expr) {
                e.eval_sample(sample_reg, &sample_ctx)
                    .map_or_else(|| set_var.expr.clone(), |smp| sample_to_string(&smp))
            } else {
                set_var.expr.clone()
            };
            set_proc_var(&set_var.name, val);
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
    // Expressions and ACL files compiled for a previous configuration are not reused.
    ibex_sample::expr::new_generation();
    {
        // The clock of `lastchg` and `lastsess` (`show stat`) starts with the proxies.
        let _ = crate::statcnt::now_ms();
        // The listeners the file descriptor budget has to leave room for.
        let stats_sockets = config.global.as_ref().map_or(0, |g| usize::from(g.stats_socket.is_some()) + g.extra_stats_sockets.len());
        let listeners = stats_sockets
            + config.listens.iter().map(|l| l.binds.len()).sum::<usize>()
            + config.frontends.iter().map(|f| frontend_binds(f).len()).sum::<usize>();
        let stats_socket = stats_sockets > 0;
        crate::globalconn::configure(config.global.as_ref().and_then(|g| g.maxconn), listeners, stats_socket);
    }
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
    crate::track::attach(&mut proxies, config);
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
        let poller = Poller::new(capacity)?;
        let mut scheduler = Scheduler::with_capacity(capacity);
        let mut fdtab = FdTab::with_capacity(capacity * 2);
        let sessions = SessionArena::with_capacity(capacity);
        let applets = AppletArena::with_capacity(capacity);

        init_global_vars(config.global.as_ref());
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
        let bufsize = config.global.as_ref().and_then(|g| g.bufsize).unwrap_or(16384);
        let bufsize_small = config.global.as_ref().and_then(|g| g.bufsize_small).unwrap_or(1024);
        let bufsize_large = config.global.as_ref().and_then(|g| g.bufsize_large);
        crate::buf::init_buffer_sizes(bufsize, bufsize_small, bufsize_large);
        if bufsize_large.is_some() {
            crate::buf::preallocate_large_buffers();
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
                let tls = bind_tls(&listen.name, &binds, b.addr)?;
                for mut listener in listeners_for(worker_id, b.addr, usize_to_u32(proxy_idx), b.sock.as_deref().unwrap_or(&ibex_config::ast::SocketTuning::default()))? {
                    listener.luid = proxies[proxy_idx].ids.listener_ids.get(bind_idx).copied().unwrap_or(0);
                    listener.maxconn = proxies[proxy_idx].maxconn.clone();
                    listener.name = b.name.as_deref().map(Into::into);
                    listener.accept_proxy = b.accept_proxy || b.accept_proxy_v2;
                    listener.accept_proxy_v2 = b.accept_proxy_v2;
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
                    let tls = bind_tls(&frontend.name, &frontend.binds, bind_addr)?.expect("QUIC requires TLS");

                    // Each request is handed to this frontend's stream engine (T130). It
                    // used to go straight to the first server of the default backend, and
                    // no rule, `use_backend`, balancing or log line ever saw it.
                    let mut ql = crate::quic_listener::QuicListener::bind_for_worker(bind_addr, &tls, None, Some(worker_id))?;
                    ql.set_frontend(proxy_idx);

                    let l_idx = quic_listeners.len();
                    let lfd = ql.raw_fd();
                    fdtab.insert(
                        lfd,
                        FdState::QuicListener { listener: usize_to_u32(l_idx) },
                        Interest::READ,
                    );
                    poller.add(ql.borrowed_fd(), raw_fd_to_u64(lfd), true, false)?;
                    quic_listeners.push(ql);
                } else {
                    let tls = bind_tls(&frontend.name, &frontend.binds, bind_addr)?;
                    for mut listener in listeners_for(worker_id, bind_addr, usize_to_u32(proxy_idx), b.sock.as_deref().unwrap_or(&ibex_config::ast::SocketTuning::default()))? {
                        listener.luid = proxies[proxy_idx].ids.listener_ids.get(bind_idx).copied().unwrap_or(0);
                        listener.maxconn = proxies[proxy_idx].maxconn.clone();
                        listener.name = b.name.as_deref().map(Into::into);
                    listener.accept_proxy = b.accept_proxy || b.accept_proxy_v2;
                    listener.accept_proxy_v2 = b.accept_proxy_v2;
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
        let now = Tick(1);
        
        let checks = if worker_id == 0 {
            init_checks(&proxies, &mut scheduler, now)
        } else {
            Vec::new()
        };


        // A worker on its own answers itself; `share_mailboxes` joins it to the others.
        let mailboxes = crate::mailbox::Mailboxes::new(1)?;
        let mb_fd = mailboxes.fd(0).as_raw_fd();
        fdtab.insert(mb_fd, FdState::Mailbox, Interest::READ);
        poller.add(mailboxes.fd(0), raw_fd_to_u64(mb_fd), true, false)?;

        Ok(Engine {
            quic_listeners,
            poller,
            scheduler,
            fdtab,
            listeners,
            proxies,
            checks,
            sessions,
            applets,
            cli_listener: None,
            cli_socket_path: None,
            extra_cli: Vec::new(),
            global_paused: false,
            fe_paused: false,
            cli_level: crate::applet::CliLevel::Admin,
            start_time,
            pid: std::process::id(),
            now,
            is_running: true,
            worker_id,
            events: Vec::with_capacity(capacity * 2),
            timer_updates: Vec::with_capacity(capacity * 2),
            log_targets,
            log_tag: syslog_tag(config.global.as_ref().and_then(|g| g.log_tag.as_deref()).unwrap_or("haproxy")).to_string(),
            global_bufsize: bufsize,
            global_maxrewrite: config
                .global
                .as_ref()
                .and_then(|g| g.maxrewrite)
                .unwrap_or(1024),
            global_h2_flood_config: ibex_proto::H2FloodConfig {
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
            },
            idle_backend_pool: IdlePool::default(),
            lifecycle: None,
            stopping: false,
            hard_stop_after: config.global.as_ref().and_then(|g| g.hard_stop_after),
            stop_deadline: None,
            cli_socket_ident: None,
            mailboxes,
            mailbox_wid: 0,
        })
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
        let raw_fd = listener.as_raw_fd();
        self.fdtab
            .insert(raw_fd, FdState::CliListener, Interest::READ);
        self.poller
            .add(listener.as_fd(), raw_fd_to_u64(raw_fd), true, false)?;
        self.cli_listener = Some(listener);
        self.cli_socket_ident = socket_file_ident(&path_buf);
        self.cli_socket_path = Some(path_buf);
        Ok(())
    }

    /// Serves one more CLI socket on `listener`, already bound (see `adopt_cli_listener`).
    ///
    /// # Errors
    /// Returns an error if registering with the poller fails.
    pub fn adopt_extra_cli_listener(&mut self, listener: UnixListener, path_buf: PathBuf, level: crate::applet::CliLevel) -> io::Result<()> {
        let raw_fd = listener.as_raw_fd();
        let idx = u32::try_from(self.extra_cli.len()).unwrap_or(u32::MAX);
        self.fdtab.insert(raw_fd, FdState::CliExtra(idx), Interest::READ);
        self.poller.add(listener.as_fd(), raw_fd_to_u64(raw_fd), true, false)?;
        let ident = socket_file_ident(&path_buf);
        self.extra_cli.push(ExtraCli { listener: Some(listener), path: path_buf, ident, level });
        Ok(())
    }

    /// Sets the level new CLI connections start at (`stats socket ... level`).
    pub fn set_cli_level(&mut self, level: crate::applet::CliLevel) {
        self.cli_level = level;
    }

    /// Makes this engine worker `wid` of `pools`, the idle server connections all workers
    /// share (`tune.idle-pool.shared`). Called before the engine runs: a worker alone keeps
    /// a pool of its own.
    pub fn share_idle_pools(&mut self, pools: &Arc<IdlePools>, wid: usize) {
        self.idle_backend_pool = pools.worker(wid);
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
        Ok(())
    }

    /// Answers what the other workers asked: a snapshot of this worker's streams, a shutdown
    /// of some of them, or the wakeup of a task whose request they all answered.
    fn serve_mailbox(&mut self) {
        let wid = self.mailbox_wid;
        for msg in self.mailboxes.take(wid) {
            match msg {
                crate::mailbox::Msg::ShowSess(g) => g.reply(wid, self.snapshot_streams()),
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
            }
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
            let fe = self.proxies.get(e.proxy_idx);
            let be = self.proxies.get(e.backend_idx).filter(|p| p.has_backend).map(|_| e.backend_idx);
            let srv = e.target_server_idx.filter(|_| e.srv_backend_idx == e.backend_idx);
            // What each side's timer means (`sc_ep_rcv_ex` / `sc_ep_snd_ex`): a receive timer
            // while that side may still send us data, a send timer while ours to it is
            // blocked. An HTTP/1 request in hand is not read from the client any more (the
            // client's timer waits only for a body or, once the response flows, for its
            // reader), and the server is not read while the response backs up or the request
            // has not been sent whole.
            let (cli_rex, cli_wex, srv_rex) = match s.txn.as_ref().filter(|_| http && s.h2_ctx.is_none()) {
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
                uri: s.txn.as_ref().and(s.req_uri.clone()),
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
        let elapsed = self.start_time.elapsed();
        let ms = u32::try_from(elapsed.as_millis() & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        Tick(if ms == 0 { 1 } else { ms })
    }

    /// Formats runtime statistics string.
    #[must_use]
    pub fn format_stats_info(&self) -> String {
        let pid = std::process::id();
        let active_conns: u32 = self.proxies.iter().map(|p| p.stats.iter().map(|s| s.act_conn.load(Ordering::Relaxed)).sum::<u32>()).sum();
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
        let now = self.current_tick();
        self.step(now)
    }

    /// Performs one single iteration of the engine execution pass.
    ///
    /// # Errors
    /// Returns an error if polling epoll fails.
    /// Binds a QUIC listener and registers it with the poller.
    ///
    /// # Errors
    /// Returns an error if the socket cannot be bound or the endpoint cannot be built.
    pub fn add_quic_listener(
        &mut self,
        addr: std::net::SocketAddr,
        tls: &rustls::ServerConfig,
        backend: Option<std::net::SocketAddr>,
    ) -> io::Result<u16> {
        let mut ql = crate::quic_listener::QuicListener::bind(addr, tls, None)?;
        if let Some(be) = backend {
            ql.set_backend(be);
        }
        let port = ql.addr().port();
        let idx = self.quic_listeners.len();
        let fd = ql.raw_fd();
        self.fdtab.insert(
            fd,
            FdState::QuicListener { listener: usize_to_u32(idx) },
            Interest::READ,
        );
        // SAFETY-adjacent: the listener owns the fd for as long as it is in the vector, and
        // it is removed from the poller only when the listener is dropped.
        self.poller.add(ql.borrowed_fd(), raw_fd_to_u64(fd), true, false)?;
        self.quic_listeners.push(ql);
        Ok(port)
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
            for fd in ql.take_released_fds() {
                self.fdtab.remove(fd);
            }
        }
        // Sockets pinned to connections by a soft stop: readable interest only.
        let mut pinned_add: Vec<(usize, RawFd)> = Vec::new();
        for (idx, ql) in self.quic_listeners.iter().enumerate() {
            for b in ql.pinned_borrowed_fds() {
                if matches!(self.fdtab.state(b.as_raw_fd()), FdState::Closed) {
                    pinned_add.push((idx, b.as_raw_fd()));
                }
            }
        }
        for (idx, fd) in pinned_add {
            let Some(ql) = self.quic_listeners.get(idx) else { continue };
            let Some(b) = ql.pinned_borrowed_fds().into_iter().find(|b| b.as_raw_fd() == fd) else { continue };
            self.fdtab.insert(
                fd,
                FdState::QuicBackend { listener: usize_to_u32(idx) },
                Interest::READ,
            );
            let _ = self.poller.add(b, raw_fd_to_u64(fd), true, false);
        }
        // Backend legs and request relays, with the interest each one has now: write only
        // while it has bytes to write. Registering them all for writing made a slow leg
        // wake the loop on every pass until it answered (T108).
        for (idx, ql) in self.quic_listeners.iter().enumerate() {
            for (b, readable, writable) in ql.io_fds() {
                let fd = b.as_raw_fd();
                let want = Interest { readable, writable };
                if matches!(self.fdtab.state(fd), FdState::Closed) {
                    self.fdtab.insert(fd, FdState::QuicBackend { listener: usize_to_u32(idx) }, want);
                    let _ = self.poller.add(b, raw_fd_to_u64(fd), readable, writable);
                } else if self.fdtab.interest(fd) != want {
                    self.fdtab.set_interest(fd, want);
                    let _ = self.poller.modify(b, raw_fd_to_u64(fd), readable, writable);
                }
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
                self.admit_connection(proxy_idx, None, st.fd, st.peer, st.local);
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

    pub fn step(&mut self, now: Tick) -> io::Result<usize> {
        self.now = now;
        self.wake_queued();

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
        let now_inst = Instant::now();
        let poll_timeout = self
            .quic_listeners
            .iter()
            .filter_map(crate::quic_listener::QuicListener::poll_timeout)
            .fold(poll_timeout, |acc, deadline| {
                acc.min(deadline.saturating_duration_since(now_inst))
            });

        // The idle server connections beyond what their servers need are purged every
        // `pool-purge-delay` (`srv_cleanup_idle_conns`): this is where that keyword acts.
        let proxies = &self.proxies;
        self.idle_backend_pool.purge(now_inst, |(be, s)| {
            proxies.get(be).and_then(|p| p.server_actconn.get(s)).map_or(0, |a| a.load(Ordering::Relaxed))
        });
        self.idle_backend_pool.sweep(now_inst);
        let poll_timeout = self
            .idle_backend_pool
            .next_sweep()
            .map_or(poll_timeout, |t| poll_timeout.min(t.saturating_duration_since(now_inst)));
        let poll_timeout = self
            .idle_backend_pool
            .next_purge()
            .map_or(poll_timeout, |t| poll_timeout.min(t.saturating_duration_since(now_inst)));

        if self.global_paused && !crate::globalconn::full() {
            self.resume_listeners_after_global();
        }
        if self.fe_paused && !self.global_paused {
            self.resume_listeners_after_frontend_limit();
        }

        // 3. Poll readiness events
        let mut events = std::mem::take(&mut self.events);
        events.clear();
        self.poller.poll(Some(poll_timeout), |ev| events.push(ev))?;

        // The time now, not the time the pass started: everything below arms its timers from
        // `now`, and a connection accepted or a request read after the poller waited would
        // otherwise have its deadlines early by the time the engine was idle (up to the 100
        // ms poll bound). One clock read per loop pass, as HAProxy's `tv_update_date` after
        // its poller. The timers that expired during the wait are woken by it too.
        let now = self.current_tick();
        self.now = now;
        self.scheduler.set_now(now);
        let _ = self.scheduler.wake_expired_tasks();

        // 4. Process polled readiness events
        let mut quic_ready: Vec<usize> = Vec::new();
        let mut mail = false;
        for &ev in &events {
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
                    self.scheduler
                        .tasklet_wakeup(task, Class::Urgent, state::WOKEN_IO);
                }
                FdState::QuicListener { listener: q_idx }
                | FdState::QuicBackend { listener: q_idx } => {
                    // A QUIC connection is not a descriptor, so there is nothing to accept
                    // and no task to wake: the listener demultiplexes by connection ID.
                    // Both the UDP socket and any backend socket it opened drive the same
                    // listener, which is why they share an arm.
                    quic_ready.push(q_idx as usize);
                }
                FdState::Mailbox => mail = true,
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
        let inst = Instant::now();
        for (idx, ql) in self.quic_listeners.iter_mut().enumerate() {
            let timer_due = ql.poll_timeout().is_some_and(|d| d <= inst);
            if timer_due {
                ql.handle_timeout(inst);
            }
            if timer_due || quic_ready.contains(&idx) {
                let _ = ql.pump(inst);
            }
        }
        self.adopt_quic_streams();
        self.sync_quic_backend_fds();

        // 5. Run runnable tasks through Dispatch
        let pid = self.pid;
        let total_tasks = self.scheduler.live_tasks();
        let run_queue_len = self.scheduler.run_queue_len();

        let mut timer_updates = std::mem::take(&mut self.timer_updates);
        timer_updates.clear();

        let mut dispatcher = EngineDispatcher {
            sessions: &mut self.sessions,
            applets: &mut self.applets,
            proxies: &mut self.proxies,
            checks: &mut self.checks,
            fdtab: &mut self.fdtab,
            poller: &mut self.poller,
            listeners: &mut self.listeners,
            start_time: self.start_time,
            pid,
            total_tasks,
            run_queue_len,
            now,
            timer_updates,
            wake_queue: Vec::new(),
            log_targets: &self.log_targets,
            log_tag: &self.log_tag,
            idle_backend_pool: &mut self.idle_backend_pool,
            mailboxes: &self.mailboxes,
            worker_id: self.mailbox_wid,
        };

        let tasks_run = self.scheduler.process_runnable_tasks(&mut dispatcher);
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
        for task_ref in dispatcher.wake_queue {
            if self.scheduler.is_live(task_ref) {
                self.scheduler
                    .tasklet_wakeup(task_ref, Class::Urgent, state::WOKEN_IO);
            }
        }
        self.timer_updates = dispatcher.timer_updates;
        // Slots this pass freed go to the queue now, not on the next poll's timeout.
        self.wake_queued();
        Ok(tasks_run)
    }

    /// Accepts on the first CLI socket (`which` is `None`) or on the `which`th further one.
    fn accept_from_cli_listener(&mut self, which: Option<usize>) {
        loop {
            let (listener, level, path) = match which {
                None => (self.cli_listener.as_ref(), self.cli_level, self.cli_socket_path.as_ref()),
                // `FdState::CliExtra(i)` is registered by `adopt_extra_cli_listener` with `i` its index.
                Some(i) => (self.extra_cli[i].listener.as_ref(), self.extra_cli[i].level, Some(&self.extra_cli[i].path)),
            };
            let Some(listener) = listener else {
                return;
            };
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    let mut applet = CliApplet::new(stream, self.now);
                    applet.level = level;
                    applet.socket_path = path.map(|p| p.display().to_string());
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
                Err(_) => {
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
            return;
        }

        // The slot of `global maxconn` is taken before accepting, atomically: workers
        // checking `full()` and then counting would overshoot it by up to one each. The
        // connection's slot is then `admit_connection`'s to release if it refuses it.
        // The frontend's `maxconn` slot is taken the same way (`ConnLimit::try_inc`).
        while self.listeners[l_idx].maxconn.try_inc() {
            if !crate::globalconn::try_acquire() {
                self.listeners[l_idx].maxconn.dec();
                break;
            }
            let accept_res = self.listeners[l_idx].accept();
            let Some((cli_fd, peer_addr)) = (match accept_res {
                Ok(Some(pair)) => Some(pair),
                Ok(None) | Err(_) => None,
            }) else {
                crate::globalconn::release();
                self.listeners[l_idx].maxconn.dec();
                break;
            };
            let local_addr = self.listeners[l_idx].addr();
            self.admit_connection(proxy_idx, Some(l_idx), cli_fd, peer_addr, local_addr);
        }
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

    /// Undoes [`Self::pause_listeners_for_global`] for the listeners that have room of
    /// their own.
    fn resume_listeners_after_global(&mut self) {
        self.global_paused = false;
        for l in &self.listeners {
            let lfd = l.raw_fd();
            if !l.is_full() && self.fdtab.interest(lfd).is_none() {
                let _ = self.poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), true, false);
                self.fdtab.set_interest(lfd, Interest::READ);
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
    ) {
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
            for srule in &self.proxies[proxy_idx].stick_rules {
                let slot = match srule.rule_type {
                    ibex_config::StickRuleType::TrackSc0 => Some(0),
                    ibex_config::StickRuleType::TrackSc1 => Some(1),
                    ibex_config::StickRuleType::TrackSc2 => Some(2),
                    _ => None,
                };
                if let Some(slot) = slot {
                    if let Some(key) = resolve_sample_stick_key(&srule.expr, sample_registry(), &sample_ctx, self.proxies[proxy_idx].stick_table.as_ref()) {
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
            for rule in &self.proxies[proxy_idx].tcp_req_conn_rules {
                let matches = match &rule.cond {
                    None => true,
                    Some(cond) => crate::proxy::eval_acl_condition(
                        cond,
                        &self.proxies[proxy_idx].acls,
                        sample_registry(),
                        &sample_ctx,
                    ),
                };
                if !matches {
                    continue;
                }
                match &rule.action {
                    ibex_config::TcpReqConnAction::TrackSc0 { table, expr } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_sample_stick_key(expr, sample_registry(), &sample_ctx, self.proxies[t_idx].stick_table.as_ref()) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                if tracked_sc[0].is_none() {
                                    let _ = tbl.update_entry(&key, |data| data.track(true));
                                    tracked_sc[0] = Some((t_idx, key));
                                }
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc1 { table, expr } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_sample_stick_key(expr, sample_registry(), &sample_ctx, self.proxies[t_idx].stick_table.as_ref()) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                if tracked_sc[1].is_none() {
                                    let _ = tbl.update_entry(&key, |data| data.track(true));
                                    tracked_sc[1] = Some((t_idx, key));
                                }
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc2 { table, expr } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_sample_stick_key(expr, sample_registry(), &sample_ctx, self.proxies[t_idx].stick_table.as_ref()) {
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
                ConnEvalOutcome::SilentDrop => {
                    raw::silent_drop(cli_fd.as_fd(), peer_addr.is_ipv6());
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
            proxy.counters().cum_conn.fetch_add(1, Ordering::Relaxed);
            proxy.counters().fe_sess_rate.tick();
            let rate = proxy.counters().fe_sess_rate.rate();
            proxy.txn_counters().fe.rate_max.fetch_max(u32::try_from(rate).unwrap_or(u32::MAX), Ordering::Relaxed);
            proxy.counters().act_conn.fetch_add(1, Ordering::Relaxed);
            // From the accept loop the slot is already taken (`try_acquire`); an HTTP/3
            // request stream arrives without one.
            if l_idx.is_none() {
                crate::globalconn::acquire();
            }
            if proxy.counters().act_conn.load(Ordering::Relaxed) > proxy.counters().max_conn.load(Ordering::Relaxed) {
                proxy.counters().max_conn.store(proxy.counters().act_conn.load(Ordering::Relaxed), Ordering::Relaxed);
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
            if self.stopping {
                if quiet {
                    self.close_idle_http_sessions();
                }
                if self.sessions.live() == 0 && !self.quic_listeners.iter().any(crate::quic_listener::QuicListener::is_busy) {
                    break;
                }
                if self.stop_deadline.is_some_and(|d| Instant::now() >= d) {
                    self.linger_close_sessions();
                    break;
                }
            }
            let now = self.current_tick();
            let ran = self.step(now)?;
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
        for ql in &mut self.quic_listeners {
            ql.begin_soft_stop();
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
                }
                // And so does every transaction it starts from here on: a request read
                // after the stop is answered with `Connection: close`, as HAProxy switches
                // a keep-alive stream to close mode once its frontend is stopping
                // (`src/mux_h1.c`, `h1_set_cli_conn_mode`). Without it the client is told
                // to reuse a connection the next loop closes under it (T166).
                e.sess.close_client = true;
                if let Some(ref mut h2_ctx) = e.sess.h2_ctx {
                    h2_ctx.send_graceful_goaway();
                    // Wake up the task so the mux can flush the frame.
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
            raw::shutdown_write(e.sess.cli.as_fd());
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
                for fd in std::iter::once(e.sess.cli.as_fd()).chain(e.sess.srv.as_ref().map(|s| s.as_fd())) {
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
                && matches!(e.sess.cli_state, ScState::Established | ScState::Ready);
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
        for task in wake {
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
fn eval_port_expr(expr: &str, registry: &Registry, ctx: &SampleContext<'_>) -> Option<u16> {
    let smp = Expr::cached(expr).ok()?.eval_sample(registry, ctx)?;
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
    SilentDrop,
}

#[derive(Debug, PartialEq, Eq)]
enum SessionEvalOutcome {
    Accept,
    Reject,
    SilentDrop,
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
        SessionEvalOutcome::Reject => raw::abort_with_rst(sess.cli.as_fd()),
        SessionEvalOutcome::SilentDrop => {
            let is_ipv6 = sess.fc_src.or(sess.client_addr).is_some_and(|a| a.is_ipv6());
            raw::silent_drop(sess.cli.as_fd(), is_ipv6);
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

    for rule in &proxy.tcp_req_conn_rules {
        let matches = match &rule.cond {
            None => true,
            Some(cond) => crate::proxy::eval_acl_condition(
                cond,
                &proxy.acls,
                registry,
                &ctx,
            ),
        };
        if !matches {
            continue;
        }
        match &rule.action {
            ibex_config::TcpReqConnAction::SilentDrop => {
                return ConnEvalOutcome::SilentDrop;
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
            ibex_config::TcpReqConnAction::SetSrcPort { expr } => {
                if let Some(port) = eval_port_expr(expr, registry, &ctx) {
                    client_addr = with_port(Some(client_addr), port);
                    fc_src = client_addr;
                    ctx.client_addr = Some(client_addr);
                    ctx.fc_src = Some(fc_src);
                }
            }
            ibex_config::TcpReqConnAction::SetDstPort { expr } => {
                if let Some(port) = eval_port_expr(expr, registry, &ctx) {
                    server_addr = with_port(Some(server_addr), port);
                    fc_dst = server_addr;
                    ctx.server_addr = Some(server_addr);
                    ctx.fc_dst = Some(fc_dst);
                }
            }
            ibex_config::TcpReqConnAction::SetSrc { expr } => {
                let val = if let Ok(e) = Expr::cached(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
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
            ibex_config::TcpReqConnAction::SetDst { expr } => {
                let val = if let Ok(e) = Expr::cached(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
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
        fc_src: sess.fc_src,
        so_name: sess.so_name.as_deref(),
        so_id: sess.so_id,
        fe_id: Some(proxy.ids.iid),
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: sess.cli_xprt.ssl_facts(),
        ssl_bc: sess.srv_xprt.ssl_facts(),
        act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        accept_date: Some(sess.log.date),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };

    for rule in &proxy.tcp_req_session_rules {
        let matches = match &rule.cond {
            None => true,
            Some(cond) => crate::proxy::eval_acl_condition(
                cond,
                &proxy.acls,
                registry,
                &ctx,
            ),
        };
        if !matches {
            continue;
        }
        match &rule.action {
            ibex_config::TcpReqSessionAction::SilentDrop => {
                return SessionEvalOutcome::SilentDrop;
            }
            ibex_config::TcpReqSessionAction::Reject => {
                return SessionEvalOutcome::Reject;
            }
            ibex_config::TcpReqSessionAction::Accept => {
                break;
            }
            ibex_config::TcpReqSessionAction::TrackSc0 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
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
            ibex_config::TcpReqSessionAction::TrackSc1 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
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
            ibex_config::TcpReqSessionAction::TrackSc2 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
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
            ibex_config::TcpReqSessionAction::SetSrc { expr } => {
                let val = if let Ok(e) = Expr::cached(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
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
            ibex_config::TcpReqSessionAction::SetDst { expr } => {
                let val = if let Ok(e) = Expr::cached(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
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
            ibex_config::TcpReqSessionAction::SetSrcPort { expr } => {
                if let Some(port) = eval_port_expr(expr, registry, &ctx) {
                    let new_addr = with_port(sess.client_addr, port);
                    sess.client_addr = Some(new_addr);
                    ctx.client_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqSessionAction::SetDstPort { expr } => {
                if let Some(port) = eval_port_expr(expr, registry, &ctx) {
                    let new_addr = with_port(sess.server_addr, port);
                    sess.server_addr = Some(new_addr);
                    ctx.server_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqSessionAction::SetVar { var_name, expr } => {
                // A sample that cannot be fetched sets nothing (`action_store`, src/vars.c).
                // The expression is a sample fetch, checked at load; one that cannot be parsed or
                // fetched sets nothing.
                let val = Expr::cached(expr).ok().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| (sample_is_empty(&smp), sample_to_string(&smp)));
                if let Some((empty, val)) = val {
                    store_var_smp(&mut sess.sess_vars, &mut sess.req_vars, var_name, val, empty);
                }
            }
            ibex_config::TcpReqSessionAction::SetVarFmt { var_name, fmt } => {
                let val = format_sample_string(fmt, &ctx, registry);
                store_var(&mut sess.sess_vars, &mut sess.req_vars, var_name, val);
            }
            ibex_config::TcpReqSessionAction::UnsetVar { var_name } => {
                unset_var(&mut sess.sess_vars, &mut sess.req_vars, var_name);
            }
            ibex_config::TcpReqSessionAction::ScIncGpc0 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::Inc),
            ibex_config::TcpReqSessionAction::ScIncGpc1 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::One, GpcOp::Inc),
            ibex_config::TcpReqSessionAction::ScSetGpt0 { sc, expr } => {
                let val = resolve_gpt0_val(expr, registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::SetTag(val));
            }
            ibex_config::TcpReqSessionAction::ScIncGpc { idx, sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Inc),
            ibex_config::TcpReqSessionAction::ScAddGpc { idx, sc, expr } => {
                let n = resolve_gpt0_val(expr, registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Add(u64::from(n)));
            }
            ibex_config::TcpReqSessionAction::ScSetGpt { idx, sc, expr } => {
                let val = resolve_gpt0_val(expr, registry, &ctx);
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
    SilentDrop,
}

#[allow(clippy::too_many_lines)]
fn eval_tcp_req_content_rules(
    proxy: &Proxy,
    proxies: &[Proxy],
    registry: &Registry,
    sess: &mut TcpSession,
    now: Tick,
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
        fc_src: sess.fc_src,
        so_name: sess.so_name.as_deref(),
        so_id: sess.so_id,
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: sess.cli_xprt.ssl_facts(),
        ssl_bc: sess.srv_xprt.ssl_facts(),
        req_body: if has_content { Some(req_bytes) } else { None },
        raw_req: (sess.mode == Mode::Tcp).then_some(req_bytes),
        // In HTTP mode the request is parsed by the time these rules run, and `path`,
        // `hdr()` and the like read it, as they do in `HAProxy`. Built from the fields: the
        // rules change `sess_vars` while this borrows.
        htx_slice: sess.has_htx.then(|| ibex_proto::htx::HtxSliceRef::new(sess.htx_buf.raw_slice(), sess.htx_blocks)),
        req_uri: sess.req_uri.as_deref(),
        req_method: sess.req_method.as_deref(),
        req_headers: sess.req_headers.as_deref(),
        act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        accept_date: Some(sess.log.date),
        last_rule: last_rule_at(sess.log.last_rule),
        prio: (sess.log.prio_class, sess.log.prio_offset),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };

    let mut has_missing_data = false;
    for rule in &proxy.tcp_req_content_rules {
        let cond_res = match &rule.cond {
            None => crate::proxy::AclEvalResult::Matched,
            Some(cond) => crate::proxy::eval_acl_condition_extended(
                cond,
                &proxy.acls,
                registry,
                &ctx,
                req_bytes,
                can_wait,
            ),
        };
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
                return ContentEvalResult::SilentDrop;
            }
            ibex_config::TcpReqContentAction::Reject => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::Reject;
            }
            ibex_config::TcpReqContentAction::Accept => {
                note_last_rule(sess, rule.line);
                return ContentEvalResult::Done;
            }
            ibex_config::TcpReqContentAction::TrackSc0 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
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
            ibex_config::TcpReqContentAction::TrackSc1 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
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
            ibex_config::TcpReqContentAction::TrackSc2 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
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
            ibex_config::TcpReqContentAction::SetSrc { expr } => {
                let val = if let Ok(e) = Expr::cached(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
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
            ibex_config::TcpReqContentAction::SetDst { expr } => {
                let val = if let Ok(e) = Expr::cached(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
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
            ibex_config::TcpReqContentAction::SetSrcPort { expr } => {
                if let Some(port) = eval_port_expr(expr, registry, &ctx) {
                    let new_addr = with_port(sess.client_addr, port);
                    sess.client_addr = Some(new_addr);
                    ctx.client_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqContentAction::SetDstPort { expr } => {
                if let Some(port) = eval_port_expr(expr, registry, &ctx) {
                    let new_addr = with_port(sess.server_addr, port);
                    sess.server_addr = Some(new_addr);
                    ctx.server_addr = Some(new_addr);
                }
            }
            ibex_config::TcpReqContentAction::SetVar { var_name, expr } => {
                // A sample that cannot be fetched sets nothing (`action_store`, src/vars.c).
                // The expression is a sample fetch, checked at load; one that cannot be parsed or
                // fetched sets nothing.
                let val = Expr::cached(expr).ok().and_then(|e| e.eval_sample(registry, &ctx)).map(|smp| (sample_is_empty(&smp), sample_to_string(&smp)));
                if let Some((empty, val)) = val {
                    store_var_smp(&mut sess.sess_vars, &mut sess.req_vars, var_name, val, empty);
                }
            }
            ibex_config::TcpReqContentAction::SetVarFmt { var_name, fmt } => {
                let val = format_sample_string(fmt, &ctx, registry);
                store_var(&mut sess.sess_vars, &mut sess.req_vars, var_name, val);
            }
            ibex_config::TcpReqContentAction::UnsetVar { var_name } => {
                unset_var(&mut sess.sess_vars, &mut sess.req_vars, var_name);
            }
            ibex_config::TcpReqContentAction::ScIncGpc0 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::Inc),
            ibex_config::TcpReqContentAction::ScIncGpc1 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::One, GpcOp::Inc),
            ibex_config::TcpReqContentAction::ScSetGpt0 { sc, expr } => {
                let val = resolve_gpt0_val(expr, registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::SetTag(val));
            }
            ibex_config::TcpReqContentAction::ScIncGpc { idx, sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Inc),
            ibex_config::TcpReqContentAction::ScAddGpc { idx, sc, expr } => {
                let n = resolve_gpt0_val(expr, registry, &ctx);
                sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Add(u64::from(n)));
            }
            ibex_config::TcpReqContentAction::ScSetGpt { idx, sc, expr } => {
                let val = resolve_gpt0_val(expr, registry, &ctx);
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
        fc_src: sess.fc_src,
        so_name: sess.so_name.as_deref(),
        so_id: sess.so_id,
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        ssl_fc: sess.cli_xprt.ssl_facts(),
        ssl_bc: sess.srv_xprt.ssl_facts(),
        res_body: Some(rep_bytes),
        raw_res: Some(rep_bytes),
        act_conn: proxy.counters().act_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        accept_date: Some(sess.log.date),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };
    for rule in &proxy.tcp_res_content_rules {
        if let Some(cond) = &rule.cond {
            // `acl_exec_cond`: a sample that may change and does not match is a miss.
            let res = crate::proxy::combine_condition(cond, |term| {
                let parsed = if proxy.acls.contains_key(&term.name) { None } else { Expr::cached(&term.name).ok() };
                let Some(expr) = proxy.acls.get(&term.name).or(parsed.as_deref()) else { return crate::proxy::AclEvalResult::NotMatched };
                if expr.fetch_name == "wait_end" && !final_ {
                    return crate::proxy::AclEvalResult::MissingData;
                }
                let matched = expr.eval(registry, &ctx);
                if !matched && !final_ && res_sample_may_change(expr, rep_bytes) {
                    crate::proxy::AclEvalResult::MissingData
                } else if matched != term.negated {
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
                return ContentEvalResult::SilentDrop;
            }
            ibex_config::TcpResAction::SetVar { var_name, expr } => {
                set_var_from_expr(&mut sess.sess_vars, &mut sess.req_vars, var_name, expr, &ctx, registry);
            }
            ibex_config::TcpResAction::SetVarFmt { var_name, fmt } => {
                store_var(&mut sess.sess_vars, &mut sess.req_vars, var_name, format_sample_string(fmt, &ctx, registry));
            }
            ibex_config::TcpResAction::UnsetVar { var_name } => unset_var(&mut sess.sess_vars, &mut sess.req_vars, var_name),
        }
    }
    ContentEvalResult::Done
}

/// `set-var(<name>) <expr>`: `action_store` (src/vars.c) -- a sample that cannot be
/// fetched sets nothing.
fn set_var_from_expr(
    sess_vars: &mut HashMap<String, String>,
    req_vars: &mut HashMap<String, String>,
    name: &str,
    expr: &str,
    ctx: &SampleContext,
    registry: &Registry,
) {
    if let Some(val) = Expr::cached(expr).ok().and_then(|e| e.eval_sample(registry, ctx)) {
        store_var_smp(sess_vars, req_vars, name, sample_to_string(&val), sample_is_empty(&val));
    }
}

/// `unset-var(<name>)`, from the scope it lives in.
fn unset_var(sess_vars: &mut HashMap<String, String>, req_vars: &mut HashMap<String, String>, name: &str) {
    if name.starts_with("proc.") {
        ibex_sample::unset_proc_var(name);
        return;
    }
    if name.starts_with("sess.") {
        sess_vars.remove(name);
    } else {
        req_vars.remove(name);
    }
    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().remove(name));
}

/// Whether a sample is empty for `ifempty`/`ifnotempty` (`var_set`, src/vars.c): only a
/// string or a binary of no bytes is; an integer, a boolean or an address never is.
fn sample_is_empty(smp: &Sample) -> bool {
    match smp {
        Sample::Str(s) => s.is_empty(),
        Sample::Bin(b) => b.is_empty(),
        _ => false,
    }
}

/// Stores a variable where its scope lives, and where the rules after it read it.
fn store_var(sess_vars: &mut HashMap<String, String>, req_vars: &mut HashMap<String, String>, name: &str, val: String) {
    let empty = val.is_empty();
    store_var_smp(sess_vars, req_vars, name, val, empty);
}

/// `name[,<cond>...]` of `set-var(...)`: the variable is set only when every condition holds
/// (`var_set`, src/vars.c). `ifexists`/`ifset` and their negations look at the variable
/// (a process variable always exists, as the configuration declares it, but is set only
/// once it has a value), `ifempty`/`ifnotempty` at the new sample. The parser refuses
/// `ifgt` and `iflt` (see `check_set_var_conds`).
fn store_var_smp(
    sess_vars: &mut HashMap<String, String>,
    req_vars: &mut HashMap<String, String>,
    spec: &str,
    val: String,
    empty: bool,
) {
    let name = spec.split(',').next().unwrap_or("");
    let is_proc = name.starts_with("proc.");
    let is_set = if is_proc {
        ibex_sample::get_proc_var(name).is_some()
    } else if name.starts_with("sess.") {
        sess_vars.contains_key(name)
    } else {
        req_vars.contains_key(name)
    };
    let exists = is_proc || is_set;
    let ok = ibex_sample::var_conds_hold(spec, exists, is_set, empty);
    if !ok {
        return;
    }
    if is_proc {
        ibex_sample::set_proc_var(name, val);
        return;
    }
    let map = if name.starts_with("sess.") { sess_vars } else { req_vars };
    map.insert(name.to_string(), val.clone());
    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(name.to_string(), val));
}

/// Runs `f` with `sess`'s variables in the thread's `CURRENT_VARS`, where the fetches and
/// converters read them, and puts them back in the session after (T152).
///
/// `CURRENT_VARS` is one map per thread, and every stream on the thread runs through it in
/// turn: a stream that waits (for its server, its body, a tarpit) leaves the thread to the
/// others, so the map holds a stream's variables only while that stream runs. It is filled
/// here, for the length of one run and never across a wait, and emptied after, so a
/// stream reads its own variables or none -- never those of the stream that ran last.
///
/// The variables are moved, not copied: the session's maps are empty while `f` runs and
/// the thread's map is the one every write lands in (`store_var` writes both; the
/// `set-var` converter, which has no session, writes only it). What it holds after `f` is
/// what the session keeps. No allocation, whatever the number of variables.
fn with_stream_vars<R>(sess: &mut TcpSession, f: impl FnOnce(&mut TcpSession) -> R) -> R {
    stream_vars_enter(sess);
    let out = f(sess);
    stream_vars_leave(Some(sess));
    out
}

/// The start of [`with_stream_vars`].
fn stream_vars_enter(sess: &mut TcpSession) {
    CURRENT_VARS.with(|v| {
        let mut map = v.borrow_mut();
        map.clear();
        map.extend(sess.sess_vars.drain());
        map.extend(sess.req_vars.drain());
    });
}

/// The end of [`with_stream_vars`]: what the thread's map holds goes back to the scope it
/// belongs to in `sess`, or is dropped with a stream that is gone.
fn stream_vars_leave(sess: Option<&mut TcpSession>) {
    CURRENT_VARS.with(|v| {
        let mut map = v.borrow_mut();
        let Some(sess) = sess else {
            map.clear();
            return;
        };
        sess.sess_vars.clear();
        sess.req_vars.clear();
        for (k, val) in map.drain() {
            let scope = if k.starts_with("sess.") { &mut sess.sess_vars } else { &mut sess.req_vars };
            scope.insert(k, val);
        }
    });
}

/// The timeouts the `*_timeout` fetches report for a stream of frontend `fe` on backend
/// `be` (the frontend until one is chosen), with what its `set-timeout` rules set (T156).
///
/// `cur_*` is the backend's timeout, the client's the frontend's, unless a rule set it,
/// as `smp_fetch_cur_*_timeout` (src/stream.c) read the stream's own timers.
fn stream_timeouts(fe: &Proxy, be: &Proxy, set: Option<&crate::proxy::TimeoutsSet>) -> ibex_sample::StreamTimeouts {
    let ms = |p: &Proxy| {
        let t = &p.stats_config.raw_timeouts;
        [t.client, t.server, t.connect, t.queue, t.tunnel, t.tarpit].map(|v| v.map_or(0, millis_to_u32))
    };
    let fe_ms = ms(fe);
    let mut be_ms = ms(be);
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
) {
    // Cloned out before `proxies` is borrowed mutably. TLS belongs to the bind that
    // accepted, not to the proxy, so it is read from the listener.
    let tls = listener_idx
        .and_then(|i| engine.listeners.get(i))
        .and_then(|l| l.tls.clone());
    let cli_raw_fd = cli_fd.as_raw_fd();
    let Some((mut sess, target_addr, srv_raw_fd)) = init_client_session(
        &mut engine.proxies,
        proxy_idx,
        cli_fd,
        engine.now,
        peer_addr,
        client_addr,
        server_addr,
        fc_src,
        fc_dst,
        tls.as_ref(),
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
    sess.h3 = listener_idx.is_none();
    sess.so_name = listener_idx.and_then(|i| engine.listeners.get(i)).and_then(|l| l.name.clone());
    sess.so_id = listener_idx.and_then(|i| engine.listeners.get(i)).map(|l| l.luid).filter(|&id| id != 0);

    let proxy = &engine.proxies[proxy_idx];

    let target_server_idx = target_addr.and_then(|t| proxy.servers.iter().position(|s| s == t));
    if let Some(idx) = target_server_idx {
        if idx < proxy.server_actconn.len() {
            proxy.server_actconn[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    let (cli_want, srv_want) = sess.interests();
    let cli_interest = Interest {
        readable: cli_want.read,
        writable: cli_want.write,
    };

    let Some(session_idx) = engine.sessions.alloc(SessionEntry {
        sess,
        task: TaskRef::NONE,
        proxy_idx,
        backend_idx: proxy_idx,
        srv_backend_idx: proxy_idx,
        target_server_idx,
        target_addr,
        cli_raw_fd,
        srv_raw_fd,
        cli_interest,
        srv_interest: Interest::NONE,
        actconn_reclaimed: false,
        stats_done: false,
        connect_log_due: proxy.log_format.is_none() && !proxy.log_target_idx.is_empty(),
        srv_served: 0,
        log_line: None,
        log_err: false,
    }) else {
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
        let _ = engine.poller.add(
            entry.sess.cli.as_fd(),
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
fn connect_addr(server: SocketAddr, dst: Option<SocketAddr>) -> SocketAddr {
    let Some(dst) = dst else { return server };
    let ip = if server.ip().is_unspecified() { dst.ip() } else { server.ip() };
    let port = if server.port() == 0 { dst.port() } else { server.port() };
    SocketAddr::new(ip, port)
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
    cli_fd: std::os::fd::OwnedFd,
    now: Tick,
    peer_addr: SocketAddr,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    fc_src: SocketAddr,
    fc_dst: SocketAddr,
    tls: Option<&Arc<rustls::ServerConfig>>,
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

    let mut sess = TcpSession::new_with_mode(
        cli_fd,
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
        .unwrap_or(global_maxrewrite);

    if let Some(cfg) = tls {
        // The connection is dropped rather than continued in the clear. Falling back to
        // plaintext here would hand an unencrypted session to a client that opened :443
        // expecting TLS -- the same downgrade `bind_tls` refuses to start with, arriving
        // one connection at a time instead of all at once. Closing is visible; serving
        // cleartext is not.
        match crate::xprt::accept_tls(&sess.cli, Arc::clone(cfg)) {
            Ok(xprt) => sess.cli_xprt = xprt,
            Err(e) => {
                eprintln!(
                    "[ibex] {}: dropping connection from {peer_addr}, TLS setup failed: {e}",
                    proxies[proxy_idx].name
                );
                return None;
            }
        }
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
        let out = with_stream_vars(&mut sess, |sess| eval_tcp_req_session_rules(&proxies[proxy_idx], proxies, registry, sess));
        CURRENT_TIMEOUTS.set(None);
        out
    };
    match session_rules {
        SessionEvalOutcome::Accept => {}
        SessionEvalOutcome::Reject => {
            raw::abort_with_rst(sess.cli.as_fd());
            proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SessionEvalOutcome::SilentDrop => {
            let is_ipv6 = peer_addr.is_ipv6();
            raw::silent_drop(sess.cli.as_fd(), is_ipv6);
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
        target_addr = match use_server {
            Some(i) => Some(proxy.servers.at(i)),
            None => proxy.select_server_with_key(sess.client_addr.map(|a| a.ip()), sess.req_uri.as_deref()),
        };
        if let Some(target) = target_addr {
            let proxies: &[Proxy] = proxies;
            let proxy = &proxies[proxy_idx];
            maybe_prepend_send_proxy(proxy, proxy, proxies, &mut sess, target);
            arm_res_inspect(proxy, &mut sess);
            sess.set_backend_timeouts(proxy);

            if let Ok((srv_fd, immediate)) = raw::connect_opts(connect_addr(target, sess.server_addr), proxy.server_tfo_of(target)) {
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
    raw::shutdown_both(entry.sess.cli.as_fd());
    if let Some(ref srv) = entry.sess.srv {
        raw::shutdown_both(srv.as_fd());
    }
    if !entry.actconn_reclaimed {
        entry.actconn_reclaimed = true;
        let proxy_idx = entry.proxy_idx;
        if proxy_idx < proxies.len() {
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
    if let Some(check) = checks
        .iter_mut()
        .find(|c| c.proxy_idx == proxy_idx && c.server_idx == server_idx)
    {
        check.enabled = enabled;
        if enabled {
            check.next_check = now;
        }
        true
    } else {
        false
    }
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

/// Internal dispatcher executing scheduler tasks against runtime sessions and health checks.
struct EngineDispatcher<'a> {
    sessions: &'a mut SessionArena,
    applets: &'a mut AppletArena,
    proxies: &'a mut Proxies,
    checks: &'a mut [ServerCheckState],
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
    /// Shared read-only: the sockets live on the `Engine`, proxies index into this.
    log_targets: &'a [SyslogTarget],
    log_tag: &'a str,
    idle_backend_pool: &'a mut IdlePool,
    mailboxes: &'a Arc<crate::mailbox::Mailboxes>,
    worker_id: usize,
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
    {
        let head = crate::proxy::find_eoh(&page).map_or(0, |(h, _)| h);
        let mut at = page[..head].iter().position(|&b| b == b'\n').map_or(head, |i| i + 1);
        while at < head {
            let end = page[at..head].iter().position(|&b| b == b'\n').map_or(head, |i| at + i + 1);
            let colon = page[at..end].iter().position(|&b| b == b':').map_or(at, |i| at + i);
            page[at..colon].make_ascii_lowercase();
            at = end;
        }
    }
    // HAProxy's 431 does not say `Connection: close`, though it closes.
    entry.sess.write_reply_with(&page, status != 431);
    // The request that could not be parsed counts as a request and as the error or failure its
    // status is (measured: `http_req_cnt=1 http_err_cnt=1` for a 400).
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
    if let Some(srv_fd) = entry.sess.srv.take() {
        let _ = poller.delete(srv_fd.as_fd());
        if let Some(sfd) = entry.srv_raw_fd.take() {
            fdtab.remove(sfd);
        }
        let reusable = reusable
            && matches!(entry.sess.srv_state, ScState::Ready | ScState::Established)
            // A connection that opened with a PROXY header speaks for this client only.
            && !entry.sess.send_proxy_prepended
            // A TLS session goes to the pool with its socket, once it is established.
            && entry.sess.srv_xprt.is_ready()
            && proxies
                .get(entry.srv_backend_idx)
                .is_some_and(|p| p.http_reuse != ibex_config::HttpReuse::Never);
        // Whether the server has closed it since is checked when it is taken
        // (`WorkerPool::take`): not here as well, a syscall on every response.
        // The pool is keyed by server; a server that maps the destination may have been
        // connected anywhere, so its connections are not pooled.
        let xprt = std::mem::replace(&mut entry.sess.srv_xprt, crate::xprt::ServerXprt::Plain);
        // Only a server's connections are pooled (`srv_add_to_idle_list` needs one).
        let key = entry
            .target_addr
            .filter(|&a| reusable && !maps_destination(a))
            .and_then(|addr| idle_key(addr, entry.srv_backend_idx, entry.target_server_idx, xprt.sni().map(str::to_string)));
        if let (Some(key), Some(be)) = (key, proxies.get(entry.srv_backend_idx)) {
            let cfg = be.ids.server_pool(key.srv.1);
            let used = be.server_actconn.get(key.srv.1).map_or(0, |a| a.load(Ordering::Relaxed)) + u32::from(parked);
            if let Err(conn) = idle_pool.keep(key, IdleConn { fd: srv_fd, xprt }, entry.srv_served >= 2, cfg, used, Instant::now()) {
                conn.close();
            }
        } else {
            let mut xprt = xprt;
            xprt.send_close_notify(srv_fd.as_fd());
        }
    }
    entry.srv_raw_fd = None;
    entry.sess.srv_park_exp = Tick::ETERNITY;
    entry.sess.srv_xprt = crate::xprt::ServerXprt::Plain;
    if let Some(s_idx) = entry.target_server_idx.take() {
        let be = entry.srv_backend_idx;
        if !entry.actconn_reclaimed && !parked && be < proxies.len() && s_idx < proxies[be].server_actconn.len() {
            proxies[be].server_actconn[s_idx].fetch_sub(1, Ordering::Relaxed);
        }
    }
    entry.target_addr = None;
    entry.srv_served = 0;
    entry.sess.srv_state = ScState::Init;
    // The next server connection is a new one and gets its own PROXY header.
    if entry.sess.mode == Mode::Http {
        entry.sess.send_proxy_prepended = false;
    }
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
        raw::shutdown_write(entry.sess.cli.as_fd());
    }
    entry.sess.txn = None;
    entry.sess.cli_state = ScState::Closed;
    entry.sess.srv_state = ScState::Closed;
    entry.sess.ending.get_or_insert(crate::proxy::Ending::Complete);
}

/// `srv_inc_sess_ctr`: a stream was assigned to the server at `addr` of backend `be_idx`,
/// whether it then reuses a connection to it or opens one (`srv_sess_rate`).
fn count_server_session(proxies: &[Proxy], be_idx: usize, addr: SocketAddr) {
    let px = &proxies[be_idx];
    px.servers
        .iter()
        .position(|s| s == addr)
        .and_then(|idx| px.server_sess_rates.get(idx))
        .inspect(|rate| rate.tick());
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
    if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.take(), entry.srv_raw_fd.take()) {
        let _ = poller.delete(srv_fd.as_fd());
        fdtab.remove(sfd);
    }

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
    entry.sess.log.redispatched |= redispatch;
    if redispatch {
        entry.sess.redispatched = true;
    }
    let target = if resuming {
        entry.target_addr
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
            .target_addr
            .or_else(|| proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref()))
    };
    // A different server is a redispatch (`wredis`), the same one a retry (`wretr`); the
    // client's persistence cookie no longer holds (`SF_DIRECT` cleared, `TX_CK_DOWN`).
    let moved = target.is_some() && entry.target_addr.is_some() && target != entry.target_addr;
    let stats = &proxies[be_idx].counters();
    let count_on_server = |redispatch: bool| {
        let mut m = proxies[be_idx].server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        old_idx.into_iter().for_each(|i| {
            let c = m.entry(i).or_default();
            c.0 += u64::from(!redispatch);
            c.1 += u64::from(redispatch);
        });
    };
    if !resuming && moved {
        count_on_server(true);
        stats.redispatches.fetch_add(1, Ordering::Relaxed);
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
    if wait && !resuming && entry.target_addr == Some(target_addr) {
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

    maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

    entry.target_addr = Some(target_addr);
    if let Ok((srv_fd, immediate)) = raw::connect_opts(connect_addr(target_addr, entry.sess.server_addr), proxies[be_idx].server_tfo_of(target_addr)) {
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
                    server_connect_failed(entry, proxies, fdtab, poller, now, true);
                }
            }
        }
    }
}

fn update_interests(entry: &mut SessionEntry, fdtab: &mut FdTab, poller: &mut Poller) {
    let (cli_want, srv_want) = entry.sess.interests();
    let new_cli_interest = Interest {
        readable: cli_want.read,
        writable: cli_want.write,
    };
    if new_cli_interest != entry.cli_interest {
        let _ = poller.modify(
            entry.sess.cli.as_fd(),
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
    let _ = poller.delete(entry.sess.cli.as_fd());
    fdtab.remove(entry.cli_raw_fd);

    if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.as_ref(), entry.srv_raw_fd) {
        let _ = poller.delete(srv_fd.as_fd());
        fdtab.remove(sfd);
    }

    let proxy_idx = entry.proxy_idx;
    proxies[proxy_idx].counters().bytes_in.fetch_add(entry.sess.bytes_in, Ordering::Relaxed);
    proxies[proxy_idx].counters().bytes_out.fetch_add(entry.sess.bytes_out, Ordering::Relaxed);
    if !entry.actconn_reclaimed {
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
fn inject_connection_token_zero_alloc(buf: &mut crate::buf::Buf, token: &str) {
    let Some((eoh_pos, eoh_len)) = crate::find_eoh(buf.readable()) else { return };
    let crlf = buf.readable()[..eoh_pos + eoh_len].windows(2).any(|w| w == b"\r\n");
    // `token` is `close` or `keep-alive`: the line is 24 bytes at most.
    let mut line = [0u8; 40];
    let mut n = 0;
    for part in [b"Connection: ".as_slice(), token.as_bytes(), if crlf { b"\r\n" } else { b"\n" }] {
        line[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    let inject = &line[..n];
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
    } else {
        buf.inject_http_header("Connection", token);
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
            fc_src: sess.fc_src,
            so_name: sess.so_name.as_deref(),
            so_id: sess.so_id,
            fc_dst: sess.fc_dst,
            is_first_req: sess.is_first_req,
            proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: sess.cli_xprt.ssl_facts(),
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
            accept_date: Some(sess.log.date),
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
            proxy.force_be_switch.iter().any(|c| crate::proxy::eval_acl_condition(c, &proxy.acls, registry, &ctx))
        };

        for rule in &proxy.use_backends {
            let mut matches = true;
            if let Some(ref cond) = rule.cond {
                matches = crate::proxy::eval_acl_condition(cond, &proxy.acls, registry, &ctx);
            }
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
        for rule in &be.use_servers {
            if !crate::proxy::eval_acl_condition(&rule.cond, &be.acls, registry, &ctx) {
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
        for rule in &be.stick_rules {
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
            if rule.cond.as_ref().is_some_and(|c| !crate::proxy::eval_acl_condition(c, &be.acls, registry, &ctx)) {
                continue;
            }
            let Some(key) = resolve_sample_stick_key(&rule.expr, registry, &ctx, Some(tbl)) else {
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
        let Some(txn) = entry.sess.txn.as_mut() else {
            // Between requests. A client that goes away here ends the session; a server
            // connection kept from the last transaction goes back to the pool.
            if !matches!(entry.sess.cli_state, ScState::Ready | ScState::Established) {
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
                    let page = proxy_error_response(&entry.sess, fe, fe, proxies, 408);
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
            reply_parse_error(entry, proxies, status);
        }

        // `timeout client` while the request is held for its body: the 408 the wait's own
        // time-out gives.
        if entry.sess.ending == Some(crate::proxy::Ending::Timeout(crate::proxy::Which::Client))
            && entry.sess.txn.as_ref().is_some_and(|t| t.body_wait.is_some_and(|w| !w.tarpit && !w.inspect))
        {
            let fe = &proxies[entry.proxy_idx];
            let page = proxy_error_response(&entry.sess, fe, fe, proxies, 408);
            entry.sess.send_before_close(&page);
            entry.sess.log.status = Some(408);
            entry.sess.log.term = Some(*b"cR");
            entry.sess.log.request = None;
            set_stream_log(entry, proxies, pid);
            close_http_session(entry, proxies, fdtab, poller, idle_pool, true);
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
                    t.req.measure_head(sess.req.readable());
                }
            }
        }

        // The response head, then whatever this pass made ready to move: a request the
        // rules just released, a response head they just processed, a reply, or the final
        // head queued behind an interim one. It moves now rather than on the next poller
        // round. Bounded, and it stops as soon as a byte pass makes no progress (a full
        // socket), so it cannot spin.
        for _ in 0..4 {
            if entry.sess.txn.as_ref().is_some_and(|t| t.rsp == MsgState::Waiting && t.reads_server())
                && !entry.sess.rep.is_empty()
            {
                if Self::l7_retry(entry, proxies, fdtab, poller, now) {
                    continue;
                }
                Self::apply_http_response_rules(entry, proxies, now);
            }
            if Self::l7_retry_failure(entry, proxies, fdtab, poller, now) {
                continue;
            }
            Self::h2_forward_response(entry);
            Self::http_server_side(entry, proxies);
            let movable = entry.sess.has_pending_output() || entry.sess.req_window() > 0;
            if !movable || entry.sess.is_done() {
                break;
            }
            let before = (
                entry.sess.req.len(),
                entry.sess.rep.len(),
                entry.sess.txn.as_ref().map(|t| (t.req, t.rsp)),
            );
            let _ = entry.sess.process(now);
            let after = (
                entry.sess.req.len(),
                entry.sess.rep.len(),
                entry.sess.txn.as_ref().map(|t| (t.req, t.rsp)),
            );
            if before == after {
                break;
            }
        }

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
        } else if drained && txn.finished() {
            Self::end_txn(entry, proxies, fdtab, poller, idle_pool, wake_queue, now, pid);
        }
        admin
    }

    /// How the server side ended, if it has, for a response the server is sending.
    fn http_server_side(entry: &mut SessionEntry, proxies: &[Proxy]) {
        let srv_eof = matches!(entry.sess.srv_state, ScState::ShutR | ScState::Closed);
        let srv_err = entry.sess.srv_state == ScState::Error;
        let Some(txn) = entry.sess.txn.as_mut() else {
            return;
        };
        // A response held by its rules (`WAIT_END`, `wait-for-body`) is here, and one they
        // rejected is not owed; the server closing behind either changes nothing.
        if !(srv_eof || srv_err) || !txn.req_rules_done || txn.local || txn.rsp.is_done() || txn.rsp_wait.is_some() || txn.aborted {
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
                if status == 502 && txn.srv_reused && entry.sess.rep.is_empty() {
                    // `abort_keep_alive`: a keep-alive request lost to a network error,
                    // nothing of a response received. The client retries only if it
                    // sees the connection close unanswered.
                    txn.close_after = true;
                    txn.aborted = true;
                    return;
                }
                if status == 502 {
                    // The server ended the connection before its response head: `SH`.
                    entry.sess.log.term = Some(*b"SH");
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
    fn h2_forward_response(entry: &mut SessionEntry) {
        let sess = &mut entry.sess;
        let (Some(h2), Some(txn)) = (sess.h2_ctx.as_mut(), sess.txn.as_mut()) else {
            return;
        };
        if txn.rsp == MsgState::Waiting || txn.rsp.is_done() {
            return;
        }
        let data = sess.rep.readable();
        let win = txn.rsp.window(data);
        if txn.rsp_interim {
            // An HTTP/1 interim response has no place in this conversion; it is dropped.
            txn.response_sent(data, win);
            sess.rep.consume(win);
            return;
        }
        let stream_id = sess.h2_active_stream_id.unwrap_or(1);
        if let MsgState::Head { body, .. } = txn.rsp {
            // The head goes out as HEADERS once all of it is here; the body follows as
            // DATA, as much as the client's windows take at a time.
            let Some((h, e)) = crate::proxy::find_eoh(data) else { return };
            let end_stream = matches!(body, crate::txn::Framing::None | crate::txn::Framing::Length(0));
            if h2.send_h1_head(stream_id, &data[..h], end_stream) {
                txn.rsp.consume(data, h + e);
                sess.rep.consume(h + e);
                // The body that came with the head goes out with it, in the same write: on
                // its own, a poller round later, it is a second write, and a second small
                // segment Nagle holds until the client's delayed ACK, ~40 ms a request (T186).
                if !end_stream {
                    Self::h2_forward_response(entry);
                }
            }
            return;
        }
        if !matches!(txn.rsp, MsgState::Body(_)) {
            // A body that broke its framing, or a tunnel (101, CONNECT), which this
            // conversion does not carry: the stream is reset and the server is let go.
            h2.send_rst_stream(stream_id, ibex_proto::h2::H2Error::InternalError);
            txn.srv_reusable = false;
            txn.rsp = MsgState::Done;
            return;
        }
        let mut out = Vec::new();
        let mut state = txn.rsp;
        let used = state.take_body(data, h2.data_budget(stream_id), &mut out);
        let end = state.is_done();
        if let Some(t) = txn.rsp_htx.as_mut() {
            // The payload, and the chunked body's end (see `htx_head_size`).
            *t += out.len() as u64 + u64::from(end && matches!(txn.rsp, MsgState::Body(crate::txn::Body::Chunked(_))));
        }
        if !out.is_empty() || end {
            h2.send_data(stream_id, &out, end);
        }
        if used > 0 || end {
            txn.rsp = state;
            sess.rep.consume(used);
        }
        let srv_gone = matches!(sess.srv_state, ScState::ShutR | ScState::Closed | ScState::Error);
        if txn.rsp.is_done() || !srv_gone || !sess.rep.is_empty() {
            return;
        }
        // The server is gone and everything it sent has been delivered.
        txn.srv_reusable = false;
        if matches!(txn.rsp, MsgState::Body(crate::txn::Body::UntilClose)) {
            // The close is the end of this body.
            h2.send_data(stream_id, &[], true);
        } else {
            // Cut short: the stream cannot be completed, so it is reset.
            h2.send_rst_stream(stream_id, ibex_proto::h2::H2Error::Cancel);
            sess.log.term = Some(*b"SD");
        }
        txn.rsp = MsgState::Done;
    }

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
        let reusable = txn.srv_reusable && !txn.local && !leftover && txn.req.is_done() && txn.rsp.is_done();
        if reusable {
            entry.srv_served = (entry.srv_served + 1).min(2);
        }
        let close = if entry.sess.h2_ctx.is_some() {
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
        // peek per request: -25% requests/s at 50 clients), and one that idles has given
        // it back before another request could tell.
        // Under `http-reuse never` the connection is the session's own (`session_add_conn`)
        // and stays on it; so does one opened with a PROXY header, whose reuse key is the
        // header (it names this client's addresses), which the pool does not key by.
        let private = entry.sess.send_proxy_prepended
            || proxies.get(entry.srv_backend_idx).is_some_and(|p| p.http_reuse == ibex_config::HttpReuse::Never);
        if !reusable {
            release_server(entry, proxies, fdtab, poller, idle_pool, false);
        } else if entry.sess.req.is_empty() && !private {
            let keeps = entry.target_server_idx.is_some_and(|i| proxies.get(entry.srv_backend_idx).is_some_and(|p| p.ids.server_pool(i).keeps_any()));
            if keeps && idle_pool.total() == 0 && entry.sess.srv.is_some() {
                entry.sess.srv_park_exp = now.add(SRV_PARK_MS);
                // Idle, it is not one of the server's connections in use (`scur`, and
                // what the lists' rule weighs); the peak in use is noted first, as the
                // lists would have (`srv_add_to_idle_list` raising `max_used_conns`).
                // (`keeps` above holds only with a server, so there is one.)
                let i = entry.target_server_idx.unwrap_or_default();
                let used = proxies.get(entry.srv_backend_idx).and_then(|p| p.server_actconn.get(i)).map_or(0, |a| a.load(Ordering::Relaxed));
                idle_pool.note_used((entry.srv_backend_idx, i), used);
                server_actconn_add(entry, proxies, false);
            } else {
                release_server(entry, proxies, fdtab, poller, idle_pool, true);
            }
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

    /// One run of a stream, with its variables where its rules read them
    /// ([`with_stream_vars`]): everything a stream evaluates happens inside a run, and a
    /// run never waits -- a stream that waits ends its run and is woken for another.
    fn step_stream(&mut self, session_idx: u32) -> Outcome {
        if let Some(entry) = self.sessions.get_mut(session_idx) {
            stream_vars_enter(&mut entry.sess);
            stream_timeouts_enter(self.proxies, entry.proxy_idx, entry.backend_idx, &entry.sess);
        }
        let out = self.step_stream_run(session_idx);
        stream_vars_leave(self.sessions.get_mut(session_idx).map(|e| &mut e.sess));
        CURRENT_TIMEOUTS.set(None);
        out
    }

    #[allow(clippy::too_many_lines)] // one dispatch chain; splitting it would obscure the order
    fn step_stream_run(&mut self, session_idx: u32) -> Outcome {
        // The time now, not the time the pass started: `step` takes its tick before it waits
        // in the poller, so a stream woken by a request after an idle second would arm a
        // `wait-for-body` of 300 ms from a second ago.
        let now = self.now;
        let mut connect_line: Option<(usize, String)> = None;
        let (is_done, pending_admin, log_line) = {
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

            // Step 1: Server connect check if connecting
            check_srv_connect(entry, self.proxies, self.fdtab, self.poller, now);

            // A readiness event on either socket: reading it may make progress again.
            if let Some(sfd) = entry.srv_raw_fd {
                if self.fdtab.ready(sfd).readable {
                    entry.sess.srv_cant_recv = false;
                    self.fdtab.clear_ready(sfd, true, false);
                }
            }
            let cfd = entry.sess.cli.as_raw_fd();
            if self.fdtab.ready(cfd).readable {
                entry.sess.cli_cant_recv = false;
                self.fdtab.clear_ready(cfd, true, false);
            }

            // Step 2: Check timeouts
            let timed_out = entry.sess.check_timeouts(now);
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
            }
            // A retry that waited out its turnaround connects now.
            if entry.sess.retry_after.is_set() && entry.sess.retry_after.is_expired(now) && !entry.sess.is_done() {
                retry_now(entry, self.proxies, self.fdtab, self.poller, now);
            }

            // Step 3: Stream engine process pass
            if !entry.sess.is_done() {
                let _ = entry.sess.process(now);
            }
            // The glitches the HTTP/2 connection counted since the last pass go to the entries
            // its stream counters track (`glitch_cnt`, `glitch_rate`).
            if let Some(n) = entry.sess.h2_ctx.as_ref().map(|h| h.glitch_count as u64).filter(|&n| n > entry.sess.glitches_credited) {
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
                server_connect_failed(entry, self.proxies, self.fdtab, self.poller, now, true);
            }

            // Step 3.3: `tcp-request session` rules that waited for the PROXY header.
            run_deferred_session_rules(entry.proxy_idx, self.proxies, &mut entry.sess);

            // Step 3.4: Content inspection for TCP rules (or before HTTP request parsing)
            if !entry.sess.tcp_inspect_done && !entry.sess.is_done() {
                let proxy_idx = entry.proxy_idx;
                match eval_tcp_req_content_rules(
                    &self.proxies[proxy_idx],
                    self.proxies,
                    sample_registry(),
                    &mut entry.sess,
                    now,
                ) {
                    ContentEvalResult::Done => {
                        entry.sess.tcp_inspect_done = true;
                        entry.sess.inspect_exp = None;
                        // `switch-mode http` made the first request's head a thing to wait
                        // for: `timeout http-request` starts now, not at the next event.
                        entry.sess.arm_request(now);
                    }
                    ContentEvalResult::Reject => {
                        raw::abort_with_rst(entry.sess.cli.as_fd());
                        self.proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                        entry.sess.cli_state = ScState::Closed;
                        entry.sess.srv_state = ScState::Closed;
                        entry.sess.tcp_inspect_done = true;
                    }
                    ContentEvalResult::SilentDrop => {
                        let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                        raw::silent_drop(entry.sess.cli.as_fd(), is_ipv6);
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
                        let _ = entry.sess.process(now);
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
                    ContentEvalResult::SilentDrop => {
                        let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                        raw::silent_drop(entry.sess.cli.as_fd(), is_ipv6);
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

            let log_line = entry.log_line.take().filter(|_| proxy_header_failure(&entry.sess).is_none()).map(|l| (l, entry.log_err));

            // Step 3.6: If in TCP mode and server not yet connected (e.g. deferred on accept-proxy or inspect), connect once ready
            if entry.sess.mode == Mode::Tcp
                && entry.sess.srv_state == ScState::Init
                && (!entry.sess.accept_proxy || entry.sess.proxy_handshake_done)
                && entry.sess.tcp_inspect_done
                && !entry.sess.is_done()
                // A retry waiting out its turnaround connects in step 2 when it is over.
                && !entry.sess.retry_after.is_set()
            {
                if entry.target_addr.is_some() {
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
            if entry.sess.wants_rerun() && !entry.sess.is_done() {
                self.wake_queue.push(entry.task);
            }

            // Step 5: Update timer. Not for a stream that has ended: its task is freed when
            // this returns `Outcome::Done`, and a timer queued on it after the pass was
            // T100's crash.
            if !entry.sess.is_done() {
                self.timer_updates
                    .push((entry.task, entry.sess.next_expiry()));
            }

            (entry.sess.is_done(), pending_admin, log_line)
        };

        if let Some((fe, line)) = connect_line {
            self.send_log_line(fe, line.as_bytes());
        }
        if let Some((line, err)) = log_line {
            let fe = self.sessions.get(session_idx).map_or(0, |e| e.proxy_idx);
            self.send_stream_log(fe, err, &line);
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
            // A TCP connection's line, and an HTTP transaction's that ended with the
            // connection rather than through `end_txn` (aborted, timed out).
            let line = self.sessions.get_mut(session_idx).and_then(|e| {
                // A refused PROXY header has its own line, never the frontend's format.
                if proxy_header_failure(&e.sess).is_some() {
                    e.log_line = None;
                    // `session_kill_embryonic`: `err` with `log-separate-errors`, else `info`.
                    let err = self.proxies[e.proxy_idx].log_opts & ibex_config::LOG_OPT_SEPARATE_ERRORS != 0;
                    return proxy_header_error_line(e, self.proxies).map(|l| (e.proxy_idx, l.into_bytes(), err));
                }
                if e.sess.mode == Mode::Tcp || e.sess.txn.is_some() {
                    account_stream(e, self.proxies);
                }
                let queued = e.log_line.take().map(|l| (l, e.log_err));
                queued
                    .or_else(|| (e.sess.mode == Mode::Tcp || e.sess.txn.is_some()).then(|| stream_log_line(e, self.proxies, self.pid)).flatten())
                    .map(|(l, err)| (e.proxy_idx, l, err))
            });
            if let Some((fe, line, err)) = line {
                self.send_stream_log(fe, err, &line);
            }
            if let Some(entry) = self.sessions.free(session_idx) {
                cleanup_done(
                    &entry,
                    self.proxies,
                    self.fdtab,
                    self.poller,
                    self.listeners,
                );
            }
            Outcome::Done
        } else {
            Outcome::Keep
        }
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
        let Some((h, e)) = crate::proxy::find_eoh(entry.sess.rep.readable()) else {
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
        let Some(snap) = entry.sess.txn.as_ref().and_then(|t| match &t.l7 {
            crate::txn::L7Retry::Saved(s) => Some((s.bytes.clone(), s.req_state)),
            _ => None,
        }) else {
            return false;
        };
        entry.sess.rep.clear();
        entry.sess.req.replace_prefix(0, &snap.0);
        if let Some(t) = entry.sess.txn.as_mut() {
            t.req = snap.1;
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
        // The connect that follows is any other retry's: a refusal at once is the next
        // failure (`server_connect_failed`: `econ` once, retries without turnaround).
        retry_now(entry, proxies, fdtab, poller, now);
        true
    }

    #[allow(clippy::too_many_lines)]
    fn apply_http_response_rules(entry: &mut SessionEntry, proxies: &[Proxy], now: Tick) {
        let threshold = entry.sess.bufsize.saturating_sub(entry.sess.maxrewrite);
        let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(entry.sess.rep.readable()) else {
            if entry.sess.rep.readable().len() > threshold {
                entry.sess.rep.clear();
                reply_error(entry, proxies, 502);
            }
            return;
        };
        let be_idx = entry.backend_idx;
        let fe_idx = entry.proxy_idx;

        let total_hdr_len = hdr_len + eoh_len;
        // Read in place: the head is borrowed from `rep` (no copy for a UTF-8 head, which is
        // every head on the fast path) and the borrow ends before `rep` is edited.
        let (status, framing, srv_has_close, srv_http11) = {
            let head = String::from_utf8_lossy(&entry.sess.rep.readable()[..total_hdr_len]);
            let status = crate::txn::status_of(&head);
            let framing = crate::txn::response_framing(&head, entry.sess.req_method.as_deref(), status);
            (status, framing, crate::txn::head_wants_close(&head), head.starts_with("HTTP/1.1"))
        };
        if total_hdr_len > threshold || status < 100 {
            entry.sess.rep.clear();
            // A response that is not HTTP: `PH`, and nothing of it counts as sent.
            entry.sess.log.term.get_or_insert(*b"PH");
            entry.sess.log.bytes_from_server = 0;
            reply_error(entry, proxies, 502);
            return;
        }
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
            entry.sess.log.data = Some(std::time::Instant::now());
            // What `%B` counts of this head: the message as the server sent it.
            txn.rsp_htx = crate::txn::htx_head_size(&entry.sess.rep.readable()[..total_hdr_len], false);
        }
        let fe_caps = &proxies[fe_idx].res_capture_slots;
        if wait.is_none() && !fe_caps.is_empty() {
            // From the bytes of the head, not a lossy copy of them.
            let head = &entry.sess.rep.readable()[..total_hdr_len];
            let headers: Vec<(&[u8], &[u8])> = head
                .split(|&b| b == b'\n')
                .skip(1)
                .filter_map(|l| {
                    let colon = l.iter().position(|&b| b == b':')?;
                    Some((&l[..colon], l[colon + 1..].strip_suffix(b"\r").unwrap_or(&l[colon + 1..])))
                })
                .collect();
            entry.sess.log.res_captures = capture_values(fe_caps.iter().map(|(n, l)| (n.as_str(), *l)), &headers);
        }
        txn.status = status;
        txn.srv_reusable = !srv_has_close
            && !server_close(proxies, entry.proxy_idx, entry.backend_idx)
            && !matches!(framing, crate::txn::Framing::UntilClose | crate::txn::Framing::Tunnel);
        if framing == crate::txn::Framing::UntilClose {
            // The server's close is the only end the client can see.
            txn.close_after = true;
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
            if let Some(txn) = sess.txn.as_mut() {
                txn.rsp = MsgState::head(framing);
                txn.rsp.measure_head(sess.rep.readable());
                if framing == crate::txn::Framing::Tunnel && txn.req.is_done() {
                    txn.req = MsgState::Tunnel;
                }
            }
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
            || !proxies[be_idx].srvexp.is_empty();

        if !has_rules {
            // `keep-alive` and `close` out of the server's `Connection`, the one this
            // connection's state calls for in (`h1_update_res_conn_value`).
            let (h, e) = crate::find_eoh(entry.sess.rep.readable()).unwrap_or_default();
            let scan = crate::txn::scan_connection(&entry.sess.rep.readable()[..h + e]);
            let token = if tunnel { None } else { crate::txn::response_connection_token(client_close, srv_http11, req_http11, false) };
            if scan.count == 0 || (scan.count == 1 && scan.plain) {
                // The usual response: no `Connection`, or one that is all `keep-alive` and
                // `close`; the head is edited where it is, with no copy.
                if scan.count == 1 {
                    entry.sess.rep.cut(scan.first.0, scan.first.1);
                }
                if let Some(tok) = token {
                    inject_connection_token_zero_alloc(&mut entry.sess.rep, tok);
                }
            } else {
                let head = String::from_utf8_lossy(&entry.sess.rep.readable()[..h + e]).into_owned();
                if let Some(new) = crate::txn::rewrite_response_connection(&head, client_close, req_http11, tunnel) {
                    entry.sess.rep.replace_prefix(h + e, new.as_bytes());
                }
            }
            set_rsp(entry);
            return;
        }

        // The whole head, blank line included: it is replaced by one that carries its own.
        // Replacing only up to the blank line left the old one in front of the body, so
        // every response through these rules arrived with four bytes more than its
        // `Content-Length`.
        let total_hdr_len = match crate::find_eoh(entry.sess.rep.readable()) {
            Some((h, e)) => h + e,
            None => return,
        };
        let hdr_bytes = &entry.sess.rep.readable()[..total_hdr_len];
        let hdr_str = String::from_utf8_lossy(hdr_bytes).into_owned();

        // Bare-LF line ends are a head too (`find_eoh` accepts them, as HAProxy's parser
        // does); split only on CRLF, such a head skipped every rule.
        let Some((first_line, rest_headers)) = hdr_str.split_once("\r\n").or_else(|| hdr_str.split_once('\n')) else {
            set_rsp(entry);
            return;
        };

        let mut status: u16 = 200;
        let mut proto_version = "HTTP/1.1".to_string();
        let mut status_msg = "OK".to_string();
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            proto_version = parts[0].to_string();
            if let Ok(st) = parts[1].parse::<u16>() {
                status = st;
            }
            if parts.len() >= 3 {
                status_msg = parts[2..].join(" ");
            }
        }

        let mut hdrs: Vec<(String, String)> = Vec::new();
        for line in rest_headers.lines() {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                hdrs.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        CURRENT_RES_STATUS.set(status);
        CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
        // `HAProxy` caps `tune.maxrewrite` at half the buffer (`src/haproxy.c`).
        let reserve = entry.sess.maxrewrite.min(entry.sess.bufsize / 2);
        let body_in_buf = entry.sess.rep.readable().len().saturating_sub(total_hdr_len);
        res_htx_init(entry.sess.bufsize, Some(reserve), &proto_version, &status_msg, &hdrs, body_in_buf);

        let registry = sample_registry();

        let req_uri_clone = entry.sess.req_uri.clone();
        let req_method_clone = entry.sess.req_method.clone();
        let req_headers_clone = entry.sess.req_headers.clone();
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
        let ctx = SampleContext {
            proxies: Some(&ProxiesView(proxies)),
            stick: Some(&stick),
            client_addr: entry.sess.client_addr,
            server_addr: entry.sess.server_addr,
            fc_src: entry.sess.fc_src,
            so_name: entry.sess.so_name.as_deref(),
            so_id: entry.sess.so_id,
            fc_dst: entry.sess.fc_dst,
            is_first_req: entry.sess.is_first_req,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: entry.sess.cli_xprt.ssl_facts(),
            ssl_bc: entry.sess.srv_xprt.ssl_facts(),
            htx: None,
            htx_slice,
            req_uri: req_uri_clone.as_deref(),
            req_method: req_method_clone.as_deref(),
            req_headers: req_headers_clone.as_deref(),
            fe_name: Some(&proxies[fe_idx].name),
            fe_id: Some(proxies[fe_idx].ids.iid),
            be_name: Some(&proxies[be_idx].name),
            be_id: Some(proxies[be_idx].ids.iid),
            be_max_retries: Some(proxies[be_idx].retries),
            cur_max_retries: Some(entry.sess.max_retries),
            res_version: Some(&proto_version),
            res_body: has_wait.then_some(res_body.as_slice()),
            unique_id: entry.sess.log.unique_id.as_deref(),
            accept_date: Some(entry.sess.log.date),
            stream: Some(stream_facts(&entry.sess, Some(status))),
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
            for rule in be.stick_rules.iter().filter(|r| r.rule_type == ibex_config::StickRuleType::StickStoreResponse) {
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
                if rule.cond.as_ref().is_some_and(|c| !crate::proxy::eval_acl_condition(c, &be.acls, registry, &ctx)) {
                    continue;
                }
                if let Some(key) = resolve_sample_stick_key(&rule.expr, registry, &ctx, Some(tbl)) {
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
            CURRENT_RES_HEADERS.with(|h| h.borrow_mut().clear());
            let tcp_ctx = SampleContext { res_version: None, ..ctx.clone() };
            // `tcp-response inspect-delay` runs from the first pass over the head; with none,
            // the rules cannot wait (`tcp_inspect_response`).
            let inspect_exp = inspect_wait.map(|w| w.deadline).or_else(|| {
                proxies[be_idx].tcp_res_inspect_delay.map(|d| now.add(u32::try_from(d.as_millis()).unwrap_or(u32::MAX)))
            });
            // A server that closed after its response does not end the wait: measured, the
            // response still waits for the whole delay.
            let inspect_final = rep_full || srv_timed_out || inspect_exp.is_none_or(|exp| exp.is_expired(now));
            for rule in proxies[be_idx].tcp_res_content_rules.iter().filter(|_| resume.is_none()) {
                let matches = match &rule.cond {
                    None => true,
                    Some(cond) => {
                        let res = crate::proxy::combine_condition(cond, |term| {
                            let parsed = if proxies[be_idx].acls.contains_key(&term.name) { None } else { Expr::cached(&term.name).ok() };
                            match proxies[be_idx].acls.get(&term.name).or(parsed.as_deref()) {
                                Some(expr) if expr.fetch_name == "wait_end" && !inspect_final => crate::proxy::AclEvalResult::MissingData,
                                Some(expr) if expr.eval(registry, &tcp_ctx) != term.negated => crate::proxy::AclEvalResult::Matched,
                                _ => crate::proxy::AclEvalResult::NotMatched,
                            }
                        });
                        if res == crate::proxy::AclEvalResult::MissingData {
                            // Held until the delay is over: the rules start again then.
                            held = Some(crate::txn::RspWait { list: 0, rule: 0, deadline: inspect_exp.unwrap_or(Tick::ETERNITY), inspect: true });
                            break 'rules None;
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
                        break 'rules None;
                    }
                    ibex_config::TcpResAction::SetVar { var_name, expr } => {
                        set_var_from_expr(&mut entry.sess.sess_vars, &mut entry.sess.req_vars, var_name, expr, &tcp_ctx, registry);
                    }
                    ibex_config::TcpResAction::SetVarFmt { var_name, fmt } => {
                        let val = format_sample_string(fmt, &tcp_ctx, registry);
                        store_var(&mut entry.sess.sess_vars, &mut entry.sess.req_vars, var_name, val);
                    }
                    ibex_config::TcpResAction::UnsetVar { var_name } => {
                        unset_var(&mut entry.sess.sess_vars, &mut entry.sess.req_vars, var_name);
                    }
                }
            }
            CURRENT_RES_STATUS.set(status);
            CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());

            // 1. The backend's `http-response` rules, then the frontend's when it is another
            // proxy; an `allow` ends only its own list.
            // `http-response capture` writes the frontend's slots, whichever proxy the rule is in.
            // The response side starts with the request's `req.*` variables gone.
            entry.sess.req_vars.retain(|k, _| !k.starts_with("req."));
            CURRENT_VARS.with(|v| v.borrow_mut().retain(|k, _| !k.starts_with("req.")));
            let fe_res_slots = &proxies[fe_idx].res_capture_slots;
            let mut stopped = None;
            LAST_RULE.set(None);
            for (list, &px) in order.iter().enumerate() {
                if resume.is_some_and(|w| list < w.list) {
                    continue;
                }
                let start = resume.filter(|w| w.list == list).map_or(0, |w| w.rule);
                let rules = proxies[px].http_res_rules.iter().map(|r| (ResOp::of_res(&r.action), r.cond.as_ref(), r.line));
                let caps = (!fe_res_slots.is_empty()).then_some((&mut res_caps, &fe_res_slots[..]));
                let mut check = |rule: usize, time_ms: u32, at_least: u32| -> BodyWait {
                    let here = resume.filter(|w| w.list == list && w.rule == rule);
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
                    (&mut hdrs, &mut status, &mut status_msg),
                    &ctx,
                    caps,
                    registry,
                    &mut entry.sess.sess_vars,
                    &mut entry.sess.req_vars,
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
                let sck = crate::cookie::process_response(cfg, target, &cookie_txn, req, status, unix_now(), &mut hdrs);
                if let Some(txn) = entry.sess.txn.as_mut() {
                    txn.ck.sck = sck;
                }
                CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
            }

            // 2. and 3. `http-after-response`, the backend's then the frontend's.
            let after = eval_after_res_rules(
                proxies,
                fe_idx,
                be_idx,
                (&mut hdrs, &mut status, &mut status_msg),
                &ctx,
                Some(&mut res_caps),
                registry,
                &mut entry.sess.sess_vars,
                &mut entry.sess.req_vars,
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
            for (k, v) in &hdrs {
                let _ = write!(new_hdr, "{k}: {v}\r\n");
            }
            new_hdr.push_str("\r\n");
            entry.sess.rep.replace_prefix(total_hdr_len, new_hdr.as_bytes());
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
            entry.sess.rep.clear();
            match stop {
                ResStop::Page(st) => reply_error(entry, proxies, st),
                ResStop::Empty(st) => reply_empty(entry, proxies, st),
                ResStop::Reply(raw) => {
                    let be_idx = if entry.backend_idx < proxies.len() { entry.backend_idx } else { entry.proxy_idx };
                    send_proxy_reply(&mut entry.sess, proxies, entry.proxy_idx, be_idx, &raw);
                }
            }
            return;
        }

        // The same `Connection` handling as without rules, on the headers the rules left.
        crate::txn::apply_response_connection(&mut hdrs, srv_http11, client_close, req_http11, tunnel);

        let mut new_hdr = format!("{proto_version} {status} {status_msg}\r\n");
        for (k, v) in hdrs {
            let _ = write!(new_hdr, "{k}: {v}\r\n");
        }
        new_hdr.push_str("\r\n");

        entry
            .sess
            .rep
            .replace_prefix(total_hdr_len, new_hdr.as_bytes());
        set_rsp(entry);
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
        let req_uri = entry.sess.req_uri.as_deref().unwrap_or("/");

        // 1. CSV telemetry
        if req_uri.contains(";csv") || req_uri.ends_with("/csv") {
            let csv = crate::stats::format_show_stat(proxies, checks, pid);
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-cache, no-store, must-revalidate\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                csv.len(),
                csv
            );
            stats_write_reply(entry, proxies, resp.as_bytes());
            return None;
        }

        // 2. JSON API data for live auto-refresh
        if req_uri.contains("/api/data") || req_uri.ends_with("/data") {
            let json = crate::stats_html::render_stats_json(proxies, checks, pid);
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-cache, no-store, must-revalidate\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                json.len(),
                json
            );
            stats_write_reply(entry, proxies, resp.as_bytes());
            return None;
        }

        // 3. Admin mutations
        let body_str =
            if let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(entry.sess.req.readable()) {
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
        let admin_cmd = crate::stats_html::parse_admin_action(query_str, &body_str);

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
                                        if let Some(check) = checks
                                            .iter_mut()
                                            .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx)
                                        {
                                            check.status = st;
                                        }
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
                        crate::track::set_status(proxies, p_idx, s_idx, st);
                    }
                }
            }

            if is_json_req {
                let body = r#"{"status":"ok","message":"Admin action applied"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Cache-Control: no-cache, no-store, must-revalidate\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    body.len(),
                    body
                );
                stats_write_reply(entry, proxies, resp.as_bytes());
                return Some(cmd);
            }

            let html = crate::stats_html::render_stats_html_for(proxies, checks, pid, &proxies[serving].stats_config);
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-cache, no-store, must-revalidate\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                html.len(),
                html
            );
            stats_write_reply(entry, proxies, resp.as_bytes());
            return Some(cmd);
        }

        // 4. Default: Render full HTML dashboard
        let html = crate::stats_html::render_stats_html_for(proxies, checks, pid, &proxies[serving].stats_config);
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Cache-Control: no-cache, no-store, must-revalidate\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            html.len(),
            html
        );
        stats_write_reply(entry, proxies, resp.as_bytes());
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
        if let Some(m_uri) = proxies[proxy_idx].monitor_uri.as_deref().filter(|_| resume.is_none()) {
            let req_uri = entry.sess.req_uri.as_deref().unwrap_or("/");
            let path = if m_uri.starts_with('/') && req_uri.contains("://") {
                split_uri(req_uri).1
            } else {
                req_uri
            };
            if path == m_uri {
                send_proxy_reply(&mut entry.sess, proxies, proxy_idx, proxy_idx, MONITOR_URI_RESPONSE);
                return None;
            }
        }

        // Serve the stats page before anything else routes this request.
        //
        // This dispatch was dropped when the action-rule engine was wired in, leaving
        // `is_stats_request` and `handle_stats_request` orphaned -- clippy flagged both
        // as never used. The effect was that every request to `stats uri` fell through
        // to normal backend routing and returned 503, so the stats page and the whole
        // web admin stopped working.
        if resume.is_none()
            && (proxies[proxy_idx].stats_config.enable
                || proxies[proxy_idx].stats_config.uri.is_some()
                || proxies[proxy_idx].stats_config.admin)
        {
            let req_uri = entry.sess.req_uri.as_deref().unwrap_or("/");
            let configured_uri = proxies[proxy_idx].stats_config.uri.as_deref();
            if Self::is_stats_request(req_uri, configured_uri)
                || (proxies[proxy_idx].servers.is_empty()
                    && proxies[proxy_idx].default_backend.is_none()
                    && proxies[proxy_idx].use_backends.is_empty())
            {
                return Self::handle_stats_request(entry, proxies, checks, pid, now, proxy_idx);
            }
        }

        let registry = sample_registry();

        // 1. Stick table tracking from http_req_rules

        let http_sample_ctx = SampleContext {
            proxies: Some(&ProxiesView(proxies)),
            client_addr: entry.sess.client_addr,
            server_addr: entry.sess.server_addr,
            fc_src: entry.sess.fc_src,
            so_name: entry.sess.so_name.as_deref(),
            so_id: entry.sess.so_id,
            fc_dst: entry.sess.fc_dst,
            is_first_req: entry.sess.is_first_req,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: entry.sess.cli_xprt.ssl_facts(),
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
            accept_date: Some(entry.sess.log.date),
            captures_req_hdr: Some(&entry.sess.log.req_captures),
            captures_res_hdr: Some(&entry.sess.log.res_captures),
            ..Default::default()
        };

        for rule in proxies[proxy_idx].http_req_rules.iter().filter(|_| resume.is_none()) {
            let matches = match &rule.cond {
                None => true,
                Some(cond) => eval_condition(cond, &http_sample_ctx, &proxies[proxy_idx].acls, registry),
            };
            if !matches {
                continue;
            }
            match &rule.action {
                ibex_config::HttpReqAction::TrackSc0 { table, expr } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_sample_stick_key(expr, registry, &http_sample_ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                        track_http_slot(proxies, &mut entry.sess.tracked_sc, 0, t_idx, k);
                    }
                }
                ibex_config::HttpReqAction::TrackSc1 { table, expr } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_sample_stick_key(expr, registry, &http_sample_ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
                        track_http_slot(proxies, &mut entry.sess.tracked_sc, 1, t_idx, k);
                    }
                }
                ibex_config::HttpReqAction::TrackSc2 { table, expr } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_sample_stick_key(expr, registry, &http_sample_ctx, proxies.get(t_idx).and_then(|p| p.stick_table.as_ref())) {
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
        let eval_http_rules = |rules: &[ibex_config::HttpReqRule], capture_exprs: &[Option<Expr>], acls: &ibex_sample::Acls, sess: &mut TcpSession, be_retries: u16, fe_name: Option<&str>, be_name: Option<&str>, pages_idx: usize, be_stage: bool, start: usize| -> Result<RuleFlow, u16> {
            macro_rules! make_ctx {
                ($s:expr) => {
                    SampleContext {
                        proxies: Some(&ProxiesView(proxies)),
                        client_addr: $s.client_addr,
                        server_addr: $s.server_addr,
                        fc_src: $s.fc_src,
                        so_name: $s.so_name.as_deref(),
                        so_id: $s.so_id,
                        fc_dst: $s.fc_dst,
                        is_first_req: $s.is_first_req,
                        proxy_tlvs: $s.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
                        ssl_fc: $s.cli_xprt.ssl_facts(),
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
                        accept_date: Some($s.log.date),
                        last_rule: last_rule_at($s.log.last_rule),
                        prio: ($s.log.prio_class, $s.log.prio_offset),
                        be_max_retries: Some(be_retries),
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
            for (rule_idx, rule) in rules.iter().enumerate().skip(start) {
                let matches = match &rule.cond {
                    None => true,
                    Some(cond) => eval_condition(cond, &make_ctx!(sess), acls, registry),
                };
                if !matches {
                    continue;
                }
                if matches!(
                    rule.action,
                    ibex_config::HttpReqAction::Return { .. }
                        | ibex_config::HttpReqAction::Deny { .. }
                        | ibex_config::HttpReqAction::Allow
                        | ibex_config::HttpReqAction::Auth { .. }
                        | ibex_config::HttpReqAction::Redirect { .. }
                        | ibex_config::HttpReqAction::Tarpit { .. }
                ) {
                    note_last_rule(sess, rule.line);
                }

                match &rule.action {
                    ibex_config::HttpReqAction::Return {
                        status,
                        content_type,
                        lf_string,
                        error_page,
                    } => {
                        let body = resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], *status, error_page.as_ref(), content_type.as_ref(), lf_string.as_ref());
                        let full_resp: Vec<u8> = match body {
                            ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                            ResolvedErrorBody::Custom { content_type, lf_string } => {
                                build_templated_error_response(*status, content_type, lf_string, &make_ctx!(sess), registry)
                            }
                        };
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, &full_resp);
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Deny {
                        deny_status,
                        content_type,
                        lf_string,
                        error_page,
                    } => {
                        let status_code = deny_status.unwrap_or(403);
                        let body = resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], status_code, error_page.as_ref(), content_type.as_ref(), lf_string.as_ref());
                        let resp: Vec<u8> = match body {
                            ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                            ResolvedErrorBody::Custom { content_type, lf_string } => {
                                build_templated_error_response(status_code, content_type, lf_string, &make_ctx!(sess), registry)
                            }
                        };
                        // Denied by the proxy: `PR`, not a rule's answer (`LR`).
                        sess.log.term = Some(*b"PR");
                        // `dreq` of the proxy whose rule denied (`http_req_get_intercept_rule`).
                        proxies[proxy_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                        for_tracked(proxies, sess, |data| data.count_err());
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, &resp);
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Tarpit { deny_status, content_type, lf_string, error_page } => {
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
                                t.body_wait = Some(crate::txn::BodyWait { backend: be_stage, rule: rule_idx, deadline, tarpit: true, inspect: false });
                            }
                            return Ok(RuleFlow::Suspend);
                        }
                        if let Some(t) = sess.txn.as_mut() {
                            t.body_wait = None;
                        }
                        let status_code = deny_status.unwrap_or(500);
                        let body = resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], status_code, error_page.as_ref(), content_type.as_ref(), lf_string.as_ref());
                        let resp: Vec<u8> = match body {
                            ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                            ResolvedErrorBody::Custom { content_type, lf_string } => {
                                build_templated_error_response(status_code, content_type, lf_string, &make_ctx!(sess), registry)
                            }
                        };
                        sess.log.term = Some(*b"PT");
                        for_tracked(proxies, sess, |data| data.count_err());
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, &resp);
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Allow => {
                        return Ok(RuleFlow::Next);
                    }
                    ibex_config::HttpReqAction::Auth { realm } => {
                        // The 401 page of the proxy with `WWW-Authenticate` added; with no
                        // realm, the name of the proxy the rule is in (`http_action_auth`).
                        let realm = realm.as_deref().or(if be_stage { be_name } else { fe_name }).unwrap_or_default();
                        let page = match resolve_error_body(&proxies[pages_idx], &proxies[proxy_idx], 401, Some(&ibex_config::ErrorPageSource::DefaultErrorfiles), None, None) {
                            ResolvedErrorBody::Raw(bytes) => bytes.to_vec(),
                            ResolvedErrorBody::Custom { content_type, lf_string } => {
                                build_templated_error_response(401, content_type, lf_string, &make_ctx!(sess), registry)
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
                        let target = format_sample_string(&r.target, &ctx, registry);
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
                                let mut host = format_sample_string("%[req.hdr(host)]", &ctx, registry);
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
                            Some(ibex_config::RedirectCookie::SetFmt(f)) => {
                                reply.push_str(&format!("set-cookie: {}; path=/;\r\n", format_sample_string(f, &ctx, registry)));
                            }
                            Some(ibex_config::RedirectCookie::Clear(n)) => reply.push_str(&format!("set-cookie: {n}; path=/; Max-Age=0;\r\n")),
                            None => {}
                        }
                        reply.push_str("\r\n");
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, reply.as_bytes());
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::SetPath { fmt } => {
                        let new_path = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, _, query) = split_uri(current_uri);
                            rebuild_uri(pfx, &new_path, query)
                        };
                        if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::ReplacePath { regex, repl } => {
                        let step = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            // A target with no path (`*`, `http://h?q=1`) is left alone.
                            target_parts(current_uri).filter(|(_, path, _)| !path.is_empty()).and_then(|(pfx, path, query)| {
                                replace_uri_part(path, regex, repl, &make_ctx!(sess), registry)
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
                    ibex_config::HttpReqAction::SetPathq { fmt } => {
                        let new_pathq = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, _, _) = split_uri(current_uri);
                            format!("{pfx}{new_pathq}")
                        };
                        if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::ReplacePathq { regex, repl } => {
                        let step = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            target_parts(current_uri).and_then(|(pfx, path, query)| {
                                let pathq = if query.is_empty() { path.to_string() } else { format!("{path}?{query}") };
                                replace_uri_part(&pathq, regex, repl, &make_ctx!(sess), registry).map(|r| r.map(|n| format!("{pfx}{n}")))
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
                    ibex_config::HttpReqAction::ReplaceUri { regex, repl } => {
                        // The whole target, scheme and authority included.
                        let step = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            replace_uri_part(current_uri, regex, repl, &make_ctx!(sess), registry)
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
                    ibex_config::HttpReqAction::SetQuery { fmt } => {
                        let new_query = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, path, _) = split_uri(current_uri);
                            rebuild_uri(pfx, path, &new_query)
                        };
                        if !req_set_uri(sess, rebuilt) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::SetUri { fmt } => {
                        let new_uri = format_sample_string(fmt, &make_ctx!(sess), registry);
                        if !req_set_uri(sess, new_uri) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::SetMethod { fmt } => {
                        let new_method = format_sample_string(fmt, &make_ctx!(sess), registry);
                        if !req_set_method(sess, new_method) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::SetSrc { expr } => {
                        let val = if let Ok(e) = Expr::cached(expr) {
                            e.eval_sample(registry, &make_ctx!(sess))
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &make_ctx!(sess), registry)
                        };
                        // The address changes, the port stays (`tcp_action_req_set_src`).
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            let port = sess.client_addr.map_or(0, |a| a.port());
                            sess.client_addr = Some(SocketAddr::new(ip, port));
                        }
                    }
                    ibex_config::HttpReqAction::SetSrcPort { expr } => {
                        if let Some(port) = eval_port_expr(expr, registry, &make_ctx!(sess)) {
                            sess.client_addr = Some(with_port(sess.client_addr, port));
                        }
                    }
                    ibex_config::HttpReqAction::SetPriorityClass { expr } | ibex_config::HttpReqAction::SetPriorityOffset { expr } => {
                        // `http_action_set_priority` (src/http_act.c): the sample as an
                        // integer (a string that is not a number is 0), clamped; a sample that
                        // cannot be fetched changes nothing.
                        let value = Expr::cached(expr)
                            .ok()
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
                    ibex_config::HttpReqAction::SetDstPort { expr } => {
                        // `tcp_action_req_set_dst_port` (src/tcp_act.c): the value as an
                        // integer, truncated to 16 bits, on the stream's destination; an
                        // address of another family becomes 0.0.0.0.
                        let port = Expr::cached(expr)
                            .ok()
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
                            ibex_config::RetriesValue::Expr(expr) => {
                                let n = Expr::cached(expr)
                                    .ok()
                                    .and_then(|e| e.eval_sample(registry, &make_ctx!(sess)))
                                    .and_then(|smp| ibex_sample::cast::cast(smp, ibex_sample::SampleType::Sint));
                                if let Some(ibex_sample::Sample::Sint(n @ 0..=100)) = n {
                                    sess.set_retries(u16::try_from(n).unwrap_or(0));
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::SetDst { expr } => {
                        let val = if let Ok(e) = Expr::cached(expr) {
                            e.eval_sample(registry, &make_ctx!(sess))
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &make_ctx!(sess), registry)
                        };
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            let port = sess.server_addr.map_or(0, |a| a.port());
                            sess.server_addr = Some(SocketAddr::new(ip, port));
                        }
                    }
                    ibex_config::HttpReqAction::SetVar { var_name, expr } => {
                        // A sample that cannot be fetched sets nothing (`action_store`, src/vars.c).
                        // The expression is a sample fetch, checked at load; one that cannot be parsed or
                        // fetched sets nothing.
                        let val = Expr::cached(expr).ok().and_then(|e| e.eval_sample(registry, &make_ctx!(sess))).map(|smp| (sample_is_empty(&smp), sample_to_string(&smp)));
                        if let Some((empty, val)) = val {
                            store_var_smp(&mut sess.sess_vars, &mut sess.req_vars, var_name, val, empty);
                        }
                    }
                    ibex_config::HttpReqAction::SetVarFmt { var_name, fmt } => {
                        let val = format_sample_string(fmt, &make_ctx!(sess), registry);
                        store_var(&mut sess.sess_vars, &mut sess.req_vars, var_name, val);
                    }
                    ibex_config::HttpReqAction::UnsetVar { var_name } => {
                        unset_var(&mut sess.sess_vars, &mut sess.req_vars, var_name);
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
                        let ms = if let Ok(expr) = Expr::cached(timeout_val) {
                            if let Some(smp) = expr.eval_sample(registry, &make_ctx!(sess)) {
                                match smp {
                                    Sample::Sint(n) => u32::try_from(n).unwrap_or(0),
                                    Sample::Str(ref s) => parse_timeout_val(s),
                                    _ => parse_timeout_val(timeout_val),
                                }
                            } else {
                                parse_timeout_val(timeout_val)
                            }
                        } else {
                            parse_timeout_val(timeout_val)
                        };
                        // `stream_set_timeout` (src/stream.c): the stream runs on it from here,
                        // and `cur_*_timeout` reports it. 0 leaves the timeout as it was.
                        if let Some(kind) = TimeoutKind::from_name(timeout_type).filter(|_| ms != 0) {
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
                            sess.req_uri = Some(new_uri);
                            rebuild_req_buffer(sess);
                        } else {
                            return Err(400);
                        }
                    }
                    ibex_config::HttpReqAction::SetHeader { name, fmt } => {
                        // A header that does not fit fails the request in strict mode and is
                        // skipped otherwise (`fail_rewrite`).
                        let val = format_sample_string(fmt, &make_ctx!(sess), registry);
                        if !req_rule_header(sess, name, &val, true) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::AddHeader { name, fmt } => {
                        let val = format_sample_string(fmt, &make_ctx!(sess), registry);
                        if !req_rule_header(sess, name, &val, false) && STRICT_MODE.get() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::DelHeader { name } => {
                        let freed = req_hdr_bytes(sess, name);
                        del_req_header(sess, name);
                        res_htx_resize(freed, 0);
                    }
                    ibex_config::HttpReqAction::ReplaceHeader { name, regex, repl } => {
                        if replace_req_header(sess, name, regex, repl).is_err() {
                            return Err(500);
                        }
                    }
                    ibex_config::HttpReqAction::ReplaceValue { name, regex, repl }
                        if replace_req_value(sess, name, regex, repl).is_err() => {
                            return Err(500);
                        }
                    ibex_config::HttpReqAction::ScIncGpc0 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::Inc),
                    ibex_config::HttpReqAction::ScIncGpc1 { sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::One, GpcOp::Inc),
                    ibex_config::HttpReqAction::ScSetGpt0 { sc, expr } => {
                        let val = resolve_gpt0_val(expr, registry, &make_ctx!(sess));
                        sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Zero, GpcOp::SetTag(val));
                    }
                    ibex_config::HttpReqAction::ScIncGpc { idx, sc } => sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Inc),
                    ibex_config::HttpReqAction::ScAddGpc { idx, sc, expr } => {
                        let n = resolve_gpt0_val(expr, registry, &make_ctx!(sess));
                        sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::Add(u64::from(n)));
                    }
                    ibex_config::HttpReqAction::ScSetGpt { idx, sc, expr } => {
                        let val = resolve_gpt0_val(expr, registry, &make_ctx!(sess));
                        sc_gpc_rule(proxies, &sess.tracked_sc, *sc, Gpc::Idx(*idx), GpcOp::SetTag(val));
                    }
                    ibex_config::HttpReqAction::WaitForBody { time_ms, at_least } => {
                        match wait_for_request_body(sess, &proxies[proxy_idx], be_stage, rule_idx, *time_ms, *at_least, now) {
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
                        let val = capture_exprs
                            .get(rule_idx)
                            .and_then(Option::as_ref)
                            .and_then(|e| e.eval_sample(registry, &make_ctx!(sess)))
                            .map(|smp| sample_to_string(&smp));
                        // `id` names one of the frontend's slots (a backend's rule too); without
                        // it the rule's own, which the engine assigned when the proxy was built.
                        // An `id` past the frontend's slots captures nothing.
                        if let (Some(target_id), Some(val)) = (id, val) {
                            // With `id`, the length is the declared slot's.
                            let max = len.or_else(|| proxies[proxy_idx].req_capture_slots.get(*target_id).map(|(_, l)| *l));
                            if let Some(slot) = sess.log.req_captures.get_mut(*target_id) {
                                *slot = Some(cut_at(&val, max.unwrap_or(usize::MAX)).to_vec());
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(RuleFlow::Next)
        };

        // Execute frontend rules
        if !resume_be && !proxies[proxy_idx].http_req_rules.is_empty() {
            let fe_rules = &proxies[proxy_idx].http_req_rules;
            let fe_acls = &proxies[proxy_idx].acls;
            let start = resume.map_or(0, |w| w.rule);
            match eval_http_rules(fe_rules, &proxies[proxy_idx].http_req_capture_exprs, fe_acls, &mut entry.sess, proxies[proxy_idx].retries, Some(&proxies[proxy_idx].name), None, proxy_idx, false, start) {
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
        entry.sess.retry_conn = proxies[be_idx].ids.retry_on & ibex_config::RE_CONN_FAILED != 0;
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
            let res = eval_tcp_req_content_rules(
                &proxies[be_idx],
                proxies,
                sample_registry(),
                &mut entry.sess,
                now,
            );
            entry.sess.inspect_exp = None;
            let wait = (res == ContentEvalResult::Waiting).then(|| crate::txn::BodyWait {
                backend: true,
                rule: 0,
                deadline: deadline.unwrap_or(Tick::ETERNITY),
                tarpit: false,
                inspect: true,
            });
            entry.sess.txn.iter_mut().for_each(|txn| txn.body_wait = wait);
            if res == ContentEvalResult::Waiting {
                // Held until the delay is over: back here then, past the rules and the
                // routing that already ran.
                return None;
            }
            match res {
                ContentEvalResult::Reject => {
                    raw::abort_with_rst(entry.sess.cli.as_fd());
                    proxies[be_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return None;
                }
                ContentEvalResult::SilentDrop => {
                    let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                    raw::silent_drop(entry.sess.cli.as_fd(), is_ipv6);
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
            match eval_http_rules(be_rules, &proxies[be_idx].http_req_capture_exprs, be_acls, &mut entry.sess, proxies[be_idx].retries, Some(&proxies[proxy_idx].name), Some(&proxies[be_idx].name), be_idx, true, start) {
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
            && Self::is_stats_request(entry.sess.req_uri.as_deref().unwrap_or("/"), proxies[be_idx].stats_config.uri.as_deref())
        {
            return Self::handle_stats_request(entry, proxies, checks, pid, now, be_idx);
        }

        // Apply forwardfor & originalto header injection. As in HAProxy
        // (`http_handle_xff_header`), the option applies when the frontend or the backend
        // sets it, and it is not applied to an address in the `except` network of any
        // proxy that sets it.
        let fe_be = [proxy_idx, be_idx];
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
                    add_req_header(&mut entry.sess, "X-Forwarded-For", &ip_str);
                }
            }
        }

        let xot_excepts: Vec<&str> = fe_be.iter().filter_map(|&i| proxies[i].stats_config.originalto.as_deref()).collect();
        if !xot_excepts.is_empty() {
            let dst_ip = entry.sess.server_addr.or(entry.target_addr).map(|a| a.ip());
            if let Some(ip) = dst_ip {
                let in_except = xot_excepts.iter().any(|e| !e.is_empty() && ip_in_cidr(ip, e));
                if !in_except {
                    let ip_str = ip.to_string();
                    add_req_header(&mut entry.sess, "X-Original-To", &ip_str);
                }
            }
        }

        // `option forwarded` (`http_handle_7239_header`): the backend's, as one more element
        // at the end of the last `Forwarded` header.
        if let Some(fwd) = proxies[be_idx].stats_config.forwarded.clone() {
            let stick = StickView::new(proxies, &entry.sess.tracked_sc);
            let element = forwarded_element(&fwd, &entry.sess, &stream_sample_ctx(&entry.sess, &proxies[proxy_idx], &proxies[be_idx], &ProxiesView(proxies), &stick));
            append_forwarded_element(&mut entry.sess, &element);
        }

        // `option http-server-close` (frontend or backend): this request has the server
        // connection to itself, and the server is asked to close it. A request that asks
        // for an upgrade keeps its `Connection` header.
        rewrite_request_connection(&mut entry.sess, server_close(proxies, proxy_idx, be_idx));

        // The backend's `cookie` line: the client's cookies are cut and may name the server.
        let cookie_server = manage_client_cookies(&mut entry.sess, &proxies[be_idx]);
        // `use-server` comes first: a server it picked (SF_ASSIGNED) is not overridden by
        // the cookie, which is still cut as above.
        let cookie_server = Self::use_server(&entry.sess, be_idx, proxies).or(cookie_server);
        // `stick match` after those (`SF_ASSIGNED`); the keys to store are queued either way.
        let assigned = cookie_server.is_some();
        let cookie_server = cookie_server.or(Self::sticking_rules(&mut entry.sess, be_idx, proxies, assigned));
        Self::route_to_server(entry, proxies, fdtab, poller, idle_pool, now, be_idx, cookie_server)
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
        let target = if let Some(idx) = cookie_server {
            Some(proxies[be_idx].servers.at(idx))
        } else {
            proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref())
        };

        let Some(target_addr) = target else {
            if cookie_server.is_none() && proxies[be_idx].all_servers_full() {
                return Self::wait_in_queue(entry, proxies, now, be_idx);
            }
            proxies[be_idx].counters().failed_conn.fetch_add(1, Ordering::Relaxed);
            // No server to connect to: `SC`, whatever the stream's progress.
            entry.sess.log.term = Some(*b"SC");
            reply_error(entry, proxies, 503);
            return None;
        };
        // Given a slot: out of the queue.
        entry.sess.queue = None;
        count_server_session(proxies, be_idx, target_addr);

        // The connection kept from this session's last transaction, if this request goes
        // to the same server: no new connection, no pool round trip. Otherwise it goes to
        // the pool (or is closed) and the request is routed as usual.
        if entry.sess.srv.is_some() {
            // A server that maps the destination may have been reached at another
            // address than this request's destination names; it is not kept.
            let same = entry.srv_backend_idx == be_idx
                && entry.target_addr == Some(target_addr)
                && !maps_destination(target_addr)
                // A TLS connection carries the name it was opened with; a request whose
                // SNI differs (another Host, under the automatic SNI) needs its own.
                && (!entry.sess.srv_xprt.is_tls()
                    || server_sni(&entry.sess, proxies, entry.proxy_idx, be_idx, entry.target_server_idx).as_deref()
                        == entry.sess.srv_xprt.sni())
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
            let alone = proxies[be_idx].http_reuse == ibex_config::HttpReuse::Never
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
                entry.sess.log.queue.get_or_insert_with(Instant::now);
                if entry.sess.srv_park_exp.is_set() {
                    entry.sess.srv_park_exp = Tick::ETERNITY;
                    server_actconn_add(entry, proxies, true);
                }
                entry.sess.server_connected(now);
                if let Some(txn) = entry.sess.txn.as_mut() {
                    txn.srv_reused = true;
                }
                return None;
            }
            release_server(entry, proxies, fdtab, poller, idle_pool, true);
        }

        let s_idx = cookie_server.or_else(|| proxies[be_idx].servers.iter().position(|s| s == target_addr));
        if let Some(idx) = s_idx {
            if idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
        entry.target_server_idx = s_idx;
        entry.srv_backend_idx = be_idx;

        maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

        entry.target_addr = Some(target_addr);

        let mut reused = None;
        entry.srv_served = 0;
        if proxies[be_idx].http_reuse != ibex_config::HttpReuse::Never && idle_pool.may_find() {
            let sni = server_sni(&entry.sess, proxies, entry.proxy_idx, be_idx, s_idx);
            let key = idle_key(target_addr, be_idx, s_idx, sni);
            // `conn_backend_get` takes none of another thread's while the server keeps fewer
            // idle connections than its `pool-low-conn` (and few fds are in use).
            let low = s_idx.map_or(0, |i| proxies[be_idx].ids.server_pool(i).low_conn);
            let steal = low == 0 || idle_pool.total() >= usize::try_from(low).unwrap_or(usize::MAX);
            if let Some((conn, safe)) = key.and_then(|k| idle_pool.take(&k, entry.sess.is_first_req, proxies[be_idx].http_reuse, steal)) {
                entry.srv_served = if safe { 2 } else { 1 };
                reused = Some(conn);
            }
        }

        if let Some(IdleConn { fd: srv_fd, xprt }) = reused {
            let sfd = srv_fd.as_raw_fd();
            entry.srv_raw_fd = Some(sfd);
            entry.sess.attach_server_with_xprt(srv_fd, xprt, now);
            entry.sess.server_connected(now);
            if let Some(txn) = entry.sess.txn.as_mut() {
                txn.srv_reused = true;
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
        } else if let Ok((srv_fd, immediate)) = raw::connect_opts(connect_addr(target_addr, entry.sess.server_addr), proxies[be_idx].server_tfo_of(target_addr)) {
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
        if let Some(q) = entry.sess.queue.as_ref() {
            if q.deadline.is_expired(now) {
                entry.sess.queue = None;
                proxies[be_idx].counters().failed_conn.fetch_add(1, Ordering::Relaxed);
                entry.sess.log.term = Some(*b"sQ");
                entry.sess.log.queue.get_or_insert_with(Instant::now);
                reply_error(entry, proxies, 503);
            }
            return None;
        }
        let ms = entry.sess.queue_ms();
        let deadline = if ms == 0 { Tick::ETERNITY } else { now.add(ms) };
        let q = crate::proxy::QueueWait::enter(entry.task, be_idx, proxies[be_idx].stats.clone(), deadline);
        entry.sess.log.be_queue = u64::from(q.pos);
        entry.sess.queue = Some(q);
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
            let res = eval_tcp_req_content_rules(
                &proxies[be_idx],
                proxies,
                sample_registry(),
                &mut entry.sess,
                now,
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
                    raw::abort_with_rst(entry.sess.cli.as_fd());
                    proxies[be_idx].counters().denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return;
                }
                ContentEvalResult::SilentDrop => {
                    let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                    raw::silent_drop(entry.sess.cli.as_fd(), is_ipv6);
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
        let target = match chosen.or(Self::sticking_rules(&mut entry.sess, be_idx, proxies, assigned)) {
            Some(i) => Some(proxies[be_idx].servers.at(i)),
            None => proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref()),
        };

        let Some(target_addr) = target else {
            entry.sess.srv_state = ScState::Error;
            return;
        };

        count_server_session(proxies, be_idx, target_addr);

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

        maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

        entry.target_addr = Some(target_addr);
        if let Ok((srv_fd, immediate)) = raw::connect_opts(connect_addr(target_addr, entry.sess.server_addr), proxies[be_idx].server_tfo_of(target_addr)) {
            let sfd = srv_fd.as_raw_fd();
            attach_server_to(&mut entry.sess, proxies, entry.proxy_idx, be_idx, s_idx, srv_fd, now);
            entry.srv_raw_fd = Some(sfd);
            if immediate {
                entry.sess.server_connected(now);
                fdtab.set_ready(sfd, false, true);
                let _ = entry.sess.process(now);
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
    }

    fn step_check(&mut self, check_idx: usize) -> Outcome {
        if check_idx < self.checks.len() {
            let check = &mut self.checks[check_idx];
            let now = self.now;
            let step = check::step_check(check, self.fdtab, self.poller, now, self.proxies);

            let proxy_idx = check.proxy_idx;
            let server_idx = check.server_idx;
            if check.enabled
                && proxy_idx < self.proxies.len()
                && server_idx < self.proxies[proxy_idx].server_statuses.len()
            {
                crate::track::set_status(self.proxies, proxy_idx, server_idx, check.status);
            }

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
                // HAProxy logs an UP/DOWN transition always, and every other check result
                // only under `option log-health-checks` (src/check.c, PR_O2_LOGHCHKS).
                // Without that gate a one-second check interval fills a collector with a
                // line per server per second.
                if !event.is_transition() && !proxy.log_health_checks {
                    return None;
                }
                let server = proxy
                    .server_ids
                    .get(server_idx)
                    .map_or("?", String::as_str);
                Some(check.log_line(&proxy.name, server, event))
            });

            if let Some(msg) = log {
                self.send_log(proxy_idx, LogLevel::Notice, msg.as_bytes());
            }

            self.timer_updates.push(pending);
            Outcome::Keep
        } else {
            Outcome::Done
        }
    }

    /// Emits one line to every syslog target the given proxy resolved to.
    ///
    /// Silent when the proxy has no targets, which is the common case: `HAProxy` logs
    /// nothing unless a `log` directive says where to.
    /// A transaction's or connection's log line, at `info` as `HAProxy` sends them.
    fn send_log_line(&self, proxy_idx: usize, line: &[u8]) {
        self.send_log(proxy_idx, LogLevel::Info, line);
    }

    /// A stream's line: `info`, or `err` when it failed and the frontend has `option
    /// log-separate-errors` (`strm_log`).
    fn send_stream_log(&self, proxy_idx: usize, err: bool, line: &[u8]) {
        let separate = self.proxies.get(proxy_idx).is_some_and(|p| p.log_opts & ibex_config::LOG_OPT_SEPARATE_ERRORS != 0);
        self.send_log(proxy_idx, if err && separate { LogLevel::Err } else { LogLevel::Info }, line);
    }

    fn send_log(&self, proxy_idx: usize, level: LogLevel, msg: &[u8]) {
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
            let _ = target.send(level, tag, "", msg);
        }
    }

    fn step_applet(&mut self, applet_idx: usize) -> Outcome {
        let applet_id = usize_to_u32(applet_idx);
        let Some(applet) = self.applets.get_mut(applet_id) else {
            return Outcome::Done;
        };

        if applet.is_done {
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
            applet.read_input();
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

        if !applet.out_buf.is_empty() {
            applet.write_output();
        }

        if applet.is_done {
            if let Some(applet) = self.applets.free(applet_id) {
                if let Some(ref stream) = applet.stream {
                    let _ = self.poller.delete(stream.as_fd());
                }
                self.fdtab.remove(applet.raw_fd);
            }
            return Outcome::Done;
        }

        let new_interest = if applet.out_buf.is_empty() {
            Interest::READ
        } else {
            Interest {
                readable: true,
                writable: true,
            }
        };

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

        self.timer_updates
            .push((applet.task, applet.last_activity.add(applet.timeout_ms)));
        Outcome::Keep
    }
}

impl Dispatch for EngineDispatcher<'_> {
    fn run(&mut self, kind: WorkKind, _state: u32) -> Outcome {
        match kind.kind() {
            Some(Kind::Stream) => {
                let session_idx = kind.index();
                self.step_stream(session_idx)
            }
            Some(Kind::Check) => {
                let check_idx = kind.index() as usize;
                self.step_check(check_idx)
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
        Sample::Bin(b) => String::from_utf8_lossy(b).to_string(),
        Sample::Meth(m) => m.as_str().to_string(),
    }
}

pub(crate) fn resolve_gpt0_val(
    expr_str: &str,
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
    if let Ok(e) = Expr::cached(expr_str) {
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

/// The stick-table key `expr_str` stands for, converted to the type of the table `table`
/// that will hold it ([`ibex_stick_table::StickTable::coerce_key`]); `None` where the
/// expression yields nothing to track, or something the table's key type cannot be made
/// of. Tracking and lookups (`in_table`, `src_*`) build their keys the same way.
pub(crate) fn resolve_sample_stick_key(
    expr_str: &str,
    registry: &Registry,
    ctx: &SampleContext,
    table: Option<&Arc<ibex_stick_table::StickTable>>,
) -> Option<StickKey> {
    // An expression that gives no sample (a header that is absent) tracks nothing.
    let smp = Expr::cached(expr_str).ok()?.eval_sample(registry, ctx)?;
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
    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                let mut expr_str = String::new();
                let mut depth = 1;
                for ec in chars.by_ref() {
                    if ec == '[' {
                        depth += 1;
                        expr_str.push(ec);
                    } else if ec == ']' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        expr_str.push(ec);
                    } else {
                        expr_str.push(ec);
                    }
                }
                if let Ok(expr) = Expr::cached(&expr_str) {
                    if let Some(smp) = expr.eval_sample(registry, ctx) {
                        match &smp {
                            // Written as text, a binary is cast with `c_bin2str`: it ends at the
                            // first NUL.
                            Sample::Bin(b) => {
                                let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                                out.push_str(&String::from_utf8_lossy(&b[..end]));
                            }
                            _ => out.push_str(&sample_to_string(&smp)),
                        }
                    }
                }
            } else if chars.peek() == Some(&'c') {
                chars.next();
                if chars.peek() == Some(&'i') {
                    chars.next();
                    let ip = ctx.client_addr.map_or_else(|| "127.0.0.1".to_string(), |a| a.ip().to_string());
                    out.push_str(&ip);
                } else {
                    out.push_str("%c");
                }
            } else if chars.peek() == Some(&'T') {
                chars.next();
                if chars.peek() == Some(&'r') {
                    chars.next();
                    out.push_str("0ms");
                } else {
                    out.push_str("%T");
                }
            } else if chars.peek() == Some(&'%') {
                chars.next();
                out.push('%');
            } else {
                out.push('%');
            }
        } else {
            out.push(c);
        }
    }
    out
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
        "path-strip-dotdot" => {
            let segments: Vec<&str> = path.split('/').collect();
            let mut stack: Vec<&str> = Vec::new();
            for seg in segments {
                if seg == ".." {
                    if stack.is_empty() {
                        // A ".." with nothing to pop would escape the root. The `full`
                        // variant discards it; the plain variant preserves it verbatim
                        // so the path is not silently altered.
                        //
                        // Both branches previously called stack.pop(), which is a no-op
                        // on an empty Vec -- so the `full` flag had no effect at all.
                        if !full {
                            stack.push(seg);
                        }
                    } else {
                        stack.pop();
                    }
                } else if seg != "." && !seg.is_empty() {
                    stack.push(seg);
                }
            }
            let mut new_path = format!("/{}", stack.join("/"));
            if path.ends_with('/') && !new_path.ends_with('/') {
                new_path.push('/');
            }
            Ok(rebuild_uri(prefix, &new_path, query))
        }
        "path-strip-dot" => {
            let segments: Vec<&str> = path.split('/').collect();
            let mut stack: Vec<&str> = Vec::new();
            for seg in segments {
                if seg != "." && !seg.is_empty() {
                    stack.push(seg);
                }
            }
            let mut new_path = format!("/{}", stack.join("/"));
            if path.ends_with('/') && !new_path.ends_with('/') {
                new_path.push('/');
            }
            Ok(rebuild_uri(prefix, &new_path, query))
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
        "percent-to-uppercase" => {
            let mut res = String::with_capacity(uri.len());
            let bytes = uri.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    if i + 2 < bytes.len() {
                        let h1 = bytes[i + 1] as char;
                        let h2 = bytes[i + 2] as char;
                        if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() {
                            res.push('%');
                            res.push(h1.to_ascii_uppercase());
                            res.push(h2.to_ascii_uppercase());
                            i += 3;
                            continue;
                        }
                    }
                    if strict {
                        return Err(());
                    }
                    res.push('%');
                    i += 1;
                } else {
                    res.push(bytes[i] as char);
                    i += 1;
                }
            }
            Ok(res)
        }
        "percent-decode-unreserved" => {
            let mut res = String::with_capacity(uri.len());
            let bytes = uri.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    if i + 2 < bytes.len() {
                        if let Ok(b) = u8::from_str_radix(&uri[i + 1..i + 3], 16) {
                            if b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~' {
                                res.push(b as char);
                                i += 3;
                                continue;
                            }
                            res.push_str(&uri[i..i + 3]);
                            i += 3;
                            continue;
                        }
                    }
                    if strict {
                        return Err(());
                    }
                    res.push('%');
                    i += 1;
                } else {
                    res.push(bytes[i] as char);
                    i += 1;
                }
            }
            Ok(res)
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
fn rewrite_request_connection(sess: &mut TcpSession, close: bool) {
    let http11 = sess.txn.as_ref().is_none_or(|t| t.req_http11);
    // One look at the head, no copy. The usual request has no `Connection`, or one that is
    // all `keep-alive` and `close` and goes whole, cut out of the head where it is.
    let scan = crate::find_eoh(sess.req.readable()).map(|(h, e)| crate::txn::scan_connection(&sess.req.readable()[..h + e]));
    let scan = scan.unwrap_or_default();
    if scan.count == 0 || (scan.count == 1 && scan.plain) {
        if scan.count == 1 {
            sess.with_htx_mut(|htx| {
                let _ = htx.remove_header("connection");
            });
            if let Some(hdrs) = sess.req_headers.as_mut() {
                hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
            }
            sess.req.cut(scan.first.0, scan.first.1);
        }
        if let Some(tok) = crate::txn::request_connection_token(close, http11, false) {
            add_req_header(sess, "Connection", tok);
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
    if let Some(tok) = crate::txn::request_connection_token(close, http11, tokens.upgrade) {
        add_req_header(sess, "Connection", tok);
    }
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

fn add_req_header(sess: &mut TcpSession, name: &str, val: &str) {
    sess.with_htx_mut(|htx| {
        let _ = htx.add_header(name, val);
    });
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    hdrs.push((name.to_string(), val.to_string()));
    sess.req_headers = Some(hdrs);
    rebuild_req_buffer(sess);
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
/// http-buffer-request` stands for (`time_ms` unset: `timeout http-request`, else `timeout
/// client`, of the frontend), reached at rule `rule` of the frontend's list or, with
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
                if sess.h2_ctx.is_none() {
                    sess.send_before_close(b"HTTP/1.1 100 Continue\r\n\r\n");
                }
                del_req_header(sess, "expect");
            }
            let timeouts = &fe.stats_config.raw_timeouts;
            let wait_ms = time_ms.or_else(|| timeouts.http_request.or(timeouts.client).map(millis_to_u32));
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
        BodyWait::Ready if held.is_some() => sess.log.request = Some(std::time::Instant::now()),
        BodyWait::TimedOut | BodyWait::ClientGone | BodyWait::Malformed => sess.log.request = None,
        _ => {}
    }
    let pending = matches!(outcome, BodyWait::Pending);
    let ready = matches!(outcome, BodyWait::Ready);
    for txn in sess.txn.as_mut() {
        txn.body_wait = pending.then_some(crate::txn::BodyWait { backend, rule, deadline, tarpit: false, inspect: false });
        if ready {
            txn.req_body = Some(std::mem::take(&mut body));
        }
    }
    outcome
}

fn del_req_header(sess: &mut TcpSession, name: &str) {
    // `-m beg|end|sub|reg` names a set of headers: remove each that matches.
    let names: Vec<String> = if name.starts_with('\0') {
        sess.htx_slice().map_or_else(Vec::new, |h| h.headers().map(|(k, _)| k.to_string()).filter(|k| header_name_matches(k, name)).collect())
    } else {
        vec![name.to_string()]
    };
    sess.with_htx_mut(|htx| {
        for n in &names {
            let _ = htx.remove_header(n);
        }
    });
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    hdrs.retain(|(k, _)| !header_name_matches(k, name));
    sess.req_headers = Some(hdrs);
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
    let body = if body == 0 { 0 } else { (8 + body).min(size.saturating_sub(reserve).saturating_sub(head)) };
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
    sess.req_uri = Some(uri);
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
    sess.req_method = Some(method);
    rebuild_req_buffer(sess);
    true
}

/// The bytes the request's headers named `name` take in the HTX message.
fn req_hdr_bytes(sess: &TcpSession, name: &str) -> usize {
    sess.htx_slice().map_or(0, |h| h.headers().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(k, v)| htx_hdr_size(k, v)).sum())
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
    if !res_htx_resize(0, htx_hdr_size(name, val)) {
        return false;
    }
    sess.htx_reserve(name.len() + val.len());
    add_req_header(sess, name, val);
    true
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
    let headers: Vec<(String, String)> = sess.htx_slice().map_or_else(Vec::new, |h| {
        h.headers().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(k, v)| (k.to_string(), v.to_string())).collect()
    });
    let mut edits: Vec<(String, String)> = Vec::new();
    let mut failed = false;
    for (k, v) in &headers {
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
            Some(n) if res_htx_resize(htx_hdr_size(k, v), htx_hdr_size(k, &n)) => edits.push((v.clone(), n)),
            _ => {
                failed = true;
                break;
            }
        }
    }
    // Each value is written at the end of the HTX, twice (the marker and the new value), the
    // old ones staying where they were until the message is defragmented.
    sess.htx_reserve(edits.iter().map(|(old, new)| old.len() + new.len() + 64).sum());
    sess.with_htx_mut(|htx| {
        // Two steps through a marker, so that a new value equal to the old value of a later
        // edit is not rewritten again. A value is replaced whole and literally: `$` is the
        // only special character in a `regex` replacement.
        for (i, (old, _)) in edits.iter().enumerate() {
            let _ = htx.replace_header(name, &format!("^{}$", ibex_regex::UserRegex::escape(old)), &format!("@@ibex-rewrite-{i}@@"));
        }
        for (i, (_, new)) in edits.iter().enumerate() {
            let _ = htx.replace_header(name, &format!("^@@ibex-rewrite-{i}@@$"), &new.replace('$', "$$"));
        }
    });
    rebuild_req_buffer(sess);
    if failed && STRICT_MODE.get() {
        Err(())
    } else {
        Ok(())
    }
}

/// Seconds since the epoch (`date.tv_sec`).
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

fn rebuild_req_buffer(sess: &mut TcpSession) {
    let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(sess.req.readable()) else {
        return;
    };
    if let Some(htx) = sess.htx_slice() {
        if sess.h2_chunk_out {
            let mut wire = htx.write_h1_wire_vec();
            // An HTTP/2 request without a length goes out chunked: the header is written with
            // the head, after the rules, which never saw it.
            if !wire.is_empty() {
                if let Some((h, _)) = crate::proxy::find_eoh(&wire) {
                    let mut v = wire[..h].to_vec();
                    v.extend_from_slice(b"\r\ntransfer-encoding: chunked");
                    v.extend_from_slice(&wire[h..]);
                    wire = v;
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

fn eval_condition(
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
}

/// One `http-response` or `http-after-response` action, whichever list it comes from.
/// The configuration encodes the actions that are not header edits as a `SetHeader` (or,
/// for `unset-var`, a `DelHeader`) whose name starts with a NUL (`rules_http.rs`).
#[derive(Clone, Copy)]
enum ResOp<'a> {
    Set(&'a str, &'a str),
    Add(&'a str, &'a str),
    Del(&'a str),
    Status(u16, Option<&'a str>),
    /// `http-response redirect location <fmt> code <c> [cookie]`.
    Redirect(&'a str, u16, Option<&'a ibex_config::RedirectCookie>),
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
    Capture(&'a str, usize),
    /// `wait-for-body time <ms> at-least <bytes>`.
    Wait(u32, u32),
}

impl<'a> ResOp<'a> {
    fn of_res(a: &'a ibex_config::HttpResAction) -> ResRule<'a> {
        ResRule::Op(match a {
            ibex_config::HttpResAction::SetHeader { name, fmt } => Self::Set(name, fmt),
            ibex_config::HttpResAction::AddHeader { name, fmt } => Self::Add(name, fmt),
            ibex_config::HttpResAction::DelHeader { name } => Self::Del(name),
            ibex_config::HttpResAction::SetStatus { status, reason } => Self::Status(*status, reason.as_deref()),
            ibex_config::HttpResAction::Redirect { location, code, cookie } => Self::Redirect(location, *code, cookie.as_ref()),
            ibex_config::HttpResAction::Capture { expr, id } => return ResRule::Capture(expr, *id),
            ibex_config::HttpResAction::WaitForBody { time_ms, at_least } => return ResRule::Wait(*time_ms, *at_least),
        })
    }

    fn of_after_res(a: &'a ibex_config::HttpAfterResAction) -> ResRule<'a> {
        ResRule::Op(match a {
            ibex_config::HttpAfterResAction::Capture { expr, id } => return ResRule::Capture(expr, *id),
            ibex_config::HttpAfterResAction::SetHeader { name, fmt } => Self::Set(name, fmt),
            ibex_config::HttpAfterResAction::AddHeader { name, fmt } => Self::Add(name, fmt),
            ibex_config::HttpAfterResAction::DelHeader { name } => Self::Del(name),
        })
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
    repl: &str,
    ctx: &SampleContext,
    registry: &Registry,
) -> Option<Result<String, ()>> {
    let re = ibex_regex::UserRegex::cached(regex).ok()?;
    let caps = re.captures(part)?;
    let fmt = format_sample_string(repl, ctx, registry);
    Some(exp_replace(&fmt, &caps).ok_or(()))
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
    hdrs: &mut Vec<(String, String)>,
    status: &mut u16,
    status_msg: &mut String,
    ctx: &SampleContext,
    registry: &Registry,
    sess_vars: &mut HashMap<String, String>,
    req_vars: &mut HashMap<String, String>,
) -> Result<bool, ResStop> {
    // A rewrite that does not fit: the response fails in strict mode, and the rule is
    // skipped otherwise (`fail_rewrite`, `src/http_act.c`).
    let failed = || if STRICT_MODE.get() { Err(ResStop::Page(500)) } else { Ok(true) };
    let publish = |hdrs: &Vec<(String, String)>| CURRENT_RES_HEADERS.with(|h| h.borrow_mut().clone_from(hdrs));
    let (act_name, act_fmt) = match op {
        ResOp::Redirect(location, code, cookie) => {
            // `http_apply_redirect_rule` (src/http_ana.c) for a `location` redirect: the
            // answer to the client is the redirect, and the server's response is dropped.
            let mut reply = format!("HTTP/1.1 {code} {}\r\ncontent-length: 0\r\nlocation: {}\r\n", status_reason(code), format_sample_string(location, ctx, registry));
            if matches!(code, 302 | 303 | 307) {
                reply.push_str("cache-control: no-cache\r\n");
            }
            match cookie {
                Some(ibex_config::RedirectCookie::Set(c)) => reply.push_str(&format!("set-cookie: {c}; path=/;\r\n")),
                Some(ibex_config::RedirectCookie::SetFmt(f)) => {
                    reply.push_str(&format!("set-cookie: {}; path=/;\r\n", format_sample_string(f, ctx, registry)));
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
                unset_var(sess_vars, req_vars, var_name);
                return Ok(true);
            }
            let freed: usize = hdrs.iter().filter(|(k, _)| header_name_matches(k, name)).map(|(k, v)| htx_hdr_size(k, v)).sum();
            hdrs.retain(|(k, _)| !header_name_matches(k, name));
            res_htx_resize(freed, 0);
            publish(hdrs);
            return Ok(true);
        }
        ResOp::Add(name, fmt) => {
            let val = format_sample_string(fmt, ctx, registry);
            if !res_htx_resize(0, htx_hdr_size(name, &val)) {
                return failed();
            }
            hdrs.push((name.to_string(), val));
            publish(hdrs);
            return Ok(true);
        }
        ResOp::Set(name, fmt) => (name, fmt),
    };
    if act_name == "\0allow" {
        return Ok(false);
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
        return res_action(ResOp::Status(code.parse().unwrap_or(*status), reason), hdrs, status, status_msg, ctx, registry, sess_vars, req_vars);
    }
    if let Some(var_name) = act_name.strip_prefix("\0set-var:") {
        // A fetch that finds nothing leaves the variable as it was (`action_store`).
        set_var_from_expr(sess_vars, req_vars, var_name, act_fmt, ctx, registry);
        return Ok(true);
    }
    if let Some(var_name) = act_name.strip_prefix("\0set-var-fmt:") {
        store_var(sess_vars, req_vars, var_name, format_sample_string(act_fmt, ctx, registry));
        return Ok(true);
    }
    if act_name == "\0strict-mode" {
        STRICT_MODE.set(act_fmt == "on");
        return Ok(true);
    }
    let replace = act_name
        .strip_prefix("\0replace-header:")
        .map(|n| (n, true))
        .or_else(|| act_name.strip_prefix("\0replace-value:").map(|n| (n, false)));
    if let Some((hdr_name, full)) = replace {
        // `http_replace_hdrs`: header by header, the first that does not fit failing the
        // action with the ones before it rewritten.
        let Some((re_str, repl)) = act_fmt.split_once('\t') else { return Ok(true) };
        let Ok(re) = ibex_regex::UserRegex::cached(re_str) else { return Ok(true) };
        let mut result = Ok(true);
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
                Some(n) if res_htx_resize(htx_hdr_size(k, v), htx_hdr_size(k, &n)) => *v = n,
                _ => {
                    result = failed();
                    break;
                }
            }
        }
        publish(hdrs);
        return result;
    }

    // `set-header`: every occurrence goes, then one is added at the end
    // (`http_action_set_header`) -- the removal stays when the addition does not fit.
    let val = format_sample_string(act_fmt, ctx, registry);
    let freed: usize = hdrs.iter().filter(|(k, _)| k.eq_ignore_ascii_case(act_name)).map(|(k, v)| htx_hdr_size(k, v)).sum();
    hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case(act_name));
    res_htx_resize(freed, 0);
    let fits = res_htx_resize(0, htx_hdr_size(act_name, &val));
    if fits {
        hdrs.push((act_name.to_string(), val));
    }
    publish(hdrs);
    if fits {
        Ok(true)
    } else {
        failed()
    }
}

/// Runs one rule list (`http_res_get_intercept_rule`): each rule whose condition holds,
/// until `allow` ends the list or an action stops the response. Every list starts in
/// strict mode, and a `strict-mode off` in it lasts to its end only.
///
/// `caps` is the response capture slots with their lengths, for the lists that have
/// `http-response capture`: a rule writes its slot there, and the rules after it (and the
/// caller, once the list is done) read what it wrote.
#[allow(clippy::too_many_arguments)]
fn run_res_rules<'a>(
    rules: impl Iterator<Item = (ResRule<'a>, Option<&'a ibex_config::AclCondition>, u32)>,
    acls: &ibex_sample::Acls,
    head: (&mut Vec<(String, String)>, &mut u16, &mut String),
    ctx: &SampleContext,
    mut caps: Option<(&mut Vec<Option<Vec<u8>>>, &[(String, usize)])>,
    registry: &Registry,
    sess_vars: &mut HashMap<String, String>,
    req_vars: &mut HashMap<String, String>,
    mut wait: Option<ResWait<'_>>,
) -> Result<Option<usize>, ResStop> {
    let (hdrs, status, status_msg) = head;
    STRICT_MODE.set(true);
    let mut result = Ok(None);
    let start = wait.as_ref().map_or(0, |w| w.start);
    for (idx, (op, cond, line)) in rules.enumerate().skip(start) {
        // The slots as the earlier rules left them, for `capture.res.hdr`.
        // and the proxy's ACLs, for `when(acl,<name>)`.
        let with_caps = SampleContext {
            captures_res_hdr: caps.as_ref().map(|(slots, _)| slots.as_slice()).or(ctx.captures_res_hdr),
            acls: Some(acls),
            ..ctx.clone()
        };
        let ctx = &with_caps;
        if cond.is_some_and(|c| !eval_condition(c, ctx, acls, registry)) {
            continue;
        }
        let op = match op {
            ResRule::Op(op) => op,
            ResRule::Capture(expr, id) => {
                // No sample, no capture (the slot keeps what it had); an `id` past the frontend's
                // slots captures nothing (`http_action_res_capture_by_id`: `id >= fe->nb_rsp_cap`).
                let val = Expr::cached(expr).ok().and_then(|e| e.eval_sample(registry, ctx)).map(|smp| sample_to_string(&smp));
                if let (Some(val), Some((slots, lens))) = (val, caps.as_mut()) {
                    if let (Some(slot), Some((_, len))) = (slots.get_mut(id), lens.get(id)) {
                        *slot = Some(cut_at(&val, *len).to_vec());
                    }
                }
                continue;
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
        if line != 0 && matches!(op, ResOp::Redirect(..) | ResOp::Set("\0allow" | "\0deny", _)) {
            LAST_RULE.set(Some(line));
        }
        match res_action(op, hdrs, status, status_msg, ctx, registry, sess_vars, req_vars) {
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
fn eval_after_res_rules(
    proxies: &[Proxy],
    fe_idx: usize,
    be_idx: usize,
    head: (&mut Vec<(String, String)>, &mut u16, &mut String),
    ctx: &SampleContext,
    mut res_caps: Option<&mut Vec<Option<Vec<u8>>>>,
    registry: &Registry,
    sess_vars: &mut HashMap<String, String>,
    req_vars: &mut HashMap<String, String>,
) -> Result<(), ResStop> {
    let (hdrs, status, status_msg) = head;
    req_vars.retain(|k, _| !k.starts_with("req."));
    CURRENT_VARS.with(|v| v.borrow_mut().retain(|k, _| !k.starts_with("req.")));
    let order: &[usize] = if fe_idx == be_idx { &[be_idx] } else { &[be_idx, fe_idx] };
    for &px in order {
        let rules = proxies[px].http_after_res_rules.iter().map(|r| (ResOp::of_after_res(&r.action), r.cond.as_ref(), 0));
        // `http-after-response capture` writes the frontend's slots, whichever proxy the rule is in.
        let fe_slots = &proxies[fe_idx].res_capture_slots;
        let caps = res_caps.as_deref_mut().filter(|_| !fe_slots.is_empty()).map(|c| (c, &fe_slots[..]));
        run_res_rules(rules, &proxies[px].acls, (&mut *hdrs, &mut *status, &mut *status_msg), ctx, caps, registry, sess_vars, req_vars, None)?;
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
/// A stats page answer, with the `http-after-response` rules of its frontend and backend
/// applied as they are to any other response.
fn stats_write_reply(entry: &mut SessionEntry, proxies: &[Proxy], raw: &[u8]) {
    let (fe, be) = (entry.proxy_idx, entry.backend_idx);
    // The page is streamed by the applet, not held in the HTX message the rules edit: they
    // see the head alone.
    let head_len = crate::proxy::find_eoh(raw).map_or(raw.len(), |(h, e)| h + e);
    match after_res_on_reply(&mut entry.sess, proxies, fe, be, &raw[..head_len]) {
        Ok(head) => {
            let mut out = head.into_owned();
            out.extend_from_slice(&raw[head_len..]);
            entry.sess.write_reply(&out);
        }
        // A rule that fails (strict mode, a rewrite that does not fit) makes the reply the 500
        // page, as it does any other (`http_reply_and_close`).
        Err(()) => reply_error(entry, proxies, 500),
    }
}

fn send_proxy_reply(sess: &mut TcpSession, proxies: &[Proxy], fe_idx: usize, be_idx: usize, raw: &[u8]) {
    if let Ok(out) = after_res_on_reply(sess, proxies, fe_idx, be_idx, raw) {
        sess.write_reply(&out);
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
    let Some((hdr_end, eoh_len, version, mut status, mut reason, mut hdrs)) = parsed else {
        return Ok(Cow::Borrowed(raw));
    };

    CURRENT_RES_STATUS.set(status);
    CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
    res_htx_init(sess.bufsize, None, &version, &reason, &hdrs, raw.len() - hdr_end - eoh_len);
    // The variables are the session's own, in `CURRENT_VARS` for the run that makes the
    // reply (`step_stream`).
    let mut sess_vars = std::mem::take(&mut sess.sess_vars);
    let mut req_vars = std::mem::take(&mut sess.req_vars);
    let mut res_caps = std::mem::take(&mut sess.log.res_captures);
    let res_caps_in = res_caps.clone();
    let stick = StickView::new(proxies, &sess.tracked_sc);
    let result = {
        // The reply is the proxy's own, and the rules read the same state they read on a server's.
        let view = ProxiesView(proxies);
        let stick = StickView::new(proxies, &sess.tracked_sc);
        let ctx = SampleContext {
            proxies: Some(&view),
            stick: Some(&stick),
            prio: (sess.log.prio_class, sess.log.prio_offset),
            client_addr: sess.client_addr,
            server_addr: sess.server_addr,
            fc_src: sess.fc_src,
            so_name: sess.so_name.as_deref(),
            so_id: sess.so_id,
            fc_dst: sess.fc_dst,
            is_first_req: sess.is_first_req,
            proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            ssl_fc: sess.cli_xprt.ssl_facts(),
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
            accept_date: Some(sess.log.date),
            stream: Some(stream_facts(sess, Some(status))),
            captures_req_hdr: Some(&sess.log.req_captures),
            captures_res_hdr: Some(&res_caps_in),
            ..Default::default()
        };
        eval_after_res_rules(
            proxies,
            fe_idx,
            be_idx,
            (&mut hdrs, &mut status, &mut reason),
            &ctx,
            Some(&mut res_caps),
            sample_registry(),
            &mut sess_vars,
            &mut req_vars,
        )
    };
    sess.sess_vars = sess_vars;
    sess.req_vars = req_vars;
    sess.log.res_captures = res_caps;
    CURRENT_RES_STATUS.set(0);
    CURRENT_RES_HEADERS.with(|h| h.borrow_mut().clear());
    result.map_err(|_| ())?;

    let mut out = format!("{version} {status} {reason}\r\n");
    for (k, v) in &hdrs {
        let _ = write!(out, "{k}: {v}\r\n");
    }
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
            Some(ibex_config::ErrorPageSource::Raw(bytes)) => return Some(bytes.clone()),
            Some(ibex_config::ErrorPageSource::Custom { content_type, lf_string }) => {
                let ctx = SampleContext {
                    proxies: Some(&ProxiesView(proxies)),
                    client_addr: sess.client_addr,
                    fc_src: sess.fc_src,
                    so_name: sess.so_name.as_deref(),
                    so_id: sess.so_id,
                    fc_dst: sess.fc_dst,
                    is_first_req: sess.is_first_req,
                    ssl_fc: sess.cli_xprt.ssl_facts(),
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
                    lf_string.as_deref(),
                    &ctx,
                    sample_registry(),
                ));
            }
            Some(ibex_config::ErrorPageSource::DefaultErrorfiles) | None => {}
        }
        proxy.error_files.get(&status).cloned()
    };
    own(be)
        .or_else(|| own(fe))
        .or_else(|| builtin_error_page(status).map(<[u8]>::to_vec))
        .unwrap_or_else(|| ibex_proto::build_synthetic_response(status, None, None))
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
        lf_string: Option<&'a str>,
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
    lf_string: Option<&'a String>,
) -> ResolvedErrorBody<'a> {
    match error_page {
        None => ResolvedErrorBody::Custom {
            content_type: content_type.map(String::as_str),
            lf_string: lf_string.map(String::as_str),
        },
        Some(ibex_config::ErrorPageSource::Raw(bytes)) => ResolvedErrorBody::Raw(bytes.as_slice()),
        Some(ibex_config::ErrorPageSource::Custom { content_type, lf_string }) => ResolvedErrorBody::Custom {
            content_type: content_type.as_deref(),
            lf_string: lf_string.as_deref(),
        },
        Some(ibex_config::ErrorPageSource::DefaultErrorfiles) => {
            for proxy in [be, fe] {
                match proxy.error_replies.get(&status) {
                    Some(ibex_config::ErrorPageSource::Raw(bytes)) => return ResolvedErrorBody::Raw(bytes.as_slice()),
                    Some(ibex_config::ErrorPageSource::Custom { content_type, lf_string }) => {
                        return ResolvedErrorBody::Custom {
                            content_type: content_type.as_deref(),
                            lf_string: lf_string.as_deref(),
                        };
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
            ResolvedErrorBody::Custom { content_type: None, lf_string: None }
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
    lf_string: Option<&str>,
    ctx: &SampleContext,
    registry: &Registry,
) -> Vec<u8> {
    let mut custom_headers: Vec<(String, String)> = Vec::new();
    let mut body_str = String::new();

    if let Some(s) = lf_string {
        let mut rest = s;
        while let Some(stripped) = rest.strip_prefix("\0HDR:") {
            if let Some((line, r)) = stripped.split_once('\n') {
                if let Some((k, v)) = line.split_once(':') {
                    let formatted_v = format_sample_string(v, ctx, registry);
                    custom_headers.push((k.to_string(), formatted_v));
                }
                rest = r;
            } else {
                break;
            }
        }
        if let Some(b) = rest.strip_prefix("\0BODY:") {
            body_str = format_sample_string(b, ctx, registry);
        } else if !rest.starts_with('\0') {
            body_str = format_sample_string(rest, ctx, registry);
        }
    }

    // The config's escapes were decoded once, when it was read (`parse_line`); a second
    // pass would turn a literal `\\n` into a newline, which `HAProxy` does not.
    let body = body_str.as_bytes();

    let reason = status_reason(status);
    let mut resp = format!("HTTP/1.1 {status} {reason}\r\n");
    if let Some(ct) = content_type {
        let _ = write!(resp, "Content-Type: {ct}\r\n");
    }
    for (k, v) in custom_headers {
        if !v.is_empty() {
            let _ = write!(resp, "{k}: {v}\r\n");
        }
    }
    let _ = write!(resp, "Content-Length: {}\r\n\r\n", body.len());

    let mut full_resp = resp.into_bytes();
    full_resp.extend_from_slice(body);
    full_resp
}

#[cfg(test)]
mod registry_tests {
    use super::{
        build_sample_registry,
        CURRENT_RES_STATUS, CURRENT_VARS,
    };
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
            v.borrow_mut().insert("txn.probe".to_string(), "seen".to_string())
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
            super::inject_connection_token_zero_alloc(&mut b, tok);
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

#[cfg(test)]
mod rate_ctr_tests {
    use super::RateCtr;

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
