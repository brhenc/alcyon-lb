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
use crate::proxy_state::ProxiesView;
use crate::syslog::SyslogTarget;
use ibex_config::LogLevel;
use crate::txn::MsgState;
use crate::proxy::{TcpSession, Timeouts};
use crate::raw;
use ibex_config::{regex, BalanceAlgorithm, Config, Mode, StickRule, UseBackendRule};
use ibex_proto::endpoint::ScState;
use ibex_sample::{Expr, Registry, Sample, SampleContext};
use ibex_sched::task::{state, Kind, TaskRef, WorkKind};
use ibex_sched::{Class, Dispatch, Outcome, Scheduler, Tick};
use ibex_stick_table::{KeyType, StickKey, StickTable, StickTableConfig};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
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
    set_proc_var, CURRENT_RES_HEADERS, CURRENT_RES_STATUS, CURRENT_TIMEOUTS, CURRENT_VARS,
};

thread_local! {
    /// What the engine's ticks count from, on this thread: set by every `step`, read by
    /// [`fresh_tick`].
    static TICK_EPOCH: Cell<Option<Instant>> = const { Cell::new(None) };
    pub static WORKER_ID: Cell<usize> = const { Cell::new(0) };
    static STRICT_MODE: Cell<bool> = const { Cell::new(true) };
    static REWRITE_ADDED_BYTES: Cell<usize> = const { Cell::new(0) };
    static MAX_REWRITE_LIMIT: Cell<usize> = const { Cell::new(8192) };
    /// The response being rewritten by `http-response`/`http-after-response`, as the HTX
    /// message `HAProxy` holds it in: (bytes in use, size). See [`res_htx_init`].
    static RES_HTX: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
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

/// Accumulated statistics per proxy.
#[derive(Default, Debug)]
pub struct ProxyStats {
    pub cum_conn: AtomicU64,
    pub act_conn: AtomicU32,
    pub max_conn: AtomicU32,
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

impl ProxyStats {
    pub fn clear(&self) {
        self.cum_conn.store(0, Ordering::Relaxed);
        let act = self.act_conn.load(Ordering::Relaxed);
        self.max_conn.store(act, Ordering::Relaxed);
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




/// A configured proxy instance.
#[derive(Debug, Clone)]
// More than three bools, and they are genuinely independent switches rather than a state
// machine: PROXY protocol on accept, v2 on accept, and the two logging options. Grouping
// them into an enum would model a relationship that does not exist.
#[allow(clippy::struct_excessive_bools)]
pub struct Proxy {
    pub id: u32,
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
    pub maxconn: u32,
    pub dispatch: Option<SocketAddr>,
    /// The `cookie` line (`ck_opts`, `cookie_*`): persistence by a cookie. Only a backend
    /// (or a `listen`) has one.
    pub cookie: Option<ibex_config::CookieConfig>,
    pub cliexp: Vec<ibex_proto::CompiledExp>,
    pub srvexp: Vec<ibex_proto::CompiledExp>,
    pub servers: Vec<SocketAddr>,
    pub server_ids: Vec<String>,
    /// Each server's persistence cookie value (`server ... cookie <value>`). A server
    /// without one is never chosen by a cookie, not even by its name.
    pub server_cookies: Vec<Option<String>>,
    pub server_statuses: Arc<Vec<AtomicU8>>,
    pub server_weights: Vec<u32>,
    pub next_server_idx: Arc<AtomicUsize>,
    pub stats: Arc<Vec<ProxyStats>>,
    pub stats_config: ibex_config::StatsConfig,
    pub default_backend: Option<String>,
    pub use_backends: Vec<UseBackendRule>,
    pub monitor_uri: Option<String>,
    pub acls: HashMap<String, Expr>,
    pub stick_table: Option<Arc<StickTable>>,
    pub stick_rules: Vec<StickRule>,
    pub accept_proxy: bool,
    pub accept_proxy_v2: bool,
    pub server_send_proxy: Vec<bool>,
    pub server_send_proxy_v2: Vec<bool>,
    /// `proxy-v2-options unique-id`, per server.
    pub server_pp_unique_id: Vec<bool>,
    pub server_backups: Vec<bool>,
    pub server_maxconn: Vec<Option<u32>>,
    pub server_actconn: Arc<Vec<AtomicU32>>,
    pub server_check_configs: Vec<Option<ServerCheckConfig>>,
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
}

impl Proxy {
    /// Returns the indices of eligible servers for request routing.
    ///
    /// Active (non-backup) servers that are UP and not saturated (actconn < maxconn) are prioritized.
    /// If at least one active server is available, only active servers are returned (backup servers receive 0 traffic).
    /// If all active servers are DOWN (or saturated), returns the first available backup alone.
    /// If no servers are available, returns an empty vector.
    #[must_use]
    pub fn eligible_server_indices(&self) -> Vec<usize> {
        let is_server_available = |idx: usize| -> bool {
            if idx >= self.servers.len() {
                return false;
            }
            if let Some(status) = self.server_statuses.get(idx) {
                if status.load(Ordering::Relaxed) != ServerStatus::Up as u8 {
                    return false;
                }
            } else {
                return false;
            }
            if let Some(Some(mc)) = self.server_maxconn.get(idx) {
                if *mc > 0 {
                    let act = self.server_actconn.get(idx).map(|a| a.load(Ordering::Relaxed)).unwrap_or(0);
                    if act >= *mc {
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
                !is_backup && is_server_available(idx)
            })
            .collect();

        if !active_up.is_empty() {
            return active_up;
        }

        // 2. No active server: the first usable backup alone (`lbprm.fbck`).
        crate::lb::first_backup(self).into_iter().collect()
    }

    /// Selects the target backend server using the configured load balancing algorithm,
    /// preferring primary servers over backup servers,
    /// or falls back to the dispatch address if all servers are down or absent.
    #[must_use]
    pub fn select_server(&mut self) -> Option<SocketAddr> {
        if self.servers.is_empty() {
            return self.dispatch;
        }
        match self.balance {
            BalanceAlgorithm::Leastconn => {
                if let Some(idx) = crate::lb::leastconn(self) {
                    Some(self.servers[idx])
                } else {
                    self.dispatch
                }
            }
            BalanceAlgorithm::StaticRr => {
                if let Some(idx) = crate::lb::static_rr(self) {
                    Some(self.servers[idx])
                } else {
                    self.dispatch
                }
            }
            BalanceAlgorithm::First => {
                if let Some(idx) = crate::lb::first(self) {
                    Some(self.servers[idx])
                } else {
                    self.dispatch
                }
            }
            BalanceAlgorithm::Random(draws) => {
                if let Some(idx) = crate::lb::random(self, draws) {
                    Some(self.servers[idx])
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
                Some(self.servers[chosen_idx])
            }
        }
    }

    /// Selects the target backend server with load balancing algorithm (Source IP hash or round-robin),
    /// respecting backup failover and connection limits.
    #[must_use]
    pub fn select_server_with_key(&mut self, source_ip: Option<IpAddr>, uri: Option<&str>) -> Option<SocketAddr> {
        if self.servers.is_empty() {
            return self.dispatch;
        }
        match self.balance {
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
                    return Some(self.servers[chosen_idx]);
                }
                let chosen_idx = eligible[self.next_server_idx.fetch_add(1, Ordering::Relaxed) % eligible.len()];
                Some(self.servers[chosen_idx])
            }
            BalanceAlgorithm::Uri => {
                let u = uri.unwrap_or("/");
                if let Some(idx) = crate::lb::balance_uri(self, u) {
                    Some(self.servers[idx])
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
    /// A finished transaction's log line, waiting to be sent to its frontend's targets.
    pub log_line: Option<String>,
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
    pub proxies: Vec<Proxy>,
    pub checks: Vec<ServerCheckState>,
    pub sessions: SessionArena,
    pub applets: AppletArena,
    pub cli_listener: Option<UnixListener>,
    pub cli_socket_path: Option<PathBuf>,
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
    pub idle_backend_pool: HashMap<SocketAddr, Vec<OwnedFd>>,
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
}

impl Drop for Engine {
    fn drop(&mut self) {
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
fn listeners_for(worker_id: usize, addr: SocketAddr, proxy: u32) -> io::Result<Vec<Listener>> {
    let mut out = Vec::new();
    for fd in crate::handover::take_inherited(worker_id, addr) {
        match Listener::adopt(fd, addr, 128, proxy) {
            Ok(l) => out.push(l),
            Err(e) => eprintln!("[WARNING] {e}; binding a fresh socket instead"),
        }
    }
    if out.is_empty() {
        out.push(Listener::bind(addr, 128, proxy)?);
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

/// `HAProxy`'s predefined ACLs (`default_acl_list`, src/acl.c), by name. `RDP_COOKIE`
/// (`req.rdp_cookie_cnt`) and `WAIT_END` (`wait_end`) are missing: Ibex has neither fetch.
const PREDEFINED_ACLS:&[(&str, &str)] = &[
    ("TRUE", "always_true"),
    ("FALSE", "always_false"),
    ("LOCALHOST", "src 127.0.0.1/8 ::1"),
    ("HTTP", "req.proto_http"),
    ("HTTP_1.0", "req.ver 1.0"),
    ("HTTP_1.1", "req.ver 1.1"),
    ("HTTP_2.0", "req.ver 2.0"),
    ("HTTP_3.0", "req.ver 3.0"),
    ("METH_CONNECT", "method CONNECT"),
    ("METH_DELETE", "method DELETE"),
    ("METH_GET", "method GET HEAD"),
    ("METH_HEAD", "method HEAD"),
    ("METH_OPTIONS", "method OPTIONS"),
    ("METH_POST", "method POST"),
    ("METH_PUT", "method PUT"),
    ("METH_TRACE", "method TRACE"),
    ("HTTP_URL_ABS", "url -m reg ^[^/:]*://"),
    ("HTTP_URL_SLASH", "url -m beg /"),
    ("HTTP_URL_STAR", "url *"),
    ("HTTP_CONTENT", "req.hdr_val(content-length) gt 0"),
    ("REQ_CONTENT", "req.len gt 0"),
];

/// A proxy's ACLs by name: the predefined ones, then its own (`find_acl_by_name` is
/// searched before `find_acl_default`, so an ACL of the same name replaces one).
fn compile_acls(acl_rules: &[ibex_config::AclRule]) -> HashMap<String, Expr> {
    let mut acls: HashMap<String, Expr> = PREDEFINED_ACLS
        .iter()
        .filter_map(|&(name, expr)| Some((name.to_string(), Expr::parse(expr).ok()?)))
        .collect();
    // A name declared on several lines is one ACL matching if any line does; the first of
    // them replaces a predefined ACL of that name.
    let mut own: HashSet<&str> = HashSet::new();
    for (rule, expr) in acl_rules.iter().filter_map(|r| Some((r, Expr::parse(&r.expr).ok()?))) {
        match acls.get_mut(&rule.name) {
            Some(first) if own.contains(rule.name.as_str()) => first.alternates.push(expr),
            _ => {
                own.insert(rule.name.as_str());
                acls.insert(rule.name.clone(), expr);
            }
        }
    }
    acls
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

    for field in &ast.store_fields {
        if field.starts_with("conn_rate") {
            track_conn_rate_ms = Some(10_000);
        } else if field.starts_with("http_req_rate") {
            track_http_req_rate_ms = Some(10_000);
        } else if field.starts_with("http_err_rate") {
            track_http_err_rate_ms = Some(10_000);
        }
    }

    let config = StickTableConfig {
        name: name.to_string(),
        key_type,
        max_size: ast.size,
        expire: ast.expire,
        flags: ibex_stick_table::table::TrackFlags {
            conn_cnt: true,
            conn_cur: true,
            http_req_cnt: true,
            http_err_cnt: true,
            bytes_in_cnt: true,
            bytes_out_cnt: true,
            gpc0: true,
        },
        track_conn_rate_ms,
        track_http_req_rate_ms,
        track_http_err_rate_ms,
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
        rules.insert(0, ibex_config::HttpReqRule { action, cond: None });
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
fn capture_values<'a>(slots: impl Iterator<Item = (&'a str, usize)>, headers: &[(&str, &str)]) -> Vec<Option<Vec<u8>>> {
    slots
        .map(|(name, len)| {
            // A slot no header fills (`declare capture`, a rule's) has no name.
            if name.is_empty() {
                return None;
            }
            headers.iter().rev().find(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| cut_at(v.trim(), len).to_vec())
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
        let headers: Vec<(&str, &str)> = entry.sess.htx_slice().map(|htx| htx.headers().collect()).unwrap_or_default();
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
            let ctx = stream_sample_ctx(&entry.sess, fe, fe, &view);
            fmt.render(&data, sample_registry(), &ctx)
        };
        if let Some(h) = fe.unique_id_header.as_deref() {
            entry.sess.req.inject_http_header(&h.to_ascii_lowercase(), &id);
        }
        entry.sess.log.unique_id = Some(id);
    }
}

/// The sample context a log line's `%[...]` reads.
fn stream_sample_ctx<'a>(s: &'a TcpSession, fe: &'a Proxy, be: &'a Proxy, view: &'a ProxiesView<'a>) -> SampleContext<'a> {
    SampleContext {
        proxies: Some(view),
        client_addr: s.client_addr,
        server_addr: s.server_addr,
        fc_src: s.fc_src,
        fc_dst: s.fc_dst,
        is_first_req: s.is_first_req,
        proxy_tlvs: s.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        htx_slice: s.htx_slice(),
        req_uri: s.req_uri.as_deref(),
        req_method: s.req_method.as_deref(),
        req_headers: s.req_headers.as_deref(),
        fe_name: Some(&fe.name),
        be_name: Some(&be.name),
        captures_req_hdr: Some(&s.log.req_captures),
        captures_res_hdr: Some(&s.log.res_captures),
        unique_id: s.log.unique_id.as_deref(),
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

/// What the session alone knows, before (or without) a server: what `unique-id-format`
/// reads when a TCP stream's PROXY header is built at connect.
fn session_log_data<'a>(s: &'a TcpSession, fe: &'a Proxy, be: &'a Proxy, pid: u32) -> crate::logfmt::LogData<'a> {
    let l = &s.log;
    let sum = |p: &Proxy| p.stats.iter().map(|st| u64::from(st.act_conn.load(Ordering::Relaxed))).sum::<u64>();
    crate::logfmt::LogData {
        client: s.client_addr,
        frontend_addr: s.server_addr,
        frontend: &fe.name,
        frontend_ssl: s.cli_xprt.is_tls(),
        backend: &be.name,
        backend_http: be.mode == Mode::Http,
        accept_date: l.date,
        t_handshake: 0,
        t_idle: l.ms(l.first_byte),
        t_request: l.ms(l.request),
        t_queue: l.ms(l.queue),
        t_connect: l.ms(l.connect),
        t_data: l.ms(l.data),
        t_close: l.ms(Some(std::time::Instant::now())),
        status: s.txn.as_ref().map(|t| t.status).or(l.status).map_or(-1, i64::from),
        bytes_out: l.bytes_from_server,
        // A request that never parsed counts nothing (`HAProxy`: `U=0` with `<BADREQ>`).
        bytes_in: if s.mode == Mode::Http && l.request.is_none() {
            0
        } else {
            s.bytes_in.saturating_sub(l.bytes_in_at_start)
        },
        // `%tsc`'s cookie characters: only a backend with a cookie mode shows them.
        cookie_state: match (&be.cookie, s.txn.as_ref()) {
            (Some(c), Some(t)) if c.rewrite || c.indirect || c.insert || c.prefix => t.ck.log_chars(),
            _ => *b"--",
        },
        actconn: sum(fe),
        feconn: sum(fe),
        retries: i64::from(s.max_retries.saturating_sub(s.conn_retries)),
        uniq_id: l.uniq_id,
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

/// The stream's log line, when its frontend logs (`HAProxy` logs nothing without a
/// `log` target).
fn stream_log_line(entry: &SessionEntry, proxies: &[Proxy], pid: u32) -> Option<String> {
    let fe = &proxies[entry.proxy_idx];
    let fmt = fe.log_format.as_ref()?;
    if fe.log_target_idx.is_empty() {
        return None;
    }
    let be = proxies.get(entry.backend_idx).unwrap_or(fe);
    let line = fmt.render(&stream_log_data(entry, proxies, entry.proxy_idx, pid), sample_registry(), &SampleContext { at_log: true, ..stream_sample_ctx(&entry.sess, fe, be, &ProxiesView(proxies)) });
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
    let defaults: Vec<usize> = config
        .defaults
        .iter()
        .flat_map(|d| d.logs.iter())
        .map(|c| intern(c, &mut targets))
        .collect();
    let defaults_log_global = config.defaults.as_ref().is_some_and(|d| d.log_global);
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

    for proxy in proxies.iter_mut() {
        let Some((_, idx, log_global)) = own.iter().find(|(n, _, _)| *n == proxy.name) else {
            continue;
        };
        let mut resolved = idx.clone();
        if *log_global {
            resolved.extend_from_slice(&global);
        }
        // `defaults` applies only where the section declared nothing of its own, which
        // is how every other defaults-inherited setting behaves.
        if resolved.is_empty() && defaults_log_global {
            resolved.extend_from_slice(&global);
        }
        if resolved.is_empty() {
            resolved.extend_from_slice(&defaults);
        }
        resolved.sort_unstable();
        resolved.dedup();
        // Kept when already there: each worker resolves again (the targets own sockets
        // and are per engine), and the cursors must stay the ones the workers share.
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
fn init_proxy_from_listen(proxy_idx: usize, listen: &ibex_config::ListenSection, nbthread: usize) -> Proxy {
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
            server_check_configs.push(Some(cfg));
        } else {
            server_check_configs.push(None);
        }
    }

    Proxy {
        id: usize_to_u32(proxy_idx),
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
        maxconn: listen.maxconn,
        dispatch: listen.dispatch,
        cookie: listen.cookie.clone(),
        cliexp,
        srvexp,
        servers: listen.servers.iter().map(|s| s.addr).collect(),
        server_ids: listen.servers.iter().map(|s| s.id.clone()).collect(),
        server_cookies: listen.servers.iter().map(|s| s.cookie.clone()).collect(),
        server_statuses: Arc::new((0..server_count).map(|_| AtomicU8::new(ServerStatus::Up as u8)).collect()),
        server_weights: listen
            .servers
            .iter()
            .map(|s| s.weight.unwrap_or(1))
            .collect(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new((0..nbthread).map(|_| ProxyStats::default()).collect()),
        stats_config: {
            let mut sc = listen.stats.clone();
            sc.raw_timeouts = listen.timeouts;
            sc.forwardfor.clone_from(&listen.forwardfor);
            sc.originalto.clone_from(&listen.originalto);
            sc
        },
        default_backend: listen.default_backend.clone(),
        use_backends: listen.use_backends.clone(),
        monitor_uri: listen.monitor_uri.clone(),
        acls: compile_acls(&listen.acls),
        stick_table,
        stick_rules: listen.stick_rules.clone(),
        accept_proxy: listen.accept_proxy,
        accept_proxy_v2: listen.accept_proxy_v2,
        server_send_proxy: listen.servers.iter().map(|s| s.send_proxy).collect(),
        server_send_proxy_v2: listen.servers.iter().map(|s| s.send_proxy_v2).collect(),
        server_pp_unique_id: listen.servers.iter().map(|s| s.proxy_v2_unique_id).collect(),
        server_backups: listen.servers.iter().map(|s| s.backup).collect(),
        server_maxconn: listen.servers.iter().map(|s| s.maxconn).collect(),
        server_actconn: Arc::new((0..server_count).map(|_| AtomicU32::new(0)).collect()),
        server_check_configs,
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
        unique_id_format: listen.unique_id_format.as_deref().and_then(compile_unique_id_format),
        unique_id_header: listen.unique_id_header.clone(),
        req_capture_slots,
        res_capture_slots: listen.res_header_captures.iter().map(|c| (c.name.clone(), c.len)).collect(),
        log_count: Arc::default(),
        log_cursors: Arc::default(),
        hash_type: listen.hash_type.unwrap_or_default(),
        hash_preserve_affinity: listen.hash_preserve_affinity.unwrap_or_default(),
        chash: Arc::default(),
    }
}

fn init_proxy_from_frontend(proxy_idx: usize, fe: &ibex_config::FrontendSection, nbthread: usize) -> Proxy {
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
        maxconn: fe.maxconn,
        dispatch: None,
        cookie: None,
        cliexp,
        srvexp: Vec::new(),
        servers: Vec::new(),
        server_ids: Vec::new(),
        server_cookies: Vec::new(),
        server_statuses: std::sync::Arc::new(Vec::new()),
        server_weights: Vec::new(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new((0..nbthread).map(|_| ProxyStats::default()).collect()),
        stats_config: {
            let mut sc = fe.stats.clone();
            sc.raw_timeouts = fe.timeouts;
            sc.forwardfor.clone_from(&fe.forwardfor);
            sc.originalto.clone_from(&fe.originalto);
            sc
        },
        default_backend: fe.default_backend.clone(),
        use_backends: fe.use_backends.clone(),
        monitor_uri: fe.monitor_uri.clone(),
        acls: compile_acls(&fe.acls),
        stick_table,
        stick_rules: fe.stick_rules.clone(),
        accept_proxy: fe.accept_proxy || fe.binds.iter().any(|b| b.accept_proxy),
        accept_proxy_v2: fe.accept_proxy_v2 || fe.binds.iter().any(|b| b.accept_proxy_v2),
        server_send_proxy: Vec::new(),
        server_send_proxy_v2: Vec::new(),
        server_pp_unique_id: Vec::new(),
        server_backups: Vec::new(),
        server_maxconn: Vec::new(),
        server_actconn: std::sync::Arc::new(Vec::new()),
        server_check_configs: Vec::new(),
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
        unique_id_format: fe.unique_id_format.as_deref().and_then(compile_unique_id_format),
        unique_id_header: fe.unique_id_header.clone(),
        req_capture_slots,
        res_capture_slots: fe.res_header_captures.iter().map(|c| (c.name.clone(), c.len)).collect(),
        log_count: Arc::default(),
        log_cursors: Arc::default(),
        hash_type: ibex_config::HashType::default(),
        hash_preserve_affinity: ibex_config::HashPreserveAffinity::default(),
        chash: Arc::default(),
    }
}

fn init_proxy_from_backend(proxy_idx: usize, be: &ibex_config::BackendSection, nbthread: usize) -> Proxy {
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
            server_check_configs.push(Some(cfg));
        } else {
            server_check_configs.push(None);
        }
    }

    Proxy {
        id: usize_to_u32(proxy_idx),
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
        maxconn: 2000,
        dispatch: be.dispatch,
        cookie: be.cookie.clone(),
        cliexp: Vec::new(),
        srvexp,
        servers: be.servers.iter().map(|s| s.addr).collect(),
        server_ids: be.servers.iter().map(|s| s.id.clone()).collect(),
        server_cookies: be.servers.iter().map(|s| s.cookie.clone()).collect(),
        server_statuses: Arc::new((0..server_count).map(|_| AtomicU8::new(ServerStatus::Up as u8)).collect()),
        server_weights: be.servers.iter().map(|s| s.weight.unwrap_or(1)).collect(),
        next_server_idx: Arc::new(AtomicUsize::new(0)),
        stats: Arc::new((0..nbthread).map(|_| ProxyStats::default()).collect()),
        stats_config: {
            let mut sc = be.stats.clone();
            sc.raw_timeouts = be.timeouts;
            sc.forwardfor.clone_from(&be.forwardfor);
            sc.originalto.clone_from(&be.originalto);
            sc
        },
        default_backend: None,
        use_backends: Vec::new(),
        monitor_uri: None,
        acls: compile_acls(&be.acls),
        stick_table,
        stick_rules: be.stick_rules.clone(),
        accept_proxy: false,
        accept_proxy_v2: false,
        server_send_proxy: be.servers.iter().map(|s| s.send_proxy).collect(),
        server_send_proxy_v2: be.servers.iter().map(|s| s.send_proxy_v2).collect(),
        server_pp_unique_id: be.servers.iter().map(|s| s.proxy_v2_unique_id).collect(),
        server_backups: be.servers.iter().map(|s| s.backup).collect(),
        server_maxconn: be.servers.iter().map(|s| s.maxconn).collect(),
        server_actconn: Arc::new((0..server_count).map(|_| AtomicU32::new(0)).collect()),
        server_check_configs,
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
        unique_id_format: be.unique_id_format.as_deref().and_then(compile_unique_id_format),
        unique_id_header: be.unique_id_header.clone(),
        req_capture_slots: Arc::from([]),
        res_capture_slots: Arc::from([]),
        log_count: Arc::default(),
        log_cursors: Arc::default(),
        hash_type: be.hash_type.unwrap_or_default(),
        hash_preserve_affinity: be.hash_preserve_affinity.unwrap_or_default(),
        chash: Arc::default(),
    }
}

fn init_checks(proxies: &[Proxy], scheduler: &mut Scheduler, now: Tick) -> Vec<ServerCheckState> {
    let mut checks = Vec::new();
    for (proxy_idx, proxy) in proxies.iter().enumerate() {
        for (server_idx, &srv_addr) in proxy.servers.iter().enumerate() {
            let Some(check_cfg) = proxy
                .server_check_configs
                .get(server_idx)
                .and_then(Clone::clone)
            else {
                continue;
            };
            let mut check = ServerCheckState::new(proxy_idx, server_idx, srv_addr, check_cfg, now);
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

fn init_global_vars(global: Option<&ibex_config::GlobalSection>) {
    if let Some(global) = global {
        let sample_reg = sample_registry();
        let sample_ctx = SampleContext::default();
        for set_var in &global.set_vars {
            let val = if set_var.is_fmt {
                format_sample_string(&set_var.expr, &sample_ctx, sample_reg)
            } else if let Ok(e) = Expr::parse(&set_var.expr) {
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
    pub fn build_shared_state(config: &Config, nbthread: usize) -> io::Result<Vec<Proxy>> {
    // An action naming a fetch or converter the registry lacks would load and then do
    // nothing on every request; `HAProxy` refuses the configuration instead.
    crate::rule_exprs::validate_config(config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut proxies = Vec::new();
    for listen in &config.listens {
        if !listen.disabled { proxies.push(init_proxy_from_listen(proxies.len(), listen, nbthread)); }
    }
    for backend in &config.backends {
        if !backend.disabled { proxies.push(init_proxy_from_backend(proxies.len(), backend, nbthread)); }
    }
    for frontend in &config.frontends {
        if !frontend.disabled { proxies.push(init_proxy_from_frontend(proxies.len(), frontend, nbthread)); }
    }
    let _ = resolve_log_targets(config, &mut proxies);
    Ok(proxies)
}

pub fn new(config: &Config, capacity: usize) -> io::Result<Self> {
        let proxies = Self::build_shared_state(config, 1)?;
        Self::new_worker(config, capacity, 0, proxies)
    }

    pub fn new_worker(config: &Config, capacity: usize, worker_id: usize, mut proxies: Vec<Proxy>) -> io::Result<Self> {
        WORKER_ID.with(|id| id.set(worker_id));
        let poller = Poller::new(capacity)?;
        let mut scheduler = Scheduler::with_capacity(capacity);
        let mut fdtab = FdTab::with_capacity(capacity * 2);
        let sessions = SessionArena::with_capacity(capacity);
        let applets = AppletArena::with_capacity(capacity);

        init_global_vars(config.global.as_ref());
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
                    addr: listen.addr,
                    quic: false,
                    ssl: false,
                    crt: vec![],
                    alpn: vec![],
                    proto: None,
                    accept_proxy: listen.accept_proxy,
                    accept_proxy_v2: listen.accept_proxy_v2,
                }]
            } else {
                listen.binds.clone()
            };
            for b in &binds {
                let tls = bind_tls(&listen.name, &binds, b.addr)?;
                for mut listener in listeners_for(worker_id, b.addr, usize_to_u32(proxy_idx))? {
                    listener.maxconn = listen.maxconn;
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
            let mut all_binds = frontend.binds.clone();
            if let Some(ba) = frontend.bind {
                if !all_binds.iter().any(|b| b.addr == ba) {
                    all_binds.insert(0, ibex_config::ast::BindConfig {
                        addr: ba,
                        quic: false,
                        ssl: false,
                        crt: vec![],
                        alpn: vec![],
                        proto: None,
                        accept_proxy: frontend.accept_proxy,
                        accept_proxy_v2: frontend.accept_proxy_v2,
                    });
                }
            }
            for b in &all_binds {
                let bind_addr = b.addr;
                if b.quic {
                    let tls = bind_tls(&frontend.name, &frontend.binds, bind_addr)?.expect("QUIC requires TLS");
                    
                    let mut be_addr = None;
                    if let Some(be_name) = &frontend.default_backend {
                        if let Some(be) = config.backends.iter().find(|b| b.name == *be_name) {
                            be_addr = be.servers.first().map(|s| s.addr).or(be.dispatch);
                        }
                    }
                    
                    let mut ql = crate::quic_listener::QuicListener::bind(bind_addr, &tls, None)?;
                    if let Some(addr) = be_addr {
                        ql.set_backend(addr);
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
                } else {
                    let tls = bind_tls(&frontend.name, &frontend.binds, bind_addr)?;
                    for mut listener in listeners_for(worker_id, bind_addr, usize_to_u32(proxy_idx))? {
                        listener.maxconn = frontend.maxconn;
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

        let log_targets = resolve_log_targets(config, &mut proxies);

        let start_time = Instant::now();
        let now = Tick(1);
        
        let checks = if worker_id == 0 {
            init_checks(&proxies, &mut scheduler, now)
        } else {
            Vec::new()
        };


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
            idle_backend_pool: HashMap::new(),
            lifecycle: None,
            stopping: false,
            hard_stop_after: config.global.as_ref().and_then(|g| g.hard_stop_after),
            stop_deadline: None,
            cli_socket_ident: None,
        })
    }

    /// Binds a Unix domain socket for CLI / `hatop` inspection.
    ///
    /// # Errors
    /// Returns an error if binding or setting non-blocking mode fails.
    pub fn bind_cli_socket<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let path_buf = path.as_ref().to_path_buf();
        let _ = std::fs::remove_file(&path_buf);
        let listener = UnixListener::bind(&path_buf)?;
        listener.set_nonblocking(true)?;
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
        let max_conns: u32 = self.proxies.iter().map(|p| p.maxconn).sum();
        crate::stats::format_show_info(
            self.start_time,
            pid,
            self.scheduler.live_tasks(),
            self.scheduler.run_queue_len(),
            active_conns,
            max_conns,
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
        let mut to_add: Vec<(usize, RawFd)> = Vec::new();
        for (idx, ql) in self.quic_listeners.iter().enumerate() {
            for fd in ql.backend_fds() {
                if matches!(self.fdtab.state(fd), FdState::Closed) {
                    to_add.push((idx, fd));
                }
            }
        }
        for (idx, fd) in to_add {
            let Some(ql) = self.quic_listeners.get(idx) else { continue };
            let Some(borrowed) = ql
                .backend_borrowed_fds()
                .into_iter()
                .find(|b| b.as_raw_fd() == fd)
            else {
                continue;
            };
            self.fdtab.insert(
                fd,
                FdState::QuicBackend { listener: usize_to_u32(idx) },
                Interest { readable: true, writable: true },
            );
            let _ = self.poller.add(borrowed, raw_fd_to_u64(fd), true, true);
        }
    }

    pub fn step(&mut self, now: Tick) -> io::Result<usize> {
        self.now = now;
        TICK_EPOCH.with(|e| e.set(Some(self.start_time)));

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
            if let Some(remain_ms) = next_timer.remaining(now) {
                Duration::from_millis(u64::from(remain_ms.min(100)))
            } else {
                Duration::from_millis(100)
            }
        };

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

        // 3. Poll readiness events
        let mut events = std::mem::take(&mut self.events);
        events.clear();
        self.poller.poll(Some(poll_timeout), |ev| events.push(ev))?;

        // 4. Process polled readiness events
        let mut quic_ready: Vec<usize> = Vec::new();
        for &ev in &events {
            match self.fdtab.state(ev.fd) {
                FdState::Listener { listener: l_idx } => {
                    let l_idx = l_idx as usize;
                    if l_idx < self.listeners.len() {
                        self.accept_from_listener(l_idx);
                    }
                }
                FdState::CliListener => {
                    self.accept_from_cli_listener();
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
                FdState::Closed => {}
            }
        }
        self.events = events;

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
        Ok(tasks_run)
    }

    fn accept_from_cli_listener(&mut self) {
        let Some(listener) = self.cli_listener.as_ref() else {
            return;
        };

        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    let applet = CliApplet::new(stream, self.now);
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

        let lfd = self.listeners[l_idx].raw_fd();
        if self.listeners[l_idx].is_full() {
            let _ = self.poller.modify(
                self.listeners[l_idx].borrowed_fd(),
                raw_fd_to_u64(lfd),
                false,
                false,
            );
            self.fdtab.set_interest(lfd, Interest::NONE);
            return;
        }

        while !self.listeners[l_idx].is_full() {
            let accept_res = self.listeners[l_idx].accept();
            let Some((cli_fd, peer_addr)) = (match accept_res {
                Ok(Some(pair)) => Some(pair),
                Ok(None) | Err(_) => None,
            }) else {
                break;
            };

            let mut sc_conn_rates = [0u64; 3];
            let mut tracked_sc: [Option<(usize, StickKey)>; 3] = [None, None, None];

            let sample_ctx = SampleContext {
                proxies: Some(&ProxiesView(&self.proxies)),
                client_addr: Some(peer_addr),
                server_addr: Some(self.listeners[l_idx].addr()),
                fc_src: Some(peer_addr),
                fc_dst: Some(self.listeners[l_idx].addr()),
                act_conn: self.proxies[proxy_idx].stats[worker_id()].act_conn.load(Ordering::Relaxed),
                cum_conn: self.proxies[proxy_idx].stats[worker_id()].cum_conn.load(Ordering::Relaxed),
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
                    if let Some(key) = resolve_sample_stick_key(&srule.expr, sample_registry(), &sample_ctx) {
                        if let Some(ref tbl) = self.proxies[proxy_idx].stick_table {
                            let _ = tbl.update_entry(&key, |data| {
                                data.conn_cnt += 1;
                                data.conn_cur += 1;
                                if let Some(ref mut r) = data.conn_rate {
                                    r.tick(1);
                                }
                            });
                            tracked_sc[slot] = Some((proxy_idx, key));
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
                        if let Some(key) = resolve_sample_stick_key(expr, sample_registry(), &sample_ctx) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                let _ = tbl.update_entry(&key, |data| {
                                    data.conn_cnt += 1;
                                    data.conn_cur += 1;
                                    if let Some(ref mut r) = data.conn_rate {
                                        r.tick(1);
                                    }
                                });
                                tracked_sc[0] = Some((t_idx, key));
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc1 { table, expr } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_sample_stick_key(expr, sample_registry(), &sample_ctx) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                let _ = tbl.update_entry(&key, |data| {
                                    data.conn_cnt += 1;
                                    data.conn_cur += 1;
                                    if let Some(ref mut r) = data.conn_rate {
                                        r.tick(1);
                                    }
                                });
                                tracked_sc[1] = Some((t_idx, key));
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc2 { table, expr } => {
                        let t_idx = if let Some(ref tname) = table {
                            self.proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                        } else {
                            proxy_idx
                        };
                        if let Some(key) = resolve_sample_stick_key(expr, sample_registry(), &sample_ctx) {
                            if let Some(ref tbl) = self.proxies[t_idx].stick_table {
                                let _ = tbl.update_entry(&key, |data| {
                                    data.conn_cnt += 1;
                                    data.conn_cur += 1;
                                    if let Some(ref mut r) = data.conn_rate {
                                        r.tick(1);
                                    }
                                });
                                tracked_sc[2] = Some((t_idx, key));
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Read conn_rates from tracked slots
            for (i, opt) in tracked_sc.iter().enumerate() {
                if let Some((t_idx, ref key)) = opt {
                    if let Some(ref tbl) = self.proxies[*t_idx].stick_table {
                        if let Ok(Some(data)) = tbl.get_entry(key) {
                            if let Some(ref r) = data.conn_rate {
                                sc_conn_rates[i] = r.rate();
                            }
                        }
                    }
                }
            }

            let listener_addr = self.listeners[l_idx].addr();
            let local_addr = listener_addr;

            let (client_addr, server_addr, fc_src, fc_dst) = match eval_tcp_req_conn_rules(
                &self.proxies[proxy_idx],
                &self.proxies,
                sample_registry(),
                peer_addr,
                local_addr,
                sc_conn_rates,
            ) {
                ConnEvalOutcome::Accept(c, s, fs, fd) => (c, s, fs, fd),
                ConnEvalOutcome::Reject => {
                    raw::abort_with_rst(cli_fd.as_fd());
                    self.proxies[proxy_idx].stats[worker_id()].denied_conn.fetch_add(1, Ordering::Relaxed);
                    for (t_idx, ref key) in tracked_sc.iter().flatten() {
                        if let Some(ref tbl) = self.proxies[*t_idx].stick_table {
                            let _ = tbl.update_entry(key, |data| {
                                data.conn_cur = data.conn_cur.saturating_sub(1);
                            });
                        }
                    }
                    drop(cli_fd);
                    continue;
                }
                ConnEvalOutcome::SilentDrop => {
                    raw::silent_drop(cli_fd.as_fd(), peer_addr.is_ipv6());
                    self.proxies[proxy_idx].stats[worker_id()].denied_conn.fetch_add(1, Ordering::Relaxed);
                    for (t_idx, ref key) in tracked_sc.iter().flatten() {
                        if let Some(ref tbl) = self.proxies[*t_idx].stick_table {
                            let _ = tbl.update_entry(key, |data| {
                                data.conn_cur = data.conn_cur.saturating_sub(1);
                            });
                        }
                    }
                    drop(cli_fd);
                    continue;
                }
            };

            self.listeners[l_idx].nbconn += 1;
            let proxy = &mut self.proxies[proxy_idx];
            proxy.stats[worker_id()].cum_conn.fetch_add(1, Ordering::Relaxed);
            proxy.stats[worker_id()].act_conn.fetch_add(1, Ordering::Relaxed);
            if proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed) > proxy.stats[worker_id()].max_conn.load(Ordering::Relaxed) {
                proxy.stats[worker_id()].max_conn.store(proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed), Ordering::Relaxed);
            }

            if self.listeners[l_idx].is_full() {
                let _ = self.poller.modify(
                    self.listeners[l_idx].borrowed_fd(),
                    raw_fd_to_u64(lfd),
                    false,
                    false,
                );
                self.fdtab.set_interest(lfd, Interest::NONE);
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
            );
        }
    }

    /// Runs the engine loop until `is_running` is set to false.
    ///
    /// # Errors
    /// Propagates polling errors.
    pub fn run_loop(&mut self) -> io::Result<()> {
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
                self.close_idle_http_sessions();
                if self.sessions.live() == 0 {
                    break;
                }
                if self.stop_deadline.is_some_and(|d| Instant::now() >= d) {
                    break;
                }
            }
            let now = self.current_tick();
            let _ = self.step(now)?;
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
    /// the opposite of a soft stop. They are closed when the loop ends.
    pub fn begin_soft_stop(&mut self) {
        if self.stopping {
            return;
        }
        self.stopping = true;
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
        if let Some(cli) = self.cli_listener.take() {
            self.fdtab.remove(cli.as_raw_fd());
            let _ = self.poller.delete(cli.as_fd());
        }

        // An HTTP session finishes the transaction it is in and then closes, instead of
        // waiting for another request that this process will not be around to serve.
        for (_, e) in self.sessions.iter_mut() {
            if e.sess.mode == Mode::Http {
                if let Some(t) = e.sess.txn.as_mut() {
                    t.close_after = true;
                }
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
        clear_proxy_counters(&mut self.proxies, target)
    }

    /// Dynamically tunes maxconn on a proxy or a server.
    pub fn set_maxconn(&mut self, px_name: &str, sv_name: Option<&str>, maxconn: u32) -> bool {
        set_proxy_maxconn(&mut self.proxies, px_name, sv_name, maxconn)
    }
}

#[derive(Debug)]
enum ConnEvalOutcome {
    Accept(SocketAddr, SocketAddr, SocketAddr, SocketAddr),
    Reject,
    SilentDrop,
}

#[derive(Debug, PartialEq, Eq)]
enum SessionEvalOutcome {
    Accept,
    Reject,
    SilentDrop,
}

#[allow(clippy::too_many_lines)]
fn eval_tcp_req_conn_rules(
    proxy: &Proxy,
    proxies: &[Proxy],
    registry: &Registry,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    sc_conn_rates: [u64; 3],
) -> ConnEvalOutcome {
    let mut client_addr = peer_addr;
    let mut server_addr = local_addr;
    let mut fc_src = peer_addr;
    let mut fc_dst = local_addr;

    let mut ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        client_addr: Some(client_addr),
        server_addr: Some(server_addr),
        fc_src: Some(fc_src),
        fc_dst: Some(fc_dst),
        sc_conn_rates,
        act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
        cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
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
            ibex_config::TcpReqConnAction::SetSrc { expr } => {
                let val = if let Ok(e) = Expr::parse(expr) {
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
                let val = if let Ok(e) = Expr::parse(expr) {
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
    ConnEvalOutcome::Accept(client_addr, server_addr, fc_src, fc_dst)
}

#[allow(clippy::too_many_lines)]
fn eval_tcp_req_session_rules(
    proxy: &Proxy,
    proxies: &[Proxy],
    registry: &Registry,
    sess: &mut TcpSession,
) -> SessionEvalOutcome {
    let mut ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src,
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
        cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };

    ibex_sample::CURRENT_VARS.with(|v| {
        let mut map = v.borrow_mut();
        map.clear();
        for (k, val) in &sess.sess_vars {
            map.insert(k.clone(), val.clone());
        }
        for (k, val) in &sess.req_vars {
            map.insert(k.clone(), val.clone());
        }
    });

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
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        let _ = tbl.update_entry(&key, |data| {
                            data.conn_cnt += 1;
                            data.conn_cur += 1;
                            if let Some(ref mut r) = data.conn_rate {
                                r.tick(1);
                            }
                        });
                        sess.tracked_sc[0] = Some((t_idx, key));
                    }
                }
            }
            ibex_config::TcpReqSessionAction::TrackSc1 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        let _ = tbl.update_entry(&key, |data| {
                            data.conn_cnt += 1;
                            data.conn_cur += 1;
                            if let Some(ref mut r) = data.conn_rate {
                                r.tick(1);
                            }
                        });
                        sess.tracked_sc[1] = Some((t_idx, key));
                    }
                }
            }
            ibex_config::TcpReqSessionAction::TrackSc2 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        let _ = tbl.update_entry(&key, |data| {
                            data.conn_cnt += 1;
                            data.conn_cur += 1;
                            if let Some(ref mut r) = data.conn_rate {
                                r.tick(1);
                            }
                        });
                        sess.tracked_sc[2] = Some((t_idx, key));
                    }
                }
            }
            ibex_config::TcpReqSessionAction::SetSrc { expr } => {
                let val = if let Ok(e) = Expr::parse(expr) {
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
                let val = if let Ok(e) = Expr::parse(expr) {
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
            ibex_config::TcpReqSessionAction::SetVar { var_name, expr } => {
                let val = if let Ok(e) = Expr::parse(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
                if var_name.starts_with("proc.") {
                    ibex_sample::set_proc_var(var_name, val);
                } else if var_name.starts_with("sess.") {
                    sess.sess_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                } else {
                    sess.req_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                }
            }
            ibex_config::TcpReqSessionAction::SetVarFmt { var_name, fmt } => {
                let val = format_sample_string(fmt, &ctx, registry);
                if var_name.starts_with("proc.") {
                    ibex_sample::set_proc_var(var_name, val);
                } else if var_name.starts_with("sess.") {
                    sess.sess_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                } else {
                    sess.req_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                }
            }
            ibex_config::TcpReqSessionAction::UnsetVar { var_name } => {
                if var_name.starts_with("sess.") {
                    sess.sess_vars.remove(var_name);
                } else {
                    sess.req_vars.remove(var_name);
                }
                ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().remove(var_name));
            }
            ibex_config::TcpReqSessionAction::ScIncGpc0 { sc } => {
                let sc_idx = *sc as usize;
                if sc_idx < 3 {
                    if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                        if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                            let _ = tbl.update_entry(key, |data| {
                                data.gpc0 = data.gpc0.saturating_add(1);
                                data.last_updated = std::time::Instant::now();
                            });
                        }
                    }
                }
            }
            ibex_config::TcpReqSessionAction::ScIncGpc1 { sc } => {
                let sc_idx = *sc as usize;
                if sc_idx < 3 {
                    if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                        if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                            let _ = tbl.update_entry(key, |data| {
                                data.gpc1 = data.gpc1.saturating_add(1);
                                data.last_updated = std::time::Instant::now();
                            });
                        }
                    }
                }
            }
            ibex_config::TcpReqSessionAction::ScSetGpt0 { sc, expr } => {
                let sc_idx = *sc as usize;
                if sc_idx < 3 {
                    if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                        let val = resolve_gpt0_val(expr, registry, &ctx);
                        if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                            let _ = tbl.update_entry(key, |data| {
                                data.gpt0 = val;
                                data.last_updated = std::time::Instant::now();
                            });
                        }
                    }
                }
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
    let expired = sess.inspect_exp.is_some_and(|exp| exp.is_expired(now));
    let client_closed = sess.cli_state == ScState::ShutR || sess.cli_state == ScState::Closed;
    let can_wait = sess.inspect_exp.is_some() && !expired && !client_closed;

    if !has_content && (can_wait || (sess.mode == Mode::Http && !client_closed)) {
        return ContentEvalResult::Waiting;
    }

    let mut ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src,
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        req_body: if has_content { Some(req_bytes) } else { None },
        act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
        cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };

    ibex_sample::CURRENT_VARS.with(|v| {
        let mut map = v.borrow_mut();
        map.clear();
        for (k, val) in &sess.sess_vars {
            map.insert(k.clone(), val.clone());
        }
        for (k, val) in &sess.req_vars {
            map.insert(k.clone(), val.clone());
        }
    });

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
                return ContentEvalResult::SilentDrop;
            }
            ibex_config::TcpReqContentAction::Reject => {
                return ContentEvalResult::Reject;
            }
            ibex_config::TcpReqContentAction::Accept => {
                return ContentEvalResult::Done;
            }
            ibex_config::TcpReqContentAction::TrackSc0 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        let _ = tbl.update_entry(&key, |data| {
                            data.conn_cnt += 1;
                            data.conn_cur += 1;
                            if let Some(ref mut r) = data.conn_rate {
                                r.tick(1);
                            }
                        });
                        sess.tracked_sc[0] = Some((t_idx, key));
                    }
                }
            }
            ibex_config::TcpReqContentAction::TrackSc1 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        let _ = tbl.update_entry(&key, |data| {
                            data.conn_cnt += 1;
                            data.conn_cur += 1;
                            if let Some(ref mut r) = data.conn_rate {
                                r.tick(1);
                            }
                        });
                        sess.tracked_sc[1] = Some((t_idx, key));
                    }
                }
            }
            ibex_config::TcpReqContentAction::TrackSc2 { table, expr } => {
                let t_idx = if let Some(ref tname) = table {
                    proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy.id as usize)
                } else {
                    proxy.id as usize
                };
                if let Some(key) = resolve_sample_stick_key(expr, registry, &ctx) {
                    if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                        let _ = tbl.update_entry(&key, |data| {
                            data.conn_cnt += 1;
                            data.conn_cur += 1;
                            if let Some(ref mut r) = data.conn_rate {
                                r.tick(1);
                            }
                        });
                        sess.tracked_sc[2] = Some((t_idx, key));
                    }
                }
            }
            ibex_config::TcpReqContentAction::SetSrc { expr } => {
                let val = if let Ok(e) = Expr::parse(expr) {
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
                let val = if let Ok(e) = Expr::parse(expr) {
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
            ibex_config::TcpReqContentAction::SetVar { var_name, expr } => {
                let val = if let Ok(e) = Expr::parse(expr) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(expr, &ctx, registry)
                };
                if var_name.starts_with("proc.") {
                    ibex_sample::set_proc_var(var_name, val);
                } else if var_name.starts_with("sess.") {
                    sess.sess_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                } else {
                    sess.req_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                }
            }
            ibex_config::TcpReqContentAction::SetVarFmt { var_name, fmt } => {
                let val = format_sample_string(fmt, &ctx, registry);
                if var_name.starts_with("proc.") {
                    ibex_sample::set_proc_var(var_name, val);
                } else if var_name.starts_with("sess.") {
                    sess.sess_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                } else {
                    sess.req_vars.insert(var_name.clone(), val.clone());
                    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.clone(), val));
                }
            }
            ibex_config::TcpReqContentAction::UnsetVar { var_name } => {
                if var_name.starts_with("sess.") {
                    sess.sess_vars.remove(var_name);
                } else {
                    sess.req_vars.remove(var_name);
                }
                ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().remove(var_name));
            }
            ibex_config::TcpReqContentAction::ScIncGpc0 { sc } => {
                let sc_idx = *sc as usize;
                if sc_idx < 3 {
                    if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                        if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                            let _ = tbl.update_entry(key, |data| {
                                data.gpc0 = data.gpc0.saturating_add(1);
                                data.last_updated = std::time::Instant::now();
                            });
                        }
                    }
                }
            }
            ibex_config::TcpReqContentAction::ScIncGpc1 { sc } => {
                let sc_idx = *sc as usize;
                if sc_idx < 3 {
                    if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                        if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                            let _ = tbl.update_entry(key, |data| {
                                data.gpc1 = data.gpc1.saturating_add(1);
                                data.last_updated = std::time::Instant::now();
                            });
                        }
                    }
                }
            }
            ibex_config::TcpReqContentAction::ScSetGpt0 { sc, expr } => {
                let sc_idx = *sc as usize;
                if sc_idx < 3 {
                    if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                        let val = resolve_gpt0_val(expr, registry, &ctx);
                        if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                            let _ = tbl.update_entry(key, |data| {
                                data.gpt0 = val;
                                data.last_updated = std::time::Instant::now();
                            });
                        }
                    }
                }
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
    let ctx = SampleContext {
        proxies: Some(&ProxiesView(proxies)),
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src,
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        res_body: Some(rep_bytes),
        act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
        cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
        unique_id: sess.log.unique_id.as_deref(),
        captures_req_hdr: Some(&sess.log.req_captures),
        captures_res_hdr: Some(&sess.log.res_captures),
        ..Default::default()
    };
    ibex_sample::CURRENT_VARS.with(|v| {
        let mut map = v.borrow_mut();
        map.clear();
        map.extend(sess.sess_vars.iter().map(|(k, val)| (k.clone(), val.clone())));
        map.extend(sess.req_vars.iter().map(|(k, val)| (k.clone(), val.clone())));
    });
    for rule in &proxy.tcp_res_content_rules {
        if let Some(cond) = &rule.cond {
            // `acl_exec_cond`: a sample that may change and does not match is a miss.
            let res = crate::proxy::combine_condition(cond, |term| {
                let parsed = if proxy.acls.contains_key(&term.name) { None } else { Expr::parse(&term.name).ok() };
                let Some(expr) = proxy.acls.get(&term.name).or(parsed.as_ref()) else { return crate::proxy::AclEvalResult::NotMatched };
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
            ibex_config::TcpResAction::Accept => return ContentEvalResult::Done,
            ibex_config::TcpResAction::Reject => return ContentEvalResult::Reject,
            ibex_config::TcpResAction::SilentDrop => return ContentEvalResult::SilentDrop,
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
    if let Some(val) = Expr::parse(expr).ok().and_then(|e| e.eval_sample(registry, ctx)) {
        store_var(sess_vars, req_vars, name, sample_to_string(&val));
    }
}

/// `unset-var(<name>)`, from the scope it lives in.
fn unset_var(sess_vars: &mut HashMap<String, String>, req_vars: &mut HashMap<String, String>, name: &str) {
    if name.starts_with("sess.") {
        sess_vars.remove(name);
    } else {
        req_vars.remove(name);
    }
    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().remove(name));
}

/// Stores a variable where its scope lives, and where the rules after it read it.
fn store_var(sess_vars: &mut HashMap<String, String>, req_vars: &mut HashMap<String, String>, name: &str, val: String) {
    if name.starts_with("proc.") {
        ibex_sample::set_proc_var(name, val);
        return;
    }
    let map = if name.starts_with("sess.") { sess_vars } else { req_vars };
    map.insert(name.to_string(), val.clone());
    ibex_sample::CURRENT_VARS.with(|v| v.borrow_mut().insert(name.to_string(), val));
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
    listener_idx: usize,
    cli_fd: std::os::fd::OwnedFd,
    peer_addr: SocketAddr,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    fc_src: SocketAddr,
    fc_dst: SocketAddr,
    tracked_sc: [Option<(usize, StickKey)>; 3],
) {
    // Cloned out before `proxies` is borrowed mutably. TLS belongs to the bind that
    // accepted, not to the proxy, so it is read from the listener.
    let tls = engine
        .listeners
        .get(listener_idx)
        .and_then(|l| l.tls.clone());
    let cli_raw_fd = cli_fd.as_raw_fd();
    let Some((sess, target_addr, srv_raw_fd)) = init_client_session(
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
    ) else {
        // TLS setup failed; the fd is dropped with the session and the connection closes.
        return;
    };

    let proxy = &mut engine.proxies[proxy_idx];

    let target_server_idx = target_addr.and_then(|t| proxy.servers.iter().position(|&s| s == t));
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
        log_line: None,
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
    let idx = proxy.servers.iter().position(|&s| s == target_addr)?;
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
                    let id = fmt.render(&session_log_data(sess, fe, proxy, std::process::id()), sample_registry(), &stream_sample_ctx(sess, fe, proxy, &ProxiesView(proxies)));
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
    proxies: &mut [Proxy],
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
    if proxies[proxy_idx].accept_proxy || proxies[proxy_idx].accept_proxy_v2 {
        sess.enable_accept_proxy(proxies[proxy_idx].accept_proxy_v2);
    }

    let registry = sample_registry();
    match eval_tcp_req_session_rules(&proxies[proxy_idx], proxies, registry, &mut sess) {
        SessionEvalOutcome::Accept => {}
        SessionEvalOutcome::Reject => {
            raw::abort_with_rst(sess.cli.as_fd());
            proxies[proxy_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        SessionEvalOutcome::SilentDrop => {
            let is_ipv6 = peer_addr.is_ipv6();
            raw::silent_drop(sess.cli.as_fd(), is_ipv6);
            proxies[proxy_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    }

    let proxy = &mut proxies[proxy_idx];

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
        && !proxy.accept_proxy
        && !proxy.accept_proxy_v2
        && sess.tcp_inspect_done
        // A proxy that routes (`use_backend`, `default_backend`) connects once the backend
        // is resolved (`connect_tcp_backend`): its own server list is not the one to use.
        && proxy.use_backends.is_empty()
        && proxy.default_backend.is_none()
    {
        target_addr = proxy.select_server_with_key(sess.client_addr.map(|a| a.ip()), sess.req_uri.as_deref());
        if let Some(target) = target_addr {
            let proxies: &[Proxy] = proxies;
            let proxy = &proxies[proxy_idx];
            maybe_prepend_send_proxy(proxy, proxy, proxies, &mut sess, target);
            arm_res_inspect(proxy, &mut sess);

            if let Ok((srv_fd, immediate)) = raw::connect(connect_addr(target, sess.server_addr)) {
                let sfd = srv_fd.as_raw_fd();
                srv_raw_fd = Some(sfd);
                sess.attach_server(srv_fd, now);
                if immediate {
                    sess.server_connected(now);
                }
            } else {
                proxy.stats[worker_id()].failed_conn.fetch_add(1, Ordering::Relaxed);
                if !sess.server_failed() {
                    sess.srv_state = ScState::Error;
                }
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
    proxies: &mut [Proxy],
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
            proxies[proxy_idx].stats[worker_id()].act_conn.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(s_idx) = entry.target_server_idx {
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
    proxies: &mut [Proxy],
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

/// Clears traffic and error counters for a specific proxy, or all proxies if `target` is `None` or `"all"`.
pub fn clear_proxy_counters(proxies: &mut [Proxy], target: Option<&str>) -> bool {
    if let Some(name) = target {
        if name.eq_ignore_ascii_case("all") {
            for p in proxies.iter_mut() {
                p.stats.iter().for_each(|s| s.clear());
            }
            true
        } else {
            let mut found = false;
            for p in proxies.iter_mut() {
                if p.name == name {
                    p.stats.iter().for_each(|s| s.clear());
                    found = true;
                }
            }
            found
        }
    } else {
        for p in proxies.iter_mut() {
            p.stats.iter().for_each(|s| s.clear());
        }
        true
    }
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

/// Dynamically configures `maxconn` on a proxy or a specific server within a proxy.
pub fn set_proxy_maxconn(
    proxies: &mut [Proxy],
    px_name: &str,
    sv_name: Option<&str>,
    val: u32,
) -> bool {
    let Some(proxy) = proxies.iter_mut().find(|p| p.name == px_name) else {
        return false;
    };
    if let Some(sv) = sv_name {
        let Some(s_idx) = proxy.server_ids.iter().position(|sid| sid == sv) else {
            return false;
        };
        if s_idx < proxy.server_maxconn.len() {
            proxy.server_maxconn[s_idx] = Some(val);
            return true;
        }
        false
    } else {
        proxy.maxconn = val;
        true
    }
}

/// Internal dispatcher executing scheduler tasks against runtime sessions and health checks.
struct EngineDispatcher<'a> {
    sessions: &'a mut SessionArena,
    applets: &'a mut AppletArena,
    proxies: &'a mut [Proxy],
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
    idle_backend_pool: &'a mut HashMap<SocketAddr, Vec<OwnedFd>>,
}

/// Answers the current request with the page for `status`, chosen as HAProxy's
/// `http_error_message` chooses it: the backend's `http-error`/`errorfile`, then the
/// frontend's, then the built-in page. Every error the proxy generates on a stream goes
/// through here, and through the `http-after-response` rules.
fn reply_error(entry: &mut SessionEntry, proxies: &[Proxy], status: u16) {
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
    let page = proxy_error_response(&entry.sess, be, &proxies[entry.proxy_idx], proxies, status);
    entry.sess.write_reply(&page);
}

/// Detaches the server connection from the session: into the idle pool when it can carry
/// another request, closed otherwise. The server slot it held is released either way.
fn release_server(
    entry: &mut SessionEntry,
    proxies: &[Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    idle_pool: &mut HashMap<SocketAddr, Vec<OwnedFd>>,
    reusable: bool,
) {
    if let Some(srv_fd) = entry.sess.srv.take() {
        let _ = poller.delete(srv_fd.as_fd());
        if let Some(sfd) = entry.srv_raw_fd.take() {
            fdtab.remove(sfd);
        }
        let reusable = reusable
            && matches!(entry.sess.srv_state, ScState::Ready | ScState::Established)
            // A connection that opened with a PROXY header speaks for this client only.
            && !entry.sess.send_proxy_prepended
            // The pool holds bare sockets; a TLS session's state does not go with them.
            && !entry.sess.srv_xprt.is_tls()
            && proxies
                .get(entry.srv_backend_idx)
                .is_some_and(|p| p.http_reuse != ibex_config::HttpReuse::Never)
            && raw::is_idle_conn_alive(srv_fd.as_fd());
        // The pool is keyed by server; a server that maps the destination may have been
        // connected anywhere, so its connections are not pooled.
        if let (true, Some(addr)) = (reusable, entry.target_addr.filter(|&a| !maps_destination(a))) {
            idle_pool.entry(addr).or_default().push(srv_fd);
        }
    }
    entry.srv_raw_fd = None;
    entry.sess.srv_xprt = crate::xprt::ServerXprt::Plain;
    if let Some(s_idx) = entry.target_server_idx.take() {
        let be = entry.srv_backend_idx;
        if !entry.actconn_reclaimed && be < proxies.len() && s_idx < proxies[be].server_actconn.len() {
            proxies[be].server_actconn[s_idx].fetch_sub(1, Ordering::Relaxed);
        }
    }
    entry.target_addr = None;
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
    idle_pool: &mut HashMap<SocketAddr, Vec<OwnedFd>>,
    reusable: bool,
) {
    // A transaction that ends with its connection, not through `end_txn` (cut short by
    // either side), logs here, while its request and response are still known.
    if entry.sess.txn.is_some() && entry.log_line.is_none() {
        entry.log_line = stream_log_line(entry, proxies, std::process::id());
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

fn retry_server_connect(
    entry: &mut SessionEntry,
    proxies: &mut [Proxy],
    fdtab: &mut FdTab,
    poller: &mut Poller,
    now: Tick,
) {
    if let (Some(srv_fd), Some(sfd)) = (entry.sess.srv.take(), entry.srv_raw_fd.take()) {
        let _ = poller.delete(srv_fd.as_fd());
        fdtab.remove(sfd);
    }

    if let Some(old_idx) = entry.target_server_idx.take() {
        let old_be = entry.srv_backend_idx;
        if old_be < proxies.len() && old_idx < proxies[old_be].server_actconn.len() {
            proxies[old_be].server_actconn[old_idx].fetch_sub(1, Ordering::Relaxed);
        }
    }

    let be_idx = EngineDispatcher::resolve_backend(entry, proxies);
    entry.backend_idx = be_idx;
    proxies[be_idx].stats[worker_id()].retries_count.fetch_add(1, Ordering::Relaxed);
    let source_ip = entry.sess.client_addr.map(|a| a.ip());
    let target = if proxies[be_idx].redisp {
        proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref())
    } else {
        entry
            .target_addr
            .or_else(|| proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref()))
    };

    let Some(target_addr) = target else {
        entry.sess.srv_state = ScState::Error;
        return;
    };

    let s_idx = proxies[be_idx]
        .servers
        .iter()
        .position(|&s| s == target_addr);
    if let Some(idx) = s_idx {
        if idx < proxies[be_idx].server_actconn.len() {
            proxies[be_idx].server_actconn[idx].fetch_add(1, Ordering::Relaxed);
        }
    }
    entry.target_server_idx = s_idx;
    entry.srv_backend_idx = be_idx;

    maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

    entry.target_addr = Some(target_addr);
    if let Ok((srv_fd, immediate)) = raw::connect(connect_addr(target_addr, entry.sess.server_addr)) {
        let sfd = srv_fd.as_raw_fd();
        entry.srv_raw_fd = Some(sfd);
        entry.sess.attach_server(srv_fd, now);
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
        proxies[be_idx].stats[worker_id()].failed_conn.fetch_add(1, Ordering::Relaxed);
        if !entry.sess.server_failed() {
            entry.sess.srv_state = ScState::Error;
            if entry.sess.mode == Mode::Http {
                reply_error(entry, proxies, 503);
            }
        }
    }
}

fn check_srv_connect(
    entry: &mut SessionEntry,
    proxies: &mut [Proxy],
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
                    let be_idx = EngineDispatcher::resolve_backend(entry, proxies);
                    proxies[be_idx].stats[worker_id()].failed_conn.fetch_add(1, Ordering::Relaxed);
                    if entry.sess.server_failed() {
                        retry_server_connect(entry, proxies, fdtab, poller, now);
                    } else {
                        entry.sess.srv_state = ScState::Error;
                        if entry.sess.mode == Mode::Http {
                            reply_error(entry, proxies, 503);
                        }
                    }
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
    proxies: &mut [Proxy],
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
    proxies[proxy_idx].stats[worker_id()].bytes_in.fetch_add(entry.sess.bytes_in, Ordering::Relaxed);
    proxies[proxy_idx].stats[worker_id()].bytes_out.fetch_add(entry.sess.bytes_out, Ordering::Relaxed);
    if !entry.actconn_reclaimed {
        proxies[proxy_idx].stats[worker_id()].act_conn.fetch_sub(1, Ordering::Relaxed);

        if let Some(s_idx) = entry.target_server_idx {
            let be_idx = entry.srv_backend_idx;
            if be_idx < proxies.len() && s_idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[s_idx].fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    for (tbl_idx, ref key) in entry.sess.tracked_sc.iter().flatten() {
        if *tbl_idx < proxies.len() {
            if let Some(ref table) = proxies[*tbl_idx].stick_table {
                let _ = table.update_entry(key, |data| {
                    data.conn_cur = data.conn_cur.saturating_sub(1);
                    data.bytes_in_cnt += entry.sess.bytes_in;
                    data.bytes_out_cnt += entry.sess.bytes_out;
                });
            }
        }
    }

    if let Some(l) = listeners.iter_mut().find(|l| l.proxy == usize_to_u32(proxy_idx)) {
        l.nbconn = l.nbconn.saturating_sub(1);
        let lfd = l.raw_fd();
        if !l.is_full() && fdtab.interest(lfd).is_none() {
            let _ = poller.modify(l.borrowed_fd(), raw_fd_to_u64(lfd), true, false);
            fdtab.set_interest(lfd, Interest::READ);
        }
    }
}

/// `HAProxy`'s `monitor-uri` answer. Ibex closes the connection after it (and the relay
/// adds `Connection: close`), where `HAProxy` keeps it alive.
const MONITOR_URI_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 58\r\n\
cache-control: no-cache\r\ncontent-type: text/html\r\n\r\n\
<html><body><h1>200 OK</h1>\nService ready.\n</body></html>\n";

fn inject_connection_close_header_zero_alloc(buf: &mut crate::buf::Buf) {
    if let Some((eoh_pos, eoh_len)) = crate::find_eoh(buf.readable()) {
        let inject = b"Connection: close\r\n";
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
            buf.inject_http_header("Connection", "close");
        }
    }
}

impl EngineDispatcher<'_> {
    fn resolve_backend(entry: &SessionEntry, proxies: &[Proxy]) -> usize {
        let proxy_idx = entry.proxy_idx;
        let proxy = &proxies[proxy_idx];

        if proxy.use_backends.is_empty() && proxy.default_backend.is_none() {
            return proxy_idx;
        }

        let ctx = SampleContext {
            proxies: Some(&ProxiesView(proxies)),
            client_addr: entry.sess.client_addr,
            server_addr: entry.sess.server_addr,
            fc_src: entry.sess.fc_src,
            fc_dst: entry.sess.fc_dst,
            is_first_req: entry.sess.is_first_req,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            // The body a `wait-for-body` saw; otherwise the bytes in the buffer.
            req_body: match entry.sess.txn.as_ref().and_then(|t| t.req_body.as_deref()) {
                Some(body) => Some(body),
                None if entry.sess.req.readable().is_empty() => None,
                None => Some(entry.sess.req.readable()),
            },
            htx: None,
            htx_slice: entry.sess.htx_slice(),
            req_uri: entry.sess.req_uri.as_deref(),
            req_method: entry.sess.req_method.as_deref(),
            req_headers: entry.sess.req_headers.as_deref(),
            act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
            cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
            unique_id: entry.sess.log.unique_id.as_deref(),
            captures_req_hdr: Some(&entry.sess.log.req_captures),
            captures_res_hdr: Some(&entry.sess.log.res_captures),
            ..Default::default()
        };

        let registry = sample_registry();

        for rule in &proxy.use_backends {
            let mut matches = true;
            if let Some(ref cond) = rule.cond {
                matches = crate::proxy::eval_acl_condition(cond, &proxy.acls, registry, &ctx);
            }
            if matches {
                if let Some(idx) = proxies.iter().position(|p| p.name == rule.backend) {
                    return idx;
                }
            }
        }

        if let Some(ref def_name) = proxy.default_backend {
            if let Some(idx) = proxies.iter().position(|p| p.name == *def_name) {
                return idx;
            }
        }

        proxy_idx
    }

    /// One pass over the HTTP transaction, after the byte layer has run: the reply owed
    /// for an unparsable request, request rules and routing (once per transaction), the
    /// response head, how each side ended, and the end of the transaction.
    #[allow(clippy::too_many_arguments)]
    fn http_step(
        entry: &mut SessionEntry,
        proxies: &mut [Proxy],
        checks: &mut [ServerCheckState],
        pid: u32,
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut HashMap<SocketAddr, Vec<OwnedFd>>,
        wake_queue: &mut Vec<TaskRef>,
        now: Tick,
    ) -> Option<crate::stats_html::AdminAction> {
        let Some(txn) = entry.sess.txn.as_mut() else {
            // Between requests. A client that goes away here ends the session; a server
            // connection kept from the last transaction goes back to the pool.
            if !matches!(entry.sess.cli_state, ScState::Ready | ScState::Established) {
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
                } else if !entry.sess.req.is_empty()
                    || (entry.sess.is_first_req && matches!(entry.sess.ending, None | Some(crate::proxy::Ending::ClientAbort)))
                {
                    // Part of a request, or a new connection closed before its first byte,
                    // then the client left: `HAProxy` logs it as a 400 the client aborted
                    // (`CR`).
                    entry.sess.log.status = Some(400);
                    entry.sess.log.term = Some(*b"CR");
                }
                if entry.sess.log.status.is_some() {
                    entry.log_line = stream_log_line(entry, proxies, pid);
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
            && entry.sess.txn.as_ref().is_some_and(|t| t.body_wait.is_some())
        {
            let fe = &proxies[entry.proxy_idx];
            let page = proxy_error_response(&entry.sess, fe, fe, proxies, 408);
            entry.sess.send_before_close(&page);
            entry.sess.log.status = Some(408);
            entry.sess.log.term = Some(*b"cR");
            entry.sess.log.request = None;
            entry.log_line = stream_log_line(entry, proxies, pid);
            close_http_session(entry, proxies, fdtab, poller, idle_pool, true);
            return None;
        }

        let mut admin = None;
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
                Self::apply_http_response_rules(entry, proxies, now);
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
        if !(srv_eof || srv_err) || !txn.req_rules_done || txn.local || txn.rsp.is_done() {
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
                    entry.sess.log.term = Some(*b"SD");
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
        proxies: &mut [Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut HashMap<SocketAddr, Vec<OwnedFd>>,
        wake_queue: &mut Vec<TaskRef>,
        now: Tick,
        pid: u32,
    ) {
        // The transaction's line, while its request and response are still here.
        if entry.sess.txn.is_some() {
            entry.log_line = stream_log_line(entry, proxies, pid);
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
        let close = if entry.sess.h2_ctx.is_some() {
            !matches!(entry.sess.cli_state, ScState::Ready | ScState::Established)
        } else {
            txn.close_after || !matches!(entry.sess.cli_state, ScState::Ready | ScState::Established)
        };
        if close {
            close_http_session(entry, proxies, fdtab, poller, idle_pool, reusable);
            return;
        }
        if !reusable {
            release_server(entry, proxies, fdtab, poller, idle_pool, false);
        }
        // A reusable server connection stays on the session for the next request, which
        // takes it if routing sends it to the same server (`connect_http_backend`).
        entry.sess.reset_for_next_request();
        // A next request already in the buffer has no socket event left to announce it:
        // run once more straight away. (Without one, the poller wakes the session.)
        if !entry.sess.req.is_empty() {
            wake_queue.push(entry.task);
        }
        if !proxies[entry.proxy_idx].tcp_req_content_rules.is_empty() {
            let _ = eval_tcp_req_content_rules(
                &proxies[entry.proxy_idx],
                proxies,
                sample_registry(),
                &mut entry.sess,
                now,
            );
        }
    }

    #[allow(clippy::too_many_lines)] // one dispatch chain; splitting it would obscure the order
    fn step_stream(&mut self, session_idx: u32) -> Outcome {
        // The time now, not the time the pass started: `step` takes its tick before it waits
        // in the poller, so a stream woken by a request after an idle second would arm a
        // `wait-for-body` of 300 ms from a second ago.
        let now = self.now;
        let (is_done, pending_admin, log_line) = {
            let Some(entry) = self.sessions.get_mut(session_idx) else {
                return Outcome::Done;
            };

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
            let _ = entry.sess.check_timeouts(now);

            // Step 3: Stream engine process pass
            if !entry.sess.is_done() {
                let _ = entry.sess.process(now);
            }

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
                    }
                    ContentEvalResult::Reject => {
                        raw::abort_with_rst(entry.sess.cli.as_fd());
                        self.proxies[proxy_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
                        entry.sess.cli_state = ScState::Closed;
                        entry.sess.srv_state = ScState::Closed;
                        entry.sess.tcp_inspect_done = true;
                    }
                    ContentEvalResult::SilentDrop => {
                        let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                        raw::silent_drop(entry.sess.cli.as_fd(), is_ipv6);
                        self.proxies[proxy_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
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
                        self.proxies[be_idx].stats[worker_id()].denied_resp.fetch_add(1, Ordering::Relaxed);
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
                        self.proxies[be_idx].stats[worker_id()].denied_resp.fetch_add(1, Ordering::Relaxed);
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

            let log_line = entry.log_line.take();

            // Step 3.6: If in TCP mode and server not yet connected (e.g. deferred on accept-proxy or inspect), connect once ready
            if entry.sess.mode == Mode::Tcp
                && entry.sess.srv_state == ScState::Init
                && (!entry.sess.accept_proxy || entry.sess.proxy_handshake_done)
                && entry.sess.tcp_inspect_done
                && !entry.sess.is_done()
            {
                Self::connect_tcp_backend(entry, self.proxies, self.fdtab, self.poller, now);
            }

            // Step 4: Update interests
            update_interests(entry, self.fdtab, self.poller);

            // Step 4b: undispatched H2 streams have no socket event to wake them; run again.
            // Pending output needs no requeue: Step 4 asked the (level-triggered) poller
            // for writability, and requeueing it here spun a CPU against a client that
            // reads slowly.
            if entry.sess.has_undispatched_h2_streams() && !entry.sess.is_done() {
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

        if let Some(line) = log_line {
            let fe = self.sessions.get(session_idx).map_or(0, |e| e.proxy_idx);
            self.send_log_line(fe, &line);
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
                e.log_line
                    .take()
                    .or_else(|| (e.sess.mode == Mode::Tcp || e.sess.txn.is_some()).then(|| stream_log_line(e, self.proxies, self.pid)).flatten())
                    .map(|l| (e.proxy_idx, l))
            });
            if let Some((fe, line)) = line {
                self.send_log_line(fe, &line);
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
        let (status, framing, srv_has_close) = {
            let head = String::from_utf8_lossy(&entry.sess.rep.readable()[..total_hdr_len]);
            let status = crate::txn::status_of(&head);
            let framing = crate::txn::response_framing(&head, entry.sess.req_method.as_deref(), status);
            (status, framing, crate::txn::head_wants_close(&head))
        };
        if total_hdr_len > threshold || status < 100 {
            entry.sess.rep.clear();
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
        let resume = txn.rsp_wait.take();
        // The final response head: `t_data`, and `capture response header`.
        if resume.is_none() {
            entry.sess.log.data = Some(std::time::Instant::now());
        }
        let fe_caps = &proxies[fe_idx].res_capture_slots;
        if resume.is_none() && !fe_caps.is_empty() {
            let head = String::from_utf8_lossy(&entry.sess.rep.readable()[..total_hdr_len]).into_owned();
            let headers: Vec<(&str, &str)> = head.split("\r\n").skip(1).filter_map(|l| l.split_once(':')).collect();
            entry.sess.log.res_captures = capture_values(fe_caps.iter().map(|(n, l)| (n.as_str(), *l)), &headers);
        }
        txn.status = status;
        txn.srv_reusable = !srv_has_close
            && !matches!(framing, crate::txn::Framing::UntilClose | crate::txn::Framing::Tunnel);
        if framing == crate::txn::Framing::UntilClose {
            // The server's close is the only end the client can see.
            txn.close_after = true;
        }
        let client_close = txn.close_after;
        let cookie_txn = txn.ck;

        if !client_close && srv_has_close {
            entry.sess.rep.remove_http_header("connection");
        } else if client_close && !srv_has_close && framing != crate::txn::Framing::Tunnel {
            inject_connection_close_header_zero_alloc(&mut entry.sess.rep);
        }
        let set_rsp = |entry: &mut SessionEntry| {
            let sess = &mut entry.sess;
            if let Some(txn) = sess.txn.as_mut() {
                txn.rsp = MsgState::head(framing);
                txn.rsp.measure_head(sess.rep.readable());
                if framing == crate::txn::Framing::Tunnel && txn.req.is_done() {
                    txn.req = MsgState::Tunnel;
                }
            }
        };

        let has_rules = !proxies[be_idx].http_res_rules.is_empty()
            || !proxies[be_idx].http_after_res_rules.is_empty()
            || !proxies[fe_idx].http_res_rules.is_empty()
            || !proxies[fe_idx].http_after_res_rules.is_empty()
            || !proxies[be_idx].tcp_res_content_rules.is_empty()
            || proxies[be_idx].cookie.is_some()
            || !proxies[be_idx].srvexp.is_empty();

        if !has_rules {
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

        let ctx = SampleContext {
            proxies: Some(&ProxiesView(proxies)),
            client_addr: entry.sess.client_addr,
            server_addr: entry.sess.server_addr,
            fc_src: entry.sess.fc_src,
            fc_dst: entry.sess.fc_dst,
            is_first_req: entry.sess.is_first_req,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            htx: None,
            htx_slice,
            req_uri: req_uri_clone.as_deref(),
            req_method: req_method_clone.as_deref(),
            req_headers: req_headers_clone.as_deref(),
            fe_name: Some(&proxies[fe_idx].name),
            be_name: Some(&proxies[be_idx].name),
            be_max_retries: Some(proxies[be_idx].retries),
            cur_max_retries: Some(entry.sess.max_retries),
            res_version: Some(&proto_version),
            res_body: has_wait.then_some(res_body.as_slice()),
            unique_id: entry.sess.log.unique_id.as_deref(),
            captures_req_hdr: Some(&entry.sess.log.req_captures),
            captures_res_hdr: Some(&res_caps_in),
            ..Default::default()
        };

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
            for rule in proxies[be_idx].tcp_res_content_rules.iter().filter(|_| resume.is_none()) {
                let matches = match &rule.cond {
                    None => true,
                    Some(cond) => eval_condition(cond, &tcp_ctx, &proxies[be_idx].acls, registry),
                };
                if !matches {
                    continue;
                }
                match &rule.action {
                    ibex_config::TcpResAction::Accept => break,
                    ibex_config::TcpResAction::Reject | ibex_config::TcpResAction::SilentDrop => {
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
            let fe_res_slots = &proxies[fe_idx].res_capture_slots;
            let mut stopped = None;
            for (list, &px) in order.iter().enumerate() {
                if resume.is_some_and(|w| list < w.list) {
                    continue;
                }
                let start = resume.filter(|w| w.list == list).map_or(0, |w| w.rule);
                let rules = proxies[px].http_res_rules.iter().map(|r| (ResOp::of_res(&r.action), r.cond.as_ref()));
                let caps = (!fe_res_slots.is_empty()).then_some((&mut res_caps, &fe_res_slots[..]));
                let mut check = |rule: usize, time_ms: u32, at_least: u32| -> BodyWait {
                    let now = fresh_tick(now);
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
                        BodyWait::Pending => held = Some(crate::txn::RspWait { list, rule, deadline }),
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
            // What the rules captured is what the log line shows, and what the rules after
            // them (`http-after-response`) read.
            entry.sess.log.res_captures.clone_from(&res_caps);
            let ctx = SampleContext { captures_res_hdr: Some(&res_caps), ..ctx.clone() };
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
            if let Err(stop) = eval_after_res_rules(
                proxies,
                fe_idx,
                be_idx,
                (&mut hdrs, &mut status, &mut status_msg),
                &ctx,
                registry,
                &mut entry.sess.sess_vars,
                &mut entry.sess.req_vars,
            ) {
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
            entry.sess.rep.clear();
            match stop {
                ResStop::Page(st) => reply_error(entry, proxies, st),
                ResStop::Empty(st) => reply_empty(entry, proxies, st),
            }
            return;
        }

        // Connection header policy:
        if !client_close {
            // Client is in keep-alive mode: strip hop-by-hop Connection: close
            hdrs.retain(|(k, v)| {
                !(k.eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("close"))
            });
        } else if !hdrs.iter().any(|(k, _v)| k.eq_ignore_ascii_case("connection")) {
            hdrs.push(("Connection".to_string(), "close".to_string()));
        }

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
        proxies: &mut [Proxy],
        checks: &mut [ServerCheckState],
        pid: u32,
        now: Tick,
    ) -> Option<crate::stats_html::AdminAction> {
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
            entry.sess.write_reply(resp.as_bytes());
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
            entry.sess.write_reply(resp.as_bytes());
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

                    for (p_idx, proxy) in proxies.iter_mut().enumerate() {
                        if target_backend.is_none() || target_backend == Some(proxy.name.as_str()) {
                            for (s_idx, sid) in proxy.server_ids.iter().enumerate() {
                                if target_server.is_none() || target_server == Some(sid.as_str()) {
                                    let new_status = match cmd.action.as_str() {
                                        "ready" | "up" | "enable" => Some(ServerStatus::Up),
                                        "drain" => Some(ServerStatus::Drain),
                                        "maint" | "down" | "disable" => Some(ServerStatus::Maint),
                                        _ => None,
                                    };
                                    if let Some(st) = new_status {
                                        proxy.server_statuses[s_idx].store(st as u8, Ordering::Relaxed);
                                        if let Some(check) = checks
                                            .iter_mut()
                                            .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx)
                                        {
                                            check.status = st;
                                        }
                                    }
                                    if let Some(w) = cmd.weight {
                                        if s_idx < proxy.server_weights.len() {
                                            proxy.server_weights[s_idx] = w;
                                        }
                                    }
                                    if let Some(mc) = cmd.maxconn {
                                        if s_idx < proxy.server_maxconn.len() {
                                            proxy.server_maxconn[s_idx] = Some(mc);
                                        }
                                    }
                                }
                            }
                        }
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
                entry.sess.write_reply(resp.as_bytes());
                return Some(cmd);
            }

            let html = crate::stats_html::render_stats_html(proxies, checks, pid);
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
            entry.sess.write_reply(resp.as_bytes());
            return Some(cmd);
        }

        // 4. Default: Render full HTML dashboard
        let html = crate::stats_html::render_stats_html(proxies, checks, pid);
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
        entry.sess.write_reply(resp.as_bytes());
        None
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::too_many_arguments)]
    fn connect_http_backend(
        entry: &mut SessionEntry,
        proxies: &mut [Proxy],
        checks: &mut [ServerCheckState],
        pid: u32,
        fdtab: &mut FdTab,
        poller: &mut Poller,
        idle_pool: &mut HashMap<SocketAddr, Vec<OwnedFd>>,
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

        // Initialize per-request thread locals
        CURRENT_VARS.with(|v| {
            let mut map = v.borrow_mut();
            map.clear();
            for (k, val) in &entry.sess.sess_vars {
                map.insert(k.clone(), val.clone());
            }
            for (k, val) in &entry.sess.req_vars {
                map.insert(k.clone(), val.clone());
            }
        });
        if resume.is_none() {
            begin_http_stream(entry, proxies, proxy_idx, pid);
        }
        CURRENT_TIMEOUTS.with(|t| {
            let mut map = t.borrow_mut();
            map.clear();
            let fe_client = proxies[proxy_idx].stats_config.raw_timeouts.client.map_or(0, millis_to_u32);
            let fe_connect = proxies[proxy_idx].stats_config.raw_timeouts.connect.map_or(0, millis_to_u32);
            let fe_server = proxies[proxy_idx].stats_config.raw_timeouts.server.map_or(0, millis_to_u32);
            let fe_queue = proxies[proxy_idx].stats_config.raw_timeouts.queue.map_or(0, millis_to_u32);
            let fe_tunnel = proxies[proxy_idx].stats_config.raw_timeouts.tunnel.map_or(0, millis_to_u32);
            let fe_tarpit = proxies[proxy_idx].stats_config.raw_timeouts.tarpit.map_or(0, millis_to_u32);

            map.insert("fe_client_timeout", fe_client);
            map.insert("cur_client_timeout", fe_client);
            map.insert("fe_connect_timeout", fe_connect);
            map.insert("cur_connect_timeout", fe_connect);
            map.insert("fe_server_timeout", fe_server);
            map.insert("cur_server_timeout", fe_server);
            map.insert("fe_queue_timeout", fe_queue);
            map.insert("cur_queue_timeout", fe_queue);
            map.insert("fe_tunnel_timeout", fe_tunnel);
            map.insert("cur_tunnel_timeout", fe_tunnel);
            map.insert("fe_tarpit_timeout", fe_tarpit);
            map.insert("cur_tarpit_timeout", fe_tarpit);

            map.insert("be_client_timeout", fe_client);
            map.insert("be_server_timeout", fe_server);
            map.insert("be_connect_timeout", fe_connect);
            map.insert("be_queue_timeout", fe_queue);
            map.insert("be_tunnel_timeout", fe_tunnel);
            map.insert("be_tarpit_timeout", fe_tarpit);
        });
        STRICT_MODE.set(true);
        REWRITE_ADDED_BYTES.set(0);
        let max_rw = proxies[proxy_idx].stats_config.maxrewrite.unwrap_or(8192);
        MAX_REWRITE_LIMIT.set(max_rw);

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
                if let Some(t) = entry.sess.txn.as_mut() {
                    t.close_after = true;
                }
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
                return Self::handle_stats_request(entry, proxies, checks, pid, now);
            }
        }

        let registry = sample_registry();

        // 1. Stick table tracking from http_req_rules
        let mut sc_http_req_rates = [0u64; 3];
        let mut sc_conn_rates = [0u64; 3];

        let http_sample_ctx = SampleContext {
            proxies: Some(&ProxiesView(proxies)),
            client_addr: entry.sess.client_addr,
            server_addr: entry.sess.server_addr,
            fc_src: entry.sess.fc_src,
            fc_dst: entry.sess.fc_dst,
            is_first_req: entry.sess.is_first_req,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            req_uri: entry.sess.req_uri.as_deref(),
            req_method: entry.sess.req_method.as_deref(),
            req_headers: entry.sess.req_headers.as_deref(),
            fe_name: Some(&proxies[proxy_idx].name),
            act_conn: proxies[proxy_idx].stats[worker_id()].act_conn.load(Ordering::Relaxed),
            cum_conn: proxies[proxy_idx].stats[worker_id()].cum_conn.load(Ordering::Relaxed),
            unique_id: entry.sess.log.unique_id.as_deref(),
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
                    if let Some(k) = resolve_sample_stick_key(expr, registry, &http_sample_ctx) {
                        let is_new = entry.sess.tracked_sc[0].as_ref().is_none_or(|(old_idx, old_k)| *old_idx != t_idx || old_k != &k);
                        if is_new {
                            if let Some(ref tbl) = proxies[t_idx].stick_table {
                                let _ = tbl.update_entry(&k, |data| {
                                    data.conn_cnt += 1;
                                    data.conn_cur += 1;
                                    if let Some(ref mut r) = data.conn_rate {
                                        r.tick(1);
                                    }
                                });
                            }
                            entry.sess.tracked_sc[0] = Some((t_idx, k));
                        }
                    }
                }
                ibex_config::HttpReqAction::TrackSc1 { table, expr } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_sample_stick_key(expr, registry, &http_sample_ctx) {
                        let is_new = entry.sess.tracked_sc[1].as_ref().is_none_or(|(old_idx, old_k)| *old_idx != t_idx || old_k != &k);
                        if is_new {
                            if let Some(ref tbl) = proxies[t_idx].stick_table {
                                let _ = tbl.update_entry(&k, |data| {
                                    data.conn_cnt += 1;
                                    data.conn_cur += 1;
                                    if let Some(ref mut r) = data.conn_rate {
                                        r.tick(1);
                                    }
                                });
                            }
                            entry.sess.tracked_sc[1] = Some((t_idx, k));
                        }
                    }
                }
                ibex_config::HttpReqAction::TrackSc2 { table, expr } => {
                    let t_idx = if let Some(ref tname) = table {
                        proxies.iter().position(|p| p.name == *tname).unwrap_or(proxy_idx)
                    } else {
                        proxy_idx
                    };
                    if let Some(k) = resolve_sample_stick_key(expr, registry, &http_sample_ctx) {
                        let is_new = entry.sess.tracked_sc[2].as_ref().is_none_or(|(old_idx, old_k)| *old_idx != t_idx || old_k != &k);
                        if is_new {
                            if let Some(ref tbl) = proxies[t_idx].stick_table {
                                let _ = tbl.update_entry(&k, |data| {
                                    data.conn_cnt += 1;
                                    data.conn_cur += 1;
                                    if let Some(ref mut r) = data.conn_rate {
                                        r.tick(1);
                                    }
                                });
                            }
                            entry.sess.tracked_sc[2] = Some((t_idx, k));
                        }
                    }
                }
                _ => {}
            }
        }

        // Count HTTP request into all active tracked slots
        for (t_idx, ref k) in entry.sess.tracked_sc.iter().flatten().filter(|_| resume.is_none()) {
            if *t_idx < proxies.len() {
                if let Some(ref tbl) = proxies[*t_idx].stick_table {
                    let _ = tbl.update_entry(k, |data| {
                        data.http_req_cnt += 1;
                        if let Some(ref mut r) = data.http_req_rate {
                            r.tick(1);
                        }
                    });
                }
            }
        }

        // Query rates for use by subsequent rules
        for (i, opt) in entry.sess.tracked_sc.iter().enumerate() {
            if let Some((t_idx, ref k)) = opt {
                if *t_idx < proxies.len() {
                    if let Some(ref tbl) = proxies[*t_idx].stick_table {
                        if let Ok(Some(data)) = tbl.get_entry(k) {
                            if let Some(ref r) = data.http_req_rate {
                                sc_http_req_rates[i] = r.rate();
                            }
                            if let Some(ref r) = data.conn_rate {
                                sc_conn_rates[i] = r.rate();
                            }
                        }
                    }
                }
            }
        }

        let act_conn = proxies[proxy_idx].stats[worker_id()].act_conn.load(Ordering::Relaxed);
        let cum_conn = proxies[proxy_idx].stats[worker_id()].cum_conn.load(Ordering::Relaxed);
        let eval_http_rules = |rules: &[ibex_config::HttpReqRule], capture_exprs: &[Option<Expr>], acls: &HashMap<String, Expr>, sess: &mut TcpSession, be_retries: u16, fe_name: Option<&str>, be_name: Option<&str>, pages_idx: usize, be_stage: bool, start: usize| -> Result<RuleFlow, u16> {
            macro_rules! make_ctx {
                ($s:expr) => {
                    SampleContext {
                        proxies: Some(&ProxiesView(proxies)),
                        client_addr: $s.client_addr,
                        server_addr: $s.server_addr,
                        fc_src: $s.fc_src,
                        fc_dst: $s.fc_dst,
                        is_first_req: $s.is_first_req,
                        proxy_tlvs: $s.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
                        htx: None,
                        htx_slice: $s.htx_slice(),
                        req_uri: $s.req_uri.as_deref(),
                        req_method: $s.req_method.as_deref(),
                        req_headers: $s.req_headers.as_deref(),
                        req_body: $s.txn.as_ref().and_then(|t| t.req_body.as_deref()),
                        fe_name,
                        be_name,
                        captures_req_hdr: Some(&$s.log.req_captures),
                        unique_id: $s.log.unique_id.as_deref(),
                        be_max_retries: Some(be_retries),
                        cur_max_retries: Some($s.max_retries),
                        act_conn,
                        cum_conn,
                        sc_http_req_rates,
                        sc_conn_rates,
                        ..Default::default()
                    }
                };
            }

            for (rule_idx, rule) in rules.iter().enumerate().skip(start) {
                let matches = match &rule.cond {
                    None => true,
                    Some(cond) => eval_condition(cond, &make_ctx!(sess), acls, registry),
                };
                if !matches {
                    continue;
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
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, &resp);
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Allow => {
                        return Ok(RuleFlow::Next);
                    }
                    ibex_config::HttpReqAction::Auth => {
                        let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"HAProxy\"\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n";
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, resp.as_bytes());
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::Redirect { location, prefix, code, .. } => {
                        let status_code = code.unwrap_or(302);
                        let loc = location.as_deref().or(prefix.as_deref()).unwrap_or("/");
                        let formatted_loc = format_sample_string(loc, &make_ctx!(sess), registry);
                        let reason = status_reason(status_code);
                        let resp = format!(
                            "HTTP/1.1 {status_code} {reason}\r\nLocation: {formatted_loc}\r\nContent-Length: 0\r\n\r\n"
                        );
                        send_proxy_reply(sess, &proxies[..], proxy_idx, pages_idx, resp.as_bytes());
                        return Ok(RuleFlow::Replied);
                    }
                    ibex_config::HttpReqAction::SetPath { fmt } => {
                        let new_path = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, _, query) = split_uri(current_uri);
                            rebuild_uri(pfx, &new_path, query)
                        };
                        sess.with_htx_mut(|htx| {
                            let _ = htx.set_path(&new_path);
                        });
                        sess.req_uri = Some(rebuilt);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::ReplacePath { regex, repl } => {
                        let result = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, path, query) = split_uri(current_uri);
                            let rust_repl = translate_backreferences(repl);
                            if let Ok(re) = regex::Regex::new(regex) {
                                let new_path = re.replace_all(path, &rust_repl).to_string();
                                let rebuilt = rebuild_uri(pfx, &new_path, query);
                                Some((new_path, rebuilt))
                            } else {
                                None
                            }
                        };
                        if let Some((new_path, rebuilt)) = result {
                            sess.with_htx_mut(|htx| {
                                let _ = htx.set_path(&new_path);
                            });
                            sess.req_uri = Some(rebuilt);
                            rebuild_req_buffer(sess);
                        }
                    }
                    ibex_config::HttpReqAction::SetPathq { fmt } => {
                        let new_pathq = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, _, _) = split_uri(current_uri);
                            format!("{pfx}{new_pathq}")
                        };
                        sess.with_htx_mut(|htx| {
                            let _ = htx.set_uri(&rebuilt);
                        });
                        sess.req_uri = Some(rebuilt);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::ReplacePathq { regex, repl } => {
                        let result = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, path, query) = split_uri(current_uri);
                            let pathq = if query.is_empty() { path.to_string() } else { format!("{path}?{query}") };
                            let rust_repl = translate_backreferences(repl);
                            if let Ok(re) = regex::Regex::new(regex) {
                                let new_pathq = re.replace_all(&pathq, &rust_repl).to_string();
                                let rebuilt = format!("{pfx}{new_pathq}");
                                Some(rebuilt)
                            } else {
                                None
                            }
                        };
                        if let Some(rebuilt) = result {
                            sess.with_htx_mut(|htx| {
                                let _ = htx.set_uri(&rebuilt);
                            });
                            sess.req_uri = Some(rebuilt);
                            rebuild_req_buffer(sess);
                        }
                    }
                    ibex_config::HttpReqAction::SetQuery { fmt } => {
                        let new_query = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let rebuilt = {
                            let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                            let (pfx, path, _) = split_uri(current_uri);
                            rebuild_uri(pfx, path, &new_query)
                        };
                        sess.with_htx_mut(|htx| {
                            let _ = htx.set_uri(&rebuilt);
                        });
                        sess.req_uri = Some(rebuilt);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::SetUri { fmt } => {
                        let new_uri = format_sample_string(fmt, &make_ctx!(sess), registry);
                        sess.with_htx_mut(|htx| {
                            let _ = htx.set_uri(&new_uri);
                        });
                        sess.req_uri = Some(new_uri);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::SetMethod { fmt } => {
                        let new_method = format_sample_string(fmt, &make_ctx!(sess), registry);
                        sess.with_htx_mut(|htx| {
                            let _ = htx.set_method(&new_method);
                        });
                        sess.req_method = Some(new_method);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::SetSrc { expr } => {
                        let val = if let Ok(e) = Expr::parse(expr) {
                            e.eval_sample(registry, &make_ctx!(sess))
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &make_ctx!(sess), registry)
                        };
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            sess.client_addr = Some(SocketAddr::new(ip, 0));
                        }
                    }
                    ibex_config::HttpReqAction::SetDstPort { expr } => {
                        // `tcp_action_req_set_dst_port` (src/tcp_act.c): the value as an
                        // integer, truncated to 16 bits, on the stream's destination; an
                        // address of another family becomes 0.0.0.0.
                        let port = Expr::parse(expr)
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
                                let n = Expr::parse(expr)
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
                        let val = if let Ok(e) = Expr::parse(expr) {
                            e.eval_sample(registry, &make_ctx!(sess))
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &make_ctx!(sess), registry)
                        };
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            sess.server_addr = Some(SocketAddr::new(ip, 0));
                        }
                    }
                    ibex_config::HttpReqAction::SetVar { var_name, expr } => {
                        let val = if let Ok(e) = Expr::parse(expr) {
                            e.eval_sample(registry, &make_ctx!(sess))
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &make_ctx!(sess), registry)
                        };
                        if var_name.starts_with("proc.") {
                            ibex_sample::set_proc_var(var_name, val);
                        } else {
                            if var_name.starts_with("sess.") {
                                sess.sess_vars.insert(var_name.clone(), val.clone());
                            } else {
                                sess.req_vars.insert(var_name.clone(), val.clone());
                            }
                            CURRENT_VARS.with(|v| {
                                v.borrow_mut().insert(var_name.clone(), val);
                            });
                        }
                    }
                    ibex_config::HttpReqAction::SetVarFmt { var_name, fmt } => {
                        let val = format_sample_string(fmt, &make_ctx!(sess), registry);
                        if var_name.starts_with("proc.") {
                            ibex_sample::set_proc_var(var_name, val);
                        } else {
                            if var_name.starts_with("sess.") {
                                sess.sess_vars.insert(var_name.clone(), val.clone());
                            } else {
                                sess.req_vars.insert(var_name.clone(), val.clone());
                            }
                            CURRENT_VARS.with(|v| {
                                v.borrow_mut().insert(var_name.clone(), val);
                            });
                        }
                    }
                    ibex_config::HttpReqAction::UnsetVar { var_name } => {
                        if var_name.starts_with("sess.") {
                            sess.sess_vars.remove(var_name);
                        } else {
                            sess.req_vars.remove(var_name);
                        }
                        CURRENT_VARS.with(|v| {
                            v.borrow_mut().remove(var_name);
                        });
                    }
                    ibex_config::HttpReqAction::StrictMode { on } => {
                        STRICT_MODE.set(*on);
                    }
                    ibex_config::HttpReqAction::SetTimeout { timeout_type, timeout_val } => {
                        let ms = if let Ok(expr) = Expr::parse(timeout_val) {
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
                        CURRENT_TIMEOUTS.with(|t| {
                            let mut map = t.borrow_mut();
                            match timeout_type.as_str() {
                                "client" => {
                                    map.insert("cur_client_timeout", ms);
                                    map.insert("cur_client_timeout_set", 1);
                                }
                                "server" => {
                                    map.insert("cur_server_timeout", ms);
                                    map.insert("cur_server_timeout_set", 1);
                                }
                                "connect" => {
                                    map.insert("cur_connect_timeout", ms);
                                    map.insert("cur_connect_timeout_set", 1);
                                }
                                "queue" => {
                                    map.insert("cur_queue_timeout", ms);
                                    map.insert("cur_queue_timeout_set", 1);
                                }
                                "tunnel" => {
                                    map.insert("cur_tunnel_timeout", ms);
                                    map.insert("cur_tunnel_timeout_set", 1);
                                }
                                "tarpit" => {
                                    map.insert("cur_tarpit_timeout", ms);
                                    map.insert("cur_tarpit_timeout_set", 1);
                                }
                                _ => {}
                            }
                        });
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
                        let val = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let added = name.len() + val.len() + 4;
                        let total = REWRITE_ADDED_BYTES.get() + added;
                        if total > MAX_REWRITE_LIMIT.get() {
                            if STRICT_MODE.get() {
                                return Err(500);
                            }
                        } else {
                            REWRITE_ADDED_BYTES.set(total);
                            set_req_header(sess, name, &val);
                        }
                    }
                    ibex_config::HttpReqAction::AddHeader { name, fmt } => {
                        let val = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let added = name.len() + val.len() + 4;
                        let total = REWRITE_ADDED_BYTES.get() + added;
                        if total > MAX_REWRITE_LIMIT.get() {
                            if STRICT_MODE.get() {
                                return Err(500);
                            }
                        } else {
                            REWRITE_ADDED_BYTES.set(total);
                            add_req_header(sess, name, &val);
                        }
                    }
                    ibex_config::HttpReqAction::DelHeader { name } => {
                        del_req_header(sess, name);
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
                    ibex_config::HttpReqAction::ScIncGpc0 { sc } => {
                        let sc_idx = *sc as usize;
                        if sc_idx < 3 {
                            if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                                if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                                    let _ = tbl.update_entry(key, |data| {
                                        data.gpc0 = data.gpc0.saturating_add(1);
                                        data.last_updated = std::time::Instant::now();
                                    });
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::ScIncGpc1 { sc } => {
                        let sc_idx = *sc as usize;
                        if sc_idx < 3 {
                            if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                                if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                                    let _ = tbl.update_entry(key, |data| {
                                        data.gpc1 = data.gpc1.saturating_add(1);
                                        data.last_updated = std::time::Instant::now();
                                    });
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::ScSetGpt0 { sc, expr } => {
                        let sc_idx = *sc as usize;
                        if sc_idx < 3 {
                            if let Some((t_idx, ref key)) = sess.tracked_sc[sc_idx] {
                                let val = resolve_gpt0_val(expr, registry, &make_ctx!(sess));
                                if let Some(tbl) = proxies.get(t_idx).and_then(|p| p.stick_table.as_ref()) {
                                    let _ = tbl.update_entry(key, |data| {
                                        data.gpt0 = val;
                                        data.last_updated = std::time::Instant::now();
                                    });
                                }
                            }
                        }
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
        let be_idx = if resume_be { entry.backend_idx } else { Self::resolve_backend(entry, proxies) };
        entry.backend_idx = be_idx;
        // `stream_set_backend` (src/stream.c): switching to a backend takes its retry
        // budget, whatever a frontend-side `set-retries` set.
        if be_idx != proxy_idx && !resume_be {
            entry.sess.set_retries(proxies[be_idx].retries);
        }
        // The server side runs on the backend's timeouts, as in HAProxy.
        if be_idx != proxy_idx {
            let t = proxies[be_idx].timeouts;
            entry.sess.timeouts.server = t.server;
            entry.sess.timeouts.connect = t.connect;
        }

        // Evaluate backend tcp-request content rules
        if !resume_be && !proxies[be_idx].tcp_req_content_rules.is_empty() {
            let res = eval_tcp_req_content_rules(
                &proxies[be_idx],
                proxies,
                sample_registry(),
                &mut entry.sess,
                now,
            );
            match res {
                ContentEvalResult::Reject => {
                    raw::abort_with_rst(entry.sess.cli.as_fd());
                    proxies[be_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return None;
                }
                ContentEvalResult::SilentDrop => {
                    let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                    raw::silent_drop(entry.sess.cli.as_fd(), is_ipv6);
                    proxies[be_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return None;
                }
                ContentEvalResult::Done | ContentEvalResult::Waiting => {}
            }
        }

        // Update backend timeouts
        CURRENT_TIMEOUTS.with(|t| {
            let mut map = t.borrow_mut();
            let be_server = proxies[be_idx].stats_config.raw_timeouts.server.map_or(0, millis_to_u32);
            let be_connect = proxies[be_idx].stats_config.raw_timeouts.connect.map_or(0, millis_to_u32);
            let be_queue = proxies[be_idx].stats_config.raw_timeouts.queue.map_or(0, millis_to_u32);
            let be_tunnel = proxies[be_idx].stats_config.raw_timeouts.tunnel.map_or(0, millis_to_u32);
            let be_tarpit = proxies[be_idx].stats_config.raw_timeouts.tarpit.map_or(0, millis_to_u32);

            map.insert("be_server_timeout", be_server);
            map.insert("be_connect_timeout", be_connect);
            map.insert("be_queue_timeout", be_queue);
            map.insert("be_tunnel_timeout", be_tunnel);
            map.insert("be_tarpit_timeout", be_tarpit);

            if be_idx != proxy_idx {
                map.insert("cur_server_timeout", be_server);
                map.insert("cur_connect_timeout", be_connect);
                map.insert("cur_queue_timeout", be_queue);
                map.insert("cur_tunnel_timeout", be_tunnel);
            }
        });

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

        // Apply forwardfor & originalto header injection. As in HAProxy
        // (`http_handle_xff_header`), the option applies when the frontend or the backend
        // sets it, and it is not applied to an address in the `except` network of any
        // proxy that sets it.
        let fe_be = [proxy_idx, be_idx];
        let xff_excepts: Vec<&str> = fe_be.iter().filter_map(|&i| proxies[i].stats_config.forwardfor.as_deref()).collect();
        if !xff_excepts.is_empty() {
            let client_ip = entry.sess.client_addr.map(|a| a.ip());
            if let Some(ip) = client_ip {
                let in_except = xff_excepts.iter().any(|e| !e.is_empty() && ip_in_cidr(ip, e));
                if !in_except {
                    let ip_str = ip.to_string();
                    set_req_header(&mut entry.sess, "X-Forwarded-For", &ip_str);
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
                    set_req_header(&mut entry.sess, "X-Original-To", &ip_str);
                }
            }
        }

        let source_ip = entry.sess.client_addr.map(|a| a.ip());
        // The backend's `cookie` line: the client's cookies are cut and may name the server.
        let cookie_server = manage_client_cookies(&mut entry.sess, &proxies[be_idx]);
        let target = if let Some(idx) = cookie_server {
            Some(proxies[be_idx].servers[idx])
        } else {
            proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref())
        };

        let Some(target_addr) = target else {
            proxies[be_idx].stats[worker_id()].failed_conn.fetch_add(1, Ordering::Relaxed);
            reply_error(entry, proxies, 503);
            return None;
        };

        // The connection kept from this session's last transaction, if this request goes
        // to the same server: no new connection, no pool round trip. Otherwise it goes to
        // the pool (or is closed) and the request is routed as usual.
        if entry.sess.srv.is_some() {
            // A server that maps the destination may have been reached at another
            // address than this request's destination names; it is not kept.
            let same = entry.srv_backend_idx == be_idx
                && entry.target_addr == Some(target_addr)
                && !maps_destination(target_addr)
                // A connection opened with a PROXY header carries only requests that would
                // send that same header: HAProxy hashes it into the reuse key, so a
                // per-request unique-id TLV gets a connection of its own.
                && (!entry.sess.send_proxy_prepended
                    || proxy_header(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr)
                        .is_some_and(|h| h == entry.sess.send_proxy_header));
            if same
                && matches!(entry.sess.srv_state, ScState::Ready | ScState::Established)
                && entry.sess.rep.is_empty()
            {
                // Its server timer is the last transaction's; this one starts its own.
                entry.sess.server_connected(now);
                if let Some(txn) = entry.sess.txn.as_mut() {
                    txn.srv_reused = true;
                }
                return None;
            }
            release_server(entry, proxies, fdtab, poller, idle_pool, true);
        }

        let s_idx = cookie_server.or_else(|| proxies[be_idx].servers.iter().position(|&s| s == target_addr));
        if let Some(idx) = s_idx {
            if idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
        entry.target_server_idx = s_idx;
        entry.srv_backend_idx = be_idx;

        maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

        entry.target_addr = Some(target_addr);

        let mut reused_fd = None;
        if proxies[be_idx].http_reuse != ibex_config::HttpReuse::Never {
            if let Some(pool) = idle_pool.get_mut(&target_addr) {
                while let Some(candidate) = pool.pop() {
                    if raw::is_idle_conn_alive(candidate.as_fd()) {
                        reused_fd = Some(candidate);
                        break;
                    }
                }
            }
        }

        if let Some(srv_fd) = reused_fd {
            let sfd = srv_fd.as_raw_fd();
            entry.srv_raw_fd = Some(sfd);
            entry.sess.attach_server(srv_fd, now);
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
        } else if let Ok((srv_fd, immediate)) = raw::connect(connect_addr(target_addr, entry.sess.server_addr)) {
            let sfd = srv_fd.as_raw_fd();
            entry.srv_raw_fd = Some(sfd);
            entry.sess.attach_server(srv_fd, now);
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
            proxies[be_idx].stats[worker_id()].failed_conn.fetch_add(1, Ordering::Relaxed);
            retry_server_connect(entry, proxies, fdtab, poller, now);
        }
        None
    }

    fn connect_tcp_backend(
        entry: &mut SessionEntry,
        proxies: &mut [Proxy],
        fdtab: &mut FdTab,
        poller: &mut Poller,
        now: Tick,
    ) {
        let be_idx = Self::resolve_backend(entry, proxies);
        entry.backend_idx = be_idx;
        if be_idx != entry.proxy_idx {
            entry.sess.set_retries(proxies[be_idx].retries);
        }
        arm_res_inspect(&proxies[be_idx], &mut entry.sess);

        if !proxies[be_idx].tcp_req_content_rules.is_empty() {
            let res = eval_tcp_req_content_rules(
                &proxies[be_idx],
                proxies,
                sample_registry(),
                &mut entry.sess,
                now,
            );
            match res {
                ContentEvalResult::Reject => {
                    raw::abort_with_rst(entry.sess.cli.as_fd());
                    proxies[be_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return;
                }
                ContentEvalResult::SilentDrop => {
                    let is_ipv6 = entry.sess.client_addr.is_some_and(|a| a.is_ipv6());
                    raw::silent_drop(entry.sess.cli.as_fd(), is_ipv6);
                    proxies[be_idx].stats[worker_id()].denied_req.fetch_add(1, Ordering::Relaxed);
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    return;
                }
                ContentEvalResult::Done | ContentEvalResult::Waiting => {}
            }
        }

        let source_ip = entry.sess.client_addr.map(|a| a.ip());
        let target = proxies[be_idx].select_server_with_key(source_ip, entry.sess.req_uri.as_deref());

        let Some(target_addr) = target else {
            entry.sess.srv_state = ScState::Error;
            return;
        };

        let s_idx = proxies[be_idx]
            .servers
            .iter()
            .position(|&s| s == target_addr);
        if let Some(idx) = s_idx {
            if idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
        entry.target_server_idx = s_idx;
        entry.srv_backend_idx = be_idx;

        maybe_prepend_send_proxy(&proxies[entry.proxy_idx], &proxies[be_idx], proxies, &mut entry.sess, target_addr);

        entry.target_addr = Some(target_addr);
        if let Ok((srv_fd, immediate)) = raw::connect(connect_addr(target_addr, entry.sess.server_addr)) {
            let sfd = srv_fd.as_raw_fd();
            entry.srv_raw_fd = Some(sfd);
            entry.sess.attach_server(srv_fd, now);
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
            proxies[be_idx].stats[worker_id()].failed_conn.fetch_add(1, Ordering::Relaxed);
            retry_server_connect(entry, proxies, fdtab, poller, now);
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
                self.proxies[proxy_idx].server_statuses[server_idx].store(check.status as u8, Ordering::Relaxed);
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
                self.send_log(proxy_idx, LogLevel::Notice, &msg);
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
    fn send_log_line(&self, proxy_idx: usize, line: &str) {
        self.send_log(proxy_idx, LogLevel::Info, line);
    }

    fn send_log(&self, proxy_idx: usize, level: LogLevel, msg: &str) {
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
    if let Ok(e) = Expr::parse(expr_str) {
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

pub(crate) fn resolve_sample_stick_key(
    expr_str: &str,
    registry: &Registry,
    ctx: &SampleContext,
) -> Option<StickKey> {
    if expr_str == "src" {
        return ctx.client_addr.map(|a| StickKey::Ip(a.ip()));
    }
    if let Ok(expr) = Expr::parse(expr_str) {
        if let Some(smp) = expr.eval_sample(registry, ctx) {
            return match smp {
                Sample::Ipv4(ip) => Some(StickKey::Ip(std::net::IpAddr::V4(ip))),
                Sample::Ipv6(ip) => Some(StickKey::Ip(std::net::IpAddr::V6(ip))),
                Sample::Sint(i) => Some(StickKey::Integer(i.cast_unsigned())),
                Sample::Str(s) => {
                    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                        Some(StickKey::Ip(ip))
                    } else {
                        Some(StickKey::String(s))
                    }
                }
                Sample::Bin(b) => Some(StickKey::Binary(b)),
                Sample::Bool(b) => Some(StickKey::Integer(u64::from(b))),
                Sample::Meth(m) => Some(StickKey::String(m.as_str().to_string())),
            };
        }
    }
    ctx.client_addr.map(|a| StickKey::Ip(a.ip()))
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
                if let Ok(expr) = Expr::parse(&expr_str) {
                    if let Some(smp) = expr.eval_sample(registry, ctx) {
                        out.push_str(&sample_to_string(&smp));
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

fn translate_backreferences(repl: &str) -> String {
    let mut out = String::with_capacity(repl.len());
    let mut chars = repl.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next_c) = chars.peek() {
                if next_c.is_ascii_digit() {
                    chars.next();
                    out.push('$');
                    out.push(next_c);
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

fn header_name_matches(header_key: &str, pattern: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("\0m:") {
        if let Some((meth, pat)) = rest.split_once(':') {
            match meth {
                "beg" => header_key.to_lowercase().starts_with(&pat.to_lowercase()),
                "end" => header_key.to_lowercase().ends_with(&pat.to_lowercase()),
                "sub" => header_key.to_lowercase().contains(&pat.to_lowercase()),
                "reg" => regex::Regex::new(pat).is_ok_and(|re| re.is_match(header_key)),
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

/// The time now. `step` takes its tick before it waits in the poller, so a stream woken by a
/// request after an idle second would arm a `wait-for-body` of 300 ms from a second ago;
/// `now`, the pass's tick, stands in where no step has run on this thread.
fn fresh_tick(now: Tick) -> Tick {
    TICK_EPOCH.with(Cell::get).map_or(now, |start| {
        let ms = u32::try_from(start.elapsed().as_millis() & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        Tick(if ms == 0 { 1 } else { ms })
    })
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
    // An HTTP/2 client's body does not pass through `req`: there is nothing to wait for.
    if sess.h2_ctx.is_some() {
        return BodyWait::Ready;
    }
    let Some(txn) = sess.txn.as_ref() else {
        return BodyWait::Ready;
    };
    let framing = match txn.req {
        MsgState::Head { body, .. } => body,
        _ => crate::txn::Framing::None,
    };
    let held = txn.body_wait.filter(|w| w.backend == backend && w.rule == rule);
    let now = fresh_tick(now);
    let deadline = match held {
        Some(w) => w.deadline,
        None => {
            // `Expect: 100-continue`: the client is invited to send its body now, and the
            // server, which was not asked, is not told to.
            let asks = |name: &str, value: &str| name.eq_ignore_ascii_case("expect") && value.trim().eq_ignore_ascii_case("100-continue");
            let expects = if let Some(htx) = sess.htx_slice() {
                htx.headers().any(|(name, value)| asks(name, value))
            } else {
                sess.req_headers.as_ref().is_some_and(|h| h.iter().any(|(name, value)| asks(name, value)))
            };
            if expects {
                sess.send_before_close(b"HTTP/1.1 100 Continue\r\n\r\n");
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
    let Some(txn) = sess.txn.as_mut() else {
        return outcome;
    };
    if matches!(outcome, BodyWait::Pending) {
        txn.body_wait = Some(crate::txn::BodyWait { backend, rule, deadline });
    } else {
        txn.body_wait = None;
        if matches!(outcome, BodyWait::Ready) {
            txn.req_body = Some(body);
        }
    }
    outcome
}

fn del_req_header(sess: &mut TcpSession, name: &str) {
    sess.with_htx_mut(|htx| {
        let _ = htx.remove_header(name);
    });
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    hdrs.retain(|(k, _)| !header_name_matches(k, name));
    sess.req_headers = Some(hdrs);
    rebuild_req_buffer(sess);
}

fn replace_req_header(sess: &mut TcpSession, name: &str, regex: &str, repl: &str) -> Result<(), ()> {
    rewrite_req_header_values(sess, name, regex, repl, false)
}

fn replace_req_value(sess: &mut TcpSession, name: &str, regex: &str, repl: &str) -> Result<(), ()> {
    rewrite_req_header_values(sess, name, regex, repl, true)
}

/// `replace-header` (`per_value` false: the whole value) and `replace-value` (`per_value`
/// true: each comma-separated value, trimmed, rejoined with `,` as HAProxy rejoins them) on
/// the request, `repl` written with HAProxy's `\N` back-references.
///
/// The head is the HTX one. The replacement given to it was `repl` untranslated, so a
/// back-reference arrived as the literal text `\1`, and `replace-value` was applied to the
/// whole value; the translated, per-value form went only to `req_headers`, which is empty
/// once the head has been parsed into HTX. And the growth was checked only against a 1 MB
/// ceiling, so a value expanded past the buffer was forwarded where HAProxy answers 500:
/// it now comes out of the `maxrewrite` budget `add-header` and `set-header` use, and
/// fails the request under `strict-mode on`.
fn rewrite_req_header_values(
    sess: &mut TcpSession,
    name: &str,
    regex: &str,
    repl: &str,
    per_value: bool,
) -> Result<(), ()> {
    let re = regex::Regex::new(regex).map_err(|_| ())?;
    let rust_repl = translate_backreferences(repl);
    let rewrite = |v: &str| -> String {
        if per_value {
            v.split(',').map(|p| re.replace_all(p.trim(), rust_repl.as_str()).into_owned()).collect::<Vec<_>>().join(",")
        } else {
            re.replace_all(v, rust_repl.as_str()).into_owned()
        }
    };
    let edits: Vec<(String, String)> = sess.htx_slice().map_or_else(Vec::new, |h| {
        h.headers()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| (v.to_string(), rewrite(v)))
            .filter(|(old, new)| old != new)
            .collect()
    });
    let growth: usize = edits.iter().map(|(old, new)| new.len().saturating_sub(old.len())).sum();
    let total = REWRITE_ADDED_BYTES.get() + growth;
    if total > MAX_REWRITE_LIMIT.get() {
        return if STRICT_MODE.get() { Err(()) } else { Ok(()) };
    }
    REWRITE_ADDED_BYTES.set(total);
    sess.with_htx_mut(|htx| {
        for (old, new) in &edits {
            // Each value is replaced whole and literally: `$` is the only special
            // character in a `regex` replacement.
            let _ = htx.replace_header(name, &format!("^{}$", regex::escape(old)), &new.replace('$', "$$"));
        }
    });
    rebuild_req_buffer(sess);
    Ok(())
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
        sess.req.replace_prefix(hdr_len + eoh_len, &htx.write_h1_wire_vec());
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
    acls: &HashMap<String, Expr>,
    registry: &Registry,
) -> bool {
    crate::proxy::combine_condition(cond, |term| {
        let term_res = if term.name == "always_true" {
            true
        } else if term.name == "always_false" {
            false
        } else if let Some(expr) = acls.get(&term.name) {
            expr.eval(registry, ctx)
        } else if let Ok(expr) = Expr::parse(&term.name) {
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
    match status {
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResStop {
    Page(u16),
    Empty(u16),
}

/// One `http-response` or `http-after-response` action, whichever list it comes from.
/// The configuration encodes the actions that are not header edits as a `SetHeader` (or,
/// for `unset-var`, a `DelHeader`) whose name starts with a NUL (`rules_http.rs`).
#[derive(Clone, Copy)]
enum ResOp<'a> {
    Set(&'a str, &'a str),
    Add(&'a str, &'a str),
    Del(&'a str),
    Status(u16),
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
            ibex_config::HttpResAction::SetStatus { status } => Self::Status(*status),
            ibex_config::HttpResAction::Capture { expr, id } => return ResRule::Capture(expr, *id),
            ibex_config::HttpResAction::WaitForBody { time_ms, at_least } => return ResRule::Wait(*time_ms, *at_least),
        })
    }

    fn of_after_res(a: &'a ibex_config::HttpAfterResAction) -> ResRule<'a> {
        ResRule::Op(match a {
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

/// `exp_replace` (`src/regex.c`): `repl` with `\0`..`\9` replaced by that group of the
/// match (nothing for a group that did not take part), `\xHH` by that byte -- computed as
/// `HAProxy` computes it, which takes any two characters -- and a backslash before
/// anything else dropped. `None`, a failed rewrite, for a backslash or `\x` cut short.
fn exp_replace(repl: &str, caps: &regex::Captures<'_>) -> Option<String> {
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
                out.extend_from_slice(m.as_str().as_bytes());
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
fn replace_each_value(v: &str, re: &regex::Regex, repl: &str) -> Option<String> {
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
        ResOp::Status(st) => {
            let reason = status_reason(st);
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
        return res_action(ResOp::Status(act_fmt.parse().unwrap_or(*status)), hdrs, status, status_msg, ctx, registry, sess_vars, req_vars);
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
        let Ok(re) = regex::Regex::new(re_str) else { return Ok(true) };
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
    rules: impl Iterator<Item = (ResRule<'a>, Option<&'a ibex_config::AclCondition>)>,
    acls: &HashMap<String, Expr>,
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
    for (idx, (op, cond)) in rules.enumerate().skip(start) {
        // The slots as the earlier rules left them, for `capture.res.hdr`.
        let with_caps;
        let ctx = match &caps {
            Some((slots, _)) => {
                with_caps = SampleContext { captures_res_hdr: Some(slots.as_slice()), ..ctx.clone() };
                &with_caps
            }
            None => ctx,
        };
        if cond.is_some_and(|c| !eval_condition(c, ctx, acls, registry)) {
            continue;
        }
        let op = match op {
            ResRule::Op(op) => op,
            ResRule::Capture(expr, id) => {
                // No sample, no capture (the slot keeps what it had); an `id` past the frontend's
                // slots captures nothing (`http_action_res_capture_by_id`: `id >= fe->nb_rsp_cap`).
                let val = Expr::parse(expr).ok().and_then(|e| e.eval_sample(registry, ctx)).map(|smp| sample_to_string(&smp));
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
    registry: &Registry,
    sess_vars: &mut HashMap<String, String>,
    req_vars: &mut HashMap<String, String>,
) -> Result<(), ResStop> {
    let (hdrs, status, status_msg) = head;
    req_vars.retain(|k, _| !k.starts_with("req."));
    CURRENT_VARS.with(|v| v.borrow_mut().retain(|k, _| !k.starts_with("req.")));
    let order: &[usize] = if fe_idx == be_idx { &[be_idx] } else { &[be_idx, fe_idx] };
    for &px in order {
        let rules = proxies[px].http_after_res_rules.iter().map(|r| (ResOp::of_after_res(&r.action), r.cond.as_ref()));
        run_res_rules(rules, &proxies[px].acls, (&mut *hdrs, &mut *status, &mut *status_msg), ctx, None, registry, sess_vars, req_vars, None)?;
    }
    Ok(())
}

/// Sends a reply the proxy made itself -- `return`, `deny`, `redirect`, `auth`, an error
/// page -- through the `http-after-response` rules first, as `http_forward_proxy_resp`
/// does for every one of them. `be_idx` is the proxy standing as `s->be`: the frontend
/// until a backend is chosen.
///
/// A rule that fails turns the reply into the 500 page, which goes through the rules once
/// more; if they fail on that too, or the failed reply was already a 500, the 500 goes out
/// without them (`http_reply_and_close`, `TX_CONST_REPLY`).
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
    // The variables are the session's own: a reply made after the request rules (502, 504)
    // comes when other streams may have run theirs on this thread.
    CURRENT_VARS.with(|v| {
        let mut map = v.borrow_mut();
        map.clear();
        map.extend(sess.sess_vars.iter().chain(sess.req_vars.iter()).map(|(k, val)| (k.clone(), val.clone())));
    });
    let mut sess_vars = std::mem::take(&mut sess.sess_vars);
    let mut req_vars = std::mem::take(&mut sess.req_vars);
    let result = {
        let ctx = SampleContext {
            client_addr: sess.client_addr,
            server_addr: sess.server_addr,
            fc_src: sess.fc_src,
            fc_dst: sess.fc_dst,
            is_first_req: sess.is_first_req,
            proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            htx_slice: sess.htx_slice(),
            req_uri: sess.req_uri.as_deref(),
            req_method: sess.req_method.as_deref(),
            req_headers: sess.req_headers.as_deref(),
            fe_name: Some(&proxies[fe_idx].name),
            be_name: Some(&proxies[be_idx].name),
            be_max_retries: Some(proxies[be_idx].retries),
            cur_max_retries: Some(sess.max_retries),
            res_version: Some(&version),
            unique_id: sess.log.unique_id.as_deref(),
            captures_req_hdr: Some(&sess.log.req_captures),
            captures_res_hdr: Some(&sess.log.res_captures),
            ..Default::default()
        };
        eval_after_res_rules(
            proxies,
            fe_idx,
            be_idx,
            (&mut hdrs, &mut status, &mut reason),
            &ctx,
            sample_registry(),
            &mut sess_vars,
            &mut req_vars,
        )
    };
    sess.sess_vars = sess_vars;
    sess.req_vars = req_vars;
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
                    fc_dst: sess.fc_dst,
                    is_first_req: sess.is_first_req,
                    htx_slice: sess.htx_slice(),
                    req_uri: sess.req_uri.as_deref(),
                    req_method: sess.req_method.as_deref(),
                    req_headers: sess.req_headers.as_deref(),
                    fe_name: Some(fe.name.as_str()),
                    be_name: Some(be.name.as_str()),
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
        build_sample_registry, inject_connection_close_header_zero_alloc,
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

    #[test]
    fn test_inject_connection_close_zero_alloc() {
        let mut b = crate::buf::Buf::standard();
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        b.writable()[..raw.len()].copy_from_slice(raw);
        b.commit(raw.len());
        inject_connection_close_header_zero_alloc(&mut b);
        // Exact bytes. `contains` passed while the header was glued onto the previous one
        // ("Content-Length: 2Connection: close") and a blank line was added -- every
        // response Ibex closed after went out that way.
        assert_eq!(
            std::str::from_utf8(b.readable()).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        );
    }

    #[test]
    fn test_inject_connection_close_bare_lf() {
        let mut b = crate::buf::Buf::standard();
        let raw = b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok";
        b.writable()[..raw.len()].copy_from_slice(raw);
        b.commit(raw.len());
        inject_connection_close_header_zero_alloc(&mut b);
        assert_eq!(
            std::str::from_utf8(b.readable()).unwrap(),
            "HTTP/1.1 200 OK\nContent-Length: 2\nConnection: close\r\n\nok"
        );
    }
}
