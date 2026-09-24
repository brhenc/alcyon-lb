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
use crate::syslog::SyslogTarget;
use ibex_config::LogLevel;
use crate::proxy::{TcpSession, Timeouts};
use crate::raw;
use ibex_config::{regex, BalanceAlgorithm, Config, Mode, StickRule, UseBackendRule};
use ibex_proto::endpoint::ScState;
use ibex_sample::{Expr, Registry, Sample, SampleContext};
use ibex_sched::task::{state, Kind, TaskRef, WorkKind};
use ibex_sched::{Class, Dispatch, Outcome, Scheduler, Tick};
use ibex_stick_table::{KeyType, StickKey, StickTable, StickTableConfig};
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
    set_proc_var, CURRENT_RES_HEADERS, CURRENT_RES_STATUS, CURRENT_TIMEOUTS, CURRENT_VARS,
};

thread_local! {
    pub static WORKER_ID: Cell<usize> = const { Cell::new(0) };
    static STRICT_MODE: Cell<bool> = const { Cell::new(true) };
    static REWRITE_ADDED_BYTES: Cell<usize> = const { Cell::new(0) };
    static MAX_REWRITE_LIMIT: Cell<usize> = const { Cell::new(8192) };
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
    pub addr: SocketAddr,
    pub mode: Mode,
    pub balance: BalanceAlgorithm,
    pub timeouts: Timeouts,
    pub retries: u16,
    pub redisp: bool,
    pub maxconn: u32,
    pub dispatch: Option<SocketAddr>,
    pub cookie_name: Option<String>,
    pub cliexp: Vec<ibex_proto::CompiledExp>,
    pub srvexp: Vec<ibex_proto::CompiledExp>,
    pub servers: Vec<SocketAddr>,
    pub server_ids: Vec<String>,
    pub server_statuses: Arc<Vec<AtomicU8>>,
    pub server_weights: Vec<u32>,
    pub next_server_idx: Arc<AtomicUsize>,
    pub stats: Arc<Vec<ProxyStats>>,
    pub stats_config: ibex_config::StatsConfig,
    pub default_backend: Option<String>,
    pub use_backends: Vec<UseBackendRule>,
    pub acls: HashMap<String, Expr>,
    pub stick_table: Option<Arc<StickTable>>,
    pub stick_rules: Vec<StickRule>,
    pub accept_proxy: bool,
    pub accept_proxy_v2: bool,
    pub server_send_proxy: Vec<bool>,
    pub server_send_proxy_v2: Vec<bool>,
    pub server_backups: Vec<bool>,
    pub server_maxconn: Vec<Option<u32>>,
    pub server_actconn: Arc<Vec<AtomicU32>>,
    pub server_check_configs: Vec<Option<ServerCheckConfig>>,
    pub tcp_req_conn_rules: Vec<ibex_config::TcpReqConnRule>,
    pub tcp_req_session_rules: Vec<ibex_config::TcpReqSessionRule>,
    pub tcp_req_content_rules: Vec<ibex_config::TcpReqContentRule>,
    pub tcp_req_inspect_delay: Option<Duration>,
    pub http_req_rules: Vec<ibex_config::HttpReqRule>,
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
}

impl Proxy {
    /// Returns the indices of eligible servers for request routing.
    ///
    /// Active (non-backup) servers that are UP and not saturated (actconn < maxconn) are prioritized.
    /// If at least one active server is available, only active servers are returned (backup servers receive 0 traffic).
    /// If all active servers are DOWN (or saturated), returns available backup servers.
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

        // 2. Failover to backup servers if all active servers are unavailable
        let backup_up: Vec<usize> = (0..self.servers.len())
            .filter(|&idx| {
                let is_backup = self.server_backups.get(idx).copied().unwrap_or(false);
                is_backup && is_server_available(idx)
            })
            .collect();

        backup_up
    }

    /// Selects a server by ID if configured, UP, and not saturated.
    #[must_use]
    pub fn select_server_by_id(&self, id: &str) -> Option<SocketAddr> {
        for (idx, sid) in self.server_ids.iter().enumerate() {
            if sid == id && idx < self.servers.len() {
                let is_up = self.server_statuses.get(idx).map(|s| s.load(Ordering::Relaxed)) == Some(ServerStatus::Up as u8);
                let not_saturated = match self.server_maxconn.get(idx) {
                    Some(Some(mc)) if *mc > 0 => {
                        let act = self.server_actconn.get(idx).map(|a| a.load(Ordering::Relaxed)).unwrap_or(0);
                        act < *mc
                    }
                    _ => true,
                };
                if is_up && not_saturated {
                    return Some(self.servers[idx]);
                }
            }
        }
        None
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
    pub fn select_server_with_key(&mut self, source_ip: Option<IpAddr>) -> Option<SocketAddr> {
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
                if let Some(idx) = crate::lb::balance_uri(self, "/") {
                    Some(self.servers[idx])
                } else {
                    self.select_server()
                }
            }
            _ => self.select_server(),
        }
    }

    /// Selects a server using the URI load balancing algorithm with a specific URI string.
    #[must_use]
    pub fn select_server_with_uri(&mut self, uri: &str) -> Option<SocketAddr> {
        if self.servers.is_empty() {
            return self.dispatch;
        }
        if let Some(idx) = crate::lb::balance_uri(self, uri) {
            Some(self.servers[idx])
        } else {
            self.select_server()
        }
    }
}

/// A session registered in the runtime engine.
pub struct SessionEntry {
    pub sess: TcpSession,
    pub task: TaskRef,
    pub proxy_idx: usize,
    pub backend_idx: usize,
    pub target_server_idx: Option<usize>,
    pub target_addr: Option<SocketAddr>,
    pub cli_raw_fd: RawFd,
    pub srv_raw_fd: Option<RawFd>,
    pub cli_interest: Interest,
    pub srv_interest: Interest,
    pub actconn_reclaimed: bool,
    pub response_rules_applied: bool,
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
    /// Value for the syslog HOSTNAME field.
    log_hostname: String,
    /// Global `tune.bufsize` value, stored per-engine to avoid races in tests that run
    /// multiple engines in the same process against the global `BUFSIZE_STANDARD` atomic.
    global_bufsize: usize,
    /// Global `tune.maxrewrite` value, stored per-engine for the same reason.
    global_maxrewrite: usize,
    /// Global HTTP/2 flood mitigation configuration.
    pub global_h2_flood_config: ibex_proto::H2FloodConfig,
    /// Shared idle backend connection pool across sessions (`http-reuse`).
    pub idle_backend_pool: HashMap<SocketAddr, Vec<OwnedFd>>,
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(ref path) = self.cli_socket_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn compile_acls(acl_rules: &[ibex_config::AclRule]) -> HashMap<String, Expr> {
    let mut acls = HashMap::new();
    for rule in acl_rules {
        if let Ok(expr) = Expr::parse(&rule.expr) {
            acls.insert(rule.name.clone(), expr);
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
            .position(|t| t.same_destination(cfg))
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
            bind_tls(fe, bind.addr)?;
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
    fe: &ibex_config::FrontendSection,
    addr: SocketAddr,
) -> io::Result<Option<Arc<rustls::ServerConfig>>> {
    let Some(bind) = fe.binds.iter().find(|b| b.addr == addr && b.ssl) else {
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
                "frontend '{}': bind {addr} has 'ssl' but no 'crt'; refusing to start \
                 rather than serve cleartext on a port configured for TLS",
                fe.name
            ),
        ));
    }
    let cfg = ibex_tls::TlsConfig::from_bind_config(bind).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frontend '{}': bind {addr} ssl: {e}", fe.name),
        )
    })?;
    Ok(Some(cfg))
}

fn init_proxy_from_listen(proxy_idx: usize, listen: &ibex_config::ListenSection, nbthread: usize) -> Proxy {
    let timeouts = Timeouts {
        client: listen.clitimeout.map_or(0, millis_to_u32),
        server: listen.srvtimeout.map_or(0, millis_to_u32),
        connect: listen.contimeout.map_or(0, millis_to_u32),
    };

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
            server_check_configs.push(Some(cfg));
        } else {
            server_check_configs.push(None);
        }
    }

    Proxy {
        id: usize_to_u32(proxy_idx),
        name: listen.name.clone(),
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
        cookie_name: listen.cookie.clone(),
        cliexp,
        srvexp,
        servers: listen.servers.iter().map(|s| s.addr).collect(),
        server_ids: listen.servers.iter().map(|s| s.id.clone()).collect(),
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
        acls: compile_acls(&listen.acls),
        stick_table,
        stick_rules: listen.stick_rules.clone(),
        accept_proxy: listen.accept_proxy,
        accept_proxy_v2: listen.accept_proxy_v2,
        server_send_proxy: listen.servers.iter().map(|s| s.send_proxy).collect(),
        server_send_proxy_v2: listen.servers.iter().map(|s| s.send_proxy_v2).collect(),
        server_backups: listen.servers.iter().map(|s| s.backup).collect(),
        server_maxconn: listen.servers.iter().map(|s| s.maxconn).collect(),
        server_actconn: Arc::new((0..server_count).map(|_| AtomicU32::new(0)).collect()),
        server_check_configs,
        tcp_req_conn_rules: listen.tcp_req_conn_rules.clone(),
        tcp_req_session_rules: listen.tcp_req_session_rules.clone(),
        tcp_req_content_rules: listen.tcp_req_content_rules.clone(),
        tcp_req_inspect_delay: listen.tcp_req_inspect_delay,
        http_req_rules: listen.http_req_rules.clone(),
        http_res_rules: listen.http_res_rules.clone(),
        http_after_res_rules: listen.http_after_res_rules.clone(),
        http_reuse: listen.http_reuse.unwrap_or_default(),
    }
}

fn init_proxy_from_frontend(proxy_idx: usize, fe: &ibex_config::FrontendSection, nbthread: usize) -> Proxy {
    let timeouts = Timeouts {
        client: fe
            .clitimeout
            .or(fe.timeouts.client)
            .map_or(0, millis_to_u32),
        server: fe.timeouts.server.map_or(0, millis_to_u32),
        connect: fe.timeouts.connect.map_or(0, millis_to_u32),
    };

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
        cookie_name: None,
        cliexp,
        srvexp: Vec::new(),
        servers: Vec::new(),
        server_ids: Vec::new(),
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
        acls: compile_acls(&fe.acls),
        stick_table,
        stick_rules: fe.stick_rules.clone(),
        accept_proxy: fe.accept_proxy || fe.binds.iter().any(|b| b.accept_proxy),
        accept_proxy_v2: fe.accept_proxy_v2 || fe.binds.iter().any(|b| b.accept_proxy_v2),
        server_send_proxy: Vec::new(),
        server_send_proxy_v2: Vec::new(),
        server_backups: Vec::new(),
        server_maxconn: Vec::new(),
        server_actconn: std::sync::Arc::new(Vec::new()),
        server_check_configs: Vec::new(),
        tcp_req_conn_rules: fe.tcp_req_conn_rules.clone(),
        tcp_req_session_rules: fe.tcp_req_session_rules.clone(),
        tcp_req_content_rules: fe.tcp_req_content_rules.clone(),
        tcp_req_inspect_delay: fe.tcp_req_inspect_delay,
        http_req_rules: fe.http_req_rules.clone(),
        http_res_rules: fe.http_res_rules.clone(),
        http_after_res_rules: fe.http_after_res_rules.clone(),
        http_reuse: ibex_config::HttpReuse::default(),
    }
}

fn init_proxy_from_backend(proxy_idx: usize, be: &ibex_config::BackendSection, nbthread: usize) -> Proxy {
    let timeouts = Timeouts {
        client: be.timeouts.client.map_or(0, millis_to_u32),
        server: be
            .srvtimeout
            .or(be.timeouts.server)
            .map_or(0, millis_to_u32),
        connect: be
            .contimeout
            .or(be.timeouts.connect)
            .map_or(0, millis_to_u32),
    };

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
            server_check_configs.push(Some(cfg));
        } else {
            server_check_configs.push(None);
        }
    }

    Proxy {
        id: usize_to_u32(proxy_idx),
        name: be.name.clone(),
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
        cookie_name: be.cookie.clone(),
        cliexp: Vec::new(),
        srvexp,
        servers: be.servers.iter().map(|s| s.addr).collect(),
        server_ids: be.servers.iter().map(|s| s.id.clone()).collect(),
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
        acls: compile_acls(&be.acls),
        stick_table,
        stick_rules: be.stick_rules.clone(),
        accept_proxy: false,
        accept_proxy_v2: false,
        server_send_proxy: be.servers.iter().map(|s| s.send_proxy).collect(),
        server_send_proxy_v2: be.servers.iter().map(|s| s.send_proxy_v2).collect(),
        server_backups: be.servers.iter().map(|s| s.backup).collect(),
        server_maxconn: be.servers.iter().map(|s| s.maxconn).collect(),
        server_actconn: Arc::new((0..server_count).map(|_| AtomicU32::new(0)).collect()),
        server_check_configs,
        tcp_req_conn_rules: Vec::new(),
        tcp_req_session_rules: Vec::new(),
        tcp_req_content_rules: be.tcp_req_content_rules.clone(),
        tcp_req_inspect_delay: be.tcp_req_inspect_delay,
        http_req_rules: be.http_req_rules.clone(),
        http_res_rules: be.http_res_rules.clone(),
        http_after_res_rules: be.http_after_res_rules.clone(),
        http_reuse: be.http_reuse.unwrap_or_default(),
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
    /// Returns an error if epoll creation or binding any listener fails.
    #[allow(clippy::too_many_lines)]
    pub fn build_shared_state(config: &Config, nbthread: usize) -> io::Result<Vec<Proxy>> {
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
            let mut listener = Listener::bind(listen.addr, 128, usize_to_u32(proxy_idx))?;
            listener.maxconn = listen.maxconn;
            let l_idx = listeners.len();
            let lfd = listener.raw_fd();
            fdtab.insert(lfd, FdState::Listener { listener: usize_to_u32(l_idx) }, Interest::READ);
            poller.add(listener.borrowed_fd(), raw_fd_to_u64(lfd), true, false)?;
            listeners.push(listener);
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
                    let tls = bind_tls(frontend, bind_addr)?.expect("QUIC requires TLS");
                    
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
                    let mut listener = Listener::bind(bind_addr, 128, usize_to_u32(proxy_idx))?;
                    listener.maxconn = frontend.maxconn;
                    listener.tls = bind_tls(frontend, bind_addr)?;
                    let l_idx = listeners.len();
                    let lfd = listener.raw_fd();
                    fdtab.insert(lfd, FdState::Listener { listener: usize_to_u32(l_idx) }, Interest::READ);
                    poller.add(listener.borrowed_fd(), raw_fd_to_u64(lfd), true, false)?;
                    listeners.push(listener);
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
            now,
            is_running: true,
            worker_id,
            events: Vec::with_capacity(capacity * 2),
            timer_updates: Vec::with_capacity(capacity * 2),
            log_targets,
            log_tag: "haproxy".to_string(),
            log_hostname: hostname(),
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

        // 1. Expire scheduler timers
        self.scheduler.set_now(now);
        let _ = self.scheduler.wake_expired_tasks();

        // 2. Determine epoll wait timeout based on scheduler
        let poll_timeout = if self.scheduler.runnable() > 0 {
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
                    self.fdtab.set_ready(ev.fd, ev.readable, ev.writable);
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
        let pid = std::process::id();
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
            log_hostname: &self.log_hostname,
            idle_backend_pool: &mut self.idle_backend_pool,
        };

        let tasks_run = self.scheduler.process_runnable_tasks(&mut dispatcher);
        for &(task_ref, expiry) in &dispatcher.timer_updates {
            self.scheduler.queue_timer(task_ref, expiry);
        }
        for task_ref in dispatcher.wake_queue {
            self.scheduler
                .tasklet_wakeup(task_ref, Class::Urgent, state::WOKEN_IO);
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
            let now = self.current_tick();
            let _ = self.step(now)?;
        }
        Ok(())
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
    registry: &Registry,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    sc_conn_rates: [u64; 3],
) -> ConnEvalOutcome {
    let mut client_addr = peer_addr;
    let mut server_addr = local_addr;
    let fc_src = peer_addr;
    let fc_dst = local_addr;

    let mut ctx = SampleContext {
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
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    client_addr = sa;
                    ctx.client_addr = Some(client_addr);
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
                } else if let Ok(sa) = val.parse::<SocketAddr>() {
                    server_addr = sa;
                    ctx.server_addr = Some(server_addr);
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
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src,
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
        cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
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
        client_addr: sess.client_addr,
        server_addr: sess.server_addr,
        fc_src: sess.fc_src,
        fc_dst: sess.fc_dst,
        proxy_tlvs: sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
        req_body: if has_content { Some(req_bytes) } else { None },
        act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
        cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
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
        target_server_idx,
        target_addr,
        cli_raw_fd,
        srv_raw_fd,
        cli_interest,
        srv_interest: Interest::NONE,
        actconn_reclaimed: false,
        response_rules_applied: false,
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

fn maybe_prepend_send_proxy(proxy: &Proxy, sess: &mut TcpSession, target_addr: SocketAddr) {
    if sess.send_proxy_prepended {
        return;
    }
    if let Some(idx) = proxy.servers.iter().position(|&s| s == target_addr) {
        let send_v2 = proxy
            .server_send_proxy_v2
            .get(idx)
            .copied()
            .unwrap_or(false);
        let send_v1 = proxy.server_send_proxy.get(idx).copied().unwrap_or(false);

        if send_v2 {
            let src = sess.client_addr;
            let dst = sess.server_addr.or(Some(proxy.addr));
            let tlv_data = sess
                .proxy_info
                .as_ref()
                .map_or(&[] as &[u8], |p| &p.tlv_data);
            let hdr =
                ibex_proto::encode_proxy_v2(ibex_proto::ProxyCommand::Proxy, src, dst, tlv_data);
            sess.req.replace_prefix(0, &hdr);
            sess.send_proxy_prepended = true;
        } else if send_v1 {
            let src = sess.client_addr;
            let dst = sess.server_addr.or(Some(proxy.addr));
            let hdr = ibex_proto::encode_proxy_v1(src, dst);
            sess.req.replace_prefix(0, &hdr);
            sess.send_proxy_prepended = true;
        }
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
    let cookie_name = proxies[proxy_idx].cookie_name.clone();
    let cliexp = proxies[proxy_idx].cliexp.clone();
    let srvexp = proxies[proxy_idx].srvexp.clone();

    let mut sess = TcpSession::new_with_mode(
        cli_fd,
        mode,
        cookie_name,
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
    } else if mode == Mode::Tcp && !proxy.accept_proxy && !proxy.accept_proxy_v2 && sess.tcp_inspect_done {
        target_addr = proxy.select_server_with_key(sess.client_addr.map(|a| a.ip()));
        if let Some(target) = target_addr {
            maybe_prepend_send_proxy(proxy, &mut sess, target);

            if let Ok((srv_fd, immediate)) = raw::connect(target) {
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
            let be_idx = entry.backend_idx;
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
        let be_idx = entry.backend_idx;
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
    log_hostname: &'a str,
    idle_backend_pool: &'a mut HashMap<SocketAddr, Vec<OwnedFd>>,
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
        let old_be = entry.backend_idx;
        if old_be < proxies.len() && old_idx < proxies[old_be].server_actconn.len() {
            proxies[old_be].server_actconn[old_idx].fetch_sub(1, Ordering::Relaxed);
        }
    }

    let be_idx = EngineDispatcher::resolve_backend(entry, proxies);
    entry.backend_idx = be_idx;
    proxies[be_idx].stats[worker_id()].retries_count.fetch_add(1, Ordering::Relaxed);
    let source_ip = entry.sess.client_addr.map(|a| a.ip());
    let target = if proxies[be_idx].redisp {
        proxies[be_idx].select_server_with_key(source_ip)
    } else {
        entry
            .target_addr
            .or_else(|| proxies[be_idx].select_server_with_key(source_ip))
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

    maybe_prepend_send_proxy(&proxies[be_idx], &mut entry.sess, target_addr);

    entry.target_addr = Some(target_addr);
    if let Ok((srv_fd, immediate)) = raw::connect(target_addr) {
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
                entry.sess.send_synthetic_response(
                    503,
                    Some("text/html; charset=utf-8"),
                    Some("<html><body><h1>503 Service Unavailable</h1>Failed to connect to backend server.</body></html>\n"),
                );
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
                            entry.sess.send_synthetic_response(
                                503,
                                Some("text/html; charset=utf-8"),
                                Some("<html><body><h1>503 Service Unavailable</h1>Failed to connect to backend server.</body></html>\n"),
                            );
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
            let be_idx = entry.backend_idx;
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

impl EngineDispatcher<'_> {
    fn resolve_backend(entry: &SessionEntry, proxies: &[Proxy]) -> usize {
        let proxy_idx = entry.proxy_idx;
        let proxy = &proxies[proxy_idx];

        if proxy.use_backends.is_empty() && proxy.default_backend.is_none() {
            return proxy_idx;
        }

        let ctx = SampleContext {
            client_addr: entry.sess.client_addr,
            server_addr: entry.target_addr,
            fc_src: entry.sess.fc_src,
            fc_dst: entry.sess.fc_dst,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            req_body: if entry.sess.req.readable().is_empty() {
                None
            } else {
                Some(entry.sess.req.readable())
            },
            htx: None,
            htx_slice: entry.sess.htx_slice(),
            req_uri: entry.sess.req_uri.as_deref(),
            req_method: entry.sess.req_method.as_deref(),
            req_headers: entry.sess.req_headers.as_deref(),
            act_conn: proxy.stats[worker_id()].act_conn.load(Ordering::Relaxed),
            cum_conn: proxy.stats[worker_id()].cum_conn.load(Ordering::Relaxed),
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

    #[allow(clippy::too_many_lines)] // one dispatch chain; splitting it would obscure the order
    fn step_stream(&mut self, session_idx: u32) -> Outcome {
        let now = self.now;
        let (is_done, pending_admin) = {
            let Some(entry) = self.sessions.get_mut(session_idx) else {
                return Outcome::Done;
            };

            // Step 1: Server connect check if connecting
            check_srv_connect(entry, self.proxies, self.fdtab, self.poller, now);

            // Step 2: Check timeouts
            let _ = entry.sess.check_timeouts(now);

            // Step 2.5: In HTTP mode, if server is Ready to read response headers, read and apply rules before client writes
            if entry.sess.mode == Mode::Http
                && entry.sess.srv_state == ScState::Ready
                && !entry.response_rules_applied
            {
                if let Some(ref srv_fd) = entry.sess.srv {
                    if entry.sess.rep.writable().is_empty() && entry.sess.rep.len() < entry.sess.rep.capacity() {
                        entry.sess.rep.compact();
                    }
                    let w = entry.sess.rep.writable();
                    if !w.is_empty() {
                        match raw::recv(srv_fd.as_fd(), w) {
                            Ok(raw::Io::Done(n)) if n > 0 => {
                                entry.sess.rep.commit(n);
                                entry.sess.bytes_in += n as u64;
                                Self::apply_http_response_rules(entry, self.proxies, now);
                            }
                            Ok(raw::Io::Closed) => {
                                entry.sess.srv_state = ScState::ShutR;
                            }
                            _ => {}
                        }
                    }
                }
            }

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

            // Step 3.5: If in HTTP mode and request headers are parsed, initiate backend connect
            let mut pending_admin = None;
            if entry.sess.mode == Mode::Http
                && entry.sess.srv_state == ScState::Init
                && (entry.sess.cli_state == ScState::Established
                    || (entry.sess.cli_state == ScState::ShutR && (entry.sess.req_headers.is_some() || entry.sess.has_htx)))
                && (entry.sess.req_headers.is_some() || entry.sess.has_htx)
                && entry.sess.tcp_inspect_done
                && !entry.sess.is_done()
            {
                pending_admin = Self::connect_http_backend(
                    entry,
                    self.proxies,
                    self.checks,
                    self.pid,
                    self.fdtab,
                    self.poller,
                    self.idle_backend_pool,
                    now,
                );
            }

            // Step 3.6: If in TCP mode and server not yet connected (e.g. deferred on accept-proxy or inspect), connect once ready
            if entry.sess.mode == Mode::Tcp
                && entry.sess.srv_state == ScState::Init
                && (!entry.sess.accept_proxy || entry.sess.proxy_handshake_done)
                && entry.sess.tcp_inspect_done
                && !entry.sess.is_done()
            {
                Self::connect_tcp_backend(entry, self.proxies, self.fdtab, self.poller, now);
            }

            // Step 3.7: If in HTTP mode and response headers are ready in rep, apply response rules
            if entry.sess.mode == Mode::Http
                && !entry.response_rules_applied
                && !entry.sess.rep.is_empty()
            {
                Self::apply_http_response_rules(entry, self.proxies, now);
            }

            // Step 3.7b: If HTTP/2 session and response is ready in rep, convert to H2 response frames
            if let Some(ref mut h2) = entry.sess.h2_ctx {
                if entry.response_rules_applied && !entry.sess.rep.is_empty() {
                    let stream_id = entry.sess.h2_active_stream_id.unwrap_or(1);
                    if h2.send_h1_response(stream_id, entry.sess.rep.readable()) {
                        entry.sess.rep.clear();
                    }
                }
            }

            // Step 3.8: In HTTP mode, if a transaction has finished (response completely sent to client)
            if entry.sess.mode == Mode::Http
                && entry.response_rules_applied
                && !entry.sess.has_pending_output()
            {
                let close_requested = if entry.sess.h2_ctx.is_some() {
                    matches!(
                        entry.sess.cli_state,
                        ScState::ShutW | ScState::Closed | ScState::Error
                    )
                } else {
                    entry.sess.connection_close
                        || matches!(
                            entry.sess.cli_state,
                            ScState::ShutW | ScState::ShutR | ScState::Closed | ScState::Error
                        )
                        || matches!(
                            entry.sess.srv_state,
                            ScState::ShutR | ScState::Closed | ScState::Error
                        )
                };
                if close_requested {
                    let srv_alive = !entry.sess.srv_connection_close
                        && !matches!(
                            entry.sess.srv_state,
                            ScState::ShutR | ScState::Closed | ScState::Error
                        );
                    if srv_alive {
                        if let Some(srv_fd) = entry.sess.srv.take() {
                            let sfd = srv_fd.as_raw_fd();
                            self.fdtab.remove(sfd);
                            let _ = self.poller.delete(srv_fd.as_fd());
                            entry.srv_raw_fd = None;
                            if let Some(target_addr) = entry.target_addr {
                                let be_idx = entry.backend_idx;
                                if self.proxies.get(be_idx).is_some_and(|p| p.http_reuse != ibex_config::HttpReuse::Never)
                                    && raw::is_idle_conn_alive(srv_fd.as_fd())
                                {
                                    self.idle_backend_pool.entry(target_addr).or_default().push(srv_fd);
                                }
                            }
                        }
                    }
                    entry.sess.cli_state = ScState::Closed;
                    entry.sess.srv_state = ScState::Closed;
                    entry.sess.ending.get_or_insert(crate::proxy::Ending::Complete);
                } else if entry.sess.cli_state.can_read() && entry.sess.cli_state.can_write() {
                    // Keep the backend connection for the next request on this session.
                    //
                    // Tearing it down after every transaction meant each keep-alive request
                    // opened a fresh upstream connection, which is both a large performance
                    // regression and a behavioural one: a backend that accepts once and
                    // serves many requests on that stream never sees request two. HAProxy
                    // reuses backend connections by default (`http-reuse safe`).
                    //
                    // It is only closed when the far end is actually finished with it --
                    // the server closed its read side, or the connection errored.
                    let backend_finished = entry.sess.srv.is_none()
                        || matches!(
                            entry.sess.srv_state,
                            ScState::Closed | ScState::Error
                        );
                    if backend_finished {
                        if let Some(srv_fd) = entry.sess.srv.take() {
                            let sfd = srv_fd.as_raw_fd();
                            self.fdtab.remove(sfd);
                            let _ = self.poller.delete(srv_fd.as_fd());
                            entry.srv_raw_fd = None;
                        }
                        entry.target_addr = None;
                        entry.target_server_idx = None;
                    }
                    entry.response_rules_applied = false;
                    entry.sess.resp_headers_processed = false;
                    if backend_finished {
                        entry.sess.srv_state = ScState::Init;
                    }
                    entry.sess.req_method = None;
                    entry.sess.req_uri = None;
                    entry.sess.req_headers = None;
                    entry.sess.clear_htx();
                    entry.sess.h2_active_stream_id = None;
                    entry.sess.cli_state = ScState::Ready;
                    entry.sess.req_vars.clear();
                    if !self.proxies[entry.proxy_idx].tcp_req_content_rules.is_empty() {
                        let _ = eval_tcp_req_content_rules(
                            &self.proxies[entry.proxy_idx],
                            self.proxies,
                            sample_registry(),
                            &mut entry.sess,
                            now,
                        );
                    }
                }
            }

            // Step 3.9: In HTTP mode, if client disconnected while idle between keep-alive requests
            if entry.sess.mode == Mode::Http
                && !entry.response_rules_applied
                && entry.sess.req.is_empty()
                && matches!(
                    entry.sess.cli_state,
                    ScState::ShutR | ScState::ShutW | ScState::Closed | ScState::Error
                )
                && entry.sess.srv.is_some()
            {
                let srv_alive = !entry.sess.srv_connection_close
                    && !matches!(
                        entry.sess.srv_state,
                        ScState::ShutR | ScState::Closed | ScState::Error
                    );
                if srv_alive {
                    if let Some(srv_fd) = entry.sess.srv.take() {
                        let sfd = srv_fd.as_raw_fd();
                        self.fdtab.remove(sfd);
                        let _ = self.poller.delete(srv_fd.as_fd());
                        entry.srv_raw_fd = None;
                        if let Some(target_addr) = entry.target_addr {
                            let be_idx = entry.backend_idx;
                            if self.proxies.get(be_idx).is_some_and(|p| p.http_reuse != ibex_config::HttpReuse::Never)
                                && raw::is_idle_conn_alive(srv_fd.as_fd())
                            {
                                self.idle_backend_pool.entry(target_addr).or_default().push(srv_fd);
                            }
                        }
                    }
                }
                entry.sess.cli_state = ScState::Closed;
                entry.sess.srv_state = ScState::Closed;
                entry.sess.ending.get_or_insert(crate::proxy::Ending::Complete);
            }

            // Step 4: Update interests
            update_interests(entry, self.fdtab, self.poller);

            // Step 4b: If there are undispatched H2 streams or pending output, re-queue tasklet for immediate processing
            if (entry.sess.has_undispatched_h2_streams() || entry.sess.has_pending_output())
                && !entry.sess.is_done()
            {
                self.wake_queue.push(entry.task);
            }

            // Step 5: Update timer
            self.timer_updates
                .push((entry.task, entry.sess.next_expiry()));

            (entry.sess.is_done(), pending_admin)
        };

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
    fn apply_http_response_rules(entry: &mut SessionEntry, proxies: &[Proxy], _now: Tick) {
        let threshold = entry.sess.bufsize.saturating_sub(entry.sess.maxrewrite);
        let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(entry.sess.rep.readable()) else {
            if entry.sess.rep.readable().len() > threshold {
                entry.response_rules_applied = true;
                entry.sess.rep.clear();
                entry.sess.send_synthetic_response(502, Some("text/html"), None);
                entry.sess.srv_state = ScState::Closed;
                entry.sess.cli_state = ScState::Established;
                entry.sess.ending.get_or_insert(crate::proxy::Ending::Error);
                entry.sess.resp_headers_processed = true;
            }
            return;
        };
        entry.response_rules_applied = true;
        let be_idx = Self::resolve_backend(entry, proxies);
        let fe_idx = entry.proxy_idx;

        let total_hdr_len = hdr_len + eoh_len;
        if total_hdr_len > threshold {
            entry.sess.rep.clear();
            entry.sess.send_synthetic_response(502, Some("text/html"), None);
            entry.sess.srv_state = ScState::Closed;
            entry.sess.cli_state = ScState::Established;
            entry.sess.ending.get_or_insert(crate::proxy::Ending::Error);
            entry.sess.resp_headers_processed = true;
            return;
        }

        let hdr_bytes = &entry.sess.rep.readable()[..total_hdr_len];
        if let Ok(s) = std::str::from_utf8(hdr_bytes) {
            for line in s.lines() {
                if let Some((k, v)) = line.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("connection") && v.trim().eq_ignore_ascii_case("close") {
                        entry.sess.connection_close = true;
                    }
                }
            }
        }

        let has_rules = !proxies[be_idx].http_res_rules.is_empty()
            || !proxies[be_idx].http_after_res_rules.is_empty()
            || !proxies[fe_idx].http_res_rules.is_empty()
            || !proxies[fe_idx].http_after_res_rules.is_empty()
            || !proxies[be_idx].srvexp.is_empty();

        if !has_rules {
            if entry.sess.srv.is_some() {
                entry.sess.srv_state = ScState::Established;
            }
            entry.sess.resp_headers_processed = true;
            return;
        }

        let hdr_str = String::from_utf8_lossy(hdr_bytes);

        let Some((first_line, rest_headers)) = hdr_str.split_once("\r\n") else {
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
        REWRITE_ADDED_BYTES.set(0);
        let max_rw = proxies[fe_idx].stats_config.maxrewrite.unwrap_or(8192);
        MAX_REWRITE_LIMIT.set(max_rw);

        let registry = sample_registry();

        let req_uri_clone = entry.sess.req_uri.clone();
        let req_method_clone = entry.sess.req_method.clone();
        let req_headers_clone = entry.sess.req_headers.clone();

        let htx_slice = if entry.sess.has_htx {
            Some(ibex_proto::htx::HtxSliceRef::new(
                entry.sess.htx_buf.raw_slice(),
                entry.sess.htx_blocks,
            ))
        } else {
            None
        };

        let ctx = SampleContext {
            client_addr: entry.sess.client_addr,
            server_addr: entry.target_addr,
            fc_src: entry.sess.fc_src,
            fc_dst: entry.sess.fc_dst,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            htx: None,
            htx_slice,
            req_uri: req_uri_clone.as_deref(),
            req_method: req_method_clone.as_deref(),
            req_headers: req_headers_clone.as_deref(),
            ..Default::default()
        };

        let mut eval_res_action = |act_name: &str, act_fmt: &str, hdrs: &mut Vec<(String, String)>, status: &mut u16, status_msg: &mut String| -> Result<bool, u16> {
            if act_name == "\0allow" {
                return Ok(false);
            }
            if act_name == "\0deny" {
                let deny_st = act_fmt.parse::<u16>().unwrap_or(403);
                return Err(deny_st);
            }
            if act_name == "\0set-status" {
                if let Ok(st) = act_fmt.parse::<u16>() {
                    *status = st;
                    *status_msg = status_reason(st).to_string();
                    CURRENT_RES_STATUS.set(st);
                }
                return Ok(true);
            }
            if let Some(var_name) = act_name.strip_prefix("\0set-var:") {
                let val = if let Ok(e) = Expr::parse(act_fmt) {
                    e.eval_sample(registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(act_fmt, &ctx, registry)
                };
                if var_name.starts_with("proc.") {
                    ibex_sample::set_proc_var(var_name, val);
                } else {
                    if var_name.starts_with("sess.") {
                        entry.sess.sess_vars.insert(var_name.to_string(), val.clone());
                    } else {
                        entry.sess.req_vars.insert(var_name.to_string(), val.clone());
                    }
                    CURRENT_VARS.with(|v| {
                        v.borrow_mut().insert(var_name.to_string(), val);
                    });
                }
                return Ok(true);
            }
            if let Some(var_name) = act_name.strip_prefix("\0unset-var:") {
                if var_name.starts_with("sess.") {
                    entry.sess.sess_vars.remove(var_name);
                } else {
                    entry.sess.req_vars.remove(var_name);
                }
                CURRENT_VARS.with(|v| {
                    v.borrow_mut().remove(var_name);
                });
                return Ok(true);
            }
            if act_name == "\0strict-mode" {
                STRICT_MODE.set(act_fmt == "on");
                return Ok(true);
            }
            if let Some(hdr_name) = act_name.strip_prefix("\0replace-header:") {
                if let Some((re_str, repl_str)) = act_fmt.split_once('\t') {
                    if let Ok(re) = regex::Regex::new(re_str) {
                        let rust_repl = translate_backreferences(repl_str);
                        let strict = STRICT_MODE.get();
                        for (k, v) in hdrs.iter_mut() {
                            if k.eq_ignore_ascii_case(hdr_name) {
                                let new_v = re.replace_all(v, &rust_repl).to_string();
                                if strict && new_v.len() > 1_048_575 {
                                    return Err(500);
                                }
                                *v = new_v;
                            }
                        }
                        CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                    }
                }
                return Ok(true);
            }
            if let Some(hdr_name) = act_name.strip_prefix("\0replace-value:") {
                if let Some((re_str, repl_str)) = act_fmt.split_once('\t') {
                    if let Ok(re) = regex::Regex::new(re_str) {
                        let rust_repl = translate_backreferences(repl_str);
                        let strict = STRICT_MODE.get();
                        for (k, v) in hdrs.iter_mut() {
                            if k.eq_ignore_ascii_case(hdr_name) {
                                let new_v = re.replace_all(v, &rust_repl).to_string();
                                if strict && new_v.len() > 1_048_575 {
                                    return Err(500);
                                }
                                *v = new_v;
                            }
                        }
                        CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                    }
                }
                return Ok(true);
            }

            let val = format_sample_string(act_fmt, &ctx, registry);
            let added = act_name.len() + val.len() + 4;
            let total = REWRITE_ADDED_BYTES.get() + added;
            if total > MAX_REWRITE_LIMIT.get() {
                if STRICT_MODE.get() {
                    return Err(500);
                }
                return Ok(true);
            }
            REWRITE_ADDED_BYTES.set(total);

            if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case(act_name)) {
                hdrs[pos].1 = val;
            } else {
                hdrs.push((act_name.to_string(), val));
            }
            CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
            Ok(true)
        };

        // 1. Apply be.http_res_rules
        for rule in &proxies[be_idx].http_res_rules {
            let matches = match &rule.cond {
                None => true,
                Some(cond) => eval_condition(cond, &ctx, &proxies[be_idx].acls, registry),
            };
            if !matches {
                continue;
            }
            match &rule.action {
                ibex_config::HttpResAction::SetHeader { name, fmt } => {
                    match eval_res_action(name, fmt, &mut hdrs, &mut status, &mut status_msg) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(err_st) => {
                            let resp = format!("HTTP/1.1 {err_st} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status_reason(err_st));
                            entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                            entry.sess.resp_headers_processed = true;
                            return;
                        }
                    }
                }
                ibex_config::HttpResAction::AddHeader { name, fmt } => {
                    if let Some(var_name) = name.strip_prefix("\0set-var:") {
                        let val = format_sample_string(fmt, &ctx, registry);
                        CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                    } else {
                        let val = format_sample_string(fmt, &ctx, registry);
                        let added = name.len() + val.len() + 4;
                        let total = REWRITE_ADDED_BYTES.get() + added;
                        if total > MAX_REWRITE_LIMIT.get() {
                            if STRICT_MODE.get() {
                                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                                entry.sess.resp_headers_processed = true;
                                return;
                            }
                        } else {
                            REWRITE_ADDED_BYTES.set(total);
                            hdrs.push((name.clone(), val));
                            CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                        }
                    }
                }
                ibex_config::HttpResAction::DelHeader { name } => {
                    if let Some(var_name) = name.strip_prefix("\0unset-var:") {
                        CURRENT_VARS.with(|v| v.borrow_mut().remove(var_name));
                    } else {
                        hdrs.retain(|(k, _)| !header_name_matches(k, name));
                        CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                    }
                }
                ibex_config::HttpResAction::SetStatus { status: new_st } => {
                    status = *new_st;
                    status_msg = status_reason(status).to_string();
                    CURRENT_RES_STATUS.set(status);
                }
            }
        }

        // 1b. Apply fe.http_res_rules
        if fe_idx != be_idx {
            for rule in &proxies[fe_idx].http_res_rules {
                let matches = match &rule.cond {
                    None => true,
                    Some(cond) => eval_condition(cond, &ctx, &proxies[fe_idx].acls, registry),
                };
                if !matches {
                    continue;
                }
                match &rule.action {
                    ibex_config::HttpResAction::SetHeader { name, fmt } => {
                        match eval_res_action(name, fmt, &mut hdrs, &mut status, &mut status_msg) {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(err_st) => {
                                let resp = format!("HTTP/1.1 {err_st} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status_reason(err_st));
                                entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                                entry.sess.resp_headers_processed = true;
                                return;
                            }
                        }
                    }
                    ibex_config::HttpResAction::AddHeader { name, fmt } => {
                        if let Some(var_name) = name.strip_prefix("\0set-var:") {
                            let val = format_sample_string(fmt, &ctx, registry);
                            CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                        } else {
                            let val = format_sample_string(fmt, &ctx, registry);
                            let added = name.len() + val.len() + 4;
                            let total = REWRITE_ADDED_BYTES.get() + added;
                            if total > MAX_REWRITE_LIMIT.get() {
                                if STRICT_MODE.get() {
                                    let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                    entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                                    entry.sess.resp_headers_processed = true;
                                    return;
                                }
                            } else {
                                REWRITE_ADDED_BYTES.set(total);
                                hdrs.push((name.clone(), val));
                                CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                            }
                        }
                    }
                    ibex_config::HttpResAction::DelHeader { name } => {
                        if let Some(var_name) = name.strip_prefix("\0unset-var:") {
                            CURRENT_VARS.with(|v| v.borrow_mut().remove(var_name));
                        } else {
                            hdrs.retain(|(k, _)| !header_name_matches(k, name));
                            CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                        }
                    }
                    ibex_config::HttpResAction::SetStatus { status: new_st } => {
                        status = *new_st;
                        status_msg = status_reason(status).to_string();
                        CURRENT_RES_STATUS.set(status);
                    }
                }
            }
        }

        // 2. Apply be.http_after_res_rules
        for rule in &proxies[be_idx].http_after_res_rules {
            let matches = match &rule.cond {
                None => true,
                Some(cond) => eval_condition(cond, &ctx, &proxies[be_idx].acls, registry),
            };
            if !matches {
                continue;
            }
            match &rule.action {
                ibex_config::HttpAfterResAction::SetHeader { name, fmt } => {
                    match eval_res_action(name, fmt, &mut hdrs, &mut status, &mut status_msg) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(err_st) => {
                            let resp = format!("HTTP/1.1 {err_st} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status_reason(err_st));
                            entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                            entry.sess.resp_headers_processed = true;
                            return;
                        }
                    }
                }
                ibex_config::HttpAfterResAction::AddHeader { name, fmt } => {
                    if let Some(var_name) = name.strip_prefix("\0set-var:") {
                        let val = format_sample_string(fmt, &ctx, registry);
                        CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                    } else {
                        let val = format_sample_string(fmt, &ctx, registry);
                        let added = name.len() + val.len() + 4;
                        let total = REWRITE_ADDED_BYTES.get() + added;
                        if total > MAX_REWRITE_LIMIT.get() {
                            if STRICT_MODE.get() {
                                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                                entry.sess.resp_headers_processed = true;
                                return;
                            }
                        } else {
                            REWRITE_ADDED_BYTES.set(total);
                            hdrs.push((name.clone(), val));
                            CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                        }
                    }
                }
                ibex_config::HttpAfterResAction::DelHeader { name } => {
                    if let Some(var_name) = name.strip_prefix("\0unset-var:") {
                        CURRENT_VARS.with(|v| v.borrow_mut().remove(var_name));
                    } else {
                        hdrs.retain(|(k, _)| !header_name_matches(k, name));
                        CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                    }
                }
            }
        }

        // 3. Apply fe.http_after_res_rules
        for rule in &proxies[fe_idx].http_after_res_rules {
            let matches = match &rule.cond {
                None => true,
                Some(cond) => eval_condition(cond, &ctx, &proxies[fe_idx].acls, registry),
            };
            if !matches {
                continue;
            }
            match &rule.action {
                ibex_config::HttpAfterResAction::SetHeader { name, fmt } => {
                    match eval_res_action(name, fmt, &mut hdrs, &mut status, &mut status_msg) {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(err_st) => {
                            let resp = format!("HTTP/1.1 {err_st} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status_reason(err_st));
                            entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                            entry.sess.resp_headers_processed = true;
                            return;
                        }
                    }
                }
                ibex_config::HttpAfterResAction::AddHeader { name, fmt } => {
                    if let Some(var_name) = name.strip_prefix("\0set-var:") {
                        let val = format_sample_string(fmt, &ctx, registry);
                        CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                    } else {
                        let val = format_sample_string(fmt, &ctx, registry);
                        let added = name.len() + val.len() + 4;
                        let total = REWRITE_ADDED_BYTES.get() + added;
                        if total > MAX_REWRITE_LIMIT.get() {
                            if STRICT_MODE.get() {
                                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                entry.sess.rep.replace_prefix(total_hdr_len, resp.as_bytes());
                                entry.sess.resp_headers_processed = true;
                                return;
                            }
                        } else {
                            REWRITE_ADDED_BYTES.set(total);
                            hdrs.push((name.clone(), val));
                            CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                        }
                    }
                }
                ibex_config::HttpAfterResAction::DelHeader { name } => {
                    if let Some(var_name) = name.strip_prefix("\0unset-var:") {
                        CURRENT_VARS.with(|v| v.borrow_mut().remove(var_name));
                    } else {
                        hdrs.retain(|(k, _)| !header_name_matches(k, name));
                        CURRENT_RES_HEADERS.with(|h| *h.borrow_mut() = hdrs.clone());
                    }
                }
            }
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
        if entry.sess.srv.is_some() {
            entry.sess.srv_state = ScState::Established;
        }
        entry.sess.resp_headers_processed = true;
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
            entry.sess.send_synthetic_bytes(resp.as_bytes());
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
            entry.sess.send_synthetic_bytes(resp.as_bytes());
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
                entry.sess.send_synthetic_bytes(resp.as_bytes());
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
            entry.sess.send_synthetic_bytes(resp.as_bytes());
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
        entry.sess.send_synthetic_bytes(resp.as_bytes());
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

        // Serve the stats page before anything else routes this request.
        //
        // This dispatch was dropped when the action-rule engine was wired in, leaving
        // `is_stats_request` and `handle_stats_request` orphaned -- clippy flagged both
        // as never used. The effect was that every request to `stats uri` fell through
        // to normal backend routing and returned 503, so the stats page and the whole
        // web admin stopped working.
        if proxies[proxy_idx].stats_config.enable
            || proxies[proxy_idx].stats_config.uri.is_some()
            || proxies[proxy_idx].stats_config.admin
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
            client_addr: entry.sess.client_addr,
            server_addr: entry.target_addr,
            fc_src: entry.sess.fc_src,
            fc_dst: entry.sess.fc_dst,
            proxy_tlvs: entry.sess.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
            req_uri: entry.sess.req_uri.as_deref(),
            req_method: entry.sess.req_method.as_deref(),
            req_headers: entry.sess.req_headers.as_deref(),
            act_conn: proxies[proxy_idx].stats[worker_id()].act_conn.load(Ordering::Relaxed),
            cum_conn: proxies[proxy_idx].stats[worker_id()].cum_conn.load(Ordering::Relaxed),
            ..Default::default()
        };

        for rule in &proxies[proxy_idx].http_req_rules {
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
        for (t_idx, ref k) in entry.sess.tracked_sc.iter().flatten() {
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
        let eval_http_rules = |rules: &[ibex_config::HttpReqRule], acls: &HashMap<String, Expr>, sess: &mut TcpSession, target_addr: Option<SocketAddr>| -> Result<Option<()>, ()> {
            macro_rules! make_ctx {
                ($s:expr) => {
                    SampleContext {
                        client_addr: $s.client_addr,
                        server_addr: target_addr,
                        fc_src: $s.fc_src,
                        fc_dst: $s.fc_dst,
                        proxy_tlvs: $s.proxy_info.as_ref().map(|p| p.tlv_data.as_slice()),
                        htx: None,
                        htx_slice: $s.htx_slice(),
                        req_uri: $s.req_uri.as_deref(),
                        req_method: $s.req_method.as_deref(),
                        req_headers: $s.req_headers.as_deref(),
                        act_conn,
                        cum_conn,
                        sc_http_req_rates,
                        sc_conn_rates,
                        ..Default::default()
                    }
                };
            }

            for rule in rules {
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
                    } => {
                        let mut custom_headers: Vec<(String, String)> = Vec::new();
                        let mut body_str = String::new();

                        if let Some(s) = lf_string.as_deref() {
                            let mut rest = s;
                            while let Some(stripped) = rest.strip_prefix("\0HDR:") {
                                if let Some((line, r)) = stripped.split_once('\n') {
                                    if let Some((k, v)) = line.split_once(':') {
                                        let formatted_v = format_sample_string(v, &make_ctx!(sess), registry);
                                        custom_headers.push((k.to_string(), formatted_v));
                                    }
                                    rest = r;
                                } else {
                                    break;
                                }
                            }
                            if let Some(b) = rest.strip_prefix("\0BODY:") {
                                body_str = format_sample_string(b, &make_ctx!(sess), registry);
                            } else if !rest.starts_with('\0') {
                                body_str = format_sample_string(rest, &make_ctx!(sess), registry);
                            }
                        }

                        let unescaped = body_str
                            .replace("\\n", "\n")
                            .replace("\\r", "\r")
                            .replace("\\t", "\t");
                        let body = unescaped.as_bytes();

                        let reason = status_reason(*status);
                        let mut resp = format!("HTTP/1.1 {status} {reason}\r\n");
                        if let Some(ct) = content_type.as_deref() {
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

                        let w = sess.rep.writable();
                        let n = w.len().min(full_resp.len());
                        w[..n].copy_from_slice(&full_resp[..n]);
                        sess.rep.commit(n);

                        if let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(sess.req.readable()) {
                            sess.req.consume(hdr_len + eoh_len);
                        }
                        sess.req_method = None;
                        sess.req_uri = None;
                        sess.req_headers = None;
                        sess.clear_htx();
                        sess.cli_state = ScState::Ready;
                        sess.srv_state = ScState::Init;
                        sess.resp_headers_processed = false;
                        return Ok(Some(()));
                    }
                    ibex_config::HttpReqAction::Deny { deny_status } => {
                        let status_code = deny_status.unwrap_or(403);
                        let reason = status_reason(status_code);
                        let resp = format!(
                            "HTTP/1.1 {status_code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let w = sess.rep.writable();
                        let n = w.len().min(resp.len());
                        w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                        sess.rep.commit(n);
                        sess.cli_state = ScState::ShutR;
                        sess.srv_state = ScState::Closed;
                        return Ok(Some(()));
                    }
                    ibex_config::HttpReqAction::Allow => {
                        return Ok(None);
                    }
                    ibex_config::HttpReqAction::Auth => {
                        let resp = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"HAProxy\"\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let w = sess.rep.writable();
                        let n = w.len().min(resp.len());
                        w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                        sess.rep.commit(n);
                        sess.cli_state = ScState::ShutR;
                        sess.srv_state = ScState::Closed;
                        return Ok(Some(()));
                    }
                    ibex_config::HttpReqAction::Redirect { location, prefix, code, .. } => {
                        let status_code = code.unwrap_or(302);
                        let loc = location.as_deref().or(prefix.as_deref()).unwrap_or("/");
                        let formatted_loc = format_sample_string(loc, &make_ctx!(sess), registry);
                        let reason = status_reason(status_code);
                        let resp = format!(
                            "HTTP/1.1 {status_code} {reason}\r\nLocation: {formatted_loc}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let w = sess.rep.writable();
                        let n = w.len().min(resp.len());
                        w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                        sess.rep.commit(n);
                        sess.cli_state = ScState::ShutR;
                        sess.srv_state = ScState::Closed;
                        return Ok(Some(()));
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
                            let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let w = sess.rep.writable();
                            let n = w.len().min(resp.len());
                            w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                            sess.rep.commit(n);
                            sess.cli_state = ScState::ShutR;
                            sess.srv_state = ScState::Closed;
                            return Ok(Some(()));
                        }
                    }
                    ibex_config::HttpReqAction::SetHeader { name, fmt } => {
                        let val = format_sample_string(fmt, &make_ctx!(sess), registry);
                        let added = name.len() + val.len() + 4;
                        let total = REWRITE_ADDED_BYTES.get() + added;
                        if total > MAX_REWRITE_LIMIT.get() {
                            if STRICT_MODE.get() {
                                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let w = sess.rep.writable();
                                let n = w.len().min(resp.len());
                                w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                                sess.rep.commit(n);
                                sess.cli_state = ScState::ShutR;
                                sess.srv_state = ScState::Closed;
                                return Ok(Some(()));
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
                                let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let w = sess.rep.writable();
                                let n = w.len().min(resp.len());
                                w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                                sess.rep.commit(n);
                                sess.cli_state = ScState::ShutR;
                                sess.srv_state = ScState::Closed;
                                return Ok(Some(()));
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
                            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let w = sess.rep.writable();
                            let n = w.len().min(resp.len());
                            w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                            sess.rep.commit(n);
                            sess.cli_state = ScState::ShutR;
                            sess.srv_state = ScState::Closed;
                            return Ok(Some(()));
                        }
                    }
                    ibex_config::HttpReqAction::ReplaceValue { name, regex, repl }
                        if replace_req_value(sess, name, regex, repl).is_err() => {
                            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let w = sess.rep.writable();
                            let n = w.len().min(resp.len());
                            w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                            sess.rep.commit(n);
                            sess.cli_state = ScState::ShutR;
                            sess.srv_state = ScState::Closed;
                            return Ok(Some(()));
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
                    _ => {}
                }
            }
            Ok(None)
        };

        // Execute frontend rules
        if !proxies[proxy_idx].http_req_rules.is_empty() {
            let fe_rules = &proxies[proxy_idx].http_req_rules;
            let fe_acls = &proxies[proxy_idx].acls;
            if let Ok(Some(())) = eval_http_rules(fe_rules, fe_acls, &mut entry.sess, entry.target_addr) {
                return None;
            }
        }

        // 3. Resolve backend and server
        let be_idx = Self::resolve_backend(entry, proxies);
        entry.backend_idx = be_idx;

        // Evaluate backend tcp-request content rules
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
            if let Ok(Some(())) = eval_http_rules(be_rules, be_acls, &mut entry.sess, entry.target_addr) {
                return None;
            }
        }

        // Apply forwardfor & originalto header injection
        if let Some(ref except_str) = proxies[be_idx].stats_config.forwardfor {
            let client_ip = entry.sess.client_addr.map(|a| a.ip());
            if let Some(ip) = client_ip {
                let in_except = if except_str.is_empty() {
                    false
                } else {
                    ip_in_cidr(ip, except_str)
                };
                if !in_except {
                    let ip_str = ip.to_string();
                    set_req_header(&mut entry.sess, "X-Forwarded-For", &ip_str);
                }
            }
        }

        if let Some(ref except_str) = proxies[be_idx].stats_config.originalto {
            let dst_ip = entry.sess.server_addr.or(entry.target_addr).map(|a| a.ip());
            if let Some(ip) = dst_ip {
                let in_except = if except_str.is_empty() {
                    false
                } else {
                    ip_in_cidr(ip, except_str)
                };
                if !in_except {
                    let ip_str = ip.to_string();
                    set_req_header(&mut entry.sess, "X-Original-To", &ip_str);
                }
            }
        }

        let has_res_rules = !proxies[be_idx].http_res_rules.is_empty()
            || !proxies[be_idx].http_after_res_rules.is_empty()
            || (be_idx != proxy_idx
                && (!proxies[proxy_idx].http_res_rules.is_empty()
                    || !proxies[proxy_idx].http_after_res_rules.is_empty()));
        if has_res_rules {
            let res_ctx = SampleContext {
                client_addr: entry.sess.client_addr,
                server_addr: entry.target_addr,
                htx: None,
                req_uri: entry.sess.req_uri.as_deref(),
                req_method: entry.sess.req_method.as_deref(),
                req_headers: entry.sess.req_headers.as_deref(),
                ..Default::default()
            };

            let mut res_rules = Vec::new();
            let mut raw_res = proxies[be_idx].http_res_rules.clone();
            if be_idx != proxy_idx {
                raw_res.extend(proxies[proxy_idx].http_res_rules.clone());
            }
            for rule in &raw_res {
                let action = match &rule.action {
                    ibex_config::HttpResAction::SetHeader { name, fmt } => {
                        let formatted_fmt = format_sample_string(fmt, &res_ctx, registry);
                        ibex_config::HttpResAction::SetHeader {
                            name: name.clone(),
                            fmt: formatted_fmt,
                        }
                    }
                    ibex_config::HttpResAction::AddHeader { name, fmt } => {
                        let formatted_fmt = format_sample_string(fmt, &res_ctx, registry);
                        ibex_config::HttpResAction::AddHeader {
                            name: name.clone(),
                            fmt: formatted_fmt,
                        }
                    }
                    other => other.clone(),
                };
                res_rules.push(ibex_config::HttpResRule {
                    action,
                    cond: rule.cond.clone(),
                });
            }
            entry.sess.http_res_rules = res_rules;

            let mut after_rules = Vec::new();
            let mut raw_after = proxies[be_idx].http_after_res_rules.clone();
            if be_idx != proxy_idx {
                raw_after.extend(proxies[proxy_idx].http_after_res_rules.clone());
            }
            for rule in &raw_after {
                let mut action = rule.action.clone();
                if let ibex_config::HttpAfterResAction::SetHeader { fmt, .. }
                | ibex_config::HttpAfterResAction::AddHeader { fmt, .. } = &mut action
                {
                    *fmt = format_sample_string(fmt, &res_ctx, registry);
                }
                after_rules.push(ibex_config::HttpAfterResRule {
                    action,
                    cond: rule.cond.clone(),
                });
            }
            entry.sess.http_after_res_rules = after_rules;
        } else {
            entry.sess.http_res_rules.clear();
            entry.sess.http_after_res_rules.clear();
        }

        let source_ip = entry.sess.client_addr.map(|a| a.ip());
        let target = if let Some(ref cval) = entry.sess.cookie_val {
            proxies[be_idx]
                .select_server_by_id(cval)
                .or_else(|| proxies[be_idx].select_server_with_key(source_ip))
        } else {
            proxies[be_idx].select_server_with_key(source_ip)
        };

        let Some(target_addr) = target else {
            proxies[be_idx].stats[worker_id()].failed_conn.fetch_add(1, Ordering::Relaxed);
            entry.sess.srv_state = ScState::Error;
            entry.sess.send_synthetic_response(
                503,
                Some("text/html; charset=utf-8"),
                Some("<html><body><h1>503 Service Unavailable</h1>No server is available to handle this request.</body></html>\n"),
            );
            return None;
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

        maybe_prepend_send_proxy(&proxies[be_idx], &mut entry.sess, target_addr);

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
        } else if let Ok((srv_fd, immediate)) = raw::connect(target_addr) {
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
        let target = proxies[be_idx].select_server_with_key(source_ip);

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

        maybe_prepend_send_proxy(&proxies[be_idx], &mut entry.sess, target_addr);

        entry.target_addr = Some(target_addr);
        if let Ok((srv_fd, immediate)) = raw::connect(target_addr) {
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
    }

    fn step_check(&mut self, check_idx: usize) -> Outcome {
        if check_idx < self.checks.len() {
            let check = &mut self.checks[check_idx];
            let now = self.now;
            let step = check::step_check(check, self.fdtab, self.poller, now);

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
            let pending = (check.task, check.next_check);
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
    fn send_log(&self, proxy_idx: usize, level: LogLevel, msg: &str) {
        let Some(proxy) = self.proxies.get(proxy_idx) else {
            return;
        };
        for &i in &proxy.log_target_idx {
            if let Some(target) = self.log_targets.get(i) {
                // Discarded deliberately: syslog over UDP is fire-and-forget, and a
                // collector that is down must not slow or fail the data path.
                let _ = target.send(level, self.log_tag, self.log_hostname, msg);
            }
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
    sess.with_htx_mut(|htx| {
        let _ = htx.replace_header(name, regex, repl);
    });
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    let re = regex::Regex::new(regex).map_err(|_| ())?;
    let rust_repl = translate_backreferences(repl);
    let strict = STRICT_MODE.get();

    for (k, v) in &mut hdrs {
        if k.eq_ignore_ascii_case(name) {
            let new_v = re.replace_all(v, &rust_repl).to_string();
            if strict && new_v.len() > 1_048_575 {
                sess.req_headers = Some(hdrs);
                return Err(());
            }
            *v = new_v;
        }
    }
    sess.req_headers = Some(hdrs);
    rebuild_req_buffer(sess);
    Ok(())
}

fn replace_req_value(sess: &mut TcpSession, name: &str, regex: &str, repl: &str) -> Result<(), ()> {
    sess.with_htx_mut(|htx| {
        let _ = htx.replace_header(name, regex, repl);
    });
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    let re = regex::Regex::new(regex).map_err(|_| ())?;
    let rust_repl = translate_backreferences(repl);
    let strict = STRICT_MODE.get();

    for (k, v) in &mut hdrs {
        if k.eq_ignore_ascii_case(name) {
            let new_v = re.replace_all(v, &rust_repl).to_string();
            if strict && new_v.len() > 1_048_575 {
                sess.req_headers = Some(hdrs);
                return Err(());
            }
            *v = new_v;
        }
    }
    sess.req_headers = Some(hdrs);
    rebuild_req_buffer(sess);
    Ok(())
}

fn rebuild_req_buffer(sess: &mut TcpSession) {
    let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(sess.req.readable()) else {
        return;
    };
    if let Some(htx) = sess.htx_slice() {
        let mut out = [0u8; 8192];
        if let Ok(n) = htx.write_h1_wire(&mut out) {
            sess.req.replace_prefix(hdr_len + eoh_len, &out[..n]);
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
    acls: &HashMap<String, Expr>,
    registry: &Registry,
) -> bool {
    let mut term_match = true;
    for term in &cond.terms {
        let term_res = if term.name == "always_true" {
            true
        } else if term.name == "always_false" {
            false
        } else if let Some(expr) = acls.get(&term.name) {
            expr.eval(registry, ctx)
        } else if let Some(f_idx) = term.name.find("-f ") {
            let before_f = &term.name[..f_idx];
            let after_f = term.name[f_idx + 3..].trim();
            let file_path = after_f.split_whitespace().next().unwrap_or(after_f);
            let case_insensitive = term.name.contains("-i");
            let expr_str = before_f.split_whitespace().next().unwrap_or(before_f);
            let mut matched = false;
            if let Ok(expr) = Expr::parse(expr_str) {
                if let Some(smp) = expr.eval_sample(registry, ctx) {
                    let s = sample_to_string(&smp);
                    if let Ok(content) = std::fs::read_to_string(file_path) {
                        for line in content.lines() {
                            let line = line.trim();
                            if line.is_empty() || line.starts_with('#') {
                                continue;
                            }
                            if case_insensitive {
                                if s.eq_ignore_ascii_case(line) {
                                    matched = true;
                                    break;
                                }
                            } else if s == line {
                                matched = true;
                                break;
                            }
                        }
                    }
                }
            }
            matched
        } else if let Ok(expr) = Expr::parse(&term.name) {
            expr.eval(registry, ctx)
        } else {
            false
        };
        let final_res = if term.negated { !term_res } else { term_res };
        if !final_res {
            term_match = false;
            break;
        }
    }
    if cond.is_if {
        term_match
    } else {
        !term_match
    }
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

#[cfg(test)]
mod registry_tests {
    use super::{build_sample_registry, CURRENT_RES_STATUS, CURRENT_VARS};
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
}
