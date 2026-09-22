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
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
    CURRENT_RES_HEADERS, CURRENT_RES_STATUS, CURRENT_TIMEOUTS, CURRENT_VARS,
};

thread_local! {
    static STRICT_MODE: Cell<bool> = const { Cell::new(true) };
    static REWRITE_ADDED_BYTES: Cell<usize> = const { Cell::new(0) };
    static MAX_REWRITE_LIMIT: Cell<usize> = const { Cell::new(8192) };
}

/// Accumulated statistics per proxy.
#[derive(Debug, Clone, Default)]
pub struct ProxyStats {
    pub cum_conn: u64,
    pub act_conn: u32,
    pub max_conn: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub retries_count: u64,
    pub redispatches: u64,
    pub failed_conn: u64,
    pub srv_err: u64,
    pub cli_err: u64,
}

impl ProxyStats {
    /// Clears accumulated traffic and error counters, resetting `max_conn` to current `act_conn`.
    pub fn clear(&mut self) {
        self.cum_conn = 0;
        self.max_conn = self.act_conn;
        self.bytes_in = 0;
        self.bytes_out = 0;
        self.retries_count = 0;
        self.redispatches = 0;
        self.failed_conn = 0;
        self.srv_err = 0;
        self.cli_err = 0;
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
    pub server_statuses: Vec<ServerStatus>,
    pub server_weights: Vec<u32>,
    pub next_server_idx: usize,
    pub stats: ProxyStats,
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
    pub server_actconn: Vec<u32>,
    pub server_check_configs: Vec<Option<ServerCheckConfig>>,
    pub tcp_req_conn_rules: Vec<ibex_config::TcpReqConnRule>,
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
                if *status != ServerStatus::Up {
                    return false;
                }
            } else {
                return false;
            }
            if let Some(Some(mc)) = self.server_maxconn.get(idx) {
                if *mc > 0 {
                    let act = self.server_actconn.get(idx).copied().unwrap_or(0);
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
                let is_up = self.server_statuses.get(idx).copied() == Some(ServerStatus::Up);
                let not_saturated = match self.server_maxconn.get(idx) {
                    Some(Some(mc)) if *mc > 0 => {
                        let act = self.server_actconn.get(idx).copied().unwrap_or(0);
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

    /// Selects the target backend server using round-robin across active (UP) servers,
    /// preferring primary servers over backup servers,
    /// or falls back to the dispatch address if all servers are down or absent.
    #[must_use]
    pub fn select_server(&mut self) -> Option<SocketAddr> {
        if self.servers.is_empty() {
            return self.dispatch;
        }
        let eligible = self.eligible_server_indices();
        if eligible.is_empty() {
            return self.dispatch;
        }
        let chosen_idx = eligible[self.next_server_idx % eligible.len()];
        self.next_server_idx = self.next_server_idx.wrapping_add(1);
        Some(self.servers[chosen_idx])
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
                let chosen_idx = eligible[self.next_server_idx % eligible.len()];
                self.next_server_idx = self.next_server_idx.wrapping_add(1);
                Some(self.servers[chosen_idx])
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
            free: Vec::new(),
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

    #[allow(clippy::cast_possible_truncation)]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u32, &mut SessionEntry)> {
        self.entries
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, opt)| opt.as_mut().map(|entry| (idx as u32, entry)))
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn iter(&self) -> impl Iterator<Item = (u32, &SessionEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(idx, opt)| opt.as_ref().map(|entry| (idx as u32, entry)))
    }
}

pub struct Engine {
    pub poller: Poller,
    pub scheduler: Scheduler,
    pub fdtab: FdTab,
    pub listeners: Vec<Listener>,
    pub proxies: Vec<Proxy>,
    pub checks: Vec<ServerCheckState>,
    pub sessions: SessionArena,
    pub applets: AppletArena,
    pub cli_listener: Option<UnixListener>,
    pub cli_socket_path: Option<PathBuf>,
    pub start_time: Instant,
    pub now: Tick,
    pub is_running: bool,
    events: Vec<crate::poller::Event>,
    timer_updates: Vec<(TaskRef, Tick)>,
    /// Every syslog target the config declared, global and per-proxy. Proxies reference
    /// these by index through `Proxy::log_target_idx`.
    log_targets: Vec<SyslogTarget>,
    /// Value for the syslog TAG field. `HAProxy` uses the program name.
    log_tag: String,
    /// Value for the syslog HOSTNAME field.
    log_hostname: String,
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
        if let Some(i) = targets
            .iter()
            .position(|t| t.addr() == cfg.addr && t.facility() == cfg.facility)
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

fn init_proxy_from_listen(proxy_idx: usize, listen: &ibex_config::ListenSection) -> Proxy {
    let timeouts = Timeouts {
        #[allow(clippy::cast_possible_truncation)]
        client: listen.clitimeout.map_or(0, |d| d.as_millis() as u32),
        #[allow(clippy::cast_possible_truncation)]
        server: listen.srvtimeout.map_or(0, |d| d.as_millis() as u32),
        #[allow(clippy::cast_possible_truncation)]
        connect: listen.contimeout.map_or(0, |d| d.as_millis() as u32),
    };

    #[allow(clippy::cast_possible_truncation)]
    let retries = listen.retries.min(u32::from(u16::MAX)) as u16;

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
        #[allow(clippy::cast_possible_truncation)]
        id: proxy_idx as u32,
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
        server_statuses: vec![ServerStatus::Up; server_count],
        server_weights: listen
            .servers
            .iter()
            .map(|s| s.weight.unwrap_or(1))
            .collect(),
        next_server_idx: 0,
        stats: ProxyStats::default(),
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
        server_actconn: vec![0; server_count],
        server_check_configs,
        tcp_req_conn_rules: listen.tcp_req_conn_rules.clone(),
        http_req_rules: listen.http_req_rules.clone(),
        http_res_rules: listen.http_res_rules.clone(),
        http_after_res_rules: listen.http_after_res_rules.clone(),
    }
}

fn init_proxy_from_frontend(proxy_idx: usize, fe: &ibex_config::FrontendSection) -> Proxy {
    let timeouts = Timeouts {
        #[allow(clippy::cast_possible_truncation)]
        client: fe
            .clitimeout
            .or(fe.timeouts.client)
            .map_or(0, |d| d.as_millis() as u32),
        #[allow(clippy::cast_possible_truncation)]
        server: fe.timeouts.server.map_or(0, |d| d.as_millis() as u32),
        #[allow(clippy::cast_possible_truncation)]
        connect: fe.timeouts.connect.map_or(0, |d| d.as_millis() as u32),
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
        #[allow(clippy::cast_possible_truncation)]
        id: proxy_idx as u32,
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
        server_statuses: Vec::new(),
        server_weights: Vec::new(),
        next_server_idx: 0,
        stats: ProxyStats::default(),
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
        server_actconn: Vec::new(),
        server_check_configs: Vec::new(),
        tcp_req_conn_rules: fe.tcp_req_conn_rules.clone(),
        http_req_rules: fe.http_req_rules.clone(),
        http_res_rules: fe.http_res_rules.clone(),
        http_after_res_rules: fe.http_after_res_rules.clone(),
    }
}

fn init_proxy_from_backend(proxy_idx: usize, be: &ibex_config::BackendSection) -> Proxy {
    let timeouts = Timeouts {
        #[allow(clippy::cast_possible_truncation)]
        client: be.timeouts.client.map_or(0, |d| d.as_millis() as u32),
        #[allow(clippy::cast_possible_truncation)]
        server: be
            .srvtimeout
            .or(be.timeouts.server)
            .map_or(0, |d| d.as_millis() as u32),
        #[allow(clippy::cast_possible_truncation)]
        connect: be
            .contimeout
            .or(be.timeouts.connect)
            .map_or(0, |d| d.as_millis() as u32),
    };

    #[allow(clippy::cast_possible_truncation)]
    let retries = be.retries.min(u32::from(u16::MAX)) as u16;

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
        #[allow(clippy::cast_possible_truncation)]
        id: proxy_idx as u32,
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
        server_statuses: vec![ServerStatus::Up; server_count],
        server_weights: be.servers.iter().map(|s| s.weight.unwrap_or(1)).collect(),
        next_server_idx: 0,
        stats: ProxyStats::default(),
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
        server_actconn: vec![0; server_count],
        server_check_configs,
        tcp_req_conn_rules: Vec::new(),
        http_req_rules: be.http_req_rules.clone(),
        http_res_rules: be.http_res_rules.clone(),
        http_after_res_rules: be.http_after_res_rules.clone(),
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
            #[allow(clippy::cast_possible_truncation)]
            let check_idx = checks.len() as u32;
            if let Some(task_ref) = scheduler.create(WorkKind::new(Kind::Check, check_idx)) {
                check.task = task_ref;
                #[allow(clippy::cast_possible_truncation)]
                let initial_delay = 50 + (check_idx * 50);
                scheduler.queue_timer(task_ref, now.add(initial_delay));
            }
            checks.push(check);
        }
    }
    checks
}

impl Engine {
    /// Constructs an `Engine` configured from the given parsed config.
    ///
    /// # Errors
    /// Returns an error if epoll creation or binding any listener fails.
    pub fn new(config: &Config, capacity: usize) -> io::Result<Self> {
        let poller = Poller::new(capacity)?;
        let mut scheduler = Scheduler::with_capacity(capacity);
        let mut fdtab = FdTab::with_capacity(capacity * 2);
        let sessions = SessionArena::with_capacity(capacity);
        let applets = AppletArena::with_capacity(capacity);

        let mut listeners = Vec::new();
        let mut proxies = Vec::new();

        // 1. Process listen sections
        for listen in &config.listens {
            if listen.disabled {
                continue;
            }

            let proxy_idx = proxies.len();
            let proxy = init_proxy_from_listen(proxy_idx, listen);

            #[allow(clippy::cast_possible_truncation)]
            let mut listener = Listener::bind(listen.addr, 128, proxy_idx as u32)?;
            listener.maxconn = listen.maxconn;

            // Keyed by the listener, not the proxy. A proxy may own several listeners
            // -- `bind :80` beside `bind :443 ssl` is the ordinary HTTP-to-HTTPS setup --
            // and storing the proxy here meant an event on the second was served by
            // looking up the first, which is the wrong socket, the wrong connection
            // accounting and, once TLS is per-bind, the wrong transport.
            let l_idx = listeners.len();
            let lfd = listener.raw_fd();
            #[allow(clippy::cast_possible_truncation)]
            fdtab.insert(
                lfd,
                FdState::Listener {
                    listener: l_idx as u32,
                },
                Interest::READ,
            );
            #[allow(clippy::cast_sign_loss)]
            poller.add(listener.borrowed_fd(), lfd as u64, true, false)?;

            listeners.push(listener);
            proxies.push(proxy);
        }

        // 2. Process backend sections
        for backend in &config.backends {
            if backend.disabled {
                continue;
            }
            let proxy_idx = proxies.len();
            let proxy = init_proxy_from_backend(proxy_idx, backend);
            proxies.push(proxy);
        }

        // 3. Process frontend sections
        for frontend in &config.frontends {
            if frontend.disabled {
                continue;
            }
            let proxy_idx = proxies.len();
            let proxy = init_proxy_from_frontend(proxy_idx, frontend);

            let mut bind_addrs = Vec::new();
            if let Some(bind_addr) = frontend.bind {
                bind_addrs.push(bind_addr);
            }
            for b in &frontend.binds {
                if !bind_addrs.contains(&b.addr) {
                    bind_addrs.push(b.addr);
                }
            }

            for bind_addr in bind_addrs {
                #[allow(clippy::cast_possible_truncation)]
                let mut listener = Listener::bind(bind_addr, 128, proxy_idx as u32)?;
                listener.maxconn = frontend.maxconn;
                listener.tls = bind_tls(frontend, bind_addr)?;

                let l_idx = listeners.len();
                let lfd = listener.raw_fd();
                #[allow(clippy::cast_possible_truncation)]
                fdtab.insert(
                    lfd,
                    FdState::Listener {
                        listener: l_idx as u32,
                    },
                    Interest::READ,
                );
                #[allow(clippy::cast_sign_loss)]
                poller.add(listener.borrowed_fd(), lfd as u64, true, false)?;

                listeners.push(listener);
            }
            proxies.push(proxy);
        }

        let log_targets = resolve_log_targets(config, &mut proxies);

        let start_time = Instant::now();
        let now = Tick(1);
        let checks = init_checks(&proxies, &mut scheduler, now);

        Ok(Engine {
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
            events: Vec::with_capacity(capacity * 2),
            timer_updates: Vec::with_capacity(capacity * 2),
            log_targets,
            log_tag: "haproxy".to_string(),
            log_hostname: hostname(),
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
        #[allow(clippy::cast_sign_loss)]
        self.poller
            .add(listener.as_fd(), raw_fd as u64, true, false)?;
        self.cli_listener = Some(listener);
        self.cli_socket_path = Some(path_buf);
        Ok(())
    }

    /// Computes the current monotonic tick.
    #[must_use]
    pub fn current_tick(&self) -> Tick {
        let elapsed = self.start_time.elapsed();
        #[allow(clippy::cast_possible_truncation)]
        let ms = (elapsed.as_millis() & 0xFFFF_FFFF) as u32;
        Tick(if ms == 0 { 1 } else { ms })
    }

    /// Formats runtime statistics string.
    #[must_use]
    pub fn format_stats_info(&self) -> String {
        let pid = std::process::id();
        let active_conns: u32 = self.proxies.iter().map(|p| p.stats.act_conn).sum();
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

        // 3. Poll readiness events
        let mut events = std::mem::take(&mut self.events);
        events.clear();
        self.poller.poll(Some(poll_timeout), |ev| events.push(ev))?;

        // 4. Process polled readiness events
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
                FdState::Closed => {}
            }
        }
        self.events = events;

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

                    #[allow(clippy::cast_sign_loss)]
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
                            let _ = self.poller.add(stream.as_fd(), raw_fd as u64, true, false);
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
            #[allow(clippy::cast_sign_loss)]
            let _ = self.poller.modify(
                self.listeners[l_idx].borrowed_fd(),
                lfd as u64,
                false,
                false,
            );
            self.fdtab.set_interest(lfd, Interest::NONE);
            return;
        }

        let registry = Registry::new();

        while !self.listeners[l_idx].is_full() {
            let accept_res = self.listeners[l_idx].accept();
            let Some((cli_fd, peer_addr)) = (match accept_res {
                Ok(Some(pair)) => Some(pair),
                Ok(None) | Err(_) => None,
            }) else {
                break;
            };

            let mut silent_dropped = false;
            let mut sc_conn_rates = [0u64; 3];
            let key = StickKey::Ip(peer_addr.ip());

            for rule in &self.proxies[proxy_idx].tcp_req_conn_rules {
                match &rule.action {
                    ibex_config::TcpReqConnAction::TrackSc0 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            self.proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            self.proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            let _ = tbl.update_entry(&key, |data| {
                                data.conn_cnt += 1;
                                data.conn_cur += 1;
                                if let Some(ref mut r) = data.conn_rate {
                                    r.tick(1);
                                }
                            });
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc1 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            self.proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            self.proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            let _ = tbl.update_entry(&key, |data| {
                                data.conn_cnt += 1;
                                data.conn_cur += 1;
                                if let Some(ref mut r) = data.conn_rate {
                                    r.tick(1);
                                }
                            });
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc2 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            self.proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            self.proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            let _ = tbl.update_entry(&key, |data| {
                                data.conn_cnt += 1;
                                data.conn_cur += 1;
                                if let Some(ref mut r) = data.conn_rate {
                                    r.tick(1);
                                }
                            });
                        }
                    }
                    _ => {}
                }
            }

            for rule in &self.proxies[proxy_idx].tcp_req_conn_rules {
                match &rule.action {
                    ibex_config::TcpReqConnAction::TrackSc0 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            self.proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            self.proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            if let Ok(Some(data)) = tbl.get_entry(&key) {
                                if let Some(ref r) = data.conn_rate {
                                    sc_conn_rates[0] = r.rate();
                                }
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc1 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            self.proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            self.proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            if let Ok(Some(data)) = tbl.get_entry(&key) {
                                if let Some(ref r) = data.conn_rate {
                                    sc_conn_rates[1] = r.rate();
                                }
                            }
                        }
                    }
                    ibex_config::TcpReqConnAction::TrackSc2 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            self.proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            self.proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            if let Ok(Some(data)) = tbl.get_entry(&key) {
                                if let Some(ref r) = data.conn_rate {
                                    sc_conn_rates[2] = r.rate();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            if self.proxies[proxy_idx].tcp_req_conn_rules.is_empty() {
                if let Some(ref table) = self.proxies[proxy_idx].stick_table {
                    let _ = table.update_entry(&key, |data| {
                        data.conn_cnt += 1;
                        data.conn_cur += 1;
                        if let Some(ref mut rate) = data.conn_rate {
                            rate.tick(1);
                        }
                    });
                }
            }

            let ctx = SampleContext {
                client_addr: Some(peer_addr),
                sc_conn_rates,
                act_conn: self.proxies[proxy_idx].stats.act_conn,
                cum_conn: self.proxies[proxy_idx].stats.cum_conn,
                ..Default::default()
            };

            for rule in &self.proxies[proxy_idx].tcp_req_conn_rules {
                match &rule.action {
                    ibex_config::TcpReqConnAction::SilentDrop
                    | ibex_config::TcpReqConnAction::Reject => {
                        let matches = match &rule.cond {
                            None => true,
                            Some(cond) => crate::proxy::eval_acl_condition(
                                cond,
                                &self.proxies[proxy_idx].acls,
                                &registry,
                                &ctx,
                            ),
                        };
                        if matches {
                            silent_dropped = true;
                            break;
                        }
                    }
                    _ => {}
                }
            }

            if silent_dropped {
                drop(cli_fd);
                continue;
            }

            self.listeners[l_idx].nbconn += 1;
            let proxy = &mut self.proxies[proxy_idx];
            proxy.stats.cum_conn += 1;
            proxy.stats.act_conn += 1;
            if proxy.stats.act_conn > proxy.stats.max_conn {
                proxy.stats.max_conn = proxy.stats.act_conn;
            }

            if self.listeners[l_idx].is_full() {
                #[allow(clippy::cast_sign_loss)]
                let _ = self.poller.modify(
                    self.listeners[l_idx].borrowed_fd(),
                    lfd as u64,
                    false,
                    false,
                );
                self.fdtab.set_interest(lfd, Interest::NONE);
            }

            register_new_session(self, proxy_idx, l_idx, cli_fd, peer_addr);
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

#[allow(clippy::too_many_lines)]
fn register_new_session(
    engine: &mut Engine,
    proxy_idx: usize,
    listener_idx: usize,
    cli_fd: std::os::fd::OwnedFd,
    peer_addr: SocketAddr,
) {
    // Cloned out before `proxies` is borrowed mutably. TLS belongs to the bind that
    // accepted, not to the proxy, so it is read from the listener.
    let tls = engine
        .listeners
        .get(listener_idx)
        .and_then(|l| l.tls.clone());
    let proxy = &mut engine.proxies[proxy_idx];
    let cli_raw_fd = cli_fd.as_raw_fd();
    let Some((mut sess, target_addr, srv_raw_fd)) =
        init_client_session(proxy, cli_fd, engine.now, peer_addr, tls.as_ref())
    else {
        // TLS setup failed; the fd is dropped with the session and the connection closes.
        return;
    };
    sess.client_addr = Some(peer_addr);

    let target_server_idx = target_addr.and_then(|t| proxy.servers.iter().position(|&s| s == t));
    if let Some(idx) = target_server_idx {
        if idx < proxy.server_actconn.len() {
            proxy.server_actconn[idx] += 1;
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
                proxy.server_actconn[idx] = proxy.server_actconn[idx].saturating_sub(1);
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
                proxy.server_actconn[idx] = proxy.server_actconn[idx].saturating_sub(1);
            }
        }
        engine.sessions.free(session_idx);
        return;
    };

    let Some(entry) = engine.sessions.get_mut(session_idx) else {
        return;
    };
    entry.task = task_ref;

    #[allow(clippy::cast_sign_loss)]
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
            cli_raw_fd as u64,
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
        #[allow(clippy::cast_sign_loss)]
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
                sfd as u64,
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

fn init_client_session(
    proxy: &mut Proxy,
    cli_fd: std::os::fd::OwnedFd,
    now: Tick,
    peer_addr: SocketAddr,
    tls: Option<&Arc<rustls::ServerConfig>>,
) -> Option<(TcpSession, Option<SocketAddr>, Option<RawFd>)> {
    let mode = proxy.mode;
    let timeouts = proxy.timeouts;
    let retries = proxy.retries;
    let cookie_name = proxy.cookie_name.clone();
    let cliexp = proxy.cliexp.clone();
    let srvexp = proxy.srvexp.clone();

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
    sess.client_addr = Some(peer_addr);
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
                    proxy.name
                );
                return None;
            }
        }
    }
    if proxy.accept_proxy || proxy.accept_proxy_v2 {
        sess.enable_accept_proxy(proxy.accept_proxy_v2);
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
    } else if mode == Mode::Tcp && !proxy.accept_proxy && !proxy.accept_proxy_v2 {
        target_addr = proxy.select_server_with_key(Some(peer_addr.ip()));
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
                proxy.stats.failed_conn += 1;
                if !sess.server_failed() {
                    sess.srv_state = ScState::Error;
                }
            }
        } else {
            sess.srv_state = ScState::Error;
        }
    }
    // In Mode::Http (or Mode::Tcp when accept_proxy is true), target connect is deferred
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
            proxies[proxy_idx].stats.act_conn =
                proxies[proxy_idx].stats.act_conn.saturating_sub(1);
        }
        if let Some(s_idx) = entry.target_server_idx {
            let be_idx = entry.backend_idx;
            if be_idx < proxies.len() && s_idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[s_idx] =
                    proxies[be_idx].server_actconn[s_idx].saturating_sub(1);
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
                p.stats.clear();
            }
            true
        } else {
            let mut found = false;
            for p in proxies.iter_mut() {
                if p.name == name {
                    p.stats.clear();
                    found = true;
                }
            }
            found
        }
    } else {
        for p in proxies.iter_mut() {
            p.stats.clear();
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
            proxies[old_be].server_actconn[old_idx] =
                proxies[old_be].server_actconn[old_idx].saturating_sub(1);
        }
    }

    let be_idx = EngineDispatcher::resolve_backend(entry, proxies);
    entry.backend_idx = be_idx;
    proxies[be_idx].stats.retries_count += 1;
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
            proxies[be_idx].server_actconn[idx] += 1;
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
                #[allow(clippy::cast_sign_loss)]
                let _ = poller.add(
                    srv.as_fd(),
                    sfd as u64,
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
                #[allow(clippy::cast_sign_loss)]
                let _ = poller.add(srv.as_fd(), sfd as u64, false, true);
            }
        }
    } else {
        proxies[be_idx].stats.failed_conn += 1;
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
                            #[allow(clippy::cast_sign_loss)]
                            let _ = poller.modify(
                                srv_fd.as_fd(),
                                sfd as u64,
                                new_interest.readable,
                                new_interest.writable,
                            );
                        }
                        fdtab.set_interest(sfd, new_interest);
                        entry.srv_interest = new_interest;
                    }
                } else {
                    let be_idx = EngineDispatcher::resolve_backend(entry, proxies);
                    proxies[be_idx].stats.failed_conn += 1;
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
        #[allow(clippy::cast_sign_loss)]
        let _ = poller.modify(
            entry.sess.cli.as_fd(),
            entry.cli_raw_fd as u64,
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
                #[allow(clippy::cast_sign_loss)]
                let _ = poller.modify(
                    srv_fd.as_fd(),
                    sfd as u64,
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
    proxies[proxy_idx].stats.bytes_in += entry.sess.bytes_in;
    proxies[proxy_idx].stats.bytes_out += entry.sess.bytes_out;
    if !entry.actconn_reclaimed {
        proxies[proxy_idx].stats.act_conn = proxies[proxy_idx].stats.act_conn.saturating_sub(1);

        if let Some(s_idx) = entry.target_server_idx {
            let be_idx = entry.backend_idx;
            if be_idx < proxies.len() && s_idx < proxies[be_idx].server_actconn.len() {
                proxies[be_idx].server_actconn[s_idx] =
                    proxies[be_idx].server_actconn[s_idx].saturating_sub(1);
            }
        }
    }

    if let Some(ref table) = proxies[proxy_idx].stick_table {
        if let Some(cli_addr) = entry.sess.client_addr {
            let key = StickKey::Ip(cli_addr.ip());
            let _ = table.update_entry(&key, |data| {
                data.conn_cur = data.conn_cur.saturating_sub(1);
                data.bytes_in_cnt += entry.sess.bytes_in;
                data.bytes_out_cnt += entry.sess.bytes_out;
            });
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    if let Some(l) = listeners.iter_mut().find(|l| l.proxy == proxy_idx as u32) {
        l.nbconn = l.nbconn.saturating_sub(1);
        let lfd = l.raw_fd();
        if !l.is_full() && fdtab.interest(lfd).is_none() {
            #[allow(clippy::cast_sign_loss)]
            let _ = poller.modify(l.borrowed_fd(), lfd as u64, true, false);
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
            htx: None,
            req_uri: entry.sess.req_uri.as_deref(),
            req_method: entry.sess.req_method.as_deref(),
            req_headers: entry.sess.req_headers.as_deref(),
            act_conn: proxy.stats.act_conn,
            cum_conn: proxy.stats.cum_conn,
            ..Default::default()
        };

        let registry = Registry::new();

        for rule in &proxy.use_backends {
            let mut matches = true;
            if let Some(ref cond) = rule.cond {
                matches = crate::proxy::eval_acl_condition(cond, &proxy.acls, &registry, &ctx);
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

            // Step 3.5: If in HTTP mode and request headers are parsed, initiate backend connect
            let mut pending_admin = None;
            if entry.sess.mode == Mode::Http
                && entry.sess.srv_state == ScState::Init
                && entry.sess.cli_state != ScState::Ready
                && !entry.sess.is_done()
            {
                pending_admin = Self::connect_http_backend(
                    entry,
                    self.proxies,
                    self.checks,
                    self.pid,
                    self.fdtab,
                    self.poller,
                    now,
                );
            }

            // Step 3.6: If in TCP mode and server not yet connected (e.g. deferred on accept-proxy), connect once handshake is done
            if entry.sess.mode == Mode::Tcp
                && entry.sess.srv_state == ScState::Init
                && (!entry.sess.accept_proxy || entry.sess.proxy_handshake_done)
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

            // Step 3.8: In HTTP mode, if a transaction has finished (response completely sent to client)
            if entry.sess.mode == Mode::Http
                && entry.response_rules_applied
                && entry.sess.rep.is_empty()
                && entry.sess.pending_resp.is_none()
                && entry.sess.cli_state.can_read()
            {
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
                let backend_finished = matches!(
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
                entry.sess.cli_state = ScState::Ready;
            }

            // Step 4: Update interests
            update_interests(entry, self.fdtab, self.poller);

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
        let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(entry.sess.rep.readable()) else {
            return;
        };
        entry.response_rules_applied = true;
        let be_idx = Self::resolve_backend(entry, proxies);
        let fe_idx = entry.proxy_idx;

        let total_hdr_len = hdr_len + eoh_len;
        let hdr_bytes = &entry.sess.rep.readable()[..total_hdr_len];
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

        let registry = build_sample_registry();

        let req_uri_clone = entry.sess.req_uri.clone();
        let req_method_clone = entry.sess.req_method.clone();
        let req_headers_clone = entry.sess.req_headers.clone();

        let ctx = SampleContext {
            client_addr: entry.sess.client_addr,
            server_addr: entry.target_addr,
            htx: None,
            req_uri: req_uri_clone.as_deref(),
            req_method: req_method_clone.as_deref(),
            req_headers: req_headers_clone.as_deref(),
            ..Default::default()
        };

        let eval_res_action = |act_name: &str, act_fmt: &str, hdrs: &mut Vec<(String, String)>, status: &mut u16, status_msg: &mut String| -> Result<bool, u16> {
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
                    e.eval_sample(&registry, &ctx)
                        .map(|smp| sample_to_string(&smp))
                        .unwrap_or_default()
                } else {
                    format_sample_string(act_fmt, &ctx, &registry)
                };
                CURRENT_VARS.with(|v| {
                    v.borrow_mut().insert(var_name.to_string(), val);
                });
                return Ok(true);
            }
            if let Some(var_name) = act_name.strip_prefix("\0unset-var:") {
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

            let val = format_sample_string(act_fmt, &ctx, &registry);
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
                Some(cond) => eval_condition(cond, &ctx, &proxies[be_idx].acls, &registry),
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
                        let val = format_sample_string(fmt, &ctx, &registry);
                        CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                    } else {
                        let val = format_sample_string(fmt, &ctx, &registry);
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
                    Some(cond) => eval_condition(cond, &ctx, &proxies[fe_idx].acls, &registry),
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
                            let val = format_sample_string(fmt, &ctx, &registry);
                            CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                        } else {
                            let val = format_sample_string(fmt, &ctx, &registry);
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
                Some(cond) => eval_condition(cond, &ctx, &proxies[be_idx].acls, &registry),
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
                        let val = format_sample_string(fmt, &ctx, &registry);
                        CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                    } else {
                        let val = format_sample_string(fmt, &ctx, &registry);
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
                Some(cond) => eval_condition(cond, &ctx, &proxies[fe_idx].acls, &registry),
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
                        let val = format_sample_string(fmt, &ctx, &registry);
                        CURRENT_VARS.with(|v| v.borrow_mut().insert(var_name.to_string(), val));
                    } else {
                        let val = format_sample_string(fmt, &ctx, &registry);
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
        entry.sess.srv_state = ScState::Established;
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
                                        proxy.server_statuses[s_idx] = st;
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
    fn connect_http_backend(
        entry: &mut SessionEntry,
        proxies: &mut [Proxy],
        checks: &mut [ServerCheckState],
        pid: u32,
        fdtab: &mut FdTab,
        poller: &mut Poller,
        now: Tick,
    ) -> Option<crate::stats_html::AdminAction> {
        let proxy_idx = entry.proxy_idx;

        // Initialize per-request thread locals
        CURRENT_VARS.with(|v| v.borrow_mut().clear());
        CURRENT_TIMEOUTS.with(|t| {
            let mut map = t.borrow_mut();
            map.clear();
            #[allow(clippy::cast_possible_truncation)]
            let fe_client = proxies[proxy_idx].stats_config.raw_timeouts.client.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let fe_connect = proxies[proxy_idx].stats_config.raw_timeouts.connect.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let fe_server = proxies[proxy_idx].stats_config.raw_timeouts.server.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let fe_queue = proxies[proxy_idx].stats_config.raw_timeouts.queue.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let fe_tunnel = proxies[proxy_idx].stats_config.raw_timeouts.tunnel.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let fe_tarpit = proxies[proxy_idx].stats_config.raw_timeouts.tarpit.map_or(0, |d| d.as_millis() as u32);

            map.insert("fe_client_timeout".into(), fe_client);
            map.insert("cur_client_timeout".into(), fe_client);
            map.insert("fe_connect_timeout".into(), fe_connect);
            map.insert("cur_connect_timeout".into(), fe_connect);
            map.insert("fe_server_timeout".into(), fe_server);
            map.insert("cur_server_timeout".into(), fe_server);
            map.insert("fe_queue_timeout".into(), fe_queue);
            map.insert("cur_queue_timeout".into(), fe_queue);
            map.insert("fe_tunnel_timeout".into(), fe_tunnel);
            map.insert("cur_tunnel_timeout".into(), fe_tunnel);
            map.insert("fe_tarpit_timeout".into(), fe_tarpit);
            map.insert("cur_tarpit_timeout".into(), fe_tarpit);

            map.insert("be_client_timeout".into(), fe_client);
            map.insert("be_server_timeout".into(), fe_server);
            map.insert("be_connect_timeout".into(), fe_connect);
            map.insert("be_queue_timeout".into(), fe_queue);
            map.insert("be_tunnel_timeout".into(), fe_tunnel);
            map.insert("be_tarpit_timeout".into(), fe_tarpit);
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

        // 1. Stick table tracking from http_req_rules
        let key_opt = entry.sess.client_addr.map(|a| StickKey::Ip(a.ip()));
        let mut sc_http_req_rates = [0u64; 3];
        let mut sc_conn_rates = [0u64; 3];

        for rule in &proxies[proxy_idx].http_req_rules {
            match &rule.action {
                ibex_config::HttpReqAction::TrackSc0 { table, .. } => {
                    let target_table = if let Some(ref tname) = table {
                        proxies
                            .iter()
                            .find(|p| p.name == *tname)
                            .and_then(|p| p.stick_table.as_ref())
                    } else {
                        proxies[proxy_idx].stick_table.as_ref()
                    };
                    if let (Some(tbl), Some(k)) = (target_table, key_opt.as_ref()) {
                        let _ = tbl.update_entry(k, |data| {
                            data.http_req_cnt += 1;
                            if let Some(ref mut r) = data.http_req_rate {
                                r.tick(1);
                            }
                        });
                    }
                }
                ibex_config::HttpReqAction::TrackSc1 { table, .. } => {
                    let target_table = if let Some(ref tname) = table {
                        proxies
                            .iter()
                            .find(|p| p.name == *tname)
                            .and_then(|p| p.stick_table.as_ref())
                    } else {
                        proxies[proxy_idx].stick_table.as_ref()
                    };
                    if let (Some(tbl), Some(k)) = (target_table, key_opt.as_ref()) {
                        let _ = tbl.update_entry(k, |data| {
                            data.http_req_cnt += 1;
                            if let Some(ref mut r) = data.http_req_rate {
                                r.tick(1);
                            }
                        });
                    }
                }
                ibex_config::HttpReqAction::TrackSc2 { table, .. } => {
                    let target_table = if let Some(ref tname) = table {
                        proxies
                            .iter()
                            .find(|p| p.name == *tname)
                            .and_then(|p| p.stick_table.as_ref())
                    } else {
                        proxies[proxy_idx].stick_table.as_ref()
                    };
                    if let (Some(tbl), Some(k)) = (target_table, key_opt.as_ref()) {
                        let _ = tbl.update_entry(k, |data| {
                            data.http_req_cnt += 1;
                            if let Some(ref mut r) = data.http_req_rate {
                                r.tick(1);
                            }
                        });
                    }
                }
                _ => {}
            }
        }

        // Query rates from stick tables
        if let Some(ref k) = key_opt {
            for rule in &proxies[proxy_idx].http_req_rules {
                match &rule.action {
                    ibex_config::HttpReqAction::TrackSc0 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            if let Ok(Some(data)) = tbl.get_entry(k) {
                                if let Some(ref r) = data.http_req_rate {
                                    sc_http_req_rates[0] = r.rate();
                                }
                                if let Some(ref r) = data.conn_rate {
                                    sc_conn_rates[0] = r.rate();
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::TrackSc1 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            if let Ok(Some(data)) = tbl.get_entry(k) {
                                if let Some(ref r) = data.http_req_rate {
                                    sc_http_req_rates[1] = r.rate();
                                }
                                if let Some(ref r) = data.conn_rate {
                                    sc_conn_rates[1] = r.rate();
                                }
                            }
                        }
                    }
                    ibex_config::HttpReqAction::TrackSc2 { table, .. } => {
                        let target_table = if let Some(ref tname) = table {
                            proxies
                                .iter()
                                .find(|p| p.name == *tname)
                                .and_then(|p| p.stick_table.as_ref())
                        } else {
                            proxies[proxy_idx].stick_table.as_ref()
                        };
                        if let Some(tbl) = target_table {
                            if let Ok(Some(data)) = tbl.get_entry(k) {
                                if let Some(ref r) = data.http_req_rate {
                                    sc_http_req_rates[2] = r.rate();
                                }
                                if let Some(ref r) = data.conn_rate {
                                    sc_conn_rates[2] = r.rate();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Fallback default tracking if no http_req_rules track
        if proxies[proxy_idx].http_req_rules.is_empty() {
            if let Some(ref table) = proxies[proxy_idx].stick_table {
                if let Some(ref k) = key_opt {
                    let _ = table.update_entry(k, |data| {
                        data.http_req_cnt += 1;
                        if let Some(ref mut rate) = data.http_req_rate {
                            rate.tick(1);
                        }
                    });
                }
            }
        }

        let registry = build_sample_registry();

        // 2. Helper closure to evaluate http-request rules
        let eval_http_rules = |rules: &[ibex_config::HttpReqRule], acls: &HashMap<String, Expr>, sess: &mut TcpSession, target_addr: Option<SocketAddr>| -> Result<Option<()>, ()> {
            for rule in rules {
                let req_uri_clone = sess.req_uri.clone();
                let req_method_clone = sess.req_method.clone();
                let req_headers_clone = sess.req_headers.clone();
                let ctx = SampleContext {
                    client_addr: sess.client_addr,
                    server_addr: target_addr,
                    htx: None,
                    req_uri: req_uri_clone.as_deref(),
                    req_method: req_method_clone.as_deref(),
                    req_headers: req_headers_clone.as_deref(),
                    act_conn: proxies[proxy_idx].stats.act_conn,
                    cum_conn: proxies[proxy_idx].stats.cum_conn,
                    sc_http_req_rates,
                    sc_conn_rates,
                    ..Default::default()
                };

                let matches = match &rule.cond {
                    None => true,
                    Some(cond) => eval_condition(cond, &ctx, acls, &registry),
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
                                        let formatted_v = format_sample_string(v, &ctx, &registry);
                                        custom_headers.push((k.to_string(), formatted_v));
                                    }
                                    rest = r;
                                } else {
                                    break;
                                }
                            }
                            if let Some(b) = rest.strip_prefix("\0BODY:") {
                                body_str = format_sample_string(b, &ctx, &registry);
                            } else if !rest.starts_with('\0') {
                                body_str = format_sample_string(rest, &ctx, &registry);
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
                        let formatted_loc = format_sample_string(loc, &ctx, &registry);
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
                        let new_path = format_sample_string(fmt, &ctx, &registry);
                        let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                        let (pfx, _, query) = split_uri(current_uri);
                        let rebuilt = rebuild_uri(pfx, &new_path, query);
                        sess.req_uri = Some(rebuilt);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::ReplacePath { regex, repl } => {
                        let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                        let (pfx, path, query) = split_uri(current_uri);
                        let rust_repl = translate_backreferences(repl);
                        if let Ok(re) = regex::Regex::new(regex) {
                            let new_path = re.replace_all(path, &rust_repl).to_string();
                            let rebuilt = rebuild_uri(pfx, &new_path, query);
                            sess.req_uri = Some(rebuilt);
                            rebuild_req_buffer(sess);
                        }
                    }
                    ibex_config::HttpReqAction::SetPathq { fmt } => {
                        let new_pathq = format_sample_string(fmt, &ctx, &registry);
                        let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                        let (pfx, _, _) = split_uri(current_uri);
                        let rebuilt = format!("{pfx}{new_pathq}");
                        sess.req_uri = Some(rebuilt);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::ReplacePathq { regex, repl } => {
                        let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                        let (pfx, path, query) = split_uri(current_uri);
                        let pathq = if query.is_empty() { path.to_string() } else { format!("{path}?{query}") };
                        let rust_repl = translate_backreferences(repl);
                        if let Ok(re) = regex::Regex::new(regex) {
                            let new_pathq = re.replace_all(&pathq, &rust_repl).to_string();
                            let rebuilt = format!("{pfx}{new_pathq}");
                            sess.req_uri = Some(rebuilt);
                            rebuild_req_buffer(sess);
                        }
                    }
                    ibex_config::HttpReqAction::SetQuery { fmt } => {
                        let new_query = format_sample_string(fmt, &ctx, &registry);
                        let current_uri = sess.req_uri.as_deref().unwrap_or("/");
                        let (pfx, path, _) = split_uri(current_uri);
                        let rebuilt = rebuild_uri(pfx, path, &new_query);
                        sess.req_uri = Some(rebuilt);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::SetUri { fmt } => {
                        let new_uri = format_sample_string(fmt, &ctx, &registry);
                        sess.req_uri = Some(new_uri);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::SetMethod { fmt } => {
                        let new_method = format_sample_string(fmt, &ctx, &registry);
                        sess.req_method = Some(new_method);
                        rebuild_req_buffer(sess);
                    }
                    ibex_config::HttpReqAction::SetSrc { expr } => {
                        let val = if let Ok(e) = Expr::parse(expr) {
                            e.eval_sample(&registry, &ctx)
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &ctx, &registry)
                        };
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            sess.client_addr = Some(SocketAddr::new(ip, 0));
                        }
                    }
                    ibex_config::HttpReqAction::SetDst { expr } => {
                        let val = if let Ok(e) = Expr::parse(expr) {
                            e.eval_sample(&registry, &ctx)
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &ctx, &registry)
                        };
                        if let Ok(ip) = val.parse::<IpAddr>() {
                            sess.server_addr = Some(SocketAddr::new(ip, 0));
                        }
                    }
                    ibex_config::HttpReqAction::SetVar { var_name, expr } => {
                        let val = if let Ok(e) = Expr::parse(expr) {
                            e.eval_sample(&registry, &ctx)
                                .map(|smp| sample_to_string(&smp))
                                .unwrap_or_default()
                        } else {
                            format_sample_string(expr, &ctx, &registry)
                        };
                        CURRENT_VARS.with(|v| {
                            v.borrow_mut().insert(var_name.clone(), val);
                        });
                    }
                    ibex_config::HttpReqAction::UnsetVar { var_name } => {
                        CURRENT_VARS.with(|v| {
                            v.borrow_mut().remove(var_name);
                        });
                    }
                    ibex_config::HttpReqAction::StrictMode { on } => {
                        STRICT_MODE.set(*on);
                    }
                    ibex_config::HttpReqAction::SetTimeout { timeout_type, timeout_val } => {
                        let ms = if let Ok(expr) = Expr::parse(timeout_val) {
                            if let Some(smp) = expr.eval_sample(&registry, &ctx) {
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
                                    map.insert("cur_client_timeout".into(), ms);
                                    map.insert("cur_client_timeout_set".into(), 1);
                                }
                                "server" => {
                                    map.insert("cur_server_timeout".into(), ms);
                                    map.insert("cur_server_timeout_set".into(), 1);
                                }
                                "connect" => {
                                    map.insert("cur_connect_timeout".into(), ms);
                                    map.insert("cur_connect_timeout_set".into(), 1);
                                }
                                "queue" => {
                                    map.insert("cur_queue_timeout".into(), ms);
                                    map.insert("cur_queue_timeout_set".into(), 1);
                                }
                                "tunnel" => {
                                    map.insert("cur_tunnel_timeout".into(), ms);
                                    map.insert("cur_tunnel_timeout_set".into(), 1);
                                }
                                "tarpit" => {
                                    map.insert("cur_tarpit_timeout".into(), ms);
                                    map.insert("cur_tarpit_timeout_set".into(), 1);
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
                        let val = format_sample_string(fmt, &ctx, &registry);
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
                        let val = format_sample_string(fmt, &ctx, &registry);
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
                    _ => {}
                }
            }
            Ok(None)
        };

        // Execute frontend rules
        let fe_rules = proxies[proxy_idx].http_req_rules.clone();
        let fe_acls = proxies[proxy_idx].acls.clone();
        if let Ok(Some(())) = eval_http_rules(&fe_rules, &fe_acls, &mut entry.sess, entry.target_addr) {
            return None;
        }

        // 3. Resolve backend and server
        let be_idx = Self::resolve_backend(entry, proxies);
        entry.backend_idx = be_idx;

        // Update backend timeouts
        CURRENT_TIMEOUTS.with(|t| {
            let mut map = t.borrow_mut();
            #[allow(clippy::cast_possible_truncation)]
            let be_server = proxies[be_idx].stats_config.raw_timeouts.server.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let be_connect = proxies[be_idx].stats_config.raw_timeouts.connect.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let be_queue = proxies[be_idx].stats_config.raw_timeouts.queue.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let be_tunnel = proxies[be_idx].stats_config.raw_timeouts.tunnel.map_or(0, |d| d.as_millis() as u32);
            #[allow(clippy::cast_possible_truncation)]
            let be_tarpit = proxies[be_idx].stats_config.raw_timeouts.tarpit.map_or(0, |d| d.as_millis() as u32);

            map.insert("be_server_timeout".into(), be_server);
            map.insert("be_connect_timeout".into(), be_connect);
            map.insert("be_queue_timeout".into(), be_queue);
            map.insert("be_tunnel_timeout".into(), be_tunnel);
            map.insert("be_tarpit_timeout".into(), be_tarpit);

            if be_idx != proxy_idx {
                map.insert("cur_server_timeout".into(), be_server);
                map.insert("cur_connect_timeout".into(), be_connect);
                map.insert("cur_queue_timeout".into(), be_queue);
                map.insert("cur_tunnel_timeout".into(), be_tunnel);
            }
        });

        // If be_idx != proxy_idx, execute backend rules
        if be_idx != proxy_idx {
            let be_rules = proxies[be_idx].http_req_rules.clone();
            let be_acls = proxies[be_idx].acls.clone();
            if let Ok(Some(())) = eval_http_rules(&be_rules, &be_acls, &mut entry.sess, entry.target_addr) {
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

        let req_uri_c = entry.sess.req_uri.clone();
        let req_meth_c = entry.sess.req_method.clone();
        let req_hdrs_c = entry.sess.req_headers.clone();
        let res_ctx = SampleContext {
            client_addr: entry.sess.client_addr,
            server_addr: entry.target_addr,
            htx: None,
            req_uri: req_uri_c.as_deref(),
            req_method: req_meth_c.as_deref(),
            req_headers: req_hdrs_c.as_deref(),
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
                    let formatted_fmt = format_sample_string(fmt, &res_ctx, &registry);
                    ibex_config::HttpResAction::SetHeader {
                        name: name.clone(),
                        fmt: formatted_fmt,
                    }
                }
                ibex_config::HttpResAction::AddHeader { name, fmt } => {
                    let formatted_fmt = format_sample_string(fmt, &res_ctx, &registry);
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
            // Only the header actions carry a log-format string that needs expanding.
            // Everything else is copied through unchanged, expressed as a default so a
            // newly added action passes through rather than needing an arm here.
            let mut action = rule.action.clone();
            if let ibex_config::HttpAfterResAction::SetHeader { fmt, .. }
            | ibex_config::HttpAfterResAction::AddHeader { fmt, .. } = &mut action
            {
                *fmt = format_sample_string(fmt, &res_ctx, &registry);
            }
            after_rules.push(ibex_config::HttpAfterResRule {
                action,
                cond: rule.cond.clone(),
            });
        }
        entry.sess.http_after_res_rules = after_rules;

        let source_ip = entry.sess.client_addr.map(|a| a.ip());
        let target = if let Some(ref cval) = entry.sess.cookie_val {
            proxies[be_idx]
                .select_server_by_id(cval)
                .or_else(|| proxies[be_idx].select_server_with_key(source_ip))
        } else {
            proxies[be_idx].select_server_with_key(source_ip)
        };

        let Some(target_addr) = target else {
            proxies[be_idx].stats.failed_conn += 1;
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
                proxies[be_idx].server_actconn[idx] += 1;
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
                    #[allow(clippy::cast_sign_loss)]
                    let _ = poller.add(
                        srv.as_fd(),
                        sfd as u64,
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
                    #[allow(clippy::cast_sign_loss)]
                    let _ = poller.add(srv.as_fd(), sfd as u64, false, true);
                }
            }
        } else {
            proxies[be_idx].stats.failed_conn += 1;
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
        let proxy_idx = entry.proxy_idx;
        let be_idx = Self::resolve_backend(entry, proxies);
        entry.backend_idx = be_idx;

        if let Some(ref table) = proxies[proxy_idx].stick_table {
            if let Some(cli_addr) = entry.sess.client_addr {
                let key = StickKey::Ip(cli_addr.ip());
                let _ = table.update_entry(&key, |data| {
                    data.conn_cnt += 1;
                    data.conn_cur += 1;
                    if let Some(ref mut rate) = data.conn_rate {
                        rate.tick(1);
                    }
                });
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
                proxies[be_idx].server_actconn[idx] += 1;
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
                    #[allow(clippy::cast_sign_loss)]
                    let _ = poller.add(
                        srv.as_fd(),
                        sfd as u64,
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
                    #[allow(clippy::cast_sign_loss)]
                    let _ = poller.add(srv.as_fd(), sfd as u64, false, true);
                }
            }
        } else {
            proxies[be_idx].stats.failed_conn += 1;
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
                self.proxies[proxy_idx].server_statuses[server_idx] = check.status;
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

    #[allow(clippy::cast_possible_truncation)]
    fn step_applet(&mut self, applet_idx: usize) -> Outcome {
        let Some(applet) = self.applets.get_mut(applet_idx as u32) else {
            return Outcome::Done;
        };

        if applet.is_done {
            if let Some(applet) = self.applets.free(applet_idx as u32) {
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
            if let Some(applet) = self.applets.free(applet_idx as u32) {
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
                #[allow(clippy::cast_sign_loss)]
                let _ = self.poller.modify(
                    stream.as_fd(),
                    applet.raw_fd as u64,
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
fn build_sample_registry() -> Registry {
    Registry::new()
}

fn sample_to_string(smp: &Sample) -> String {
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

fn format_sample_string(fmt: &str, ctx: &SampleContext, registry: &Registry) -> String {
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
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    hdrs.push((name.to_string(), val.to_string()));
    sess.req_headers = Some(hdrs);
    rebuild_req_buffer(sess);
}

fn del_req_header(sess: &mut TcpSession, name: &str) {
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    hdrs.retain(|(k, _)| !header_name_matches(k, name));
    sess.req_headers = Some(hdrs);
    rebuild_req_buffer(sess);
}

fn replace_req_header(sess: &mut TcpSession, name: &str, regex: &str, repl: &str) -> Result<(), ()> {
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
