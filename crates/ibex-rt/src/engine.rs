// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/haproxy.c (run_poll_loop, process_task), src/listener.c,
// and src/stream.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The integrated runtime engine: listeners, connections, poller, scheduler, and proxies.
//!
//! Connects [`Listener`], [`Poller`], [`FdTab`], [`Scheduler`], and [`TcpSession`]
//! into the single-threaded soft-realtime execution loop described in `design/008-tcp-first.md`.

use crate::applet::{AppletArena, AppletContext, CliApplet};
use crate::check::{self, ServerCheckConfig, ServerCheckState, ServerStatus};
use crate::fdtab::{FdState, FdTab, Interest};
use crate::listener::Listener;
use crate::poller::Poller;
use crate::proxy::{TcpSession, Timeouts};
use crate::raw;
use ibex_config::{BalanceAlgorithm, Config, Mode, StickRule, UseBackendRule};
use ibex_proto::endpoint::ScState;
use ibex_sample::{Expr, Registry, SampleContext};
use ibex_sched::task::{state, Kind, TaskRef, WorkKind};
use ibex_sched::{Class, Dispatch, Outcome, Scheduler, Tick};
use ibex_stick_table::{KeyType, StickKey, StickTable, StickTableConfig};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        stats_config: listen.stats.clone(),
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
        tcp_req_conn_rules: Vec::new(),
        http_req_rules: Vec::new(),
        http_res_rules: Vec::new(),
        http_after_res_rules: Vec::new(),
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
        stats_config: fe.stats.clone(),
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
        http_res_rules: Vec::new(),
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
        stats_config: be.stats.clone(),
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

            let lfd = listener.raw_fd();
            #[allow(clippy::cast_possible_truncation)]
            fdtab.insert(
                lfd,
                FdState::Listener {
                    listener: proxy_idx as u32,
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

                let lfd = listener.raw_fd();
                #[allow(clippy::cast_possible_truncation)]
                fdtab.insert(
                    lfd,
                    FdState::Listener {
                        listener: proxy_idx as u32,
                    },
                    Interest::READ,
                );
                #[allow(clippy::cast_sign_loss)]
                poller.add(listener.borrowed_fd(), lfd as u64, true, false)?;

                listeners.push(listener);
            }
            proxies.push(proxy);
        }

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
                    let proxy_idx = l_idx as usize;
                    if proxy_idx < self.proxies.len() {
                        self.accept_from_listener(proxy_idx);
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
    fn accept_from_listener(&mut self, proxy_idx: usize) {
        #[allow(clippy::cast_possible_truncation)]
        let Some(l_idx) = self
            .listeners
            .iter()
            .position(|l| l.proxy == proxy_idx as u32)
        else {
            return;
        };

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

            register_new_session(self, proxy_idx, cli_fd, peer_addr);
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
    cli_fd: std::os::fd::OwnedFd,
    peer_addr: SocketAddr,
) {
    let proxy = &mut engine.proxies[proxy_idx];
    let cli_raw_fd = cli_fd.as_raw_fd();
    let (mut sess, target_addr, srv_raw_fd) =
        init_client_session(proxy, cli_fd, engine.now, peer_addr);
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
) -> (TcpSession, Option<SocketAddr>, Option<RawFd>) {
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
    (sess, target_addr, srv_raw_fd)
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
                && !entry.sess.resp_headers_processed
                && !entry.sess.rep.is_empty()
            {
                Self::apply_http_response_rules(entry, self.proxies, now);
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
        let be_idx = Self::resolve_backend(entry, proxies);
        let fe_idx = entry.proxy_idx;

        let total_hdr_len = hdr_len + eoh_len;
        let hdr_bytes = &entry.sess.rep.readable()[..total_hdr_len];
        let hdr_str = String::from_utf8_lossy(hdr_bytes);

        let Some((first_line, rest_headers)) = hdr_str.split_once("\r\n") else {
            return;
        };

        let mut hdrs: Vec<(String, String)> = Vec::new();
        for line in rest_headers.lines() {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                hdrs.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        // Apply be.http_res_rules
        for rule in &proxies[be_idx].http_res_rules {
            match &rule.action {
                ibex_config::HttpResAction::SetHeader { name, fmt } => {
                    let val = fmt.clone();
                    if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case(name)) {
                        hdrs[pos].1 = val;
                    } else {
                        hdrs.push((name.clone(), val));
                    }
                }
                ibex_config::HttpResAction::AddHeader { name, fmt } => {
                    hdrs.push((name.clone(), fmt.clone()));
                }
                ibex_config::HttpResAction::DelHeader { name } => {
                    hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                }
                ibex_config::HttpResAction::SetStatus { .. } => {}
            }
        }

        // Apply be.http_after_res_rules
        for rule in &proxies[be_idx].http_after_res_rules {
            match &rule.action {
                ibex_config::HttpAfterResAction::SetHeader { name, fmt } => {
                    let val = if fmt == "%Tr" {
                        "0ms".to_string()
                    } else {
                        fmt.clone()
                    };
                    if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case(name)) {
                        hdrs[pos].1 = val;
                    } else {
                        hdrs.push((name.clone(), val));
                    }
                }
                ibex_config::HttpAfterResAction::AddHeader { name, fmt } => {
                    let val = if fmt == "%Tr" {
                        "0ms".to_string()
                    } else {
                        fmt.clone()
                    };
                    hdrs.push((name.clone(), val));
                }
                ibex_config::HttpAfterResAction::DelHeader { name } => {
                    hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                }
            }
        }

        // Apply fe.http_after_res_rules
        for rule in &proxies[fe_idx].http_after_res_rules {
            match &rule.action {
                ibex_config::HttpAfterResAction::SetHeader { name, fmt } => {
                    let val = if fmt == "%Tr" {
                        "0ms".to_string()
                    } else {
                        fmt.clone()
                    };
                    if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case(name)) {
                        hdrs[pos].1 = val;
                    } else {
                        hdrs.push((name.clone(), val));
                    }
                }
                ibex_config::HttpAfterResAction::AddHeader { name, fmt } => {
                    let val = if fmt == "%Tr" {
                        "0ms".to_string()
                    } else {
                        fmt.clone()
                    };
                    hdrs.push((name.clone(), val));
                }
                ibex_config::HttpAfterResAction::DelHeader { name } => {
                    hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                }
            }
        }

        let mut new_hdr = format!("{first_line}\r\n");
        for (k, v) in hdrs {
            let _ = write!(new_hdr, "{k}: {v}\r\n");
        }
        new_hdr.push_str("\r\n");

        entry
            .sess
            .rep
            .replace_prefix(total_hdr_len, new_hdr.as_bytes());
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

        // Check if stats are enabled on this proxy and URI matches
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

        // 2. Evaluate http-request rules
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
            act_conn: proxies[proxy_idx].stats.act_conn,
            cum_conn: proxies[proxy_idx].stats.cum_conn,
            sc_http_req_rates,
            sc_conn_rates,
            ..Default::default()
        };

        let registry = Registry::new();

        for rule in &proxies[proxy_idx].http_req_rules {
            let matches = match &rule.cond {
                None => true,
                Some(cond) => eval_condition(cond, &ctx, &proxies[proxy_idx].acls, &registry),
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
                    let unescaped;
                    let body = if let Some(s) = lf_string.as_deref() {
                        unescaped = s
                            .replace("\\n", "\n")
                            .replace("\\r", "\r")
                            .replace("\\t", "\t");
                        unescaped.as_str()
                    } else {
                        ""
                    };
                    let ctype = content_type.as_deref().unwrap_or("text/plain");
                    let reason = status_reason(*status);
                    let resp = format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        reason,
                        ctype,
                        body.len(),
                        body
                    );
                    let w = entry.sess.rep.writable();
                    let n = w.len().min(resp.len());
                    w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                    entry.sess.rep.commit(n);
                    entry.sess.cli_state = ScState::ShutR;
                    entry.sess.srv_state = ScState::Closed;
                    return None;
                }
                ibex_config::HttpReqAction::Deny { deny_status } => {
                    let status_code = deny_status.unwrap_or(403);
                    let reason = status_reason(status_code);
                    let resp = format!(
                        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let w = entry.sess.rep.writable();
                    let n = w.len().min(resp.len());
                    w[..n].copy_from_slice(&resp.as_bytes()[..n]);
                    entry.sess.rep.commit(n);
                    entry.sess.cli_state = ScState::ShutR;
                    entry.sess.srv_state = ScState::Closed;
                    return None;
                }
                ibex_config::HttpReqAction::SetHeader { name, fmt } => {
                    let val = format_sample_string(fmt, &ctx);
                    set_req_header(&mut entry.sess, name, &val);
                }
                ibex_config::HttpReqAction::AddHeader { name, fmt } => {
                    let val = format_sample_string(fmt, &ctx);
                    add_req_header(&mut entry.sess, name, &val);
                }
                ibex_config::HttpReqAction::DelHeader { name } => {
                    del_req_header(&mut entry.sess, name);
                }
                _ => {}
            }
        }

        // 3. Resolve backend and server
        let be_idx = Self::resolve_backend(entry, proxies);
        entry.backend_idx = be_idx;
        entry.sess.http_res_rules = proxies[be_idx].http_res_rules.clone();
        let mut after_rules = proxies[be_idx].http_after_res_rules.clone();
        after_rules.extend(proxies[proxy_idx].http_after_res_rules.clone());
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
            let _ = check::step_check(check, self.fdtab, self.poller, now);

            let proxy_idx = check.proxy_idx;
            let server_idx = check.server_idx;
            if check.enabled
                && proxy_idx < self.proxies.len()
                && server_idx < self.proxies[proxy_idx].server_statuses.len()
            {
                self.proxies[proxy_idx].server_statuses[server_idx] = check.status;
            }

            self.timer_updates.push((check.task, check.next_check));
            Outcome::Keep
        } else {
            Outcome::Done
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

fn format_sample_string(fmt: &str, ctx: &SampleContext) -> String {
    if fmt == "%ci" || fmt == "%[src]" {
        ctx.client_addr
            .map_or_else(|| "127.0.0.1".to_string(), |a| a.ip().to_string())
    } else if fmt == "%Tr" {
        "0ms".to_string()
    } else {
        fmt.to_string()
    }
}

fn set_req_header(sess: &mut TcpSession, name: &str, val: &str) {
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    if let Some(pos) = hdrs.iter().position(|(k, _)| k.eq_ignore_ascii_case(name)) {
        hdrs[pos].1 = val.to_string();
    } else {
        hdrs.push((name.to_string(), val.to_string()));
    }
    rebuild_req_buffer(sess, &hdrs);
    sess.req_headers = Some(hdrs);
}

fn add_req_header(sess: &mut TcpSession, name: &str, val: &str) {
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    hdrs.push((name.to_string(), val.to_string()));
    rebuild_req_buffer(sess, &hdrs);
    sess.req_headers = Some(hdrs);
}

fn del_req_header(sess: &mut TcpSession, name: &str) {
    let mut hdrs = sess.req_headers.take().unwrap_or_default();
    hdrs.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    rebuild_req_buffer(sess, &hdrs);
    sess.req_headers = Some(hdrs);
}

fn rebuild_req_buffer(sess: &mut TcpSession, hdrs: &[(String, String)]) {
    let Some((hdr_len, eoh_len)) = crate::proxy::find_eoh(sess.req.readable()) else {
        return;
    };
    let method = sess.req_method.as_deref().unwrap_or("GET");
    let uri = sess.req_uri.as_deref().unwrap_or("/");
    let mut new_hdr = format!("{method} {uri} HTTP/1.1\r\n");
    for (k, v) in hdrs {
        let _ = write!(new_hdr, "{k}: {v}\r\n");
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
        let expr_opt = acls
            .get(&term.name)
            .cloned()
            .or_else(|| Expr::parse(&term.name).ok());
        if let Some(expr) = expr_opt {
            let res = expr.eval(registry, ctx);
            let term_res = if term.negated { !res } else { res };
            if !term_res {
                term_match = false;
                break;
            }
        } else {
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
