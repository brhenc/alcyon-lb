// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The servers of one backend, read through one door (T637, slices S1a and S1b).
//!
//! A server is a position in about 25 parallel arrays. They live in [`ServerArrays`] (inline in
//! [`Proxy`]) and [`ServerIdArrays`] (in [`ProxyIdInfo`]), whose fields are private to this
//! module: the compiler, not only `harness/server_set_census.py`, keeps every other file from
//! naming one. Every reader and writer goes through [`ServerSet`] (by slot, for the request
//! path, which holds a slot number for the life of a stream) and [`Srv`] (a server that
//! exists). When the set of servers can change at run time
//! (`docs/design/runtime-server-set-2026-11-16.md`) there is one place that knows what a
//! missing server looks like.
//!
//! Today the set is a *view* of the proxy's arrays: nothing is copied and nothing changes
//! behaviour. A slot is empty when its name is empty (a configured server always has one), and
//! [`ServerSet::at`], [`ServerSet::find`], [`ServerSet::by_puid`] and [`ServerSet::live`] do
//! not return an empty slot. The by-slot accessors the request path uses (`status_at`,
//! `actconn_inc`, ...) do not look at the name: they are the loads the old code made.
//!
//! The hot state several threads write (status, stream count, session rate) is one array of
//! `Cell`s in [`ServerCells`], shared by every clone of the proxy. Only `base` exists yet:
//! section 3.1's `more` segments (servers added at run time) arrive with `add server`, and the
//! address, weight and `maxconn` keep their own shared types until then.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use crate::check::{ServerCheckConfig, ServerStatus};
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use crate::engine::{Proxy, ProxyIdInfo, RateCtr, SrvPoolCfg};
use crate::track::Track;

type RetrCounts = std::collections::HashMap<usize, (u64, u64, u64)>;

/// The hot, shared state of one server: what several threads write (T637 section 3.1's `Cell`,
/// without the address, the weight and the `maxconn`, which keep their own types for now).
#[derive(Debug, Default)]
struct Cell {
    status: AtomicU8,
    actconn: AtomicU32,
    rate: RateCtr,
}

/// The cells of the servers of the configuration (`base`). Later slices add the servers
/// created at run time next to it; one object shared by every table of the proxy.
#[derive(Debug, Default)]
struct ServerCells {
    base: Box<[Cell]>,
}

/// A slot is named by a sample fetch, a `use-server` target, or another server's `track`.
/// `set server <b>/<s> name` refuses to rename it and `del server` refuses to remove it
/// (HAProxy `SRV_F_NAME_REFD`). Load-only: set once, never cleared.
pub const NAME_REFD: u8 = 0x1;
/// A `resolvers` section resolves the slot's address at run time (HAProxy
/// `SRV_F_NON_PURGEABLE`). `del server` refuses it, but a rename is allowed. Load-only.
pub const NON_PURGEABLE: u8 = 0x2;

/// The per-server arrays of a [`Proxy`], private to this module (T637, section 4.2): the only
/// way to a server is [`ServerSet`].
#[derive(Debug, Clone)]
pub struct ServerArrays {
    cells: Arc<ServerCells>,
    /// Each server's address, shared by every worker: `set server ... addr` changes it
    /// in place (T177).
    servers: crate::srv_rt::ServerAddrs,
    server_ids: crate::srv_rt::ServerNames,
    /// Each server's persistence cookie value (`server ... cookie <value>`). A server
    /// without one is never chosen by a cookie, not even by its name.
    server_cookies: Vec<Option<Box<str>>>,
    /// `track` of each server (`None` for one that tracks nothing; empty when none does).
    server_track: Option<Arc<Vec<Option<crate::track::Track>>>>,
    /// Each server's current weight and its configured one (`iweight`: what `set server
    /// ... weight <n>%` is a share of, and the `initial` of `get weight`), shared by every
    /// worker: `set weight` changes it in place (T177).
    server_weights: crate::srv_rt::ServerWeights,
    server_send_proxy: Vec<bool>,
    /// `tfo` per server, in `servers` order.
    server_tfo: Vec<bool>,
    server_send_proxy_v2: Vec<bool>,
    /// `proxy-v2-options unique-id`, per server.
    server_pp_unique_id: Vec<bool>,
    server_backups: Vec<bool>,
    /// Each server's load-only "pointed to" flags, one byte per slot ([`NAME_REFD`],
    /// [`NON_PURGEABLE`]): a sample fetch's argument (`srv_is_up(be/s)` and the other `srv_*`),
    /// a `use-server` target, or another server's `track` names it, so `set server <b>/<s> name`
    /// refuses to rename it and `del server` refuses to remove it; a `resolvers` section resolves
    /// its address, so `del server` refuses it (a rename stays allowed). One byte per slot, not
    /// two `bool` arrays, so the flags do not grow `Proxy`'s inline size (`struct_sizes.rs`).
    /// Empty when no server has either flag.
    server_name_flags: Box<[u8]>,
    /// Each server's `maxconn`, shared by every worker: `set maxconn server` changes it in
    /// place (T177).
    server_maxconn: crate::srv_rt::ServerMaxconns,
    /// Per server `(wretr, wredis, econ)`: retries on it, redispatches away from it, and
    /// streams whose last connect attempt, out of retries, failed on it.
    server_retr: Arc<std::sync::Mutex<RetrCounts>>,
    /// Each server's check parameters, `None` for a server without `check`. The servers
    /// whose parameters are the same share one (T304: 60,000 servers of a backend hold one).
    server_check_configs: Vec<Option<Arc<ServerCheckConfig>>>,
    /// Each server's TLS (`server ... ssl`), `None` for a plaintext one (T113).
    server_tls: Vec<Option<Arc<crate::srv_tls::ServerTls>>>,
    /// Each server's health-check TLS (`check-ssl`, or `ssl` inherited), `None` for
    /// plaintext checks.
    server_check_tls: Vec<Option<Arc<crate::srv_tls::CheckTls>>>,
}

/// One server's `set-proxy-v2-tlv-fmt(<id>) [<fmt>]` TLVs (`srv->pp_tlvs`), compiled once
/// and in the order `make_proxy_line_v2` sends them: the `default-server` ones first, then
/// the server's own. `fmt` is `None` for a TLV without a format, whose value is empty.
#[derive(Debug, Clone)]
pub struct SrvPpv2Tlvs {
    pub tlvs: Vec<(u8, Option<Arc<crate::logfmt::LogFormat>>)>,
}

/// The per-server arrays of a [`ProxyIdInfo`], private to this module for the same reason.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Default)]
pub struct ServerIdArrays {
    /// Each server's numeric id in this proxy (`puid`), what `srv_id`, the `sid` column of
    /// `show stat` and `show servers state` report, and where the server's points on a
    /// consistent-hash ring come from. Empty when no server has an `id` of its own: they are
    /// then 1, 2, 3...; read it with [`Proxy::server_puid`].
    server_puids: Vec<u32>,
    /// Whether each server has an `id` of its own (`srv_f_forced_id`); empty when none does
    /// (see [`Proxy::server_forced_id`]).
    server_forced_ids: Vec<bool>,
    /// What `show servers state` reports as each server's `srv_check_health` while no check
    /// runs on it; empty when that is 0 for all (see [`Proxy::server_init_health`]).
    server_init_health: Vec<u32>,
    /// Which servers the configuration disabled (`SRV_ADMF_CMAINT`, 4 in `show servers state`
    /// whatever the CLI does afterwards); empty when none (see [`Proxy::server_cmaint`]).
    server_cmaint: Vec<bool>,
    /// Which servers have no address (`init-addr none` after a name did not resolve, or a
    /// resolver took it: `SRV_ADMF_RMAINT`, 32 in `show servers state`, `MAINT
    /// (resolution)`), and the operator's admin state kept under it (`SRV_ADMF_FMAINT`,
    /// `SRV_ADMF_FDRAIN`): 0 none, else 1 + that [`ServerStatus`]; empty when no server's
    /// address is a name (see [`Proxy::server_rmaint`], [`Proxy::server_rmaint_kept`]).
    server_rmaint: Arc<Vec<std::sync::atomic::AtomicU8>>,
    /// The name each server's address was written as (`srv_fqdn`); empty when no server's
    /// was (see [`Proxy::server_fqdn`]).
    server_fqdns: Vec<Option<Box<str>>>,
    /// Which servers' `srv_fqdn` the server-state file had changed from the CLI
    /// (`SRV_ADMF_FQDN_CHANGED`, 64 in `srv_admin_state`; T490); empty when none.
    server_fqdn_changed: Vec<bool>,
    /// The slots of the servers whose name is an SRV record (`srvrecord`, T487): the target
    /// each took and `SRV_ADMF_FQDN_CHANGED`; `None` when no server's name is one.
    server_srv: Option<Arc<crate::resolvers::SrvSlots>>,
    /// Each server's `port` (`check port`, `default-server port`): `srv_agent_port`, and
    /// `srv_check_port` of a server with no check; empty when no server has one.
    server_check_ports: Vec<u16>,
    /// `pool-max-conn`, `pool-low-conn` and `pool-purge-delay` per server; empty when every
    /// server has the defaults (read it with [`ProxyIdInfo::server_pool`]). Read when a
    /// server connection is released, so it lives here, off `Proxy`'s inline size
    /// (`struct_sizes.rs`).
    server_pool: Vec<SrvPoolCfg>,
    /// What the server-state file gave each server (T490, [`crate::server_state`]): read
    /// by `init_checks` and by the `lastchg` columns; empty when no file was applied.
    server_restored: Vec<Option<crate::server_state::Restored>>,
    /// Each server's `set-proxy-v2-tlv-fmt(<id>) [<fmt>]` TLVs, compiled; a `None` slot
    /// has none and the outer `None` means no server of the proxy does, so a proxy without
    /// the keyword pays nothing to look (read it with [`ServerSet::pp_tlv_fmts_at`]).
    server_pp_tlv_fmts: Option<Arc<Vec<Option<Arc<SrvPpv2Tlvs>>>>>,
}

impl Default for ServerArrays {
    fn default() -> Self {
        Self {
            cells: Arc::default(),
            servers: Vec::new().into(),
            server_ids: crate::srv_rt::ServerNames::default(),
            server_cookies: Vec::new(),
            server_track: None,
            server_weights: std::iter::empty().collect(),
            server_send_proxy: Vec::new(),
            server_tfo: Vec::new(),
            server_send_proxy_v2: Vec::new(),
            server_pp_unique_id: Vec::new(),
            server_backups: Vec::new(),
            server_name_flags: Box::default(),
            server_maxconn: std::iter::empty().collect(),
            server_retr: Arc::default(),
            server_check_configs: Vec::new(),
            server_tls: Vec::new(),
            server_check_tls: Vec::new(),
        }
    }
}

impl ServerArrays {
    /// The arrays of a section's `servers`.
    pub(crate) fn build(servers: &[alcyon_config::Server], extras: &alcyon_config::ast::ServerExtras, check_timeout: Option<Duration>) -> Self {
        let status = |i: usize, s: &alcyon_config::Server| AtomicU8::new(initial_status(s, extras.unresolved(i)));
        let base = servers.iter().enumerate().map(|(i, s)| Cell { status: status(i, s), ..Cell::default() }).collect();
        Self {
            cells: Arc::new(ServerCells { base }),
            servers: servers.iter().map(|s| s.addr).collect(),
            server_ids: servers.iter().map(|s| s.id.clone()).collect(),
            server_cookies: servers.iter().map(|s| s.cookie.as_deref().map(Box::from)).collect(),
            server_track: None,
            server_weights: servers.iter().map(|s| s.weight.unwrap_or(1)).collect(),
            server_send_proxy: servers.iter().map(|s| s.send_proxy).collect(),
            server_tfo: servers.iter().map(|s| s.tfo).collect(),
            server_send_proxy_v2: servers.iter().map(|s| s.send_proxy_v2).collect(),
            server_pp_unique_id: servers.iter().map(|s| s.proxy_v2_unique_id).collect(),
            server_backups: servers.iter().map(|s| s.backup).collect(),
            server_name_flags: Box::default(),
            server_maxconn: servers.iter().map(|s| s.maxconn).collect(),
            server_retr: Arc::default(),
            server_check_configs: server_check_configs(servers, check_timeout),
            server_tls: Vec::new(),
            server_check_tls: Vec::new(),
        }
    }
}

impl ServerIdArrays {
    /// The arrays of a section's `servers`.
    pub(crate) fn build(servers: &[alcyon_config::Server], extras: &alcyon_config::ast::ServerExtras, mode_http: bool) -> Self {
        Self {
            server_puids: server_puids(servers.len(), extras),
            server_forced_ids: server_forced_ids(servers.len(), extras),
            server_init_health: server_init_health(servers.len(), extras),
            server_cmaint: server_cmaint(servers),
            server_rmaint: server_rmaint(servers, extras),
            server_fqdns: server_fqdns(servers.len(), extras),
            server_fqdn_changed: server_fqdn_changed(servers.len(), extras),
            server_srv: crate::resolvers::SrvSlots::new(servers.len(), extras),
            server_check_ports: server_check_ports(servers),
            server_pool: pool_cfgs(servers, mode_http),
            server_restored: Vec::new(),
            server_pp_tlv_fmts: pp_tlv_fmts(servers.len(), extras),
        }
    }
}

/// The `set-proxy-v2-tlv-fmt` formats of [`ServerIdArrays`], compiled once; `None` when no
/// server of the proxy has one.
fn pp_tlv_fmts(count: usize, extras: &alcyon_config::ast::ServerExtras) -> Option<Arc<Vec<Option<Arc<SrvPpv2Tlvs>>>>> {
    if extras.ppv2_tlvs.is_empty() {
        return None;
    }
    let mut slots = vec![None; count];
    for (idx, tlvs) in &extras.ppv2_tlvs {
        // A format the configuration passed: `validate_config` refused the proxy otherwise,
        // as `HAProxy` does at load.
        let compiled: Vec<(u8, Option<Arc<crate::logfmt::LogFormat>>)> = tlvs
            .iter()
            .map(|t| {
                let fmt = (!t.fmt.is_empty())
                    .then(|| crate::logfmt::LogFormat::compile_rule(&t.fmt, &crate::engine::sample_registry(), false).ok())
                    .flatten()
                    .map(Arc::new);
                (t.id, fmt)
            })
            .collect();
        let idx = *idx as usize;
        if idx < count {
            slots[idx] = Some(Arc::new(SrvPpv2Tlvs { tlvs: compiled }));
        }
    }
    Some(Arc::new(slots))
}

/// The idle connection settings of each server of a proxy, and its `proto h2` in `mode http`
/// (`mode_http`); empty when all are the defaults.
fn pool_cfgs(servers: &[alcyon_config::Server], mode_http: bool) -> Vec<SrvPoolCfg> {
    let cfg = |s: &alcyon_config::Server| {
        let p = s.pool.as_deref().copied().unwrap_or_default();
        SrvPoolCfg { max_conn: p.max_conn, low_conn: p.low_conn, purge_delay_ms: p.purge_delay, h2: mode_http && s.proto_h2, max_reuse: p.max_reuse }
    };
    if servers.iter().all(|s| cfg(s) == SrvPoolCfg::DEFAULT) {
        Vec::new()
    } else {
        servers.iter().map(cfg).collect()
    }
}

#[allow(clippy::too_many_lines)] // a field-by-field mirror of the section
/// The state a server starts in: `disabled` is maintenance, which the CLI's `enable
/// server` ends.
fn initial_status(s: &alcyon_config::Server, unresolved: bool) -> u8 {
    // A server whose name did not resolve (`init-addr none`) has no address to send to.
    if s.disabled || unresolved { ServerStatus::Maint as u8 } else { ServerStatus::Up as u8 }
}

/// The ids of the servers for [`Proxy::server_puids`]: empty when none asked for one.
fn server_puids(count: usize, extras: &alcyon_config::ast::ServerExtras) -> Vec<u32> {
    if extras.puid.is_empty() { Vec::new() } else { alcyon_config::ast::server_puids(count, &extras.puid) }
}

/// The values for [`Proxy::server_init_health`]: empty when all are 0.
fn server_init_health(count: usize, extras: &alcyon_config::ast::ServerExtras) -> Vec<u32> {
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
fn server_cmaint(servers: &[alcyon_config::Server]) -> Vec<bool> {
    if servers.iter().any(|s| s.disabled) { servers.iter().map(|s| s.disabled).collect() } else { Vec::new() }
}

/// The flags for [`Proxy::server_rmaint`]: one per server when an address was written as a
/// name (a resolver may take it away at run time), else empty. A `disabled` server keeps
/// `Maint` under it.
fn server_rmaint(servers: &[alcyon_config::Server], extras: &alcyon_config::ast::ServerExtras) -> Arc<Vec<std::sync::atomic::AtomicU8>> {
    if extras.names.is_empty() {
        Arc::default()
    } else {
        let kept = |i: usize| if servers.get(i).is_some_and(|s| s.disabled) { ServerStatus::Maint } else { ServerStatus::Up };
        Arc::new((0..servers.len()).map(|i| std::sync::atomic::AtomicU8::new(if extras.unresolved(i) { kept(i) as u8 + 1 } else { 0 })).collect())
    }
}

/// The names for [`Proxy::server_fqdn`]: empty when no address was written as one.
/// An SRV record's name is no `srv_fqdn`: the slot's target is (see [`Proxy::server_srv_fqdn`]).
fn server_fqdns(count: usize, extras: &alcyon_config::ast::ServerExtras) -> Vec<Option<Box<str>>> {
    if extras.names.is_empty() { Vec::new() } else { (0..count).map(|i| extras.fqdn(i).filter(|f| !f.starts_with('_')).map(Box::from)).collect() }
}

/// [`ProxyIdInfo::server_fqdn_changed`].
fn server_fqdn_changed(count: usize, extras: &alcyon_config::ast::ServerExtras) -> Vec<bool> {
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
fn server_check_ports(servers: &[alcyon_config::ast::Server]) -> Vec<u16> {
    if servers.iter().all(|s| s.check_port.is_none()) {
        return Vec::new();
    }
    servers.iter().map(|s| s.check_port.unwrap_or(0)).collect()
}

/// The flags for [`Proxy::server_forced_ids`]: empty when none asked for an id.
fn server_forced_ids(count: usize, extras: &alcyon_config::ast::ServerExtras) -> Vec<bool> {
    let mut forced = Vec::new();
    for &(i, _) in &extras.puid {
        forced.resize(count, false);
        if let Some(slot) = forced.get_mut(i as usize) {
            *slot = true;
        }
    }
    forced
}

/// The check parameters of each server of a section (`inter`, `fastinter`, `downinter`,
/// `rise`, `fall`, and `timeout check` or else `inter`): one shared copy for each run of
/// servers that have the same, which is every server of a backend whose `server` lines
/// differ only by name and address.
fn server_check_configs(servers: &[alcyon_config::ast::Server], check_timeout: Option<Duration>) -> Vec<Option<Arc<ServerCheckConfig>>> {
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

/// The servers of a proxy.
#[derive(Clone, Copy)]
pub struct ServerSet<'a>(&'a Proxy);

/// One server of a [`ServerSet`]. Only the set makes one.
#[derive(Clone, Copy)]
pub struct Srv<'a> {
    px: &'a Proxy,
    i: usize,
}

impl Proxy {
    /// `srv_check_health` of the server at `idx` while no check runs on it.
    #[must_use]
    pub fn server_init_health(&self, idx: usize) -> u32 {
        self.ids.srv.server_init_health.get(idx).copied().unwrap_or(0)
    }

    /// The numeric id of the server at `idx` (`puid`).
    #[must_use]
    pub fn server_puid(&self, idx: usize) -> u32 {
        self.ids.srv.server_puids.get(idx).copied().unwrap_or_else(|| u32::try_from(idx + 1).unwrap_or(u32::MAX))
    }

    /// Whether the configuration disabled the server at `idx` (`SRV_ADMF_CMAINT`).
    #[must_use]
    pub fn server_cmaint(&self, idx: usize) -> bool {
        self.ids.srv.server_cmaint.get(idx).copied().unwrap_or(false)
    }

    /// Whether the server at `idx` has no address (`SRV_ADMF_RMAINT`): it stays in
    /// maintenance whatever the CLI asks, until its resolver gives it one (`crate::resolvers`).
    #[must_use]
    pub fn server_rmaint(&self, idx: usize) -> bool {
        self.ids.srv.server_rmaint.get(idx).is_some_and(|f| f.load(Ordering::Relaxed) != 0)
    }

    /// The admin state the operator (or `disabled`) gave the server at `idx` while it is in
    /// `SRV_ADMF_RMAINT`: `Maint`, `Drain` or `Up`, the one it takes back when its name
    /// resolves again. `Up` when it is not in `RMAINT`.
    #[must_use]
    pub fn server_rmaint_kept(&self, idx: usize) -> ServerStatus {
        match self.ids.srv.server_rmaint.get(idx).map_or(0, |f| f.load(Ordering::Relaxed)) {
            0 => ServerStatus::Up,
            v => ServerStatus::from(v - 1),
        }
    }

    /// Puts the server at `idx` in `SRV_ADMF_RMAINT`, keeping the admin state `kept`, or takes
    /// it out with `None` (a server whose address is a name: the others have no flag).
    pub fn set_server_rmaint(&self, idx: usize, kept: Option<ServerStatus>) {
        if let Some(f) = self.ids.srv.server_rmaint.get(idx) {
            f.store(kept.map_or(0, |k| k as u8 + 1), Ordering::Relaxed);
        }
    }

    /// The name the address of the server at `idx` was written as, if it was one.
    #[must_use]
    pub fn server_fqdn(&self, idx: usize) -> Option<&str> {
        self.ids.srv.server_fqdns.get(idx).and_then(Option::as_deref)
    }

    /// Whether the server-state file kept `SRV_ADMF_FQDN_CHANGED` for the server at `idx`.
    #[must_use]
    pub fn server_fqdn_changed(&self, idx: usize) -> bool {
        self.ids.srv.server_fqdn_changed.get(idx).copied().unwrap_or(false)
            || self.ids.srv.server_srv.as_ref().is_some_and(|v| v.changed.get(idx).is_some_and(|c| c.load(Ordering::Relaxed)))
    }

    /// The SRV record the server at `idx` is a slot of (`srvrecord`), if any.
    #[must_use]
    pub fn server_srv_record(&self, idx: usize) -> Option<&str> {
        self.ids.srv.server_srv.as_ref().and_then(|v| v.record.get(idx)).and_then(Option::as_deref)
    }

    /// The target the SRV slot at `idx` took (`srv->hostname`), if it took one.
    #[must_use]
    pub fn server_srv_fqdn(&self, idx: usize) -> Option<Box<str>> {
        self.ids.srv.server_srv.as_ref().and_then(|v| v.fqdn(idx))
    }

    /// Sets (or clears) the target of the SRV slot at `idx`; setting one raises
    /// `SRV_ADMF_FQDN_CHANGED`. A server that is no slot has no target to set.
    pub fn set_server_srv_fqdn(&self, idx: usize, v: Option<&str>) {
        if let Some(slots) = &self.ids.srv.server_srv {
            slots.set_fqdn(idx, v);
        }
    }

    /// The `resolvers` section the server at `idx` names, if any (`srv->resolvers`).
    #[must_use]
    pub fn server_resolvers(&self, idx: usize) -> Option<&str> {
        self.ids.srv.server_srv.as_ref().and_then(|v| v.section.get(idx)).and_then(Option::as_deref)
    }

    /// The name the server at `idx` resolves now (`srv->hostname`): the one `set server fqdn`
    /// or an SRV record gave it, else the configuration's.
    #[must_use]
    pub fn server_hostname(&self, idx: usize) -> Option<Box<str>> {
        self.server_srv_fqdn(idx).or_else(|| self.server_fqdn(idx).map(Box::from))
    }

    /// `set server fqdn`: the name `srv_fqdn` shows from now on (no flag yet).
    pub fn set_server_hostname(&self, idx: usize, v: &str) {
        if let Some(slots) = &self.ids.srv.server_srv {
            slots.set_name(idx, Some(v));
        }
    }

    /// Raises `SRV_ADMF_FQDN_CHANGED` for the server at `idx`.
    pub fn mark_server_fqdn_changed(&self, idx: usize) {
        if let Some(c) = self.ids.srv.server_srv.as_ref().and_then(|v| v.changed.get(idx)) {
            c.store(true, Ordering::Relaxed);
        }
    }

    /// The `port` keyword of the server at `idx`, 0 without one (`srv_agent_port`).
    #[must_use]
    pub fn server_check_port(&self, idx: usize) -> u16 {
        self.ids.srv.server_check_ports.get(idx).copied().unwrap_or(0)
    }

    /// Whether the server at `idx` has an `id` of its own (`SRV_F_FORCED_ID`).
    #[must_use]
    pub fn server_forced_id(&self, idx: usize) -> bool {
        self.ids.srv.server_forced_ids.get(idx).copied().unwrap_or(false)
    }

    /// This proxy's servers.
    #[must_use]
    pub fn srv_set(&self) -> ServerSet<'_> {
        ServerSet(self)
    }

    /// Server `idx`'s configured weight, whatever it is now.
    #[must_use]
    pub fn initial_weight(&self, idx: usize) -> u32 {
        self.srv_set().at(idx).and_then(|s| s.initial_weight()).unwrap_or(1)
    }

    /// Changes server `idx`'s current weight, keeping the configured one for
    /// [`Self::initial_weight`]. The weights are shared: every worker's next balancing
    /// decision sees it.
    pub fn set_weight(&self, idx: usize, weight: u32) {
        if let Some(s) = self.srv_set().at(idx) {
            s.set_weight(weight);
        }
        self.fwrr.changed();
        self.chash.changed();
    }

    /// The places where the load writes into the set (the proxy is not shared yet).
    pub fn srv_set_mut(&mut self) -> ServerSetMut<'_> {
        ServerSetMut(self)
    }
}

impl<'a> ServerSet<'a> {
    /// Number of slots, empty ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.srv.server_ids.len()
    }

    /// No slot at all (a frontend, or a backend without servers).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.srv.servers.is_empty()
    }

    /// The cell of slot `i`, whether or not a server is in it: the hot paths hold a slot
    /// number across the life of a stream, and book it by number.
    #[inline]
    fn cell(self, i: usize) -> Option<&'a Cell> {
        self.0.srv.cells.base.get(i)
    }

    /// The cell holding slot `i`'s status.
    #[inline]
    #[must_use]
    pub fn status_cell(&self, i: usize) -> Option<&'a AtomicU8> {
        self.cell(i).map(|c| &c.status)
    }

    /// Slot `i`'s status as stored.
    #[inline]
    #[must_use]
    pub fn status_at(&self, i: usize) -> Option<u8> {
        self.cell(i).map(|c| c.status.load(Ordering::Relaxed))
    }

    /// Streams on slot `i` now, 0 for a slot that is not one.
    #[inline]
    #[must_use]
    pub fn actconn_at(&self, i: usize) -> u32 {
        self.cell(i).map_or(0, |c| c.actconn.load(Ordering::Relaxed))
    }

    /// Slot `i`'s stream count, to take a slot in it or give one back.
    #[inline]
    #[must_use]
    pub fn actconn_cell(&self, i: usize) -> Option<&'a AtomicU32> {
        self.cell(i).map(|c| &c.actconn)
    }

    /// Books one more stream on slot `i`.
    #[inline]
    pub fn actconn_inc(&self, i: usize) {
        if let Some(a) = self.actconn_cell(i) {
            a.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Books one stream less on slot `i`.
    #[inline]
    pub fn actconn_dec(&self, i: usize) {
        if let Some(a) = self.actconn_cell(i) {
            a.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Slot `i`'s current weight.
    #[inline]
    #[must_use]
    pub fn weight_at(&self, i: usize) -> Option<u32> {
        self.0.srv.server_weights.get(i)
    }

    /// Slot `i`'s `maxconn`, `None` when it has none.
    #[inline]
    #[must_use]
    pub fn maxconn_at(&self, i: usize) -> Option<u32> {
        self.0.srv.server_maxconn.get(i)
    }

    /// Whether slot `i` is a `backup` server.
    #[inline]
    #[must_use]
    pub fn backup_at(&self, i: usize) -> bool {
        self.0.srv.server_backups.get(i).copied().unwrap_or(false)
    }

    /// The name in slot `i`, whether or not a server is in it (the log line and the messages
    /// name the server a stream holds by its slot).
    #[inline]
    #[must_use]
    pub fn name_at(&self, i: usize) -> Option<&'static str> {
        self.0.srv.server_ids.get(i)
    }

    /// Slot `i`'s address (`Proxy::servers`), which a stream books by number; panics when
    /// there is no such slot, as indexing does.
    #[inline]
    #[must_use]
    pub fn addr_at(&self, i: usize) -> SocketAddr {
        self.0.srv.servers.at(i)
    }

    /// Changes slot `i`'s address in place for every worker; false when there is no such slot.
    #[must_use]
    pub fn set_addr_at(&self, i: usize, a: SocketAddr) -> bool {
        self.0.srv.servers.set(i, a)
    }

    /// The address of every slot, in order.
    pub fn addrs(&self) -> impl Iterator<Item = SocketAddr> + 'a {
        self.0.srv.servers.iter()
    }

    /// Slot `i`'s address, `None` when there is no such slot.
    #[inline]
    #[must_use]
    pub fn addr_get(&self, i: usize) -> Option<SocketAddr> {
        self.0.srv.servers.get(i)
    }

    /// The first slot whose address is `a` and that is not gone. A slot is gone when its
    /// state is `Retiring`: that is set when a `del server` closes the door and stays set
    /// under the emptied name once the delete commits, so one load of the state byte
    /// rejects both an in-flight and a committed delete (the request is load-balanced, not
    /// assigned to the slot).
    #[must_use]
    pub fn slot_of_addr(&self, a: SocketAddr) -> Option<usize> {
        let mut i = 0;
        while let Some(s) = self.0.srv.servers.get(i) {
            if s == a && self.status_at(i) != Some(crate::check::RETIRING) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Slot `i`'s TLS, `None` for a plaintext server.
    #[must_use]
    pub fn tls_at(&self, i: usize) -> Option<&'a Arc<crate::srv_tls::ServerTls>> {
        self.0.srv.server_tls.get(i).and_then(Option::as_ref)
    }

    /// Slot `i`'s health-check TLS.
    #[must_use]
    pub fn check_tls_at(&self, i: usize) -> Option<&'a Arc<crate::srv_tls::CheckTls>> {
        self.0.srv.server_check_tls.get(i).and_then(Option::as_ref)
    }

    /// Slot `i`'s persistence cookie value.
    #[inline]
    #[must_use]
    pub fn cookie_at(&self, i: usize) -> Option<&'a str> {
        self.0.srv.server_cookies.get(i).and_then(Option::as_deref)
    }

    /// Whether slot `i` sends a PROXY protocol v1 header.
    #[must_use]
    pub fn send_proxy_at(&self, i: usize) -> bool {
        self.0.srv.server_send_proxy.get(i).copied().unwrap_or(false)
    }

    /// Whether slot `i` sends a PROXY protocol v2 header.
    #[must_use]
    pub fn send_proxy_v2_at(&self, i: usize) -> bool {
        self.0.srv.server_send_proxy_v2.get(i).copied().unwrap_or(false)
    }

    /// Whether slot `i`'s PROXY v2 header carries the unique id.
    #[must_use]
    pub fn pp_unique_id_at(&self, i: usize) -> bool {
        self.0.srv.server_pp_unique_id.get(i).copied().unwrap_or(false)
    }

    /// Slot `i`'s `set-proxy-v2-tlv-fmt(<id>) [<fmt>]` TLVs, in send order, `None` when
    /// the server has none.
    #[must_use]
    pub fn pp_tlv_fmts_at(&self, i: usize) -> Option<&'a SrvPpv2Tlvs> {
        self.0.ids.srv.server_pp_tlv_fmts.as_ref().and_then(|slots| slots.get(i)).and_then(Option::as_ref).map(Arc::as_ref)
    }

    /// Slot `i`'s session-rate counter.
    #[inline]
    #[must_use]
    pub fn sess_rate_at(&self, i: usize) -> Option<&'a RateCtr> {
        self.cell(i).map(|c| &c.rate)
    }

    /// Adds `(wretr, wredis, econ)` to slot `i`'s counts.
    pub fn bump_retr(&self, i: usize, d: (u64, u64, u64)) {
        let mut m = self.0.srv.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let c = m.entry(i).or_default();
        c.0 += d.0;
        c.1 += d.1;
        c.2 += d.2;
    }

    /// Forgets every slot's retry counts (`clear counters all`).
    pub fn retr_clear(&self) {
        self.0.srv.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    }

    /// Forgets slot `i`'s retry counts.
    pub fn retr_remove(&self, i: usize) {
        self.0.srv.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&i);
    }

    /// Whether a panic left the retry counts half-changed.
    #[must_use]
    pub fn retr_poisoned(&self) -> bool {
        self.0.srv.server_retr.is_poisoned()
    }

    /// Changes slot `i`'s `maxconn`; false when there is no such slot.
    #[must_use]
    pub fn set_maxconn(&self, i: usize, v: Option<u32>) -> bool {
        self.0.srv.server_maxconn.set(i, v)
    }

    /// How many slots have a health check.
    #[must_use]
    pub fn checked_count(&self) -> usize {
        self.0.srv.server_check_configs.iter().flatten().count()
    }

    /// Whether the server at `addr` has `tfo`.
    #[must_use]
    pub fn tfo_of(&self, addr: SocketAddr) -> bool {
        self.slot_of_addr(addr).and_then(|i| self.0.srv.server_tfo.get(i).copied()).unwrap_or(false)
    }

    /// The server in slot `i`; `None` when there is no such slot or it is empty.
    #[must_use]
    pub fn at(&self, i: usize) -> Option<Srv<'a>> {
        self.0.srv.server_ids.get(i).filter(|n| !n.is_empty()).map(|_| Srv { px: self.0, i })
    }

    /// The server called `name`.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Srv<'a>> {
        self.live().find(|s| s.name() == name)
    }

    /// The server whose `puid` is `id`.
    #[must_use]
    pub fn by_puid(&self, id: u32) -> Option<Srv<'a>> {
        self.live().find(|s| s.puid() == id)
    }

    /// The servers that exist, in the order they are listed.
    pub fn live(&self) -> impl Iterator<Item = Srv<'a>> + 'a {
        let px = self.0;
        (0..px.srv.server_ids.len()).filter_map(move |i| px.srv_set().at(i))
    }

    /// Whether any server is up (`Up` itself: a draining server is not).
    #[must_use]
    pub fn any_up(&self) -> bool {
        self.0.srv.cells.base.iter().any(|c| c.status.load(Ordering::Relaxed) == ServerStatus::Up as u8)
    }

    /// `(slot, status)` of every status cell, for the page that totals them.
    pub fn raw_statuses(&self) -> impl Iterator<Item = u8> + 'a {
        self.0.srv.cells.base.iter().map(|c| c.status.load(Ordering::Relaxed))
    }

    /// Whether slot `i` has a health-check configuration.
    #[must_use]
    pub fn checked(&self, i: usize) -> bool {
        self.0.srv.server_check_configs.get(i).is_some_and(Option::is_some)
    }

    /// How many slots have a check configuration vector (the length views are sized to).
    #[must_use]
    pub fn check_slots(&self) -> usize {
        self.0.srv.server_check_configs.len()
    }

    /// Slot `i`'s check configuration.
    #[must_use]
    pub fn check_config(&self, i: usize) -> Option<&'a Arc<ServerCheckConfig>> {
        self.0.srv.server_check_configs.get(i).and_then(Option::as_ref)
    }

    /// Slot `i`'s tracking, `None` when it tracks nothing.
    #[must_use]
    pub fn track(&self, i: usize) -> Option<&'a Track> {
        self.0.srv.server_track.as_ref()?.get(i)?.as_ref()
    }

    /// What each slot tracks, `None` when no server tracks anything.
    #[must_use]
    pub fn tracks(&self) -> Option<&'a [Option<Track>]> {
        self.0.srv.server_track.as_ref().map(|t| t.as_slice())
    }

    /// The `(wretr, wredis, econ)` of slot `i`.
    #[must_use]
    pub fn retr(&self, i: usize) -> (u64, u64, u64) {
        self.0.srv.server_retr.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&i).copied().unwrap_or_default()
    }
}

impl<'a> Srv<'a> {
    /// The slot, which streams, checks and messages hold.
    #[must_use]
    pub fn index(&self) -> usize {
        self.i
    }

    /// Its name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.px.srv.server_ids.get(self.i).unwrap_or("")
    }

    /// Renames it (the CLI; allocates).
    pub fn rename(&self, new: &str) {
        self.px.srv.server_ids.set(self.i, new);
    }

    /// Its numeric id in the backend.
    #[must_use]
    pub fn puid(&self) -> u32 {
        self.px.server_puid(self.i)
    }

    /// Its address; `None` when the address array has no such slot.
    #[must_use]
    pub fn addr(&self) -> Option<SocketAddr> {
        self.px.srv.servers.get(self.i)
    }

    /// Changes its address, in place for every worker.
    pub fn set_addr(&self, a: SocketAddr) {
        self.px.srv.servers.set(self.i, a);
    }

    /// The cell holding its status.
    #[must_use]
    pub fn status_cell(&self) -> Option<&'a AtomicU8> {
        self.px.srv_set().status_cell(self.i)
    }

    /// Its status as stored.
    #[must_use]
    pub fn raw_status(&self) -> Option<u8> {
        self.status_cell().map(|a| a.load(Ordering::Relaxed))
    }

    /// Stores its status and returns the one it had.
    #[must_use]
    pub fn swap_status(&self, v: u8) -> Option<u8> {
        self.status_cell().map(|a| a.swap(v, Ordering::Relaxed))
    }

    /// Stores its status.
    pub fn store_status(&self, v: u8) {
        if let Some(a) = self.status_cell() {
            a.store(v, Ordering::Relaxed);
        }
    }

    /// Stores `v` unless the current status is `RETIRING` (`del server` in flight).
    pub fn store_status_unless_retiring(&self, v: u8) -> bool {
        let Some(a) = self.status_cell() else { return false };
        a.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
            (cur != crate::check::RETIRING).then_some(v)
        })
        .is_ok()
    }

    /// Its current weight.
    #[must_use]
    pub fn weight(&self) -> Option<u32> {
        self.px.srv.server_weights.get(self.i)
    }

    /// Its configured weight.
    #[must_use]
    pub fn initial_weight(&self) -> Option<u32> {
        self.px.srv.server_weights.initial(self.i)
    }

    /// Sets its current weight, keeping the configured one.
    pub fn set_weight(&self, w: u32) {
        self.px.srv.server_weights.set(self.i, w);
    }

    /// Its `maxconn`, `None` when it has none.
    #[must_use]
    pub fn maxconn(&self) -> Option<u32> {
        self.px.srv.server_maxconn.get(self.i)
    }

    /// Streams on it now.
    #[must_use]
    pub fn actconn(&self) -> u32 {
        self.px.srv_set().actconn_at(self.i)
    }

    /// Its session-rate counter.
    #[must_use]
    pub fn sess_rate(&self) -> Option<&'a RateCtr> {
        self.px.srv.cells.base.get(self.i).map(|c| &c.rate)
    }

    /// Whether it is a `backup` server.
    #[must_use]
    pub fn backup(&self) -> bool {
        self.px.srv.server_backups.get(self.i).copied().unwrap_or(false)
    }

    /// Whether it has TLS (`ssl`).
    #[must_use]
    pub fn has_tls(&self) -> bool {
        self.px.srv.server_tls.get(self.i).is_some_and(Option::is_some)
    }

    /// Whether a sample fetch, a `use-server` target, or another server's `track` names it
    /// ([`NAME_REFD`]), so it cannot be renamed or removed.
    #[must_use]
    pub fn name_refd(&self) -> bool {
        self.px.srv.server_name_flags.get(self.i).copied().unwrap_or(0) & NAME_REFD != 0
    }

    /// Whether it has a `resolvers` section ([`NON_PURGEABLE`]), so `del server` cannot remove it
    /// at runtime (a rename is still allowed).
    #[must_use]
    pub fn non_purgeable(&self) -> bool {
        self.px.srv.server_name_flags.get(self.i).copied().unwrap_or(0) & NON_PURGEABLE != 0
    }

    /// Its check configuration.
    #[must_use]
    pub fn check_config(&self) -> Option<&'a Arc<ServerCheckConfig>> {
        self.px.srv_set().check_config(self.i)
    }

    /// Whether it has no address (`SRV_ADMF_RMAINT`).
    #[must_use]
    pub fn rmaint(&self) -> bool {
        self.px.server_rmaint(self.i)
    }
}

/// Sets one bit of a slot's load-only name flags, allocating the per-slot byte array on the
/// first mark.
fn set_name_flag(flags: &mut Box<[u8]>, n: usize, i: usize, bit: u8) {
    if flags.is_empty() {
        *flags = vec![0; n].into_boxed_slice();
    }
    flags[i] |= bit;
}

/// What the load writes into a proxy's server arrays while it still owns the proxy.
pub struct ServerSetMut<'a>(&'a mut Proxy);

impl ServerSetMut<'_> {
    /// Builds the TLS of every server of `proxy` from its section (`servers`). Done once per
    /// proxy at load, as `ssl_sock_prepare_srv_ctx` is, so a missing `ca-file` or `crt` is
    /// a load error and `alcyon -c` reports it.
    ///
    /// # Errors
    /// The first server whose TLS cannot be set up.
    pub fn attach_tls(&mut self, servers: &[alcyon_config::Server], mode_http: bool, section: &str) -> std::io::Result<()> {
        self.0.srv.server_tls.clear();
        self.0.srv.server_check_tls.clear();
        // A backend with no TLS server anywhere keeps both maps empty; indexing is by
        // `.get(i)`, which reads an empty map as "all plaintext". So 60,000 plaintext
        // servers cost nothing here -- the memory-bound tests stay where they were.
        if !servers.iter().any(|s| s.ssl.as_deref().is_some_and(|x| x.ssl || x.check_uses_tls(s.check_port))) {
            return Ok(());
        }
        self.0.srv.server_tls.resize_with(servers.len(), || None);
        self.0.srv.server_check_tls.resize_with(servers.len(), || None);
        for (i, s) in servers.iter().enumerate() {
            if !s.ssl.as_deref().is_some_and(|x| x.ssl || x.check_uses_tls(s.check_port)) {
                continue;
            }
            let who = format!("'server {}/{}'", section, s.id);
            self.0.srv.server_tls[i] = crate::srv_tls::ServerTls::from_server(s, mode_http, &who)?.map(Arc::new);
            self.0.srv.server_check_tls[i] = crate::srv_tls::CheckTls::from_server(s, &who)?.map(Arc::new);
        }
        Ok(())
    }


    /// Marks slot `i` as named by a sample fetch, a `use-server` target, or a `track`, so it
    /// cannot be renamed or removed.
    pub fn mark_name_refd(&mut self, i: usize) {
        set_name_flag(&mut self.0.srv.server_name_flags, self.0.srv.server_ids.len(), i, NAME_REFD);
    }

    /// Marks slot `i` as addressed by a `resolvers` section, so `del server` refuses it.
    pub fn mark_non_purgeable(&mut self, i: usize) {
        set_name_flag(&mut self.0.srv.server_name_flags, self.0.srv.server_ids.len(), i, NON_PURGEABLE);
    }

    /// Gives each server what it tracks.
    pub fn set_tracks(&mut self, t: Vec<Option<Track>>) {
        self.0.srv.server_track = Some(Arc::new(t));
    }

    /// What `show servers state` prints as slot `i`'s health when it has no check.
    pub fn set_init_health(&mut self, i: usize, health: u32) {
        let n = self.0.srv.servers.len();
        let h = &mut self.0.ids.srv.server_init_health;
        if h.len() < n {
            h.resize(n, 0);
        }
        h[i] = health;
    }

    /// What the server-state file gave slot `i`.
    pub fn set_restored(&mut self, i: usize, r: crate::server_state::Restored) {
        let n = self.0.srv.servers.len();
        let slots = &mut self.0.ids.srv.server_restored;
        if slots.len() < n {
            slots.resize(n, None);
        }
        slots[i] = Some(r);
    }

    /// Points slot `i`'s checks at `port`, when it has a check.
    pub fn set_check_port(&mut self, i: usize, port: u16) {
        if let Some(slot) = self.0.srv.server_check_configs.get_mut(i) {
            if let Some(cfg) = slot.as_deref() {
                *slot = Some(Arc::new(ServerCheckConfig { check_port: Some(port), ..cfg.clone() }));
            }
        }
    }
}

impl ProxyIdInfo {
    /// What the server-state file gave server `i`, if anything.
    #[must_use]
    pub fn restored(&self, i: usize) -> Option<&crate::server_state::Restored> {
        self.srv.server_restored.get(i).and_then(Option::as_ref)
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
        self.srv.server_pool.get(i).copied().unwrap_or(SrvPoolCfg::DEFAULT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies() -> crate::engine::Proxies {
        let c = "defaults\n    mode http\nbackend b\n    server s1 127.0.0.1:1 id 7\n    server s2 127.0.0.1:2 backup\n    server s3 127.0.0.1:3\nfrontend f\n    bind 127.0.0.1:0\n";
        let config = alcyon_config::parse_str(c).expect("config");
        crate::engine::Engine::build_shared_state(&config).expect("proxies")
    }

    fn backend(proxies: &crate::engine::Proxies) -> &Proxy {
        proxies.iter().find(|p| p.name == "b").expect("b")
    }

    #[test]
    fn a_check_port_reaches_the_check_of_a_checked_server_only() {
        let c = "defaults\n    mode http\nbackend b\n    server s1 127.0.0.1:1 check\n    server s2 127.0.0.1:2\nfrontend f\n    bind 127.0.0.1:0\n";
        let config = alcyon_config::parse_str(c).expect("config");
        let mut all = crate::engine::Engine::build_shared_state(&config).expect("proxies").into_vec();
        let p = all.iter_mut().find(|p| p.name == "b").expect("b");
        p.srv_set_mut().set_check_port(0, 9999);
        p.srv_set_mut().set_check_port(1, 9999);
        assert_eq!(p.srv_set().check_config(0).and_then(|c| c.check_port), Some(9999));
        assert!(p.srv_set().check_config(1).is_none());
        p.srv_set_mut().set_check_port(7, 9999);
    }

    #[test]
    fn a_server_without_an_address_keeps_the_admin_state_under_its_maintenance() {
        let c = "defaults\n    mode http\nbackend b\n    server s1 a.test:80 init-addr none\n    server s2 127.0.0.1:2\n";
        let config = alcyon_config::parse_str(c).expect("config");
        let all = crate::engine::Engine::build_shared_state(&config).expect("proxies");
        let p = backend(&all);
        assert!(p.server_rmaint(0));
        assert!(!p.server_rmaint(1));
        assert_eq!(p.server_rmaint_kept(0), ServerStatus::Up);
        p.set_server_rmaint(0, Some(ServerStatus::Drain));
        assert_eq!(p.server_rmaint_kept(0), ServerStatus::Drain);
        p.set_server_rmaint(0, None);
        assert!(!p.server_rmaint(0));
        p.set_server_rmaint(9, Some(ServerStatus::Maint));
        assert_eq!(p.server_rmaint_kept(9), ServerStatus::Up);
    }

    #[test]
    fn a_server_is_found_by_name_by_slot_and_by_id() {
        let all = proxies();
        let p = backend(&all);
        let set = p.srv_set();
        assert_eq!(set.len(), 3);
        assert_eq!(set.find("s2").map(|s| s.index()), Some(1));
        assert!(set.find("nobody").is_none());
        assert_eq!(set.at(2).map(|s| s.name()), Some("s3"));
        assert!(set.at(3).is_none());
        assert_eq!(set.by_puid(7).map(|s| s.name()), Some("s1"));
        assert!(set.by_puid(99).is_none());
        assert!(set.at(1).expect("s2").backup());
        assert!(!set.at(0).expect("s1").backup());
    }

    #[test]
    fn live_skips_an_empty_slot_and_so_do_the_lookups() {
        let all = proxies();
        let p = backend(&all);
        p.srv_set().at(1).expect("s2").rename("");
        let set = p.srv_set();
        assert_eq!(set.len(), 3, "the slot is still there");
        assert_eq!(set.live().map(|s| s.name()).collect::<Vec<_>>(), ["s1", "s3"]);
        assert!(set.at(1).is_none());
        assert!(set.find("").is_none());
        assert_eq!(set.live().map(|s| s.index()).collect::<Vec<_>>(), [0, 2]);
    }

    #[test]
    fn a_rename_and_an_address_are_seen_through_the_set() {
        let all = proxies();
        let p = backend(&all);
        let s = p.srv_set().find("s3").expect("s3");
        s.rename("three");
        assert!(p.srv_set().find("s3").is_none());
        let s = p.srv_set().find("three").expect("three");
        let a: SocketAddr = "10.0.0.1:80".parse().expect("addr");
        s.set_addr(a);
        assert_eq!(p.srv_set().at(2).and_then(|s| s.addr()), Some(a));
        s.set_weight(5);
        assert_eq!((s.weight(), p.initial_weight(2)), (Some(5), 1));
        assert_eq!(s.actconn(), 0);
        assert_eq!(s.maxconn(), None);
    }

    #[test]
    fn a_stream_is_booked_on_a_slot_by_number_and_a_missing_slot_books_nothing() {
        let all = proxies();
        let set = backend(&all).srv_set();
        set.actconn_inc(1);
        set.actconn_inc(1);
        set.actconn_dec(1);
        set.actconn_inc(9);
        set.actconn_dec(9);
        assert_eq!((set.actconn_at(0), set.actconn_at(1), set.actconn_at(9)), (0, 1, 0));
        assert!(set.actconn_cell(9).is_none());
        assert_eq!(set.status_at(0), Some(ServerStatus::Up as u8));
        assert_eq!(set.status_at(9), None);
        assert!(set.sess_rate_at(2).is_some() && set.sess_rate_at(3).is_none());
    }

    #[test]
    fn retry_counts_are_kept_by_slot_until_they_are_cleared() {
        let all = proxies();
        let set = backend(&all).srv_set();
        set.bump_retr(0, (1, 0, 0));
        set.bump_retr(0, (0, 1, 1));
        set.bump_retr(2, (0, 0, 1));
        assert_eq!((set.retr(0), set.retr(2)), ((1, 1, 1), (0, 0, 1)));
        set.retr_remove(0);
        assert_eq!((set.retr(0), set.retr(2)), ((0, 0, 0), (0, 0, 1)));
        set.retr_clear();
        assert_eq!(set.retr(2), (0, 0, 0));
        assert!(!set.retr_poisoned());
    }

    #[test]
    fn addresses_maxconn_and_the_name_marks_are_read_and_written_by_slot() {
        let mut all = proxies().into_vec();
        let p = all.iter_mut().find(|p| p.name == "b").expect("b");
        let a2: SocketAddr = "127.0.0.1:2".parse().expect("addr");
        assert_eq!(p.srv_set().addr_at(1), a2);
        assert_eq!(p.srv_set().addr_get(1), Some(a2));
        assert_eq!(p.srv_set().addr_get(7), None);
        assert_eq!(p.srv_set().slot_of_addr(a2), Some(1));
        assert_eq!(p.srv_set().addrs().count(), 3);
        let b: SocketAddr = "10.0.0.9:9".parse().expect("addr");
        assert!(p.srv_set().set_addr_at(1, b));
        assert!(!p.srv_set().set_addr_at(7, b));
        assert_eq!(p.srv_set().slot_of_addr(b), Some(1));
        assert!(p.srv_set().set_maxconn(0, Some(4)));
        assert_eq!((p.srv_set().maxconn_at(0), p.srv_set().maxconn_at(1)), (Some(4), None));
        assert_eq!(p.srv_set().name_at(2), Some("s3"));
        assert!(!p.srv_set().at(0).expect("s1").name_refd());
        p.srv_set_mut().mark_name_refd(0);
        p.srv_set_mut().mark_name_refd(2);
        assert!(p.srv_set().at(0).expect("s1").name_refd());
        assert!(!p.srv_set().at(1).expect("s2").name_refd());
        assert!(p.srv_set().at(2).expect("s3").name_refd());
        assert_eq!(p.srv_set().checked_count(), 0);
        assert!(!p.srv_set().tfo_of(a2));
        let s0 = p.srv_set().at(0).expect("s1");
        s0.store_status(crate::check::RETIRING);
        assert!(!s0.store_status_unless_retiring(crate::check::ServerStatus::Up as u8));
        s0.store_status(crate::check::ServerStatus::Maint as u8);
        assert!(s0.store_status_unless_retiring(crate::check::ServerStatus::Up as u8));
    }
}
