// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/backend.c (smp_fetch_nbsrv, smp_fetch_srv_is_up,
// smp_fetch_be_conn_free, smp_fetch_srv_conn_free, sample_conv_*), include/haproxy/backend.h
// (be_usable_srv), src/sample.c (smp_resolve_args) and src/stick_table.c
// (sample_conv_in_table). Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors.
// See LICENSE.

//! The proxies' live state, as the sample fetches read it, and the load-time resolution of
//! the backend, server and table arguments those fetches take.
//!
//! [`ProxiesView`] is what [`ibex_sample::SampleContext::proxies`] points at: it reads the
//! server statuses the health checks write, the per-server connection counts, weights and
//! `maxconn`s, and the stick tables, from the worker's own [`Proxy`] list.
//!
//! [`check_expr`] is the load-time half. `HAProxy` resolves a fetch's `<backend>`,
//! `[<backend>/]<server>` and `<table>` arguments when it loads the configuration and
//! refuses one that names nothing; it also refuses here, with `HAProxy`'s wording, what
//! Ibex registers no implementation for ([`ibex_sample::NOT_IMPLEMENTED`]).

use crate::check::ServerStatus;
use crate::engine::Proxy;
use ibex_config::{Config, SectionKind};
use ibex_sample::{
    not_implemented_message, Expr, FrontendCounter, ProxyState, Registry, Sample, ServerState, StickData, StickGpc, StickOp,
    StickState,
};
use ibex_stick_table::{StickKey, StickTable};
use std::sync::atomic::Ordering;

/// The [`ProxyState`] of a worker's proxies.
#[derive(Debug, Clone, Copy)]
pub struct ProxiesView<'a>(pub &'a [Proxy]);

fn status(p: &Proxy, i: usize) -> ServerStatus {
    p.server_statuses.get(i).map_or(ServerStatus::Down, |s| ServerStatus::from(s.load(Ordering::Relaxed)))
}

/// `srv_currently_usable`: running, and with a weight to take traffic (a server drained
/// from the CLI has its weight taken away in `HAProxy`).
fn usable(p: &Proxy, i: usize) -> bool {
    status(p, i) == ServerStatus::Up && p.server_weights.get(i).unwrap_or(1) > 0
}

fn is_backup(p: &Proxy, i: usize) -> bool {
    p.server_backups.get(i).copied().unwrap_or(false)
}

/// `smp_fetch_srv_is_up`: not in maintenance, and not stopped by its check.
fn is_up(p: &Proxy, i: usize) -> bool {
    !matches!(status(p, i), ServerStatus::Down | ServerStatus::Maint)
}

fn cur_sess(p: &Proxy, i: usize) -> u32 {
    p.server_actconn.get(i).map_or(0, |a| a.load(Ordering::Relaxed))
}

/// The usable active servers, and the first usable backup (`lbprm.fbck`: Ibex has no
/// `option allbackups`, so the first one is the one that takes traffic).
fn recount(p: &Proxy) -> (usize, Option<usize>) {
    let n = p.servers.len();
    let act = (0..n).filter(|&i| !is_backup(p, i) && usable(p, i)).count();
    let fbck = (0..n).find(|&i| is_backup(p, i) && usable(p, i));
    (act, fbck)
}

impl<'a> ProxiesView<'a> {
    /// The proxy with a backend named `name` (a `backend` or a `listen`).
    #[must_use]
    pub fn backend(&self, name: &str) -> Option<&'a Proxy> {
        self.0.iter().find(|p| p.has_backend && p.name == name)
    }
}

/// `be_usable_srv`.
#[must_use]
pub fn usable_servers(p: &Proxy) -> i64 {
    match recount(p) {
        (0, Some(_)) => 1,
        (act, _) => i64::try_from(act).unwrap_or(i64::MAX),
    }
}

/// `lbprm.tot_weight`: the usable active servers' weights, or the first usable backup's
/// when there are none (`update_backend_weight`).
#[must_use]
pub fn total_weight(p: &Proxy) -> u32 {
    let weight = |i: usize| p.server_weights.get(i).unwrap_or(1);
    match recount(p) {
        (0, Some(b)) => weight(b),
        (0, None) => 0,
        _ => (0..p.servers.len()).filter(|&i| !is_backup(p, i) && usable(p, i)).map(weight).sum(),
    }
}

impl ProxyState for ProxiesView<'_> {
    fn usable_servers(&self, backend: &str) -> Option<i64> {
        self.backend(backend).map(usable_servers)
    }

    fn backend_conn_free(&self, backend: &str) -> Option<i64> {
        let p = self.backend(backend)?;
        let (act, fbck) = recount(p);
        let mut free = 0i64;
        for i in 0..p.servers.len() {
            if !usable(p, i) || (is_backup(p, i) && (act > 0 || fbck != Some(i))) {
                continue;
            }
            match p.server_maxconn.get(i) {
                None | Some(0) => return Some(-1),
                Some(mc) => free += i64::from(mc.saturating_sub(cur_sess(p, i))),
            }
        }
        Some(free)
    }

    fn server(&self, backend: &str, server: &str) -> Option<ServerState> {
        let p = self.backend(backend)?;
        let i = p.server_ids.iter().position(|s| s == server)?;
        Some(ServerState {
            is_up: is_up(p, i),
            cur_sess: cur_sess(p, i),
            maxconn: p.server_maxconn.get(i),
            sess_rate: p.server_sess_rates.get(i).map_or(0, |r| to_i64(r.rate())),
            weight: p.server_weights.get(i).unwrap_or(1),
            iweight: p.server_weights.initial(i).unwrap_or(1),
            uweight: p.server_weights.get(i).unwrap_or(1),
        })
    }

    fn frontend_counter(&self, frontend: &str, counter: FrontendCounter) -> Option<i64> {
        let p = self.0.iter().find(|p| p.has_frontend && p.name == frontend)?;
        // `HAProxy` sums the counters of every thread group; Ibex keeps one set per worker.
        Some(match counter {
            FrontendCounter::Conn => p.stats.iter().map(|s| i64::from(s.act_conn.load(Ordering::Relaxed))).sum(),
            FrontendCounter::SessRate => p.stats.iter().map(|s| to_i64(s.fe_sess_rate.rate())).sum(),
            FrontendCounter::ReqRate => p.stats.iter().map(|s| to_i64(s.fe_req_rate.rate())).sum(),
        })
    }

    fn backend_sess_rate(&self, backend: &str) -> Option<i64> {
        let p = self.backend(backend)?;
        Some(p.stats.iter().map(|s| to_i64(s.be_sess_rate.rate())).sum())
    }

    fn active_connections(&self) -> i64 {
        self.0
            .iter()
            .filter(|p| p.has_frontend)
            .flat_map(|p| p.stats.iter())
            .map(|s| i64::from(s.act_conn.load(Ordering::Relaxed)))
            .sum()
    }

    fn default_backend(&self, frontend: &str) -> Option<String> {
        self.0.iter().find(|p| p.has_frontend && p.name == frontend)?.default_backend.clone()
    }

    fn frontend_exists(&self, name: &str) -> bool {
        self.0.iter().any(|p| p.has_frontend && p.name == name)
    }

    fn table_has_key(&self, table: &str, key: &Sample) -> Option<bool> {
        let t = self.0.iter().find(|p| p.name == table)?.stick_table.as_ref()?;
        // A sample the table's key type cannot be made of is no key: not in the table.
        let Some(key) = t.coerce_key(sample_stick_key(key.clone())) else { return Some(false) };
        t.get_entry(&key).ok().map(|e| e.is_some())
    }

    fn table_write(&self, table: &str, key: &Sample, op: StickOp) -> Option<i64> {
        let t = self.0.iter().find(|p| p.name == table)?.stick_table.as_ref()?;
        let key = t.coerce_key(sample_stick_key(key.clone()))?;
        apply_op(t, &key, true, op)
    }

    fn table_usage(&self, table: &str) -> Option<(i64, i64)> {
        let t = self.0.iter().find(|p| p.name == table)?.stick_table.as_ref()?;
        let used = i64::try_from(t.len()).unwrap_or(i64::MAX);
        let size = i64::try_from(t.config().max_size).unwrap_or(i64::MAX);
        Some((used, size.saturating_sub(used).max(0)))
    }

    fn table_value(&self, table: &str, key: &Sample, data: StickData) -> Option<i64> {
        let t = self.0.iter().find(|p| p.name == table)?.stick_table.as_ref()?;
        // A sample the table's key type cannot be made of finds no entry.
        let Some(key) = t.coerce_key(sample_stick_key(key.clone())) else {
            return if matches!(data, StickData::Expire | StickData::Idle) { None } else { Some(0) };
        };
        entry_value(t, &key, data)
    }
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// The stick-table entries one stream tracks, for the `sc_*` and `src_*` fetches
/// ([`StickState`]). It is a copy of the stream's slots taken when a sample context is built
/// (the rules that track an entry keep it up to date with [`StickView::track`]), so the
/// context does not borrow the stream's own slots, which those rules assign.
#[derive(Debug)]
pub struct StickView<'a> {
    proxies: &'a [Proxy],
    tracked: std::cell::RefCell<[Option<(usize, StickKey)>; 3]>,
}

impl<'a> StickView<'a> {
    #[must_use]
    pub fn new(proxies: &'a [Proxy], tracked: &[Option<(usize, StickKey)>; 3]) -> Self {
        // Nothing tracked (the usual case): no key to clone.
        let tracked = if tracked.iter().all(Option::is_none) { [None, None, None] } else { tracked.clone() };
        Self { proxies, tracked: std::cell::RefCell::new(tracked) }
    }

    /// Slot `slot` now tracks `key` in the table of proxy `t_idx`.
    pub fn track(&self, slot: usize, t_idx: usize, key: &StickKey) {
        if let Some(s) = self.tracked.borrow_mut().get_mut(slot) {
            *s = Some((t_idx, key.clone()));
        }
    }
}

/// `data` of the entry `key` of `table`: 0 if there is no such entry,
/// no sample if the table does not store `data` (`smp_fetch_conn_cnt` and its siblings).
fn entry_value(table: &StickTable, key: &StickKey, data: StickData) -> Option<i64> {
    let Some(e) = table.get_entry(key).ok().flatten() else {
        // The times of an entry that is not there are no sample (`table_expire` falls back on its default).
        return if matches!(data, StickData::Expire | StickData::Idle) { None } else { Some(0) };
    };
    let f = table.config().flags;
    let cfg = table.config();
    let rate = |r: &Option<ibex_stick_table::rate::SlidingRate>| r.as_ref().map(|r| to_i64(r.rate()));
    match data {
        StickData::ConnCnt => f.conn_cnt.then(|| to_i64(e.conn_cnt)),
        StickData::ConnCur => f.conn_cur.then(|| i64::from(e.conn_cur)),
        StickData::ConnRate => cfg.track_conn_rate_ms.and(rate(&e.conn_rate)),
        StickData::SessCnt => f.sess_cnt.then(|| to_i64(e.sess_cnt)),
        StickData::SessRate => rate(&e.sess_rate),
        StickData::HttpReqCnt => f.http_req_cnt.then(|| to_i64(e.http_req_cnt)),
        StickData::HttpReqRate => cfg.track_http_req_rate_ms.and(rate(&e.http_req_rate)),
        StickData::HttpErrCnt => f.http_err_cnt.then(|| to_i64(e.http_err_cnt)),
        StickData::HttpErrRate => cfg.track_http_err_rate_ms.and(rate(&e.http_err_rate)),
        StickData::HttpFailCnt => f.http_fail_cnt.then(|| to_i64(e.http_fail_cnt)),
        StickData::HttpFailRate => rate(&e.http_fail_rate),
        StickData::KbytesIn => f.bytes_in_cnt.then(|| to_i64(e.bytes_in_cnt >> 10)),
        StickData::KbytesOut => f.bytes_out_cnt.then(|| to_i64(e.bytes_out_cnt >> 10)),
        StickData::BytesInRate => rate(&e.bytes_in_rate),
        StickData::BytesOutRate => rate(&e.bytes_out_rate),
        StickData::GlitchCnt => f.glitch_cnt.then(|| to_i64(e.glitch_cnt)),
        StickData::GlitchRate => rate(&e.glitch_rate),
        // On a table that stores the array form, `gpc0`, `gpc1`, `gpt0` and the legacy rates are its
        // elements 0 and 1 (measured on HAProxy 3.5-dev8-885761-29); the array form of a
        // legacy table is not there.
        StickData::Gpc0 => if f.gpc0 { Some(to_i64(e.gpc0)) } else { e.gpc.first().map(|v| to_i64(*v)) },
        StickData::Gpc1 => if f.gpc1 { Some(to_i64(e.gpc1)) } else { e.gpc.get(1).map(|v| to_i64(*v)) },
        StickData::Gpt0 => if f.gpt0 { Some(i64::from(e.gpt0)) } else { e.gpt.first().map(|v| i64::from(*v)) },
        StickData::Gpc0Rate => rate(&e.gpc0_rate).or_else(|| e.gpc_rate.first().map(|r| to_i64(r.rate()))),
        StickData::Gpc1Rate => rate(&e.gpc1_rate).or_else(|| e.gpc_rate.get(1).map(|r| to_i64(r.rate()))),
        StickData::GpcIdx(i) => e.gpc.get(i).map(|v| to_i64(*v)),
        StickData::GpcRateIdx(i) => e.gpc_rate.get(i).map(|r| to_i64(r.rate())),
        StickData::GptIdx(i) => e.gpt.get(i).map(|v| i64::from(*v)),
        StickData::Trackers => Some(i64::from(e.trackers)),
        StickData::ServerId => f.server_id.then(|| e.server_id.map_or(0, i64::from)),
        StickData::Idle => Some(to_i64(u64::try_from(e.last_updated.elapsed().as_millis()).unwrap_or(u64::MAX))),
        StickData::Expire => {
            let idle = u128::from(u64::try_from(e.last_updated.elapsed().as_millis()).unwrap_or(u64::MAX));
            Some(to_i64(u64::try_from(cfg.expire.as_millis().saturating_sub(idle)).unwrap_or(u64::MAX)))
        }
    }
}

impl StickState for StickView<'_> {
    /// `smp_fetch_sc_stkctr`.
    fn tracked(&self, slot: usize, table: Option<&str>, data: StickData) -> Option<i64> {
        let slots = self.tracked.borrow();
        let (t_idx, key) = slots.get(slot)?.as_ref()?;
        let px = self.proxies.get(*t_idx)?;
        let tracked = px.stick_table.as_ref()?;
        let Some(name) = table else { return entry_value(tracked, key, data) };
        // An alternate table: the same key, looked up there, unless its key type differs.
        let alt_px = self.proxies.iter().find(|p| p.name == name)?;
        let alt = alt_px.stick_table.as_ref()?;
        if alt.config().key_type != tracked.config().key_type {
            return None;
        }
        entry_value(alt, key, data)
    }

    /// `smp_fetch_sc_key` and `smp_fetch_sc_tracked`.
    fn tracked_key(&self, slot: usize, table: Option<&str>) -> Option<Sample> {
        let slots = self.tracked.borrow();
        let (t_idx, key) = slots.get(slot)?.as_ref()?;
        let tracked = self.proxies.get(*t_idx)?.stick_table.as_ref()?;
        let Some(name) = table else { return Some(key_sample(key)) };
        // An alternate table of the same key type: tracked there whether or not the entry exists.
        let alt = self.proxies.iter().find(|p| p.name == name)?.stick_table.as_ref()?;
        if alt.config().key_type != tracked.config().key_type {
            return None;
        }
        Some(key_sample(key))
    }

    /// `smp_fetch_src_stkctr`, which looks the entry up and never creates it.
    fn source(&self, ip: std::net::IpAddr, tables: &[&str], data: StickData) -> Option<i64> {
        let px = tables
            .iter()
            .find_map(|name| self.proxies.iter().find(|p| p.name == *name && p.stick_table.is_some()))?;
        let table = px.stick_table.as_ref()?;
        let Some(key) = table.coerce_key(StickKey::Ip(ip)) else { return Some(0) };
        entry_value(table, &key, data)
    }

    /// `smp_fetch_src_updt_conn_cnt` and the `src_inc_gpc*`/`src_clr_gpc*`, which create the
    /// entry (the table's own key type applied to the address).
    fn write_source(&self, ip: std::net::IpAddr, tables: &[&str], op: StickOp) -> Option<i64> {
        let px = tables
            .iter()
            .find_map(|name| self.proxies.iter().find(|p| p.name == *name && p.stick_table.is_some()))?;
        let table = px.stick_table.as_ref()?;
        let key = table.coerce_key(StickKey::Ip(ip))?;
        apply_op(table, &key, true, op)
    }

    /// `smp_fetch_sc_inc_gpc0` and its siblings: the tracked entry, or the one of the same
    /// key in an alternate table, which is looked up and not created.
    fn write_tracked(&self, slot: usize, table: Option<&str>, op: StickOp) -> Option<i64> {
        let slots = self.tracked.borrow();
        let (t_idx, key) = slots.get(slot)?.as_ref()?;
        let tracked = self.proxies.get(*t_idx)?.stick_table.as_ref()?;
        let Some(name) = table else { return apply_op(tracked, key, true, op) };
        let alt = self.proxies.iter().find(|p| p.name == name)?.stick_table.as_ref()?;
        if alt.config().key_type != tracked.config().key_type {
            return None;
        }
        apply_op(alt, key, false, op)
    }
}

/// `op` applied to the entry `key` of `table`, which is created when `create`: the value the
/// fetch gives, none where the table does not store what is written.
fn apply_op(table: &StickTable, key: &StickKey, create: bool, op: StickOp) -> Option<i64> {
    use ibex_stick_table::{Gpc, GpcOp};
    let gpc = |g: StickGpc| match g {
        StickGpc::Zero => Gpc::Zero,
        StickGpc::One => Gpc::One,
        StickGpc::Idx(i) => Gpc::Idx(i),
    };
    match op {
        StickOp::IncGpc(g) => table.gpc_op(key, create, gpc(g), GpcOp::Inc),
        StickOp::ClrGpc(g) => table.gpc_op(key, create, gpc(g), GpcOp::Clr),
        StickOp::UpdtConnCnt => {
            if !table.config().flags.conn_cnt {
                return None;
            }
            let mut count = 0;
            table
                .update_entry(key, |e| {
                    e.conn_cnt += 1;
                    count = e.conn_cnt;
                })
                .ok()?;
            Some(to_i64(count))
        }
    }
}

/// `stkey_to_smp`: a key as a sample of its type.
fn key_sample(key: &StickKey) -> Sample {
    match key {
        StickKey::Ip(std::net::IpAddr::V4(ip)) => Sample::Ipv4(*ip),
        StickKey::Ip(std::net::IpAddr::V6(ip)) => Sample::Ipv6(*ip),
        StickKey::Integer(i) => Sample::Sint(i64::try_from(*i).unwrap_or(i64::MAX)),
        StickKey::String(s) => Sample::Str(s.clone()),
        StickKey::Binary(b) => Sample::Bin(b.clone()),
    }
}

/// The stick-table key a sample stands for, before the table's key type is applied
/// ([`ibex_stick_table::StickTable::coerce_key`]). A string stays a string: whether it is an
/// address is for the table to say.
pub(crate) fn sample_stick_key(smp: Sample) -> StickKey {
    match smp {
        Sample::Ipv4(ip) => StickKey::Ip(std::net::IpAddr::V4(ip)),
        Sample::Ipv6(ip) => StickKey::Ip(std::net::IpAddr::V6(ip)),
        Sample::Sint(i) => StickKey::Integer(i.cast_unsigned()),
        Sample::Str(s) => StickKey::String(s),
        Sample::Bin(b) => StickKey::Binary(b),
        Sample::Bool(b) => StickKey::Integer(u64::from(b)),
        Sample::Meth(m) => StickKey::String(m.as_str().to_string()),
    }
}

// ---- load time ---------------------------------------------------------------------

/// The section an expression is written in, as the argument resolution needs it.
#[derive(Debug, Clone, Copy)]
pub struct Where<'a> {
    pub section: SectionKind,
    /// `None` for an unnamed `defaults`.
    pub proxy: Option<&'a str>,
}

/// The argument a fetch or converter takes that names something in the configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ArgKind {
    /// `[<frontend>]`, defaulting to the current proxy (`ARGT_FE`).
    Frontend,
    /// `[<backend>]`, defaulting to the current proxy (`ARGT_BE`).
    Backend,
    /// `[<backend>/]<server>` (`ARGT_SRV`).
    Server,
    /// `[<table>]`, defaulting to the current proxy (`ARGT_TAB`).
    Table,
    /// `<userlist>` (`ARGT_USR`), with no default.
    Userlist,
}

/// Where a fetch's argument that names something is, and what it names.
#[derive(Clone, Copy)]
struct ArgSpec {
    kind: ArgKind,
    /// Its place among the fetch's arguments, from 0.
    pos: usize,
    /// Whether it may be left out without the current proxy standing in for it: the
    /// optional table of the `sc_*` fetches.
    optional: bool,
}

/// The data types the `sc_*`, `sc[0-9]_*` and `src_*` fetches read.
const STICK_FETCHES: &[&str] = &[
    "conn_cnt", "conn_cur", "conn_rate", "sess_cnt", "http_req_cnt", "http_req_rate", "http_err_cnt",
    "http_err_rate", "kbytes_in", "kbytes_out", "sess_rate", "http_fail_cnt", "http_fail_rate", "bytes_in_rate",
    "bytes_out_rate", "glitch_cnt", "glitch_rate", "trackers", "tracked", "updt_conn_cnt", "get_gpc0", "get_gpc1",
    "get_gpt0", "gpc0_rate", "gpc1_rate", "inc_gpc0", "inc_gpc1", "clr_gpc0", "clr_gpc1",
];

/// The `sc_*` and `src_*` fetches of the array form of the general purpose storage, which take
/// the element first: `sc_get_gpc(<idx>,<ctr>[,<table>])`, `src_get_gpc(<idx>,<table>)`.
const GPC_ARRAY_FETCHES: &[&str] = &["get_gpc", "get_gpt", "gpc_rate", "inc_gpc", "clr_gpc"];

fn fetch_arg(name: &str) -> Option<ArgSpec> {
    let at = |kind, pos| Some(ArgSpec { kind, pos, optional: false });
    match name {
        "nbsrv" | "be_conn_free" | "be_sess_rate" => at(ArgKind::Backend, 0),
        // T331: the weight fetches name their server as `srv_conn` does.
        "srv_is_up" | "srv_conn" | "srv_conn_free" | "srv_sess_rate" | "srv_weight" | "srv_iweight" | "srv_uweight" => {
            at(ArgKind::Server, 0)
        }
        "fe_conn" | "fe_sess_rate" | "fe_req_rate" => at(ArgKind::Frontend, 0),
        "http_auth" | "http_auth_group" => at(ArgKind::Userlist, 0),
        "table_cnt" | "table_avl" => at(ArgKind::Table, 0),
        _ => {
            // `sc_<what>(<ctr>[,<table>])`, `sc[0-9]_<what>([<table>])`, `src_<what>(<table>)`.
            let (prefix, what) = name.split_once('_')?;
            if GPC_ARRAY_FETCHES.contains(&what) {
                return match prefix {
                    "sc" => Some(ArgSpec { kind: ArgKind::Table, pos: 2, optional: true }),
                    // The one shorthand of an array form `HAProxy` registers.
                    "sc1" if what == "clr_gpc" => Some(ArgSpec { kind: ArgKind::Table, pos: 1, optional: true }),
                    "src" => at(ArgKind::Table, 1),
                    _ => None,
                };
            }
            if !STICK_FETCHES.contains(&what) {
                return None;
            }
            // A tracker count is a stream's (`sc_*`), and `src_updt_conn_cnt` is the only
            // `src_*` that writes.
            let exists = match what {
                "trackers" | "tracked" => prefix != "src",
                "updt_conn_cnt" => prefix == "src",
                _ => true,
            };
            if !exists {
                return None;
            }
            match prefix {
                "sc" => Some(ArgSpec { kind: ArgKind::Table, pos: 1, optional: true }),
                "sc0" | "sc1" | "sc2" => Some(ArgSpec { kind: ArgKind::Table, pos: 0, optional: true }),
                "src" => at(ArgKind::Table, 0),
                _ => None,
            }
        }
    }
}

/// The `table_*` converters that read a counter: each takes a table.
const TABLE_CONVERTERS: &[&str] = &[
    "table_conn_cnt", "table_conn_cur", "table_conn_rate", "table_sess_cnt", "table_http_req_cnt",
    "table_http_req_rate", "table_http_err_cnt", "table_http_err_rate", "table_kbytes_in", "table_kbytes_out",
    "table_gpc0", "table_gpc1", "table_gpt0", "table_sess_rate", "table_bytes_in_rate", "table_bytes_out_rate",
    "table_trackers", "table_expire", "table_idle", "table_server_id", "table_glitch_cnt", "table_glitch_rate",
    "table_http_fail_cnt", "table_http_fail_rate", "table_gpc0_rate", "table_gpc1_rate", "table_inc_gpc0",
    "table_inc_gpc1", "table_clr_gpc0", "table_clr_gpc1",
];

/// The `table_*` converters that take an element first (`table_gpc(<idx>,<table>)`).
const TABLE_CONVERTERS_AT: &[&str] = &["table_gpc", "table_gpt", "table_gpc_rate", "table_inc_gpc", "table_clr_gpc"];

fn converter_arg(name: &str) -> Option<ArgSpec> {
    if TABLE_CONVERTERS_AT.contains(&name) {
        return Some(ArgSpec { kind: ArgKind::Table, pos: 1, optional: false });
    }
    (name == "in_table" || TABLE_CONVERTERS.contains(&name)).then_some(ArgSpec { kind: ArgKind::Table, pos: 0, optional: false })
}

/// T341: how many arguments a fetch that names one proxy, server or table has (`ARG1`), or
/// none (`srv_id`, `srv_name`): `make_arg_list` refuses what follows the last one.
fn fetch_max_args(name: &str) -> Option<usize> {
    match name {
        "srv_id" | "srv_name" => Some(0),
        "nbsrv" | "be_conn_free" | "be_sess_rate" | "srv_is_up" | "srv_conn" | "srv_conn_free" | "srv_sess_rate"
        | "srv_weight" | "srv_iweight" | "srv_uweight" | "fe_conn" | "fe_sess_rate" | "fe_req_rate" | "table_cnt"
        | "table_avl" => Some(1),
        _ => None,
    }
}

/// The array forms take the element and the counter or table both: `sc_get_gpc(<idx>,<ctr>)`,
/// `src_get_gpc(<idx>,<table>)`, `table_gpc(<idx>,<table>)`. `HAProxy` refuses one written with
/// less (a table may be left empty, not left out): "missing arguments (got 1/2), type 'table'
/// expected", for a fetch, and "invalid arg 2 in converter ..." for a converter.
fn array_arity(name: &str, given: usize, converter: bool) -> Option<String> {
    let needs_two = if converter {
        TABLE_CONVERTERS_AT.contains(&name)
    } else {
        name.split_once('_').is_some_and(|(prefix, what)| matches!(prefix, "sc" | "src") && GPC_ARRAY_FETCHES.contains(&what))
    };
    if !needs_two || given >= 2 {
        return None;
    }
    let kind = if given == 0 || name.starts_with("sc_") { "integer" } else { "table" };
    Some(if converter {
        format!("invalid arg {} in converter '{name}' : missing arguments (got {given}/2), type '{kind}' expected.", given + 1)
    } else {
        format!("fetch method '{name}' : missing arguments (got {given}/2), type '{kind}' expected.")
    })
}

/// Names Ibex once registered, returning a constant, that `HAProxy` does not have. A
/// configuration that uses one fails on `HAProxy` with "unknown fetch method", and now
/// on Ibex too, wherever it appears.
const NOT_HAPROXY_FETCHES: &[&str] = &[
    "src_trackers", "src_in_table",
    // Counters on the connection's own context that nothing filled in: `HAProxy` has no such
    // fetch (its counters are `fe_*`, `be_*`, `srv_*` and the stick-table ones).
    "conn_cnt", "conn_rate", "cum_conn", "err_cnt", "err_rate", "req_cnt", "req_rate", "sess_cnt", "sess_rate",
    // `sc_bytes_in_cnt` and its siblings: the stick-table fetches are `kbytes_in` and `bytes_in_rate`;
    // the general purpose counters are read with `sc_get_gpc0` and `sc_get_gpt0`.
    "sc_bytes_in_cnt", "sc_bytes_out_cnt", "sc_gpc0", "sc_gpc1", "sc_gpt0",
    "sc0_bytes_in_cnt", "sc0_bytes_out_cnt", "sc1_bytes_in_cnt", "sc1_bytes_out_cnt",
    "sc2_bytes_in_cnt", "sc2_bytes_out_cnt",
    "src_bytes_in_cnt", "src_bytes_out_cnt", "src_gpc0", "src_gpc1", "src_gpt0",
];

fn has_backend(config: &Config, name: &str) -> bool {
    config.backends.iter().any(|b| b.name == name) || config.listens.iter().any(|l| l.name == name)
}

fn has_frontend(config: &Config, name: &str) -> bool {
    config.frontends.iter().any(|f| f.name == name) || config.listens.iter().any(|l| l.name == name)
}

fn has_proxy(config: &Config, name: &str) -> bool {
    has_backend(config, name) || config.frontends.iter().any(|f| f.name == name)
}

fn has_server(config: &Config, proxy: &str, server: &str) -> bool {
    config.backends.iter().filter(|b| b.name == proxy).any(|b| b.servers.iter().any(|s| s.id == server))
        || config.listens.iter().filter(|l| l.name == proxy).any(|l| l.servers.iter().any(|s| s.id == server))
}

fn has_table(config: &Config, name: &str) -> bool {
    config.backends.iter().any(|b| b.name == name && b.stick_table.is_some())
        || config.listens.iter().any(|l| l.name == name && l.stick_table.is_some())
        || config.frontends.iter().any(|f| f.name == name && f.stick_table.is_some())
}

/// Resolves one argument as `smp_resolve_args` does, with its messages.
fn resolve(config: &Config, at: Where<'_>, spec: ArgSpec, arg: Option<&str>, what: &str) -> Result<(), String> {
    let ArgSpec { kind, pos, optional } = spec;
    let n = pos + 1;
    // A defaults section is no proxy to default an argument to: `HAProxy` resolves a rule
    // written there in the defaults section itself, and refuses a server without its
    // backend and an omitted table ("backend name must be set"). Its `unique-id-format` and
    // `log-format` are resolved in each proxy that inherits them ([`check_sample_refs`]).
    let cur = match at.section {
        SectionKind::Defaults => None,
        _ => at.proxy,
    };
    let arg = arg.filter(|a| !a.is_empty());
    if optional && arg.is_none() {
        return Ok(());
    }
    match kind {
        ArgKind::Frontend => match (arg, cur) {
            (Some(fe), _) if !has_frontend(config, fe) => {
                Err(format!("unable to find frontend '{fe}' referenced in arg {n} of {what}"))
            }
            (None, Some(px)) if !has_frontend(config, px) => {
                Err(format!("proxy '{px}', referenced in arg {n} of {what}, has not frontend capability"))
            }
            _ => Ok(()),
        },
        ArgKind::Backend => match (arg, cur) {
            (Some(be), _) if !has_backend(config, be) => {
                Err(format!("unable to find backend '{be}' referenced in arg {n} of {what}"))
            }
            (None, Some(px)) if !has_backend(config, px) => {
                Err(format!("proxy '{px}', referenced in arg {n} of {what}, has not backend capability"))
            }
            _ => Ok(()),
        },
        ArgKind::Server => {
            let Some(arg) = arg else {
                return Err(format!("missing server name in arg {n} of {what}"));
            };
            let (px, srv) = match arg.split_once('/') {
                Some((px, srv)) => {
                    if !has_proxy(config, px) {
                        return Err(format!("unable to find proxy '{px}' referenced in arg {n} of {what}"));
                    }
                    (px, srv)
                }
                None => match cur {
                    Some(px) => (px, arg),
                    None => return Err(format!("backend name must be set in arg {n} of {what}")),
                },
            };
            if has_server(config, px, srv) {
                Ok(())
            } else {
                Err(format!("unable to find server '{srv}' in proxy '{px}', referenced in arg {n} of {what}"))
            }
        }
        ArgKind::Userlist => match arg {
            None => Err(format!("missing userlist name in arg {n} of {what}")),
            Some(u) if !config.userlists.iter().any(|l| l.name == u) => {
                Err(format!("unable to find userlist '{u}' referenced in arg {n} of {what}"))
            }
            Some(_) => Ok(()),
        },
        ArgKind::Table => match arg.or(cur) {
            Some(t) if !has_table(config, t) => Err(format!("unable to find table '{t}' referenced in arg {n} of {what}")),
            Some(_) => Ok(()),
            None => Err(format!("table name must be set in arg {n} of {what}")),
        },
    }
}

/// Checks one sample expression written at `at`: no fetch or converter Ibex does not
/// implement, and every backend, server and table argument naming something configured.
///
/// `context` names the place in `HAProxy`'s words ("ACL keyword" for an ACL, "sample fetch
/// keyword" otherwise).
///
/// # Errors
/// The first problem, worded as `HAProxy` words it where it refuses the same thing.
pub fn check_expr(config: &Config, registry: &Registry, at: Where<'_>, expr: &str, acl: bool) -> Result<(), String> {
    // The expression is the first word: an ACL's pattern follows it.
    let word = expr.split_whitespace().next().unwrap_or("");
    let Ok(e) = Expr::parse(word) else { return Ok(()) };
    let in_proxy = at.proxy.map(|p| format!(" in proxy '{p}'")).unwrap_or_default();
    if let Some(msg) = not_implemented_message(&e.fetch_name) {
        return Err(msg);
    }
    if NOT_HAPROXY_FETCHES.contains(&e.fetch_name.as_str()) && registry.get_fetch(&e.fetch_name).is_none() {
        return Err(format!("unknown fetch method '{}'", e.fetch_name));
    }
    // An ACL keyword Ibex has no fetch behind would load and never match, so a `deny if`
    // on it lets everything through (T132): refuse it, as `HAProxy` refuses a keyword it
    // does not know ("unknown fetch method '%s' in ACL expression '%s'").
    if acl && !registry.has_fetch(&e.fetch_name) {
        let written = word.split('(').next().unwrap_or(word);
        return Err(format!(
            "unknown fetch method '{written}' in ACL expression '{written}' (HAProxy does not know it, or Ibex does not implement it)."
        ));
    }
    for (c, _) in &e.converters {
        if let Some(msg) = not_implemented_message(c) {
            return Err(msg);
        }
    }
    // `request_date()` is one empty unit to `HAProxy` (`make_arg_list`), which it refuses;
    // `Expr::parse` sees no argument there, as in a bare `request_date`.
    let empty_unit = matches!(e.fetch_name.as_str(), "accept_date" | "request_date")
        && e.fetch_args.is_empty()
        && word.split(',').next().is_some_and(|f| f.trim_end().ends_with("()"));
    let fetch_args = if empty_unit { vec![String::new()] } else { e.fetch_args.clone() };
    if let Some(msg) = ibex_sample::check_raw_fetch_args(&e.fetch_name, &fetch_args) {
        return Err(msg);
    }
    if let Some(msg) = ibex_sample::check_dump_all_vars_args(&e.fetch_name, &e.fetch_args) {
        return Err(msg);
    }
    if let Some(msg) = array_arity(&e.fetch_name, e.fetch_args.len(), false) {
        return Err(msg);
    }
    for (c, args) in &e.converters {
        if let Some(msg) = array_arity(c, args.len(), true) {
            return Err(msg);
        }
    }
    if let Some(max) = fetch_max_args(&e.fetch_name).filter(|m| e.fetch_args.len() > *m) {
        let rest = e.fetch_args[max..].join(",");
        let rest = if max == 0 { rest } else { format!(",{rest}") };
        return Err(format!("fetch method '{}' : expected ')' before '{rest})'.", e.fetch_name));
    }
    if let Some(spec) = fetch_arg(&e.fetch_name) {
        let what = format!("{} '{}'{in_proxy}", if acl { "ACL keyword" } else { "sample fetch keyword" }, e.fetch_name);
        resolve(config, at, spec, e.fetch_args.get(spec.pos).map(String::as_str), &what)?;
    }
    for (c, args) in &e.converters {
        if let Some(spec) = converter_arg(c) {
            let what = format!("conversion keyword '{c}' for sample fetch keyword '{}'{in_proxy}", e.fetch_name);
            resolve(config, at, spec, args.get(spec.pos).map(String::as_str), &what)?;
        }
    }
    Ok(())
}

/// [`check_expr`] over every ACL and log-format expression the parser recorded
/// ([`Config::sample_refs`]).
///
/// # Errors
/// The first that fails, with its line.
pub fn check_sample_refs(config: &Config, registry: &Registry) -> Result<(), String> {
    for r in &config.sample_refs {
        let in_line = |e: String| format!("parsing [line {}]: {e}", r.line);
        // The patterns of an anonymous ACL, which a named one has checked since `validate_acls`.
        if let (true, Some(full)) = (r.acl, r.full.as_deref()) {
            if let Err(e) = Expr::parse(full) {
                let what = match r.directive.as_str() {
                    "http-request" | "http-response" | "http-after-response" => {
                        format!("an '{} {}' condition", r.directive, r.action)
                    }
                    "use_backend" | "use-server" => "switching rule".to_string(),
                    "force-persist" | "ignore-persist" => format!("a '{}' rule", r.directive),
                    "stick" => "sticking condition".to_string(),
                    d => format!("an '{d}' condition"),
                };
                return Err(in_line(format!("error detected while parsing {what} : {e}.")));
            }
        }
        // A fetch or converter that does not exist would load and yield an empty value on
        // every request; `sample_parse_expr` refuses it wherever the `%[...]` is written.
        // (An ACL's expression is checked by `check_expr`, in `HAProxy`'s ACL wording.)
        // `log-format`, `unique-id-format`, `error-log-format` and `log-format-sd` are compiled, and refused
        // in `HAProxy`'s "failed to parse log-format" words, by `validate_formats`.
        if !r.acl && !matches!(r.directive.as_str(), "log-format" | "unique-id-format" | "error-log-format" | "log-format-sd") {
            // A `%[...]` may not end in commas, unlike a rule's expression: the converter
            // `sample_parse_expr` finds after them is the `]`, an empty name (T341).
            let trailing = r.expr.ends_with(',').then(|| Err("unknown converter ''".to_string()));
            trailing
                .unwrap_or_else(|| crate::rule_exprs::check_sample_expr(&r.expr, registry))
                .map_err(|e| in_line(format!("failed to parse sample expression <{}> : {e}", r.expr)))?;
        }
        // A fetch of the response where the stream has none would read the response of
        // whatever stream ran last on the thread (T156): in a request rule, and for the
        // headers in a log-format, rendered once they are gone. `HAProxy` refuses both.
        // An ACL is only warned about there, and never matches.
        // The headers of neither side are left when a log line is rendered (`log-format`,
        // `error-log-format`, `log-format-sd`): `hdr` needs both, and a request fetch the
        // request's. `HAProxy` refuses them all at load (3.5-dev8-885761-29, T286); the
        // captures (`%hr`, `capture.req.hdr`) are what a log line reads headers with.
        let in_log = matches!(r.directive.as_str(), "log-format" | "error-log-format" | "log-format-sd");
        let part_missing = |fetch: &str| match r.directive.as_str() {
            "http-response" | "http-after-response" => crate::rule_exprs::request_part(fetch, false),
            _ if in_log && fetch == "hdr" => Some("HTTP request headers,HTTP response headers"),
            _ if in_log => crate::rule_exprs::request_part(fetch, false)
                .filter(|p| p.ends_with("headers"))
                .or_else(|| crate::rule_exprs::response_part(fetch)),
            _ => crate::rule_exprs::response_part(fetch).or_else(|| crate::rule_exprs::server_part(fetch)),
        };
        if let Some(part) = (!r.acl).then(|| part_missing(crate::rule_exprs::leading_fetch(&r.expr))).flatten() {
            let fetch = crate::rule_exprs::leading_fetch(&r.expr);
            let why = format!("sample fetch <{fetch}> may not be reliably used here because it needs '{part}' which is not available here.");
            let headers = part.ends_with("headers");
            let refused = match r.directive.as_str() {
                "http-request" | "http-response" | "http-after-response" => {
                    let kind = match r.section {
                        SectionKind::Frontend => "frontend",
                        SectionKind::Backend => "backend",
                        SectionKind::Listen => "proxy",
                        SectionKind::Defaults => "defaults",
                    };
                    let what = r.proxy.as_deref().map_or_else(|| format!("{kind} section"), |n| format!("{kind} '{n}'"));
                    Some(format!("error detected in {what} while parsing '{} {}' rule : {why}", r.directive, r.action))
                }
                "log-format" | "error-log-format" | "log-format-sd" if headers => Some(format!("failed to parse {} : {why}", r.directive)),
                // The unique id is made from the request: neither the response nor the server
                // is there yet (T341).
                "unique-id-format" => Some(format!("failed to parse unique-id : {why}")),
                _ => None,
            };
            if let Some(e) = refused {
                return Err(in_line(e));
            }
        }
        if let (SectionKind::Defaults, "unique-id-format" | "log-format" | "error-log-format" | "log-format-sd") = (r.section, r.directive.as_str()) {
            // Resolved in each proxy that inherited it, as if written there.
            for (section, name) in format_users(config, &r.directive, &r.expr) {
                check_expr(config, registry, Where { section, proxy: Some(name) }, &r.expr, false).map_err(in_line)?;
            }
            continue;
        }
        let at = Where { section: r.section, proxy: r.proxy.as_deref() };
        check_expr(config, registry, at, &r.expr, r.acl).map_err(in_line)?;
    }
    Ok(())
}

/// The proxies whose `directive` (`unique-id-format`, or `log-format`, which only a proxy
/// with a frontend compiles) contains the expression `expr`.
fn format_users<'c>(config: &'c Config, directive: &str, expr: &str) -> Vec<(SectionKind, &'c str)> {
    let uses = |fmt: &str| ibex_config::parser::log_format_exprs(fmt).contains(&expr);
    let custom = |spec: &Option<ibex_config::LogFormatSpec>| matches!(spec, Some(ibex_config::LogFormatSpec::Custom(f)) if uses(f));
    let of = |fmt: &Option<String>| fmt.as_deref().is_some_and(uses);
    let pick = |spec: &Option<ibex_config::LogFormatSpec>, elf: &Option<String>, sd: &Option<String>, uid: &Option<String>| match directive {
        "log-format" => custom(spec),
        "error-log-format" => of(elf),
        "log-format-sd" => of(sd),
        _ => of(uid),
    };
    let fes = config.frontends.iter().filter(|f| pick(&f.log_format, &f.error_log_format, &f.log_format_sd, &f.unique_id_format));
    let lis = config.listens.iter().filter(|l| pick(&l.log_format, &l.error_log_format, &l.log_format_sd, &l.unique_id_format));
    let bes = config.backends.iter().filter(|b| directive == "unique-id-format" && b.unique_id_format.as_deref().is_some_and(uses));
    fes.map(|f| (SectionKind::Frontend, f.name.as_str()))
        .chain(lis.map(|l| (SectionKind::Listen, l.name.as_str())))
        .chain(bes.map(|b| (SectionKind::Backend, b.name.as_str())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which table argument each stick fetch has, from `stick_table.c`'s keyword lists
    /// (`ARG2(2,SINT,TAB)` and so on): the array forms take it second (`src_*`) or third (`sc_*`),
    /// the `sc[0-2]_*` shorthands first, and a name that is not a keyword has none.
    #[test]
    fn the_table_argument_of_the_stick_fetches() {
        let pos = |n: &str| fetch_arg(n).map(|s| (s.pos, s.optional));
        assert_eq!(pos("src_get_gpc"), Some((1, false)));
        assert_eq!(pos("sc_get_gpc"), Some((2, true)));
        assert_eq!(pos("sc1_clr_gpc"), Some((1, true)));
        assert_eq!(pos("sc_get_gpc0"), Some((1, true)));
        assert_eq!(pos("sc0_get_gpc0"), Some((0, true)));
        assert_eq!(pos("src_get_gpc0"), Some((0, false)));
        assert_eq!(pos("table_cnt"), Some((0, false)));
        // `HAProxy` has no `sc0_get_gpc`, `src_tracked` or `src_trackers`: no argument to resolve.
        assert_eq!(pos("sc0_get_gpc"), None);
        assert_eq!(pos("src_tracked"), None);
        assert_eq!(pos("src_trackers"), None);
        assert_eq!(pos("sc_key"), None);
    }

    /// A table may be left empty in the array forms, not left out; measured on `HAProxy` 3.5-dev8-885761-29.
    #[test]
    fn the_array_forms_need_their_second_argument() {
        assert!(array_arity("src_get_gpc", 1, false).is_some_and(|m| m.contains("(got 1/2), type 'table'")));
        assert!(array_arity("sc_get_gpc", 0, false).is_some_and(|m| m.contains("(got 0/2), type 'integer'")));
        assert!(array_arity("table_gpc", 1, true).is_some_and(|m| m.starts_with("invalid arg 2 in converter")));
        assert_eq!(array_arity("src_get_gpc", 2, false), None);
        assert_eq!(array_arity("src_get_gpc0", 0, false), None);
    }
}
