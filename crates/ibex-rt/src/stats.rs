// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/stats.c, src/stats-proxy.c and include/haproxy/stats-proxy.h.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Statistics reporting for Ibex.
//!
//! Generates `HAProxy`-compatible telemetry:
//! - `show info`: 14 mandatory fields for monitoring clients (e.g. `hatop`).
//! - `show stat`: 146-column CSV telemetry output matching `data/stats_csv_header.txt`.

use crate::check::{ServerCheckState, ServerStatus};
use crate::engine::Proxy;
pub use crate::stats_html::render_stats_html;
use std::time::Instant;
use crate::cpu;

/// Global CPU usage threshold for flood detection (tune.glitches.kill.cpu-usage)
pub static GLITCHES_KILL_CPU_USAGE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Checks if the current CPU usage exceeds the configured flood threshold.
pub fn is_cpu_glitch_threshold_exceeded(cpu_usage: u8) -> bool {
    let threshold = GLITCHES_KILL_CPU_USAGE.load(std::sync::atomic::Ordering::Relaxed);
    threshold > 0 && cpu_usage >= threshold
}


/// Number of columns `HAProxy` 3.5 emits in `show stat`.
///
/// `hatop` parses this CSV **positionally**, so a row of the wrong width silently
/// misaligns every column past the divergence -- which reads as corrupt data rather
/// than a missing feature. Asserted by test against `data/stats_csv_header.txt`.
pub const STAT_FIELD_COUNT: usize = 146;

/// Column names in emission order, captured from a live `HAProxy` 3.5 `show stat`.
///
/// Index 119 is a literal `-` separator, after which come the per-module `h2_*`,
/// `ssl_*` and `h1_*` columns registered outside the main stat table.
pub static STAT_FIELDS: [&str; STAT_FIELD_COUNT] = [
    "pxname",
    "svname",
    "qcur",
    "qmax",
    "scur",
    "smax",
    "slim",
    "stot",
    "bin",
    "bout",
    "dreq",
    "dresp",
    "ereq",
    "econ",
    "eresp",
    "wretr",
    "wredis",
    "status",
    "weight",
    "act",
    "bck",
    "chkfail",
    "chkdown",
    "lastchg",
    "downtime",
    "qlimit",
    "pid",
    "iid",
    "sid",
    "throttle",
    "lbtot",
    "tracked",
    "type",
    "rate",
    "rate_lim",
    "rate_max",
    "check_status",
    "check_code",
    "check_duration",
    "hrsp_1xx",
    "hrsp_2xx",
    "hrsp_3xx",
    "hrsp_4xx",
    "hrsp_5xx",
    "hrsp_other",
    "hanafail",
    "req_rate",
    "req_rate_max",
    "req_tot",
    "cli_abrt",
    "srv_abrt",
    "comp_in",
    "comp_out",
    "comp_byp",
    "comp_rsp",
    "lastsess",
    "last_chk",
    "last_agt",
    "qtime",
    "ctime",
    "rtime",
    "ttime",
    "agent_status",
    "agent_code",
    "agent_duration",
    "check_desc",
    "agent_desc",
    "check_rise",
    "check_fall",
    "check_health",
    "agent_rise",
    "agent_fall",
    "agent_health",
    "addr",
    "cookie",
    "mode",
    "algo",
    "conn_rate",
    "conn_rate_max",
    "conn_tot",
    "intercepted",
    "dcon",
    "dses",
    "wrew",
    "connect",
    "reuse",
    "cache_lookups",
    "cache_hits",
    "srv_icur",
    "src_ilim",
    "qtime_max",
    "ctime_max",
    "rtime_max",
    "ttime_max",
    "eint",
    "idle_conn_cur",
    "safe_conn_cur",
    "used_conn_cur",
    "need_conn_est",
    "uweight",
    "agg_server_status",
    "agg_server_check_status",
    "agg_check_status",
    "srid",
    "sess_other",
    "h1sess",
    "h2sess",
    "h3sess",
    "req_other",
    "h1req",
    "h2req",
    "h3req",
    "proto",
    "priv_idle_cur",
    "reqbin",
    "reqbout",
    "resbin",
    "resbout",
    "cache_hint_hits",
    "-",
    "h2_headers_rcvd",
    "h2_data_rcvd",
    "h2_settings_rcvd",
    "h2_rst_stream_rcvd",
    "h2_goaway_rcvd",
    "h2_detected_conn_protocol_errors",
    "h2_detected_strm_protocol_errors",
    "h2_rst_stream_resp",
    "h2_goaway_resp",
    "h2_open_connections",
    "h2_backend_open_streams",
    "h2_total_connections",
    "h2_backend_total_streams",
    "ssl_sess",
    "ssl_reused_sess",
    "ssl_failed_handshake",
    "ssl_ocsp_staple",
    "ssl_failed_ocsp_staple",
    "h1_open_connections",
    "h1_open_streams",
    "h1_total_connections",
    "h1_total_streams",
    "h1_bytes_in",
    "h1_bytes_out",
    "h1_spliced_bytes_in",
    "h1_spliced_bytes_out",
];

/// The `show stat` CSV header line, including `HAProxy`'s leading `# `.
#[must_use]
pub fn stats_csv_header() -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("# ");
    s.push_str(&STAT_FIELDS.join(","));
    s.push('\n');
    s
}

/// One `show stat` row, built by column name so the width cannot drift.
///
/// Every column starts empty. Empty and `0` mean different things to a stats consumer
/// -- empty is "not applicable", zero is a measurement -- so unknown columns are left
/// empty rather than zero-filled.
pub struct StatRow {
    fields: Vec<String>,
}

impl Default for StatRow {
    fn default() -> Self {
        Self::new()
    }
}

impl StatRow {
    #[must_use]
    pub fn new() -> Self {
        let mut fields = vec![String::new(); STAT_FIELD_COUNT];
        fields[119] = "-".to_string();
        StatRow { fields }
    }

    /// Sets a column by name. An unknown name is ignored rather than panicking: a typo
    /// must not take down a proxy that was only asked for statistics.
    pub fn set(&mut self, name: &str, value: impl std::fmt::Display) {
        if let Some(i) = STAT_FIELDS.iter().position(|f| *f == name) {
            self.fields[i] = value.to_string();
        }
    }

    #[must_use]
    pub fn finish(&self) -> String {
        let mut s = self.fields.join(",");
        s.push('\n');
        s
    }
}

/// Formats the `show info` output for `HATop` and CLI consumers.
#[must_use]
#[allow(clippy::too_many_lines)]
/// Worker threads this process runs, for `show info` `Nbthread`; set once at startup.
pub static NBTHREAD: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

pub fn format_show_info(start_time: Instant, pid: u32, total_tasks: usize, run_queue_len: usize, active_conns: u32, max_conns: u32) -> String {
    format_show_info_counts(start_time, pid, total_tasks, run_queue_len, active_conns, max_conns, 0, 0)
}

/// [`format_show_info`] with the cumulative connections and requests the proxies counted
/// (`CumConns`, `CumReq`).
#[must_use]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn format_show_info_counts(
    start_time: Instant,
    pid: u32,
    total_tasks: usize,
    run_queue_len: usize,
    active_conns: u32,
    max_conns: u32,
    cum_conns: u64,
    cum_reqs: u64,
) -> String {
    // `Ulimit-n` and `Maxsock`: as the startup settled them (`globalconn::apply_nofile_limit`),
    // or else the descriptors the process may hold (`getrlimit`).
    let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile).current.unwrap_or(0);
    let ulimit_n = crate::globalconn::ulimit_n().unwrap_or(nofile);
    let maxsock = crate::globalconn::maxsock_value().unwrap_or(nofile);
    // `global maxconn` and its configured ceiling, when there is one.
    let maxconn = if crate::globalconn::max() > 0 { crate::globalconn::max() } else { max_conns };
    let hard_maxconn = if crate::globalconn::hard() > 0 { crate::globalconn::hard() } else { max_conns };
    let nbthread = NBTHREAD.load(std::sync::atomic::Ordering::Relaxed).max(1);
    let elapsed = start_time.elapsed();
    let total_secs = elapsed.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let idle_pct = cpu::get_idle_pct();
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    let dropped_logs = crate::syslog::dropped_logs();
    format!(
        "Name: Ibex
\
         Version: 0.1.0
\
         Release_date: 2026/09/21
\
         Nbthread: {nbthread}
\
         Nbproc: 1
\
         Process_num: 1
\
         Pid: {pid}
\
         Uptime: {days}d {hours}h{mins:02}m{secs:02}s
\
         Uptime_sec: {total_secs}
\
         Memmax_MB: 0
\
         PoolAlloc_MB: 0
\
         PoolUsed_MB: 0
\
         PoolFailed: 0
\
         Ulimit-n: {ulimit_n}
\
         Maxsock: {maxsock}
\
         Maxconn: {maxconn}
\
         Hard_maxconn: {hard_maxconn}
\
         CurrConns: {active_conns}
\
         CumConns: {cum_conns}
\
         CumReq: {cum_reqs}
\
         MaxSslConns: 0
\
         CurrSslConns: 0
\
         CumSslConns: 0
\
         Maxpipes: 0
\
         PipesUsed: 0
\
         PipesFree: 0
\
         ConnRate: 0
\
         ConnRateLimit: 0
\
         MaxConnRate: 0
\
         SessRate: 0
\
         SessRateLimit: 0
\
         MaxSessRate: 0
\
         SslRate: 0
\
         SslRateLimit: 0
\
         MaxSslRate: 0
\
         SslFrontendKeyRate: 0
\
         SslFrontendMaxKeyRate: 0
\
         SslFrontendSessionReuse_pct: 0
\
         SslBackendKeyRate: 0
\
         SslBackendMaxKeyRate: 0
\
         SslCacheLookups: 0
\
         SslCacheMisses: 0
\
         CompressBpsIn: 0
\
         CompressBpsOut: 0
\
         CompressBpsRateLim: 0
\
         ZlibMemUsage: 0
\
         MaxZlibMemUsage: 0
\
         Tasks: {total_tasks}
\
         Run_queue: {run_queue_len}
\
         Idle_pct: {idle_pct}
\
         node: ibex
\
         description: Ibex Router
\
         Stopping: 0
\
         Jobs: 0
\
         Unstoppable Jobs: 0
\
         Listeners: 0
\
         ActivePeers: 0
\
         ConnectedPeers: 0
\
         DroppedLogs: {dropped_logs}
\
         BusyPolling: 0
\
         FailedResolutions: 0
\
         TotalBytesOut: 0
\
         TotalSplicedBytesOut: 0
\
         BytesOutRate: 0
\
         DebugCommandsIssued: 0
\
         CumRecvLogs: 0
\
         Build info: 0.1.0
\
         Memmax_bytes: 0
\
         PoolAlloc_bytes: 0
\
         PoolUsed_bytes: 0
\
         Start_time_sec: 0
\
         Tainted: 0
\
         TotalWarnings: 0
\
         MaxconnReached: 0
\
         BootTime_ms: 0
\
         Niced_tasks: 0
\
         CurrStreams: 0
\
         CumStreams: 0
\
         BlockedTrafficWarnings: 0
\
         PatternsAdded: 0
\
         PatternsFreed: 0
\
         NbThreadGroups: 0
\
         Master_id: master
\
         Worker_id: worker
"
    )
}

/// Generates the full `show stat` CSV text for all configured proxies and servers.
#[must_use]
pub fn format_show_stat(proxies: &[Proxy], checks: &[ServerCheckState], pid: u32) -> String {
    format_show_stat_filtered(proxies, checks, pid, None, None, None)
}

/// The `pid` column: the process number, 1 with a single process (HAProxy 3.5-dev8), not
/// the operating-system process id.
const PROCESS_NUM: u32 = 1;

/// What a proxy that never took a request reports.
static EMPTY: std::sync::LazyLock<crate::statcnt::TxnCounters> = std::sync::LazyLock::new(crate::statcnt::TxnCounters::default);

fn ld(a: &std::sync::atomic::AtomicU64) -> u64 {
    a.load(std::sync::atomic::Ordering::Relaxed)
}

/// The columns every kind of row counts the same way: response classes and requests (HTTP
/// only: `HAProxy` leaves them empty in TCP mode), bytes, aborts and the timings.
fn fill_counters(r: &mut StatRow, c: &crate::statcnt::TxnCounters, http: bool, timed: bool) {
    if http {
        for (name, h) in ["hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other"].iter().zip(&c.hrsp) {
            r.set(name, ld(h));
        }
        r.set("req_tot", ld(&c.req_tot));
        r.set("mode", "http");
    } else {
        r.set("mode", "tcp");
    }
    r.set("bin", ld(&c.bin));
    r.set("bout", ld(&c.bout));
    if timed {
        r.set("cli_abrt", ld(&c.cli_abrt));
        r.set("srv_abrt", ld(&c.srv_abrt));
        if let Some(secs) = crate::statcnt::TxnCounters::since_secs(c.last_sess.load(std::sync::atomic::Ordering::Relaxed)) {
            r.set("lastsess", secs);
        }
        let counted = if http { ld(&c.req_tot) } else { ld(&c.lbtot) };
        r.set("qtime", c.qtime.avg(counted));
        r.set("ctime", c.ctime.avg(counted));
        r.set("rtime", c.rtime.avg(counted));
        r.set("ttime", c.ttime.avg(counted));
        r.set("qtime_max", c.qtime.max());
        r.set("ctime_max", c.ctime.max());
        r.set("rtime_max", c.rtime.max());
        r.set("ttime_max", c.ttime.max());
        r.set("wrew", 0);
        r.set("eint", 0);
    }
}

fn write_frontend_row(out: &mut String, proxy: &Proxy, _pid: u32, iid: u32) {
    let c = proxy.ids.tc.get().map_or(&*EMPTY, |p| &p.fe);
    let http = proxy.mode == ibex_config::Mode::Http;
    let mut r = StatRow::new();
    r.set("pxname", &proxy.name);
    r.set("svname", "FRONTEND");
    r.set("scur", proxy.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>());
    r.set("smax", proxy.stats.iter().map(|s| s.max_conn.load(std::sync::atomic::Ordering::Relaxed)).max().unwrap_or(0));
    r.set("slim", proxy.maxconn.get());
    let stot = proxy.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>();
    r.set("stot", stot);
    r.set("dreq", proxy.stats.iter().map(|s| s.denied_req.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>());
    r.set("dresp", proxy.stats.iter().map(|s| s.denied_resp.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>());
    r.set("dcon", proxy.stats.iter().map(|s| s.denied_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>());
    r.set("ereq", ld(&c.ereq));
    r.set("status", "OPEN");
    r.set("pid", PROCESS_NUM);
    r.set("iid", iid);
    r.set("sid", 0);
    r.set("type", 0);
    let rate: u64 = proxy.stats.iter().map(|s| s.fe_sess_rate.rate()).sum();
    let rate_max = u64::from(c.rate_max.load(std::sync::atomic::Ordering::Relaxed));
    r.set("rate", rate);
    r.set("rate_lim", 0);
    r.set("rate_max", rate_max);
    r.set("conn_rate", rate);
    r.set("conn_rate_max", rate_max);
    r.set("conn_tot", stot);
    if !http {
        r.set("req_tot", 0);
    }
    if http {
        r.set("req_rate", proxy.stats.iter().map(|s| s.fe_req_rate.rate()).sum::<u64>());
        r.set("req_rate_max", c.req_rate_max.load(std::sync::atomic::Ordering::Relaxed));
        r.set("comp_in", 0);
        r.set("comp_out", 0);
        r.set("comp_byp", 0);
        r.set("comp_rsp", 0);
        r.set("cache_lookups", 0);
        r.set("cache_hits", 0);
    }
    fill_counters(&mut r, c, http, false);
    r.set("eint", 0);
    r.set("dses", 0);
    r.set("wrew", 0);
    out.push_str(&r.finish());
}

fn write_server_row(
    out: &mut String,
    proxy: &Proxy,
    s_idx: usize,
    check_state: Option<&ServerCheckState>,
    _pid: u32,
    iid: u32,
    sid: u32,
) {
    let srv_name = if s_idx < proxy.server_ids.len() {
        &proxy.server_ids[s_idx]
    } else {
        "srv"
    };
    let srv_addr = proxy.servers.at(s_idx);
    let (status_str, chkfail, chkdown, check_status, check_code, check_duration) =
        if let Some(c) = check_state {
            (
                c.status.as_str().to_string(),
                c.failed_checks,
                c.down_transitions,
                c.last_status_code,
                if c.status == ServerStatus::Up { 200 } else { 0 },
                c.check_duration_ms,
            )
        } else {
            let s = proxy
                .server_statuses.get(s_idx).map(|s| ServerStatus::from(s.load(std::sync::atomic::Ordering::Relaxed))).unwrap_or(ServerStatus::Up);
            let tracker = !crate::track::tracked_label(proxy, s_idx).is_empty();
            let s_str = match s {
                ServerStatus::Up if tracker => "UP".to_string(),
                ServerStatus::Up => "no check".to_string(),
                ServerStatus::Down => "DOWN".to_string(),
                ServerStatus::Drain => "DRAIN".to_string(),
                // The maintenance of a tracker's target says where it comes from.
                ServerStatus::Maint if crate::track::inherited(proxy, s_idx) => {
                    format!("MAINT (via {})", crate::track::tracked_label(proxy, s_idx))
                }
                ServerStatus::Maint => "MAINT".to_string(),
            };
            (s_str, 0, 0, "", 0, 0)
        };
    let has_check = check_state.is_some();

    let is_backup = proxy.server_backups.get(s_idx).copied().unwrap_or(false);
    let (act, bck) = if is_backup { (0, 1) } else { (1, 0) };
    let scur = proxy.server_actconn.get(s_idx).map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0);
    let weight = proxy.server_weights.get(s_idx).unwrap_or(1);
    let slim = proxy
        .server_maxconn
        .get(s_idx)
        .map_or(String::new(), |m| m.to_string());

    let mut r = StatRow::new();
    r.set("pxname", &proxy.name);
    r.set("svname", srv_name);
    let pc = proxy.ids.tc.get();
    let c = pc.and_then(|p| p.srv.get(s_idx)).unwrap_or(&EMPTY);
    r.set("qcur", 0);
    r.set("qmax", 0);
    r.set("scur", scur);
    r.set("smax", c.smax.load(std::sync::atomic::Ordering::Relaxed).max(scur));
    r.set("slim", &slim);
    r.set("stot", ld(&c.stot));
    r.set("dresp", 0);
    r.set("eresp", ld(&c.eresp));
    r.set("lbtot", ld(&c.lbtot));
    r.set("connect", ld(&c.connect));
    r.set("reuse", ld(&c.reuse));
    r.set("rate", c.sess_rate.rate());
    r.set("rate_max", c.rate_max.load(std::sync::atomic::Ordering::Relaxed));
    r.set("lastchg", crate::statcnt::TxnCounters::since_secs(c.last_chg.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or_else(|| crate::statcnt::now_ms() / 1000));
    fill_counters(&mut r, c, proxy.mode == ibex_config::Mode::Http, true);
    r.set("uweight", weight);
    let (wretr, wredis, econ) = proxy
        .server_retr
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&s_idx)
        .copied()
        .unwrap_or_default();
    r.set("econ", econ);
    r.set("wretr", wretr);
    r.set("wredis", wredis);
    r.set("status", status_str);
    r.set("tracked", crate::track::tracked_label(proxy, s_idx));
    r.set("weight", weight);
    r.set("act", act);
    r.set("bck", bck);
    if has_check {
        r.set("chkfail", chkfail);
        r.set("chkdown", chkdown);
        r.set("downtime", c.downtime_secs());
    }
    r.set("pid", PROCESS_NUM);
    r.set("iid", iid);
    r.set("sid", sid);
    r.set("type", 2);
    if has_check {
        r.set("check_status", check_status);
        r.set("check_code", check_code);
        r.set("check_duration", check_duration);
    }
    r.set("addr", srv_addr);
    out.push_str(&r.finish());
}

fn write_backend_row(out: &mut String, proxy: &Proxy, _pid: u32, iid: u32) {
    use std::sync::atomic::Ordering::Relaxed;
    let c = proxy.ids.tc.get().map_or(&*EMPTY, |p| &p.be);
    let http = proxy.mode == ibex_config::Mode::Http;
    let up = |i: usize| {
        proxy
            .server_statuses
            .get(i)
            .is_none_or(|s| matches!(ServerStatus::from(s.load(Relaxed)), ServerStatus::Up | ServerStatus::Drain))
    };
    let backup = |i: usize| proxy.server_backups.get(i).copied().unwrap_or(false);
    let act = (0..proxy.servers.len()).filter(|&i| !backup(i) && up(i)).count();
    let bck = (0..proxy.servers.len()).filter(|&i| backup(i) && up(i)).count();
    let weight: u32 = (0..proxy.servers.len()).filter(|&i| !backup(i) && up(i)).map(|i| proxy.server_weights.get(i).unwrap_or(1)).sum();
    let scur: u32 = (0..proxy.servers.len()).map(|i| proxy.server_actconn.get(i).map_or(0, |a| a.load(Relaxed))).sum();
    let be_down = !proxy.servers.is_empty() && act + bck == 0 && proxy.ids.tc.get().is_some_and(|p| p.be.down_since.load(Relaxed) != 0);
    let mut r = StatRow::new();
    r.set("pxname", &proxy.name);
    r.set("svname", "BACKEND");
    r.set("qcur", proxy.stats[0].queue_cur.load(Relaxed));
    r.set("qmax", proxy.stats[0].queue_max.load(Relaxed));
    r.set("scur", scur);
    r.set("smax", c.smax.load(Relaxed).max(scur));
    r.set("slim", proxy.maxconn.get());
    r.set("stot", ld(&c.stot));
    r.set("dreq", proxy.counters().denied_req.load(Relaxed));
    r.set("dresp", proxy.counters().denied_resp.load(Relaxed));
    r.set("econ", proxy.counters().failed_conn.load(Relaxed));
    r.set("eresp", ld(&c.eresp));
    r.set("wretr", proxy.counters().retries_count.load(Relaxed));
    r.set("wredis", proxy.counters().redispatches.load(Relaxed));
    r.set("status", if be_down { "DOWN" } else { "UP" });
    r.set("weight", weight);
    r.set("uweight", weight);
    r.set("act", act);
    r.set("bck", bck);
    r.set("chkdown", ld(&c.chkdown));
    r.set("lastchg", crate::statcnt::TxnCounters::since_secs(c.last_chg.load(Relaxed)).unwrap_or_else(|| crate::statcnt::now_ms() / 1000));
    r.set("downtime", c.downtime_secs());
    r.set("lbtot", ld(&c.lbtot));
    r.set("connect", ld(&c.connect));
    r.set("reuse", ld(&c.reuse));
    r.set("rate", c.sess_rate.rate());
    r.set("rate_max", c.rate_max.load(Relaxed));
    r.set("pid", PROCESS_NUM);
    r.set("iid", iid);
    r.set("sid", 0);
    r.set("type", 1);
    if http {
        r.set("comp_in", 0);
        r.set("comp_out", 0);
        r.set("comp_byp", 0);
        r.set("comp_rsp", 0);
        r.set("cache_lookups", 0);
        r.set("cache_hits", 0);
    }
    fill_counters(&mut r, c, http, true);
    out.push_str(&r.finish());
}

/// Generates `show stat` CSV text with optional filtering by proxy iid, type bitmask, and server sid.
#[must_use]
pub fn format_show_stat_filtered(
    proxies: &[Proxy],
    checks: &[ServerCheckState],
    pid: u32,
    iid_filter: Option<i32>,
    type_filter: Option<i32>,
    sid_filter: Option<i32>,
) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str(&stats_csv_header());

    let match_type = |type_val: i32| -> bool {
        match type_filter {
            None | Some(-1 | 33_554_431 | 0x00FF_FFFF) => true,
            Some(t) => t == type_val || (t & (1 << type_val)) != 0,
        }
    };

    // `HAProxy` lists the proxies in the order the sections were written.
    let mut order: Vec<usize> = (0..proxies.len()).collect();
    order.sort_by_key(|&i| proxies[i].ids.decl);
    for p_idx in order {
        let proxy = &proxies[p_idx];
        let iid = proxy.ids.iid;
        if let Some(f_iid) = iid_filter {
            if f_iid != -1 && u32::try_from(f_iid).ok() != Some(iid) {
                continue;
            }
        }

        if proxy.has_frontend
            && match_type(0)
            && (sid_filter.is_none() || sid_filter == Some(-1) || sid_filter == Some(0))
        {
            write_frontend_row(&mut out, proxy, pid, iid);
        }

        if match_type(2) {
            for (s_idx, _) in proxy.servers.iter().enumerate() {
                let sid = proxy.server_puid(s_idx);
                if let Some(f_sid) = sid_filter {
                    if f_sid != -1 && u32::try_from(f_sid).ok() != Some(sid) {
                        continue;
                    }
                }
                let check_state = checks
                    .iter()
                    .find(|c| c.proxy_idx == p_idx && c.server_idx == s_idx);
                write_server_row(&mut out, proxy, s_idx, check_state, pid, iid, sid);
            }
        }

        if proxy.has_backend
            && match_type(1)
            && (sid_filter.is_none() || sid_filter == Some(-1) || sid_filter == Some(0))
        {
            write_backend_row(&mut out, proxy, pid, iid);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Timeouts;
    use ibex_config::Mode;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn show_info_contains_all_fourteen_mandatory_hatop_keys() {
        let out = format_show_info_counts(Instant::now(), 1234, 10, 2, 5, 1000, 7, 9);
        let mandatory = [
            "Name:",
            "Version:",
            "Release_date:",
            "Nbproc:",
            "Process_num:",
            "Pid:",
            "Uptime:",
            "Maxconn:",
            "CurrConns:",
            "Maxpipes:",
            "PipesUsed:",
            "Tasks:",
            "Run_queue:",
            "node:",
        ];
        for key in mandatory {
            assert!(
                out.lines().any(|l| l.starts_with(key)),
                "missing mandatory key {key} in show info output"
            );
        }
    }

    #[test]
    fn show_stat_csv_has_at_least_fifty_one_commas_per_line() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let proxy = Proxy {
            id: 0,
            ids: Box::new(crate::engine::ProxyIdInfo { iid: 2, ..Default::default() }),
            log_target_idx: Vec::new(),
            log_health_checks: false,
            name: "test_proxy".into(),
            has_frontend: true,
            has_backend: true,
            addr,
            mode: Mode::Tcp,
            timeouts: Timeouts::default(),
            retries: 3,
            redisp: false,
            redisp_after: -1,
            maxconn: 1000.into(),
            dispatch: None,
            cookie: None,
            cliexp: Vec::new(),
            srvexp: Vec::new(),
            servers: vec![addr].into(),
            server_ids: vec!["srv1".into()],
            server_cookies: vec![None],
            server_statuses: std::sync::Arc::new(vec![std::sync::atomic::AtomicU8::new(0)]),
            server_track: None,
            server_weights: [1].into_iter().collect(),
            next_server_idx: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            stats: std::sync::Arc::new(vec![crate::engine::ProxyStats::default()]),
            stats_config: ibex_config::StatsConfig::default(),
            balance: ibex_config::BalanceAlgorithm::RoundRobin,
            default_backend: None,
            use_backends: Vec::new(),
            use_servers: Vec::new(),
            force_be_switch: Vec::new(),
            disabled_backends: std::sync::Arc::default(),
            monitor_uri: None,
            acls: ibex_sample::Acls::default(),
            stick_table: None,
            stick_rules: Vec::new(),
            server_send_proxy: vec![false],
            server_tfo: vec![false],
            server_send_proxy_v2: vec![false],
            server_pp_unique_id: vec![false],
            server_backups: vec![false],
            server_maxconn: [None].into_iter().collect(),
            server_actconn: std::sync::Arc::new(vec![std::sync::atomic::AtomicU32::new(0)]),
            server_retr: Default::default(),
            server_sess_rates: std::sync::Arc::new(vec![crate::engine::RateCtr::default()]),
            server_check_configs: vec![None],
            server_tls: vec![None],
            server_check_tls: vec![None],
            tcp_req_conn_rules: Vec::new(),
            tcp_req_session_rules: Vec::new(),
            tcp_req_content_rules: Vec::new(),
            tcp_req_inspect_delay: None,
            tcp_res_content_rules: Vec::new(),
            tcp_res_inspect_delay: None,
            http_req_rules: Vec::new(),
            http_req_capture_exprs: Vec::new(),
            http_res_rules: Vec::new(),
            http_after_res_rules: Vec::new(),
            http_reuse: ibex_config::HttpReuse::default(),
            abortonclose: true,
            h1_adjust: 0,
            h1_case: std::sync::Arc::default(),
            error_files: std::collections::HashMap::new(),
            error_replies: std::collections::HashMap::new(),
            log_tag: None,
            log_cursors: std::sync::Arc::default(),
            hash_type: ibex_config::HashType::default(),
            hash_preserve_affinity: ibex_config::HashPreserveAffinity::default(),
            chash: std::sync::Arc::default(),
            fwrr: std::sync::Arc::default(),
            log_format: None,
            dont_log_null: false,
            log_opts: 0,
            unique_id_format: None,
            unique_id_header: None,
            req_capture_slots: std::sync::Arc::new([]),
            res_capture_slots: std::sync::Arc::new([]),
            log_count: std::sync::Arc::default(),
        };

        let csv = format_show_stat(&[proxy], &[], 9999);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(
            lines.len() >= 4,
            "expected header + frontend + server + backend"
        );

        for (i, line) in lines.iter().enumerate() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let comma_count = line.matches(',').count();
            assert!(
                comma_count >= 51,
                "line {i} has {comma_count} commas (< 51): {line}"
            );
        }
    }
}
