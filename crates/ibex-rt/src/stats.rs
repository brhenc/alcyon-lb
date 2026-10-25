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
pub use crate::stats_typed::StatFormat;

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

/// Column name -> position, for [`StatRow::set`].
static FIELD_INDEX: std::sync::LazyLock<std::collections::HashMap<&'static str, usize>> =
    std::sync::LazyLock::new(|| STAT_FIELDS.iter().enumerate().map(|(i, n)| (*n, i)).collect());

/// The strings of a `show stat` row, as the pool keeps them.
#[derive(Debug, Default)]
struct RowFields(Vec<String>);

impl ibex_alloc::Poolable for RowFields {
    fn footprint(&self) -> usize {
        self.0.capacity() * std::mem::size_of::<String>() + self.0.iter().map(String::capacity).sum::<usize>()
    }

    /// The values are statistics, not request data: no wipe.
    fn reset(&mut self, _wipe: bool) {
        for f in &mut self.0 {
            f.clear();
        }
    }

    /// Only a whole row: one emptied by `mem::take` is not worth keeping.
    fn keep(&self, max_footprint: usize) -> bool {
        self.0.len() == STAT_FIELD_COUNT && self.footprint() <= max_footprint
    }

    fn try_new() -> Option<Self> {
        Some(RowFields((0..STAT_FIELD_COUNT).map(|_| String::with_capacity(ROW_FIELD_CAP)).collect()))
    }
}

ibex_alloc::declare_pool!(
    /// `show pools` `stat_row`: rows given back by [`StatRow`]'s `Drop`, with the capacity
    /// their strings grew to: the next row of this thread starts from them, so a scrape
    /// allocates no row after the first.
    static ROW_POOL: Pool<RowFields> = ibex_alloc::PoolSpec::new("stat_row").max_count(8);
);

/// Lists the pool in `show pools` from the start.
pub fn register_pools() {
    ROW_POOL.register();
}

const ROW_FIELD_CAP: usize = 24;

/// Puts one `show stat` row, its strings sized for long values, into this thread's pool.
pub fn reserve_row_pool() {
    // The lookup tables are built on first use: build them now.
    std::sync::LazyLock::force(&FIELD_INDEX);
    std::sync::LazyLock::force(&EMPTY);
    let _ = PROCESS_START.get_or_init(Instant::now);
    let fields: Vec<String> = (0..STAT_FIELD_COUNT).map(|_| String::with_capacity(64)).collect();
    ROW_POOL.give(RowFields(fields));
}

impl Drop for StatRow {
    fn drop(&mut self) {
        ROW_POOL.give(RowFields(std::mem::take(&mut self.fields)));
    }
}

impl Default for StatRow {
    fn default() -> Self {
        Self::new()
    }
}

impl StatRow {
    #[must_use]
    pub fn new() -> Self {
        let mut fields = ROW_POOL.take_raw(<RowFields as ibex_alloc::Poolable>::try_new).map_or_else(|| (0..STAT_FIELD_COUNT).map(|_| String::with_capacity(ROW_FIELD_CAP)).collect(), |r| r.0);
        fields[119].push('-');
        StatRow { fields }
    }

    /// Sets a column by name. An unknown name is ignored rather than panicking: a typo
    /// must not take down a proxy that was only asked for statistics.
    pub fn set(&mut self, name: &str, value: impl std::fmt::Display) {
        use std::fmt::Write;
        if let Some(&i) = FIELD_INDEX.get(name) {
            let f = &mut self.fields[i];
            f.clear();
            let _ = write!(f, "{value}");
        }
    }

    /// Sets `name` to `value` unless the row already has one.
    fn default_to(&mut self, name: &str, value: &str) {
        let field = FIELD_INDEX.get(name).and_then(|&i| self.fields.get_mut(i));
        if let Some(f) = field.filter(|f| f.is_empty()) {
            f.push_str(value);
        }
    }

    /// The columns `HAProxy` prints for an object and Ibex does not track: the per-protocol
    /// and TLS module counters (`h1_*`, `h2_*`, `ssl_*`), the byte counters by direction,
    /// the connection-pool gauges of a server, `lastsess`, `srid`, the session and request
    /// counts by protocol, `intercepted` and the backend's `agg_*`. They get what `HAProxy`
    /// prints for an object that has seen nothing (0, `lastsess` -1), so a consumer that
    /// reads them by name finds them (T245). `obj` is `F`, `B` or `S`.
    fn default_untracked(&mut self, obj: char, http: bool, algo: &str) {
        for n in ["reqbin", "reqbout", "resbin", "resbout"] {
            self.default_to(n, "0");
        }
        // Module counters: every column after the `-` separator.
        let module: &[&str] = &STAT_FIELDS[120..];
        match obj {
            'F' => {
                for n in module {
                    self.default_to(n, "0");
                }
                for n in ["sess_other", "h1sess", "h2sess", "h3sess", "req_other", "h1req", "h2req", "h3req"] {
                    self.default_to(n, "0");
                }
                if http {
                    self.default_to("cache_hint_hits", "0");
                    self.default_to("intercepted", "0");
                }
            }
            'B' => {
                for n in module {
                    self.default_to(n, "0");
                }
                for n in ["agg_server_status", "agg_server_check_status", "agg_check_status"] {
                    self.default_to(n, "0");
                }
                self.default_to("lastsess", "-1");
                self.default_to("algo", algo);
                if http {
                    self.default_to("cache_hint_hits", "0");
                }
            }
            _ => {
                for n in module.iter().filter(|n| n.starts_with("ssl_")) {
                    self.default_to(n, "0");
                }
                self.default_to("lastsess", "-1");
                for n in ["srid", "priv_idle_cur", "srv_icur", "idle_conn_cur", "safe_conn_cur", "used_conn_cur", "need_conn_est"] {
                    self.default_to(n, "0");
                }
            }
        }
    }

    /// Appends the row in `fmt`; the CSV row is what [`StatRow::finish`] returns.
    pub(crate) fn emit(&self, out: &mut String, fmt: StatFormat) {
        match fmt {
            StatFormat::Csv => {
                // `HAProxy` ends every row with a comma after the last column.
                for f in &self.fields {
                    out.push_str(f);
                    out.push(',');
                }
                out.push('\n');
            }
            _ => crate::stats_typed::emit_stat_row(out, &self.fields, fmt),
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
/// `global node` and `global description`, set once at startup by [`set_identity`].
static IDENTITY: std::sync::RwLock<(Option<String>, Option<String>)> = std::sync::RwLock::new((None, None));

/// Records `global node` and `global description` (`global.node`, `global.desc`).
pub fn set_identity(node: Option<&str>, description: Option<&str>) {
    if let Ok(mut id) = IDENTITY.write() {
        *id = (node.map(str::to_string), description.map(str::to_string));
    }
}

/// `global node`, or the host name (HAProxy: `gethostname()`) when none was given.
#[must_use]
pub fn node_name() -> String {
    if let Some(n) = IDENTITY.read().ok().and_then(|id| id.0.clone()) {
        return n;
    }
    // uname(2), not /proc, which is not there in a chroot (T240).
    rustix::system::uname().nodename().to_string_lossy().trim().to_string()
}

/// Calls `f` with the node name (`global node`, or the host name) without copying it.
pub fn with_node<R>(f: impl FnOnce(&str) -> R) -> R {
    node_of(IDENTITY.read(), f)
}

/// [`with_node`] on the result of taking the lock: a lock that cannot be taken gives the host name.
fn node_of<G: std::ops::Deref<Target = (Option<String>, Option<String>)>, E, R>(id: Result<G, E>, f: impl FnOnce(&str) -> R) -> R {
    let held = id.ok();
    if let Some(n) = held.as_deref().and_then(|id| id.0.as_deref()) {
        return f(n);
    }
    let u = rustix::system::uname();
    f(u.nodename().to_string_lossy().trim())
}

/// Calls `f` with `global description` when one was given, without copying it.
pub fn with_description<R>(f: impl FnOnce(Option<&str>) -> R) -> R {
    description_of(IDENTITY.read(), f)
}

/// [`with_description`] on the result of taking the lock: a lock poisoned (or otherwise not
/// taken) gives no description.
fn description_of<G: std::ops::Deref<Target = (Option<String>, Option<String>)>, E, R>(id: Result<G, E>, f: impl FnOnce(Option<&str>) -> R) -> R {
    match id {
        Ok(id) => f(id.1.as_deref()),
        Err(_) => f(None),
    }
}

/// `global description`, if one was given.
#[must_use]
pub fn description() -> Option<String> {
    IDENTITY.read().ok().and_then(|id| id.1.clone())
}

pub static NBTHREAD: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

// T320: process-wide count of streams (HTTP transactions, TCP sessions, CLI connections).
pub static CUM_STREAMS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// T320: TLS connections open now, client and server side (`CurrSslConns`).
pub static SSL_CURR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// T320: TLS connections set up since start, client and server side (`CumSslConns`).
pub static SSL_CUM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// T320: highest `SslRate` seen (`MaxSslRate`); reset by `clear counters`.
pub static SSL_MAX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// T320: connections accepted on `ssl` binds over the last second (`SslRate`).
pub static SSL_RATE: std::sync::Mutex<crate::engine::RateCtr> = std::sync::Mutex::new(crate::engine::RateCtr::new());

/// T320: a connection was accepted on an `ssl` bind: counts it in the rate, raising the
/// maximum (`listener_accept`).
pub fn ssl_conn_accepted() {
    let rate = {
        let r = SSL_RATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        r.tick();
        r.rate()
    };
    SSL_MAX.fetch_max(u32::try_from(rate).unwrap_or(u32::MAX), std::sync::atomic::Ordering::Relaxed);
}

/// T320: one TLS connection, client or server side, in `CurrSslConns` from the moment its TLS
/// layer is set up until it is dropped, and in `CumSslConns` from that moment on, whether or not
/// its handshake completes: `HAProxy` counts both in `ssl_sock_init` and takes `CurrSslConns`
/// back when the connection is freed. Owned by the transport, so every path that drops one
/// settles it.
pub struct SslConnCount(());

impl SslConnCount {
    #[must_use]
    pub fn new() -> Self {
        SSL_CURR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SSL_CUM.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(())
    }
}

impl Default for SslConnCount {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SslConnCount {
    fn drop(&mut self) {
        SSL_CURR.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

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
    let pairs = show_info_pairs(start_time, pid, total_tasks, run_queue_len, active_conns, max_conns, cum_conns, cum_reqs);
    crate::stats_typed::render_info(&pairs, StatFormat::Csv)
}

/// [`format_show_info_counts`] as `typed` lines or JSON (`show info typed|json`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn format_show_info_as(
    fmt: StatFormat,
    start_time: Instant,
    pid: u32,
    total_tasks: usize,
    run_queue_len: usize,
    active_conns: u32,
    max_conns: u32,
    cum_conns: u64,
    cum_reqs: u64,
) -> String {
    let pairs = show_info_pairs(start_time, pid, total_tasks, run_queue_len, active_conns, max_conns, cum_conns, cum_reqs);
    crate::stats_typed::render_info(&pairs, fmt)
}

/// This worker's identifier (`Worker_id`): a random UUID, drawn once.
/// Draws the identifier now, so the first `show info` or scrape does not read the file.
pub fn prewarm_worker_id() {
    worker_id();
}

fn worker_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/random/uuid").map(|u| u.trim().to_string()).unwrap_or_else(|_| "00000000-0000-4000-8000-000000000000".to_string())
    })
}

/// The `show info` fields in HAProxy's order. Fields HAProxy leaves out when unset
/// (`Master_id`) is left out: Ibex has no master process; `description` is there when
/// `global description` is set. Fields Ibex does not track (`Memmax_*`, the pool sizes, `Jobs`,
/// `Listeners`, `TotalBytesOut`, the SSL and compression rates, ...) print 0 where
/// HAProxy prints a measurement.
#[allow(clippy::too_many_arguments)]
/// When the process started, set by the first engine (the one `show info` and the Prometheus
/// scrape both count `Uptime_sec` from), and the scheduler's task counts as the last pass of
/// the engine loop saw them: a request rule answering a scrape cannot reach the scheduler.
static PROCESS_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
static SCHED_TASKS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static SCHED_RUNQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Records the engine's start time (the first one wins).
pub fn note_process_start(t: Instant) {
    let _ = PROCESS_START.set(t);
}

/// Records the scheduler's `Tasks` and `Run_queue` for [`process_info_pairs`].
pub fn note_sched(tasks: usize, run_queue: usize) {
    SCHED_TASKS.store(tasks, std::sync::atomic::Ordering::Relaxed);
    SCHED_RUNQ.store(run_queue, std::sync::atomic::Ordering::Relaxed);
}

/// Fills `p` with the `show info` pairs for the Prometheus scrape: the same function as the
/// CLI's, fed from the proxies' counters and the recorded start time and task counts, so the
/// numbers agree.
pub fn process_info_pairs(p: &mut InfoPairs, proxies: &[Proxy]) {
    use std::sync::atomic::Ordering::Relaxed;
    let (mut active_conns, mut max_conns, mut cum_conns, mut cum_reqs) = (0u32, 0u32, 0u64, 0u64);
    for px in proxies {
        active_conns += px.stats.iter().map(|s| s.act_conn.load(Relaxed)).sum::<u32>();
        max_conns += px.maxconn.get();
        cum_conns += px.stats.iter().map(|s| s.cum_conn.load(Relaxed)).sum::<u64>();
        cum_reqs += px.ids.tc.get().map_or(0, |c| c.fe.req_tot.load(Relaxed));
    }
    p.n = 0;
    fill_info_pairs(
        p,
        *PROCESS_START.get_or_init(Instant::now),
        std::process::id(),
        SCHED_TASKS.load(Relaxed),
        SCHED_RUNQ.load(Relaxed),
        active_conns,
        max_conns,
        cum_conns,
        cum_reqs,
    );
}

/// The `show info` pairs, held so that a refill reuses the values' storage: a scrape fills the
/// same one every time and allocates nothing once it has been through once.
#[derive(Default)]
pub struct InfoPairs {
    pub v: Vec<(&'static str, String)>,
    n: usize,
}

impl InfoPairs {
    fn put(&mut self, name: &'static str, val: std::fmt::Arguments<'_>) {
        use std::fmt::Write;
        if self.n == self.v.len() {
            self.v.push((name, String::with_capacity(32)));
        }
        let slot = &mut self.v[self.n];
        slot.0 = name;
        slot.1.clear();
        let _ = slot.1.write_fmt(val);
        self.n += 1;
    }

    /// The pairs of the last fill.
    #[must_use]
    pub fn pairs(&self) -> &[(&'static str, String)] {
        &self.v[..self.n]
    }

    /// Room for every pair, so that the first fill allocates nothing either.
    #[must_use]
    pub fn presized() -> Self {
        let mut p = InfoPairs::default();
        for _ in 0..96 {
            p.v.push(("", String::with_capacity(48)));
        }
        p
    }
}

fn show_info_pairs(
    start_time: Instant,
    pid: u32,
    total_tasks: usize,
    run_queue_len: usize,
    active_conns: u32,
    max_conns: u32,
    cum_conns: u64,
    cum_reqs: u64,
) -> Vec<(&'static str, String)> {
    let mut p = InfoPairs::default();
    fill_info_pairs(&mut p, start_time, pid, total_tasks, run_queue_len, active_conns, max_conns, cum_conns, cum_reqs);
    p.v.truncate(p.n);
    p.v
}

fn fill_info_pairs(
    p: &mut InfoPairs,
    start_time: Instant,
    pid: u32,
    total_tasks: usize,
    run_queue_len: usize,
    active_conns: u32,
    max_conns: u32,
    cum_conns: u64,
    cum_reqs: u64,
) {
    // `Ulimit-n` and `Maxsock`: as the startup settled them (`globalconn::apply_nofile_limit`),
    // or else the descriptors the process may hold (`getrlimit`).
    let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile).current.unwrap_or(0);
    let ulimit_n = crate::globalconn::ulimit_n().unwrap_or(nofile);
    let maxsock = crate::globalconn::maxsock_value().unwrap_or(nofile);
    // `global maxconn` and its configured ceiling, when there is one.
    let maxconn = if crate::globalconn::max() > 0 { crate::globalconn::max() } else { max_conns };
    let hard_maxconn = if crate::globalconn::hard() > 0 { crate::globalconn::hard() } else { max_conns };
    let nbthread = NBTHREAD.load(std::sync::atomic::Ordering::Relaxed).max(1);
    let total_secs = start_time.elapsed().as_secs();
    let (days, hours, mins, secs) = (total_secs / 86400, (total_secs % 86400) / 3600, (total_secs % 3600) / 60, total_secs % 60);
    let start_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().saturating_sub(total_secs));
    let idle_pct = cpu::get_idle_pct();
    let (pool_alloc, pool_used) = ibex_alloc::global_pool_registry().totals();
    p.put("Name", format_args!("{}", "Ibex"));
    p.put("Version", format_args!("{}", crate::version::VERSION));
    p.put("Release_date", format_args!("{}", crate::version::DATE));
    p.put("Nbthread", format_args!("{}", nbthread));
    p.put("Nbproc", format_args!("{}", "1"));
    p.put("Process_num", format_args!("{}", "1"));
    p.put("Pid", format_args!("{}", pid));
    p.put("Uptime", format_args!("{days}d {hours}h{mins:02}m{secs:02}s"));
    p.put("Uptime_sec", format_args!("{}", total_secs));
    p.put("Memmax_MB", format_args!("{}", crate::globalconn::memmax_mb()));
    p.put("PoolAlloc_MB", format_args!("{}", (pool_alloc / 1_048_576)));
    p.put("PoolUsed_MB", format_args!("{}", (pool_used / 1_048_576)));
    p.put("PoolFailed", format_args!("{}", ibex_alloc::global_pool_registry().failures()));
    p.put("Ulimit-n", format_args!("{}", ulimit_n));
    p.put("Maxsock", format_args!("{}", maxsock));
    p.put("Maxconn", format_args!("{}", maxconn));
    p.put("Hard_maxconn", format_args!("{}", hard_maxconn));
    p.put("CurrConns", format_args!("{}", active_conns));
    p.put("CumConns", format_args!("{}", cum_conns));
    p.put("CumReq", format_args!("{}", cum_reqs));
    p.put("MaxSslConns", format_args!("{}", "0"));
    p.put("CurrSslConns", format_args!("{}", SSL_CURR.load(std::sync::atomic::Ordering::Relaxed)));
    p.put("CumSslConns", format_args!("{}", SSL_CUM.load(std::sync::atomic::Ordering::Relaxed)));
    p.put("Maxpipes", format_args!("{}", "0"));
    p.put("PipesUsed", format_args!("{}", "0"));
    p.put("PipesFree", format_args!("{}", "0"));
    p.put("ConnRate", format_args!("{}", crate::engine::GLOBAL_CONN_RATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner).rate()));
    p.put("ConnRateLimit", format_args!("{}", "0"));
    p.put("MaxConnRate", format_args!("{}", crate::engine::MAX_CONN_RATE.load(std::sync::atomic::Ordering::Relaxed)));
    p.put("SessRate", format_args!("{}", crate::engine::GLOBAL_SESS_RATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner).rate()));
    p.put("SessRateLimit", format_args!("{}", "0"));
    p.put("MaxSessRate", format_args!("{}", crate::engine::MAX_SESS_RATE.load(std::sync::atomic::Ordering::Relaxed)));
    p.put("SslRate", format_args!("{}", SSL_RATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner).rate()));
    p.put("SslRateLimit", format_args!("{}", "0"));
    p.put("MaxSslRate", format_args!("{}", SSL_MAX.load(std::sync::atomic::Ordering::Relaxed)));
    p.put("SslFrontendKeyRate", format_args!("{}", "0"));
    p.put("SslFrontendMaxKeyRate", format_args!("{}", "0"));
    p.put("SslFrontendSessionReuse_pct", format_args!("{}", "0"));
    p.put("SslBackendKeyRate", format_args!("{}", "0"));
    p.put("SslBackendMaxKeyRate", format_args!("{}", "0"));
    p.put("SslCacheLookups", format_args!("{}", "0"));
    p.put("SslCacheMisses", format_args!("{}", "0"));
    p.put("CompressBpsIn", format_args!("{}", "0"));
    p.put("CompressBpsOut", format_args!("{}", "0"));
    p.put("CompressBpsRateLim", format_args!("{}", "0"));
    p.put("ZlibMemUsage", format_args!("{}", "0"));
    p.put("MaxZlibMemUsage", format_args!("{}", "0"));
    p.put("Tasks", format_args!("{}", total_tasks));
    p.put("Run_queue", format_args!("{}", run_queue_len));
    p.put("Idle_pct", format_args!("{}", idle_pct));
    crate::stats::with_node(|n| p.put("node", format_args!("{n}")));
    crate::stats::with_description(|d| if let Some(d) = d { p.put("description", format_args!("{d}")) });
    p.put("Stopping", format_args!("{}", "0"));
    p.put("Jobs", format_args!("{}", "0"));
    p.put("Unstoppable Jobs", format_args!("{}", "0"));
    p.put("Listeners", format_args!("{}", crate::globalconn::listeners()));
    p.put("ActivePeers", format_args!("{}", "0"));
    p.put("ConnectedPeers", format_args!("{}", "0"));
    p.put("DroppedLogs", format_args!("{}", crate::syslog::dropped_logs()));
    p.put("BusyPolling", format_args!("{}", "0"));
    p.put("FailedResolutions", format_args!("{}", "0"));
    p.put("TotalBytesOut", format_args!("{}", crate::raw::bytes_out()));
    p.put("TotalSplicedBytesOut", format_args!("{}", "0"));
    p.put("BytesOutRate", format_args!("{}", "0"));
    p.put("DebugCommandsIssued", format_args!("{}", "0"));
    p.put("CumRecvLogs", format_args!("{}", "0"));
    p.put("Build info", format_args!("{}", crate::version::VERSION));
    p.put("Memmax_bytes", format_args!("{}", (crate::globalconn::memmax_mb().wrapping_mul(1_048_576))));
    p.put("PoolAlloc_bytes", format_args!("{}", pool_alloc));
    p.put("PoolUsed_bytes", format_args!("{}", pool_used));
    p.put("Start_time_sec", format_args!("{}", start_sec));
    p.put("Tainted", format_args!("{}", "0"));
    p.put("TotalWarnings", format_args!("{}", "0"));
    p.put("MaxconnReached", format_args!("{}", crate::globalconn::reached()));
    p.put("BootTime_ms", format_args!("{}", "0"));
    p.put("Niced_tasks", format_args!("{}", "0"));
    p.put("CurrStreams", format_args!("{}", "0"));
    p.put("CumStreams", format_args!("{}", crate::stats::CUM_STREAMS.load(std::sync::atomic::Ordering::Relaxed)));
    p.put("BlockedTrafficWarnings", format_args!("{}", crate::watchdog::blocked_traffic_warnings()));
    p.put("PatternsAdded", format_args!("{}", "0"));
    p.put("PatternsFreed", format_args!("{}", "0"));
    p.put("NbThreadGroups", format_args!("{}", "1"));
    p.put("Worker_id", format_args!("{}", worker_id()));
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
    }
    r.set("eint", ld(&c.eint));
}

/// `algo`: the balance algorithm as `HAProxy` names it. `random` and the default
/// (no `balance` line) print `unknown` on HAProxy; Ibex does not tell the default from an
/// explicit `roundrobin`, and prints `roundrobin`.
fn balance_name(proxy: &Proxy) -> &'static str {
    use ibex_config::BalanceAlgorithm as B;
    match proxy.balance {
        B::RoundRobin => "roundrobin",
        B::Source => "source",
        B::Uri => "uri",
        B::Leastconn => "leastconn",
        B::StaticRr => "static-rr",
        B::First => "first",
        B::Random(_) => "unknown",
    }
}

pub(crate) fn write_frontend_row(out: &mut String, fmt: StatFormat, proxy: &Proxy, _pid: u32, iid: u32) {
    let c = proxy.ids.tc.get().map_or(&*EMPTY, |p| &p.fe);
    let http = proxy.mode == ibex_config::Mode::Http;
    let mut r = StatRow::new();
    r.set("pxname", &proxy.name);
    r.set("svname", "FRONTEND");
    r.set("scur", proxy.stats.iter().map(|s| s.act_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u32>());
    r.set("smax", proxy.stats.iter().map(|s| s.max_conn.load(std::sync::atomic::Ordering::Relaxed)).max().unwrap_or(0));
    r.set("slim", proxy.maxconn.get());
    let stot = proxy.stats.iter().map(|s| s.cum_conn.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>();
    // A connection whose TLS handshake failed is a `conn_tot` but never became a session.
    let failed_hs: u64 = proxy.stats.iter().map(|s| s.ssl_failed_hs.load(std::sync::atomic::Ordering::Relaxed)).sum();
    r.set("stot", stot.saturating_sub(failed_hs));
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
    r.set("conn_rate", proxy.stats.iter().map(|s| s.fe_conn_rate.rate()).sum::<u64>());
    r.set("conn_rate_max", u64::from(c.conn_rate_max.load(std::sync::atomic::Ordering::Relaxed)));
    r.set("conn_tot", stot);
    r.set("ssl_failed_handshake", proxy.stats.iter().map(|s| s.ssl_failed_hs.load(std::sync::atomic::Ordering::Relaxed)).sum::<u64>());
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
    r.set("dses", 0);
    r.set("wrew", 0);
    r.default_untracked('F', http, "");
    r.emit(out, fmt);
}

pub(crate) fn write_server_row(
    out: &mut String,
    fmt: StatFormat,
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
    // Everything below is written into the row's strings as it is read: a `show stat` row of
    // a scrape allocates nothing (T369).
    struct Word<'a>(Option<&'a ServerCheckState>, &'static str, &'a str);
    impl std::fmt::Display for Word<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                Some(c) => write!(f, "{}", crate::check::StatusWord(c)),
                None if self.2.is_empty() => f.write_str(self.1),
                None => write!(f, "MAINT (via {})", self.2),
            }
        }
    }
    struct Star<'a>(bool, &'a str);
    impl std::fmt::Display for Star<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.0 {
                f.write_str("* ")?;
            }
            f.write_str(self.1)
        }
    }
    struct Opt<T>(Option<T>);
    impl<T: std::fmt::Display> std::fmt::Display for Opt<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.as_ref().map_or(Ok(()), |v| write!(f, "{v}"))
        }
    }
    let status_str = if let Some(c) = check_state {
        Word(Some(c), "", "")
    } else {
        let s = proxy.server_statuses.get(s_idx).map(|s| ServerStatus::from(s.load(std::sync::atomic::Ordering::Relaxed))).unwrap_or(ServerStatus::Up);
        let tracker = !crate::track::tracked_label(proxy, s_idx).is_empty();
        match s {
            ServerStatus::Up if tracker => Word(None, "UP", ""),
            ServerStatus::Up => Word(None, "no check", ""),
            ServerStatus::Down => Word(None, "DOWN", ""),
            ServerStatus::Drain => Word(None, "DRAIN", ""),
            // The maintenance of a tracker's target says where it comes from.
            ServerStatus::Maint if crate::track::inherited(proxy, s_idx) => Word(None, "", crate::track::tracked_label(proxy, s_idx)),
            ServerStatus::Maint => Word(None, "MAINT", ""),
        }
    };
    let (chkfail, chkdown) = check_state.map_or((0, 0), |c| (c.failed_checks, c.down_transitions));
    // A star while a check is running; the code only for the statuses that carry data
    // (L57DATA and above); the info text as `last_chk`.
    let check_status = Opt(check_state.map(|c| Star(c.in_progress, c.last_status_code)));
    let check_code = Opt(check_state.filter(|c| c.carries_code()).map(|c| c.http_code.unwrap_or(0)));
    let last_chk = check_state.and_then(|c| c.last_status_info.as_deref()).unwrap_or("");
    // From the first completed check on (`HCHK_STATUS_CHECKED`), not while `INI`.
    let check_duration = Opt(check_state.filter(|c| c.last_status_code != "INI").map(|c| c.check_duration_ms));
    // `get_check_status_description`: the fixed text of the status.
    let check_desc = check_state.map_or("", |c| c.last_status_desc);
    let has_check = check_state.is_some();

    let is_backup = proxy.server_backups.get(s_idx).copied().unwrap_or(false);
    let (act, bck) = if is_backup { (0, 1) } else { (1, 0) };
    let scur = proxy.server_actconn.get(s_idx).map(|a| a.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0);
    let weight = proxy.server_weights.get(s_idx).unwrap_or(1);
    let slim = Opt(proxy.server_maxconn.get(s_idx));

    let mut r = StatRow::new();
    r.set("pxname", &proxy.name);
    r.set("svname", srv_name);
    let pc = proxy.ids.tc.get();
    let c = pc.and_then(|p| p.srv.get(s_idx)).unwrap_or(&EMPTY);
    r.set("qcur", 0);
    r.set("qmax", 0);
    r.set("scur", scur);
    r.set("smax", c.smax.load(std::sync::atomic::Ordering::Relaxed).max(scur));
    r.set("slim", slim);
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
    // A server in maintenance has its checks paused: no check column (`CHK_ST_PAUSED`).
    if has_check && !check_state.is_some_and(|c| c.status == ServerStatus::Maint) {
        r.set("check_status", check_status);
        r.set("check_code", check_code);
        r.set("check_duration", check_duration);
        r.set("last_chk", last_chk);
        r.set("check_desc", check_desc);
    }
    r.set("addr", srv_addr);
    r.default_untracked('S', proxy.mode == ibex_config::Mode::Http, "");
    r.emit(out, fmt);
}

pub(crate) fn write_backend_row(out: &mut String, fmt: StatFormat, proxy: &Proxy, _pid: u32, iid: u32) {
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
    r.default_untracked('B', http, balance_name(proxy));
    r.emit(out, fmt);
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
    format_show_stat_as(proxies, checks, pid, iid_filter, type_filter, sid_filter, StatFormat::Csv)
}

/// [`format_show_stat_filtered`] in the given format: CSV, `typed` lines or JSON.
#[must_use]
pub fn format_show_stat_as(
    proxies: &[Proxy],
    checks: &[ServerCheckState],
    pid: u32,
    iid_filter: Option<i32>,
    type_filter: Option<i32>,
    sid_filter: Option<i32>,
    fmt: StatFormat,
) -> String {
    let mut out = String::with_capacity(4096);
    if fmt == StatFormat::Csv {
        out.push_str(&stats_csv_header());
    }

    let match_type = |type_val: i32| -> bool {
        match type_filter {
            None | Some(-1 | 33_554_431 | 0x00FF_FFFF) => true,
            Some(t) => (t & (1 << type_val)) != 0,
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
            write_frontend_row(&mut out, fmt, proxy, pid, iid);
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
                    .find(|c| c.proxy() == p_idx && c.server() == s_idx);
                write_server_row(&mut out, fmt, proxy, s_idx, check_state, pid, iid, sid);
            }
        }

        if proxy.has_backend
            && match_type(1)
            && (sid_filter.is_none() || sid_filter == Some(-1) || sid_filter == Some(0))
        {
            write_backend_row(&mut out, fmt, proxy, pid, iid);
        }
    }

    if fmt == StatFormat::Json {
        return format!("[{out}]\n");
    }
    out
}

#[cfg(test)]
    /// S3: a dropped row goes to the `stat_row` pool and the next row takes it, emptied.
    #[test]
    fn a_dropped_stat_row_is_taken_again_by_the_next() {
        let mut row = StatRow::new();
        row.set("pxname", "fe");
        let ptr = row.fields.as_ptr();
        drop(row);
        assert_eq!(ROW_POOL.local_count(), 1);
        let again = StatRow::new();
        assert_eq!(again.fields.as_ptr(), ptr, "the same strings came back");
        assert!(again.fields[0].is_empty());
        assert_eq!(ROW_POOL.local_count(), 0);
    }

mod tests {
    use super::*;

    /// `SslConnCount::default()` counts a TLS connection as `new()` does. No oracle value:
    /// the type is a private RAII guard; the observable counters (`CurrSslConns`,
    /// `CumSslConns`) are tested through show info. Deltas are `>=` because the statics
    /// are shared with every test of this binary.
    #[test]
    fn ssl_conn_count_default_counts_like_new() {
        use std::sync::atomic::Ordering::Relaxed;
        let cum = SSL_CUM.load(Relaxed);
        let guard = SslConnCount::default();
        assert!(SSL_CUM.load(Relaxed) > cum);
        assert!(SSL_CURR.load(Relaxed) >= 1);
        drop(guard);
    }
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
            desc: None,
            balance: ibex_config::BalanceAlgorithm::RoundRobin,
            default_backend: None,
            use_backends: Vec::new(),
            use_servers: Vec::new(),
            force_be_switch: Vec::new(),
            disabled_backends: std::sync::Arc::default(),
            monitor: None,
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
            rules: Box::default(),
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
            extra_log: None,
            dont_log_null: false,
            ignore_probes: false,
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

    fn host_name_for_test() -> String {
        rustix::system::uname().nodename().to_string_lossy().trim().to_string()
    }

    /// With no `global node` the host name is given, with no `global description` none; a lock
    /// that cannot be taken gives no description, and a thread's pool of rows holds eight.
    #[test]
    fn identity_defaults_and_a_full_row_pool() {
        assert!(with_node(|n| !n.is_empty() && n == n.trim()));
        assert_eq!(with_description(|d| d.map(str::to_string)), None);
        let held: (Option<String>, Option<String>) = (None, Some("d".into()));
        assert_eq!(description_of(Ok::<_, ()>(&held), |d| d.map(str::to_string)), Some("d".to_string()));
        assert_eq!(description_of(Err::<&(Option<String>, Option<String>), ()>(()), |d| d.map(str::to_string)), None);
        assert_eq!(node_of(Ok::<_, ()>(&held), |n| n.to_string()), host_name_for_test());
        assert_eq!(node_of(Err::<&(Option<String>, Option<String>), ()>(()), |n| n.to_string()), host_name_for_test());
        let named: (Option<String>, Option<String>) = (Some("n1".into()), None);
        assert_eq!(node_of(Ok::<_, ()>(&named), |n| n.to_string()), "n1");
        let rows: Vec<StatRow> = (0..10).map(|_| StatRow::new()).collect();
        drop(rows);
    }
}
