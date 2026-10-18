// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The Prometheus exporter, `http-request use-service prometheus-exporter` (T368).
//!
//! HAProxy's `addons/promex/service-prometheus.c` walks the stats columns and prints each one
//! that has a Prometheus name, for every frontend, backend and server. This does the same
//! over the same sources as the CLI: the process section is `show info`
//! ([`crate::stats::process_info_pairs`]: memory, pools, `Memmax`, connections) and the
//! proxy sections are `show stat` rows, so a number here is the number there. A column
//! Ibex does not track (the per-connection-pool gauges, `lastsess`, the byte counters by
//! direction, the aggregate check states, agent checks) has no family: it is left out, not
//! printed as 0 (docs/differences.md lists them). The names, types and HELP texts are in
//! `promex_tables.rs`, generated from a HAProxy 3.5-dev8 built with `USE_PROMEX=1`.
//!
//! A scrape allocates: the `show info` pairs and one `show stat` CSV with its field offsets
//! (what `show stat` itself costs), in a handful of buffers whose number does not depend on
//! the traffic. The rendering into the caller's `String` allocates nothing once that has
//! room.

use crate::check::ServerCheckState;
use crate::engine::Proxy;
use crate::promex_tables::{Metric, BACK, FRONT, PROCESS, SRV};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::LazyLock;

pub const SCOPE_GLOBAL: u8 = 1;
pub const SCOPE_FRONT: u8 = 2;
pub const SCOPE_BACK: u8 = 4;
pub const SCOPE_SERVER: u8 = 8;
/// Accepted (`scope=listener`), nothing in it: Ibex has no per-listener stats.
pub const SCOPE_LISTENER: u8 = 16;
/// `scope=resolvers`: accepted, nothing in it: Ibex has no resolvers section to count.
pub const SCOPE_RESOLVERS: u8 = 32;
pub const SCOPE_ALL: u8 = 63;

/// What the request's query string asked for (`promex_parse_uri`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub scopes: u8,
    /// `no-maint`: servers in maintenance are left out.
    pub no_maint: bool,
    /// `desc-labels`: a `desc` label on what has a `description`.
    pub desc_labels: bool,
    /// `metrics=a,-b`: the full names asked for / refused. Empty `include` with
    /// `include_by_default` means everything not excluded.
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub include_by_default: bool,
}

impl Default for Query {
    fn default() -> Self {
        Query { scopes: SCOPE_ALL, no_maint: false, desc_labels: false, include: Vec::new(), exclude: Vec::new(), include_by_default: true }
    }
}

/// `url_decode(.., 1)`: `%XX` and `+`; `None` on a bad escape.
fn url_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let h = b.get(i + 1..i + 3)?;
                let v = u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
                out.push(v);
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Reads the query string of `uri`. `None` is HAProxy's `400`: a `scope` with no value or a
/// scope that does not exist, a bad escape, a value holding a second `=`.
#[must_use]
pub fn parse_query(uri: &str) -> Option<Query> {
    let mut q = Query::default();
    let Some((_, qs)) = uri.split_once('?') else { return Some(q) };
    let qs = qs.split('#').next().unwrap_or("");
    let mut scope_seen = false;
    for part in qs.split('&') {
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (part, None),
        };
        if v.is_some_and(|v| v.contains('=')) {
            return None;
        }
        let key = url_decode(k)?;
        let val = match v {
            Some(v) => Some(url_decode(v)?),
            None => None,
        };
        match key.as_str() {
            "scope" => {
                if !scope_seen {
                    scope_seen = true;
                    q.scopes = 0;
                }
                match val.as_deref()? {
                    "" => q.scopes = 0,
                    "*" => q.scopes = SCOPE_ALL,
                    "global" => q.scopes |= SCOPE_GLOBAL,
                    "server" => q.scopes |= SCOPE_SERVER,
                    "backend" => q.scopes |= SCOPE_BACK,
                    "frontend" => q.scopes |= SCOPE_FRONT,
                    "listener" => q.scopes |= SCOPE_LISTENER,
                    "resolvers" => q.scopes |= SCOPE_RESOLVERS,
                    _ => return None,
                }
            }
            "metrics" => {
                for m in val?.split(',') {
                    if let Some(x) = m.strip_prefix('-') {
                        if !x.is_empty() {
                            q.exclude.push(x.to_string());
                        }
                    } else if !m.is_empty() {
                        q.include_by_default = false;
                        q.include.push(m.to_string());
                    }
                }
            }
            "no-maint" => q.no_maint = true,
            "desc-labels" => q.desc_labels = true,
            // `extra-counters` adds the stats modules' counters (`h1`, `h2`, `ssl`, ...),
            // which Ibex does not count: accepted, and nothing is added.
            _ => {}
        }
    }
    Some(q)
}

impl Query {
    /// `promex_filter_metric`: is the family `name` refused by `metrics=`?
    fn refuses(&self, name: &str) -> bool {
        if self.include.is_empty() && self.exclude.is_empty() {
            return false;
        }
        if self.exclude.iter().any(|e| e == name) {
            return true;
        }
        !self.include.iter().any(|i| i == name) && !self.include_by_default
    }
}

fn header(out: &mut String, name: &str, help: &str, ty: &str) {
    let _ = write!(out, "# HELP {name} {help}\n# TYPE {name} {ty}\n");
}

fn ty(counter: bool) -> &'static str {
    if counter {
        "counter"
    } else {
        "gauge"
    }
}

/// The value of a `show info` pair as a sample value: a number, or `NaN`.
fn num(v: &str) -> &str {
    if v.is_empty() || v.parse::<f64>().is_err() {
        "NaN"
    } else {
        v
    }
}

fn render_process(proxies: &[Proxy], q: &Query, out: &mut String) {
    let pairs = crate::stats::process_info_pairs(proxies);
    let desc = crate::stats::description();
    let get = |col: &str| pairs.iter().find(|(k, _)| *k == col).map(|(_, v)| v.as_str());
    let desc_label = |out: &mut String, first: bool| {
        if let (Some(d), true) = (desc.as_deref(), q.desc_labels) {
            let _ = write!(out, "{}desc=\"{d}\"", if first { "" } else { "," });
        }
    };
    for m in PROCESS {
        if q.refuses(m.name) {
            continue;
        }
        // A column `show info` does not print has no family here.
        let Some(v) = get(m.col) else { continue };
        let label_name = match m.name {
            "haproxy_process_node" => Some("node"),
            "haproxy_process_worker_id" => Some("worker_id"),
            "haproxy_process_build_info" => Some("version"),
            _ => None,
        };
        if let Some(l) = label_name {
            if v.is_empty() {
                continue;
            }
            header(out, m.name, m.help, "gauge");
            let _ = write!(out, "{}{{{l}=\"{v}\"", m.name);
            if q.desc_labels {
                desc_label(out, false);
            }
            out.push_str("} 1\n");
            continue;
        }
        header(out, m.name, m.help, ty(m.counter));
        let _ = write!(out, "{}", m.name);
        if q.desc_labels && desc.is_some() {
            out.push('{');
            desc_label(out, true);
            out.push('}');
        }
        let _ = writeln!(out, " {}", num(v));
    }
    if let Some(d) = desc.as_deref() {
        let name = "haproxy_process_description";
        if !q.refuses(name) {
            header(out, name, "Worker process's description string", "gauge");
            let _ = writeln!(out, "{name}{{desc=\"{d}\"}} 1");
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Front,
    Back,
    Server,
}

struct Row {
    p_idx: usize,
    kind: Kind,
    /// Index of the row's first field start in `Rows::offs`.
    off: usize,
}

/// The `show stat` rows of every proxy, with where each field of each begins.
struct Rows {
    csv: String,
    rows: Vec<Row>,
    offs: Vec<u32>,
}

static COLS: LazyLock<HashMap<&'static str, usize>> =
    LazyLock::new(|| crate::stats::STAT_FIELDS.iter().enumerate().map(|(i, n)| (*n, i)).collect());

impl Rows {
    fn collect(proxies: &[Proxy], checks: &[ServerCheckState], pid: u32) -> Rows {
        let mut csv = String::with_capacity(4096);
        let mut rows = Vec::new();
        let mut offs: Vec<u32> = Vec::new();
        let mut order: Vec<usize> = (0..proxies.len()).collect();
        order.sort_by_key(|&i| proxies[i].ids.decl);
        let mut mark = |csv: &String, p_idx: usize, kind: Kind, from: usize, rows: &mut Vec<Row>, offs: &mut Vec<u32>| {
            let off = offs.len();
            offs.push(u32::try_from(from).unwrap_or(u32::MAX));
            for (i, b) in csv.as_bytes()[from..].iter().enumerate() {
                if *b == b',' {
                    offs.push(u32::try_from(from + i + 1).unwrap_or(u32::MAX));
                }
            }
            // The row ends at its LF: the sentinel is one past it, so that the last field
            // ends where `-1` puts it.
            offs.push(u32::try_from(csv.len()).unwrap_or(u32::MAX));
            rows.push(Row { p_idx, kind, off });
        };
        for p_idx in order {
            let proxy = &proxies[p_idx];
            let iid = proxy.ids.iid;
            if proxy.has_frontend {
                let from = csv.len();
                crate::stats::write_frontend_row(&mut csv, crate::stats_typed::StatFormat::Csv, proxy, pid, iid);
                mark(&csv, p_idx, Kind::Front, from, &mut rows, &mut offs);
            }
            for s_idx in 0..proxy.servers.len() {
                let from = csv.len();
                let check = checks.iter().find(|c| c.proxy() == p_idx && c.server() == s_idx);
                crate::stats::write_server_row(&mut csv, crate::stats_typed::StatFormat::Csv, proxy, s_idx, check, pid, iid, proxy.server_puid(s_idx));
                mark(&csv, p_idx, Kind::Server, from, &mut rows, &mut offs);
            }
            if proxy.has_backend {
                let from = csv.len();
                crate::stats::write_backend_row(&mut csv, crate::stats_typed::StatFormat::Csv, proxy, pid, iid);
                mark(&csv, p_idx, Kind::Back, from, &mut rows, &mut offs);
            }
        }
        Rows { csv, rows, offs }
    }

    /// Field `col` of row `r`; empty when the row has no such column.
    fn field(&self, r: &Row, col: usize) -> &str {
        match (self.offs.get(r.off + col), self.offs.get(r.off + col + 1)) {
            (Some(&a), Some(&b)) if b > a => &self.csv[a as usize..(b as usize).saturating_sub(1).max(a as usize)],
            _ => "",
        }
    }
}

/// Columns whose value Ibex does not keep: `show stat` prints the default `HAProxy` prints for
/// an object that saw nothing (`StatRow::default_untracked`), which a scrape must not pass for a
/// measurement. The families of these columns are not served.
const UNTRACKED: &[&str] = &[
    "intercepted",
    "cache_hint_hits",
    "agg_server_status",
    "agg_server_check_status",
    "agg_check_status",
    "lastsess",
    "priv_idle_cur",
    "srv_icur",
    "idle_conn_cur",
    "safe_conn_cur",
    "used_conn_cur",
    "need_conn_est",
    "reqbin",
    "reqbout",
    "resbin",
    "resbout",
    "check_status",
    "agent_status",
    "agent_code",
    "agent_duration",
];

/// Columns that exist for an HTTP proxy only (`px->mode != PR_MODE_HTTP` skips them).
const HTTP_ONLY: &[&str] = &[
    "req_rate_max",
    "req_tot",
    "intercepted",
    "cache_lookups",
    "cache_hits",
    "cache_hint_hits",
    "comp_in",
    "comp_out",
    "comp_byp",
    "comp_rsp",
    "hrsp_1xx",
];

const TIME_AVG: &[&str] = &["qtime", "ctime", "rtime", "ttime", "qt_max", "ct_max", "rt_max", "tt_max", "check_duration"];

/// `UP` / `DOWN` / `MAINT` / `DRAIN` / `NOLB` of a `show stat` status word.
fn server_state(status: &str) -> &'static str {
    if status.starts_with("MAINT") {
        "MAINT"
    } else if status.starts_with("DRAIN") {
        "DRAIN"
    } else if status.starts_with("NOLB") {
        "NOLB"
    } else if status.starts_with("UP") {
        "UP"
    } else {
        "DOWN"
    }
}

fn render_objects(rows: &Rows, proxies: &[Proxy], table: &[Metric], kind: Kind, q: &Query, out: &mut String) {
    let status_col = COLS.get("status").copied().unwrap_or(0);
    for m in table {
        if q.refuses(m.name) || UNTRACKED.contains(&m.col) {
            continue;
        }
        let Some(&col) = COLS.get(m.col) else { continue };
        let mut first = true;
        for r in rows.rows.iter().filter(|r| r.kind == kind) {
            let proxy = &proxies[r.p_idx];
            if HTTP_ONLY.contains(&m.col) && proxy.mode != ibex_config::Mode::Http {
                continue;
            }
            let value = rows.field(r, col);
            let status = rows.field(r, status_col);
            if kind == Kind::Server && q.no_maint && status.starts_with("MAINT") {
                continue;
            }
            // A server without a check has no check code, and a check that never ran no duration.
            let checked = COLS.get("check_status").is_some_and(|&c| !rows.field(r, c).is_empty());
            if kind == Kind::Server && (m.col == "check_code" && !checked || m.col == "check_duration" && value.is_empty()) {
                continue;
            }
            // `check_code` is 0 for a check that got no layer 5-7 answer (`status < L57DATA`).
            let value = if m.col == "check_code" && value.is_empty() { "0" } else { value };
            let pname = rows.field(r, 0);
            let svname = rows.field(r, 1);
            let desc = if q.desc_labels { proxy.desc.as_deref() } else { None };
            let mut labels = String::new();
            let _ = write!(labels, "proxy=\"{pname}\"");
            if let Some(d) = desc {
                let _ = write!(labels, ",desc=\"{d}\"");
            }
            if kind == Kind::Server {
                let _ = write!(labels, ",server=\"{svname}\"");
            }
            let head = |out: &mut String, first: &mut bool, counter: bool| {
                if *first {
                    header(out, m.name, m.help, ty(counter));
                    *first = false;
                }
            };
            if m.col == "status" {
                let states: &[&str] = match kind {
                    Kind::Server => &["DOWN", "UP", "MAINT", "DRAIN", "NOLB"],
                    _ => &["DOWN", "UP"],
                };
                let cur = match kind {
                    Kind::Server => server_state(status),
                    Kind::Front => {
                        if status.starts_with("STOP") {
                            "DOWN"
                        } else {
                            "UP"
                        }
                    }
                    Kind::Back => {
                        if status.starts_with("UP") {
                            "UP"
                        } else {
                            "DOWN"
                        }
                    }
                };
                head(out, &mut first, false);
                for s in states {
                    let _ = writeln!(out, "{}{{{labels},state=\"{s}\"}} {}", m.name, u8::from(*s == cur));
                }
                continue;
            }
            if m.col == "hrsp_1xx" {
                head(out, &mut first, true);
                for (i, code) in ["1xx", "2xx", "3xx", "4xx", "5xx", "other"].iter().enumerate() {
                    let c = COLS.get(["hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other"][i]).copied().unwrap_or(0);
                    let _ = writeln!(out, "{}{{{labels},code=\"{code}\"}} {}", m.name, num(rows.field(r, c)));
                }
                continue;
            }
            // The type of a family is the type of its first value: an empty one (no check
            // on the first server) makes the family a gauge, as HAProxy prints it.
            let counter = m.counter && !value.is_empty();
            head(out, &mut first, counter);
            if TIME_AVG.contains(&m.col) && !value.is_empty() {
                let ms: f64 = value.parse().unwrap_or(0.0);
                let _ = writeln!(out, "{}{{{labels}}} {:.6}", m.name, ms / 1000.0);
            } else {
                let _ = writeln!(out, "{}{{{labels}}} {}", m.name, num(value));
            }
        }
    }
}

/// Renders a scrape of the proxies, checks and process into `out`.
pub fn render(proxies: &[Proxy], checks: &[ServerCheckState], pid: u32, q: &Query, out: &mut String) {
    if q.scopes & SCOPE_GLOBAL != 0 {
        render_process(proxies, q, out);
    }
    if q.scopes & (SCOPE_FRONT | SCOPE_BACK | SCOPE_SERVER) != 0 {
        let rows = Rows::collect(proxies, checks, pid);
        if q.scopes & SCOPE_FRONT != 0 {
            render_objects(&rows, proxies, FRONT, Kind::Front, q, out);
        }
        if q.scopes & SCOPE_BACK != 0 {
            render_objects(&rows, proxies, BACK, Kind::Back, q, out);
        }
        if q.scopes & SCOPE_SERVER != 0 {
            render_objects(&rows, proxies, SRV, Kind::Server, q, out);
        }
    }
}

/// The reply to a scrape: HAProxy's head (`cache-control: no-cache`, the text exposition
/// type, chunked) and the body in one chunk. `HEAD` gets the head only; a query string
/// HAProxy refuses gets its `400`.
#[must_use]
pub fn scrape_reply(proxies: &[Proxy], checks: &[ServerCheckState], pid: u32, method: &str, uri: &str, close: bool) -> Vec<u8> {
    let Some(q) = parse_query(uri) else {
        return b"HTTP/1.1 400 Bad request\r\ncontent-length: 90\r\ncache-control: no-cache\r\ncontent-type: text/html\r\nconnection: close\r\n\r\n<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n".to_vec();
    };
    let mut body = String::with_capacity(32 * 1024);
    render(proxies, checks, pid, &q, &mut body);
    let mut out = Vec::with_capacity(body.len() + 256);
    out.extend_from_slice(b"HTTP/1.1 200 OK\r\ncache-control: no-cache\r\ncontent-type: text/plain; version=0.0.4\r\ntransfer-encoding: chunked\r\n");
    if close {
        out.extend_from_slice(b"connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    if method != "HEAD" {
        if !body.is_empty() {
            out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            out.extend_from_slice(body.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
    }
    out
}
