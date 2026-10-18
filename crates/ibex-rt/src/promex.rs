// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The Prometheus exporter, `http-request use-service prometheus-exporter` (T368, T369).
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
//! The scrape is a resumable producer, as HAProxy's applet is: [`scrape_chunk`] formats the
//! next lines into a per-thread scratch string (HAProxy's `trash`), copies whole lines into the
//! destination -- the session's response buffer, a pool chunk -- as one HTTP chunk, and returns
//! when it is full; the [`Cursor`] (a few integers kept in the session) says where to go on.
//! Memory is one buffer and the scratch whatever the number of servers, and nothing is
//! allocated per scrape once [`prewarm`] has run at start-up.

use crate::check::ServerCheckState;
use crate::engine::Proxy;
use crate::promex_tables::{Metric, BACK, FRONT, PROCESS, SRV};
use std::cell::RefCell;
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

const MAX_METRICS_PARAMS: usize = 8;
/// The longest query value (after decoding) that is understood; a longer one is a 400.
const MAX_VALUE: usize = 512;

/// What the request's query string asked for (`promex_parse_uri`), borrowing the URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query<'a> {
    pub scopes: u8,
    /// `no-maint`: servers in maintenance are left out.
    pub no_maint: bool,
    /// `desc-labels`: a `desc` label on what has a `description`.
    pub desc_labels: bool,
    /// The raw values of the `metrics=` parameters (`a,-b`), decoded when read.
    metrics: [&'a str; MAX_METRICS_PARAMS],
    n_metrics: usize,
}

impl Default for Query<'_> {
    fn default() -> Self {
        Query { scopes: SCOPE_ALL, no_maint: false, desc_labels: false, metrics: [""; MAX_METRICS_PARAMS], n_metrics: 0 }
    }
}

/// `url_decode(.., 1)` into `buf`: `%XX` and `+`; `None` on a bad escape or a value that does
/// not fit.
fn url_decode<'b>(s: &str, buf: &'b mut [u8; MAX_VALUE]) -> Option<&'b str> {
    let b = s.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        let c = match b[i] {
            b'+' => b' ',
            b'%' => {
                let h = b.get(i + 1..i + 3)?;
                let v = u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
                i += 2;
                v
            }
            c => c,
        };
        *buf.get_mut(n)? = c;
        n += 1;
        i += 1;
    }
    std::str::from_utf8(&buf[..n]).ok()
}

/// Reads the query string of `uri`, allocating nothing. `None` is HAProxy's `400`: a `scope`
/// with no value or a scope that does not exist, a bad escape, a value holding a second `=`
/// (and, here, more than 8 `metrics=` or a value over 512 bytes).
#[must_use]
pub fn parse_query(uri: &str) -> Option<Query<'_>> {
    let mut q = Query::default();
    let Some((_, qs)) = uri.split_once('?') else { return Some(q) };
    let qs = qs.split('#').next().unwrap_or("");
    let mut scope_seen = false;
    let (mut kb, mut vb) = ([0u8; MAX_VALUE], [0u8; MAX_VALUE]);
    for part in qs.split('&') {
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (part, None),
        };
        if v.is_some_and(|v| v.contains('=')) {
            return None;
        }
        let key = url_decode(k, &mut kb)?;
        let val = match v {
            Some(v) => Some(url_decode(v, &mut vb)?),
            None => None,
        };
        match key {
            "scope" => {
                if !scope_seen {
                    scope_seen = true;
                    q.scopes = 0;
                }
                match val? {
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
                val?;
                if q.n_metrics == MAX_METRICS_PARAMS {
                    return None;
                }
                q.metrics[q.n_metrics] = v?;
                q.n_metrics += 1;
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

impl Query<'_> {
    /// `promex_filter_metric`: is the family `name` refused by `metrics=`?
    fn refuses(&self, name: &str) -> bool {
        if self.n_metrics == 0 {
            return false;
        }
        let (mut positive, mut included, mut excluded) = (false, false, false);
        let mut buf = [0u8; MAX_VALUE];
        for raw in &self.metrics[..self.n_metrics] {
            let Some(val) = url_decode(raw, &mut buf) else { continue };
            for m in val.split(',') {
                if let Some(x) = m.strip_prefix('-') {
                    excluded |= x == name;
                } else if !m.is_empty() {
                    positive = true;
                    included |= m == name;
                }
            }
        }
        excluded || (positive && !included)
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

static COLS: LazyLock<HashMap<&'static str, usize>> =
    LazyLock::new(|| crate::stats::STAT_FIELDS.iter().enumerate().map(|(i, n)| (*n, i)).collect());


#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Front,
    Back,
    Server,
}

const PH_PROCESS: u8 = 0;
const PH_FRONT: u8 = 1;
const PH_BACK: u8 = 2;
const PH_SERVER: u8 = 3;
const PH_DONE: u8 = 4;

/// Where a scrape stands: a few integers, kept in the session between two fills of its
/// response buffer (HAProxy keeps the same in the applet's context).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    phase: u8,
    /// The metric in the phase's table.
    m: u16,
    /// The proxy (by declaration order) and server of the next row.
    pos: u32,
    s: u32,
    /// Whether the metric's HELP/TYPE lines are still to be printed.
    first: bool,
    /// The closing chunk has been written.
    pub finished: bool,
}

impl Cursor {
    #[must_use]
    pub const fn start() -> Cursor {
        Cursor { phase: PH_PROCESS, m: 0, pos: 0, s: 0, first: true, finished: false }
    }

    fn next_phase(&mut self) {
        self.phase += 1;
        self.m = 0;
        self.pos = 0;
        self.s = 0;
        self.first = true;
    }

    fn next_metric(&mut self) {
        self.m += 1;
        self.pos = 0;
        self.s = 0;
        self.first = true;
    }
}

thread_local! {
    /// HAProxy's `trash`: a unit (the lines of one metric for one object) is formatted here
    /// and copied whole into the response buffer, or left for the next fill.
    static TRASH: RefCell<String> = const { RefCell::new(String::new()) };
    /// The `show stat` row of the object being printed, and where each of its fields begins.
    static ROW: RefCell<(String, Vec<u32>)> = const { RefCell::new((String::new(), Vec::new())) };
    static INFO: RefCell<crate::stats::InfoPairs> = RefCell::new(crate::stats::InfoPairs::default());
}

const TRASH_CAP: usize = 8192;
const ROW_CAP: usize = 16384;

/// Allocates what a scrape uses on this thread, without rendering one: the scratch strings, the
/// `show info` values, a `show stat` row (strings of 64 bytes) and boxes for 16 concurrent scrapes.
/// Called when the engine starts, on the worker's thread, only if a `use-service
/// prometheus-exporter` rule is configured. A value that outgrows its string, or a 17th
/// concurrent scrape, allocates once.
pub fn prewarm() {
    LazyLock::force(&COLS);
    TRASH.with_borrow_mut(|t| t.reserve(TRASH_CAP));
    ROW.with_borrow_mut(|(s, o)| {
        s.reserve(ROW_CAP);
        o.reserve(256);
    });
    INFO.with_borrow_mut(|i| *i = crate::stats::InfoPairs::presized());
    crate::stats::reserve_row_pool();
    crate::proxy::reserve_scrape_boxes(16);
}

/// Position `pos` of the proxies in declaration order (`show stat`'s order).
fn proxy_at(proxies: &[Proxy], sorted: bool, pos: usize) -> Option<usize> {
    if sorted {
        return (pos < proxies.len()).then_some(pos);
    }
    (0..proxies.len()).find(|&i| proxies.iter().filter(|p| p.ids.decl < proxies[i].ids.decl).count() == pos)
}

struct Ctx<'a> {
    proxies: &'a [Proxy],
    checks: &'a [ServerCheckState],
    pid: u32,
    sorted: bool,
}

/// Formats the next unit into `out` and moves `cur` past it. `false` when there is nothing
/// more. A unit can be empty (a row the metric skips).
fn produce(cur: &mut Cursor, c: &Ctx<'_>, q: &Query<'_>, info: &crate::stats::InfoPairs, out: &mut String) -> bool {
    loop {
        match cur.phase {
            PH_PROCESS => {
                if q.scopes & SCOPE_GLOBAL == 0 {
                    cur.next_phase();
                    continue;
                }
                let idx = cur.m as usize;
                if idx > PROCESS.len() {
                    cur.next_phase();
                    continue;
                }
                cur.next_metric();
                process_unit(idx, q, info, out);
                return true;
            }
            PH_FRONT | PH_BACK | PH_SERVER => {
                let (kind, table, scope) = match cur.phase {
                    PH_FRONT => (Kind::Front, FRONT, SCOPE_FRONT),
                    PH_BACK => (Kind::Back, BACK, SCOPE_BACK),
                    _ => (Kind::Server, SRV, SCOPE_SERVER),
                };
                if q.scopes & scope == 0 {
                    cur.next_phase();
                    continue;
                }
                let Some(m) = table.get(cur.m as usize) else {
                    cur.next_phase();
                    continue;
                };
                if q.refuses(m.name) || UNTRACKED.contains(&m.col) || !COLS.contains_key(m.col) {
                    cur.next_metric();
                    continue;
                }
                // The next row of this kind.
                let mut found = None;
                while (cur.pos as usize) < c.proxies.len() {
                    let Some(p_idx) = proxy_at(c.proxies, c.sorted, cur.pos as usize) else { break };
                    let px = &c.proxies[p_idx];
                    match kind {
                        Kind::Front | Kind::Back => {
                            let has = if kind == Kind::Front { px.has_frontend } else { px.has_backend };
                            cur.pos += 1;
                            if has {
                                found = Some((p_idx, 0));
                                break;
                            }
                        }
                        Kind::Server => {
                            if (cur.s as usize) < px.servers.len() {
                                found = Some((p_idx, cur.s as usize));
                                cur.s += 1;
                                break;
                            }
                            cur.pos += 1;
                            cur.s = 0;
                        }
                    }
                }
                let Some((p_idx, s_idx)) = found else {
                    cur.next_metric();
                    continue;
                };
                let before = out.len();
                let first = cur.first;
                if object_unit(c, q, m, kind, p_idx, s_idx, first, out) {
                    cur.first = false;
                }
                if out.len() > before {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

fn process_unit(idx: usize, q: &Query<'_>, info: &crate::stats::InfoPairs, out: &mut String) {
    let pairs = info.pairs();
    crate::stats::with_description(|desc| {
        if idx == PROCESS.len() {
            let name = "haproxy_process_description";
            if let (Some(d), false) = (desc, q.refuses(name)) {
                header(out, name, "Worker process's description string", "gauge");
                let _ = writeln!(out, "{name}{{desc=\"{d}\"}} 1");
            }
            return;
        }
        let m = &PROCESS[idx];
        if q.refuses(m.name) {
            return;
        }
        // A column `show info` does not print has no family here.
        let Some((_, v)) = pairs.iter().find(|(k, _)| *k == m.col) else { return };
        let label_name = match m.name {
            "haproxy_process_node" => Some("node"),
            "haproxy_process_worker_id" => Some("worker_id"),
            "haproxy_process_build_info" => Some("version"),
            _ => None,
        };
        let desc = desc.filter(|_| q.desc_labels);
        if let Some(l) = label_name {
            if v.is_empty() {
                return;
            }
            header(out, m.name, m.help, "gauge");
            let _ = write!(out, "{}{{{l}=\"{v}\"", m.name);
            if let Some(d) = desc {
                let _ = write!(out, ",desc=\"{d}\"");
            }
            out.push_str("} 1\n");
            return;
        }
        header(out, m.name, m.help, ty(m.counter));
        out.push_str(m.name);
        if let Some(d) = desc {
            let _ = write!(out, "{{desc=\"{d}\"}}");
        }
        let _ = writeln!(out, " {}", num(v));
    });
}

fn gen_row(c: &Ctx<'_>, kind: Kind, p_idx: usize, s_idx: usize, buf: &mut String, offs: &mut Vec<u32>) {
    use crate::stats_typed::StatFormat::Csv;
    let proxy = &c.proxies[p_idx];
    let iid = proxy.ids.iid;
    buf.clear();
    match kind {
        Kind::Front => crate::stats::write_frontend_row(buf, Csv, proxy, c.pid, iid),
        Kind::Back => crate::stats::write_backend_row(buf, Csv, proxy, c.pid, iid),
        Kind::Server => {
            let check = c.checks.iter().find(|k| k.proxy() == p_idx && k.server() == s_idx);
            crate::stats::write_server_row(buf, Csv, proxy, s_idx, check, c.pid, iid, proxy.server_puid(s_idx));
        }
    }
    offs.clear();
    offs.push(0);
    for (i, b) in buf.as_bytes().iter().enumerate() {
        if *b == b',' {
            offs.push(u32::try_from(i + 1).unwrap_or(u32::MAX));
        }
    }
    offs.push(u32::try_from(buf.len()).unwrap_or(u32::MAX));
}

fn field<'r>(buf: &'r str, offs: &[u32], col: usize) -> &'r str {
    match (offs.get(col), offs.get(col + 1)) {
        (Some(&a), Some(&b)) if b > a => &buf[a as usize..(b as usize).saturating_sub(1).max(a as usize)],
        _ => "",
    }
}

/// The lines of metric `m` for one object into `out`; whether a sample was printed (the
/// metric's header is, with the first one).
#[allow(clippy::too_many_arguments)]
fn object_unit(c: &Ctx<'_>, q: &Query<'_>, m: &Metric, kind: Kind, p_idx: usize, s_idx: usize, first: bool, out: &mut String) -> bool {
    let proxy = &c.proxies[p_idx];
    if HTTP_ONLY.contains(&m.col) && proxy.mode != ibex_config::Mode::Http {
        return false;
    }
    let col = COLS[m.col];
    ROW.with_borrow_mut(|(buf, offs)| {
        gen_row(c, kind, p_idx, s_idx, buf, offs);
        let value = field(buf, offs, col);
        let status = field(buf, offs, COLS["status"]);
        if kind == Kind::Server && q.no_maint && status.starts_with("MAINT") {
            return false;
        }
        // A server without a check has no check code, and a check that never ran no duration.
        let checked = !field(buf, offs, COLS["check_status"]).is_empty();
        if kind == Kind::Server && (m.col == "check_code" && !checked || m.col == "check_duration" && value.is_empty()) {
            return false;
        }
        // `check_code` is 0 for a check that got no layer 5-7 answer (`status < L57DATA`).
        let value = if m.col == "check_code" && value.is_empty() { "0" } else { value };
        let pname = field(buf, offs, 0);
        let svname = field(buf, offs, 1);
        let desc = if q.desc_labels { proxy.desc.as_deref() } else { None };
        let labels = |out: &mut String| {
            let _ = write!(out, "proxy=\"{pname}\"");
            if let Some(d) = desc {
                let _ = write!(out, ",desc=\"{d}\"");
            }
            if kind == Kind::Server {
                let _ = write!(out, ",server=\"{svname}\"");
            }
        };
        let hdr = |out: &mut String, counter: bool| {
            if first {
                header(out, m.name, m.help, ty(counter));
            }
        };
        if m.col == "status" {
            let (states, cur): (&[&str], &str) = match kind {
                Kind::Server => (&["DOWN", "UP", "MAINT", "DRAIN", "NOLB"], server_state(status)),
                Kind::Front => (&["DOWN", "UP"], if status.starts_with("STOP") { "DOWN" } else { "UP" }),
                Kind::Back => (&["DOWN", "UP"], if status.starts_with("UP") { "UP" } else { "DOWN" }),
            };
            hdr(out, false);
            for st in states {
                let _ = write!(out, "{}{{", m.name);
                labels(out);
                let _ = writeln!(out, ",state=\"{st}\"}} {}", u8::from(*st == cur));
            }
            return true;
        }
        if m.col == "hrsp_1xx" {
            hdr(out, true);
            for (code, name) in ["1xx", "2xx", "3xx", "4xx", "5xx", "other"].iter().zip(["hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other"]) {
                let _ = write!(out, "{}{{", m.name);
                labels(out);
                let _ = writeln!(out, ",code=\"{code}\"}} {}", num(field(buf, offs, COLS[name])));
            }
            return true;
        }
        // The type of a family is the type of its first value: an empty one (no check
        // on the first server) makes the family a gauge, as HAProxy prints it.
        hdr(out, m.counter && !value.is_empty());
        let _ = write!(out, "{}{{", m.name);
        labels(out);
        if TIME_AVG.contains(&m.col) && !value.is_empty() {
            let ms: f64 = value.parse().unwrap_or(0.0);
            let _ = writeln!(out, "}} {:.6}", ms / 1000.0);
        } else {
            let _ = writeln!(out, "}} {}", num(value));
        }
        true
    })
}

/// The reply head of a scrape: HAProxy's (`cache-control: no-cache`, the text exposition type,
/// chunked). The body follows in chunks from [`scrape_chunk`].
pub const REPLY_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\ncache-control: no-cache\r\ncontent-type: text/plain; version=0.0.4\r\ntransfer-encoding: chunked\r\n\r\n";

/// HAProxy's 400 for a query string it refuses.
pub const BAD_QUERY: &[u8] = b"HTTP/1.1 400 Bad request\r\ncontent-length: 90\r\ncache-control: no-cache\r\ncontent-type: text/html\r\nconnection: close\r\n\r\n<html><body><h1>400 Bad request</h1>\nYour browser sent an invalid request.\n</body></html>\n";

/// The room a chunk needs ahead of its data (`<hex>\r\n`) and after it (`\r\n`).
const CHUNK_PRE: usize = 8;
const CHUNK_POST: usize = 2;
/// A fill is not attempted with less room than this.
pub const MIN_ROOM: usize = 1024;

/// Writes the next chunk of the scrape of `uri` into `dst`, from `cur`, and returns the bytes
/// written (0 when `dst` has too little room or the scrape is over). Whole units only: the one
/// that does not fit waits for the next call. The closing `0` chunk is written once everything
/// else has been, and sets `cur.finished`. Allocates nothing once [`prewarm`] has run.
pub fn scrape_chunk(cur: &mut Cursor, proxies: &[Proxy], checks: &[ServerCheckState], pid: u32, uri: &str, dst: &mut [u8]) -> usize {
    use std::io::Write as _;
    if cur.finished || dst.len() < MIN_ROOM {
        return 0;
    }
    let Some(q) = parse_query(uri) else {
        cur.finished = true;
        return 0;
    };
    let sorted = proxies.windows(2).all(|w| w[0].ids.decl < w[1].ids.decl);
    let c = Ctx { proxies, checks, pid, sorted };
    let room = dst.len() - CHUNK_PRE - CHUNK_POST;
    let mut w = 0usize;
    if cur.phase != PH_DONE {
        if q.scopes & SCOPE_GLOBAL != 0 && cur.phase == PH_PROCESS {
            INFO.with_borrow_mut(|i| crate::stats::process_info_pairs(i, proxies));
        }
        INFO.with_borrow(|info| {
            TRASH.with_borrow_mut(|trash| {
                while cur.phase != PH_DONE {
                    let prev = *cur;
                    trash.clear();
                    if !produce(cur, &c, &q, info, trash) {
                        cur.phase = PH_DONE;
                        break;
                    }
                    if w + trash.len() > room {
                        *cur = prev;
                        // A unit that cannot fit even an empty buffer would never be sent.
                        if w == 0 {
                            cur.phase = PH_DONE;
                        }
                        break;
                    }
                    dst[CHUNK_PRE + w..CHUNK_PRE + w + trash.len()].copy_from_slice(trash.as_bytes());
                    w += trash.len();
                }
            });
        });
    }
    if w > 0 {
        let mut pre = [0u8; CHUNK_PRE];
        let mut p = &mut pre[..];
        let _ = write!(p, "{w:x}\r\n");
        let plen = CHUNK_PRE - p.len();
        dst.copy_within(CHUNK_PRE..CHUNK_PRE + w, plen);
        dst[..plen].copy_from_slice(&pre[..plen]);
        dst[plen + w..plen + w + 2].copy_from_slice(b"\r\n");
        return plen + w + 2;
    }
    if cur.phase == PH_DONE {
        dst[..5].copy_from_slice(b"0\r\n\r\n");
        cur.finished = true;
        return 5;
    }
    0
}

/// Fills the session's response buffer with the next chunk of its scrape, if the buffer has
/// room; called on every pass over the session while `sess.scrape` is set.
pub fn pump(sess: &mut crate::proxy::TcpSession, proxies: &[Proxy], checks: &[ServerCheckState], pid: u32) {
    let Some(mut cur) = sess.scrape() else { return };
    if sess.rep.writable().is_empty() && sess.rep.len() < sess.rep.capacity() {
        sess.rep.compact();
    }
    let uri = sess.req_uri.as_deref().unwrap_or("");
    let n = scrape_chunk(&mut cur, proxies, checks, pid, uri, sess.rep.writable());
    sess.rep.commit(n);
    sess.set_scrape(if cur.finished { None } else { Some(cur) });
}

/// Whether `uri` is a query string HAProxy answers with a 400.
#[must_use]
pub fn query_ok(uri: &str) -> bool {
    parse_query(uri).is_some()
}
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

