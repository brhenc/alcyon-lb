// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The per-transaction counters `show stat` reports for a frontend, a backend and each
//! server: the response classes, request and byte totals, error counts and the averaged
//! timings (T165).
//!
//! They are made on first use ([`Proxy::tc`]): a configuration of sixty thousand backends
//! that never saw a request pays one empty cell each. Under `tune.ibex.counters shared` (the
//! default) one set is shared by every worker; each counter is a relaxed atomic that a stream
//! touches once, when it ends. Under `per-thread` (T582,
//! `docs/design/per-thread-counters-2026-11-02.md`) the counters a stream writes
//! ([`HotRow`]) are one row per object per worker ([`CounterTable`]), written by that worker
//! alone without a locked instruction; the readers sum the rows ([`snapshot`]).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// A counted add: the shared-memory read-modify-write of the stream accounting
/// ([`crate::probe`] counts them in a debug build).
#[inline]
pub fn add(a: &AtomicU64, v: u64) {
    crate::probe::rmw();
    a.fetch_add(v, Ordering::Relaxed);
}

/// [`add`] that does nothing for a zero: a byte count of an empty direction.
#[inline]
pub fn add_nz(a: &AtomicU64, v: u64) {
    if v != 0 {
        add(a, v);
    }
}

/// A counted maximum.
#[inline]
pub fn max(a: &AtomicU32, v: u32) {
    // A maximum is beaten rarely: one plain load, no locked instruction, when it is not.
    if v > a.load(Ordering::Relaxed) {
        crate::probe::rmw();
        a.fetch_max(v, Ordering::Relaxed);
    }
}

/// Samples a running average spans (`TIME_STATS_SAMPLES`).
const SAMPLES: u64 = 512;

/// The four timings of a row, in [`HotRow::tsum`] and [`TxnCounters::tmax`]: queue, connect,
/// response, total (`qtime`, `ctime`, `rtime`, `ttime`).
pub const QTIME: usize = 0;
pub const CTIME: usize = 1;
pub const RTIME: usize = 2;
pub const TTIME: usize = 3;

/// Adds a sample of `ms` to the running sum `sum`, as `HAProxy` keeps one
/// (`swrate_add_dynamic`), `counted` being the requests (or connections) the row has served:
/// the average divides by them up to [`SAMPLES`] (`stats_fill_sv_stats`). A load and a store:
/// one writer at a time is the rule in both modes (a race in `shared` loses a sample).
#[inline]
pub fn swrate_add(sum: &AtomicU64, ms: u64, counted: u64) {
    let window = if counted > SAMPLES { SAMPLES } else { 0 };
    let s = sum.load(Ordering::Relaxed);
    let decay = if window > 0 { s.div_ceil(window) } else { 0 };
    sum.store(s - decay + ms, Ordering::Relaxed);
}

/// The average of a running sum, rounded up as `swrate_avg` does.
#[must_use]
pub fn swrate_avg(sum: u64, counted: u64) -> u64 {
    let n = if counted > 0 && counted < SAMPLES { counted } else { SAMPLES };
    sum.div_ceil(n)
}

/// The counters a stream writes when it ends, of one frontend, backend or server
/// (`docs/design/per-thread-counters-2026-11-02.md` §2). With `tune.ibex.counters shared`
/// there is one, [`TxnCounters::hot`], written by every thread with locked adds; with
/// `per-thread` each thread has its own in its [`Slab`], written with a plain load and store,
/// and the readers sum them ([`snapshot`]).
#[derive(Default, Debug)]
pub struct HotRow {
    /// Responses by class: 1xx to 5xx, then anything else (`hrsp_*`).
    pub hrsp: [AtomicU64; 6],
    /// Requests (`req_tot`).
    pub req_tot: AtomicU64,
    /// Streams, or for a server the connections tried, retries included (`stot`).
    pub stot: AtomicU64,
    /// Times the load balancer chose it (`lbtot`).
    pub lbtot: AtomicU64,
    /// Attempts that made a new server connection, failed ones included (`connect`), and
    /// attempts that used one that already existed (`reuse`).
    pub connect: AtomicU64,
    pub reuse: AtomicU64,
    /// Request bytes as parsed, response bytes as the server sent them (`bin`, `bout`).
    pub bin: AtomicU64,
    pub bout: AtomicU64,
    pub cli_abrt: AtomicU64,
    pub srv_abrt: AtomicU64,
    /// Response failures (`eresp`). Connection failures (`econ`) are in
    /// `ProxyStats::failed_conn` (backend) and `Proxy::server_retr` (server).
    pub eresp: AtomicU64,
    /// Requests the frontend could not parse (`ereq`).
    pub ereq: AtomicU64,
    /// Internal errors (`eint`): streams a panic ended (T447).
    pub eint: AtomicU64,
    /// The running sums of the timings ([`QTIME`] ... [`TTIME`], [`swrate_add`]).
    pub tsum: [AtomicU64; 4],
    /// When a stream last ended on it, in [`now_ms`] (0: never).
    pub last_sess: AtomicU64,
    /// Streams ending per second on it (`rate`), for a backend or a server.
    pub sess_rate: crate::engine::RateCtr,
    /// The greatest sessions per second seen (`rate_max`). For a frontend it follows the
    /// proxy's session rate and stays in [`TxnCounters::hot`]; for a backend or a server, per
    /// thread, the reader sums the threads' peaks (Q3: an upper bound when they were not
    /// simultaneous, exact with one thread, as `MaxConnRate`).
    pub rate_max: AtomicU32,
}

/// The [`HotRow::hrsp`] class of a response status: 1xx to 5xx, then anything else.
#[inline]
#[must_use]
pub fn status_class(status: i64) -> usize {
    match status {
        100..=199 => 0,
        200..=299 => 1,
        300..=399 => 2,
        400..=499 => 3,
        500..=599 => 4,
        _ => 5,
    }
}

impl HotRow {
    /// Counts a response status in its class.
    #[inline]
    pub fn count_status<W: Write>(&self, w: W, status: i64) {
        w.add(&self.hrsp[status_class(status)], 1);
    }

    /// Zeroes everything but the session rate (`clear counters all`), as the shared set is.
    fn clear(&self) {
        for c in self.hrsp.iter().chain(&self.tsum).chain([
            &self.req_tot,
            &self.stot,
            &self.lbtot,
            &self.connect,
            &self.reuse,
            &self.bin,
            &self.bout,
            &self.cli_abrt,
            &self.srv_abrt,
            &self.eresp,
            &self.ereq,
            &self.eint,
        ]) {
            c.store(0, Ordering::Relaxed);
        }
        self.rate_max.store(0, Ordering::Relaxed);
    }
}

/// How the accounting writes a row: a counted locked add on the shared set, or a load and
/// a store on the thread's own row. Chosen once per stream end ([`Rows`]), so a site costs
/// no branch.
pub trait Write: Copy {
    fn add(self, a: &AtomicU64, v: u64);
    /// A maximum: written only when beaten.
    fn max(self, a: &AtomicU32, v: u32);
}

/// [`Write`] on the shared set.
#[derive(Clone, Copy, Debug)]
pub struct Shared;

impl Write for Shared {
    #[inline]
    fn add(self, a: &AtomicU64, v: u64) {
        add(a, v);
    }
    #[inline]
    fn max(self, a: &AtomicU32, v: u32) {
        max(a, v);
    }
}

/// [`Write`] on a row only this thread writes: no lock prefix, no line another core writes.
#[derive(Clone, Copy, Debug)]
pub struct Owned;

impl Write for Owned {
    #[inline]
    fn add(self, a: &AtomicU64, v: u64) {
        a.store(a.load(Ordering::Relaxed).wrapping_add(v), Ordering::Relaxed);
    }
    #[inline]
    fn max(self, a: &AtomicU32, v: u32) {
        if v > a.load(Ordering::Relaxed) {
            a.store(v, Ordering::Relaxed);
        }
    }
}

/// Where the accounting of this thread finds the row of an object, and how it writes it.
pub trait Rows<'a>: Copy {
    type W: Write;
    fn w(self) -> Self::W;
    /// Row `k` of proxy `p`: [`FE`], [`BE`], or `SRV + i` for server `i`.
    fn row(self, p: &'a crate::engine::Proxy, k: usize) -> Option<&'a HotRow>;
    /// [`Rows::row`] and the object's shared part (its maxima).
    fn obj(self, p: &'a crate::engine::Proxy, k: usize) -> Option<(&'a HotRow, &'a TxnCounters)>;
}

/// The shared part of object `k` of `p`.
#[inline]
fn cold(p: &crate::engine::Proxy, k: usize) -> Option<&TxnCounters> {
    let c = p.txn_counters();
    match k {
        FE => Some(&c.fe),
        BE => Some(&c.be),
        i => c.srv.get(i - SRV),
    }
}

/// Row [`Rows::row`] of a proxy as a frontend, as a backend, and of its first server.
pub const FE: usize = 0;
pub const BE: usize = 1;
pub const SRV: usize = 2;

/// The shared sets ([`TxnCounters::hot`]): `tune.ibex.counters shared`, or a thread that has
/// no slab.
#[derive(Clone, Copy, Debug)]
pub struct SharedRows;

impl<'a> Rows<'a> for SharedRows {
    type W = Shared;
    #[inline]
    fn w(self) -> Shared {
        Shared
    }
    #[inline]
    fn row(self, p: &'a crate::engine::Proxy, k: usize) -> Option<&'a HotRow> {
        cold(p, k).map(|c| &c.hot)
    }
    #[inline]
    fn obj(self, p: &'a crate::engine::Proxy, k: usize) -> Option<(&'a HotRow, &'a TxnCounters)> {
        cold(p, k).map(|c| (&c.hot, c))
    }
}

/// This thread's slab of a [`CounterTable`].
#[derive(Clone, Copy, Debug)]
pub struct OwnRows<'a> {
    /// The table's [`CounterTable::spans`] and the slab's rows, loaded once per stream.
    spans: &'a [(u32, u32)],
    rows: &'a [HotRow],
}

impl<'a> Rows<'a> for OwnRows<'a> {
    type W = Owned;
    #[inline]
    fn w(self) -> Owned {
        Owned
    }
    #[inline]
    fn row(self, p: &'a crate::engine::Proxy, k: usize) -> Option<&'a HotRow> {
        // `k` is in the proxy's span: its servers are the ones the table was made for (the
        // shared sets answer `None` past them, which the callers never ask). Out of the slab,
        // `None`; never another thread's memory.
        let &(base, len) = self.spans.get(p.id as usize)?;
        debug_assert!(k < len as usize, "row {k} of a proxy of {len}");
        self.rows.get(base as usize + k)
    }
    #[inline]
    fn obj(self, p: &'a crate::engine::Proxy, k: usize) -> Option<(&'a HotRow, &'a TxnCounters)> {
        Some((self.row(p, k)?, cold(p, k)?))
    }
}

/// The rows this thread writes for the proxies of `any` (any proxy of the list: they share
/// one table): its slab under `per-thread`, else the shared sets. Its rows of a proxy that
/// `clear counters` cleared since are zeroed first (one shared load when none was).
#[inline]
#[must_use]
pub fn own_rows(any: &crate::engine::Proxy) -> Option<OwnRows<'_>> {
    let table = any.ids.rows.as_deref()?;
    let slab = table.slabs.get(crate::engine::worker_id())?.get()?;
    let cleared = table.cleared.load(Ordering::Acquire);
    if cleared != slab.cleared_seen.load(Ordering::Relaxed) {
        slab.catch_up(table, cleared);
    }
    Some(OwnRows { spans: &table.spans, rows: &slab.rows })
}

/// The counters of one frontend, one backend or one server: the per-stream ones
/// ([`HotRow`], shared here under `tune.ibex.counters shared`) and those written rarely,
/// which stay one shared copy in every mode: the maxima (written only when beaten) and the
/// server state.
#[derive(Default, Debug)]
// One cache line boundary per set, so a frontend's counters and a backend's do not share lines.
#[repr(align(64))]
pub struct TxnCounters {
    pub hot: HotRow,
    /// The greatest of each timing ([`QTIME`] ... [`TTIME`]: `qtime_max` ...).
    pub tmax: [AtomicU32; 4],
    /// The greatest requests per second seen (`req_rate_max`).
    pub req_rate_max: AtomicU32,
    /// The greatest connections per second seen (`conn_rate_max`): every accepted connection,
    /// a failed TLS handshake included.
    pub conn_rate_max: AtomicU32,
    /// The most streams it served at once, as seen when one ended (`smax`).
    pub smax: AtomicU32,
    /// Times a check took it down (`chkdown`), for a server.
    pub chkdown: AtomicU64,
    /// A server's last state change in [`now_ms`] (0: none since the start), when it went
    /// down (0: it is not) and the time it has been down before that, in milliseconds.
    pub last_chg: AtomicU64,
    pub down_since: AtomicU64,
    pub downtime_ms: AtomicU64,
}

impl TxnCounters {
    /// Counts a response status in its class, on the shared set.
    pub fn count_status(&self, status: i64) {
        self.hot.count_status(Shared, status);
    }

    /// Seconds since `stamp` (a [`now_ms`] value), or `None` when it was never set.
    #[must_use]
    pub fn since_secs(stamp: u64) -> Option<u64> {
        (stamp != 0).then(|| now_ms().saturating_sub(stamp) / 1000)
    }

    /// A state change of a server: from `was_down` to `down` (`lastchg`, `downtime`).
    pub fn state_changed(&self, was_down: bool, down: bool) {
        let now = now_ms();
        self.last_chg.store(now, Ordering::Relaxed);
        if down && !was_down {
            self.chkdown.fetch_add(1, Ordering::Relaxed);
            self.down_since.store(now, Ordering::Relaxed);
        } else if was_down && !down {
            let since = self.down_since.swap(0, Ordering::Relaxed);
            if since != 0 {
                self.downtime_ms.fetch_add(now.saturating_sub(since), Ordering::Relaxed);
            }
        }
    }

    /// The seconds spent down, the present spell included (`downtime`).
    #[must_use]
    pub fn downtime_secs(&self) -> u64 {
        let since = self.down_since.load(Ordering::Relaxed);
        let open = if since == 0 { 0 } else { now_ms().saturating_sub(since) };
        (self.downtime_ms.load(Ordering::Relaxed) + open) / 1000
    }

    /// Zeroes the maxima only (`clear counters` without `all`); `smax` shows at least the
    /// current sessions again. The per-thread rows' `rate_max` go with [`CounterTable::clear`].
    pub fn clear_max(&self) {
        self.hot.rate_max.store(0, Ordering::Relaxed);
        self.smax.store(0, Ordering::Relaxed);
        self.req_rate_max.store(0, Ordering::Relaxed);
        self.conn_rate_max.store(0, Ordering::Relaxed);
    }

    /// Zeroes everything (`clear counters`); the per-thread rows go with [`CounterTable::clear`].
    pub fn clear(&self) {
        self.hot.clear();
        for t in &self.tmax {
            t.store(0, Ordering::Relaxed);
        }
        self.clear_max();
    }
}

/// Milliseconds since the first call, never 0, on the loop's clock for the pass
/// ([`crate::txnlog::loop_now`]: `HAProxy`'s `now_ms`, read once per pass; a clock read
/// where no loop runs). The rate counters of a request read it five times (T550 Q2).
#[must_use]
pub fn now_ms() -> u64 {
    match crate::txnlog::loop_ms() {
        0 => ms_at(crate::txnlog::loop_now()),
        ms => ms,
    }
}

/// [`now_ms`] for the instant `t`.
#[must_use]
pub fn ms_at(t: Instant) -> u64 {
    static EPOCH: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    t.saturating_duration_since(*EPOCH).as_millis() as u64 + 1
}

/// A proxy's counters: as a frontend, as a backend, and one set per server.
#[derive(Debug)]
pub struct ProxyCounters {
    pub fe: TxnCounters,
    pub be: TxnCounters,
    pub srv: Box<[TxnCounters]>,
    /// Server state-change lines waiting to be written ([`crate::srvlog`]).
    pub srv_events: crate::srvlog::Queue,
    /// Operator changes to checked servers waiting for the owner of the checks
    /// ([`crate::track::CheckOps`], T593).
    pub check_ops: crate::track::CheckOps,
    /// What the stats pages of the other workers read of the checks ([`crate::track::CheckViews`], T597).
    pub check_views: crate::track::CheckViews,
}

impl ProxyCounters {
    #[must_use]
    pub fn new(servers: usize) -> Self {
        ProxyCounters { fe: TxnCounters::default(), be: TxnCounters::default(), srv: (0..servers).map(|_| TxnCounters::default()).collect(), srv_events: crate::srvlog::Queue::default(), check_ops: crate::track::CheckOps::default(), check_views: crate::track::CheckViews::default() }
    }
}

/// Rows of every worker's [`Slab`], for `show pools` (pool `counters`): allocated is the rows
/// that exist (the two guard rows of each slab included), used the rows of objects.
pub static COUNTERS_POOL: ibex_alloc::ArenaStats =
    ibex_alloc::ArenaStats::new("counters", std::mem::size_of::<HotRow>(), std::mem::align_of::<HotRow>(), file!(), line!());

/// `show pools` provider for the `counters` pool: listed only once a slab exists
/// (`tune.ibex.counters per-thread`), so `shared` prints `HAProxy`'s list.
#[must_use]
pub fn counters_pool_stats() -> Option<ibex_alloc::PoolHead> {
    let head = COUNTERS_POOL.head();
    (head.allocated > 0).then_some(head)
}

/// The per-thread counter rows of `tune.ibex.counters per-thread` (design §2): one [`Slab`]
/// per worker, each holding a [`HotRow`] for every frontend, backend and server, at a place
/// fixed when the configuration is loaded. Built with the proxies, shared by them
/// ([`crate::engine::ProxyIdInfo::rows`]); each worker fills its own slab when it starts
/// ([`CounterTable::start_worker`]), so the request path never allocates.
#[derive(Debug)]
pub struct CounterTable {
    /// Where proxy `p`'s rows start in a slab (after the guard row), and how many it has.
    spans: Box<[(u32, u32)]>,
    /// Per proxy, bumped by `clear counters`: the clears of everything in the high half, the
    /// clears of the maxima in the low one. A slab whose rows of the proxy are from an older
    /// value reads as zero (or as no maxima), and its owner zeroes them before it next
    /// writes: no thread writes another's slab.
    epochs: Box<[AtomicU64]>,
    /// Bumped after any of [`Self::epochs`]: an owner looks at the proxies' only when it moved.
    cleared: AtomicU64,
    slabs: Box<[std::sync::OnceLock<Slab>]>,
}

/// One clear of everything in [`CounterTable::epochs`] (which clears the maxima too).
const CLEAR_ALL: u64 = (1 << 32) | 1;

impl CounterTable {
    /// The table of `proxies` (`2 + servers` rows each) for `threads` workers.
    #[must_use]
    pub fn new(proxies: &[crate::engine::Proxy], threads: usize) -> Self {
        let mut spans = Vec::with_capacity(proxies.len());
        let mut at = 1u32;
        for p in proxies {
            let n = u32::try_from(SRV + p.servers.len()).unwrap_or(u32::MAX);
            spans.push((at, n));
            at = at.saturating_add(n);
        }
        CounterTable {
            spans: spans.into_boxed_slice(),
            epochs: proxies.iter().map(|_| AtomicU64::new(0)).collect(),
            cleared: AtomicU64::new(0),
            slabs: (0..threads.max(1)).map(|_| std::sync::OnceLock::new()).collect(),
        }
    }

    /// Rows a slab holds, the two guard rows included.
    #[must_use]
    pub fn slab_rows(&self) -> usize {
        self.spans.last().map_or(2, |&(b, n)| (b + n) as usize + 1)
    }

    /// Bytes of every worker's slab: what the startup notice prints.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.slab_rows() * std::mem::size_of::<HotRow>() * self.slabs.len()
    }

    #[must_use]
    pub fn threads(&self) -> usize {
        self.slabs.len()
    }

    /// Makes the slab of worker `worker` (design Q4: eager, fallible, no cap). A worker past
    /// the table's threads has none and counts on the shared sets.
    ///
    /// # Errors
    ///
    /// The allocator refused the slab: the message names its size.
    pub fn start_worker(&self, worker: usize) -> std::io::Result<()> {
        let Some(cell) = self.slabs.get(worker) else { return Ok(()) };
        if cell.get().is_some() {
            return Ok(());
        }
        let n = self.slab_rows();
        let mut rows = Vec::new();
        let mut seen = Vec::new();
        if rows.try_reserve_exact(n).is_err() || seen.try_reserve_exact(self.epochs.len()).is_err() {
            return Err(std::io::Error::other(format!(
                "tune.ibex.counters per-thread: cannot allocate the {} bytes of thread {}'s counter rows",
                n * std::mem::size_of::<HotRow>(),
                worker + 1
            )));
        }
        rows.extend((0..n).map(|_| HotRow::default()));
        let cleared = AtomicU64::new(self.cleared.load(Ordering::Acquire));
        seen.extend(self.epochs.iter().map(|e| AtomicU64::new(e.load(Ordering::Relaxed))));
        let mut slab = Slab { rows: rows.into_boxed_slice(), seen: seen.into_boxed_slice(), cleared_seen: cleared, published: ibex_alloc::arena::Published::default() };
        let mut last = slab.published;
        COUNTERS_POOL.publish_arena::<HotRow>(&mut last, &slab);
        slab.published = last;
        let _ = cell.set(slab);
        Ok(())
    }

    /// `clear counters all` (`all`) or `clear counters` of proxy `p`: each owner zeroes its
    /// own rows when it next counts on them, the readers count them as zero meanwhile.
    /// `p` is a proxy's id: the table was made from the whole proxy list, which never changes
    /// after (`Proxies` is shared and frozen), so every id has its epoch and span.
    pub fn clear(&self, p: usize, all: bool) {
        debug_assert!(p < self.epochs.len(), "proxy {p} of a table of {}", self.epochs.len());
        self.epochs[p].fetch_add(if all { CLEAR_ALL } else { 1 }, Ordering::Relaxed);
        self.cleared.fetch_add(1, Ordering::Release);
    }

    /// The rows of object `k` of proxy `p` in every slab that has them, with whether the
    /// slab's maxima of the proxy are current; a slab whose totals were cleared since it last
    /// wrote them is left out. The session rate is not cleared: it is in `rate` of every slab.
    fn each(&self, p: usize, k: usize, mut f: impl FnMut(&HotRow, bool, bool)) {
        // `p` is in range as in [`Self::clear`].
        debug_assert!(p < self.spans.len(), "proxy {p} of a table of {}", self.spans.len());
        // Every proxy has a frontend and a backend row whatever its sections, and the readers
        // ask for servers below `servers.len()` (`show stat`, the stats page, Prometheus), the
        // count the span was made with (Ibex has no `add server`).
        let ((base, n), epoch) = (self.spans[p], &self.epochs[p]);
        debug_assert!(k < n as usize, "row {k} of a proxy of {n}");
        let at = base as usize + k;
        let want = epoch.load(Ordering::Relaxed);
        for slab in self.slabs.iter().filter_map(std::sync::OnceLock::get) {
            let seen = slab.seen[p].load(Ordering::Relaxed);
            f(&slab.rows[at], seen >> 32 == want >> 32, seen == want);
        }
    }
}

/// One worker's rows ([`CounterTable`]): written by that worker alone, read by any.
#[derive(Debug)]
pub struct Slab {
    /// A guard row, the rows of every proxy, a guard row: the slab's first and last cache
    /// lines hold nothing another thread writes.
    rows: Box<[HotRow]>,
    /// Per proxy, the [`CounterTable::epochs`] value its rows here belong to.
    seen: Box<[AtomicU64]>,
    /// The [`CounterTable::cleared`] the slab caught up with.
    cleared_seen: AtomicU64,
    published: ibex_alloc::arena::Published,
}

impl Slab {
    /// Zeroes this thread's rows of every proxy `clear counters` cleared since it last looked
    /// (`cleared` being [`CounterTable::cleared`] as just read). The owner's call only.
    #[cold]
    #[inline(never)]
    fn catch_up(&self, table: &CounterTable, cleared: u64) {
        for ((epoch, seen), &(base, n)) in table.epochs.iter().zip(&self.seen).zip(&table.spans) {
            let want = epoch.load(Ordering::Relaxed);
            let had = seen.load(Ordering::Relaxed);
            if want == had {
                continue;
            }
            for r in self.rows.get(base as usize..(base + n) as usize).unwrap_or(&[]) {
                if had >> 32 == want >> 32 {
                    r.rate_max.store(0, Ordering::Relaxed);
                } else {
                    r.clear();
                }
            }
            seen.store(want, Ordering::Relaxed);
        }
        self.cleared_seen.store(cleared, Ordering::Relaxed);
    }
}

impl Drop for Slab {
    fn drop(&mut self) {
        COUNTERS_POOL.retire(&mut self.published);
    }
}

/// `pool_gc` asks nothing of the slabs: their size is fixed with the configuration, never
/// grown, never compacted.
impl ibex_alloc::Arena<HotRow> for Slab {
    fn slots(&self) -> usize {
        self.rows.len()
    }
    fn live(&self) -> usize {
        self.rows.len().saturating_sub(2)
    }
    fn compact(&mut self) -> usize {
        0
    }
}

/// What the readers print of an object's [`HotRow`]s: the shared set and every thread's row,
/// summed (design §4).
#[derive(Debug, Default, Clone, Copy)]
pub struct Snapshot {
    pub hrsp: [u64; 6],
    pub req_tot: u64,
    pub stot: u64,
    pub lbtot: u64,
    pub connect: u64,
    pub reuse: u64,
    pub bin: u64,
    pub bout: u64,
    pub cli_abrt: u64,
    pub srv_abrt: u64,
    pub eresp: u64,
    pub ereq: u64,
    pub eint: u64,
    /// The latest of the rows'.
    pub last_sess: u64,
    /// The averages of the timings: of the one row under `shared`; under `per-thread` the
    /// mean of the averages of the rows that counted any (design Q2: equal with one thread).
    pub tavg: [u64; 4],
    /// The rows' rates and peaks, summed (Q3).
    pub rate: u64,
    pub rate_max: u64,
}

impl Snapshot {
    fn add(&mut self, r: &HotRow, totals: bool, maxima: bool, http: bool, avg: &mut ([u64; 4], u64)) {
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        self.rate += r.sess_rate.rate();
        if maxima {
            self.rate_max += u64::from(r.rate_max.load(Ordering::Relaxed));
        }
        if !totals {
            return;
        }
        for (s, h) in self.hrsp.iter_mut().zip(&r.hrsp) {
            *s += ld(h);
        }
        for (s, a) in [
            (&mut self.req_tot, &r.req_tot),
            (&mut self.stot, &r.stot),
            (&mut self.lbtot, &r.lbtot),
            (&mut self.connect, &r.connect),
            (&mut self.reuse, &r.reuse),
            (&mut self.bin, &r.bin),
            (&mut self.bout, &r.bout),
            (&mut self.cli_abrt, &r.cli_abrt),
            (&mut self.srv_abrt, &r.srv_abrt),
            (&mut self.eresp, &r.eresp),
            (&mut self.ereq, &r.ereq),
            (&mut self.eint, &r.eint),
        ] {
            *s += ld(a);
        }
        self.last_sess = self.last_sess.max(ld(&r.last_sess));
        let counted = if http { ld(&r.req_tot) } else { ld(&r.lbtot) };
        let sums = r.tsum.each_ref().map(ld);
        if counted > 0 || sums.iter().any(|&v| v > 0) {
            for (a, s) in avg.0.iter_mut().zip(sums) {
                *a += swrate_avg(s, counted);
            }
            avg.1 += 1;
        }
    }
}

/// The counters of object `k` ([`FE`], [`BE`], `SRV + i`) of proxy `p`, every row summed.
#[must_use]
pub fn snapshot(p: &crate::engine::Proxy, k: usize) -> Snapshot {
    let http = p.mode == ibex_config::Mode::Http;
    let mut s = Snapshot::default();
    let mut avg = ([0u64; 4], 0u64);
    if let Some(c) = p.ids.tc.get() {
        let shared = match k {
            FE => Some(&c.fe.hot),
            BE => Some(&c.be.hot),
            i => c.srv.get(i - SRV).map(|s| &s.hot),
        };
        if let Some(r) = shared {
            s.add(r, true, true, http, &mut avg);
        }
    }
    if let Some(t) = p.ids.rows.as_deref() {
        t.each(p.id as usize, k, |r, totals, maxima| s.add(r, totals, maxima, http, &mut avg));
    }
    if avg.1 > 0 {
        s.tavg = avg.0.map(|a| a.div_ceil(avg.1));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn average_rounds_up_like_swrate() {
        let t = AtomicU64::new(0);
        swrate_add(&t, 200, 1);
        for _ in 0..6 {
            swrate_add(&t, 0, 1);
        }
        // 200 over seven requests is 28.6: `HAProxy` printed 29 (3.5-dev8-885761-29), and
        // 25 over the eight a backend counted.
        let sum = t.load(Ordering::Relaxed);
        assert_eq!(swrate_avg(sum, 7), 29);
        assert_eq!(swrate_avg(sum, 8), 25);
    }

    #[test]
    fn statuses_fall_in_their_class() {
        let c = TxnCounters::default();
        for s in [101, 200, 204, 301, 404, 503, 600, -1] {
            c.count_status(s);
        }
        let got: Vec<u64> = c.hot.hrsp.iter().map(|h| h.load(Ordering::Relaxed)).collect();
        assert_eq!(got, [1, 2, 1, 1, 1, 2]);
    }

    #[test]
    fn a_slab_is_made_once_per_worker_and_never_compacted() {
        let mut t = CounterTable::new(&[], 2);
        assert_eq!(t.slab_rows(), 2, "the guard rows");
        assert!(t.start_worker(5).is_ok(), "a worker past the table has no slab");
        assert!(t.start_worker(0).is_ok());
        assert!(t.start_worker(0).is_ok(), "a second start keeps the slab");
        let slab = t.slabs[0].get_mut().expect("worker 0's slab");
        assert_eq!(ibex_alloc::Arena::<HotRow>::compact(slab), 0);
        assert!(t.slabs[1].get().is_none() && t.slabs.get(5).is_none());
    }

}
