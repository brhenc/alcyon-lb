// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `Pool<T>`: the one per-thread object cache (`docs/design/memory-2026-10-24.md` §3).
//!
//! Every pool is a [`declare_pool!`] static. Each thread has its own LIFO cache of `T`s per
//! pool, and one byte budget shared by all its pools ([`HOT`], `tune.memory.hot-size`):
//! `HAProxy`'s `pool_cache_bytes` against `global.tune.pool_cache_size`. Giving an object back
//! when the thread is over 3/4 of the budget evicts from that pool
//! (`pool_evict_from_local_cache`); over the whole budget, evicts largest pool first down to
//! 7/8 (`pool_evict_from_local_caches`, which uses an LRU across pools: design §2.3). No pool
//! is evicted under its floor; only [`drain_local_pools`] (`pool_gc`) goes below it.
//!
//! The fast path (take and give on a cache hit) reads and writes this thread's memory only:
//! the pool's `RefCell` cache and the thread's [`HOT`] cells. Another thread reads the counts
//! through each pool's per-thread slot, which the owning thread writes once per loop pass
//! ([`pass`]), and only when something changed. `show pools` derives `used = allocated -
//! cached` from those slots: `cached` is the objects in the caches, `used` the [`PoolBox`]es
//! alive. An object taken out with [`Pool::take_raw`] leaves the pool's accounting until it is
//! given back: that is how the spare strings (plain `String`s in samples) are used.
//!
//! No `unsafe` here. Objects are dropped outside the cache's borrow, so a `T` whose drop or
//! `reset` uses another pool (a header list giving its strings back) cannot re-enter a borrow.

use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread::LocalKey;
use std::time::{Duration, Instant};

use crate::{PoolHead, PoolReg};

/// `CONFIG_HAP_POOL_CACHE_SIZE`: `tune.memory.hot-size` when it is not set.
pub const HOT_SIZE_DEFAULT: usize = 524_288;
/// The most pools a process declares (S1-S4 need about twenty).
pub const MAX_POOLS: usize = 64;
/// Threads with their own `show pools` slot; a thread past these publishes into a shared
/// overflow slot (an atomic add per pass instead of a store).
pub const MAX_THREADS: usize = 256;
/// `CONFIG_HAP_POOL_CLUSTER_SIZE`: `HAProxy` evicts this many at a time; Ibex evicts one at a
/// time (its objects vary in size) but keeps the cluster in the share rule.
const CLUSTER: usize = 8;

// -----------------------------------------------------------------------------
// What a pooled object is
// -----------------------------------------------------------------------------

/// What a pooled object must do.
pub trait Poolable: Sized + 'static {
    /// Bytes this object holds (its capacity, not its length): the byte budget sums these.
    fn footprint(&self) -> usize;
    /// Makes it ready for the next owner: clears it, and wipes the used bytes when `wipe`
    /// (`tune.ibex.zero-buffers`). Called on every give, whether the object is kept or freed.
    fn reset(&mut self, wipe: bool);
    /// Whether it is worth keeping: not when larger than `max_footprint` (the pool's largest
    /// object, at most `tune.memory.hot-size`).
    fn keep(&self, max_footprint: usize) -> bool {
        self.footprint() <= max_footprint
    }
    /// A new object for a cache miss, or `None` when memory is short (no abort).
    fn try_new() -> Option<Self>;
    /// The size `show pools` prints for a pool whose objects have a configured size
    /// (`tune.bufsize`), read when it is shown; 0: [`PoolSpec::size`], else the mean.
    fn nominal_size() -> usize {
        0
    }
}

impl Poolable for String {
    #[inline]
    fn footprint(&self) -> usize {
        self.capacity()
    }
    #[inline]
    fn reset(&mut self, wipe: bool) {
        if wipe && !self.is_empty() {
            crate::wipe_string(self);
        }
        self.clear();
    }
    #[inline]
    fn keep(&self, max_footprint: usize) -> bool {
        self.capacity() != 0 && self.capacity() <= max_footprint
    }
    fn try_new() -> Option<Self> {
        Some(String::new())
    }
}

impl Poolable for Vec<u8> {
    #[inline]
    fn footprint(&self) -> usize {
        self.capacity()
    }
    #[inline]
    fn reset(&mut self, wipe: bool) {
        if wipe && !self.is_empty() {
            crate::wipe_bytes(self);
        }
        self.clear();
    }
    #[inline]
    fn keep(&self, max_footprint: usize) -> bool {
        self.capacity() != 0 && self.capacity() <= max_footprint
    }
    fn try_new() -> Option<Self> {
        Some(Vec::new())
    }
}

/// What a pool is: its `show pools` name and where it is declared, and its limits.
#[derive(Debug, Clone, Copy)]
pub struct PoolSpec {
    pub name: &'static str,
    /// Nominal object size for `show pools`; 0 = objects of varying size (the mean is shown).
    pub size: usize,
    /// The largest footprint kept (also bounded by `tune.memory.hot-size`).
    pub max_item: usize,
    /// The most objects one thread keeps.
    pub max_count: usize,
    /// Objects per thread eviction leaves (`minavail`); not counted against the budget.
    pub floor: usize,
    /// Whether [`Pool::take`] counts the objects it makes, for [`Pool::set_limit`]
    /// (`tune.buffers.limit`). Only for pools used through [`PoolBox`].
    pub limited: bool,
    /// Whether the give's wipe follows `tune.ibex.zero-spares` (spare strings and lists) instead
    /// of `tune.ibex.zero-buffers` (buffers). Both are read from the thread's copy.
    pub spares: bool,
    /// Alignment `show pools` prints (`/8`); the buffers' is 64.
    pub align: usize,
    pub file: &'static str,
    pub line: u32,
}

impl PoolSpec {
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        PoolSpec { name, size: 0, max_item: usize::MAX, max_count: usize::MAX, floor: 0, limited: false, spares: false, align: 8, file: "", line: 0 }
    }
    #[must_use]
    pub const fn size(mut self, n: usize) -> Self {
        self.size = n;
        self
    }
    #[must_use]
    pub const fn max_item(mut self, n: usize) -> Self {
        self.max_item = n;
        self
    }
    #[must_use]
    pub const fn max_count(mut self, n: usize) -> Self {
        self.max_count = n;
        self
    }
    #[must_use]
    pub const fn floor(mut self, n: usize) -> Self {
        self.floor = n;
        self
    }
    #[must_use]
    pub const fn limited(mut self) -> Self {
        self.limited = true;
        self
    }
    /// The give wipes under `tune.ibex.zero-spares` (the spare strings and lists).
    #[must_use]
    pub const fn spares(mut self) -> Self {
        self.spares = true;
        self
    }
    #[must_use]
    pub const fn align(mut self, n: usize) -> Self {
        self.align = n;
        self
    }
    #[must_use]
    pub const fn at(mut self, file: &'static str, line: u32) -> Self {
        self.file = file;
        self.line = line;
        self
    }
}

// -----------------------------------------------------------------------------
// The per-thread state
// -----------------------------------------------------------------------------

/// One thread's cache of one pool. Public for [`declare_pool!`] only.
pub struct Cache<T> {
    inner: RefCell<Local<T>>,
}

struct Local<T> {
    items: Vec<T>,
    /// [`PoolBox`]es made minus dropped on this thread (a box can die on another thread).
    boxes: isize,
    /// In this thread's [`HOT`] list of pools.
    touched: bool,
    /// What this thread last added to the overflow slot (threads past [`MAX_THREADS`]).
    over: (usize, usize, isize),
    /// The pool's shared part, known once the thread used the pool.
    shared: Option<&'static PoolShared>,
}

impl<T> Cache<T> {
    #[must_use]
    pub const fn new() -> Self {
        Cache { inner: RefCell::new(Local { items: Vec::new(), boxes: 0, touched: false, over: (0, 0, 0), shared: None }) }
    }
}

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A thread whose pools were published into the overflow slot takes its share out when it ends.
impl<T> Drop for Cache<T> {
    fn drop(&mut self) {
        let l = self.inner.get_mut();
        if l.over != (0, 0, 0) {
            if let Some(shared) = l.shared {
                let s = &shared.shown[MAX_THREADS];
                s.count.fetch_sub(l.over.0, Ordering::Relaxed);
                s.bytes.fetch_sub(l.over.1, Ordering::Relaxed);
                s.boxes.fetch_sub(l.over.2, Ordering::Relaxed);
            }
        }
    }
}

/// The thread's byte budget across all its pools (`pool_cache_bytes`, `pool_cache_count`),
/// its copy of the settings, and the pools it has used.
struct Hot {
    /// Footprints cached by this thread above the pools' floors.
    bytes: Cell<usize>,
    /// `tune.memory.hot-size`, and 3/4 of it.
    max: Cell<usize>,
    three_q: Cell<usize>,
    /// `tune.ibex.zero-buffers`.
    wipe: Cell<bool>,
    /// `tune.ibex.zero-spares`.
    wipe_spares: Cell<bool>,
    /// `tune.ibex.ssl-zero-buffers` (default on).
    wipe_ssl: Cell<bool>,
    /// The settings generation copied.
    gen: Cell<u64>,
    /// When [`pass`] publishes next (`None`: at the next pass).
    next_publish: Cell<Option<Instant>>,
    pools: [Cell<Option<&'static dyn PoolDyn>>; MAX_POOLS],
    npools: Cell<usize>,
}

thread_local! {
    static HOT: Hot = const {
        Hot {
            bytes: Cell::new(0),
            max: Cell::new(HOT_SIZE_DEFAULT),
            three_q: Cell::new(HOT_SIZE_DEFAULT / 4 * 3),
            wipe: Cell::new(false),
            wipe_spares: Cell::new(false),
            wipe_ssl: Cell::new(true),
            gen: Cell::new(0),
            next_publish: Cell::new(None),
            pools: [const { Cell::new(None) }; MAX_POOLS],
            npools: Cell::new(0),
        }
    };
    static SLOT: SlotGuard = const { SlotGuard(Cell::new(SLOT_UNSET)) };
}

const SLOT_UNSET: usize = usize::MAX;

/// This thread's `show pools` slot, given back when the thread ends.
struct SlotGuard(Cell<usize>);

static SLOTS_USED: [AtomicBool; MAX_THREADS] = [const { AtomicBool::new(false) }; MAX_THREADS];
/// One past the highest slot ever given out: what a `show pools` sums over.
static SLOT_HWM: AtomicUsize = AtomicUsize::new(0);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let i = self.0.get();
        if i < MAX_THREADS {
            for_each_pool(|p| p.clear_slot(i));
            SLOTS_USED[i].store(false, Ordering::Release);
        }
    }
}

/// This thread's slot ([`MAX_THREADS`] = the overflow slot).
fn thread_slot() -> usize {
    SLOT.try_with(|g| {
        if g.0.get() == SLOT_UNSET {
            let i = (0..MAX_THREADS)
                .find(|&i| SLOTS_USED[i].compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok())
                .unwrap_or(MAX_THREADS);
            if i < MAX_THREADS {
                SLOT_HWM.fetch_max(i + 1, Ordering::Relaxed);
            }
            g.0.set(i);
        }
        g.0.get()
    })
    .unwrap_or(MAX_THREADS)
}

// -----------------------------------------------------------------------------
// Settings: copied into each thread, never read on the fast path
// -----------------------------------------------------------------------------

static HOT_SIZE: AtomicUsize = AtomicUsize::new(HOT_SIZE_DEFAULT);
/// Raised by every setting change; each thread copies the settings at its next [`pass`].
static SETTINGS_GEN: AtomicU64 = AtomicU64::new(0);

/// Sets `tune.memory.hot-size`: the bytes each thread's pools keep at most, together. The
/// calling thread follows at once (evicting if it is over), the others at their next [`pass`].
pub fn set_hot_size(bytes: usize) {
    HOT_SIZE.store(bytes.max(1), Ordering::Relaxed);
    settings_changed();
}

/// `tune.memory.hot-size`.
#[must_use]
pub fn hot_size() -> usize {
    HOT_SIZE.load(Ordering::Relaxed)
}

/// This thread's copy of `tune.ibex.ssl-zero-buffers` (on when the thread is ending).
#[inline]
pub(crate) fn wipe_ssl_on() -> bool {
    HOT.try_with(|h| h.wipe_ssl.get()).unwrap_or(true)
}

/// A setting the threads copy changed (`tune.memory.hot-size`, `tune.ibex.zero-buffers`,
/// `tune.ibex.zero-spares`).
pub(crate) fn settings_changed() {
    SETTINGS_GEN.fetch_add(1, Ordering::Release);
    refresh_local();
}

fn refresh_local() {
    let over = HOT
        .try_with(|h| {
            h.gen.set(SETTINGS_GEN.load(Ordering::Acquire));
            let max = HOT_SIZE.load(Ordering::Relaxed);
            h.max.set(max);
            h.three_q.set(max / 4 * 3);
            h.wipe.set(crate::zero_buffers());
            h.wipe_spares.set(crate::zero_spares());
            h.wipe_ssl.set(crate::ssl_zero_buffers());
            h.bytes.get() > max
        })
        .unwrap_or(false);
    if over {
        evict_across();
    }
}

/// How often [`pass`] publishes at most. A pass per request (one connection, `ab -c 1`)
/// published every pass cost ~300 instructions per request on the rules scenario; at this
/// rate it is a few. `show pools` and `pool_gc` publish their own thread at once.
const PUBLISH_EVERY: Duration = Duration::from_millis(10);

/// Once per loop pass of every engine thread (`now` is the pass's clock): copies changed
/// settings, and publishes this thread's counts of every pool it used for `show pools`, at
/// most every [`PUBLISH_EVERY`] (no dirty flag on the fast path). An idle thread passes at
/// least every poll timeout. Inlined into the loop: a load and two compares when there is
/// nothing to do (a call that also did the `Instant` arithmetic every pass cost ~200
/// instructions per request on the rules scenario, ab1).
#[inline]
pub fn pass(now: Instant) {
    let due = HOT
        .try_with(|h| h.gen.get() != SETTINGS_GEN.load(Ordering::Relaxed) || h.next_publish.get().is_none_or(|t| now >= t))
        .unwrap_or(false);
    if due {
        pass_due(now);
    }
}

#[cold]
#[inline(never)]
fn pass_due(now: Instant) {
    let (stale, publish) = HOT
        .try_with(|h| {
            let stale = h.gen.get() != SETTINGS_GEN.load(Ordering::Relaxed);
            let publish = h.next_publish.get().is_none_or(|t| now >= t);
            if publish {
                h.next_publish.set(now.checked_add(PUBLISH_EVERY));
            }
            (stale, publish && h.npools.get() != 0)
        })
        .unwrap_or((false, false));
    if stale {
        refresh_local();
    }
    if publish {
        publish_local();
    }
}

/// Publishes this thread's counts of every pool it used.
pub fn publish_local() {
    let slot = thread_slot();
    let _ = HOT.try_with(|h| {
        for p in h.pools[..h.npools.get()].iter().filter_map(Cell::get) {
            p.publish_local(slot);
        }
    });
}



/// Empties every pool cache of the calling thread, floors included (`pool_gc`, T445). Returns
/// the objects freed. They were wiped when they were given back.
pub fn drain_local_pools() -> usize {
    let mut n = 0;
    let pools: [Option<&'static dyn PoolDyn>; MAX_POOLS] = HOT
        .try_with(|h| std::array::from_fn(|i| h.pools[i].get()))
        .unwrap_or([None; MAX_POOLS]);
    for p in pools.into_iter().flatten() {
        n += p.drain_local();
    }
    publish_local();
    n
}

/// Bytes this thread's pools hold against `tune.memory.hot-size`.
#[must_use]
pub fn local_hot_bytes() -> usize {
    HOT.try_with(|h| h.bytes.get()).unwrap_or(0)
}

/// Over the whole budget: evicts from this thread's pool holding the most counted bytes, then
/// the next, until the thread is at 7/8 of the budget or nothing above a floor is left.
#[cold]
fn evict_across() {
    loop {
        let Ok((bytes, max)) = HOT.try_with(|h| (h.bytes.get(), h.max.get())) else { return };
        if bytes <= max / 8 * 7 {
            return;
        }
        let mut best: Option<(&'static dyn PoolDyn, usize)> = None;
        let _ = HOT.try_with(|h| {
            for p in h.pools[..h.npools.get()].iter().filter_map(Cell::get) {
                let b = p.local_hot_bytes();
                if b > best.map_or(0, |x| x.1) {
                    best = Some((p, b));
                }
            }
        });
        let Some((p, _)) = best else { return };
        // One at a time: the objects vary in size, and one may be most of the budget.
        if p.evict_local(1) == 0 {
            return;
        }
    }
}

// -----------------------------------------------------------------------------
// The registry: every declared pool, for `show pools`, `pool_gc` and thread exit
// -----------------------------------------------------------------------------

/// What the registry, `pool_gc` and the cross-pool eviction need of a pool, whatever its `T`.
pub trait PoolDyn: Sync {
    fn name(&self) -> &'static str;
    /// The `show pools` line's figures, summed over the threads' published slots.
    fn head(&self) -> PoolHead;
    /// Frees this thread's cache of the pool, floor included; returns the objects freed.
    fn drain_local(&self) -> usize;
    /// This thread's bytes counted against the budget.
    fn local_hot_bytes(&self) -> usize;
    /// This thread's objects above the floor.
    fn local_hot_count(&self) -> usize;
    /// Evicts up to `n` objects above the floor from this thread's cache; returns how many.
    fn evict_local(&self, n: usize) -> usize;
    fn publish_local(&self, slot: usize);
    fn clear_slot(&self, slot: usize);
}

static DECLARED: [OnceLock<&'static dyn PoolDyn>; MAX_POOLS] = [const { OnceLock::new() }; MAX_POOLS];
static NDECLARED: AtomicUsize = AtomicUsize::new(0);

/// Calls `f` on every pool declared and used so far, in the order they were first used.
/// Takes no lock and allocates nothing.
pub fn for_each_pool(mut f: impl FnMut(&'static dyn PoolDyn)) {
    let n = NDECLARED.load(Ordering::Acquire).min(MAX_POOLS);
    for slot in &DECLARED[..n] {
        if let Some(p) = slot.get() {
            f(*p);
        }
    }
}

// -----------------------------------------------------------------------------
// The pool
// -----------------------------------------------------------------------------

/// One thread's figures in a pool, as `show pools` reads them. A line of its own: the owner
/// stores into it once per pass, `show pools` loads.
#[repr(align(64))]
struct Shown {
    count: AtomicUsize,
    bytes: AtomicUsize,
    boxes: AtomicIsize,
}

/// What every thread shares of a pool: the slots, the miss-path counters. Public for
/// [`declare_pool!`] only.
pub struct PoolShared {
    registered: AtomicBool,
    /// Objects made by [`Pool::take`] and not freed (`limited` pools only).
    grown: AtomicIsize,
    failures: AtomicUsize,
    limit: AtomicUsize,
    shown: [Shown; MAX_THREADS + 1],
}

impl PoolShared {
    #[must_use]
    pub const fn new() -> Self {
        PoolShared {
            registered: AtomicBool::new(false),
            grown: AtomicIsize::new(0),
            failures: AtomicUsize::new(0),
            limit: AtomicUsize::new(0),
            shown: [const { Shown { count: AtomicUsize::new(0), bytes: AtomicUsize::new(0), boxes: AtomicIsize::new(0) } }; MAX_THREADS + 1],
        }
    }
}

impl Default for PoolShared {
    fn default() -> Self {
        Self::new()
    }
}

/// A pool of `T`, declared with [`declare_pool!`]. Holds only references and constants, so
/// the compiler sees through it: the thread-local access and the spec's limits are folded
/// into each call site.
pub struct Pool<T: Poolable> {
    spec: PoolSpec,
    shared: &'static PoolShared,
    cache: &'static LocalKey<Cache<T>>,
    _t: PhantomData<fn() -> T>,
}

impl<T: Poolable> Pool<T> {
    #[doc(hidden)]
    #[must_use]
    pub const fn new(spec: PoolSpec, shared: &'static PoolShared, cache: &'static LocalKey<Cache<T>>) -> Self {
        Pool { spec, shared, cache, _t: PhantomData }
    }

    #[must_use]
    pub fn spec(&self) -> &PoolSpec {
        &self.spec
    }

    /// A cached object, else a new one ([`Poolable::try_new`]), as a [`PoolBox`] that goes
    /// back on drop; `None` when the pool is at its limit or memory is short (`failures` + 1).
    #[inline]
    pub fn take(&'static self) -> Option<PoolBox<T>> {
        self.take_with(T::try_new)
    }

    /// [`Self::take`] with `init` making the object on a miss.
    #[inline(always)] // see `put`
    #[allow(clippy::inline_always)]
    pub fn take_with(&'static self, init: impl FnOnce() -> Option<T>) -> Option<PoolBox<T>> {
        let v = match self.pop(true) {
            Some(v) => v,
            None => self.miss(true, init)?,
        };
        Some(PoolBox { v: Some(v), pool: self })
    }

    /// A cached object, else `init()`, taken out of the pool's accounting: it is the caller's
    /// until it is given back with [`Self::give`], if ever. `None` only when `init` fails.
    #[inline(always)] // see `put`
    #[allow(clippy::inline_always)]
    pub fn take_raw(&'static self, init: impl FnOnce() -> Option<T>) -> Option<T> {
        match self.pop(false) {
            Some(v) => Some(v),
            None => self.miss(false, init),
        }
    }

    /// Gives `v` back: reset (and wiped under `tune.ibex.zero-buffers`, or `tune.ibex.zero-spares` for a [`PoolSpec::spares`] pool), then kept for the next
    /// take, or freed when it is too large, the thread keeps enough of them, or the budget
    /// says so.
    #[inline(always)] // see `put`
    #[allow(clippy::inline_always)]
    pub fn give(&'static self, v: T) {
        self.put(v, false);
    }

    /// [`Self::take_with`] for an owner that keeps the object itself (a `Buf` holds its memory
    /// as a `Box<[u8]>`): the object counts as in use until [`Self::give_counted`] or
    /// [`Self::discard_counted`].
    #[inline(always)] // see `put`
    #[allow(clippy::inline_always)]
    pub fn take_counted(&'static self, init: impl FnOnce() -> Option<T>) -> Option<T> {
        match self.pop(true) {
            Some(v) => Some(v),
            None => self.miss(true, init),
        }
    }

    /// Gives back an object from [`Self::take_counted`] (what `PoolBox`'s drop does).
    #[inline(always)] // see `put`
    #[allow(clippy::inline_always)]
    pub fn give_counted(&'static self, v: T) {
        self.put(v, true);
    }

    /// An object from [`Self::take_counted`] that is not worth pooling (of another size than the
    /// pool's now): freed, no longer in use.
    pub fn discard_counted(&'static self, v: T) {
        self.free_given(v, true);
    }

    /// Fills this thread's cache with `n` new objects (at start, before any request).
    pub fn prefill(&'static self, n: usize) {
        for _ in 0..n {
            let Some(v) = T::try_new() else { return };
            if self.spec.limited {
                self.shared.grown.fetch_add(1, Ordering::Relaxed);
            }
            self.give(v);
        }
    }

    /// `tune.buffers.limit`: the most objects [`Self::take`] makes (0: no limit). For
    /// `limited` pools.
    pub fn set_limit(&self, n: usize) {
        self.shared.limit.store(n, Ordering::Relaxed);
    }

    /// Refused takes since the start.
    #[must_use]
    pub fn failures(&self) -> usize {
        self.shared.failures.load(Ordering::Relaxed)
    }

    /// Objects in this thread's cache.
    #[must_use]
    pub fn local_count(&self) -> usize {
        self.cache.try_with(|c| c.inner.try_borrow().map_or(0, |l| l.items.len())).unwrap_or(0)
    }

    /// Footprints of this thread's cache.
    #[must_use]
    pub fn local_bytes(&self) -> usize {
        self.cache.try_with(|c| c.inner.try_borrow().map_or(0, |l| l.items.iter().map(T::footprint).sum())).unwrap_or(0)
    }

    #[inline(always)] // see `put`
    #[allow(clippy::inline_always)]
    fn pop(&'static self, boxed: bool) -> Option<T> {
        let floor = self.spec.floor;
        self.cache
            .try_with(|c| {
                let mut l = c.inner.try_borrow_mut().ok()?;
                let v = l.items.pop()?;
                if boxed {
                    l.boxes += 1;
                }
                if l.items.len() >= floor {
                    let fp = v.footprint();
                    HOT.with(|h| h.bytes.set(h.bytes.get() - fp));
                }
                Some(v)
            })
            .unwrap_or(None)
    }

    /// Inlined, as are the takes, so that a caller with the pool as a known static (a
    /// `declare_pool!`'s non-inlined wrapper, `ibex_sample::spare::give`) reaches the cache's
    /// thread-local directly and folds the spec: not inlined, the cache was reached through
    /// the stored `LocalKey`'s function pointer (~450 instructions per request, rules, ab1).
    #[inline(always)]
    #[allow(clippy::inline_always)]
    fn put(&'static self, mut v: T, boxed: bool) {
        let spares = self.spec.spares;
        let (wipe, max) = HOT
            .try_with(|h| (if spares { h.wipe_spares.get() } else { h.wipe.get() }, h.max.get()))
            .unwrap_or((true, 0));
        v.reset(wipe);
        let fp = v.footprint();
        let spec = &self.spec;
        let kept = self.cache.try_with(|c| {
            let Ok(mut l) = c.inner.try_borrow_mut() else { return Err(v) };
            let n = l.items.len();
            // A floor object is kept whatever the budget; the others only when they fit it.
            let counted = n >= spec.floor;
            let max_item = if counted && max < spec.max_item { max } else { spec.max_item };
            if n >= spec.max_count || !v.keep(max_item) {
                return Err(v);
            }
            if n == l.items.capacity() && !self.grow_items(&mut l) {
                return Err(v);
            }
            l.items.push(v);
            if boxed {
                l.boxes -= 1;
            }
            Ok(counted)
        });
        match kept {
            Ok(Ok(counted)) => {
                let over = HOT
                    .try_with(|h| {
                        if !counted {
                            return false;
                        }
                        let b = h.bytes.get() + fp;
                        h.bytes.set(b);
                        b > h.three_q.get()
                    })
                    .unwrap_or(false);
                if over {
                    self.over_three_quarters();
                }
            }
            Ok(Err(v)) => self.free_given(v, boxed),
            Err(_) => {}
        }
    }

    /// The cache's `Vec` is full: grows it (fallibly), and on the first use on this thread puts
    /// the pool in the registry and in this thread's list.
    #[cold]
    #[inline(never)]
    fn grow_items(&'static self, l: &mut Local<T>) -> bool {
        self.touch(l);
        let more = l.items.capacity().max(CLUSTER);
        l.items.try_reserve(more).is_ok()
    }

    /// Lists the pool in `show pools` before any thread used it (as `HAProxy` lists the pools
    /// it creates at boot). Using it does this too.
    pub fn register(&'static self) {
        if !self.shared.registered.swap(true, Ordering::AcqRel) {
            let i = NDECLARED.fetch_add(1, Ordering::AcqRel);
            if let Some(slot) = DECLARED.get(i) {
                let _ = slot.set(self);
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn touch(&'static self, l: &mut Local<T>) {
        if l.touched {
            return;
        }
        l.touched = true;
        l.shared = Some(self.shared);
        self.register();
        let _ = HOT.try_with(|h| {
            let n = h.npools.get();
            if n < MAX_POOLS {
                h.pools[n].set(Some(self));
                h.npools.set(n + 1);
            }
        });
    }

    /// A miss: makes an object with `init`, within the limit.
    #[cold]
    fn miss(&'static self, boxed: bool, init: impl FnOnce() -> Option<T>) -> Option<T> {
        let _ = self.cache.try_with(|c| {
            if let Ok(mut l) = c.inner.try_borrow_mut() {
                self.touch(&mut l);
            }
        });
        let limited = boxed && self.spec.limited;
        if limited {
            let lim = self.shared.limit.load(Ordering::Relaxed);
            if lim != 0 && self.shared.grown.load(Ordering::Relaxed) >= isize::try_from(lim).unwrap_or(isize::MAX) {
                self.shared.failures.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        let Some(v) = init() else {
            self.shared.failures.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if limited {
            self.shared.grown.fetch_add(1, Ordering::Relaxed);
        }
        if boxed {
            self.box_delta(1);
        }
        Some(v)
    }

    fn box_delta(&'static self, d: isize) {
        let _ = self.cache.try_with(|c| {
            if let Ok(mut l) = c.inner.try_borrow_mut() {
                l.boxes += d;
            }
        });
    }

    /// An object given back and not kept: it was reset (wiped) already; freed here.
    #[cold]
    #[inline(never)]
    fn free_given(&'static self, v: T, boxed: bool) {
        if boxed {
            self.box_delta(-1);
        }
        if self.spec.limited {
            self.shared.grown.fetch_sub(1, Ordering::Relaxed);
        }
        drop(v);
    }

    /// `pool_put_to_cache` over 3/4 of the budget: evicts clusters from this pool while it
    /// holds more than its share (16 + count/8) and the thread stays over 3/4; then, over the
    /// whole budget, across pools.
    #[cold]
    #[inline(never)]
    fn over_three_quarters(&'static self) {
        // `pool_cache_count`: the thread's cached objects above the floors, summed here (cold)
        // rather than kept on the fast path.
        let share = || {
            let mut count = 0;
            let _ = HOT.try_with(|h| {
                for p in h.pools[..h.npools.get()].iter().filter_map(Cell::get) {
                    count += p.local_hot_count();
                }
            });
            16 + count / 8
        };
        if self.local_count() >= share() + CLUSTER {
            loop {
                let n = self.local_count();
                let go = n >= CLUSTER && n >= share() && HOT.try_with(|h| h.bytes.get() > h.three_q.get()).unwrap_or(false);
                if !go || self.evict_n(1) == 0 {
                    break;
                }
            }
        }
        if HOT.try_with(|h| h.bytes.get() > h.max.get()).unwrap_or(false) {
            evict_across();
        }
    }

    /// Evicts up to `n` objects above the floor, newest first, each dropped outside the borrow.
    fn evict_n(&self, n: usize) -> usize {
        let floor = self.spec.floor;
        let mut done = 0;
        while done < n {
            let one = self
                .cache
                .try_with(|c| {
                    let mut l = c.inner.try_borrow_mut().ok()?;
                    if l.items.len() <= floor {
                        return None;
                    }
                    l.items.pop()
                })
                .ok()
                .flatten();
            let Some(v) = one else { break };
            let fp = v.footprint();
            let _ = HOT.try_with(|h| h.bytes.set(h.bytes.get() - fp));
            if self.spec.limited {
                self.shared.grown.fetch_sub(1, Ordering::Relaxed);
            }
            drop(v);
            done += 1;
        }
        done
    }
}

impl<T: Poolable> PoolDyn for Pool<T> {
    fn name(&self) -> &'static str {
        self.spec.name
    }

    fn head(&self) -> PoolHead {
        let hwm = SLOT_HWM.load(Ordering::Relaxed).min(MAX_THREADS);
        let (mut count, mut bytes, mut boxes) = (0usize, 0usize, 0isize);
        for s in self.shared.shown[..hwm].iter().chain(std::iter::once(&self.shared.shown[MAX_THREADS])) {
            count = count.wrapping_add(s.count.load(Ordering::Relaxed));
            bytes = bytes.wrapping_add(s.bytes.load(Ordering::Relaxed));
            boxes = boxes.wrapping_add(s.boxes.load(Ordering::Relaxed));
        }
        let used = usize::try_from(boxes).unwrap_or(0);
        let nominal = T::nominal_size();
        let size = if self.spec.size != 0 {
            self.spec.size
        } else if nominal != 0 {
            nominal
        } else {
            bytes.checked_div(count).unwrap_or(0)
        };
        let align = self.spec.align;
        PoolHead {
            name: self.spec.name,
            size,
            align,
            allocated: count + used,
            alloc_bytes: bytes + used * size,
            used,
            cached: count,
            needed_avg: 0,
            failures: self.shared.failures.load(Ordering::Relaxed),
            users: 1,
            reg: Some(PoolReg { name: self.spec.name, size, flags: 0, align, file: self.spec.file, line: self.spec.line }),
        }
    }

    fn drain_local(&self) -> usize {
        let Ok((items, counted_bytes)) = self.cache.try_with(|c| {
            let Ok(mut l) = c.inner.try_borrow_mut() else { return (Vec::new(), 0) };
            let counted_bytes = l.items.iter().skip(self.spec.floor).map(T::footprint).sum::<usize>();
            (std::mem::take(&mut l.items), counted_bytes)
        }) else {
            return 0;
        };
        let n = items.len();
        let _ = HOT.try_with(|h| h.bytes.set(h.bytes.get() - counted_bytes));
        if self.spec.limited {
            self.shared.grown.fetch_sub(isize::try_from(n).unwrap_or(isize::MAX), Ordering::Relaxed);
        }
        drop(items);
        n
    }

    fn local_hot_bytes(&self) -> usize {
        self.cache.try_with(|c| c.inner.try_borrow().map_or(0, |l| l.items.iter().skip(self.spec.floor).map(T::footprint).sum())).unwrap_or(0)
    }

    fn evict_local(&self, n: usize) -> usize {
        self.evict_n(n)
    }

    fn local_hot_count(&self) -> usize {
        self.local_count().saturating_sub(self.spec.floor)
    }

    fn publish_local(&self, slot: usize) {
        let _ = self.cache.try_with(|c| {
            let Ok(mut l) = c.inner.try_borrow_mut() else { return };
            let now = (l.items.len(), l.items.iter().map(T::footprint).sum::<usize>(), l.boxes);
            if slot < MAX_THREADS {
                let s = &self.shared.shown[slot];
                s.count.store(now.0, Ordering::Relaxed);
                s.bytes.store(now.1, Ordering::Relaxed);
                s.boxes.store(now.2, Ordering::Relaxed);
            } else {
                let s = &self.shared.shown[MAX_THREADS];
                let was = l.over;
                s.count.fetch_add(now.0.wrapping_sub(was.0), Ordering::Relaxed);
                s.bytes.fetch_add(now.1.wrapping_sub(was.1), Ordering::Relaxed);
                s.boxes.fetch_add(now.2.wrapping_sub(was.2), Ordering::Relaxed);
                l.over = now;
            }
        });
    }

    fn clear_slot(&self, slot: usize) {
        if let Some(s) = self.shared.shown.get(slot) {
            s.count.store(0, Ordering::Relaxed);
            s.bytes.store(0, Ordering::Relaxed);
            s.boxes.store(0, Ordering::Relaxed);
        }
    }
}

// -----------------------------------------------------------------------------
// PoolBox
// -----------------------------------------------------------------------------

/// An object from [`Pool::take`] that goes back to its pool when dropped, on whatever thread
/// drops it. `Deref<Target = T>`.
pub struct PoolBox<T: Poolable> {
    v: Option<T>,
    pool: &'static Pool<T>,
}

impl<T: Poolable> PoolBox<T> {
    /// The object, out of the pool for good.
    #[must_use]
    pub fn into_inner(mut self) -> T {
        let v = self.v.take();
        self.pool.box_delta(-1);
        if self.pool.spec.limited {
            self.pool.shared.grown.fetch_sub(1, Ordering::Relaxed);
        }
        match v {
            Some(v) => v,
            None => unreachable!("a PoolBox holds its object until it is dropped"),
        }
    }
}

impl<T: Poolable> std::ops::Deref for PoolBox<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        match &self.v {
            Some(v) => v,
            None => unreachable!("a PoolBox holds its object until it is dropped"),
        }
    }
}

impl<T: Poolable> std::ops::DerefMut for PoolBox<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        match &mut self.v {
            Some(v) => v,
            None => unreachable!("a PoolBox holds its object until it is dropped"),
        }
    }
}

impl<T: Poolable> Drop for PoolBox<T> {
    #[inline]
    fn drop(&mut self) {
        if let Some(v) = self.v.take() {
            self.pool.put(v, true);
        }
    }
}

impl<T: Poolable + std::fmt::Debug> std::fmt::Debug for PoolBox<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PoolBox").field(&self.v).finish()
    }
}

/// Declares a pool: a static [`Pool`] with its thread-local caches, registered (for
/// `show pools`, `pool_gc` and the budget) the first time a thread uses it.
///
/// ```ignore
/// ibex_alloc::declare_pool!(pub static SPARE_STR: Pool<String> = PoolSpec::new("spare_str").max_item(16384));
/// ```
#[macro_export]
macro_rules! declare_pool {
    ($(#[$m:meta])* $vis:vis static $name:ident : Pool<$t:ty> = $spec:expr;) => {
        $(#[$m])*
        $vis static $name: $crate::pool::Pool<$t> = {
            static SHARED: $crate::pool::PoolShared = $crate::pool::PoolShared::new();
            ::std::thread_local! {
                static CACHE: $crate::pool::Cache<$t> = const { $crate::pool::Cache::new() };
            }
            $crate::pool::Pool::new($spec.at(file!(), line!()), &SHARED, &CACHE)
        };
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::declare_pool!(static LIMITED: Pool<Vec<u8>> = PoolSpec::new("t_limited").limited(););
    crate::declare_pool!(static BYTES: Pool<Vec<u8>> = PoolSpec::new("t_bytes").max_count(1000););
    crate::declare_pool!(static FLOORED: Pool<Vec<u8>> = PoolSpec::new("t_floored").floor(2););
    crate::declare_pool!(static WIDE: Pool<String> = PoolSpec::new("t_wide").max_count(1000););

    fn vec_of(cap: usize) -> Option<Vec<u8>> {
        let mut v = Vec::new();
        v.try_reserve_exact(cap).ok()?;
        Some(v)
    }

    /// Design §6 S1: with `limit 2`, the third take is refused and counted.
    #[test]
    fn a_take_past_the_limit_is_none_and_counted() {
        LIMITED.set_limit(2);
        let a = LIMITED.take_with(|| vec_of(64));
        let b = LIMITED.take_with(|| vec_of(64));
        assert!(a.is_some() && b.is_some());
        assert!(LIMITED.take_with(|| vec_of(64)).is_none(), "a third take under limit 2");
        assert_eq!(LIMITED.failures(), 1);
        drop(a);
        // The one given back is taken again: no growth, no failure.
        assert!(LIMITED.take_with(|| vec_of(64)).is_some());
        assert_eq!(LIMITED.failures(), 1);
        drop(b);
    }

    /// LIFO, emptied, and counted in `show pools` once published: `used` is the boxes alive.
    #[test]
    fn a_given_object_comes_back_and_is_counted() {
        let mut v = BYTES.take_raw(|| vec_of(300)).expect("vec");
        v.extend_from_slice(b"secret");
        let cap = v.capacity();
        BYTES.give(v);
        assert_eq!(BYTES.local_count(), 1);
        assert_eq!(BYTES.local_bytes(), cap);
        let b = BYTES.take().expect("cached");
        assert!(b.is_empty() && b.capacity() == cap);
        publish_local();
        let h = BYTES.head();
        assert_eq!((h.cached, h.used, h.allocated), (0, 1, 1), "{h:?}");
        drop(b);
        publish_local();
        let h = BYTES.head();
        assert_eq!((h.cached, h.used, h.allocated, h.alloc_bytes), (1, 0, 1, cap), "{h:?}");
        assert!(crate::global_pool_registry().show_pools(&[]).contains("  - Pool t_bytes ("));
        assert_eq!(drain_local_pools() >= 1, true);
        assert_eq!(BYTES.local_count(), 0);
    }

    /// One budget across pools: over it, the thread is brought back to 7/8, largest pool
    /// first; an object larger than the budget is not kept; a floor stays whatever the budget.
    /// (One test: `set_hot_size` is process-wide.)
    #[test]
    fn the_thread_keeps_no_more_than_hot_size() {
        set_hot_size(65_536);
        let _ = drain_local_pools();
        for _ in 0..100 {
            BYTES.give(vec_of(4096).expect("vec"));
            let mut s = String::new();
            s.reserve_exact(1024);
            WIDE.give(s);
            assert!(local_hot_bytes() <= 65_536, "{}", local_hot_bytes());
        }
        assert!(local_hot_bytes() > 65_536 / 2, "{}", local_hot_bytes());
        assert_eq!(local_hot_bytes(), BYTES.local_bytes() + WIDE.local_bytes());
        // Larger than the budget: freed.
        BYTES.give(vec_of(70_000).expect("vec"));
        assert!(BYTES.local_bytes() < 70_000);
        // A smaller budget evicts at once on this thread.
        set_hot_size(8192);
        assert!(local_hot_bytes() <= 8192, "{}", local_hot_bytes());
        // Floor: two kept even when each is larger than the budget, and not counted.
        let _ = drain_local_pools();
        for _ in 0..3 {
            FLOORED.give(vec_of(16_384).expect("vec"));
        }
        assert_eq!(FLOORED.local_count(), 2);
        assert_eq!(local_hot_bytes(), 0);
        assert_eq!(drain_local_pools(), 2);
        set_hot_size(HOT_SIZE_DEFAULT);
    }

    /// The wipe follows `tune.ibex.zero-buffers`: on, the used bytes are zeroed before the
    /// object is kept. (What a freed one left is checked by `ibex-rt`'s `spare_strings` test.)
    #[test]
    fn a_reset_wipes_the_used_bytes() {
        let mut s = String::from("hunter2");
        s.reset(true);
        assert!(s.is_empty());
        let mut v = b"hunter2".to_vec();
        let keep = v.clone();
        v.reset(false);
        assert!(v.is_empty() && v.capacity() >= keep.len());
    }
}
