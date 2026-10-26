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
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
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
/// `tune.memory.prealloc` (T475): the most objects a thread's cache of a
/// [`PoolSpec::presized`] pool holds; the rest of what [`Pool::prealloc`] makes is in the
/// pool's [`Shelf`], which any thread takes from on a miss and gives to past this. 32 standard
/// buffers are `HAProxy`'s per-thread cache (`CONFIG_HAP_POOL_CACHE_SIZE`, 512 KiB of 16 KiB),
/// and a small figure lets a busy thread use nearly all of the limit while the others are idle
/// (it can reach `limit - (nbthread - 1) * PREALLOC_LOCAL`).
pub const PREALLOC_LOCAL: usize = 4 * CLUSTER;

// -----------------------------------------------------------------------------
// What a pooled object is
// -----------------------------------------------------------------------------

/// What a pooled object must do.
pub trait Poolable: Sized + Send + 'static {
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
    /// Whether [`Pool::prealloc`] can raise this thread's floor and count past the spec's
    /// (`tune.memory.prealloc`, T468). Off, the per-thread figure is never read: the spec's
    /// constants are folded as before.
    pub presized: bool,
    /// Alignment `show pools` prints (`/8`); the buffers' is 64.
    pub align: usize,
    pub file: &'static str,
    pub line: u32,
}

impl PoolSpec {
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        PoolSpec { name, size: 0, max_item: usize::MAX, max_count: usize::MAX, floor: 0, limited: false, spares: false, presized: false, align: 8, file: "", line: 0 }
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
    /// [`Pool::prealloc`] may size this pool's caches (`tune.memory.prealloc`).
    #[must_use]
    pub const fn presized(mut self) -> Self {
        self.presized = true;
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
    /// [`Pool::fill_reserve`]'s per-thread reserve (S6b), kept aside from the cache's objects.
    reserve: RefCell<Vec<T>>,
    /// How many the reserve lacks, read by every give ([`Pool::reserve_lacks`]).
    lack: Cell<u32>,
    /// The reserve's size, as asked.
    reserve_cap: Cell<usize>,
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
    /// [`Pool::prealloc`]'s size: this thread's floor and most kept, when above the spec's
    /// (a [`PoolSpec::presized`] pool only).
    pre: usize,
}

impl<T> Cache<T> {
    #[must_use]
    pub const fn new() -> Self {
        Cache {
            inner: RefCell::new(Local { items: Vec::new(), boxes: 0, touched: false, over: (0, 0, 0), shared: None, pre: 0 }),
            reserve: RefCell::new(Vec::new()),
            lack: Cell::new(0),
            reserve_cap: Cell::new(0),
        }
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
    /// `tune.fail-alloc` under `-dMfail`: the percentage of misses refused (0: none).
    fail: Cell<u8>,
    /// The last refusal was one of `tune.fail-alloc`'s ([`take_injected`]).
    injected: Cell<bool>,
    /// This thread's random state for `tune.fail-alloc`.
    rng: Cell<u32>,
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
            fail: Cell::new(0),
            injected: Cell::new(false),
            rng: Cell::new(0),
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

/// One past the highest slot ever given out.
pub(crate) fn slot_hwm() -> usize {
    SLOT_HWM.load(Ordering::Relaxed).min(MAX_THREADS)
}

/// This thread's slot ([`MAX_THREADS`] = the overflow slot).
pub(crate) fn thread_slot() -> usize {
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

/// `tune.fail-alloc` as `-dMfail` makes it count (0 without `-dMfail`).
static FAIL_RATE: AtomicU8 = AtomicU8::new(0);

/// Sets the percentage of pool allocations refused at random (`-dMfail` with `tune.fail-alloc`,
/// `HAProxy`'s `mem_should_fail`): every take of a counted pool (buffers) and every new session
/// may be refused with this probability, as a failed `malloc` would be. While it is not 0 the
/// thread caches keep nothing, so that every take is an allocation that may fail, as in
/// `HAProxy`, where the check comes before the cache. Taken at the next [`pass`] by the other
/// threads. Values over 100 count as 100.
pub fn set_fail_alloc(percent: u8) {
    FAIL_RATE.store(percent.min(100), Ordering::Relaxed);
    settings_changed();
}

/// `-dMfail` (`POOL_DBG_FAIL_ALLOC`): `tune.fail-alloc` counts only with it.
static DEBUG_FAIL: AtomicBool = AtomicBool::new(false);

/// Records `-dMfail` (`true`) or `-dMno-fail`, from the command line, before the configuration
/// is applied.
pub fn set_debug_fail(on: bool) {
    DEBUG_FAIL.store(on, Ordering::Relaxed);
}

/// The refusal rate the configuration's `tune.fail-alloc` makes (`rate`, `None` when unset):
/// none without `-dMfail`; 1 % with it when the configuration says nothing (`HAProxy`'s
/// `-dMfail` presets `mem_fail_rate` to 1).
#[must_use]
pub fn effective_fail_alloc(rate: Option<u8>) -> u8 {
    if DEBUG_FAIL.load(Ordering::Relaxed) { rate.unwrap_or(1) } else { 0 }
}

/// Whether this allocation is one `tune.fail-alloc` refuses (`mem_should_fail`). A load and a
/// compare when it is off.
#[inline]
#[must_use]
pub fn inject_failure() -> bool {
    HOT.try_with(|h| h.fail.get() != 0 && roll(h)).unwrap_or(false)
}

#[cold]
#[inline(never)]
fn roll(h: &Hot) -> bool {
    // xorshift32, seeded per thread from its slot; quality is not the point.
    let mut x = h.rng.get();
    if x == 0 {
        x = 0x9e37_79b9 ^ u32::try_from(thread_slot()).unwrap_or(0).wrapping_mul(0x85eb_ca6b);
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    h.rng.set(x);
    let refused = x % 100 < u32::from(h.fail.get());
    h.injected.set(refused);
    refused
}

/// Whether the last refusal on this thread was one of `tune.fail-alloc`'s (and forgets it): a
/// caller that would collect and retry after a real failure does not after one of these, as
/// `HAProxy` does not.
#[must_use]
pub fn take_injected() -> bool {
    HOT.try_with(|h| h.injected.replace(false)).unwrap_or(false)
}

/// This thread's copy of `tune.ibex.ssl-zero-buffers` (on when the thread is ending).
#[inline]
pub(crate) fn wipe_ssl_on() -> bool {
    HOT.try_with(|h| h.wipe_ssl.get()).unwrap_or(true)
}

/// Sets this thread's copy of `tune.ibex.ssl-zero-buffers` only, until its next refresh: for a
/// test that must not change the setting under the other tests of its process
/// ([`crate::stack_probe`]).
#[cfg(feature = "test-probe")]
pub(crate) fn set_thread_wipe_ssl(on: bool) {
    let _ = HOT.try_with(|h| h.wipe_ssl.set(on));
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
            h.fail.set(FAIL_RATE.load(Ordering::Relaxed));
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



/// Empties every pool cache of the calling thread, floors included (`pool_gc`, T445), and its
/// `zero-on-free` quarantine. Returns the objects and blocks freed. The objects were wiped when
/// they were given back, the blocks are wiped now.
pub fn drain_local_pools() -> usize {
    let mut n = 0;
    let pools: [Option<&'static dyn PoolDyn>; MAX_POOLS] = HOT
        .try_with(|h| std::array::from_fn(|i| h.pools[i].get()))
        .unwrap_or([None; MAX_POOLS]);
    for p in pools.into_iter().flatten() {
        n += p.drain_local();
    }
    publish_local();
    // And what `tune.ibex.zero-on-free soft` holds of the freed memory, wiped.
    n + crate::zero_on_free::drain_local()
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
        // One at a time: the objects vary in size, and one may be most of the budget. Stops
        // when nothing could be evicted (a cache borrowed further up the stack).
        let Some(_) = best.filter(|(p, _)| p.evict_local(1) != 0) else { return };
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
    /// Objects and footprints on the pool's [`Shelf`], changed under its lock.
    shelf_count: AtomicUsize,
    shelf_bytes: AtomicUsize,
    /// Called after objects were put on the shelf ([`Pool::set_on_shelve`], S6b): the
    /// buffers' wakes the streams other threads have waiting for one.
    on_shelve: OnceLock<fn()>,
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
            shelf_count: AtomicUsize::new(0),
            shelf_bytes: AtomicUsize::new(0),
            on_shelve: OnceLock::new(),
            shown: [const { Shown { count: AtomicUsize::new(0), bytes: AtomicUsize::new(0), boxes: AtomicIsize::new(0) } }; MAX_THREADS + 1],
        }
    }
}

impl Default for PoolShared {
    fn default() -> Self {
        Self::new()
    }
}

/// The objects of a [`PoolSpec::presized`] pool that no thread's cache holds (T475,
/// `HAProxy`'s `pool_head->free_list` behind the thread caches). Locked only on a miss and on a
/// give past [`PREALLOC_LOCAL`], a cluster at a time: never on a take or give the cache serves.
/// Public for [`declare_pool!`] only.
pub struct Shelf<T>(Mutex<Vec<T>>);

impl<T> Shelf<T> {
    #[must_use]
    pub const fn new() -> Self {
        Shelf(Mutex::new(Vec::new()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<T>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<T> Default for Shelf<T> {
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
    shelf: &'static Shelf<T>,
    cache: &'static LocalKey<Cache<T>>,
    _t: PhantomData<fn() -> T>,
}

impl<T: Poolable> Pool<T> {
    #[doc(hidden)]
    #[must_use]
    pub const fn new(spec: PoolSpec, shared: &'static PoolShared, shelf: &'static Shelf<T>, cache: &'static LocalKey<Cache<T>>) -> Self {
        Pool { spec, shared, shelf, cache, _t: PhantomData }
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

    /// `tune.memory.prealloc` (T468): `n` objects made for this thread, all floor objects (no
    /// eviction, no `pool_gc` takes them). Up to [`PREALLOC_LOCAL`] fill this thread's cache,
    /// which then holds no more; the rest go on the pool's [`Shelf`], where a thread whose cache
    /// is empty finds them (T475). False when memory is short (what was made stays). For a
    /// [`PoolSpec::presized`] pool, at start, after [`Self::set_limit`].
    #[must_use]
    pub fn prealloc(&'static self, n: usize) -> bool {
        let k = n.min(PREALLOC_LOCAL);
        let have = self
            .cache
            .try_with(|c| {
                let mut l = c.inner.try_borrow_mut().ok()?;
                self.touch(&mut l);
                l.pre = k;
                let more = k.saturating_sub(l.items.len());
                l.items.try_reserve_exact(more).ok()?;
                Some(l.items.len())
            })
            .ok()
            .flatten();
        let Some(have) = have else { return false };
        self.prefill(k.saturating_sub(have));
        if self.local_count() < k {
            return false;
        }
        let mut stock = self.shelf.lock();
        // Room for every object the limit allows, so that a give never grows the shelf.
        let room = self.shared.limit.load(Ordering::Relaxed).max(stock.len() + n - k);
        let more = room.saturating_sub(stock.len());
        if stock.try_reserve_exact(more).is_err() {
            return false;
        }
        for _ in k..n {
            let Some(v) = T::try_new() else { return false };
            if self.spec.limited {
                self.shared.grown.fetch_add(1, Ordering::Relaxed);
            }
            self.shared.shelf_count.fetch_add(1, Ordering::Relaxed);
            self.shared.shelf_bytes.fetch_add(v.footprint(), Ordering::Relaxed);
            stock.push(v);
        }
        true
    }

    /// This thread's floor: the spec's, or [`Self::prealloc`]'s when larger.
    #[inline(always)]
    #[allow(clippy::inline_always)]
    fn floor_of(&self, l: &Local<T>) -> usize {
        if self.spec.presized && l.pre != 0 { l.pre } else { self.spec.floor }
    }

    /// `tune.buffers.limit`: the most objects [`Self::take`] makes (0: no limit). For
    /// `limited` pools.
    pub fn set_limit(&self, n: usize) {
        self.shared.limit.store(n, Ordering::Relaxed);
    }

    /// What to call after objects were put on the shelf (S6b: the buffers wake the waiters of
    /// other threads). Once per process; later calls are ignored.
    pub fn set_on_shelve(&self, f: fn()) {
        let _ = self.shared.on_shelve.set(f);
    }

    fn shelved(&self) {
        if let Some(f) = self.shared.on_shelve.get() {
            f();
        }
    }

    /// Room on the shelf of a [`PoolSpec::presized`] pool for every object the limit allows
    /// (S6b: `tune.buffers.limit` without `tune.memory.prealloc`), so that
    /// [`Self::shelve_local`] never allocates. At start; false when memory is short.
    #[must_use]
    pub fn reserve_shelf(&self) -> bool {
        let lim = self.shared.limit.load(Ordering::Relaxed);
        let mut stock = self.shelf.lock();
        let more = lim.saturating_sub(stock.len());
        stock.try_reserve_exact(more).is_ok()
    }

    /// Moves what this thread's cache holds onto the shelf, as much as it has room for (S6b):
    /// another thread was refused an object at the limit while these sat here. How many moved.
    /// Then calls the [`Self::set_on_shelve`] hook when any did.
    #[must_use]
    pub fn shelve_local(&'static self) -> usize {
        if !self.spec.presized {
            return 0;
        }
        let moved = self
            .cache
            .try_with(|c| {
                let Ok(mut l) = c.inner.try_borrow_mut() else { return 0 };
                let floor = self.floor_of(&l);
                let mut stock = self.shelf.lock();
                let k = (stock.capacity() - stock.len()).min(l.items.len());
                let at = l.items.len() - k;
                let (mut bytes, mut hot) = (0, 0);
                for (i, o) in l.items.drain(at..).enumerate() {
                    let fp = o.footprint();
                    bytes += fp;
                    // The objects above the floor were counted in the thread's budget.
                    if at + i >= floor {
                        hot += fp;
                    }
                    stock.push(o);
                }
                self.shared.shelf_count.fetch_add(k, Ordering::Relaxed);
                self.shared.shelf_bytes.fetch_add(bytes, Ordering::Relaxed);
                let _ = HOT.try_with(|h| h.bytes.set(h.bytes.get() - hot));
                k
            })
            .unwrap_or(0);
        if moved > 0 {
            self.shelved();
        }
        moved
    }

    /// Whether [`Self::take`] refuses to make another object: a `limited` pool holding its
    /// [`Self::set_limit`] objects (cached ones included, as `HAProxy`'s `pool->limit`).
    #[must_use]
    pub fn at_limit(&self) -> bool {
        let lim = self.shared.limit.load(Ordering::Relaxed);
        self.spec.limited && lim != 0 && self.shared.grown.load(Ordering::Relaxed) >= isize::try_from(lim).unwrap_or(isize::MAX)
    }

    /// Objects on the shelf, any thread's to take.
    #[must_use]
    pub fn shelf_len(&self) -> usize {
        self.shared.shelf_count.load(Ordering::Relaxed)
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

    /// Makes this thread's reserve `n` objects, each from `init` (the caller's counted take), and
    /// keeps them aside: only [`Self::take_reserve`] hands them out (`tune.buffers.reserve`,
    /// `HAProxy`'s `th_ctx->emergency_bufs`). False when `init` or memory refuses; what was made stays.
    #[must_use]
    pub fn fill_reserve(&self, n: usize, mut init: impl FnMut() -> Option<T>) -> bool {
        self.cache
            .try_with(|c| {
                let Ok(mut r) = c.reserve.try_borrow_mut() else { return false };
                c.reserve_cap.set(n);
                let more = n.saturating_sub(r.len());
                if r.try_reserve_exact(more).is_err() {
                    return false;
                }
                while r.len() < n {
                    let Some(v) = init() else { return false };
                    r.push(v);
                }
                c.lack.set(0);
                true
            })
            .unwrap_or(false)
    }

    /// An object of this thread's reserve for a take of queue `q` that the pool refused, if the
    /// reserve allows it (`left * 3 >= q * reserve`: queue 3 only while it is full, queue 0 down
    /// to the last). The reserve then lacks one.
    #[cold]
    #[inline(never)]
    pub fn take_reserve(&self, q: usize) -> Option<T> {
        self.cache
            .try_with(|c| {
                let mut r = c.reserve.try_borrow_mut().ok()?;
                if r.is_empty() || r.len() * 3 < q * c.reserve_cap.get() {
                    return None;
                }
                let v = r.pop()?;
                c.lack.set(c.lack.get() + 1);
                Some(v)
            })
            .ok()
            .flatten()
    }

    /// Whether this thread's reserve lacks an object: a give looks at this before the pool.
    #[inline(always)] // one thread-local read on the give path
    #[allow(clippy::inline_always)]
    pub fn reserve_lacks(&self) -> bool {
        self.cache.try_with(|c| c.lack.get() != 0).unwrap_or(false)
    }

    /// Puts a given object into the reserve if it lacks one; handed back when it is full.
    #[cold]
    #[inline(never)]
    pub fn refill_reserve(&self, v: T) -> Option<T> {
        let r = self.cache.try_with(|c| {
            let Ok(mut r) = c.reserve.try_borrow_mut() else { return Some(v) };
            if r.len() >= c.reserve_cap.get() || r.len() == r.capacity() {
                return Some(v);
            }
            r.push(v);
            c.lack.set(c.lack.get().saturating_sub(1));
            None
        });
        r.unwrap_or(None)
    }

    /// Objects in this thread's reserve.
    #[must_use]
    pub fn reserve_len(&self) -> usize {
        self.cache.try_with(|c| c.reserve.try_borrow().map_or(0, |r| r.len())).unwrap_or(0)
    }

    /// Footprints of this thread's cache.
    #[must_use]
    pub fn local_bytes(&self) -> usize {
        self.cache.try_with(|c| c.inner.try_borrow().map_or(0, |l| l.items.iter().map(T::footprint).sum())).unwrap_or(0)
    }

    #[inline(always)] // see `put`
    #[allow(clippy::inline_always)]
    fn pop(&'static self, boxed: bool) -> Option<T> {
        self.cache
            .try_with(|c| {
                let mut l = c.inner.try_borrow_mut().ok()?;
                let floor = self.floor_of(&l);
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
        let (wipe, max, fail) = HOT
            .try_with(|h| (if spares { h.wipe_spares.get() } else { h.wipe.get() }, h.max.get(), h.fail.get() != 0))
            .unwrap_or((true, 0, false));
        v.reset(wipe);
        let fp = v.footprint();
        let spec = &self.spec;
        let kept = self.cache.try_with(|c| {
            let Ok(mut l) = c.inner.try_borrow_mut() else { return Err(v) };
            let n = l.items.len();
            // A floor object is kept whatever the budget; the others only when they fit it.
            let counted = n >= self.floor_of(&l);
            // Folded to the spec's constant unless the pool is `presized`.
            let max_count = if spec.presized && l.pre != 0 { l.pre } else { spec.max_count };
            let max_item = if counted && max < spec.max_item { max } else { spec.max_item };
            // Not kept, or no room and the `Vec` cannot grow (memory is short).
            // Under `tune.fail-alloc` nothing is kept: each take is an allocation that may fail.
            if n >= max_count || fail || !v.keep(max_item) || (n == l.items.capacity() && !self.grow_items(&mut l)) {
                return Err(v);
            }
            l.items.push(v);
            if boxed {
                l.boxes -= 1;
            }
            Ok(counted)
        });
        // No cache (the thread is ending): `v` went with the closure; nothing to count.
        match kept.unwrap_or(Ok(false)) {
            Ok(counted) => {
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
            Err(v) => self.not_kept(v, boxed),
        }
    }

    /// A given object the cache does not keep: onto the shelf when the cache of a
    /// [`Self::prealloc`]ed pool is full (T475), else freed.
    #[cold]
    #[inline(never)]
    fn not_kept(&'static self, v: T, boxed: bool) {
        let v = if self.spec.presized { self.shelve(v, boxed) } else { Some(v) };
        match v {
            Some(v) => self.free_given(v, boxed),
            None => self.shelved(),
        }
    }

    /// `v` and a cluster of the cache's objects onto the shelf, when the cache holds its
    /// [`Self::prealloc`] size; else `v` back. Nothing allocated: the shelf has room for the limit.
    fn shelve(&'static self, v: T, boxed: bool) -> Option<T> {
        let fail = HOT.try_with(|h| h.fail.get() != 0).unwrap_or(true);
        if fail || !v.keep(self.spec.max_item) {
            return Some(v);
        }
        let moved = self.cache.try_with(|c| {
            let Ok(mut l) = c.inner.try_borrow_mut() else { return Err(v) };
            if l.pre == 0 || l.items.len() < l.pre {
                return Err(v);
            }
            let mut stock = self.shelf.lock();
            let k = CLUSTER.min(l.items.len());
            if stock.capacity() - stock.len() <= k {
                return Err(v);
            }
            let mut bytes = v.footprint();
            stock.push(v);
            let at = l.items.len() - k;
            for o in l.items.drain(at..) {
                bytes += o.footprint();
                stock.push(o);
            }
            self.shared.shelf_count.fetch_add(k + 1, Ordering::Relaxed);
            self.shared.shelf_bytes.fetch_add(bytes, Ordering::Relaxed);
            if boxed {
                l.boxes -= 1;
            }
            Ok(())
        });
        // No cache (the thread is ending): `v` went with the closure, as in `put`.
        moved.map_or(None, Result::err)
    }

    /// A miss on a [`Self::prealloc`]ed pool: an object from the shelf, and up to a cluster
    /// more into this thread's cache (T475).
    fn unshelve(&'static self, boxed: bool) -> Option<T> {
        if self.shared.shelf_count.load(Ordering::Relaxed) == 0 {
            return None;
        }
        self.cache
            .try_with(|c| {
                let mut l = c.inner.try_borrow_mut().ok()?;
                let mut stock = self.shelf.lock();
                let v = stock.pop()?;
                let mut bytes = v.footprint();
                let more = (CLUSTER - 1).min(l.pre.saturating_sub(l.items.len())).min(l.items.capacity() - l.items.len()).min(stock.len());
                let at = stock.len() - more;
                for o in stock.drain(at..) {
                    bytes += o.footprint();
                    l.items.push(o);
                }
                self.shared.shelf_count.fetch_sub(more + 1, Ordering::Relaxed);
                self.shared.shelf_bytes.fetch_sub(bytes, Ordering::Relaxed);
                if boxed {
                    l.boxes += 1;
                }
                Some(v)
            })
            .ok()
            .flatten()
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
        if self.spec.presized {
            if let Some(v) = self.unshelve(boxed) {
                return Some(v);
            }
        }
        let limited = boxed && self.spec.limited;
        if (limited && self.at_limit()) || (boxed && inject_failure()) {
            self.shared.failures.fetch_add(1, Ordering::Relaxed);
            return None;
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
        let mut done = 0;
        while done < n {
            let one = self
                .cache
                .try_with(|c| {
                    let mut l = c.inner.try_borrow_mut().ok()?;
                    if l.items.len() <= self.floor_of(&l) {
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
        count = count.wrapping_add(self.shared.shelf_count.load(Ordering::Relaxed));
        bytes = bytes.wrapping_add(self.shared.shelf_bytes.load(Ordering::Relaxed));
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
        // `tune.memory.prealloc`'s objects stay: the pool is sized once, at start (T468).
        if self.spec.presized && self.cache.try_with(|c| c.inner.try_borrow().map_or(0, |l| l.pre)).unwrap_or(0) != 0 {
            return self.evict_n(usize::MAX);
        }
        // An ending thread (no cache any more) or a borrowed one has nothing to drain here.
        let (items, counted_bytes) = self
            .cache
            .try_with(|c| {
                let Ok(mut l) = c.inner.try_borrow_mut() else { return (Vec::new(), 0) };
                let counted_bytes = l.items.iter().skip(self.spec.floor).map(T::footprint).sum::<usize>();
                (std::mem::take(&mut l.items), counted_bytes)
            })
            .unwrap_or_default();
        let n = items.len();
        let _ = HOT.try_with(|h| h.bytes.set(h.bytes.get() - counted_bytes));
        if self.spec.limited {
            self.shared.grown.fetch_sub(isize::try_from(n).unwrap_or(isize::MAX), Ordering::Relaxed);
        }
        drop(items);
        n
    }

    fn local_hot_bytes(&self) -> usize {
        self.cache.try_with(|c| c.inner.try_borrow().map_or(0, |l| l.items.iter().skip(self.floor_of(&l)).map(T::footprint).sum())).unwrap_or(0)
    }

    fn evict_local(&self, n: usize) -> usize {
        self.evict_n(n)
    }

    fn local_hot_count(&self) -> usize {
        self.cache.try_with(|c| c.inner.try_borrow().map_or(0, |l| l.items.len().saturating_sub(self.floor_of(&l)))).unwrap_or(0)
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
    ///
    /// # Panics
    ///
    /// Never: a box holds its object until it is dropped or this takes it.
    #[must_use]
    pub fn into_inner(mut self) -> T {
        let v = self.v.take();
        self.pool.box_delta(-1);
        if self.pool.spec.limited {
            self.pool.shared.grown.fetch_sub(1, Ordering::Relaxed);
        }
        v.expect("a PoolBox holds its object until it is dropped")
    }
}

impl<T: Poolable> std::ops::Deref for PoolBox<T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.v.as_ref().expect("a PoolBox holds its object until it is dropped")
    }
}

impl<T: Poolable> std::ops::DerefMut for PoolBox<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.v.as_mut().expect("a PoolBox holds its object until it is dropped")
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
            static SHELF: $crate::pool::Shelf<$t> = $crate::pool::Shelf::new();
            ::std::thread_local! {
                static CACHE: $crate::pool::Cache<$t> = const { $crate::pool::Cache::new() };
            }
            $crate::pool::Pool::new($spec.at(file!(), line!()), &SHARED, &SHELF, &CACHE)
        };
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::declare_pool!(static RSV: Pool<Vec<u8>> = PoolSpec::new("t_reserve"););

    /// S6b: the per-thread reserve is taken only by a class the gate allows (`left*3 >= q*reserve`),
    /// each take leaves the reserve lacking one, and a give refills it before anything else.
    #[test]
    fn reserve_gate_and_refill() {
        let mut made = 0;
        assert!(RSV.fill_reserve(3, || {
            made += 1;
            Some(vec![0u8; 8])
        }));
        assert_eq!((made, RSV.reserve_len()), (3, 3));
        assert!(!RSV.reserve_lacks());
        // q=3 needs the reserve full: 3*3 >= 3*3
        assert!(RSV.take_reserve(3).is_some());
        assert!(RSV.reserve_lacks());
        // full is gone: q=3 refused (2*3 < 3*3), q=2 allowed (6 >= 6), q=0 down to the last
        assert!(RSV.take_reserve(3).is_none());
        assert!(RSV.take_reserve(2).is_some());
        assert!(RSV.take_reserve(0).is_some());
        assert!(RSV.take_reserve(0).is_none(), "empty");
        // gives refill the reserve, and only it, until it is full again
        assert!(RSV.refill_reserve(vec![1]).is_none());
        assert_eq!(RSV.reserve_len(), 1);
        assert!(RSV.refill_reserve(vec![1]).is_none());
        assert!(RSV.refill_reserve(vec![1]).is_none());
        assert!(!RSV.reserve_lacks());
        assert_eq!(RSV.refill_reserve(vec![9]).map(|v| v[0]), Some(9), "full: handed back");
        // another thread has its own, empty reserve
        std::thread::spawn(|| assert!(!RSV.reserve_lacks() && RSV.take_reserve(0).is_none())).join().unwrap();
    }

    crate::declare_pool!(static LIMITED: Pool<Vec<u8>> = PoolSpec::new("t_limited").limited(););
    crate::declare_pool!(static BYTES: Pool<Vec<u8>> = PoolSpec::new("t_bytes").max_count(1000););
    crate::declare_pool!(static FLOORED: Pool<Vec<u8>> = PoolSpec::new("t_floored").floor(2););
    crate::declare_pool!(static WIDE: Pool<String> = PoolSpec::new("t_wide").max_count(1000););
    crate::declare_pool!(static COUNTED: Pool<Vec<u8>> = PoolSpec::new("t_counted").limited(););
    crate::declare_pool!(static ONE: Pool<Vec<u8>> = PoolSpec::new("t_one").limited().max_count(1););
    crate::declare_pool!(static FAILING: Pool<Vec<u8>> = PoolSpec::new("t_failing"););
    crate::declare_pool!(static RANDOM: Pool<Vec<u8>> = PoolSpec::new("t_random").limited(););
    crate::declare_pool!(static OVER: Pool<Vec<u8>> = PoolSpec::new("t_over"););
    crate::declare_pool!(static BLOBS: Pool<Blob> = PoolSpec::new("t_blobs").max_item(100););
    crate::declare_pool!(static PREFILLED: Pool<Blob> = PoolSpec::new("t_prefilled").limited(););
    crate::declare_pool!(static PRESIZED: Pool<Blob> = PoolSpec::new("t_presized").limited().floor(1).max_count(2).presized(););
    crate::declare_pool!(static SHELVED: Pool<Blob> = PoolSpec::new("t_shelved").limited().max_item(100).max_count(2).presized(););
    crate::declare_pool!(static LIMIT_SHELF: Pool<Blob> = PoolSpec::new("t_limit_shelf").limited().floor(1).max_count(8).presized(););

    /// A pooled type that keeps the default [`Poolable::keep`] (footprint within the bound).
    #[derive(Debug, Default)]
    struct Blob(usize);

    impl Poolable for Blob {
        fn footprint(&self) -> usize {
            self.0
        }
        fn reset(&mut self, _wipe: bool) {}
        fn try_new() -> Option<Self> {
            Some(Blob(10))
        }
    }

    crate::declare_pool!(static SIZED: Pool<Sized4k> = PoolSpec::new("t_sized"););
    crate::declare_pool!(static SPEC_SIZED: Pool<Vec<u8>> = PoolSpec::new("t_spec_sized").size(24););
    crate::declare_pool!(static DISCARD: Pool<Vec<u8>> = PoolSpec::new("t_discard"););

    /// A pooled type with a configured size, as the buffers have (`tune.bufsize`).
    #[derive(Debug, Default)]
    struct Sized4k;

    impl Poolable for Sized4k {
        fn footprint(&self) -> usize {
            1
        }
        fn reset(&mut self, _wipe: bool) {}
        fn try_new() -> Option<Self> {
            Some(Sized4k)
        }
        fn nominal_size() -> usize {
            4096
        }
    }

    /// The builders run at run time (a `static`'s are evaluated by the compiler), and the
    /// size and alignment `show pools` prints come from the spec or the type.
    #[test]
    fn the_spec_builders_and_the_shown_size_follow_the_spec_and_the_type() {
        let spec = PoolSpec::new("t_rt").size(24).align(64).max_count(3).floor(1);
        assert_eq!((spec.size, spec.align, spec.max_count, spec.floor), (24, 64, 3, 1));
        drop(SIZED.take().unwrap());
        let h = SIZED.head();
        assert_eq!((h.size, h.align), (4096, 8), "the type's nominal size, the default alignment");
        assert_eq!(SPEC_SIZED.head().size, 24, "the spec's size");
    }

    /// An object taken counted and discarded is freed and no longer in use.
    #[test]
    fn a_discarded_counted_object_is_freed_and_not_in_use() {
        let v = DISCARD.take_counted(|| Some(vec![0u8; 8])).unwrap();
        publish_local();
        assert_eq!(DISCARD.head().used, 1);
        DISCARD.discard_counted(v);
        publish_local();
        assert_eq!((DISCARD.head().used, DISCARD.local_count()), (0, 0));
    }

    thread_local! {
        static RUNTIME_CACHE: Cache<Vec<u8>> = const { Cache::new() };
    }
    static RUNTIME_SHARED: PoolShared = PoolShared::new();
    static RUNTIME_SHELF: Shelf<Vec<u8>> = Shelf::new();

    /// `-dMfail` with `tune.fail-alloc 50`: about half the takes are refused, each counted and
    /// marked as injected, nothing is cached meanwhile (each take is an allocation), and the
    /// rate counts only with `-dMfail`, 1 % when the configuration gives none.
    #[test]
    fn fail_alloc_refuses_at_its_rate_and_caches_nothing() {
        set_debug_fail(false);
        assert_eq!(effective_fail_alloc(Some(5)), 0);
        set_debug_fail(true);
        assert_eq!((effective_fail_alloc(None), effective_fail_alloc(Some(7))), (1, 7));
        set_debug_fail(false);
        let failures = RANDOM.failures();
        set_fail_alloc(50);
        let mut refused = 0;
        for _ in 0..1000 {
            match RANDOM.take_with(|| vec_of(64)) {
                None => {
                    assert!(take_injected() && !take_injected(), "marked once");
                    refused += 1;
                }
                Some(b) => drop(b),
            }
        }
        assert_eq!(RANDOM.local_count(), 0, "nothing cached under tune.fail-alloc");
        set_fail_alloc(0);
        assert!((300..700).contains(&refused), "{refused} of 1000");
        assert_eq!(RANDOM.failures(), failures + refused);
        assert!(RANDOM.take_with(|| vec_of(64)).is_some() && !take_injected());
    }

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
        assert_eq!(hot_size(), 65_536);
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

    /// A pool can be put together at run time (the builders and `new`s are `const` for
    /// `declare_pool!`, which never runs them): the spec is what the builders said, the caches
    /// and shared part start empty, and the pool hands back what it was given.
    #[test]
    fn a_pool_built_at_run_time_has_its_spec_and_works() {
        let spec = PoolSpec::new("t_runtime").size(64).max_item(4096).max_count(3).floor(1).limited().spares().at("here.rs", 7);
        assert_eq!((spec.name, spec.size, spec.max_item, spec.max_count, spec.floor), ("t_runtime", 64, 4096, 3, 1));
        assert!(spec.limited && spec.spares);
        assert_eq!((spec.file, spec.line), ("here.rs", 7));
        assert!(Cache::<String>::default().inner.borrow().items.is_empty());
        let shared = PoolShared::default();
        assert!(!shared.registered.load(Ordering::Relaxed) && shared.failures.load(Ordering::Relaxed) == 0);
        let pool: &'static Pool<Vec<u8>> = Box::leak(Box::new(Pool::new(spec, &RUNTIME_SHARED, &RUNTIME_SHELF, &RUNTIME_CACHE)));
        assert_eq!(pool.spec().name, "t_runtime");
        assert_eq!(PoolDyn::name(pool), "t_runtime");
        pool.give(vec_of(100).expect("vec"));
        pool.give(vec_of(200).expect("vec"));
        assert_eq!(pool.local_count(), 2);
        assert_eq!(pool.take_raw(|| None).map(|v| v.capacity()), Some(200));
    }

    /// `take` makes a new object with `try_new` (String, Vec, a type with the default `keep`);
    /// the box derefs to it, prints as `PoolBox(..)`, and `into_inner` takes it out of the
    /// pool's accounting (the box count goes back down: nothing is in use).
    #[test]
    fn a_box_derefs_prints_and_gives_up_its_object() {
        let mut s = WIDE.take().expect("string");
        s.push_str("abc");
        assert_eq!(s.as_str(), "abc");
        assert_eq!(format!("{s:?}"), "PoolBox(Some(\"abc\"))");
        assert_eq!(s.into_inner(), "abc");
        let mut v = BYTES.take().expect("bytes");
        v.push(7);
        assert_eq!(&v[..], &[7]);
        drop(v);
        assert!(BYTES.local_count() >= 1, "the dropped box went back to the pool");
        let one = COUNTED.take().expect("counted");
        assert_eq!(COUNTED.shared.grown.load(Ordering::Relaxed), 1);
        let _ = one.into_inner();
        assert_eq!(COUNTED.shared.grown.load(Ordering::Relaxed), 0, "out of the limit's count");
        // The default `keep`: within `max_item` kept, over it freed.
        BLOBS.give(Blob(50));
        BLOBS.give(Blob(500));
        assert_eq!(BLOBS.local_count(), 1);
        assert_eq!(BLOBS.take().map(|b| b.into_inner().0), Some(50));
        assert_eq!(BLOBS.take().map(|b| b.into_inner().0), Some(10), "a new one from try_new");
    }

    /// A byte buffer's wipe zeroes its used bytes before it is emptied.
    #[test]
    fn a_wiped_byte_buffer_keeps_no_byte_of_what_it_held() {
        let mut v = b"hunter2".to_vec();
        v.reset(true);
        assert!(v.is_empty());
        // SAFETY: the 7 bytes were initialized (with the secret, then the wipe) and `u8` has no
        // invalid values; this reads them back without writing.
        unsafe { v.set_len(7) };
        assert_eq!(&v[..], &[0; 7]);
        let mut w = *b"secret!";
        crate::wipe_bytes(&mut w);
        assert_eq!(w, [0; 7]);
    }

    /// `prefill` makes objects ahead (counted for the limit); evicting and draining free them
    /// and take them out of that count again; an `init` that fails is a failure.
    #[test]
    fn prefill_evict_drain_and_a_failed_init_are_counted() {
        PREFILLED.prefill(3);
        assert_eq!(PREFILLED.local_count(), 3);
        assert_eq!(PREFILLED.shared.grown.load(Ordering::Relaxed), 3);
        assert_eq!(PREFILLED.evict_local(1), 1);
        assert_eq!(PREFILLED.shared.grown.load(Ordering::Relaxed), 2);
        assert_eq!(PREFILLED.drain_local(), 2);
        assert_eq!(PREFILLED.shared.grown.load(Ordering::Relaxed), 0);
        assert!(FAILING.take_with(|| None).is_none());
        assert_eq!(FAILING.failures(), 1);
    }

    /// T468: only a pool built with `presized()` reads the per-thread size.
    #[test]
    fn presized_is_off_unless_asked() {
        assert!(!PoolSpec::new("t_plain").presized);
        assert!(PoolSpec::new("t_sized_rt").presized().presized);
    }

    /// T468: `prealloc(n)` fills the thread's cache to `n` past the spec's `max_count`, the
    /// objects are floor objects (no budget, no eviction) and `pool_gc` (`drain_local`) keeps
    /// them; at the limit a take past them is refused.
    #[test]
    fn prealloc_fills_past_max_count_and_survives_eviction_and_drain() {
        PRESIZED.set_limit(5);
        assert!(PRESIZED.prealloc(5));
        assert_eq!(PRESIZED.local_count(), 5);
        assert_eq!(PRESIZED.local_hot_bytes(), 0, "prealloc objects are not counted against the budget");
        assert_eq!(PRESIZED.evict_local(5), 0);
        assert_eq!(PRESIZED.drain_local(), 0);
        let boxes: Vec<_> = (0..5).map(|_| PRESIZED.take().expect("a prealloc object")).collect();
        assert!(PRESIZED.take().is_none(), "past the limit");
        drop(boxes);
        assert_eq!(PRESIZED.local_count(), 5, "all kept, past max_count 2");
        assert_eq!(PRESIZED.shared.grown.load(Ordering::Relaxed), 5);
    }

    /// A shelf made at run time (`declare_pool!`'s is evaluated by the compiler) starts empty.
    #[test]
    fn a_shelf_made_at_run_time_is_empty() {
        let shelf = Shelf::<Blob>::default();
        assert_eq!(shelf.lock().len(), 0);
    }

    /// T475: past [`PREALLOC_LOCAL`], `prealloc(n)` puts the rest on the shelf. A miss takes
    /// one from it and a cluster more into the cache; a give to a full cache moves itself and a
    /// cluster onto it. `show pools` counts the shelf as cached: `allocated` stays at the limit.
    #[test]
    fn prealloc_past_the_local_size_shelves_the_rest_for_any_thread() {
        std::thread::spawn(|| {
            SHELVED.set_limit(40);
            assert!(SHELVED.prealloc(40));
            assert_eq!(SHELVED.local_count(), PREALLOC_LOCAL);
            assert_eq!(SHELVED.shared.shelf_count.load(Ordering::Relaxed), 8);
            assert_eq!(SHELVED.shared.grown.load(Ordering::Relaxed), 40);
            let mut boxes: Vec<_> = (0..PREALLOC_LOCAL).map(|_| SHELVED.take().expect("a cached object")).collect();
            boxes.push(SHELVED.take().expect("one from the shelf"));
            assert_eq!(SHELVED.local_count(), CLUSTER - 1, "and a cluster less one into the cache");
            assert_eq!(SHELVED.shared.shelf_count.load(Ordering::Relaxed), 0);
            boxes.extend((0..CLUSTER - 1).map(|_| SHELVED.take().expect("a cached object")));
            assert!(SHELVED.take().is_none(), "past the limit");
            assert_eq!(SHELVED.failures(), 1);
            drop(boxes);
            assert_eq!(SHELVED.local_count(), PREALLOC_LOCAL - 1, "a full cache shelved itself and a cluster");
            assert_eq!(SHELVED.shared.shelf_count.load(Ordering::Relaxed), 40 - (PREALLOC_LOCAL - 1));
            super::publish_local();
            let h = SHELVED.head();
            assert_eq!((h.allocated, h.cached, h.used), (40, 40, 0));
            assert_eq!(h.alloc_bytes, 400);
            // Too large to keep: freed, not shelved.
            SHELVED.give(Blob(1000));
            assert_eq!(SHELVED.local_count(), PREALLOC_LOCAL - 1);
            assert_eq!(SHELVED.shared.shelf_count.load(Ordering::Relaxed), 40 - (PREALLOC_LOCAL - 1));
        })
        .join()
        .expect("thread");
        // A thread that did not prealloc keeps the spec's two and frees the third.
        std::thread::spawn(|| {
            for _ in 0..3 {
                SHELVED.give(Blob(10));
            }
            assert_eq!(SHELVED.local_count(), 2);
            assert_eq!(SHELVED.shared.shelf_count.load(Ordering::Relaxed), 40 - (PREALLOC_LOCAL - 1));
        })
        .join()
        .expect("thread");
    }

    static SHELVED_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// S6b: at the limit, without prealloc, the objects one thread's cache holds go onto the
    /// shelf when asked (`shelve_local`), the hook is called, and another thread's miss is
    /// served from the shelf instead of being refused. Objects above the floor leave the
    /// thread's byte budget with them.
    #[test]
    fn a_thread_shelves_its_cache_for_another_thread_at_the_limit() {
        LIMIT_SHELF.set_limit(4);
        assert!(LIMIT_SHELF.reserve_shelf());
        LIMIT_SHELF.set_on_shelve(|| {
            SHELVED_CALLS.fetch_add(1, Ordering::Relaxed);
        });
        std::thread::spawn(|| {
            assert_eq!(LIMIT_SHELF.shelve_local(), 0, "nothing cached");
            let boxes: Vec<_> = (0..4).map(|_| LIMIT_SHELF.take().expect("within the limit")).collect();
            assert!(LIMIT_SHELF.take().is_none(), "past the limit");
            drop(boxes);
            assert_eq!(LIMIT_SHELF.local_count(), 4);
            let hot = super::local_hot_bytes();
            assert_eq!(SHELVED_CALLS.load(Ordering::Relaxed), 0);
            assert_eq!(LIMIT_SHELF.shelve_local(), 4);
            assert_eq!(SHELVED_CALLS.load(Ordering::Relaxed), 1, "the hook");
            assert_eq!(super::local_hot_bytes(), hot - 30, "the three above the floor left the budget");
            assert_eq!(LIMIT_SHELF.local_count(), 0);
        })
        .join()
        .expect("thread A");
        std::thread::spawn(|| {
            let boxes: Vec<_> = (0..4).map(|_| LIMIT_SHELF.take().expect("one from the shelf")).collect();
            assert_eq!(LIMIT_SHELF.local_count(), 0, "one at a time: nothing more into a cache without prealloc");
            assert!(LIMIT_SHELF.take().is_none(), "the limit holds");
            assert_eq!(LIMIT_SHELF.shared.grown.load(Ordering::Relaxed), 4);
            drop(boxes);
        })
        .join()
        .expect("thread B");
        // A pool that is not presized has no shelf.
        assert_eq!(LIMITED.shelve_local(), 0);
    }

    /// A box given back to a full pool is freed and leaves the limit's count; eviction stops at
    /// the floor.
    #[test]
    fn a_box_not_kept_is_uncounted_and_eviction_stops_at_the_floor() {
        let a = ONE.take_with(|| vec_of(64)).expect("a");
        let b = ONE.take_with(|| vec_of(64)).expect("b");
        assert_eq!(ONE.shared.grown.load(Ordering::Relaxed), 2);
        drop(a);
        drop(b);
        assert_eq!(ONE.local_count(), 1, "max_count 1");
        assert_eq!(ONE.shared.grown.load(Ordering::Relaxed), 1, "the freed one is uncounted");
        let _ = FLOORED.drain_local();
        FLOORED.give(vec_of(64).expect("vec"));
        FLOORED.give(vec_of(64).expect("vec"));
        assert_eq!(FLOORED.evict_local(5), 0, "both are floor objects");
        assert_eq!(FLOORED.local_count(), 2);
        let hot = FLOORED.local_hot_bytes();
        assert_eq!(hot, 0, "floor objects are not counted against the budget");
        assert!(FLOORED.take_raw(|| None).is_some());
        assert_eq!(FLOORED.local_hot_bytes(), 0, "taking a floor object uncounts nothing");
    }

    /// A thread past the slots publishes into the shared overflow slot, and takes its share
    /// out again when it ends (it has no slot of its own to free).
    #[test]
    fn the_overflow_slot_is_emptied_by_the_thread_that_filled_it() {
        let count = || OVER.shared.shown[MAX_THREADS].count.load(Ordering::Relaxed);
        let bytes = || OVER.shared.shown[MAX_THREADS].bytes.load(Ordering::Relaxed);
        std::thread::spawn(move || {
            // What a thread past the first MAX_THREADS is given.
            SLOT.with(|s| s.0.set(MAX_THREADS));
            OVER.give(vec_of(100).expect("vec"));
            OVER.give(vec_of(100).expect("vec"));
            super::publish_local();
            assert_eq!((count(), bytes()), (2, 200));
            OVER.give(vec_of(100).expect("vec"));
            super::publish_local();
            assert_eq!((count(), bytes()), (3, 300), "the change since the last publish");
        })
        .join()
        .expect("thread");
        assert_eq!((count(), bytes()), (0, 0));
    }
}
