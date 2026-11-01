// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy 1.0.2 struct buffer (haproxy.c) and modern src/buf.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! A fixed-capacity byte FIFO with lock-free thread-local size-class pooling.
//!
//! Allocated once at stream setup and never grown, so forwarding never allocates. This
//! is the direct descendant of 1.0's `struct buffer { char *r, *w; int l; ... }`, with
//! the pointer arithmetic replaced by indices.
//!
//! Provides three pool size classes matching `HAProxy`:
//! - **Standard buffer** (`tune.bufsize`, default 16,384 bytes): the main data-path buffer.
//! - **Small buffer** (`tune.bufsize.small`, default 1,024 bytes): for light contexts, with
//!   an explicit automatic promotion path to standard buffer upon overflow.
//! - **Large buffer** (`tune.bufsize.large`, optional, off by default): preallocated per thread
//!   when enabled.

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;
use ibex_alloc::pool::{Pool, PoolDyn, PoolSpec, Poolable};
use ibex_alloc::{declare_pool, PoolHead};

/// Configured buffer sizes (in bytes).
static BUFSIZE_STANDARD: AtomicUsize = AtomicUsize::new(16_384);
static BUFSIZE_SMALL: AtomicUsize = AtomicUsize::new(1_024);
static BUFSIZE_LARGE: AtomicUsize = AtomicUsize::new(0); // 0 means not configured

/// Standard `HAProxy` buffer size constant (16,384 bytes).
pub const BUFSIZE: usize = 16_384;

/// The error a stream's I/O returns when a buffer it needs cannot be had (S5): the stream is
/// failed as `HAProxy` fails one whose allocation failed (`500`, `%ts` `I`), not the process.
/// `ENOMEM` as an OS error: it allocates nothing, and it is told apart from the parser's
/// "no room in the HTX" errors, which have the same kind (`OutOfMemory`) and are a `400`.
#[must_use]
pub fn oom() -> std::io::Error {
    std::io::Error::from_raw_os_error(nix::libc::ENOMEM)
}

/// Whether `e` is [`oom`] (not any error of kind `OutOfMemory`).
#[must_use]
pub fn is_oom(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(nix::libc::ENOMEM)
}

/// Returns current configured standard buffer size (`tune.bufsize`).
#[must_use]
pub fn get_bufsize() -> usize {
    BUFSIZE_STANDARD.load(Ordering::Relaxed)
}

/// Returns current configured small buffer size (`tune.bufsize.small`).
#[must_use]
pub fn get_bufsize_small() -> usize {
    BUFSIZE_SMALL.load(Ordering::Relaxed)
}

/// Returns current configured large buffer size (`tune.bufsize.large`).
#[must_use]
pub fn get_bufsize_large() -> Option<usize> {
    let sz = BUFSIZE_LARGE.load(Ordering::Relaxed);
    if sz > 0 {
        Some(sz)
    } else {
        None
    }
}


/// Standard buffers ever taken from the heap (never decremented): what `trim_idle` watches.
/// Written on the miss path only.
static BUF_STD_FRESH: AtomicUsize = AtomicUsize::new(0);

/// The memory of a buffer, as the pools hold it. `CLASS` is 0 for the standard size, 1 for the
/// small and 2 for the large one; the size is read when a new one is made, so a pool never
/// has to know it.
pub struct Mem<const CLASS: u8>(Box<[u8]>);

impl<const CLASS: u8> Mem<CLASS> {
    /// The size of this class now.
    fn size() -> usize {
        match CLASS {
            0 => get_bufsize(),
            1 => get_bufsize_small(),
            _ => get_bufsize_large().unwrap_or(65536),
        }
    }
}

impl<const CLASS: u8> Poolable for Mem<CLASS> {
    #[inline]
    fn footprint(&self) -> usize {
        self.0.len()
    }
    /// Nothing: the owner (`Buf`'s drop) zeroed what was written before it gave the memory
    /// back, and only what was written (`hwm`).
    #[inline]
    fn reset(&mut self, _wipe: bool) {}
    /// Only memory of the size configured now is pooled: one grown by a head rewrite, or made
    /// before the sizes were set, is freed.
    #[inline]
    fn keep(&self, max_footprint: usize) -> bool {
        self.0.len() == Self::size() && self.0.len() <= max_footprint
    }
    fn nominal_size() -> usize {
        Self::size()
    }
    fn try_new() -> Option<Self> {
        let m = try_zeroed(Self::size())?;
        if CLASS == 0 {
            BUF_STD_FRESH.fetch_add(1, Ordering::Relaxed);
        }
        Some(Mem(m))
    }
}

// Floor 64: what a thread has always kept, and what keeps the steady state at no malloc
// (design 3.3). The floor objects are not counted against `tune.memory.hot-size`.
// `limited`: `tune.buffers.limit` counts the standard buffers (`pool_head_buffer->limit`).
// `presized`: `tune.memory.prealloc` sizes it from `maxconn` (T468, [`prealloc_standard`]).
declare_pool!(static BUF_STD: Pool<Mem<0>> = PoolSpec::new("buffer").floor(MAX_CACHED_PER_THREAD).max_count(MAX_CACHED_PER_THREAD).align(64).limited().presized(););
declare_pool!(static BUF_SMALL: Pool<Mem<1>> = PoolSpec::new("small_buffer").floor(MAX_CACHED_PER_THREAD).max_count(MAX_CACHED_PER_THREAD).align(64););
declare_pool!(static BUF_LARGE: Pool<Mem<2>> = PoolSpec::new("large_buffer").floor(MAX_CACHED_PER_THREAD).max_count(MAX_CACHED_PER_THREAD).align(64););

/// One pool as `show pools` prints it; this thread's counts are published first, so that a
/// caller reading its own buffers sees them at once.
fn pool_head<const C: u8>(pool: &'static Pool<Mem<C>>) -> PoolHead {
    ibex_alloc::pool::publish_local();
    PoolDyn::head(pool)
}

/// Provider for the standard buffer pool (`show pools`).
pub fn buffer_pool_stats() -> Option<PoolHead> {
    Some(pool_head(&BUF_STD))
}

/// Provider for the small buffer pool (`show pools`).
pub fn small_buffer_pool_stats() -> Option<PoolHead> {
    Some(pool_head(&BUF_SMALL))
}

/// Provider for the large buffer pool (`show pools`); none when not configured.
pub fn large_buffer_pool_stats() -> Option<PoolHead> {
    get_bufsize_large()?;
    Some(pool_head(&BUF_LARGE))
}

fn register_arena_pools(reg: &ibex_alloc::PoolRegistry) {
    reg.register_provider("session", crate::engine::session_pool_stats);
    reg.register_provider("appctx", crate::applet::appctx_pool_stats);
    reg.register_provider("task", ibex_sched::task_pool_stats);
    // The `ibex_alloc::Pool`s list themselves when first used; these are listed from the start.
    crate::reuse::register_pools();
}

static INIT_REGISTRY: Once = Once::new();

/// Ensures buffer pool stats providers are registered in [`ibex_alloc::global_pool_registry`].
pub fn ensure_registered() {
    INIT_REGISTRY.call_once(|| {
        let reg = ibex_alloc::global_pool_registry();
        BUF_STD.register();
        BUF_SMALL.register();
        register_arena_pools(reg);
    });
}

/// Initializes buffer size classes and registers pool providers.
pub fn init_buffer_sizes(standard: usize, small: usize, large: Option<usize>) {
    let standard = (standard + 15) & !15;
    let small = (small + 15) & !15;
    BUFSIZE_STANDARD.store(standard, Ordering::SeqCst);
    ibex_sample::registry::set_trash_size(standard);
    BUFSIZE_SMALL.store(small, Ordering::SeqCst);
    if let Some(l) = large {
        let large_rounded = (l + 15) & !15;
        BUFSIZE_LARGE.store(large_rounded, Ordering::SeqCst);
    } else {
        BUFSIZE_LARGE.store(0, Ordering::SeqCst);
    }

    // Memory made for other sizes is of no use now.
    let _ = (BUF_STD.drain_local(), BUF_SMALL.drain_local(), BUF_LARGE.drain_local());
    BUF_STD.register();
    BUF_SMALL.register();
    register_arena_pools(ibex_alloc::global_pool_registry());
    if large.is_some() {
        BUF_LARGE.register();
    }
}

/// Size class descriptor for a pooled or custom buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufClass {
    Small,
    Standard,
    Large,
    Custom,
}

const MAX_CACHED_PER_THREAD: usize = 64;

/// Number of times the idle hook gave free heap memory back to the system.
static HEAP_TRIMS: AtomicUsize = AtomicUsize::new(0);

/// Fresh heap buffers it takes since the last trim for another one to be worth it.
const TRIM_MIN_FRESH: usize = 64;
/// How long no buffer has had to come from the heap before the pages are given back.
const TRIM_QUIET: std::time::Duration = std::time::Duration::from_millis(500);

struct TrimState {
    seen: usize,
    changed: Option<std::time::Instant>,
    trimmed_at: usize,
}

/// Process-wide trim state so only one thread claims a quiet period (T321).
static TRIM_STATE: std::sync::Mutex<TrimState> =
    std::sync::Mutex::new(TrimState { seen: 0, changed: None, trimmed_at: 0 });

/// Number of times the idle hook gave free heap memory back to the system.
#[must_use]
pub fn heap_trims() -> usize {
    HEAP_TRIMS.load(Ordering::Relaxed)
}

/// Gives the allocator's free pages back once a burst is over (T318). A burst of
/// connections in flight needs a buffer each, hundreds at once; they are freed afterwards
/// (the pool caches only `MAX_CACHED_PER_THREAD`), but glibc keeps the pages in its free
/// lists and RSS stays at the peak -- 9 KB per connection after 1000 slow clients, where
/// `HAProxy` is at 4.5 KB. `HAProxy` has the same `malloc_trim` in its pool garbage
/// collector. Called on every pass of the engine loop (at most every 100 ms): when at
/// least `TRIM_MIN_FRESH` buffers had to be allocated from the heap since the last trim and
/// none has been for `TRIM_QUIET`, the trim is done.
pub fn trim_idle(now: std::time::Instant) {
    let allocated = BUF_STD_FRESH.load(Ordering::Relaxed);
    let mut state = TRIM_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if allocated != state.seen || state.changed.is_none() {
        state.seen = allocated;
        state.changed = Some(now);
        return;
    }
    let quiet = state.changed.is_some_and(|c| now.saturating_duration_since(c) >= TRIM_QUIET);
    let mut claimed = false;
    if quiet && allocated.wrapping_sub(state.trimmed_at) >= TRIM_MIN_FRESH {
        state.trimmed_at = allocated;
        claimed = true;
    }
    drop(state);
    if claimed && ibex_alloc::trim_heap() {
        HEAP_TRIMS.fetch_add(1, Ordering::Relaxed);
    }
}

/// `pool_gc` (T445) empties these caches with the others (`ibex_alloc::drain_local_pools`).
/// Preallocates three large buffers in the current thread's cache if large buffers are configured.
pub fn preallocate_large_buffers() {
    if get_bufsize_large().is_some() {
        BUF_LARGE.prefill(3);
    }
}

/// A buffer's memory from the pool of its class, counted as in use. Not inlined into the many
/// callers: the pool is a known static here.
/// `n` zeroed bytes, or `None` when the allocator has none (S5: the caller fails its stream; a
/// `vec!` would abort the process).
pub(crate) fn try_zeroed(n: usize) -> Option<Box<[u8]>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).ok()?;
    v.resize(n, 0);
    Some(v.into_boxed_slice())
}

/// A buffer's memory from the pool of its class, or `None` (`failures` counted by the pool).
#[inline(never)]
fn take_mem<const C: u8>(pool: &'static Pool<Mem<C>>) -> Option<Box<[u8]>> {
    match pool.take_counted(Mem::<C>::try_new) {
        Some(m) => Some(m.0),
        None => take_mem_again(pool),
    }
}

/// The allocator refused a buffer: every cache is given back and it is asked once more (design
/// 3.5, `pool_gc` then retry, as `HAProxy`'s `pool_alloc_nocache`). Not when the pool is at
/// its limit, which a collection does not change, nor when `tune.fail-alloc` refused it, which
/// `HAProxy` does not retry either.
#[cold]
#[inline(never)]
fn take_mem_again<const C: u8>(pool: &'static Pool<Mem<C>>) -> Option<Box<[u8]>> {
    if ibex_alloc::pool::take_injected() || pool.at_limit() {
        return None;
    }
    crate::pool_gc::pool_gc();
    pool.take_counted(Mem::<C>::try_new).map(|m| m.0)
}

/// Gives a buffer's memory back to the pool of its class.
#[inline(never)]
fn give_mem<const C: u8>(pool: &'static Pool<Mem<C>>, data: Box<[u8]>) {
    pool.give_counted(Mem(data));
}

/// `tune.buffers.limit`: the most standard buffers the process holds at once, cached ones
/// included (0: no limit; `HAProxy` raises 1 and 2 to 3, as the parser does). A take past it is
/// refused, and the stream waits for one ([`crate::buf_wait`], S6).
pub fn set_buffers_limit(n: usize) {
    BUF_STD.set_limit(n);
    // S6b: a thread's cache can hold buffers counted against the limit while another thread's
    // stream waits; they go to the pool's shelf (room for the limit, made now), and putting
    // them there wakes the waiting threads.
    BUF_STD.set_on_shelve(crate::buf_wait::shelved);
    // Memory short at start: the shelf has what room it got (`shelve_local` moves no more),
    // and a waiter beyond it waits for its own thread's buffers, as before.
    let _ = n != 0 && BUF_STD.reserve_shelf();
}

// `tune.buffers.reserve` (S6b, `HAProxy`'s `th_ctx->emergency_bufs`, `src/dynbuf.c`): each
// thread makes this many standard buffers at start and keeps them aside. A take the pool refuses
// may have one, by its class (`b_may_alloc_for_crit`: `left * 3 >= q * reserve`, so a client's
// first receive buffer only while the reserve is full, a local reply down to the last); a
// buffer given back refills the reserve before the pool.

/// `tune.buffers.reserve` when it is not set (`RESERVED_BUFS`, include/haproxy/defaults.h).
pub const RESERVED_BUFS: usize = 4;


/// `tune.buffers.limit` `limit` with `tune.buffers.reserve` `reserve` on `nbthread` threads:
/// the limit each emergency buffer raises by one (`dynbuf.c:285`), none without a limit.
#[must_use]
pub fn limit_with_reserve(limit: usize, reserve: usize, nbthread: usize) -> usize {
    if limit == 0 { 0 } else { limit.saturating_add(reserve.saturating_mul(nbthread.max(1))) }
}

/// Makes this thread's `reserve` emergency buffers (at start, after [`init_buffer_sizes`] and
/// [`set_buffers_limit`] with [`limit_with_reserve`]). False when memory is short.
#[must_use]
pub fn fill_emergency(reserve: usize) -> bool {
    ensure_registered();
    BUF_STD.fill_reserve(reserve, || take_mem(&BUF_STD).map(Mem))
}

/// An emergency buffer for a take of queue `q` the pool refused, if the reserve allows it.
fn take_emergency(q: usize) -> Option<Box<[u8]>> {
    BUF_STD.take_reserve(q).map(|m| m.0)
}

/// A standard buffer given back: into the reserve if it lacks one (`__b_free`), else back.
#[inline(always)]
#[allow(clippy::inline_always)] // one thread-local read on the give path
fn refill_emergency(data: Box<[u8]>) -> Option<Box<[u8]>> {
    if BUF_STD.reserve_lacks() { refill_slow(data) } else { Some(data) }
}

#[cold]
#[inline(never)]
fn refill_slow(data: Box<[u8]>) -> Option<Box<[u8]>> {
    // A buffer of another size (`tune.bufsize` changed) is not an emergency one.
    if data.len() != get_bufsize() {
        return Some(data);
    }
    BUF_STD.refill_reserve(Mem(data)).map(|m| m.0)
}

/// Puts this thread's cached standard buffers on the pool's shelf for another thread's waiters
/// (S6b); how many.
#[must_use]
pub fn shelve_standard() -> usize {
    BUF_STD.shelve_local()
}

/// Standard buffers in this thread's cache.
#[must_use]
pub fn cached_standard() -> usize {
    BUF_STD.local_count()
}

/// Standard buffers on the pool's shelf.
#[must_use]
pub fn shelved_standard() -> usize {
    BUF_STD.shelf_len()
}

/// `tune.memory.prealloc` (T468): this thread's cache of standard buffers holds `n`, made now,
/// kept whatever the budget and `pool_gc`. False when memory is short. After
/// [`init_buffer_sizes`], on the worker thread.
pub fn prealloc_standard(n: usize) -> bool {
    ensure_registered();
    BUF_STD.prealloc(n)
}

/// Whether the standard buffer pool is at `tune.buffers.limit`: a stream refused one waits
/// (S6, [`crate::buf_wait`]).
#[must_use]
pub fn standard_at_limit() -> bool {
    BUF_STD.at_limit()
}

fn alloc_standard() -> Option<Box<[u8]>> {
    ensure_registered();
    take_mem(&BUF_STD)
}

fn alloc_small() -> Option<Box<[u8]>> {
    ensure_registered();
    take_mem(&BUF_SMALL)
}

fn alloc_large() -> Option<Box<[u8]>> {
    ensure_registered();
    take_mem(&BUF_LARGE)
}

/// The `lo` value when no descriptors were written.
const NO_LO: u32 = u32::MAX;

/// Zeroes `0..hwm` and `lo..` of `data` (see `Buf`'s `hwm` and `lo`).
fn wipe_marked(data: &mut [u8], hwm: u32, lo: u32) {
    let n = (hwm as usize).min(data.len());
    if n > 0 {
        ibex_alloc::wipe(&mut data[..n]);
    }
    if (lo as usize) < data.len() {
        ibex_alloc::wipe(&mut data[(lo as usize).max(n)..]);
    }
}

/// An offset as kept in the high-water marks (4 bytes each, the buffers being far smaller):
/// one that does not fit is `u32::MAX`, which zeroes to the end, never too little.
fn to_mark(v: usize) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// [`Buf::eoh`] not looked for since the bytes last changed.
const EOH_UNKNOWN: u32 = 0;
/// [`Buf::eoh`] looked for and not found. An end found has `e - 1` in the low two bits,
/// never 0, so neither of these is one.
const EOH_NONE: u32 = 4;

/// [`Buf::eoh`] as kept: the end at `h` of length `e` (2, 3 or 4) as `h << 2 | (e - 1)`, or
/// unknown when `h` does not fit (it is then looked for each time).
fn eoh_pack(eoh: Option<(usize, usize)>) -> u32 {
    match eoh {
        None => EOH_NONE,
        Some((h, e)) => match u32::try_from(h) {
            Ok(h) if h < 1 << 30 && (2..=4).contains(&e) => h << 2 | (e as u32 - 1),
            _ => EOH_UNKNOWN,
        },
    }
}

/// The [`Buf::eoh`] that [`eoh_pack`] kept, if one is.
fn eoh_unpack(v: u32) -> Option<Option<(usize, usize)>> {
    match v {
        EOH_UNKNOWN => None,
        EOH_NONE => Some(None),
        v if v & 3 == 0 => None,
        v => Some(Some(((v >> 2) as usize, (v & 3) as usize + 1))),
    }
}

/// A fixed-capacity FIFO of bytes with size-class pooling.
///
/// Data lives in `[head, head+len)`. Rather than a true ring, the buffer compacts when
/// the tail runs out of room, exactly as `HAProxy`'s does: a proxy's access pattern is
/// fill-then-drain, so a compaction is rare and a wrap check on every byte is not.
#[derive(Debug)]
pub struct Buf {
    data: Box<[u8]>,
    head: usize,
    len: usize,
    /// High-water mark: no byte at or past it was ever written, so releasing the buffer
    /// zeroes `0..hwm` only (`tune.ibex.zero-buffers`, T437 5b). Raised by every method
    /// that makes bytes readable; [`Self::raw_slice_mut`] raises it to the capacity.
    hwm: u32,
    /// The HTX layout keeps its block descriptors at the end of the memory: the lowest
    /// offset written there (`usize::MAX`: none). Released, `lo..` is zeroed as well.
    lo: u32,
    class: BufClass,
    /// [`crate::proxy::find_eoh`] of [`Self::readable`], once read: the head is looked up by
    /// several stages of a request and of a response (T433). Every `&mut self` method
    /// forgets it, so it can only be stale through a change this type does not make. Packed
    /// in the padding after `class` (`EohMemo`): the session holds two of these.
    eoh: Cell<u32>,
}

impl Drop for Buf {
    fn drop(&mut self) {
        // Never allocated, or released: nothing to give back.
        if self.data.is_empty() {
            return;
        }
        // The plaintext of this owner must not be what the next one reads (or what is left
        // in the heap): zero what was written, before the box is pooled or freed.
        self.wipe_used();
        let data = std::mem::replace(&mut self.data, Box::new([]));
        match self.class {
            BufClass::Standard => {
                if let Some(data) = refill_emergency(data) {
                    give_mem(&BUF_STD, data);
                }
                crate::buf_wait::offer();
            }
            BufClass::Small => give_mem(&BUF_SMALL, data),
            BufClass::Large => give_mem(&BUF_LARGE, data),
            BufClass::Custom => {}
        }
    }
}

impl Default for Buf {
    fn default() -> Self {
        Self::standard()
    }
}

impl Buf {
    /// Zeroes the bytes that were written (`0..hwm`) when `tune.ibex.zero-buffers` is on.
    #[inline]
    fn wipe_used(&mut self) {
        wipe_marked(&mut self.data, self.hwm, self.lo);
        self.hwm = 0;
        self.lo = NO_LO;
    }

    /// The memory for an HTX written by the caller, whose layout is `tail` bytes of data
    /// from the front and descriptors from the end. Unlike [`Self::raw_slice_mut`] it does
    /// not count the whole capacity as written: the caller says what it wrote with
    /// [`Self::note_htx`], after each use, or the bytes stay when the buffer is released.
    #[must_use]
    pub fn htx_slice_mut(&mut self) -> &mut [u8] {
        self.eoh.set(EOH_UNKNOWN);
        self.alloc_if_needed();
        &mut self.data
    }

    /// X1 (`docs/design/htx-engine-2026-11-01.md` section 2.1): the memory for an HTX over the
    /// first `head_len` readable bytes (the received head), with the last `reserve` bytes of
    /// the memory as its reserve: [`ibex_proto::htx::HtxSlice::over_received`] of what this
    /// returns. Readable bytes that reach into the reserve are moved to the front first;
    /// `None` when they do not fit before it even so, when `head_len` is more than is
    /// readable, or when the buffer has no memory. The caller records what it wrote with
    /// [`Self::note_htx`] (`tail_addr`, descriptor bytes), and while the HTX lives, writes
    /// no more than `region.reserve_start` minus the readable end into [`Self::writable`]:
    /// the reserve is not this buffer's free space then (X2).
    pub fn htx_over_head(&mut self, head_len: usize, reserve: usize) -> Option<(&mut [u8], ibex_proto::htx::HtxRegion)> {
        if self.data.is_empty() || head_len > self.len || reserve > self.data.len() {
            return None;
        }
        let reserve_start = self.data.len() - reserve;
        if self.head + self.len > reserve_start {
            if self.len > reserve_start {
                return None;
            }
            self.compact();
        }
        // An edit may rewrite the head's bytes (a shorter value, a defrag).
        self.eoh.set(EOH_UNKNOWN);
        let region = ibex_proto::htx::HtxRegion { head_start: self.head, head_end: self.head + head_len, reserve_start };
        Some((&mut self.data, region))
    }

    /// Records that an HTX of `tail` data bytes and `desc_bytes` of descriptors is in the
    /// memory ([`Self::htx_slice_mut`]).
    pub fn note_htx(&mut self, tail: usize, desc_bytes: usize) {
        self.hwm = self.hwm.max(to_mark(tail.min(self.data.len())));
        self.lo = self.lo.min(to_mark(self.data.len().saturating_sub(desc_bytes)));
    }

    /// Raises the high-water mark to the end of the data.
    #[inline]
    fn mark(&mut self) {
        self.hwm = self.hwm.max(to_mark(self.head + self.len));
    }

    /// Puts `new` in place of the memory, zeroing what was written to the old one first.
    fn replace_data(&mut self, new: Box<[u8]>) {
        self.wipe_used();
        self.data = new;
    }

    /// Allocates a standard-size buffer from the thread-local pool.
    #[must_use]
    pub fn standard() -> Self {
        let mut b = Self::unallocated(BufClass::Standard);
        b.alloc_if_needed();
        b
    }

    /// Allocates a small-size buffer from the thread-local pool.
    #[must_use]
    pub fn small() -> Self {
        let mut b = Self::unallocated(BufClass::Small);
        b.alloc_if_needed();
        b
    }

    /// Allocates a large-size buffer from the thread-local pool.
    #[must_use]
    pub fn large() -> Self {
        let mut b = Self::unallocated(BufClass::Large);
        b.alloc_if_needed();
        b
    }

    /// Allocates a buffer of the given capacity, mapping matching sizes to their pool class.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        if cap == get_bufsize() {
            Self::standard()
        } else if cap == get_bufsize_small() {
            Self::small()
        } else if Some(cap) == get_bufsize_large() {
            Self::large()
        } else {
            Buf {
                data: try_zeroed(cap).unwrap_or_default(),
                head: 0,
                len: 0,
                hwm: 0,
                lo: NO_LO,
                class: BufClass::Custom,

                eoh: Cell::new(EOH_UNKNOWN),
            }
        }
    }

    /// A buffer of `class` that takes its memory from the pool only when something is
    /// written to it (`b_alloc` on demand): a connection that has nothing in transit holds
    /// none.
    #[must_use]
    pub fn unallocated(class: BufClass) -> Self {
        Buf { data: Box::new([]), head: 0, len: 0, hwm: 0, lo: NO_LO, class, eoh: Cell::new(EOH_UNKNOWN) }
    }

    /// Whether the buffer holds memory now.
    #[must_use]
    #[inline]
    pub fn is_allocated(&self) -> bool {
        !self.data.is_empty()
    }

    /// Gives the memory of an empty pooled buffer back to the thread's pool
    /// (`b_free` once a mux's buffer is drained); the next write takes one again. A buffer
    /// holding data, or of no pool class, is left alone.
    pub fn release(&mut self) {
        self.eoh.set(EOH_UNKNOWN);
        if self.len == 0 && !self.data.is_empty() && self.class != BufClass::Custom {
            drop(std::mem::replace(self, Buf::unallocated(self.class)));
        }
    }

    /// The capacity of the class: what the buffer holds once it has memory.
    fn nominal(&self) -> usize {
        match self.class {
            BufClass::Standard => get_bufsize(),
            BufClass::Small => get_bufsize_small(),
            BufClass::Large => get_bufsize_large().unwrap_or(65536),
            BufClass::Custom => 0,
        }
    }

    /// Takes the memory of the class from the pool unless the buffer has it (`b_alloc`).
    /// `false` when there is none to be had (S5): the buffer stays without memory, every
    /// write to it writes nothing, and the caller fails its stream ([`oom`]).
    #[inline]
    pub fn alloc_if_needed(&mut self) -> bool {
        self.eoh.set(EOH_UNKNOWN);
        !self.data.is_empty() || self.alloc_now()
    }

    /// [`Self::alloc_if_needed`], or for a standard buffer the pool refused, one of the thread's
    /// emergency buffers if the reserve allows a take of queue `class` (`tune.buffers.reserve`, S6b).
    #[inline]
    pub fn alloc_for(&mut self, class: crate::buf_wait::Class) -> bool {
        self.alloc_if_needed() || self.alloc_emergency(class)
    }

    #[cold]
    #[inline(never)]
    fn alloc_emergency(&mut self, class: crate::buf_wait::Class) -> bool {
        if self.class != BufClass::Standard {
            return false;
        }
        let Some(data) = take_emergency(class as usize) else { return false };
        self.data = data;
        self.head = 0;
        true
    }

    #[cold]
    #[inline(never)]
    fn alloc_now(&mut self) -> bool {
        let data = match self.class {
            BufClass::Standard => alloc_standard(),
            BufClass::Small => alloc_small(),
            BufClass::Large => alloc_large(),
            BufClass::Custom => None,
        };
        let Some(data) = data else { return false };
        self.data = data;
        self.head = 0;
        true
    }

    /// Returns the pool size class this buffer belongs to.
    #[must_use]
    #[inline]
    pub const fn class(&self) -> BufClass {
        self.class
    }

    /// Promotes a [`BufClass::Small`] buffer to [`BufClass::Standard`] capacity.
    ///
    /// Copies existing valid bytes to the new buffer and recycles the small buffer back
    /// to the thread-local small pool without data loss.
    /// Returns `true` if promoted, or `false` if already standard/large/custom.
    pub fn promote_to_standard(&mut self) -> bool {
        self.eoh.set(EOH_UNKNOWN);
        if self.class != BufClass::Small {
            return false;
        }
        if self.data.is_empty() {
            self.class = BufClass::Standard;
            return true;
        }

        // No standard buffer to be had: the bytes stay in the small one, which is full.
        let Some(mut new_data) = alloc_standard() else { return false };
        if self.len > 0 {
            let valid = &self.data[self.head..self.head + self.len];
            new_data[..self.len].copy_from_slice(valid);
        }
        let mut old_small = std::mem::replace(&mut self.data, new_data);
        wipe_marked(&mut old_small, self.hwm, self.lo);
        self.lo = NO_LO;
        self.hwm = to_mark(self.len);
        self.head = 0;
        self.class = BufClass::Standard;

        // Recycle old small buffer back to thread cache
        give_mem(&BUF_SMALL, old_small);

        true
    }

    /// Appends `bytes` to the buffer, automatically promoting from [`BufClass::Small`]
    /// to [`BufClass::Standard`] if needed to prevent truncation.
    pub fn put(&mut self, bytes: &[u8]) -> bool {
        self.eoh.set(EOH_UNKNOWN);
        self.alloc_if_needed();
        if self.head > 0 && self.head + self.len + bytes.len() > self.data.len() {
            self.compact();
        }
        if self.len + bytes.len() > self.data.len() && self.class == BufClass::Small {
            self.promote_to_standard();
        }
        let avail = self.data.len().saturating_sub(self.head + self.len);
        let to_write = bytes.len().min(avail);
        let start = self.head + self.len;
        self.data[start..start + to_write].copy_from_slice(&bytes[..to_write]);
        self.len += to_write;
        self.mark();
        to_write == bytes.len()
    }

    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        if self.data.is_empty() {
            self.nominal()
        } else {
            self.data.len()
        }
    }

    #[must_use]
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == self.capacity()
    }

    /// Returns a shared slice of the entire underlying buffer allocation.
    #[must_use]
    #[inline]
    pub fn raw_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable slice of the entire underlying buffer allocation.
    #[must_use]
    #[inline]
    pub fn raw_slice_mut(&mut self) -> &mut [u8] {
        self.eoh.set(EOH_UNKNOWN);
        self.alloc_if_needed();
        self.hwm = to_mark(self.data.len());
        &mut self.data
    }

    /// Bytes available to read.
    #[must_use]
    #[inline]
    pub fn readable(&self) -> &[u8] {
        &self.data[self.head..self.head + self.len]
    }

    /// [`crate::proxy::find_eoh`] of [`Self::readable`]: the end of the message head at its
    /// start, looked for once until the bytes change.
    #[must_use]
    #[inline]
    pub fn eoh(&self) -> Option<(usize, usize)> {
        if let Some(known) = eoh_unpack(self.eoh.get()) {
            debug_assert_eq!(known, crate::proxy::find_eoh(self.readable()), "stale end of head");
            return known;
        }
        let found = crate::proxy::find_eoh(self.readable());
        self.eoh.set(eoh_pack(found));
        found
    }

    /// Bytes available to read, for changing them in place.
    #[must_use]
    #[inline]
    pub fn readable_mut(&mut self) -> &mut [u8] {
        self.eoh.set(EOH_UNKNOWN);
        &mut self.data[self.head..self.head + self.len]
    }

    /// Lets `edit` change the readable bytes in place, given [`Self::eoh`] of them, on the
    /// promise that it moves no line end (it changes the case of header names, say): the end
    /// of the head stays known. Debug builds check the promise.
    pub fn edit_keeping_lines(&mut self, edit: impl FnOnce(&mut [u8], Option<(usize, usize)>)) {
        let eoh = self.eoh();
        edit(&mut self.data[self.head..self.head + self.len], eoh);
        debug_assert_eq!(eoh, crate::proxy::find_eoh(self.readable()), "an edit kept as in place moved the end of the head");
        self.eoh.set(eoh_pack(eoh));
    }

    /// Moves readable data to index 0 so full remaining capacity is contiguous at the tail.
    pub fn compact(&mut self) {
        self.eoh.set(EOH_UNKNOWN);
        if self.head > 0 {
            if self.len > 0 {
                self.data.copy_within(self.head..self.head + self.len, 0);
            }
            self.head = 0;
        }
    }

    /// Contiguous space available to write into, compacting or promoting if necessary.
    pub fn writable(&mut self) -> &mut [u8] {
        self.eoh.set(EOH_UNKNOWN);
        self.alloc_if_needed();
        if self.head > 0 && self.head + self.len == self.data.len() {
            self.compact();
        }
        if self.is_full() && self.class == BufClass::Small {
            self.promote_to_standard();
        }
        let start = self.head + self.len;
        &mut self.data[start..]
    }

    /// Ensures contiguous writable space of at least `needed` bytes exists,
    /// compacting and/or promoting a small buffer to standard if necessary.
    pub fn ensure_writable(&mut self, needed: usize) -> &mut [u8] {
        self.eoh.set(EOH_UNKNOWN);
        self.alloc_if_needed();
        if self.head > 0 && self.data.len().saturating_sub(self.head + self.len) < needed {
            self.compact();
        }
        let avail = self.data.len().saturating_sub(self.head + self.len);
        if avail < needed && self.class == BufClass::Small {
            self.promote_to_standard();
        }
        let start = self.head + self.len;
        &mut self.data[start..]
    }

    /// Commits `n` bytes written into [`Self::writable`].
    ///
    /// # Panics
    /// If `n` exceeds the space reported by the last `writable()` call.
    pub fn commit(&mut self, n: usize) {
        self.eoh.set(EOH_UNKNOWN);
        assert!(
            self.head + self.len + n <= self.data.len(),
            "commit({n}) past end of buffer"
        );
        self.len += n;
        self.mark();
    }

    /// Discards `n` bytes from the front.
    pub fn consume(&mut self, n: usize) {
        self.eoh.set(EOH_UNKNOWN);
        let n = n.min(self.len);
        self.head += n;
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
        }
    }

    pub fn clear(&mut self) {
        self.eoh.set(EOH_UNKNOWN);
        self.head = 0;
        self.len = 0;
    }

    /// Makes room for at least `min` bytes in all: a message held whole until its end
    /// arrives, longer than the buffer (a chunked body's trailer section behind its head).
    /// `false` when the memory cannot be had (S5): the buffer is as it was.
    pub fn grow_capacity(&mut self, min: usize) -> bool {
        self.eoh.set(EOH_UNKNOWN);
        self.grow_to(min)
    }

    /// Makes the backing store at least `min` bytes, readable data moved to index 0.
    ///
    /// A head rewrite can make the message longer than the buffer it was read into when the
    /// peer filled it (head and the start of a body in one read). Dropping the bytes that no
    /// longer fit would silently lose body bytes the socket already delivered, so the buffer
    /// grows by what the rewrite added. Later reads then see the extra room as ordinary
    /// space and the body behind the head stays intact.
    fn grow_to(&mut self, min: usize) -> bool {
        self.eoh.set(EOH_UNKNOWN);
        if !self.alloc_if_needed() && self.class != BufClass::Custom {
            return false;
        }
        if self.class == BufClass::Small && min > self.data.len() {
            self.promote_to_standard();
        }
        if min > self.data.len() {
            let Some(mut bigger) = try_zeroed(min) else { return false };
            bigger[..self.len].copy_from_slice(&self.data[self.head..self.head + self.len]);
            self.replace_data(bigger);
            self.head = 0;
            self.hwm = to_mark(self.len);
        } else if self.head > 0 {
            self.data.copy_within(self.head..self.head + self.len, 0);
            self.head = 0;
        }
        true
    }

    /// Replaces the leading `old_len` bytes in the readable portion of the buffer
    /// with `new_data`. The remainder is never truncated: the buffer grows if needed.
    pub fn replace_prefix(&mut self, old_len: usize, new_data: &[u8]) {
        self.eoh.set(EOH_UNKNOWN);
        self.alloc_if_needed();
        let old_len = old_len.min(self.len);
        let rem_len = self.len - old_len;
        let needed = new_data.len() + rem_len;
        if needed > self.data.len() && self.class == BufClass::Small {
            self.promote_to_standard();
        }
        let rem_src = self.head + old_len;
        if needed > self.data.len() {
            // Not even a standard buffer holds it: grow, remainder after the new prefix.
            let mut bigger = vec![0u8; needed].into_boxed_slice();
            bigger[new_data.len()..].copy_from_slice(&self.data[rem_src..rem_src + rem_len]);
            bigger[..new_data.len()].copy_from_slice(new_data);
            self.replace_data(bigger);
        } else {
            self.data.copy_within(rem_src..rem_src + rem_len, new_data.len());
            self.data[..new_data.len()].copy_from_slice(new_data);
        }
        self.head = 0;
        self.len = needed;
        self.mark();
    }

    /// Injects or updates an HTTP header in the readable portion of the buffer.
    ///
    /// Compacts the buffer if necessary so readable data starts at index 0 and maximum
    /// tail capacity is available.
    /// Returns `true` if successful, or `false` if buffer capacity was exceeded or malformed.
    pub fn inject_http_header(&mut self, name: &str, value: &str) -> bool {
        self.eoh.set(EOH_UNKNOWN);
        let added_approx = name.len() + value.len() + 4;
        self.grow_to(self.len + added_approx);
        if let Some(new_len) =
            ibex_proto::inject_http_header_with_len(&mut self.data, self.len, name, value)
        {
            self.len = new_len;
            self.mark();
            true
        } else {
            false
        }
    }

    /// Puts `line` (a header line with its CRLF) after the last header of a head that ends in
    /// CRLF CRLF, in place: the tail of the data moves up, nothing is copied through a scratch
    /// buffer, and the end of the head stays known. False, nothing changed, for a head with
    /// another end (a bare LF), no head, or no room.
    pub fn insert_last_header(&mut self, line: &[u8]) -> bool {
        let n = line.len();
        let eoh = self.eoh();
        let Some((h, 4)) = eoh.filter(|_| self.grow_to(self.len + n)) else { return false };
        // `grow_to` left the data at the start of the memory.
        let at = self.head + h + 2;
        self.data.copy_within(at..self.head + self.len, at + n);
        self.data[at..at + n].copy_from_slice(line);
        self.len += n;
        self.mark();
        // The old last header ended at `h`; the new one at `h + n`.
        self.eoh.set(eoh_pack(Some((h + n, 4))));
        true
    }

    /// Cuts `start..end` (offsets in the readable data) out of the buffer.
    pub fn cut(&mut self, start: usize, end: usize) {
        self.eoh.set(EOH_UNKNOWN);
        let (a, b) = (self.head + start.min(self.len), self.head + end.min(self.len));
        self.data.copy_within(b..self.head + self.len, a);
        self.len -= b - a;
    }

    /// Removes all occurrences of an HTTP header from the readable portion of the buffer.
    ///
    /// Returns `true` if successful, or `false` if the buffer is malformed.
    pub fn remove_http_header(&mut self, name: &str) -> bool {
        self.eoh.set(EOH_UNKNOWN);
        self.alloc_if_needed();
        if self.head > 0 {
            self.data.copy_within(self.head..self.head + self.len, 0);
            self.head = 0;
        }
        if let Some(new_len) =
            ibex_proto::remove_http_header_with_len(&mut self.data, self.len, name)
        {
            self.len = new_len;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Buf;

    /// X1: the head of the readable bytes indexed in place, its descriptors in the reserve at
    /// the end of the memory; the body between them is not touched, and readable bytes that
    /// reach into the reserve are moved to the front first.
    #[test]
    fn a_received_head_is_indexed_over_the_buffer_with_the_reserve_at_its_end() {
        let head = b"GET / HTTP/1.1\r\nHost: h\r\nX-MiXed: v\r\n\r\n";
        let mut b = Buf::with_capacity(256);
        // 100 bytes read and consumed: the head starts at 100 and its body reaches past 192.
        b.ensure_writable(100)[..100].fill(b'z');
        b.commit(100);
        b.consume(99);
        let w = b.ensure_writable(head.len() + 60);
        w[..head.len()].copy_from_slice(head);
        w[head.len()..head.len() + 60].fill(b'B');
        b.commit(head.len() + 60);
        b.consume(1);
        assert!(b.htx_over_head(head.len() + 61, 64).is_none(), "the head is longer than the readable bytes");
        assert!(b.htx_over_head(head.len(), 256).is_none(), "the reserve leaves no room for the bytes");
        let (mem, region) = b.htx_over_head(head.len(), 128).expect("fits once compacted");
        assert_eq!((region.head_start, region.head_end, region.reserve_start), (0, head.len(), 128));
        let mut htx = ibex_proto::htx::HtxSlice::over_received(mem, region).unwrap();
        let mut p = ibex_proto::H1Parser::new(false);
        assert_eq!(p.index_head_in_place(&mut htx).unwrap(), head.len());
        assert_eq!(htx.as_ref().get_header_bytes(b"x-mixed"), Some(&b"v"[..]));
        assert_eq!(htx.headers().map(|(n, _)| n).collect::<Vec<_>>(), ["Host", "X-MiXed"]);
        let (tail, descs) = (htx.tail_addr(), htx.num_blocks() * ibex_proto::htx::HTX_DESC_SIZE);
        b.note_htx(tail, descs);
        assert_eq!(&b.readable()[..head.len()], head);
        assert_eq!(&b.readable()[head.len()..], &[b'B'; 60][..]);
    }

    /// T183: a buffer of a pooled class holds memory only between a write and the release
    /// that follows its draining; its capacity is its class's either way.
    #[test]
    fn an_unallocated_buffer_takes_memory_on_write_and_gives_it_back_empty() {
        use super::{get_bufsize, get_bufsize_large, get_bufsize_small, BufClass};
        for (class, cap) in [
            (BufClass::Standard, get_bufsize()),
            (BufClass::Small, get_bufsize_small()),
            (BufClass::Large, get_bufsize_large().unwrap_or(65536)),
        ] {
            let mut b = Buf::unallocated(class);
            assert!(!b.is_allocated());
            assert_eq!(b.capacity(), cap);
            assert!(!b.is_full());
            b.ensure_writable(2)[..2].copy_from_slice(b"ab");
            b.commit(2);
            assert!(b.is_allocated());
            b.release();
            assert!(b.is_allocated(), "a buffer holding data keeps it");
            b.consume(2);
            b.release();
            assert!(!b.is_allocated());
            assert_eq!(b.class(), class);
        }
        // A small one with no memory yet is promoted without taking any.
        let mut b = Buf::unallocated(BufClass::Small);
        assert!(b.promote_to_standard());
        assert!(!b.is_allocated());
        assert_eq!(b.capacity(), get_bufsize());
        // A buffer of no class is never released, and has no memory to take.
        let mut c = Buf::with_capacity(3);
        c.release();
        assert!(c.is_allocated());
        let mut z = Buf::unallocated(BufClass::Custom);
        assert_eq!(z.capacity(), 0);
        assert!(z.writable().is_empty());
    }

    #[test]
    fn fills_drains_and_resets() {
        let mut b = Buf::with_capacity(8);
        assert!(b.is_empty());
        b.writable()[..4].copy_from_slice(b"abcd");
        b.commit(4);
        assert_eq!(b.readable(), b"abcd");
        b.consume(2);
        assert_eq!(b.readable(), b"cd");
        b.consume(2);
        assert!(b.is_empty());
        assert_eq!(b.capacity(), 8, "capacity never changes");
    }

    #[test]
    fn compacts_rather_than_wrapping() {
        let mut b = Buf::with_capacity(8);
        b.writable()[..8].copy_from_slice(b"12345678");
        b.commit(8);
        assert!(b.is_full());
        b.consume(6);
        assert_eq!(b.readable(), b"78");
        // Tail is exhausted; writable() must compact to expose room again.
        let w = b.writable();
        assert_eq!(w.len(), 6, "compaction should free the consumed prefix");
        w[..3].copy_from_slice(b"abc");
        b.commit(3);
        assert_eq!(b.readable(), b"78abc");
    }

    #[test]
    fn partial_consume_preserves_order() {
        let mut b = Buf::with_capacity(16);
        for chunk in [b"aa".as_slice(), b"bb", b"cc"] {
            let w = b.writable();
            w[..chunk.len()].copy_from_slice(chunk);
            b.commit(chunk.len());
        }
        assert_eq!(b.readable(), b"aabbcc");
        b.consume(3);
        assert_eq!(b.readable(), b"bcc");
    }

    #[test]
    fn over_consume_is_clamped_not_a_panic() {
        let mut b = Buf::with_capacity(4);
        b.writable()[..2].copy_from_slice(b"hi");
        b.commit(2);
        b.consume(999);
        assert!(b.is_empty());
    }

    #[test]
    fn replace_prefix_shrink_and_grow() {
        let mut b = Buf::with_capacity(32);
        b.writable()[..7].copy_from_slice(b"1234rem");
        b.commit(7);
        assert_eq!(b.readable(), b"1234rem");

        // Grow prefix
        b.replace_prefix(4, b"ABCDE");
        assert_eq!(b.readable(), b"ABCDErem");

        // Shrink prefix
        b.replace_prefix(5, b"XYZ");
        assert_eq!(b.readable(), b"XYZrem");
    }

    #[test]
    fn the_end_of_the_head_packs_and_unpacks() {
        use super::{eoh_pack, eoh_unpack};
        for eoh in [None, Some((0, 2)), Some((0, 3)), Some((0, 4)), Some((1, 2)), Some((14, 4)), Some((23, 3)), Some((1 << 29, 2)), Some(((1 << 30) - 1, 4))] {
            assert_eq!(eoh_unpack(eoh_pack(eoh)), Some(eoh), "{eoh:?}");
        }
        for eoh in [Some((1 << 30, 4)), Some((usize::MAX, 2)), Some((5, 1)), Some((5, 5))] {
            assert_eq!(eoh_unpack(eoh_pack(eoh)), None, "{eoh:?}");
        }
    }

    /// T433: the end of the head a buffer remembers is the one of its bytes after every way
    /// of changing them: read once, changed, read again.
    #[test]
    fn the_end_of_the_head_follows_every_change() {
        use crate::proxy::find_eoh;
        let req: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\n\nrest";
        let fresh = |b: &Buf| find_eoh(b.readable());
        let filled = |cap: usize| {
            let mut b = Buf::with_capacity(cap);
            assert!(b.put(req));
            assert_eq!(b.eoh(), Some((23, 4)));
            b
        };
        let mut edits: Vec<(&str, Box<dyn Fn(&mut Buf)>)> = vec![
            ("put", Box::new(|b| { b.clear(); b.put(b"A\r\n"); b.eoh(); b.put(b"\r\n"); })),
            ("commit", Box::new(|b| { b.clear(); b.put(b"A\n"); b.eoh(); b.writable()[0] = b'\n'; b.commit(1); })),
            ("ensure_writable", Box::new(|b| { b.clear(); b.put(b"A\n"); b.eoh(); b.ensure_writable(1)[0] = b'\n'; b.commit(1); })),
            ("consume", Box::new(|b| b.consume(27))),
            ("clear", Box::new(Buf::clear)),
            ("readable_mut", Box::new(|b| b.readable_mut()[16..18].copy_from_slice(b"\r\n"))),
            ("raw_slice_mut", Box::new(|b| b.raw_slice_mut()[16..18].copy_from_slice(b"\r\n"))),
            ("replace_prefix", Box::new(|b| b.replace_prefix(27, b"GET / HTTP/1.1\r\n\r\n"))),
            ("inject_http_header", Box::new(|b| assert!(b.inject_http_header("X-Added", "1")))),
            ("remove_http_header", Box::new(|b| assert!(b.remove_http_header("Host")))),
            ("cut", Box::new(|b| b.cut(16, 25))),
            ("compact", Box::new(|b| { b.consume(3); b.eoh(); b.compact(); })),
            ("grow_capacity", Box::new(|b| { b.consume(3); b.eoh(); b.grow_capacity(256); })),
            ("release", Box::new(|b| { b.clear(); b.eoh(); b.release(); })),
            ("edit_keeping_lines", Box::new(|b| b.edit_keeping_lines(|d, _| d[16..20].make_ascii_uppercase()))),
        ];
        edits.push(("promote_to_standard", Box::new(|b| { b.promote_to_standard(); })));
        for (name, edit) in &edits {
            for cap in [64, 4096] {
                let mut b = filled(cap);
                edit(&mut b);
                let want = fresh(&b);
                assert_eq!(b.eoh(), want, "{name}");
                assert_eq!(b.eoh(), want, "{name}, read again");
            }
        }
        let mut small = Buf::small();
        assert!(small.put(b"GET / HTTP/1.1\r\n\r\n"));
        assert_eq!(small.eoh(), Some((14, 4)));
        assert!(small.promote_to_standard());
        assert_eq!(small.eoh(), Some((14, 4)));
    }

    #[test]
    fn rewrite_of_a_full_buffer_keeps_every_byte() {
        let mut b = Buf::with_capacity(32);
        b.writable()[..32].copy_from_slice(b"HEAD\r\n\r\n0123456789abcdefghijklmn");
        b.commit(32);
        b.replace_prefix(8, b"LONGER-HEAD\r\n\r\n");
        assert_eq!(b.readable(), b"LONGER-HEAD\r\n\r\n0123456789abcdefghijklmn");

        let mut b = Buf::with_capacity(40);
        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODYBODY";
        b.writable()[..req.len()].copy_from_slice(req);
        b.commit(req.len());
        assert!(b.inject_http_header("X-Added", "1234567890"));
        assert_eq!(b.readable(), b"GET / HTTP/1.1\r\nHost: x\r\nX-Added: 1234567890\r\n\r\nBODYBODY");
    }

    #[test]
    fn rewrite_of_a_small_or_consumed_buffer_keeps_every_byte() {
        let mut b = Buf::small();
        let n = b.capacity();
        let mut req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        req.resize(n, b'z');
        b.writable()[..n].copy_from_slice(&req);
        b.commit(n);
        assert!(b.inject_http_header("X-Added", "1"));
        assert_eq!(b.len(), n + "X-Added: 1\r\n".len());
        assert!(b.readable().ends_with(&req[req.len() - 100..]));

        // A full small buffer whose prefix grows is promoted to a standard one.
        let mut b = Buf::small();
        let n = b.capacity();
        b.writable()[..n].fill(b'r');
        b.commit(n);
        b.replace_prefix(4, b"a-longer-prefix");
        assert_eq!(b.len(), n - 4 + 15);
        assert!(b.readable().starts_with(b"a-longer-prefixrrrr"));

        // A buffer whose front was consumed is compacted, not truncated.
        let mut b = Buf::with_capacity(64);
        let req = b"junkGET / HTTP/1.1\r\nHost: x\r\n\r\nBODY";
        b.writable()[..req.len()].copy_from_slice(req);
        b.commit(req.len());
        b.consume(4);
        assert!(b.inject_http_header("X-Added", "1"));
        assert_eq!(b.readable(), b"GET / HTTP/1.1\r\nHost: x\r\nX-Added: 1\r\n\r\nBODY");
    }

    #[test]
    fn buf_http_header_injection_and_removal() {
        let mut b = Buf::with_capacity(256);
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        b.writable()[..req.len()].copy_from_slice(req);
        b.commit(req.len());

        // Inject new header
        assert!(b.inject_http_header("X-Forwarded-Proto", "https"));
        let readable_str = std::str::from_utf8(b.readable()).unwrap();
        assert!(readable_str.contains("X-Forwarded-Proto: https\r\n"));
        assert!(readable_str.ends_with("\r\n\r\n"));

        // Update existing header
        assert!(b.inject_http_header("Host", "api.example.com"));
        let updated_str = std::str::from_utf8(b.readable()).unwrap();
        assert!(updated_str.contains("Host: api.example.com\r\n"));
        assert!(!updated_str.contains("Host: example.com\r\n"));

        // Remove header
        assert!(b.remove_http_header("X-Forwarded-Proto"));
        let removed_str = std::str::from_utf8(b.readable()).unwrap();
        assert!(!removed_str.contains("X-Forwarded-Proto"));
        assert_eq!(
            removed_str,
            "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        );
    }

    #[test]
    fn small_buffer_overflow_promotes_to_standard_without_truncating() {
        let mut b = Buf::small();
        assert_eq!(b.capacity(), 1024);
        assert_eq!(b.class(), super::BufClass::Small);

        // Write 1000 bytes into small buffer
        let chunk1 = vec![b'A'; 1000];
        assert!(b.put(&chunk1));
        assert_eq!(b.len(), 1000);
        assert_eq!(b.capacity(), 1024);

        // Overflow by 100 bytes (total 1100 > 1024)
        let chunk2 = vec![b'B'; 100];
        assert!(b.put(&chunk2));
        assert_eq!(b.len(), 1100, "all 1100 bytes must be present without truncation");
        assert_eq!(b.class(), super::BufClass::Standard);
        assert!(b.capacity() >= 16384, "capacity must be at least standard 16384 bytes");
        assert_eq!(&b.readable()[..1000], &chunk1[..]);
        assert_eq!(&b.readable()[1000..1100], &chunk2[..]);
    }
}
