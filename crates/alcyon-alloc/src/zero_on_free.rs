// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.zero-on-free off|soft|hard` (T459): what the process's allocator does with a block
//! when it is freed, for every heap free in the process (rustls and ring state, Alcyon's own
//! objects, std). Pooled objects are not freed: their pools wipe them (`tune.alcyon.zero-buffers`,
//! `zero-spares`, `ssl-zero-buffers`). The stack is not covered.
//!
//! - `off` (default): the block goes to the system allocator as it is.
//! - `hard`: the block is overwritten with zeros (a `memset` the compiler may not drop, the
//!   bytes handed to `black_box` before the free) and then freed. The old block of a
//!   reallocation is wiped too: with the setting on, a reallocation is an allocation, a copy and
//!   a free of the old block, so the C library never moves a block behind the wipe's back.
//! - `soft`: the block goes on this thread's quarantine (an intrusive FIFO: the next pointer,
//!   the size and the time are written over the block's first bytes, so the allocator allocates
//!   nothing) and is wiped and freed later, by the thread's loop pass ([`pass`]): all of it on a
//!   pass that found no events, up to [`PASS_BUDGET_DEFAULT`] bytes on a busy one. A
//!   quarantined block is not reused while it waits.
//!
//! The bounds of `soft`, each of which takes the `hard` path when it is reached:
//! - bytes: a thread holds at most `4 x tune.memory.hot-size` (`set_bounds`); past it the
//!   oldest blocks are wiped and freed at once (`forced`), and a block larger than the bound
//!   does not wait at all;
//! - age: every pass, busy or idle, first wipes what is older than 100 ms (`expired`), so a
//!   freed secret lives at most about that long whatever the load;
//! - `pool_gc` ([`crate::drain_local_pools`]) and a refused allocation empty the quarantine;
//! - a thread's end empties it, and a thread that never ran a pass has none (nothing would
//!   empty it): its frees take the `hard` path.
//!
//! The quarantine is per thread and the fast path takes no lock: a block freed on a thread joins
//! that thread's quarantine. The thread-local state has no destructor (a global allocator may
//! not use one); the thread's end is seen by a second thread-local, which [`pass`] touches from
//! ordinary code. The figures (`show info`) are published by each thread at most every 10 ms.

// The quarantine's header is read and written with `read_unaligned`/`write_unaligned`, whatever
// the block's alignment: the casts to wider pointers are never dereferenced as aligned.
#![allow(clippy::cast_ptr_alignment)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::pool::MAX_THREADS;

/// `tune.alcyon.zero-on-free`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ZeroOnFree {
    /// Freed as it is (the default while Alcyon is compared with `HAProxy`).
    #[default]
    Off,
    /// Quarantined, then wiped and freed when the thread has time, within the bounds.
    Soft,
    /// Wiped, then freed.
    Hard,
}

impl ZeroOnFree {
    /// The configuration word: `off`, `soft` or `hard`.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "off" => Some(Self::Off),
            "soft" => Some(Self::Soft),
            "hard" => Some(Self::Hard),
            _ => None,
        }
    }

    /// The configuration word.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Soft => "soft",
            Self::Hard => "hard",
        }
    }
}

const OFF: u8 = 0;
const SOFT: u8 = 1;
const HARD: u8 = 2;

static MODE: AtomicU8 = AtomicU8::new(OFF);
/// Set once a mode other than `off` was ever set: until then [`pass`] is one load.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The byte bound of a thread's quarantine; 0: four times `tune.memory.hot-size`.
static MAX_BYTES: AtomicUsize = AtomicUsize::new(0);
static MAX_AGE_MS: AtomicU64 = AtomicU64::new(100);
static PASS_BUDGET: AtomicUsize = AtomicUsize::new(PASS_BUDGET_DEFAULT);
/// When the first pass ran: the quarantine's times are milliseconds since then.
static EPOCH: OnceLock<Instant> = OnceLock::new();

/// The bytes a busy pass wipes and frees at most (an idle pass frees everything).
pub const PASS_BUDGET_DEFAULT: usize = 16 * 1024;
const PUBLISH_EVERY_MS: u64 = 10;

/// Sets `tune.alcyon.zero-on-free`. Leaving `soft` empties each thread's quarantine at its next
/// pass.
pub fn set_zero_on_free(mode: ZeroOnFree) {
    let m = match mode {
        ZeroOnFree::Off => OFF,
        ZeroOnFree::Soft => SOFT,
        ZeroOnFree::Hard => HARD,
    };
    if m != OFF {
        ACTIVE.store(true, Ordering::Relaxed);
    }
    MODE.store(m, Ordering::Relaxed);
}

/// `tune.alcyon.zero-on-free`.
#[must_use]
pub fn zero_on_free() -> ZeroOnFree {
    match MODE.load(Ordering::Relaxed) {
        SOFT => ZeroOnFree::Soft,
        HARD => ZeroOnFree::Hard,
        _ => ZeroOnFree::Off,
    }
}

/// The `soft` bounds: the bytes a thread's quarantine holds at most (0: four times
/// `tune.memory.hot-size`) and the age past which a pass frees a block, busy or not.
pub fn set_bounds(max_bytes: usize, max_age: Duration) {
    MAX_BYTES.store(max_bytes, Ordering::Relaxed);
    MAX_AGE_MS.store(u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX), Ordering::Relaxed);
}

/// The bytes a busy pass frees at most ([`PASS_BUDGET_DEFAULT`]).
pub fn set_pass_budget(bytes: usize) {
    PASS_BUDGET.store(bytes, Ordering::Relaxed);
}

fn max_bytes() -> usize {
    match MAX_BYTES.load(Ordering::Relaxed) {
        0 => crate::pool::hot_size().saturating_mul(4),
        n => n,
    }
}

// -----------------------------------------------------------------------------
// The quarantine
// -----------------------------------------------------------------------------

/// What a quarantined block holds in its first bytes: the next block, its size, and its time
/// (milliseconds since [`EPOCH`]) shifted left by 8 over the log2 of its alignment.
const HEADER: usize = 3 * std::mem::size_of::<usize>();

struct Quarantine {
    /// Whether this thread runs passes (so something frees its quarantine).
    on: Cell<bool>,
    head: Cell<*mut u8>,
    tail: Cell<*mut u8>,
    bytes: Cell<usize>,
    blocks: Cell<usize>,
    max_bytes: Cell<usize>,
    now_ms: Cell<u64>,
    next_publish_ms: Cell<u64>,
    slot: Cell<usize>,
    queued: Cell<u64>,
    wiped: Cell<u64>,
    forced: Cell<u64>,
    expired: Cell<u64>,
}

thread_local! {
    /// No destructor: the allocator reads it.
    static Q: Quarantine = const {
        Quarantine {
            on: Cell::new(false),
            head: Cell::new(std::ptr::null_mut()),
            tail: Cell::new(std::ptr::null_mut()),
            bytes: Cell::new(0),
            blocks: Cell::new(0),
            max_bytes: Cell::new(0),
            now_ms: Cell::new(0),
            next_publish_ms: Cell::new(0),
            slot: Cell::new(usize::MAX),
            queued: Cell::new(0),
            wiped: Cell::new(0),
            forced: Cell::new(0),
            expired: Cell::new(0),
        }
    };
    /// Empties the quarantine when the thread ends. Only [`pass`] touches it, never the allocator.
    static END: EndGuard = const { EndGuard };
}

struct EndGuard;

impl Drop for EndGuard {
    fn drop(&mut self) {
        let _ = Q.try_with(|q| {
            q.on.set(false);
            free_all(q);
            for (r, c) in RETIRED.iter().zip([&q.queued, &q.wiped, &q.forced, &q.expired]) {
                r.fetch_add(c.replace(0), Ordering::Relaxed);
            }
            if let Some(s) = SHOWN.get(q.slot.get()) {
                s.clear();
            }
        });
    }
}

/// Overwrites `n` bytes at `ptr` with zeros so that the compiler cannot drop the stores as
/// dead before the free that follows: the pointer is handed to `black_box`, an opaque use.
///
/// # Safety
/// `ptr` is valid for writes of `n` bytes.
#[inline]
unsafe fn wipe(ptr: *mut u8, n: usize) {
    // SAFETY: the caller's.
    unsafe { std::ptr::write_bytes(ptr, 0, n) };
    std::hint::black_box(ptr);
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// Gives a block to the system allocator, through the test watch ([`crate::watch_freed`]).
///
/// # Safety
/// `ptr` was allocated by `System` with `layout`, and is not used again.
#[inline]
unsafe fn system_free(ptr: *mut u8, layout: Layout) {
    // SAFETY: the caller's.
    unsafe {
        crate::watch_on_free(ptr, layout.size());
        System.dealloc(ptr, layout);
    }
}

/// What the global allocators do on `dealloc`: free, wipe and free, or quarantine. `WATCH`: the
/// test watch ([`crate::watch_freed`]) on the `off` path too (the counting allocator); the
/// process's allocator leaves it out of its `off` path, which is then a load and a compare.
///
/// # Safety
/// `ptr` was allocated by `System` with `layout`, and is not used again.
#[inline]
pub(crate) unsafe fn release<const WATCH: bool>(ptr: *mut u8, layout: Layout) {
    let mode = MODE.load(Ordering::Relaxed);
    if mode == OFF {
        // SAFETY: the caller's.
        unsafe {
            if WATCH {
                crate::watch_on_free(ptr, layout.size());
            }
            System.dealloc(ptr, layout);
        }
        return;
    }
    // SAFETY: the caller's.
    unsafe { release_slow(ptr, layout, mode) };
}

#[cold]
#[inline(never)]
unsafe fn release_slow(ptr: *mut u8, layout: Layout, mode: u8) {
    // SAFETY: the caller's.
    if mode == SOFT && layout.size() >= HEADER && unsafe { quarantine(ptr, layout) } {
        return;
    }
    let _ = Q.try_with(|q| q.wiped.set(q.wiped.get() + 1));
    // SAFETY: the caller's: the block is live for `layout.size()` bytes until it is freed.
    unsafe {
        wipe(ptr, layout.size());
        system_free(ptr, layout);
    }
}

/// Puts the block at the tail of this thread's quarantine; false when it is to be wiped now
/// (no passes on this thread, or larger than the bound).
unsafe fn quarantine(ptr: *mut u8, layout: Layout) -> bool {
    Q.try_with(|q| {
        if !q.on.get() {
            return false;
        }
        let size = layout.size();
        let max = q.max_bytes.get();
        if size > max {
            q.forced.set(q.forced.get() + 1);
            return false;
        }
        let meta = (q.now_ms.get() << 8) | u64::from(layout.align().trailing_zeros());
        // SAFETY: the block is at least `HEADER` bytes and ours until it is freed; unaligned
        // writes, whatever the block's alignment.
        unsafe {
            ptr.cast::<usize>().write_unaligned(0);
            ptr.cast::<usize>().add(1).write_unaligned(size);
            ptr.cast::<u64>().add(2).write_unaligned(meta);
        }
        let tail = q.tail.get();
        if tail.is_null() {
            q.head.set(ptr);
        } else {
            // SAFETY: the tail is a quarantined block: its first word is its next pointer.
            unsafe { tail.cast::<usize>().write_unaligned(ptr as usize) };
        }
        q.tail.set(ptr);
        q.bytes.set(q.bytes.get() + size);
        q.blocks.set(q.blocks.get() + 1);
        q.queued.set(q.queued.get() + 1);
        while q.bytes.get() > max {
            free_head(q);
            q.forced.set(q.forced.get() + 1);
        }
        true
    })
    .unwrap_or(false)
}

/// The head block's time, or `None` when the quarantine is empty.
fn head_time(q: &Quarantine) -> Option<u64> {
    let h = q.head.get();
    // SAFETY: a non-null head is a quarantined block with its header.
    (!h.is_null()).then(|| unsafe { h.cast::<u64>().add(2).read_unaligned() } >> 8)
}

/// Wipes and frees the oldest block; returns its size (0: empty).
fn free_head(q: &Quarantine) -> usize {
    let h = q.head.get();
    if h.is_null() {
        return 0;
    }
    // SAFETY: a quarantined block: its header was written by `quarantine`, its size and
    // alignment are the layout it was allocated with, and nothing else refers to it.
    unsafe {
        let next = h.cast::<usize>().read_unaligned() as *mut u8;
        let size = h.cast::<usize>().add(1).read_unaligned();
        let align = 1usize << (h.cast::<u64>().add(2).read_unaligned() & 0xff);
        q.head.set(next);
        if next.is_null() {
            q.tail.set(std::ptr::null_mut());
        }
        q.bytes.set(q.bytes.get() - size);
        q.blocks.set(q.blocks.get() - 1);
        wipe(h, size);
        system_free(h, Layout::from_size_align_unchecked(size, align));
        size
    }
}

fn free_all(q: &Quarantine) -> usize {
    let mut n = 0;
    while free_head(q) != 0 {
        n += 1;
    }
    n
}

/// Empties this thread's quarantine (wiped); returns the blocks freed. For `pool_gc`.
#[must_use]
pub fn drain_local() -> usize {
    Q.try_with(|q| {
        let n = free_all(q);
        publish(q);
        n
    })
    .unwrap_or(0)
}

/// For the allocators' failure path: empties the quarantine without publishing (no atomics a
/// test of the refusal counts). Returns whether anything was freed.
pub(crate) fn drain_for_refusal() -> bool {
    Q.try_with(|q| free_all(q) != 0).unwrap_or(false)
}

/// Once per loop pass of an engine thread, `idle` when the poller returned no events: marks
/// the thread as one with a quarantine, frees what is older than the age bound, then
/// everything (`idle`) or up to the pass budget. One load while the setting was never on.
#[inline]
pub fn pass(now: Instant, idle: bool) {
    if ACTIVE.load(Ordering::Relaxed) {
        pass_slow(now, idle);
    }
}

#[cold]
#[inline(never)]
fn pass_slow(now: Instant, idle: bool) {
    END.with(|_| {});
    let epoch = *EPOCH.get_or_init(|| now);
    let now_ms = u64::try_from(now.saturating_duration_since(epoch).as_millis()).unwrap_or(u64::MAX >> 8);
    let soft = MODE.load(Ordering::Relaxed) == SOFT;
    let max = max_bytes();
    let age = MAX_AGE_MS.load(Ordering::Relaxed);
    let budget = PASS_BUDGET.load(Ordering::Relaxed);
    let _ = Q.try_with(|q| {
        if q.slot.get() == usize::MAX {
            q.slot.set(crate::pool::thread_slot());
        }
        q.on.set(soft);
        q.max_bytes.set(max);
        q.now_ms.set(now_ms);
        if !soft || idle {
            free_all(q);
        } else {
            while head_time(q).is_some_and(|t| t.saturating_add(age) <= now_ms) {
                free_head(q);
                q.expired.set(q.expired.get() + 1);
            }
            let mut spent = 0;
            while spent < budget && !q.head.get().is_null() {
                spent += free_head(q);
            }
            while q.bytes.get() > max {
                free_head(q);
                q.forced.set(q.forced.get() + 1);
            }
        }
        if now_ms >= q.next_publish_ms.get() {
            q.next_publish_ms.set(now_ms + PUBLISH_EVERY_MS);
            publish(q);
        }
    });
}

// -----------------------------------------------------------------------------
// The figures
// -----------------------------------------------------------------------------

/// The quarantine's figures (`show info`): what waits now, and what was done since the start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuarantineStats {
    /// Bytes waiting.
    pub bytes: usize,
    /// Blocks waiting.
    pub blocks: usize,
    /// How long the oldest waiting block has waited, in milliseconds.
    pub oldest_ms: u64,
    /// Blocks that went into a quarantine.
    pub queued: u64,
    /// Blocks wiped at once on their free (`hard`, too small to hold the header, or a thread
    /// without passes).
    pub wiped: u64,
    /// Blocks wiped at once because the byte bound was reached (the `soft` bound against a denial of service).
    pub forced: u64,
    /// Blocks freed by a pass because they reached the age bound (the confidentiality bound).
    pub expired: u64,
}

struct Shown {
    bytes: AtomicUsize,
    blocks: AtomicUsize,
    oldest: AtomicU64,
    counts: [AtomicU64; 4],
}

impl Shown {
    fn clear(&self) {
        self.bytes.store(0, Ordering::Relaxed);
        self.blocks.store(0, Ordering::Relaxed);
        self.oldest.store(u64::MAX, Ordering::Relaxed);
        for c in &self.counts {
            c.store(0, Ordering::Relaxed);
        }
    }
}

static SHOWN: [Shown; MAX_THREADS] = [const {
    Shown { bytes: AtomicUsize::new(0), blocks: AtomicUsize::new(0), oldest: AtomicU64::new(u64::MAX), counts: [const { AtomicU64::new(0) }; 4] }
}; MAX_THREADS];
/// The counts of the threads that ended.
static RETIRED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

fn publish(q: &Quarantine) {
    let Some(s) = SHOWN.get(q.slot.get()) else { return };
    s.bytes.store(q.bytes.get(), Ordering::Relaxed);
    s.blocks.store(q.blocks.get(), Ordering::Relaxed);
    s.oldest.store(head_time(q).unwrap_or(u64::MAX), Ordering::Relaxed);
    for (c, v) in s.counts.iter().zip([&q.queued, &q.wiped, &q.forced, &q.expired]) {
        c.store(v.get(), Ordering::Relaxed);
    }
}

/// This thread's figures, exact.
#[must_use]
pub fn local_stats() -> QuarantineStats {
    Q.try_with(|q| QuarantineStats {
        bytes: q.bytes.get(),
        blocks: q.blocks.get(),
        oldest_ms: head_time(q).map_or(0, |t| q.now_ms.get().saturating_sub(t)),
        queued: q.queued.get(),
        wiped: q.wiped.get(),
        forced: q.forced.get(),
        expired: q.expired.get(),
    })
    .unwrap_or_default()
}

/// The process's figures: every thread's as it last published them (at most 10 ms old), and
/// those of the threads that ended.
#[must_use]
pub fn stats() -> QuarantineStats {
    let mut st = QuarantineStats::default();
    let mut c = [0u64; 4];
    for (t, r) in c.iter_mut().zip(&RETIRED) {
        *t = r.load(Ordering::Relaxed);
    }
    let mut oldest = u64::MAX;
    for s in &SHOWN[..crate::pool::slot_hwm()] {
        st.bytes += s.bytes.load(Ordering::Relaxed);
        st.blocks += s.blocks.load(Ordering::Relaxed);
        oldest = oldest.min(s.oldest.load(Ordering::Relaxed));
        for (t, v) in c.iter_mut().zip(&s.counts) {
            *t += v.load(Ordering::Relaxed);
        }
    }
    let now_ms = EPOCH.get().map_or(0, |e| u64::try_from(e.elapsed().as_millis()).unwrap_or(u64::MAX));
    st.oldest_ms = if oldest == u64::MAX { 0 } else { now_ms.saturating_sub(oldest) };
    [st.queued, st.wiped, st.forced, st.expired] = c;
    st
}

/// The quarantine as a `show pools` line (T470), named as an Alcyon pool since `HAProxy` has no
/// equivalent: present with `soft` only (the other modes keep nothing), `allocated` and `used` are
/// the blocks waiting (as the threads last published them, at most 10 ms old), `size` their mean
/// size, and `alloc_bytes` the exact bytes, which `Total:` adds up.
#[must_use]
pub fn quarantine_head() -> Option<crate::PoolHead> {
    if zero_on_free() != ZeroOnFree::Soft {
        return None;
    }
    let s = stats();
    Some(crate::PoolHead {
        name: "zero_quarantine",
        size: s.bytes.checked_div(s.blocks).unwrap_or(0),
        align: 1,
        allocated: s.blocks,
        alloc_bytes: s.bytes,
        used: s.blocks,
        cached: 0,
        needed_avg: s.blocks,
        failures: 0,
        users: 1,
        reg: None,
    })
}

// -----------------------------------------------------------------------------
// The allocator
// -----------------------------------------------------------------------------

/// A reallocation with the setting on: an allocation by `alloc`, a copy, and the old block
/// released as a free is. Null (the old block kept) when the allocation fails.
///
/// # Safety
/// As [`GlobalAlloc::realloc`].
pub(crate) unsafe fn realloc_by_copy(ptr: *mut u8, layout: Layout, new_size: usize, alloc: impl FnOnce(Layout) -> *mut u8) -> *mut u8 {
    // SAFETY: `GlobalAlloc::realloc`'s contract: `new_size` rounded to the alignment fits.
    let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
    let new = alloc(new_layout);
    if !new.is_null() {
        // SAFETY: both blocks are live and distinct, each at least the smaller size.
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
            release::<true>(ptr, layout);
        }
    }
    new
}

/// Whether reallocations go through [`realloc_by_copy`].
#[inline]
pub(crate) fn wipes() -> bool {
    MODE.load(Ordering::Relaxed) != OFF
}

/// The process's allocator (the `alcyon` binary's `#[global_allocator]`): the system allocator,
/// with `tune.alcyon.zero-on-free` on every free. It counts nothing (no shared write per
/// allocation); the test binaries' [`crate::CountingAllocator`] applies the same setting.
pub struct AlcyonAllocator;

#[allow(unsafe_code)]
// SAFETY: every block comes from `System` and goes back to it with its layout.
unsafe impl GlobalAlloc for AlcyonAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's.
        let p = unsafe { System.alloc(layout) };
        if p.is_null() && drain_for_refusal() {
            // SAFETY: the caller's.
            return unsafe { System.alloc(layout) };
        }
        p
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's.
        let p = unsafe { System.alloc_zeroed(layout) };
        if p.is_null() && drain_for_refusal() {
            // SAFETY: the caller's.
            return unsafe { System.alloc_zeroed(layout) };
        }
        p
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's.
        unsafe { release::<false>(ptr, layout) };
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if wipes() {
            // SAFETY: the caller's.
            return unsafe { realloc_by_copy(ptr, layout, new_size, |l| self.alloc(l)) };
        }
        // SAFETY: the caller's.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if p.is_null() && drain_for_refusal() {
            // SAFETY: the caller's.
            return unsafe { System.realloc(ptr, layout, new_size) };
        }
        p
    }
}
