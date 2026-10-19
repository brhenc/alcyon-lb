// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Allocation counting oracle and fixed-size object memory pools for Project Ibex.
//!
//! Provides:
//! - [`CountingAllocator`]: A global allocator wrapping [`std::alloc::System`] that
//!   tracks allocations, reallocations, frees, and byte volumes for regression pinning.
//! - [`alloc_counters`]: Snapshots allocation counters before and after request processing.
//! - [`Pool`]: Fixed-size object pools with free lists based on index handles (derived from
//!   `ebtree`'s index arena precedent) under `#![forbid(unsafe_code)]`.
//! - [`PoolRegistry`]: Registry for pool tracking and `HAProxy`-compatible `show pools` CLI dumps.

use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

// -----------------------------------------------------------------------------
// Allocation Counters & Oracle (Item 1)
// -----------------------------------------------------------------------------

/// Allocation counters snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AllocCounters {
    pub alloc_count: usize,
    pub realloc_count: usize,
    pub dealloc_count: usize,
    pub bytes_allocated: usize,
    pub bytes_deallocated: usize,
}

impl AllocCounters {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            alloc_count: 0,
            realloc_count: 0,
            dealloc_count: 0,
            bytes_allocated: 0,
            bytes_deallocated: 0,
        }
    }

    #[must_use]
    pub fn bytes_live(&self) -> usize {
        self.bytes_allocated.saturating_sub(self.bytes_deallocated)
    }

    #[must_use]
    pub fn live_allocations(&self) -> usize {
        self.alloc_count.saturating_sub(self.dealloc_count)
    }

    #[must_use]
    pub fn diff(&self, after: &AllocCounters) -> AllocDiff {
        AllocDiff {
            alloc_count: after.alloc_count.saturating_sub(self.alloc_count),
            realloc_count: after.realloc_count.saturating_sub(self.realloc_count),
            dealloc_count: after.dealloc_count.saturating_sub(self.dealloc_count),
            bytes_allocated: after.bytes_allocated.saturating_sub(self.bytes_allocated),
            bytes_deallocated: after.bytes_deallocated.saturating_sub(self.bytes_deallocated),
        }
    }
}

/// Difference between two [`AllocCounters`] snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AllocDiff {
    pub alloc_count: usize,
    pub realloc_count: usize,
    pub dealloc_count: usize,
    pub bytes_allocated: usize,
    pub bytes_deallocated: usize,
}

impl AllocDiff {
    #[must_use]
    pub fn net_bytes(&self) -> isize {
        let alloc = isize::try_from(self.bytes_allocated).unwrap_or(isize::MAX);
        let dealloc = isize::try_from(self.bytes_deallocated).unwrap_or(isize::MAX);
        alloc.saturating_sub(dealloc)
    }
}

static GLOBAL_ALLOCS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// This thread's allocations, deallocations, reallocations, bytes allocated and bytes
    /// deallocated, for [`thread_alloc_counters`]. `const`-initialised, so reading it never
    /// allocates.
    static THREAD: [std::cell::Cell<usize>; 5] = const {
        [const { std::cell::Cell::new(0) }; 5]
    };
}

/// Adds to this thread's counters. `try_with`: during thread teardown the slot may be gone
/// while the thread still frees memory.
fn count_thread(i: usize, n: usize) {
    let _ = THREAD.try_with(|t| t[i].set(t[i].get() + n));
}
static GLOBAL_REALLOCS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_DEALLOCS: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_BYTES_ALLOC: AtomicUsize = AtomicUsize::new(0);
static GLOBAL_BYTES_DEALLOC: AtomicUsize = AtomicUsize::new(0);

/// Global counting allocator wrapping `std::alloc::System`.
pub struct CountingAllocator {
    allocs: AtomicUsize,
    reallocs: AtomicUsize,
    deallocs: AtomicUsize,
    bytes_alloc: AtomicUsize,
    bytes_dealloc: AtomicUsize,
}

impl Default for CountingAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CountingAllocator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allocs: AtomicUsize::new(0),
            reallocs: AtomicUsize::new(0),
            deallocs: AtomicUsize::new(0),
            bytes_alloc: AtomicUsize::new(0),
            bytes_dealloc: AtomicUsize::new(0),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> AllocCounters {
        AllocCounters {
            alloc_count: self.allocs.load(Ordering::SeqCst),
            realloc_count: self.reallocs.load(Ordering::SeqCst),
            dealloc_count: self.deallocs.load(Ordering::SeqCst),
            bytes_allocated: self.bytes_alloc.load(Ordering::SeqCst),
            bytes_deallocated: self.bytes_dealloc.load(Ordering::SeqCst),
        }
    }

    pub fn reset(&self) {
        self.allocs.store(0, Ordering::SeqCst);
        self.reallocs.store(0, Ordering::SeqCst);
        self.deallocs.store(0, Ordering::SeqCst);
        self.bytes_alloc.store(0, Ordering::SeqCst);
        self.bytes_dealloc.store(0, Ordering::SeqCst);
    }
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let sz = layout.size();
            self.allocs.fetch_add(1, Ordering::SeqCst);
            self.bytes_alloc.fetch_add(sz, Ordering::SeqCst);
            GLOBAL_ALLOCS.fetch_add(1, Ordering::SeqCst);
            GLOBAL_BYTES_ALLOC.fetch_add(sz, Ordering::SeqCst);
            count_thread(0, 1);
            count_thread(3, sz);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        let sz = layout.size();
        self.deallocs.fetch_add(1, Ordering::SeqCst);
        self.bytes_dealloc.fetch_add(sz, Ordering::SeqCst);
        GLOBAL_DEALLOCS.fetch_add(1, Ordering::SeqCst);
        GLOBAL_BYTES_DEALLOC.fetch_add(sz, Ordering::SeqCst);
        count_thread(1, 1);
        count_thread(4, sz);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            let old_size = layout.size();
            self.reallocs.fetch_add(1, Ordering::SeqCst);
            GLOBAL_REALLOCS.fetch_add(1, Ordering::SeqCst);
            count_thread(2, 1);
            if new_size > old_size {
                let diff = new_size - old_size;
                self.bytes_alloc.fetch_add(diff, Ordering::SeqCst);
                GLOBAL_BYTES_ALLOC.fetch_add(diff, Ordering::SeqCst);
                count_thread(3, diff);
            } else {
                let diff = old_size - new_size;
                self.bytes_dealloc.fetch_add(diff, Ordering::SeqCst);
                GLOBAL_BYTES_DEALLOC.fetch_add(diff, Ordering::SeqCst);
                count_thread(4, diff);
            }
        }
        new_ptr
    }
}

/// Takes a snapshot of the global allocation counters.
#[must_use]
pub fn alloc_counters() -> AllocCounters {
    AllocCounters {
        alloc_count: GLOBAL_ALLOCS.load(Ordering::SeqCst),
        realloc_count: GLOBAL_REALLOCS.load(Ordering::SeqCst),
        dealloc_count: GLOBAL_DEALLOCS.load(Ordering::SeqCst),
        bytes_allocated: GLOBAL_BYTES_ALLOC.load(Ordering::SeqCst),
        bytes_deallocated: GLOBAL_BYTES_DEALLOC.load(Ordering::SeqCst),
    }
}

/// This thread's allocation counters, through [`CountingAllocator`].
///
/// [`alloc_counters`] is process-wide, so a test asserting "this code allocates nothing"
/// also counts every other thread in the test binary -- a backend thread an earlier test
/// left winding down, or a test running in parallel -- and goes red at random. Code that
/// runs on the calling thread is measured exactly here.
#[must_use]
pub fn thread_alloc_counters() -> AllocCounters {
    THREAD.with(|t| AllocCounters {
        alloc_count: t[0].get(),
        dealloc_count: t[1].get(),
        realloc_count: t[2].get(),
        bytes_allocated: t[3].get(),
        bytes_deallocated: t[4].get(),
    })
}

/// Resets the global allocation counters.
pub fn reset_alloc_counters() {
    GLOBAL_ALLOCS.store(0, Ordering::SeqCst);
    GLOBAL_REALLOCS.store(0, Ordering::SeqCst);
    GLOBAL_DEALLOCS.store(0, Ordering::SeqCst);
    GLOBAL_BYTES_ALLOC.store(0, Ordering::SeqCst);
    GLOBAL_BYTES_DEALLOC.store(0, Ordering::SeqCst);
}

// -----------------------------------------------------------------------------
// Fixed-Size Object Pools (Item 2)
// -----------------------------------------------------------------------------

/// Metadata and runtime usage statistics for a memory pool.
///
/// Matches the fields displayed by `HAProxy`'s `show pools`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolHead {
    pub name: &'static str,
    pub size: usize,
    pub align: usize,
    pub allocated: usize,
    pub alloc_bytes: usize,
    pub used: usize,
    pub cached: usize,
    pub needed_avg: usize,
    pub failures: usize,
    pub users: usize,
    /// What `show pools detailed` lists under the pool. Inline, not a `Vec`: the Prometheus
    /// scrape reads every provider's head and must not allocate. Every pool Ibex has is
    /// provided by one place, so one registrant is all there is.
    pub reg: Option<PoolReg>,
}

/// One registrant of a pool (`HAProxy`'s `struct pool_registration`), for `show pools detailed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolReg {
    pub name: &'static str,
    pub size: usize,
    pub flags: u32,
    pub align: usize,
    /// The Rust `file!()` / `line!()` of the code that provides the pool.
    pub file: &'static str,
    pub line: u32,
}

/// Provider function returning current [`PoolHead`] stats for a pool.
pub type PoolStatsFn = fn() -> Option<PoolHead>;

/// Registry of active memory pools in the runtime.
///
/// Decoupled from the data path: does not perform lock acquisitions or heap allocations
/// during buffer take or return. Pools register atomic stats providers, and [`PoolRegistry::show_pools`]
/// queries them on-demand when `show pools` is invoked.
pub struct PoolRegistry {
    providers: RwLock<Vec<(&'static str, PoolStatsFn)>>,
}

impl Default for PoolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolRegistry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            providers: RwLock::new(Vec::new()),
        }
    }

    /// Registers a pool stats provider.
    pub fn register_provider(&self, name: &'static str, provider: PoolStatsFn) {
        if let Ok(mut list) = self.providers.write() {
            if let Some(pos) = list.iter().position(|(n, _)| *n == name) {
                list[pos] = (name, provider);
            } else {
                list.push((name, provider));
            }
        }
    }

    /// Calls `f` with the stats of every registered provider, without allocating (the
    /// Prometheus render must not).
    pub fn for_each(&self, mut f: impl FnMut(&PoolHead)) {
        // A poisoned lock still holds a valid list: the stats are read, not the list changed.
        let list = self.providers.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, provider) in list.iter() {
            if let Some(p) = provider() {
                f(&p);
            }
        }
    }

    /// Sum of the `failures` counters of every registered provider (`pool_total_failures()`,
    /// `show info` `PoolFailed`).
    #[must_use]
    pub fn failures(&self) -> u64 {
        let mut total = 0;
        self.for_each(|p| total += p.failures as u64);
        total
    }

    /// Unregisters a pool stats provider.
    pub fn unregister_provider(&self, name: &'static str) {
        if let Ok(mut list) = self.providers.write() {
            list.retain(|(n, _)| *n != name);
        }
    }

    /// Clears all registered providers.
    pub fn clear(&self) {
        if let Ok(mut list) = self.providers.write() {
            list.clear();
        }
    }

    /// `show pools [byname|bysize|byusage] [detailed] [match <pfx>] [<nb>]` as `HAProxy`
    /// prints it (`cli_parse_show_pools` and `dump_pools_info` in `src/pool.c`). `args` are
    /// the words after `show pools`; an unknown one yields `HAProxy`'s error text.
    ///
    /// `used` counts the blocks held in thread caches too, as `HAProxy`'s does. The limit
    /// cuts the printed lines only: `Total:` covers every pool that matched.
    #[must_use]
    pub fn show_pools(&self, args: &[&str]) -> String {
        const USAGE: &str = "Expects either 'byname', 'bysize', 'byusage', 'match <pfx>', 'detailed', or a max number of output lines.\n\n";
        let (mut by, mut detailed, mut prefix, mut maxcnt) = (0u8, false, None, 0usize);
        let mut it = args.iter().copied().peekable();
        while let Some(a) = it.next() {
            match a {
                "byname" => by = 1,
                "bysize" => by = 2,
                "byusage" => by = 3,
                "detailed" => detailed = true,
                "match" if it.peek().is_some_and(|n| !n.is_empty()) => prefix = it.next(),
                _ if a.as_bytes().first().is_some_and(u8::is_ascii_digit) => {
                    // C's atoi: the leading digits.
                    let digits = a.bytes().take_while(u8::is_ascii_digit).count();
                    maxcnt = a[..digits].parse().unwrap_or(usize::MAX);
                }
                _ => return USAGE.to_string(),
            }
        }

        let providers: Vec<PoolStatsFn> = self
            .providers
            .read()
            .map(|list| list.iter().map(|(_, f)| *f).collect())
            .unwrap_or_default();
        let mut pools: Vec<PoolHead> = providers.into_iter().filter_map(|f| f()).collect();
        pools.retain(|p| !(by == 3 && p.allocated == 0) && prefix.is_none_or(|x| p.name.starts_with(x)));
        match by {
            1 => pools.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes())),
            2 => pools.sort_by_key(|p| std::cmp::Reverse(p.size)),
            3 => pools.sort_by_key(|p| std::cmp::Reverse(p.alloc_bytes)),
            _ => {}
        }
        if maxcnt == 0 || maxcnt > pools.len() {
            maxcnt = pools.len();
        }

        let mut out = String::from("Dumping pools usage");
        if pools.len() > maxcnt {
            let _ = write!(out, " (limited to the first {maxcnt} entries)");
        }
        out.push_str(". Use SIGQUIT to flush them.\n");

        let (mut total_alloc, mut total_used, mut total_cached) = (0u64, 0u64, 0u64);
        for (i, p) in pools.iter().enumerate() {
            total_alloc += p.alloc_bytes as u64;
            total_used += ((p.used + p.cached) * p.size) as u64;
            total_cached += (p.cached * p.size) as u64;
            if i >= maxcnt {
                continue;
            }
            // Ibex merges no pools, so `[SHARED]` is never printed.
            let _ = writeln!(
                out,
                "  - Pool {} ({} bytes/{}) : {} allocated ({} bytes), {} used (~{} by thread caches), needed_avg {}, {} failures, {} users, @0x{:x}",
                p.name,
                p.size,
                p.align,
                p.allocated,
                p.alloc_bytes,
                p.used + p.cached,
                p.cached,
                p.needed_avg,
                p.failures,
                p.users,
                p.name.as_ptr() as usize,
            );
            if detailed {
                if let Some(r) = &p.reg {
                    // C's "%#x" prints a zero as "0".
                    let flags = if r.flags == 0 { "0".to_string() } else { format!("{:#x}", r.flags) };
                    let _ = writeln!(
                        out,
                        "      >  {:<12}: size={} flags={} align={} [{}:{}]",
                        r.name, r.size, flags, r.align, r.file, r.line
                    );
                }
            }
        }

        // The CLI adds the empty line that ends every answer.
        let _ = write!(
            out,
            "Total: {} pools, {total_alloc} bytes allocated, {total_used} used (~{total_cached} by thread caches).\n\n",
            pools.len()
        );
        out
    }

    /// Returns the total allocated and used bytes across all pools.
    ///
    /// Matches the arithmetic of [`Self::show_pools`]'s `Total:` line (`used` includes the caches).
    #[must_use]
    pub fn totals(&self) -> (u64, u64) {
        // `for_each`, not a copy of the provider list: a scrape calls this and allocates nothing.
        let mut total_alloc_bytes: u64 = 0;
        let mut total_used_bytes: u64 = 0;
        self.for_each(|p| {
            total_alloc_bytes += p.alloc_bytes as u64;
            total_used_bytes += ((p.used + p.cached) * p.size) as u64;
        });
        (total_alloc_bytes, total_used_bytes)
    }
}

static GLOBAL_REGISTRY: PoolRegistry = PoolRegistry::new();

/// Returns a reference to the global pool registry.
#[must_use]
pub fn global_pool_registry() -> &'static PoolRegistry {
    &GLOBAL_REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_counters_snapshot_and_diff() {
        let before = AllocCounters {
            alloc_count: 10,
            realloc_count: 2,
            dealloc_count: 5,
            bytes_allocated: 1000,
            bytes_deallocated: 400,
        };
        let after = AllocCounters {
            alloc_count: 15,
            realloc_count: 3,
            dealloc_count: 9,
            bytes_allocated: 1600,
            bytes_deallocated: 800,
        };
        let diff = before.diff(&after);
        assert_eq!(diff.alloc_count, 5);
        assert_eq!(diff.realloc_count, 1);
        assert_eq!(diff.dealloc_count, 4);
        assert_eq!(diff.bytes_allocated, 600);
        assert_eq!(diff.bytes_deallocated, 400);
        assert_eq!(diff.net_bytes(), 200);
    }

    // Signature is fixed by `register_provider`, which takes a provider that may report
    // nothing; this one always can, hence the lint.
    #[allow(clippy::unnecessary_wraps)]
    fn sample_buffer_stats() -> Option<PoolHead> {
        Some(PoolHead {
            name: "buffer",
            size: 16384,
            align: 8,
            allocated: 67,
            alloc_bytes: 1_097_728,
            used: 67,
            cached: 0,
            needed_avg: 12,
            failures: 0,
            users: 1,
            reg: None,
        })
    }

    #[test]
    fn test_pool_registry_and_show_pools_output() {
        let registry = PoolRegistry::new();
        registry.register_provider("buffer", sample_buffer_stats);

        let dump = registry.show_pools(&[]);
        assert!(dump.starts_with("Dumping pools usage. Use SIGQUIT to flush them.\n"));
        assert!(dump.contains("- Pool buffer (16384 bytes/8) : 67 allocated (1097728 bytes), 67 used"));
        assert!(dump.contains("Total: 1 pools, 1097728 bytes allocated, 1097728 used"));
    }

    // A provider whose pool is gone; the signature is fixed by `register_provider`.
    #[allow(clippy::unnecessary_wraps)]
    fn absent_stats() -> Option<PoolHead> {
        None
    }

    /// A provider that reports nothing is skipped by `totals`, neither counted as zero nor a reason to
    /// drop the providers after it.
    #[test]
    fn test_totals_skips_provider_reporting_nothing() {
        let reg = PoolRegistry::new();
        reg.register_provider("absent", absent_stats);
        assert_eq!(reg.totals(), (0, 0));
        reg.register_provider("buffer", sample_buffer_stats);
        assert_eq!(reg.totals(), (1_097_728, 67 * 16384));
    }

    /// `for_each` (Prometheus, `PoolFailed`) skips a provider reporting nothing, goes on to
    /// the ones after it, and still reads after a panic while the list was held.
    #[test]
    fn test_for_each_skips_absent_and_survives_a_poisoned_list() {
        let reg = PoolRegistry::new();
        reg.register_provider("absent", absent_stats);
        reg.register_provider("buffer", sample_buffer_stats);
        let mut names = Vec::new();
        reg.for_each(|p| names.push(p.name));
        assert_eq!(names, ["buffer"]);
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _held = reg.providers.write().unwrap();
                    panic!("poison the list");
                })
                .join();
        });
        assert!(reg.providers.is_poisoned());
        assert_eq!(reg.failures(), 0);
        let mut n = 0;
        reg.for_each(|_| n += 1);
        assert_eq!(n, 1);
    }

    /// `detailed` prints a registrant line for a pool that has one and nothing for one that
    /// has none.
    #[test]
    fn test_detailed_lists_only_pools_with_a_registrant() {
        let reg = PoolRegistry::new();
        reg.register_provider("buffer", sample_buffer_stats);
        let plain = reg.show_pools(&["detailed"]);
        assert!(!plain.contains("      >"), "{plain}");
        reg.register_provider("reg", with_reg_stats);
        let d = reg.show_pools(&["detailed"]);
        assert!(d.contains("      >  withreg     : size=32 flags=0x8 align=8 [x.rs:7]\n"), "{d}");
    }

    #[allow(clippy::unnecessary_wraps)]
    fn with_reg_stats() -> Option<PoolHead> {
        let mut p = sample_buffer_stats()?;
        p.name = "reg";
        p.reg = Some(PoolReg { name: "withreg", size: 32, flags: 8, align: 8, file: "x.rs", line: 7 });
        Some(p)
    }
}

static TRIM_DISABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// `tune.ibex.zero-buffers` (default on): whether a buffer given back to its pool, or dropped,
/// is overwritten with zeros first. Set from the configuration each time an engine is built.
static ZERO_BUFFERS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// Sets `tune.ibex.zero-buffers`.
pub fn set_zero_buffers(on: bool) {
    ZERO_BUFFERS.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Whether released buffers are zeroed (`tune.ibex.zero-buffers`).
#[must_use]
#[inline]
pub fn zero_buffers() -> bool {
    ZERO_BUFFERS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Overwrites `bytes` with zeros in a way the compiler may not drop (the `zeroize` crate:
/// volatile writes and a compiler fence), when `tune.ibex.zero-buffers` is on. Not inlined:
/// it is compiled here, at this crate's optimisation level (`[profile.dev.package.ibex-alloc]`),
/// not at the caller's, where a debug build ran 16 KB of volatile stores at opt-level 0.
#[inline(never)]
pub fn wipe(bytes: &mut [u8]) {
    if zero_buffers() {
        zeroize::Zeroize::zeroize(bytes);
    }
}

/// `global no-memory-trimming`: when set, [`trim_heap`] does nothing. Set from the
/// configuration each time an engine is built, so a reload follows the new file.
pub fn set_trim_disabled(disabled: bool) {
    TRIM_DISABLED.store(disabled, core::sync::atomic::Ordering::Relaxed);
}

/// Gives the free pages of the allocator's heap back to the system (glibc `malloc_trim`).
/// Returns whether anything was done: false where the allocator has no such call, or when
/// `no-memory-trimming` is set.
#[must_use]
#[allow(unsafe_code)]
pub fn trim_heap() -> bool {
    if TRIM_DISABLED.load(core::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        // SAFETY: `malloc_trim` takes no pointer, is thread-safe in glibc, and only
        // releases memory the allocator has already freed.
        unsafe {
            malloc_trim(0);
        }
        true
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
    }
}
