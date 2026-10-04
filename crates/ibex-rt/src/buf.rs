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

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;
use ibex_alloc::PoolHead;

/// Configured buffer sizes (in bytes).
static BUFSIZE_STANDARD: AtomicUsize = AtomicUsize::new(16_384);
static BUFSIZE_SMALL: AtomicUsize = AtomicUsize::new(1_024);
static BUFSIZE_LARGE: AtomicUsize = AtomicUsize::new(0); // 0 means not configured

/// Standard `HAProxy` buffer size constant (16,384 bytes).
pub const BUFSIZE: usize = 16_384;

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

// Global atomic pool statistics counters
static BUF_STD_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BUF_STD_USED: AtomicUsize = AtomicUsize::new(0);
static BUF_STD_CACHED: AtomicUsize = AtomicUsize::new(0);

static BUF_SMALL_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BUF_SMALL_USED: AtomicUsize = AtomicUsize::new(0);
static BUF_SMALL_CACHED: AtomicUsize = AtomicUsize::new(0);

static BUF_LARGE_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BUF_LARGE_USED: AtomicUsize = AtomicUsize::new(0);
static BUF_LARGE_CACHED: AtomicUsize = AtomicUsize::new(0);

/// Decoupled provider for standard buffer pool metrics (`show pools`).
pub fn buffer_pool_stats() -> Option<PoolHead> {
    let size = get_bufsize();
    let allocated = BUF_STD_ALLOCATED.load(Ordering::Relaxed);
    let used = BUF_STD_USED.load(Ordering::Relaxed);
    let cached = BUF_STD_CACHED.load(Ordering::Relaxed);
    Some(PoolHead {
        name: "buffer",
        size,
        align: 64,
        allocated,
        alloc_bytes: allocated * size,
        used,
        cached,
        needed_avg: used,
        failures: 0,
        users: 1,
    })
}

/// Decoupled provider for small buffer pool metrics (`show pools`).
pub fn small_buffer_pool_stats() -> Option<PoolHead> {
    let size = get_bufsize_small();
    let allocated = BUF_SMALL_ALLOCATED.load(Ordering::Relaxed);
    let used = BUF_SMALL_USED.load(Ordering::Relaxed);
    let cached = BUF_SMALL_CACHED.load(Ordering::Relaxed);
    Some(PoolHead {
        name: "small_buffer",
        size,
        align: 64,
        allocated,
        alloc_bytes: allocated * size,
        used,
        cached,
        needed_avg: used,
        failures: 0,
        users: 1,
    })
}

/// Decoupled provider for large buffer pool metrics (`show pools`).
pub fn large_buffer_pool_stats() -> Option<PoolHead> {
    let size = get_bufsize_large()?;
    let allocated = BUF_LARGE_ALLOCATED.load(Ordering::Relaxed);
    let used = BUF_LARGE_USED.load(Ordering::Relaxed);
    let cached = BUF_LARGE_CACHED.load(Ordering::Relaxed);
    Some(PoolHead {
        name: "large_buffer",
        size,
        align: 64,
        allocated,
        alloc_bytes: allocated * size,
        used,
        cached,
        needed_avg: used,
        failures: 0,
        users: 1,
    })
}

static INIT_REGISTRY: Once = Once::new();

/// Ensures buffer pool stats providers are registered in [`ibex_alloc::global_pool_registry`].
pub fn ensure_registered() {
    INIT_REGISTRY.call_once(|| {
        let reg = ibex_alloc::global_pool_registry();
        reg.register_provider("buffer", buffer_pool_stats);
        reg.register_provider("small_buffer", small_buffer_pool_stats);
    });
}

/// Initializes buffer size classes and registers pool providers.
pub fn init_buffer_sizes(standard: usize, small: usize, large: Option<usize>) {
    let standard = (standard + 15) & !15;
    let small = (small + 15) & !15;
    BUFSIZE_STANDARD.store(standard, Ordering::SeqCst);
    BUFSIZE_SMALL.store(small, Ordering::SeqCst);
    if let Some(l) = large {
        let large_rounded = (l + 15) & !15;
        BUFSIZE_LARGE.store(large_rounded, Ordering::SeqCst);
    } else {
        BUFSIZE_LARGE.store(0, Ordering::SeqCst);
    }

    let reg = ibex_alloc::global_pool_registry();
    reg.register_provider("buffer", buffer_pool_stats);
    reg.register_provider("small_buffer", small_buffer_pool_stats);
    if large.is_some() {
        reg.register_provider("large_buffer", large_buffer_pool_stats);
    } else {
        reg.unregister_provider("large_buffer");
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

struct ThreadPools {
    small: Vec<Box<[u8]>>,
    standard: Vec<Box<[u8]>>,
    large: Vec<Box<[u8]>>,
}

impl ThreadPools {
    const fn new() -> Self {
        Self {
            small: Vec::new(),
            standard: Vec::new(),
            large: Vec::new(),
        }
    }
}

thread_local! {
    static THREAD_POOLS: RefCell<ThreadPools> = const { RefCell::new(ThreadPools::new()) };
}

/// Preallocates three large buffers in the current thread's cache if large buffers are configured.
pub fn preallocate_large_buffers() {
    if let Some(sz) = get_bufsize_large() {
        THREAD_POOLS.with(|pools| {
            let mut p = pools.borrow_mut();
            while p.large.len() < 3 {
                p.large.push(vec![0u8; sz].into_boxed_slice());
                BUF_LARGE_ALLOCATED.fetch_add(1, Ordering::Relaxed);
                BUF_LARGE_CACHED.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

fn alloc_standard() -> Box<[u8]> {
    ensure_registered();
    let target_sz = get_bufsize();
    let recycled = THREAD_POOLS.with(|pools| {
        let mut p = pools.borrow_mut();
        if let Some(buf) = p.standard.pop() {
            if buf.len() == target_sz {
                BUF_STD_CACHED.fetch_sub(1, Ordering::Relaxed);
                BUF_STD_USED.fetch_add(1, Ordering::Relaxed);
                return Some(buf);
            }
        }
        None
    });

    if let Some(buf) = recycled {
        buf
    } else {
        BUF_STD_ALLOCATED.fetch_add(1, Ordering::Relaxed);
        BUF_STD_USED.fetch_add(1, Ordering::Relaxed);
        vec![0u8; target_sz].into_boxed_slice()
    }
}

fn alloc_small() -> Box<[u8]> {
    ensure_registered();
    let target_sz = get_bufsize_small();
    let recycled = THREAD_POOLS.with(|pools| {
        let mut p = pools.borrow_mut();
        if let Some(buf) = p.small.pop() {
            if buf.len() == target_sz {
                BUF_SMALL_CACHED.fetch_sub(1, Ordering::Relaxed);
                BUF_SMALL_USED.fetch_add(1, Ordering::Relaxed);
                return Some(buf);
            }
        }
        None
    });

    if let Some(buf) = recycled {
        buf
    } else {
        BUF_SMALL_ALLOCATED.fetch_add(1, Ordering::Relaxed);
        BUF_SMALL_USED.fetch_add(1, Ordering::Relaxed);
        vec![0u8; target_sz].into_boxed_slice()
    }
}

fn alloc_large() -> Box<[u8]> {
    ensure_registered();
    let target_sz = get_bufsize_large().unwrap_or(65536);
    let recycled = THREAD_POOLS.with(|pools| {
        let mut p = pools.borrow_mut();
        if let Some(buf) = p.large.pop() {
            if buf.len() == target_sz {
                BUF_LARGE_CACHED.fetch_sub(1, Ordering::Relaxed);
                BUF_LARGE_USED.fetch_add(1, Ordering::Relaxed);
                return Some(buf);
            }
        }
        None
    });

    if let Some(buf) = recycled {
        buf
    } else {
        BUF_LARGE_ALLOCATED.fetch_add(1, Ordering::Relaxed);
        BUF_LARGE_USED.fetch_add(1, Ordering::Relaxed);
        vec![0u8; target_sz].into_boxed_slice()
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
    class: BufClass,
}

impl Drop for Buf {
    fn drop(&mut self) {
        match self.class {
            BufClass::Standard => {
                let data = std::mem::replace(&mut self.data, Box::new([]));
                let target_sz = get_bufsize();
                if data.len() == target_sz {
                    let pushed = THREAD_POOLS.with(|pools| {
                        let mut p = pools.borrow_mut();
                        if p.standard.len() < MAX_CACHED_PER_THREAD {
                            p.standard.push(data);
                            BUF_STD_USED.fetch_sub(1, Ordering::Relaxed);
                            BUF_STD_CACHED.fetch_add(1, Ordering::Relaxed);
                            true
                        } else {
                            false
                        }
                    });
                    if !pushed {
                        BUF_STD_USED.fetch_sub(1, Ordering::Relaxed);
                    }
                } else {
                    // Grown by a head rewrite: not poolable, but no longer in use.
                    BUF_STD_USED.fetch_sub(1, Ordering::Relaxed);
                }
            }
            BufClass::Small => {
                let data = std::mem::replace(&mut self.data, Box::new([]));
                let target_sz = get_bufsize_small();
                if data.len() == target_sz {
                    let pushed = THREAD_POOLS.with(|pools| {
                        let mut p = pools.borrow_mut();
                        if p.small.len() < MAX_CACHED_PER_THREAD {
                            p.small.push(data);
                            BUF_SMALL_USED.fetch_sub(1, Ordering::Relaxed);
                            BUF_SMALL_CACHED.fetch_add(1, Ordering::Relaxed);
                            true
                        } else {
                            false
                        }
                    });
                    if !pushed {
                        BUF_SMALL_USED.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
            BufClass::Large => {
                let data = std::mem::replace(&mut self.data, Box::new([]));
                if let Some(target_sz) = get_bufsize_large() {
                    if data.len() == target_sz {
                        let pushed = THREAD_POOLS.with(|pools| {
                            let mut p = pools.borrow_mut();
                            if p.large.len() < MAX_CACHED_PER_THREAD {
                                p.large.push(data);
                                BUF_LARGE_USED.fetch_sub(1, Ordering::Relaxed);
                                BUF_LARGE_CACHED.fetch_add(1, Ordering::Relaxed);
                                true
                            } else {
                                false
                            }
                        });
                        if !pushed {
                            BUF_LARGE_USED.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
            }
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
    /// Allocates a standard-size buffer from the thread-local pool.
    #[must_use]
    pub fn standard() -> Self {
        Buf {
            data: alloc_standard(),
            head: 0,
            len: 0,
            class: BufClass::Standard,
        }
    }

    /// Allocates a small-size buffer from the thread-local pool.
    #[must_use]
    pub fn small() -> Self {
        Buf {
            data: alloc_small(),
            head: 0,
            len: 0,
            class: BufClass::Small,
        }
    }

    /// Allocates a large-size buffer from the thread-local pool.
    #[must_use]
    pub fn large() -> Self {
        Buf {
            data: alloc_large(),
            head: 0,
            len: 0,
            class: BufClass::Large,
        }
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
                data: vec![0u8; cap].into_boxed_slice(),
                head: 0,
                len: 0,
                class: BufClass::Custom,
            }
        }
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
        if self.class != BufClass::Small {
            return false;
        }

        let mut new_data = alloc_standard();
        if self.len > 0 {
            let valid = &self.data[self.head..self.head + self.len];
            new_data[..self.len].copy_from_slice(valid);
        }
        let old_small = std::mem::replace(&mut self.data, new_data);
        self.head = 0;
        self.class = BufClass::Standard;

        // Recycle old small buffer back to thread cache
        let target_sz = get_bufsize_small();
        if old_small.len() == target_sz {
            let pushed = THREAD_POOLS.with(|pools| {
                let mut p = pools.borrow_mut();
                if p.small.len() < MAX_CACHED_PER_THREAD {
                    p.small.push(old_small);
                    BUF_SMALL_USED.fetch_sub(1, Ordering::Relaxed);
                    BUF_SMALL_CACHED.fetch_add(1, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            });
            if !pushed {
                BUF_SMALL_USED.fetch_sub(1, Ordering::Relaxed);
            }
        }

        true
    }

    /// Appends `bytes` to the buffer, automatically promoting from [`BufClass::Small`]
    /// to [`BufClass::Standard`] if needed to prevent truncation.
    pub fn put(&mut self, bytes: &[u8]) -> bool {
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
        self.data.len()
    }

    #[must_use]
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == self.data.len()
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
        &mut self.data
    }

    /// Bytes available to read.
    #[must_use]
    #[inline]
    pub fn readable(&self) -> &[u8] {
        &self.data[self.head..self.head + self.len]
    }

    /// Moves readable data to index 0 so full remaining capacity is contiguous at the tail.
    pub fn compact(&mut self) {
        if self.head > 0 {
            if self.len > 0 {
                self.data.copy_within(self.head..self.head + self.len, 0);
            }
            self.head = 0;
        }
    }

    /// Contiguous space available to write into, compacting or promoting if necessary.
    pub fn writable(&mut self) -> &mut [u8] {
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
        assert!(
            self.head + self.len + n <= self.data.len(),
            "commit({n}) past end of buffer"
        );
        self.len += n;
    }

    /// Discards `n` bytes from the front.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.head += n;
        self.len -= n;
        if self.len == 0 {
            self.head = 0;
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// Makes the backing store at least `min` bytes, readable data moved to index 0.
    ///
    /// A head rewrite can make the message longer than the buffer it was read into when the
    /// peer filled it (head and the start of a body in one read). Dropping the bytes that no
    /// longer fit would silently lose body bytes the socket already delivered, so the buffer
    /// grows by what the rewrite added. Later reads then see the extra room as ordinary
    /// space and the body behind the head stays intact.
    fn grow_to(&mut self, min: usize) {
        if self.class == BufClass::Small && min > self.data.len() {
            self.promote_to_standard();
        }
        if min > self.data.len() {
            let mut bigger = vec![0u8; min].into_boxed_slice();
            bigger[..self.len].copy_from_slice(&self.data[self.head..self.head + self.len]);
            self.data = bigger;
            self.head = 0;
        } else if self.head > 0 {
            self.data.copy_within(self.head..self.head + self.len, 0);
            self.head = 0;
        }
    }

    /// Replaces the leading `old_len` bytes in the readable portion of the buffer
    /// with `new_data`. The remainder is never truncated: the buffer grows if needed.
    pub fn replace_prefix(&mut self, old_len: usize, new_data: &[u8]) {
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
            self.data = bigger;
        } else {
            self.data.copy_within(rem_src..rem_src + rem_len, new_data.len());
            self.data[..new_data.len()].copy_from_slice(new_data);
        }
        self.head = 0;
        self.len = needed;
    }

    /// Injects or updates an HTTP header in the readable portion of the buffer.
    ///
    /// Compacts the buffer if necessary so readable data starts at index 0 and maximum
    /// tail capacity is available.
    /// Returns `true` if successful, or `false` if buffer capacity was exceeded or malformed.
    pub fn inject_http_header(&mut self, name: &str, value: &str) -> bool {
        let added_approx = name.len() + value.len() + 4;
        self.grow_to(self.len + added_approx);
        if let Some(new_len) =
            ibex_proto::inject_http_header_with_len(&mut self.data, self.len, name, value)
        {
            self.len = new_len;
            true
        } else {
            false
        }
    }

    /// Removes all occurrences of an HTTP header from the readable portion of the buffer.
    ///
    /// Returns `true` if successful, or `false` if the buffer is malformed.
    pub fn remove_http_header(&mut self, name: &str) -> bool {
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
