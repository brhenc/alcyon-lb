//! Pre-allocated memory arena adhering to NASA JPL Rule 3 (no dynamic allocations on hot path).

use crate::error::{IbexError, IbexResult};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Static arena with fixed compile-time or boot-time allocated capacity.
pub struct StaticArena<const N: usize> {
    storage: Box<[UnsafeCell<u8>; N]>,
    offset: AtomicUsize,
}

// Safety: Access to allocated memory is managed via atomic bump pointer and safe slices.
#[allow(unsafe_code)]
unsafe impl<const N: usize> Sync for StaticArena<N> {}
#[allow(unsafe_code)]
unsafe impl<const N: usize> Send for StaticArena<N> {}

impl<const N: usize> StaticArena<N> {
    /// Creates a new static arena of capacity `N` allocated entirely at boot-time.
    pub fn new() -> Self {
        // Safe allocation at startup
        let storage = Box::new([const { UnsafeCell::new(0) }; N]);
        Self {
            storage,
            offset: AtomicUsize::new(0),
        }
    }

    /// Allocates `size` bytes with specified alignment from the pre-allocated arena.
    #[allow(unsafe_code)]
    pub fn alloc(&self, size: usize, align: usize) -> IbexResult<&mut [u8]> {
        if size == 0 {
            return Ok(&mut []);
        }

        let align_mask = align.saturating_sub(1);
        let mut current = self.offset.load(Ordering::Relaxed);

        loop {
            let aligned = (current + align_mask) & !align_mask;
            let next = aligned + size;

            if next > N {
                return Err(IbexError::OutOfMemory {
                    needed: size,
                    remaining: N.saturating_sub(aligned),
                });
            }

            match self.offset.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let ptr = self.storage[aligned].get();
                    // Safety: We reserved [aligned..next] exclusively via atomic CAS
                    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, size) };
                    return Ok(slice);
                }
                Err(actual) => {
                    current = actual;
                }
            }
        }
    }

    /// Resets the arena pointer to zero (to be reused across transactions/cycles).
    pub fn reset(&self) {
        self.offset.store(0, Ordering::Release);
    }

    /// Returns currently allocated bytes.
    #[inline(always)]
    pub fn allocated_bytes(&self) -> usize {
        self.offset.load(Ordering::Relaxed)
    }

    /// Returns remaining available bytes.
    #[inline(always)]
    pub fn remaining_bytes(&self) -> usize {
        N.saturating_sub(self.allocated_bytes())
    }

    /// Capacity of the arena in bytes.
    pub const fn capacity() -> usize {
        N
    }
}

impl<const N: usize> Default for StaticArena<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_allocation_and_reset() {
        let arena = StaticArena::<1024>::new();
        assert_eq!(arena.remaining_bytes(), 1024);

        let slice1 = arena.alloc(128, 8).expect("Allocation should succeed");
        assert_eq!(slice1.len(), 128);
        slice1[0] = 0xAA;
        slice1[127] = 0x55;

        let slice2 = arena.alloc(256, 16).expect("Allocation should succeed");
        assert_eq!(slice2.len(), 256);

        assert!(arena.allocated_bytes() >= 384);
        arena.reset();
        assert_eq!(arena.allocated_bytes(), 0);
    }

    #[test]
    fn test_arena_exhaustion() {
        let arena = StaticArena::<64>::new();
        assert!(arena.alloc(100, 1).is_err());
    }
}
