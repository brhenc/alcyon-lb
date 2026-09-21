//! Fixed Capacity Object Pool (JPL Rule 3) for zero-allocation reuse.

use crate::error::{IbexError, IbexResult};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A fixed-size, lock-free object pool allocating all objects at boot-time.
pub struct FixedPool<T: Default, const CAPACITY: usize> {
    storage: Box<[UnsafeCell<T>; CAPACITY]>,
    free_indices: Box<[AtomicUsize; CAPACITY]>,
    top: AtomicUsize,
}

#[allow(unsafe_code)]
unsafe impl<T: Default + Send, const CAPACITY: usize> Send for FixedPool<T, CAPACITY> {}
#[allow(unsafe_code)]
unsafe impl<T: Default + Sync, const CAPACITY: usize> Sync for FixedPool<T, CAPACITY> {}

impl<T: Default, const CAPACITY: usize> FixedPool<T, CAPACITY> {
    /// Creates and pre-allocates all items at initialization.
    pub fn new() -> Self {
        let storage = Box::new(std::array::from_fn(|_| UnsafeCell::new(T::default())));
        let free_indices = Box::new(std::array::from_fn(|i| AtomicUsize::new(i)));
        Self {
            storage,
            free_indices,
            top: AtomicUsize::new(CAPACITY),
        }
    }

    /// Acquires an available object index from the pool.
    pub fn acquire_index(&self) -> IbexResult<usize> {
        loop {
            let current_top = self.top.load(Ordering::Acquire);
            if current_top == 0 {
                return Err(IbexError::PoolExhausted { capacity: CAPACITY });
            }
            let next_top = current_top - 1;
            if self
                .top
                .compare_exchange_weak(
                    current_top,
                    next_top,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let index = self.free_indices[next_top].load(Ordering::Relaxed);
                return Ok(index);
            }
        }
    }

    /// Releases an object index back to the pool.
    pub fn release_index(&self, index: usize) -> IbexResult<()> {
        if index >= CAPACITY {
            return Err(IbexError::InvalidState(format!(
                "Invalid index {index} for capacity {CAPACITY}"
            )));
        }
        loop {
            let current_top = self.top.load(Ordering::Acquire);
            if current_top >= CAPACITY {
                return Err(IbexError::InvalidState("Pool already full".to_string()));
            }
            self.free_indices[current_top].store(index, Ordering::Relaxed);
            if self
                .top
                .compare_exchange_weak(
                    current_top,
                    current_top + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Accesses an object by index.
    ///
    /// # Safety
    /// Caller must hold the acquired index exclusively.
    #[allow(unsafe_code)]
    pub unsafe fn get_mut(&self, index: usize) -> &mut T {
        &mut *self.storage[index].get()
    }

    /// Returns the number of currently available objects.
    pub fn available(&self) -> usize {
        self.top.load(Ordering::Relaxed)
    }

    /// Total capacity.
    pub const fn capacity() -> usize {
        CAPACITY
    }
}

impl<T: Default, const CAPACITY: usize> Default for FixedPool<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[derive(Default, Debug, PartialEq, Eq)]
    struct ConnectionContext {
        id: u64,
        active: bool,
    }

    #[test]
    fn test_fixed_pool_lifecycle() {
        let pool = FixedPool::<ConnectionContext, 4>::new();
        assert_eq!(pool.available(), 4);

        let idx0 = pool.acquire_index().expect("acquire 0");
        let idx1 = pool.acquire_index().expect("acquire 1");
        assert_eq!(pool.available(), 2);

        unsafe {
            let obj = pool.get_mut(idx0);
            obj.id = 42;
            obj.active = true;
        }

        unsafe {
            assert_eq!(pool.get_mut(idx0).id, 42);
        }

        pool.release_index(idx0).expect("release 0");
        assert_eq!(pool.available(), 3);

        pool.release_index(idx1).expect("release 1");
        assert_eq!(pool.available(), 4);
    }
}
