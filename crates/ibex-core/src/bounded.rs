//! Bounded data structures with statically enforced capacity (JPL Rule 2 & 3).

use crate::error::{IbexError, IbexResult};

/// Fixed capacity vector allocated on the stack or inline without heap growth.
#[derive(Debug, Clone)]
pub struct BoundedVec<T, const N: usize> {
    data: [Option<T>; N],
    len: usize,
}

impl<T: Copy, const N: usize> BoundedVec<T, N> {
    /// Creates a new empty bounded vector.
    pub const fn new() -> Self {
        Self {
            data: [None; N],
            len: 0,
        }
    }

    /// Appends an item if capacity allows.
    pub fn push(&mut self, item: T) -> IbexResult<()> {
        if self.len >= N {
            return Err(IbexError::CapacityExceeded {
                requested: self.len + 1,
                capacity: N,
            });
        }
        self.data[self.len] = Some(item);
        self.len += 1;
        Ok(())
    }

    /// Pops the last item.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            None
        } else {
            self.len -= 1;
            self.data[self.len].take()
        }
    }

    /// Returns the element at index.
    pub fn get(&self, index: usize) -> Option<T> {
        if index < self.len {
            self.data[index]
        } else {
            None
        }
    }

    /// Length of the vector.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True if empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Clears the vector.
    pub fn clear(&mut self) {
        self.len = 0;
        for i in 0..N {
            self.data[i] = None;
        }
    }
}

impl<T: Copy, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded Ring Buffer for fixed-size token streaming and packet buffering.
pub struct BoundedRingBuffer<T: Copy + Default, const N: usize> {
    buffer: [T; N],
    head: usize,
    tail: usize,
    count: usize,
}

impl<T: Copy + Default, const N: usize> BoundedRingBuffer<T, N> {
    /// Creates a new empty bounded ring buffer.
    pub fn new() -> Self {
        Self {
            buffer: [T::default(); N],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Enqueues an element.
    pub fn push(&mut self, item: T) -> IbexResult<()> {
        if self.count >= N {
            return Err(IbexError::CapacityExceeded {
                requested: self.count + 1,
                capacity: N,
            });
        }
        self.buffer[self.tail] = item;
        self.tail = (self.tail + 1) % N;
        self.count += 1;
        Ok(())
    }

    /// Dequeues an element.
    pub fn pop(&mut self) -> Option<T> {
        if self.count == 0 {
            None
        } else {
            let item = self.buffer[self.head];
            self.head = (self.head + 1) % N;
            self.count -= 1;
            Some(item)
        }
    }

    /// Current count of elements.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// True if empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// True if full.
    pub const fn is_full(&self) -> bool {
        self.count >= N
    }

    /// Capacity.
    pub const fn capacity(&self) -> usize {
        N
    }
}

impl<T: Copy + Default, const N: usize> Default for BoundedRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_vec() {
        let mut v = BoundedVec::<u32, 3>::new();
        assert!(v.is_empty());
        assert_eq!(v.push(10), Ok(()));
        assert_eq!(v.push(20), Ok(()));
        assert_eq!(v.push(30), Ok(()));
        assert!(v.push(40).is_err());
        assert_eq!(v.len(), 3);
        assert_eq!(v.get(1), Some(20));
        assert_eq!(v.pop(), Some(30));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn test_ring_buffer() {
        let mut ring = BoundedRingBuffer::<u8, 4>::new();
        assert!(ring.push(1).is_ok());
        assert!(ring.push(2).is_ok());
        assert!(ring.push(3).is_ok());
        assert!(ring.push(4).is_ok());
        assert!(ring.push(5).is_err());

        assert_eq!(ring.pop(), Some(1));
        assert!(ring.push(5).is_ok());
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert_eq!(ring.pop(), Some(4));
        assert_eq!(ring.pop(), Some(5));
        assert_eq!(ring.pop(), None);
    }
}
