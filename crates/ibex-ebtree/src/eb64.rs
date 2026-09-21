//! 64-bit Elastic Binary Tree (eb64)
//!
//! $O(k)$ deterministic bit-indexed binary tree for 64-bit keys (timestamps, counters, 64-bit IDs).

use ibex_core::ibex_assert;

#[derive(Debug, Clone)]
struct Node<V> {
    key: u64,
    value: V,
    bit: u8, // 0..63: bit index being tested
    left: Option<Box<Node<V>>>,
    right: Option<Box<Node<V>>>,
}

/// 64-bit Elastic Binary Tree
#[derive(Debug, Clone, Default)]
pub struct Eb64Tree<V> {
    root: Option<Box<Node<V>>>,
    count: usize,
}

impl<V> Eb64Tree<V> {
    /// Creates a new empty tree.
    pub const fn new() -> Self {
        Self {
            root: None,
            count: 0,
        }
    }

    /// Number of elements.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// True if empty.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Inserts a key-value pair. Returns previous value if key existed.
    pub fn insert(&mut self, key: u64, value: V) -> Option<V> {
        ibex_assert!(self.count < usize::MAX, "Tree count within bounds");
        if self.root.is_none() {
            self.root = Some(Box::new(Node {
                key,
                value,
                bit: 63,
                left: None,
                right: None,
            }));
            self.count += 1;
            return None;
        }

        let mut curr = self.root.as_mut().expect("Checked non-empty");
        for _ in 0..64 {
            if curr.key == key {
                let old = std::mem::replace(&mut curr.value, value);
                return Some(old);
            }

            let bit_val = (key >> curr.bit) & 1;
            if bit_val == 0 {
                if curr.left.is_none() {
                    let next_bit = if curr.bit > 0 { curr.bit - 1 } else { 0 };
                    curr.left = Some(Box::new(Node {
                        key,
                        value,
                        bit: next_bit,
                        left: None,
                        right: None,
                    }));
                    self.count += 1;
                    return None;
                }
                curr = curr.left.as_mut().expect("Exists");
            } else {
                if curr.right.is_none() {
                    let next_bit = if curr.bit > 0 { curr.bit - 1 } else { 0 };
                    curr.right = Some(Box::new(Node {
                        key,
                        value,
                        bit: next_bit,
                        left: None,
                        right: None,
                    }));
                    self.count += 1;
                    return None;
                }
                curr = curr.right.as_mut().expect("Exists");
            }
        }

        let old = std::mem::replace(&mut curr.value, value);
        Some(old)
    }

    /// Looks up a key, returning reference to value.
    pub fn lookup(&self, key: u64) -> Option<&V> {
        let mut curr = self.root.as_deref()?;
        for _ in 0..64 {
            if curr.key == key {
                return Some(&curr.value);
            }
            let bit_val = (key >> curr.bit) & 1;
            curr = if bit_val == 0 {
                curr.left.as_deref()?
            } else {
                curr.right.as_deref()?
            };
        }
        if curr.key == key {
            Some(&curr.value)
        } else {
            None
        }
    }

    /// Looks up a key, returning mutable reference to value.
    pub fn lookup_mut(&mut self, key: u64) -> Option<&mut V> {
        let mut curr = self.root.as_deref_mut()?;
        for _ in 0..64 {
            if curr.key == key {
                return Some(&mut curr.value);
            }
            let bit_val = (key >> curr.bit) & 1;
            curr = if bit_val == 0 {
                curr.left.as_deref_mut()?
            } else {
                curr.right.as_deref_mut()?
            };
        }
        if curr.key == key {
            Some(&mut curr.value)
        } else {
            None
        }
    }

    /// Clears the tree.
    pub fn clear(&mut self) {
        self.root = None;
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eb64_insert_lookup() {
        let mut tree = Eb64Tree::new();
        assert_eq!(tree.insert(1_000_000_000_000, "val1"), None);
        assert_eq!(tree.lookup(1_000_000_000_000), Some(&"val1"));
        assert_eq!(tree.lookup(2), None);
    }
}
