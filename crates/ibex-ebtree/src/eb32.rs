//! 32-bit Elastic Binary Tree (eb32)
//!
//! $O(k)$ deterministic bit-indexed binary tree for 32-bit keys (IPv4, port numbers, numeric session IDs).

use ibex_core::ibex_assert;

#[derive(Debug, Clone)]
struct Node<V> {
    key: u32,
    value: V,
    bit: u8, // 0..31: bit index being tested
    left: Option<Box<Node<V>>>,
    right: Option<Box<Node<V>>>,
}

/// 32-bit Elastic Binary Tree
#[derive(Debug, Clone, Default)]
pub struct Eb32Tree<V> {
    root: Option<Box<Node<V>>>,
    count: usize,
}

impl<V> Eb32Tree<V> {
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
    pub fn insert(&mut self, key: u32, value: V) -> Option<V> {
        ibex_assert!(self.count < usize::MAX, "Tree size within bounds");
        if self.root.is_none() {
            self.root = Some(Box::new(Node {
                key,
                value,
                bit: 31,
                left: None,
                right: None,
            }));
            self.count += 1;
            return None;
        }

        // Standard bit-index traversal (max 32 steps guaranteed)
        let mut curr = self.root.as_mut().expect("Checked non-empty");
        for _ in 0..32 {
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

        // Fallback replacement if maximum bit depth reached
        let old = std::mem::replace(&mut curr.value, value);
        Some(old)
    }

    /// Looks up a key, returning reference to value.
    pub fn lookup(&self, key: u32) -> Option<&V> {
        let mut curr = self.root.as_deref()?;
        for _ in 0..32 {
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
    pub fn lookup_mut(&mut self, key: u32) -> Option<&mut V> {
        let mut curr = self.root.as_deref_mut()?;
        for _ in 0..32 {
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
    fn test_eb32_insert_lookup() {
        let mut tree = Eb32Tree::new();
        assert!(tree.is_empty());

        assert_eq!(tree.insert(100, "node-100"), None);
        assert_eq!(tree.insert(200, "node-200"), None);
        assert_eq!(tree.insert(100, "node-100-updated"), Some("node-100"));

        assert_eq!(tree.len(), 2);
        assert_eq!(tree.lookup(100), Some(&"node-100-updated"));
        assert_eq!(tree.lookup(200), Some(&"node-200"));
        assert_eq!(tree.lookup(300), None);
    }
}
