//! String Elastic Binary Tree (ebst)
//!
//! Radix/crit-bit tree for string keys (URIs, hostnames, HTTP header values)
//! with support for longest prefix matching and exact matching.

use ibex_core::ibex_assert;

#[derive(Debug, Clone)]
struct Node<V> {
    key: String,
    value: V,
    byte_idx: usize,
    bit_idx: u8,
    left: Option<Box<Node<V>>>,
    right: Option<Box<Node<V>>>,
}

/// String Elastic Binary Tree
#[derive(Debug, Clone, Default)]
pub struct EbStTree<V> {
    root: Option<Box<Node<V>>>,
    count: usize,
}

impl<V> EbStTree<V> {
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

    /// Helper to get the bit value at a specific byte and bit index.
    #[inline(always)]
    fn get_bit(bytes: &[u8], byte_idx: usize, bit_idx: u8) -> u8 {
        if byte_idx < bytes.len() {
            (bytes[byte_idx] >> bit_idx) & 1
        } else {
            0
        }
    }

    /// Inserts a string key and value.
    pub fn insert(&mut self, key: &str, value: V) -> Option<V> {
        ibex_assert!(self.count < usize::MAX, "Tree size bounded");
        if self.root.is_none() {
            self.root = Some(Box::new(Node {
                key: key.to_string(),
                value,
                byte_idx: 0,
                bit_idx: 7,
                left: None,
                right: None,
            }));
            self.count += 1;
            return None;
        }

        let key_bytes = key.as_bytes();
        let mut curr = self.root.as_mut().expect("Root exists");
        let max_depth = key_bytes.len().saturating_mul(8) + 64;

        for _ in 0..max_depth {
            if curr.key == key {
                let old = std::mem::replace(&mut curr.value, value);
                return Some(old);
            }

            let bit_val = Self::get_bit(key_bytes, curr.byte_idx, curr.bit_idx);
            if bit_val == 0 {
                if curr.left.is_none() {
                    let (next_byte, next_bit) = if curr.bit_idx > 0 {
                        (curr.byte_idx, curr.bit_idx - 1)
                    } else {
                        (curr.byte_idx + 1, 7)
                    };
                    curr.left = Some(Box::new(Node {
                        key: key.to_string(),
                        value,
                        byte_idx: next_byte,
                        bit_idx: next_bit,
                        left: None,
                        right: None,
                    }));
                    self.count += 1;
                    return None;
                }
                curr = curr.left.as_mut().expect("Exists");
            } else {
                if curr.right.is_none() {
                    let (next_byte, next_bit) = if curr.bit_idx > 0 {
                        (curr.byte_idx, curr.bit_idx - 1)
                    } else {
                        (curr.byte_idx + 1, 7)
                    };
                    curr.right = Some(Box::new(Node {
                        key: key.to_string(),
                        value,
                        byte_idx: next_byte,
                        bit_idx: next_bit,
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

    /// Looks up an exact string key.
    pub fn lookup(&self, key: &str) -> Option<&V> {
        let key_bytes = key.as_bytes();
        let mut curr = self.root.as_deref()?;
        let max_depth = key_bytes.len().saturating_mul(8) + 64;

        for _ in 0..max_depth {
            if curr.key == key {
                return Some(&curr.value);
            }
            let bit_val = Self::get_bit(key_bytes, curr.byte_idx, curr.bit_idx);
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

    /// Longest prefix match: finds the value whose key is the longest prefix of `input`.
    pub fn longest_prefix_match(&self, input: &str) -> Option<(&str, &V)> {
        let mut best_match: Option<(&str, &V)> = None;
        let mut stack = Vec::with_capacity(32);

        if let Some(root) = self.root.as_deref() {
            stack.push(root);
        }

        while let Some(node) = stack.pop() {
            if input.starts_with(&node.key) {
                match best_match {
                    Some((best_key, _)) if node.key.len() > best_key.len() => {
                        best_match = Some((&node.key, &node.value));
                    }
                    None => {
                        best_match = Some((&node.key, &node.value));
                    }
                    _ => {}
                }
            }
            if let Some(left) = node.left.as_deref() {
                stack.push(left);
            }
            if let Some(right) = node.right.as_deref() {
                stack.push(right);
            }
        }

        best_match
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
    fn test_ebst_exact_and_prefix() {
        let mut tree = EbStTree::new();
        assert_eq!(tree.insert("/api/v1", "backend_v1"), None);
        assert_eq!(tree.insert("/api/v2", "backend_v2"), None);
        assert_eq!(tree.insert("/static", "backend_static"), None);

        assert_eq!(tree.lookup("/api/v1"), Some(&"backend_v1"));
        assert_eq!(tree.lookup("/api/v2"), Some(&"backend_v2"));
        assert_eq!(tree.lookup("/unknown"), None);

        let (prefix, val) = tree
            .longest_prefix_match("/api/v1/users/42")
            .expect("Match prefix");
        assert_eq!(prefix, "/api/v1");
        assert_eq!(*val, "backend_v1");
    }
}
