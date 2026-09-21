//! Multi-Byte Elastic Binary Tree (ebmb)
//!
//! Binary crit-bit tree for arbitrary multi-byte keys (IPv6 addresses, TLS session IDs, binary tokens).

use ibex_core::ibex_assert;

#[derive(Debug, Clone)]
struct Node<V> {
    key: Vec<u8>,
    value: V,
    byte_idx: usize,
    bit_idx: u8,
    left: Option<Box<Node<V>>>,
    right: Option<Box<Node<V>>>,
}

/// Multi-byte Elastic Binary Tree
#[derive(Debug, Clone, Default)]
pub struct EbMbTree<V> {
    root: Option<Box<Node<V>>>,
    count: usize,
}

impl<V> EbMbTree<V> {
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

    #[inline(always)]
    fn get_bit(bytes: &[u8], byte_idx: usize, bit_idx: u8) -> u8 {
        if byte_idx < bytes.len() {
            (bytes[byte_idx] >> bit_idx) & 1
        } else {
            0
        }
    }

    /// Inserts a byte-slice key and value.
    pub fn insert(&mut self, key: &[u8], value: V) -> Option<V> {
        ibex_assert!(self.count < usize::MAX, "Tree size bounded");
        if self.root.is_none() {
            self.root = Some(Box::new(Node {
                key: key.to_vec(),
                value,
                byte_idx: 0,
                bit_idx: 7,
                left: None,
                right: None,
            }));
            self.count += 1;
            return None;
        }

        let mut curr = self.root.as_mut().expect("Root exists");
        let max_depth = key.len().saturating_mul(8) + 64;

        for _ in 0..max_depth {
            if curr.key.as_slice() == key {
                let old = std::mem::replace(&mut curr.value, value);
                return Some(old);
            }

            let bit_val = Self::get_bit(key, curr.byte_idx, curr.bit_idx);
            if bit_val == 0 {
                if curr.left.is_none() {
                    let (next_byte, next_bit) = if curr.bit_idx > 0 {
                        (curr.byte_idx, curr.bit_idx - 1)
                    } else {
                        (curr.byte_idx + 1, 7)
                    };
                    curr.left = Some(Box::new(Node {
                        key: key.to_vec(),
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
                        key: key.to_vec(),
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

    /// Looks up an exact byte-slice key.
    pub fn lookup(&self, key: &[u8]) -> Option<&V> {
        let mut curr = self.root.as_deref()?;
        let max_depth = key.len().saturating_mul(8) + 64;

        for _ in 0..max_depth {
            if curr.key.as_slice() == key {
                return Some(&curr.value);
            }
            let bit_val = Self::get_bit(key, curr.byte_idx, curr.bit_idx);
            curr = if bit_val == 0 {
                curr.left.as_deref()?
            } else {
                curr.right.as_deref()?
            };
        }
        if curr.key.as_slice() == key {
            Some(&curr.value)
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
    fn test_ebmb_ipv6_lookup() {
        let mut tree = EbMbTree::new();
        let ip1 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ip2 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        assert_eq!(tree.insert(&ip1, "session_ip1"), None);
        assert_eq!(tree.insert(&ip2, "session_ip2"), None);

        assert_eq!(tree.lookup(&ip1), Some(&"session_ip1"));
        assert_eq!(tree.lookup(&ip2), Some(&"session_ip2"));
        assert_eq!(tree.lookup(&[0u8; 16]), None);
    }
}
