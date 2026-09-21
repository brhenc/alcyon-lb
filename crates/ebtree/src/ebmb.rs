// SPDX-License-Identifier: LGPL-2.1-only
// Derived from HAProxy include/import/ebmbtree.h and ebsttree.h.
// Copyright (C) 2002-2011 Willy Tarreau <w@1wt.eu>. See LICENSE.

//! Multi-byte and string-keyed elastic binary tree (`EbMbTree`).
//!
//! Port of `HAProxy`'s `ebmbtree` / `ebsttree` onto a memory-safe index arena
//! under `#![forbid(unsafe_code)]`.
//! Provides $O(k)$ lookup, insertion, and deletion for byte strings and domain names (SNI).

use crate::tref::{Branch, Half, Parent, Side, ROOT};

/// Maximum number of nodes. One index is reserved as the `ROOT` sentinel.
pub const MAX_NODES: u32 = ROOT - 1;

/// Sentinel `bit` value marking the head of a duplicate subtree.
const DUP: i32 = -1;

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug)]
struct Node {
    branches: [Branch; 2],
    node_p: Parent,
    leaf_p: Parent,
    bit: i32,
    key: Box<[u8]>,
    data: u32,
}

#[derive(Copy, Clone)]
enum Up {
    Leaf(u32),
    Link(u32),
}

#[inline]
fn get_bit(key: &[u8], bit: u32) -> u32 {
    let byte_idx = (bit >> 3) as usize;
    let bit_idx = 7 - (bit & 7);
    if byte_idx < key.len() {
        (u32::from(key[byte_idx]) >> bit_idx) & 1
    } else {
        0
    }
}

#[allow(clippy::cast_possible_truncation)]
#[inline]
fn diverge_bit(a: &[u8], b: &[u8]) -> Option<u32> {
    if a == b {
        return None;
    }
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        if a[i] != b[i] {
            let diff = a[i] ^ b[i];
            let bit_in_byte = diff.leading_zeros();
            return Some(((i as u32) * 8) + bit_in_byte);
        }
    }
    let longer = if a.len() > b.len() { a } else { b };
    for (i, &byte) in longer.iter().enumerate().skip(min_len) {
        if byte != 0 {
            let bit_in_byte = byte.leading_zeros();
            return Some(((i as u32) * 8) + bit_in_byte);
        }
    }
    Some((min_len as u32) * 8)
}

/// An elastic binary tree over variable-length byte keys (`&[u8]`).
#[derive(Clone, Debug)]
pub struct EbMbTree {
    nodes: Vec<Node>,
    free: Vec<u32>,
    root: [Branch; 2],
    unique: bool,
    len: usize,
}

impl Default for EbMbTree {
    fn default() -> Self {
        Self::new()
    }
}

impl EbMbTree {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            free: Vec::new(),
            root: [Branch::NONE, Branch::NONE],
            unique: false,
            len: 0,
        }
    }

    #[must_use]
    pub const fn new_unique() -> Self {
        let mut t = Self::new();
        t.unique = true;
        t
    }

    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(cap),
            free: Vec::new(),
            root: [Branch::NONE, Branch::NONE],
            unique: false,
            len: 0,
        }
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
    pub fn key_of(&self, idx: u32) -> &[u8] {
        &self.nodes[idx as usize].key
    }

    #[must_use]
    #[inline]
    pub fn data_of(&self, idx: u32) -> u32 {
        self.nodes[idx as usize].data
    }

    #[inline]
    pub fn data_of_mut(&mut self, idx: u32) -> &mut u32 {
        &mut self.nodes[idx as usize].data
    }

    fn alloc(&mut self, key: &[u8], data: u32) -> u32 {
        let node = Node {
            branches: [Branch::NONE; 2],
            node_p: Parent::NONE,
            leaf_p: Parent::NONE,
            bit: 0,
            key: key.into(),
            data,
        };
        if let Some(idx) = self.free.pop() {
            self.nodes[idx as usize] = node;
            idx
        } else {
            let idx = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
            assert!(idx < MAX_NODES, "ebtree: arena exhausted");
            self.nodes.push(node);
            idx
        }
    }

    #[inline]
    fn set_slot(&mut self, p: Parent, b: Branch) {
        let s = p.side().idx();
        if p.is_root() {
            self.root[s] = b;
        } else {
            self.nodes[p.owner() as usize].branches[s] = b;
        }
    }

    #[inline]
    fn write_up(&mut self, up: Up, p: Parent) {
        match up {
            Up::Leaf(n) => self.nodes[n as usize].leaf_p = p,
            Up::Link(n) => self.nodes[n as usize].node_p = p,
        }
    }

    /// Inserts `key`. Returns the arena index of the inserted node, or the existing node index if unique.
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    pub fn insert(&mut self, key: &[u8], data: u32) -> u32 {
        if self.root[0].is_none() {
            let new = self.alloc(key, data);
            self.nodes[new as usize].leaf_p = Parent::root(Side::Left);
            self.nodes[new as usize].node_p = Parent::NONE;
            self.root[0] = Branch::new(new, Half::Leaf);
            self.len += 1;
            return new;
        }

        let mut slot = Parent::root(Side::Left);
        let mut troot = self.root[0];
        let old: u32;
        let up: Up;

        loop {
            if troot.half() == Half::Leaf {
                old = troot.index();
                up = Up::Leaf(old);
                break;
            }

            let o = troot.index();
            let old_bit = self.nodes[o as usize].bit;
            let okey = &self.nodes[o as usize].key;

            if old_bit < 0 {
                old = o;
                up = Up::Link(o);
                break;
            }

            if let Some(div_bit) = diverge_bit(key, okey) {
                if (div_bit as i32) < old_bit {
                    old = o;
                    up = Up::Link(o);
                    break;
                }
            } else {
                old = o;
                up = Up::Link(o);
                break;
            }

            let side = get_bit(key, old_bit as u32) as usize;
            slot = Parent::new(o, if side == 0 { Side::Left } else { Side::Right });
            troot = self.nodes[o as usize].branches[side];
        }

        let okey = &self.nodes[old as usize].key;

        if &**okey == key {
            if self.unique {
                return old;
            }
            if troot.half() != Half::Leaf {
                let new = self.alloc(key, data);
                return self.insert_dup(old, new);
            }
        }

        let new = self.alloc(key, data);
        self.nodes[new as usize].node_p = match up {
            Up::Leaf(n) => self.nodes[n as usize].leaf_p,
            Up::Link(n) => self.nodes[n as usize].node_p,
        };

        let is_equal = &self.nodes[old as usize].key[..] == key;
        let bit = if is_equal {
            DUP
        } else if let Some(div_bit) = diverge_bit(key, &self.nodes[old as usize].key) {
            div_bit as i32
        } else {
            DUP
        };
        self.nodes[new as usize].bit = bit;

        let new_leaf = Branch::new(new, Half::Leaf);
        let new_is_right = if is_equal {
            true
        } else if bit >= 0 {
            get_bit(key, bit as u32) == 1
        } else {
            true
        };

        if new_is_right {
            self.nodes[new as usize].branches[Side::Left.idx()] = troot;
            self.nodes[new as usize].branches[Side::Right.idx()] = new_leaf;
            self.nodes[new as usize].leaf_p = Parent::new(new, Side::Right);
            self.write_up(up, Parent::new(new, Side::Left));
        } else {
            self.nodes[new as usize].branches[Side::Left.idx()] = new_leaf;
            self.nodes[new as usize].branches[Side::Right.idx()] = troot;
            self.nodes[new as usize].leaf_p = Parent::new(new, Side::Left);
            self.write_up(up, Parent::new(new, Side::Right));
        }

        self.set_slot(slot, Branch::new(new, Half::Link));
        self.len += 1;
        new
    }

    fn insert_dup(&mut self, sub_start: u32, new: u32) -> u32 {
        let mut sub = sub_start;
        let mut head = sub_start;

        while self.nodes[head as usize].branches[Side::Right.idx()].half() != Half::Leaf {
            let last = head;
            head = self.nodes[head as usize].branches[Side::Right.idx()].index();
            if self.nodes[head as usize].bit > self.nodes[last as usize].bit + 1 {
                sub = head;
            }
        }

        let new_leaf = Branch::new(new, Half::Leaf);

        if self.nodes[head as usize].bit < DUP {
            self.nodes[new as usize].bit = DUP;
            let leaf = self.nodes[head as usize].branches[Side::Right.idx()].index();
            self.nodes[head as usize].branches[Side::Right.idx()] = Branch::new(new, Half::Link);
            self.nodes[new as usize].node_p = self.nodes[leaf as usize].leaf_p;
            self.nodes[new as usize].leaf_p = Parent::new(new, Side::Right);
            self.nodes[leaf as usize].leaf_p = Parent::new(new, Side::Left);
            self.nodes[new as usize].branches[Side::Left.idx()] = Branch::new(leaf, Half::Leaf);
            self.nodes[new as usize].branches[Side::Right.idx()] = new_leaf;
        } else {
            self.nodes[new as usize].bit = self.nodes[sub as usize].bit - 1;
            let p = self.nodes[sub as usize].node_p;
            self.set_slot(p, Branch::new(new, Half::Link));
            self.nodes[new as usize].node_p = p;
            self.nodes[new as usize].leaf_p = Parent::new(new, Side::Right);
            self.nodes[sub as usize].node_p = Parent::new(new, Side::Left);
            self.nodes[new as usize].branches[Side::Left.idx()] = Branch::new(sub, Half::Link);
            self.nodes[new as usize].branches[Side::Right.idx()] = new_leaf;
        }

        self.len += 1;
        new
    }

    #[inline]
    fn walk_down(&self, mut t: Branch, side: Side) -> Option<u32> {
        if t.is_none() {
            return None;
        }
        while t.half() == Half::Link {
            t = self.nodes[t.index() as usize].branches[side.idx()];
            if t.is_none() {
                return None;
            }
        }
        Some(t.index())
    }

    #[must_use]
    pub fn first(&self) -> Option<u32> {
        self.walk_down(self.root[0], Side::Left)
    }

    #[must_use]
    pub fn last(&self) -> Option<u32> {
        self.walk_down(self.root[0], Side::Right)
    }

    fn next_from_parent(&self, mut t: Parent) -> Option<u32> {
        if t.is_none() {
            return None;
        }
        while t.side() == Side::Right {
            t = self.nodes[t.owner() as usize].node_p;
            if t.is_none() {
                return None;
            }
        }
        let sibling = if t.is_root() {
            self.root[Side::Right.idx()]
        } else {
            self.nodes[t.owner() as usize].branches[Side::Right.idx()]
        };
        self.walk_down(sibling, Side::Left)
    }

    #[must_use]
    pub fn next(&self, idx: u32) -> Option<u32> {
        self.next_from_parent(self.nodes[idx as usize].leaf_p)
    }

    #[must_use]
    pub fn prev(&self, idx: u32) -> Option<u32> {
        let mut t = self.nodes[idx as usize].leaf_p;
        while t.side() == Side::Left {
            if t.is_root() {
                return None;
            }
            t = self.nodes[t.owner() as usize].node_p;
            if t.is_none() {
                return None;
            }
        }
        let sibling = if t.is_root() {
            self.root[Side::Left.idx()]
        } else {
            self.nodes[t.owner() as usize].branches[Side::Left.idx()]
        };
        self.walk_down(sibling, Side::Right)
    }

    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self,
            cur: self.first(),
        }
    }

    /// Exact key lookup, returning data value.
    #[must_use]
    pub fn lookup(&self, key: &[u8]) -> Option<u32> {
        self.lookup_node(key)
            .map(|idx| self.nodes[idx as usize].data)
    }

    /// Exact key lookup, returning the arena node index.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    #[must_use]
    pub fn lookup_node(&self, key: &[u8]) -> Option<u32> {
        let mut troot = self.root[0];
        if troot.is_none() {
            return None;
        }

        while troot.half() == Half::Link {
            let o = troot.index() as usize;
            let node = &self.nodes[o];
            if node.bit < 0 {
                if &*node.key == key {
                    return Some(o as u32);
                }
                troot = node.branches[Side::Left.idx()];
                continue;
            }

            let side = get_bit(key, node.bit as u32) as usize;
            troot = node.branches[side];
            if troot.is_none() {
                return None;
            }
        }

        let leaf_idx = troot.index() as usize;
        if &*self.nodes[leaf_idx].key == key {
            Some(leaf_idx as u32)
        } else {
            None
        }
    }

    /// Removes the node at `idx` from the tree.
    pub fn delete(&mut self, idx: u32) -> bool {
        if self.nodes[idx as usize].leaf_p.is_none() {
            return false;
        }

        let leaf_p = self.nodes[idx as usize].leaf_p;
        let pside = leaf_p.side();

        if leaf_p.is_root() {
            self.root[Side::Left.idx()] = Branch::NONE;
            self.unlink_and_recycle(idx);
            return true;
        }

        let parent = leaf_p.owner();
        let gp = self.nodes[parent as usize].node_p;
        let sibling = self.nodes[parent as usize].branches[1 - pside.idx()];
        self.set_slot(gp, sibling);
        self.set_back_link(sibling, gp);

        self.nodes[parent as usize].node_p = Parent::NONE;

        if !self.nodes[idx as usize].node_p.is_none() {
            let node_p = self.nodes[idx as usize].node_p;
            let branches = self.nodes[idx as usize].branches;
            let bit = self.nodes[idx as usize].bit;

            self.nodes[parent as usize].node_p = node_p;
            self.nodes[parent as usize].branches = branches;
            self.nodes[parent as usize].bit = bit;

            self.set_slot(node_p, Branch::new(parent, Half::Link));

            for side in [Side::Left, Side::Right] {
                let child = self.nodes[parent as usize].branches[side.idx()];
                self.set_back_link(child, Parent::new(parent, side));
            }
        }

        self.unlink_and_recycle(idx);
        true
    }

    #[inline]
    fn set_back_link(&mut self, child: Branch, p: Parent) {
        if child.is_none() {
            return;
        }
        let c = child.index() as usize;
        match child.half() {
            Half::Leaf => self.nodes[c].leaf_p = p,
            Half::Link => self.nodes[c].node_p = p,
        }
    }

    fn unlink_and_recycle(&mut self, idx: u32) {
        self.nodes[idx as usize].leaf_p = Parent::NONE;
        self.nodes[idx as usize].node_p = Parent::NONE;
        self.nodes[idx as usize].branches = [Branch::NONE, Branch::NONE];
        self.free.push(idx);
        self.len -= 1;
    }

    /// Verifies structural invariants for testing.
    ///
    /// # Errors
    /// Returns an error description if an invariant is violated.
    pub fn check_invariants(&self) -> Result<(), String> {
        if self.root[Side::Right.idx()] != Branch::NONE {
            return Err("root right branch must always be NONE".into());
        }
        if self.root[0].is_none() {
            return if self.len == 0 {
                Ok(())
            } else {
                Err(format!("empty root but len={}", self.len))
            };
        }

        let mut seen_leaves = 0usize;
        let mut stack = vec![(self.root[0], Parent::root(Side::Left))];

        while let Some((branch, expected_parent)) = stack.pop() {
            if branch.is_none() {
                return Err("branch in active tree is NONE".into());
            }
            let n = branch.index() as usize;
            if n >= self.nodes.len() {
                return Err(format!("branch index {n} out of bounds"));
            }

            match branch.half() {
                Half::Leaf => {
                    seen_leaves += 1;
                    if self.nodes[n].leaf_p != expected_parent {
                        return Err(format!(
                            "leaf {n}: leaf_p {:?} != expected {:?}",
                            self.nodes[n].leaf_p, expected_parent
                        ));
                    }
                }
                Half::Link => {
                    if self.nodes[n].node_p != expected_parent {
                        return Err(format!(
                            "link {n}: node_p {:?} != expected {:?}",
                            self.nodes[n].node_p, expected_parent
                        ));
                    }
                    stack.push((
                        self.nodes[n].branches[Side::Right.idx()],
                        Parent::new(branch.index(), Side::Right),
                    ));
                    stack.push((
                        self.nodes[n].branches[Side::Left.idx()],
                        Parent::new(branch.index(), Side::Left),
                    ));
                }
            }
        }

        if seen_leaves != self.len {
            return Err(format!(
                "reachable leaves {seen_leaves} != len {}",
                self.len
            ));
        }

        Ok(())
    }
}

/// Iterator over node indices in `EbMbTree`.
pub struct Iter<'a> {
    inner: &'a EbMbTree,
    cur: Option<u32>,
}

impl Iterator for Iter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.cur?;
        self.cur = self.inner.next(cur);
        Some(cur)
    }
}

impl<'a> IntoIterator for &'a EbMbTree {
    type Item = u32;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebmb_basic_crud() {
        let mut tree = EbMbTree::new_unique();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);

        let n1 = tree.insert(b"example.com", 100);
        let n2 = tree.insert(b"api.example.com", 200);
        let _n3 = tree.insert(b"admin.example.com", 300);
        let _n4 = tree.insert(b"wildcard.org", 400);

        assert_eq!(tree.len(), 4);
        tree.check_invariants().unwrap();

        assert_eq!(tree.lookup(b"example.com"), Some(100));
        assert_eq!(tree.lookup(b"api.example.com"), Some(200));
        assert_eq!(tree.lookup(b"admin.example.com"), Some(300));
        assert_eq!(tree.lookup(b"wildcard.org"), Some(400));
        assert_eq!(tree.lookup(b"nonexistent.com"), None);

        // Delete n2 (api.example.com)
        assert!(tree.delete(n2));
        assert_eq!(tree.len(), 3);
        tree.check_invariants().unwrap();
        assert_eq!(tree.lookup(b"api.example.com"), None);
        assert_eq!(tree.lookup(b"example.com"), Some(100));

        // Re-insert api.example.com
        let _n2_new = tree.insert(b"api.example.com", 250);
        assert_eq!(tree.lookup(b"api.example.com"), Some(250));
        tree.check_invariants().unwrap();

        // Unique duplicate insert
        let dup = tree.insert(b"example.com", 999);
        assert_eq!(dup, n1);
        assert_eq!(tree.lookup(b"example.com"), Some(100));
    }

    #[test]
    fn test_ebmb_shared_prefix() {
        let mut tree = EbMbTree::new_unique();
        tree.insert(b"abc", 1);
        tree.insert(b"abcd", 2);
        tree.insert(b"abce", 3);
        tree.insert(b"ab", 4);
        tree.insert(b"a", 5);

        assert_eq!(tree.len(), 5);
        tree.check_invariants().unwrap();

        assert_eq!(tree.lookup(b"a"), Some(5));
        assert_eq!(tree.lookup(b"ab"), Some(4));
        assert_eq!(tree.lookup(b"abc"), Some(1));
        assert_eq!(tree.lookup(b"abcd"), Some(2));
        assert_eq!(tree.lookup(b"abce"), Some(3));
    }
}
