//! 32-bit-keyed elastic binary tree.
//!
//! Port of HAProxy's `eb32tree` (`include/import/eb32tree.h`, `src/eb32tree.c`,
//! ebtree 6.0.6 by Willy Tarreau) onto an index arena. See `design/004-ebtree.md`.

use crate::tref::{Branch, Half, Parent, Side, ROOT};

/// Maximum number of nodes. One index is reserved as the `ROOT` sentinel.
pub const MAX_NODES: u32 = ROOT - 1;

/// Sentinel `bit` value marking the head of a duplicate subtree.
const DUP: i16 = -1;

#[derive(Clone, Debug)]
struct Node {
    /// Branches of this node's *link* half.
    branches: [Branch; 2],
    /// Parent of this node's link half. `NONE` while the link half is unused.
    node_p: Parent,
    /// Parent of this node's leaf half. Always set for a node in the tree.
    leaf_p: Parent,
    /// Bit position this link discriminates on. Negative marks a duplicate subtree.
    bit: i16,
    key: u32,
    /// Opaque payload owned by the caller.
    ///
    /// ebtree is intrusive: in C the node is embedded in the payload struct. Here the
    /// caller keeps its own storage and hands us an index into it, which preserves the
    /// property that matters — the tree allocates nothing per insertion — without
    /// needing the tree to own or drop user data.
    data: u32,
}

/// Where a displaced node's parent link lives, so it can be rewritten once the new
/// node is placed. Stands in for C's `eb_troot_t **up_ptr`, which aliases either
/// `old->leaf_p` or `old->node_p`.
#[derive(Copy, Clone)]
enum Up {
    Leaf(u32),
    Link(u32),
}

/// An elastic binary tree over `u32` keys.
///
/// Depth is bounded by key width (32), not by element count and not by key
/// distribution — there is no input an adversary can choose that degrades it. See
/// `design/003-scheduler.md` §5.
#[derive(Clone, Debug)]
pub struct Eb32Tree {
    nodes: Vec<Node>,
    free: Vec<u32>,
    /// The tree root's branch slots. Only `[0]` is ever occupied; `[1]` stays `NONE`
    /// and is what terminates an upward walk in [`Self::next`], exactly as the NULL
    /// right branch does in C.
    root: [Branch; 2],
    unique: bool,
    len: usize,
}

impl Default for Eb32Tree {
    fn default() -> Self {
        Self::new()
    }
}

impl Eb32Tree {
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

    /// A tree that refuses duplicate keys (C's `EB_ROOT_UNIQUE`).
    #[must_use]
    pub const fn new_unique() -> Self {
        let mut t = Self::new();
        t.unique = true;
        t
    }

    /// Pre-allocates arena capacity. Call at boot so the data path never grows the
    /// arena.
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
    pub fn key_of(&self, idx: u32) -> u32 {
        self.nodes[idx as usize].key
    }

    #[must_use]
    #[inline]
    pub fn data_of(&self, idx: u32) -> u32 {
        self.nodes[idx as usize].data
    }

    // ---- arena -----------------------------------------------------------------

    fn alloc(&mut self, key: u32, data: u32) -> u32 {
        let node = Node {
            branches: [Branch::NONE; 2],
            node_p: Parent::NONE,
            leaf_p: Parent::NONE,
            bit: 0,
            key,
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

    // ---- slot access -------------------------------------------------------------
    //
    // A `Parent` names an `eb_root` (the tree root, or a node's branch array) plus a
    // side. These two helpers are the arena equivalent of dereferencing a tagged
    // parent pointer and indexing `b[side]`.

    #[inline]
    #[allow(dead_code)] // used by delete(), next commit
    fn slot(&self, p: Parent) -> Branch {
        let s = p.side().idx();
        if p.is_root() {
            self.root[s]
        } else {
            self.nodes[p.owner() as usize].branches[s]
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

    // ---- insert ------------------------------------------------------------------

    /// Inserts `key`. Returns the arena index of the inserted node, or — in a unique
    /// tree where `key` is already present — the index of the existing node.
    ///
    /// Mirrors `__eb32_insert()`.
    pub fn insert(&mut self, key: u32, data: u32) -> u32 {
        // Empty tree: the node's leaf half hangs directly off the root's left slot,
        // and its link half stays unused. This is the case that makes the structure
        // "elastic" — one item needs exactly one node.
        if self.root[0].is_none() {
            let new = self.alloc(key, data);
            self.nodes[new as usize].leaf_p = Parent::root(Side::Left);
            self.nodes[new as usize].node_p = Parent::NONE;
            self.root[0] = Branch::new(new, Half::Leaf);
            self.len += 1;
            return new;
        }

        // Descend. `slot` is the branch we arrived through; `troot` is what it holds.
        let mut slot = Parent::root(Side::Left);
        let mut troot = self.root[0];
        let old: u32;
        let up: Up;

        loop {
            if troot.half() == Half::Leaf {
                // Reached a leaf: the new node is inserted above it.
                old = troot.index();
                up = Up::Leaf(old);
                break;
            }

            let o = troot.index();
            let old_bit = self.nodes[o as usize].bit;
            let okey = self.nodes[o as usize].key;

            // Stop when the keys diverge above this node's bit, or when we are in
            // front of a duplicate subtree. The short-circuit on `old_bit < 0` is
            // load-bearing: the shift below is meaningless for a negative bit.
            if old_bit < 0 || ((key ^ okey) >> old_bit) >= 2 {
                old = o;
                up = Up::Link(o);
                break;
            }

            let side = Side::from_bit(key >> old_bit);
            slot = Parent::new(o, side);
            troot = self.nodes[o as usize].branches[side.idx()];
        }

        let okey = self.nodes[old as usize].key;

        // Equal keys: either reject (unique tree), extend an existing duplicate
        // subtree, or fall through to create a fresh one.
        if key == okey {
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
        self.nodes[new as usize].bit = if key == okey {
            DUP
        } else {
            // flsnz(x) - 1: index of the highest bit where the keys differ.
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            {
                (31 - (key ^ okey).leading_zeros()) as i16
            }
        };

        let new_leaf = Branch::new(new, Half::Leaf);
        if key >= okey {
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

    /// Inserts into an existing duplicate subtree. Mirrors `__eb_insert_dup()`.
    ///
    /// Duplicates form a right-leaning chain of nodes with strictly decreasing
    /// negative `bit` values. Gaps in that sequence are "holes" left by earlier
    /// removals, and are reused in preference to deepening the chain.
    fn insert_dup(&mut self, sub_start: u32, new: u32) -> u32 {
        let mut sub = sub_start;
        let mut head = sub_start;

        // Find the deepest hole along the right spine.
        while self.nodes[head as usize].branches[Side::Right.idx()].half() != Half::Leaf {
            let last = head;
            head = self.nodes[head as usize].branches[Side::Right.idx()].index();
            if self.nodes[head as usize].bit > self.nodes[last as usize].bit + 1 {
                sub = head;
            }
        }

        let new_leaf = Branch::new(new, Half::Leaf);

        if self.nodes[head as usize].bit < DUP {
            // A hole sits just before the leaf; drop the new node into it.
            self.nodes[new as usize].bit = DUP;
            let leaf = self.nodes[head as usize].branches[Side::Right.idx()].index();
            self.nodes[head as usize].branches[Side::Right.idx()] = Branch::new(new, Half::Link);
            self.nodes[new as usize].node_p = self.nodes[leaf as usize].leaf_p;
            self.nodes[new as usize].leaf_p = Parent::new(new, Side::Right);
            self.nodes[leaf as usize].leaf_p = Parent::new(new, Side::Left);
            self.nodes[new as usize].branches[Side::Left.idx()] = Branch::new(leaf, Half::Leaf);
            self.nodes[new as usize].branches[Side::Right.idx()] = new_leaf;
        } else {
            // No hole: insert above `sub` at the lowest level.
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

    // ---- traversal ---------------------------------------------------------------

    #[inline]
    fn walk_down(&self, mut t: Branch, side: Side) -> Option<u32> {
        if t.is_none() {
            return None;
        }
        // Bounded by key width: a descent can never exceed 32 link levels plus the
        // duplicate chain.
        while t.half() == Half::Link {
            t = self.nodes[t.index() as usize].branches[side.idx()];
            if t.is_none() {
                return None;
            }
        }
        Some(t.index())
    }

    /// Leftmost (smallest-keyed) node.
    #[must_use]
    pub fn first(&self) -> Option<u32> {
        self.walk_down(self.root[0], Side::Left)
    }

    /// Rightmost (largest-keyed) node.
    #[must_use]
    pub fn last(&self) -> Option<u32> {
        self.walk_down(self.root[0], Side::Right)
    }

    /// Next node in key order. Mirrors `eb_next()`.
    #[must_use]
    pub fn next(&self, idx: u32) -> Option<u32> {
        let mut t = self.nodes[idx as usize].leaf_p;
        // Walk up while we are a right child. Terminates because the root's own
        // parent link is never a right child.
        while t.side() == Side::Right {
            t = self.nodes[t.owner() as usize].node_p;
            if t.is_none() {
                return None;
            }
        }
        // We are a left child: the answer is the leftmost leaf of our right sibling.
        // At the root this reads `root[1]`, which is always NONE — that is precisely
        // how C detects the end of the tree.
        let sibling = if t.is_root() {
            self.root[Side::Right.idx()]
        } else {
            self.nodes[t.owner() as usize].branches[Side::Right.idx()]
        };
        self.walk_down(sibling, Side::Left)
    }

    /// Previous node in key order. Mirrors `eb_prev()`.
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

    /// Iterates node indices in ascending key order.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            tree: self,
            cur: self.first(),
        }
    }

    // ---- lookup ------------------------------------------------------------------

    /// Finds a node with exactly `key`. If duplicates exist, returns the first in
    /// insertion order.
    #[must_use]
    pub fn lookup(&self, key: u32) -> Option<u32> {
        let mut t = self.root[0];
        if t.is_none() {
            return None;
        }
        loop {
            if t.half() == Half::Leaf {
                let n = t.index();
                return if self.nodes[n as usize].key == key {
                    Some(n)
                } else {
                    None
                };
            }
            let n = t.index();
            let bit = self.nodes[n as usize].bit;
            if bit < 0 {
                // Head of a duplicate subtree: every leaf below shares one key.
                let leaf = self.walk_down(t, Side::Left)?;
                return if self.nodes[leaf as usize].key == key {
                    Some(leaf)
                } else {
                    None
                };
            }
            #[allow(clippy::cast_sign_loss)]
            let side = Side::from_bit(key >> bit);
            t = self.nodes[n as usize].branches[side.idx()];
            if t.is_none() {
                return None;
            }
        }
    }
}

/// Ascending iterator over node indices.
pub struct Iter<'a> {
    tree: &'a Eb32Tree,
    cur: Option<u32>,
}

impl Iterator for Iter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let cur = self.cur?;
        self.cur = self.tree.next(cur);
        Some(cur)
    }
}
