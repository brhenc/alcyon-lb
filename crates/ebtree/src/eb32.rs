// SPDX-License-Identifier: LGPL-2.1-only
// Derived from HAProxy include/import/eb32tree.h and src/eb32tree.c.
// Copyright (C) 2002-2011 Willy Tarreau <w@1wt.eu>. See LICENSE.

//! 32-bit-keyed elastic binary tree.
//!
//! Port of `HAProxy`'s `eb32tree` (`include/import/eb32tree.h`, `src/eb32tree.c`,
//! ebtree 6.0.6 by Willy Tarreau) onto an index arena. See `design/004-ebtree.md`.

use crate::tref::{Branch, Half, Parent, Side, ROOT};

/// Maximum number of nodes. One index is reserved as the `ROOT` sentinel.
pub const MAX_NODES: u32 = ROOT - 1;

/// Sentinel `bit` value marking the head of a duplicate subtree.
const DUP: i16 = -1;

/// The end of the free list: no slot index reaches it (`MAX_NODES` < `ROOT` < `u32::MAX`).
const NO_FREE: u32 = u32::MAX;

// `node_p` / `leaf_p` keep the names they have in the C original so the port can be
// cross-referenced against `include/import/ebtree-t.h` line for line. That is worth more
// than satisfying the struct_field_names heuristic.
#[allow(clippy::struct_field_names)]
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
    /// The first free slot of the arena, or [`NO_FREE`]; each free slot's `data` names the
    /// next. Intrusive, so that a delete never allocates (T465: a `Vec` free list grew on a
    /// delete and aborted the process when memory ran out).
    free: u32,
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
            free: NO_FREE,
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
            free: NO_FREE,
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

    /// Makes room for `additional` more nodes at once, at boot, when the caller knows how
    /// many it is about to insert (one timer per health check), instead of growing the
    /// arena by doubling past what is needed.
    pub fn reserve(&mut self, additional: usize) {
        self.nodes.reserve(additional);
    }

    /// How many nodes the tree holds before its arena must grow: an insert past it allocates.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.nodes.capacity()
    }

    /// Whether the next insert needs no allocation, making room for one more node (fallibly)
    /// when it would: `false` when that memory cannot be had.
    #[inline]
    pub fn try_room_for_one(&mut self) -> bool {
        self.free != NO_FREE || self.nodes.len() < self.nodes.capacity() || self.nodes.try_reserve(1).is_ok()
    }

    /// Makes room for `total` nodes in all, `false` (the tree unchanged) when the memory cannot
    /// be had. A caller that does this before it needs a node never has an insert allocate.
    pub fn try_reserve_total(&mut self, total: usize) -> bool {
        self.nodes.try_reserve_exact(total.saturating_sub(self.nodes.len())).is_ok()
    }

    fn alloc(&mut self, key: u32, data: u32) -> u32 {
        let node = Node {
            branches: [Branch::NONE; 2],
            node_p: Parent::NONE,
            leaf_p: Parent::NONE,
            bit: 0,
            key,
            data,
        };
        if self.free == NO_FREE {
            let idx = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
            assert!(idx < MAX_NODES, "ebtree: arena exhausted");
            self.nodes.push(node);
            idx
        } else {
            let idx = self.free;
            self.free = self.nodes[idx as usize].data;
            self.nodes[idx as usize] = node;
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
            i16::try_from((key ^ okey).ilog2()).unwrap_or(0)
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

    /// The next node in key order, starting from a *parent link* rather than a node.
    ///
    /// Shared by [`Self::next`] and [`Self::lookup_ge`]. In C these are the same code
    /// because `leaf_p` and `node_p` are both `eb_troot_t`; here they are the same
    /// type (`Parent`) but reached from different fields, so the sharing is explicit.
    fn next_from_parent(&self, mut t: Parent) -> Option<u32> {
        if t.is_none() {
            return None;
        }
        // Walk up while we are a right child. Terminates at the root, whose own
        // parent link is a left link by construction.
        while t.side() == Side::Right {
            t = self.nodes[t.owner() as usize].node_p;
            if t.is_none() {
                return None;
            }
        }
        // We are a left child: the answer is the leftmost leaf of our right sibling.
        // At the root this reads `root[1]`, which is always NONE — precisely how C
        // detects the end of the tree.
        let sibling = if t.is_root() {
            self.root[Side::Right.idx()]
        } else {
            self.nodes[t.owner() as usize].branches[Side::Right.idx()]
        };
        self.walk_down(sibling, Side::Left)
    }

    /// Next node in key order. Mirrors `eb_next()`.
    #[must_use]
    pub fn next(&self, idx: u32) -> Option<u32> {
        self.next_from_parent(self.nodes[idx as usize].leaf_p)
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
    #[must_use]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self,
            cur: self.first(),
        }
    }

    // ---- invariant checking --------------------------------------------------------

    /// Verifies every structural invariant, returning `Err` with a description of the
    /// first violation. Intended for tests and fuzzing.
    ///
    /// Traversal can look correct while the tree is internally malformed in a way that
    /// only surfaces several deletions later, so this checks the structure directly
    /// rather than inferring health from observable behaviour.
    ///
    /// # Errors
    /// Returns a description of the first invariant violated.
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
        let mut stack = vec![(self.root[0], Parent::root(Side::Left), i32::MAX)];

        while let Some((branch, expect_parent, parent_bit)) = stack.pop() {
            if branch.is_none() {
                return Err(format!("NONE branch reachable from {expect_parent:?}"));
            }
            let n = branch.index() as usize;
            if n >= self.nodes.len() {
                return Err(format!("index {n} out of arena bounds"));
            }

            match branch.half() {
                Half::Leaf => {
                    if self.nodes[n].leaf_p != expect_parent {
                        return Err(format!(
                            "leaf {n}: leaf_p is {:?}, parent says {expect_parent:?}",
                            self.nodes[n].leaf_p
                        ));
                    }
                    seen_leaves += 1;
                }
                Half::Link => {
                    if self.nodes[n].node_p != expect_parent {
                        return Err(format!(
                            "link {n}: node_p is {:?}, parent says {expect_parent:?}",
                            self.nodes[n].node_p
                        ));
                    }
                    let bit = i32::from(self.nodes[n].bit);
                    // Bit ordering runs in opposite directions in the two regions of
                    // the tree, which is easy to get wrong:
                    //
                    // * Main tree (parent bit >= 0): bits strictly *decrease* going
                    //   down. This is what bounds depth by key width.
                    // * Duplicate subtree (parent bit < 0): bits strictly *increase*
                    //   going down, normally by exactly one, toward -1 at the bottom.
                    //   `__eb_insert_dup` detects a reusable "hole" precisely as a
                    //   gap in that sequence (`head->bit > last->bit + 1`).
                    //
                    // Entry into a duplicate subtree still satisfies the main-tree
                    // rule, since any negative bit is below any non-negative one.
                    if parent_bit >= 0 {
                        if bit >= parent_bit {
                            return Err(format!(
                                "link {n}: main-tree bit {bit} must be below parent bit {parent_bit}"
                            ));
                        }
                    } else {
                        if bit >= 0 {
                            return Err(format!(
                                "link {n}: bit {bit} must stay negative inside a duplicate subtree (parent {parent_bit})"
                            ));
                        }
                        if bit <= parent_bit {
                            return Err(format!(
                                "link {n}: duplicate-subtree bit {bit} must be above parent bit {parent_bit}"
                            ));
                        }
                    }
                    stack.push((
                        self.nodes[n].branches[Side::Right.idx()],
                        Parent::new(branch.index(), Side::Right),
                        bit,
                    ));
                    stack.push((
                        self.nodes[n].branches[Side::Left.idx()],
                        Parent::new(branch.index(), Side::Left),
                        bit,
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

        // Keys must be non-decreasing in traversal order, and traversal must visit
        // exactly the reachable leaves.
        let mut count = 0usize;
        let mut prev: Option<u32> = None;
        for i in self {
            let k = self.key_of(i);
            if let Some(pk) = prev {
                if k < pk {
                    return Err(format!("traversal out of order: {pk} then {k}"));
                }
            }
            prev = Some(k);
            count += 1;
            if count > self.len {
                return Err("traversal exceeded len (cycle?)".into());
            }
        }
        if count != self.len {
            return Err(format!("traversal visited {count}, len is {}", self.len));
        }

        Ok(())
    }

    /// Maximum leaf depth. Must stay bounded by key width regardless of input.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        if self.root[0].is_none() {
            return 0;
        }
        let mut max = 0usize;
        let mut stack = vec![(self.root[0], 1usize)];
        while let Some((b, d)) = stack.pop() {
            if b.is_none() {
                continue;
            }
            match b.half() {
                Half::Leaf => max = max.max(d),
                Half::Link => {
                    let n = b.index() as usize;
                    stack.push((self.nodes[n].branches[0], d + 1));
                    stack.push((self.nodes[n].branches[1], d + 1));
                }
            }
        }
        max
    }

    // ---- delete ------------------------------------------------------------------

    /// Removes the node at `idx` from the tree and returns its arena slot to the free
    /// list. Returns `false` if the node was not linked.
    ///
    /// Mirrors `__eb_delete()`. The interesting part is that removing a node's *leaf*
    /// half may leave its *link* half still structurally in use. The resolution is
    /// that our parent's link half becomes free at exactly the same moment, so the
    /// parent is recycled in place to take over our link role. Note also that a node
    /// is frequently its own parent — `insert` attaches a new node's leaf to its own
    /// link half — and that case falls out of the same code rather than needing a
    /// branch.
    pub fn delete(&mut self, idx: u32) -> bool {
        if self.nodes[idx as usize].leaf_p.is_none() {
            return false;
        }

        let leaf_p = self.nodes[idx as usize].leaf_p;
        let pside = leaf_p.side();

        // Attached directly to the tree root. C detects this by testing whether the
        // parent's right branch is NULL, which is true only for the root; here the
        // root is named, so the test is direct.
        if leaf_p.is_root() {
            self.root[Side::Left.idx()] = Branch::NONE;
            self.unlink_and_recycle(idx);
            return true;
        }

        let parent = leaf_p.owner();

        // Reparent our sibling directly onto the grandparent, cutting `parent`'s link
        // half out of the tree. Read the grandparent link before it is cleared.
        let gp = self.nodes[parent as usize].node_p;
        let sibling = self.nodes[parent as usize].branches[1 - pside.idx()];
        self.set_slot(gp, sibling);
        self.set_back_link(sibling, gp);

        // `parent`'s link half is now unused. If `parent == idx` this also clears our
        // own `node_p`, which makes the check below take the early exit — exactly the
        // behaviour C relies on without special-casing it.
        self.nodes[parent as usize].node_p = Parent::NONE;

        if !self.nodes[idx as usize].node_p.is_none() {
            // Our link half is still in use. Move it wholesale onto `parent`, whose
            // link half just became free. `parent` sits below us in the tree, so its
            // key shares every bit above `bit` and remains a valid representative for
            // the branch test.
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

    /// Points a child's upward link at `p`, choosing `leaf_p` or `node_p` according to
    /// which half of the child is attached.
    #[inline]
    fn set_back_link(&mut self, child: Branch, p: Parent) {
        if child.is_none() {
            return;
        }
        match child.half() {
            Half::Leaf => self.nodes[child.index() as usize].leaf_p = p,
            Half::Link => self.nodes[child.index() as usize].node_p = p,
        }
    }

    fn unlink_and_recycle(&mut self, idx: u32) {
        let n = &mut self.nodes[idx as usize];
        n.leaf_p = Parent::NONE;
        n.node_p = Parent::NONE;
        n.branches = [Branch::NONE; 2];
        n.data = self.free;
        self.free = idx;
        self.len -= 1;
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
            let side = Side::from_bit(key >> bit);
            t = self.nodes[n as usize].branches[side.idx()];
            if t.is_none() {
                return None;
            }
        }
    }
    /// Smallest node whose key is `>= x`, or `None` if every key is smaller.
    ///
    /// Mirrors `eb32_lookup_ge()`. This is the operation the timer wait queue is built
    /// on. Note that `HAProxy`'s *wrapping* tick search is caller-level logic, not a
    /// property of the tree: it calls `lookup_ge(now - TIMER_LOOK_BACK)` and, on
    /// `None`, wraps to `first()`, which treats the key space as a circle. See
    /// `design/003-scheduler.md` §4.
    #[must_use]
    pub fn lookup_ge(&self, x: u32) -> Option<u32> {
        let mut troot = self.root[0];
        if troot.is_none() {
            return None;
        }

        // On leaving this loop, `up` names the parent link from which to continue
        // searching rightwards.
        let up: Parent;

        loop {
            if troot.half() == Half::Leaf {
                // All upper bits were common. Take this leaf if it is large enough,
                // otherwise continue from its parent.
                let n = troot.index();
                if self.nodes[n as usize].key >= x {
                    return Some(n);
                }
                up = self.nodes[n as usize].leaf_p;
                break;
            }

            let n = troot.index();
            let y = self.nodes[n as usize].key;
            let bit = self.nodes[n as usize].bit;

            // `bit & 31` matches C's masking, which maps the negative duplicate-tree
            // marker onto bit 31.
            let z = 1u32 << (bit & 31);

            if bit < 0 {
                // Top of a duplicate subtree: every leaf below shares one key, so
                // either the whole subtree qualifies or none of it does.
                if y >= x {
                    return self.walk_down(
                        self.nodes[n as usize].branches[Side::Left.idx()],
                        Side::Left,
                    );
                }
                up = self.nodes[n as usize].node_p;
                break;
            }

            // Any differing bit *above* this node's bit means the entire subtree is
            // uniformly on one side of `x`.
            if (x ^ y) & z.wrapping_shl(1).wrapping_neg() != 0 {
                let shift = u32::try_from(bit).unwrap_or(0);
                if (y >> shift) > (x >> shift) {
                    // Whole subtree exceeds x: its minimum is the answer.
                    return self.walk_down(
                        self.nodes[n as usize].branches[Side::Left.idx()],
                        Side::Left,
                    );
                }
                // Whole subtree is below x: continue after it.
                up = self.nodes[n as usize].node_p;
                break;
            }

            let side = if x & z == 0 { Side::Left } else { Side::Right };
            troot = self.nodes[n as usize].branches[side.idx()];
            if troot.is_none() {
                return None;
            }
        }

        self.next_from_parent(up)
    }
}

impl<'a> IntoIterator for &'a Eb32Tree {
    type Item = u32;
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// Ascending iterator over node indices.
pub struct Iter<'a> {
    inner: &'a Eb32Tree,
    cur: Option<u32>,
}

impl Iterator for Iter<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let cur = self.cur?;
        self.cur = self.inner.next(cur);
        Some(cur)
    }
}

#[cfg(test)]
mod layout {
    #[test]
    fn node_size_is_compact() {
        // C: eb32_node is 40 bytes and carries no payload; the payload lives in the
        // enclosing struct. Ours carries key AND payload in less space.
        let sz = core::mem::size_of::<super::Node>();
        println!("ebtree::Node = {sz} bytes");
        assert!(sz <= 28, "Node grew to {sz} bytes");
    }
}
