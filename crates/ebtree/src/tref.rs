// SPDX-License-Identifier: LGPL-2.1-only
// Derived from HAProxy include/import/ebtree-t.h (eb_troot_t tagging scheme).
// Copyright (C) 2002-2011 Willy Tarreau <w@1wt.eu>. See LICENSE.

//! Tagged references into the node arena.
//!
//! `HAProxy`'s ebtree stores a one-bit tag in the low bit of every pointer
//! (`eb_troot_t`), and that single tag namespace carries **two unrelated meanings**
//! depending on which field holds it:
//!
//! | Field | tag 0 | tag 1 |
//! |---|---|---|
//! | `branches[]` | `EB_LEAF` | `EB_NODE` |
//! | `node_p`, `leaf_p` | `EB_LEFT` | `EB_RGHT` |
//!
//! Mixing them up is a silent corruption in C and is prevented only by convention.
//! Here they are two distinct types that cannot be assigned to one another, which is
//! the cheapest correctness win available in the whole translation.
//!
//! Both pack an arena index into the upper 31 bits, so a reference is 4 bytes rather
//! than the 8 a pointer would cost. Since descending a tree is pointer-chasing bound,
//! that density is the point, not a micro-optimisation.

/// Arena index reserved to mean "the tree root's own branch slots".
pub(crate) const ROOT: u32 = 0x7FFF_FFFF;

/// Which half of a node a branch points at.
///
/// Every ebtree node is *simultaneously* a leaf and an internal link; this selects
/// which half is attached at a given branch.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Half {
    /// The node's leaf half — it carries a key and terminates a descent.
    Leaf,
    /// The node's link half — it discriminates on `bit` and has two branches.
    Link,
}

/// Which side of an `eb_root` a child is attached to.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Side {
    Left = 0,
    Right = 1,
}

impl Side {
    #[inline]
    pub(crate) const fn idx(self) -> usize {
        self as usize
    }

    #[inline]
    pub(crate) const fn from_bit(b: u32) -> Self {
        if b & 1 == 0 {
            Side::Left
        } else {
            Side::Right
        }
    }
}

/// A downward reference: "this branch holds *that* half of node N".
///
/// Corresponds to a tagged `eb_troot_t` stored in `eb_root::b[]`.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct Branch(u32);

impl Branch {
    pub(crate) const NONE: Branch = Branch(u32::MAX);

    #[inline]
    pub(crate) const fn new(idx: u32, half: Half) -> Self {
        Branch((idx << 1) | (matches!(half, Half::Link) as u32))
    }

    #[inline]
    pub(crate) const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }

    #[inline]
    pub(crate) const fn index(self) -> u32 {
        self.0 >> 1
    }

    #[inline]
    pub(crate) const fn half(self) -> Half {
        if self.0 & 1 == 0 {
            Half::Leaf
        } else {
            Half::Link
        }
    }
}

impl core::fmt::Debug for Branch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_none() {
            write!(f, "Branch(none)")
        } else {
            write!(f, "Branch({}:{:?})", self.index(), self.half())
        }
    }
}

/// An upward reference: "my parent is the branch array of node N (or the tree root),
/// and I hang off its left/right slot".
///
/// Corresponds to a tagged `eb_troot_t` stored in `eb_node::node_p` / `eb_node::leaf_p`.
/// Note that in C this points at an `eb_root`, which — because `branches` is the first
/// field of `eb_node` — is the same address as the node itself. Here the owner is named
/// explicitly instead of relying on that layout coincidence.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct Parent(u32);

impl Parent {
    pub(crate) const NONE: Parent = Parent(u32::MAX);

    #[inline]
    pub(crate) const fn new(owner: u32, side: Side) -> Self {
        Parent((owner << 1) | (side as u32))
    }

    #[inline]
    pub(crate) const fn root(side: Side) -> Self {
        Self::new(ROOT, side)
    }

    #[inline]
    pub(crate) const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }

    #[inline]
    pub(crate) const fn owner(self) -> u32 {
        self.0 >> 1
    }

    #[inline]
    pub(crate) const fn is_root(self) -> bool {
        self.owner() == ROOT
    }

    #[inline]
    pub(crate) const fn side(self) -> Side {
        if self.0 & 1 == 0 {
            Side::Left
        } else {
            Side::Right
        }
    }
}

impl core::fmt::Debug for Parent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_none() {
            write!(f, "Parent(none)")
        } else if self.is_root() {
            write!(f, "Parent(ROOT:{:?})", self.side())
        } else {
            write!(f, "Parent({}:{:?})", self.owner(), self.side())
        }
    }
}
