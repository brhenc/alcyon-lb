// SPDX-License-Identifier: LGPL-2.1-only
//
// Elastic binary trees, ported to Rust.
//
// Derived from HAProxy's ebtree (version 6.0.6):
//   include/import/ebtree.h, ebtree-t.h, eb32tree.h
//   src/ebtree.c, src/eb32tree.c
// Copyright (C) 2002-2011 Willy Tarreau <w@1wt.eu>
//
// The upstream headers grant the LGPL "version 2.1 exclusively" -- version 2.1
// only, with no "or later" option -- so this crate is LGPL-2.1-only and may not
// be relicensed to LGPL-3.0. See LICENSE in the repository root.
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, version 2.1 exclusively.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.

//! Elastic binary trees.
//!
//! A Rust implementation of Willy Tarreau's ebtree (as used throughout `HAProxy` for the
//! scheduler run queue, timer wait queue, stick tables and server queues), built on an
//! index arena with tagged `u32` references instead of tagged pointers.
//!
//! # What makes it elastic
//!
//! A classic critical-bit trie stores data only at leaves and needs separate internal
//! nodes for branch points: N items cost N leaves plus N−1 internal nodes. In an
//! ebtree every node is *simultaneously* a leaf and an internal link, so **N items
//! need exactly N nodes** and an insertion allocates nothing.
//!
//! # Why this shape
//!
//! | Property | Consequence |
//! |---|---|
//! | Depth bounded by key width, not element count | O(32) worst case on any input — no degenerate case an adversary can trigger |
//! | No rebalancing | insert/delete touch O(1) nodes plus the descent |
//! | Ordered traversal | `first`/`next`/`prev` — which a hash map cannot provide |
//! | Allocation-free insertion | usable on a data path that must not allocate |
//!
//! The depth bound is the interesting one for adversarial workloads. An unbalanced BST
//! degrades to O(n) on sorted input and a hash table degrades to O(n) under collision
//! flooding; an ebtree's structure is determined by bit positions rather than
//! comparisons, so no choice of keys degrades it.
//!
//! # Relationship to the C original
//!
//! The algorithms are ported directly; the representation is not. C uses the low bit of
//! each pointer as a tag, with two different tag meanings depending on the field. Here
//! those are two distinct types ([`tref::Branch`] and `Parent`) that cannot be
//! confused, and references are 4-byte arena indices rather than 8-byte pointers —
//! which roughly halves node size and fits more of the tree in cache.
//!
//! No `unsafe` is used, and none is needed.

#![forbid(unsafe_code)]

mod tref;

pub mod eb32;

pub use eb32::{Eb32Tree, MAX_NODES};
pub use tref::{Half, Side};
