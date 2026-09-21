//! # `ibex-ebtree`
//!
//! High-performance, memory-safe Elastic Binary Tree (`ebtree`) engine.
//! Provides deterministic $O(k)$ lookup time, cache-locality, and bit-indexed prefix search.
//!
//! Sub-trees:
//! - `eb32`: 32-bit integer and IPv4 indexing.
//! - `eb64`: 64-bit integer, timestamp, and counter indexing.
//! - `ebst`: Zero-copy string indexing with longest prefix match.
//! - `ebmb`: Multi-byte binary blob and IPv6 indexing.

pub mod eb32;
pub mod eb64;
pub mod ebmb;
pub mod ebst;

pub use eb32::Eb32Tree;
pub use eb64::Eb64Tree;
pub use ebmb::EbMbTree;
pub use ebst::EbStTree;
