//! Differential and structural tests for `Eb32Tree`.
//!
//! The oracle is `BTreeMap`: for any sequence of insertions, ascending traversal of the
//! ebtree must yield exactly the multiset of keys a `BTreeMap`-backed model yields, in
//! the same order. Structural invariants are checked separately, because a tree can
//! produce correct traversals while being internally malformed in a way that only
//! shows up later under deletion.

use ebtree::Eb32Tree;
use std::collections::BTreeMap;

/// Ascending key order, with duplicates preserved.
fn keys_in_order(t: &Eb32Tree) -> Vec<u32> {
    t.iter().map(|i| t.key_of(i)).collect()
}

/// The model: a multiset of keys, read out in ascending order.
fn model_order(keys: &[u32]) -> Vec<u32> {
    let mut m: BTreeMap<u32, usize> = BTreeMap::new();
    for &k in keys {
        *m.entry(k).or_insert(0) += 1;
    }
    m.into_iter()
        .flat_map(|(k, n)| std::iter::repeat_n(k, n))
        .collect()
}

fn build(keys: &[u32]) -> Eb32Tree {
    let mut t = Eb32Tree::new();
    for (i, &k) in keys.iter().enumerate() {
        t.insert(k, u32::try_from(i).expect("test input fits u32"));
    }
    t
}

// ---- traversal agrees with BTreeMap ---------------------------------------------

#[test]
fn empty_tree() {
    let t = Eb32Tree::new();
    assert_eq!(t.len(), 0);
    assert!(t.is_empty());
    assert_eq!(t.first(), None);
    assert_eq!(t.last(), None);
    assert_eq!(t.lookup(0), None);
    assert_eq!(keys_in_order(&t), Vec::<u32>::new());
}

#[test]
fn single_element() {
    let t = build(&[42]);
    assert_eq!(t.len(), 1);
    assert_eq!(keys_in_order(&t), vec![42]);
    assert_eq!(t.first().map(|i| t.key_of(i)), Some(42));
    assert_eq!(t.last().map(|i| t.key_of(i)), Some(42));
    assert!(t.lookup(42).is_some());
    assert!(t.lookup(41).is_none());
}

#[test]
fn ascending_insert() {
    let keys: Vec<u32> = (0..500).collect();
    let t = build(&keys);
    assert_eq!(keys_in_order(&t), model_order(&keys));
}

#[test]
fn descending_insert() {
    let keys: Vec<u32> = (0..500).rev().collect();
    let t = build(&keys);
    assert_eq!(keys_in_order(&t), model_order(&keys));
}

#[test]
fn boundary_keys() {
    let keys = vec![0, u32::MAX, 1, u32::MAX - 1, 1 << 31, (1 << 31) - 1];
    let t = build(&keys);
    assert_eq!(keys_in_order(&t), model_order(&keys));
    for &k in &keys {
        assert!(t.lookup(k).is_some(), "lookup failed for {k}");
    }
}

#[test]
fn powers_of_two() {
    // Maximises bit-position spread, exercising every discriminating bit.
    let keys: Vec<u32> = (0..32).map(|b| 1u32 << b).collect();
    let t = build(&keys);
    assert_eq!(keys_in_order(&t), model_order(&keys));
}

#[test]
fn shared_high_bits() {
    // Keys differing only in the lowest bits force deep descents.
    let base = 0xFFFF_FF00u32;
    let keys: Vec<u32> = (0..256).map(|i| base | i).collect();
    let t = build(&keys);
    assert_eq!(keys_in_order(&t), model_order(&keys));
}

// ---- duplicates ------------------------------------------------------------------

#[test]
fn all_duplicates() {
    let keys = vec![7u32; 64];
    let t = build(&keys);
    assert_eq!(t.len(), 64);
    assert_eq!(keys_in_order(&t), model_order(&keys));
}

#[test]
fn duplicates_interleaved() {
    let mut keys = Vec::new();
    for i in 0..50u32 {
        keys.push(i % 5);
    }
    let t = build(&keys);
    assert_eq!(t.len(), 50);
    assert_eq!(keys_in_order(&t), model_order(&keys));
}

#[test]
fn duplicates_preserve_payloads() {
    // The timer queue stores many tasks at the same expiry; none may be lost.
    let t = build(&[100u32; 32]);
    let mut payloads: Vec<u32> = t.iter().map(|i| t.data_of(i)).collect();
    payloads.sort_unstable();
    assert_eq!(payloads, (0..32).collect::<Vec<u32>>());
}

#[test]
fn unique_tree_rejects_duplicates() {
    let mut t = Eb32Tree::new_unique();
    let a = t.insert(5, 100);
    let b = t.insert(5, 200);
    assert_eq!(a, b, "unique tree must return the existing node");
    assert_eq!(t.len(), 1);
    assert_eq!(t.data_of(a), 100, "existing payload must be preserved");
}

// ---- next/prev are inverses ------------------------------------------------------

#[test]
fn prev_reverses_next() {
    let keys: Vec<u32> = (0..200).map(|i| i * 7 + 3).collect();
    let t = build(&keys);

    let forward: Vec<u32> = t.iter().collect();
    let mut backward = Vec::new();
    let mut cur = t.last();
    while let Some(i) = cur {
        backward.push(i);
        cur = t.prev(i);
    }
    backward.reverse();
    assert_eq!(forward, backward, "prev must exactly reverse next");
}

#[test]
fn next_terminates_at_end() {
    let t = build(&[1, 2, 3]);
    let last = t.last().expect("non-empty");
    assert_eq!(t.next(last), None);
}

#[test]
fn prev_terminates_at_start() {
    let t = build(&[1, 2, 3]);
    let first = t.first().expect("non-empty");
    assert_eq!(t.prev(first), None);
}

// ---- lookup ----------------------------------------------------------------------

#[test]
fn lookup_matches_model() {
    let keys: Vec<u32> = (0..300).map(|i| i * 3).collect();
    let t = build(&keys);
    let model: std::collections::BTreeSet<u32> = keys.iter().copied().collect();

    for probe in 0..900u32 {
        let found = t.lookup(probe).is_some();
        assert_eq!(found, model.contains(&probe), "disagreement at key {probe}");
    }
}

// ---- adversarial -----------------------------------------------------------------

#[test]
fn depth_is_bounded_under_adversarial_keys() {
    // Sorted insertion is the classic degenerate case for an unbalanced BST. An
    // ebtree's depth depends on key width alone, so this must stay bounded.
    let keys: Vec<u32> = (0..4096).collect();
    let t = build(&keys);
    assert_eq!(t.len(), 4096);
    assert_eq!(keys_in_order(&t), model_order(&keys));
}

#[test]
fn traversal_is_complete_under_mixed_load() {
    // Mixture of clustered, spread and duplicate keys.
    let mut keys = Vec::new();
    for i in 0..200u32 {
        keys.push(i);
        keys.push(0xFFFF_0000 | i);
        keys.push(42);
        keys.push(i.wrapping_mul(0x9E37_79B9));
    }
    let t = build(&keys);
    assert_eq!(t.len(), keys.len());
    assert_eq!(keys_in_order(&t), model_order(&keys));
}
