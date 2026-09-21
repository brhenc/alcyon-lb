//! Tests for `delete` and `lookup_ge`.
//!
//! Delete is the subtle operation: removing a node's leaf half may leave its link half
//! structurally in use, and the fix-up recycles the parent in place. A tree can survive
//! many deletions looking correct from the outside while being internally malformed, so
//! every test here checks structural invariants, not just observable behaviour.

use ebtree::Eb32Tree;
use std::collections::BTreeMap;

fn build(keys: &[u32]) -> (Eb32Tree, Vec<u32>) {
    let mut t = Eb32Tree::new();
    let idx: Vec<u32> = keys
        .iter()
        .enumerate()
        .map(|(i, &k)| t.insert(k, u32::try_from(i).unwrap_or(0)))
        .collect();
    (t, idx)
}

fn keys_in_order(t: &Eb32Tree) -> Vec<u32> {
    t.iter().map(|i| t.key_of(i)).collect()
}

fn model_order(keys: &[u32]) -> Vec<u32> {
    let mut m: BTreeMap<u32, usize> = BTreeMap::new();
    for &k in keys {
        *m.entry(k).or_insert(0) += 1;
    }
    m.into_iter()
        .flat_map(|(k, n)| std::iter::repeat_n(k, n))
        .collect()
}

fn ok(t: &Eb32Tree, ctx: &str) {
    if let Err(e) = t.check_invariants() {
        panic!("invariant violated {ctx}: {e}");
    }
}

// ---- delete ----------------------------------------------------------------------

#[test]
fn delete_only_element() {
    let (mut t, idx) = build(&[42]);
    assert!(t.delete(idx[0]));
    ok(&t, "after deleting sole element");
    assert!(t.is_empty());
    assert_eq!(t.first(), None);
    assert_eq!(t.lookup(42), None);
}

#[test]
fn delete_unlinked_node_returns_false() {
    let (mut t, idx) = build(&[1, 2]);
    assert!(t.delete(idx[0]));
    assert!(!t.delete(idx[0]), "double delete must be rejected");
}

#[test]
fn delete_every_element_in_insertion_order() {
    let keys: Vec<u32> = (0..200).collect();
    let (mut t, idx) = build(&keys);
    for (n, &i) in idx.iter().enumerate() {
        assert!(t.delete(i));
        ok(&t, &format!("after deleting #{n}"));
        assert_eq!(t.len(), keys.len() - n - 1);
    }
    assert!(t.is_empty());
}

#[test]
fn delete_every_element_in_reverse_order() {
    let keys: Vec<u32> = (0..200).collect();
    let (mut t, idx) = build(&keys);
    for (n, &i) in idx.iter().enumerate().rev() {
        assert!(t.delete(i));
        ok(&t, &format!("after deleting #{n}"));
    }
    assert!(t.is_empty());
}

#[test]
fn delete_leaves_correct_remainder() {
    let keys: Vec<u32> = (0..100).map(|i| i * 5).collect();
    let (mut t, idx) = build(&keys);

    // Delete every third element.
    let mut remaining: Vec<u32> = Vec::new();
    for (n, (&k, &i)) in keys.iter().zip(idx.iter()).enumerate() {
        if n % 3 == 0 {
            assert!(t.delete(i));
            ok(&t, &format!("after deleting key {k}"));
        } else {
            remaining.push(k);
        }
    }
    assert_eq!(keys_in_order(&t), model_order(&remaining));
    for &k in &remaining {
        assert!(t.lookup(k).is_some(), "lost key {k}");
    }
}

#[test]
fn delete_from_duplicate_subtree() {
    // The timer queue's access pattern: many entries share a key, removed one by one.
    let keys = vec![77u32; 40];
    let (mut t, idx) = build(&keys);
    for (n, &i) in idx.iter().enumerate() {
        assert!(t.delete(i));
        ok(&t, &format!("after removing dup #{n}"));
        assert_eq!(t.len(), 40 - n - 1);
    }
    assert!(t.is_empty());
}

#[test]
fn delete_interleaved_duplicates() {
    let mut keys = Vec::new();
    for i in 0..60u32 {
        keys.push(i % 4);
    }
    let (mut t, idx) = build(&keys);
    for (n, &i) in idx.iter().enumerate().filter(|(n, _)| n % 2 == 0) {
        assert!(t.delete(i));
        ok(&t, &format!("after removing #{n}"));
    }
    let remaining: Vec<u32> = keys
        .iter()
        .enumerate()
        .filter(|(n, _)| n % 2 == 1)
        .map(|(_, &k)| k)
        .collect();
    assert_eq!(keys_in_order(&t), model_order(&remaining));
}

#[test]
fn delete_then_reinsert_reuses_arena() {
    let (mut t, idx) = build(&[1, 2, 3, 4]);
    for &i in &idx {
        assert!(t.delete(i));
    }
    assert!(t.is_empty());
    for k in 10..20u32 {
        t.insert(k, k);
        ok(&t, &format!("after reinserting {k}"));
    }
    assert_eq!(keys_in_order(&t), (10..20).collect::<Vec<u32>>());
}

#[test]
fn delete_boundary_keys() {
    let keys = vec![0, u32::MAX, 1 << 31, (1 << 31) - 1, 1, u32::MAX - 1];
    let (mut t, idx) = build(&keys);
    for (n, &i) in idx.iter().enumerate() {
        assert!(t.delete(i));
        ok(&t, &format!("after deleting boundary #{n}"));
    }
}

// ---- lookup_ge -------------------------------------------------------------------

/// The oracle: `BTreeMap`'s own range query.
fn model_ge(keys: &[u32], x: u32) -> Option<u32> {
    keys.iter().copied().filter(|&k| k >= x).min()
}

#[test]
fn lookup_ge_empty() {
    let t = Eb32Tree::new();
    assert_eq!(t.lookup_ge(0), None);
    assert_eq!(t.lookup_ge(u32::MAX), None);
}

#[test]
fn lookup_ge_exhaustive_small() {
    let keys: Vec<u32> = vec![10, 20, 30, 40, 50];
    let (t, _) = build(&keys);
    for x in 0..60u32 {
        let got = t.lookup_ge(x).map(|i| t.key_of(i));
        assert_eq!(got, model_ge(&keys, x), "lookup_ge({x})");
    }
}

#[test]
fn lookup_ge_past_the_end() {
    let keys = vec![1, 2, 3];
    let (t, _) = build(&keys);
    assert_eq!(t.lookup_ge(4), None);
    assert_eq!(t.lookup_ge(u32::MAX), None);
}

#[test]
fn lookup_ge_exact_match_returns_that_key() {
    let keys: Vec<u32> = (0..100).map(|i| i * 7).collect();
    let (t, _) = build(&keys);
    for &k in &keys {
        let got = t.lookup_ge(k).map(|i| t.key_of(i));
        assert_eq!(got, Some(k), "exact lookup_ge({k})");
    }
}

#[test]
fn lookup_ge_on_duplicates_returns_first() {
    let keys = vec![5u32, 5, 5, 9, 9, 12];
    let (t, _) = build(&keys);
    assert_eq!(t.lookup_ge(5).map(|i| t.key_of(i)), Some(5));
    assert_eq!(t.lookup_ge(6).map(|i| t.key_of(i)), Some(9));
    assert_eq!(t.lookup_ge(9).map(|i| t.key_of(i)), Some(9));
    assert_eq!(t.lookup_ge(10).map(|i| t.key_of(i)), Some(12));
    assert_eq!(t.lookup_ge(13), None);
}

#[test]
fn lookup_ge_boundary_keys() {
    let keys = vec![0u32, 1, 1 << 31, u32::MAX];
    let (t, _) = build(&keys);
    for &x in &[0u32, 1, 2, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, u32::MAX] {
        let got = t.lookup_ge(x).map(|i| t.key_of(i));
        assert_eq!(got, model_ge(&keys, x), "lookup_ge({x})");
    }
}

#[test]
fn lookup_ge_clustered_keys() {
    // Shared high bits: exercises the "no common bits above this one" test.
    let keys: Vec<u32> = (0..64).map(|i| 0xABCD_0000u32 | (i * 3)).collect();
    let (t, _) = build(&keys);
    for x in (0xABCD_0000u32..0xABCD_0100).step_by(1) {
        let got = t.lookup_ge(x).map(|i| t.key_of(i));
        assert_eq!(got, model_ge(&keys, x), "lookup_ge({x:#x})");
    }
    assert_eq!(t.lookup_ge(0).map(|i| t.key_of(i)), Some(0xABCD_0000));
}

#[test]
fn lookup_ge_after_deletions() {
    let keys: Vec<u32> = (0..100).map(|i| i * 4).collect();
    let (mut t, idx) = build(&keys);
    let mut live: Vec<u32> = keys.clone();

    for n in (0..100).step_by(3) {
        assert!(t.delete(idx[n]));
        live.retain(|&k| k != keys[n]);
        ok(&t, &format!("after delete #{n}"));
        for x in [0u32, 7, 100, 200, 399, 400] {
            let got = t.lookup_ge(x).map(|i| t.key_of(i));
            assert_eq!(got, model_ge(&live, x), "lookup_ge({x}) after delete #{n}");
        }
    }
}

// ---- depth -----------------------------------------------------------------------

#[test]
fn depth_stays_bounded_on_adversarial_input() {
    // Sorted keys degrade an unbalanced BST to O(n). An ebtree's depth is a function
    // of key width alone. Duplicates extend the chain below the 32 link levels, so
    // this uses distinct keys to bound the structural depth.
    let keys: Vec<u32> = (0..10_000).collect();
    let (t, _) = build(&keys);
    ok(&t, "adversarial sorted insert");
    assert!(
        t.max_depth() <= 33,
        "depth {} exceeded key-width bound",
        t.max_depth()
    );
}
