//! Stateful randomised testing: arbitrary interleavings of insert and delete, with
//! structural invariants verified after *every* operation.
//!
//! Delete's fix-up path (recycling the parent node to take over the deleted node's
//! link half) is the most intricate code in the crate, and its failure mode is a tree
//! that still traverses correctly but is internally malformed. Checking invariants
//! per-operation is what turns that into a caught failure rather than a latent one.

use ebtree::Eb32Tree;
use proptest::prelude::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
enum Op {
    Insert(u32),
    DeleteNth(usize),
    LookupGe(u32),
}

fn op_strategy(key_max: u32) -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..key_max).prop_map(Op::Insert),
        2 => (0usize..64).prop_map(Op::DeleteNth),
        1 => (0..key_max).prop_map(Op::LookupGe),
    ]
}

/// Runs an operation sequence against both the tree and a `BTreeMap` model.
fn run(ops: &[Op]) -> Result<(), TestCaseError> {
    let mut t = Eb32Tree::new();
    // model: key -> live payload ids, in insertion order
    let mut model: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    // live nodes, parallel to the model, so DeleteNth can pick one
    let mut live: Vec<(u32, u32)> = Vec::new(); // (arena idx, key)
    let mut next_payload = 0u32;

    for (step, op) in ops.iter().enumerate() {
        match *op {
            Op::Insert(k) => {
                let idx = t.insert(k, next_payload);
                model.entry(k).or_default().push(next_payload);
                live.push((idx, k));
                next_payload += 1;
            }
            Op::DeleteNth(n) => {
                if live.is_empty() {
                    continue;
                }
                let pos = n % live.len();
                let (idx, k) = live.swap_remove(pos);
                prop_assert!(t.delete(idx), "step {}: delete({}) returned false", step, idx);
                let v = model.get_mut(&k).expect("model must have the key");
                v.pop();
                if v.is_empty() {
                    model.remove(&k);
                }
            }
            Op::LookupGe(x) => {
                let got = t.lookup_ge(x).map(|i| t.key_of(i));
                let want = model.keys().copied().find(|&k| k >= x);
                prop_assert_eq!(got, want, "step {}: lookup_ge({})", step, x);
            }
        }

        // Structural health after every single operation.
        if let Err(e) = t.check_invariants() {
            return Err(TestCaseError::fail(format!(
                "step {step}: invariant violated after {op:?}: {e}"
            )));
        }

        let expected_len: usize = model.values().map(Vec::len).sum();
        prop_assert_eq!(t.len(), expected_len, "step {}: len mismatch", step);
    }

    // Final agreement on full ordering.
    let got: Vec<u32> = t.iter().map(|i| t.key_of(i)).collect();
    let want: Vec<u32> = model
        .iter()
        .flat_map(|(&k, v)| std::iter::repeat_n(k, v.len()))
        .collect();
    prop_assert_eq!(got, want, "final traversal");
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    /// Wide key space: mostly distinct keys, exercising the main tree.
    #[test]
    fn mixed_ops_wide_keys(ops in prop::collection::vec(op_strategy(u32::MAX), 0..200)) {
        run(&ops)?;
    }

    /// Narrow key space: duplicates dominate, exercising duplicate subtrees and the
    /// hole-reuse path in `insert_dup`.
    #[test]
    fn mixed_ops_duplicate_heavy(ops in prop::collection::vec(op_strategy(6), 0..200)) {
        run(&ops)?;
    }

    /// Medium key space: both paths, plus frequent transitions between them.
    #[test]
    fn mixed_ops_medium_keys(ops in prop::collection::vec(op_strategy(64), 0..250)) {
        run(&ops)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Depth must stay bounded by key width no matter what an adversary inserts.
    /// Duplicates form a chain below the link levels, so this uses distinct keys.
    #[test]
    fn depth_bounded_for_distinct_keys(keys in prop::collection::hash_set(any::<u32>(), 0..2000)) {
        let mut t = Eb32Tree::new();
        for (i, &k) in keys.iter().enumerate() {
            t.insert(k, u32::try_from(i).unwrap_or(0));
        }
        prop_assert!(
            t.max_depth() <= 33,
            "depth {} exceeded key-width bound for {} distinct keys",
            t.max_depth(), keys.len()
        );
        prop_assert!(t.check_invariants().is_ok());
    }
}
