//! Randomised differential testing against `BTreeMap`.
//!
//! Hand-written cases test what the author thought of. These test what they did not.

use ebtree::Eb32Tree;
use proptest::prelude::*;
use std::collections::BTreeMap;

fn model_order(keys: &[u32]) -> Vec<u32> {
    let mut m: BTreeMap<u32, usize> = BTreeMap::new();
    for &k in keys {
        *m.entry(k).or_insert(0) += 1;
    }
    m.into_iter()
        .flat_map(|(k, n)| std::iter::repeat(k).take(n))
        .collect()
}

fn build(keys: &[u32]) -> Eb32Tree {
    let mut t = Eb32Tree::new();
    for (i, &k) in keys.iter().enumerate() {
        t.insert(k, u32::try_from(i).unwrap_or(u32::MAX));
    }
    t
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Ascending traversal must match BTreeMap for any key sequence.
    #[test]
    fn traversal_matches_btreemap(keys in prop::collection::vec(any::<u32>(), 0..300)) {
        let t = build(&keys);
        prop_assert_eq!(t.len(), keys.len());
        let got: Vec<u32> = t.iter().map(|i| t.key_of(i)).collect();
        prop_assert_eq!(got, model_order(&keys));
    }

    /// Keys drawn from a small domain, so duplicates dominate. This is the timer-queue
    /// access pattern: many tasks sharing an expiry millisecond.
    #[test]
    fn duplicate_heavy_matches_btreemap(keys in prop::collection::vec(0u32..8, 0..300)) {
        let t = build(&keys);
        prop_assert_eq!(t.len(), keys.len());
        let got: Vec<u32> = t.iter().map(|i| t.key_of(i)).collect();
        prop_assert_eq!(got, model_order(&keys));
    }

    /// Keys sharing high bits, forcing deep descents.
    #[test]
    fn clustered_keys_match_btreemap(low in prop::collection::vec(0u32..64, 0..200)) {
        let keys: Vec<u32> = low.iter().map(|&l| 0xDEAD_BE00u32 | l).collect();
        let t = build(&keys);
        let got: Vec<u32> = t.iter().map(|i| t.key_of(i)).collect();
        prop_assert_eq!(got, model_order(&keys));
    }

    /// Every inserted key must be findable; no key outside the set may be found.
    #[test]
    fn lookup_agrees_with_set(
        keys in prop::collection::vec(0u32..1000, 0..200),
        probes in prop::collection::vec(0u32..1000, 1..100),
    ) {
        let t = build(&keys);
        let set: std::collections::BTreeSet<u32> = keys.iter().copied().collect();
        for p in probes {
            prop_assert_eq!(t.lookup(p).is_some(), set.contains(&p), "key {}", p);
        }
    }

    /// `prev` must be the exact inverse of `next` over the whole tree.
    #[test]
    fn prev_inverts_next(keys in prop::collection::vec(any::<u32>(), 1..200)) {
        let t = build(&keys);
        let forward: Vec<u32> = t.iter().collect();

        let mut backward = Vec::new();
        let mut cur = t.last();
        while let Some(i) = cur {
            backward.push(i);
            cur = t.prev(i);
        }
        backward.reverse();
        prop_assert_eq!(forward, backward);
    }

    /// Insertion order must not affect the resulting key order.
    #[test]
    fn insertion_order_is_irrelevant(
        mut keys in prop::collection::vec(any::<u32>(), 0..150),
        seed in any::<u64>(),
    ) {
        let a = build(&keys);
        let order_a: Vec<u32> = a.iter().map(|i| a.key_of(i)).collect();

        // Deterministic shuffle (xorshift) so failures reproduce from the seed.
        let mut s = seed | 1;
        for i in (1..keys.len()).rev() {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            keys.swap(i, (s as usize) % (i + 1));
        }

        let b = build(&keys);
        let order_b: Vec<u32> = b.iter().map(|i| b.key_of(i)).collect();
        prop_assert_eq!(order_a, order_b);
    }

    /// The payload of every inserted node must survive, once each.
    #[test]
    fn payloads_are_never_lost(keys in prop::collection::vec(0u32..32, 0..200)) {
        let t = build(&keys);
        let mut payloads: Vec<u32> = t.iter().map(|i| t.data_of(i)).collect();
        payloads.sort_unstable();
        let expected: Vec<u32> = (0..u32::try_from(keys.len()).unwrap_or(0)).collect();
        prop_assert_eq!(payloads, expected);
    }
}
