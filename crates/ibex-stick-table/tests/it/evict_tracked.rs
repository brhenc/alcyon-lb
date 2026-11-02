// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A full table never evicts an entry a session tracks (T611 / #7): HAProxy's
//! `stktable_trash_oldest` skips referenced entries, and a new key that finds no room is
//! simply not tracked. Evicting the tracked one would drop its `conn_cur` and rate counters.

use ibex_stick_table::{KeyType, StickKey, StickTable, StickTableConfig, StickTableError};

fn table(max: usize) -> StickTable {
    StickTable::new(StickTableConfig {
        key_type: KeyType::Integer,
        max_size: max,
        expire: std::time::Duration::from_secs(3600),
        ..StickTableConfig::default()
    })
}

fn k(n: u64) -> StickKey {
    StickKey::Integer(n)
}

#[test]
fn full_table_keeps_tracked_entries() {
    let t = table(2);
    t.update_entry(&k(1), |d| d.track(true)).unwrap(); // oldest, tracked
    t.update_entry(&k(2), |_| {}).unwrap();
    // k(1) is the LRU head. k(2) is the only evictable one.
    t.update_entry(&k(3), |_| {}).unwrap();
    let e1 = t.get_entry(&k(1)).unwrap().expect("tracked entry must survive");
    assert_eq!(e1.conn_cur, 1);
    assert!(t.get_entry(&k(2)).unwrap().is_none(), "the untracked one is evicted instead");
    assert!(t.get_entry(&k(3)).unwrap().is_some());
}

#[test]
fn full_table_of_tracked_entries_refuses_the_new_key() {
    let t = table(2);
    t.update_entry(&k(1), |d| d.track(true)).unwrap();
    t.update_entry(&k(2), |d| d.track(true)).unwrap();
    let r = t.update_entry(&k(3), |_| {});
    assert!(matches!(r, Err(StickTableError::CapacityExceeded(2))), "{r:?}");
    assert_eq!(t.get_entry(&k(1)).unwrap().unwrap().conn_cur, 1);
    assert_eq!(t.get_entry(&k(2)).unwrap().unwrap().conn_cur, 1);
    assert!(t.get_entry(&k(3)).unwrap().is_none());
    // Once one is released it can be evicted.
    t.update_entry(&k(1), |d| d.untrack()).unwrap();
    t.update_entry(&k(3), |_| {}).unwrap();
    assert!(t.get_entry(&k(1)).unwrap().is_none());
}

/// A binary key is its bytes padded with zeros, as in `HAProxy` (oracle 3.5-dev8, `type binary
/// len 4`, keys `a`, `a\0`, `a\0\0` sent through `b64dec`: one entry `61000000`, `http_req_cnt=3`).
/// The tree used to keep each as an entry of its own that a lookup could not find again, so a
/// repeated key added entries instead of counting (T611 / #9).
#[test]
fn binary_keys_differing_by_trailing_nuls_are_one_key() {
    let t = table(8);
    for k in [vec![1u8], vec![1, 0], vec![1, 0, 0], vec![1]] {
        t.update_entry(&StickKey::Binary(k), |d| d.conn_cnt += 1).unwrap();
    }
    assert_eq!(t.len(), 1);
    for k in [vec![1u8], vec![1, 0], vec![1, 0, 0]] {
        assert_eq!(t.get_entry(&StickKey::Binary(k)).unwrap().unwrap().conn_cnt, 4);
    }
    // A different key is still a different key, and so is an all-NUL one.
    t.update_entry(&StickKey::Binary(vec![1, 0, 2]), |_| {}).unwrap();
    t.update_entry(&StickKey::Binary(vec![0, 0]), |_| {}).unwrap();
    t.update_entry(&StickKey::Binary(vec![]), |_| {}).unwrap();
    assert_eq!(t.len(), 3);
    assert!(t.delete_entry(&StickKey::Binary(vec![1, 0])).unwrap());
    assert_eq!(t.len(), 2);
}
