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
