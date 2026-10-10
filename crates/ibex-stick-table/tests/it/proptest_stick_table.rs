// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Property-based tests for `StickTable` storage engine and `StickKey` operations.

use ibex_stick_table::{KeyType, StickKey, StickTable, StickTableConfig};
use proptest::prelude::*;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn arb_stick_key() -> impl Strategy<Value = StickKey> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|b| StickKey::Ip(IpAddr::V4(Ipv4Addr::from(b)))),
        any::<[u8; 16]>().prop_map(|b| StickKey::Ip(IpAddr::V6(Ipv6Addr::from(b)))),
        any::<u64>().prop_map(StickKey::Integer),
        "[a-zA-Z0-9_-]{1,32}".prop_map(StickKey::String),
        prop::collection::vec(any::<u8>(), 0..32).prop_map(StickKey::Binary),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// StickKey From implementations produce expected variants.
    #[test]
    fn prop_stick_key_conversions(
        v4 in any::<[u8; 4]>(),
        v6 in any::<[u8; 16]>(),
        int_val in any::<u64>(),
        str_val in "[a-z]{1,16}"
    ) {
        let ip4 = Ipv4Addr::from(v4);
        let key_v4: StickKey = ip4.into();
        prop_assert_eq!(key_v4, StickKey::Ip(IpAddr::V4(ip4)));

        let ip6 = Ipv6Addr::from(v6);
        let key_v6: StickKey = ip6.into();
        prop_assert_eq!(key_v6, StickKey::Ip(IpAddr::V6(ip6)));

        let key_int: StickKey = int_val.into();
        prop_assert_eq!(key_int, StickKey::Integer(int_val));

        let key_str: StickKey = str_val.as_str().into();
        prop_assert_eq!(key_str, StickKey::String(str_val));
    }

    /// StickTable update and get round-trip preserves tracked counters.
    #[test]
    fn prop_stick_table_counter_accumulation(
        key in arb_stick_key(),
        increments in prop::collection::vec(1u64..100, 1..20)
    ) {
        let config = StickTableConfig {
            name: "prop_table".to_string(),
            key_type: KeyType::String,
            max_size: 10_000,
            ..Default::default()
        };
        let table = StickTable::new(config);

        let mut expected_total = 0u64;
        for inc in increments {
            expected_total = expected_total.saturating_add(inc);
            table.update_entry(&key, |e| {
                e.conn_cnt = e.conn_cnt.saturating_add(inc);
                e.gpc0 = e.gpc0.saturating_add(inc);
            }).unwrap();
        }

        let entry = table.get_entry(&key).unwrap().expect("entry exists");
        prop_assert_eq!(entry.conn_cnt, expected_total);
        prop_assert_eq!(entry.gpc0, expected_total);
    }

    /// StickTable capacity is strictly bounded by max_size.
    #[test]
    fn prop_stick_table_capacity_bound(
        keys in prop::collection::vec(arb_stick_key(), 10..50),
        max_size in 5usize..15
    ) {
        let config = StickTableConfig {
            name: "bounded_table".to_string(),
            key_type: KeyType::String,
            max_size,
            ..Default::default()
        };
        let table = StickTable::new(config);

        for key in &keys {
            let _ = table.update_entry(key, |e| {
                e.conn_cnt += 1;
            });
            prop_assert!(table.len() <= max_size, "Table len {} exceeded max_size {}", table.len(), max_size);
        }
    }

    /// Dump entries returns all currently stored keys.
    #[test]
    fn prop_stick_table_dump_consistency(
        keys in prop::collection::vec(0u64..1000, 1..30)
    ) {
        let config = StickTableConfig {
            name: "dump_table".to_string(),
            key_type: KeyType::Integer,
            max_size: 10_000,
            ..Default::default()
        };
        let table = StickTable::new(config);

        let mut inserted = HashMap::new();
        for &k in &keys {
            let stick_key = StickKey::Integer(k);
            let count = inserted.entry(k).or_insert(0u64);
            *count += 1;
            table.update_entry(&stick_key, |e| e.conn_cnt += 1).unwrap();
        }

        let dumped = table.dump_entries().unwrap();
        let dumped_set: HashSet<StickKey> = dumped.into_iter().map(|(k, _)| k).collect();

        for &k in inserted.keys() {
            prop_assert!(dumped_set.contains(&StickKey::Integer(k)));
        }
    }

    /// Clear operation empties the table.
    #[test]
    fn prop_stick_table_clear(
        keys in prop::collection::vec(arb_stick_key(), 1..20)
    ) {
        let config = StickTableConfig {
            name: "clear_table".to_string(),
            max_size: 1000,
            ..Default::default()
        };
        let table = StickTable::new(config);

        for k in &keys {
            let _ = table.update_entry(k, |e| e.conn_cnt += 1);
        }
        prop_assert!(!table.is_empty());

        table.clear().unwrap();
        prop_assert_eq!(table.len(), 0);
        prop_assert!(table.is_empty());
    }
}
