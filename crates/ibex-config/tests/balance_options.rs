// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Project Ibex Contributors. See LICENSE.

//! `hash-type`, `hash-preserve-affinity` and `balance random(N)`: where they are read and
//! what is refused (`cfgparse-listen.c`, `backend_parse_balance`).

use ibex_config::{parse_str, BalanceAlgorithm, HashPreserveAffinity, HashType};

#[test]
fn hash_options_are_read_in_listen_and_inherited_from_defaults() {
    let cfg = parse_str(
        "defaults\n  hash-type consistent\n  hash-preserve-affinity maxconn\n\
         backend b\n  server s 127.0.0.1:8001\n\
         listen l\n  bind 127.0.0.1:8080\n  hash-type map-based\n  hash-preserve-affinity always\n",
    )
    .expect("parse");
    assert_eq!(cfg.backends[0].hash_type, Some(HashType::Consistent));
    assert_eq!(cfg.backends[0].hash_preserve_affinity, Some(HashPreserveAffinity::MaxConn));
    assert_eq!(cfg.listens[0].hash_type, Some(HashType::MapBased));
    assert_eq!(cfg.listens[0].hash_preserve_affinity, Some(HashPreserveAffinity::Always));
}

#[test]
fn malformed_or_unimplemented_forms_are_refused() {
    for (line, why) in [
        ("balance random(x)", "a non-numeric draw count"),
        ("hash-type", "no hashing method"),
        // A hash function or `avalanche` modifier: HAProxy takes them, Ibex does not hash
        // with anything but sdbm-avalanche yet, so it must not accept and ignore them.
        ("hash-type consistent djb2", "a hash function Ibex does not implement"),
        ("hash-preserve-affinity", "no mode"),
        ("hash-preserve-affinity sometimes", "an unknown mode"),
    ] {
        let cfg = format!("backend b\n  {line}\n  server s 127.0.0.1:8001\n");
        assert!(parse_str(&cfg).is_err(), "{line}: {why}");
    }
    assert!(matches!(
        parse_str("backend b\n  balance random(3)\n").expect("parse").backends[0].balance,
        BalanceAlgorithm::Random(3)
    ));
}
