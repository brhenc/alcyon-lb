// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `hash-type`, `hash-preserve-affinity` and `balance random(N)`: where they are read and
//! what is refused (`cfgparse-listen.c`, `backend_parse_balance`).

use alcyon_config::{parse_str, BalanceAlgorithm, HashPreserveAffinity, HashType, UriHash};

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
        ("balance unknown", "an unknown balance algorithm"),
        ("balance random(x)", "a non-numeric draw count"),
        ("hash-type", "no hashing method"),
        // A hash function or `avalanche` modifier: HAProxy takes them, Alcyon does not hash
        // with anything but sdbm-avalanche yet, so it must not accept and ignore them.
        ("hash-type consistent djb2", "a hash function Alcyon does not implement"),
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

/// `balance uri` options, as `backend_parse_balance` (`src/backend.c`) refuses them; the
/// messages are `haproxy -c`'s (3.5-dev8, 2026-11-15), after its `parsing [file:line] : `.
#[test]
fn balance_uri_refuses_what_haproxy_refuses_in_its_words() {
    for (line, message) in [
        ("balance uri junk", "balance uri only accepts parameters 'len', 'depth', 'path-only', and 'whole' (got 'junk')."),
        ("balance uri whole junk", "balance uri only accepts parameters 'len', 'depth', 'path-only', and 'whole' (got 'junk')."),
        ("balance uri len", "balance uri : 'len' expects a positive integer (got '')."),
        ("balance uri len 0", "balance uri : 'len' expects a positive integer (got '0')."),
        ("balance uri len x", "balance uri : 'len' expects a positive integer (got 'x')."),
        ("balance uri depth", "balance uri : 'depth' expects a positive integer (got '')."),
        ("balance uri depth -1", "balance uri : 'depth' expects a positive integer (got '-1')."),
        ("balance uri len 4 depth", "balance uri : 'depth' expects a positive integer (got '')."),
        // `atoi` wraps 2^31 to a negative int.
        ("balance uri len 2147483648", "balance uri : 'len' expects a positive integer (got '2147483648')."),
    ] {
        let cfg = format!("backend b\n  {line}\n  server s 127.0.0.1:8001\n");
        match parse_str(&cfg) {
            Ok(_) => panic!("{line}: accepted"),
            Err(e) => assert!(e.to_string().ends_with(message), "{line}: {e}"),
        }
    }
}

/// `balance random(...)` errors, as `backend_parse_balance` (`src/backend.c`) refuses them; the
/// messages are `haproxy -c`'s (3.5-dev8, 2026-11-15), after its `parsing [file:line] : `.
#[test]
fn balance_random_refuses_what_haproxy_refuses_in_its_words() {
    for (line, message) in [
        ("balance random(x)", "balance random : unexpected character 'x' after argument."),
        ("balance random(5x)", "balance random : unexpected character 'x' after argument."),
        ("balance random(x", "balance random : unexpected character 'x' after argument."),
        ("balance random(-x)", "balance random : unexpected character '-' after argument."),
        ("balance random(08)", "balance random : unexpected character '8' after argument."),
        ("balance random(5", "balance random : missing closing parenthesis."),
        ("balance random(", "balance random : missing closing parenthesis."),
        ("balance random(0)", "balance random : number of draws must be at least 1."),
        ("balance random(-1)", "balance random : number of draws must be at least 1."),
        ("balance random(2147483648)", "balance random : number of draws must be at least 1."),
    ] {
        let cfg = format!("backend b\n  {line}\n  server s 127.0.0.1:8001\n");
        match parse_str(&cfg) {
            Ok(_) => panic!("{line}: accepted"),
            Err(e) => assert!(e.to_string().ends_with(message), "{line}: {e}"),
        }
    }
}

/// What `haproxy -c` accepts stays accepted: bare `balance`, `random()`, every `balance uri`
/// option, and words after an algorithm that takes none (`backend_parse_balance` does not look
/// at them; measured `rc=0` for each line on 3.5-dev8).
#[test]
fn balance_lines_haproxy_accepts() {
    for line in [
        "balance",
        "balance random()",
        "balance random() junk",
        "balance random(3)junk",
        "balance random(0x3)",
        "balance random(+3)",
        "balance random(010)",
        "balance random(4294967297)",
        "balance uri whole",
        "balance uri len 4",
        "balance uri depth 2",
        "balance uri path-only",
        "balance uri path-only whole len 9 depth 2",
        "balance uri len 3x",
        "balance uri len 4294967297",
        "balance uri depth 2147483647",
        "balance roundrobin junk",
        "balance leastconn junk",
        "balance static-rr junk",
        "balance first junk",
        "balance source junk",
        "balance random junk",
        "balance random(2) junk",
    ] {
        let cfg = format!("backend b\n  {line}\n  server s 127.0.0.1:8001\n");
        assert!(parse_str(&cfg).is_ok(), "{line}: {:?}", parse_str(&cfg).err());
    }
}

/// Bare `balance`, `balance random()`, and `strtol(..., 0)` draw counts match `HAProxy`'s
/// `backend_parse_balance`.
#[test]
fn bare_balance_and_random_draws_match_haproxy() {
    let algo = |line: &str| {
        let cfg = parse_str(&format!("backend b\n  {line}\n  server s 127.0.0.1:8001\n")).expect(line);
        cfg.backends[0].balance
    };
    assert_eq!(algo("balance"), BalanceAlgorithm::Random(1));
    assert_eq!(algo("balance random"), BalanceAlgorithm::Random(2));
    assert_eq!(algo("balance random()"), BalanceAlgorithm::Random(2));
    assert_eq!(algo("balance random(0x3)"), BalanceAlgorithm::Random(3));
    assert_eq!(algo("balance random(010)"), BalanceAlgorithm::Random(8));
    assert_eq!(algo("balance random(4294967297)"), BalanceAlgorithm::Random(1));

    let cfg = parse_str(
        "defaults\n  balance uri len 5\n\
         backend b\n  balance\n  server s 127.0.0.1:8001\n",
    )
    .expect("bare balance after defaults uri");
    assert_eq!(cfg.backends[0].balance, BalanceAlgorithm::Random(1));
    assert_eq!(cfg.backends[0].balance_uri, UriHash::default());
}

/// What the parser keeps of the `balance uri` options (read by `lb::uri_hash_key`).
#[test]
fn balance_uri_options_are_stored() {
    let uri = |line: &str| {
        let cfg = parse_str(&format!("backend b\n  {line}\n")).expect(line);
        assert_eq!(cfg.backends[0].balance, BalanceAlgorithm::Uri, "{line}");
        cfg.backends[0].balance_uri
    };
    assert_eq!(uri("balance uri"), UriHash::default());
    assert_eq!(
        uri("balance uri path-only whole len 9 depth 2"),
        UriHash { len: 9, depth_end: 3, whole: true, path_only: true }
    );
    // A repeated option keeps its last value.
    assert_eq!(uri("balance uri len 4 len 6").len, 6);
    assert_eq!(uri("balance uri depth 1 depth 3").depth_end, 4);
    // `atoi`: a sign, digits up to the first other byte, the result cut to an `int`.
    assert_eq!(uri("balance uri len +5").len, 5);
    assert_eq!(uri("balance uri len 3x").len, 3);
    assert_eq!(uri("balance uri len 4294967297").len, 1);
    assert_eq!(uri("balance uri depth 2147483647").depth_end, i32::MIN);
}

/// The options follow the `balance uri` line they came with: inherited from `defaults`
/// with it, replaced by a section's own `balance`, and gone after another algorithm.
#[test]
fn balance_uri_options_follow_the_balance_line() {
    let cfg = parse_str(
        "defaults\n  balance uri len 5\n\
         backend inherits\n  server s 127.0.0.1:8001\n\
         backend own\n  balance uri whole\n\
         backend other\n  balance uri depth 2\n  balance roundrobin\n\
         listen l\n  bind 127.0.0.1:8080\n  balance uri path-only\n\
         listen m\n  bind 127.0.0.1:8081\n",
    )
    .expect("parse");
    assert_eq!(cfg.backends[0].balance, BalanceAlgorithm::Uri);
    assert_eq!(cfg.backends[0].balance_uri, UriHash { len: 5, ..UriHash::default() });
    assert_eq!(cfg.backends[1].balance_uri, UriHash { whole: true, ..UriHash::default() });
    assert_eq!(cfg.backends[2].balance, BalanceAlgorithm::RoundRobin);
    assert_eq!(cfg.backends[2].balance_uri, UriHash::default());
    assert_eq!(cfg.listens[0].balance_uri, UriHash { path_only: true, ..UriHash::default() });
    assert_eq!(cfg.listens[1].balance_uri, UriHash { len: 5, ..UriHash::default() });
}
