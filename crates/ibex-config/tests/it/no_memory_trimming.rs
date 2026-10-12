// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `global no-memory-trimming` (T319). Results of `haproxy -c` (3.5-dev8-885761-29): the
//! keyword alone is accepted; with an argument it fails with "'no-memory-trimming' cannot
//! handle unexpected argument 'foo'."; in `defaults` it is "unknown keyword
//! 'no-memory-trimming' in 'defaults' section".

use ibex_config::parse_str;

#[test]
fn no_memory_trimming_is_kept() {
    let c = parse_str("global\n  no-memory-trimming\n").expect("accepted");
    assert!(c.global.expect("global").no_memory_trimming);
    let c = parse_str("global\n  maxconn 10\n").expect("accepted");
    assert!(!c.global.expect("global").no_memory_trimming);
}

#[test]
fn no_memory_trimming_takes_no_argument() {
    let e = parse_str("global\n  no-memory-trimming foo\n").expect_err("refused");
    assert_eq!(e.message, "'no-memory-trimming' cannot handle unexpected argument 'foo'.");
}

#[test]
fn no_memory_trimming_is_global_only() {
    let e = parse_str("defaults\n  no-memory-trimming\n").expect_err("refused");
    assert!(e.message.contains("unknown keyword 'no-memory-trimming'"), "{}", e.message);
}
