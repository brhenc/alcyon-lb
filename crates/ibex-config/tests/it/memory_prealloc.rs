// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.memory.prealloc on|off` (T468, Ibex extension): `HAProxy` 3.5-dev8-885761-29 has no such
//! keyword (`haproxy -c`: "unknown keyword 'tune.memory.prealloc' in 'global' section; did you
//! mean 'prealloc-fd' maybe ?"). Read as `tune.ibex.zero-buffers` reads `on|off`. That it needs
//! `maxconn` or `-m` is checked at load (`-m` is on the command line), in ibex-rt's
//! `memory_prealloc` test.

use ibex_config::parse_str;

fn prealloc(v: &str) -> Option<bool> {
    parse_str(&format!("global\n  maxconn 10\n  tune.memory.prealloc {v}\n")).expect("accepted").global.expect("global").memory_prealloc
}

#[test]
fn prealloc_reads_on_and_off() {
    assert_eq!(prealloc("on"), Some(true));
    assert_eq!(prealloc("off"), Some(false));
    assert_eq!(parse_str("global\n  maxconn 10\n").expect("accepted").global.expect("global").memory_prealloc, None);
}

#[test]
fn prealloc_refuses_other_arguments() {
    let e = parse_str("global\n  tune.memory.prealloc\n").expect_err("no arg");
    assert_eq!(e.message, "'tune.memory.prealloc' expects 'on' or 'off'.");
    for v in ["yes", "1"] {
        let e = parse_str(&format!("global\n  tune.memory.prealloc {v}\n")).expect_err(v);
        assert_eq!(e.message, format!("'tune.memory.prealloc' expects 'on' or 'off', got '{v}'."), "{v:?}");
    }
    let e = parse_str("global\n  tune.memory.prealloc on 2\n").expect_err("two args");
    assert_eq!(e.message, "'tune.memory.prealloc' cannot handle unexpected argument '2'.");
}
