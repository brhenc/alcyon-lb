// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.memory.hot-size <bytes>` (T444 row 2, S1): read as `HAProxy`'s `mem_parse_global_hot_size`
//! (src/pool.c) reads it, `atol` then "strictly positive". Measured on 3.5-dev8-885761-29
//! (`haproxy -c`): `65536`, `+5`, `12abc` (12), `64k` (64) and a number past `LONG_MAX`
//! (saturated) are accepted; `0`, `-1`, `abc`, `0x10` and a missing value give
//! "'tune.memory.hot-size' expects a strictly positive value."; a second argument gives
//! "'tune.memory.hot-size' cannot handle unexpected argument '2'.".

use ibex_config::parse_str;

fn hot(v: &str) -> Option<usize> {
    parse_str(&format!("global\n  tune.memory.hot-size {v}\n")).expect("accepted").global.expect("global").hot_size
}

#[test]
fn hot_size_reads_its_number_as_atol_does() {
    assert_eq!(hot("65536"), Some(65536));
    assert_eq!(hot("+5"), Some(5));
    assert_eq!(hot("12abc"), Some(12));
    assert_eq!(hot("64k"), Some(64));
    assert_eq!(hot("99999999999999999999"), Some(usize::try_from(i64::MAX).unwrap_or(usize::MAX)));
    assert_eq!(parse_str("global\n  maxconn 10\n").expect("accepted").global.expect("global").hot_size, None);
}

#[test]
fn hot_size_refuses_what_haproxy_refuses() {
    for v in ["0", "-1", "abc", "0x10", ""] {
        let e = parse_str(&format!("global\n  tune.memory.hot-size {v}\n")).expect_err(v);
        assert_eq!(e.message, "'tune.memory.hot-size' expects a strictly positive value.", "{v:?}");
    }
    let e = parse_str("global\n  tune.memory.hot-size 1 2\n").expect_err("two args");
    assert_eq!(e.message, "'tune.memory.hot-size' cannot handle unexpected argument '2'.");
}
