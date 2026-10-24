// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ibex.zero-spares on|off` (S1), an Ibex-only keyword: wipe the spare strings and
//! lists the pools keep for the rules when they are given back. HAProxy refuses it as unknown.

use ibex_config::parse_str;

#[test]
fn zero_spares_is_kept_and_unset_is_none() {
    let g = |text: &str| parse_str(text).expect("accepted").global.expect("global").zero_spares;
    assert_eq!(g("global\n  tune.ibex.zero-spares off\n"), Some(false));
    assert_eq!(g("global\n  tune.ibex.zero-spares on\n"), Some(true));
    assert_eq!(g("global\n  maxconn 10\n"), None);
}

#[test]
fn zero_spares_wants_exactly_on_or_off() {
    for (text, want) in [
        ("global\n  tune.ibex.zero-spares\n", "expects 'on' or 'off'"),
        ("global\n  tune.ibex.zero-spares maybe\n", "expects 'on' or 'off', got 'maybe'"),
        ("global\n  tune.ibex.zero-spares on now\n", "cannot handle unexpected argument 'now'"),
    ] {
        let e = parse_str(text).expect_err("refused");
        assert!(e.message.contains(want), "{text:?}: {}", e.message);
    }
}
