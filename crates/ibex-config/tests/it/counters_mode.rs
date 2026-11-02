// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ibex.counters shared|per-thread` (T582, D-4), an Ibex-only keyword: `HAProxy`
//! 3.5-dev8 refuses it as unknown. `per-tgroup` is refused: Ibex runs one thread group, so it
//! would be `shared` under another name (AGENTS.md §5;
//! `docs/design/per-thread-counters-2026-11-02.md` §5).

use ibex_config::ast::CountersMode;
use ibex_config::parse_str;

#[test]
fn counters_mode_is_kept_and_unset_means_none() {
    let g = |text: &str| parse_str(text).expect("accepted").global.expect("global").counters;
    assert_eq!(g("global\n  tune.ibex.counters shared\n"), Some(CountersMode::Shared));
    assert_eq!(g("global\n  tune.ibex.counters per-thread\n"), Some(CountersMode::PerThread));
    assert_eq!(g("global\n  maxconn 10\n"), None);
}

#[test]
fn counters_mode_refuses_per_tgroup_and_anything_else() {
    for (text, want) in [
        ("global\n  tune.ibex.counters\n", "'tune.ibex.counters' expects 'shared' or 'per-thread'."),
        (
            "global\n  tune.ibex.counters per-tgroup\n",
            "'tune.ibex.counters': 'per-tgroup' is not implemented (one thread group); expected 'shared' or 'per-thread'",
        ),
        ("global\n  tune.ibex.counters on\n", "'tune.ibex.counters' expects 'shared' or 'per-thread', got 'on'."),
        ("global\n  tune.ibex.counters per-thread now\n", "'tune.ibex.counters' cannot handle unexpected argument 'now'."),
    ] {
        let e = parse_str(text).expect_err("refused");
        assert_eq!(e.message, want, "{text:?}");
    }
}
