// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ibex.h3-path relay|mux` (T509, Ibex-only, temporary: deleted with the relay in slice
//! H5 of `docs/design/h3-engine-2026-10-26.md`): which path an HTTP/3 request takes into the
//! stream engine, the HTTP/1 relay over a socket pair (`relay`, the default) or the h3 mux
//! through the bridge h2 streams use (`mux`). HAProxy refuses it as unknown.

use ibex_config::parse_str;

#[test]
fn h3_path_is_kept_and_unset_is_none() {
    let g = |text: &str| parse_str(text).expect("accepted").global.expect("global").h3_mux;
    assert_eq!(g("global\n  tune.ibex.h3-path mux\n"), Some(true));
    assert_eq!(g("global\n  tune.ibex.h3-path relay\n"), Some(false));
    assert_eq!(g("global\n  nbthread 1\n"), None);
}

#[test]
fn h3_path_wants_exactly_relay_or_mux() {
    for (text, want) in [
        ("global\n  tune.ibex.h3-path\n", "expects 'relay' or 'mux'"),
        ("global\n  tune.ibex.h3-path quic\n", "expects 'relay' or 'mux', got 'quic'"),
        ("global\n  tune.ibex.h3-path mux now\n", "cannot handle unexpected argument 'now'"),
    ] {
        let e = parse_str(text).expect_err(text).to_string();
        assert!(e.contains(want), "{text:?}: {e}");
    }
}
