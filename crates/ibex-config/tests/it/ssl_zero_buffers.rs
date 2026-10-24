// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.ibex.ssl-zero-buffers on|off` (S2), an Ibex-only keyword: wipe the TLS record buffers (plaintext and ciphertext) when
//! they are released, default on. HAProxy refuses it as unknown.

use ibex_config::parse_str;

#[test]
fn ssl_zero_buffers_is_kept_and_unset_is_none() {
    let g = |text: &str| parse_str(text).expect("accepted").global.expect("global").ssl_zero_buffers;
    assert_eq!(g("global\n  tune.ibex.ssl-zero-buffers off\n"), Some(false));
    assert_eq!(g("global\n  tune.ibex.ssl-zero-buffers on\n"), Some(true));
    assert_eq!(g("global\n  maxconn 10\n"), None);
}

#[test]
fn ssl_zero_buffers_wants_exactly_on_or_off() {
    for (text, want) in [
        ("global\n  tune.ibex.ssl-zero-buffers\n", "expects 'on' or 'off'"),
        ("global\n  tune.ibex.ssl-zero-buffers maybe\n", "expects 'on' or 'off', got 'maybe'"),
        ("global\n  tune.ibex.ssl-zero-buffers on now\n", "cannot handle unexpected argument 'now'"),
    ] {
        let e = parse_str(text).expect_err("refused");
        assert!(e.message.contains(want), "{text:?}: {}", e.message);
    }
}
