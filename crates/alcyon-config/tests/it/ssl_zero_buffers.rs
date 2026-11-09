// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.ssl-zero-buffers on|off` (S2), an Alcyon-only keyword: wipe the TLS record buffers (plaintext and ciphertext) when
//! they are released, default on. HAProxy refuses it as unknown.

use alcyon_config::parse_str;

#[test]
fn ssl_zero_buffers_is_kept_and_unset_is_none() {
    let g = |text: &str| parse_str(text).expect("accepted").global.expect("global").ssl_zero_buffers;
    assert_eq!(g("global\n  tune.alcyon.ssl-zero-buffers off\n"), Some(false));
    assert_eq!(g("global\n  tune.alcyon.ssl-zero-buffers on\n"), Some(true));
    assert_eq!(g("global\n  maxconn 10\n"), None);
}

#[test]
fn ssl_zero_buffers_wants_exactly_on_or_off() {
    for (text, want) in [
        ("global\n  tune.alcyon.ssl-zero-buffers\n", "expects 'on', 'on-free' or 'off'"),
        ("global\n  tune.alcyon.ssl-zero-buffers maybe\n", "expects 'on', 'on-free' or 'off', got 'maybe'"),
        ("global\n  tune.alcyon.ssl-zero-buffers on_free\n", "expects 'on', 'on-free' or 'off', got 'on_free'"),
        ("global\n  tune.alcyon.ssl-zero-buffers on now\n", "cannot handle unexpected argument 'now'"),
    ] {
        let e = parse_str(text).expect_err("refused");
        assert!(e.message.contains(want), "{text:?}: {}", e.message);
    }
}

/// T553: `on-free` keeps the TLS wipe (`ssl_zero_buffers` is `Some(true)`) and moves the
/// transmit buffer's wipe from the give-back to the pool's free (`ssl_zero_on_free`).
#[test]
fn ssl_zero_buffers_on_free_is_a_third_value() {
    let g = |text: &str| {
        let g = parse_str(text).expect("accepted").global.expect("global");
        (g.ssl_zero_buffers, g.ssl_zero_on_free)
    };
    assert_eq!(g("global\n  tune.alcyon.ssl-zero-buffers on-free\n"), (Some(true), true));
    assert_eq!(g("global\n  tune.alcyon.ssl-zero-buffers on\n"), (Some(true), false));
    assert_eq!(g("global\n  tune.alcyon.ssl-zero-buffers off\n"), (Some(false), false));
    assert_eq!(g("global\n  maxconn 10\n"), (None, false));
}
