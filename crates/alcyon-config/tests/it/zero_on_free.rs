// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tune.alcyon.zero-on-free off|soft|hard` (T459), an Alcyon-only keyword: `HAProxy` 3.5-dev8 refuses
//! it ("unknown keyword 'tune.alcyon.zero-on-free' in 'global' section").

use alcyon_config::ast::ZeroOnFree;
use alcyon_config::parse_str;

#[test]
fn zero_on_free_is_kept_and_unset_means_none() {
    let g = |text: &str| parse_str(text).expect("accepted").global.expect("global").zero_on_free;
    assert_eq!(g("global\n  tune.alcyon.zero-on-free off\n"), Some(ZeroOnFree::Off));
    assert_eq!(g("global\n  tune.alcyon.zero-on-free soft\n"), Some(ZeroOnFree::Soft));
    assert_eq!(g("global\n  tune.alcyon.zero-on-free hard\n"), Some(ZeroOnFree::Hard));
    assert_eq!(g("global\n  maxconn 10\n"), None);
}

#[test]
fn zero_on_free_wants_exactly_off_soft_or_hard() {
    for (text, want) in [
        ("global\n  tune.alcyon.zero-on-free\n", "'tune.alcyon.zero-on-free' expects 'off', 'soft' or 'hard'."),
        ("global\n  tune.alcyon.zero-on-free on\n", "'tune.alcyon.zero-on-free' expects 'off', 'soft' or 'hard', got 'on'."),
        ("global\n  tune.alcyon.zero-on-free soft now\n", "'tune.alcyon.zero-on-free' cannot handle unexpected argument 'now'."),
    ] {
        let e = parse_str(text).expect_err("refused");
        assert_eq!(e.message, want, "{text:?}");
    }
}
