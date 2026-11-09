// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `option redispatch [<interval>]` as `cfgparse-listen.c` reads it (T112): the interval is
//! `atol`'d, 0 (or text) switches the option off, `no option redispatch` clears it, and
//! `defaults` hands the interval down. Reaches the data path in
//! `alcyon-rt` `retry_server_connect` (`crates/alcyon-rt/tests/redispatch.rs` drives it).

use alcyon_config::parse_str;

fn be(opts: &str) -> (bool, i32) {
    let cfg = parse_str(&format!("backend b\n{opts}  server s 127.0.0.1:1\n")).expect("parse");
    (cfg.backends[0].redisp, cfg.backends[0].redisp_after)
}

#[test]
fn the_interval_is_read_like_atol() {
    assert_eq!(be(""), (false, -1));
    assert_eq!(be("  option redispatch\n"), (true, -1));
    assert_eq!(be("  option redispatch 3\n"), (true, 3));
    assert_eq!(be("  option redispatch -2\n"), (true, -2));
    assert_eq!(be("  option redispatch 1.5\n"), (true, 1));
    assert_eq!(be("  option redispatch +3\n"), (true, 3));
    assert_eq!(be("  option redispatch   7x\n"), (true, 7));
    assert!(!be("  option redispatch 0\n").0);
    assert!(!be("  option redispatch abc\n").0);
    assert_eq!(be("  option redispatch 2\n  option redispatch\n"), (true, -1), "the last line replaces the interval");
    assert!(!be("  option redispatch 2\n  no option redispatch\n").0);
}

/// The old `redisp` keyword: HAProxy 3.5 refuses it in every section ("not supported
/// anymore since HAProxy 2.1. Use 'option redispatch'", measured).
#[test]
fn the_legacy_redisp_keyword_is_refused() {
    for cfg in [
        "defaults\n  redisp\nbackend a\n  server s 127.0.0.1:1\n",
        "backend b\n  redisp\n  server s 127.0.0.1:1\n",
        "listen l\n  bind 127.0.0.1:0\n  redisp\n  server s 127.0.0.1:1\n",
    ] {
        let err = parse_str(cfg).expect_err("redisp must be refused");
        assert!(err.to_string().contains("not supported anymore since HAProxy 2.1"), "{err}");
    }
}

#[test]
fn defaults_hand_the_interval_down_and_a_section_overrides_it() {
    let cfg = parse_str(
        "defaults\n  option redispatch 4\nbackend a\n  server s 127.0.0.1:1\nbackend b\n  option redispatch 2\n  server s 127.0.0.1:1\n\
         backend c\n  no option redispatch\n  server s 127.0.0.1:1\nlisten l\n  bind 127.0.0.1:0\n  server s 127.0.0.1:1\n",
    )
    .expect("parse");
    let got: Vec<_> = cfg.backends.iter().map(|b| (b.redisp, b.redisp_after)).collect();
    assert_eq!(got[0], (true, 4));
    assert_eq!(got[1], (true, 2));
    assert!(!got[2].0);
    assert_eq!((cfg.listens[0].redisp, cfg.listens[0].redisp_after), (true, 4));
}
