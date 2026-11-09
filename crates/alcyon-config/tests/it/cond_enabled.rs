// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `enabled(<option>)` in `.if` and `-cc` (T131 item 9). The answers are those of
//! `HAProxy` 3.5-dev8-885761-29 on Linux, measured with `.if enabled(X)` after the global
//! lines shown, and with `haproxy -cc`: the options are the configuration's as read so far.

use alcyon_config::{cond, parse_str};

/// `enabled(name)` as a `.if` answers it after `global_lines` (each ending in a newline).
fn enabled(name: &str, global_lines: &str) -> bool {
    let cfg = parse_str(&format!(
        "global\n{global_lines}.if enabled({name})\n  maxconn 1111\n.else\n  maxconn 2222\n.endif\n"
    ))
    .expect("parses");
    cfg.global.expect("a global section").maxconn == Some(1111)
}

#[test]
fn the_defaults_are_haproxys_on_linux() {
    for (name, want) in [
        ("POLL", true),
        ("EPOLL", true),
        ("KQUEUE", false),
        ("EVPORTS", false),
        ("SPLICE", true),
        ("GETADDRINFO", true),
        ("REUSEPORT", true),
        ("FAST-FORWARD", true),
        ("SERVER-SSL-VERIFY-NONE", false),
        // Names are exact, and an unknown one is false.
        ("foo", false),
        ("poll", false),
    ] {
        assert_eq!(enabled(name, ""), want, "enabled({name})");
        assert_eq!(cond::eval_cc(&format!("enabled({name})")), Ok(want), "-cc enabled({name})");
    }
}

#[test]
fn the_global_lines_above_the_condition_change_the_answer() {
    let off = "noepoll\nnopoll\nnosplice\ntune.disable-fast-forward\nssl-server-verify none\n";
    for (name, want) in [
        ("POLL", false),
        ("EPOLL", false),
        ("SPLICE", false),
        ("FAST-FORWARD", false),
        ("SERVER-SSL-VERIFY-NONE", true),
        ("GETADDRINFO", true),
        ("REUSEPORT", true),
    ] {
        assert_eq!(enabled(name, off), want, "enabled({name}) after {off:?}");
    }
    assert!(!enabled("GETADDRINFO", "nogetaddrinfo\n"));
    assert!(!enabled("REUSEPORT", "noreuseport\n"));
    assert!(!enabled("SERVER-SSL-VERIFY-NONE", "ssl-server-verify required\n"));
    // Only what has been read: a line after the condition does not count.
    let cfg = parse_str("global\n.if enabled(EPOLL)\n  maxconn 1111\n.else\n  maxconn 2222\n.endif\nnoepoll\n").expect("parses");
    assert_eq!(cfg.global.expect("global").maxconn, Some(1111));
}

#[test]
fn this_build_is_not_in_fips_mode() {
    assert_eq!(cond::eval_cc("fips_mode()"), Ok(false));
    assert_eq!(cond::eval_cc("!fips_mode()"), Ok(true));
}
