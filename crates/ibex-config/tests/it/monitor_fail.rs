// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `monitor fail if|unless <cond>`: the parser's answers, as `haproxy -c` (3.5-dev8) gives
//! them. `monitor-uri` is not a keyword on a backend.

use ibex_config::parse_str;

const FE: &str = "defaults\n  mode http\nfrontend f\n  bind 127.0.0.1:8080\n";

fn err(cfg: &str) -> String {
    parse_str(cfg).expect_err("refused").message
}

#[test]
fn monitor_fail_takes_an_if_or_unless_condition() {
    for line in ["monitor fail if { req.hdr(x) -m found }", "monitor fail unless { req.hdr(x) -m found }"] {
        parse_str(&format!("{FE}  {line}\n")).unwrap_or_else(|e| panic!("{line}: {}", e.message));
    }
    // A listen section takes it too.
    parse_str("defaults\n  mode http\nlisten l\n  bind 127.0.0.1:8080\n  monitor fail if TRUE\n").unwrap();
}

#[test]
fn monitor_fail_without_a_condition_is_refused() {
    let want = "'monitor fail' requires either 'if' or 'unless' followed by a condition.";
    assert_eq!(err(&format!("{FE}  monitor fail\n")), want);
    assert_eq!(err(&format!("{FE}  monitor fail foo\n")), want);
}

#[test]
fn monitor_only_supports_fail() {
    assert_eq!(err(&format!("{FE}  monitor foo if TRUE\n")), "'monitor' only supports 'fail'.");
    assert_eq!(err(&format!("{FE}  monitor\n")), "'monitor' only supports 'fail'.");
}

#[test]
fn monitor_is_not_allowed_in_defaults() {
    assert_eq!(err("defaults\n  mode http\n  monitor fail if TRUE\n"), "'monitor' not allowed in 'defaults' section.");
}

#[test]
fn a_backend_ignores_monitor_with_a_warning() {
    parse_str("defaults\n  mode http\nbackend b\n  monitor fail if TRUE\n").unwrap();
}
