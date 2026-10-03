// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Braces in a rule's condition stand alone, as `HAProxy` (3.5-dev8-885761-29) reads
//! them with `haproxy -c`, measured 2026-10-03: `{ path /a }` and `!{ path /a }` load;
//! `{path /a }` and `{path /a}` are refused (unknown keyword `{path`), and so is
//! `{ path /a}` ("missing closing '}' in condition").

use ibex_config::parse_str;

fn rule(cond: &str) -> Result<ibex_config::Config, ibex_config::ConfigError> {
    parse_str(&format!(
        "frontend fe\n  mode http\n  bind 127.0.0.1:29000\n  http-request return status 201 if {cond}\n"
    ))
}

#[test]
fn a_brace_must_be_a_word_of_its_own() {
    for ok in ["{ path /a }", "!{ path /a }", "! { path /a }", "{ path /a } || { path /b }"] {
        rule(ok).unwrap_or_else(|e| panic!("HAProxy accepts `if {ok}`: {e}"));
    }
    for bad in ["{path /a }", "{path /a}", "{ path /a}", "{ path /a"] {
        assert!(rule(bad).is_err(), "HAProxy refuses `if {bad}`");
    }
}
