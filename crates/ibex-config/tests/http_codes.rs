// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-err-codes` and `http-fail-codes` (`global`): the lines `HAProxy` refuses, and the
//! sets it builds.
//!
//! Every verdict and message below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-04, with `haproxy -c` on the same lines.

use ibex_config::parse_config;

fn global(line: &str) -> Result<ibex_config::GlobalSection, String> {
    parse_config(&format!("global\n    {line}\n")).map(|c| c.global.expect("global")).map_err(|e| e.to_string())
}

#[test]
fn the_lines_haproxy_refuses_are_refused_with_its_messages() {
    let form = "Ranges must be in the form [+-]{low[-{high}]}[,...].";
    for (line, want) in [
        ("http-err-codes", "Missing status codes range for 'http-err-codes'.".to_string()),
        ("http-err-codes abc", format!("Invalid status codes range 'abc' in 'http-err-codes' at position 0. {form}")),
        ("http-err-codes +", format!("Invalid status codes range '+' in 'http-err-codes' at position 1. {form}")),
        ("http-err-codes 400-", format!("Invalid status codes range '400-' in 'http-err-codes' at position 4. {form}")),
        ("http-err-codes 400,,500", format!("Invalid status codes range '400,,500' in 'http-err-codes' at position 4. {form}")),
        ("http-err-codes 99", "Invalid status codes range '99' in 'http-err-codes'.".to_string()),
        ("http-err-codes 600", "Invalid status codes range '600' in 'http-err-codes'.".to_string()),
        ("http-err-codes 500-400", "Invalid status codes range '500-400' in 'http-err-codes'.".to_string()),
        ("http-err-codes 400x", format!("Invalid status codes range '400x' in 'http-err-codes' at position 3. {form}")),
        ("http-fail-codes 1000", "Invalid status codes range '1000' in 'http-fail-codes'.".to_string()),
    ] {
        let err = global(line).expect_err(line);
        assert!(err.contains(&want), "{line}: {err}");
    }
}

#[test]
fn the_sets_are_built_as_haproxy_builds_them() {
    let g = global("http-err-codes 220 +300-499 -300-399").expect("accepted");
    let e = g.http_err_codes.expect("set");
    assert!(e.contains(220) && e.contains(400) && e.contains(499));
    assert!(!e.contains(300) && !e.contains(399) && !e.contains(500) && !e.contains(401 + 100));
    let g = global("http-fail-codes -550-580 +555,599,556-566").expect("accepted");
    let f = g.http_fail_codes.expect("set");
    assert!(f.contains(500) && f.contains(555) && f.contains(556) && f.contains(599));
    assert!(!f.contains(550) && !f.contains(501) && !f.contains(505));
    // Two lines add up; a sign sticks along a comma list.
    let g = global("http-err-codes +300\n    http-err-codes +310,320 -400").expect("accepted");
    let e = g.http_err_codes.expect("set");
    assert!(e.contains(300) && e.contains(310) && e.contains(320) && e.contains(401) && !e.contains(400));
}
