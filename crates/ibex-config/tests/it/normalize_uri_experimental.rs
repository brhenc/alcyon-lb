// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T430 row 30: `http-request normalize-uri` is an experimental action. `HAProxy` 3.5-dev8
//! refuses it, before it looks at the arguments, unless a `global` section above it has
//! `expose-experimental-directives` (measured with `haproxy -c` on 2026-10-19).

use ibex_config::parse_config;

fn cfg(global: &str, rule: &str) -> String {
    format!(
        "{global}defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         frontend fe\n    bind 127.0.0.1:8080\n    {rule}\n    default_backend be\n\nbackend be\n    server s 127.0.0.1:9\n"
    )
}

const MSG: &str = "'normalize-uri' action is experimental, must be allowed via a global 'expose-experimental-directives'";

#[test]
fn refused_without_the_global_before_the_arguments_are_read() {
    for rule in [
        "http-request normalize-uri path-merge-slashes",
        "http-request normalize-uri foo",
        "http-request normalize-uri path-merge-slashes foo",
        "http-request normalize-uri",
    ] {
        let err = parse_config(&cfg("", rule)).expect_err(rule).to_string();
        assert!(err.contains(MSG), "{rule}: {err}");
    }
}

#[test]
fn accepted_with_the_global_and_the_arguments_are_then_checked() {
    let g = "global\n    expose-experimental-directives\n\n";
    parse_config(&cfg(g, "http-request normalize-uri path-merge-slashes")).expect("accepted");
    let err = parse_config(&cfg(g, "http-request normalize-uri foo")).expect_err("refused").to_string();
    assert!(err.contains("unknown normalizer 'foo'"), "{err}");
}

#[test]
fn a_global_below_the_rule_is_too_late() {
    let text = format!("{}\nglobal\n    expose-experimental-directives\n", cfg("", "http-request normalize-uri path-merge-slashes"));
    let err = parse_config(&text).expect_err("refused").to_string();
    assert!(err.contains(MSG), "{err}");
}
