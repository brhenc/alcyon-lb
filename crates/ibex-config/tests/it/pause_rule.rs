// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request pause` / `http-response pause` (T380): the argument forms and the four
//! refusals, measured with `haproxy -c` on `HAProxy 3.5-dev8-885761-29` on 2026-10-18.

use ibex_config::{parse_config, HttpReqAction, HttpResAction};

fn cfg(rules: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         frontend fe\n    bind 127.0.0.1:8080\n    {rules}\n    default_backend be\n\nbackend be\n    server s 127.0.0.1:9\n"
    )
}

#[test]
fn a_time_or_an_expression_is_accepted() {
    for (line, time_ms, expr) in [
        ("http-request pause 300", 300, None),
        ("http-request pause 1s", 1000, None),
        ("http-request pause 1d", 86_400_000, None),
        ("http-request pause 2147483647", 2_147_483_647, None),
        ("http-request pause 100 if { path /a }", 100, None),
        ("http-request pause req.hdr(x),mul(1)", 0, Some("req.hdr(x),mul(1)")),
        ("http-request pause var(txn.a) unless { path /a }", 0, Some("var(txn.a)")),
    ] {
        let c = parse_config(&cfg(line)).unwrap_or_else(|e| panic!("{line}: {e}"));
        assert_eq!(
            c.frontends[0].http_req_rules[0].action,
            HttpReqAction::Pause { time_ms, expr: expr.map(str::to_string) },
            "{line}"
        );
    }
    let c = parse_config(&cfg("http-response pause 50ms")).expect("parses");
    assert_eq!(c.frontends[0].http_res_rules[0].action, HttpResAction::Pause { time_ms: 50, expr: None });
}

#[test]
fn the_lines_haproxy_refuses_are_refused_with_its_message() {
    for (line, msg) in [
        ("http-request pause 0", "null value is not valid for a 'pause' rule"),
        ("http-request pause 0ms", "null value is not valid for a 'pause' rule"),
        ("http-request pause 5x", "unexpected character 'x' in rule 'pause'"),
        ("http-request pause -1", "unexpected character '-' in rule 'pause'"),
        (
            "http-request pause 2147483648",
            "timer overflow in argument '2147483648' to rule 'pause' (maximum value is 2147483647 ms or ~24.8 days)",
        ),
        ("http-response pause 0", "null value is not valid for a 'pause' rule"),
        (
            "http-request pause 1s 2s",
            "'http-request pause' expects either 'if' or 'unless' followed by a condition but found '2s'.",
        ),
    ] {
        let err = parse_config(&cfg(line)).expect_err(line).to_string();
        assert!(err.contains(msg), "{line}: {err}");
    }
}
