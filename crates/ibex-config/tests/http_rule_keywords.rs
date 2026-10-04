// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The HTTP rule keywords of T124 at load: what `HAProxy` 3.5-dev8-885761-29 accepts and
//! refuses, measured on 2026-10-04 with `haproxy -c` on the same lines.

use ibex_config::{parse_config, HttpReqAction};

fn cfg(section: &str, rules: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         {section} fe\n    bind 127.0.0.1:8080\n    {rules}\n    default_backend be\n\nbackend be\n    server s 127.0.0.1:9\n"
    )
}

#[test]
fn set_priority_actions_parse_with_their_expression_and_condition() {
    let c = parse_config(&cfg("frontend", "http-request set-priority-class int(3) if TRUE")).expect("accepted");
    let rule = &c.frontends[0].http_req_rules[0];
    assert!(matches!(&rule.action, HttpReqAction::SetPriorityClass { expr } if expr == "int(3)"));
    assert!(rule.cond.is_some());
    let c = parse_config(&cfg("frontend", "http-request set-priority-offset req.hdr(x-o)")).expect("accepted");
    assert!(matches!(&c.frontends[0].http_req_rules[0].action, HttpReqAction::SetPriorityOffset { expr } if expr == "req.hdr(x-o)"));
}

#[test]
fn the_priority_lines_haproxy_refuses_are_refused() {
    for (line, want) in [
        ("http-request set-priority-class", "missing fetch method"),
        ("http-request set-priority-offset", "missing fetch method"),
        ("http-request set-priority-offset foo(1) bar", "expects either 'if' or 'unless'"),
        ("http-request set-priority-class int(1) int(2)", "expects either 'if' or 'unless' followed by a condition but found 'int(2)'"),
        // Not in `http-response` or `http-after-response`.
        ("http-response set-priority-class int(1)", "set-priority-class"),
        ("http-after-response set-priority-class int(1)", "set-priority-class"),
    ] {
        let err = parse_config(&cfg("frontend", line)).expect_err(line).to_string();
        assert!(err.contains(want), "{line}: {err}");
    }
}
