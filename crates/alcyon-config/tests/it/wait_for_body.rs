// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request|http-response wait-for-body` and `option http-buffer-request`: the
//! syntax `HAProxy` accepts and the lines it refuses.
//!
//! Every verdict and message below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-04, with `haproxy -c` on the same lines.

use alcyon_config::{parse_config, HttpReqAction, HttpResAction};

fn cfg(rules: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         frontend fe\n    bind 127.0.0.1:8080\n    {rules}\n    default_backend be\n\nbackend be\n    server s 127.0.0.1:9\n"
    )
}

fn req_action(line: &str) -> HttpReqAction {
    let c = parse_config(&cfg(line)).unwrap_or_else(|e| panic!("{line}: {e}"));
    c.frontends[0].http_req_rules[0].action.clone()
}

#[test]
fn the_request_forms_haproxy_accepts_are_accepted_with_their_values() {
    let wait = |time_ms, at_least| HttpReqAction::WaitForBody { time_ms: Some(time_ms), at_least };
    for (line, want) in [
        ("http-request wait-for-body time 1s", wait(1000, 0)),
        ("http-request wait-for-body time 1", wait(1, 0)),
        ("http-request wait-for-body time 0", wait(0, 0)),
        ("http-request wait-for-body time 1d", wait(86_400_000, 0)),
        ("http-request wait-for-body time 1500us", wait(2, 0)),
        ("http-request wait-for-body time 1s at-least 5", wait(1000, 5)),
        ("http-request wait-for-body at-least 5 time 1s", wait(1000, 5)),
        ("http-request wait-for-body time 1s at-least 10k", wait(1000, 10 * 1024)),
        ("http-request wait-for-body time 1s at-least 2m", wait(1000, 2 * 1024 * 1024)),
        ("http-request wait-for-body time 1s at-least 1g", wait(1000, 1 << 30)),
        ("http-request wait-for-body time 1s at-least 0", wait(1000, 0)),
        ("http-request wait-for-body time 1s at-least 1K", wait(1000, 1024)),
        ("http-request wait-for-body time 1s at-least 0k", wait(1000, 0)),
        ("http-request wait-for-body time 1s at-least 4194303k", wait(1000, 4_194_303 * 1024)),
        ("http-request wait-for-body time 2147483647", wait(2_147_483_647, 0)),
        ("http-request wait-for-body time 2147483s", wait(2_147_483_000, 0)),
        ("http-request wait-for-body time 1h", wait(3_600_000, 0)),
        ("http-request wait-for-body time 1m", wait(60_000, 0)),
        // A repeated argument replaces the one before.
        ("http-request wait-for-body time 1s time 2s", wait(2000, 0)),
        ("http-request wait-for-body time 1s at-least 5 at-least 6", wait(1000, 6)),
        ("http-request wait-for-body time 1s at-least 5 if { path /a }", wait(1000, 5)),
        ("http-request wait-for-body time 1s unless { path /a }", wait(1000, 0)),
    ] {
        assert_eq!(req_action(line), want, "{line}");
    }
}

#[test]
fn the_condition_is_kept() {
    let c = parse_config(&cfg("http-request wait-for-body time 1s if { path /a }")).expect("parses");
    assert!(c.frontends[0].http_req_rules[0].cond.is_some());
}

#[test]
fn the_request_lines_haproxy_refuses_are_refused_with_its_message() {
    for (line, msg) in [
        ("http-request wait-for-body", "expects time <time> [ at-least <bytes> ]."),
        ("http-request wait-for-body at-least 5", "expects time <time> [ at-least <bytes> ]."),
        ("http-request wait-for-body foo", "expects time <time> [ at-least <bytes> ]."),
        ("http-request wait-for-body time", "missing argument for 'time'."),
        ("http-request wait-for-body time 1s time", "missing argument for 'time'."),
        ("http-request wait-for-body at-least", "missing argument for 'at-least'."),
        ("http-request wait-for-body time 2s at-least", "missing argument for 'at-least'."),
        ("http-request wait-for-body time abc", "unexpected character 'a'."),
        ("http-request wait-for-body time 1.5s", "unexpected character '.'."),
        ("http-request wait-for-body time 1s at-least abc", "unexpected character 'a'."),
        ("http-request wait-for-body time 1s at-least -1", "unexpected character '-'."),
        ("http-request wait-for-body time 1s at-least 0x10", "unexpected character 'x'."),
        ("http-request wait-for-body time 1s at-least 1.5k", "unexpected character '.'."),
        ("http-request wait-for-body time 1s at-least 1kb", "unexpected character 'b'."),
        ("http-request wait-for-body time 1s at-least 10G", "unexpected character 'G'."),
        ("http-request wait-for-body time 1s at-least 4194304k", "unexpected character 'k'."),
        ("http-request wait-for-body time 5xs", "unexpected character 'x'."),
        ("http-request wait-for-body time 1S", "unexpected character 'S'."),
        ("http-request wait-for-body time s", "unexpected character 's'."),
        (
            "http-request wait-for-body time 2147483648",
            "time overflow (maximum value is 2147483647 ms or ~24.8 days).",
        ),
        ("http-request wait-for-body time 1s at-least 5000000000", "unexpected character '0'."),
        (
            "http-request wait-for-body time 100000000s",
            "time overflow (maximum value is 2147483647 ms or ~24.8 days).",
        ),
        (
            "http-request wait-for-body time 1s foo",
            "'http-request wait-for-body' expects either 'if' or 'unless' followed by a condition but found 'foo'.",
        ),
    ] {
        let err = parse_config(&cfg(line)).expect_err(line).to_string();
        assert!(err.contains(msg), "{line}: {err}");
    }
}

#[test]
fn the_response_form_is_accepted_and_refused_like_the_request_one() {
    let cfg = |line: &str| {
        format!(
            "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
             frontend fe\n    bind 127.0.0.1:8080\n    {line}\n    default_backend be\n\nbackend be\n    {line}\n    server s 127.0.0.1:9\n"
        )
    };
    let c = parse_config(&cfg("http-response wait-for-body at-least 5 time 1s")).expect("parses");
    assert_eq!(
        c.frontends[0].http_res_rules[0].action,
        HttpResAction::WaitForBody { time_ms: 1000, at_least: 5 }
    );
    assert_eq!(
        c.backends[0].http_res_rules[0].action,
        HttpResAction::WaitForBody { time_ms: 1000, at_least: 5 }
    );
    for (line, msg) in [
        ("http-response wait-for-body", "expects time <time> [ at-least <bytes> ]."),
        ("http-response wait-for-body time", "missing argument for 'time'."),
        ("http-response wait-for-body time 1s at-least x", "unexpected character 'x'."),
        (
            "http-response wait-for-body time 1s foo",
            "'http-response wait-for-body' expects either 'if' or 'unless' followed by a condition but found 'foo'.",
        ),
    ] {
        let err = parse_config(&cfg(line)).expect_err(line).to_string();
        assert!(err.contains(msg), "{line}: {err}");
    }
}

#[test]
fn the_option_is_accepted_where_haproxy_accepts_it_and_inherited_from_defaults() {
    let parsed = |defaults: &str, fe: &str, be: &str| {
        parse_config(&format!(
            "defaults\n    mode http\n    timeout client 5s\n    timeout server 5s\n    timeout connect 1s\n    {defaults}\n\n\
             frontend fe\n    bind 127.0.0.1:8080\n    {fe}\n    default_backend be\n\nbackend be\n    {be}\n    server s 127.0.0.1:9\n\n\
             listen l\n    bind 127.0.0.1:8081\n    server s 127.0.0.1:9\n"
        ))
        .unwrap_or_else(|e| panic!("{defaults} / {fe} / {be}: {e}"))
    };
    let on = "option http-buffer-request";
    let off = "no option http-buffer-request";
    let c = parsed("", on, "");
    assert_eq!((c.frontends[0].buffer_request, c.backends[0].buffer_request, c.listens[0].buffer_request), (true, false, false));
    let c = parsed("", "", on);
    assert_eq!((c.frontends[0].buffer_request, c.backends[0].buffer_request), (false, true));
    let c = parsed(on, "", "");
    assert_eq!((c.frontends[0].buffer_request, c.backends[0].buffer_request, c.listens[0].buffer_request), (true, true, true));
    let c = parsed(on, off, off);
    assert_eq!((c.frontends[0].buffer_request, c.backends[0].buffer_request, c.listens[0].buffer_request), (false, false, true));
}
