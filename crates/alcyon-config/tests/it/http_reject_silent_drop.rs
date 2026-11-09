// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request reject`, `http-request silent-drop` and `http-response silent-drop` load
//! (tasks/T305 item 1). Measured with `haproxy -c` on 3.5-dev8: each takes an optional
//! `if`/`unless` condition and nothing else but `rst-ttl <1-255>` (which Alcyon refuses on `http-response` only);
//! `http-response reject` and `http-after-response silent-drop` are refused by `HAProxy`.

use alcyon_config::{parse_str, HttpReqAction};

fn load(rule: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse_str(&format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         frontend f\n  bind 127.0.0.1:29001\n  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"
    ))
}

#[test]
fn the_request_actions_load_with_and_without_a_condition() {
    for (rule, want) in [
        ("http-request reject", HttpReqAction::Reject),
        ("http-request reject if { path /x }", HttpReqAction::Reject),
        ("http-request reject unless { src 10.0.0.0/8 }", HttpReqAction::Reject),
        ("http-request silent-drop", HttpReqAction::SilentDrop),
        ("http-request silent-drop if { path /x }", HttpReqAction::SilentDrop),
    ] {
        let cfg = load(rule).unwrap_or_else(|e| panic!("{rule}: {e}"));
        let r = &cfg.frontends[0].http_req_rules;
        assert_eq!(r.len(), 1, "{rule}");
        assert_eq!(r[0].action, want, "{rule}");
        assert_eq!(r[0].cond.is_some(), rule.contains(" if ") || rule.contains(" unless "), "{rule}");
    }
}

#[test]
fn the_response_action_loads() {
    for rule in ["http-response silent-drop", "http-response silent-drop if { status 200 }"] {
        let cfg = load(rule).unwrap_or_else(|e| panic!("{rule}: {e}"));
        assert_eq!(cfg.frontends[0].http_res_rules.len(), 1, "{rule}");
    }
}

#[test]
fn extra_words_and_the_actions_haproxy_has_not_are_refused() {
    for rule in [
        "http-request reject foo",
        "http-request silent-drop foo",
        "http-response silent-drop foo",
        "http-response reject",
        "http-after-response silent-drop",
        // HAProxy takes this; Alcyon would ignore it (tests/it/rst_ttl.rs has the request form).
        "http-response silent-drop rst-ttl 5",
    ] {
        assert!(load(rule).is_err(), "{rule} should be refused");
    }
    let err = load("http-request reject foo").expect_err("refused");
    assert!(err.message.contains("'http-request reject' expects either 'if' or 'unless' followed by a condition but found 'foo'"), "{}", err.message);
    let err = load("http-response silent-drop rst-ttl 5").expect_err("refused");
    assert!(err.message.contains("not implemented"), "{}", err.message);
}
