// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The legacy `sc-set-gpt0[(<sc>)]` without a value (T149b).
//!
//! `HAProxy` 3.5-dev8-885761-29 loads `http-request sc-set-gpt0`, `... sc-set-gpt0(0)`,
//! `tcp-request session sc-set-gpt0(0)` and `tcp-request content sc-set-gpt0` with no value
//! (`haproxy -c`, rule inside a frontend with a table that stores gpt0): the value is 0, as
//! it already is for `sc-add-gpc` and `sc-set-gpt`. Ibex refused them.

use ibex_config::{parse_config, HttpReqAction, TcpReqContentAction, TcpReqSessionAction};

fn load(rule_set: &str, action: &str) -> ibex_config::Config {
    parse_config(&format!("frontend fe\n  mode http\n  bind 127.0.0.1:1\n  {rule_set} {action}\n")).unwrap_or_else(|e| panic!("{rule_set} {action}: {e}"))
}

#[test]
fn a_missing_value_is_zero_in_http_request() {
    for action in ["sc-set-gpt0", "sc-set-gpt0(1)"] {
        let cfg = load("http-request", action);
        let rule = &cfg.frontends[0].http_req_rules[0];
        let sc = if action.contains('1') { 1 } else { 0 };
        match &rule.action {
            HttpReqAction::ScSetGpt0 { sc: s, expr } => assert_eq!((*s, expr.as_str()), (sc, "0"), "{action}"),
            other => panic!("{action}: {other:?}"),
        }
    }
}

#[test]
fn a_missing_value_is_zero_in_tcp_request_session() {
    let cfg = load("tcp-request session", "sc-set-gpt0(0)");
    match &cfg.frontends[0].tcp_req_session_rules[0].action {
        TcpReqSessionAction::ScSetGpt0 { expr, .. } => assert_eq!(expr, "0"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_missing_value_is_zero_in_tcp_request_content() {
    let cfg = load("tcp-request content", "sc-set-gpt0");
    match &cfg.frontends[0].tcp_req_content_rules[0].action {
        TcpReqContentAction::ScSetGpt0 { expr, .. } => assert_eq!(expr, "0"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_value_is_still_read() {
    let cfg = load("http-request", "sc-set-gpt0 7");
    match &cfg.frontends[0].http_req_rules[0].action {
        HttpReqAction::ScSetGpt0 { expr, .. } => assert_eq!(expr, "7"),
        other => panic!("{other:?}"),
    }
}
