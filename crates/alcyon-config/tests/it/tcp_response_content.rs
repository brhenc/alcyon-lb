// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `tcp-response content`: which actions load. Measured against `HAProxy`
//! 3.5-dev8-885761-29 with `haproxy -c`, 2026-10-03 (`tcp_parse_tcp_rep`, `src/tcp_rules.c`).
//! Alcyon implements accept, reject, silent-drop, set-var, set-var-fmt and unset-var on the
//! response; every other action `HAProxy` takes there is refused until it is implemented,
//! and the ones `HAProxy` refuses are refused too.

use alcyon_config::parse_str;

fn backend_rule(action: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse_str(&format!(
        "defaults\n  mode tcp\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         backend b\n  tcp-response inspect-delay 1s\n  tcp-response content {action}\n  server s 127.0.0.1:1\n"
    ))
}

#[test]
fn the_implemented_response_actions_load() {
    for action in [
        "accept",
        "reject",
        "silent-drop",
        "set-var(res.p) res.payload(0,0)",
        "set-var-fmt(res.p) \"%[res.len]\"",
        "unset-var(res.p)",
        "reject unless { res.payload(0,0),fix_is_valid }",
    ] {
        let cfg = backend_rule(action).unwrap_or_else(|e| panic!("{action}: {e}"));
        assert_eq!(cfg.backends[0].tcp_res_content_rules.len(), 1, "{action}");
    }
}

#[test]
fn response_actions_haproxy_refuses_or_alcyon_does_not_run_are_refused() {
    // HAProxy refuses these on the response side.
    for action in ["track-sc0 src", "set-src src", "set-dst dst", "use-service prometheus-exporter", "switch-mode http"] {
        assert!(backend_rule(action).is_err(), "HAProxy refuses tcp-response content {action}");
    }
    // HAProxy accepts these; Alcyon does not run them on the response yet.
    for action in ["close", "sc-inc-gpc0(0)", "do-log"] {
        let err = backend_rule(action).expect_err(action);
        assert!(err.message.contains("not implemented"), "{action}: {}", err.message);
    }
}

#[test]
fn tcp_response_is_refused_in_a_frontend() {
    let err = parse_str(
        "defaults\n  mode tcp\nfrontend f\n  bind 127.0.0.1:29000\n  tcp-response content reject\n  default_backend b\n\
         backend b\n  server s 127.0.0.1:1\n",
    )
    .expect_err("HAProxy: tcp-response content is only allowed in 'backend' sections");
    assert!(!err.message.is_empty());
}

#[test]
fn tcp_response_in_defaults_needs_a_named_section() {
    let section = |head: &str| {
        parse_str(&format!(
            "{head}\n  mode tcp\n  tcp-response inspect-delay 1s\n  tcp-response content reject\nbackend b\n  server s 127.0.0.1:1\n"
        ))
    };
    // HAProxy: "tcp-response content is only allowed in 'backend' sections or 'defaults'
    // section with a name".
    assert!(section("defaults").is_err(), "HAProxy refuses it in an anonymous defaults");
    let cfg = section("defaults d").expect("HAProxy accepts it in a named defaults");
    assert_eq!(cfg.backends[0].tcp_res_content_rules.len(), 1, "the backend inherits it");
}
