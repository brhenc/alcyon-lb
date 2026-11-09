// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `silent-drop rst-ttl <1-255>` (tasks/T302 item 7 / T305 item 7). Measured on `HAProxy`
//! 3.5-dev8: `tcp-request connection|session|content` and `http-request` take it before the
//! condition; 0, 256 and -1 are "valid rst-ttl values are [1-255]", a missing value is
//! "missing rst-ttl value", `abc` and `5x` are "invalid character starting at '...' (value
//! `HAProxy` sets `IP_TTL` to that value (1 without the option) and then `SO_LINGER` 0.

use alcyon_config::{parse_str, HttpReqAction, TcpReqConnAction, TcpReqContentAction, TcpReqSessionAction};

fn load(rule: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse_str(&format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         frontend f\n  bind 127.0.0.1:29002\n  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"
    ))
}

#[test]
fn the_ttl_is_kept_on_every_request_form() {
    let c = load("tcp-request connection silent-drop rst-ttl 5").expect("conn");
    assert_eq!(c.frontends[0].tcp_req_conn_rules[0].action, TcpReqConnAction::SilentDropTtl(5));
    let c = load("tcp-request session silent-drop rst-ttl 255 if TRUE").expect("session");
    assert_eq!(c.frontends[0].tcp_req_session_rules[0].action, TcpReqSessionAction::SilentDropTtl(255));
    assert!(c.frontends[0].tcp_req_session_rules[0].cond.is_some());
    let c = load("tcp-request content silent-drop rst-ttl 1 unless TRUE").expect("content");
    assert_eq!(c.frontends[0].tcp_req_content_rules[0].action, TcpReqContentAction::SilentDropTtl(1));
    let c = load("http-request silent-drop rst-ttl 7 if { path /x }").expect("http");
    assert_eq!(c.frontends[0].http_req_rules[0].action, HttpReqAction::SilentDropTtl(7));
    assert!(c.frontends[0].http_req_rules[0].cond.is_some());
    // Without the option the action is the plain one (a TTL of 1).
    let c = load("tcp-request connection silent-drop").expect("plain");
    assert_eq!(c.frontends[0].tcp_req_conn_rules[0].action, TcpReqConnAction::SilentDrop);
}

#[test]
fn the_ttl_is_checked_as_haproxy_checks_it() {
    for form in ["tcp-request connection", "tcp-request session", "tcp-request content", "http-request"] {
        for (arg, want) in [
            ("0", "valid rst-ttl values are [1-255]"),
            ("256", "valid rst-ttl values are [1-255]"),
            ("-1", "valid rst-ttl values are [1-255]"),
            ("99999999999", "valid rst-ttl values are [1-255]"),
            ("abc", "invalid character starting at 'abc' (value 1-255 expected)"),
            ("5x", "invalid character starting at 'x' (value 1-255 expected)"),
        ] {
            let err = load(&format!("{form} silent-drop rst-ttl {arg}")).expect_err(arg);
            assert!(err.message.contains(want), "{form} {arg}: {}", err.message);
        }
        let err = load(&format!("{form} silent-drop rst-ttl")).expect_err("missing");
        assert!(err.message.contains("missing rst-ttl value"), "{form}: {}", err.message);
        let err = load(&format!("{form} silent-drop rst-ttl if TRUE")).expect_err("if as value");
        assert!(err.message.contains("invalid character starting at 'if'"), "{form}: {}", err.message);
    }
}

#[test]
fn the_response_forms_still_refuse_it() {
    for rule in ["http-response silent-drop rst-ttl 5", "tcp-response content silent-drop rst-ttl 5"] {
        let cfg = format!(
            "defaults\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\nbackend b\n  mode tcp\n  {rule}\n  server s 127.0.0.1:1\n"
        );
        let err = parse_str(&cfg).expect_err(rule);
        assert!(err.message.contains("not implemented"), "{rule}: {}", err.message);
    }
}
