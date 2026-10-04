// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request set-timeout` is refused where `HAProxy` refuses it (`cfg_parse_rule_set_timeout`,
//! src/action.c): a timeout of a side the proxy does not have, a name it does not know, a
//! null value. Ibex 8392fff accepted all of them, and a frontend's `set-timeout server`
//! then changed nothing. Messages measured on `HAProxy` 3.5-dev8-885761-29.

use ibex_config::parse_config;

fn cfg(section: &str, rules: &str) -> String {
    let bind = if section.starts_with("backend") { "" } else { "    bind 127.0.0.1:8080\n" };
    format!("defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n{section}\n{bind}{rules}")
}

fn refused(section: &str, rules: &str) -> String {
    match parse_config(&cfg(section, rules)) {
        Ok(_) => panic!("accepted in {section}: {rules}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_timeout_of_a_side_the_proxy_does_not_have_is_refused() {
    for kind in ["server", "connect", "queue", "tunnel"] {
        let e = refused("frontend f", &format!("    http-request set-timeout {kind} 3s\n"));
        assert!(
            e.contains("error detected in frontend 'f' while parsing 'http-request set-timeout' rule : 'f' has no backend capability."),
            "{kind}: {e}"
        );
    }
    let e = refused("backend b", "    http-request set-timeout client 3s\n");
    assert!(
        e.contains("error detected in backend 'b' while parsing 'http-request set-timeout' rule : 'b' has no frontend capability."),
        "{e}"
    );
}

#[test]
fn an_unknown_timeout_or_a_null_one_is_refused() {
    let e = refused("frontend f", "    http-request set-timeout foo 3s\n");
    assert!(
        e.contains("error detected in frontend 'f' while parsing 'http-request set-timeout' rule : 'set-timeout' rule supports 'client'/'connect'/'queue'/'server'/'tarpit'/'tunnel' (got 'foo')."),
        "{e}"
    );
    let e = refused("frontend f", "    http-request set-timeout client 0\n");
    assert!(
        e.contains("error detected in frontend 'f' while parsing 'http-request set-timeout' rule : null value is not valid for a 'set-timeout client' rule."),
        "{e}"
    );
}

#[test]
fn what_haproxy_accepts_is_accepted() {
    for (section, rules) in [
        ("frontend f", "    http-request set-timeout tarpit 3s\n    http-request set-timeout client int(3),mul(1000)\n"),
        ("backend b", "    http-request set-timeout server 3s\n    http-request set-timeout tarpit 3s\n"),
        (
            "listen l",
            "    http-request set-timeout client 3s\n    http-request set-timeout server 3s\n    http-request set-timeout connect 3s\n\
             \x20   http-request set-timeout queue 3s\n    http-request set-timeout tunnel 3s\n",
        ),
    ] {
        if let Err(e) = parse_config(&cfg(section, rules)) {
            panic!("{section}: {rules}: {e}");
        }
    }
}
