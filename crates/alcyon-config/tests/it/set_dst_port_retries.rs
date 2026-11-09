// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! `http-request set-dst-port` and `http-request set-retries`, and servers without a
//! port, as the reference `HAProxy` (3.5-dev8-885761-29) accepts and refuses them with
//! `haproxy -c`, measured 2026-10-03. The parsers are `tcp_parse_set_src_dst`
//! (`src/tcp_act.c`) and `stream_parse_set_retries` (`src/stream.c`).

use alcyon_config::{parse_str, HttpReqAction};

const DEFAULTS: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn parse(body: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse_str(&format!("{DEFAULTS}{body}"))
}

fn backend_rule(rule: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse(&format!("backend b\n  http-request {rule}\n  server s 127.0.0.1:1\n"))
}

fn frontend_rule(rule: &str) -> Result<alcyon_config::Config, alcyon_config::ConfigError> {
    parse(&format!(
        "frontend f\n  bind 127.0.0.1:29000\n  http-request {rule}\n  default_backend b\n\
         backend b\n  server s 127.0.0.1:1\n"
    ))
}

#[test]
fn set_retries_takes_an_integer_from_0_to_100_or_an_expression() {
    // `strtol(.., 0)`: a sign, hex and octal; 0144 is 100.
    for arg in ["0", "3", "100", "+5", "0x10", "0x64", "0144", "var(txn.r)", "req.hdr(x-r)", "2 if TRUE"] {
        let cfg = backend_rule(&format!("set-retries {arg}")).unwrap_or_else(|e| panic!("HAProxy accepts {arg}: {e}"));
        assert!(
            matches!(cfg.backends[0].http_req_rules[0].action, HttpReqAction::SetRetries { .. }),
            "{arg}"
        );
    }
    for (arg, why) in [
        ("", "no argument"),
        ("101", "above 100"),
        ("-1", "negative"),
        ("0x65", "101 in hex"),
        ("0145", "101 in octal"),
        ("08", "not octal, so an expression, and no fetch is called 08"),
        ("3 4", "a second argument"),
        // HAProxy also refuses an unknown fetch (`set-retries nosuch`); Alcyon checks fetch
        // names in no action yet (tasks/T91-fetch-names-in-actions.md).
    ] {
        assert!(backend_rule(&format!("set-retries {arg}")).is_err(), "HAProxy refuses set-retries {arg:?} ({why})");
    }
}

#[test]
fn set_retries_is_refused_where_there_is_no_backend() {
    let err = frontend_rule("set-retries 3").expect_err("HAProxy: only available in backend or listen section");
    assert!(err.message.contains("backend or listen"), "{}", err.message);
    let err = parse("defaults d2\n  mode http\n  http-request set-retries 3\nbackend b\n  server s 127.0.0.1:1\n")
        .expect_err("HAProxy: not allowed in 'defaults' sections");
    assert!(err.message.contains("defaults"), "{}", err.message);
    // A listen section has a backend.
    parse("listen l\n  bind 127.0.0.1:29000\n  http-request set-retries 2 if TRUE\n  server s 127.0.0.1:1\n")
        .expect("HAProxy accepts set-retries in a listen section");
}

#[test]
fn set_dst_port_takes_exactly_one_expression() {
    for arg in ["hdr(x-port)", "int(4000)", "var(txn.p) if TRUE"] {
        let cfg = frontend_rule(&format!("set-dst-port {arg}")).unwrap_or_else(|e| panic!("HAProxy accepts {arg}: {e}"));
        assert!(
            matches!(cfg.frontends[0].http_req_rules[0].action, HttpReqAction::SetDstPort { .. }),
            "{arg}"
        );
    }
    for (arg, why) in [
        ("", "missing fetch method"),
        ("4000", "a bare number is not a fetch"),
        ("int(4000) int(5)", "a second expression"),
    ] {
        assert!(frontend_rule(&format!("set-dst-port {arg}")).is_err(), "HAProxy refuses set-dst-port {arg:?} ({why})");
    }
}

#[test]
fn a_server_without_a_port_maps_the_destination_port() {
    // `!port1 || !port2` in `_srv_parse_init` (src/server.c): SRV_F_MAPPORTS.
    let cfg = parse("backend b\n  server s 127.0.0.1\n  server t 0.0.0.0:0\n").expect("HAProxy accepts a server without a port");
    assert_eq!(cfg.backends[0].servers[0].addr, "127.0.0.1:0".parse().expect("addr"));
    assert_eq!(cfg.backends[0].servers[1].addr, "0.0.0.0:0".parse().expect("addr"));
}
