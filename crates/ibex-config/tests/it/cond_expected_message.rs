// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T430 row 19: "'<list> <action>' expects either 'if' or 'unless' followed by a condition
//! but found 'x'." ends with a full stop in `HAProxy` 3.5-dev8 for every action (measured
//! with `haproxy -c` on 2026-10-19).

use ibex_config::parse_config;

fn cfg(rule: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         frontend fe\n    bind 127.0.0.1:8080\n    {rule}\n    default_backend be\n\nbackend be\n    server s 127.0.0.1:9\n"
    )
}

#[test]
fn the_message_ends_with_a_full_stop_for_every_action() {
    for (rule, act, list, found) in [
        ("http-request silent-drop foo", "silent-drop", "http-request", "foo"),
        ("http-response silent-drop foo", "silent-drop", "http-response", "foo"),
        ("http-request add-headers-bin bin(00) foo", "add-headers-bin", "http-request", "foo"),
        ("http-request del-headers-bin bin(00) foo", "del-headers-bin", "http-request", "foo"),
        ("http-request set-headers-bin bin(00) prefix p foo", "set-headers-bin", "http-request", "foo"),
        ("http-response del-headers-bin bin(00) -m str foo", "del-headers-bin", "http-response", "foo"),
        ("http-request auth foo", "auth", "http-request", "foo"),
        ("http-request reject foo", "reject", "http-request", "foo"),
        ("http-request deny status 400 deny_status 401", "deny", "http-request", "deny_status"),
    ] {
        let want = format!("'{list} {act}' expects either 'if' or 'unless' followed by a condition but found '{found}'.");
        let err = parse_config(&cfg(rule)).expect_err(rule).to_string();
        assert!(err.contains(&want), "{rule}: {err}");
    }
}
