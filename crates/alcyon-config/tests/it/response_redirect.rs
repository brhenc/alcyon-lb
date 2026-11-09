// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-response redirect`: the syntax `HAProxy` accepts and the lines it refuses, and
//! the line number every http-request, http-response, tcp-request content and
//! tcp-response content rule carries for `last_rule_line`.
//!
//! Every verdict and message below was measured on the reference binary,
//! `HAProxy 3.5-dev8-885761-29`, on 2026-10-04, with `haproxy -c` on the same lines.

use alcyon_config::{parse_config, HttpResAction, RedirectCookie};

fn cfg(rules: &str) -> String {
    format!(
        "defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n\
         frontend fe\n    bind 127.0.0.1:8080\n    default_backend be\n\nbackend be\n    {rules}\n    server s 127.0.0.1:9\n"
    )
}

fn action(line: &str) -> HttpResAction {
    let c = parse_config(&cfg(line)).unwrap_or_else(|e| panic!("{line}: {e}"));
    c.backends[0].http_res_rules[0].action.clone()
}

fn redirect(location: &str, code: u16, cookie: Option<RedirectCookie>) -> HttpResAction {
    HttpResAction::Redirect { location: location.to_string(), code, cookie }
}

#[test]
fn the_location_forms_haproxy_accepts_are_accepted_with_their_values() {
    let set = |s: &str| Some(RedirectCookie::Set(s.to_string()));
    let clear = |s: &str| Some(RedirectCookie::Clear(s.to_string()));
    for (line, want) in [
        ("http-response redirect location /x", redirect("/x", 302, None)),
        ("http-response redirect location /x code 301", redirect("/x", 301, None)),
        ("http-response redirect location /x code 303", redirect("/x", 303, None)),
        ("http-response redirect location /x code 307", redirect("/x", 307, None)),
        ("http-response redirect location /x code 308", redirect("/x", 308, None)),
        ("http-response redirect code 308 location /x", redirect("/x", 308, None)),
        // A repeated argument replaces the one before.
        ("http-response redirect location /a location /b", redirect("/b", 302, None)),
        ("http-response redirect location /x code 301 code 308", redirect("/x", 308, None)),
        // Options that only shape a `prefix` or `scheme` redirect do nothing to a location.
        ("http-response redirect location /x drop-query keep-query append-slash", redirect("/x", 302, None)),
        ("http-response redirect location /x set-cookie a=1", redirect("/x", 302, set("a=1"))),
        ("http-response redirect location /x set-cookie ck", redirect("/x", 302, set("ck"))),
        ("http-response redirect location /x clear-cookie a", redirect("/x", 302, clear("a"))),
        // Of set-cookie and clear-cookie the last one stands.
        ("http-response redirect location /x set-cookie a=1 clear-cookie b", redirect("/x", 302, clear("b"))),
        ("http-response redirect location /x clear-cookie a set-cookie b=1", redirect("/x", 302, set("b=1"))),
        ("http-response redirect location /x unless { status 200 }", redirect("/x", 302, None)),
    ] {
        assert_eq!(action(line), want, "{line}");
    }
}

#[test]
fn the_lines_haproxy_refuses_are_refused_with_its_message() {
    for (line, message) in [
        ("http-response redirect", "redirection type expected ('prefix', 'location', or 'scheme')."),
        ("http-response redirect code 301", "redirection type expected ('prefix', 'location', or 'scheme')."),
        ("http-response redirect scheme https", "response only supports redirect type 'location'."),
        ("http-response redirect prefix /p", "response only supports redirect type 'location'."),
        ("http-response redirect location /x code 200", "'code': unsupported HTTP code '200' (must be one of 301, 302, 303, 307 or 308)."),
        ("http-response redirect location /x code 304", "'code': unsupported HTTP code '304' (must be one of 301, 302, 303, 307 or 308)."),
        ("http-response redirect location /x code x", "'code': unsupported HTTP code 'x' (must be one of 301, 302, 303, 307 or 308)."),
        ("http-response redirect location /x code", "missing argument for 'code'."),
        ("http-response redirect location", "missing argument for 'location'."),
        ("http-response redirect location /x set-cookie", "missing argument for 'set-cookie'."),
        ("http-response redirect location /x clear-cookie", "missing argument for 'clear-cookie'."),
        (
            "http-response redirect location /x bogus",
            "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was 'bogus').",
        ),
        ("http-response redirect location /x set-cookie-fmt", "missing argument for 'set-cookie-fmt'."),
        // Accepted by HAProxy, not done by Alcyon: refused rather than ignored.
        ("http-response redirect location /x ignore-empty", "not implemented"),
    ] {
        let err = parse_config(&cfg(line)).err().unwrap_or_else(|| panic!("{line}: accepted")).to_string();
        assert!(err.contains(message), "{line}: {err}");
    }
}

#[test]
fn every_kind_of_rule_knows_its_own_line() {
    let text = [
        "defaults",                              // 1
        "  mode http",                           // 2
        "  timeout connect 1s",                  // 3
        "  timeout client 5s",                   // 4
        "  timeout server 5s",                   // 5
        "frontend fe",                           // 6
        "  bind 127.0.0.1:8080",                 // 7
        "  tcp-request content accept if TRUE",  // 8
        "  http-request deny if FALSE",          // 9
        "",                                      // 10
        "  http-request allow",                  // 11
        "  default_backend be",                  // 12
        "backend be",                            // 13
        "  tcp-response content accept if TRUE", // 14
        "  http-response deny if FALSE",         // 15
        "  http-response redirect location /x",  // 16
        "  http-response allow",                 // 17
        "  server s 127.0.0.1:9",
        "",
    ]
    .join("\n");
    let c = parse_config(&text).unwrap_or_else(|e| panic!("{e}"));
    let fe = &c.frontends[0];
    assert_eq!(fe.tcp_req_content_rules[0].line, 8);
    assert_eq!(fe.http_req_rules.iter().map(|r| r.line).collect::<Vec<_>>(), [9, 11]);
    let be = &c.backends[0];
    assert_eq!(be.tcp_res_content_rules[0].line, 14);
    assert_eq!(be.http_res_rules.iter().map(|r| r.line).collect::<Vec<_>>(), [15, 16, 17]);
}

#[test]
fn a_rule_inherited_from_defaults_keeps_the_line_it_was_written_on() {
    let text = [
        "defaults d",
        "  mode http",
        "  timeout connect 1s",
        "  timeout client 5s",
        "  timeout server 5s",
        "  http-request deny if FALSE",
        "frontend fe from d",
        "  bind 127.0.0.1:8080",
        "  default_backend be",
        "backend be",
        "  server s 127.0.0.1:9",
        "",
    ]
    .join("\n");
    let c = parse_config(&text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(c.frontends[0].http_req_rules[0].line, 6);
}

#[test]
fn every_http_request_action_knows_its_own_line() {
    let rules = [
        "http-request replace-path (.*) \\1",
        "http-request set-pathq /x",
        "http-request replace-pathq a b",
        "http-request set-query x=1",
        "http-request unset-var(txn.a)",
        "http-request set-timeout client 5s",
    ];
    let text = cfg("").replace("    default_backend be\n", &format!("    {}\n    default_backend be\n", rules.join("\n    ")));
    let c = parse_config(&text).unwrap_or_else(|e| panic!("{e}"));
    // `cfg` puts the frontend's first rule on line 9.
    let lines: Vec<u32> = c.frontends[0].http_req_rules.iter().map(|r| r.line).collect();
    assert_eq!(lines, [9, 10, 11, 12, 13, 14]);
}
