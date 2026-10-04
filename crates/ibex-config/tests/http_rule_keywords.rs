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

fn with_userlist(body: &str) -> Result<ibex_config::Config, String> {
    parse_config(&format!(
        "userlist ul\n{body}\ndefaults\n    mode http\n    timeout client 5s\nfrontend fe\n    bind 127.0.0.1:8080\n    http-request return status 200\n"
    ))
    .map_err(|e| e.to_string())
}

#[test]
fn a_userlist_resolves_its_groups_both_ways() {
    let c = with_userlist(
        "    group admins users u1\n    group dev\n    user u1 insecure-password pass1 groups dev\n    \
         user u2 insecure-password pass2 groups admins,dev\n    user u3",
    )
    .expect("accepted");
    let ul = &c.userlists[0];
    assert_eq!(ul.name, "ul");
    let by = |n: &str| ul.users.iter().find(|u| u.name == n).expect(n).clone();
    assert_eq!(by("u1").groups, ["dev", "admins"]);
    assert_eq!(by("u2").groups, ["admins", "dev"]);
    assert_eq!(by("u2").password.as_deref(), Some("pass2"));
    assert_eq!((by("u3").password, by("u3").groups), (None, Vec::<String>::new()));
}

#[test]
fn the_userlist_lines_haproxy_refuses_are_refused_with_its_messages() {
    for (body, want) in [
        ("    user", "'user' expects <name> as arguments."),
        ("    group", "'group' expects <name> as arguments."),
        ("    group a,b", "character ',' is not permitted in 'group' name 'a,b'."),
        ("    user u1 insecure-password p extra", "'user' only supports 'password', 'insecure-password' and 'groups' options."),
        ("    bogus x", "unknown keyword 'bogus' in 'userlist' section"),
        ("    user u1 groups g", "userlist 'ul': no such group 'g' specified in user 'u1'"),
        ("    group g users nou", "userlist 'ul': no such user 'nou' specified in group 'g'"),
        // A crypt(3) hash cannot be checked by Ibex: refused rather than never matching.
        ("    user u1 password $5$salt$abc", "not supported"),
    ] {
        let err = with_userlist(body).expect_err(body);
        assert!(err.contains(want), "{body}: {err}");
    }
    // A duplicate is ignored (HAProxy warns), the first one stays.
    let c = with_userlist("    user u1 insecure-password a\n    user u1 insecure-password b").expect("accepted");
    assert_eq!(c.userlists[0].users.len(), 1);
    assert_eq!(c.userlists[0].users[0].password.as_deref(), Some("a"));
}

#[test]
fn the_auth_action_takes_a_realm() {
    let c = parse_config(&cfg("frontend", "http-request auth realm \"my realm\" if TRUE")).expect("accepted");
    assert!(matches!(&c.frontends[0].http_req_rules[0].action, HttpReqAction::Auth { realm: Some(r) } if r == "my realm"));
    let c = parse_config(&cfg("frontend", "http-request auth")).expect("accepted");
    assert!(matches!(&c.frontends[0].http_req_rules[0].action, HttpReqAction::Auth { realm: None }));
    for (line, want) in [
        ("http-request auth realm", "missing realm value."),
        ("http-request auth foo", "expects either 'if' or 'unless' followed by a condition but found 'foo'"),
        ("http-request auth realm a b", "found 'b'"),
    ] {
        let err = parse_config(&cfg("frontend", line)).expect_err(line).to_string();
        assert!(err.contains(want), "{line}: {err}");
    }
}
