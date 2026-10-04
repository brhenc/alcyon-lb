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

fn forwarded(opt: &str) -> Result<Option<ibex_config::Forwarded>, String> {
    parse_config(&format!(
        "defaults\n    mode http\n    timeout client 5s\n    timeout connect 5s\n    timeout server 5s\n\
         backend be\n    {opt}\n    server s 127.0.0.1:9\n"
    ))
    .map(|c| c.backends[0].forwarded.clone().map(|f| *f))
    .map_err(|e| e.to_string())
}

#[test]
fn option_forwarded_keeps_the_parameters_it_names() {
    use ibex_config::ForwardedValue::{Default as Plain, Expr, Off};
    // No parameter is `proto for`.
    let f = forwarded("option forwarded").expect("accepted").expect("set");
    assert!(f.proto && f.for_ == Plain && f.host == Off && f.by == Off && f.by_port == Off && f.for_port == Off);
    // Parameters replace that default, a later form of the same parameter wins.
    let f = forwarded("option forwarded for-expr src for_port-expr str(id) by by_port-expr int(10)").expect("accepted").expect("set");
    assert!(!f.proto);
    assert_eq!((f.for_, f.for_port, f.by, f.by_port), (Expr("src".into()), Expr("str(id)".into()), Plain, Expr("int(10)".into())));
    let f = forwarded("option forwarded for-expr str(abc) for").expect("accepted").expect("set");
    assert_eq!(f.for_, Plain);
    let f = forwarded("option forwarded host-expr str(override)").expect("accepted").expect("set");
    assert_eq!((f.proto, f.host, f.for_), (false, Expr("str(override)".into()), Off));
    // `no option forwarded` turns off what `defaults` set.
    let c = parse_config(
        "defaults\n    mode http\n    timeout client 5s\n    timeout connect 5s\n    timeout server 5s\n    option forwarded\n\
         backend a\n    server s 127.0.0.1:9\nbackend b\n    no option forwarded\n    server s 127.0.0.1:9\n",
    )
    .expect("accepted");
    assert!(c.backends[0].forwarded.is_some());
    assert!(c.backends[1].forwarded.is_none());
}

#[test]
fn option_forwarded_refusals_are_haproxys() {
    let list = "'option forwarded' only supports optional values: 'proto', 'host', 'host-expr', 'by', 'by-expr', \
                'by_port', 'by_port-expr', 'for', 'for-expr', 'for_port' and 'for_port-expr'.";
    for (line, want) in [
        ("option forwarded for-expr", "'for-expr' expects <expr> as argument."),
        ("option forwarded bogus", list),
        ("option forwarded proto-expr str(a)", list),
        ("option forwarded for-expr str(a) bogus", list),
    ] {
        let err = forwarded(line).expect_err(line);
        assert!(err.contains(want), "{line}: {err}");
    }
}

#[test]
fn errorloc_and_replace_uri_refusals() {
    for (line, want) in [
        ("errorloc 503", "errorloc : expects <status_code> and <url> as arguments."),
        ("errorloc 503 /x extra", "errorloc : expects exactly two arguments."),
        ("errorloc 999 /x", "errorloc : status code '999' not handled."),
        ("errorloc302 abc /x", "errorloc302 : status code '0' not handled."),
        ("http-request replace-uri a", "expects <regex> and <replace>"),
    ] {
        let err = parse_config(&cfg("frontend", line)).expect_err(line).to_string();
        assert!(err.contains(want), "{line}: {err}");
    }
}

#[test]
fn replace_uri_without_a_condition() {
    let c = parse_config(&cfg("frontend", "http-request replace-uri ^/a /b")).expect("accepted");
    let rule = &c.frontends[0].http_req_rules[0];
    assert!(matches!(&rule.action, HttpReqAction::ReplaceUri { regex, repl } if regex == "^/a" && repl == "/b"));
    assert!(rule.cond.is_none());
}

#[test]
fn more_userlist_lines() {
    for (text, want) in [
        ("userlist\n  user a\n", "'userlist' expects <name> as arguments."),
        ("userlist ul\n  group g bogus\n", "'group' only supports 'users' option."),
    ] {
        let err = parse_config(text).expect_err(text).to_string();
        assert!(err.contains(want), "{text}: {err}");
    }
    // `users` with no list is accepted, as HAProxy accepts it.
    assert!(parse_config("userlist ul\n  group g users\n").is_ok());
    // A duplicate group is ignored (HAProxy warns), and so is a second userlist of a name.
    let c = parse_config("userlist ul\n  group g\n  group g\n  user a insecure-password x\nuserlist ul\n  user b\n").expect("accepted");
    assert_eq!(c.userlists.len(), 1);
    assert_eq!(c.userlists[0].groups, ["g"]);
    assert_eq!(c.userlists[0].users.len(), 1);
}
