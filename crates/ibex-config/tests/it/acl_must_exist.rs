// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A condition that names an ACL which does not exist is refused at load, with the text
//! `haproxy -c` (3.5-dev8) gives for each kind of rule, measured 2026-10-18 (T430 row 1).

use ibex_config::parse_str;

const HEAD: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

fn err(body: &str) -> (usize, String) {
    match parse_str(&format!("{HEAD}{body}")) {
        Err(e) => (e.line, e.message),
        Ok(_) => (0, "LOADED".to_string()),
    }
}

fn ok(body: &str) {
    parse_str(&format!("{HEAD}{body}")).unwrap_or_else(|e| panic!("{body}: {}", e.message));
}

#[test]
fn each_rule_kind_refuses_an_unknown_acl_with_its_own_text() {
    let fe = "frontend f\n  bind :8080\n";
    let be = "backend b\n  server s 127.0.0.1:1\n";
    let sw = "error detected while parsing switching rule : no such ACL : 'nosuch'.";
    let cases: Vec<(String, &str, String)> = vec![
        (format!("{be}{fe}  use_backend b if nosuch\n"), "", sw.into()),
        (format!("{be}  use-server s if nosuch\n"), "", sw.into()),
        (format!("{fe}  http-request deny if nosuch\n"), "", "error detected while parsing an 'http-request deny' condition : no such ACL : 'nosuch'.".into()),
        (format!("{fe}  http-request deny unless !nosuch\n"), "", "error detected while parsing an 'http-request deny' condition : no such ACL : 'nosuch'.".into()),
        (format!("{fe}  http-request set-var(txn.x) str(a) if nosuch\n"), "", "error detected while parsing an 'http-request set-var(txn.x)' condition : no such ACL : 'nosuch'.".into()),
        (format!("{be}  http-response deny if nosuch\n"), "", "error detected while parsing an 'http-response deny' condition : no such ACL : 'nosuch'.".into()),
        (format!("{be}  http-after-response set-header x y if nosuch\n"), "", "error detected while parsing an 'http-after-response set-header' condition : no such ACL : 'nosuch'.".into()),
        (format!("{fe}  tcp-request connection reject if nosuch\n"), "", "'tcp-request connection reject' : error detected in frontend 'f' while parsing 'if' condition : no such ACL : 'nosuch'".into()),
        (format!("{fe}  tcp-request session reject if nosuch\n"), "", "'tcp-request session reject' : error detected in frontend 'f' while parsing 'if' condition : no such ACL : 'nosuch'".into()),
        (format!("{fe}  tcp-request content reject if nosuch\n"), "", "'tcp-request content reject' : error detected in frontend 'f' while parsing 'if' condition : no such ACL : 'nosuch'".into()),
        (format!("{be}  tcp-request content accept if nosuch\n"), "", "'tcp-request content accept' : error detected in backend 'b' while parsing 'if' condition : no such ACL : 'nosuch'".into()),
        (format!("{be}  tcp-response content reject if nosuch\n"), "", "'tcp-response content reject' : error detected in backend 'b' while parsing 'if' condition : no such ACL : 'nosuch'".into()),
        (format!("listen l\n  bind :8080\n  tcp-request content reject if nosuch\n"), "", "'tcp-request content reject' : error detected in proxy 'l' while parsing 'if' condition : no such ACL : 'nosuch'".into()),
        (format!("{be}  http-request redirect location /x if nosuch\n"), "", "error detected in backend 'b' while parsing 'http-request redirect' rule : error in condition: no such ACL : 'nosuch'.".into()),
        (format!("{fe}  monitor-uri /m\n  monitor fail if nosuch\n"), "", "error detected while parsing a 'monitor fail' condition : no such ACL : 'nosuch'.".into()),
        (format!("{be}  stick-table type ip size 1k\n  stick on src if nosuch\n"), "", "'stick': error detected while parsing sticking condition : no such ACL : 'nosuch'.".into()),
        (format!("{be}  stick-table type ip size 1k\n  stick match src if nosuch\n"), "", "'stick': error detected while parsing sticking condition : no such ACL : 'nosuch'.".into()),
        (format!("{be}  stick-table type ip size 1k\n  stick store-request src if nosuch\n"), "", "'stick': error detected while parsing sticking condition : no such ACL : 'nosuch'.".into()),
        (format!("{fe}  force-be-switch if nosuch\n"), "", "'force-be-switch' : no such ACL : 'nosuch'.".into()),
        (format!("listen l\n  bind :8080\n  stats enable\n  stats admin if nosuch\n"), "", "error detected while parsing a 'stats admin' rule : no such ACL : 'nosuch'.".into()),
    ];
    let mut bad = Vec::new();
    for (body, _, want) in &cases {
        let (_, got) = err(body);
        if &got != want {
            bad.push(format!("{body}\n  want: {want}\n  got:  {got}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn the_error_is_on_the_line_of_the_rule() {
    let (line, _) = err("backend b\n  server s 127.0.0.1:1\nfrontend f\n  bind :8080\n  use_backend b if nosuch\n");
    assert_eq!(line, 10);
}

#[test]
fn the_first_unknown_term_is_named() {
    let (_, m) = err("frontend f\n  bind :8080\n  acl x path /x\n  http-request deny if x nosuch1 nosuch2\n");
    assert!(m.ends_with("no such ACL : 'nosuch1'."), "{m}");
    let (_, m) = err("frontend f\n  bind :8080\n  http-request deny if { path /x } nosuch || TRUE\n");
    assert!(m.ends_with("no such ACL : 'nosuch'."), "{m}");
}

#[test]
fn predefined_declared_and_anonymous_acls_are_valid() {
    ok("backend b\n  server s 127.0.0.1:1\nfrontend f\n  bind :8080\n  acl x path /x\n  acl nosuch path /y\n  http-request deny if x !nosuch\n  http-request deny if TRUE FALSE LOCALHOST HTTP HTTP_1.0 HTTP_1.1 HTTP_2.0 HTTP_3.0 METH_CONNECT METH_DELETE METH_GET METH_HEAD METH_OPTIONS METH_POST METH_PUT METH_TRACE HTTP_URL_ABS HTTP_URL_SLASH HTTP_URL_STAR HTTP_CONTENT RDP_COOKIE REQ_CONTENT WAIT_END\n  use_backend b if { path /x } || x\n  default_backend b\n");
}

#[test]
fn an_acl_is_known_only_after_its_line_and_only_in_its_own_section() {
    // later in the same section: refused
    let (line, m) = err("frontend f\n  bind :8080\n  http-request deny if later\n  acl later path /x\n");
    assert_eq!(line, 8);
    assert!(m.ends_with("no such ACL : 'later'."), "{m}");
    // a frontend's ACL in a backend: refused
    let (_, m) = err("backend b\n  server s 127.0.0.1:1\n  http-request deny if fa\nfrontend f\n  bind :8080\n  acl fa path /x\n");
    assert!(m.ends_with("no such ACL : 'fa'."), "{m}");
    let (_, m) = err("backend b\n  server s 127.0.0.1:1\nfrontend f\n  bind :8080\n  acl fa path /x\nbackend c\n  http-request deny if fa\n");
    assert!(m.ends_with("no such ACL : 'fa'."), "{m}");
}

/// `stats http-request <action> if <cond>` is worded as the proxy's own `http-request` rule
/// (3.5-dev8: "an 'http-request auth' condition"), `stats admin` as a 'stats admin' rule.
#[test]
fn stats_rules_refuse_an_unknown_acl_with_haproxys_text() {
    let fe = "frontend f\n  bind :8080\n  stats uri /st\n";
    for (rule, text) in [
        ("stats http-request deny if nosuch", "error detected while parsing an 'http-request deny' condition : no such ACL : 'nosuch'."),
        ("stats http-request auth if nosuch", "error detected while parsing an 'http-request auth' condition : no such ACL : 'nosuch'."),
        ("stats http-request allow if nosuch", "error detected while parsing an 'http-request allow' condition : no such ACL : 'nosuch'."),
        ("stats admin if nosuch", "error detected while parsing a 'stats admin' rule : no such ACL : 'nosuch'."),
    ] {
        assert_eq!(err(&format!("{fe}  {rule}\n")).1, text, "{rule}");
    }
}
