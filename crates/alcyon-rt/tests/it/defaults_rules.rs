// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Where a `defaults` section may hold TCP/HTTP rules, and who may inherit them.
//!
//! `HAProxy` 3.5-dev8-885761-29, 2026-10-03, `haproxy -c -f` on each of these (the sections
//! carry `mode http` and the three timeouts; `rule` is `http-request deny` unless noted):
//!
//! * an **unnamed** `defaults` with `http-request`, `http-response` or `http-after-response`
//!   exits 1 with `'<keyword>' not allowed in anonymous 'defaults' section.`, and with
//!   `tcp-request connection|session|content` with `tcp-request <sub> is not allowed in
//!   anonymous 'defaults' sections`; `http-error`, `http-check send` and `option httpchk`
//!   there are accepted;
//! * a **named** `defaults d` holding rules (`proxy_ref_defaults`, `src/proxy.c`):
//!   one frontend `from d` is accepted, two frontends are, two backends are;
//!   a frontend and a backend (or a listen) both `from d` exits 1 with `frontends and
//!   backends cannot inherit from the same defaults section if it defines TCP/HTTP rules`;
//!   a `listen from d` exits 1 with `a listen section cannot inherit from a defaults section
//!   defining TCP/HTTP rules`; another `defaults d2 from d` exits 1 with `a defaults section
//!   cannot inherit from a defaults section defining TCP/HTTP rules`; a backend from a
//!   `defaults` with `tcp-request connection|session` exits 1 with `a backend section cannot
//!   inherit from a defaults section defining 'tcp-request connection' or 'tcp-request
//!   session' rules`; a frontend from one with `tcp-response content` exits 1 with `a
//!   frontend section cannot inherit from a defaults section defining 'tcp-response content'
//!   rules`;
//! * a named `defaults` with **no** rule is inherited by anything.
//!
//! Alcyon accepted every refused case: it copies the defaults into each section, so the rule
//! ran in a section `HAProxy` would not have given it.

use std::process::Command;

const TIMEOUTS: &str = "  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

/// `alcyon -c -f <cfg>`: (exit code, stdout + stderr).
fn check(i: usize, cfg: &str) -> (Option<i32>, String) {
    let p = std::env::temp_dir().join(format!("alcyon_defrules_{}_{i}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&p).output().expect("run alcyon -c");
    let _ = std::fs::remove_file(&p);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn fe(name: &str, from: &str, port: u16) -> String {
    format!("frontend {name}{from}\n  bind 127.0.0.1:{port}\n")
}

/// `(configuration, text the error must contain)`; `None` for a configuration both accept.
fn cases() -> Vec<(String, Option<&'static str>)> {
    let anon = |rule: &str, rest: &str| format!("defaults\n{TIMEOUTS}  {rule}\n{rest}");
    let named = |rule: &str, rest: &str| format!("defaults d\n{TIMEOUTS}  {rule}\n{rest}");
    let fe1 = fe("fe", "", 1);
    let fe_d = fe("fe", " from d", 1);
    vec![
        // An unnamed defaults holds no rules.
        (anon("http-request deny", &fe1), Some("'http-request' not allowed in anonymous 'defaults' section.")),
        (anon("http-response set-header x y", &fe1), Some("'http-response' not allowed in anonymous 'defaults' section.")),
        (anon("http-after-response set-header x y", &fe1), Some("'http-after-response' not allowed in anonymous 'defaults' section.")),
        (anon("tcp-request content accept", &fe1), Some("tcp-request content is not allowed in anonymous 'defaults' sections")),
        (anon("tcp-request connection accept", &fe1), Some("tcp-request connection is not allowed in anonymous 'defaults' sections")),
        (anon("tcp-request session accept", &fe1), Some("tcp-request session is not allowed in anonymous 'defaults' sections")),
        (anon("http-error status 503 content-type text/plain string x", &fe1), None),
        (anon("option httpchk\n  http-check send hdr x y", "backend be\n  server s 127.0.0.1:1 check\n"), None),
        // A named one is inherited by one kind of section.
        (named("http-request deny", &fe_d), None),
        (named("http-request deny", &format!("{}{}", fe("fe", " from d", 1), fe("fe2", " from d", 2))), None),
        (named("http-request deny", "backend be from d\nbackend be2 from d\n"), None),
        (named("http-request deny", &format!("{fe_d}backend be from d\n")), Some("frontends and backends cannot inherit from the same defaults section if it defines TCP/HTTP rules")),
        (named("http-request deny", &format!("backend be from d\n{}", fe("fe", " from d", 1))), Some("frontends and backends cannot inherit from the same defaults section if it defines TCP/HTTP rules")),
        (named("tcp-request content accept", &format!("{fe_d}backend be from d\n")), Some("frontends and backends cannot inherit from the same defaults section if it defines TCP/HTTP rules")),
        (named("http-response set-header x y", &format!("{fe_d}backend be from d\n")), Some("frontends and backends cannot inherit from the same defaults section if it defines TCP/HTTP rules")),
        (named("http-request deny", "listen li from d\n  bind 127.0.0.1:2\n"), Some("a listen section cannot inherit from a defaults section defining TCP/HTTP rules")),
        (named("http-request deny", &format!("defaults d2 from d\n{TIMEOUTS}{}", fe("fe", " from d2", 1))), Some("a defaults section cannot inherit from a defaults section defining TCP/HTTP rules")),
        (named("tcp-request connection accept", "backend be from d\n"), Some("a backend section cannot inherit from a defaults section defining 'tcp-request connection' or 'tcp-request session' rules")),
        (named("tcp-request session accept", "backend be from d\n"), Some("a backend section cannot inherit from a defaults section defining 'tcp-request connection' or 'tcp-request session' rules")),
        (named("tcp-request connection accept", &fe_d), None),
        // A named defaults without rules is inherited by anything.
        (named("option httplog", &format!("{fe_d}backend be from d\nlisten li from d\n  bind 127.0.0.1:2\ndefaults d2 from d\n{TIMEOUTS}")), None),
    ]
}

#[test]
fn defaults_rules_are_refused_where_haproxy_refuses_them() {
    let mut wrong = Vec::new();
    for (i, (cfg, want)) in cases().iter().enumerate() {
        let (code, text) = check(i, cfg);
        match want {
            Some(w) if code != Some(1) || !text.contains(w) => {
                wrong.push(format!("case {i}: exit {code:?}, wanted 1 and {w:?}; got {text:?}\n{cfg}"));
            }
            None if code != Some(0) => wrong.push(format!("case {i}: exit {code:?}, wanted 0; got {text:?}\n{cfg}")),
            _ => {}
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ from HAProxy:\n{}", wrong.len(), cases().len(), wrong.join("\n"));
}

/// The tcp-response case needs a backend-only defaults: `tcp-response content` is the one
/// rule a backend may inherit and a frontend may not.
#[test]
fn a_frontend_cannot_inherit_tcp_response_content_rules() {
    let cfg = format!(
        "defaults d\n{TIMEOUTS}  tcp-response content accept\n{}",
        fe("fe", " from d", 1)
    );
    let (code, text) = check(100, &cfg);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("a frontend section cannot inherit from a defaults section defining 'tcp-response content' rules"),
        "{text}"
    );
    let ok = format!("defaults d\n{TIMEOUTS}  tcp-response content accept\nbackend be from d\n");
    let (code, text) = check(101, &ok);
    assert_eq!(code, Some(0), "{text}");
}

/// `http-check send` in a `defaults` section, whose `%[...]` arguments name backends and
/// servers that must exist.
///
/// `HAProxy`, same version and date: in an **unnamed** `defaults` they are resolved only when a
/// backend inherits the check -- a `backend` after it, and the section having `option
/// httpchk`, whether or not the backend has a `check` server -- and then refused with the
/// defaults section's own line (`unable to find backend 'nope' referenced in arg 1 of ACL
/// keyword 'nbsrv' in proxy ''`); `srv_is_up(s)` there is `backend name must be set`. In a
/// **named** one they are resolved always (`... in proxy 'd'`), used or not. Alcyon refused
/// the unnamed ones whatever followed.
#[test]
fn defaults_http_check_send_is_resolved_where_a_backend_inherits_it() {
    let chk = |send: &str, rest: &str| format!("defaults\n{TIMEOUTS}  option httpchk\n  http-check send hdr x {send}\n{rest}");
    let be = "backend be\n  server s 127.0.0.1:1 check\n";
    let nope = "unable to find backend 'nope'";
    let cases: Vec<(String, Option<&str>)> = vec![
        (chk("%[nbsrv(nope)]", ""), None),
        (chk("%[nbsrv(nope)]", &fe("fe", "", 1)), None),
        (chk("%[nbsrv(nope)]", be), Some(nope)),
        (chk("%[nbsrv(nope)]", "backend be\n  server s 127.0.0.1:1\n"), Some(nope)),
        (chk("%[nbsrv(nope)]", "listen li\n  bind 127.0.0.1:2\n  server s 127.0.0.1:1 check\n"), None),
        (
            // Without `option httpchk` the rules never reach the backend.
            format!("defaults\n{TIMEOUTS}  http-check send hdr x %[nbsrv(nope)]\n{be}"),
            None,
        ),
        (chk("%[nbsrv(be)]", be), None),
        (chk("%[nbsrv]", be), None),
        (chk("%[srv_is_up(s)]", be), Some("backend name must be set")),
        (chk("%[srv_is_up(be/s)]", be), None),
        (
            format!("defaults d\n{TIMEOUTS}  option httpchk\n  http-check send hdr x %[nbsrv(nope)]\n{be}"),
            Some(nope),
        ),
        (
            format!("defaults d\n{TIMEOUTS}  option httpchk\n  http-check send hdr x %[nbsrv(nope)]\nbackend be from d\n  server s 127.0.0.1:1 check\n"),
            Some(nope),
        ),
        (
            format!("defaults\n{TIMEOUTS}backend be\n  option httpchk\n  http-check send hdr x %[nbsrv(nope)]\n  server s 127.0.0.1:1 check\n"),
            Some(nope),
        ),
    ];
    let mut wrong = Vec::new();
    for (i, (cfg, want)) in cases.iter().enumerate() {
        let (code, text) = check(200 + i, cfg);
        match want {
            Some(w) if code != Some(1) || !text.contains(w) => {
                wrong.push(format!("case {i}: exit {code:?}, wanted 1 and {w:?}; got {text:?}\n{cfg}"));
            }
            None if code != Some(0) => wrong.push(format!("case {i}: exit {code:?}, wanted 0; got {text:?}\n{cfg}")),
            _ => {}
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ from HAProxy:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
}
