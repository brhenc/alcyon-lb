// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What `alcyon -c` refuses among the fetches and converters that read proxy, server, queue
//! and stick-table state.
//!
//! Two kinds of refusal:
//!
//! * **`HAProxy` refuses it too.** A backend, server or table argument that names nothing
//!   is resolved when the configuration loads (`smp_resolve_args`, `src/sample.c`), not
//!   per request. Measured on 2026-10-03 with `haproxy -c -f` (`HAProxy`
//!   3.5-dev8-885761-29) on [`config`] carrying each rule: every `ARG_REFUSED` rule exits 1
//!   with the quoted text in its message (for example `unable to find server 'zz' in proxy
//!   'be', referenced in arg 1 of sample fetch keyword 'srv_is_up' ...`), and every
//!   `ACCEPTED` rule exits 0. `src_trackers` and `src_in_table` are not `HAProxy` fetches
//!   ("unknown fetch method").
//! * **Alcyon has not implemented it.** `HAProxy` accepts every `NOT_IMPLEMENTED` rule (exit
//!   0, same measurement). Alcyon has no server queues, does not count a backend's streams,
//!   keeps no tracker count on a stick-table entry, and has only the `table_*` converters that read a counter. These
//!   used to load and evaluate to a constant 0 or 1. They are refused now, naming what is
//!   missing, wherever the expression appears: an ACL, an inline condition, a log-format,
//!   a rule action, `http-check send`.

use std::process::Command;

fn alcyon_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_alcyon"))
}

/// A configuration with `fe_rule` in frontend `fe` and `be_rule` in backend `be`.
fn config(fe_rule: &str, be_rule: &str) -> String {
    format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         frontend fe\n  bind 127.0.0.1:1\n  {fe_rule}\n  default_backend be\n\
         backend be\n  stick-table type ip size 10 store gpt0\n  {be_rule}\n  server s1 127.0.0.1:1\n"
    )
}

/// `alcyon -c -f <cfg>`: (exit code, stdout + stderr).
fn check(i: usize, cfg: &str) -> (Option<i32>, String) {
    let p = std::env::temp_dir().join(format!("alcyon_srvstate_{}_{i}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let out = Command::new(alcyon_bin()).arg("-c").arg("-f").arg(&p).output().expect("run alcyon -c");
    let _ = std::fs::remove_file(&p);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// `(frontend rule, backend rule, text the error must contain)`.
const ARG_REFUSED: &[(&str, &str, &str)] = &[
    ("http-request set-header x %[nbsrv(nope)]", "", "unable to find backend 'nope'"),
    ("http-request set-header x %[nbsrv]", "", "proxy 'fe', referenced in arg 1 of sample fetch keyword 'nbsrv'"),
    ("http-request set-header x %[srv_is_up(nope/s1)]", "", "unable to find proxy 'nope'"),
    ("http-request set-header x %[srv_is_up(be/zz)]", "", "unable to find server 'zz' in proxy 'be'"),
    ("http-request set-header x %[srv_is_up(s1)]", "", "unable to find server 's1' in proxy 'fe'"),
    ("use_backend be if { nbsrv(nope) lt 1 }", "", "unable to find backend 'nope'"),
    ("acl a srv_is_up(be/zz)\n  http-request deny if a", "", "unable to find server 'zz' in proxy 'be'"),
    ("http-request set-header x %[srv_conn]", "", "missing server name in arg 1 of sample fetch keyword 'srv_conn'"),
    ("http-request set-header x %[src,in_table(nope)]", "", "unable to find table 'nope'"),
    ("http-request set-header x %[src,in_table]", "", "unable to find table 'fe'"),
    ("", "unique-id-format %[srv_is_up(zz)]", "unable to find server 'zz' in proxy 'be'"),
    ("", "option httpchk\n  http-check send hdr x %[nbsrv(nope)]", "unable to find backend 'nope'"),
    ("http-request set-var(txn.x) nbsrv(nope)", "", "unable to find backend 'nope'"),
    ("http-request set-header x %[be_conn_free(nope)]", "", "unable to find backend 'nope'"),
    ("http-request set-header x %[srv_conn_free(be/zz)]", "", "unable to find server 'zz' in proxy 'be'"),
    // T139, measured: the array forms need the table (or the counter) argument, empty at most.
    ("http-request set-header x %[src_get_gpc(0)]", "", "missing arguments (got 1/2), type 'table' expected"),
    ("http-request set-header x %[src_inc_gpc(0)]", "", "missing arguments (got 1/2), type 'table' expected"),
    ("http-request set-header x %[sc_get_gpc(0)]", "", "missing arguments (got 1/2), type 'integer' expected"),
    ("http-request set-header x %[src,table_gpc(0)]", "", "invalid arg 2 in converter 'table_gpc' : missing arguments (got 1/2), type 'table' expected"),
    ("http-request set-header x %[src_trackers]", "", "unknown fetch method 'src_trackers'"),
    ("http-request set-header x %[src_in_table]", "", "unknown fetch method 'src_in_table'"),
];

/// The control: the same fetches with arguments that resolve.
const ACCEPTED: &[(&str, &str)] = &[
    ("http-request set-header x %[nbsrv(be)]", ""),
    ("http-request set-header x %[srv_is_up(be/s1)]", ""),
    ("http-request set-header x %[str(x),nbsrv]", ""),
    ("use_backend be if { nbsrv(be) lt 1 }", ""),
    ("", "http-request set-header x %[nbsrv]"),
    ("", "http-request set-header x \"%[srv_is_up(s1)] %[srv_conn(s1)] %[srv_conn_free(s1)] %[be_conn_free]\""),
    ("http-request set-header x %[src,in_table(be)]", ""),
    ("http-request set-var(txn.x) nbsrv(be)", ""),
    ("", "unique-id-format %[srv_is_up(s1)]\n  option httpchk\n  http-check send hdr x %[unique-id]"),
    ("http-request set-header x %[str(fe),fe_exists]", ""),
    // Implemented by T139 (they were refused: "Alcyon keeps no tracker count", and so on).
    ("http-request set-header x %[sc_trackers(0)]", ""),
    ("http-request set-header x %[src,table_server_id(be)]", ""),
    ("http-request set-header x %[src,table_expire(be)]", ""),
    ("http-request set-header x %[src,table_inc_gpc0(be)]", ""),
    ("http-request set-header x %[src,table_bytes_in_rate(be)]", ""),
];

/// `(frontend rule, backend rule, the keyword the error must name)`.
const NOT_IMPLEMENTED: &[(&str, &str, &str)] = &[
    ("use_backend be if { queue(be) gt 1 }", "", "queue"),
    ("acl q avg_queue(be) gt 1\n  use_backend be if q", "", "avg_queue"),
    ("http-request set-header x %[srv_queue(be/s1)]", "", "srv_queue"),
    ("http-request set-header x %[str(be/s1),srv_queue]", "", "srv_queue"),
    ("http-request set-var(txn.x) be_conn(be)", "", "be_conn"),
    ("http-request set-var(txn.x) str(be/s1),srv_queue", "", "srv_queue"),
    ("", "http-request set-header x %[be_conn]", "be_conn"),
    ("", "option httpchk\n  http-check send hdr x %[queue]", "queue"),
];

#[test]
fn alcyon_c_resolves_backend_server_and_table_arguments_as_haproxy_does() {
    let mut wrong = Vec::new();
    for (i, &(fe, be, want)) in ARG_REFUSED.iter().enumerate() {
        let (code, text) = check(i, &config(fe, be));
        if code != Some(1) || !text.contains(want) {
            wrong.push(format!("fe `{fe}` be `{be}`: exit {code:?}, wanted 1 and {want:?}; got {text:?}"));
        }
    }
    for (i, &(fe, be)) in ACCEPTED.iter().enumerate() {
        let (code, text) = check(100 + i, &config(fe, be));
        if code != Some(0) {
            wrong.push(format!("control fe `{fe}` be `{be}`: exit {code:?}, wanted 0; got {text:?}"));
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ from HAProxy:\n{}", wrong.len(), ARG_REFUSED.len() + ACCEPTED.len(), wrong.join("\n"));
}

#[test]
fn alcyon_c_refuses_what_alcyon_does_not_implement_instead_of_returning_a_constant() {
    let mut wrong = Vec::new();
    for (i, &(fe, be, kw)) in NOT_IMPLEMENTED.iter().enumerate() {
        let (code, text) = check(200 + i, &config(fe, be));
        if code != Some(1) || !text.contains(&format!("'{kw}'")) || !text.contains("not implemented in Alcyon") {
            wrong.push(format!("fe `{fe}` be `{be}`: exit {code:?}, wanted 1 naming '{kw}' as not implemented in Alcyon; got {text:?}"));
        }
    }
    assert!(wrong.is_empty(), "{} of {} loaded, or were refused without saying why:\n{}", wrong.len(), NOT_IMPLEMENTED.len(), wrong.join("\n"));
}

/// The timeouts every configuration below starts its sections with.
const TIMEOUTS: &str = "  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n";

/// A `defaults` section `d` holding `rule`, a backend `be from d` with servers `servers`,
/// and an anonymous `defaults` for a frontend.
fn named_defaults(rule: &str, servers: &str) -> String {
    format!(
        "defaults d\n{TIMEOUTS}  {rule}\ndefaults\n{TIMEOUTS}frontend fe\n  bind 127.0.0.1:1\n  default_backend be\n\
         backend be from d\n  stick-table type ip size 10\n  {servers}\n"
    )
}

/// An anonymous `defaults` holding `directive`, inherited by `frontend fe` and `backend be`
/// (server `s1`).
fn anonymous_defaults(directive: &str) -> String {
    format!(
        "defaults\n{TIMEOUTS}  {directive}\nfrontend fe\n  bind 127.0.0.1:1\n  default_backend be\n\
         backend be\n  stick-table type ip size 10\n  server s1 127.0.0.1:1 check\n"
    )
}

/// The same, inherited by `listen li` (server `s1`) and `backend be` (server `s2`).
fn listen_defaults(directive: &str) -> String {
    format!(
        "defaults\n{TIMEOUTS}  {directive}\nlisten li\n  bind 127.0.0.1:1\n  server s1 127.0.0.1:1\n\
         backend be\n  server s2 127.0.0.1:1\n"
    )
}

/// An expression written in a `defaults` section. `HAProxy` resolves a rule's (and an
/// `http-check send`'s) in the defaults section itself, where there is no current proxy to
/// default an omitted argument to: a server without its backend and an omitted table are
/// refused, an omitted backend is not. A `unique-id-format` or `log-format` is resolved in
/// each proxy that inherits it, as if written there; a backend does not compile a
/// `log-format`.
///
/// Measured with `haproxy -c -f` on each configuration, `HAProxy` 3.5-dev8-885761-29,
/// 2026-10-03. Refused (exit 1), with the message quoted:
///
/// ```text
/// named, http-request %[srv_is_up(s1)], be has s1  backend name must be set in arg 1 of sample
///                                                  fetch keyword 'srv_is_up' in http-request
///                                                  expression in proxy 'd'.
/// named, http-request %[src,in_table]              table name must be set in arg 1 of conversion
///                                                  keyword 'in_table' for sample fetch keyword 'src' ...
/// anon, option httpchk + http-check send hdr x %[srv_is_up(s1)], be has s1 with check
///                                                  backend name must be set in arg 1 of ACL keyword
///                                                  'srv_is_up' in proxy ''.
/// anon, unique-id-format %[srv_is_up(s1)]          unable to find server 's1' in proxy 'fe', ...
///                                                  in unique-id-format string in proxy 'fe'.
/// anon, unique-id-format %[nbsrv]                  proxy 'fe', referenced in arg 1 of sample fetch
///                                                  keyword 'nbsrv' ..., has not backend capability.
/// anon, unique-id-format %[src,in_table]           unable to find table 'fe' referenced in arg 1 ...
/// anon, log-format %[srv_is_up(s1)]                unable to find server 's1' in proxy 'fe', ...
/// named, unique-id-format %[srv_is_up(s1)], be has s2 only
///                                                  unable to find server 's1' in proxy 'be', ...
/// ```
///
/// Accepted (exit 0): named `http-request set-header x %[nbsrv]`; named
/// `unique-id-format %[srv_is_up(s1)]` with `be` having s1 (the frontend uses another
/// defaults); anonymous `unique-id-format %[srv_is_up(be/s1)]`; `unique-id-format %[nbsrv]`
/// inherited by a listen and a backend; `log-format %[srv_is_up(s1)]` inherited by a listen
/// with s1 and a backend without it; named rules with every argument given.
#[test]
fn alcyon_c_resolves_an_expression_in_defaults_where_haproxy_does() {
    let refused: &[(String, &str)] = &[
        (named_defaults("http-request set-header x %[srv_is_up(s1)]", "server s1 127.0.0.1:1"), "backend name must be set in arg 1 of sample fetch keyword 'srv_is_up'"),
        (named_defaults("http-request set-header x %[src,in_table]", "server s1 127.0.0.1:1"), "table name must be set in arg 1 of conversion keyword 'in_table'"),
        (anonymous_defaults("option httpchk\n  http-check send hdr x %[srv_is_up(s1)]"), "backend name must be set in arg 1 of"),
        (anonymous_defaults("unique-id-format %[srv_is_up(s1)]"), "unable to find server 's1' in proxy 'fe'"),
        (anonymous_defaults("unique-id-format %[nbsrv]"), "proxy 'fe', referenced in arg 1 of sample fetch keyword 'nbsrv'"),
        (anonymous_defaults("unique-id-format %[src,in_table]"), "unable to find table 'fe'"),
        (anonymous_defaults("log-format %[srv_is_up(s1)]"), "unable to find server 's1' in proxy 'fe'"),
        (named_defaults("unique-id-format %[srv_is_up(s1)]", "server s2 127.0.0.1:1"), "unable to find server 's1' in proxy 'be'"),
    ];
    let accepted: &[String] = &[
        named_defaults("http-request set-header x %[nbsrv]", "server s1 127.0.0.1:1"),
        named_defaults("unique-id-format %[srv_is_up(s1)]", "server s1 127.0.0.1:1"),
        anonymous_defaults("unique-id-format %[srv_is_up(be/s1)]"),
        listen_defaults("unique-id-format %[nbsrv]"),
        listen_defaults("log-format %[srv_is_up(s1)]"),
        named_defaults(
            "http-request set-header x %[srv_is_up(be/s1)]\n  http-request set-header y %[nbsrv(be)]\n  \
             http-request set-header z %[src,in_table(be)]",
            "server s1 127.0.0.1:1",
        ),
    ];
    let mut wrong = Vec::new();
    for (i, (cfg, want)) in refused.iter().enumerate() {
        let (code, text) = check(300 + i, cfg);
        if code != Some(1) || !text.contains(want) {
            wrong.push(format!("{cfg}=> exit {code:?}, wanted 1 and {want:?}; got {text:?}\n"));
        }
    }
    for (i, cfg) in accepted.iter().enumerate() {
        let (code, text) = check(400 + i, cfg);
        if code != Some(0) {
            wrong.push(format!("control {cfg}=> exit {code:?}, wanted 0; got {text:?}\n"));
        }
    }
    assert!(wrong.is_empty(), "{} of {} cases differ from HAProxy:\n{}", wrong.len(), refused.len() + accepted.len(), wrong.join("\n"));
}
