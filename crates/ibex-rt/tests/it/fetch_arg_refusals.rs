// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! What `ibex -c` does with the arguments of `fe_conn`, `fe_sess_rate`, `fe_req_rate`,
//! `be_sess_rate`, `srv_sess_rate`, the `sc_*`, `sc[0-9]_*` and `src_*` fetches, and the
//! fetches `HAProxy` does not have.
//!
//! Measured on 2026-10-03 with `haproxy -c -f` (`HAProxy` 3.5-dev8-885761-29) on the same
//! [`config`] carrying each rule: every `ARG_REFUSED` rule exits 1 with the quoted text in
//! its message and every `ACCEPTED` rule exits 0. These were all accepted by Ibex, so a
//! `fe_conn(typo)` or an `src_conn_cnt(typo)` loaded and read something else.
//!
//! `err_cnt`, `err_rate`, `conn_cnt`, `conn_rate`, `cum_conn`, `req_cnt`, `req_rate`,
//! `sess_cnt` and `sess_rate` are not `HAProxy` fetches at all ("unknown fetch method"); Ibex
//! registered them and returned a field that nothing filled in.

use std::process::Command;

fn ibex_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_ibex"))
}

/// A configuration with `fe_rule` in frontend `fe` (which has no stick-table) and `be_rule`
/// in backend `be` (which has one); `lst` is a `listen`.
fn config(fe_rule: &str, be_rule: &str) -> String {
    format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout server 5s\n  timeout connect 5s\n\
         listen lst\n  bind 127.0.0.1:2\n  server s1 127.0.0.1:1\n\
         frontend fe\n  bind 127.0.0.1:1\n  {fe_rule}\n  default_backend be\n\
         backend be\n  stick-table type ip size 10 store conn_cnt,http_req_cnt\n  {be_rule}\n  server s1 127.0.0.1:1\n"
    )
}

/// `ibex -c -f <cfg>`: (exit code, stdout + stderr).
fn check(i: usize, cfg: &str) -> (Option<i32>, String) {
    let p = std::env::temp_dir().join(format!("ibex_fetchargs_{}_{i}.cfg", std::process::id()));
    std::fs::write(&p, cfg).expect("write config");
    let out = Command::new(ibex_bin()).arg("-c").arg("-f").arg(&p).output().expect("run ibex -c");
    let _ = std::fs::remove_file(&p);
    (out.status.code(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// `(frontend rule, backend rule, text the error must contain)`.
const ARG_REFUSED: &[(&str, &str, &str)] = &[
    ("http-request set-header x %[fe_conn(nope)]", "", "unable to find frontend 'nope' referenced in arg 1 of sample fetch keyword 'fe_conn'"),
    ("http-request set-header x %[fe_conn(be)]", "", "unable to find frontend 'be' referenced in arg 1 of sample fetch keyword 'fe_conn'"),
    ("", "http-request set-header x %[fe_conn]", "proxy 'be', referenced in arg 1 of sample fetch keyword 'fe_conn'"),
    ("", "http-request set-header x %[fe_sess_rate]", "proxy 'be', referenced in arg 1 of sample fetch keyword 'fe_sess_rate'"),
    ("http-request set-header x %[fe_req_rate(nope)]", "", "unable to find frontend 'nope' referenced in arg 1 of sample fetch keyword 'fe_req_rate'"),
    ("http-request set-header x %[be_sess_rate(fe)]", "", "unable to find backend 'fe' referenced in arg 1 of sample fetch keyword 'be_sess_rate'"),
    ("http-request set-header x %[be_sess_rate]", "", "proxy 'fe', referenced in arg 1 of sample fetch keyword 'be_sess_rate'"),
    ("http-request set-header x %[srv_sess_rate(be/nope)]", "", "unable to find server 'nope' in proxy 'be'"),
    ("http-request set-header x %[srv_sess_rate(s1)]", "", "unable to find server 's1' in proxy 'fe'"),
    ("http-request set-header x %[srv_sess_rate]", "", "missing server name in arg 1 of sample fetch keyword 'srv_sess_rate'"),
    ("http-request set-header x %[sc_conn_cnt(0,nope)]", "", "unable to find table 'nope' referenced in arg 2 of sample fetch keyword 'sc_conn_cnt'"),
    ("http-request set-header x %[sc0_conn_cnt(nope)]", "", "unable to find table 'nope' referenced in arg 1 of sample fetch keyword 'sc0_conn_cnt'"),
    ("http-request set-header x %[src_conn_cnt(nope)]", "", "unable to find table 'nope' referenced in arg 1 of sample fetch keyword 'src_conn_cnt'"),
    ("http-request set-header x %[src_http_req_cnt(fe)]", "", "unable to find table 'fe' referenced in arg 1 of sample fetch keyword 'src_http_req_cnt'"),
    ("http-request set-header x %[src_conn_cnt]", "", "unable to find table 'fe' referenced in arg 1 of sample fetch keyword 'src_conn_cnt'"),
    ("acl a src_conn_cnt(nope) gt 1\n  http-request deny if a", "", "unable to find table 'nope'"),
    ("http-request set-header x %[src,table_conn_cnt(nope)]", "", "unable to find table 'nope' referenced in arg 1 of conversion keyword 'table_conn_cnt'"),
    ("http-request set-header x %[src,table_gpc0]", "", "unable to find table 'fe' referenced in arg 1 of conversion keyword 'table_gpc0'"),
    ("http-request set-header x %[err_cnt]", "", "unknown fetch method 'err_cnt'"),
    ("http-request set-header x %[err_rate]", "", "unknown fetch method 'err_rate'"),
    ("http-request set-header x %[sess_rate]", "", "unknown fetch method 'sess_rate'"),
    ("http-request set-header x %[conn_rate]", "", "unknown fetch method 'conn_rate'"),
    ("http-request set-header x %[req_rate]", "", "unknown fetch method 'req_rate'"),
    ("http-request set-header x %[cum_conn]", "", "unknown fetch method 'cum_conn'"),
];

/// The control: the same fetches with arguments that resolve.
const ACCEPTED: &[(&str, &str)] = &[
    ("http-request set-header x %[fe_conn]", ""),
    ("http-request set-header x %[fe_conn(fe)]", ""),
    ("http-request set-header x \"%[fe_conn(lst)] %[fe_sess_rate(lst)] %[fe_req_rate(lst)]\"", ""),
    ("", "http-request set-header x \"%[fe_sess_rate(fe)] %[fe_req_rate(fe)]\""),
    ("http-request set-header x \"%[fe_sess_rate] %[fe_req_rate] %[fe_defbe]\"", ""),
    ("http-request set-header x \"%[be_sess_rate(be)] %[be_sess_rate(lst)]\"", ""),
    ("", "http-request set-header x %[be_sess_rate]"),
    ("http-request set-header x %[srv_sess_rate(be/s1)]", ""),
    ("", "http-request set-header x %[srv_sess_rate(s1)]"),
    ("http-request set-header x \"%[sc_conn_cnt(0)] %[sc_conn_cnt(0,be)] %[sc0_conn_cnt] %[sc1_conn_cnt(be)]\"", ""),
    ("http-request set-header x \"%[src_conn_cnt(be)] %[src_http_req_cnt(be)]\"", ""),
    ("", "http-request set-header x %[src_conn_cnt]"),
    ("acl a src_conn_cnt(be) gt 1\n  http-request deny if a", ""),
    ("http-request set-header x \"%[src,table_conn_cnt(be)] %[src,table_http_req_cnt(be)] %[src,table_gpc0(be)]\"", ""),
    ("", "http-request set-header x %[src,table_conn_cnt]"),
];

#[test]
fn ibex_c_resolves_the_arguments_of_the_counter_fetches_as_haproxy_does() {
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

/// T341: a fetch that names one backend, server, frontend or table takes nothing after it, and
/// `srv_id`/`srv_name` take nothing at all. `make_arg_list` stops at the last argument the
/// fetch has and refuses what follows. Measured on 3.5-dev8-885761-29, 2026-10-17, `haproxy -c`
/// with `http-request set-var(txn.r) <expr>` in frontend `fe`; all accepted by Ibex before.
#[test]
fn a_fetch_given_more_arguments_than_it_has_is_refused() {
    let refused: &[(&str, &str)] = &[
        ("srv_uweight(be/s1,x)", "fetch method 'srv_uweight' : expected ')' before ',x)'."),
        ("srv_iweight(be/s1,x)", "fetch method 'srv_iweight' : expected ')' before ',x)'."),
        ("srv_weight(be/s1,x)", "fetch method 'srv_weight' : expected ')' before ',x)'."),
        ("srv_conn(be/s1,x)", "fetch method 'srv_conn' : expected ')' before ',x)'."),
        ("srv_conn(be/s1,x,y)", "fetch method 'srv_conn' : expected ')' before ',x,y)'."),
        ("srv_conn(be/s1,)", "fetch method 'srv_conn' : expected ')' before ',)'."),
        ("srv_conn_free(be/s1,x)", "fetch method 'srv_conn_free' : expected ')' before ',x)'."),
        ("srv_is_up(be/s1,x)", "fetch method 'srv_is_up' : expected ')' before ',x)'."),
        ("srv_sess_rate(be/s1,x)", "fetch method 'srv_sess_rate' : expected ')' before ',x)'."),
        ("srv_id(be/s1)", "fetch method 'srv_id' : expected ')' before 'be/s1)'."),
        ("srv_name(be/s1,x)", "fetch method 'srv_name' : expected ')' before 'be/s1,x)'."),
        ("nbsrv(be,x)", "fetch method 'nbsrv' : expected ')' before ',x)'."),
        ("nbsrv(be,)", "fetch method 'nbsrv' : expected ')' before ',)'."),
        ("be_sess_rate(be,x)", "fetch method 'be_sess_rate' : expected ')' before ',x)'."),
        ("be_conn_free(be,x)", "fetch method 'be_conn_free' : expected ')' before ',x)'."),
        ("fe_conn(fe,x)", "fetch method 'fe_conn' : expected ')' before ',x)'."),
        ("fe_sess_rate(fe,x)", "fetch method 'fe_sess_rate' : expected ')' before ',x)'."),
        ("fe_req_rate(fe,x)", "fetch method 'fe_req_rate' : expected ')' before ',x)'."),
        ("table_cnt(fe,x)", "fetch method 'table_cnt' : expected ')' before ',x)'."),
        ("table_avl(fe,x)", "fetch method 'table_avl' : expected ')' before ',x)'."),
    ];
    for (i, (expr, text)) in refused.iter().enumerate() {
        let (code, out) = check(900 + i, &config(&format!("http-request set-var(txn.r) {expr}"), ""));
        assert_eq!(code, Some(1), "`{expr}` must be refused: {out}");
        assert!(out.contains(text), "`{expr}`: expected {text:?} in: {out}");
    }
    for (i, expr) in ["srv_conn(be/s1)", "srv_uweight(be/s1)", "nbsrv(be)", "fe_conn"].iter().enumerate() {
        let (code, out) = check(950 + i, &config(&format!("http-request set-var(txn.r) {expr}"), ""));
        assert_eq!(code, Some(0), "`{expr}` must load: {out}");
    }
}
