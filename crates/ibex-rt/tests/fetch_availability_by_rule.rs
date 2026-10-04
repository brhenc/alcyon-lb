// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! Which fetches a rule may use (T146 item 13, after T156): a fetch that reads what a rule
//! of that kind no longer, or does not yet, have is refused at load -- the response buffer in
//! a request rule or a `tcp-request`, the request headers and the request buffer in a
//! response rule, and so on. All the texts were measured on `HAProxy 3.5-dev8-885761-29` on
//! 2026-10-04; the sets of fetches come from `SMP_USE_*` in its `src/*fetch*.c` and
//! `src/payload.c`. A fetch in an ACL is only warned about there, and still loads.

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn check(section: &str, rule: &str) -> (bool, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    let tail = if section == "frontend" {
        format!("  {rule}\n  default_backend b\nbackend b\n  server s 127.0.0.1:1\n")
    } else {
        format!("  default_backend b\nbackend b\n  server s 127.0.0.1:1\n  {rule}\n")
    };
    let cfg = format!(
        "defaults\n  mode http\n  timeout client 5s\n  timeout connect 5s\n  timeout server 5s\nfrontend f\n  bind 127.0.0.1:1\n{tail}"
    );
    f.write_all(cfg.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn set_var(part: &str) -> String {
    format!("fetch method 'set-var(txn.x)' extracts information from '{part}', none of which is available here")
}

#[test]
fn request_headers_in_a_response_rule() {
    let mut cases: Vec<(String, String, String)> = Vec::new();
    for kw in ["http-response", "http-after-response"] {
        let head = format!("error detected in frontend 'f' while parsing '{kw}");
        for fetch in [
            "req.hdr(x)", "path", "req.cook(a)", "req.body_len", "url_param(a)", "http_auth_user", "base",
            "cook(a)", "req.fhdr(a)", "query", "url", "pathq",
        ] {
            cases.push((
                "frontend".into(),
                format!("{kw} set-var(txn.x) {fetch}"),
                format!("{head} set-var(txn.x)' rule : fetch method 'set-var(txn.x)' extracts information from 'HTTP request headers', none of which is available here."),
            ));
        }
        for fetch in ["req.hdr(y)", "path", "url", "query"] {
            let name = fetch.split('(').next().unwrap_or(fetch);
            cases.push((
                "frontend".into(),
                format!("{kw} set-header x %[{fetch}]"),
                format!("{head} set-header' rule : sample fetch <{name}> may not be reliably used here because it needs 'HTTP request headers' which is not available here."),
            ));
        }
    }
    let mut wrong = Vec::new();
    for (section, rule, want) in &cases {
        let (ok, err) = check(section, rule);
        if ok || !err.contains(want.as_str()) {
            wrong.push(format!("{rule}: loaded={ok}, stderr={err:?}, wanted {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn what_a_response_rule_may_still_read() {
    for rule in [
        "http-response set-var(txn.x) hdr(x)",
        "http-response set-var(txn.x) req.ver",
        "http-response set-var(txn.x) method",
        "http-response set-var(txn.x) status",
        "http-response deny if { req.hdr(x) -m found }",
        "http-response deny if { path /a }",
        "http-after-response set-var(txn.x) method",
    ] {
        let (ok, err) = check("frontend", rule);
        assert!(ok, "{rule}: {err}");
    }
}

#[test]
fn the_response_buffer_in_a_request_rule() {
    let mut wrong = Vec::new();
    let mut expect = |section: &str, rule: &str, want: String| {
        let (ok, err) = check(section, rule);
        if ok || !err.contains(want.as_str()) {
            wrong.push(format!("{rule}: loaded={ok}, stderr={err:?}, wanted {want:?}"));
        }
    };
    let frontend = "error detected in frontend 'f' while parsing 'http-request";
    for fetch in ["res.len", "res.payload(0,1)", "res.ssl_hello_type", "rep_ssl_hello_type", "res.payload_lv(0,1)"] {
        expect(
            "frontend",
            &format!("http-request set-var(txn.x) {fetch}"),
            format!("{frontend} set-var(txn.x)' rule : fetch method 'set-var(txn.x)' extracts information from 'response buffer', none of which is available here."),
        );
    }
    expect(
        "frontend",
        "http-request set-header x %[res.len]",
        format!("{frontend} set-header' rule : sample fetch <res.len> may not be reliably used here because it needs 'response buffer' which is not available here."),
    );
    for kw in ["tcp-request content", "tcp-request session"] {
        for fetch in ["res.len", "res.payload(0,1)", "res.ssl_hello_type", "rep_ssl_hello_type"] {
            expect("frontend", &format!("{kw} set-var(txn.x) {fetch}"), set_var("response buffer"));
        }
    }
    expect("backend", "tcp-request content set-var(txn.x) res.len", set_var("response buffer"));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for rule in [
        "tcp-request content set-var(txn.x) payload(0,1)",
        "tcp-request content accept if { rep_ssl_hello_type 2 }",
        "http-request deny if { res.len gt 0 }",
    ] {
        let (ok, err) = check("frontend", rule);
        assert!(ok, "{rule}: {err}");
    }
}

#[test]
fn the_request_side_in_a_tcp_response_rule() {
    let mut wrong = Vec::new();
    for (fetch, part) in [
        ("req.len", "request buffer"),
        ("req.ssl_sni", "request buffer"),
        ("req.payload(0,1)", "request buffer"),
        ("req.rdp_cookie", "request buffer"),
        ("req.hdr(x)", "HTTP request headers"),
        ("path", "HTTP request headers"),
    ] {
        let rule = format!("tcp-response content set-var(txn.x) {fetch}");
        let want = set_var(part);
        let (ok, err) = check("backend", &rule);
        if ok || !err.contains(&want) {
            wrong.push(format!("{rule}: loaded={ok}, stderr={err:?}, wanted {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for rule in ["tcp-response content set-var(txn.x) res.len", "tcp-response content set-var(txn.x) method"] {
        let (ok, err) = check("backend", rule);
        assert!(ok, "{rule}: {err}");
    }
}
