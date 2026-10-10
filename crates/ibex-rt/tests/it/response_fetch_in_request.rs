// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A fetch of the response where there is none is refused at load (T156).
//!
//! `status`, `res.hdr()` and the other fetches of the HTTP response read, in Ibex, the
//! response of whatever stream ran last on the thread when they are evaluated where the
//! stream has none: in `http-request` rules, and for the header fetches in a log-format,
//! which is rendered after the response headers are gone. `HAProxy` refuses them there
//! (`SMP_USE_HRSHP`, "HTTP response"; `SMP_USE_HRSHV`, "HTTP response headers", the latter
//! also in log-formats). Messages measured on `HAProxy` 3.5-dev8-885761-29; Ibex 8392fff
//! accepted every one of these configurations.

use ibex_config::parse_config;
use ibex_rt::rule_exprs::validate_config;

fn cfg(fe: &str) -> String {
    format!(
        "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         frontend f\n  bind 127.0.0.1:19812\n{fe}  default_backend b\nbackend b\n  server s 127.0.0.1:1\n"
    )
}

fn check(fe: &str) -> Result<(), String> {
    let c = parse_config(&cfg(fe)).map_err(|e| format!("parse: {e}"))?;
    validate_config(&c)
}

const HRSHP: &str = "'HTTP response'";
const HRSHV: &str = "'HTTP response headers'";

#[test]
fn a_response_fetch_in_an_http_request_log_format_is_refused() {
    for (rule, fetch, part) in [
        ("http-request set-header x %[status]", "status", HRSHP),
        ("http-request set-header x %[res.hdr(x)]", "res.hdr", HRSHV),
        ("http-request set-header x %[res.fhdr(x)]", "res.fhdr", HRSHV),
        ("http-request set-header x %[res.ver]", "res.ver", HRSHP),
        ("http-request set-var-fmt(txn.x) %[status]", "status", HRSHP),
        ("http-request redirect location %[res.hdr(x)]", "res.hdr", HRSHV),
        ("http-request set-header x %[status] if FALSE", "status", HRSHP),
    ] {
        let action = rule.split_whitespace().nth(1).unwrap_or_default();
        let want = format!(
            "error detected in frontend 'f' while parsing 'http-request {action}' rule : sample fetch <{fetch}> may not be reliably used here because it needs {part} which is not available here."
        );
        match check(&format!("  {rule}\n")) {
            Ok(()) => panic!("accepted: {rule}"),
            Err(e) => assert!(e.contains(&want), "{rule}:\n got {e}\nwant {want}"),
        }
    }
}

#[test]
fn a_response_fetch_as_an_http_request_expression_is_refused() {
    for (rule, want) in [
        (
            "http-request set-var(txn.x) status",
            format!("error detected in frontend 'f' while parsing 'http-request set-var(txn.x)' rule : fetch method 'set-var(txn.x)' extracts information from {HRSHP}, none of which is available here."),
        ),
        (
            "http-request set-var(txn.x) res.hdr(x)",
            format!("error detected in frontend 'f' while parsing 'http-request set-var(txn.x)' rule : fetch method 'set-var(txn.x)' extracts information from {HRSHV}, none of which is available here."),
        ),
        (
            "http-request track-sc0 status",
            format!("error detected in frontend 'f' while parsing 'http-request track-sc0' rule : fetch method 'status' extracts information from {HRSHP}, none of which is available here."),
        ),
        (
            "http-request capture res.hdr(x) len 10",
            format!("error detected in frontend 'f' while parsing 'http-request capture' rule : fetch method 'res.hdr(x)' extracts information from {HRSHV}, none of which is available here."),
        ),
        (
            "tcp-request content set-var(txn.x) status",
            format!("fetch method 'set-var(txn.x)' extracts information from {HRSHP}, none of which is available here"),
        ),
    ] {
        match check(&format!("  {rule}\n")) {
            Ok(()) => panic!("accepted: {rule}"),
            Err(e) => assert!(e.contains(&want), "{rule}:\n got {e}\nwant {want}"),
        }
    }
}

#[test]
fn a_response_header_fetch_in_a_log_format_is_refused() {
    for (line, kw, fetch) in [
        ("log-format \"%[res.hdr(x)]\"", "log-format", "res.hdr"),
        ("log-format \"%[res.cook(x)] %[res.ver]\"", "log-format", "res.cook"),
        ("log-format \"%[status] %[res.timer.hdr]\"", "log-format", "res.timer.hdr"),
        ("unique-id-format %[res.hdr(x)]", "unique-id", "res.hdr"),
    ] {
        let want = format!("failed to parse {kw} : sample fetch <{fetch}> may not be reliably used here because it needs {HRSHV} which is not available here.");
        match check(&format!("  {line}\n")) {
            Ok(()) => panic!("accepted: {line}"),
            Err(e) => assert!(e.contains(&want), "{line}:\n got {e}\nwant {want}"),
        }
    }
}

#[test]
fn what_haproxy_accepts_is_accepted() {
    for fe in [
        // The status and the other persistent facts of the response are the log's.
        "  log-format \"%[status] %[res.ver]\"\n",
        "  http-response set-header x %[status]\n  http-after-response set-header y %[res.hdr(x)]\n",
        "  http-response set-var(txn.a) res.hdr(x)\n  http-request set-header x %[var(txn.a)]\n",
        // `hdr` and `cookie` read the request in a request rule.
        "  http-request set-header x %[hdr(host)] \n  http-request set-var(txn.c) cookie(c)\n",
        // An ACL is only warned about by HAProxy, and never matches.
        "  http-request deny if { status 200 }\n",
    ] {
        if let Err(e) = check(fe) {
            panic!("{fe}: {e}");
        }
    }
}

#[test]
fn the_section_is_named_as_haproxy_names_it() {
    let head = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";
    let rule = "  http-request set-header x %[status]\n";
    for (text, what) in [
        (format!("{head}frontend f\n  bind 127.0.0.1:19812\n  default_backend b\nbackend b\n{rule}  server s 127.0.0.1:1\n"), "backend 'b'"),
        (format!("{head}listen l\n  bind 127.0.0.1:19812\n{rule}  server s 127.0.0.1:1\n"), "proxy 'l'"),
        (
            format!("defaults d\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n{rule}frontend f from d\n  bind 127.0.0.1:19812\n"),
            "defaults 'd'",
        ),
    ] {
        let want = format!("error detected in {what} while parsing 'http-request set-header' rule : sample fetch <status> may not be reliably used here because it needs {HRSHP} which is not available here.");
        let got = parse_config(&text).map_err(|e| e.to_string()).and_then(|c| validate_config(&c));
        match got {
            Ok(()) => panic!("accepted:\n{text}"),
            Err(e) => assert!(e.contains(&want), "got {e}\nwant {want}"),
        }
    }
}
