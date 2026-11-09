// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T432: a word after an action's own arguments is refused, as `HAProxy` refuses it, for every
//! action of `http-request`, `http-response`, `http-after-response` and `tcp-request` /
//! `tcp-response` that Alcyon accepts. One row per rule list and action; the message is what
//! `haproxy -c` (3.5-dev8, 2026-10-19) printed for `<rule> foo`. The `http-*` lists say
//! "expects either 'if' or 'unless' ... found 'foo'.", the `tcp-*` lists "only accepts 'if' or
//! 'unless', in frontend 'f' (got 'foo')"; a few actions refuse on their own arity instead.

use alcyon_config::parse_config;

fn cfg(rule: &str, in_backend: bool) -> String {
    let (f, b) = if in_backend { ("", rule) } else { (rule, "") };
    let t = if rule.contains("gpc0") || rule.contains("gpc1") || rule.contains("gpt0") {
        "gpc0,gpc1,gpt0,conn_rate(10s)"
    } else {
        "gpc(2),gpt(2),conn_rate(10s)"
    };
    format!(
        "global\n  expose-experimental-directives\n\
         userlist u\n  user a insecure-password b\n\
         defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
         frontend f\n  bind 127.0.0.1:29555\n  stick-table type ip size 1k store {t}\n  {f}\n  default_backend b\n\
         backend b\n  stick-table type ip size 1k store {t}\n  {b}\n  server s 127.0.0.1:1\n"
    )
}

/// (rule list, action and its arguments, HAProxy's message for a stray `foo` after them)
const ROWS: &[(&str, &str, &str)] = &[
    ("http-request", "allow", "'http-request allow' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "deny", "'http-request deny' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "deny deny_status 400", "'http-request deny' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "deny status 400", "'http-request deny' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "tarpit", "'http-request tarpit' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "tarpit deny_status 400", "'http-request tarpit' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "return status 200", "'http-request return' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-header A b", "'http-request set-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "add-header A b", "'http-request add-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "del-header A", "'http-request del-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "replace-header A a b", "'http-request replace-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "replace-value A a b", "'http-request replace-value' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-path /x", "expects exactly 1 argument <format>."),
    ("http-request", "replace-path a b", "expects exactly 2 arguments <match-regex> and <replace-format>."),
    ("http-request", "set-pathq /x", "expects exactly 1 argument <format>."),
    ("http-request", "replace-pathq a b", "expects exactly 2 arguments <match-regex> and <replace-format>."),
    ("http-request", "replace-uri a b", "expects exactly 2 arguments <match-regex> and <replace-format>."),
    ("http-request", "set-query q=1", "expects exactly 1 argument <format>."),
    ("http-request", "set-uri /x", "expects exactly 1 argument <format>."),
    ("http-request", "set-method GET", "expects exactly 1 argument <format>."),
    ("http-request", "set-src src", "'http-request set-src' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-dst src", "'http-request set-dst' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-src-port int(80)", "'http-request set-src-port' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-dst-port int(80)", "'http-request set-dst-port' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-priority-class int(1)", "'http-request set-priority-class' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-priority-offset int(1)", "'http-request set-priority-offset' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-retries 2", "'http-request set-retries' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "redirect location /x", "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was 'foo')."),
    ("http-request", "redirect prefix /x", "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was 'foo')."),
    ("http-request", "redirect scheme https", "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was 'foo')."),
    ("http-request", "strict-mode on", "'http-request strict-mode' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "disable-l7-retry", "'http-request disable-l7-retry' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "normalize-uri fragment-strip", "'http-request normalize-uri' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-timeout server 5s", "'http-request set-timeout' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "auth", "'http-request auth' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "capture req.hdr(host) len 10", "'http-request capture' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "reject", "'http-request reject' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "silent-drop", "'http-request silent-drop' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "wait-for-body time 1s", "'http-request wait-for-body' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "pause 10", "'http-request pause' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "track-sc0 src", "'http-request track-sc0' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "track-sc1 src", "'http-request track-sc1' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "track-sc2 src", "'http-request track-sc2' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "sc-inc-gpc0(0)", "'http-request sc-inc-gpc0(0)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "sc-inc-gpc1(0)", "'http-request sc-inc-gpc1(0)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "sc-set-gpt0(0) 1", "'http-request sc-set-gpt0(0)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "sc-inc-gpc(0,0)", "'http-request sc-inc-gpc(0,0)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "sc-add-gpc(0,0) 1", "'http-request sc-add-gpc(0,0)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-var(txn.x) str(a)", "'http-request set-var(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "unset-var(txn.x)", "'http-request unset-var(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "set-headers-bin req.hdrs_bin", "'http-request set-headers-bin' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "add-headers-bin req.hdrs_bin", "'http-request add-headers-bin' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "sc-set-gpt0(0) 1", "'http-request sc-set-gpt0(0)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-request", "track-sc0 src table b", "'http-request track-sc0' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "allow", "'http-response allow' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "deny", "'http-response deny' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "deny status 400", "'http-response deny' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "return status 200", "'http-response return' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "set-header A b", "'http-response set-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "add-header A b", "'http-response add-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "del-header A", "'http-response del-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "replace-header A a b", "'http-response replace-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "replace-value A a b", "'http-response replace-value' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "set-status 200", "'http-response set-status' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "set-status 200 reason foo", "'http-response set-status' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "redirect location /x", "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was 'foo')."),
    ("http-response", "strict-mode on", "'http-response strict-mode' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "silent-drop", "'http-response silent-drop' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "set-var(txn.x) str(a)", "'http-response set-var(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "unset-var(txn.x)", "'http-response unset-var(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "wait-for-body time 1s", "'http-response wait-for-body' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-response", "pause 10", "'http-response pause' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "set-header A b", "'http-after-response set-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "add-header A b", "'http-after-response add-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "del-header A", "'http-after-response del-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "replace-header A a b", "'http-after-response replace-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "replace-value A a b", "'http-after-response replace-value' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "set-status 200", "'http-after-response set-status' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "strict-mode on", "'http-after-response strict-mode' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "set-var(txn.x) str(a)", "'http-after-response set-var(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "unset-var(txn.x)", "'http-after-response unset-var(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("http-after-response", "allow", "'http-after-response allow' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
    ("tcp-request connection", "accept", "'tcp-request connection accept' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "reject", "'tcp-request connection reject' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "silent-drop", "'tcp-request connection silent-drop' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "track-sc0 src", "'tcp-request connection track-sc0' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "set-src src", "'tcp-request connection set-src' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "set-src-port int(80)", "'tcp-request connection set-src-port' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "set-dst src", "'tcp-request connection set-dst' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "set-dst-port int(80)", "'tcp-request connection set-dst-port' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request connection", "expect-proxy layer4", "'tcp-request connection expect-proxy' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "accept", "'tcp-request session accept' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "reject", "'tcp-request session reject' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "silent-drop", "'tcp-request session silent-drop' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "track-sc0 src", "'tcp-request session track-sc0' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "sc-inc-gpc0(0)", "'tcp-request session sc-inc-gpc0(0)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "sc-set-gpt0(0) 1", "'tcp-request session sc-set-gpt0(0)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "set-var(txn.x) str(a)", "'tcp-request session set-var(txn.x)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "unset-var(txn.x)", "'tcp-request session unset-var(txn.x)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "set-src src", "'tcp-request session set-src' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "set-dst src", "'tcp-request session set-dst' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "set-src-port int(80)", "'tcp-request session set-src-port' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request session", "set-dst-port int(80)", "'tcp-request session set-dst-port' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "accept", "'tcp-request content accept' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "reject", "'tcp-request content reject' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "silent-drop", "'tcp-request content silent-drop' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "capture req.payload(0,5) len 5", "'tcp-request content capture' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "track-sc0 src", "'tcp-request content track-sc0' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "sc-inc-gpc0(0)", "'tcp-request content sc-inc-gpc0(0)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "sc-set-gpt0(0) 1", "'tcp-request content sc-set-gpt0(0)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "set-var(txn.x) str(a)", "'tcp-request content set-var(txn.x)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "unset-var(txn.x)", "'tcp-request content unset-var(txn.x)' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "set-dst src", "'tcp-request content set-dst' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "set-dst-port int(80)", "'tcp-request content set-dst-port' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "set-src src", "'tcp-request content set-src' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "set-src-port int(80)", "'tcp-request content set-src-port' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-request content", "switch-mode http", "'tcp-request content switch-mode' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
    ("tcp-response content", "accept", "'tcp-response content accept' only accepts 'if' or 'unless', in backend 'b' (got 'foo')"),
    ("tcp-response content", "reject", "'tcp-response content reject' only accepts 'if' or 'unless', in backend 'b' (got 'foo')"),
    ("tcp-response content", "silent-drop", "'tcp-response content silent-drop' only accepts 'if' or 'unless', in backend 'b' (got 'foo')"),
    ("tcp-response content", "set-var(txn.x) str(a)", "'tcp-response content set-var(txn.x)' only accepts 'if' or 'unless', in backend 'b' (got 'foo')"),
    ("tcp-response content", "unset-var(txn.x)", "'tcp-response content unset-var(txn.x)' only accepts 'if' or 'unless', in backend 'b' (got 'foo')"),
];

#[test]
fn a_stray_word_after_the_arguments_is_refused_with_haproxys_text() {
    let mut bad = Vec::new();
    for (list, act, want) in ROWS {
        let in_backend = *list == "tcp-response content" || act.starts_with("set-retries") || act.starts_with("set-timeout");
        let rule = format!("{list} {act}");
        if let Err(e) = parse_config(&cfg(&rule, in_backend)) {
            bad.push(format!("BASE REFUSED {rule}: {e}"));
            continue;
        }
        let rule = format!("{rule} foo");
        match parse_config(&cfg(&rule, in_backend)) {
            Ok(_) => bad.push(format!("ACCEPTED   {rule}")),
            Err(e) if e.to_string().contains(want) => {}
            Err(e) => bad.push(format!("WRONG TEXT {rule}: {e} (want {want})")),
        }
    }
    assert!(bad.is_empty(), "{} of {} rows:\n{}", bad.len(), ROWS.len(), bad.join("\n"));
}

/// The same actions still load with their condition, and with no word after the arguments.
#[test]
fn the_same_rules_load_with_and_without_a_condition() {
    for (list, act, _) in ROWS {
        let in_backend = *list == "tcp-response content" || act.starts_with("set-retries") || act.starts_with("set-timeout");
        for tail in ["", " if { always_true }", " unless { always_true }"] {
            let rule = format!("{list} {act}{tail}");
            if parse_config(&cfg(&format!("{list} {act}"), in_backend)).is_err() {
                continue; // the row above reports a base Alcyon does not load
            }
            if let Err(e) = parse_config(&cfg(&rule, in_backend)) {
                panic!("{rule}: {e}");
            }
        }
    }
}

/// Forms the one-per-action table does not reach: options before the stray word, the
/// proxy kinds `tcp-request` names, and `strict-mode`'s own value check. Each message was
/// printed by `haproxy -c` (3.5-dev8, 2026-10-19).
#[test]
fn stray_words_after_options_and_in_other_sections() {
    for (rule, want) in [
        ("http-request del-header A -m str foo", "'http-request del-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
        ("http-response del-header A -m str foo", "'http-response del-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
        ("http-after-response del-header A -m str foo", "'http-after-response del-header' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
        // `-m` without its method (HAProxy also names the proxy: "error detected in frontend 'f' while ...").
        ("http-request del-header A -m", "while parsing 'http-request del-header' rule : -m flag expects exactly 1 argument."),
        ("http-response del-header A -m", "while parsing 'http-response del-header' rule : -m flag expects exactly 1 argument."),
        ("http-after-response del-header A -m", "while parsing 'http-after-response del-header' rule : -m flag expects exactly 1 argument."),
        ("http-request track-sc0 src table b foo", "'http-request track-sc0' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
        ("http-request deny status 400 bar baz", "'http-request deny' expects either 'if' or 'unless' followed by a condition but found 'bar'."),
        ("http-request set-var-fmt(txn.x) a b", "'http-request set-var-fmt(txn.x)' expects either 'if' or 'unless' followed by a condition but found 'b'."),
        ("http-request strict-mode off foo", "'http-request strict-mode' expects either 'if' or 'unless' followed by a condition but found 'foo'."),
        ("http-request strict-mode foo", "Unexpected value 'foo'. Only 'on' and 'off' are supported."),
        ("http-response strict-mode foo", "Unexpected value 'foo'. Only 'on' and 'off' are supported."),
        ("http-after-response strict-mode", "expects exactly 1 arguments."),
        ("tcp-request content switch-mode http proto h2 foo", "'tcp-request content switch-mode' only accepts 'if' or 'unless', in frontend 'f' (got 'foo')"),
        ("tcp-request content accept foo", "in frontend 'f' (got 'foo')"),
    ] {
        let err = parse_config(&cfg(rule, false)).expect_err(rule).to_string();
        assert!(err.contains(want), "{rule}: {err}");
    }
    // `listen` is "proxy", a named `defaults` is "defaults" (measured).
    let listen = "listen l\n  mode http\n  bind 127.0.0.1:29556\n  tcp-request content accept foo\n  server s 127.0.0.1:1\n";
    let err = parse_config(listen).expect_err("listen").to_string();
    assert!(err.contains("'tcp-request content accept' only accepts 'if' or 'unless', in proxy 'l' (got 'foo')"), "{err}");
    let defaults = "defaults d\n  mode http\n  tcp-response content accept foo\n";
    let err = parse_config(defaults).expect_err("defaults").to_string();
    assert!(err.contains("'tcp-response content accept' only accepts 'if' or 'unless', in defaults 'd' (got 'foo')"), "{err}");
    let backend = "backend b\n  mode http\n  tcp-request content accept foo\n  server s 127.0.0.1:1\n";
    let err = parse_config(backend).expect_err("backend").to_string();
    assert!(err.contains("in backend 'b' (got 'foo')"), "{err}");
}

/// The valid forms next to the refused ones still load.
#[test]
fn the_valid_forms_still_load() {
    for rule in [
        "http-request del-header A -m str if { always_true }",
        "http-request track-sc0 src table b if { always_true }",
        "http-request track-sc0 src if { always_true }",
        "http-request set-var-fmt(txn.x) %[src] if { always_true }",
        "http-request strict-mode off if { always_true }",
        "http-response strict-mode on",
        "http-request sc-set-gpt0(0) 3 if { always_true }",
        "tcp-request content switch-mode http proto h2 if { always_true }",
        "tcp-request content switch-mode http",
        "tcp-request content capture req.payload(0,5) len 5 if { always_true }",
        "tcp-request connection expect-proxy layer4 if { always_true }",
        "http-request replace-uri a b if { always_true }",
    ] {
        parse_config(&cfg(rule, false)).unwrap_or_else(|e| panic!("{rule}: {e}"));
    }
    // A backend rule (a frontend has no server timeout to set).
    for rule in ["http-request set-timeout server 5s", "http-request set-timeout server 5s if { always_true }"] {
        parse_config(&cfg(rule, true)).unwrap_or_else(|e| panic!("{rule}: {e}"));
    }
    let err = parse_config(&cfg("http-request set-timeout server 5s foo", true)).expect_err("set-timeout").to_string();
    assert!(err.contains("'http-request set-timeout' expects either 'if' or 'unless' followed by a condition but found 'foo'."), "{err}");
}
