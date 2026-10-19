// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T430 row 38: the texts of an `http-request`, `http-response` or `http-after-response` action
//! with no argument. Every expected line was printed by `haproxy -c` (3.5-dev8) for the
//! rule alone in a frontend `f` with `mode http`, minus its `parsing [file:line] : ` location.
//! Only actions Ibex implements are listed; the others are refused by name (`unknown ...
//! action`), which is the other side of the same difference (see the task file).

use std::io::Write;
use std::process::Command;

const CASES: &[(&str, &str, &str)] = &[
    ("http-request", "redirect", "error detected in frontend 'f' while parsing 'http-request redirect' rule : redirection type expected ('prefix', 'location', or 'scheme')."),
    ("http-request", "set-header", "error detected in frontend 'f' while parsing 'http-request set-header' rule : expects exactly 2 arguments."),
    ("http-request", "add-header", "error detected in frontend 'f' while parsing 'http-request add-header' rule : expects exactly 2 arguments."),
    ("http-request", "del-header", "error detected in frontend 'f' while parsing 'http-request del-header' rule : expects at least 1 argument."),
    ("http-request", "replace-header", "error detected in frontend 'f' while parsing 'http-request replace-header' rule : expects exactly 3 arguments."),
    ("http-request", "replace-value", "error detected in frontend 'f' while parsing 'http-request replace-value' rule : expects exactly 3 arguments."),
    ("http-request", "set-path", "error detected in frontend 'f' while parsing 'http-request set-path' rule : expects exactly 1 argument <format>."),
    ("http-request", "set-pathq", "error detected in frontend 'f' while parsing 'http-request set-pathq' rule : expects exactly 1 argument <format>."),
    ("http-request", "set-query", "error detected in frontend 'f' while parsing 'http-request set-query' rule : expects exactly 1 argument <format>."),
    ("http-request", "set-uri", "error detected in frontend 'f' while parsing 'http-request set-uri' rule : expects exactly 1 argument <format>."),
    ("http-request", "set-method", "error detected in frontend 'f' while parsing 'http-request set-method' rule : expects exactly 1 argument <format>."),
    ("http-request", "set-src", "error detected in frontend 'f' while parsing 'http-request set-src' rule : missing fetch method."),
    ("http-request", "set-src-port", "error detected in frontend 'f' while parsing 'http-request set-src-port' rule : missing fetch method."),
    ("http-request", "set-dst", "error detected in frontend 'f' while parsing 'http-request set-dst' rule : missing fetch method."),
    ("http-request", "set-dst-port", "error detected in frontend 'f' while parsing 'http-request set-dst-port' rule : missing fetch method."),
    ("http-request", "set-var", "error detected in frontend 'f' while parsing 'http-request set-var' rule : invalid or incomplete action 'set-var'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-request", "set-var-fmt", "error detected in frontend 'f' while parsing 'http-request set-var-fmt' rule : invalid or incomplete action 'set-var-fmt'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-request", "unset-var", "error detected in frontend 'f' while parsing 'http-request unset-var' rule : invalid or incomplete action 'unset-var'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-request", "capture", "error detected in frontend 'f' while parsing 'http-request capture' rule : expects <expression> [ 'len' <length> | id <idx> ]."),
    ("http-request", "track-sc0", "error detected in frontend 'f' while parsing 'http-request track-sc0' rule : missing fetch method."),
    ("http-request", "track-sc1", "error detected in frontend 'f' while parsing 'http-request track-sc1' rule : missing fetch method."),
    ("http-request", "track-sc2", "error detected in frontend 'f' while parsing 'http-request track-sc2' rule : missing fetch method."),
    ("http-request", "sc-add-gpc", "error detected in frontend 'f' while parsing 'http-request sc-add-gpc' rule : Missing or invalid arguments for 'sc-add-gpc'. Expects sc-add-gpc(<GPC ID>,<Track ID>)."),
    ("http-request", "set-timeout", "error detected in frontend 'f' while parsing 'http-request set-timeout' rule : expects exactly 2 arguments."),
    ("http-request", "set-priority-class", "error detected in frontend 'f' while parsing 'http-request set-priority-class' rule : missing fetch method."),
    ("http-request", "set-priority-offset", "error detected in frontend 'f' while parsing 'http-request set-priority-offset' rule : missing fetch method."),
    ("http-request", "use-service", "error detected in frontend 'f' while parsing 'http-request use-service' rule : 'use-service' expects a service name.."),
    ("http-request", "wait-for-body", "error detected in frontend 'f' while parsing 'http-request wait-for-body' rule : expects time <time> [ at-least <bytes> ]."),
    ("http-request", "strict-mode", "error detected in frontend 'f' while parsing 'http-request strict-mode' rule : expects exactly 1 arguments."),
    ("http-request", "replace-path", "error detected in frontend 'f' while parsing 'http-request replace-path' rule : expects exactly 2 arguments <match-regex> and <replace-format>."),
    ("http-request", "replace-pathq", "error detected in frontend 'f' while parsing 'http-request replace-pathq' rule : expects exactly 2 arguments <match-regex> and <replace-format>."),
    ("http-request", "add-headers-bin", "error detected in frontend 'f' while parsing 'http-request add-headers-bin' rule : expects exactly one argument or three arguments <headers> prefix <pfx>."),
    ("http-request", "set-headers-bin", "error detected in frontend 'f' while parsing 'http-request set-headers-bin' rule : expects exactly one argument or three arguments <headers> prefix <pfx>."),
    ("http-request", "del-headers-bin", "error detected in frontend 'f' while parsing 'http-request del-headers-bin' rule : expects at least 1 argument."),
    ("http-request", "sc-inc-gpc", "error detected in frontend 'f' while parsing 'http-request sc-inc-gpc' rule : invalid gpc ID 'sc-inc-gpc'. Expects sc-inc-gpc(<GPC ID>,<Track ID>)."),
    ("http-response", "redirect", "error detected in frontend 'f' while parsing 'http-response redirect' rule : redirection type expected ('prefix', 'location', or 'scheme')."),
    ("http-response", "set-header", "error detected in frontend 'f' while parsing 'http-response set-header' rule : expects exactly 2 arguments."),
    ("http-response", "add-header", "error detected in frontend 'f' while parsing 'http-response add-header' rule : expects exactly 2 arguments."),
    ("http-response", "del-header", "error detected in frontend 'f' while parsing 'http-response del-header' rule : expects at least 1 argument."),
    ("http-response", "replace-header", "error detected in frontend 'f' while parsing 'http-response replace-header' rule : expects exactly 3 arguments."),
    ("http-response", "replace-value", "error detected in frontend 'f' while parsing 'http-response replace-value' rule : expects exactly 3 arguments."),
    ("http-response", "set-status", "error detected in frontend 'f' while parsing 'http-response set-status' rule : expects 1 argument: <status>; or 3 arguments: <status> reason <fmt>."),
    ("http-response", "set-var", "error detected in frontend 'f' while parsing 'http-response set-var' rule : invalid or incomplete action 'set-var'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-response", "set-var-fmt", "error detected in frontend 'f' while parsing 'http-response set-var-fmt' rule : invalid or incomplete action 'set-var-fmt'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-response", "unset-var", "error detected in frontend 'f' while parsing 'http-response unset-var' rule : invalid or incomplete action 'unset-var'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-response", "capture", "error detected in frontend 'f' while parsing 'http-response capture' rule : expects <expression> id <idx>."),
    ("http-response", "strict-mode", "error detected in frontend 'f' while parsing 'http-response strict-mode' rule : expects exactly 1 arguments."),
    ("http-response", "wait-for-body", "error detected in frontend 'f' while parsing 'http-response wait-for-body' rule : expects time <time> [ at-least <bytes> ]."),
    ("http-after-response", "set-header", "error detected in frontend 'f' while parsing 'http-after-response set-header' rule : expects exactly 2 arguments."),
    ("http-after-response", "add-header", "error detected in frontend 'f' while parsing 'http-after-response add-header' rule : expects exactly 2 arguments."),
    ("http-after-response", "del-header", "error detected in frontend 'f' while parsing 'http-after-response del-header' rule : expects at least 1 argument."),
    ("http-after-response", "replace-header", "error detected in frontend 'f' while parsing 'http-after-response replace-header' rule : expects exactly 3 arguments."),
    ("http-after-response", "replace-value", "error detected in frontend 'f' while parsing 'http-after-response replace-value' rule : expects exactly 3 arguments."),
    ("http-after-response", "set-status", "error detected in frontend 'f' while parsing 'http-after-response set-status' rule : expects 1 argument: <status>; or 3 arguments: <status> reason <fmt>."),
    ("http-after-response", "set-var", "error detected in frontend 'f' while parsing 'http-after-response set-var' rule : invalid or incomplete action 'set-var'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-after-response", "set-var-fmt", "error detected in frontend 'f' while parsing 'http-after-response set-var-fmt' rule : invalid or incomplete action 'set-var-fmt'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-after-response", "unset-var", "error detected in frontend 'f' while parsing 'http-after-response unset-var' rule : invalid or incomplete action 'unset-var'. Expects 'set-var(<var-name>)', 'set-var-fmt(<var-name>)' or 'unset-var(<var-name>)'."),
    ("http-after-response", "capture", "error detected in frontend 'f' while parsing 'http-after-response capture' rule : expects <expression> id <idx>."),
    ("http-after-response", "strict-mode", "error detected in frontend 'f' while parsing 'http-after-response strict-mode' rule : expects exactly 1 arguments."),
];

#[test]
fn an_action_without_its_argument_is_refused_with_haproxy_s_text() {
    let mut wrong = Vec::new();
    for (list, action, want) in CASES {
        let cfg = format!("defaults\n  mode http\n  timeout client 1s\n  timeout connect 1s\n  timeout server 1s\nfrontend f\n  bind 127.0.0.1:18437\n  {list} {action}\n");
        let mut f = tempfile::NamedTempFile::new().expect("tmp");
        f.write_all(cfg.as_bytes()).expect("cfg");
        let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(f.path()).output().expect("-c");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        if out.status.code() == Some(0) || !text.lines().any(|l| l.ends_with(want) && l.contains(&format!("'{list} {action}'")) ) {
            wrong.push(format!("{list} {action}: wanted {want:?}, got {text:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
