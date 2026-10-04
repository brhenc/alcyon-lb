// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! A pattern that does not parse in an anonymous ACL (`{ path_len abc }`) stops the load
//! (T146 item 12), as one in a named ACL already did. Measured on
//! `HAProxy 3.5-dev8-885761-29` on 2026-10-04: the text depends on the directive the
//! condition is on.

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

#[test]
fn a_bad_pattern_in_an_anonymous_acl_stops_the_load() {
    let cases: &[(&str, &str, &str)] = &[
        ("frontend", "http-request deny if { req.len -m int abc }", "error detected while parsing an 'http-request deny' condition : 'abc' is not a number."),
        ("frontend", "http-request deny if { req.ssl_ver 3.x }", "error detected while parsing an 'http-request deny' condition : '3.x' is not a dotted number."),
        ("frontend", "http-request deny if { path_len abc }", "'abc' is not a number."),
        ("frontend", "http-request deny if { dst_port 80-x }", "error detected while parsing an 'http-request deny' condition : '80-x' is not a valid number range."),
        ("frontend", "http-request deny if { src 1.2.3.x }", "error detected while parsing an 'http-request deny' condition : '1.2.3.x' is not a valid IPv4 or IPv6 address."),
        ("frontend", "http-request deny unless { path_len abc }", "error detected while parsing an 'http-request deny' condition : 'abc' is not a number."),
        ("frontend", "http-request deny if TRUE || { path_len abc }", "error detected while parsing an 'http-request deny' condition : 'abc' is not a number."),
        ("frontend", "http-request set-header x y if { path_len abc }", "error detected while parsing an 'http-request set-header' condition : 'abc' is not a number."),
        ("frontend", "http-response deny if { path_len abc }", "error detected while parsing an 'http-response deny' condition : 'abc' is not a number."),
        ("frontend", "http-response set-header x y if { status abc }", "error detected while parsing an 'http-response set-header' condition : 'abc' is not a number."),
        ("frontend", "http-after-response set-header x y if { status abc }", "error detected while parsing an 'http-after-response set-header' condition : 'abc' is not a number."),
        ("frontend", "use_backend b if { path_len abc }", "error detected while parsing switching rule : 'abc' is not a number."),
        ("backend", "use-server s if { path_len abc }", "error detected while parsing switching rule : 'abc' is not a number."),
        ("frontend", "http-request deny if { path -m foo /a }", "unknown matching method 'foo' when parsing ACL expression."),
    ];
    let mut wrong = Vec::new();
    for (section, rule, why) in cases {
        let (ok, err) = check(section, rule);
        if ok || !err.contains(why) {
            wrong.push(format!("{rule}: loaded={ok}, stderr={err:?}, wanted {why:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn good_anonymous_patterns_still_load() {
    for rule in [
        "http-request deny if { req.len -m int 5 }",
        "http-request deny if { req.ssl_ver 3.1 }",
        "http-request deny if { path_len 3:10 }",
        "http-request deny if { dst_port 80:90 } || { src 10.0.0.0/8 ::1 }",
        "http-request deny if { path -m reg ^/a.*b$ } !{ path_beg /x /y }",
    ] {
        let (ok, err) = check("frontend", rule);
        assert!(ok, "{rule}: {err}");
    }
}
