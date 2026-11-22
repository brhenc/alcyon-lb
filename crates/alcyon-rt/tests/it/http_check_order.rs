// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Order of `http-check` rules at load: `HAProxy` refuses several orders of
//! `connect` / `send` / `expect` rules that `Alcyon` used to accept (HCHKREFUSE).
//! Every row was measured on `HAProxy` 3.5-dev11-ce79f339c with `haproxy -c` in a
//! backend with `option httpchk` and `server s1 127.0.0.1:1 check`; the reason is
//! the text after the keyword in the `[ALERT]` line. Set
//! `T281_ORACLE=/path/to/haproxy` to run this file against `HAProxy`: it passes
//! all rows.

use std::process::Command;

/// `(rules, reason after the keyword when refused, or accepted)`.
const ROWS: &[(&str, Option<&str>)] = &[
    (
        "http-check send meth GET\n  http-check send meth GET",
        Some(
            "'http-check send' : unable to add http-check send rule at step 2 (missing connect rule)..",
        ),
    ),
    (
        "http-check send meth GET\n  http-check expect status 200\n  http-check send meth GET",
        Some(
            "'http-check send' : unable to add http-check send rule at step 3 (missing connect rule)..",
        ),
    ),
    (
        "http-check send meth GET\n  http-check connect",
        Some(
            "'http-check connect' : first step MUST also be a 'connect', optionally preceded by a \
             'set-var', an 'unset-var' or a 'comment', when there is a 'connect' step in the \
             tcp-check ruleset.",
        ),
    ),
    (
        "http-check send meth GET\n  http-check expect status 200\n  http-check connect\n  \
         http-check send meth GET",
        Some(
            "'http-check connect' : first step MUST also be a 'connect', optionally preceded by a \
             'set-var', an 'unset-var' or a 'comment', when there is a 'connect' step in the \
             tcp-check ruleset.",
        ),
    ),
    (
        "http-check connect\n  http-check send meth GET\n  http-check connect",
        Some(
            "'http-check connect' : unable to add http-check connect rule at step 2 (missing expect rule)..",
        ),
    ),
    (
        "http-check connect\n  http-check expect status 200",
        Some(
            "'http-check expect' : unable to add http-check expect rule at step 2 (missing send rule)..",
        ),
    ),
    (
        "http-check connect\n  http-check send meth GET\n  http-check expect status 200\n  \
         http-check connect\n  http-check send meth GET\n  http-check expect status 200",
        None,
    ),
    (
        "http-check send meth GET\n  http-check expect status 200",
        None,
    ),
];

/// A `defaults ... from` section starts its own http-check ruleset (the ruleset
/// name is per section, `*http-check-<id>_<file>-<line>`), so the parent's rules
/// do not make the child's first `send` look like a second one: `HAProxy`
/// accepts both of these.
#[test]
fn defaults_from_section_starts_its_own_ruleset() {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    for cfg in [
        "defaults d0\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n  \
         option httpchk\n  http-check send meth HEAD\n  \
         defaults from d0\n  http-check send meth GET\n  \
         backend b from d0\n  server s1 127.0.0.1:1 check\n",
        "defaults d0\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n  \
         option httpchk\n  http-check send meth HEAD\n  \
         defaults d1 from d0\n  http-check send meth GET\n  \
         backend b from d1\n  server s1 127.0.0.1:1 check\n",
    ] {
        let dir = tempfile::TempDir::new().expect("tmp");
        let path = dir.path().join("p.cfg");
        std::fs::write(&path, cfg).expect("write");
        let out = Command::new(&bin)
            .arg("-c")
            .arg("-f")
            .arg(&path)
            .output()
            .unwrap_or_else(|e| panic!("run {bin}: {e}"));
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "expected the config to be accepted:\n{stderr}\n{cfg}");
    }
}

#[test]
fn http_check_rule_orders_match_haproxy() {
    let bin = std::env::var("T281_ORACLE").unwrap_or_else(|_| env!("CARGO_BIN_EXE_alcyon").to_string());
    for (rules, expected) in ROWS {
        let dir = tempfile::TempDir::new().expect("tmp");
        let path = dir.path().join("p.cfg");
        let cfg = format!(
            "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n\
             backend b\n  option httpchk\n  {rules}\n  server s1 127.0.0.1:1 check\n"
        );
        std::fs::write(&path, &cfg).expect("write");
        let out = Command::new(&bin)
            .arg("-c")
            .arg("-f")
            .arg(&path)
            .output()
            .unwrap_or_else(|e| panic!("run {bin}: {e}"));
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        match expected {
            Some(reason) => {
                assert!(
                    !out.status.success(),
                    "expected `{rules}` to be refused, it was accepted:\n{stderr}"
                );
                assert!(
                    stderr.contains(reason),
                    "expected `{reason}` in the stderr for `{rules}`:\n{stderr}"
                );
            }
            None => {
                assert!(
                    out.status.success(),
                    "expected `{rules}` to be accepted, it was refused:\n{stderr}"
                );
            }
        }
    }
}
