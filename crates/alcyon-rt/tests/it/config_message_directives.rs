// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `.alert`, `.warning`, `.notice` and `.diag` in a configuration (T146 item 16, after T131).
//!
//! Measured on `HAProxy 3.5-dev8-885761-29` on 2026-10-04 with `-c`: `.alert` is fatal
//! (exit 1, "[ALERT] ... parsing [file:line]: 'text'."), `.warning` and `.notice` print the
//! same line at their own severity and the load goes on, `.diag` prints nothing without
//! `-dD`, and none of them does anything inside an `.if` that is false. They take at most
//! one argument: "Unexpected argument 'b' for '.warning'. Use quotes if the message should
//! contain spaces."; none is an empty message.

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

fn check(body: &str) -> (bool, String, String) {
    let mut f = NamedTempFile::new().expect("tmp");
    f.write_all(body.as_bytes()).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(f.path()).output().expect("run");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned(), f.path().display().to_string())
}

#[test]
fn alert_is_fatal_and_the_others_print() {
    let (ok, err, path) = check(".alert \"boom here\"\n");
    assert!(!ok, "an .alert must stop the load: {err}");
    assert!(err.contains("'boom here'."), "{err}");

    let (ok, err, path_w) = check(".warning \"careful\"\n");
    assert!(ok, "a .warning must not stop the load: {err}");
    assert!(err.contains(&format!("config : parsing [{path_w}:1]: 'careful'.")) && err.contains("[WARNING]"), "{err}");

    let (ok, err, path_n) = check("defaults\n  mode http\n.notice \"fyi\"\n");
    assert!(ok, "{err}");
    assert!(err.contains(&format!("config : parsing [{path_n}:3]: 'fyi'.")) && err.contains("[NOTICE]"), "{err}");
    let _ = path;

    let (ok, err, _) = check(".diag \"diagnostic\"\n");
    assert!(ok && !err.contains("diagnostic"), "{err}");
}

#[test]
fn nothing_happens_in_a_false_if_and_arguments_are_checked() {
    let (ok, err, _) = check(".if 0\n.alert \"no\"\n.warning \"no\"\n.endif\n");
    assert!(ok && !err.contains("'no'"), "{err}");
    let (ok, err, path) = check(".if 1\n.warning \"yes\"\n.endif\n");
    assert!(ok && err.contains(&format!("parsing [{path}:2]: 'yes'.")), "{err}");

    let (ok, err, _) = check(".alert\n");
    assert!(!ok && err.contains("''."), "{err}");
    for kw in [".warning", ".alert", ".notice"] {
        let (ok, err, _) = check(&format!("{kw} a b \"c d\"\n"));
        assert!(
            !ok && err.contains(&format!("Unexpected argument 'b' for '{kw}'. Use quotes if the message should contain spaces.")),
            "{kw}: {err}"
        );
    }
}
