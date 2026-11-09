// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request normalize-uri` keywords (T358, T359).
//!
//! Each normalizer takes only the option `HAProxy` gives it (`full` for `path-strip-dotdot`,
//! `strict` for the percent ones); another word before the condition is refused with
//! `HAProxy`'s message (measured with `haproxy -c` on 3.5-dev8-885761-29).
//! An unknown normalizer is refused by `HAProxy` too (`unknown normalizer 'bogus'`) and was accepted
//! and ignored by Alcyon. All eight are accepted.

use std::process::Command;

// One file per call: tests run in parallel and rules of the same length used to share a name.
static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn check(rule: &str) -> (bool, String) {
    let cfg = format!(
        "global\n  expose-experimental-directives\ndefaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n\
         listen f\n  bind 127.0.0.1:1\n  http-request normalize-uri {rule}\n  server s 127.0.0.1:1\n"
    );
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("alcyon-nur-{}-{n}.cfg", std::process::id()));
    std::fs::write(&path, cfg).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_alcyon")).arg("-c").arg("-f").arg(&path).output().expect("alcyon -c");
    let _ = std::fs::remove_file(&path);
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn an_option_a_normalizer_does_not_take_is_refused_as_haproxy_does() {
    // Messages measured with `haproxy -c` on 3.5-dev8-885761-29.
    for (rule, msg) in [
        ("path-strip-dot strict", "expects either 'if' or 'unless' followed by a condition but found 'strict'"),
        ("fragment-strip strict", "expects either 'if' or 'unless' followed by a condition but found 'strict'"),
        ("percent-decode-unreserved strict x", "expects either 'if' or 'unless' followed by a condition but found 'x'"),
        ("path-strip-dotdot strict", "unknown argument 'strict' for 'path-strip-dotdot' normalizer"),
        ("percent-to-uppercase full", "unknown argument 'full' for 'percent-to-uppercase' normalizer"),
    ] {
        let (ok, err) = check(rule);
        assert!(!ok, "{rule} was accepted");
        assert!(err.contains(msg), "{rule}: {err}");
    }
}

#[test]
fn an_unknown_normalizer_is_refused() {
    let (ok, err) = check("bogus");
    assert!(!ok, "accepted");
    assert!(err.contains("unknown normalizer 'bogus'"), "{err}");
}

#[test]
fn the_normalizers_that_match_haproxy_are_accepted() {
    for rule in [
        "path-merge-slashes",
        "query-sort-by-name",
        "percent-to-uppercase",
        "percent-to-uppercase strict",
        "percent-decode-unreserved",
        "fragment-strip",
        "fragment-encode",
        "path-strip-dot",
        "path-strip-dotdot",
        "path-strip-dotdot full",
        "path-strip-dotdot full if TRUE",
    ] {
        let (ok, err) = check(rule);
        assert!(ok, "{rule} refused: {err}");
    }
}
