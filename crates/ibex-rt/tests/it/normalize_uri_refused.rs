// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! `http-request normalize-uri` keywords (T358, T359).
//!
//! `path-strip-dot` and `path-strip-dotdot` (with and without `full`) rewrite the forwarded
//! path differently from `HAProxy` (`tasks/T359-normalize-uri-path-normalizers.md` has the
//! measured outputs): a wrong rewrite can bypass a path ACL or a routing rule, so `ibex -c`
//! refuses them until they are ported (`haproxy -c` accepts them, measured on
//! 3.5-dev8-885761-29). An unknown normalizer is refused by `HAProxy` too (`unknown normalizer
//! 'bogus'`) and was accepted and ignored by Ibex. The other six keywords give the same
//! answers as `HAProxy` (measured on 15 paths each) and are accepted.

use std::process::Command;

fn check(rule: &str) -> (bool, String) {
    let cfg = format!(
        "global\n  expose-experimental-directives\ndefaults\n  mode http\n  timeout client 1s\n  timeout server 1s\n  timeout connect 1s\n\
         listen f\n  bind 127.0.0.1:1\n  http-request normalize-uri {rule}\n  server s 127.0.0.1:1\n"
    );
    let path = std::env::temp_dir().join(format!("ibex-nur-{}-{}.cfg", std::process::id(), rule.len()));
    std::fs::write(&path, cfg).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(&path).output().expect("ibex -c");
    let _ = std::fs::remove_file(&path);
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn the_path_strip_normalizers_are_refused_until_they_match_haproxy() {
    for rule in ["path-strip-dot", "path-strip-dotdot", "path-strip-dotdot full", "path-strip-dot strict"] {
        let (ok, err) = check(rule);
        assert!(!ok, "{rule} was accepted");
        assert!(err.contains("is not implemented as HAProxy does it in Ibex yet (T359)"), "{rule}: {err}");
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
    ] {
        let (ok, err) = check(rule);
        assert!(ok, "{rule} refused: {err}");
    }
}
