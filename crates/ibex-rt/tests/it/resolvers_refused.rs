// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T358 #4: Ibex does no DNS resolution at run time (out of M1 scope, docs/milestones.md).
//! `HAProxy` 3.5-dev8 accepts a `resolvers` section; Ibex accepted it and dropped it, which let
//! an operator believe their servers re-resolved. The section, `resolvers` in `defaults` and
//! `resolvers` on a `server` line are refused, naming the keyword.

use std::process::Command;

fn check(cfg_text: &str) -> (bool, String) {
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(cfg.path(), cfg_text).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(cfg.path()).output().expect("run ibex -c");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

const BASE: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

#[test]
fn a_resolvers_section_is_refused() {
    let (ok, err) = check(&format!("{BASE}resolvers dns\n  nameserver ns1 127.0.0.1:53\nlisten s\n  bind 127.0.0.1:0\n"));
    assert!(!ok, "accepted and dropped");
    assert!(err.contains("'resolvers'") && err.contains("not supported"), "{err}");
}

#[test]
fn resolvers_in_defaults_and_on_a_server_are_refused() {
    let (ok, err) = check(&format!("{BASE}  resolvers dns\nlisten s\n  bind 127.0.0.1:0\n"));
    assert!(!ok && err.contains("'resolvers'"), "{err}");
    let (ok, err) = check(&format!("{BASE}listen s\n  bind 127.0.0.1:0\n  server a 127.0.0.1:1 resolvers dns\n"));
    assert!(!ok && err.contains("'resolvers'"), "{err}");
}
