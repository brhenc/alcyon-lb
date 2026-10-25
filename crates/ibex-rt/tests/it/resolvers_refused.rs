// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! T358 #4, revised by T483: a `resolvers` section is parsed and checked as `HAProxy` 3.5-dev8
//! does (T483), but nothing resolves at run time until T484, so what would use it, a
//! server's `resolvers` (or `default-server`'s), is refused naming the keyword: an operator
//! must not believe their servers re-resolve.

use std::process::Command;

fn check(cfg_text: &str) -> (bool, String) {
    let cfg = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(cfg.path(), cfg_text).expect("write cfg");
    let out = Command::new(env!("CARGO_BIN_EXE_ibex")).arg("-c").arg("-f").arg(cfg.path()).output().expect("run ibex -c");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

const BASE: &str = "defaults\n  mode http\n  timeout connect 1s\n  timeout client 1s\n  timeout server 1s\n";

#[test]
fn a_resolvers_section_is_parsed() {
    let (ok, err) = check(&format!("{BASE}resolvers dns\n  nameserver ns1 127.0.0.1:53\nlisten s\n  bind 127.0.0.1:0\n"));
    assert!(ok, "{err}");
    // A section line is a section wherever it is indented, as in `HAProxy`: this one has no
    // nameserver, which is a warning.
    let (ok, err) = check(&format!("{BASE}  resolvers dns\nlisten s\n  bind 127.0.0.1:0\n"));
    assert!(ok && err.contains("resolvers 'dns' [") && err.contains("has no nameservers configured!"), "{err}");
}

#[test]
fn resolvers_on_a_server_or_default_server_is_refused() {
    let ns = "resolvers dns\n  nameserver ns1 127.0.0.1:53\n";
    let (ok, err) = check(&format!("{BASE}{ns}listen s\n  bind 127.0.0.1:0\n  server a 127.0.0.1:1 resolvers dns\n"));
    assert!(!ok && err.contains("'resolvers' is not supported"), "{err}");
    let (ok, err) = check(&format!("{BASE}{ns}listen s\n  bind 127.0.0.1:0\n  default-server resolvers dns\n  server a 127.0.0.1:1\n"));
    assert!(!ok && err.contains("'resolvers' is not supported"), "{err}");
}
