// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T479: rustls 0.24 is the only rustls any non-test target links. rustls 0.23 stays a
//! dev-dependency (an independent client in `tcp_ctx.rs`, and the HTTP/3 test clients of
//! ibex-quic and ibex-rt), never a normal one: in the workspace's normal dependency graph
//! nothing depends on it.

use std::process::Command;

#[test]
fn no_workspace_crate_has_rustls_023_as_a_normal_dependency() {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["tree", "--offline", "-e", "normal", "--prefix", "none", "--workspace", "--manifest-path", manifest, "-i", "rustls@0.23"])
        .output()
        .expect("cargo tree");
    assert!(out.status.success(), "cargo tree -i rustls@0.23: {}", String::from_utf8_lossy(&out.stderr));
    let dependents = String::from_utf8_lossy(&out.stdout);
    assert!(dependents.trim().is_empty(), "rustls 0.23 is a normal dependency of:\n{dependents}");
}
