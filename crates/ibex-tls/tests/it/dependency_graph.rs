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

fn tree(args: &[&str]) -> (bool, String, String) {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["tree", "--offline", "-e", "normal", "--prefix", "none", "--manifest-path", manifest])
        .args(args)
        .output()
        .expect("cargo tree");
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Zeroize review (zrev): QUIC reaches vanilla `ring` only through the provider selection
/// (`tune.ibex.crypto-provider ring`). The vendored quinn-proto is built without its `ring`
/// feature (its own HMAC/HKDF/AEAD would bypass `ring-ibex`): `ring` is not in its normal graph,
/// and in the whole workspace's normal graph the only crate that depends on `ring` is
/// `rustls-ring`, the provider `ibex_tls::provider` picks it by.
#[test]
fn quic_reaches_vanilla_ring_only_through_the_rustls_ring_provider() {
    let (ok, out, err) = tree(&["-p", "quinn-proto"]);
    assert!(ok, "cargo tree: {err}");
    assert!(!out.lines().any(|l| l.starts_with("ring ") || l.starts_with("rustls ")), "quinn-proto's normal graph contains ring or rustls 0.23:\n{out}");
    let (ok, out, err) = tree(&["--workspace", "-i", "ring@0.17.14", "--depth", "1"]);
    assert!(ok, "cargo tree: {err}");
    let dependents: Vec<&str> = out.lines().skip(1).filter(|l| !l.trim().is_empty()).collect();
    assert!(dependents.len() == 1 && dependents[0].starts_with("rustls-ring "), "vanilla ring has other normal dependents:\n{out}");
}

/// The same for the fork: only its rustls provider depends on `ringibex`.
#[test]
fn ringibex_is_reached_only_through_its_rustls_provider() {
    let (ok, out, err) = tree(&["--workspace", "-i", "ringibex", "--depth", "1"]);
    assert!(ok, "cargo tree: {err}");
    let dependents: Vec<&str> = out.lines().skip(1).filter(|l| !l.trim().is_empty()).collect();
    assert!(dependents.len() == 1 && dependents[0].starts_with("rustls-ringibex "), "ringibex has other normal dependents:\n{out}");
}
