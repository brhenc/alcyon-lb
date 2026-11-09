// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! T461: QUIC's TLS is rustls 0.24 on the provider `tune.alcyon.crypto-provider` chooses.
//! quinn-proto is built without `rustls-ring`: in the binary's dependency graph (normal edges,
//! the features of a release build) it reaches neither *ring* nor rustls 0.23. With
//! `rustls-ring` it linked vanilla *ring* for its stateless-reset HMAC, its token keys and its
//! Retry tag even with `ring-alcyon` chosen, and its own rustls 0.23 for the handshake.

use std::process::Command;

/// What depends on `pkg`, as `cargo tree` prints it for alcyon-quic's normal (non-dev) build.
fn dependents_of(pkg: &str) -> String {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["tree", "--offline", "-e", "normal,features", "--prefix", "none", "--manifest-path", manifest, "-p", "alcyon-quic", "-i", pkg])
        .output()
        .expect("cargo tree");
    assert!(out.status.success(), "cargo tree -i {pkg}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn quinn_proto_reaches_neither_ring_nor_rustls_023() {
    let ring = dependents_of("ring");
    assert!(!ring.contains("quinn-proto"), "quinn-proto depends on vanilla ring:\n{ring}");
    let rustls = dependents_of("rustls@0.23");
    assert!(!rustls.contains("quinn-proto"), "quinn-proto depends on rustls 0.23:\n{rustls}");
}
