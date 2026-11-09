// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::env;
use std::path::PathBuf;

// This crate compiles HAProxy's own src/h1.c and src/http.c, for alcyon-proto's opt-in
// `haproxy-ffi` feature. It is not a default member of the workspace (T630), so `cargo build`
// and `cargo test` on a machine with no HAProxy tree never get here; `--workspace` (the gate)
// does, and needs the tree: `HAPROXY_REF`, else `$ALCYON_REFERENCE/haproxy` (README, "Running
// the oracle tests").
fn main() {
    println!("cargo:rerun-if-env-changed=HAPROXY_REF");
    println!("cargo:rerun-if-env-changed=ALCYON_REFERENCE");
    let ref_path = match (env::var_os("HAPROXY_REF").filter(|v| !v.is_empty()), env::var_os("ALCYON_REFERENCE").filter(|v| !v.is_empty())) {
        (Some(tree), _) => PathBuf::from(tree),
        (None, Some(reference)) => PathBuf::from(reference).join("haproxy"),
        (None, None) => panic!(
            "alcyon-h1-sys needs the HAProxy source tree: set ALCYON_REFERENCE (the directory holding haproxy/src/h1.c; \
             README, \"Running the oracle tests\") or HAPROXY_REF (the tree itself). Plain `cargo build` / `cargo test` \
             leave this crate out."
        ),
    };

    if !ref_path.join("src/h1.c").exists() {
        panic!(
            "HAProxy reference tree not found at {} (from HAPROXY_REF or ALCYON_REFERENCE): no src/h1.c there.",
            ref_path.display()
        );
    }

    cc::Build::new()
        .warnings(false)
        .file(ref_path.join("src/h1.c"))
        .file(ref_path.join("src/http.c"))
        .file("src/stub.c")
        .include(ref_path.join("include"))
        .compile("haproxy-h1");

    println!("cargo:rerun-if-changed=src/stub.c");
}
