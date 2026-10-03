// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::env;
use std::path::PathBuf;

fn main() {
    let haproxy_ref = env::var("HAPROXY_REF").unwrap_or_else(|_| "/home/bhenc/reference/haproxy".to_string());
    let ref_path = PathBuf::from(haproxy_ref);

    if !ref_path.exists() || !ref_path.join("src/h1.c").exists() {
        panic!("HAProxy reference tree not found at {}. Please set HAPROXY_REF to the path of the HAProxy source tree.", ref_path.display());
    }

    cc::Build::new()
        .warnings(false)
        .file(ref_path.join("src/h1.c"))
        .file(ref_path.join("src/http.c"))
        .file("src/stub.c")
        .include(ref_path.join("include"))
        .compile("haproxy-h1");

    println!("cargo:rerun-if-env-changed=HAPROXY_REF");
    println!("cargo:rerun-if-changed=src/stub.c");
}
