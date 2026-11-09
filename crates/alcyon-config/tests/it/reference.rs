// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Where this crate's oracle tests find `HAProxy` (T630; the same helper as alcyon-rt's tests/common).

/// `$ALCYON_REFERENCE/<rel>`: a file of the reference `HAProxy` builds (T630; README, "Running the
/// oracle tests"), for example `haproxy/haproxy`, `haproxy-quic/haproxy` or
/// `haproxy-1.0.2/haproxy102`. `None`, after a line saying why the caller skips, when the
/// variable is unset or empty or the file is not there. There is no default under anyone's
/// home; the gate checks the files exist before its suite runs (`harness/reference.py
/// --require`), so a skip cannot pass a gate.
pub fn reference(rel: &str) -> Option<std::path::PathBuf> {
    let Some(root) = std::env::var_os("ALCYON_REFERENCE").filter(|v| !v.is_empty()) else {
        println!("skipped: ALCYON_REFERENCE is not set (this test needs $ALCYON_REFERENCE/{rel})");
        return None;
    };
    let p = std::path::Path::new(&root).join(rel);
    if p.exists() {
        Some(p)
    } else {
        println!("skipped: {} does not exist (ALCYON_REFERENCE)", p.display());
        None
    }
}
