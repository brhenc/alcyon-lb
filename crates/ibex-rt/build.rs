// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//! The version `ibex -v` and `show info` print, from git, as HAProxy's `3.5-dev8-885761-29`
//! comes from its tree: `IBEX_VERSION` is the package version plus `git describe` of the last
//! `ibex-*` tag (`0.1.0-rc1`, `0.1.0-rc1-3-gabcdef12`), `IBEX_COMMIT` the short commit and
//! `IBEX_DATE` its date (`2026/10/18`). Without git (a source tarball) the last two are empty
//! and the version is the package's.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn main() {
    let pkg = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let commit = git(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_default();
    let version = match git(&["describe", "--tags", "--match", "ibex-*", "--abbrev=8"]) {
        Some(d) => format!("{pkg}-{}", d.trim_start_matches("ibex-")),
        None if !commit.is_empty() => format!("{pkg}-g{commit}"),
        None => pkg,
    };
    let date = git(&["log", "-1", "--format=%cd", "--date=format:%Y/%m/%d"]).unwrap_or_default();
    println!("cargo:rustc-env=IBEX_VERSION={version}");
    println!("cargo:rustc-env=IBEX_COMMIT={commit}");
    println!("cargo:rustc-env=IBEX_DATE={date}");

    // Run again when HEAD moves (a commit, a checkout) or a tag is added. In a worktree HEAD
    // is in its own git dir, the branches and tags in the common one.
    println!("cargo:rerun-if-changed=build.rs");
    if let (Some(dir), Some(common)) = (git(&["rev-parse", "--git-dir"]), git(&["rev-parse", "--git-common-dir"])) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={common}/packed-refs");
        println!("cargo:rerun-if-changed={common}/refs/tags");
        if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
            let path = Path::new(&common).join(head_ref);
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
