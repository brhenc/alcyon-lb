// SPDX-License-Identifier: LGPL-2.1-only
// Copyright (C) 2002-2011 Willy Tarreau <w@1wt.eu>. See LICENSE.

//! ebtree's integration tests, one binary (T260). Each former `tests/<name>.rs` is the
//! module `<name>` here: run one file's tests with `cargo test -p ebtree --test it <name>::`.
//!
//! A new test file is a module listed below, not a new binary, unless it needs its own
//! process (a `#[global_allocator]`, allocation/RSS counting of the test process, rlimits,
//! signal handlers, cwd, environment changes, other process-wide state); then it gets its
//! own `[[test]]` in Cargo.toml and says why in its header. harness/test_layout.py fails on
//! a test file no target compiles.

mod delete_and_ge;
mod differential;
mod proptest_diff;
mod proptest_stateful;
