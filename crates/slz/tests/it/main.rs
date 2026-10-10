// SPDX-License-Identifier: MIT
// Copyright (C) 2013-2015 Willy Tarreau <w@1wt.eu>. See crates/slz/LICENSE.

//! slz's integration tests, one binary (T260). Each former `tests/<name>.rs` is the
//! module `<name>` here: run one file's tests with `cargo test -p slz --test it <name>::`.
//!
//! A new test file is a module listed below, not a new binary, unless it needs its own
//! process (a `#[global_allocator]`, allocation/RSS counting of the test process, rlimits,
//! signal handlers, cwd, environment changes, other process-wide state); then it gets its
//! own `[[test]]` in Cargo.toml and says why in its header. harness/test_layout.py fails on
//! a test file no target compiles.

mod test_slz;
