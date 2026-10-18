// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! ibex-crypt's integration tests, one binary (T260). Each former `tests/<name>.rs` is the
//! module `<name>` here: run one file's tests with `cargo test -p ibex-crypt --test it <name>::`.
//!
//! A new test file is a module listed below, not a new binary, unless it needs its own
//! process (a `#[global_allocator]`, allocation/RSS counting of the test process, rlimits,
//! signal handlers, cwd, environment changes, other process-wide state); then it gets its
//! own `[[test]]` in Cargo.toml and says why in its header. `harness/test_layout.py` fails on
//! a test file no target compiles.

mod glibc_vectors;
mod xxh3;
