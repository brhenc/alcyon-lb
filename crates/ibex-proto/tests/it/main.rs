// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! ibex-proto's integration tests, one binary (T260). Each former `tests/<name>.rs` is the
//! module `<name>` here: run one file's tests with `cargo test -p ibex-proto --test it <name>::`.
//!
//! A new test file is a module listed below, not a new binary, unless it needs its own
//! process (a `#[global_allocator]`, allocation/RSS counting of the test process, rlimits,
//! signal handlers, cwd, environment changes, other process-wide state); then it gets its
//! own `[[test]]` in Cargo.toml and says why in its header. `harness/test_layout.py` fails on
//! a test file no target compiles.
//!
//! Own binaries: `htx_allocation` (reasons in Cargo.toml).

mod h1_strictness;
mod h3_framing;
mod haproxy_ffi_differential;
mod http1_conformance;
mod http2_conformance;
mod htx_differential;
mod layering;
mod parser_seam;
mod proxy_protocol_tests;
mod qpack_field_cap;
mod qpack_static;
mod smuggling_cl_te;
