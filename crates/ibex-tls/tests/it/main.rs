// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

#![allow(clippy::disallowed_macros)] // tests print with eprintln!; see /clippy.toml

//! ibex-tls's integration tests, one binary (T260). Each former `tests/<name>.rs` is the
//! module `<name>` here: run one file's tests with `cargo test -p ibex-tls --test it <name>::`.
//!
//! A new test file is a module listed below, not a new binary, unless it needs its own
//! process (a `#[global_allocator]`, allocation/RSS counting of the test process, rlimits,
//! signal handlers, cwd, environment changes, other process-wide state); then it gets its
//! own `[[test]]` in Cargo.toml and says why in its header. `harness/test_layout.py` fails on
//! a test file no target compiles.
//!
//! Own binaries: `server_verify` (reasons in Cargo.toml).

#[path = "../common/mod.rs"]
mod common;

mod arena;
mod cert_validation;
mod config;
mod e2e_tls_nginx_proxy;
mod handshake;
mod resolver;
mod tcp_ctx;
mod tokio_integration;
