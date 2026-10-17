// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! ibex-sample's integration tests, one binary (T260). Each former `tests/<name>.rs` is the
//! module `<name>` here: run one file's tests with `cargo test -p ibex-sample --test it <name>::`.
//!
//! A new test file is a module listed below, not a new binary, unless it needs its own
//! process (a `#[global_allocator]`, allocation/RSS counting of the test process, rlimits,
//! signal handlers, cwd, environment changes, other process-wide state); then it gets its
//! own `[[test]]` in Cargo.toml and says why in its header. `harness/test_layout.py` fails on
//! a test file no target compiles.
//!
//! Own binaries: `ltime_local`, `sample_semantics` (reasons in Cargo.toml).

mod converter_batch_coverage;
mod converters_bulk;
mod matcher_unknown_method;
mod proptest_cast;
mod proptest_cidr;
mod proptest_converters;
mod proptest_expr;
mod proptest_rawpayload;
mod registry_cover;
mod rfc7239;
mod sample_arg_tokens;
mod field_word_count_overflow;
mod field_word_parity;
mod field_word_table;
mod str_to_int_cast;
mod t136_edges;
mod tcp_converters_non_binary;
mod t20_converters;
mod t251_concat_cap;
mod t251_map_tables;
