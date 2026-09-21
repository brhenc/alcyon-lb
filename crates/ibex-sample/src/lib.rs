// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/sample.h, sample-t.h and src/sample.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The Sample / Converter / Matcher Lattice.
//!
//! Implements `HAProxy`'s typed sample fetch, converter, and matching engine
//! as designed in `design/007-sample-lattice.md`.

#![forbid(unsafe_code)]

pub mod cast;
pub mod expr;
pub mod matcher;
pub mod registry;
pub mod sample;

pub use cast::{can_cast, cast};
pub use expr::Expr;
pub use matcher::{IntOp, Matcher};
pub use registry::{ConvDesc, ConvFn, FetchDesc, FetchFn, Registry, SampleContext};
pub use sample::{Sample, SampleType, TypeSpec, SAMPLE_TYPES_COUNT};
