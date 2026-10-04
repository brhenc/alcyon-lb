// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/sample.h, sample-t.h and src/sample.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The Sample / Converter / Matcher Lattice.
//!
//! Implements `HAProxy`'s typed sample fetch, converter, and matching engine
//! as designed in `design/007-sample-lattice.md`.

#![forbid(unsafe_code)]

pub mod auth;
pub mod cast;
pub mod expr;
pub mod fix;
pub mod hash;
pub mod localtime;
pub mod matcher;
pub mod rawpayload;
pub mod rfc7239;
pub mod registry;
pub mod sample;

pub use auth::{set_userlists, AuthUser, AuthUserlist};
pub use cast::{can_cast, cast};
pub use expr::Expr;
pub use matcher::{IntOp, IntRange, Matcher};
pub use registry::{
    check_converter_args, get_proc_var, not_implemented, not_implemented_message, sample_registry, set_proc_var, unset_proc_var, var_conds_hold, ConvDesc,
    ConvFn, CtxConvDesc, CtxConvFn, FetchDesc, FetchFn, FrontendCounter, ProxyState, Registry,
    ServerState, SampleContext, SslFacts, StickData, StickGpc, StickOp, StickState, StreamFacts, CURRENT_VARS, STOPPING, GLOBAL_PROC_VARS, SAMPLE_REGISTRY,
};
pub use rawpayload::{check_args as check_raw_fetch_args, raw_may_change};
pub use sample::{Sample, SampleType, TypeSpec, SAMPLE_TYPES_COUNT};
