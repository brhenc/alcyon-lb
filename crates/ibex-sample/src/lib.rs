// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy include/haproxy/sample.h, sample-t.h and src/sample.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The Sample / Converter / Matcher Lattice.
//!
//! Implements `HAProxy`'s typed sample fetch, converter, and matching engine
//! as designed in `design/007-sample-lattice.md`.

#![forbid(unsafe_code)]

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod acl_types;
pub mod acls;
pub mod argspec;
pub mod aes;
pub mod auth;
pub mod capture_write;
pub mod cast;
mod cookie_names;
pub mod expr;
pub mod fix;
mod h1_clean;
pub mod hash;
pub mod ja4;
pub mod localtime;
pub mod matcher;
pub mod patref;
pub mod pattable;
pub mod rawpayload;
pub mod rfc7239;
pub mod registry;
pub mod sample;
pub mod vars;

pub use acls::Acls;
pub use argspec::check_typed_expr;
pub use auth::{set_userlists, AuthUser, AuthUserlist};
pub use ibex_crypt::CryptHash;
pub use cast::{can_cast, cast};
pub use expr::Expr;
pub use matcher::{IntOp, IntRange, Matcher};
pub use registry::{set_debug_sink, take_debug_destinations, DebugSinkFn, 
    check_converter_args, check_dump_all_vars_args, get_proc_var, not_implemented, not_implemented_message, sample_registry, set_proc_var, unset_proc_var, var_conds_hold, ConvDesc,
    ConvFn, CtxConvDesc, CtxConvFn, FetchDesc, FetchFn, FrontendCounter, ProxyState, Registry,
    ServerState, SampleContext, ConnErr, SslFacts, StickData, StickGpc, StickOp, StickState, StreamFacts, StreamTimeouts, TimeoutKind, CURRENT_VARS, CPU_USAGE_SOURCE, STOPPING, THREAD_ID, GLOBAL_PROC_VARS, SAMPLE_REGISTRY,
};
pub use rawpayload::{check_args as check_raw_fetch_args, raw_may_change};
pub use vars::VarMap;
pub use sample::{Sample, SampleType, TypeSpec, SAMPLE_TYPES_COUNT};
