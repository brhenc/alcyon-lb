// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! # `ibex-stick-table`
//!
//! Stick Table engine compatible with `HAProxy` semantics.
//! Provides key-indexed connection tracking, sliding-window rate limiters,
//! general-purpose counters, and soft-realtime memory allocation.

#![forbid(unsafe_code)]

pub mod entry;
pub mod rate;
pub mod table;

pub use entry::{StickEntryData, StickKey};
pub use rate::SlidingRate;
pub use table::{coerce_key, Gpc, GpcOp, KeyType, StickTable, StickTableConfig, StickTableError};
