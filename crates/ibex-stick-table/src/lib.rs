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
pub use table::{KeyType, StickTable, StickTableConfig, StickTableError};
