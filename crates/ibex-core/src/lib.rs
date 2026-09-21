//! # `ibex-core`
//!
//! Foundations and soft-realtime safety primitives for Project Ibex.
//! Implements NASA JPL Power of 10 safety guidelines:
//! - Static pre-allocation at initialization (zero heap alloc on request path).
//! - Statically bounded loops (`bounded_loop!`).
//! - High assertion density (`ibex_assert!`).
//! - Bounded ring buffers and fixed-capacity object pools.

pub mod arena;
pub mod bounded;
pub mod error;
pub mod jpl;
pub mod pool;

pub use arena::StaticArena;
pub use bounded::{BoundedRingBuffer, BoundedVec};
pub use error::{IbexError, IbexResult};
pub use jpl::SafetyContract;
pub use pool::FixedPool;
