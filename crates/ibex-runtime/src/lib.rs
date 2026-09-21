//! # `ibex-runtime`
//!
//! High-performance async runtime combining:
//! - Pingora foundations
//! - RCU dynamic routing tables
//! - Stick table tracking and ACL evaluation
//! - Dynamic HTX / Pingora parser dispatching

pub mod engine;
pub mod rcu_table;

pub use engine::IbexEngine;
pub use rcu_table::{RcuRoutingTable, RoutingSnapshot};
