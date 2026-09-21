//! # `ibex-vtest`
//!
//! HAProxy VTest / VTC regression test runner and parser in Rust.

pub mod runner;
pub mod vtc;

pub use runner::{VtcRunner, VtcTestReport};
pub use vtc::{VtcClientSpec, VtcParser, VtcScript, VtcServerSpec};
