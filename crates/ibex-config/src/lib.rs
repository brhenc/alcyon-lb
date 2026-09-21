//! # `ibex-config`
//!
//! HAProxy configuration grammar parser, AST representations, and ACL evaluation engine.

pub mod acl;
pub mod ast;
pub mod parser;

pub use acl::{evaluate_acl, RequestEvaluationContext};
pub use ast::*;
pub use parser::ConfigParser;
