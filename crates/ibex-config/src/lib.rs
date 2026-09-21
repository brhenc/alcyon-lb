// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

//! `HAProxy` 1.0 configuration parser for Ibex.
//!
//! Provides a typed abstract syntax tree (AST), lexical analyzer, and configuration
//! parser matching the syntax and semantics of `HAProxy` 1.0.2.

#![forbid(unsafe_code)]

pub mod ast;
pub mod error;
pub mod lexer;
pub mod parser;

use std::fs;
use std::path::Path;

pub use ast::{Config, HeaderExp, ListenSection, LogConfig, LogFacility, LogLevel, Mode, Server};
pub use error::ConfigError;
pub use parser::parse_str;

/// Parses an `HAProxy` 1.0 configuration file from disk.
///
/// # Errors
///
/// Returns a `ConfigError` if the file cannot be read or if parsing fails.
pub fn parse_file(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path_ref = path.as_ref();
    let content = fs::read_to_string(path_ref).map_err(|e| {
        ConfigError::new(
            1,
            1,
            format!("Error reading configuration file '{}': {e}", path_ref.display()),
        )
    })?;
    parse_str(&content)
}
