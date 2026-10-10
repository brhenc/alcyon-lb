// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

use std::fmt;

/// An error encountered while parsing an `HAProxy` configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// 1-based line number where the error occurred.
    pub line: usize,
    /// 1-based column number where the error occurred.
    pub col: usize,
    /// Detailed, actionable description of what went wrong.
    pub message: String,
    /// Alerts that name their own place, as some of `HAProxy`'s checks after the parse do
    /// (`HTTP frontend 'f' enables HTTP/2 via ALPN at [cfg:9], ...`): each a line of the
    /// configuration and a text where `{at}` stands for `[file:line]`. When there are any,
    /// they are printed as they are, one per line, in place of `message`.
    pub alerts: Vec<(usize, String)>,
}

impl ConfigError {
    /// Construct a new `ConfigError` with line, column, and message.
    #[must_use]
    pub fn new(line: usize, col: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            col,
            message: message.into(),
            alerts: Vec::new(),
        }
    }

    /// An error reported as `alerts` (see the field), the first one's line as its own.
    #[must_use]
    pub fn alerts(alerts: Vec<(usize, String)>) -> Self {
        let (line, message) = alerts.first().cloned().unwrap_or_default();
        Self { line, col: 1, message, alerts }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, col {}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for ConfigError {}
