// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// Stick table configuration in AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickTableConfigAst {
    pub key_type: String,
    /// `len <n>` of a `string` or `binary` type: the longest key kept; `None` is the default (32).
    pub key_len: Option<usize>,
    pub size: usize,
    pub expire: Duration,
    pub store_fields: Vec<String>,
}

/// Stick rule type and sample expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickRule {
    pub rule_type: StickRuleType,
    pub expr: String,
    /// `table <name>` of `stick on|match|store-request|store-response`: the proxy whose
    /// stick-table the rule uses; `None` is the section's own.
    pub table: Option<String>,
    /// `if|unless <cond>` of the same.
    pub cond: Option<AclCondition>,
}

impl StickRule {
    /// A rule with no `table` and no condition (what `track-sc*` takes).
    #[must_use]
    pub fn new(rule_type: StickRuleType, expr: String) -> Self {
        Self { rule_type, expr, table: None, cond: None }
    }
}

/// Type of stick rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StickRuleType {
    StickOn,
    StickMatch,
    StickStoreRequest,
    StickStoreResponse,
    TrackSc0,
    TrackSc1,
    TrackSc2,
}

