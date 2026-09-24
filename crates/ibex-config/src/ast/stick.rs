// SPDX-License-Identifier: GPL-2.0-or-later
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// Stick table configuration in AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickTableConfigAst {
    pub key_type: String,
    pub size: usize,
    pub expire: Duration,
    pub store_fields: Vec<String>,
}

/// Stick rule type and sample expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StickRule {
    pub rule_type: StickRuleType,
    pub expr: String,
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

