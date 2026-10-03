// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
#![allow(clippy::struct_excessive_bools)]

#[allow(unused_imports)]
use super::*;

/// ACL condition with `if` or `unless` and multiple ACL terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclCondition {
    /// True for `if`, false for `unless`.
    pub is_if: bool,
    /// ACL terms (e.g. `is_static !is_local` or `{ path_beg /api/ }`), which must all hold. A term
    /// named [`AclCondition::OR`] separates alternatives: `a b || c` is `(a && b) || c`,
    /// as `HAProxy` reads it (`build_acl_cond`, src/acl.c).
    pub terms: Vec<AclTerm>,
}

impl AclCondition {
    /// The name of the separator term between alternatives (`||` or `or` in the config).
    pub const OR: &'static str = "||";

    /// The alternatives, each a run of terms that must all hold.
    pub fn suites(&self) -> impl Iterator<Item = &[AclTerm]> {
        self.terms.split(|t| t.name == Self::OR)
    }
}

/// Single term within an ACL condition expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclTerm {
    /// Whether the term is negated with `!`.
    pub negated: bool,
    /// Name or inline expression of the ACL to evaluate.
    pub name: String,
}

/// Declared ACL rule (`acl <name> <expr>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    /// ACL name (e.g. `is_static`).
    pub name: String,
    /// Raw sample expression & matcher pattern (e.g. `path_beg /static` or `req.hdr(Host),lower -m str example.com`).
    pub expr: String,
}

