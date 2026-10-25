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


/// The kind of section a [`SampleRef`] was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    Defaults,
    Frontend,
    Backend,
    Listen,
}

/// Where a sample expression was written, as the parser saw it: an ACL's expression
/// (`acl <name> <expr>`, `{ <expr> ... }`) or a log-format's `%[<expr>]`.
///
/// `HAProxy` resolves the backend, server and table arguments of every sample expression
/// when it loads the configuration, and so must Ibex; but ACLs are stored as text and
/// log-formats are spread over dozens of actions, so the parser records each expression
/// here, with its section, for the runtime's load-time check to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleRef {
    /// 1-based line of the configuration the expression is on.
    pub line: usize,
    /// The section it is in.
    pub section: SectionKind,
    /// That section's name (`None` for an unnamed `defaults`).
    pub proxy: Option<String>,
    /// Whether it is an ACL expression (`true`) or a log-format's (`false`).
    pub acl: bool,
    /// The directive the expression is on, its first word (`http-request`,
    /// `unique-id-format`, ...).
    pub directive: String,
    /// The directive's second word: the action of a rule (`set-header`,
    /// `set-var-fmt(txn.x)`), empty when there is none.
    pub action: String,
    /// The expression: the fetch, its arguments and its converters (`nbsrv(be),add(1)`),
    /// without an ACL's pattern or a log-format's surroundings.
    pub expr: String,
    /// For an anonymous ACL (`{ ... }`), the whole expression with its flags and patterns,
    /// as `acl <name> ...` would hold it: what is compiled when the configuration loads.
    pub full: Option<String>,
    /// `expr` is a whole format string (a rule's `set-header` value, `redirect` target,
    /// `lf-string`, ...), to be compiled as `HAProxy` compiles a rule's `log-format`, so that an
    /// alias it does not know is refused at load (T455). `acl` is `false` and the `%[...]`
    /// expressions in it are recorded on their own, before this one.
    pub whole_format: bool,
}
