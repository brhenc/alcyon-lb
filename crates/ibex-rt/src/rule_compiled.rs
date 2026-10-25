// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The expressions of the `http-request`, `http-response` and `http-after-response` rules,
//! compiled when the proxy is built: a rule's condition with its ACLs resolved, its sample
//! expression, its format's `%[...]`. `HAProxy` compiles them at load (`build_acl_cond`,
//! `sample_parse_expr`, `parse_logformat_string`); Ibex looked each one up by its text, in a
//! per-thread map, on every request (S7, `docs/design/memory-2026-10-24.md` §1.3).
//!
//! What they render and evaluate to is what the text forms do ([`crate::engine`]'s
//! `eval_condition` and `render_sample_format_into`); only the lookups are gone.

use ibex_config::{AclCondition, HttpAfterResAction, HttpReqAction, HttpResAction};
use ibex_sample::acls::AclRef;
use ibex_sample::{Acls, Expr, Registry, SampleContext};

use crate::proxy::AclEvalResult;

/// One term of a [`Cond`].
#[derive(Debug, Clone)]
enum Term {
    /// `always_true` / `always_false`, and a term that names nothing and does not parse (false).
    Const(bool),
    /// One of the proxy's ACLs.
    Acl(AclRef),
    /// An anonymous ACL (`{ path_beg /x }`) or a bare expression.
    Expr(Box<Expr>),
}

/// A rule's condition, its terms resolved against the proxy's ACLs.
#[derive(Debug, Clone)]
pub struct Cond {
    is_if: bool,
    /// The alternatives (the runs of terms between `||`), each term with whether it is negated.
    suites: Vec<Vec<(bool, Term)>>,
}

impl Cond {
    /// `cond` with its names looked up in `acls` now, as `eval_condition` looks them up per
    /// request: `always_true`, `always_false`, then the ACL of that name, then the name as an
    /// expression.
    #[must_use]
    pub fn compile(cond: &AclCondition, acls: &Acls) -> Self {
        let term = |name: &str| match name {
            "always_true" => Term::Const(true),
            "always_false" => Term::Const(false),
            name => acls.resolve(name).map_or_else(|| Expr::parse(name).map_or(Term::Const(false), |e| Term::Expr(Box::new(e))), Term::Acl),
        };
        let suites = cond.suites().map(|s| s.iter().map(|t| (t.negated, term(&t.name))).collect()).collect();
        Self { is_if: cond.is_if, suites }
    }

    /// Whether the condition holds, `acls` being the ones it was compiled with.
    #[must_use]
    pub fn eval(&self, ctx: &SampleContext, acls: &Acls, registry: &Registry) -> bool {
        crate::proxy::combine_suites(self.is_if, self.suites.iter().map(Vec::as_slice), |(negated, term)| {
            let res = match term {
                Term::Const(b) => *b,
                Term::Acl(r) => acls.at(*r).is_some_and(|e| e.eval(registry, ctx)),
                Term::Expr(e) => e.eval(registry, ctx),
            };
            if *negated ^ res {
                AclEvalResult::Matched
            } else {
                AclEvalResult::NotMatched
            }
        }) == AclEvalResult::Matched
    }
}

/// A piece of a [`Format`].
#[derive(Debug, Clone)]
enum Seg {
    /// Text written as it is.
    Lit(String),
    /// A `%[...]`: its sample, encoded as the format's context wants; nothing for one that does
    /// not parse.
    Sample(Option<Box<Expr>>),
    /// A `%<alias>`.
    Alias(String),
}

/// A rule's format (`set-header`, `add-header`, `set-var-fmt`), cut into its pieces.
#[derive(Debug, Clone, Default)]
pub struct Format {
    segs: Vec<Seg>,
}

impl Format {
    /// `fmt` cut as `render_sample_format_into` reads it.
    #[must_use]
    pub fn compile(fmt: &str) -> Self {
        let mut segs = Vec::new();
        let mut lit = String::new();
        let mut chars = fmt.char_indices().peekable();
        while let Some((_, c)) = chars.next() {
            if c != '%' {
                lit.push(c);
                continue;
            }
            match chars.peek().map(|p| p.1) {
                Some('[') => {
                    chars.next();
                    let start = chars.peek().map_or(fmt.len(), |p| p.0);
                    let mut end = fmt.len();
                    let mut depth = 1;
                    for (i, ec) in chars.by_ref() {
                        if ec == '[' {
                            depth += 1;
                        } else if ec == ']' {
                            depth -= 1;
                            if depth == 0 {
                                end = i;
                                break;
                            }
                        }
                    }
                    flush(&mut segs, &mut lit);
                    segs.push(Seg::Sample(Expr::parse(&fmt[start..end]).ok().map(Box::new)));
                }
                Some(a) if a.is_ascii_alphanumeric() => {
                    let start = chars.peek().map_or(fmt.len(), |p| p.0);
                    let mut end = fmt.len();
                    while let Some(&(i, ac)) = chars.peek() {
                        if !ac.is_ascii_alphanumeric() {
                            end = i;
                            break;
                        }
                        chars.next();
                    }
                    flush(&mut segs, &mut lit);
                    segs.push(Seg::Alias(fmt[start..end].to_string()));
                }
                Some('%') => {
                    chars.next();
                    lit.push('%');
                }
                _ => lit.push('%'),
            }
        }
        flush(&mut segs, &mut lit);
        Self { segs }
    }

    /// Rendered and appended to `out`; `http` encodes the samples and aliases as a header
    /// value wants them.
    pub fn render_into(&self, out: &mut String, ctx: &SampleContext, registry: &Registry, http: bool) {
        let push = |out: &mut String, v: &str| if http { crate::engine::push_http_encoded(out, v) } else { out.push_str(v) };
        for seg in &self.segs {
            match seg {
                Seg::Lit(s) => out.push_str(s),
                Seg::Sample(e) => {
                    if let Some(smp) = e.as_ref().and_then(|e| e.eval_sample(registry, ctx)) {
                        crate::engine::push_sample(out, &smp, &push);
                        ibex_sample::spare::give_sample(smp);
                    }
                }
                Seg::Alias(name) => crate::engine::push_alias(out, name, ctx, &push),
            }
        }
    }
}

fn flush(segs: &mut Vec<Seg>, lit: &mut String) {
    if !lit.is_empty() {
        segs.push(Seg::Lit(std::mem::take(lit)));
    }
}

/// A proxy's rule lists, compiled ([`crate::engine::Proxy::rules`]): one entry per rule of
/// each list, in its order.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    pub http_req: Vec<Rule>,
    pub http_res: Vec<Rule>,
    pub http_after_res: Vec<Rule>,
}

/// What one rule has compiled: its condition, its expression, its format.
#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub cond: Option<Cond>,
    pub expr: Option<Expr>,
    pub fmt: Option<Format>,
}

impl Rule {
    fn new(cond: Option<&AclCondition>, acls: &Acls, expr: Option<&str>, fmt: Option<&str>) -> Self {
        Self {
            cond: cond.map(|c| Cond::compile(c, acls)),
            expr: expr.and_then(|e| Expr::parse(e).ok()),
            fmt: fmt.map(Format::compile),
        }
    }
}

/// The `http-request` rules', in their order.
#[must_use]
pub fn http_req(rules: &[ibex_config::HttpReqRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| {
            let (expr, fmt) = match &r.action {
                HttpReqAction::Capture { expr, .. } | HttpReqAction::SetVar { expr, .. } => (Some(expr.as_str()), None),
                HttpReqAction::SetHeader { fmt, .. } | HttpReqAction::AddHeader { fmt, .. } | HttpReqAction::SetVarFmt { fmt, .. } => (None, Some(fmt.as_str())),
                _ => (None, None),
            };
            Rule::new(r.cond.as_ref(), acls, expr, fmt)
        })
        .collect()
}

/// What a response `set-header`/`add-header` compiles: the response rules keep their other
/// actions under names that start with a NUL (`\0set-var:<name>` and its expression, ...);
/// of those, `set-var` has an expression and `set-var-fmt` a format.
fn res_header(cond: Option<&AclCondition>, acls: &Acls, name: &str, fmt: &str) -> Rule {
    if name.starts_with("\0set-var:") {
        Rule::new(cond, acls, Some(fmt), None)
    } else if name.starts_with("\0set-var-fmt:") || !name.starts_with('\0') {
        Rule::new(cond, acls, None, Some(fmt))
    } else {
        Rule::new(cond, acls, None, None)
    }
}

/// The `http-response` rules', in their order.
#[must_use]
pub fn http_res(rules: &[ibex_config::HttpResRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| match &r.action {
            HttpResAction::SetHeader { name, fmt } | HttpResAction::AddHeader { name, fmt } => res_header(r.cond.as_ref(), acls, name, fmt),
            _ => Rule::new(r.cond.as_ref(), acls, None, None),
        })
        .collect()
}

/// The `http-after-response` rules', in their order.
#[must_use]
pub fn http_after_res(rules: &[ibex_config::HttpAfterResRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| match &r.action {
            HttpAfterResAction::SetHeader { name, fmt } | HttpAfterResAction::AddHeader { name, fmt } => res_header(r.cond.as_ref(), acls, name, fmt),
            HttpAfterResAction::Capture { .. } | HttpAfterResAction::DelHeader { .. } => Rule::new(r.cond.as_ref(), acls, None, None),
        })
        .collect()
}
