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

use ibex_config::{AclCondition, HttpAfterResAction, HttpReqAction, HttpResAction, TcpReqConnAction, TcpReqContentAction, TcpReqSessionAction, TcpResAction};
use ibex_sample::acls::AclRef;
use ibex_sample::{Acls, Expr, Registry, SampleContext};

use crate::logfmt::{LogData, LogFormat, Part};
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

impl Cond {
    /// [`Cond::eval`] for a `tcp-request content` rule, which may wait for more data
    /// (the payload-aware evaluation, `proxy::eval_expr_extended`).
    #[must_use]
    pub fn eval_extended(&self, ctx: &SampleContext, acls: &Acls, registry: &Registry, req_bytes: &[u8], can_wait: bool) -> AclEvalResult {
        self.eval_terms(acls, |e, negated| crate::proxy::eval_expr_extended(e, negated, registry, ctx, req_bytes, can_wait))
    }

    /// The condition combined as `acl_exec_cond` does, each term that resolves to an expression
    /// judged by `judge` (the expression and whether the term is negated). A term that names
    /// nothing is a miss that `!` turns into a hit.
    #[must_use]
    pub fn eval_terms(&self, acls: &Acls, mut judge: impl FnMut(&Expr, bool) -> AclEvalResult) -> AclEvalResult {
        crate::proxy::combine_suites(self.is_if, self.suites.iter().map(Vec::as_slice), |(negated, term)| {
            let hit = |b: bool| if *negated ^ b { AclEvalResult::Matched } else { AclEvalResult::NotMatched };
            match term {
                Term::Const(b) => hit(*b),
                Term::Acl(r) => acls.at(*r).map_or_else(|| hit(false), |e| judge(e, *negated)),
                Term::Expr(e) => judge(e, *negated),
            }
        })
    }
}

/// A rule's format (`set-header`, `add-header`, `set-var-fmt`), compiled by the `log-format`
/// compiler ([`LogFormat::compile_rule`], T455): `HAProxy` compiles it at load
/// (`parse_logformat_string`) and refuses what it does not know, which
/// [`crate::proxy_state::check_sample_refs`] does for Ibex; what is left here has compiled.
#[derive(Debug, Clone, Default)]
pub struct Format {
    lf: Option<LogFormat>,
    /// The whole format when it is only text: written as it is.
    literal: Option<String>,
    /// The pieces of a format that is text and plain samples: rendered without the line
    /// renderer, as `HAProxy` does a header value (a sample written `%XX`-encoded when `http`).
    parts: Option<Vec<Part>>,
    http: bool,
    /// It has an alias, so it reads the context's names and addresses at least.
    alias: bool,
    /// It reads the stream's measures ([`LogFormat::needs_stream`]) / the request line.
    stream: bool,
    line: bool,
}

/// What a format with only text and samples is given in place of the stream's data.
fn no_data() -> &'static LogData<'static> {
    static EMPTY: std::sync::LazyLock<LogData<'static>> = std::sync::LazyLock::new(LogData::default);
    &EMPTY
}

impl Format {
    /// `fmt` compiled; `http` is whether a sample is written `%XX`-encoded, as a header's or a
    /// path's value wants (`LOG_OPT_HTTP`). A format that does not compile renders nothing: the
    /// load refused it before.
    #[must_use]
    pub fn compile(fmt: &str, http: bool) -> Self {
        let lf = LogFormat::compile_rule(fmt, crate::engine::sample_registry(), http).ok();
        let literal = lf.as_ref().and_then(LogFormat::literal);
        let alias = lf.as_ref().is_some_and(LogFormat::has_alias);
        let stream = lf.as_ref().is_some_and(LogFormat::needs_stream);
        let line = lf.as_ref().is_some_and(LogFormat::uses_request_line);
        let parts = lf.as_ref().and_then(LogFormat::parts).filter(|_| literal.is_none());
        Self { lf, literal, parts, http, alias, stream, line }
    }

    /// Rendered and appended to `out`. `data` is what the caller knows of the stream; without
    /// it a format that reads nothing of the stream but `ctx`'s names and addresses is rendered
    /// from `ctx` alone, and any other from what a stream that has just begun measured.
    pub fn render_into(&self, out: &mut String, ctx: &SampleContext, registry: &Registry, data: Option<&LogData>) {
        if let Some(text) = &self.literal {
            out.push_str(text);
            return;
        }
        if let (Some(parts), None) = (&self.parts, data) {
            let push = |out: &mut String, v: &str| if self.http { crate::engine::push_http_encoded(out, v) } else { out.push_str(v) };
            for part in parts {
                match part {
                    Part::Text(t) => out.push_str(t),
                    Part::Sample(e) => {
                        if let Some(smp) = e.eval_smp(registry, ctx) {
                            crate::engine::push_smp(out, &smp, &push);
                        }
                    }
                }
            }
            return;
        }
        let Some(lf) = &self.lf else { return };
        match data {
            Some(d) => lf.render_value_into(out, d, registry, ctx),
            None if self.alias => lf.render_value_into(out, &LogData::of_context(ctx), registry, ctx),
            None => lf.render_value_into(out, no_data(), registry, ctx),
        }
    }

    /// Whether the format reads the request line ([`LogFormat::uses_request_line`]).
    #[must_use]
    pub fn uses_request_line(&self) -> bool {
        self.line
    }

    /// Whether the format reads the stream's measures ([`LogFormat::needs_stream`]).
    #[must_use]
    pub fn needs_stream(&self) -> bool {
        self.stream
    }
}

/// The `lf-string` of a reply (`return`, `deny`, `tarpit`, `http-error`, `errorfiles`), cut at
/// load: the `hdr` lines it carries, then the body. The parser encodes them in one string,
/// `\0HDR:<name>: <format>\n` for each and `\0BODY:<format>` (or a bare format) for the body.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    hdrs: Vec<(String, Format)>,
    body: Option<Format>,
}

/// Two replies are equal when they are the same one (a stop reason carries the rule's).
impl PartialEq for Reply {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for Reply {}

impl Reply {
    /// `lf_string` cut into its pieces, each format compiled.
    #[must_use]
    pub fn compile(lf_string: Option<&str>) -> Self {
        let mut reply = Self::default();
        let mut rest = lf_string.unwrap_or_default();
        while let Some(stripped) = rest.strip_prefix("\0HDR:") {
            let Some((line, r)) = stripped.split_once('\n') else { break };
            rest = r;
            if let Some((k, v)) = line.split_once(':') {
                reply.hdrs.push((k.to_string(), Format::compile(v, true)));
            }
        }
        if lf_string.is_some() {
            if let Some(b) = rest.strip_prefix("\0BODY:") {
                reply.body = Some(Format::compile(b, false));
            } else if !rest.starts_with('\0') {
                reply.body = Some(Format::compile(rest, false));
            }
        }
        reply
    }

    /// Whether any of the reply's formats reads the stream's measures.
    #[must_use]
    pub fn needs_stream(&self) -> bool {
        self.hdrs.iter().map(|(_, f)| f).chain(self.body.iter()).any(Format::needs_stream)
    }

    /// Whether any of the reply's formats reads the request line.
    #[must_use]
    pub fn uses_request_line(&self) -> bool {
        self.hdrs.iter().map(|(_, f)| f).chain(self.body.iter()).any(Format::uses_request_line)
    }

    /// The `hdr` lines appended to `head` (`name: value\r\n`, a line whose value is empty
    /// left out) and the body to `body`, in that order, as the formats are evaluated. `data` is
    /// what the caller knows of the stream; the reply's `status` is the one `%ST` prints.
    pub fn render(&self, head: &mut String, body: &mut String, ctx: &SampleContext, registry: &Registry, status: u16, data: Option<&LogData>) {
        let data = LogData { status: i64::from(status), ..data.cloned().unwrap_or_else(|| LogData::of_context(ctx)) };
        let data = &data;
        for (k, f) in &self.hdrs {
            let mark = head.len();
            head.push_str(k);
            head.push_str(": ");
            let at = head.len();
            f.render_into(head, ctx, registry, Some(data));
            if head.len() == at {
                head.truncate(mark);
            } else {
                head.push_str("\r\n");
            }
        }
        if let Some(b) = &self.body {
            b.render_into(body, ctx, registry, Some(data));
        }
    }
}

/// The templates of a proxy's `http-error` / `errorfiles` replies, compiled.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn reply_pages(pages: &std::collections::HashMap<u16, ibex_config::ErrorPageSource>) -> std::collections::HashMap<u16, std::sync::Arc<Reply>> {
    pages
        .iter()
        .filter_map(|(status, page)| match page {
            ibex_config::ErrorPageSource::Custom { lf_string, .. } => Some((*status, std::sync::Arc::new(Reply::compile(lf_string.as_deref())))),
            _ => None,
        })
        .collect()
}

/// A proxy's rule lists, compiled ([`crate::engine::Proxy::rules`]): one entry per rule of
/// each list, in its order.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    pub http_req: Vec<Rule>,
    pub http_res: Vec<Rule>,
    pub http_after_res: Vec<Rule>,
    /// The `tcp-request connection|session|content` and `tcp-response content` rules, in the
    /// order of `Proxy::tcp_req_*_rules` and `Proxy::tcp_res_content_rules`.
    pub tcp_req_conn: Vec<Rule>,
    pub tcp_req_session: Vec<Rule>,
    pub tcp_req_content: Vec<Rule>,
    pub tcp_res_content: Vec<Rule>,
    /// The `stick` rules and `track-sc` of the old style (`Proxy::stick_rules`).
    pub stick: Vec<Rule>,
    /// `use_backend` and `use-server` rules (their conditions), and `force-be-switch` conditions.
    pub use_backend: Vec<Rule>,
    pub use_server: Vec<Rule>,
    pub force_be: Vec<Cond>,
    /// The `http-error` / `errorfiles` templates of `Proxy::error_replies`, by status.
    pub reply_pages: std::collections::HashMap<u16, std::sync::Arc<Reply>>,
    /// Some response rule's format reads the stream's measures: the response context then
    /// carries the timers.
    pub res_stream: bool,
}

impl Rules {
    /// The rules with `res_stream` worked out from the response rules' formats.
    #[must_use]
    pub fn finish(mut self) -> Self {
        let reads = |r: &Rule| {
            r.fmt.iter().chain(r.fmt2.iter()).any(Format::needs_stream) || r.reply.iter().chain(r.page.iter()).any(|p| p.needs_stream())
        };
        self.res_stream = self.http_res.iter().chain(&self.http_after_res).any(reads) || self.reply_pages.values().any(|p| p.needs_stream());
        self
    }
}

/// What one rule has compiled: its condition, its expression, its format.
#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub cond: Option<Cond>,
    pub expr: Option<Expr>,
    pub fmt: Option<Format>,
    /// A second format of the rule: a `redirect`'s `set-cookie-fmt`.
    pub fmt2: Option<Format>,
    /// The `lf-string` of a `return`, `deny` or `tarpit` (the reply it builds), and the one of
    /// its `error_page` when that is a template.
    pub reply: Option<std::sync::Arc<Reply>>,
    pub page: Option<std::sync::Arc<Reply>>,
    /// The variable of a `set-var`, `set-var-fmt` or `unset-var`, resolved to its number at
    /// load (T595): the request path looks up no name.
    pub var: Option<ibex_sample::vars::VarRef>,
}

impl Rule {
    /// The variable `spec` (`name[,<cond>...]`) this rule names. A rule built without it (a
    /// test) resolves it here, by name.
    #[must_use]
    pub fn var(&self, spec: &str) -> std::borrow::Cow<'_, ibex_sample::vars::VarRef> {
        match &self.var {
            Some(v) => std::borrow::Cow::Borrowed(v),
            None => std::borrow::Cow::Owned(ibex_sample::vars::VarRef::resolve(spec)),
        }
    }

    /// The rule with its variable `spec` resolved.
    fn with_var(mut self, spec: &str) -> Self {
        self.var = Some(ibex_sample::vars::VarRef::resolve(spec));
        self
    }

    fn new(cond: Option<&AclCondition>, acls: &Acls, expr: Option<&str>, fmt: Option<(&str, bool)>) -> Self {
        Self {
            cond: cond.map(|c| Cond::compile(c, acls)),
            expr: expr.and_then(|e| Expr::parse(e).ok()),
            fmt: fmt.map(|(f, http)| Format::compile(f, http)),
            fmt2: None,
            reply: None,
            page: None,
            var: None,
        }
    }

    /// The rule with the reply its `lf-string` and `error_page` make.
    fn with_reply(mut self, lf_string: Option<&str>, page: Option<&ibex_config::ErrorPageSource>) -> Self {
        self.reply = lf_string.map(|l| std::sync::Arc::new(Reply::compile(Some(l))));
        self.page = match page {
            Some(ibex_config::ErrorPageSource::Custom { lf_string, .. }) => Some(std::sync::Arc::new(Reply::compile(lf_string.as_deref()))),
            _ => None,
        };
        self
    }

    /// The rule with `fmt` as its second format (rendered `%XX`-encoded, like a header's).
    fn with_fmt2(mut self, fmt: Option<&str>) -> Self {
        self.fmt2 = fmt.map(|f| Format::compile(f, true));
        self
    }
}

/// The `http-request` rules', in their order.
#[must_use]
pub fn http_req(rules: &[ibex_config::HttpReqRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| {
            let (expr, fmt) = match &r.action {
                HttpReqAction::Capture { expr, .. }
                | HttpReqAction::DoResolve(ibex_config::ast::DoResolve { expr, .. })
                | HttpReqAction::SetVar { expr, .. }
                | HttpReqAction::TrackSc0 { expr, .. }
                | HttpReqAction::TrackSc1 { expr, .. }
                | HttpReqAction::TrackSc2 { expr, .. }
                | HttpReqAction::SetSrc { expr }
                | HttpReqAction::SetDst { expr }
                | HttpReqAction::SetSrcPort { expr }
                | HttpReqAction::SetDstPort { expr }
                | HttpReqAction::SetPriorityClass { expr }
                | HttpReqAction::SetPriorityOffset { expr }
                | HttpReqAction::SetRetries { value: ibex_config::RetriesValue::Expr(expr) }
                | HttpReqAction::ScSetGpt0 { expr, .. }
                | HttpReqAction::ScAddGpc { expr, .. }
                | HttpReqAction::ScSetGpt { expr, .. }
                | HttpReqAction::Pause { expr: Some(expr), .. }
                | HttpReqAction::HeadersBin { expr, .. }
                | HttpReqAction::SetTimeout { timeout_val: expr, .. } => (Some(expr.as_str()), None),
                HttpReqAction::SetVarFmt { fmt, .. } => (None, Some((fmt.as_str(), false))),
                HttpReqAction::ReplaceHeader { repl, .. }
                | HttpReqAction::ReplaceValue { repl, .. }
                | HttpReqAction::ReplacePath { repl, .. }
                | HttpReqAction::ReplacePathq { repl, .. }
                | HttpReqAction::ReplaceUri { repl, .. } => (None, Some((repl.as_str(), true))),
                HttpReqAction::SetHeader { fmt, .. }
                | HttpReqAction::AddHeader { fmt, .. }
                | HttpReqAction::SetPath { fmt }
                | HttpReqAction::SetPathq { fmt }
                | HttpReqAction::SetQuery { fmt }
                | HttpReqAction::SetUri { fmt }
                | HttpReqAction::SetMethod { fmt } => (None, Some((fmt.as_str(), true))),
                HttpReqAction::Redirect(rd) => (None, Some((rd.target.as_str(), true))),
                _ => (None, None),
            };
            let cookie = match &r.action {
                HttpReqAction::Redirect(ibex_config::RedirectRule { cookie: Some(ibex_config::RedirectCookie::SetFmt(f)), .. }) => Some(f.as_str()),
                _ => None,
            };
            let (lf, page) = match &r.action {
                HttpReqAction::Return { lf_string, error_page, .. }
                | HttpReqAction::Deny { lf_string, error_page, .. }
                | HttpReqAction::Tarpit { lf_string, error_page, .. } => (lf_string.as_deref(), error_page.as_ref()),
                _ => (None, None),
            };
            let rule = Rule::new(r.cond.as_ref(), acls, expr, fmt).with_fmt2(cookie).with_reply(lf, page);
            match &r.action {
                HttpReqAction::SetVar { var_name, .. } | HttpReqAction::SetVarFmt { var_name, .. } | HttpReqAction::UnsetVar { var_name } => rule.with_var(var_name),
                _ => rule,
            }
        })
        .collect()
}

/// What a response `set-header`/`add-header` compiles: the response rules keep their other
/// actions under names that start with a NUL (`\0set-var:<name>` and its expression, ...);
/// of those, `set-var` has an expression and `set-var-fmt` a format.
fn res_header(cond: Option<&AclCondition>, acls: &Acls, name: &str, fmt: &str) -> Rule {
    if let Some(spec) = name.strip_prefix("\0set-var:") {
        Rule::new(cond, acls, Some(fmt), None).with_var(spec)
    } else if name.starts_with("\0hdrs-bin:") {
        Rule::new(cond, acls, Some(fmt), None)
    } else if let Some(spec) = name.strip_prefix("\0set-var-fmt:") {
        Rule::new(cond, acls, None, Some((fmt, false))).with_var(spec)
    } else if name.starts_with("\0replace-header:") || name.starts_with("\0replace-value:") {
        // `<regex>\t<replacement>`: the replacement is a format.
        Rule::new(cond, acls, None, fmt.split_once('\t').map(|(_, repl)| (repl, true)))
    } else if !name.starts_with('\0') {
        Rule::new(cond, acls, None, Some((fmt, true)))
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
            HttpResAction::Capture { expr, .. } | HttpResAction::Pause { expr: Some(expr), .. } => Rule::new(r.cond.as_ref(), acls, Some(expr), None),
            HttpResAction::Return { lf_string, error_page, .. } => Rule::new(r.cond.as_ref(), acls, None, None).with_reply(lf_string.as_deref(), error_page.as_ref()),
            HttpResAction::Redirect { location, cookie, .. } => {
                let cookie = match cookie {
                    Some(ibex_config::RedirectCookie::SetFmt(f)) => Some(f.as_str()),
                    _ => None,
                };
                Rule::new(r.cond.as_ref(), acls, None, Some((location, true))).with_fmt2(cookie)
            }
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
            HttpAfterResAction::Capture { expr, .. } => Rule::new(r.cond.as_ref(), acls, Some(expr), None),
            HttpAfterResAction::DelHeader { .. } => Rule::new(r.cond.as_ref(), acls, None, None),
        })
        .collect()
}

/// The `use_backend` rules', in their order: the condition.
#[must_use]
pub fn use_backend(rules: &[ibex_config::UseBackendRule], acls: &Acls) -> Vec<Rule> {
    rules.iter().map(|r| Rule::new(r.cond.as_ref(), acls, None, None)).collect()
}

/// The `use-server` rules', in their order: the condition.
#[must_use]
pub fn use_server(rules: &[ibex_config::UseServerRule], acls: &Acls) -> Vec<Rule> {
    rules.iter().map(|r| Rule::new(Some(&r.cond), acls, None, None)).collect()
}

/// The `force-be-switch` conditions, compiled.
#[must_use]
pub fn force_be(conds: &[AclCondition], acls: &Acls) -> Vec<Cond> {
    conds.iter().map(|c| Cond::compile(c, acls)).collect()
}

/// The `stick` rules', in their order: the condition, the key's expression.
#[must_use]
pub fn stick(rules: &[ibex_config::StickRule], acls: &Acls) -> Vec<Rule> {
    rules.iter().map(|r| Rule::new(r.cond.as_ref(), acls, Some(&r.expr), None)).collect()
}

/// The `tcp-request connection` rules', in their order: the condition, and the expression of
/// `track-sc`, `set-src`, `set-dst` and their ports.
#[must_use]
pub fn tcp_req_conn(rules: &[ibex_config::TcpReqConnRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| {
            let expr = match &r.action {
                TcpReqConnAction::TrackSc0 { expr, .. }
                | TcpReqConnAction::TrackSc1 { expr, .. }
                | TcpReqConnAction::TrackSc2 { expr, .. }
                | TcpReqConnAction::SetSrc { expr }
                | TcpReqConnAction::SetDst { expr }
                | TcpReqConnAction::SetSrcPort { expr }
                | TcpReqConnAction::SetDstPort { expr } => Some(expr.as_str()),
                _ => None,
            };
            Rule::new(r.cond.as_ref(), acls, expr, None)
        })
        .collect()
}

/// The `tcp-request session` rules', in their order.
#[must_use]
pub fn tcp_req_session(rules: &[ibex_config::TcpReqSessionRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| {
            let (expr, fmt) = match &r.action {
                TcpReqSessionAction::TrackSc0 { expr, .. }
                | TcpReqSessionAction::TrackSc1 { expr, .. }
                | TcpReqSessionAction::TrackSc2 { expr, .. }
                | TcpReqSessionAction::SetVar { expr, .. }
                | TcpReqSessionAction::SetSrc { expr }
                | TcpReqSessionAction::SetDst { expr }
                | TcpReqSessionAction::SetSrcPort { expr }
                | TcpReqSessionAction::SetDstPort { expr }
                | TcpReqSessionAction::ScSetGpt0 { expr, .. }
                | TcpReqSessionAction::ScAddGpc { expr, .. }
                | TcpReqSessionAction::ScSetGpt { expr, .. } => (Some(expr.as_str()), None),
                TcpReqSessionAction::SetVarFmt { fmt, .. } => (None, Some((fmt.as_str(), false))),
                _ => (None, None),
            };
            let rule = Rule::new(r.cond.as_ref(), acls, expr, fmt);
            match &r.action {
                TcpReqSessionAction::SetVar { var_name, .. } | TcpReqSessionAction::SetVarFmt { var_name, .. } | TcpReqSessionAction::UnsetVar { var_name } => rule.with_var(var_name),
                _ => rule,
            }
        })
        .collect()
}

/// The `tcp-request content` rules', in their order.
#[must_use]
pub fn tcp_req_content(rules: &[ibex_config::TcpReqContentRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| {
            let (expr, fmt) = match &r.action {
                TcpReqContentAction::TrackSc0 { expr, .. }
                | TcpReqContentAction::TrackSc1 { expr, .. }
                | TcpReqContentAction::TrackSc2 { expr, .. }
                | TcpReqContentAction::SetVar { expr, .. }
                | TcpReqContentAction::DoResolve(ibex_config::ast::DoResolve { expr, .. })
                | TcpReqContentAction::SetSrc { expr }
                | TcpReqContentAction::SetDst { expr }
                | TcpReqContentAction::SetSrcPort { expr }
                | TcpReqContentAction::SetDstPort { expr }
                | TcpReqContentAction::Capture { expr, .. }
                | TcpReqContentAction::ScSetGpt0 { expr, .. }
                | TcpReqContentAction::ScAddGpc { expr, .. }
                | TcpReqContentAction::ScSetGpt { expr, .. } => (Some(expr.as_str()), None),
                TcpReqContentAction::SetVarFmt { fmt, .. } => (None, Some((fmt.as_str(), false))),
                _ => (None, None),
            };
            let rule = Rule::new(r.cond.as_ref(), acls, expr, fmt);
            match &r.action {
                TcpReqContentAction::SetVar { var_name, .. } | TcpReqContentAction::SetVarFmt { var_name, .. } | TcpReqContentAction::UnsetVar { var_name } => rule.with_var(var_name),
                _ => rule,
            }
        })
        .collect()
}

/// The `tcp-response content` rules', in their order.
#[must_use]
pub fn tcp_res_content(rules: &[ibex_config::TcpResContentRule], acls: &Acls) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| match &r.action {
            TcpResAction::SetVar { expr, var_name } => Rule::new(r.cond.as_ref(), acls, Some(expr), None).with_var(var_name),
            TcpResAction::SetVarFmt { fmt, var_name } => Rule::new(r.cond.as_ref(), acls, None, Some((fmt, false))).with_var(var_name),
            TcpResAction::UnsetVar { var_name } => Rule::new(r.cond.as_ref(), acls, None, None).with_var(var_name),
            _ => Rule::new(r.cond.as_ref(), acls, None, None),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibex_config::AclTerm;

    /// A compiled condition holds when its text does (`eval_condition`, which looks each term
    /// up per request).
    #[test]
    fn conditions_hold_as_their_text_does() {
        let acls = Acls::compile([("yes", "always_true"), ("no", "always_false")]);
        let registry = crate::engine::sample_registry();
        let ctx = SampleContext::default();
        let cases: &[&[(bool, &str)]] = &[
            &[(false, "always_true")],
            &[(true, "always_true")],
            &[(false, "always_false")],
            &[(false, "yes"), (true, "no")],
            &[(false, "no"), (false, AclCondition::OR), (false, "yes")],
            &[(false, "yes"), (false, AclCondition::OR)],
            &[(false, "TRUE")],
            &[(true, "FALSE")],
            &[(false, "{ always_true }")],
            &[(false, "not an expression(")],
            &[(true, "not an expression(")],
            &[],
        ];
        for is_if in [true, false] {
            for terms in cases {
                let cond = AclCondition { is_if, terms: terms.iter().map(|&(negated, name)| AclTerm { negated, name: name.to_string() }).collect() };
                let text = crate::engine::eval_condition(&cond, &ctx, &acls, registry);
                assert_eq!(Cond::compile(&cond, &acls).eval(&ctx, &acls, registry), text, "{cond:?}");
            }
        }
    }

    /// A constant term (`always_true`, `always_false`) is decided without the judge, the way
    /// [`Cond::eval`] decides it; an expression term goes to the judge with its negation.
    #[test]
    fn eval_terms_decides_constant_terms_itself() {
        let acls = Acls::compile([]);
        let cases: &[(&[(bool, &str)], AclEvalResult)] = &[
            (&[(false, "always_true")], AclEvalResult::Matched),
            (&[(true, "always_true")], AclEvalResult::NotMatched),
            (&[(false, "always_false")], AclEvalResult::NotMatched),
            (&[(true, "always_false")], AclEvalResult::Matched),
        ];
        for &(terms, want) in cases {
            let cond = AclCondition { is_if: true, terms: terms.iter().map(|&(negated, name)| AclTerm { negated, name: name.to_string() }).collect() };
            let got = Cond::compile(&cond, &acls).eval_terms(&acls, |_, _| panic!("a constant needs no judge"));
            assert_eq!(got, want, "{terms:?}");
        }
        let cond = AclCondition { is_if: true, terms: vec![AclTerm { negated: true, name: "src 1.2.3.4".to_string() }] };
        let mut seen = None;
        let got = Cond::compile(&cond, &acls).eval_terms(&acls, |_, negated| {
            seen = Some(negated);
            AclEvalResult::MissingData
        });
        assert_eq!((got, seen), (AclEvalResult::MissingData, Some(true)));
    }

    /// Two replies are equal only when they are the same reply.
    #[test]
    fn a_reply_equals_only_itself() {
        let a = Reply::compile(Some("x"));
        let b = Reply::compile(Some("x"));
        assert!(a == a);
        assert!(a != b);
    }

    /// A compiled format renders what the old text renderer did, for the formats that
    /// renderer knew (`render_sample_format_into`): samples, the address and name aliases.
    #[test]
    fn formats_render_as_their_text_does() {
        let registry = crate::engine::sample_registry();
        let ctx = SampleContext::default();
        let formats = ["", "plain", "%[str(a)]", "a%[str(x)]b%[str(y)]c", "%[str(a),concat([x])]", "%%", "%ci:%cp-%[str(b)]", "%fi:%fp", "\u{e9}%[str(\u{fc} x)]"];
        for http in [false, true] {
            for fmt in formats {
                let mut text = String::new();
                crate::engine::render_sample_format_into(&mut text, fmt, &ctx, registry, http);
                let mut compiled = String::new();
                Format::compile(fmt, http).render_into(&mut compiled, &ctx, registry, None);
                assert_eq!(compiled, text, "{fmt:?} (http {http})");
            }
        }
    }

    /// A format of text and plain samples is rendered by its own pieces; the line renderer gives
    /// the same text for it, whichever way the sample is written (T455).
    #[test]
    fn the_piecewise_renderer_writes_what_the_line_renderer_does() {
        let registry = crate::engine::sample_registry();
        let ctx = SampleContext::default();
        let formats = [
            "x%[str(a)]y",
            "%[str(a b)]",
            "%[int(5)]-%[int(-3)]",
            "%[str(caf\u{e9})]",
            "%[str(a%b)]",
            "%[str(abc),upper]%[str()]z",
            "%[str(a),hex]",
            "%[bool(true)]",
            "%[ipv4(1.2.3.4)] %[ipv6(::1)]",
            "100%%",
            "%[str(a)]%%[b]",
        ];
        for http in [false, true] {
            for fmt in formats {
                let piecewise = Format::compile(fmt, http);
                assert!(piecewise.parts.is_some() || piecewise.literal.is_some(), "{fmt:?} is not piecewise");
                let mut fast = String::new();
                piecewise.render_into(&mut fast, &ctx, registry, None);
                let mut line = String::new();
                LogFormat::compile_rule(fmt, registry, http).expect("compiles").render_value_into(&mut line, &LogData::default(), registry, &ctx);
                assert_eq!(fast, line, "{fmt:?} (http {http})");
            }
        }
    }
}

#[cfg(test)]
mod var_ref_tests {
    use super::Rule;

    /// A rule compiled from the configuration carries its variable resolved; one built
    /// without it (as unit tests build rules) resolves it on demand, to the same variable.
    #[test]
    fn a_rule_without_a_resolved_variable_resolves_it_by_name() {
        let bare = Rule::default();
        let compiled = Rule::default().with_var("txn.p,ifnotset");
        assert_eq!(bare.var("txn.p,ifnotset").name(), compiled.var("txn.p,ifnotset").name());
        assert!(matches!(bare.var("txn.p"), std::borrow::Cow::Owned(_)));
        assert!(matches!(compiled.var("txn.p,ifnotset"), std::borrow::Cow::Borrowed(_)));
    }
}
