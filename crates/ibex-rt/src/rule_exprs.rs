// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c (sample_parse_expr) and src/stick_table.c
// (parse_set_gpt). Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors.
// See LICENSE.

//! Load-time check of the sample expressions in rule actions against the fetch and
//! converter registry.
//!
//! `ibex-config` parses an action's expression as text, because the registry lives in
//! `ibex-sample` and the configuration crate cannot see it; the runtime evaluates it per
//! request, where an unknown name yields nothing. Without this check a typo in
//! `http-request set-var(txn.x) hdr(x-foo),lowr` loads and the action silently does
//! nothing on every request. `HAProxy` refuses it at load ("unknown fetch method '%s'",
//! "unknown converter '%s'", `sample_parse_expr`), and so does this, from
//! [`crate::engine::Engine::build_shared_state`] and from the binary before `-c` reports
//! a configuration valid.
//!
//! Only action expressions are checked. Log-format arguments (`set-header`,
//! `set-var-fmt`, `return lf-string`, ...), ACL conditions and `stick on/match/store`
//! expressions are not.

use ibex_config::{
    Config, HttpAfterResAction, HttpAfterResRule, HttpReqAction, HttpReqRule, HttpResAction,
    HttpResRule, RetriesValue, TcpReqConnAction, TcpReqConnRule, TcpReqContentAction,
    TcpReqContentRule, TcpReqSessionAction, TcpReqSessionRule, TcpResAction, TcpResContentRule,
};
use crate::proxy_state::{check_expr, Where};
use ibex_config::SectionKind;
use ibex_sample::Registry;

/// `is_idchar` (`include/haproxy/tools.h`): the characters of a fetch or converter name.
fn is_idchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | ':')
}

/// Splits `s` at every `sep` outside parentheses and quotes.
fn split_top_level(s: &str, sep: impl Fn(char) -> bool) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut quote, mut start) = (0usize, None, 0);
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => depth = depth.saturating_sub(1),
            (None, c) if depth == 0 && sep(c) => {
                out.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn leading_name(s: &str) -> &str {
    let s = s.trim_start();
    let end = s.find(|c: char| !is_idchar(c)).unwrap_or(s.len());
    &s[..end]
}

/// Checks the fetch and every converter `expr` names, as `sample_parse_expr` resolves
/// them: the fetch is the leading run of name characters, exactly as written (`hdr_beg`
/// and `path_beg` are ACL keywords, not fetches, and names are case-sensitive), and
/// converters follow it after commas (empty ones, as in `src,,lower`, are skipped).
///
/// # Errors
/// `HAProxy`'s message: "missing fetch method", "unknown fetch method '<name>'" or
/// "unknown converter '<name>'".
pub fn check_sample_expr(expr: &str, registry: &Registry) -> Result<(), String> {
    // The expression is the first word; the action parsers hand over at most that and
    // what Ibex does not yet refuse after it.
    let word = split_top_level(expr.trim(), char::is_whitespace).into_iter().next().unwrap_or("");
    let mut terms = split_top_level(word, |c| c == ',').into_iter();
    let fetch = leading_name(terms.next().unwrap_or(""));
    if fetch.is_empty() {
        return Err("missing fetch method".to_string());
    }
    if let Some(msg) = ibex_sample::not_implemented_message(fetch) {
        return Err(msg);
    }
    if registry.get_fetch(fetch).is_none() {
        return Err(format!("unknown fetch method '{fetch}'"));
    }
    for term in terms.filter(|t| !t.trim().is_empty()) {
        let conv = leading_name(term);
        if let Some(msg) = ibex_sample::not_implemented_message(conv) {
            return Err(msg);
        }
        if !registry.has_converter(conv) {
            return Err(format!("unknown converter '{conv}'"));
        }
    }
    Ok(())
}

/// `sc-set-gpt0`'s value: a plain integer as `strtol(.., 10)` reads all of it, else an
/// expression (`parse_set_gpt`, `src/stick_table.c`). `0x10` is an expression there.
fn check_int_or_expr(value: &str, registry: &Registry) -> Result<(), String> {
    let v = value.trim();
    let digits = v.strip_prefix(['-', '+']).unwrap_or(v);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(());
    }
    check_sample_expr(v, registry)
}

/// The expressions one rule carries, with the action keyword `HAProxy` names in its error.
type Exprs<'a> = Vec<(String, &'a str, bool)>;

fn track(n: u8, expr: &str) -> (String, &str, bool) {
    (format!("track-sc{n}"), expr, false)
}

fn http_req(a: &HttpReqAction) -> Exprs<'_> {
    match a {
        HttpReqAction::TrackSc0 { expr, .. } => vec![track(0, expr)],
        HttpReqAction::TrackSc1 { expr, .. } => vec![track(1, expr)],
        HttpReqAction::TrackSc2 { expr, .. } => vec![track(2, expr)],
        HttpReqAction::SetSrc { expr } => vec![("set-src".into(), expr, false)],
        HttpReqAction::SetDst { expr } => vec![("set-dst".into(), expr, false)],
        HttpReqAction::SetDstPort { expr } => vec![("set-dst-port".into(), expr, false)],
        HttpReqAction::SetRetries { value: RetriesValue::Expr(expr) } => {
            vec![("set-retries".into(), expr, false)]
        }
        HttpReqAction::SetVar { var_name, expr } => vec![(format!("set-var({var_name})"), expr, false)],
        HttpReqAction::Capture { expr, .. } => vec![("capture".into(), expr, false)],
        HttpReqAction::ScSetGpt0 { sc, expr } => vec![(format!("sc-set-gpt0({sc})"), expr, true)],
        _ => Vec::new(),
    }
}

/// `http-response` and `http-after-response` encode `set-var` as a header action named
/// `"\0set-var:<var>"` (`set-var-fmt`, a log format, is `"\0set-var-fmt:<var>"`).
fn res_set_var<'a>(name: &str, fmt: &'a str) -> Exprs<'a> {
    name.strip_prefix("\0set-var:")
        .map(|v| vec![(format!("set-var({v})"), fmt, false)])
        .unwrap_or_default()
}

fn http_res(a: &HttpResAction) -> Exprs<'_> {
    match a {
        HttpResAction::SetHeader { name, fmt } => res_set_var(name, fmt),
        _ => Vec::new(),
    }
}

fn http_after_res(a: &HttpAfterResAction) -> Exprs<'_> {
    match a {
        HttpAfterResAction::SetHeader { name, fmt } => res_set_var(name, fmt),
        _ => Vec::new(),
    }
}

fn tcp_conn(a: &TcpReqConnAction) -> Exprs<'_> {
    match a {
        TcpReqConnAction::TrackSc0 { expr, .. } => vec![track(0, expr)],
        TcpReqConnAction::TrackSc1 { expr, .. } => vec![track(1, expr)],
        TcpReqConnAction::TrackSc2 { expr, .. } => vec![track(2, expr)],
        TcpReqConnAction::SetSrc { expr } => vec![("set-src".into(), expr, false)],
        TcpReqConnAction::SetDst { expr } => vec![("set-dst".into(), expr, false)],
        _ => Vec::new(),
    }
}

fn tcp_session(a: &TcpReqSessionAction) -> Exprs<'_> {
    match a {
        TcpReqSessionAction::TrackSc0 { expr, .. } => vec![track(0, expr)],
        TcpReqSessionAction::TrackSc1 { expr, .. } => vec![track(1, expr)],
        TcpReqSessionAction::TrackSc2 { expr, .. } => vec![track(2, expr)],
        TcpReqSessionAction::SetVar { var_name, expr } => vec![(format!("set-var({var_name})"), expr, false)],
        TcpReqSessionAction::SetSrc { expr } => vec![("set-src".into(), expr, false)],
        TcpReqSessionAction::SetDst { expr } => vec![("set-dst".into(), expr, false)],
        TcpReqSessionAction::ScSetGpt0 { sc, expr } => vec![(format!("sc-set-gpt0({sc})"), expr, true)],
        _ => Vec::new(),
    }
}

fn tcp_content(a: &TcpReqContentAction) -> Exprs<'_> {
    match a {
        TcpReqContentAction::TrackSc0 { expr, .. } => vec![track(0, expr)],
        TcpReqContentAction::TrackSc1 { expr, .. } => vec![track(1, expr)],
        TcpReqContentAction::TrackSc2 { expr, .. } => vec![track(2, expr)],
        TcpReqContentAction::SetVar { var_name, expr } => vec![(format!("set-var({var_name})"), expr, false)],
        TcpReqContentAction::SetSrc { expr } => vec![("set-src".into(), expr, false)],
        TcpReqContentAction::SetDst { expr } => vec![("set-dst".into(), expr, false)],
        TcpReqContentAction::ScSetGpt0 { sc, expr } => vec![(format!("sc-set-gpt0({sc})"), expr, true)],
        _ => Vec::new(),
    }
}

fn tcp_res(a: &TcpResAction) -> Exprs<'_> {
    match a {
        TcpResAction::SetVar { var_name, expr } => vec![(format!("set-var({var_name})"), expr, false)],
        TcpResAction::Accept
        | TcpResAction::Reject
        | TcpResAction::SilentDrop
        | TcpResAction::SetVarFmt { .. }
        | TcpResAction::UnsetVar { .. } => Vec::new(),
    }
}

/// One section's rule lists. A section without a list passes an empty slice.
struct Section<'a> {
    what: String,
    at: Where<'a>,
    http_req: &'a [HttpReqRule],
    http_res: &'a [HttpResRule],
    http_after_res: &'a [HttpAfterResRule],
    tcp_conn: &'a [TcpReqConnRule],
    tcp_session: &'a [TcpReqSessionRule],
    tcp_content: &'a [TcpReqContentRule],
    tcp_res_content: &'a [TcpResContentRule],
}

impl Section<'_> {
    fn check(&self, config: &Config, registry: &Registry) -> Result<(), String> {
        let lists: [(&str, Vec<Exprs<'_>>); 7] = [
            ("http-request", self.http_req.iter().map(|r| http_req(&r.action)).collect()),
            ("http-response", self.http_res.iter().map(|r| http_res(&r.action)).collect()),
            ("http-after-response", self.http_after_res.iter().map(|r| http_after_res(&r.action)).collect()),
            ("tcp-request connection", self.tcp_conn.iter().map(|r| tcp_conn(&r.action)).collect()),
            ("tcp-request session", self.tcp_session.iter().map(|r| tcp_session(&r.action)).collect()),
            ("tcp-request content", self.tcp_content.iter().map(|r| tcp_content(&r.action)).collect()),
            ("tcp-response content", self.tcp_res_content.iter().map(|r| tcp_res(&r.action)).collect()),
        ];
        for (kw, rules) in &lists {
            for (action, expr, int_ok) in rules.iter().flatten() {
                let res = if *int_ok {
                    check_int_or_expr(expr, registry)
                } else {
                    check_sample_expr(expr, registry)
                }
                .and_then(|()| {
                    if *int_ok && expr.trim().trim_start_matches(['-', '+']).bytes().all(|b| b.is_ascii_digit()) {
                        Ok(())
                    } else {
                        check_expr(config, registry, self.at, expr, false)
                    }
                });
                res.map_err(|e| {
                    format!("error detected in {} while parsing '{kw} {action}' rule : {e}", self.what)
                })?;
            }
        }
        Ok(())
    }
}

/// Checks every rule action's sample expression in `config` against `registry`.
///
/// Disabled sections are checked too: `HAProxy` parses them, and refuses them the same.
///
/// # Errors
/// The first unknown fetch or converter, with the section and the rule named as
/// `HAProxy` names them: "error detected in backend 'be' while parsing 'http-request
/// set-retries' rule : unknown fetch method 'nosuch'".
pub fn validate_rule_exprs(config: &Config, registry: &Registry) -> Result<(), String> {
    let mut sections = Vec::new();
    if let Some(d) = &config.defaults {
        sections.push(Section {
            what: "defaults section".to_string(),
            at: Where { section: SectionKind::Defaults, proxy: d.name.as_deref() },
            http_req: &d.http_req_rules,
            http_res: &d.http_res_rules,
            http_after_res: &d.http_after_res_rules,
            tcp_conn: &d.tcp_req_conn_rules,
            tcp_session: &d.tcp_req_session_rules,
            tcp_content: &d.tcp_req_content_rules,
            tcp_res_content: &d.tcp_res_content_rules,
        });
    }
    for l in &config.listens {
        sections.push(Section {
            what: format!("proxy '{}'", l.name),
            at: Where { section: SectionKind::Listen, proxy: Some(&l.name) },
            http_req: &l.http_req_rules,
            http_res: &l.http_res_rules,
            http_after_res: &l.http_after_res_rules,
            tcp_conn: &l.tcp_req_conn_rules,
            tcp_session: &l.tcp_req_session_rules,
            tcp_content: &l.tcp_req_content_rules,
            tcp_res_content: &l.tcp_res_content_rules,
        });
    }
    for f in &config.frontends {
        sections.push(Section {
            what: format!("frontend '{}'", f.name),
            at: Where { section: SectionKind::Frontend, proxy: Some(&f.name) },
            http_req: &f.http_req_rules,
            http_res: &f.http_res_rules,
            http_after_res: &f.http_after_res_rules,
            tcp_conn: &f.tcp_req_conn_rules,
            tcp_session: &f.tcp_req_session_rules,
            tcp_content: &f.tcp_req_content_rules,
            tcp_res_content: &[],
        });
    }
    for b in &config.backends {
        sections.push(Section {
            what: format!("backend '{}'", b.name),
            at: Where { section: SectionKind::Backend, proxy: Some(&b.name) },
            http_req: &b.http_req_rules,
            http_res: &b.http_res_rules,
            http_after_res: &b.http_after_res_rules,
            tcp_conn: &[],
            tcp_session: &[],
            tcp_content: &b.tcp_req_content_rules,
            tcp_res_content: &b.tcp_res_content_rules,
        });
    }
    sections.iter().try_for_each(|s| s.check(config, registry))
}

/// [`validate_rule_exprs`] against the registry the engine evaluates with.
///
/// # Errors
/// As [`validate_rule_exprs`].
pub fn validate_config(config: &Config) -> Result<(), String> {
    let registry = crate::engine::sample_registry();
    crate::proxy_state::check_sample_refs(config, registry)?;
    validate_acls(config)?;
    validate_rule_exprs(config, registry)?;
    validate_formats(config, registry)
}

/// Compiles every `acl` line. An ACL that does not compile is left out when its proxy is
/// built, and a rule that names it then never matches -- a deny list that silently allows
/// everything -- so it is refused here, as `HAProxy` does ("error detected while parsing
/// ACL 'bad' : '-z' is not a valid ACL option").
///
/// # Errors
/// The first `acl` line that does not compile, with its proxy and ACL named.
pub fn validate_acls(config: &Config) -> Result<(), String> {
    let listens = config.listens.iter().map(|l| ("proxy", &l.name, &l.acls));
    let frontends = config.frontends.iter().map(|f| ("frontend", &f.name, &f.acls));
    let backends = config.backends.iter().map(|b| ("backend", &b.name, &b.acls));
    for (kind, name, acls) in listens.chain(frontends).chain(backends) {
        for rule in acls {
            ibex_sample::Expr::parse(&rule.expr).map_err(|e| {
                format!("error detected in {kind} '{name}' while parsing ACL '{}' : {e}", rule.name)
            })?;
        }
    }
    Ok(())
}

/// Compiles every `log-format` and `unique-id-format` (`HAProxy`: "failed to parse
/// log-format : ..."). A frontend's log format is compiled only when it has somewhere to
/// log, as `HAProxy` skips it otherwise ("log format ignored for frontend ... since it has
/// no log address").
///
/// # Errors
/// The first format that does not compile.
pub fn validate_formats(config: &Config, registry: &Registry) -> Result<(), String> {
    use crate::logfmt::{format_string, LogFormat};
    let global_logs = config.global.as_ref().is_some_and(|g| !g.logs.is_empty());
    let check = |what: &str, name: &str, kind: &str, fmt: &str| {
        LogFormat::compile(fmt, registry).map(|_| ()).map_err(|e| format!("{what} '{name}': failed to parse {kind} : {e}"))
    };
    let sections = config
        .frontends
        .iter()
        .map(|f| ("frontend", &f.name, f.mode, &f.log_format, &f.unique_id_format, !f.logs.is_empty() || f.log_global && global_logs))
        .chain(config.listens.iter().map(|l| {
            ("proxy", &l.name, l.mode, &l.log_format, &l.unique_id_format, !l.logs.is_empty() || l.log_global && global_logs)
        }));
    for (what, name, mode, log_format, unique_id_format, logs) in sections {
        if let (Some(spec), true) = (log_format, logs) {
            check(what, name, "log-format", format_string(spec, mode == ibex_config::Mode::Http))?;
        }
        if let Some(fmt) = unique_id_format {
            check(what, name, "unique-id", fmt)?;
        }
    }
    for b in &config.backends {
        if let Some(fmt) = &b.unique_id_format {
            check("backend", &b.name, "unique-id", fmt)?;
        }
    }
    // `http-request capture ... id <n>` fills an existing request slot: a `declare
    // capture`, a `capture request header`, or another rule's (`check_http_req_capture`).
    let sections = config
        .frontends
        .iter()
        .map(|f| (&f.name, &f.http_req_rules, &f.req_header_captures))
        .chain(config.listens.iter().map(|l| (&l.name, &l.http_req_rules, &l.req_header_captures)));
    // Without `id` a rule takes a slot of its own, which only a proxy that receives
    // requests has (`parse_http_req_capture`).
    for b in &config.backends {
        if b.http_req_rules.iter().any(|r| matches!(r.action, ibex_config::HttpReqAction::Capture { id: None, .. })) {
            return Err(format!(
                "error detected in backend '{0}' while parsing 'http-request capture' rule : proxy '{0}' has no frontend capability.",
                b.name
            ));
        }
    }
    for (name, rules, caps) in sections {
        for r in rules {
            if let ibex_config::HttpReqAction::Capture { id: Some(id), .. } = r.action {
                let slots = caps.len() + rules.iter().filter(|r| matches!(r.action, ibex_config::HttpReqAction::Capture { id: None, .. })).count();
                if id >= slots {
                    return Err(format!("Proxy '{name}': unable to find capture id '{id}' referenced by http-request capture rule."));
                }
            }
        }
    }
    // `http-check send`: the `hdr` values, `uri-lf` and `body-lf` are log-formats
    // (`parse_tcpcheck_send_http`, "'%s' invalid log-format string").
    let checks = config
        .backends
        .iter()
        .map(|b| ("backend", &b.name, &b.http_checks))
        .chain(config.listens.iter().map(|l| ("proxy", &l.name, &l.http_checks)));
    for (what, name, actions) in checks {
        for act in actions {
            if let ibex_config::ast::HttpCheckAction::Send { uri, uri_lf, headers, body, body_lf, .. } = act {
                for (_, v) in headers {
                    check(what, name, "http-check send hdr", v)?;
                }
                if let (Some(u), true) = (uri, *uri_lf) {
                    check(what, name, "http-check send uri-lf", u)?;
                }
                if let (Some(b), true) = (body, *body_lf) {
                    check(what, name, "http-check send body-lf", b)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each case measured with `haproxy -c` as `http-request set-var(txn.x) <expr>` (or
    /// `sc-set-gpt0(0) <value>`), `HAProxy` 3.5-dev8-885761-29, 2026-10-03.
    #[test]
    fn names_are_resolved_as_haproxy_resolves_them() {
        let reg = Registry::new();
        assert_eq!(check_sample_expr("src", &reg), Ok(()));
        assert_eq!(check_sample_expr("req.hdr(x-a,1),lower", &reg), Ok(()));
        assert_eq!(check_sample_expr("str(a),,lower", &reg), Ok(()));
        assert_eq!(check_sample_expr("nosuch", &reg), Err("unknown fetch method 'nosuch'".into()));
        assert_eq!(check_sample_expr("hdr_beg(host)", &reg), Err("unknown fetch method 'hdr_beg'".into()));
        assert_eq!(check_sample_expr("src,lowr", &reg), Err("unknown converter 'lowr'".into()));
        // As the text reaches here when the quotes survive tokenizing: the quoted space and
        // comma are inside the argument (`haproxy -c` on `str('a b'),lowr`: unknown converter).
        assert_eq!(check_sample_expr("str('a b'),lowr", &reg), Err("unknown converter 'lowr'".into()));
        assert_eq!(check_sample_expr("%[src]", &reg), Err("missing fetch method".into()));
        assert_eq!(check_int_or_expr("-1", &reg), Ok(()));
        assert_eq!(check_int_or_expr("0x10", &reg), Err("unknown fetch method '0x10'".into()));
    }
}
