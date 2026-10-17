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
    if !registry.has_fetch(fetch) {
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
    // An expression that does not parse would answer nothing on every request (T341:
    // `hmac(sha256,var(txn.k))`, an unclosed argument, text after one).
    let parsed = ibex_sample::Expr::parse(word)?;
    for (name, args) in &parsed.converters {
        if let Some(msg) = ibex_sample::check_converter_args(name, args) {
            return Err(msg);
        }
    }
    Ok(())
}

/// What a fetch that reads only the HTTP response needs of it, in `HAProxy`'s words:
/// "HTTP response" for its persistent facts (`SMP_USE_HRSHP`: the status, the version),
/// "HTTP response headers" for what is gone once they are forwarded (`SMP_USE_HRSHV`).
/// `None` for any other fetch, `hdr` and `cookie` among them: they read the request in a
/// request rule.
#[must_use]
pub fn response_part(fetch: &str) -> Option<&'static str> {
    match fetch {
        "status" | "txn.status" | "res.ver" | "resp_ver" | "server_status" | "res.comp" | "res.comp_algo"
        | "res.cache_hit" | "res.cache_name" | "capture.res.hdr" => Some("HTTP response"),
        "res.hdr" | "res.hdr_cnt" | "res.hdr_ip" | "res.hdr_val" | "res.hdr_names" | "res.hdrs" | "res.hdrs_bin"
        | "res.fhdr" | "res.fhdr_cnt" | "res.cook" | "res.cook_cnt" | "res.cook_val" | "res.cook_names"
        | "res.body" | "res.body_len" | "res.body_size" | "res.timer.hdr" | "shdr" | "shdr_cnt" | "shdr_ip"
        | "shdr_val" | "scook" | "scook_cnt" | "scook_val" => Some("HTTP response headers"),
        // `SMP_USE_L6RES` (`src/payload.c`): the raw response, which a request rule or a
        // `tcp-request` has not got.
        "res.len" | "res.payload" | "res.payload_lv" | "res.ssl_hello_type" | "rep_ssl_hello_type" => Some("response buffer"),
        _ => None,
    }
}

/// T326, T341: what a request-side rule cannot read of the server, which is not chosen yet,
/// in `HAProxy`'s words (`fetch_src_names`, `src/sample.c`): the server itself
/// (`SMP_USE_SERVR`), its address (`SMP_USE_L4SRV`) and its connection (`SMP_USE_L5SRV`), from
/// the keyword lists of `backend.c`, `connection.c`, `sample.c`, `stream.c`, `tcp_sample.c`,
/// `ssl_sample.c` and `stconn.c`. A response rule and a log line may read them.
#[must_use]
pub fn server_part(fetch: &str) -> Option<&'static str> {
    match fetch {
        "srv_id" | "srv_name" => Some("server"),
        "bc_err" | "bc_err_name" | "bc_err_str" | "bc_glitches" | "bc_http_major" | "bc_be_queue" | "bc_srv_queue"
        | "bc.timer.connect" | "req.timer.queue" | "txn.conn_retries" | "txn.redispatched" | "bc_dst" | "bc_dst_port"
        | "bc_reused" | "bc_src" | "bc_src_port" => Some("server address"),
        // Not the `ssl_bc_*_secret` keylog fetches: `HAProxy` files those under `SMP_USE_L5CLI`.
        "bc_nb_streams" | "bc_settings_streams_limit" | "bs.aborted" | "bs.debug_str" | "bs.id" | "bs.rst_code"
        | "ssl_bc" | "ssl_bc_alg_keysize" | "ssl_bc_alpn" | "ssl_bc_cipher" | "ssl_bc_client_random" | "ssl_bc_curve"
        | "ssl_bc_err" | "ssl_bc_err_str" | "ssl_bc_is_resumed" | "ssl_bc_npn" | "ssl_bc_protocol"
        | "ssl_bc_server_random" | "ssl_bc_session_id" | "ssl_bc_session_key" | "ssl_bc_sni" | "ssl_bc_unique_id"
        | "ssl_bc_use_keysize" => Some("server-side connection"),
        _ => None,
    }
}

const REQUEST_HEADER_FETCHES: &[&str] = &[
    "base",
    "base32",
    "base32+src",
    "baseq",
    "cook",
    "cook_cnt",
    "cook_val",
    "hdr_cnt",
    "hdr_ip",
    "hdr_val",
    "http_auth_type",
    "http_auth_user",
    "http_auth_pass",
    "http_auth_bearer",
    "http_auth",
    "http_auth_group",
    "path",
    "pathq",
    "query",
    "req.body",
    "req.body_len",
    "req.body_size",
    "req.body_param",
    "req.hdrs",
    "req.hdrs_bin",
    "req.cook",
    "req.cook_cnt",
    "req.cook_val",
    "req.cook_names",
    "req.fhdr",
    "req.fhdr_cnt",
    "req.hdr",
    "req.hdr_cnt",
    "req.hdr_ip",
    "req.hdr_names",
    "req.hdr_val",
    "url",
    "url32",
    "url32+src",
    "url_ip",
    "url_port",
    "url_param",
    "urlp",
    "urlp_val",
    "req.timer.idle",
    "req.timer.tq",
    "req.timer.hdr",
    "fcgi.docroot",
    "fcgi.index",
];


const REQUEST_BUFFER_FETCHES: &[&str] = &[
    "req.len",
    "req_len",
    "req.payload",
    "req.payload_lv",
    "req.ssl_hello_type",
    "req_ssl_hello_type",
    "req.ssl_sni",
    "req_ssl_sni",
    "req.ssl_ver",
    "req_ssl_ver",
    "req.rdp_cookie",
    "rdp_cookie",
    "req.rdp_cookie_cnt",
    "rdp_cookie_cnt",
    "req.ssl_alpn",
    "req.ssl_ec_ext",
    "req.ssl_st_ext",
];

/// What a fetch that reads only the request needs of it, which a response rule no longer
/// has (`SMP_USE_HRQHV` without `SMP_USE_HRSHV`, `src/http_fetch.c`): "HTTP request
/// headers" -- and, with `raw`, for a `tcp-response` rule, the raw request (`SMP_USE_L6REQ`,
/// `src/payload.c`) too. `hdr`, `cookie` and `internal.htx*` read either side and are not
/// here; the request line's persistent facts (`method`, `req.ver`) are still there.
#[must_use]
pub fn request_part(fetch: &str, raw: bool) -> Option<&'static str> {
    if REQUEST_HEADER_FETCHES.contains(&fetch) {
        Some("HTTP request headers")
    } else if raw && REQUEST_BUFFER_FETCHES.contains(&fetch) {
        Some("request buffer")
    } else {
        None
    }
}

/// The fetch `expr` starts with.
#[must_use]
pub fn leading_fetch(expr: &str) -> &str {
    let word = split_top_level(expr.trim(), char::is_whitespace).into_iter().next().unwrap_or("");
    leading_name(split_top_level(word, |c| c == ',').into_iter().next().unwrap_or(""))
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
        HttpReqAction::SetPriorityClass { expr } => vec![("set-priority-class".into(), expr, false)],
        HttpReqAction::SetPriorityOffset { expr } => vec![("set-priority-offset".into(), expr, false)],
        HttpReqAction::SetRetries { value: RetriesValue::Expr(expr) } => {
            vec![("set-retries".into(), expr, false)]
        }
        HttpReqAction::SetVar { var_name, expr } => vec![(format!("set-var({var_name})"), expr, false)],
        HttpReqAction::Capture { expr, .. } => vec![("capture".into(), expr, false)],
        HttpReqAction::ScSetGpt0 { sc, expr } => vec![(format!("sc-set-gpt0({sc})"), expr, true)],
        HttpReqAction::ScAddGpc { idx, sc, expr } => vec![(format!("sc-add-gpc({idx},{sc})"), expr, true)],
        HttpReqAction::ScSetGpt { idx, sc, expr } => vec![(format!("sc-set-gpt({idx},{sc})"), expr, true)],
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
        HttpResAction::Capture { expr, .. } => vec![("capture".into(), expr, false)],
        _ => Vec::new(),
    }
}

fn http_after_res(a: &HttpAfterResAction) -> Exprs<'_> {
    match a {
        HttpAfterResAction::SetHeader { name, fmt } => res_set_var(name, fmt),
        HttpAfterResAction::Capture { expr, .. } => vec![("capture".into(), expr, false)],
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
        TcpReqSessionAction::ScAddGpc { idx, sc, expr } => vec![(format!("sc-add-gpc({idx},{sc})"), expr, true)],
        TcpReqSessionAction::ScSetGpt { idx, sc, expr } => vec![(format!("sc-set-gpt({idx},{sc})"), expr, true)],
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
        TcpReqContentAction::ScAddGpc { idx, sc, expr } => vec![(format!("sc-add-gpc({idx},{sc})"), expr, true)],
        TcpReqContentAction::ScSetGpt { idx, sc, expr } => vec![(format!("sc-set-gpt({idx},{sc})"), expr, true)],
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
                // A request rule has no response to read: its fetches would read the one of
                // whatever stream ran last on the thread (T156); a response rule has no
                // request headers left, and a `tcp-response` no request at all. `HAProxy`
                // names the action for `set-var`, the expression for the others.
                let fetch = leading_fetch(expr);
                let part = match *kw {
                    "http-request" | "tcp-request content" | "tcp-request session" | "tcp-request connection" => {
                        response_part(fetch).or_else(|| server_part(fetch))
                    }
                    "http-response" | "http-after-response" => request_part(fetch, false),
                    _ => request_part(fetch, true), // "tcp-response content", the last of the seven
                };
                if let Some(part) = part {
                    let name = if action.starts_with("set-var(") {
                        action.as_str()
                    } else {
                        split_top_level(expr.trim(), char::is_whitespace).into_iter().next().unwrap_or("")
                    };
                    let msg = format!("fetch method '{name}' extracts information from '{part}', none of which is available here");
                    return Err(if kw.starts_with("http-") {
                        format!("error detected in {} while parsing '{kw} {action}' rule : {msg}.", self.what)
                    } else {
                        msg
                    });
                }
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
    // `option forwarded ... for-expr <expr>` and the other `-expr` parameters; a `defaults`
    // option is checked in each proxy that inherited it.
    let proxies = config
        .listens
        .iter()
        .map(|l| (format!("proxy '{}'", l.name), SectionKind::Listen, &l.name, &l.forwarded))
        .chain(config.backends.iter().map(|b| (format!("backend '{}'", b.name), SectionKind::Backend, &b.name, &b.forwarded)));
    for (what, section, name, forwarded) in proxies {
        for (_, expr) in forwarded.iter().flat_map(|f| f.exprs()) {
            check_sample_expr(expr, registry)
                .and_then(|()| check_expr(config, registry, Where { section, proxy: Some(name) }, expr, false))
                .map_err(|e| format!("{what}: failed to parse 'option forwarded' expression '{expr}' in : {e}"))?;
        }
    }
    sections.iter().try_for_each(|s| s.check(config, registry))
}

/// Checks the pattern of every `stick on|match|store-request|store-response` rule: the fetch
/// and converters exist ("'stick': unknown fetch method 'nosuch'", `parse_stick`).
///
/// # Errors
/// The first unknown fetch or converter, with the section and the rule named.
pub fn validate_stick_rules(config: &Config, registry: &Registry) -> Result<(), String> {
    use ibex_config::StickRuleType;
    let sections = config
        .listens
        .iter()
        .map(|p| (format!("proxy '{}'", p.name), Where { section: SectionKind::Listen, proxy: Some(&p.name) }, &p.stick_rules))
        .chain(config.backends.iter().map(|p| (format!("backend '{}'", p.name), Where { section: SectionKind::Backend, proxy: Some(&p.name) }, &p.stick_rules)));
    for (what, at, rules) in sections {
        for r in rules {
            let kw = match r.rule_type {
                StickRuleType::StickOn => "stick on",
                StickRuleType::StickMatch => "stick match",
                StickRuleType::StickStoreRequest => "stick store-request",
                StickRuleType::StickStoreResponse => "stick store-response",
                _ => continue,
            };
            check_sample_expr(&r.expr, registry)
                .and_then(|()| check_expr(config, registry, at, &r.expr, false))
                .map_err(|e| format!("error detected in {what} while parsing '{kw}' rule : {e}"))?;
        }
    }
    Ok(())
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
    validate_stick_rules(config, registry)?;
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
/// log-format : ..."). A frontend's log format is compiled whether or not it has somewhere
/// to log: `HAProxy` parses it on the `log-format` line and only warns "log format
/// ignored for frontend ... since it has no log address" afterwards (measured with
/// `haproxy -c`: a bad format is fatal without a `log` line too).
///
/// # Errors
/// The first format that does not compile.
pub fn validate_formats(config: &Config, registry: &Registry) -> Result<(), String> {
    use crate::logfmt::{format_string, LogFormat};
    let check = |what: &str, name: &str, kind: &str, fmt: &str| {
        LogFormat::compile(fmt, registry).map(|_| ()).map_err(|e| format!("{what} '{name}': failed to parse {kind} : {e}"))
    };
    let sections = config
        .frontends
        .iter()
        .map(|f| ("frontend", &f.name, f.mode, &f.log_format, &f.unique_id_format, &f.error_log_format, &f.log_format_sd))
        .chain(config.listens.iter().map(|l| ("proxy", &l.name, l.mode, &l.log_format, &l.unique_id_format, &l.error_log_format, &l.log_format_sd)));
    for (what, name, mode, log_format, unique_id_format, error_log_format, log_format_sd) in sections {
        if let Some(fmt) = error_log_format {
            check(what, name, "error-log-format", fmt)?;
        }
        if let Some(fmt) = log_format_sd {
            check(what, name, "log-format-sd", fmt)?;
        }
        if let Some(spec) = log_format {
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
    // `http-response capture ... id <n>` fills a response slot of the proxy that receives the
    // requests: a `declare capture response` or a `capture response header`. A backend's
    // rule names one of its frontend's, found only when a response comes back.
    let sections = config
        .frontends
        .iter()
        .map(|f| (&f.name, &f.http_res_rules, &f.http_after_res_rules, f.res_header_captures.len()))
        .chain(config.listens.iter().map(|l| (&l.name, &l.http_res_rules, &l.http_after_res_rules, l.res_header_captures.len())));
    for (name, rules, after, slots) in sections {
        // `http-after-response capture` is checked the same way and worded as `http-response`.
        let ids = rules
            .iter()
            .filter_map(|r| if let HttpResAction::Capture { id, .. } = r.action { Some(id) } else { None })
            .chain(after.iter().filter_map(|r| if let HttpAfterResAction::Capture { id, .. } = r.action { Some(id) } else { None }));
        for id in ids {
            if id >= slots {
                return Err(format!("Proxy '{name}': unable to find capture id '{id}' referenced by http-response capture rule."));
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
            if let ibex_config::ast::HttpCheckAction::SetVar { var_name, expr } = act {
                check_sample_expr(expr, registry)
                    .map_err(|e| format!("{what} '{name}': error detected while parsing http-check set-var({var_name}) : {e}"))?;
            }
            if let ibex_config::ast::HttpCheckAction::Expect { pattern, .. } = act {
                use ibex_config::ast::HttpCheckExpectPattern as P;
                let lfs: Vec<&str> = match pattern {
                    P::StringLf(t) => vec![t.as_str()],
                    P::Hdr { name, value, .. } => [Some(name), value.as_ref()]
                        .into_iter()
                        .flatten()
                        .filter(|p| p.lf)
                        .map(|p| p.text.as_str())
                        .collect(),
                    _ => Vec::new(),
                };
                for f in lfs {
                    check(what, name, "http-check expect", f)?;
                }
            }
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
