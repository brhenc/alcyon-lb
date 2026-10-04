// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c and src/acl.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sample expression parsing, compilation, and evaluation.
//!
//! Parses expressions like `req.hdr(Host),lower -m str example.com` or `path_beg /api`.

use crate::matcher::Matcher;
use crate::registry::{Registry, SampleContext};
use crate::sample::Sample;

/// A parsed and compiled sample expression with optional matcher.
#[derive(Debug, Clone)]
pub struct Expr {
    pub fetch_name: String,
    pub fetch_args: Vec<String>,
    pub converters: Vec<(String, Vec<String>)>,
    pub matcher: Option<Matcher>,
    /// The other `acl` lines of the same name: an ACL declared several times matches if
    /// any of its lines does (`find_acl_by_name` + `acl_exec_cond` walk the whole list).
    pub alternates: Vec<Expr>,
}

/// `is_idchar` (include/haproxy/tools.h): what a fetch or converter name may contain.
fn is_idchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | ':')
}

impl Expr {
    /// Parses an expression string into an [`Expr`].
    ///
    /// # Errors
    /// Returns an error if the expression syntax or matcher compilation fails.
    #[allow(clippy::too_many_lines)]
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut input = input.trim();
        if input.starts_with('{') && input.ends_with('}') {
            input = input[1..input.len() - 1].trim();
        }
        if input.is_empty() {
            return Err("Empty sample expression".to_string());
        }

        let (expr_part, matcher_part) = split_expr_and_matcher(input);
        let m_tokens = matcher_part.map(tokenize_matcher_part).unwrap_or_default();
        let chain = split_call_chain(expr_part);
        if chain.is_empty() {
            return Err("Missing expression".to_string());
        }

        let (mut fetch_name, fetch_args) = parse_call(chain[0]);
        if fetch_name.is_empty()
            || !fetch_name
                .chars()
                .all(is_idchar)
        {
            return Err(format!("Invalid sample fetch name '{fetch_name}'"));
        }

        let mut converters = Vec::new();
        for conv_str in &chain[1..] {
            let (c_name, c_args) = parse_call(conv_str);
            if c_name.is_empty()
                || !c_name
                    .chars()
                    .all(is_idchar)
            {
                return Err(format!("Invalid converter name '{c_name}'"));
            }
            if matches!(
                c_name.as_str(),
                "add" | "sub" | "mul" | "div" | "mod" | "and" | "or" | "xor"
            ) {
                if let Some(arg) = c_args.first() {
                    let trimmed = arg.trim().trim_matches('"').trim_matches('\'');
                    let is_int = trimmed.parse::<i64>().is_ok()
                        || trimmed
                            .strip_prefix("0x")
                            .or_else(|| trimmed.strip_prefix("0X"))
                            .is_some_and(|hex| i64::from_str_radix(hex, 16).is_ok());
                    let var_name = if trimmed.starts_with("var(") && trimmed.ends_with(')') {
                        &trimmed[4..trimmed.len() - 1]
                    } else {
                        trimmed
                    };
                    let is_var = var_name.starts_with("proc.")
                        || var_name.starts_with("sess.")
                        || var_name.starts_with("req.")
                        || var_name.starts_with("txn.")
                        || var_name.starts_with("res.");
                    if !is_int && !is_var {
                        return Err(format!(
                            "invalid integer argument '{arg}' for converter '{c_name}'"
                        ));
                    }
                } else {
                    return Err(format!("missing argument for converter '{c_name}'"));
                }
            }
            converters.push((c_name, c_args));
        }

        // ACL keyword shorthands (`path_beg`, `hdr_sub`, `url_len`, `shdr_reg`, `req_ver`, ...):
        // a fetch and a default match method (`haproxy -dKacl`). Any other name is the
        // fetch itself, where HAProxy also lets a few bare names (`hdr_val`, `scook`, ...)
        // stand for the dotted ones Ibex registers.
        let mut default_method = "found";
        if let Some((fetch, method)) = acl_keyword(&fetch_name) {
            fetch_name = fetch.to_string();
            default_method = method;
        } else if let Some(canonical) = fetch_alias(&fetch_name) {
            fetch_name = canonical.to_string();
        }

        // What follows the expression is `parse_acl_expr`'s: options (`-i`, `-n`, `-m <method>`,
        // `-f <file>`, `--`) up to the first word that is not one, then patterns, every
        // remaining word being one. Patterns read from a file join the inline ones.
        let tokens = m_tokens;
        let mut match_method = default_method;
        let mut forced = false;
        let mut case_insensitive = false;
        let mut files_loaded = false;
        let mut file_patterns: Vec<String> = Vec::new();
        let mut idx = 0;
        while idx < tokens.len() && tokens[idx].starts_with('-') {
            match tokens[idx].as_str() {
                "-i" => case_insensitive = true,
                "-n" => {}
                "-m" => {
                    if files_loaded {
                        return Err("'-m' must only be specified before patterns and files in parsing ACL expression".to_string());
                    }
                    if forced {
                        return Err("only one explicit matching method can be defined with '-m' parameter".to_string());
                    }
                    idx += 1;
                    let m_method = tokens
                        .get(idx)
                        .ok_or_else(|| "Missing matcher method after -m".to_string())?;
                    match_method = match m_method.as_str() {
                        "str" => "str",
                        "beg" => "beg",
                        "end" => "end",
                        "sub" => "sub",
                        "dir" => "dir",
                        "dom" => "dom",
                        "reg" => "reg",
                        "int" => "int",
                        "gt" => "gt",
                        "ge" => "ge",
                        "lt" => "lt",
                        "le" => "le",
                        "eq" => "eq",
                        "ne" => "ne",
                        "ip" => "ip",
                        "len" => "len",
                        "bin" => "bin",
                        "found" => "found",
                        other => return Err(format!("Unknown matcher method '{other}'")),
                    };
                    forced = true;
                }
                "-f" => {
                    idx += 1;
                    let path = tokens
                        .get(idx)
                        .ok_or_else(|| "Missing file name after -f".to_string())?;
                    file_patterns.extend(read_pattern_file(path)?);
                    files_loaded = true;
                }
                "--" => {
                    idx += 1;
                    break;
                }
                other => {
                    return Err(format!(
                        "'{other}' is not a valid ACL option. Please use '--' before any pattern beginning with a '-'"
                    ));
                }
            }
            idx += 1;
        }
        let inline = &tokens[idx.min(tokens.len())..];
        let has_patterns = !file_patterns.is_empty() || !inline.is_empty();

        if has_patterns && match_method == "found" && !forced {
            match_method = default_match_method(&fetch_name, converters.is_empty());
        }

        // A keyword's own match method only applies when there is something to match.
        if !has_patterns && !forced {
            match_method = "found";
        }

        let mut patterns = file_patterns;
        if match_method == "int" {
            // `eq`, `ge`, `gt`, `le`, `lt` before a value make it a range (and stay in force
            // for the values after it), unless the value is a range already.
            let mut op = "eq";
            for word in inline {
                if matches!(word.as_str(), "eq" | "ge" | "gt" | "le" | "lt") {
                    op = word.as_str();
                    continue;
                }
                let word = unescape_pattern(word);
                let word = if matches!(fetch_name.as_str(), "req.ssl_ver" | "req_ssl_ver") { dotted_ver(&word)? } else { word };
                patterns.push(int_pattern_with_op(op, &word)?);
            }
        } else {
            patterns.extend(inline.iter().map(|w| unescape_pattern(w)));
        }

        let matcher = if match_method == "found" {
            if forced { Some(Matcher::Found) } else { None }
        } else if patterns.is_empty() {
            Some(Matcher::compile_with_flags(match_method, "", case_insensitive)?)
        } else {
            let mut list = Vec::with_capacity(patterns.len());
            for pattern in &patterns {
                list.push(Matcher::compile_with_flags(match_method, pattern, case_insensitive)?);
            }
            if list.len() == 1 {
                list.pop()
            } else {
                Some(Matcher::Any(list))
            }
        };

        Ok(Expr {
            fetch_name,
            fetch_args,
            converters,
            matcher,
            alternates: Vec::new(),
        })
    }

    /// Evaluates the expression against the sample context to produce a sample value.
    #[must_use]
    pub fn eval_sample(&self, registry: &Registry, ctx: &SampleContext) -> Option<Sample> {
        let conv_refs: Vec<(&str, Vec<String>)> = self
            .converters
            .iter()
            .map(|(name, args)| (name.as_str(), args.clone()))
            .collect();

        registry.eval(&self.fetch_name, &self.fetch_args, &conv_refs, ctx)
    }

    /// Evaluates the expression against the sample context to produce all sample values.
    #[must_use]
    pub fn eval_all_samples(&self, registry: &Registry, ctx: &SampleContext) -> Vec<Sample> {
        let conv_refs: Vec<(&str, Vec<String>)> = self
            .converters
            .iter()
            .map(|(name, args)| (name.as_str(), args.clone()))
            .collect();

        registry.eval_all(&self.fetch_name, &self.fetch_args, &conv_refs, ctx)
    }

    /// Evaluates the expression condition, returning `true` if the condition matches
    /// it or any of the other lines of its ACL.
    #[must_use]
    pub fn eval(&self, registry: &Registry, ctx: &SampleContext) -> bool {
        self.eval_line(registry, ctx) || self.alternates.iter().any(|e| e.eval(registry, ctx))
    }

    fn eval_line(&self, registry: &Registry, ctx: &SampleContext) -> bool {
        let samples = self.eval_all_samples(registry, ctx);
        if samples.is_empty() {
            return false;
        }
        if let Some(ref matcher) = self.matcher {
            samples.iter().any(|smp| matcher.matches(smp))
        } else {
            samples.iter().any(|smp| match smp {
                Sample::Bool(b) => *b,
                Sample::Sint(i) => *i != 0,
                _ => true,
            })
        }
    }
}

/// The ACL keywords that are a fetch with a default match method, as `haproxy -dKacl`
/// lists them: `<family>[_<beg|end|sub|dir|dom|reg|len>]` for the string families, and a
/// handful of one-off names.
fn acl_keyword(name: &str) -> Option<(&'static str, &'static str)> {
    const FAMILIES: &[(&str, &str)] = &[
        ("base", "base"),
        ("cook", "req.cook"),
        ("hdr", "req.hdr"),
        ("path", "path"),
        ("scook", "res.cook"),
        ("shdr", "res.hdr"),
        ("url", "url"),
        ("urlp", "urlp"),
    ];
    const SUFFIXES: &[&str] = &["beg", "end", "sub", "dir", "dom", "reg", "len"];
    for &(family, fetch) in FAMILIES {
        let Some(rest) = name.strip_prefix(family) else { continue };
        if rest.is_empty() {
            return Some((fetch, "str"));
        }
        if let Some(suffix) = rest.strip_prefix('_') {
            if let Some(m) = SUFFIXES.iter().find(|s| **s == suffix) {
                return Some((fetch, m));
            }
        }
    }
    Some(match name {
        "method" => ("method", "str"),
        "req_ver" => ("req.ver", "str"),
        "resp_ver" => ("res.ver", "str"),
        "req_ssl_sni" => ("req.ssl_sni", "str"),
        "req_ssl_ver" | "req.ssl_ver" => ("req.ssl_ver", "int"),
        "req_rdp_cookie" => ("req.rdp_cookie", "str"),
        "req_rdp_cookie_cnt" => ("req.rdp_cookie_cnt", "int"),
        "payload" => ("payload", "bin"),
        "payload_lv" => ("payload_lv", "bin"),
        "ssl_fc_sni_end" => ("ssl_fc_sni", "end"),
        "ssl_fc_sni_reg" => ("ssl_fc_sni", "reg"),
        "http_auth_group" => ("http_auth_group", "str"),
        _ => return None,
    })
}

/// A bare `HAProxy` fetch name whose implementation Ibex registers under the dotted one.
fn fetch_alias(name: &str) -> Option<&'static str> {
    let canonical = match name {
        "hdr_val" => "req.hdr_val",
        "hdr_ip" => "req.hdr_ip",
        "cook_val" => "req.cook_val",
        "scook_cnt" => "res.cook_cnt",
        "scook_val" => "res.cook_val",
        "shdr_cnt" => "res.hdr_cnt",
        "shdr_val" => "res.hdr_val",
        "shdr_ip" => "res.hdr_ip",
        "rdp_cookie" => "req.rdp_cookie",
        "rdp_cookie_cnt" => "req.rdp_cookie_cnt",
        _ => return None,
    };
    let reg = crate::registry::sample_registry();
    (reg.get_fetch(name).is_none() && reg.get_fetch(canonical).is_some()).then_some(canonical)
}

/// The match method a fetch takes when none is given (`parse_acl_expr` picks it from the
/// type of the sample): integers for numbers, addresses for IPs, strings otherwise.
fn default_match_method(fetch_name: &str, no_converter: bool) -> &'static str {
    if fetch_name == "src" || fetch_name == "dst" {
        "ip"
    } else if fetch_name.ends_with("_port") || fetch_name == "status" || fetch_name.starts_with("sc_") {
        "int"
    } else if let Some(desc) = no_converter
        .then(|| crate::registry::sample_registry().get_fetch(fetch_name))
        .flatten()
    {
        match desc.out_type {
            crate::sample::SampleType::Sint => "int",
            crate::sample::SampleType::Ipv4 | crate::sample::SampleType::Ipv6 => "ip",
            _ => "str",
        }
    } else {
        "str"
    }
}

/// The patterns of a `-f` file (`pat_ref_read_from_file`): one per line, leading blanks
/// and trailing blanks (as measured) dropped, the line ending at CR or LF; empty lines and lines starting with `#` are skipped.
fn read_pattern_file(path: &str) -> Result<Vec<String>, String> {
    let text = std::fs::read(path).map_err(|_| format!("failed to open pattern file <{path}>"))?;
    let text = String::from_utf8_lossy(&text);
    Ok(text
        .split('\n')
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.trim_start_matches([' ', '\t']))
        .map(|line| line.split('\r').next().unwrap_or(line))
        .map(|line| line.trim_end_matches([' ', '\t']))
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// `pat_parse_dotted_ver`: the patterns of `req.ssl_ver` are `<major>[.<minor>]` numbers, alone
/// or around a `:` or `-` of a range, each standing for `major << 16 | minor`.
fn dotted_ver(word: &str) -> Result<String, String> {
    let one = |t: &str| -> Result<String, String> {
        let (major, minor) = t.split_once('.').unwrap_or((t, ""));
        let major: i64 = major.parse().map_err(|_| format!("'{word}' is not a dotted number"))?;
        let minor: i64 = if t.contains('.') { minor.parse().map_err(|_| format!("'{word}' is not a dotted number"))? } else { 0 };
        if !(0..65536).contains(&major) || !(0..65536).contains(&minor) {
            return Err(format!("'{word}' is not a dotted number"));
        }
        Ok(((major << 16) | minor).to_string())
    };
    match word.find([':', '-']) {
        None => one(word),
        Some(at) => {
            let (lo, hi) = (&word[..at], &word[at + 1..]);
            Ok(format!("{}:{}", if lo.is_empty() { String::new() } else { one(lo)? }, if hi.is_empty() { String::new() } else { one(hi)? }))
        }
    }
}

/// An integer pattern under the operator in force: `gt 5` is the range `6:`, `le 5` is
/// `:5`; with `eq`, or a value that is a range already, it is taken as is.
fn int_pattern_with_op(op: &str, value: &str) -> Result<String, String> {
    if op == "eq" || value.contains([':', '-']) {
        return Ok(value.to_string());
    }
    let digits = value.split('.').next().unwrap_or(value);
    let n: i64 = digits
        .parse()
        .map_err(|_| format!("'{value}' is neither a number nor a supported operator"))?;
    Ok(match op {
        "gt" => format!("{}:", n.saturating_add(1)),
        "ge" => format!("{n}:"),
        "lt" => format!(":{}", n.saturating_sub(1)),
        _ => format!(":{n}"),
    })
}

fn split_expr_and_matcher(input: &str) -> (&str, Option<&str>) {
    let mut paren_depth = 0usize;
    let mut in_quote = None;
    let mut split_pos = None;

    for (i, ch) in input.char_indices() {
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch == '(' {
            paren_depth += 1;
        } else if ch == ')' {
            paren_depth = paren_depth.saturating_sub(1);
        } else if paren_depth == 0 && (ch == ' ' || ch == '\t') {
            split_pos = Some(i);
            break;
        }
    }

    if let Some(pos) = split_pos {
        (&input[..pos], Some(input[pos..].trim_start()))
    } else {
        (input, None)
    }
}

fn split_call_chain(expr_part: &str) -> Vec<&str> {
    let mut calls = Vec::new();
    let mut paren_depth = 0usize;
    let mut in_quote = None;
    let mut start = 0;

    for (i, ch) in expr_part.char_indices() {
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch == '(' {
            paren_depth += 1;
        } else if ch == ')' {
            paren_depth = paren_depth.saturating_sub(1);
        } else if ch == ',' && paren_depth == 0 {
            calls.push(&expr_part[start..i]);
            start = i + 1;
        }
    }
    if start < expr_part.len() {
        calls.push(&expr_part[start..]);
    }
    calls
}

fn unquote_arg(arg: &str) -> &str {
    if (arg.starts_with('"') && arg.ends_with('"') && arg.len() >= 2)
        || (arg.starts_with('\'') && arg.ends_with('\'') && arg.len() >= 2)
    {
        &arg[1..arg.len() - 1]
    } else {
        arg
    }
}

/// `str( x )` is the string " x ": the one fetch whose argument is data keeps its
/// whitespace; every other argument is trimmed.
fn trim_arg<'a>(name: &str, arg: &'a str) -> &'a str {
    if name == "str" { arg } else { arg.trim() }
}

fn parse_call(input: &str) -> (String, Vec<String>) {
    let input = input.trim();
    if let Some(open_idx) = input.find('(') {
        let name = input[..open_idx].trim().to_string();
        let rest = &input[open_idx + 1..];
        let args_str = rest.rfind(')').map_or(rest, |close_idx| &rest[..close_idx]);

        let mut args = Vec::new();
        let mut paren_depth = 0usize;
        let mut in_quote = None;
        let mut start = 0;

        for (i, ch) in args_str.char_indices() {
            if let Some(q) = in_quote {
                if ch == q {
                    in_quote = None;
                }
            } else if ch == '"' || ch == '\'' {
                in_quote = Some(ch);
            } else if ch == '(' {
                paren_depth += 1;
            } else if ch == ')' {
                paren_depth = paren_depth.saturating_sub(1);
            } else if ch == ',' && paren_depth == 0 {
                let arg = trim_arg(&name, &args_str[start..i]);
                let unquoted = unquote_arg(arg);
                args.push(unquoted.to_string());
                start = i + 1;
            }
        }
        if start <= args_str.len() {
            let arg = trim_arg(&name, &args_str[start..]);
            if !arg.is_empty() || !args.is_empty() {
                let unquoted = unquote_arg(arg);
                args.push(unquoted.to_string());
            }
        }

        (name, args)
    } else {
        (input.to_string(), Vec::new())
    }
}

fn tokenize_matcher_part(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quote = None;
    let mut esc = false;

    for ch in input.chars() {
        if esc {
            current.push('\\');
            current.push(ch);
            esc = false;
            continue;
        }
        if ch == '\\' {
            esc = true;
            continue;
        }
        if let Some(q) = in_quote {
            if ch == q {
                in_quote = None;
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quote = Some(ch);
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(current);
                current = String::new();
            }
        } else {
            current.push(ch);
        }
    }
    if esc {
        current.push('\\');
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn unescape_pattern(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    'r' => {
                        out.push('\r');
                        chars.next();
                    }
                    'n' => {
                        out.push('\n');
                        chars.next();
                    }
                    't' => {
                        out.push('\t');
                        chars.next();
                    }
                    '0' => {
                        out.push('\0');
                        chars.next();
                    }
                    '\\' => {
                        out.push('\\');
                        chars.next();
                    }
                    ' ' => {
                        out.push(' ');
                        chars.next();
                    }
                    '"' => {
                        out.push('"');
                        chars.next();
                    }
                    '\'' => {
                        out.push('\'');
                        chars.next();
                    }
                    '$' => {
                        out.push('$');
                        chars.next();
                    }
                    _ => {
                        out.push(c);
                    }
                }
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {

    /// `is_idchar` (include/haproxy/tools.h): names take `-`, `+` and `:` too --
    /// `unique-id`, `ssl_c_s_dn`'s siblings, `51d.all`.
    #[test]
    fn names_may_contain_haproxy_s_identifier_characters() {
        assert_eq!(Expr::parse("unique-id").expect("unique-id").fetch_name, "unique-id");
        assert!(Expr::parse("str(a),my-conv").is_ok());
        assert!(Expr::parse("bad name").is_err() || Expr::parse("bad name").map(|e| e.fetch_name).as_deref() != Ok("bad name"));
    }

    /// A stream that tracks an entry in slot 0 only.
    #[derive(Debug)]
    struct Slot0;
    impl crate::StickState for Slot0 {
        fn tracked(&self, slot: usize, _table: Option<&str>, data: crate::StickData) -> Option<i64> {
            match (slot, data) {
                (0, crate::StickData::ConnRate) => Some(150),
                (0, crate::StickData::HttpReqRate) => Some(75),
                _ => None,
            }
        }
        fn source(&self, _addr: IpAddr, _tables: &[&str], _data: crate::StickData) -> Option<i64> {
            None
        }
    }

    use super::*;
    use ibex_proto::htx::{HeaderField, HttpMethod, HttpVersion, Htx, HtxBlock, RequestLine};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_parse_and_eval_expression() {
        let registry = Registry::new();

        let mut htx = Htx::new();
        htx.push(HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Get,
            uri: "/test/path".into(),
            version: HttpVersion::Http11,
        }));
        htx.push(HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "Example.COM".into(),
        }));
        htx.push(HtxBlock::Eoh);
        htx.push(HtxBlock::Eom);

        let ctx = SampleContext {
            client_addr: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                54321,
            )),
            server_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80)),
            htx: Some(&htx),
            act_conn: 1,
            ..Default::default()
        };

        // Expression 1: req.hdr(Host),lower -m str example.com
        let expr1 = Expr::parse("req.hdr(Host),lower -m str example.com").unwrap();
        assert!(expr1.eval(&registry, &ctx));

        // Expression 2: src -m ip 192.168.1.50
        let expr2 = Expr::parse("src -m ip 192.168.1.50").unwrap();
        assert!(expr2.eval(&registry, &ctx));

        // Expression 3: src_port -m gt 50000
        let expr3 = Expr::parse("src_port -m gt 50000").unwrap();
        assert!(expr3.eval(&registry, &ctx));

        // Shorthand 1: path_beg /test
        let expr_shorthand = Expr::parse("path_beg /test").unwrap();
        assert!(expr_shorthand.eval(&registry, &ctx));

        // Inline condition with braces: { path /test/path }
        let expr_path = Expr::parse("{ path /test/path }").unwrap();
        assert!(expr_path.eval(&registry, &ctx));

        // Inline condition: { path_beg /test/ }
        let expr_path_beg = Expr::parse("{ path_beg /test/ }").unwrap();
        assert!(expr_path_beg.eval(&registry, &ctx));

        // Rate limit expressions, on a stream that tracks an entry in slot 0 only.
        let mut ctx_rates = ctx.clone();
        ctx_rates.stick = Some(&Slot0);

        let expr_rate1 = Expr::parse("{ sc_conn_rate(0) gt 100 }").unwrap();
        assert!(expr_rate1.eval(&registry, &ctx_rates));

        let expr_rate2 = Expr::parse("{ sc_http_req_rate(0) gt 50 }").unwrap();
        assert!(expr_rate2.eval(&registry, &ctx_rates));

        let expr_rate_false = Expr::parse("{ sc_http_req_rate(0) gt 100 }").unwrap();
        assert!(!expr_rate_false.eval(&registry, &ctx_rates));

        // Nothing is tracked in slot 1: no sample, so no condition on it holds.
        let expr_empty_slot = Expr::parse("{ sc_conn_rate(1) ge 0 }").unwrap();
        assert!(!expr_empty_slot.eval(&registry, &ctx_rates));

        // `src_*` looks the client's address up in a table: the one it names, or else the
        // current proxy's (none here); this stream's view has no entry for it.
        let expr_src = Expr::parse("{ src_conn_cnt(t) ge 0 }").unwrap();
        assert!(!expr_src.eval(&registry, &ctx_rates));
        let expr_src_own = Expr::parse("{ src_conn_cnt ge 0 }").unwrap();
        assert!(!expr_src_own.eval(&registry, &ctx_rates));

        // Shorthand 2: hdr(Host) -i example.com
        let expr_shorthand2 = Expr::parse("hdr(Host) -i example.com").unwrap();
        assert!(expr_shorthand2.eval(&registry, &ctx));

        // Test var with regsub
        crate::CURRENT_VARS.with(|v| {
            v.borrow_mut().insert("sess.str3".to_string(), "this is a string".to_string());
        });
        let expr_var = Expr::parse("var(sess.str3),regsub(is a,is also a)").unwrap();
        let val = expr_var.eval_sample(&registry, &ctx);
        assert_eq!(val, Some(Sample::Str("this is also a string".to_string())));
    }

    /// T99: an expression holds every pattern it was given, `-i` and `-m` apply to all of
    /// them, and a match on any one is a match.
    fn holds(expr: &str, sample: Sample) -> bool {
        let e = Expr::parse(expr).unwrap_or_else(|err| panic!("{expr}: {err}"));
        let m = e.matcher.expect("a matcher");
        m.matches(&sample)
    }

    #[test]
    fn every_pattern_of_an_expression_is_kept() {
        let s = |t: &str| Sample::Str(t.to_string());
        for (expr, hits, misses) in [
            ("path /a /b /c", vec!["/a", "/b", "/c"], vec!["/d", "/ab"]),
            ("path -m beg /a /b", vec!["/a1", "/b1"], vec!["/c1"]),
            ("path_beg /a /b", vec!["/a1", "/b1"], vec!["/c1"]),
            ("path_end .x .y", vec!["/f.x", "/f.y"], vec!["/f.z"]),
            ("path_sub aa bb", vec!["/1aa", "/1bb"], vec!["/1cc"]),
            ("path_reg ^/a ^/b$", vec!["/a1", "/b"], vec!["/b1", "/c"]),
            ("path -i /a /b", vec!["/A", "/B"], vec!["/c"]),
            ("path_dir a b", vec!["/q/a/z", "/q/b?x"], vec!["/q/c/z", "/q/ab/z"]),
            ("hdr_dir(host) a b", vec!["x/a"], vec!["x/c"]),
            ("hdr_dom(host) a.com b.org", vec!["x.a.com", "y.b.org:80"], vec!["c.net", "xa.com"]),
            ("path -m dom -i A.COM", vec!["x.a.com"], vec!["xa.com"]),
            ("path -m len 2 4:5", vec!["ab", "abcd", "abcde"], vec!["a", "abc", "abcdef"]),
            ("path -- /a /b", vec!["/a", "/b"], vec!["/c"]),
            ("path -n /a /b", vec!["/a", "/b"], vec!["/c"]),
            ("path -m str -i /a /b", vec!["/A", "/B"], vec!["/c"]),
        ] {
            for h in hits {
                assert!(holds(expr, s(h)), "{expr} should match {h}");
            }
            for m in misses {
                assert!(!holds(expr, s(m)), "{expr} should not match {m}");
            }
        }
        // one pattern stays a bare matcher, several make a list
        assert!(!matches!(Expr::parse("path /a").unwrap().matcher, Some(Matcher::Any(_))));
        assert!(matches!(Expr::parse("path /a /b").unwrap().matcher, Some(Matcher::Any(_))));
    }

    #[test]
    fn integer_patterns_are_ranges_and_operators_stay_in_force() {
        let n = Sample::Sint;
        for (expr, hits, misses) in [
            ("sc_conn_rate(0) 1:5 10 20:30", vec![1, 3, 5, 10, 25, 30], vec![0, 6, 11, 31]),
            ("status :2 100:", vec![1, 2, 100, 500], vec![3, 99]),
            ("status gt 100 200", vec![101, 201], vec![100, 50]),
            ("status lt 5 eq 7", vec![4, 7], vec![5, 8]),
            ("status ge 5 le 1", vec![1, 5, 6], vec![2, 4]),
            ("status -m int 1:5 10", vec![3, 10], vec![7]),
            ("status gt 1.5", vec![2], vec![1]),
            ("src_port -m gt 5", vec![6], vec![5]),
        ] {
            for h in hits {
                assert!(holds(expr, n(h)), "{expr} should match {h}");
            }
            for m in misses {
                assert!(!holds(expr, n(m)), "{expr} should not match {m}");
            }
        }
    }

    #[test]
    fn a_fetch_of_an_address_type_matches_addresses_by_default() {
        let ip = |a: [u8; 4]| Sample::Ipv4(Ipv4Addr::from(a));
        assert!(holds("req.hdr_ip(x-f) 10.0.0.0/8 192.168.0.0/16", ip([192, 168, 1, 1])));
        assert!(!holds("req.hdr_ip(x-f) 10.0.0.0/8 192.168.0.0/16", ip([172, 16, 0, 1])));
    }

    #[test]
    fn ip_patterns_are_all_networks() {
        let ip = |a: [u8; 4]| Sample::Ipv4(Ipv4Addr::from(a));
        assert!(holds("src 10.0.0.0/8 127.0.0.0/8", ip([127, 0, 0, 1])));
        assert!(holds("src 10.0.0.0/8 192.168.0.1", ip([192, 168, 0, 1])));
        assert!(!holds("src 10.0.0.0/8 192.168.0.1", ip([192, 168, 0, 2])));
    }

    #[test]
    fn patterns_from_files_join_the_inline_ones() {
        let path = std::env::temp_dir().join(format!("ibex-t99-{}.pat", std::process::id()));
        std::fs::write(&path, "/f1\r\n# comment\n\n  /f2  \n\t/f3\n").expect("write");
        let p = path.display();
        let s = |t: &str| Sample::Str(t.to_string());
        for hit in ["/f1", "/f2", "/f3", "/x"] {
            assert!(holds(&format!("path -f {p} /x"), s(hit)), "{hit}");
        }
        assert!(!holds(&format!("path -f {p} /x"), s("# comment")));
        assert!(!holds(&format!("path -f {p} /x"), s("/y")));
        assert!(holds(&format!("path -m beg -f {p}"), s("/f1/more")));
        assert!(holds(&format!("path -i -f {p}"), s("/F2")));
        std::fs::remove_file(&path).expect("remove");
        assert!(Expr::parse(&format!("path -f {p}")).is_err(), "a missing file is refused");
    }

    #[test]
    fn bad_options_are_refused() {
        for bad in [
            "path -m",
            "path -m nope /a",
            "path -m str -m beg /a",
            "path -f",
            "path -z /a",
            "status gt abc",
            "status 5:1",
            "status :",
            "status x",
            "path -m len x",
        ] {
            assert!(Expr::parse(bad).is_err(), "{bad} should be refused");
        }
        let file = std::env::temp_dir().join(format!("ibex-t99-m-{}.pat", std::process::id()));
        std::fs::write(&file, "/a\n").expect("write");
        assert!(Expr::parse(&format!("path -f {} -m beg", file.display())).is_err(), "-m after -f");
        std::fs::remove_file(&file).expect("remove");
    }

    #[test]
    fn an_acl_of_several_lines_matches_any_of_them() {
        let registry = Registry::new();
        let mut first = Expr::parse("path /a").unwrap();
        first.alternates.push(Expr::parse("path /b").unwrap());
        let mut htx = Htx::new();
        htx.push(HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Get,
            uri: "/b".into(),
            version: HttpVersion::Http11,
        }));
        htx.push(HtxBlock::Eoh);
        htx.push(HtxBlock::Eom);
        let ctx = SampleContext { htx: Some(&htx), ..Default::default() };
        assert!(first.eval(&registry, &ctx));
        assert!(!Expr::parse("path /a").unwrap().eval(&registry, &ctx));
    }

    #[test]
    fn a_pattern_list_waits_for_the_payload_like_its_members() {
        let list = Expr::parse("req.payload(0,0) -m sub abc de").unwrap().matcher.unwrap();
        assert_eq!(list.min_pattern_len(), 2);
        assert!(list.may_match_later(false));
        assert!(!list.may_match_later(true));
        let reg = Expr::parse("req.payload(0,0) -m reg ^a b$").unwrap().matcher.unwrap();
        assert!(reg.may_match_later(true));
        let beg = Expr::parse("req.payload(0,0) -m beg a b").unwrap().matcher.unwrap();
        assert!(!beg.may_match_later(false));
    }
}
