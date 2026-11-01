// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy src/sample.c and src/acl.c.
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Sample expression parsing, compilation, and evaluation.
//!
//! Parses expressions like `req.hdr(Host),lower -m str example.com` or `path_beg /api`.

use crate::matcher::Matcher;
use crate::registry::{Compiled, Registry, SampleContext};
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
    /// The value of a constant expression ([`Expr::constant`]), computed on first use.
    constant: std::sync::OnceLock<Option<Sample>>,
    /// The fetch and converters resolved to function pointers when the expression is parsed
    /// (against [`crate::sample_registry`]); the data path then looks up no name and
    /// initialises nothing.
    compiled: Option<Compiled>,
}

/// The fetches whose sample is a function of their arguments only (`smp_fetch_const_*`,
/// src/sample.c): with no converter, the expression is a constant.
const CONST_FETCHES: [&str; 7] = ["str", "int", "bin", "bool", "ipv4", "ipv6", "meth"];

/// `is_idchar` (include/haproxy/tools.h): what a fetch or converter name may contain.
fn is_idchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | ':')
}

thread_local! {
    static PARSES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many times [`Expr::parse`] has run on this thread: a test reads it around a request
/// to show that the data path parses nothing once the configuration is compiled.
#[must_use]
pub fn parses_on_this_thread() -> u64 {
    PARSES.with(std::cell::Cell::get)
}

/// Bumped by [`new_generation`]: the expressions a thread has cached belong to the
/// configuration that was current when it parsed them.
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many different texts one thread keeps compiled. Every text cached is configuration
/// text, so a real configuration stays far below it; the bound only keeps a caller that
/// passed other text from growing the cache.
const CACHE_MAX: usize = 16_384;

type ExprCache = std::collections::HashMap<Box<str>, Result<std::rc::Rc<Expr>, String>>;

thread_local! {
    static CACHE: std::cell::RefCell<(u64, ExprCache)> = std::cell::RefCell::new((0, ExprCache::new()));
}

/// A new configuration is being built: every thread forgets the expressions it compiled
/// for the previous one (a `-f` file read again, a map reloaded) on its next lookup.
pub fn new_generation() {
    GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The current expression generation: it changes whenever any engine in the process is
/// built, which empties every thread's cache (a test that counts parses reads it before and
/// after, and measures again if it moved).
#[must_use]
pub fn generation() -> u64 {
    GENERATION.load(std::sync::atomic::Ordering::Relaxed)
}

impl Expr {
    /// [`Expr::parse`], once per text and thread: the expression compiled the first time
    /// `input` is evaluated, as `HAProxy` compiles it once when the configuration loads
    /// (`sample_parse_expr`). The data path calls this with configuration text (a rule's
    /// expression, an anonymous ACL, a `%[...]`), so after the first request nothing is
    /// parsed, and an ACL's `-f` file is not looked at again.
    ///
    /// A `-f` pattern list still follows `add acl` / `del acl` and the like: the compiled
    /// matcher holds the shared reference and recompiles when its version changes
    /// ([`crate::patref::FileMatcher`]).
    ///
    /// # Errors
    /// As [`Expr::parse`], the error remembered as well.
    pub fn cached(input: &str) -> Result<std::rc::Rc<Self>, String> {
        crate::work::note(crate::work::Op::ExprLookup, 1);
        let generation = GENERATION.load(std::sync::atomic::Ordering::Relaxed);
        let hit = CACHE.with(|c| {
            let mut c = c.borrow_mut();
            if c.0 != generation {
                c.1.clear();
                c.0 = generation;
            }
            c.1.get(input).cloned()
        });
        if let Some(hit) = hit {
            return hit;
        }
        let parsed = Self::parse(input).map(std::rc::Rc::new);
        CACHE.with(|c| {
            let mut c = c.borrow_mut();
            if c.0 == generation && c.1.len() < CACHE_MAX {
                c.1.insert(input.into(), parsed.clone());
            }
        });
        parsed
    }

    /// Parses an expression string into an [`Expr`].
    ///
    /// # Errors
    /// Returns an error if the expression syntax or matcher compilation fails.
    #[allow(clippy::too_many_lines)]
    pub fn parse(input: &str) -> Result<Self, String> {
        PARSES.with(|n| n.set(n.get() + 1));
        let mut input = input.trim();
        if input.starts_with('{') && input.ends_with('}') {
            input = input[1..input.len() - 1].trim();
        }
        if input.is_empty() {
            return Err("Empty sample expression".to_string());
        }

        let (expr_part, matcher_part) = split_expr_and_matcher(input);
        let m_tokens = matcher_part.map(tokenize_matcher_part).unwrap_or_default();
        let mut chain = parse_chain(expr_part)?.into_iter();
        let Some((mut fetch_name, fetch_args)) = chain.next() else {
            return Err("Missing expression".to_string());
        };
        if fetch_name.is_empty()
            || !fetch_name
                .chars()
                .all(is_idchar)
        {
            return Err(format!("Invalid sample fetch name '{fetch_name}'"));
        }

        let mut converters = Vec::new();
        for (c_name, c_args) in chain {
            if c_name.is_empty()
                || !c_name
                    .chars()
                    .all(is_idchar)
            {
                return Err(format!("Invalid converter name '{c_name}'"));
            }
            // `check_operator`: a variable, or an integer `read_int64` takes whole; `-`, `+`
            // and nothing are 0 (T343: `HAProxy` accepts `and(-)` and a bare `add`).
            if matches!(c_name.as_str(), "add" | "sub" | "mul" | "div" | "mod" | "and" | "or" | "xor") {
                let arg = c_args.first().map_or("", String::as_str);
                if crate::argspec::read_int64_whole(arg).is_none() && !crate::argspec::is_variable(arg) {
                    return Err(format!("invalid args in converter '{c_name}' : expects an integer or a variable name."));
                }
            }
            converters.push((c_name, c_args));
        }

        // ACL keyword shorthands (`path_beg`, `hdr_sub`, `url_len`, `shdr_reg`, `req_ver`, ...):
        // a fetch and a default match method (`haproxy -dKacl`). Any other name is the
        // fetch itself, where HAProxy also lets a few bare names (`hdr_val`, `scook`, ...)
        // stand for the dotted ones Ibex registers.
        let kw = fetch_name.clone();
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
        let mut acl_files: Vec<std::sync::Arc<crate::patref::PatRef>> = Vec::new();
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
                    // `parse_acl_expr`: unless the method is `found`, the expression's output
                    // type must cast to what the method matches on. An unknown name is
                    // refused below; a type nobody can name (an unregistered fetch) is not
                    // checked here.
                    if let Some(ty) = crate::acl_types::expr_output_type(&fetch_name, &converters) {
                        crate::acl_types::check_match_method(m_method, &kw, ty)?;
                    }
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
                        "bool" => "bool",
                        other => return Err(format!("unknown matching method '{other}' when parsing ACL expression")),
                    };
                    forced = true;
                }
                "-f" => {
                    idx += 1;
                    let path = tokens
                        .get(idx)
                        .ok_or_else(|| "Missing file name after -f".to_string())?;
                    acl_files.push(crate::patref::acl_file(path)?);
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
        let has_patterns = !acl_files.is_empty() || !inline.is_empty();

        if has_patterns && match_method == "found" && !forced {
            // A binary sample has no default method: the payload fetches are ACL keywords
            // only as `payload` and `payload_lv`.
            if converters.is_empty() && matches!(fetch_name.as_str(), "req.payload" | "req.payload_lv" | "res.payload" | "res.payload_lv") {
                return Err(format!(
                    "matching method must be specified first (using '-m') when using a sample fetch of this type ('{fetch_name}')"
                ));
            }
            match_method = default_match_method(&fetch_name, &converters);
        }

        // A keyword's own match method only applies when there is something to match.
        if !has_patterns && !forced {
            match_method = "found";
        }

        let mut patterns: Vec<String> = Vec::new();
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
        } else if patterns.is_empty() && acl_files.is_empty() {
            Some(Matcher::compile_with_flags(match_method, "", case_insensitive)?)
        } else {
            // The patterns of a `-f` file are read where they are, so that `add acl` and
            // `del acl` on the stats socket change what the next request matches.
            let mut list = Vec::with_capacity(patterns.len() + acl_files.len());
            for file in acl_files {
                list.push(Matcher::File(std::sync::Arc::new(crate::patref::FileMatcher::new(file, match_method, case_insensitive)?)));
            }
            for pattern in &patterns {
                list.push(Matcher::compile_with_flags(match_method, pattern, case_insensitive)?);
            }
            if list.len() == 1 {
                list.pop()
            } else {
                Some(Matcher::Any(list))
            }
        };

        let mut compiled = crate::sample_registry().compile(&fetch_name, &converters);
        if fetch_name == "var" {
            if let (Some(c), Some(name)) = (compiled.as_mut(), fetch_args.first()) {
                c.resolve_var(name);
            }
        }
        Ok(Expr {
            fetch_name,
            fetch_args,
            converters,
            matcher,
            alternates: Vec::new(),
            constant: std::sync::OnceLock::new(),
            compiled,
        })
    }

    /// The sample of a constant expression (`str(hello)`, `int(5)`: a constant fetch and no
    /// converter), evaluated once and borrowed after, as `HAProxy`'s `smp_fetch_const_str`
    /// points at its argument: `set-var` copies it into the variable with no allocation
    /// (T364 S6). `None` for any other expression.
    #[must_use]
    pub fn constant(&self, registry: &Registry) -> Option<&Sample> {
        if !self.converters.is_empty() || self.matcher.is_some() || !CONST_FETCHES.contains(&self.fetch_name.as_str()) {
            return None;
        }
        self.constant
            .get_or_init(|| registry.eval(&self.fetch_name, &self.fetch_args, &[], &SampleContext::default()))
            .as_ref()
    }

    /// The compiled form. A known fetch is always compiled at parse (debug assertion); an
    /// unknown fetch or converter is not, and the by-name path answers (empty) as before.
    fn compiled(&self, registry: &Registry) -> Option<&Compiled> {
        debug_assert!(
            self.compiled.is_some() || !registry.has_fetch(&self.fetch_name) || self.converters.iter().any(|(n, _)| !registry.has_converter(n)),
            "expression {:?} was not compiled at parse",
            self.fetch_name
        );
        self.compiled.as_ref()
    }

    /// Evaluates the expression against the sample context to produce a sample value.
    #[must_use]
    pub fn eval_sample(&self, registry: &Registry, ctx: &SampleContext) -> Option<Sample> {
        match self.compiled(registry) {
            Some(c) => Registry::eval_c(c, &self.fetch_args, &self.converters, ctx),
            None => registry.eval_g(&self.fetch_name, &self.fetch_args, &self.converters, ctx),
        }
    }

    /// Evaluates the expression against the sample context to produce all sample values.
    #[must_use]
    pub fn eval_all_samples(&self, registry: &Registry, ctx: &SampleContext) -> Vec<Sample> {
        match self.compiled(registry) {
            Some(c) => Registry::eval_all_c(c, &self.fetch_args, &self.converters, ctx),
            None => registry.eval_all_g(&self.fetch_name, &self.fetch_args, &self.converters, ctx),
        }
    }

    /// Evaluates the expression condition, returning `true` if the condition matches
    /// it or any of the other lines of its ACL.
    #[must_use]
    pub fn eval(&self, registry: &Registry, ctx: &SampleContext) -> bool {
        self.eval_line(registry, ctx) || self.alternates.iter().any(|e| e.eval(registry, ctx))
    }

    fn eval_line(&self, registry: &Registry, ctx: &SampleContext) -> bool {
        // No list of the samples and no copy of the converters: each sample is matched as it
        // comes (T437).
        let test = |smp: &Sample| match self.matcher {
            Some(ref matcher) => matcher.matches(smp),
            None => match smp {
                Sample::Bool(b) => *b,
                Sample::Sint(i) => *i != 0,
                _ => true,
            },
        };
        match self.compiled(registry) {
            Some(c) => Registry::any_acl_c(c, &self.fetch_args, &self.converters, ctx, test),
            None => registry.any_acl(&self.fetch_name, &self.fetch_args, &self.converters, ctx, test),
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
/// type of the sample): integers for numbers, addresses for IPs, strings otherwise. With
/// converters, it is the type the last one leaves.
fn default_match_method(fetch_name: &str, converters: &[(String, Vec<String>)]) -> &'static str {
    use crate::sample::{SampleType, TypeSpec};
    let reg = crate::registry::sample_registry();
    if let Some((name, _)) = converters.last() {
        let out = reg
            .get_converter(name)
            .map(|c| c.out_type)
            .or_else(|| reg.get_ctx_converter(name).map(|c| c.out_type));
        return match out {
            Some(TypeSpec::Exact(SampleType::Sint | SampleType::Bool)) => "int",
            Some(TypeSpec::Exact(SampleType::Ipv4 | SampleType::Ipv6) | TypeSpec::Addr) => "ip",
            Some(TypeSpec::Same | TypeSpec::Any) => default_match_method(fetch_name, &converters[..converters.len() - 1]),
            _ => "str",
        };
    }
    if fetch_name == "src" || fetch_name == "dst" {
        "ip"
    } else if fetch_name.ends_with("_port") || fetch_name == "status" || fetch_name.starts_with("sc_") {
        "int"
    } else if let Some(desc) = reg.get_fetch(fetch_name) {
        match desc.out_type {
            SampleType::Sint => "int",
            SampleType::Ipv4 | SampleType::Ipv6 => "ip",
            _ => "str",
        }
    } else {
        "str"
    }
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

    let mut escaped = false;
    for (i, ch) in input.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' && in_quote != Some('\'') {
            // `make_arg_list` escapes only these; `\)` still closes the arguments.
            escaped = matches!(input.as_bytes().get(i + 1), Some(b'\\' | b' ' | b'"' | b'\''));
        } else if let Some(q) = in_quote {
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

/// The fetch and converters of `expr_part`, each with its arguments: `sample_parse_expr`'s
/// walk. A name runs to `(` or `,`; its arguments are `make_arg_list`'s ([`scan_arg`]); after
/// them comes `,` or the end.
fn parse_chain(expr_part: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    let b = expr_part.as_bytes();
    let mut calls: Vec<(String, Vec<String>)> = Vec::new();
    let mut pos = 0;
    loop {
        let name_end = b[pos..].iter().position(|c| matches!(c, b'(' | b',')).map_or(b.len(), |n| pos + n);
        let name = expr_part[pos..name_end].trim().to_string();
        pos = name_end;
        let mut args = Vec::new();
        if b.get(pos) == Some(&b'(') {
            pos += 1;
            loop {
                let (arg, stop) = scan_arg(b, &mut pos);
                args.push(arg);
                match stop {
                    Some(b',') => pos += 1,
                    Some(_) => {
                        pos += 1;
                        break;
                    }
                    None => {
                        return Err(if calls.is_empty() {
                            format!("fetch method '{name}' : expected ')'")
                        } else {
                            // HAProxy counts the empty argument a missing paren leaves.
                            let n = if args.len() > 1 { args.len() - 1 } else { args.len() };
                            format!("invalid arg {} in converter '{name}' : expected ')'", n + 1)
                        });
                    }
                }
            }
            // `f()` has no argument; `f(,)` has two empty ones.
            // The names fetches read an empty argument as the delimiter NUL, `()` too (T340).
            let names_fetch = calls.is_empty()
                && matches!(
                    name.as_str(),
                    "req.hdr_names" | "res.hdr_names" | "req.cook_names" | "res.cook_names"
                );
            if args.len() == 1 && args[0].is_empty() && !names_fetch {
                args.clear();
            }
        }
        let first = calls.is_empty();
        calls.push((name, args));
        match b.get(pos) {
            None => return Ok(calls),
            // `sample_parse_expr` skips a run of commas (`str(a),,lower`), trailing ones too
            // (T341). In a `%[...]` the `]` follows them: the log-format parser refuses that.
            Some(b',') => {
                while b.get(pos) == Some(&b',') {
                    pos += 1;
                }
                if pos == b.len() {
                    return Ok(calls);
                }
            }
            Some(_) if first => return Err("missing comma after fetch keyword".to_string()),
            Some(_) => {
                // HAProxy checks a converter's arguments (`val_args`) before it looks for the
                // comma after them: `hmac(sha256,var(txn.k))` is refused for its key.
                let (name, args) = calls.last().map_or(("", &[][..]), |c| (c.0.as_str(), c.1.as_slice()));
                return Err(crate::registry::check_converter_args(name, args)
                    .unwrap_or_else(|| format!("missing comma after converter '{name}'")));
            }
        }
    }
}

/// One argument from `b[*pos..]`, as `make_arg_list` (src/arg.c) reads it: blanks are kept;
/// a quote toggles quoting wherever it is and is dropped; outside single quotes a backslash
/// escapes `\`, a blank, `"` and `'`, makes `\r`, `\n` and `\t` control characters, and stays
/// before anything else; an unquoted `,` or `)` ends the argument, and is returned (`None` at
/// the end of the text). `*pos` is left on the character that stopped it.
fn scan_arg(b: &[u8], pos: &mut usize) -> (String, Option<u8>) {
    let (mut squote, mut dquote) = (false, false);
    let mut out = Vec::new();
    while let Some(&c) = b.get(*pos) {
        match c {
            b'"' if !squote => dquote = !dquote,
            b'\'' if !dquote => squote = !squote,
            b'\\' if !squote && *pos + 1 < b.len() => match b[*pos + 1] {
                n @ (b'\\' | b' ' | b'"' | b'\'') => {
                    out.push(n);
                    *pos += 1;
                }
                b'r' => {
                    out.push(b'\r');
                    *pos += 1;
                }
                b'n' => {
                    out.push(b'\n');
                    *pos += 1;
                }
                b't' => {
                    out.push(b'\t');
                    *pos += 1;
                }
                _ => out.push(b'\\'),
            },
            b',' | b')' if !squote && !dquote => return (String::from_utf8_lossy(&out).into_owned(), Some(c)),
            _ => out.push(c),
        }
        *pos += 1;
    }
    (String::from_utf8_lossy(&out).into_owned(), None)
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
        fn tracked_key(&self, _slot: usize, _table: Option<&str>) -> Option<crate::Sample> {
            None
        }
        fn write_tracked(&self, _slot: usize, _table: Option<&str>, _op: crate::StickOp) -> Option<i64> {
            None
        }
        fn write_source(&self, _addr: IpAddr, _tables: &[&str], _op: crate::StickOp) -> Option<i64> {
            None
        }
    }

    /// The stand-in tracks nothing and writes nothing.
    #[test]
    fn the_slot0_stand_in_answers_nothing_for_keys_and_writes() {
        use crate::StickState;
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        assert!(Slot0.tracked_key(0, None).is_none());
        assert!(Slot0.write_tracked(0, None, crate::StickOp::UpdtConnCnt).is_none());
        assert!(Slot0.write_source(ip, &[], crate::StickOp::UpdtConnCnt).is_none());
    }

    use super::*;

    /// The default match method follows the type the converters leave, not the fetch's:
    /// `src,table_trackers(t) eq 1` compares integers (`unknown_key.vtc`).
    #[test]
    fn a_converter_sets_the_default_match_method() {
        Expr::parse("src,table_trackers(test) eq 1").expect("an integer match");
        Expr::parse("src,in_table(test) 1").expect("a boolean matched as an integer");
        assert!(Expr::parse("src,lower 300.1.1.1").is_ok(), "a string match");
        assert!(Expr::parse("src 300.1.1.1").is_err(), "an address match");
        assert!(Expr::parse("src,ipmask(24) 300.1.1.1").is_err(), "a converter that leaves an address");
        assert!(Expr::parse("src,debug 300.1.1.1").is_err(), "a converter that keeps the fetch's type");
        Expr::parse("str(a),map_str_ip(/dev/null) 10.0.0.1").expect("a converter that makes an address");
        assert!(Expr::parse("str(a),map_str_ip(/dev/null) 300.1.1.1").is_err(), "a converter that makes an address");
    }
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
            v.borrow_mut().insert("sess.str3", Sample::Str("this is a string".to_string()));
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
