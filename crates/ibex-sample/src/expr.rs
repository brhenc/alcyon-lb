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
}

impl Expr {
    /// Parses an expression string into an [`Expr`].
    ///
    /// # Errors
    /// Returns an error if the expression syntax or matcher compilation fails.
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut input = input.trim();
        if input.starts_with('{') && input.ends_with('}') {
            input = input[1..input.len() - 1].trim();
        }
        if input.is_empty() {
            return Err("Empty sample expression".to_string());
        }

        let mut parts = input.split_whitespace();
        let expr_part = parts
            .next()
            .ok_or_else(|| "Missing expression".to_string())?;

        // Parse fetch and converter chain: e.g. "fetch(arg),conv1(arg),conv2"
        let chain: Vec<&str> = expr_part.split(',').collect();
        let (mut fetch_name, fetch_args) = parse_call(chain[0]);

        let mut converters = Vec::new();
        for conv_str in &chain[1..] {
            let (c_name, c_args) = parse_call(conv_str);
            converters.push((c_name, c_args));
        }

        // Shorthand method resolution (e.g. path_beg, hdr_sub)
        let mut default_method = "found";
        if let Some(suffix) = fetch_name.strip_prefix("path_") {
            default_method = match suffix {
                "beg" => "beg",
                "end" => "end",
                "sub" => "sub",
                "reg" => "reg",
                _ => "found",
            };
            fetch_name = "path".to_string();
        } else if let Some(suffix) = fetch_name.strip_prefix("hdr_") {
            default_method = match suffix {
                "beg" => "beg",
                "end" => "end",
                "sub" => "sub",
                "reg" => "reg",
                _ => "str",
            };
            fetch_name = "req.hdr".to_string();
        } else if fetch_name == "hdr" {
            fetch_name = "req.hdr".to_string();
            default_method = "str";
        }

        // Optional matcher parts: e.g. `-m str pattern`, `-i pattern`, `pattern`, `gt 100`
        let mut matcher = None;
        let mut match_method = default_method;
        let mut pattern = String::new();
        let mut case_insensitive = false;

        while let Some(arg) = parts.next() {
            if arg == "-m" {
                match_method = parts
                    .next()
                    .ok_or_else(|| "Missing matcher method after -m".to_string())?;
            } else if arg == "-i" {
                case_insensitive = true;
            } else if arg == "-n" {
                // Negative / no-op flag
            } else if matches!(arg, "gt" | "ge" | "lt" | "le" | "eq" | "ne") {
                match_method = arg;
                if let Some(next_tok) = parts.next() {
                    pattern = next_tok.to_string();
                }
            } else if pattern.is_empty() {
                pattern = arg.to_string();
            }
        }

        if !pattern.is_empty() {
            if match_method == "found" {
                if fetch_name == "src" || fetch_name == "dst" {
                    match_method = "ip";
                } else if fetch_name.ends_with("_port")
                    || fetch_name == "status"
                    || fetch_name.starts_with("sc_")
                {
                    match_method = "int";
                } else {
                    match_method = "str";
                }
            }
            matcher = Some(Matcher::compile_with_flags(
                match_method,
                &pattern,
                case_insensitive,
            )?);
        } else if match_method != "found" {
            matcher = Some(Matcher::compile_with_flags(
                match_method,
                &pattern,
                case_insensitive,
            )?);
        }

        Ok(Expr {
            fetch_name,
            fetch_args,
            converters,
            matcher,
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

    /// Evaluates the expression condition, returning `true` if the condition matches.
    #[must_use]
    pub fn eval(&self, registry: &Registry, ctx: &SampleContext) -> bool {
        let sample = self.eval_sample(registry, ctx);
        match (&self.matcher, sample) {
            (Some(matcher), Some(smp)) => matcher.matches(&smp),
            (None, Some(smp)) => match smp {
                Sample::Bool(b) => b,
                Sample::Sint(i) => i != 0,
                _ => true,
            },
            _ => false,
        }
    }
}

fn parse_call(input: &str) -> (String, Vec<String>) {
    let input = input.trim();
    if let Some((name, rest)) = input.split_once('(') {
        let args_str = rest.strip_suffix(')').unwrap_or(rest);
        let args: Vec<String> = args_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        (name.trim().to_string(), args)
    } else {
        (input.to_string(), Vec::new())
    }
}

#[cfg(test)]
mod tests {
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
            cum_conn: 1,
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

        // Rate limit expressions
        let mut ctx_rates = ctx.clone();
        ctx_rates.sc_conn_rates[0] = 150;
        ctx_rates.sc_http_req_rates[0] = 75;

        let expr_rate1 = Expr::parse("{ sc_conn_rate(0) gt 100 }").unwrap();
        assert!(expr_rate1.eval(&registry, &ctx_rates));

        let expr_rate2 = Expr::parse("{ sc_http_req_rate(0) gt 50 }").unwrap();
        assert!(expr_rate2.eval(&registry, &ctx_rates));

        let expr_rate_false = Expr::parse("{ sc_http_req_rate(0) gt 100 }").unwrap();
        assert!(!expr_rate_false.eval(&registry, &ctx_rates));

        // Shorthand 2: hdr(Host) -i example.com
        let expr_shorthand2 = Expr::parse("hdr(Host) -i example.com").unwrap();
        assert!(expr_shorthand2.eval(&registry, &ctx));
    }
}
