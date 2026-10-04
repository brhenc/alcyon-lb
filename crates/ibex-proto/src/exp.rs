// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from HAProxy 1.0.2 cliexp / srvexp rewriting (haproxy.c:apply_filter).
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Client and server regex header rewrite engine (`cliexp` and `srvexp`).

use crate::htx::{Htx, HtxBlock};
use ibex_regex::UserRegex as Regex;

/// A compiled regex rewrite rule.
#[derive(Debug, Clone)]
pub struct CompiledExp {
    pub regex: Regex,
    pub replacement: String,
}

impl CompiledExp {
    /// Compiles a new regex rewrite rule, converting `HAProxy` \1 backreferences to Rust $1.
    ///
    /// # Errors
    /// Returns a regex compilation error if `pattern` is invalid.
    pub fn new(pattern: &str, replacement: impl Into<String>) -> Result<Self, ibex_regex::Error> {
        let regex = Regex::new(pattern)?;
        let rep_str = replacement.into();
        let converted_rep = convert_haproxy_replacement(&rep_str);
        Ok(CompiledExp {
            regex,
            replacement: converted_rep,
        })
    }

    /// Applies regex substitution to a single line.
    #[must_use]
    pub fn apply(&self, line: &str) -> String {
        self.regex
            .replace_all(line, self.replacement.as_str())
            .into_owned()
    }
}

fn convert_haproxy_replacement(rep: &str) -> String {
    let mut out = String::with_capacity(rep.len());
    let mut chars = rep.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next.is_ascii_digit() && next != '0' {
                    out.push('$');
                    out.push(next);
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// Searches for a cookie by name in an HTTP header block (looking for `Cookie:` lines).
#[must_use]
pub fn extract_cookie(headers: &str, cookie_name: &str) -> Option<String> {
    for line in headers.lines() {
        let trimmed = line.trim();
        if let Some(cookie_hdr) = trimmed
            .strip_prefix("Cookie:")
            .or_else(|| trimmed.strip_prefix("cookie:"))
        {
            for part in cookie_hdr.split(';') {
                let p = part.trim();
                if let Some((k, v)) = p.split_once('=') {
                    if k.trim() == cookie_name {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

/// Rewrites a complete raw HTTP header block line-by-line using the given compiled regex rules.
#[must_use]
pub fn rewrite_header_block(headers_raw: &str, rules: &[CompiledExp]) -> String {
    if rules.is_empty() {
        return headers_raw.to_string();
    }
    let mut out = String::with_capacity(headers_raw.len() + 64);
    let mut first = true;
    for line in headers_raw.split("\r\n") {
        if !first {
            out.push_str("\r\n");
        }
        first = false;
        let mut curr_line = line.to_string();
        for rule in rules {
            if rule.regex.is_match(&curr_line) {
                curr_line = rule.apply(&curr_line);
            }
        }
        out.push_str(&curr_line);
    }
    out
}

/// Applies client expression rules (`cliexp`) to request start line and request headers.
pub fn apply_cliexp(htx: &mut Htx, rules: &[CompiledExp]) {
    if rules.is_empty() {
        return;
    }

    // 1. Rewrite Request Line URI if needed
    if let Some(req) = htx.req_line_mut() {
        for rule in rules {
            let orig_uri = req.uri.clone();
            let new_uri = rule.apply(&orig_uri);
            if new_uri != orig_uri {
                req.uri = new_uri;
            }
        }
    }

    // 2. Rewrite Request Headers
    apply_header_rules(htx, rules);
}

/// Applies server expression rules (`srvexp`) to response status line and response headers.
pub fn apply_srvexp(htx: &mut Htx, rules: &[CompiledExp]) {
    if rules.is_empty() {
        return;
    }

    // 1. Rewrite Response Reason if needed
    if let Some(res) = htx.res_line_mut() {
        for rule in rules {
            let orig_reason = res.reason.clone();
            let new_reason = rule.apply(&orig_reason);
            if new_reason != orig_reason {
                res.reason = new_reason;
            }
        }
    }

    // 2. Rewrite Response Headers
    apply_header_rules(htx, rules);
}

fn apply_header_rules(htx: &mut Htx, rules: &[CompiledExp]) {
    for block in htx.blocks_mut() {
        if let HtxBlock::Header(ref mut h) = block {
            for rule in rules {
                // Check if rule matches "Name: Value" format or direct value
                let formatted = format!("{}: {}", h.name, h.value);
                if rule.regex.is_match(&formatted) {
                    let replaced = rule.apply(&formatted);
                    if let Some((new_name, new_val)) = replaced.split_once(':') {
                        h.name = new_name.trim().to_string();
                        h.value = new_val.trim().to_string();
                    }
                } else if rule.regex.is_match(&h.value) {
                    h.value = rule.apply(&h.value);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htx::{HeaderField, HttpMethod, HttpVersion, RequestLine};

    #[test]
    fn cliexp_rewrites_uri_and_headers() {
        let mut htx = Htx::new();
        htx.push(HtxBlock::ReqLine(RequestLine {
            method: HttpMethod::Get,
            uri: "/old-api/v1/users".into(),
            version: HttpVersion::Http11,
        }));
        htx.push(HtxBlock::Header(HeaderField {
            name: "Host".into(),
            value: "internal.legacy.net".into(),
        }));
        htx.push(HtxBlock::Header(HeaderField {
            name: "User-Agent".into(),
            value: "curl/7.68.0".into(),
        }));
        htx.push(HtxBlock::Eoh);
        htx.push(HtxBlock::Eom);

        let rules = vec![
            CompiledExp::new(r"/old-api/v1/(.*)", "/api/v2/$1").unwrap(),
            CompiledExp::new(r"internal\.legacy\.net", "api.modern.io").unwrap(),
        ];

        apply_cliexp(&mut htx, &rules);

        assert_eq!(htx.req_line().unwrap().uri, "/api/v2/users");
        assert_eq!(htx.get_header("host"), Some("api.modern.io"));
        assert_eq!(htx.get_header("user-agent"), Some("curl/7.68.0"));
    }

    #[test]
    fn test_extract_cookie() {
        let headers = "GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=123; SERVERID=srv2; theme=dark\r\n\r\n";
        assert_eq!(extract_cookie(headers, "SERVERID"), Some("srv2".into()));
        assert_eq!(extract_cookie(headers, "session"), Some("123".into()));
        assert_eq!(extract_cookie(headers, "other"), None);
    }

    #[test]
    fn test_rewrite_header_block_with_haproxy_backrefs() {
        let raw = "GET http://foo.free.fr/index.html HTTP/1.0\r\nHost: foo.free.fr\r\nProxy-Connection: Keep-Alive\r\n\r\n";
        let rules = vec![
            CompiledExp::new(r"^(GET.*)(\.free\.fr)(.*)", r"\1.online.fr\3").unwrap(),
            CompiledExp::new(r"^Proxy-Connection:.*", "Proxy-Connection: close").unwrap(),
        ];
        let rewritten = rewrite_header_block(raw, &rules);
        assert!(rewritten.starts_with("GET http://foo.online.fr/index.html HTTP/1.0\r\n"));
        assert!(rewritten.contains("Proxy-Connection: close\r\n"));
    }
}
