// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Which ACLs a condition may name. `HAProxy` resolves each name while it reads the rule,
//! against the ACLs declared so far in the same proxy (an ACL of a `defaults` section, of
//! another proxy or declared further down is "no such ACL") and the predefined ones of
//! `default_acl_list` (`src/acl.c`). The parser keeps that scope here, as it walks the lines,
//! so that [`check_term`] can refuse the name in one place whatever the rule kind. The text
//! of the refusal depends on the rule, as in `HAProxy`; it is built from the line being read.

use std::cell::RefCell;

use super::{ConfigError, Token};

const PREDEFINED: &[&str] = &[
    "TRUE", "FALSE", "LOCALHOST", "HTTP", "HTTP_1.0", "HTTP_1.1", "HTTP_2.0", "HTTP_3.0", "METH_CONNECT", "METH_DELETE",
    "METH_GET", "METH_HEAD", "METH_OPTIONS", "METH_POST", "METH_PUT", "METH_TRACE", "HTTP_URL_ABS", "HTTP_URL_SLASH",
    "HTTP_URL_STAR", "HTTP_CONTENT", "RDP_COOKIE", "REQ_CONTENT", "WAIT_END",
];

#[derive(Default)]
struct Scope {
    /// False outside `parse_str`: the condition parser is then called on its own (unit
    /// tests) and checks nothing.
    active: bool,
    acls: Vec<String>,
    /// `frontend`, `backend` or `proxy` (a `listen`), and the proxy's name.
    kind: &'static str,
    proxy: String,
    /// The words of the line being read.
    line: Vec<String>,
}

thread_local! {
    static SCOPE: RefCell<Scope> = RefCell::new(Scope::default());
}

/// Starts a parse: the scope is active and empty.
pub(crate) fn begin() {
    SCOPE.with(|s| *s.borrow_mut() = Scope { active: true, ..Scope::default() });
}

/// Ends a parse.
pub(crate) fn end() {
    SCOPE.with(|s| *s.borrow_mut() = Scope::default());
}

/// Called for every line before it is parsed: a section header opens a new scope, any line is
/// remembered for the text of a refusal.
pub(crate) fn enter_line(tokens: &[Token]) {
    SCOPE.with(|s| {
        let mut s = s.borrow_mut();
        let kw = tokens.first().map_or("", |t| t.text.as_str());
        let kind = match kw {
            "frontend" => Some("frontend"),
            "backend" => Some("backend"),
            "listen" => Some("proxy"),
            "global" | "defaults" | "ring" | "userlist" | "peers" | "mailers" | "resolvers" | "http-errors" | "cache"
            | "program" | "log-forward" | "fcgi-app" | "crt-store" | "traces" | "acme" | "thread-group" => Some(""),
            _ => None,
        };
        if let Some(kind) = kind {
            s.acls.clear();
            s.kind = if kind.is_empty() { "proxy" } else { kind };
            s.proxy = if kind.is_empty() { String::new() } else { tokens.get(1).map(|t| t.text.clone()).unwrap_or_default() };
        }
        s.line = tokens.iter().map(|t| t.text.clone()).collect();
    });
}

/// Records an `acl` line that parsed.
pub(crate) fn declare(name: &str) {
    SCOPE.with(|s| {
        let mut s = s.borrow_mut();
        if s.active && !s.acls.iter().any(|a| a == name) {
            s.acls.push(name.to_string());
        }
    });
}

/// Refuses the ACL name `name` (a term of a condition, at `at`) if it is neither declared
/// before in this proxy nor predefined, with the text `HAProxy` gives for the rule being read.
pub(crate) fn check_term(name: &str, at: &Token) -> Result<(), ConfigError> {
    SCOPE.with(|s| {
        let s = s.borrow();
        if !s.active || PREDEFINED.contains(&name) || s.acls.iter().any(|a| a == name) {
            return Ok(());
        }
        let w = |i: usize| s.line.get(i).map_or("", String::as_str);
        let no = format!("no such ACL : '{name}'");
        let msg = match w(0) {
            "use_backend" | "use-server" => format!("error detected while parsing switching rule : {no}."),
            "tcp-request" | "tcp-response" => format!(
                "'{} {} {}' : error detected in {} '{}' while parsing 'if' condition : {no}",
                w(0),
                w(1),
                w(2),
                s.kind,
                s.proxy
            ),
            "http-request" | "http-response" | "http-after-response" if w(1) == "redirect" => format!(
                "error detected in {} '{}' while parsing '{} redirect' rule : error in condition: {no}.",
                s.kind,
                s.proxy,
                w(0)
            ),
            "http-request" | "http-response" | "http-after-response" => {
                format!("error detected while parsing an '{} {}' condition : {no}.", w(0), w(1))
            }
            // A stats rule is parsed as the proxy's own `http-request` rule, and worded so.
            "stats" if w(1) == "http-request" => {
                format!("error detected while parsing an 'http-request {}' condition : {no}.", w(2))
            }
            "stats" => format!("error detected while parsing a 'stats {}' rule : {no}.", w(1)),
            "monitor" => format!("error detected while parsing a 'monitor fail' condition : {no}."),
            "stick" => format!("'stick': error detected while parsing sticking condition : {no}."),
            "force-be-switch" => format!("'force-be-switch' : {no}."),
            kw => format!("error detected while parsing a '{kw}' rule : {no}."),
        };
        Err(ConfigError::new(at.line, at.col, msg))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_without_a_text_of_its_own_gets_the_generic_one() {
        begin();
        let tok = |t: &str| Token { text: t.to_string(), line: 3, col: 1 };
        enter_line(&[tok("backend"), tok("b")]);
        enter_line(&[tok("some-rule"), tok("if"), tok("nosuch")]);
        let e = check_term("nosuch", &tok("nosuch")).unwrap_err();
        end();
        assert_eq!(e.message, "error detected while parsing a 'some-rule' rule : no such ACL : 'nosuch'.");
    }
}
