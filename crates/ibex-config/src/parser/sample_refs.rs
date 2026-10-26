// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! Records where sample expressions are written, for the load-time check of their
//! arguments and names (`ibex-rt`'s `rule_exprs`).
//!
//! Two places are unambiguous from the words of a line alone, whatever the directive:
//! an ACL's expression -- the word after `acl <name>`, or after a `{` opening an anonymous
//! ACL -- and a log-format's `%[<expr>]` (or `%{<flags>}[<expr>]`). Rule actions whose
//! argument is a bare expression (`set-var`, `track-sc0`, ...) are in the AST already and
//! are checked from there.

use super::{CurrentSection, SampleRef, SectionKind, Token};

/// The section kind and name of `section`, if it is one sample expressions are written in.
fn section_of(section: &CurrentSection) -> Option<(SectionKind, Option<String>)> {
    match section {
        CurrentSection::Defaults(d) => Some((SectionKind::Defaults, d.name.clone())),
        CurrentSection::Frontend(f) => Some((SectionKind::Frontend, Some(f.name.clone()))),
        CurrentSection::Backend(b) => Some((SectionKind::Backend, Some(b.name.clone()))),
        CurrentSection::Listen(l) => Some((SectionKind::Listen, Some(l.name.clone()))),
        CurrentSection::Global(_) | CurrentSection::Userlist(_) | CurrentSection::HttpErrors(..) | CurrentSection::Ring(_) | CurrentSection::LogForward(_)
        | CurrentSection::Resolvers(_) => None,
    }
}

/// The expressions of every `%[...]` in `fmt`, in order. `%%` is a literal percent sign;
/// `%{+Q}[...]` carries flags before the expression.
pub fn log_format_exprs(fmt: &str) -> Vec<&str> {
    let bytes = fmt.as_bytes();
    let mut found = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] != b'%' {
            pos += 1;
            continue;
        }
        if bytes.get(pos + 1) == Some(&b'%') {
            pos += 2;
            continue;
        }
        let mut open = pos + 1;
        if bytes.get(open) == Some(&b'{') {
            match fmt[open..].find('}') {
                Some(end) => open += end + 1,
                None => break,
            }
        }
        if bytes.get(open) != Some(&b'[') {
            pos += 1;
            continue;
        }
        // T343: with no `]` (`%[int(` where an unquoted blank ended the word), `HAProxy` parses the
        // expression to the end of the text and refuses what it finds there.
        let Some(close) = expr_end(bytes, open + 1) else {
            found.push(&fmt[open + 1..]);
            break;
        };
        found.push(&fmt[open + 1..close]);
        pos = close + 1;
    }
    found
}

/// The index of the `]` closing an expression that starts at `start`, skipping escaped
/// characters, quoted text and parenthesised arguments.
fn expr_end(bytes: &[u8], start: usize) -> Option<usize> {
    let (mut depth, mut quote, mut at) = (0usize, None, start);
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == b'\\' {
            at += 2;
            continue;
        }
        match quote {
            Some(q) if byte == q => quote = None,
            Some(_) => {}
            None => match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                b']' if depth == 0 => return Some(at),
                _ => {}
            },
        }
        at += 1;
    }
    None
}

/// Appends the sample expressions on the directive `tokens`, written in `section`, to `out`.
pub(crate) fn collect(section: &CurrentSection, tokens: &[Token], out: &mut Vec<SampleRef>) {
    let Some((kind, proxy)) = section_of(section) else { return };
    let push = |out: &mut Vec<SampleRef>, t: &Token, acl: bool, expr: &str, full: Option<String>| {
        out.push(SampleRef {
            line: t.line,
            section: kind,
            proxy: proxy.clone(),
            acl,
            directive: tokens[0].text.clone(),
            action: tokens.get(1).map(|t| t.text.clone()).unwrap_or_default(),
            expr: expr.to_string(),
            full,
            whole_format: false,
        });
    };
    if tokens[0].text == "acl" {
        if let Some(t) = tokens.get(2) {
            push(out, t, true, &t.text, None);
        }
    }
    // A server's `sni <expr>` is a sample expression evaluated when it is connected to.
    if matches!(tokens[0].text.as_str(), "server" | "server-template") || tokens[0].text == "default-server" {
        for (i, t) in tokens.iter().enumerate() {
            if t.text == "sni" {
                if let Some(e) = tokens.get(i + 1) {
                    push(out, e, false, &e.text, None);
                }
            }
        }
        return;
    }
    // `http-check send uri <uri>` and `body <string>` are literal (`uri-lf`, `body-lf` and
    // the `hdr` values are the log-formats), and so is `option httpchk`'s URI.
    let literal_after = |i: usize| {
        i > 0
            && ((tokens[0].text == "http-check"
                && tokens.get(1).is_some_and(|t| t.text == "send")
                && matches!(tokens[i - 1].text.as_str(), "uri" | "body" | "meth" | "ver"))
                || (tokens[0].text == "option" && tokens.get(1).is_some_and(|t| t.text == "httpchk")))
    };
    for (i, t) in tokens.iter().enumerate() {
        if t.text == "{" {
            if let Some(next) = tokens.get(i + 1).filter(|n| n.text != "}") {
                let end = tokens[i + 1..].iter().position(|w| w.text == "}").map_or(tokens.len(), |e| i + 1 + e);
                let full = tokens[i + 1..end].iter().map(|w| super::acl::expr_word(&w.text)).collect::<Vec<_>>().join(" ");
                push(out, next, true, &next.text, Some(full));
            }
            continue;
        }
        if literal_after(i) {
            continue;
        }
        for expr in log_format_exprs(&t.text) {
            push(out, t, false, expr, None);
        }
    }
    // The whole formats, after the expressions in them, which are checked first.
    for i in format_words(tokens) {
        let t = &tokens[i];
        out.push(SampleRef {
            line: t.line,
            section: kind,
            proxy: proxy.clone(),
            acl: false,
            directive: tokens[0].text.clone(),
            action: tokens.get(1).map(|t| t.text.clone()).unwrap_or_default(),
            expr: t.text.clone(),
            full: None,
            whole_format: true,
        });
    }
}

/// The indexes of the words of a rule that `HAProxy` compiles as a format
/// (`parse_logformat_string`): a header's value, a `set-var-fmt`'s, the target of a `set-path`
/// or `redirect`, the replacement of a `replace-header`, an `lf-string`.
fn format_words(tokens: &[Token]) -> Vec<usize> {
    let word = |i: usize| tokens.get(i).map(|t| t.text.as_str());
    let a = match word(0) {
        Some("http-request" | "http-response" | "http-after-response") => 1,
        Some("tcp-request" | "tcp-response") => 2,
        _ => return Vec::new(),
    };
    let Some(action) = word(a) else { return Vec::new() };
    let mut found = Vec::new();
    match action {
        "set-header" | "add-header" | "early-hint" | "replace-path" | "replace-pathq" | "replace-uri" => found.push(a + 2),
        "set-path" | "set-pathq" | "set-query" | "set-uri" | "set-method" => found.push(a + 1),
        "replace-header" | "replace-value" => found.push(a + 3),
        "redirect" => {
            if let Some(i) = tokens.iter().position(|t| matches!(t.text.as_str(), "location" | "prefix" | "scheme")) {
                found.push(i + 1);
            }
        }
        _ if action.starts_with("set-var-fmt") => found.push(a + 1),
        _ => {}
    }
    for (i, t) in tokens.iter().enumerate() {
        if matches!(t.text.as_str(), "lf-string" | "set-cookie-fmt") && !found.contains(&(i + 1)) {
            found.push(i + 1);
        }
    }
    found.retain(|&i| i < tokens.len() && tokens[i].text != "if" && tokens[i].text != "unless");
    found
}

#[cfg(test)]
mod tests {
    use super::log_format_exprs;

    #[test]
    fn finds_each_expression_of_a_log_format() {
        assert_eq!(log_format_exprs("a%[nbsrv(be)]-%[srv_is_up(s),iif(up,down)]"), ["nbsrv(be)", "srv_is_up(s),iif(up,down)"]);
        assert_eq!(log_format_exprs("%{+Q}[req.hdr(x)] %%[not] %ci"), ["req.hdr(x)"]);
        assert_eq!(log_format_exprs("%[str(a]b)]"), ["str(a]b)"]);
        // T343: the rest of the text, which `HAProxy` parses as the expression and refuses
        // (`%[int(` "expected type 'integer' at position 1, but got nothing").
        assert_eq!(log_format_exprs("%[unterminated"), ["unterminated"]);
        assert!(log_format_exprs("%{+Q").is_empty());
        assert_eq!(log_format_exprs(r#"%[str("a]b")] %[str(a\]b)]"#), [r#"str("a]b")"#, r"str(a\]b)"]);
    }
}
