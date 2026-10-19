// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;
use super::acl_scope;

pub(crate) fn parse_acl(acls: &mut Vec<AclRule>, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<acl> expects <name> and <expression> as arguments.",
        ));
    }
    let name = tokens[1].text.clone();
    validate_acl_regexes(&tokens[2..])?;
    let expr = tokens[2..].iter().map(|t| expr_word(&t.text)).collect::<Vec<_>>().join(" ");
    acl_scope::declare(&name);
    acls.push(AclRule { name, expr });
    Ok(())
}

pub(crate) fn parse_acl_condition_from_tokens(tokens: &[Token]) -> Result<Option<AclCondition>, ConfigError> {
    if tokens.is_empty() {
        return Ok(None);
    }
    let is_if = match tokens[0].text.as_str() {
        "if" => true,
        "unless" => false,
        other => {
            return Err(ConfigError::new(
                tokens[0].line,
                tokens[0].col,
                format!("expected 'if' or 'unless', got <{other}>"),
            ));
        }
    };

    let mut terms = Vec::new();
    // A `!` standing alone negates the term after it (`! { path /a }`).
    let mut negate_next = false;
    let mut i = 1;
    while i < tokens.len() {
        let tok = &tokens[i];
        if tok.text == "!" {
            negate_next = !negate_next;
            i += 1;
            continue;
        }
        if tok.text == "||" || tok.text == "or" {
            terms.push(AclTerm { negated: false, name: AclCondition::OR.to_string() });
            negate_next = false;
            i += 1;
            continue;
        }
        let before = terms.len();
        // `!` attached to a term negates it, a brace included (`!is_n`, `!{ path /a }`).
        let (bang, text) = match tok.text.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, tok.text.as_str()),
        };
        if text == "{" {
            let open = &tokens[i];
            let mut brace_tokens = vec![std::borrow::Cow::Borrowed("{")];
            i += 1;
            if let Some(end) = tokens[i..].iter().position(|t| t.text == "}") {
                validate_acl_regexes(&tokens[i..i + end])?;
            }
            while i < tokens.len() && tokens[i].text != "}" {
                brace_tokens.push(expr_word(&tokens[i].text));
                i += 1;
            }
            if i == tokens.len() {
                return Err(ConfigError::new(open.line, open.col, "missing closing '}' in condition"));
            }
            brace_tokens.push(std::borrow::Cow::Borrowed("}"));
            i += 1;
            terms.push(AclTerm { negated: bang, name: brace_tokens.join(" ") });
        } else if text.starts_with('{') {
            // `HAProxy` reads a brace only as a word of its own.
            return Err(ConfigError::new(tok.line, tok.col, format!("unknown ACL or sample keyword '{text}'")));
        } else {
            acl_scope::check_term(text, tok)?;
            terms.push(AclTerm { negated: bang, name: text.to_string() });
            i += 1;
        }
        if negate_next && terms.len() > before {
            if let Some(t) = terms.last_mut() {
                t.negated = !t.negated;
            }
            negate_next = false;
        }
    }

    Ok(Some(AclCondition { is_if, terms }))
}

/// Refuses at load an ACL whose `-m reg` (or `*_reg`) pattern does not compile, as
/// `HAProxy` does ("regex '(' is invalid"), and with it a pattern only a PCRE2 has that
/// Ibex cannot run, so that a rule on it is not one that silently never matches.
/// `words` is the ACL expression: the fetch, its flags and its patterns.
fn validate_acl_regexes(words: &[Token]) -> Result<(), ConfigError> {
    let Some(fetch) = words.first() else { return Ok(()) };
    let mut is_reg = fetch.text.split(['(', ',']).next().is_some_and(|f| f.ends_with("_reg"));
    let mut i = 1;
    let mut patterns_from = None;
    while i < words.len() {
        match words[i].text.as_str() {
            "--" => {
                patterns_from = Some(i + 1);
                break;
            }
            "-m" => {
                is_reg = words.get(i + 1).is_some_and(|m| m.text == "reg");
                i += 2;
            }
            "-f" | "-M" | "-u" => i += 2,
            f if f.len() > 1 && f.starts_with('-') && f[1..].chars().all(|c| c.is_ascii_alphabetic()) => i += 1,
            _ => {
                patterns_from = Some(i);
                break;
            }
        }
    }
    if let (true, Some(from)) = (is_reg, patterns_from) {
        for pattern in &words[from.min(words.len())..] {
            validate_regex_nocapture(pattern)?;
        }
    }
    Ok(())
}

/// The refusal for a word where `if`/`unless` (or the end of the line) should be, in a
/// `tcp-request` / `tcp-response` rule: `'tcp-request content accept' only accepts 'if' or
/// 'unless', in frontend 'f' (got 'x')` (`tcp_parse_tcp_req`, `src/tcp_rules.c`). The
/// parser does not know which proxy it is in: `@PROXY@` stands for `frontend 'f'`, and
/// [`in_proxy`] fills it in.
pub(crate) fn tcp_trailing_word(tokens: &[Token], found: &Token) -> ConfigError {
    let w = |i: usize| tokens.get(i).map_or("", |t| t.text.as_str());
    ConfigError::new(
        found.line,
        found.col,
        format!("'{} {} {}' only accepts 'if' or 'unless', in @PROXY@ (got '{}')", w(0), w(1), w(2), found.text),
    )
}

/// Say which proxy a `tcp-request` / `tcp-response` rule was in (`frontend 'f'`, `defaults
/// 'd'`...), where [`tcp_trailing_word`] left `@PROXY@`.
pub(crate) fn in_proxy(r: Result<(), ConfigError>, kind: &str, name: &str) -> Result<(), ConfigError> {
    r.map_err(|mut e| {
        if e.message.contains("@PROXY@") {
            e.message = e.message.replace("@PROXY@", &format!("{kind} '{name}'"));
        }
        e
    })
}

/// The condition of a `tcp-request` / `tcp-response` rule, which must start at `tokens[at]`:
/// the action's own arguments end there. Anything else is refused ([`tcp_trailing_word`]);
/// it is never skipped. Gives the index of the condition and the condition.
pub(crate) fn parse_rule_condition(
    tokens: &[Token],
    at: usize,
) -> Result<(Option<usize>, Option<AclCondition>), ConfigError> {
    match tokens.get(at) {
        None => Ok((None, None)),
        Some(t) if t.text == "if" || t.text == "unless" => Ok((Some(at), parse_acl_condition_from_tokens(&tokens[at..])?)),
        Some(t) => Err(tcp_trailing_word(tokens, t)),
    }
}

/// An action with one argument at `tokens[at]` (a sample expression, a format) and then the
/// condition: the argument is empty when the line ends or `if`/`unless` comes first, and a
/// second word is refused.
pub(crate) fn tcp_arg_and_cond(tokens: &[Token], at: usize) -> Result<(String, Option<AclCondition>), ConfigError> {
    let arg = tokens.get(at).filter(|t| t.text != "if" && t.text != "unless");
    let (_, cond) = parse_rule_condition(tokens, at + usize::from(arg.is_some()))?;
    Ok((arg.map_or_else(String::new, |t| t.text.clone()), cond))
}

/// Where the arguments of a rule end for the actions whose grammar is a list of keywords
/// (`return`, `deny`, `redirect`): the index of the first `if`/`unless` at or after `start`.
/// The caller then walks `start..` up to it and refuses every word it does not know; nothing
/// in between is skipped. An action with a fixed number of arguments does not use this: it
/// asks for the condition at the index its last argument ends at (`expect_cond_in`,
/// [`parse_rule_condition`]), so that a stray word is refused.
pub(crate) fn args_end(tokens: &[Token], start: usize) -> Option<usize> {
    for (idx, tok) in tokens.iter().enumerate().skip(start) {
        if tok.text == "if" || tok.text == "unless" {
            return Some(idx);
        }
    }
    None
}

pub(crate) fn join_tokens_until(tokens: &[Token], start: usize, cond_idx: Option<usize>) -> String {
    let limit = cond_idx.unwrap_or(tokens.len());
    tokens[start..limit]
        .iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}


/// One config word, as the sample-expression parser will split it back out of the joined
/// text: quoted, with `\\` and `\"` escaped, when it holds what that parser splits on or
/// decodes (blanks, quotes, a backslash). The lexer has already applied `parse_line`'s
/// escapes, so a pattern such as `"a b\r\n"` is these bytes and must stay one word.
pub(super) fn expr_word(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.is_empty() && !text.chars().any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\')) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    std::borrow::Cow::Owned(out)
}
