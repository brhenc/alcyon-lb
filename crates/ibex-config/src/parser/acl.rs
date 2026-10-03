// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

pub(crate) fn parse_acl(acls: &mut Vec<AclRule>, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<acl> expects <name> and <expression> as arguments.",
        ));
    }
    let name = tokens[1].text.clone();
    let expr_tokens: Vec<&str> = tokens[2..].iter().map(|t| t.text.as_str()).collect();
    let expr = expr_tokens.join(" ");
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
            let mut brace_tokens = vec!["{"];
            i += 1;
            while i < tokens.len() && tokens[i].text != "}" {
                brace_tokens.push(tokens[i].text.as_str());
                i += 1;
            }
            if i == tokens.len() {
                return Err(ConfigError::new(open.line, open.col, "missing closing '}' in condition"));
            }
            brace_tokens.push("}");
            i += 1;
            terms.push(AclTerm { negated: bang, name: brace_tokens.join(" ") });
        } else if text.starts_with('{') {
            // `HAProxy` reads a brace only as a word of its own.
            return Err(ConfigError::new(tok.line, tok.col, format!("unknown ACL or sample keyword '{text}'")));
        } else {
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

pub(crate) fn parse_rule_condition(
    tokens: &[Token],
    start: usize,
) -> Result<(Option<usize>, Option<AclCondition>), ConfigError> {
    let cond_idx = find_cond_idx(tokens, start);
    let cond = match cond_idx {
        Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
        None => None,
    };
    Ok((cond_idx, cond))
}

pub(crate) fn find_cond_idx(tokens: &[Token], start: usize) -> Option<usize> {
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

