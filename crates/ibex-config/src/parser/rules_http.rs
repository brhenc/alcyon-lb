// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::{
    find_cond_idx, join_tokens_until, parse_acl_condition_from_tokens, parse_error_body_args,
    parse_rule_condition, parse_gpc_array_action, parse_sc_counter_action, parse_u16, ConfigError, ErrorPageSource,
    AclCondition, HttpAfterResAction, HttpAfterResRule, HttpReqAction, HttpReqRule, HttpResAction,
    HttpResRule, RedirectCookie, RedirectKind, RedirectRule, RetriesValue, Token,
};

/// The single sample expression at `tokens[2]` and the optional condition after it, as
/// `sample_parse_expr` then `parse_rule_cond` take them: a second word that is not
/// `if`/`unless` is refused, as is a word that cannot name a fetch.
fn parse_one_expr_and_cond(
    tokens: &[Token],
    act_token: &Token,
) -> Result<(String, Option<AclCondition>), ConfigError> {
    let act = &act_token.text;
    let Some(expr) = tokens.get(2).filter(|t| !matches!(t.text.as_str(), "" | "if" | "unless")) else {
        return Err(ConfigError::new(act_token.line, act_token.col, format!("<http-request {act}> missing fetch method")));
    };
    if !expr.text.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(ConfigError::new(expr.line, expr.col, format!("unknown fetch method '{}'", expr.text)));
    }
    Ok((expr.text.clone(), expect_cond_at(tokens, 3, act_token)?))
}

/// The optional `if`/`unless` condition starting at `tokens[at]`; any other word there is
/// refused, as `HAProxy` refuses it.
/// The `reason <text>` of `set-status <code> reason <text>` (`tokens[3]`, `tokens[4]`), as
/// `HAProxy`'s `parse_http_set_status` takes it: `reason` followed by anything but `if` or
/// `unless`. The text is literal (measured: `%[...]` is not expanded).
fn set_status_reason(tokens: &[Token], what: &str) -> Result<Option<String>, ConfigError> {
    let reason = match (tokens.get(3), tokens.get(4)) {
        (Some(k), Some(t)) if k.text == "reason" && t.text != "if" && t.text != "unless" => Some(t.text.clone()),
        _ => None,
    };
    // Whatever follows has to be the condition, or nothing (`HAProxy`: "expects either 'if'
    // or 'unless' followed by a condition but found ...").
    if let Some(t) = tokens.get(if reason.is_some() { 5 } else { 3 }) {
        if t.text != "if" && t.text != "unless" {
            return Err(ConfigError::new(
                t.line,
                t.col,
                format!("'{what} set-status' expects either 'if' or 'unless' followed by a condition but found '{}'.", t.text),
            ));
        }
    }
    Ok(reason)
}

fn expect_cond_at(tokens: &[Token], at: usize, act_token: &Token) -> Result<Option<AclCondition>, ConfigError> {
    match tokens.get(at) {
        None => Ok(None),
        Some(t) if t.text == "if" || t.text == "unless" => parse_acl_condition_from_tokens(&tokens[at..]),
        Some(t) => Err(ConfigError::new(
            t.line,
            t.col,
            format!(
                "'http-request {}' expects either 'if' or 'unless' followed by a condition but found '{}'",
                act_token.text, t.text
            ),
        )),
    }
}

/// The one argument at `tokens[2]` (a `set-var` expression, a `set-var-fmt` format) and
/// the optional condition after it: a second word that is not `if`/`unless` is refused,
/// as `HAProxy` refuses it. Ibex joined the words and set the variable to something else.
fn one_arg_and_cond(tokens: &[Token], kw: &str, act_token: &Token) -> Result<(String, Option<AclCondition>), ConfigError> {
    let arg = tokens.get(2).filter(|t| t.text != "if" && t.text != "unless").map_or_else(String::new, |t| t.text.clone());
    let at = if arg.is_empty() { 2 } else { 3 };
    match tokens.get(at) {
        None => Ok((arg, None)),
        Some(t) if t.text == "if" || t.text == "unless" => Ok((arg, parse_acl_condition_from_tokens(&tokens[at..])?)),
        Some(t) => Err(ConfigError::new(
            t.line,
            t.col,
            format!(
                "'{kw} {}' expects either 'if' or 'unless' followed by a condition but found '{}'.",
                act_token.text, t.text
            ),
        )),
    }
}

/// `strtol(s, &end, 0)` with `*end == '\0'`: decimal, `0x` hex or leading-`0` octal, with
/// an optional sign; `None` if anything is left over.
fn strtol0(s: &str) -> Option<i64> {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else if digits.len() > 1 && digits.starts_with('0') {
        i64::from_str_radix(&digits[1..], 8).ok()?
    } else {
        digits.parse::<i64>().ok()?
    };
    Some(if neg { -n } else { n })
}

/// A time in milliseconds as `parse_time_err(.., TIME_UNIT_MS)` reads it: digits, then
/// `us`, `ms`, `s`, `m`, `h` or `d` (none: milliseconds), `us` rounded up. The messages
/// are `HAProxy`'s.
pub(crate) fn parse_time_ms(text: &str) -> Result<u32, String> {
    const OVERFLOW: &str = "time overflow (maximum value is 2147483647 ms or ~24.8 days).";
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err(format!("unexpected character '{}'.", text.chars().next().unwrap_or('\0')));
    }
    let value: u128 = text[..digits].parse().unwrap_or(u128::MAX);
    let unit = &text[digits..];
    let (mul, div): (u128, u128) = match unit {
        "" | "ms" => (1, 1),
        "us" => (1, 1000),
        "s" => (1000, 1),
        "m" => (60_000, 1),
        "h" => (3_600_000, 1),
        "d" => (86_400_000, 1),
        other => return Err(format!("unexpected character '{}'.", other.chars().next().unwrap_or('\0'))),
    };
    let ms = value.saturating_mul(mul).saturating_add(div - 1) / div;
    u32::try_from(ms).ok().filter(|m| *m < 0x8000_0000).ok_or_else(|| OVERFLOW.to_string())
}

/// A size as `parse_size_err` reads it: digits, then an optional `k`, `m` or `g` (either
/// case), the result within 32 bits. An overflow names the character that overflowed.
fn parse_size_u32(text: &str) -> Result<u32, String> {
    if !text.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(format!("unexpected character '{}'.", text.chars().next().unwrap_or('\0')));
    }
    let mut value: u32 = 0;
    let mut chars = text.chars();
    let mut unit = None;
    for c in chars.by_ref() {
        let Some(d) = c.to_digit(10) else {
            unit = Some(c);
            break;
        };
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(d))
            .ok_or_else(|| format!("unexpected character '{c}'."))?;
    }
    let Some(unit) = unit else { return Ok(value) };
    let shift = match unit.to_ascii_lowercase() {
        'k' => 10,
        'm' => 20,
        'g' => 30,
        other => return Err(format!("unexpected character '{other}'.")),
    };
    if let Some(extra) = chars.next() {
        return Err(format!("unexpected character '{extra}'."));
    }
    value.checked_mul(1 << shift).ok_or_else(|| format!("unexpected character '{unit}'."))
}

/// `wait-for-body time <time> [ at-least <bytes> ] [ if|unless <cond> ]` for
/// `http-request` and `http-response` (`side`): the arguments come in either order and a
/// repeated one replaces the one before; `time` is required.
fn parse_wait_for_body(
    tokens: &[Token],
    side: &str,
    act_token: &Token,
) -> Result<(u32, u32, Option<AclCondition>), ConfigError> {
    let fail = |t: &Token, msg: String| ConfigError::new(t.line, t.col, msg);
    let mut time = None;
    let mut at_least = 0;
    let mut i = 2;
    while let Some(t) = tokens.get(i).filter(|t| matches!(t.text.as_str(), "time" | "at-least")) {
        let Some(arg) = tokens.get(i + 1).filter(|a| !a.text.is_empty()) else {
            return Err(fail(t, format!("missing argument for '{}'.", t.text)));
        };
        if t.text == "time" {
            time = Some(parse_time_ms(&arg.text).map_err(|m| fail(arg, m))?);
        } else {
            at_least = parse_size_u32(&arg.text).map_err(|m| fail(arg, m))?;
        }
        i += 2;
    }
    let Some(time) = time else {
        return Err(fail(act_token, "expects time <time> [ at-least <bytes> ].".to_string()));
    };
    let cond = match tokens.get(i) {
        None => None,
        Some(t) if t.text == "if" || t.text == "unless" => parse_acl_condition_from_tokens(&tokens[i..])?,
        Some(t) => {
            return Err(fail(
                t,
                format!(
                    "'{side} {}' expects either 'if' or 'unless' followed by a condition but found '{}'.",
                    act_token.text, t.text
                ),
            ));
        }
    };
    Ok((time, at_least, cond))
}

#[allow(clippy::too_many_lines)]
/// Parses one rule and gives what it pushed the line it was written on.
pub(crate) fn parse_http_req_rule(
    rules: &mut Vec<HttpReqRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let before = rules.len();
    let res = parse_http_req_rule_at(rules, tokens, kw);
    let line = u32::try_from(kw.line).unwrap_or(u32::MAX);
    for r in rules.iter_mut().skip(before) {
        r.line = line;
    }
    res
}

fn parse_http_req_rule_at(
    rules: &mut Vec<HttpReqRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-request> expects an action as argument.",
        ));
    }

    let act_token = &tokens[1];
    let act_str = act_token.text.as_str();

    if act_str == "track-sc0" || act_str == "track-sc1" || act_str == "track-sc2" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request track-sc*> expects sample expression.",
            ));
        }
        let expr = tokens[2].text.clone();
        let mut table = None;
        let mut cond_start = None;
        let mut i = 3;
        while i < tokens.len() {
            if tokens[i].text == "table" && i + 1 < tokens.len() {
                table = Some(tokens[i + 1].text.clone());
                i += 2;
            } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                cond_start = Some(i);
                break;
            } else {
                i += 1;
            }
        }
        let cond = if let Some(idx) = cond_start {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = match act_str {
            "track-sc1" => HttpReqAction::TrackSc1 { expr, table },
            "track-sc2" => HttpReqAction::TrackSc2 { expr, table },
            _ => HttpReqAction::TrackSc0 { expr, table },
        };
        rules.push(HttpReqRule { action, cond, line: 0 });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_token)? {
        let (_, cond) = parse_rule_condition(tokens, 2)?;
        rules.push(HttpReqRule { action: HttpReqAction::ScIncGpc0 { sc }, cond, line: 0 });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_token)? {
        let (_, cond) = parse_rule_condition(tokens, 2)?;
        rules.push(HttpReqRule { action: HttpReqAction::ScIncGpc1 { sc }, cond, line: 0 });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_token)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 2, cond_idx);
        // No value is 0, as `HAProxy` reads it (`strtol` stops at the end of the line).
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(HttpReqRule { action: HttpReqAction::ScSetGpt0 { sc, expr }, cond, line: 0 });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-inc-gpc", act_token)? {
        let (_, cond) = parse_rule_condition(tokens, 2)?;
        rules.push(HttpReqRule { action: HttpReqAction::ScIncGpc { idx, sc }, cond, line: 0 });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-add-gpc", act_token)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 2, cond_idx);
        // No value is 0: `strtol` reads nothing and the end of the line is what it stopped at.
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(HttpReqRule { action: HttpReqAction::ScAddGpc { idx, sc, expr }, cond, line: 0 });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-set-gpt", act_token)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 2, cond_idx);
        // No value is 0: `strtol` reads nothing and the end of the line is what it stopped at.
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(HttpReqRule { action: HttpReqAction::ScSetGpt { idx, sc, expr }, cond, line: 0 });
    } else if act_str == "return" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());

        // `errorfiles <name>` (if present) must pick a single status code out of a whole
        // section, so `status` is resolved first, in a pre-scan, exactly like HAProxy's own
        // two-pass argument parsing for this action.
        let mut status = 200u16;
        for i in 2..limit {
            if tokens[i].text == "status" && i + 1 < limit {
                status = parse_u16(&tokens[i + 1], "status")?;
                break;
            }
        }

        let (content_type, lf_string, error_page) = parse_error_body_args(tokens, 2, limit, status)?;

        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Return {
                status,
                content_type,
                lf_string,
                error_page,
            },
            cond,
            line: 0,
        });
    } else if act_str == "deny" || act_str == "tarpit" {
        // `tarpit` takes the arguments of `deny`; its default status is 500, not 403.
        let default_status = if act_str == "tarpit" { 500 } else { 403 };
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());

        // `deny_status` is only accepted as the first argument; `status` anywhere, the last
        // of either winning (`http_parse_http_reply`, measured). `status` is the status of a
        // reply built like `return`'s -- an empty one when nothing gives it a body -- while
        // `deny_status` picks the page the proxy has for the code.
        let mut deny_status = None;
        let mut status_keyword = false;
        for i in 2..limit {
            let word = tokens[i].text.as_str();
            if word == "deny_status" && i != 2 {
                return Err(ConfigError::new(
                    tokens[i].line,
                    tokens[i].col,
                    format!("'http-request {act_str}' expects either 'if' or 'unless' followed by a condition but found 'deny_status'"),
                ));
            }
            if (word == "status" || word == "deny_status") && i + 1 < limit {
                let code = parse_u16(&tokens[i + 1], "deny_status")?;
                if !(200..=599).contains(&code) {
                    return Err(ConfigError::new(tokens[i + 1].line, tokens[i + 1].col, format!("Unexpected status code '{code}'")));
                }
                deny_status = Some(code);
                status_keyword = word == "status";
            }
        }

        let (content_type, lf_string, mut error_page) =
            parse_error_body_args(tokens, 2, limit, deny_status.unwrap_or(default_status))?;

        // HAProxy: "for compatibility purposes, when no argument is defined, or only
        // 'deny_status', the argument 'default-errorfiles' is implied" -- i.e. a bare
        // `deny` (or one with only a `deny_status`) must still consult the proxy's
        // configured error page, not synthesize an empty body the way a bare `return`
        // does; with `status` it does synthesize one.
        if !status_keyword && error_page.is_none() && content_type.is_none() && lf_string.is_none() {
            super::error_pages::check_default_errorfiles(deny_status.unwrap_or(default_status), act_token)?;
            error_page = Some(ErrorPageSource::DefaultErrorfiles);
        }

        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: if act_str == "tarpit" {
                HttpReqAction::Tarpit { deny_status, content_type, lf_string, error_page }
            } else {
                HttpReqAction::Deny { deny_status, content_type, lf_string, error_page }
            },
            cond,
            line: 0,
        });
    } else if act_str == "allow" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Allow,
            cond,
            line: 0,
        });
    } else if act_str == "set-header" || act_str == "add-header" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-header|add-header> expects <name> and <fmt>.",
            ));
        }
        let name = tokens[2].text.clone();
        let fmt = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if act_str == "set-header" {
            HttpReqAction::SetHeader { name, fmt }
        } else {
            HttpReqAction::AddHeader { name, fmt }
        };
        rules.push(HttpReqRule { action, cond, line: 0 });
    } else if act_str == "del-header" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request del-header> expects <name>.",
            ));
        }
        let name = tokens[2].text.clone();
        let mut method = None;
        let mut i = 3;
        while i < tokens.len() {
            if tokens[i].text == "-m" && i + 1 < tokens.len() {
                method = Some(tokens[i + 1].text.clone());
                i += 2;
            } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                break;
            } else {
                i += 1;
            }
        }
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let encoded_name = match method.as_deref() {
            Some("str") | None => name,
            Some(m) => format!("\0m:{m}:{name}"),
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::DelHeader { name: encoded_name },
            cond,
            line: 0,
        });
    } else if act_str == "replace-header" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-header> expects <name>, <regex>, <replace>.",
            ));
        }
        // A regex that cannot be compiled would make the rule do nothing on every request;
        // HAProxy refuses one it cannot compile, and so does this.
        super::scalars::validate_regex(&tokens[3])?;
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplaceHeader { name, regex, repl },
            cond,
            line: 0,
        });
    } else if act_str == "replace-value" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-value> expects <name>, <regex>, <replace>.",
            ));
        }
        // A regex that cannot be compiled would make the rule do nothing on every request;
        // HAProxy refuses one it cannot compile, and so does this.
        super::scalars::validate_regex(&tokens[3])?;
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplaceValue { name, regex, repl },
            cond,
            line: 0,
        });
    } else if act_str == "set-path" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-path> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetPath { fmt },
            cond,
            line: 0,
        });
    } else if act_str == "replace-path" {
        let (regex, repl, cond) = parse_replace_uri(tokens, "replace-path")?;
        rules.push(HttpReqRule { action: HttpReqAction::ReplacePath { regex, repl }, cond, line: 0 });
    } else if act_str == "set-pathq" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-pathq> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetPathq { fmt },
            cond,
            line: 0,
        });
    } else if act_str == "replace-pathq" {
        let (regex, repl, cond) = parse_replace_uri(tokens, "replace-pathq")?;
        rules.push(HttpReqRule { action: HttpReqAction::ReplacePathq { regex, repl }, cond, line: 0 });
    } else if act_str == "replace-uri" {
        let (regex, repl, cond) = parse_replace_uri(tokens, "replace-uri")?;
        rules.push(HttpReqRule { action: HttpReqAction::ReplaceUri { regex, repl }, cond, line: 0 });
    } else if act_str == "set-query" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-query> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetQuery { fmt },
            cond,
            line: 0,
        });
    } else if act_str == "set-uri" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-uri> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetUri { fmt },
            cond,
            line: 0,
        });
    } else if act_str == "set-method" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-method> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetMethod { fmt },
            cond,
            line: 0,
        });
    } else if act_str == "set-src" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetSrc { expr },
            cond,
            line: 0,
        });
    } else if act_str == "set-dst" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetDst { expr },
            cond,
            line: 0,
        });
    } else if act_str == "set-src-port" {
        let (expr, cond) = parse_one_expr_and_cond(tokens, act_token)?;
        rules.push(HttpReqRule {
            action: HttpReqAction::SetSrcPort { expr },
            cond,
            line: 0,
        });
    } else if act_str == "set-priority-class" || act_str == "set-priority-offset" {
        let (expr, cond) = parse_one_expr_and_cond(tokens, act_token)?;
        let action = if act_str == "set-priority-class" {
            HttpReqAction::SetPriorityClass { expr }
        } else {
            HttpReqAction::SetPriorityOffset { expr }
        };
        rules.push(HttpReqRule { action, cond, line: 0 });
    } else if act_str == "set-dst-port" {
        let (expr, cond) = parse_one_expr_and_cond(tokens, act_token)?;
        rules.push(HttpReqRule {
            action: HttpReqAction::SetDstPort { expr },
            cond,
            line: 0,
        });
    } else if act_str == "set-retries" {
        // `stream_parse_set_retries` (src/stream.c): an integer as `strtol(.., 0)` reads
        // it, in 0..=100, else an expression. The section checks (no frontend, no
        // defaults) are where the section is known: `parse_frontend_section`,
        // `parse_defaults_section`.
        let Some(arg) = tokens.get(2).filter(|t| !matches!(t.text.as_str(), "" | "if" | "unless")) else {
            return Err(ConfigError::new(
                act_token.line,
                act_token.col,
                "<http-request set-retries> expects exactly 1 argument (an expression or an integer between 1 and 100)",
            ));
        };
        let value = match strtol0(&arg.text) {
            Some(n) if (0..=100).contains(&n) => RetriesValue::Fixed(u16::try_from(n).unwrap_or(0)),
            Some(_) => {
                return Err(ConfigError::new(
                    arg.line,
                    arg.col,
                    "<http-request set-retries> expects an expression or an integer between 1 and 100",
                ))
            }
            None => RetriesValue::Expr(parse_one_expr_and_cond(tokens, act_token)?.0),
        };
        let cond = expect_cond_at(tokens, 3, act_token)?;
        rules.push(HttpReqRule {
            action: HttpReqAction::SetRetries { value },
            cond,
            line: 0,
        });
    } else if act_str == "redirect" {
        let (rule, cond) = parse_req_redirect(tokens)?;
        rules.push(HttpReqRule { action: HttpReqAction::Redirect(rule), cond, line: 0 });
    } else if act_str == "strict-mode" {
        let on = tokens.get(2).is_none_or(|t| t.text == "on");
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::StrictMode { on },
            cond,
            line: 0,
        });
    } else if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let is_fmt = act_str.starts_with("set-var-fmt(");
        let var_name = act_token
            .text
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        super::check_set_var_conds(act_token, &var_name)?;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if is_fmt {
            HttpReqAction::SetVarFmt {
                var_name,
                fmt: expr,
            }
        } else {
            HttpReqAction::SetVar { var_name, expr }
        };
        rules.push(HttpReqRule { action, cond, line: 0 });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_token
            .text
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::UnsetVar { var_name },
            cond,
            line: 0,
        });
    } else if act_str == "normalize-uri" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request normalize-uri> expects a normalizer.",
            ));
        }
        let normalizer = tokens[2].text.clone();
        let mut full = false;
        let mut strict = false;
        let cond_idx = find_cond_idx(tokens, 3);
        let limit = cond_idx.unwrap_or(tokens.len());
        for tok in &tokens[3..limit] {
            if tok.text == "full" {
                full = true;
            } else if tok.text == "strict" {
                strict = true;
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::NormalizeUri {
                normalizer,
                full,
                strict,
            },
            cond,
            line: 0,
        });
    } else if act_str == "set-timeout" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-timeout> expects <type> and <value>.",
            ));
        }
        let timeout_type = tokens[2].text.clone();
        // `cfg_parse_rule_set_timeout` (src/action.c). Which side the proxy has is checked
        // by the caller, which knows the section ([`set_timeout_sides`]).
        if !matches!(timeout_type.as_str(), "client" | "connect" | "queue" | "server" | "tarpit" | "tunnel") {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!(
                    "error detected while parsing 'http-request set-timeout' rule : 'set-timeout' rule supports 'client'/'connect'/'queue'/'server'/'tarpit'/'tunnel' (got '{timeout_type}')."
                ),
            ));
        }
        let cond_idx = find_cond_idx(tokens, 3);
        let limit = cond_idx.unwrap_or(tokens.len());
        let timeout_val = tokens[3..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        if parse_time_ms(&timeout_val) == Ok(0) {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("error detected while parsing 'http-request set-timeout' rule : null value is not valid for a 'set-timeout {timeout_type}' rule."),
            ));
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetTimeout {
                timeout_type,
                timeout_val,
            },
            cond,
            line: 0,
        });
    } else if act_str == "auth" {
        // `parse_http_auth` (src/http_act.c): `auth [realm <realm>]`, then a condition.
        let (realm, at) = if tokens.get(2).is_some_and(|t| t.text == "realm") {
            match tokens.get(3) {
                Some(r) if !matches!(r.text.as_str(), "" | "if" | "unless") => (Some(r.text.clone()), 4),
                _ => {
                    return Err(ConfigError::new(
                        act_token.line,
                        act_token.col,
                        "error detected while parsing 'http-request auth' rule : missing realm value.",
                    ))
                }
            }
        } else {
            (None, 2)
        };
        let cond = expect_cond_at(tokens, at, act_token)?;
        rules.push(HttpReqRule {
            action: HttpReqAction::Auth { realm },
            cond,
            line: 0,
        });
    } else if act_str == "capture" {
        // `parse_http_req_capture`: `capture <sample> [ len <n> | id <idx> ]`, then nothing but
        // a condition. `len` is read by atoi(3), `id` by strtol with a full-string check.
        let refuse = |what: String| {
            ConfigError::new(act_token.line, act_token.col, format!("error detected while parsing 'http-request capture' rule : {what}"))
        };
        let word = |i: usize| tokens.get(i).map_or("", |t| t.text.as_str());
        let usage = "expects <expression> [ 'len' <length> | id <idx> ].";
        if word(2).is_empty() {
            return Err(refuse(usage.to_string()));
        }
        let mut len = None;
        let mut id = None;
        match word(3) {
            "len" if !word(4).is_empty() => {
                let t = word(4).trim_start();
                let (neg, digits) = t.strip_prefix('-').map_or((false, t.strip_prefix('+').unwrap_or(t)), |d| (true, d));
                let end = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
                let n = digits[..end].parse::<usize>().unwrap_or(if end == 0 { 0 } else { usize::MAX });
                if neg || n == 0 {
                    return Err(refuse("length must be > 0.".to_string()));
                }
                len = Some(n);
            }
            "id" if !word(4).is_empty() => match word(4).parse::<usize>() {
                Ok(n) if word(4).bytes().all(|c| c.is_ascii_digit()) => id = Some(n),
                _ => return Err(refuse(format!("cannot parse id '{}'.", word(4)))),
            },
            _ => return Err(refuse(usage.to_string())),
        }
        let cond = match tokens.get(5) {
            None => None,
            Some(t) if t.text == "if" || t.text == "unless" => parse_acl_condition_from_tokens(&tokens[5..])?,
            Some(t) => {
                return Err(ConfigError::new(
                    t.line,
                    t.col,
                    format!("'http-request capture' expects either 'if' or 'unless' followed by a condition but found '{}'.", t.text),
                ))
            }
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Capture { expr: tokens[2].text.clone(), len, id },
            cond,
            line: 0,
        });
    } else if act_str == "wait-for-body" {
        let (time, at_least, cond) = parse_wait_for_body(tokens, "http-request", act_token)?;
        rules.push(HttpReqRule { action: HttpReqAction::WaitForBody { time_ms: Some(time), at_least }, cond, line: 0 });
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-request action <{act_str}>"),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
/// Parses one rule and gives what it pushed the line it was written on.
pub(crate) fn parse_http_res_rule(
    rules: &mut Vec<HttpResRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let before = rules.len();
    let res = parse_http_res_rule_at(rules, tokens, kw);
    let line = u32::try_from(kw.line).unwrap_or(u32::MAX);
    for r in rules.iter_mut().skip(before) {
        r.line = line;
    }
    res
}

fn parse_http_res_rule_at(
    rules: &mut Vec<HttpResRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-response> expects an action as argument.",
        ));
    }
    let act_token = &tokens[1];
    let act_str = act_token.text.as_str();

    if act_str == "set-header" || act_str == "add-header" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response set-header|add-header> expects <name> and <fmt>.",
            ));
        }
        let name = tokens[2].text.clone();
        let fmt = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if act_str == "set-header" {
            HttpResAction::SetHeader { name, fmt }
        } else {
            HttpResAction::AddHeader { name, fmt }
        };
        rules.push(HttpResRule { action, cond, line: 0 });
    } else if act_str == "del-header" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response del-header> expects <name>.",
            ));
        }
        let name = tokens[2].text.clone();
        let mut method = None;
        let mut i = 3;
        while i < tokens.len() {
            if tokens[i].text == "-m" && i + 1 < tokens.len() {
                method = Some(tokens[i + 1].text.clone());
                i += 2;
            } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                break;
            } else {
                i += 1;
            }
        }
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let encoded_name = match method.as_deref() {
            Some("str") | None => name,
            Some(m) => format!("\0m:{m}:{name}"),
        };
        rules.push(HttpResRule {
            action: HttpResAction::DelHeader { name: encoded_name },
            cond,
            line: 0,
        });
    } else if act_str == "set-status" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response set-status> expects <status>.",
            ));
        }
        let status = parse_u16(&tokens[2], "set-status")?;
        let reason = set_status_reason(tokens, "http-response")?;
        let cond_idx = find_cond_idx(tokens, if reason.is_some() { 5 } else { 3 });
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetStatus { status, reason },
            cond,
            line: 0,
        });
    } else if act_str == "capture" {
        let (expr, id, cond) = parse_res_capture(tokens, act_token, "http-response")?;
        rules.push(HttpResRule { action: HttpResAction::Capture { expr, id }, cond, line: 0 });
    } else if act_str == "replace-header" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response replace-header> expects <name>, <regex>, <replace>.",
            ));
        }
        // A regex that cannot be compiled would make the rule do nothing on every
        // response; HAProxy refuses one it cannot compile, and so does this.
        super::scalars::validate_regex(&tokens[3])?;
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: format!("\0replace-header:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
            line: 0,
        });
    } else if act_str == "replace-value" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response replace-value> expects <name>, <regex>, <replace>.",
            ));
        }
        // A regex that cannot be compiled would make the rule do nothing on every
        // response; HAProxy refuses one it cannot compile, and so does this.
        super::scalars::validate_regex(&tokens[3])?;
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: format!("\0replace-value:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
            line: 0,
        });
    } else if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        // `set-var-fmt` takes a log-format string, `set-var` a sample expression; they are
        // told apart by the marker, or `set-var-fmt(txn.x) abc` would be evaluated as a
        // fetch named `abc`.
        let marker = if act_str.starts_with("set-var-fmt(") { "set-var-fmt" } else { "set-var" };
        let var_name = act_token
            .text
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        super::check_set_var_conds(act_token, &var_name)?;
        let (expr, cond) = one_arg_and_cond(tokens, "http-response", act_token)?;
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: format!("\0{marker}:{var_name}"),
                fmt: expr,
            },
            cond,
            line: 0,
        });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_token
            .text
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::DelHeader {
                name: format!("\0unset-var:{var_name}"),
            },
            cond,
            line: 0,
        });
    } else if act_str == "strict-mode" {
        let on = tokens.get(2).is_none_or(|t| t.text == "on");
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0strict-mode".to_string(),
                fmt: if on { "on".into() } else { "off".into() },
            },
            cond,
            line: 0,
        });
    } else if act_str == "allow" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0allow".to_string(),
                fmt: String::new(),
            },
            cond,
            line: 0,
        });
    } else if act_str == "deny" {
        // `parse_http_deny` (`src/http_act.c`): with nothing, or only `deny_status <code>`,
        // the reply is the proxy's page for the status (502 by default here) and the
        // status must have a built-in one; otherwise the words are an `http_reply`, here
        // only `status <code>`, and the reply is empty.
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let fmt = if limit == 2 {
            String::new()
        } else if tokens[2].text == "deny_status" && limit == 4 {
            let status = parse_u16(&tokens[3], "deny_status")?;
            super::error_pages::check_default_errorfiles(status, act_token)?;
            status.to_string()
        } else {
            let mut status = 502;
            let mut i = 2;
            while i < limit {
                if (tokens[i].text == "status" || (i == 2 && tokens[i].text == "deny_status")) && i + 1 < limit {
                    status = parse_u16(&tokens[i + 1], "status")?;
                    if !(200..=599).contains(&status) {
                        return Err(ConfigError::new(
                            tokens[i + 1].line,
                            tokens[i + 1].col,
                            format!("Unexpected status code '{status}'"),
                        ));
                    }
                    i += 2;
                } else {
                    // HAProxy also takes a body here (`content-type`, `string`, `hdr`,
                    // `errorfile`, ...). Ibex would drop it, so it is refused until it is
                    // implemented (AGENTS.md rule 5); an unknown word is refused by HAProxy
                    // too.
                    return Err(ConfigError::new(
                        tokens[i].line,
                        tokens[i].col,
                        format!(
                            "'http-response deny' takes only 'status <code>' in Ibex; '{}' is not supported",
                            tokens[i].text
                        ),
                    ));
                }
            }
            format!("{status}:empty")
        };
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0deny".to_string(),
                fmt,
            },
            cond,
            line: 0,
        });
    } else if act_str == "redirect" {
        let (action, cond) = parse_res_redirect(tokens)?;
        rules.push(HttpResRule { action, cond, line: 0 });
    } else if act_str == "wait-for-body" {
        let (time_ms, at_least, cond) = parse_wait_for_body(tokens, "http-response", act_token)?;
        rules.push(HttpResRule { action: HttpResAction::WaitForBody { time_ms, at_least }, cond, line: 0 });
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-response action <{act_str}>"),
        ));
    }
    Ok(())
}

/// `http-request replace-path|replace-pathq|replace-uri <match-regex> <replace-format>
/// [if|unless <cond>]` (`parse_replace_uri`, `src/http_act.c`): exactly two arguments, then
/// a condition or nothing; a regex that does not compile stops the load.
fn parse_replace_uri(tokens: &[Token], name: &str) -> Result<(String, String, Option<AclCondition>), ConfigError> {
    let kw = &tokens[1];
    let bad_count = tokens.len() < 4 || tokens.get(4).is_some_and(|t| t.text != "if" && t.text != "unless");
    if bad_count {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("error detected while parsing 'http-request {name}' rule : expects exactly 2 arguments <match-regex> and <replace-format>."),
        ));
    }
    if let Err(e) = ibex_regex::UserRegex::new(&tokens[2].text) {
        return Err(ConfigError::new(
            tokens[2].line,
            tokens[2].col,
            format!("error detected while parsing 'http-request {name}' rule : failed to parse the regex : regex '{}' is invalid ({e}).", tokens[2].text),
        ));
    }
    let cond = find_cond_idx(tokens, 4).map(|idx| parse_acl_condition_from_tokens(&tokens[idx..])).transpose()?.flatten();
    Ok((tokens[2].text.clone(), tokens[3].text.clone(), cond))
}

/// `http-request redirect location|prefix|scheme <fmt> [code <c>] [set-cookie <c> |
/// set-cookie-fmt <f> | clear-cookie <n>] [drop-query | keep-query] [append-slash]
/// [ignore-empty] [if|unless <cond>]` (`http_parse_redirect_rule`, `src/http_act.c`). The
/// last type on the line stands, as does the last cookie option.
fn parse_req_redirect(tokens: &[Token]) -> Result<(RedirectRule, Option<AclCondition>), ConfigError> {
    let cond_idx = find_cond_idx(tokens, 2);
    let limit = cond_idx.unwrap_or(tokens.len());
    let mut rule = RedirectRule {
        kind: RedirectKind::Location,
        target: String::new(),
        code: 302,
        cookie: None,
        drop_query: false,
        keep_query: false,
        append_slash: false,
        ignore_empty: false,
    };
    let mut have_kind = false;
    let mut i = 2;
    while i < limit {
        let t = &tokens[i];
        let word = t.text.as_str();
        let arg = || {
            tokens
                .get(i + 1)
                .filter(|_| i + 1 < limit)
                .ok_or_else(|| ConfigError::new(t.line, t.col, format!("missing argument for '{word}'.")))
        };
        match word {
            "location" | "prefix" | "scheme" => {
                rule.target.clone_from(&arg()?.text);
                rule.kind = match word {
                    "location" => RedirectKind::Location,
                    "prefix" => RedirectKind::Prefix,
                    _ => RedirectKind::Scheme,
                };
                have_kind = true;
                i += 2;
            }
            "code" => {
                let a = arg()?;
                rule.code = match a.text.parse::<u16>() {
                    Ok(c @ (301 | 302 | 303 | 307 | 308)) => c,
                    _ => {
                        return Err(ConfigError::new(
                            a.line,
                            a.col,
                            format!("'code': unsupported HTTP code '{}' (must be one of 301, 302, 303, 307 or 308).", a.text),
                        ))
                    }
                };
                i += 2;
            }
            "set-cookie" => {
                rule.cookie = Some(RedirectCookie::Set(arg()?.text.clone()));
                i += 2;
            }
            "set-cookie-fmt" => {
                rule.cookie = Some(RedirectCookie::SetFmt(arg()?.text.clone()));
                i += 2;
            }
            "clear-cookie" => {
                rule.cookie = Some(RedirectCookie::Clear(arg()?.text.clone()));
                i += 2;
            }
            "drop-query" => {
                rule.drop_query = true;
                i += 1;
            }
            "keep-query" => {
                rule.keep_query = true;
                i += 1;
            }
            "append-slash" => {
                rule.append_slash = true;
                i += 1;
            }
            "ignore-empty" => {
                rule.ignore_empty = true;
                i += 1;
            }
            _ => {
                return Err(ConfigError::new(
                    t.line,
                    t.col,
                    format!(
                        "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was '{word}')."
                    ),
                ))
            }
        }
    }
    if !have_kind {
        let at = tokens.get(1).unwrap_or(&tokens[0]);
        return Err(ConfigError::new(at.line, at.col, "redirection type expected ('prefix', 'location', or 'scheme')."));
    }
    let cond = cond_idx.map(|idx| parse_acl_condition_from_tokens(&tokens[idx..])).transpose()?.flatten();
    Ok((rule, cond))
}

/// `http-response redirect location <fmt> [code <c>] [set-cookie <c> | clear-cookie <n>]
/// [drop-query | keep-query | append-slash] [if|unless <cond>]` (`http_parse_redirect_rule`,
/// `src/http_act.c`). A response only takes the `location` type; the options that shape a
/// `prefix` or `scheme` redirect do nothing to a location, so they are accepted and not
/// kept. `ignore-empty` is not done by Ibex, and is refused.
fn parse_res_redirect(tokens: &[Token]) -> Result<(HttpResAction, Option<AclCondition>), ConfigError> {
    #[derive(PartialEq)]
    enum Kind {
        Location,
        Other,
    }
    let cond_idx = find_cond_idx(tokens, 2);
    let limit = cond_idx.unwrap_or(tokens.len());
    let (mut kind, mut location, mut code, mut cookie) = (None, String::new(), 302, None);
    let mut i = 2;
    while i < limit {
        let t = &tokens[i];
        let word = t.text.as_str();
        let arg = |word: &str| {
            tokens
                .get(i + 1)
                .filter(|_| i + 1 < limit)
                .ok_or_else(|| ConfigError::new(t.line, t.col, format!("missing argument for '{word}'.")))
        };
        match word {
            "location" => {
                location.clone_from(&arg(word)?.text);
                kind = Some(Kind::Location);
                i += 2;
            }
            "prefix" | "scheme" => {
                arg(word)?;
                kind = Some(Kind::Other);
                i += 2;
            }
            "code" => {
                let a = arg(word)?;
                code = match a.text.parse::<u16>() {
                    Ok(c @ (301 | 302 | 303 | 307 | 308)) => c,
                    _ => {
                        return Err(ConfigError::new(
                            a.line,
                            a.col,
                            format!("'code': unsupported HTTP code '{}' (must be one of 301, 302, 303, 307 or 308).", a.text),
                        ))
                    }
                };
                i += 2;
            }
            "set-cookie" => {
                cookie = Some(RedirectCookie::Set(arg(word)?.text.clone()));
                i += 2;
            }
            "clear-cookie" => {
                cookie = Some(RedirectCookie::Clear(arg(word)?.text.clone()));
                i += 2;
            }
            "set-cookie-fmt" => {
                cookie = Some(RedirectCookie::SetFmt(arg(word)?.text.clone()));
                i += 2;
            }
            "ignore-empty" => {
                return Err(ConfigError::new(t.line, t.col, format!("'http-response redirect {word}' is not implemented.")));
            }
            "drop-query" | "keep-query" | "append-slash" => i += 1,
            _ => {
                return Err(ConfigError::new(
                    t.line,
                    t.col,
                    format!(
                        "expects 'code', 'prefix', 'location', 'scheme', 'set-cookie', 'set-cookie-fmt', 'clear-cookie', 'drop-query', 'keep-query', 'ignore-empty' or 'append-slash' (was '{word}')."
                    ),
                ))
            }
        }
    }
    let at = tokens.get(1).unwrap_or(&tokens[0]);
    match kind {
        None => Err(ConfigError::new(at.line, at.col, "redirection type expected ('prefix', 'location', or 'scheme').")),
        Some(Kind::Other) => Err(ConfigError::new(at.line, at.col, "response only supports redirect type 'location'.")),
        Some(Kind::Location) => {
            let cond = cond_idx.map(|idx| parse_acl_condition_from_tokens(&tokens[idx..])).transpose()?.flatten();
            Ok((HttpResAction::Redirect { location, code, cookie }, cond))
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_http_after_res_rule(
    rules: &mut Vec<HttpAfterResRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-after-response> expects an action as argument.",
        ));
    }
    let act_token = &tokens[1];
    let act_str = act_token.text.as_str();

    if act_str == "set-header" || act_str == "add-header" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response set-header|add-header> expects <name> and <fmt>.",
            ));
        }
        let name = tokens[2].text.clone();
        let fmt = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if act_str == "set-header" {
            HttpAfterResAction::SetHeader { name, fmt }
        } else {
            HttpAfterResAction::AddHeader { name, fmt }
        };
        rules.push(HttpAfterResRule { action, cond });
    } else if act_str == "del-header" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response del-header> expects <name>.",
            ));
        }
        let name = tokens[2].text.clone();
        let mut method = None;
        let mut i = 3;
        while i < tokens.len() {
            if tokens[i].text == "-m" && i + 1 < tokens.len() {
                method = Some(tokens[i + 1].text.clone());
                i += 2;
            } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                break;
            } else {
                i += 1;
            }
        }
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let encoded_name = match method.as_deref() {
            Some("str") | None => name,
            Some(m) => format!("\0m:{m}:{name}"),
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::DelHeader { name: encoded_name },
            cond,
        });
    } else if act_str == "set-status" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response set-status> expects <status>.",
            ));
        }
        let status = parse_u16(&tokens[2], "set-status")?;
        let reason = set_status_reason(tokens, "http-after-response")?;
        let cond_idx = find_cond_idx(tokens, if reason.is_some() { 5 } else { 3 });
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0set-status".to_string(),
                // Read back by `res_action` (`engine.rs`): `<code>` or `<code>\0<reason>`.
                fmt: match reason {
                    Some(r) => format!("{status}\0{r}"),
                    None => status.to_string(),
                },
            },
            cond,
        });
    } else if act_str == "replace-header" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response replace-header> expects <name>, <regex>, <replace>.",
            ));
        }
        // A regex that cannot be compiled would make the rule do nothing on every
        // response; HAProxy refuses one it cannot compile, and so does this.
        super::scalars::validate_regex(&tokens[3])?;
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: format!("\0replace-header:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
        });
    } else if act_str == "replace-value" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response replace-value> expects <name>, <regex>, <replace>.",
            ));
        }
        // A regex that cannot be compiled would make the rule do nothing on every
        // response; HAProxy refuses one it cannot compile, and so does this.
        super::scalars::validate_regex(&tokens[3])?;
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: format!("\0replace-value:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
        });
    } else if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        // `set-var-fmt` takes a log-format string, `set-var` a sample expression; they are
        // told apart by the marker, or `set-var-fmt(txn.x) abc` would be evaluated as a
        // fetch named `abc`.
        let marker = if act_str.starts_with("set-var-fmt(") { "set-var-fmt" } else { "set-var" };
        let var_name = act_token
            .text
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        super::check_set_var_conds(act_token, &var_name)?;
        let (expr, cond) = one_arg_and_cond(tokens, "http-after-response", act_token)?;
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: format!("\0{marker}:{var_name}"),
                fmt: expr,
            },
            cond,
        });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_token
            .text
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::DelHeader {
                name: format!("\0unset-var:{var_name}"),
            },
            cond,
        });
    } else if act_str == "strict-mode" {
        let on = tokens.get(2).is_none_or(|t| t.text == "on");
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0strict-mode".to_string(),
                fmt: if on { "on".into() } else { "off".into() },
            },
            cond,
        });
    } else if act_str == "allow" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0allow".to_string(),
                fmt: String::new(),
            },
            cond,
        });
    } else if act_str == "capture" {
        let (expr, id, cond) = parse_res_capture(tokens, act_token, "http-after-response")?;
        rules.push(HttpAfterResRule { action: HttpAfterResAction::Capture { expr, id }, cond });
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-after-response action <{act_str}>"),
        ));
    }
    Ok(())
}


/// `cfg_parse_rule_set_timeout`: a `set-timeout` of the server side (`server`, `connect`,
/// `queue`, `tunnel`) needs a proxy with a backend, one of the client side a proxy with a
/// frontend. Run on the rule `parse_http_req_rule` has just added to `rules`.
pub(crate) fn set_timeout_sides(rules: &[HttpReqRule], kw: &Token, name: &str, has_fe: bool, has_be: bool) -> Result<(), ConfigError> {
    let Some(HttpReqRule { action: HttpReqAction::SetTimeout { timeout_type, .. }, .. }) = rules.last() else {
        return Ok(());
    };
    let missing = match timeout_type.as_str() {
        "server" | "connect" | "queue" | "tunnel" if !has_be => "backend",
        "client" if !has_fe => "frontend",
        _ => return Ok(()),
    };
    Err(ConfigError::new(
        kw.line,
        kw.col,
        format!("error detected while parsing 'http-request set-timeout' rule : '{name}' has no {missing} capability."),
    ))
}

/// HAProxy words a rule's parse error "error detected in <kind> '<name>' while parsing ...";
/// the rule parsers do not know the section, so the caller names it here.
pub(crate) fn in_section(r: Result<(), ConfigError>, kind: &str, name: &str) -> Result<(), ConfigError> {
    r.map_err(|mut e| {
        if let Some(rest) = e.message.strip_prefix("error detected while parsing") {
            e.message = format!("error detected in {kind} '{name}' while parsing{rest}");
        }
        e
    })
}

/// `parse_http_res_capture` / `parse_http_after_res_capture`: `capture <sample> id <idx>`,
/// and nothing but a condition after it -- unlike `http-request capture` there is no `len`,
/// the slot has one. `rule` is the keyword the rule was written under.
fn parse_res_capture(
    tokens: &[Token],
    act_token: &Token,
    rule: &str,
) -> Result<(String, usize, Option<AclCondition>), ConfigError> {
    let refuse = |at: &Token, what: String| {
        ConfigError::new(at.line, at.col, format!("error detected while parsing '{rule} capture' rule : {what}"))
    };
    let word = |i: usize| tokens.get(i).map_or("", |t| t.text.as_str());
    if word(2).is_empty() || word(3).is_empty() {
        return Err(refuse(act_token, "expects <expression> id <idx>.".to_string()));
    }
    if word(3) != "id" {
        return Err(refuse(act_token, format!("expects 'id', found '{}'.", word(3))));
    }
    if word(4).is_empty() {
        return Err(refuse(act_token, "expects <expression> id <idx>.".to_string()));
    }
    let Ok(id) = word(4).parse::<usize>() else {
        return Err(refuse(act_token, format!("cannot parse id '{}'.", word(4))));
    };
    let cond = match tokens.get(5) {
        None => None,
        Some(t) if t.text == "if" || t.text == "unless" => parse_acl_condition_from_tokens(&tokens[5..])?,
        Some(t) => {
            return Err(ConfigError::new(
                t.line,
                t.col,
                format!("'{rule} capture' expects either 'if' or 'unless' followed by a condition but found '{}'.", t.text),
            ))
        }
    };
    Ok((tokens[2].text.clone(), id, cond))
}
