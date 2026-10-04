// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::{
    find_cond_idx, join_tokens_until, parse_acl_condition_from_tokens, parse_error_body_args,
    parse_rule_condition, parse_sc_counter_action, parse_u16, ConfigError, ErrorPageSource,
    AclCondition, HttpAfterResAction, HttpAfterResRule, HttpReqAction, HttpReqRule, HttpResAction,
    HttpResRule, RetriesValue, Token,
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
fn parse_time_ms(text: &str) -> Result<u32, String> {
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
pub(crate) fn parse_http_req_rule(
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
        rules.push(HttpReqRule { action, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_token)? {
        let (_, cond) = parse_rule_condition(tokens, 2)?;
        rules.push(HttpReqRule { action: HttpReqAction::ScIncGpc0 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_token)? {
        let (_, cond) = parse_rule_condition(tokens, 2)?;
        rules.push(HttpReqRule { action: HttpReqAction::ScIncGpc1 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_token)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 2, cond_idx);
        if expr.is_empty() {
            return Err(ConfigError::new(
                act_token.line,
                act_token.col,
                "<http-request sc-set-gpt0> expects value or expression",
            ));
        }
        rules.push(HttpReqRule { action: HttpReqAction::ScSetGpt0 { sc, expr }, cond });
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
        });
    } else if act_str == "deny" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());

        let mut deny_status = None;
        for i in 2..limit {
            if (tokens[i].text == "status" || tokens[i].text == "deny_status") && i + 1 < limit {
                deny_status = Some(parse_u16(&tokens[i + 1], "deny_status")?);
                break;
            }
        }

        let (content_type, lf_string, mut error_page) =
            parse_error_body_args(tokens, 2, limit, deny_status.unwrap_or(403))?;

        // HAProxy: "for compatibility purposes, when no argument is defined, or only
        // 'deny_status', the argument 'default-errorfiles' is implied" -- i.e. a bare
        // `deny` (or one with only a status) must still consult the proxy's configured
        // error page, not synthesize an empty body the way a bare `return` does.
        if error_page.is_none() && content_type.is_none() && lf_string.is_none() {
            super::error_pages::check_default_errorfiles(deny_status.unwrap_or(403), act_token)?;
            error_page = Some(ErrorPageSource::DefaultErrorfiles);
        }

        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Deny {
                deny_status,
                content_type,
                lf_string,
                error_page,
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
        rules.push(HttpReqRule {
            action: HttpReqAction::Allow,
            cond,
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
        rules.push(HttpReqRule { action, cond });
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
        });
    } else if act_str == "replace-header" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-header> expects <name>, <regex>, <replace>.",
            ));
        }
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
        });
    } else if act_str == "replace-value" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-value> expects <name>, <regex>, <replace>.",
            ));
        }
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
        });
    } else if act_str == "replace-path" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-path> expects <regex> and <replace>.",
            ));
        }
        let regex = tokens[2].text.clone();
        let repl = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplacePath { regex, repl },
            cond,
        });
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
        });
    } else if act_str == "replace-pathq" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-pathq> expects <regex> and <replace>.",
            ));
        }
        let regex = tokens[2].text.clone();
        let repl = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplacePathq { regex, repl },
            cond,
        });
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
        });
    } else if act_str == "set-dst-port" {
        let (expr, cond) = parse_one_expr_and_cond(tokens, act_token)?;
        rules.push(HttpReqRule {
            action: HttpReqAction::SetDstPort { expr },
            cond,
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
        });
    } else if act_str == "redirect" {
        let mut location = None;
        let mut scheme = None;
        let mut prefix = None;
        let mut code = None;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            match tokens[i].text.as_str() {
                "location" if i + 1 < limit => {
                    location = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "scheme" if i + 1 < limit => {
                    scheme = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "prefix" if i + 1 < limit => {
                    prefix = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "code" if i + 1 < limit => {
                    code = Some(parse_u16(&tokens[i + 1], "code")?);
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Redirect {
                location,
                scheme,
                prefix,
                code,
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
        rules.push(HttpReqRule {
            action: HttpReqAction::StrictMode { on },
            cond,
        });
    } else if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let is_fmt = act_str.starts_with("set-var-fmt(");
        let var_name = act_token
            .text
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
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
        rules.push(HttpReqRule { action, cond });
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
        let cond_idx = find_cond_idx(tokens, 3);
        let limit = cond_idx.unwrap_or(tokens.len());
        let timeout_val = tokens[3..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
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
        });
    } else if act_str == "auth" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Auth,
            cond,
        });
    } else if act_str == "capture" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = if limit > 2 { tokens[2].text.clone() } else { String::new() };
        let mut len = None;
        let mut id = None;
        let mut i = 3;
        while i < limit {
            if tokens[i].text == "len" && i + 1 < limit {
                len = Some(tokens[i + 1].text.parse::<usize>().unwrap_or(64));
                i += 2;
            } else if tokens[i].text == "id" && i + 1 < limit {
                id = Some(tokens[i + 1].text.parse::<usize>().unwrap_or(0));
                i += 2;
            } else {
                i += 1;
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Capture { expr, len, id },
            cond,
        });
    } else if act_str == "wait-for-body" {
        let (time, at_least, cond) = parse_wait_for_body(tokens, "http-request", act_token)?;
        rules.push(HttpReqRule { action: HttpReqAction::WaitForBody { time_ms: Some(time), at_least }, cond });
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
pub(crate) fn parse_http_res_rule(
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
        rules.push(HttpResRule { action, cond });
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
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetStatus { status },
            cond,
        });
    } else if act_str == "capture" {
        // `parse_http_res_capture`: `capture <sample> id <idx>`, and nothing but a condition
        // after it -- unlike `http-request capture` there is no `len`, the slot has one.
        let refuse = |at: &Token, what: String| {
            ConfigError::new(at.line, at.col, format!("error detected while parsing 'http-response capture' rule : {what}"))
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
                    format!("'http-response capture' expects either 'if' or 'unless' followed by a condition but found '{}'.", t.text),
                ))
            }
        };
        rules.push(HttpResRule { action: HttpResAction::Capture { expr: tokens[2].text.clone(), id }, cond });
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
        let (expr, cond) = one_arg_and_cond(tokens, "http-response", act_token)?;
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
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
        rules.push(HttpResRule {
            action: HttpResAction::DelHeader {
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
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
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
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0allow".to_string(),
                fmt: String::new(),
            },
            cond,
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
        });
    } else if act_str == "wait-for-body" {
        let (time_ms, at_least, cond) = parse_wait_for_body(tokens, "http-response", act_token)?;
        rules.push(HttpResRule { action: HttpResAction::WaitForBody { time_ms, at_least }, cond });
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-response action <{act_str}>"),
        ));
    }
    Ok(())
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
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0set-status".to_string(),
                fmt: status.to_string(),
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
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-after-response action <{act_str}>"),
        ));
    }
    Ok(())
}

