// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

pub(crate) fn parse_tcp_req_connection(
    rules: &mut Vec<TcpReqConnRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<tcp-request connection> expects <action>",
        ));
    }
    let act_tok = &tokens[2];
    match act_tok.text.as_str() {
        "track-sc0" | "track-sc1" | "track-sc2" => {
            let (expr, table, cond_start) = parse_track_sc_args(tokens, 3, &|t| tcp_trailing_word(tokens, t))?;
            let cond = match cond_start {
                Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
                None => None,
            };
            let action = match act_tok.text.as_str() {
                "track-sc1" => TcpReqConnAction::TrackSc1 { expr, table },
                "track-sc2" => TcpReqConnAction::TrackSc2 { expr, table },
                _ => TcpReqConnAction::TrackSc0 { expr, table },
            };
            rules.push(TcpReqConnRule { action, cond });
        }
        "silent-drop" => {
            let ttl = parse_rst_ttl(tokens, 3)?;
            let (_, cond) = parse_rule_condition(tokens, ttl.map_or(3, |t| t.1))?;
            let action = ttl.map_or(TcpReqConnAction::SilentDrop, |t| TcpReqConnAction::SilentDropTtl(t.0));
            rules.push(TcpReqConnRule { action, cond });
        }
        "reject" => {
            let (_, cond) = parse_rule_condition(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::Reject, cond });
        }
        "accept" => {
            let (_, cond) = parse_rule_condition(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::Accept, cond });
        }
        "set-src" => {
            let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SetSrc { expr }, cond });
        }
        "set-src-port" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                if expr.is_empty() {
                    return Err(ConfigError::new(act_tok.line, act_tok.col, "missing fetch method"));
                }
                rules.push(TcpReqConnRule { action: TcpReqConnAction::SetSrcPort { expr }, cond });
            }
            "set-dst-port" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                if expr.is_empty() {
                    return Err(ConfigError::new(act_tok.line, act_tok.col, "missing fetch method"));
                }
                rules.push(TcpReqConnRule { action: TcpReqConnAction::SetDstPort { expr }, cond });
            }
            "set-dst" => {
            let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SetDst { expr }, cond });
        }
        "expect-proxy" => {
            // HAProxy: only `layer4`, then `if`/`unless` or nothing.
            let arg = tokens.get(3).map_or("", |t| t.text.as_str());
            if arg != "layer4" {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    format!("'tcp-request connection expect-proxy' only supports 'layer4' (got '{arg}')"),
                ));
            }
            let (_, cond) = parse_rule_condition(tokens, 4)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::ExpectProxy, cond });
        }
        "do-log" => {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                "action do-log is not supported in this build",
            ));
        }
        other => {
            if other.starts_with("lua.") {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    format!("lua actions require Lua support, which this build does not have: <{other}>"),
                ));
            }
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("unknown tcp-request connection action <{other}>"),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_tcp_req_session(
    rules: &mut Vec<TcpReqSessionRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<tcp-request session> expects <action>",
        ));
    }
    let act_tok = &tokens[2];
    let act_str = &act_tok.text;
    if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let is_fmt = act_str.starts_with("set-var-fmt(");
        let var_name = act_str
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        check_set_var_conds(&tokens[2], &var_name)?;
        let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
        let action = if is_fmt {
            TcpReqSessionAction::SetVarFmt { var_name, fmt: expr }
        } else {
            TcpReqSessionAction::SetVar { var_name, expr }
        };
        rules.push(TcpReqSessionRule { action, cond });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_str
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::UnsetVar { var_name }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScIncGpc0 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScIncGpc1 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_tok)? {
        let (expr, cond) = sc_value_and_cond(tokens)?;
        // No value is 0, as `HAProxy` reads it (`strtol` stops at the end of the line).
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScSetGpt0 { sc, expr }, cond });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-inc-gpc", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScIncGpc { idx, sc }, cond });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-add-gpc", act_tok)? {
        let (expr, cond) = sc_value_and_cond(tokens)?;
        // No value is 0: `strtol` reads nothing and the end of the line is what it stopped at.
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScAddGpc { idx, sc, expr }, cond });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-set-gpt", act_tok)? {
        let (expr, cond) = sc_value_and_cond(tokens)?;
        // No value is 0: `strtol` reads nothing and the end of the line is what it stopped at.
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScSetGpt { idx, sc, expr }, cond });
    } else {
        match act_str.as_str() {
            "track-sc0" | "track-sc1" | "track-sc2" => {
                let (expr, table, cond_start) = parse_track_sc_args(tokens, 3, &|t| tcp_trailing_word(tokens, t))?;
                let cond = match cond_start {
                    Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
                    None => None,
                };
                let action = match act_str.as_str() {
                    "track-sc1" => TcpReqSessionAction::TrackSc1 { expr, table },
                    "track-sc2" => TcpReqSessionAction::TrackSc2 { expr, table },
                    _ => TcpReqSessionAction::TrackSc0 { expr, table },
                };
                rules.push(TcpReqSessionRule { action, cond });
            }
            "silent-drop" => {
                let ttl = parse_rst_ttl(tokens, 3)?;
                let (_, cond) = parse_rule_condition(tokens, ttl.map_or(3, |t| t.1))?;
                let action = ttl.map_or(TcpReqSessionAction::SilentDrop, |t| TcpReqSessionAction::SilentDropTtl(t.0));
                rules.push(TcpReqSessionRule { action, cond });
            }
            "reject" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::Reject, cond });
            }
            "accept" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::Accept, cond });
            }
            "set-src" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetSrc { expr }, cond });
            }
            "set-src-port" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                if expr.is_empty() {
                    return Err(ConfigError::new(act_tok.line, act_tok.col, "missing fetch method"));
                }
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetSrcPort { expr }, cond });
            }
            "set-dst-port" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                if expr.is_empty() {
                    return Err(ConfigError::new(act_tok.line, act_tok.col, "missing fetch method"));
                }
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetDstPort { expr }, cond });
            }
            "set-dst" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetDst { expr }, cond });
            }
            "expect-proxy" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "'expect-proxy layer4' is not allowed in 'tcp-request session' rules",
                ));
            }
            "attach-srv" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action attach-srv is not supported in this build",
                ));
            }
            "do-log" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action do-log is not supported in this build",
                ));
            }
            other => {
                if other.starts_with("lua.") {
                    return Err(ConfigError::new(
                        act_tok.line,
                        act_tok.col,
                        format!("lua actions require Lua support, which this build does not have: <{other}>"),
                    ));
                }
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    format!("unknown tcp-request session action <{other}>"),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_tcp_content_var(
    tokens: &[Token],
    act_str: &str,
) -> Result<Option<TcpReqContentRule>, ConfigError> {
    if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let is_fmt = act_str.starts_with("set-var-fmt(");
        let var_name = act_str
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        check_set_var_conds(&tokens[2], &var_name)?;
        let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
        let action = if is_fmt {
            TcpReqContentAction::SetVarFmt { var_name, fmt: expr }
        } else {
            TcpReqContentAction::SetVar { var_name, expr }
        };
        Ok(Some(TcpReqContentRule { action, cond, line: 0 }))
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_str
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        Ok(Some(TcpReqContentRule {
            action: TcpReqContentAction::UnsetVar { var_name },
            cond,
            line: 0,
        }))
    } else {
        Ok(None)
    }
}

pub(crate) fn parse_tcp_content_switch_mode(
    tokens: &[Token],
) -> Result<TcpReqContentRule, ConfigError> {
    let mut proto = None;
    // `switch-mode http [proto <name>]`, then the condition.
    let mut at = 4;
    if let Some(name) = tokens.get(5).filter(|_| tokens.get(4).is_some_and(|t| t.text == "proto")) {
        proto = Some(name.text.clone());
        at = 6;
    }
    let (_, cond) = parse_rule_condition(tokens, at)?;
    Ok(TcpReqContentRule {
        action: TcpReqContentAction::SwitchModeHttp { proto },
        cond,
        line: 0,
    })
}

/// `tcp-response content <action>`: the request-side grammar, kept only for the actions
/// the response side runs (`eval_tcp_res_content_rules` in ibex-rt). `HAProxy` takes a
/// few more there, refused here until they run; the rest it refuses itself
/// (`tcp_parse_tcp_rep`, `src/tcp_rules.c`).
/// Parses one rule and gives what it pushed the line it was written on.
pub(crate) fn parse_tcp_res_content(
    rules: &mut Vec<TcpResContentRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let before = rules.len();
    let res = parse_tcp_res_content_at(rules, tokens, kw);
    let line = u32::try_from(kw.line).unwrap_or(u32::MAX);
    for r in rules.iter_mut().skip(before) {
        r.line = line;
    }
    res
}

fn parse_tcp_res_content_at(
    rules: &mut Vec<TcpResContentRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let at = tokens.get(2).unwrap_or(kw);
    let act = at.text.as_str();
    let name = act.split('(').next().unwrap_or(act);
    if matches!(
        name,
        "close" | "send-spoe-group" | "set-log-level" | "set-nice" | "sc-add-gpc" | "sc-inc-gpc"
            | "sc-inc-gpc0" | "sc-inc-gpc1" | "sc-set-gpt" | "sc-set-gpt0" | "set-vars-from-map"
            | "do-log" | "set-fc-mark" | "set-fc-tos" | "set-mark" | "set-tos" | "set-bandwidth-limit"
    ) {
        return Err(ConfigError::new(at.line, at.col, format!("'tcp-response content {name}' is not implemented")));
    }
    let mut parsed = Vec::new();
    parse_tcp_req_content(&mut parsed, tokens, kw)?;
    for TcpReqContentRule { action, cond, line } in parsed {
        let action = match action {
            TcpReqContentAction::Accept => TcpResAction::Accept,
            TcpReqContentAction::Reject => TcpResAction::Reject,
            TcpReqContentAction::SilentDrop => TcpResAction::SilentDrop,
            // The TTL would be dropped: refused (HAProxy takes it here too).
            TcpReqContentAction::SilentDropTtl(_) => {
                return Err(ConfigError::new(at.line, at.col, "'tcp-response content silent-drop rst-ttl' is not implemented"))
            }
            TcpReqContentAction::SetVar { var_name, expr } => TcpResAction::SetVar { var_name, expr },
            TcpReqContentAction::SetVarFmt { var_name, fmt } => TcpResAction::SetVarFmt { var_name, fmt },
            TcpReqContentAction::UnsetVar { var_name } => TcpResAction::UnsetVar { var_name },
            _ => {
                return Err(ConfigError::new(
                    at.line,
                    at.col,
                    format!(
                        "'tcp-response content' expects 'accept', 'reject', 'silent-drop', 'set-var(*)', \
                         'set-var-fmt(*)' or 'unset-var(*)' (got '{act}')"
                    ),
                ))
            }
        };
        rules.push(TcpResContentRule { action, cond, line });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
/// Parses one rule and gives what it pushed the line it was written on.
pub(crate) fn parse_tcp_req_content(
    rules: &mut Vec<TcpReqContentRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let before = rules.len();
    let res = parse_tcp_req_content_at(rules, tokens, kw);
    let line = u32::try_from(kw.line).unwrap_or(u32::MAX);
    for r in rules.iter_mut().skip(before) {
        r.line = line;
    }
    res
}

fn parse_tcp_req_content_at(
    rules: &mut Vec<TcpReqContentRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<tcp-request content> expects <action>",
        ));
    }
    let act_tok = &tokens[2];
    let act_str = &act_tok.text;
    if act_str == "do-resolve" || act_str.starts_with("do-resolve(") {
        let (dr, cond) = super::resolvers::parse_do_resolve("tcp-request content", tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::DoResolve(dr), cond, line: 0 });
    } else if let Some(rule) = parse_tcp_content_var(tokens, act_str)? {
        rules.push(rule);
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScIncGpc0 { sc }, cond, line: 0 });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScIncGpc1 { sc }, cond, line: 0 });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_tok)? {
        let (expr, cond) = sc_value_and_cond(tokens)?;
        // No value is 0, as `HAProxy` reads it (`strtol` stops at the end of the line).
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScSetGpt0 { sc, expr }, cond, line: 0 });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-inc-gpc", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScIncGpc { idx, sc }, cond, line: 0 });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-add-gpc", act_tok)? {
        let (expr, cond) = sc_value_and_cond(tokens)?;
        // No value is 0: `strtol` reads nothing and the end of the line is what it stopped at.
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScAddGpc { idx, sc, expr }, cond, line: 0 });
    } else if let Some((idx, sc)) = parse_gpc_array_action(act_str, "sc-set-gpt", act_tok)? {
        let (expr, cond) = sc_value_and_cond(tokens)?;
        // No value is 0: `strtol` reads nothing and the end of the line is what it stopped at.
        let expr = if expr.is_empty() { "0".to_string() } else { expr };
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScSetGpt { idx, sc, expr }, cond, line: 0 });
    } else if act_str.starts_with("lua.") {
        return Err(ConfigError::new(
            act_tok.line,
            act_tok.col,
            format!("lua actions require Lua support, which this build does not have: <{act_str}>"),
        ));
    } else {
        match act_str.as_str() {
            "track-sc0" | "track-sc1" | "track-sc2" => {
                let (expr, table, cond_start) = parse_track_sc_args(tokens, 3, &|t| tcp_trailing_word(tokens, t))?;
                let cond = match cond_start {
                    Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
                    None => None,
                };
                let action = match act_str.as_str() {
                    "track-sc1" => TcpReqContentAction::TrackSc1 { expr, table },
                    "track-sc2" => TcpReqContentAction::TrackSc2 { expr, table },
                    _ => TcpReqContentAction::TrackSc0 { expr, table },
                };
                rules.push(TcpReqContentRule { action, cond, line: 0 });
            }
            "silent-drop" => {
                let ttl = parse_rst_ttl(tokens, 3)?;
                let (_, cond) = parse_rule_condition(tokens, ttl.map_or(3, |t| t.1))?;
                let action = ttl.map_or(TcpReqContentAction::SilentDrop, |t| TcpReqContentAction::SilentDropTtl(t.0));
                rules.push(TcpReqContentRule { action, cond, line: 0 });
            }
            "reject" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::Reject, cond, line: 0 });
            }
            "accept" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::Accept, cond, line: 0 });
            }
            "set-src" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetSrc { expr }, cond, line: 0 });
            }
            "set-src-port" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                if expr.is_empty() {
                    return Err(ConfigError::new(act_tok.line, act_tok.col, "missing fetch method"));
                }
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetSrcPort { expr }, cond, line: 0 });
            }
            "set-dst-port" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                if expr.is_empty() {
                    return Err(ConfigError::new(act_tok.line, act_tok.col, "missing fetch method"));
                }
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetDstPort { expr }, cond, line: 0 });
            }
            "set-dst" => {
                let (expr, cond) = tcp_arg_and_cond(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetDst { expr }, cond, line: 0 });
            }
            "capture" => {
                // `tcp_parse_capture`: `capture <sample> len <n>`, the length is mandatory.
                let refuse = |what: &str| {
                    ConfigError::new(act_tok.line, act_tok.col, format!("'tcp-request content capture' : {what}"))
                };
                let word = |i: usize| tokens.get(i).map_or("", |t| t.text.as_str());
                if word(3).is_empty() {
                    return Err(refuse("missing fetch method"));
                }
                let mut len = 0usize;
                let mut next = 4;
                if word(4) == "len" {
                    // atoi(3): digits after an optional sign, anything else reads 0.
                    let t = word(5).trim_start();
                    let (neg, digits) = t.strip_prefix('-').map_or((false, t.strip_prefix('+').unwrap_or(t)), |d| (true, d));
                    let end = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
                    let n = digits[..end].parse::<usize>().unwrap_or(if end == 0 { 0 } else { usize::MAX });
                    if neg || n == 0 {
                        return Err(refuse("length must be > 0"));
                    }
                    len = n;
                    next = 6;
                }
                if len == 0 {
                    return Err(refuse("a positive 'len' argument is mandatory"));
                }
                let (_, cond) = parse_rule_condition(tokens, next)?;
                let action = TcpReqContentAction::Capture { expr: tokens[3].text.clone(), len, id: None };
                rules.push(TcpReqContentRule { action, cond, line: 0 });
            }
            "switch-mode" => {
                rules.push(parse_tcp_content_switch_mode(tokens)?);
            }
            "use-service" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action use-service is not supported in this build",
                ));
            }
            "do-log" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action do-log is not supported in this build",
                ));
            }
            other => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    format!("unknown tcp-request content action <{other}>"),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_listen_tcp_request(
    listen: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "missing argument for 'tcp-request'",
        ));
    }
    match tokens[1].text.as_str() {
        "inspect-delay" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<tcp-request inspect-delay> expects delay timeout",
                ));
            }
            listen.tcp_req_inspect_delay = Some(parse_inspect_delay(&tokens[2], "request", "proxy", &listen.name)?);
            Ok(())
        }
        "connection" => in_proxy(parse_tcp_req_connection(&mut listen.tcp_req_conn_rules, tokens, kw), "proxy", &listen.name),
        "session" => in_proxy(parse_tcp_req_session(&mut listen.tcp_req_session_rules, tokens, kw), "proxy", &listen.name),
        "content" => in_proxy(parse_tcp_req_content(&mut listen.tcp_req_content_rules, tokens, kw), "proxy", &listen.name),
        other => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("unknown tcp-request subcommand <{other}>, expects 'inspect-delay', 'connection', 'session', or 'content'"),
        )),
    }
}

pub(crate) fn parse_frontend_tcp_request(
    fe: &mut FrontendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "missing argument for 'tcp-request'",
        ));
    }
    match tokens[1].text.as_str() {
        "inspect-delay" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<tcp-request inspect-delay> expects delay timeout",
                ));
            }
            fe.tcp_req_inspect_delay = Some(parse_inspect_delay(&tokens[2], "request", "proxy", &fe.name)?);
            Ok(())
        }
        "connection" => in_proxy(parse_tcp_req_connection(&mut fe.tcp_req_conn_rules, tokens, kw), "frontend", &fe.name),
        "session" => in_proxy(parse_tcp_req_session(&mut fe.tcp_req_session_rules, tokens, kw), "frontend", &fe.name),
        "content" => in_proxy(parse_tcp_req_content(&mut fe.tcp_req_content_rules, tokens, kw), "frontend", &fe.name),
        other => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("unknown tcp-request subcommand <{other}>, expects 'inspect-delay', 'connection', 'session', or 'content'"),
        )),
    }
}

pub(crate) fn parse_backend_tcp_request(
    be: &mut BackendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "missing argument for 'tcp-request'",
        ));
    }
    match tokens[1].text.as_str() {
        "inspect-delay" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<tcp-request inspect-delay> expects delay timeout",
                ));
            }
            be.tcp_req_inspect_delay = Some(parse_inspect_delay(&tokens[2], "request", "proxy", &be.name)?);
            Ok(())
        }
        "content" => in_proxy(parse_tcp_req_content(&mut be.tcp_req_content_rules, tokens, kw), "backend", &be.name),
        "connection" | "session" => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("'tcp-request {}' is not allowed in a backend", tokens[1].text),
        )),
        other => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("unknown tcp-request subcommand <{other}>, expects 'inspect-delay' or 'content'"),
        )),
    }
}

pub(crate) fn parse_sc_counter_action(
    act_str: &str,
    prefix: &str,
    act_tok: &Token,
) -> Result<Option<u8>, ConfigError> {
    if act_str == prefix {
        return Ok(Some(0));
    }
    if let Some(rest) = act_str.strip_prefix(prefix) {
        if !rest.starts_with('(') {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("invalid stick table track ID. Expects {prefix}(<Track ID>)"),
            ));
        }
        if !rest.ends_with(')') {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("missing closing parenthesis in <{act_str}>"),
            ));
        }
        let inner = &rest[1..rest.len() - 1];
        let val = inner.parse::<u8>().map_err(|_| {
            ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("invalid stick counter index in <{act_str}>"),
            )
        })?;
        if val > 2 {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("stick counter index must be 0, 1, or 2 in <{act_str}>"),
            ));
        }
        return Ok(Some(val));
    }
    Ok(None)
}

pub(crate) fn parse_track_sc_args(
    tokens: &[Token],
    start: usize,
    refuse: &dyn Fn(&Token) -> ConfigError,
) -> Result<(String, Option<String>, Option<usize>), ConfigError> {
    if tokens.len() <= start {
        return Err(ConfigError::new(
            tokens.get(start - 1).map_or(0, |t| t.line),
            tokens.get(start - 1).map_or(0, |t| t.col),
            "track-sc* expects sample expression",
        ));
    }
    let expr = tokens[start].text.clone();
    let mut table = None;
    let mut cond_start = None;
    let mut i = start + 1;
    while i < tokens.len() {
        if tokens[i].text == "table" && i + 1 < tokens.len() {
            table = Some(tokens[i + 1].text.clone());
            i += 2;
        } else if tokens[i].text == "if" || tokens[i].text == "unless" {
            cond_start = Some(i);
            break;
        } else {
            // `track-scN <expr> [table <t>]` and then the condition; a word that is neither
            // is refused, not skipped (a `table` with no name lands here too).
            return Err(refuse(&tokens[i]));
        }
    }
    Ok((expr, table, cond_start))
}


/// The array forms of the general purpose actions: `sc-inc-gpc(<idx>,<sc>)`,
/// `sc-add-gpc(<idx>,<sc>) <value>` and `sc-set-gpt(<idx>,<sc>) <value>` (`parse_inc_gpc`,
/// `parse_add_gpc` and `parse_set_gpt`, `src/stick_table.c`, which words the messages).
/// `None` if `act_str` is not one of them; the legacy `sc-inc-gpc0`, `sc-inc-gpc1` and
/// `sc-set-gpt0` are parsed before this is asked.
pub(crate) fn parse_gpc_array_action(
    act_str: &str,
    prefix: &str,
    act_tok: &Token,
) -> Result<Option<(usize, u8)>, ConfigError> {
    let Some(rest) = act_str.strip_prefix(prefix) else { return Ok(None) };
    let err = |m: String| ConfigError::new(act_tok.line, act_tok.col, m);
    let add = prefix == "sc-add-gpc";
    let what = if prefix == "sc-set-gpt" { "GPT" } else { "GPC" };
    let expects = format!("Expects {prefix}(<{what} ID>,<Track ID>)");
    let Some(args) = rest.strip_prefix('(') else {
        return Err(err(if add {
            format!("Missing or invalid arguments for '{act_str}'. {expects}")
        } else {
            format!("invalid {} ID '{act_str}'. {expects}", what.to_lowercase())
        }));
    };
    // `strtoul`: the digits, which must be followed by the comma.
    let digits = args.bytes().take_while(u8::is_ascii_digit).count();
    let Some(after) = args[digits..].strip_prefix(',') else {
        return Err(err(if add {
            format!("Missing gpc ID. Expects {act_str}(<GPC ID>,<Track ID>)")
        } else {
            format!("Missing {} ID '{act_str}'. {expects}", what.to_lowercase())
        }));
    };
    let idx = args[..digits].parse::<usize>().unwrap_or(usize::MAX);
    let sc_digits = after.strip_prefix('-').map_or(0, |_| 1) + after.trim_start_matches('-').bytes().take_while(u8::is_ascii_digit).count();
    let Some(tail) = after[sc_digits..].strip_prefix(')').filter(|t| t.is_empty()) else {
        return Err(err(format!(
            "invalid stick table track ID '{}'. {expects}",
            if add { after } else { act_str }
        )));
    };
    debug_assert!(tail.is_empty());
    match after[..sc_digits].parse::<i64>() {
        Ok(sc) if (0..3).contains(&sc) => Ok(Some((idx, u8::try_from(sc).unwrap_or(0)))),
        _ => Err(err(format!(
            "invalid stick table track ID '{act_str}'. The max allowed ID is 2{}",
            if prefix == "sc-set-gpt" { "" } else { " (tune.stick-counters)" }
        ))),
    }
}

/// The value of `sc-set-gpt0`, `sc-set-gpt` and `sc-add-gpc` and the condition. HAProxy reads
/// the next word as the value's sample fetch, so `if`/`unless` there is `unknown fetch
/// method 'if'`; no word at all is accepted (the value is 0).
fn sc_value_and_cond(tokens: &[Token]) -> Result<(String, Option<AclCondition>), ConfigError> {
    if let Some(t) = tokens.get(3).filter(|t| t.text == "if" || t.text == "unless") {
        return Err(ConfigError::new(t.line, t.col, format!("unknown fetch method '{}'", t.text)));
    }
    tcp_arg_and_cond(tokens, 3)
}
