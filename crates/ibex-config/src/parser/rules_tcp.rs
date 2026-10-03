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
            let (expr, table, cond_start) = parse_track_sc_args(tokens, 3)?;
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
            let (_, cond) = parse_rule_condition(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SilentDrop, cond });
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
            let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
            let expr = join_tokens_until(tokens, 3, cond_idx);
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SetSrc { expr }, cond });
        }
        "set-dst" => {
            let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
            let expr = join_tokens_until(tokens, 3, cond_idx);
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SetDst { expr }, cond });
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
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
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
        let (cond_idx, cond) = parse_rule_condition(tokens, 4)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
        if expr.is_empty() {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                "<tcp-request session sc-set-gpt0> expects value or expression",
            ));
        }
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScSetGpt0 { sc, expr }, cond });
    } else {
        match act_str.as_str() {
            "track-sc0" | "track-sc1" | "track-sc2" => {
                let (expr, table, cond_start) = parse_track_sc_args(tokens, 3)?;
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
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SilentDrop, cond });
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
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetSrc { expr }, cond });
            }
            "set-dst" => {
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetDst { expr }, cond });
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
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
        let action = if is_fmt {
            TcpReqContentAction::SetVarFmt { var_name, fmt: expr }
        } else {
            TcpReqContentAction::SetVar { var_name, expr }
        };
        Ok(Some(TcpReqContentRule { action, cond }))
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_str
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        Ok(Some(TcpReqContentRule {
            action: TcpReqContentAction::UnsetVar { var_name },
            cond,
        }))
    } else {
        Ok(None)
    }
}

pub(crate) fn parse_tcp_content_switch_mode(
    tokens: &[Token],
) -> Result<TcpReqContentRule, ConfigError> {
    let mut proto = None;
    let (cond_idx, cond) = parse_rule_condition(tokens, 4)?;
    let limit = cond_idx.unwrap_or(tokens.len());
    let mut i = 4;
    while i < limit {
        if tokens[i].text == "proto" && i + 1 < limit {
            proto = Some(tokens[i + 1].text.clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(TcpReqContentRule {
        action: TcpReqContentAction::SwitchModeHttp { proto },
        cond,
    })
}

/// `tcp-response content <action>`: the request-side grammar, kept only for the actions
/// the response side runs (`eval_tcp_res_content_rules` in ibex-rt). `HAProxy` takes a
/// few more there, refused here until they run; the rest it refuses itself
/// (`tcp_parse_tcp_rep`, `src/tcp_rules.c`).
pub(crate) fn parse_tcp_res_content(
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
    for TcpReqContentRule { action, cond } in parsed {
        let action = match action {
            TcpReqContentAction::Accept => TcpResAction::Accept,
            TcpReqContentAction::Reject => TcpResAction::Reject,
            TcpReqContentAction::SilentDrop => TcpResAction::SilentDrop,
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
        rules.push(TcpResContentRule { action, cond });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_tcp_req_content(
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
    if let Some(rule) = parse_tcp_content_var(tokens, act_str)? {
        rules.push(rule);
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScIncGpc0 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScIncGpc1 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_tok)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 4)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
        if expr.is_empty() {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                "<tcp-request content sc-set-gpt0> expects value or expression",
            ));
        }
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScSetGpt0 { sc, expr }, cond });
    } else if act_str.starts_with("lua.") {
        return Err(ConfigError::new(
            act_tok.line,
            act_tok.col,
            format!("lua actions require Lua support, which this build does not have: <{act_str}>"),
        ));
    } else {
        match act_str.as_str() {
            "track-sc0" | "track-sc1" | "track-sc2" => {
                let (expr, table, cond_start) = parse_track_sc_args(tokens, 3)?;
                let cond = match cond_start {
                    Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
                    None => None,
                };
                let action = match act_str.as_str() {
                    "track-sc1" => TcpReqContentAction::TrackSc1 { expr, table },
                    "track-sc2" => TcpReqContentAction::TrackSc2 { expr, table },
                    _ => TcpReqContentAction::TrackSc0 { expr, table },
                };
                rules.push(TcpReqContentRule { action, cond });
            }
            "silent-drop" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SilentDrop, cond });
            }
            "reject" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::Reject, cond });
            }
            "accept" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::Accept, cond });
            }
            "set-src" => {
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetSrc { expr }, cond });
            }
            "set-dst" => {
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetDst { expr }, cond });
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
            listen.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
            Ok(())
        }
        "connection" => parse_tcp_req_connection(&mut listen.tcp_req_conn_rules, tokens, kw),
        "session" => parse_tcp_req_session(&mut listen.tcp_req_session_rules, tokens, kw),
        "content" => parse_tcp_req_content(&mut listen.tcp_req_content_rules, tokens, kw),
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
            fe.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
            Ok(())
        }
        "connection" => parse_tcp_req_connection(&mut fe.tcp_req_conn_rules, tokens, kw),
        "session" => parse_tcp_req_session(&mut fe.tcp_req_session_rules, tokens, kw),
        "content" => parse_tcp_req_content(&mut fe.tcp_req_content_rules, tokens, kw),
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
            be.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
            Ok(())
        }
        "content" => parse_tcp_req_content(&mut be.tcp_req_content_rules, tokens, kw),
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
            i += 1;
        }
    }
    Ok((expr, table, cond_start))
}

