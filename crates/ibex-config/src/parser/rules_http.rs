use super::{
    find_cond_idx, join_tokens_until, parse_acl_condition_from_tokens, parse_error_body_args,
    parse_rule_condition, parse_sc_counter_action, parse_u16, ConfigError, ErrorPageSource,
    HttpAfterResAction, HttpAfterResRule, HttpReqAction, HttpReqRule, HttpResAction, HttpResRule,
    Token,
};

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
    } else if act_str == "replace-header" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response replace-header> expects <name>, <regex>, <replace>.",
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
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: format!("\0set-var:{var_name}"),
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
        let mut status = None;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            if (tokens[i].text == "status" || tokens[i].text == "deny_status") && i + 1 < limit {
                status = Some(parse_u16(&tokens[i + 1], "status")?);
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
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0deny".to_string(),
                fmt: status.map_or_else(String::new, |s| s.to_string()),
            },
            cond,
        });
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
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: format!("\0set-var:{var_name}"),
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
    } else if act_str == "deny" {
        let mut status = None;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            if (tokens[i].text == "status" || tokens[i].text == "deny_status") && i + 1 < limit {
                status = Some(parse_u16(&tokens[i + 1], "status")?);
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
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0deny".to_string(),
                fmt: status.map_or_else(String::new, |s| s.to_string()),
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

