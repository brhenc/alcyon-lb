use super::*;

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_defaults_directive(
    defaults: &mut DefaultsSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "mode" => {
            let mut mode = defaults.mode.unwrap_or(Mode::Tcp);
            parse_mode(&mut mode, tokens, kw)?;
            defaults.mode = Some(mode);
            Ok(())
        }
        "timeout" => parse_timeout_directive(&mut defaults.timeouts, tokens, kw),
        "retries" => {
            let mut r = defaults.retries.unwrap_or(0);
            parse_retries(&mut r, tokens, kw)?;
            defaults.retries = Some(r);
            Ok(())
        }
        "redisp" => {
            defaults.redisp = true;
            Ok(())
        }
        "maxconn" => {
            let mut mc = defaults.maxconn.unwrap_or(0);
            parse_maxconn(&mut mc, tokens, kw)?;
            defaults.maxconn = Some(mc);
            Ok(())
        }
        "balance" => {
            let mut b = defaults.balance.unwrap_or(BalanceAlgorithm::RoundRobin);
            parse_balance(&mut b, tokens, kw)?;
            defaults.balance = Some(b);
            Ok(())
        }
        "cookie" => {
            let mut c = defaults.cookie.clone();
            parse_cookie(&mut c, tokens, kw)?;
            defaults.cookie = c;
            Ok(())
        }
        "default-server" => parse_default_server(&mut defaults.default_server, tokens, kw),
        "stats" => parse_stats_directive(&mut defaults.stats, tokens, kw),
        "errorfile" | "errorfiles" | "http-error" => {
            parse_proxy_error_page(&mut defaults.error_files, &mut defaults.error_replies, tokens, kw)
        }
        "tcp-request" => {
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
                    defaults.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
                    Ok(())
                }
                "connection" => parse_tcp_req_connection(&mut defaults.tcp_req_conn_rules, tokens, kw),
                "session" => parse_tcp_req_session(&mut defaults.tcp_req_session_rules, tokens, kw),
                "content" => parse_tcp_req_content(&mut defaults.tcp_req_content_rules, tokens, kw),
                other => Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("unknown tcp-request subcommand <{other}>, expects 'inspect-delay', 'connection', 'session', or 'content'"),
                )),
            }
        }
        "tcp-response" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "missing argument for 'tcp-response'",
                ));
            }
            match tokens[1].text.as_str() {
                "inspect-delay" => {
                    if tokens.len() < 3 {
                        return Err(ConfigError::new(
                            kw.line,
                            kw.col,
                            "<tcp-response inspect-delay> expects delay timeout",
                        ));
                    }
                    defaults.tcp_res_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-response inspect-delay")?);
                    Ok(())
                }
                "content" => parse_tcp_req_content(&mut defaults.tcp_res_content_rules, tokens, kw),
                other => Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("unknown tcp-response subcommand <{other}>, expects 'inspect-delay' or 'content'"),
                )),
            }
        }
        "http-request" => parse_http_req_rule(&mut defaults.http_req_rules, tokens, kw),
        "http-response" => parse_http_res_rule(&mut defaults.http_res_rules, tokens, kw),
        "http-after-response" => {
            parse_http_after_res_rule(&mut defaults.http_after_res_rules, tokens, kw)
        }
        "log" => parse_log(&mut defaults.logs, tokens, kw).map(|g| defaults.log_global |= g),
        "log-tag" => parse_log_tag(tokens, kw).map(|t| defaults.log_tag = Some(t)),
        "option" => parse_option_defaults(defaults, tokens, kw),
        "no" => parse_no_directive(tokens, kw),
        "declare" => parse_declare(tokens, kw),
        "contimeout" => parse_contimeout(kw),
        "clitimeout" => parse_clitimeout(kw),
        "srvtimeout" => parse_srvtimeout(kw),
        "dispatch" => parse_dispatch(kw),
        "http-reuse" => parse_http_reuse(&mut defaults.http_reuse, tokens, kw),
        "hash-type" => {
            let mut ht = defaults.hash_type.unwrap_or_default();
            parse_hash_type(&mut ht, tokens, kw)?;
            defaults.hash_type = Some(ht);
            Ok(())
        }
        "hash-preserve-affinity" => {
            let mut a = defaults.hash_preserve_affinity.unwrap_or_default();
            parse_hash_preserve_affinity(&mut a, tokens, kw)?;
            defaults.hash_preserve_affinity = Some(a);
            Ok(())
        }
        "cliexp" => parse_cliexp(kw),
        "srvexp" => parse_srvexp(kw),
        "http-check" => {
            parse_http_check_directive(&mut defaults.http_checks, tokens, kw)?;
            Ok(())
        }
        "tcp-check" => {
            parse_tcp_check_directive(&mut defaults.tcp_checks, tokens, kw)?;
            Ok(())
        }
        "log-format" | "log-format-sd" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported", kw.text),
            ))
        }
        other if IGNORED_DEFAULTS_KEYWORDS.iter().any(|(k, _)| *k == other) => Ok(()),
        _ => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{}' in 'defaults' section", kw.text),
        )),
    }
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn parse_option_defaults(
    defaults: &mut DefaultsSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        match tokens[1].text.as_str() {
            "log-health-checks" => {
                defaults.log_health_checks = true;
            }
            "httpchk" => {
                parse_httpchk_option(&mut defaults.httpchk, tokens, kw)?;
            }
            "tcp-check" => {
                defaults.tcp_check = true;
            }
            _ if parse_proto_check_option(&mut defaults.proto_check, tokens, kw)? => {}
            other => {
                refuse_if_check_option(other, kw)?;
                eprintln!("[ibex] warning: ignored option '{other}'");
            }
        }
    }
    Ok(())
}

