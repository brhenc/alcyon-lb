use super::*;

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
        "errorfile" => {
            // errorfile <status> <file> in defaults
            Ok(())
        }
        "tcp-request" => {
            if tokens.len() >= 3 && tokens[1].text == "inspect-delay" {
                defaults.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
                Ok(())
            } else {
                Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("tcp-request subcommand '{}' is not supported in defaults", tokens[1].text),
                ))
            }
        }
        "log" => {
            defaults.log_global |= parse_log(&mut defaults.logs, tokens, kw)?;
            Ok(())
        }
        "option" => parse_option_defaults(defaults, tokens, kw),
        "no" => parse_no_directive(tokens, kw),
        "declare" => parse_declare(tokens, kw),
        "contimeout" => parse_contimeout(kw),
        "clitimeout" => parse_clitimeout(kw),
        "srvtimeout" => parse_srvtimeout(kw),
        "dispatch" => parse_dispatch(kw),
        "http-reuse" => parse_http_reuse(&mut defaults.http_reuse, tokens, kw),
        "cliexp" => parse_cliexp(kw),
        "srvexp" => parse_srvexp(kw),
        "tcp-response" | "http-request" | "http-response" | "http-after-request" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("directive '{}' is not supported in defaults", kw.text),
            ))
        }
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
            other => {
                refuse_if_check_option(other, kw)?;
                eprintln!("[ibex] warning: ignored option '{other}'");
            }
        }
    }
    Ok(())
}

