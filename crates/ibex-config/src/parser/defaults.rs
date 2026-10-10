// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;
use crate::ast::HttpMode;

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
        "retry-on" => {
            let mut r = defaults.retry_on.unwrap_or(crate::ast::RE_CONN_FAILED);
            super::parse_retry_on(&mut r, tokens, kw)?;
            defaults.retry_on = Some(r);
            Ok(())
        }
        "redisp" => parse_redisp(kw),
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
        "id" => Err(ConfigError::new(kw.line, kw.col, "'id' not allowed in 'defaults' section.")),
        "default-server" => parse_default_server(&mut defaults.default_server, tokens, kw),
        "stats" => parse_stats_directive(&mut defaults.stats, tokens, kw),
        "errorfile" | "errorfiles" | "http-error" | "errorloc" | "errorloc302" | "errorloc303" => {
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
                    defaults.tcp_req_inspect_delay = Some(parse_inspect_delay(&tokens[2], "request", "defaults", defaults.name.as_deref().unwrap_or_default())?);
                    Ok(())
                }
                sub @ ("connection" | "session" | "content") if defaults.name.is_none() => Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    format!("tcp-request {sub} is not allowed in anonymous 'defaults' sections"),
                )),
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
                    defaults.tcp_res_inspect_delay = Some(parse_inspect_delay(&tokens[2], "response", "defaults", defaults.name.as_deref().unwrap_or_default())?);
                    Ok(())
                }
                "content" if defaults.name.is_none() => Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "tcp-response content is only allowed in 'backend' sections or 'defaults' section with a name",
                )),
                "content" => parse_tcp_res_content(&mut defaults.tcp_res_content_rules, tokens, kw),
                other => Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("unknown tcp-response subcommand <{other}>, expects 'inspect-delay' or 'content'"),
                )),
            }
        }
        // `HAProxy` keeps no rule of an unnamed `defaults` section: the sections that follow
        // do not inherit them (`src/cfgparse-listen.c`).
        kw_name @ ("http-request" | "http-response" | "http-after-response") if defaults.name.is_none() => {
            Err(ConfigError::new(kw.line, kw.col, format!("'{kw_name}' not allowed in anonymous 'defaults' section.")))
        }
        "http-request" if tokens.get(1).is_some_and(|t| t.text == "set-retries") => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            "'set-retries' is not allowed in 'defaults' sections",
        )),
        "http-request" => in_section(parse_http_req_rule(&mut defaults.http_req_rules, tokens, kw), "defaults", defaults.name.as_deref().unwrap_or_default()),
        "http-response" => in_section(parse_http_res_rule(&mut defaults.http_res_rules, tokens, kw), "defaults", defaults.name.as_deref().unwrap_or_default()),
        "http-after-response" => {
            in_section(parse_http_after_res_rule(&mut defaults.http_after_res_rules, tokens, kw), "defaults", defaults.name.as_deref().unwrap_or_default())
        }
        "log" => parse_log(&mut defaults.logs, tokens, kw).map(|g| defaults.log_global |= g),
        "log-tag" => parse_log_tag(tokens, kw).map(|t| defaults.log_tag = Some(t)),
        "option" => parse_option_defaults(defaults, tokens, kw),
        "no" => parse_no_defaults(defaults, tokens, kw),
        "declare" => refuse_declare(DeclareIn::Defaults, kw),
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
        "grace" => parse_grace(kw),
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
        "log-format" => {
            defaults.log_format = Some(LogFormatSpec::Custom(parse_format_arg(tokens, kw)?));
            Ok(())
        }
        "log-format-sd" => Err(ConfigError::new(kw.line, kw.col, "'log-format-sd' is not implemented".to_string())),
        "unique-id-format" => {
            defaults.unique_id_format = Some(parse_format_arg(tokens, kw)?);
            Ok(())
        }
        "unique-id-header" => match tokens.get(1) {
            Some(t) => {
                defaults.unique_id_header = Some(t.text.clone());
                Ok(())
            }
            None => Err(ConfigError::new(kw.line, kw.col, "unique-id-header expects an argument.".to_string())),
        },
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
    // `option httplog`/`tcplog` (and `clf`) are the log format (T53), ahead of the option
    // table: the table would otherwise warn and drop them.
    if let Some(spec) = parse_log_option(tokens, kw) {
        defaults.log_format = Some(spec?);
        return Ok(());
    }
    if !check_option(OptSection::Defaults, tokens, kw)? {
        return Ok(());
    }
    match tokens[1].text.as_str() {
        "forwardfor" => {
            let (except, if_none) = parse_forward_option(tokens, kw)?;
            defaults.forwardfor = Some(except);
            defaults.forwardfor_if_none = if_none;
        }
        "originalto" => defaults.originalto = Some(parse_forward_option(tokens, kw)?.0),
        "forwarded" => defaults.forwarded = Some(Box::new(parse_forwarded_option(tokens)?)),
        "redispatch" => set_redispatch(&mut defaults.redisp, &mut defaults.redisp_after, tokens),
        "http-buffer-request" => defaults.buffer_request = true,
        "abortonclose" => defaults.abortonclose = Some(true),
        "http-server-close" => defaults.http_mode = HttpMode::ServerClose,
        "httpclose" => defaults.http_mode = HttpMode::Close,
        "persist" => defaults.persist = true,
        "http-keep-alive" => defaults.http_mode = HttpMode::KeepAlive,
        "dontlognull" => defaults.dontlognull = true,
        "h1-case-adjust-bogus-client" => defaults.h1_adjust |= crate::ast::H1_ADJ_CLIENT,
        "h1-case-adjust-bogus-server" => defaults.h1_adjust |= crate::ast::H1_ADJ_SERVER,
        "dontlog-normal" | "log-separate-errors" | "logasap" => defaults.log_opts |= crate::ast::log_opt_bit(&tokens[1].text),
        "accept-unsafe-violations-in-http-request" => defaults.stats.accept_unsafe_request = true,
        "log-health-checks" => defaults.log_health_checks = true,
        "httpchk" => parse_httpchk_option(&mut defaults.httpchk, tokens, kw)?,
        "tcp-check" => defaults.tcp_check = true,
        _ => {
            parse_proto_check_option(&mut defaults.proto_check, tokens, kw)?;
        }
    }
    Ok(())
}

/// `no option <name>` in `defaults`.
pub(crate) fn parse_no_defaults(defaults: &mut DefaultsSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.get(1).is_some_and(|t| t.text == "log") {
        defaults.logs.clear();
        defaults.log_global = false;
        return Ok(());
    }
    if tokens.get(1).is_none_or(|t| t.text != "option") {
        return parse_no_directive(tokens, kw);
    }
    match check_no_option(OptSection::Defaults, tokens, kw)? {
        Some("redispatch") => (defaults.redisp, defaults.redisp_after) = (false, -1),
        Some("http-buffer-request") => defaults.buffer_request = false,
        Some("abortonclose") => defaults.abortonclose = Some(false),
        Some("http-server-close") if defaults.http_mode == HttpMode::ServerClose => defaults.http_mode = HttpMode::KeepAlive,
        Some("httpclose") if defaults.http_mode == HttpMode::Close => defaults.http_mode = HttpMode::KeepAlive,
        Some("persist") => defaults.persist = false,
        Some("dontlognull") => defaults.dontlognull = false,
        Some("h1-case-adjust-bogus-client") => defaults.h1_adjust &= !crate::ast::H1_ADJ_CLIENT,
        Some("h1-case-adjust-bogus-server") => defaults.h1_adjust &= !crate::ast::H1_ADJ_SERVER,
        Some(n @ ("dontlog-normal" | "log-separate-errors" | "logasap")) => defaults.log_opts &= !crate::ast::log_opt_bit(n),
        Some("accept-unsafe-violations-in-http-request") => defaults.stats.accept_unsafe_request = false,
        Some("log-health-checks") => defaults.log_health_checks = false,
        Some("forwarded") => defaults.forwarded = None,
        _ => {}
    }
    Ok(())
}
