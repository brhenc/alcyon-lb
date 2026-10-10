// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::collections::HashMap;

use super::*;
use crate::ast::HttpMode;

pub(crate) fn parse_listen_header(
    tokens: &[Token],
    kw: &Token,
    named_defaults: &HashMap<String, DefaultsSection>,
    current_defaults: Option<&DefaultsSection>,
) -> Result<ListenSection, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<listen> expects <id> as argument.",
        ));
    }

    let id = tokens[1].text.clone();
    let (defaults, rest_idx) = if tokens.len() >= 3 && tokens[2].text == "from" {
        if tokens.len() < 4 || tokens[3].text.is_empty() {
            return Err(ConfigError::new(tokens[2].line, tokens[2].col, "'from' expects a defaults section name".to_string()));
        }
        let def_name = &tokens[3].text;
        let def = named_defaults.get(def_name).ok_or_else(|| {
            ConfigError::new(tokens[3].line, tokens[3].col, format!("defaults section '{def_name}' not found for listen '{id}'."))
        })?;
        (Some(def), 4)
    } else {
        (current_defaults, 2)
    };

    if tokens.len() > rest_idx && !tokens[rest_idx].text.is_empty() {
        return Err(ConfigError::new(
            tokens[rest_idx].line,
            tokens[rest_idx].col,
            "please use the 'bind' keyword for listening addresses",
        ));
    }
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let mut accept_proxy = false;
    let mut accept_proxy_v2 = false;

    if let Some(extra_tokens) = tokens.get(rest_idx + 1..) {
        for tok in extra_tokens {
            if tok.text == "accept-proxy" {
                accept_proxy = true;
            } else if tok.text == "accept-proxy-v2" {
                accept_proxy = true;
                accept_proxy_v2 = true;
            }
        }
    }

    let mode = defaults.and_then(|d| d.mode).unwrap_or(Mode::Tcp);
    let timeouts = defaults.map_or_else(TimeoutConfig::default, |d| d.timeouts);

    Ok(ListenSection {
        httpchk: defaults.and_then(|d| d.httpchk.clone()),
        proto_check: defaults.and_then(|d| d.proto_check.clone()),
        http_checks: defaults.map_or_else(Vec::new, |d| d.http_checks.clone()),
        http_check_own: false,
        tcp_checks: defaults.map_or_else(Vec::new, |d| d.tcp_checks.clone()),
        tcp_check: defaults.is_some_and(|d| d.tcp_check),
        name: id,
        addr,
        binds: Vec::new(),
        mode,
        disabled: false,
        id: None,
        description: None,
        cookie: defaults.and_then(|d| d.cookie.clone()),
        contimeout: timeouts.connect,
        clitimeout: timeouts.client,
        srvtimeout: timeouts.server,
        timeouts,
        retries: defaults.and_then(|d| d.retries).unwrap_or(3),
        retry_on: defaults.and_then(|d| d.retry_on).unwrap_or(crate::ast::RE_CONN_FAILED),
        redisp: defaults.map_or(false, |d| d.redisp),
        redisp_after: defaults.map_or(-1, |d| if d.redisp { d.redisp_after } else { -1 }),
        maxconn: defaults.and_then(|d| d.maxconn).unwrap_or(0),
        dispatch: None,
        default_server: defaults.and_then(|d| d.default_server.clone()),
        use_servers: Vec::new(),
        servers: Vec::new(),
        server_extras: ServerExtras::default(),
        logs: defaults.map_or_else(Vec::new, |d| d.logs.clone()),
        log_tag: defaults.and_then(|d| d.log_tag.clone()),
        log_global: defaults.map_or(false, |d| d.log_global),
        log_format: defaults.and_then(|d| d.log_format.clone()),
        unique_id_format: defaults.and_then(|d| d.unique_id_format.clone()),
        unique_id_header: defaults.and_then(|d| d.unique_id_header.clone()),
        req_header_captures: Vec::new(),
        res_header_captures: Vec::new(),
        log_health_checks: defaults.map_or(false, |d| d.log_health_checks),
        buffer_request: defaults.is_some_and(|d| d.buffer_request),
        abortonclose: defaults.and_then(|d| d.abortonclose),
        h1_adjust: defaults.map_or(0, |d| d.h1_adjust),
        http_mode: defaults.map_or(HttpMode::KeepAlive, |d| d.http_mode),
        persist: defaults.is_some_and(|d| d.persist),
        dontlognull: defaults.is_some_and(|d| d.dontlognull),
        http_ignore_probes: defaults.is_some_and(|d| d.http_ignore_probes),
        log_opts: defaults.map_or(0, |d| d.log_opts),
        cliexp: Vec::new(),
        srvexp: Vec::new(),
        acls: Vec::new(),
        use_backends: Vec::new(),
        force_be_switch: Vec::new(),
        monitor_uri: None,
        default_backend: None,
        balance: defaults.and_then(|d| d.balance).unwrap_or(BalanceAlgorithm::RoundRobin),
        stick_table: None,
        stick_rules: Vec::new(),
        tcp_req_inspect_delay: defaults.and_then(|d| d.tcp_req_inspect_delay),
        tcp_req_conn_rules: defaults.map_or_else(Vec::new, |d| d.tcp_req_conn_rules.clone()),
        tcp_req_session_rules: defaults.map_or_else(Vec::new, |d| d.tcp_req_session_rules.clone()),
        tcp_req_content_rules: defaults.map_or_else(Vec::new, |d| d.tcp_req_content_rules.clone()),
        tcp_res_inspect_delay: defaults.and_then(|d| d.tcp_res_inspect_delay),
        tcp_res_content_rules: defaults.map_or_else(Vec::new, |d| d.tcp_res_content_rules.clone()),
        http_req_rules: defaults.map_or_else(Vec::new, |d| d.http_req_rules.clone()),
        http_res_rules: defaults.map_or_else(Vec::new, |d| d.http_res_rules.clone()),
        http_after_res_rules: defaults.map_or_else(Vec::new, |d| d.http_after_res_rules.clone()),
        accept_proxy,
        accept_proxy_v2,
        http_reuse: defaults.and_then(|d| d.http_reuse),
        hash_type: defaults.and_then(|d| d.hash_type),
        hash_preserve_affinity: defaults.and_then(|d| d.hash_preserve_affinity),
        forwardfor: defaults.and_then(|d| d.forwardfor.clone()),
        forwardfor_if_none: defaults.is_some_and(|d| d.forwardfor_if_none),
        forwarded: defaults.and_then(|d| d.forwarded.clone()),
        originalto: defaults.and_then(|d| d.originalto.clone()),
        stats: defaults.map_or_else(StatsConfig::default, |d| d.stats.clone()),
        error_files: defaults.map_or_else(HashMap::new, |d| d.error_files.clone()),
        error_replies: defaults.map_or_else(HashMap::new, |d| d.error_replies.clone()),
    })
}

pub(crate) fn parse_frontend_header(
    tokens: &[Token],
    kw: &Token,
    named_defaults: &HashMap<String, DefaultsSection>,
    current_defaults: Option<&DefaultsSection>,
) -> Result<FrontendSection, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<frontend> expects <id> as argument.",
        ));
    }

    let id = tokens[1].text.clone();
    let (defaults, rest_idx) = if tokens.len() >= 3 && tokens[2].text == "from" {
        if tokens.len() < 4 || tokens[3].text.is_empty() {
            return Err(ConfigError::new(tokens[2].line, tokens[2].col, "'from' expects a defaults section name".to_string()));
        }
        let def_name = &tokens[3].text;
        let def = named_defaults.get(def_name).ok_or_else(|| {
            ConfigError::new(tokens[3].line, tokens[3].col, format!("defaults section '{def_name}' not found for frontend '{id}'."))
        })?;
        (Some(def), 4)
    } else {
        (current_defaults, 2)
    };

    if tokens.len() > rest_idx && !tokens[rest_idx].text.is_empty() {
        return Err(ConfigError::new(tokens[rest_idx].line, tokens[rest_idx].col, "please use the 'bind' keyword for listening addresses".to_string()));
    }

    let mode = defaults.and_then(|d| d.mode).unwrap_or(Mode::Tcp);
    let timeouts = defaults.map_or_else(TimeoutConfig::default, |d| d.timeouts);

    Ok(FrontendSection {
        name: id,
        bind: None,
        binds: Vec::new(),
        mode,
        disabled: false,
        id: None,
        description: None,
        clitimeout: timeouts.client,
        timeouts,
        maxconn: defaults.and_then(|d| d.maxconn).unwrap_or(0),
        default_backend: None,
        use_backends: Vec::new(),
        force_be_switch: Vec::new(),
        monitor_uri: None,
        acls: Vec::new(),
        cliexp: Vec::new(),
        logs: defaults.map_or_else(Vec::new, |d| d.logs.clone()),
        log_tag: defaults.and_then(|d| d.log_tag.clone()),
        log_global: defaults.map_or(false, |d| d.log_global),
        log_format: defaults.and_then(|d| d.log_format.clone()),
        unique_id_format: defaults.and_then(|d| d.unique_id_format.clone()),
        unique_id_header: defaults.and_then(|d| d.unique_id_header.clone()),
        req_header_captures: Vec::new(),
        res_header_captures: Vec::new(),
        log_health_checks: defaults.map_or(false, |d| d.log_health_checks),
        buffer_request: defaults.is_some_and(|d| d.buffer_request),
        http_mode: defaults.map_or(HttpMode::KeepAlive, |d| d.http_mode),
        dontlognull: defaults.is_some_and(|d| d.dontlognull),
        http_ignore_probes: defaults.is_some_and(|d| d.http_ignore_probes),
        h1_adjust: defaults.map_or(0, |d| d.h1_adjust & crate::ast::H1_ADJ_CLIENT),
        log_opts: defaults.map_or(0, |d| d.log_opts),
        stick_table: None,
        stick_rules: Vec::new(),
        tcp_req_inspect_delay: defaults.and_then(|d| d.tcp_req_inspect_delay),
        tcp_req_conn_rules: defaults.map_or_else(Vec::new, |d| d.tcp_req_conn_rules.clone()),
        tcp_req_session_rules: defaults.map_or_else(Vec::new, |d| d.tcp_req_session_rules.clone()),
        tcp_req_content_rules: defaults.map_or_else(Vec::new, |d| d.tcp_req_content_rules.clone()),
        http_req_rules: defaults.map_or_else(Vec::new, |d| d.http_req_rules.clone()),
        http_res_rules: defaults.map_or_else(Vec::new, |d| d.http_res_rules.clone()),
        http_after_res_rules: defaults.map_or_else(Vec::new, |d| d.http_after_res_rules.clone()),
        accept_proxy: false,
        accept_proxy_v2: false,
        forwardfor: defaults.and_then(|d| d.forwardfor.clone()),
        forwardfor_if_none: defaults.is_some_and(|d| d.forwardfor_if_none),
        originalto: defaults.and_then(|d| d.originalto.clone()),
        stats: defaults.map_or_else(StatsConfig::default, |d| d.stats.clone()),
        error_files: defaults.map_or_else(HashMap::new, |d| d.error_files.clone()),
        error_replies: defaults.map_or_else(HashMap::new, |d| d.error_replies.clone()),
    })
}

pub(crate) fn parse_backend_header(
    tokens: &[Token],
    kw: &Token,
    named_defaults: &HashMap<String, DefaultsSection>,
    current_defaults: Option<&DefaultsSection>,
) -> Result<BackendSection, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<backend> expects <id> as argument.",
        ));
    }

    let id = tokens[1].text.clone();
    let (defaults, rest_idx) = if tokens.len() >= 3 && tokens[2].text == "from" {
        if tokens.len() < 4 || tokens[3].text.is_empty() {
            return Err(ConfigError::new(tokens[2].line, tokens[2].col, "'from' expects a defaults section name".to_string()));
        }
        let def_name = &tokens[3].text;
        let def = named_defaults.get(def_name).ok_or_else(|| {
            ConfigError::new(tokens[3].line, tokens[3].col, format!("defaults section '{def_name}' not found for backend '{id}'."))
        })?;
        (Some(def), 4)
    } else {
        (current_defaults, 2)
    };

    if tokens.len() > rest_idx && !tokens[rest_idx].text.is_empty() {
        return Err(ConfigError::new(tokens[rest_idx].line, tokens[rest_idx].col, "unexpected extra argument in backend header".to_string()));
    }
    let mode = defaults.and_then(|d| d.mode).unwrap_or(Mode::Tcp);
    let timeouts = defaults.map_or_else(TimeoutConfig::default, |d| d.timeouts);

    Ok(BackendSection {
        httpchk: defaults.and_then(|d| d.httpchk.clone()),
        proto_check: defaults.and_then(|d| d.proto_check.clone()),
        http_checks: defaults.map_or_else(Vec::new, |d| d.http_checks.clone()),
        http_check_own: false,
        tcp_checks: defaults.map_or_else(Vec::new, |d| d.tcp_checks.clone()),
        tcp_check: defaults.is_some_and(|d| d.tcp_check),
        name: id,
        logs: defaults.map_or_else(Vec::new, |d| d.logs.clone()),
        log_tag: defaults.and_then(|d| d.log_tag.clone()),
        log_global: defaults.map_or(false, |d| d.log_global),
        log_format: defaults.and_then(|d| d.log_format.clone()),
        unique_id_format: defaults.and_then(|d| d.unique_id_format.clone()),
        unique_id_header: defaults.and_then(|d| d.unique_id_header.clone()),
        log_health_checks: defaults.map_or(false, |d| d.log_health_checks),
        buffer_request: defaults.is_some_and(|d| d.buffer_request),
        abortonclose: defaults.and_then(|d| d.abortonclose),
        h1_adjust: defaults.map_or(0, |d| d.h1_adjust & crate::ast::H1_ADJ_SERVER),
        http_mode: defaults.map_or(HttpMode::KeepAlive, |d| d.http_mode),
        persist: defaults.is_some_and(|d| d.persist),
        mode,
        disabled: false,
        id: None,
        description: None,
        balance: defaults.and_then(|d| d.balance).unwrap_or(BalanceAlgorithm::RoundRobin),
        cookie: defaults.and_then(|d| d.cookie.clone()),
        contimeout: timeouts.connect,
        srvtimeout: timeouts.server,
        timeouts,
        retries: defaults.and_then(|d| d.retries).unwrap_or(3),
        retry_on: defaults.and_then(|d| d.retry_on).unwrap_or(crate::ast::RE_CONN_FAILED),
        redisp: defaults.map_or(false, |d| d.redisp),
        redisp_after: defaults.map_or(-1, |d| if d.redisp { d.redisp_after } else { -1 }),
        dispatch: None,
        default_server: defaults.and_then(|d| d.default_server.clone()),
        use_servers: Vec::new(),
        servers: Vec::new(),
        server_extras: ServerExtras::default(),
        srvexp: Vec::new(),
        acls: Vec::new(),
        stick_table: None,
        stick_rules: Vec::new(),
        tcp_req_inspect_delay: defaults.and_then(|d| d.tcp_req_inspect_delay),
        tcp_req_content_rules: defaults.map_or_else(Vec::new, |d| d.tcp_req_content_rules.clone()),
        tcp_res_inspect_delay: defaults.and_then(|d| d.tcp_res_inspect_delay),
        tcp_res_content_rules: defaults.map_or_else(Vec::new, |d| d.tcp_res_content_rules.clone()),
        http_req_rules: defaults.map_or_else(Vec::new, |d| d.http_req_rules.clone()),
        http_res_rules: defaults.map_or_else(Vec::new, |d| d.http_res_rules.clone()),
        http_after_res_rules: defaults.map_or_else(Vec::new, |d| d.http_after_res_rules.clone()),
        http_reuse: defaults.and_then(|d| d.http_reuse),
        hash_type: defaults.and_then(|d| d.hash_type),
        hash_preserve_affinity: defaults.and_then(|d| d.hash_preserve_affinity),
        forwardfor: defaults.and_then(|d| d.forwardfor.clone()),
        forwardfor_if_none: defaults.is_some_and(|d| d.forwardfor_if_none),
        forwarded: defaults.and_then(|d| d.forwarded.clone()),
        originalto: defaults.and_then(|d| d.originalto.clone()),
        stats: defaults.map_or_else(StatsConfig::default, |d| d.stats.clone()),
        error_files: defaults.map_or_else(HashMap::new, |d| d.error_files.clone()),
        error_replies: defaults.map_or_else(HashMap::new, |d| d.error_replies.clone()),
    })
}

/// `id <n>` in a proxy section (`cfg_parse_listen`, `src/cfgparse-listen.c`). `HAProxy`
/// reads it with `atol` into an `int`, so anything that does not come out above zero,
/// words and values past `i32::MAX` included, is "custom id has to be > 0".
fn parse_proxy_id(id: &mut Option<u32>, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    let Some(arg) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
        return Err(ConfigError::new(kw.line, kw.col, "'id' expects an integer argument."));
    };
    let digits: String = arg.text.trim_start().chars().take_while(char::is_ascii_digit).collect();
    // `atol`, then the `int` it is stored in.
    let value = digits.parse::<i64>().map_or(0, |v| i64::from(v as i32));
    if value <= 0 {
        return Err(ConfigError::new(arg.line, arg.col, "custom id has to be > 0."));
    }
    *id = u32::try_from(value).ok();
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_listen_directive(
    proxy: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "mode" => parse_mode(&mut proxy.mode, tokens, kw),
        "description" => {
            proxy.description = Some(super::global::parse_description(tokens, kw)?);
            Ok(())
        }
        "disabled" => {
            proxy.disabled = true;
            Ok(())
        }
        "id" => parse_proxy_id(&mut proxy.id, tokens, kw),
        "cookie" => parse_cookie(&mut proxy.cookie, tokens, kw),
        "contimeout" => parse_contimeout(kw),
        "clitimeout" => parse_clitimeout(kw),
        "srvtimeout" => parse_srvtimeout(kw),
        "timeout" => parse_timeout_directive(&mut proxy.timeouts, tokens, kw),
        "retries" => parse_retries(&mut proxy.retries, tokens, kw),
        "retry-on" => super::parse_retry_on(&mut proxy.retry_on, tokens, kw),
        "redisp" => parse_redisp(kw),
        "maxconn" => parse_maxconn(&mut proxy.maxconn, tokens, kw),
        "grace" => parse_grace(kw),
        "dispatch" => parse_dispatch(kw),
        "default-server" => parse_default_server(&mut proxy.default_server, tokens, kw),
        "server" => parse_server(
            &mut proxy.servers,
            &mut proxy.server_extras,
            proxy.default_server.as_ref(),
            tokens,
            kw,
        ),
        "log" => parse_log(&mut proxy.logs, tokens, kw).map(|g| proxy.log_global |= g),
        "log-tag" => parse_log_tag(tokens, kw).map(|t| proxy.log_tag = Some(t)),
        "cliexp" => parse_cliexp(kw),
        "srvexp" => parse_srvexp(kw),
        "balance" => parse_balance(&mut proxy.balance, tokens, kw),
        "http-reuse" => parse_http_reuse(&mut proxy.http_reuse, tokens, kw),
        "hash-type" => {
            let mut ht = proxy.hash_type.unwrap_or_default();
            parse_hash_type(&mut ht, tokens, kw)?;
            proxy.hash_type = Some(ht);
            Ok(())
        }
        "hash-preserve-affinity" => {
            let mut a = proxy.hash_preserve_affinity.unwrap_or_default();
            parse_hash_preserve_affinity(&mut a, tokens, kw)?;
            proxy.hash_preserve_affinity = Some(a);
            Ok(())
        }
        "acl" => parse_acl(&mut proxy.acls, tokens, kw),
        "use_backend" => parse_use_backend(&mut proxy.use_backends, tokens, kw),
        "use-server" => parse_use_server(&mut proxy.use_servers, tokens, kw),
        "force-be-switch" => parse_force_be_switch(&mut proxy.force_be_switch, tokens, kw),
        "monitor-uri" => parse_monitor_uri(&mut proxy.monitor_uri, tokens, kw),
        "default_backend" => parse_default_backend(&mut proxy.default_backend, tokens, kw),
        "option" => parse_option_listen(proxy, tokens, kw),
        "no" => parse_no_listen(proxy, tokens, kw),
        "declare" if tokens.get(1).is_some_and(|t| t.text == "capture") => {
            let rule_slots = rule_capture_slots(&proxy.http_req_rules);
            parse_declare_capture(&mut proxy.req_header_captures, &mut proxy.res_header_captures, rule_slots, tokens, kw)
        }
        "declare" => parse_declare(tokens, kw),
        "bind" => parse_listen_bind(proxy, tokens, kw),
        "stick-table" => parse_stick_table(&mut proxy.stick_table, tokens, kw),
        "stick" => parse_stick_rule(&mut proxy.stick_rules, tokens, kw),
        "track-sc0" | "track-sc1" | "track-sc2" => {
            parse_track_rule(&mut proxy.stick_rules, tokens, kw)
        }
        "tcp-request" => parse_listen_tcp_request(proxy, tokens, kw),
        "http-request" => in_section(parse_http_req_rule(&mut proxy.http_req_rules, tokens, kw), "proxy", &proxy.name),
        "http-response" => in_section(parse_http_res_rule(&mut proxy.http_res_rules, tokens, kw), "proxy", &proxy.name),
        "http-after-response" => {
            in_section(parse_http_after_res_rule(&mut proxy.http_after_res_rules, tokens, kw), "proxy", &proxy.name)
        }
        "stats" => parse_stats_directive(&mut proxy.stats, tokens, kw),
        "http-check" => {
            take_own_http_check(&mut proxy.http_check_own, &mut proxy.httpchk, &mut proxy.http_checks);
            parse_http_check_directive(&mut proxy.http_checks, tokens, kw)?;
            Ok(())
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
                    proxy.tcp_res_inspect_delay = Some(parse_inspect_delay(&tokens[2], "response", "proxy", &proxy.name)?);
                    Ok(())
                }
                "content" => parse_tcp_res_content(&mut proxy.tcp_res_content_rules, tokens, kw),
                other => Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("unknown tcp-response subcommand <{other}>, expects 'inspect-delay' or 'content'"),
                )),
            }
        }
        "tcp-check" => {
            parse_tcp_check_directive(&mut proxy.tcp_checks, tokens, kw)?;
            Ok(())
        }
        "errorfile" | "errorfiles" | "http-error" | "errorloc" | "errorloc302" | "errorloc303" => {
            parse_proxy_error_page(&mut proxy.error_files, &mut proxy.error_replies, tokens, kw)
        }
        "log-format" => {
            proxy.log_format = Some(LogFormatSpec::Custom(parse_format_arg(tokens, kw)?));
            Ok(())
        }
        "log-format-sd" => Err(ConfigError::new(kw.line, kw.col, "'log-format-sd' is not implemented".to_string())),
        "unique-id-format" => {
            proxy.unique_id_format = Some(parse_format_arg(tokens, kw)?);
            Ok(())
        }
        "unique-id-header" => match tokens.get(1) {
            Some(t) => {
                proxy.unique_id_header = Some(t.text.clone());
                Ok(())
            }
            None => Err(ConfigError::new(kw.line, kw.col, "unique-id-header expects an argument.".to_string())),
        },
        "capture" => {
            let rule_slots = rule_capture_slots(&proxy.http_req_rules);
            parse_capture(&mut proxy.req_header_captures, &mut proxy.res_header_captures, rule_slots, tokens, kw)
        }
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{other}' in 'listen' section"),
        )),
    }
}

pub(crate) fn parse_frontend_directive(
    fe: &mut FrontendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "bind" => parse_frontend_bind(fe, tokens, kw),
        // `HAProxy` checks the line, warns, and runs without it: persistence is the
        // backend's (`warnifnotcap(curproxy, PR_CAP_BE, ...)`).
        "cookie" => {
            parse_cookie(&mut None, tokens, kw)?;
            eprintln!(
                "[ibex] warning: line {}: 'cookie' ignored because frontend '{}' has no backend capability.",
                kw.line, fe.name
            );
            Ok(())
        }
        "tcp-request" => parse_frontend_tcp_request(fe, tokens, kw),
        // `stream_parse_set_retries`: a retry budget belongs to a backend.
        "http-request" if tokens.get(1).is_some_and(|t| t.text == "set-retries") => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            "'set-retries' only available in backend or listen section",
        )),
        "http-request" => in_section(
            parse_http_req_rule(&mut fe.http_req_rules, tokens, kw)
                .and_then(|()| set_timeout_sides(&fe.http_req_rules, kw, &fe.name, true, false)),
            "frontend",
            &fe.name,
        ),
        "http-response" => in_section(parse_http_res_rule(&mut fe.http_res_rules, tokens, kw), "frontend", &fe.name),
        "http-after-response" => {
            in_section(parse_http_after_res_rule(&mut fe.http_after_res_rules, tokens, kw), "frontend", &fe.name)
        }
        "mode" => parse_mode(&mut fe.mode, tokens, kw),
        "description" => {
            fe.description = Some(super::global::parse_description(tokens, kw)?);
            Ok(())
        }
        "id" => parse_proxy_id(&mut fe.id, tokens, kw),
        "disabled" => {
            fe.disabled = true;
            Ok(())
        }
        "option" => parse_option_frontend(fe, tokens, kw),
        "no" => parse_no_frontend(fe, tokens, kw),
        "declare" if tokens.get(1).is_some_and(|t| t.text == "capture") => {
            let rule_slots = rule_capture_slots(&fe.http_req_rules);
            parse_declare_capture(&mut fe.req_header_captures, &mut fe.res_header_captures, rule_slots, tokens, kw)
        }
        "declare" => parse_declare(tokens, kw),
        "clitimeout" => parse_clitimeout(kw),
        "contimeout" => parse_contimeout(kw),
        "srvtimeout" => parse_srvtimeout(kw),
        "dispatch" => parse_dispatch(kw),
        "grace" => parse_grace(kw),
        "cliexp" => parse_cliexp(kw),
        "srvexp" => parse_srvexp(kw),
        "timeout" => parse_timeout_directive(&mut fe.timeouts, tokens, kw),
        "maxconn" => parse_maxconn(&mut fe.maxconn, tokens, kw),
        "log" => parse_log(&mut fe.logs, tokens, kw).map(|g| fe.log_global |= g),
        "log-tag" => parse_log_tag(tokens, kw).map(|t| fe.log_tag = Some(t)),
        "acl" => parse_acl(&mut fe.acls, tokens, kw),
        "use_backend" => parse_use_backend(&mut fe.use_backends, tokens, kw),
        "force-be-switch" => parse_force_be_switch(&mut fe.force_be_switch, tokens, kw),
        // `HAProxy` warns that a frontend has no backend capability and keeps the rule,
        // then fails the load because the frontend has no server by that name.
        "use-server" => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!(
                "frontend '{}' : unable to find server '{}' referenced in a 'use-server' rule.",
                fe.name,
                tokens.get(1).map_or("", |t| t.text.as_str())
            ),
        )),
        "monitor-uri" => parse_monitor_uri(&mut fe.monitor_uri, tokens, kw),
        "default_backend" => parse_default_backend(&mut fe.default_backend, tokens, kw),
        "stick-table" => parse_stick_table(&mut fe.stick_table, tokens, kw),
        // A frontend has no backend capability: `HAProxy` warns and ignores the line.
        "stick" => {
            eprintln!("[ibex] warning: 'stick' ignored because frontend '{}' has no backend capability.", fe.name);
            Ok(())
        }
        "track-sc0" | "track-sc1" | "track-sc2" => {
            parse_track_rule(&mut fe.stick_rules, tokens, kw)
        }
        "stats" => parse_stats_directive(&mut fe.stats, tokens, kw),
        "http-check" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                "'http-check' is not supported in frontend",
            ))
        }
        "errorfile" | "errorfiles" | "http-error" | "errorloc" | "errorloc302" | "errorloc303" => {
            parse_proxy_error_page(&mut fe.error_files, &mut fe.error_replies, tokens, kw)
        }
        "log-format" => {
            fe.log_format = Some(LogFormatSpec::Custom(parse_format_arg(tokens, kw)?));
            Ok(())
        }
        "log-format-sd" => Err(ConfigError::new(kw.line, kw.col, "'log-format-sd' is not implemented".to_string())),
        "unique-id-format" => {
            fe.unique_id_format = Some(parse_format_arg(tokens, kw)?);
            Ok(())
        }
        "unique-id-header" => match tokens.get(1) {
            Some(t) => {
                fe.unique_id_header = Some(t.text.clone());
                Ok(())
            }
            None => Err(ConfigError::new(kw.line, kw.col, "unique-id-header expects an argument.".to_string())),
        },
        "capture" => {
            let rule_slots = rule_capture_slots(&fe.http_req_rules);
            parse_capture(&mut fe.req_header_captures, &mut fe.res_header_captures, rule_slots, tokens, kw)
        }
        "retry-on" => Err(ConfigError::new(kw.line, kw.col, "'retry-on' only available in backend or listen section")),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{other}' in 'frontend' section"),
        )),
    }
}

pub(crate) fn parse_backend_directive(
    be: &mut BackendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "mode" => parse_mode(&mut be.mode, tokens, kw),
        "description" => {
            be.description = Some(super::global::parse_description(tokens, kw)?);
            Ok(())
        }
        "id" => parse_proxy_id(&mut be.id, tokens, kw),
        "disabled" => {
            be.disabled = true;
            Ok(())
        }
        "use-server" => parse_use_server(&mut be.use_servers, tokens, kw),
        "balance" => parse_balance(&mut be.balance, tokens, kw),
        "http-reuse" => parse_http_reuse(&mut be.http_reuse, tokens, kw),
        "hash-type" => {
            let mut ht = be.hash_type.unwrap_or_default();
            parse_hash_type(&mut ht, tokens, kw)?;
            be.hash_type = Some(ht);
            Ok(())
        }
        "hash-preserve-affinity" => {
            let mut a = be.hash_preserve_affinity.unwrap_or_default();
            parse_hash_preserve_affinity(&mut a, tokens, kw)?;
            be.hash_preserve_affinity = Some(a);
            Ok(())
        }
        "cookie" => parse_cookie(&mut be.cookie, tokens, kw),
        "contimeout" => parse_contimeout(kw),
        "clitimeout" => parse_clitimeout(kw),
        "srvtimeout" => parse_srvtimeout(kw),
        "timeout" => parse_timeout_directive(&mut be.timeouts, tokens, kw),
        "retries" => parse_retries(&mut be.retries, tokens, kw),
        "retry-on" => super::parse_retry_on(&mut be.retry_on, tokens, kw),
        "redisp" => parse_redisp(kw),
        "dispatch" => parse_dispatch(kw),
        "default-server" => parse_default_server(&mut be.default_server, tokens, kw),
        "server" => parse_server(&mut be.servers, &mut be.server_extras, be.default_server.as_ref(), tokens, kw),
        "tcp-request" => parse_backend_tcp_request(be, tokens, kw),
        "http-request" => in_section(
            parse_http_req_rule(&mut be.http_req_rules, tokens, kw)
                .and_then(|()| set_timeout_sides(&be.http_req_rules, kw, &be.name, false, true)),
            "backend",
            &be.name,
        ),
        "http-response" => in_section(parse_http_res_rule(&mut be.http_res_rules, tokens, kw), "backend", &be.name),
        "http-after-response" => {
            in_section(parse_http_after_res_rule(&mut be.http_after_res_rules, tokens, kw), "backend", &be.name)
        }
        "option" => parse_option_backend(be, tokens, kw),
        "no" => parse_no_backend(be, tokens, kw),
        "declare" => refuse_declare(DeclareIn::Backend, kw),
        "grace" => parse_grace(kw),
        "cliexp" => parse_cliexp(kw),
        "srvexp" => parse_srvexp(kw),
        "acl" => parse_acl(&mut be.acls, tokens, kw),
        "stick-table" => parse_stick_table(&mut be.stick_table, tokens, kw),
        "stick" => parse_stick_rule(&mut be.stick_rules, tokens, kw),
        "track-sc0" | "track-sc1" | "track-sc2" => {
            parse_track_rule(&mut be.stick_rules, tokens, kw)
        }
        "stats" => parse_stats_directive(&mut be.stats, tokens, kw),
        // `log` is valid in every proxy section, backends included. It was wired for
        // global, listen and frontend but not here, which alone blocked 19 reg-tests
        // -- the health-check suites all declare their syslog target on the backend.
        "log" => parse_log(&mut be.logs, tokens, kw).map(|g| be.log_global |= g),
        "log-tag" => parse_log_tag(tokens, kw).map(|t| be.log_tag = Some(t)),
        "http-check" => {
            take_own_http_check(&mut be.http_check_own, &mut be.httpchk, &mut be.http_checks);
            parse_http_check_directive(&mut be.http_checks, tokens, kw)?;
            Ok(())
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
                    be.tcp_res_inspect_delay = Some(parse_inspect_delay(&tokens[2], "response", "proxy", &be.name)?);
                    Ok(())
                }
                "content" => parse_tcp_res_content(&mut be.tcp_res_content_rules, tokens, kw),
                other => Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("unknown tcp-response subcommand <{other}>, expects 'inspect-delay' or 'content'"),
                )),
            }
        }
        "tcp-check" => {
            parse_tcp_check_directive(&mut be.tcp_checks, tokens, kw)?;
            Ok(())
        }
        "errorfile" | "errorfiles" | "http-error" | "errorloc" | "errorloc302" | "errorloc303" => {
            parse_proxy_error_page(&mut be.error_files, &mut be.error_replies, tokens, kw)
        }
        // Ignored in backends, as `HAProxy` ignores it ("'log-format' directive is ignored
        // in backends"): a backend's transactions log through their frontend.
        "log-format" => parse_format_arg(tokens, kw).map(|_| ()),
        "log-format-sd" => Err(ConfigError::new(kw.line, kw.col, "'log-format-sd' is not implemented".to_string())),
        "unique-id-format" => {
            be.unique_id_format = Some(parse_format_arg(tokens, kw)?);
            Ok(())
        }
        "unique-id-header" => match tokens.get(1) {
            Some(t) => {
                be.unique_id_header = Some(t.text.clone());
                Ok(())
            }
            None => Err(ConfigError::new(kw.line, kw.col, "unique-id-header expects an argument.".to_string())),
        },
        // `HAProxy`: "'capture' ignored because backend has no frontend capability".
        "capture" => parse_capture(&mut Vec::new(), &mut Vec::new(), 0, tokens, kw),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{other}' in 'backend' section"),
        )),
    }
}

/// Parses one `bind` line of a `listen` or a `frontend` (`section` names which, for the
/// messages): the address, then the keywords. Both sections share this, so a keyword is
/// honoured or refused the same way in either (T110).
///
/// A keyword Ibex handles is read here; every other one goes to
/// `bind_keywords::unimplemented_bind_keyword`, which refuses it (or an unknown one, as
/// `HAProxy` does): a keyword that is accepted must reach the data path.
pub(crate) fn parse_bind(tokens: &[Token], kw: &Token, section: &str) -> Result<BindConfig, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<bind> expects <addr:port> as argument.",
        ));
    }
    let (addr, quic) = parse_socket_addr(&tokens[1], None)?;
    let mut bind = BindConfig {
        sock: None,
        line: kw.line,
        addr,
        quic,
        ssl: false,
        crt: Vec::new(),
        alpn: Vec::new(),
        proto: None,
        accept_proxy: false,
        accept_proxy_v2: false,
        name: None,
        id: None,
        min_ver: None,
        max_ver: None,
    };
    let prefix = format!("'bind {}' in section '{section}'", tokens[1].text);
    let arg = |i: usize, what: &str| -> Result<&Token, ConfigError> {
        tokens.get(i + 1).filter(|t| !t.text.is_empty()).ok_or_else(|| {
            ConfigError::new(tokens[i].line, tokens[i].col, format!("{prefix} : '{}' : {what}", tokens[i].text))
        })
    };

    let mut versions = super::tls_versions::TlsRange::default();
    let mut i = 2;
    while i < tokens.len() {
        if let Some(last) = super::tls_versions::version_keyword(&mut versions, tokens, i, &prefix)? {
            i = last + 1;
            continue;
        }
        match tokens[i].text.as_str() {
            "ssl" => bind.ssl = true,
            "crt" => {
                bind.crt.push(arg(i, "missing certificate location")?.text.clone());
                i += 1;
            }
            "alpn" => {
                bind.alpn = arg(i, "missing ALPN protocol list")?
                    .text
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                i += 1;
            }
            "proto" => {
                bind.proto = Some(arg(i, "missing protocol name")?.text.clone());
                i += 1;
            }
            "name" => {
                bind.name = Some(arg(i, "missing name")?.text.clone());
                i += 1;
            }
            "id" => {
                let a = arg(i, "expects an integer argument")?;
                let value = a.text.parse::<i64>().map_err(|_| {
                    ConfigError::new(a.line, a.col, format!("{prefix} : 'id' : expects an integer argument, found '{}'", a.text))
                })?;
                if value <= 0 || value > i64::from(i32::MAX) {
                    return Err(ConfigError::new(a.line, a.col, format!("{prefix} : 'id' : custom id has to be > 0")));
                }
                bind.id = u32::try_from(value).ok();
                i += 1;
            }
            "accept-proxy" => bind.accept_proxy = true,
            "accept-proxy-v2" => {
                bind.accept_proxy = true;
                bind.accept_proxy_v2 = true;
            }
            // Socket options: `Listener::bind_tuned` applies them to the listening socket.
            "backlog" => {
                let a = arg(i, "expects an integer argument")?;
                bind.sock.get_or_insert_with(Default::default).backlog = Some(a.text.parse::<u32>().map_err(|_| {
                    ConfigError::new(a.line, a.col, format!("{prefix} : 'backlog' : expects an integer argument, found '{}'", a.text))
                })?);
                i += 1;
            }
            "v6only" => bind.sock.get_or_insert_with(Default::default).v6only = Some(true),
            "v4v6" => bind.sock.get_or_insert_with(Default::default).v6only = Some(false),
            "tcp-ut" => {
                let a = arg(i, "expects a delay as argument")?;
                bind.sock.get_or_insert_with(Default::default).tcp_user_timeout = Some(parse_timeout(a, "tcp-ut")?);
                i += 1;
            }
            "mss" => {
                let a = arg(i, "missing MSS value")?;
                let v = a.text.parse::<i64>().unwrap_or(0).unsigned_abs();
                if !(1..=65535).contains(&v) {
                    return Err(ConfigError::new(
                        a.line,
                        a.col,
                        format!("{prefix} : 'mss' : expects an MSS with and absolute value between 1 and 65535"),
                    ));
                }
                bind.sock.get_or_insert_with(Default::default).mss = u32::try_from(v).ok();
                i += 1;
            }
            "cc" => {
                bind.sock.get_or_insert_with(Default::default).congestion = Some(arg(i, "expects a congestion control algorithm")?.text.clone());
                i += 1;
            }
            // Threads are not numbered in Ibex: the kernel spreads connections over the
            // workers (`SO_REUSEPORT`). `thread all` is what that already does.
            "thread" => {
                let a = arg(i, "expects a thread set")?;
                if a.text != "all" {
                    return Err(ConfigError::new(
                        a.line,
                        a.col,
                        format!("{prefix} : 'thread' : only 'thread all' is supported by Ibex, found '{}'", a.text),
                    ));
                }
                i += 1;
            }
            _ => return Err(super::bind_keywords::unimplemented_bind_keyword(tokens, i, section)),
        }
        i += 1;
    }
    if versions.is_empty() {
        return Err(ConfigError::new(kw.line, kw.col, format!("all SSL/TLS versions are disabled for bind '{}'.", tokens[1].text)));
    }
    bind.min_ver = versions.min;
    bind.max_ver = versions.max;
    Ok(bind)
}

/// `bind_parse_id`: a listener id may be given once in a proxy.
fn check_bind_id(binds: &[BindConfig], bind: &BindConfig, kw: &Token, section: &str) -> Result<(), ConfigError> {
    let Some(id) = bind.id else { return Ok(()) };
    if let Some(other) = binds.iter().find(|b| b.id == Some(id)) {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            format!(
                "'bind {}' in section '{section}' : 'id' : custom id {id} already used by 'bind {}'",
                bind.addr, other.addr
            ),
        ));
    }
    Ok(())
}

pub(crate) fn parse_listen_bind(
    proxy: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let bind = parse_bind(tokens, kw, "listen")?;
    if bind.quic {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "QUIC is not supported in listen sections".to_string(),
        ));
    }
    if proxy.binds.is_empty() {
        proxy.addr = bind.addr;
    }
    check_bind_id(&proxy.binds, &bind, kw, "listen")?;
    proxy.accept_proxy |= bind.accept_proxy;
    proxy.accept_proxy_v2 |= bind.accept_proxy_v2;
    proxy.binds.push(bind);
    Ok(())
}

pub(crate) fn parse_frontend_bind(
    fe: &mut FrontendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let mut bind = parse_bind(tokens, kw, "frontend")?;
    if fe.bind.is_none() {
        fe.bind = Some(bind.addr);
    }
    fe.accept_proxy |= bind.accept_proxy;
    fe.accept_proxy_v2 |= bind.accept_proxy_v2;

    if bind.quic && !bind.ssl {
        return Err(ConfigError::new(kw.line, kw.col, "QUIC protocol detected, enabling ssl. Use 'ssl' to shut this warning. Proxy no SSL certificate specified for bind (use 'crt')".to_string()));
    }
    if bind.quic && bind.alpn.is_empty() {
        bind.alpn.push("h3".to_string());
    }
    check_bind_id(&fe.binds, &bind, kw, "frontend")?;
    fe.binds.push(bind);
    Ok(())
}

pub(crate) fn parse_option_listen(
    proxy: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    // `option httplog`/`tcplog` (and `clf`) are the log format (T53), ahead of the option
    // table: the table would otherwise warn and drop them.
    if let Some(spec) = parse_log_option(tokens, kw) {
        proxy.log_format = Some(spec?);
        return Ok(());
    }
    if !check_option(OptSection::Listen, tokens, kw)? {
        return Ok(());
    }
    match tokens[1].text.as_str() {
        "forwardfor" => {
            let (except, if_none) = parse_forward_option(tokens, kw)?;
            proxy.forwardfor = Some(except);
            proxy.forwardfor_if_none = if_none;
        }
        "originalto" => proxy.originalto = Some(parse_forward_option(tokens, kw)?.0),
        "forwarded" => proxy.forwarded = Some(Box::new(parse_forwarded_option(tokens)?)),
        "redispatch" => set_redispatch(&mut proxy.redisp, &mut proxy.redisp_after, tokens),
        "http-buffer-request" => proxy.buffer_request = true,
        "abortonclose" => proxy.abortonclose = Some(true),
        "http-server-close" => proxy.http_mode = HttpMode::ServerClose,
        "httpclose" => proxy.http_mode = HttpMode::Close,
        "persist" => proxy.persist = true,
        "http-keep-alive" => proxy.http_mode = HttpMode::KeepAlive,
        "dontlognull" => proxy.dontlognull = true,
        "http-ignore-probes" => proxy.http_ignore_probes = true,
        "h1-case-adjust-bogus-client" => proxy.h1_adjust |= crate::ast::H1_ADJ_CLIENT,
        "h1-case-adjust-bogus-server" => proxy.h1_adjust |= crate::ast::H1_ADJ_SERVER,
        "dontlog-normal" | "log-separate-errors" | "logasap" => proxy.log_opts |= crate::ast::log_opt_bit(&tokens[1].text),
        "accept-unsafe-violations-in-http-request" => proxy.stats.accept_unsafe_request = true,
        "accept-unsafe-violations-in-http-response" | "accept-invalid-http-response" => {
            proxy.stats.accept_unsafe_response = true;
        }
        "log-health-checks" => proxy.log_health_checks = true,
        "httpchk" => {
            take_own_http_check(&mut proxy.http_check_own, &mut proxy.httpchk, &mut proxy.http_checks);
            parse_httpchk_option(&mut proxy.httpchk, tokens, kw)?;
        }
        "tcp-check" => proxy.tcp_check = true,
        _ => {
            parse_proto_check_option(&mut proxy.proto_check, tokens, kw)?;
        }
    }
    Ok(())
}

pub(crate) fn parse_option_frontend(
    fe: &mut FrontendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    // `option httplog`/`tcplog` (and `clf`) are the log format (T53), ahead of the option
    // table: the table would otherwise warn and drop them.
    if let Some(spec) = parse_log_option(tokens, kw) {
        fe.log_format = Some(spec?);
        return Ok(());
    }
    if !check_option(OptSection::Frontend, tokens, kw)? {
        return Ok(());
    }
    // The options a frontend implements are `forwardfor`, `originalto` and
    // `accept-unsafe-violations-in-http-request`; every other one `check_option` lets
    // through needs a backend, and was warned about there.
    if tokens[1].text == "accept-unsafe-violations-in-http-request" {
        fe.stats.accept_unsafe_request = true;
        return Ok(());
    }
    if tokens[1].text == "http-buffer-request" {
        fe.buffer_request = true;
        return Ok(());
    }
    if tokens[1].text == "abortonclose" {
        // A frontend's own `abortonclose` decides only whether a TLS handshake goes on once
        // the client has shut its side (`ssl_sock_to_buf`); Ibex does not look (T227).
        eprintln!("[ibex] warning: 'option abortonclose' in a frontend is not implemented and is ignored.");
        return Ok(());
    }
    if matches!(tokens[1].text.as_str(), "http-server-close" | "http-keep-alive" | "httpclose") {
        fe.http_mode = match tokens[1].text.as_str() {
            "http-server-close" => HttpMode::ServerClose,
            "httpclose" => HttpMode::Close,
            _ => HttpMode::KeepAlive,
        };
        return Ok(());
    }
    if tokens[1].text == "dontlognull" {
        fe.dontlognull = true;
        return Ok(());
    }
    if tokens[1].text == "http-ignore-probes" {
        fe.http_ignore_probes = true;
        return Ok(());
    }
    if tokens[1].text == "h1-case-adjust-bogus-client" {
        fe.h1_adjust |= crate::ast::H1_ADJ_CLIENT;
        return Ok(());
    }
    if matches!(tokens[1].text.as_str(), "dontlog-normal" | "log-separate-errors" | "logasap") {
        fe.log_opts |= crate::ast::log_opt_bit(&tokens[1].text);
        return Ok(());
    }
    let (except, if_none) = parse_forward_option(tokens, kw)?;
    if tokens[1].text == "forwardfor" {
        fe.forwardfor = Some(except);
        fe.forwardfor_if_none = if_none;
    } else {
        fe.originalto = Some(except);
    }
    Ok(())
}

pub(crate) fn parse_option_backend(
    be: &mut BackendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    // Parsed (an error in it is still an error) and ignored in backends, as `HAProxy`
    // ignores it ("'option httplog' directive is ignored in backends").
    if let Some(spec) = parse_log_option(tokens, kw) {
        // `httpslog` too: refused where it would take effect, ignored here like the rest.
        return if tokens[1].text == "httpslog" { Ok(()) } else { spec.map(|_| ()) };
    }
    if !check_option(OptSection::Backend, tokens, kw)? {
        return Ok(());
    }
    match tokens[1].text.as_str() {
        "forwardfor" => {
            let (except, if_none) = parse_forward_option(tokens, kw)?;
            be.forwardfor = Some(except);
            be.forwardfor_if_none = if_none;
        }
        "originalto" => be.originalto = Some(parse_forward_option(tokens, kw)?.0),
        "forwarded" => be.forwarded = Some(Box::new(parse_forwarded_option(tokens)?)),
        "redispatch" => set_redispatch(&mut be.redisp, &mut be.redisp_after, tokens),
        "http-buffer-request" => be.buffer_request = true,
        "abortonclose" => be.abortonclose = Some(true),
        "http-server-close" => be.http_mode = HttpMode::ServerClose,
        "httpclose" => be.http_mode = HttpMode::Close,
        "persist" => be.persist = true,
        "h1-case-adjust-bogus-server" => be.h1_adjust |= crate::ast::H1_ADJ_SERVER,
        "http-keep-alive" => be.http_mode = HttpMode::KeepAlive,
        "accept-unsafe-violations-in-http-response" | "accept-invalid-http-response" => {
            be.stats.accept_unsafe_response = true;
        }
        "log-health-checks" => be.log_health_checks = true,
        "httpchk" => {
            take_own_http_check(&mut be.http_check_own, &mut be.httpchk, &mut be.http_checks);
            parse_httpchk_option(&mut be.httpchk, tokens, kw)?;
        }
        "tcp-check" => be.tcp_check = true,
        _ => {
            parse_proto_check_option(&mut be.proto_check, tokens, kw)?;
        }
    }
    Ok(())
}

/// `no option <name>` in a proxy section: turns off an option this section inherited.
pub(crate) fn parse_no_listen(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.get(1).is_some_and(|t| t.text == "log") {
        proxy.logs.clear();
        proxy.log_global = false;
        return Ok(());
    }
    if tokens.get(1).is_none_or(|t| t.text != "option") {
        return parse_no_directive(tokens, kw);
    }
    match check_no_option(OptSection::Listen, tokens, kw)? {
        Some("redispatch") => (proxy.redisp, proxy.redisp_after) = (false, -1),
        Some("http-buffer-request") => proxy.buffer_request = false,
        Some("abortonclose") => proxy.abortonclose = Some(false),
        Some("http-server-close") if proxy.http_mode == HttpMode::ServerClose => proxy.http_mode = HttpMode::KeepAlive,
        Some("httpclose") if proxy.http_mode == HttpMode::Close => proxy.http_mode = HttpMode::KeepAlive,
        Some("persist") => proxy.persist = false,
        Some("dontlognull") => proxy.dontlognull = false,
        Some("http-ignore-probes") => proxy.http_ignore_probes = false,
        Some("h1-case-adjust-bogus-client") => proxy.h1_adjust &= !crate::ast::H1_ADJ_CLIENT,
        Some("h1-case-adjust-bogus-server") => proxy.h1_adjust &= !crate::ast::H1_ADJ_SERVER,
        Some(n @ ("dontlog-normal" | "log-separate-errors" | "logasap")) => proxy.log_opts &= !crate::ast::log_opt_bit(n),
        Some("accept-unsafe-violations-in-http-request") => proxy.stats.accept_unsafe_request = false,
        Some("accept-unsafe-violations-in-http-response") => proxy.stats.accept_unsafe_response = false,
        Some("log-health-checks") => proxy.log_health_checks = false,
        Some("forwarded") => proxy.forwarded = None,
        _ => {}
    }
    Ok(())
}

pub(crate) fn parse_no_frontend(fe: &mut FrontendSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.get(1).is_some_and(|t| t.text == "log") {
        fe.logs.clear();
        fe.log_global = false;
        return Ok(());
    }
    if tokens.get(1).is_none_or(|t| t.text != "option") {
        return parse_no_directive(tokens, kw);
    }
    match check_no_option(OptSection::Frontend, tokens, kw)? {
        Some("accept-unsafe-violations-in-http-request") => fe.stats.accept_unsafe_request = false,
        Some("http-buffer-request") => fe.buffer_request = false,
        Some("http-server-close") if fe.http_mode == HttpMode::ServerClose => fe.http_mode = HttpMode::KeepAlive,
        Some("httpclose") if fe.http_mode == HttpMode::Close => fe.http_mode = HttpMode::KeepAlive,
        Some("dontlognull") => fe.dontlognull = false,
        Some("http-ignore-probes") => fe.http_ignore_probes = false,
        Some("h1-case-adjust-bogus-client") => fe.h1_adjust &= !crate::ast::H1_ADJ_CLIENT,
        Some(n @ ("dontlog-normal" | "log-separate-errors" | "logasap")) => fe.log_opts &= !crate::ast::log_opt_bit(n),
        _ => {}
    }
    Ok(())
}

pub(crate) fn parse_no_backend(be: &mut BackendSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.get(1).is_some_and(|t| t.text == "log") {
        be.logs.clear();
        be.log_global = false;
        return Ok(());
    }
    if tokens.get(1).is_none_or(|t| t.text != "option") {
        return parse_no_directive(tokens, kw);
    }
    match check_no_option(OptSection::Backend, tokens, kw)? {
        Some("redispatch") => (be.redisp, be.redisp_after) = (false, -1),
        Some("http-buffer-request") => be.buffer_request = false,
        Some("abortonclose") => be.abortonclose = Some(false),
        Some("http-server-close") if be.http_mode == HttpMode::ServerClose => be.http_mode = HttpMode::KeepAlive,
        Some("httpclose") if be.http_mode == HttpMode::Close => be.http_mode = HttpMode::KeepAlive,
        Some("persist") => be.persist = false,
        Some("h1-case-adjust-bogus-server") => be.h1_adjust &= !crate::ast::H1_ADJ_SERVER,
        Some("log-health-checks") => be.log_health_checks = false,
        Some("forwarded") => be.forwarded = None,
        Some("accept-unsafe-violations-in-http-response") => be.stats.accept_unsafe_response = false,
        _ => {}
    }
    Ok(())
}

/// `monitor-uri <uri>` (frontend and listen sections).
fn parse_monitor_uri(
    monitor_uri: &mut Option<String>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let Some(uri) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
        return Err(ConfigError::new(kw.line, kw.col, "'monitor-uri' expects an URI."));
    };
    *monitor_uri = Some(uri.text.clone());
    Ok(())
}
