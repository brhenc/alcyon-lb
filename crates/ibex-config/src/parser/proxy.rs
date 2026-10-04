// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use std::collections::HashMap;

use super::*;

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
        tcp_checks: defaults.map_or_else(Vec::new, |d| d.tcp_checks.clone()),
        tcp_check: defaults.is_some_and(|d| d.tcp_check),
        name: id,
        addr,
        binds: Vec::new(),
        mode,
        disabled: false,
        cookie: defaults.and_then(|d| d.cookie.clone()),
        contimeout: timeouts.connect,
        clitimeout: timeouts.client,
        srvtimeout: timeouts.server,
        timeouts,
        retries: defaults.and_then(|d| d.retries).unwrap_or(3),
        redisp: defaults.map_or(false, |d| d.redisp),
        redisp_after: defaults.map_or(-1, |d| if d.redisp { d.redisp_after } else { -1 }),
        maxconn: defaults.and_then(|d| d.maxconn).unwrap_or(2000),
        grace: None,
        dispatch: None,
        default_server: defaults.and_then(|d| d.default_server.clone()),
        use_servers: Vec::new(),
        servers: Vec::new(),
        logs: defaults.map_or_else(Vec::new, |d| d.logs.clone()),
        log_tag: defaults.and_then(|d| d.log_tag.clone()),
        log_global: defaults.map_or(false, |d| d.log_global),
        log_format: defaults.and_then(|d| d.log_format.clone()),
        unique_id_format: defaults.and_then(|d| d.unique_id_format.clone()),
        unique_id_header: defaults.and_then(|d| d.unique_id_header.clone()),
        req_header_captures: Vec::new(),
        res_header_captures: Vec::new(),
        log_health_checks: defaults.map_or(false, |d| d.log_health_checks),
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
        clitimeout: timeouts.client,
        timeouts,
        maxconn: defaults.and_then(|d| d.maxconn).unwrap_or(2000),
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
        mode,
        disabled: false,
        balance: defaults.and_then(|d| d.balance).unwrap_or(BalanceAlgorithm::RoundRobin),
        cookie: defaults.and_then(|d| d.cookie.clone()),
        contimeout: timeouts.connect,
        srvtimeout: timeouts.server,
        timeouts,
        retries: defaults.and_then(|d| d.retries).unwrap_or(3),
        redisp: defaults.map_or(false, |d| d.redisp),
        redisp_after: defaults.map_or(-1, |d| if d.redisp { d.redisp_after } else { -1 }),
        dispatch: None,
        default_server: defaults.and_then(|d| d.default_server.clone()),
        use_servers: Vec::new(),
        servers: Vec::new(),
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
        originalto: defaults.and_then(|d| d.originalto.clone()),
        stats: defaults.map_or_else(StatsConfig::default, |d| d.stats.clone()),
        error_files: defaults.map_or_else(HashMap::new, |d| d.error_files.clone()),
        error_replies: defaults.map_or_else(HashMap::new, |d| d.error_replies.clone()),
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_listen_directive(
    proxy: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "mode" => parse_mode(&mut proxy.mode, tokens, kw),
        "disabled" => {
            proxy.disabled = true;
            Ok(())
        }
        "cookie" => parse_cookie(&mut proxy.cookie, tokens, kw),
        "contimeout" => parse_contimeout(kw),
        "clitimeout" => parse_clitimeout(kw),
        "srvtimeout" => parse_srvtimeout(kw),
        "timeout" => parse_timeout_directive(&mut proxy.timeouts, tokens, kw),
        "retries" => parse_retries(&mut proxy.retries, tokens, kw),
        "redisp" => {
            proxy.redisp = true;
            proxy.redisp_after = -1;
            Ok(())
        }
        "maxconn" => parse_maxconn(&mut proxy.maxconn, tokens, kw),
        "grace" => parse_grace(&mut proxy.grace, tokens, kw),
        "dispatch" => parse_dispatch(kw),
        "default-server" => parse_default_server(&mut proxy.default_server, tokens, kw),
        "server" => parse_server(
            &mut proxy.servers,
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
        "accept-proxy" => {
            proxy.accept_proxy = true;
            Ok(())
        }
        "accept-proxy-v2" => {
            proxy.accept_proxy = true;
            proxy.accept_proxy_v2 = true;
            Ok(())
        }
        "stick-table" => parse_stick_table(&mut proxy.stick_table, tokens, kw),
        "stick" => parse_stick_rule(&mut proxy.stick_rules, tokens, kw),
        "track-sc0" | "track-sc1" | "track-sc2" => {
            parse_track_rule(&mut proxy.stick_rules, tokens, kw)
        }
        "tcp-request" => parse_listen_tcp_request(proxy, tokens, kw),
        "http-request" => parse_http_req_rule(&mut proxy.http_req_rules, tokens, kw),
        "http-response" => parse_http_res_rule(&mut proxy.http_res_rules, tokens, kw),
        "http-after-response" => {
            parse_http_after_res_rule(&mut proxy.http_after_res_rules, tokens, kw)
        }
        "stats" => parse_stats_directive(&mut proxy.stats, tokens, kw),
        "http-check" => {
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
                    proxy.tcp_res_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-response inspect-delay")?);
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
        "errorfile" | "errorfiles" | "http-error" => {
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
        "accept-proxy" => {
            fe.accept_proxy = true;
            Ok(())
        }
        "accept-proxy-v2" => {
            fe.accept_proxy = true;
            fe.accept_proxy_v2 = true;
            Ok(())
        }
        "tcp-request" => parse_frontend_tcp_request(fe, tokens, kw),
        // `stream_parse_set_retries`: a retry budget belongs to a backend.
        "http-request" if tokens.get(1).is_some_and(|t| t.text == "set-retries") => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            "'set-retries' only available in backend or listen section",
        )),
        "http-request" => parse_http_req_rule(&mut fe.http_req_rules, tokens, kw),
        "http-response" => parse_http_res_rule(&mut fe.http_res_rules, tokens, kw),
        "http-after-response" => {
            parse_http_after_res_rule(&mut fe.http_after_res_rules, tokens, kw)
        }
        "mode" => parse_mode(&mut fe.mode, tokens, kw),
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
        "stick" => parse_stick_rule(&mut fe.stick_rules, tokens, kw),
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
        "errorfile" | "errorfiles" | "http-error" => {
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
        "redisp" => {
            be.redisp = true;
            be.redisp_after = -1;
            Ok(())
        }
        "dispatch" => parse_dispatch(kw),
        "default-server" => parse_default_server(&mut be.default_server, tokens, kw),
        "server" => parse_server(&mut be.servers, be.default_server.as_ref(), tokens, kw),
        "tcp-request" => parse_backend_tcp_request(be, tokens, kw),
        "http-request" => parse_http_req_rule(&mut be.http_req_rules, tokens, kw),
        "http-response" => parse_http_res_rule(&mut be.http_res_rules, tokens, kw),
        "http-after-response" => {
            parse_http_after_res_rule(&mut be.http_after_res_rules, tokens, kw)
        }
        "option" => parse_option_backend(be, tokens, kw),
        "no" => parse_no_backend(be, tokens, kw),
        "declare" => refuse_declare(DeclareIn::Backend, kw),
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
                    be.tcp_res_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-response inspect-delay")?);
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
        "errorfile" | "errorfiles" | "http-error" => {
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
/// `bind_keywords::unimplemented_bind_keyword`, which refuses it or skips it and its
/// argument with a warning, and refuses an unknown one as `HAProxy` does.
fn parse_bind(tokens: &[Token], kw: &Token, section: &str) -> Result<BindConfig, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<bind> expects <addr:port> as argument.",
        ));
    }
    let (addr, quic) = parse_socket_addr(&tokens[1], None)?;
    let mut bind = BindConfig {
        addr,
        quic,
        ssl: false,
        crt: Vec::new(),
        alpn: Vec::new(),
        proto: None,
        accept_proxy: false,
        accept_proxy_v2: false,
    };
    let prefix = format!("'bind {}' in section '{section}'", tokens[1].text);
    let arg = |i: usize, what: &str| -> Result<&Token, ConfigError> {
        tokens.get(i + 1).filter(|t| !t.text.is_empty()).ok_or_else(|| {
            ConfigError::new(tokens[i].line, tokens[i].col, format!("{prefix} : '{}' : {what}", tokens[i].text))
        })
    };

    let mut i = 2;
    while i < tokens.len() {
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
            "accept-proxy" => bind.accept_proxy = true,
            "accept-proxy-v2" => {
                bind.accept_proxy = true;
                bind.accept_proxy_v2 = true;
            }
            _ => i = super::bind_keywords::unimplemented_bind_keyword(tokens, i, section)?,
        }
        i += 1;
    }
    Ok(bind)
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
        "forwardfor" => proxy.forwardfor = Some(parse_forward_option(tokens, kw)?),
        "originalto" => proxy.originalto = Some(parse_forward_option(tokens, kw)?),
        "redispatch" => set_redispatch(&mut proxy.redisp, &mut proxy.redisp_after, tokens),
        "accept-unsafe-violations-in-http-request" => proxy.stats.accept_unsafe_request = true,
        "log-health-checks" => proxy.log_health_checks = true,
        "httpchk" => parse_httpchk_option(&mut proxy.httpchk, tokens, kw)?,
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
    let except = Some(parse_forward_option(tokens, kw)?);
    if tokens[1].text == "forwardfor" {
        fe.forwardfor = except;
    } else {
        fe.originalto = except;
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
        "forwardfor" => be.forwardfor = Some(parse_forward_option(tokens, kw)?),
        "originalto" => be.originalto = Some(parse_forward_option(tokens, kw)?),
        "redispatch" => set_redispatch(&mut be.redisp, &mut be.redisp_after, tokens),
        "log-health-checks" => be.log_health_checks = true,
        "httpchk" => parse_httpchk_option(&mut be.httpchk, tokens, kw)?,
        "tcp-check" => be.tcp_check = true,
        _ => {
            parse_proto_check_option(&mut be.proto_check, tokens, kw)?;
        }
    }
    Ok(())
}

/// `no option <name>` in a proxy section: turns off an option this section inherited.
pub(crate) fn parse_no_listen(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.get(1).is_none_or(|t| t.text != "option") {
        return parse_no_directive(tokens, kw);
    }
    match check_no_option(OptSection::Listen, tokens, kw)? {
        Some("redispatch") => (proxy.redisp, proxy.redisp_after) = (false, -1),
        Some("accept-unsafe-violations-in-http-request") => proxy.stats.accept_unsafe_request = false,
        Some("log-health-checks") => proxy.log_health_checks = false,
        _ => {}
    }
    Ok(())
}

pub(crate) fn parse_no_frontend(fe: &mut FrontendSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.get(1).is_none_or(|t| t.text != "option") {
        return parse_no_directive(tokens, kw);
    }
    if let Some("accept-unsafe-violations-in-http-request") = check_no_option(OptSection::Frontend, tokens, kw)? {
        fe.stats.accept_unsafe_request = false;
    }
    Ok(())
}

pub(crate) fn parse_no_backend(be: &mut BackendSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.get(1).is_none_or(|t| t.text != "option") {
        return parse_no_directive(tokens, kw);
    }
    match check_no_option(OptSection::Backend, tokens, kw)? {
        Some("redispatch") => (be.redisp, be.redisp_after) = (false, -1),
        Some("log-health-checks") => be.log_health_checks = false,
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
