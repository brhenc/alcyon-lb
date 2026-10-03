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
        mode,
        disabled: false,
        cookie: defaults.and_then(|d| d.cookie.clone()),
        contimeout: timeouts.connect,
        clitimeout: timeouts.client,
        srvtimeout: timeouts.server,
        timeouts,
        retries: defaults.and_then(|d| d.retries).unwrap_or(3),
        redisp: defaults.map_or(false, |d| d.redisp),
        maxconn: defaults.and_then(|d| d.maxconn).unwrap_or(2000),
        grace: None,
        dispatch: None,
        default_server: defaults.and_then(|d| d.default_server.clone()),
        servers: Vec::new(),
        logs: defaults.map_or_else(Vec::new, |d| d.logs.clone()),
        log_tag: defaults.and_then(|d| d.log_tag.clone()),
        log_global: defaults.map_or(false, |d| d.log_global),
        log_health_checks: defaults.map_or(false, |d| d.log_health_checks),
        cliexp: Vec::new(),
        srvexp: Vec::new(),
        acls: Vec::new(),
        use_backends: Vec::new(),
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
        forwardfor: None,
        originalto: None,
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
        monitor_uri: None,
        acls: Vec::new(),
        cliexp: Vec::new(),
        logs: defaults.map_or_else(Vec::new, |d| d.logs.clone()),
        log_tag: defaults.and_then(|d| d.log_tag.clone()),
        log_global: defaults.map_or(false, |d| d.log_global),
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
        forwardfor: None,
        originalto: None,
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
        dispatch: None,
        default_server: defaults.and_then(|d| d.default_server.clone()),
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
        forwardfor: None,
        originalto: None,
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
        "monitor-uri" => parse_monitor_uri(&mut proxy.monitor_uri, tokens, kw),
        "default_backend" => parse_default_backend(&mut proxy.default_backend, tokens, kw),
        "option" => parse_option_listen(proxy, tokens, kw),
        "no" => parse_no_directive(tokens, kw),
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
                "content" => parse_tcp_req_content(&mut proxy.tcp_res_content_rules, tokens, kw),
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
        "log-format" | "log-format-sd" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported", kw.text),
            ))
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
        "no" => parse_no_directive(tokens, kw),
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
        "log-format" | "log-format-sd" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported", kw.text),
            ))
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
        "no" => parse_no_directive(tokens, kw),
        "declare" => parse_declare(tokens, kw),
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
                "content" => parse_tcp_req_content(&mut be.tcp_res_content_rules, tokens, kw),
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
        "log-format" | "log-format-sd" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported", kw.text),
            ))
        }
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{other}' in 'backend' section"),
        )),
    }
}

pub(crate) fn parse_listen_bind(
    proxy: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<bind> expects <addr:port> as argument.",
        ));
    }
    let (addr, is_quic) = parse_socket_addr(&tokens[1], None)?;
    if is_quic {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "QUIC is not supported in listen sections".to_string(),
        ));
    }
    proxy.addr = addr;
    for tok in &tokens[2..] {
        if tok.text == "accept-proxy" {
            proxy.accept_proxy = true;
        } else if tok.text == "accept-proxy-v2" {
            proxy.accept_proxy = true;
            proxy.accept_proxy_v2 = true;
        }
    }
    Ok(())
}

pub(crate) fn parse_frontend_bind(
    fe: &mut FrontendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<bind> expects <addr:port> as argument.",
        ));
    }
    let (addr, is_quic) = parse_socket_addr(&tokens[1], None)?;
    let mut ssl = false;
    let mut crt = Vec::new();
    let mut alpn = Vec::new();
    let mut proto = None;
    let mut accept_proxy = false;
    let mut accept_proxy_v2 = false;

    let mut i = 2;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "ssl" => ssl = true,
            "crt" if i + 1 < tokens.len() => {
                i += 1;
                crt.push(tokens[i].text.clone());
            }
            "alpn" if i + 1 < tokens.len() => {
                i += 1;
                let protos: Vec<String> = tokens[i]
                    .text
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                alpn = protos;
            }
            "proto" if i + 1 < tokens.len() => {
                i += 1;
                proto = Some(tokens[i].text.clone());
            }
            "accept-proxy" => accept_proxy = true,
            "accept-proxy-v2" => {
                accept_proxy = true;
                accept_proxy_v2 = true;
            }
            _ => {}
        }
        i += 1;
    }

    if fe.bind.is_none() {
        fe.bind = Some(addr);
    }
    if accept_proxy {
        fe.accept_proxy = true;
    }
    if accept_proxy_v2 {
        fe.accept_proxy_v2 = true;
    }

    if is_quic && !ssl {
        return Err(ConfigError::new(kw.line, kw.col, "QUIC protocol detected, enabling ssl. Use 'ssl' to shut this warning. Proxy no SSL certificate specified for bind (use 'crt')".to_string()));
    }
    if is_quic && alpn.is_empty() {
        alpn.push("h3".to_string());
    }
    fe.binds.push(BindConfig {
        addr,
        quic: is_quic,
        ssl,
        crt,
        alpn,
        proto,
        accept_proxy,
        accept_proxy_v2,
    });
    Ok(())
}

pub(crate) fn parse_option_listen(
    proxy: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        match tokens[1].text.as_str() {
            "forwardfor" => {
                let except = if tokens.len() >= 4 && tokens[2].text == "except" {
                    tokens[3].text.clone()
                } else {
                    String::new()
                };
                proxy.forwardfor = Some(except);
            }
            "originalto" => {
                let except = if tokens.len() >= 4 && tokens[2].text == "except" {
                    tokens[3].text.clone()
                } else {
                    String::new()
                };
                proxy.originalto = Some(except);
            }
            "redispatch" => {
                proxy.redisp = true;
            }
            "log-health-checks" => {
                proxy.log_health_checks = true;
            }
            "httpchk" => {
                parse_httpchk_option(&mut proxy.httpchk, tokens, kw)?;
            }
            "tcp-check" => {
                proxy.tcp_check = true;
            }
            _ if parse_proto_check_option(&mut proxy.proto_check, tokens, kw)? => {}
            other => {
                refuse_if_check_option(other, kw)?;
                eprintln!("[ibex] warning: ignored option '{other}'");
            }
        }
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn parse_option_frontend(
    fe: &mut FrontendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        match tokens[1].text.as_str() {
            "forwardfor" => {
                let except = if tokens.len() >= 4 && tokens[2].text == "except" {
                    tokens[3].text.clone()
                } else {
                    String::new()
                };
                fe.forwardfor = Some(except);
            }
            "originalto" => {
                let except = if tokens.len() >= 4 && tokens[2].text == "except" {
                    tokens[3].text.clone()
                } else {
                    String::new()
                };
                fe.originalto = Some(except);
            }
            "log-health-checks" => {
                fe.log_health_checks = true;
            }
            other => {
                refuse_if_check_option(other, kw)?;
                eprintln!("[ibex] warning: ignored option '{other}'");
            }
        }
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn parse_option_backend(
    be: &mut BackendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        match tokens[1].text.as_str() {
            "forwardfor" => {
                let except = if tokens.len() >= 4 && tokens[2].text == "except" {
                    tokens[3].text.clone()
                } else {
                    String::new()
                };
                be.forwardfor = Some(except);
            }
            "originalto" => {
                let except = if tokens.len() >= 4 && tokens[2].text == "except" {
                    tokens[3].text.clone()
                } else {
                    String::new()
                };
                be.originalto = Some(except);
            }
            "redispatch" => {
                be.redisp = true;
            }
            "log-health-checks" => {
                be.log_health_checks = true;
            }
            "httpchk" => {
                parse_httpchk_option(&mut be.httpchk, tokens, kw)?;
            }
            "tcp-check" => {
                be.tcp_check = true;
            }
            _ if parse_proto_check_option(&mut be.proto_check, tokens, kw)? => {}
            other => {
                refuse_if_check_option(other, kw)?;
                eprintln!("[ibex] warning: ignored option '{other}'");
            }
        }
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
