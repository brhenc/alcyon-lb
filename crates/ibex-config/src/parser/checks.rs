use super::*;

pub(crate) fn refuse_if_check_option(name: &str, kw: &Token) -> Result<(), ConfigError> {
    if CHECK_OPTIONS_THAT_MUST_NOT_BE_IGNORED.contains(&name) {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            format!(
                "'option {name}' is not supported (only TCP connect health checks are \
                 implemented); accepting it would silently downgrade the check"
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn parse_httpchk_option(
    httpchk: &mut Option<HttpChkConfig>,
    tokens: &[Token],
    _kw: &Token,
) -> Result<(), ConfigError> {
    let args: Vec<&str> = tokens.iter().skip(2).map(|t| t.text.as_str()).collect();
    let cfg = match args.len() {
        0 => HttpChkConfig {
            method: Some("OPTIONS".to_string()),
            uri: Some("/".to_string()),
            version: Some("HTTP/1.0".to_string()),
            host: None,
        },
        1 => HttpChkConfig {
            method: Some("OPTIONS".to_string()),
            uri: Some(args[0].to_string()),
            version: Some("HTTP/1.0".to_string()),
            host: None,
        },
        2 => HttpChkConfig {
            method: Some(args[0].to_string()),
            uri: Some(args[1].to_string()),
            version: Some("HTTP/1.0".to_string()),
            host: None,
        },
        3 => HttpChkConfig {
            method: Some(args[0].to_string()),
            uri: Some(args[1].to_string()),
            version: Some(args[2].to_string()),
            host: None,
        },
        _ => HttpChkConfig {
            method: Some(args[0].to_string()),
            uri: Some(args[1].to_string()),
            version: Some(args[2].to_string()),
            host: Some(args[3].to_string()),
        },
    };
    *httpchk = Some(cfg);
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_http_check_directive(
    rules: &mut Vec<HttpCheckAction>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "http-check requires a subcommand",
        ));
    }

    match tokens[1].text.as_str() {
        "send" => {
            let mut method = None;
            let mut uri = None;
            let mut version = None;
            let mut headers = Vec::new();
            let mut body = None;

            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].text.as_str() {
                    "meth" => {
                        i += 1;
                        if i < tokens.len() {
                            method = Some(tokens[i].text.clone());
                        }
                    }
                    "uri" | "uri-lf" => {
                        i += 1;
                        if i < tokens.len() {
                            uri = Some(unescape_string(&tokens[i].text));
                        }
                    }
                    "ver" => {
                        i += 1;
                        if i < tokens.len() {
                            version = Some(tokens[i].text.clone());
                        }
                    }
                    "hdr" | "hdr-lf" => {
                        if i + 2 < tokens.len() {
                            let hname = tokens[i + 1].text.clone();
                            let hval = unescape_string(&tokens[i + 2].text);
                            headers.push((hname, hval));
                            i += 2;
                        }
                    }
                    "body" | "body-lf" => {
                        i += 1;
                        if i < tokens.len() {
                            body = Some(unescape_string(&tokens[i].text));
                        }
                    }
                    other => {
                        eprintln!("[ibex] warning: ignored http-check send parameter '{other}'");
                    }
                }
                i += 1;
            }

            rules.push(HttpCheckAction::Send {
                method,
                uri,
                version,
                headers,
                body,
            });
            Ok(())
        }
        "expect" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "http-check expect requires pattern",
                ));
            }

            let mut i = 2;
            let mut negate = false;
            if tokens[i].text == "!" {
                negate = true;
                i += 1;
            }

            if i >= tokens.len() {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "http-check expect requires pattern",
                ));
            }

            let pat_token = &tokens[i];
            let mut pat_name = pat_token.text.as_str();
            if pat_name.starts_with('!') {
                negate = true;
                pat_name = &pat_name[1..];
            }

            let pattern = match pat_name {
                "status" => {
                    i += 1;
                    if i >= tokens.len() {
                        return Err(ConfigError::new(
                            kw.line,
                            kw.col,
                            "http-check expect status requires status code or range",
                        ));
                    }
                    let val = &tokens[i].text;
                    if let Some((low, high)) = val.split_once('-') {
                        let l = low.parse::<u16>().map_err(|_| {
                            ConfigError::new(kw.line, kw.col, format!("invalid status '{low}'"))
                        })?;
                        let h = high.parse::<u16>().map_err(|_| {
                            ConfigError::new(kw.line, kw.col, format!("invalid status '{high}'"))
                        })?;
                        HttpCheckExpectPattern::StatusRange(l, h)
                    } else if val.contains(',') {
                        let mut codes = Vec::new();
                        for part in val.split(',') {
                            let code = part.trim().parse::<u16>().map_err(|_| {
                                ConfigError::new(kw.line, kw.col, format!("invalid status '{part}'"))
                            })?;
                            codes.push(code);
                        }
                        HttpCheckExpectPattern::Status(codes)
                    } else {
                        let code = val.parse::<u16>().map_err(|_| {
                            ConfigError::new(kw.line, kw.col, format!("invalid status '{val}'"))
                        })?;
                        HttpCheckExpectPattern::Status(vec![code])
                    }
                }
                "rstatus" => {
                    i += 1;
                    if i >= tokens.len() {
                        return Err(ConfigError::new(
                            kw.line,
                            kw.col,
                            "http-check expect rstatus requires regex pattern",
                        ));
                    }
                    HttpCheckExpectPattern::RStatus(unescape_string(&tokens[i].text))
                }
                "string" => {
                    i += 1;
                    if i >= tokens.len() {
                        return Err(ConfigError::new(
                            kw.line,
                            kw.col,
                            "http-check expect string requires pattern",
                        ));
                    }
                    HttpCheckExpectPattern::String(unescape_string(&tokens[i].text))
                }
                "rstring" => {
                    i += 1;
                    if i >= tokens.len() {
                        return Err(ConfigError::new(
                            kw.line,
                            kw.col,
                            "http-check expect rstring requires regex pattern",
                        ));
                    }
                    HttpCheckExpectPattern::RString(unescape_string(&tokens[i].text))
                }
                "hdr" | "fhdr" => {
                    let is_fhdr = pat_name == "fhdr";
                    i += 1;
                    let mut name = String::new();
                    let mut match_type = MatchType::Str;
                    let mut value = None;
                    let mut value_match_type = MatchType::Str;

                    while i < tokens.len() {
                        match tokens[i].text.as_str() {
                            "name" | "name-lf" => {
                                i += 1;
                                if i < tokens.len() && tokens[i].text == "-m" {
                                    i += 1;
                                    if i < tokens.len() {
                                        match_type = parse_match_type(&tokens[i].text);
                                        i += 1;
                                    }
                                }
                                if i < tokens.len() {
                                    name = unescape_string(&tokens[i].text);
                                }
                            }
                            "-m" => {
                                i += 1;
                                if i < tokens.len() {
                                    match_type = parse_match_type(&tokens[i].text);
                                }
                            }
                            "value" | "value-lf" => {
                                i += 1;
                                if i < tokens.len() && tokens[i].text == "-m" {
                                    i += 1;
                                    if i < tokens.len() {
                                        value_match_type = parse_match_type(&tokens[i].text);
                                        i += 1;
                                    }
                                }
                                if i < tokens.len() {
                                    value = Some(unescape_string(&tokens[i].text));
                                }
                            }
                            _ => {}
                        }
                        i += 1;
                    }

                    if is_fhdr {
                        HttpCheckExpectPattern::Fhdr {
                            name,
                            match_type,
                            value,
                            value_match_type,
                        }
                    } else {
                        HttpCheckExpectPattern::Hdr {
                            name,
                            match_type,
                            value,
                            value_match_type,
                        }
                    }
                }
                other => {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        format!("'http-check expect {other}' is not supported"),
                    ));
                }
            };

            rules.push(HttpCheckAction::Expect { pattern, negate });
            Ok(())
        }
        "connect" => {
            let mut addr = None;
            let mut port = None;
            let mut send_proxy = false;

            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].text.as_str() {
                    "addr" => {
                        i += 1;
                        if i < tokens.len() {
                            if let Ok(parsed_addr) = tokens[i].text.parse::<SocketAddr>() {
                                addr = Some(parsed_addr);
                                port = Some(parsed_addr.port());
                            } else if let Ok(ip) = tokens[i].text.parse::<IpAddr>() {
                                addr = Some(SocketAddr::new(ip, 0));
                            }
                        }
                    }
                    "port" => {
                        i += 1;
                        if i < tokens.len() {
                            port = Some(parse_u16(&tokens[i], "port")?);
                        }
                    }
                    "send-proxy" => send_proxy = true,
                    _ => {}
                }
                i += 1;
            }

            rules.push(HttpCheckAction::Connect {
                addr,
                port,
                send_proxy,
            });
            Ok(())
        }
        "comment" => {
            let comment = if tokens.len() >= 3 {
                tokens[2].text.clone()
            } else {
                String::new()
            };
            rules.push(HttpCheckAction::Comment(comment));
            Ok(())
        }
        "disable-on-404" => {
            rules.push(HttpCheckAction::DisableOn404);
            Ok(())
        }
        "send-state" => {
            rules.push(HttpCheckAction::SendState);
            Ok(())
        }
        "set-var" => {
            let var_name = tokens.get(2).map_or("", |t| t.text.as_str()).to_string();
            let expr = tokens.get(3).map_or("", |t| t.text.as_str()).to_string();
            rules.push(HttpCheckAction::SetVar { var_name, expr });
            Ok(())
        }
        "unset-var" => {
            let var_name = tokens.get(2).map_or("", |t| t.text.as_str()).to_string();
            rules.push(HttpCheckAction::UnsetVar { var_name });
            Ok(())
        }
        other if other.starts_with("set-var(") => {
            let var_name = other
                .trim_start_matches("set-var(")
                .trim_end_matches(')')
                .to_string();
            let expr = tokens.get(2).map_or("", |t| t.text.as_str()).to_string();
            rules.push(HttpCheckAction::SetVar { var_name, expr });
            Ok(())
        }
        other if other.starts_with("unset-var(") => {
            let var_name = other
                .trim_start_matches("unset-var(")
                .trim_end_matches(')')
                .to_string();
            rules.push(HttpCheckAction::UnsetVar { var_name });
            Ok(())
        }
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("'http-check {other}' is not supported"),
        )),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_tcp_check_directive(
    rules: &mut Vec<TcpCheckAction>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "tcp-check requires a subcommand",
        ));
    }

    match tokens[1].text.as_str() {
        "connect" => {
            let mut port = None;
            let mut send_proxy = false;

            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].text.as_str() {
                    "port" => {
                        i += 1;
                        if i < tokens.len() {
                            port = Some(parse_u16(&tokens[i], "port")?);
                        }
                    }
                    "send-proxy" => send_proxy = true,
                    _ => {}
                }
                i += 1;
            }

            rules.push(TcpCheckAction::Connect { port, send_proxy });
            Ok(())
        }
        "send" | "send-lf" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "tcp-check send requires data",
                ));
            }
            let data = unescape_string(&tokens[2].text).into_bytes();
            rules.push(TcpCheckAction::Send(data));
            Ok(())
        }
        "send-binary" | "send-binary-lf" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "tcp-check send-binary requires hex data",
                ));
            }
            let data = parse_hex_binary(&tokens[2].text).map_err(|e| {
                ConfigError::new(kw.line, kw.col, format!("invalid hex data: {e}"))
            })?;
            rules.push(TcpCheckAction::Send(data));
            Ok(())
        }
        "expect" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "tcp-check expect requires pattern",
                ));
            }

            let mut negate = false;
            let mut min_recv = None;
            let mut comment = None;
            let mut pattern = None;

            let mut i = 2;
            while i < tokens.len() {
                let token_text = &tokens[i].text;
                if token_text == "!" {
                    negate = true;
                    i += 1;
                    continue;
                }
                if token_text == "min-recv" {
                    i += 1;
                    if i < tokens.len() {
                        min_recv = Some(parse_usize(&tokens[i], "min-recv")?);
                    }
                    i += 1;
                    continue;
                }
                if token_text == "comment" {
                    i += 1;
                    if i < tokens.len() {
                        comment = Some(unescape_string(&tokens[i].text));
                    }
                    i += 1;
                    continue;
                }

                let mut ptext = token_text.as_str();
                if ptext.starts_with('!') {
                    negate = true;
                    ptext = &ptext[1..];
                }

                match ptext {
                    "string" => {
                        i += 1;
                        if i < tokens.len() {
                            pattern = Some(TcpCheckExpectPattern::String(unescape_string(&tokens[i].text)));
                        }
                    }
                    "binary" => {
                        i += 1;
                        if i < tokens.len() {
                            let b = parse_hex_binary(&tokens[i].text).map_err(|e| {
                                ConfigError::new(kw.line, kw.col, format!("invalid hex pattern: {e}"))
                            })?;
                            pattern = Some(TcpCheckExpectPattern::Binary(b));
                        }
                    }
                    "rstring" => {
                        i += 1;
                        if i < tokens.len() {
                            pattern = Some(TcpCheckExpectPattern::RString(unescape_string(&tokens[i].text)));
                        }
                    }
                    "error-status" | "on-error" | "status-code" => {
                        i += 1;
                    }
                    other => {
                        return Err(ConfigError::new(
                            kw.line,
                            kw.col,
                            format!("'tcp-check expect {other}' is not supported"),
                        ));
                    }
                }
                i += 1;
            }

            let Some(pat) = pattern else {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "tcp-check expect requires a pattern",
                ));
            };

            rules.push(TcpCheckAction::Expect {
                pattern: pat,
                negate,
                min_recv,
                comment,
            });
            Ok(())
        }
        "comment" => {
            let comment = if tokens.len() >= 3 {
                tokens[2].text.clone()
            } else {
                String::new()
            };
            rules.push(TcpCheckAction::Comment(comment));
            Ok(())
        }
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("'tcp-check {other}' is not supported"),
        )),
    }
}

pub(crate) fn build_resolved_http_check(
    httpchk: Option<&HttpChkConfig>,
    http_checks: &[HttpCheckAction],
    server: &Server,
) -> ResolvedHttpCheck {
    let mut method = httpchk
        .and_then(|h| h.method.clone())
        .unwrap_or_else(|| "OPTIONS".to_string());
    let mut uri = httpchk
        .and_then(|h| h.uri.clone())
        .unwrap_or_else(|| "/".to_string());
    let mut version = httpchk
        .and_then(|h| h.version.clone())
        .unwrap_or_else(|| "HTTP/1.0".to_string());
    let mut host = httpchk.and_then(|h| h.host.clone());
    let mut headers = Vec::new();
    let mut body = None;
    let mut send_state = false;
    let mut expect_rules = Vec::new();
    let check_port = server.check_port;
    let send_proxy = server.send_proxy || server.send_proxy_v2;

    for act in http_checks {
        match act {
            HttpCheckAction::Send {
                method: req_method,
                uri: req_uri,
                version: req_version,
                headers: req_headers,
                body: req_body,
            } => {
                if let Some(m) = req_method {
                    method.clone_from(m);
                }
                if let Some(u) = req_uri {
                    uri.clone_from(u);
                }
                if let Some(v) = req_version {
                    version.clone_from(v);
                }
                for (name, val) in req_headers {
                    if name.eq_ignore_ascii_case("host") {
                        host = Some(val.clone());
                    }
                    headers.push((name.clone(), val.clone()));
                }
                if let Some(b) = req_body {
                    body = Some(b.clone());
                }
            }
            HttpCheckAction::Expect { pattern, negate } => {
                expect_rules.push(ResolvedHttpExpectRule {
                    pattern: pattern.into(),
                    negate: *negate,
                });
            }
            HttpCheckAction::SendState => {
                send_state = true;
            }
            _ => {}
        }
    }

    if expect_rules.is_empty() {
        expect_rules.push(ResolvedHttpExpectRule {
            pattern: ResolvedHttpExpectPattern::StatusRange(200, 399),
            negate: false,
        });
    }

    ResolvedHttpCheck {
        method,
        uri,
        version,
        host,
        headers,
        body,
        send_state,
        expect_rules,
        check_port,
        send_proxy,
    }
}

pub(crate) fn build_resolved_tcp_steps(
    tcp_checks: &[TcpCheckAction],
    server: &Server,
) -> Vec<ResolvedTcpStep> {
    let mut steps = Vec::new();
    let has_connect = tcp_checks
        .iter()
        .any(|a| matches!(a, TcpCheckAction::Connect { .. }));

    if !has_connect {
        steps.push(ResolvedTcpStep::Connect {
            port: server.check_port,
            send_proxy: server.send_proxy || server.send_proxy_v2,
        });
    }

    for act in tcp_checks {
        match act {
            TcpCheckAction::Connect { port, send_proxy } => {
                steps.push(ResolvedTcpStep::Connect {
                    port: port.or(server.check_port),
                    send_proxy: *send_proxy || server.send_proxy || server.send_proxy_v2,
                });
            }
            TcpCheckAction::Send(data) => {
                steps.push(ResolvedTcpStep::Send(data.clone()));
            }
            TcpCheckAction::Expect {
                pattern,
                negate,
                min_recv,
                comment,
            } => {
                steps.push(ResolvedTcpStep::Expect {
                    pattern: pattern.into(),
                    negate: *negate,
                    min_recv: min_recv.unwrap_or(0),
                    comment: comment.clone(),
                });
            }
            TcpCheckAction::Comment(c) => {
                steps.push(ResolvedTcpStep::Comment(c.clone()));
            }
        }
    }

    steps
}

pub(crate) fn register_checks_from_config(config: &Config) {
    clear_resolved_checks();
    let mut proxy_idx = 0;

    for listen in &config.listens {
        register_section_checks(
            proxy_idx,
            listen.httpchk.as_ref(),
            &listen.http_checks,
            &listen.tcp_checks,
            listen.tcp_check,
            &listen.servers,
        );
        proxy_idx += 1;
    }

    for backend in &config.backends {
        register_section_checks(
            proxy_idx,
            backend.httpchk.as_ref(),
            &backend.http_checks,
            &backend.tcp_checks,
            backend.tcp_check,
            &backend.servers,
        );
        proxy_idx += 1;
    }
}

pub(crate) fn register_section_checks(
    proxy_idx: usize,
    httpchk: Option<&HttpChkConfig>,
    http_checks: &[HttpCheckAction],
    tcp_checks: &[TcpCheckAction],
    tcp_check: bool,
    servers: &[Server],
) {
    for (server_idx, server) in servers.iter().enumerate() {
        if !server.check {
            continue;
        }
        let resolved = if tcp_check || !tcp_checks.is_empty() {
            let steps = build_resolved_tcp_steps(tcp_checks, server);
            ResolvedCheckConfig::TcpSteps(steps)
        } else if httpchk.is_some() || !http_checks.is_empty() {
            let chk = build_resolved_http_check(httpchk, http_checks, server);
            ResolvedCheckConfig::Http(chk)
        } else {
            ResolvedCheckConfig::TcpConnect
        };

        register_resolved_check(proxy_idx, server_idx, resolved.clone());
        register_resolved_check_for_addr(server.addr, resolved.clone());
        if let Some(port) = server.check_port {
            register_resolved_check_for_addr(
                SocketAddr::new(server.addr.ip(), port),
                resolved,
            );
        }
    }
}

