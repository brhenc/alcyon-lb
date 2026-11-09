// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

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
/// A section with `http-check` rules or `option httpchk` of its own does not inherit the
/// defaults' (`HAProxy` hands a proxy the defaults' rule set only when it has none): the
/// first of them drops what the section was given.
pub(crate) fn take_own_http_check(
    own: &mut bool,
    httpchk: &mut Option<HttpChkConfig>,
    http_checks: &mut Vec<HttpCheckAction>,
) {
    if !*own {
        *own = true;
        // Whether the checks are HTTP ones stays; the inherited request does not.
        *httpchk = httpchk.as_ref().map(|_| HttpChkConfig { method: None, uri: None, version: None, host: None });
        http_checks.clear();
    }
}

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

pub(crate) fn parse_proto_check_option(
    proto_check: &mut Option<ProtoCheckConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<bool, ConfigError> {
    if tokens.len() < 2 {
        return Ok(false);
    }
    match tokens[1].text.as_str() {
        "redis-check" => {
            *proto_check = Some(ProtoCheckConfig::Redis);
            Ok(true)
        }
        "smtpchk" => {
            let cmd = if tokens.len() >= 4 && (tokens[2].text == "HELO" || tokens[2].text == "EHLO") {
                Some(format!("{} {}", tokens[2].text, tokens[3].text))
            } else if tokens.len() >= 3 && (tokens[2].text == "HELO" || tokens[2].text == "EHLO") {
                Some(tokens[2].text.clone())
            } else {
                None
            };
            *proto_check = Some(ProtoCheckConfig::Smtp { cmd });
            Ok(true)
        }
        "ldap-check" => {
            *proto_check = Some(ProtoCheckConfig::Ldap);
            Ok(true)
        }
        "mysql-check" => {
            let mut user = None;
            let mut version = MysqlCheckVersion::Post41;
            let mut i = 2;
            while i < tokens.len() {
                if tokens[i].text == "user" {
                    i += 1;
                    if i < tokens.len() {
                        user = Some(tokens[i].text.clone());
                    }
                    i += 1;
                    if i < tokens.len() {
                        match tokens[i].text.as_str() {
                            "pre-41" => version = MysqlCheckVersion::Pre41,
                            "post-41" => version = MysqlCheckVersion::Post41,
                            "post-80" => version = MysqlCheckVersion::Post80,
                            other => {
                                return Err(ConfigError::new(
                                    kw.line,
                                    kw.col,
                                    format!("keyword 'user' only supports 'post-41', 'pre-41' and 'post-80' (got '{other}')."),
                                ));
                            }
                        }
                        i += 1;
                    }
                } else {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        format!("'option mysql-check' only supports optional values: 'user' (got '{}').", tokens[i].text),
                    ));
                }
            }
            *proto_check = Some(ProtoCheckConfig::Mysql { user, version });
            Ok(true)
        }
        "pgsql-check" => {
            let mut user = None;
            let mut i = 2;
            while i < tokens.len() {
                if tokens[i].text == "user" {
                    i += 1;
                    if i < tokens.len() {
                        user = Some(tokens[i].text.clone());
                    }
                    i += 1;
                } else {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        format!("'option pgsql-check' only supports optional values: 'user' (got '{}').", tokens[i].text),
                    ));
                }
            }
            let Some(u) = user else {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'option pgsql-check' expects 'user <username>' as argument.",
                ));
            };
            *proto_check = Some(ProtoCheckConfig::Pgsql { user: u });
            Ok(true)
        }
        "ssl-hello-chk" => {
            *proto_check = Some(ProtoCheckConfig::SslHello);
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// `min-recv`, read as `atol` does (a text that is no number is 0), within -1 to INT_MAX.
fn parse_min_recv(text: &str, kw: &Token) -> Result<i64, ConfigError> {
    let t = text.trim_start();
    let (neg, digits) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let n: i64 = digits.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap_or(0);
    let n = if neg { -n } else { n };
    if (-1..=i64::from(i32::MAX)).contains(&n) {
        Ok(n)
    } else {
        Err(check_err(kw, "'min-recv' expects -1 or an integer from 0 to INT_MAX"))
    }
}

fn check_err(kw: &Token, msg: impl Into<String>) -> ConfigError {
    ConfigError::new(kw.line, kw.col, msg.into())
}

/// `-m <str|beg|end|sub|reg>` after a header `name` or `value` keyword of `expect hdr`.
/// Returns the pattern text and where parsing resumes.
fn parse_hdr_pattern(
    tokens: &[Token],
    mut i: usize,
    what: &str,
    lf: bool,
    kw: &Token,
) -> Result<(HdrPattern, usize), ConfigError> {
    let mut mt = MatchType::Str;
    if tokens.get(i).is_some_and(|t| t.text == "-m") {
        let Some(m) = tokens.get(i + 1) else {
            return Err(check_err(
                kw,
                format!("'{what}' : '-m' expects at a matching pattern ('str', 'beg', 'end', 'sub' or 'reg')"),
            ));
        };
        mt = match m.text.as_str() {
            "str" => MatchType::Str,
            "beg" => MatchType::Beg,
            "end" => MatchType::End,
            "sub" => MatchType::Sub,
            "reg" => {
                if lf {
                    return Err(check_err(
                        kw,
                        format!("'{what}': log-format string is not supported with a regex matching method"),
                    ));
                }
                MatchType::Reg
            }
            other => {
                return Err(check_err(
                    kw,
                    format!("'{what}' : '-m' only supports 'str', 'beg', 'end', 'sub' or 'reg' (got '{other}')"),
                ))
            }
        };
        i += 2;
    }
    let Some(text) = tokens.get(i) else {
        return Err(check_err(kw, format!("'{what}' expect a pattern with the value keyword")));
    };
    if mt == MatchType::Reg {
        validate_regex(text)?;
    }
    Ok((HdrPattern { text: text.text.clone(), lf, mt }, i + 1))
}

/// `http-check expect`: the status list of `status 200-399,404`.
fn parse_status_ranges(text: &str, kw: &Token) -> Result<Vec<(u16, u16)>, ConfigError> {
    let mut out = Vec::new();
    for part in text.split(',') {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let parse = |s: &str| {
            s.parse::<u16>()
                .map_err(|_| check_err(kw, format!("invalid character in the list of status codes '{text}'")))
        };
        let (lo, hi) = (parse(lo)?, parse(hi)?);
        if lo > hi {
            return Err(check_err(kw, format!("invalid range of status codes '{text}'")));
        }
        out.push((lo, hi));
    }
    Ok(out)
}

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_http_check_directive(
    rules: &mut Vec<HttpCheckAction>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(check_err(kw, "http-check requires a subcommand"));
    }
    let sub = tokens[1].text.as_str();
    let has_send = rules.iter().any(|r| matches!(r, HttpCheckAction::Send { .. }));

    match sub {
        "send" => {
            // Alcyon runs one request per check: a second `send` (a script of several
            // requests, with their `expect` rules between) would have to be merged into
            // the first, and `HAProxy` does not merge them.
            if has_send {
                return Err(check_err(
                    kw,
                    "a second 'http-check send' is not supported: Alcyon runs one request per check",
                ));
            }
            let mut method = None;
            let mut uri = None;
            let mut uri_lf = false;
            let mut version = None;
            let mut headers: Vec<(String, String)> = Vec::new();
            let mut body = None;
            let mut body_lf = false;

            let mut i = 2;
            while i < tokens.len() {
                let key = tokens[i].text.as_str();
                let arg = |n: usize| {
                    tokens.get(i + n).map(|t| t.text.clone()).ok_or_else(|| {
                        check_err(kw, format!("'{key}' expects a string as argument."))
                    })
                };
                match key {
                    "meth" => {
                        method = Some(arg(1)?);
                        i += 1;
                    }
                    "uri" | "uri-lf" => {
                        uri_lf = key == "uri-lf";
                        uri = Some(arg(1)?);
                        i += 1;
                    }
                    "ver" => {
                        version = Some(arg(1)?);
                        i += 1;
                    }
                    "hdr" => {
                        if i + 2 >= tokens.len() {
                            return Err(check_err(kw, "'hdr' expects <name> and <value> as arguments"));
                        }
                        let (name, value) = (arg(1)?, arg(2)?);
                        if name.eq_ignore_ascii_case("host")
                            && headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"))
                        {
                            return Err(check_err(kw, "'host' header already defined"));
                        }
                        // `HAProxy` drops these two: the length is its own.
                        if !(name.eq_ignore_ascii_case("content-length")
                            || name.eq_ignore_ascii_case("transfer-encoding"))
                        {
                            headers.push((name, value));
                        }
                        i += 2;
                    }
                    "body" | "body-lf" => {
                        body_lf = key == "body-lf";
                        body = Some(arg(1)?);
                        i += 1;
                    }
                    "comment" => {
                        // Only read back in messages about a failing `send`, which Alcyon
                        // does not word: the text is checked and dropped.
                        arg(1)?;
                        i += 1;
                    }
                    other => {
                        return Err(check_err(
                            kw,
                            format!(
                                "expects 'comment', 'meth', 'uri', 'uri-lf', 'ver', 'hdr', 'body' or 'body-lf' but got '{other}' as argument."
                            ),
                        ));
                    }
                }
                i += 1;
            }

            rules.push(HttpCheckAction::Send {
                method,
                uri,
                uri_lf,
                version,
                headers,
                body,
                body_lf,
            });
            Ok(())
        }
        "expect" => {
            let mut negate = false;
            let mut min_recv: i64 = -1;
            let mut comment = None;
            let mut pattern = None;
            let mut i = 2;
            let one_pattern = |pattern: &Option<HttpCheckExpectPattern>| {
                if pattern.is_some() {
                    Err(check_err(kw, "only one pattern expected"))
                } else {
                    Ok(())
                }
            };
            while i < tokens.len() {
                let mut key = tokens[i].text.as_str();
                let mut in_pattern = false;
                while let Some(rest) = key.strip_prefix('!') {
                    negate = !negate;
                    in_pattern = true;
                    key = rest;
                }
                if key.is_empty() {
                    i += 1;
                    key = tokens.get(i).map_or("", |t| t.text.as_str());
                }
                let arg = |n: usize, what: &str| {
                    tokens.get(i + n).ok_or_else(|| check_err(kw, format!("'{key}' expects {what} as argument")))
                };
                match key {
                    "min-recv" if !in_pattern => {
                        let v = arg(1, "a integer")?;
                        min_recv = parse_min_recv(&v.text, kw)?;
                        i += 1;
                    }
                    "comment" if !in_pattern => {
                        comment = Some(arg(1, "a string")?.text.clone());
                        i += 1;
                    }
                    "status" | "rstatus" => {
                        one_pattern(&pattern)?;
                        let v = arg(1, "a <pattern>")?;
                        pattern = Some(if key == "status" {
                            HttpCheckExpectPattern::Status(parse_status_ranges(&v.text, kw)?)
                        } else {
                            validate_regex_nocapture(v)?;
                            HttpCheckExpectPattern::RStatus(v.text.clone())
                        });
                        i += 1;
                    }
                    "string" | "rstring" | "string-lf" => {
                        one_pattern(&pattern)?;
                        let v = arg(1, "a <pattern>")?;
                        pattern = Some(match key {
                            "string" => HttpCheckExpectPattern::String(v.text.clone()),
                            "string-lf" => HttpCheckExpectPattern::StringLf(v.text.clone()),
                            _ => {
                                validate_regex_nocapture(v)?;
                                HttpCheckExpectPattern::RString(v.text.clone())
                            }
                        });
                        i += 1;
                    }
                    "hdr" | "fhdr" => {
                        one_pattern(&pattern)?;
                        let what = key;
                        let name_kw = tokens.get(i + 1).map(|t| t.text.as_str());
                        if tokens.get(i + 2).is_none() || !matches!(name_kw, Some("name" | "name-lf")) {
                            return Err(check_err(
                                kw,
                                format!("'{what}' expects at the name keyword as first argument followed by a pattern"),
                            ));
                        }
                        let (name, next) = parse_hdr_pattern(tokens, i + 2, what, name_kw == Some("name-lf"), kw)?;
                        i = next;
                        let value = match tokens.get(i).map(|t| t.text.as_str()) {
                            Some(v @ ("value" | "value-lf")) => {
                                let (p, next) = parse_hdr_pattern(tokens, i + 1, what, v == "value-lf", kw)?;
                                i = next;
                                Some(p)
                            }
                            _ => None,
                        };
                        pattern = Some(HttpCheckExpectPattern::Hdr { full: what == "fhdr", name, value });
                        // `i` is already past the pattern.
                        continue;
                    }
                    "on-success" | "on-error" | "ok-status" | "error-status" | "tout-status" | "status-code"
                    | "custom" => {
                        return Err(check_err(
                            kw,
                            format!(
                                "'http-check expect {key}' is not supported: Alcyon does not implement it, and the rule would be evaluated without it"
                            ),
                        ));
                    }
                    other => {
                        return Err(check_err(
                            kw,
                            format!(
                                "'only supports min-recv, [!]string', '[!]rstring', '[!]string-lf', '[!]status', '[!]rstatus', [!]hdr, [!]fhdr or comment but got '{other}' as argument."
                            ),
                        ));
                    }
                }
                i += 1;
            }
            let Some(pattern) = pattern else {
                return Err(check_err(kw, "http-check expect requires pattern"));
            };
            rules.push(HttpCheckAction::Expect { pattern, negate, min_recv, comment });
            Ok(())
        }
        "connect" => {
            // The connection options that change where or how Alcyon connects are the ones
            // implemented; each other is refused rather than dropped.
            if rules
                .iter()
                .any(|r| !matches!(r, HttpCheckAction::Comment(_) | HttpCheckAction::SetVar { .. } | HttpCheckAction::UnsetVar { .. }))
            {
                return Err(check_err(
                    kw,
                    "only one 'http-check connect', before the request, is supported: Alcyon runs one request per check",
                ));
            }
            let mut addr = None;
            let mut port = None;
            let mut send_proxy = false;

            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].text.as_str() {
                    "addr" => {
                        i += 1;
                        let Some(t) = tokens.get(i) else {
                            return Err(check_err(kw, "'addr' expects an address as argument"));
                        };
                        if let Ok(sa) = t.text.parse::<SocketAddr>() {
                            addr = Some(sa);
                            port = Some(sa.port());
                        } else if let Ok(ip) = t.text.parse::<IpAddr>() {
                            addr = Some(SocketAddr::new(ip, 0));
                        } else {
                            return Err(check_err(kw, format!("'addr' : cannot parse address '{}'", t.text)));
                        }
                    }
                    "port" => {
                        i += 1;
                        let Some(t) = tokens.get(i) else {
                            return Err(check_err(kw, "'port' expects a port as argument"));
                        };
                        port = Some(parse_u16(t, "port")?);
                    }
                    "send-proxy" => send_proxy = true,
                    "comment" => {
                        i += 1;
                        if tokens.get(i).is_none() {
                            return Err(check_err(kw, "'comment' expects a string as argument"));
                        }
                    }
                    other => {
                        return Err(check_err(
                            kw,
                            format!("'http-check connect {other}' is not supported: Alcyon does not implement it"),
                        ));
                    }
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
            let Some(t) = tokens.get(2) else {
                return Err(check_err(kw, "'comment' expects a string as argument"));
            };
            rules.push(HttpCheckAction::Comment(t.text.clone()));
            Ok(())
        }
        "send-state" => {
            rules.push(HttpCheckAction::SendState);
            Ok(())
        }
        "disable-on-404" => Err(check_err(
            kw,
            "'http-check disable-on-404' is not supported: Alcyon does not implement it, and a 404 would fail the check",
        )),
        other if other.starts_with("set-var(") || other.starts_with("unset-var(") => {
            let set = other.starts_with("set-var(");
            let Some(var_name) = other
                .strip_prefix(if set { "set-var(" } else { "unset-var(" })
                .and_then(|n| n.strip_suffix(')'))
            else {
                return Err(check_err(kw, format!("'{other}' : missing closing parenthesis")));
            };
            if !var_name.starts_with("check.") || var_name.contains(',') || var_name.len() == "check.".len() {
                return Err(check_err(
                    kw,
                    format!("'{other}' : only variables of the 'check' scope are supported (check.<name>)"),
                ));
            }
            if set {
                let Some(expr) = tokens.get(2) else {
                    return Err(check_err(kw, format!("'{other}' expects an expression")));
                };
                rules.push(HttpCheckAction::SetVar { var_name: var_name.to_string(), expr: expr.text.clone() });
            } else {
                rules.push(HttpCheckAction::UnsetVar { var_name: var_name.to_string() });
            }
            Ok(())
        }
        other => Err(check_err(kw, format!("'http-check {other}' is not supported"))),
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
            let mut comment = None;

            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].text.as_str() {
                    "port" => {
                        i += 1;
                        let Some(t) = tokens.get(i) else {
                            return Err(check_err(kw, "'port' expects a port as argument"));
                        };
                        port = Some(parse_u16(t, "port")?);
                    }
                    "send-proxy" => send_proxy = true,
                    "comment" => {
                        i += 1;
                        let Some(t) = tokens.get(i) else {
                            return Err(check_err(kw, "'comment' expects a string as argument"));
                        };
                        comment = Some(t.text.clone());
                    }
                    other => {
                        return Err(check_err(
                            kw,
                            format!("'tcp-check connect {other}' is not supported: Alcyon does not implement it"),
                        ));
                    }
                }
                i += 1;
            }

            rules.push(TcpCheckAction::Connect { port, send_proxy, comment });
            Ok(())
        }
        "send-lf" | "send-binary-lf" => Err(check_err(
            kw,
            format!(
                "'tcp-check {}' is not supported: Alcyon does not implement log-format data, which would be sent as written",
                tokens[1].text
            ),
        )),
        "send" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "tcp-check send requires data",
                ));
            }
            let data = tokens[2].text.clone().into_bytes();
            rules.push(TcpCheckAction::Send(data));
            Ok(())
        }
        "send-binary" => {
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
                        min_recv = Some(parse_min_recv(&tokens[i].text, kw)?);
                    }
                    i += 1;
                    continue;
                }
                if token_text == "comment" {
                    i += 1;
                    if i < tokens.len() {
                        comment = Some(tokens[i].text.clone());
                    }
                    i += 1;
                    continue;
                }

                let mut ptext = token_text.as_str();
                if ptext.starts_with('!') {
                    negate = true;
                    ptext = &ptext[1..];
                }

                if matches!(ptext, "string" | "binary" | "rstring") && pattern.is_some() {
                    return Err(check_err(kw, "only one pattern expected"));
                }
                match ptext {
                    "string" => {
                        i += 1;
                        if i < tokens.len() {
                            pattern = Some(TcpCheckExpectPattern::String(tokens[i].text.clone()));
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
                            validate_regex_nocapture(&tokens[i])?;
                            pattern = Some(TcpCheckExpectPattern::RString(tokens[i].text.clone()));
                        }
                    }
                    "error-status" | "on-error" | "on-success" | "ok-status" | "status-code" | "tout-status"
                    | "string-lf" | "binary-lf" | "rstring-lf" => {
                        return Err(ConfigError::new(
                            kw.line,
                            kw.col,
                            format!(
                                "'tcp-check expect {ptext}' is not supported: Alcyon does not implement it, and the \
                                 rule would be evaluated without it"
                            ),
                        ));
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
            let Some(t) = tokens.get(2) else {
                return Err(check_err(kw, "'comment' expects a string as argument"));
            };
            rules.push(TcpCheckAction::Comment(t.text.clone()));
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
    let host = httpchk.and_then(|h| h.host.clone());
    let mut headers = Vec::new();
    let mut uri_lf = false;
    let mut body = None;
    let mut body_lf = false;
    let mut send_state = false;
    // `option httpchk` carries a request; the empty one a section keeps from the defaults
    // (see `take_own_http_check`) only says the checks are HTTP.
    let mut has_send = httpchk.is_some_and(|h| h.method.is_some());
    let mut pre_rules = Vec::new();
    let mut rules = Vec::new();
    let mut check_port = server.check_port;
    let mut connect_addr = None;
    let mut send_proxy = server.send_proxy || server.send_proxy_v2;
    let mut pending_comment: Option<&String> = None;
    let mut seen_expect = false;
    // `HAProxy` numbers each `http-check` line it keeps as a rule (all but `send-state`
    // and `disable-on-404`, which are flags) from 0, in order.
    let mut rule_index = 0usize;

    for act in http_checks {
        let index = rule_index;
        if !matches!(act, HttpCheckAction::SendState) {
            rule_index += 1;
        }
        match act {
            HttpCheckAction::Send {
                method: req_method,
                uri: req_uri,
                uri_lf: req_uri_lf,
                version: req_version,
                headers: req_headers,
                body: req_body,
                body_lf: req_body_lf,
            } => {
                has_send = true;
                if let Some(m) = req_method {
                    method.clone_from(m);
                }
                if let Some(u) = req_uri {
                    uri.clone_from(u);
                    uri_lf = *req_uri_lf;
                }
                if let Some(v) = req_version {
                    version.clone_from(v);
                }
                headers.extend(req_headers.iter().cloned());
                if let Some(b) = req_body {
                    body = Some(b.clone());
                    body_lf = *req_body_lf;
                }
            }
            HttpCheckAction::Expect { pattern, negate, min_recv, comment } => {
                seen_expect = true;
                rules.push(ResolvedHttpRule::Expect(ResolvedHttpExpectRule {
                    pattern: pattern.clone(),
                    negate: *negate,
                    min_recv: *min_recv,
                    comment: comment.clone().or_else(|| pending_comment.cloned()),
                    step: index + 1,
                }));
            }
            HttpCheckAction::SetVar { var_name, expr } => {
                let rule = ResolvedHttpRule::SetVar { var_name: var_name.clone(), expr: expr.clone() };
                if seen_expect { rules.push(rule) } else { pre_rules.push(rule) }
            }
            HttpCheckAction::UnsetVar { var_name } => {
                let rule = ResolvedHttpRule::UnsetVar { var_name: var_name.clone() };
                if seen_expect { rules.push(rule) } else { pre_rules.push(rule) }
            }
            HttpCheckAction::Connect { addr, port, send_proxy: sp } => {
                connect_addr = *addr;
                if port.is_some() {
                    check_port = *port;
                }
                send_proxy |= *sp;
            }
            HttpCheckAction::Comment(c) => {
                pending_comment = Some(c);
                continue;
            }
            HttpCheckAction::SendState => {
                send_state = true;
            }
        }
        pending_comment = None;
    }

    if !rules.iter().any(|r| matches!(r, ResolvedHttpRule::Expect(_))) {
        rules.push(ResolvedHttpRule::Expect(ResolvedHttpExpectRule {
            pattern: HttpCheckExpectPattern::Status(vec![(200, 399)]),
            negate: false,
            min_recv: -1,
            comment: None,
            // After the request: the implicit send of `option httpchk` is rule 0 when
            // the section has no `http-check` line.
            step: rule_index.max(1) + 1,
        }));
    }

    ResolvedHttpCheck {
        method,
        uri,
        uri_lf,
        version,
        host,
        headers,
        body,
        body_lf,
        has_send,
        send_state,
        pre_rules,
        rules,
        check_port,
        send_proxy,
        connect_addr,
    }
}

pub(crate) fn build_resolved_tcp_steps(
    tcp_checks: &[TcpCheckAction],
    server: &Server,
) -> Vec<ResolvedTcpStep> {
    let mut steps = Vec::new();
    // HAProxy adds a connect only when the first rule is not one.
    let has_connect = tcp_checks
        .iter()
        .find(|a| !matches!(a, TcpCheckAction::Comment(_)))
        .is_some_and(|a| matches!(a, TcpCheckAction::Connect { .. }));

    if !has_connect {
        steps.push(ResolvedTcpStep::Connect {
            port: server.check_port,
            send_proxy: server.send_proxy || server.send_proxy_v2,
            implicit: true,
            rule_port: None,
            comment: None,
        });
    }

    for act in tcp_checks {
        match act {
            TcpCheckAction::Connect { port, send_proxy, comment } => {
                steps.push(ResolvedTcpStep::Connect {
                    port: port.or(server.check_port),
                    send_proxy: *send_proxy || server.send_proxy || server.send_proxy_v2,
                    implicit: false,
                    rule_port: *port,
                    comment: comment.clone(),
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
                    min_recv: min_recv.unwrap_or(-1),
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
            listen.proto_check.as_ref(),
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
            backend.proto_check.as_ref(),
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
    proto_check: Option<&ProtoCheckConfig>,
    http_checks: &[HttpCheckAction],
    tcp_checks: &[TcpCheckAction],
    tcp_check: bool,
    servers: &[Server],
) {
    // The servers of a section mostly resolve to the same check (the server's `port` is
    // folded in, so not always): they share the previous one's when it is equal.
    let mut shared: Option<std::sync::Arc<ResolvedCheckConfig>> = None;
    for (server_idx, server) in servers.iter().enumerate() {
        if !server.check {
            continue;
        }
        let resolved = if let Some(proto) = proto_check {
            match proto {
                ProtoCheckConfig::Redis => ResolvedCheckConfig::Redis,
                ProtoCheckConfig::Smtp { cmd } => ResolvedCheckConfig::Smtp(cmd.clone()),
                ProtoCheckConfig::Ldap => ResolvedCheckConfig::Ldap,
                ProtoCheckConfig::Mysql { user, version } => ResolvedCheckConfig::Mysql {
                    user: user.clone(),
                    version: *version,
                },
                ProtoCheckConfig::Pgsql { user } => ResolvedCheckConfig::Pgsql {
                    user: user.clone(),
                },
                ProtoCheckConfig::SslHello => ResolvedCheckConfig::SslHello,
            }
        } else if tcp_check || !tcp_checks.is_empty() {
            let steps = build_resolved_tcp_steps(tcp_checks, server);
            ResolvedCheckConfig::TcpSteps(steps)
        } else if httpchk.is_some() {
            let chk = build_resolved_http_check(httpchk, http_checks, server);
            ResolvedCheckConfig::Http(Box::new(chk))
        } else {
            ResolvedCheckConfig::TcpConnect
        };

        let resolved = match shared.take() {
            Some(prev) if *prev == resolved => prev,
            _ => std::sync::Arc::new(resolved),
        };
        register_resolved_check(proxy_idx, server_idx, std::sync::Arc::clone(&resolved));
        register_resolved_check_for_addr(server.addr, std::sync::Arc::clone(&resolved));
        if let Some(port) = server.check_port {
            register_resolved_check_for_addr(
                SocketAddr::new(server.addr.ip(), port),
                std::sync::Arc::clone(&resolved),
            );
        }
        shared = Some(resolved);
    }
}

