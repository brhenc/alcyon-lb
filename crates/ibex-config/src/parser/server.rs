// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;

pub(crate) fn parse_server(
    servers: &mut Vec<Server>,
    default_server: Option<&DefaultServerConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<server> expects <name> and <addr:port> as arguments.",
        ));
    }
    // No port is port 0: the server connects to the stream's destination port
    // (`SRV_F_MAPPORTS`; see `connect_addr` in ibex-rt).
    let (addr, is_quic) = parse_socket_addr(&tokens[2], Some(0))?;
    if is_quic {
        return Err(ConfigError::new(kw.line, kw.col, "QUIC not supported for backend servers".to_string()));
    }
    let who = Some(tokens[1].text.as_str());
    let mut check = default_server.is_some_and(|d| d.check);
    let mut inter = default_server.and_then(|d| d.inter);
    let mut fall = default_server.and_then(|d| d.fall);
    let mut rise = default_server.and_then(|d| d.rise);
    let mut send_proxy = default_server.is_some_and(|d| d.send_proxy);
    let mut send_proxy_v2 = default_server.is_some_and(|d| d.send_proxy_v2);
    let mut maxconn = default_server.and_then(|d| d.maxconn);
    let mut check_port = default_server.and_then(|d| d.check_port);
    let mut check_proto = default_server.and_then(|d| d.check_proto.clone());
    let mut weight = default_server.and_then(|d| d.weight);
    let mut backup = default_server.is_some_and(|d| d.backup);
    let mut cookie = default_server.and_then(|d| d.cookie.clone());
    let mut proxy_v2_unique_id = default_server.is_some_and(|d| d.proxy_v2_unique_id);
    let mut disabled = default_server.is_some_and(|d| d.disabled);

    // Every keyword HAProxy knows is either implemented here or listed, with what Ibex
    // does about it, in `server_keywords.rs`. A keyword's argument is consumed with it.
    let mut i = 3;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "check" => check = true,
            "no-check" => check = false,
            "inter" => {
                inter = Some(parse_timeout(server_kw_arg(tokens, i, who, "expects a delay as argument.")?, "inter")?);
                i += 1;
            }
            "fall" => {
                fall = Some(parse_u32(server_kw_arg(tokens, i, who, "expects an integer argument.")?, "fall")?);
                i += 1;
            }
            "rise" => {
                rise = Some(parse_u32(server_kw_arg(tokens, i, who, "expects an integer argument.")?, "rise")?);
                i += 1;
            }
            "send-proxy" => send_proxy = true,
            "no-send-proxy" => send_proxy = false,
            "send-proxy-v2" => send_proxy_v2 = true,
            "no-send-proxy-v2" => send_proxy_v2 = false,
            "weight" => {
                i += 1;
                if i < tokens.len() {
                    weight = Some(parse_u32(&tokens[i], "weight")?);
                }
            }
            "maxconn" => {
                i += 1;
                if i < tokens.len() {
                    maxconn = Some(parse_u32(&tokens[i], "maxconn")?);
                }
            }
            "port" => {
                check_port = Some(parse_u16(server_kw_arg(tokens, i, who, "expects a port number as argument.")?, "port")?);
                i += 1;
            }
            "check-proto" => {
                check_proto = Some(parse_server_proto(tokens, i, who)?);
                i += 1;
            }
            "proto" => {
                parse_server_proto(tokens, i, who)?;
                i += 1;
            }
            "cookie" => {
                cookie = Some(server_kw_arg(tokens, i, who, "expects <value> as argument.")?.text.clone());
                i += 1;
            }
            "proxy-v2-options" => {
                i += 1;
                proxy_v2_unique_id |= parse_proxy_v2_options(tokens.get(i), kw)?;
            }
            "backup" => backup = true,
            "no-backup" => backup = false,
            "disabled" => disabled = true,
            "enabled" => disabled = false,
            // What these turn on, Ibex never does: they leave the server as Ibex runs it.
            "stick" | "no-agent-check" | "no-check-send-proxy" | "no-check-reuse-pool" | "no-ssl"
            | "no-check-ssl" | "no-send-proxy-v2-ssl" | "no-send-proxy-v2-ssl-cn" | "no-sni-auto"
            | "no-check-sni-auto" => {}
            _ => i = unimplemented_server_keyword(tokens, i, who)?,
        }
        i += 1;
    }

    servers.push(Server {
        check_port,
        check_proto,
        check_ssl: false,
        proxy_v2_unique_id,
        id: tokens[1].text.clone(),
        addr,
        check,
        inter,
        fall,
        rise,
        send_proxy,
        send_proxy_v2,
        weight,
        maxconn,
        backup,
        cookie,
        disabled,
    });
    Ok(())
}

/// `proto <mux>` and `check-proto <mux>`: the protocol spoken to the server. Ibex speaks
/// HTTP/1.1. `h2` is accepted with a warning: a server that expects h2 refuses HTTP/1.1
/// rather than misreading it, and two reg-tests that pass rely on it. `HAProxy` refuses a
/// protocol it has no mux for ("'proto' :  unknown MUX protocol 'h3'.").
fn parse_server_proto(tokens: &[Token], i: usize, server: Option<&str>) -> Result<String, ConfigError> {
    let kw = &tokens[i];
    let value = &server_kw_arg(tokens, i, server, ": missing value.")?.text;
    let prefix = server_prefix(server);
    match value.as_str() {
        "h1" => {}
        "h2" => eprintln!(
            "[ibex] warning: {prefix}'{} h2' is not implemented and is ignored; Ibex speaks HTTP/1.1 to this server.",
            kw.text
        ),
        "fcgi" | "spop" | "quic" | "qmux" | "none" => {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("{prefix}'{}' : '{value}' is not supported: Ibex speaks only HTTP/1.1 to servers.", kw.text),
            ));
        }
        other => {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("{prefix}'{}' :  unknown MUX protocol '{other}'.", kw.text),
            ));
        }
    }
    Ok(value.clone())
}

pub(crate) fn parse_default_server(
    def: &mut Option<DefaultServerConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let mut cfg = def.take().unwrap_or_default();
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "check" => cfg.check = true,
            "no-check" => cfg.check = false,
            "inter" => {
                cfg.inter = Some(parse_timeout(server_kw_arg(tokens, i, None, "expects a delay as argument.")?, "inter")?);
                i += 1;
            }
            "fall" => {
                cfg.fall = Some(parse_u32(server_kw_arg(tokens, i, None, "expects an integer argument.")?, "fall")?);
                i += 1;
            }
            "rise" => {
                cfg.rise = Some(parse_u32(server_kw_arg(tokens, i, None, "expects an integer argument.")?, "rise")?);
                i += 1;
            }
            "send-proxy" => cfg.send_proxy = true,
            "no-send-proxy" => cfg.send_proxy = false,
            "send-proxy-v2" => cfg.send_proxy_v2 = true,
            "no-send-proxy-v2" => cfg.send_proxy_v2 = false,
            "weight" => {
                i += 1;
                if i < tokens.len() {
                    cfg.weight = Some(parse_u32(&tokens[i], "weight")?);
                }
            }
            "maxconn" => {
                i += 1;
                if i < tokens.len() {
                    cfg.maxconn = Some(parse_u32(&tokens[i], "maxconn")?);
                }
            }
            "port" => {
                cfg.check_port = Some(parse_u16(server_kw_arg(tokens, i, None, "expects a port number as argument.")?, "port")?);
                i += 1;
            }
            "check-proto" => {
                cfg.check_proto = Some(parse_server_proto(tokens, i, None)?);
                i += 1;
            }
            "proto" => {
                parse_server_proto(tokens, i, None)?;
                i += 1;
            }
            "cookie" => {
                cfg.cookie = Some(server_kw_arg(tokens, i, None, "expects <value> as argument.")?.text.clone());
                i += 1;
            }
            "proxy-v2-options" => {
                i += 1;
                cfg.proxy_v2_unique_id |= parse_proxy_v2_options(tokens.get(i), kw)?;
            }
            "backup" => cfg.backup = true,
            "no-backup" => cfg.backup = false,
            "disabled" => cfg.disabled = true,
            "enabled" => cfg.disabled = false,
            "stick" | "no-agent-check" | "no-check-send-proxy" | "no-check-reuse-pool" | "no-ssl"
            | "no-check-ssl" | "no-send-proxy-v2-ssl" | "no-send-proxy-v2-ssl-cn" | "no-sni-auto"
            | "no-check-sni-auto" => {}
            _ => i = unimplemented_server_keyword(tokens, i, None)?,
        }
        i += 1;
    }
    *def = Some(cfg);
    Ok(())
}

pub(crate) fn parse_balance(
    balance: &mut BalanceAlgorithm,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<balance> expects an algorithm as argument.",
        ));
    }
    *balance = match tokens[1].text.as_str() {
        "roundrobin" => BalanceAlgorithm::RoundRobin,
        "source" => BalanceAlgorithm::Source,
        "uri" => BalanceAlgorithm::Uri,
        "leastconn" => BalanceAlgorithm::Leastconn,
        "static-rr" => BalanceAlgorithm::StaticRr,
        "first" => BalanceAlgorithm::First,
        "random" => BalanceAlgorithm::Random(2),
        other if other.starts_with("random(") => {
            let Some(inner) = other.strip_prefix("random(").and_then(|s| s.strip_suffix(')')) else {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    "random : missing closing parenthesis.",
                ));
            };
            let draws: u32 = inner.parse().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("random : unexpected argument '{inner}'."),
                )
            })?;
            if draws < 1 {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    "random : number of draws must be at least 1.",
                ));
            }
            BalanceAlgorithm::Random(draws)
        }
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("unknown balance algorithm <{other}>"),
            ));
        }
    };
    Ok(())
}

pub(crate) fn parse_hash_type(
    hash_type: &mut HashType,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "'hash-type' only supports 'consistent' and 'map-based'.",
        ));
    }
    *hash_type = match tokens[1].text.as_str() {
        "consistent" => HashType::Consistent,
        "map-based" => HashType::MapBased,
        _ => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                "'hash-type' only supports 'consistent' and 'map-based'.",
            ));
        }
    };
    if tokens.len() > 2 {
        return Err(ConfigError::new(
            tokens[2].line,
            tokens[2].col,
            "'hash-type': hash function and 'avalanche' modifiers are not implemented.",
        ));
    }
    Ok(())
}

pub(crate) fn parse_hash_preserve_affinity(
    mode: &mut HashPreserveAffinity,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "'hash-preserve-affinity' needs a keyword to specify when to preserve hash affinity.",
        ));
    }
    *mode = match tokens[1].text.as_str() {
        "always" => HashPreserveAffinity::Always,
        "maxconn" => HashPreserveAffinity::MaxConn,
        "maxqueue" => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                "'hash-preserve-affinity maxqueue' is not implemented: Ibex has no per-server \
                 request queue, so it cannot hold a request at a saturated server until that \
                 server's queue fills. Use 'always' or 'maxconn'.",
            ));
        }
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("'hash-preserve-affinity': unknown keyword '{other}'."),
            ));
        }
    };
    Ok(())
}

pub(crate) fn parse_http_reuse(
    reuse: &mut Option<HttpReuse>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-reuse> expects a strategy ('never', 'safe', 'aggressive', 'always') as argument.",
        ));
    }
    *reuse = match tokens[1].text.as_str() {
        "never" => Some(HttpReuse::Never),
        "safe" => Some(HttpReuse::Safe),
        "aggressive" => Some(HttpReuse::Aggressive),
        "always" => Some(HttpReuse::Always),
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("unknown http-reuse strategy <{other}>, expected 'never', 'safe', 'aggressive', or 'always'"),
            ));
        }
    };
    Ok(())
}


/// `proxy-v2-options <option>[,<option>]*` (`srv_parse_proxy_v2_options`): whether it asks
/// for `unique-id`. `HAProxy`'s other options (the SSL ones, `authority`, `crc32c`) put TLVs
/// in the header that Ibex does not build, so they are refused rather than left out of it.
fn parse_proxy_v2_options(arg: Option<&Token>, kw: &Token) -> Result<bool, ConfigError> {
    let text = arg.map_or("", |t| t.text.as_str());
    let mut unique_id = false;
    for opt in text.split(',') {
        match opt {
            "unique-id" => unique_id = true,
            "ssl" | "cert-cn" | "cert-key" | "cert-sig" | "ssl-cipher" | "authority" | "crc32c" => {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    format!("'proxy-v2-options' : '{opt}' is not implemented in Ibex"),
                ));
            }
            _ => {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{opt}' : proxy v2 option not implemented")));
            }
        }
    }
    Ok(unique_id)
}
