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
    let (addr, is_quic) = parse_socket_addr(&tokens[2], None)?;
    if is_quic {
        return Err(ConfigError::new(kw.line, kw.col, "QUIC not supported for backend servers".to_string()));
    }
    let mut check = default_server.is_some_and(|d| d.check);
    let mut inter = default_server.and_then(|d| d.inter);
    let mut fall = default_server.and_then(|d| d.fall);
    let mut rise = default_server.and_then(|d| d.rise);
    let mut send_proxy = default_server.is_some_and(|d| d.send_proxy);
    let mut send_proxy_v2 = default_server.is_some_and(|d| d.send_proxy_v2);
    let mut maxconn = default_server.and_then(|d| d.maxconn);
    let mut check_port = default_server.and_then(|d| d.check_port);
    let mut check_proto = default_server.and_then(|d| d.check_proto.clone());
    let mut check_ssl = default_server.is_some_and(|d| d.check_ssl);
    let mut weight = None;
    let mut backup = false;

    let mut i = 3;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "check" => check = true,
            "inter" => {
                i += 1;
                if i < tokens.len() {
                    inter = Some(parse_timeout(&tokens[i], "inter")?);
                }
            }
            "fall" => {
                i += 1;
                if i < tokens.len() {
                    fall = Some(parse_u32(&tokens[i], "fall")?);
                }
            }
            "rise" => {
                i += 1;
                if i < tokens.len() {
                    rise = Some(parse_u32(&tokens[i], "rise")?);
                }
            }
            "send-proxy" => send_proxy = true,
            "send-proxy-v2" => send_proxy_v2 = true,
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
            "check-port" | "port" => {
                i += 1;
                if i < tokens.len() {
                    check_port = Some(parse_u16(&tokens[i], "check-port")?);
                }
            }
            "check-proto" => {
                i += 1;
                if i < tokens.len() {
                    check_proto = Some(tokens[i].text.clone());
                }
            }
            "check-ssl" => check_ssl = true,
            "backup" => backup = true,
            _ => {}
        }
        i += 1;
    }

    servers.push(Server {
        check_port,
        check_proto,
        check_ssl,
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
    });
    Ok(())
}

pub(crate) fn parse_default_server(
    def: &mut Option<DefaultServerConfig>,
    tokens: &[Token],
    _kw: &Token,
) -> Result<(), ConfigError> {
    let mut cfg = def.take().unwrap_or_default();
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "check" => cfg.check = true,
            "inter" => {
                i += 1;
                if i < tokens.len() {
                    cfg.inter = Some(parse_timeout(&tokens[i], "inter")?);
                }
            }
            "fall" => {
                i += 1;
                if i < tokens.len() {
                    cfg.fall = Some(parse_u32(&tokens[i], "fall")?);
                }
            }
            "rise" => {
                i += 1;
                if i < tokens.len() {
                    cfg.rise = Some(parse_u32(&tokens[i], "rise")?);
                }
            }
            "send-proxy" => cfg.send_proxy = true,
            "send-proxy-v2" => cfg.send_proxy_v2 = true,
            "maxconn" => {
                i += 1;
                if i < tokens.len() {
                    cfg.maxconn = Some(parse_u32(&tokens[i], "maxconn")?);
                }
            }
            "check-port" | "port" => {
                i += 1;
                if i < tokens.len() {
                    cfg.check_port = Some(parse_u16(&tokens[i], "check-port")?);
                }
            }
            "check-proto" => {
                i += 1;
                if i < tokens.len() {
                    cfg.check_proto = Some(tokens[i].text.clone());
                }
            }
            "check-ssl" => cfg.check_ssl = true,
            _ => {}
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

