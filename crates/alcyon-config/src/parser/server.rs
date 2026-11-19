// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

use super::*;
use crate::{ObserveMode, OnErrorMode};

#[allow(clippy::too_many_lines)]
pub(crate) fn parse_server(
    servers: &mut Vec<Server>,
    extras: &mut ServerExtras,
    default_server: Option<&DefaultServerConfig>,
    proxy: &str,
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
    if let Some(first) = extras.name_lines.get(tokens[1].text.as_str()) {
        let id = &tokens[1].text;
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("'server {proxy}/{id}' : another server named '{id}' was already defined at line {first}, please use a distinct name."),
        ));
    }
    // No port is port 0: the server connects to the stream's destination port
    // (`SRV_F_MAPPORTS`; see `connect_addr` in alcyon-rt).
    let (addr, is_quic, fqdn) = parse_server_addr(&tokens[2], Some(0))?;
    if is_quic {
        return Err(ConfigError::new(kw.line, kw.col, "QUIC not supported for backend servers".to_string()));
    }
    let who = Some(tokens[1].text.as_str());
    if let Some(name) = &fqdn {
        let prefix = server_keywords::server_prefix(who);
        // A name starting with `_` is an SRV record (T487): `crate::resolvers` in alcyon-rt
        // queries it and its records fill the slots (`srv_fill`).
        if !address::dn_label_ok(name) {
            return Err(ConfigError::new(tokens[2].line, tokens[2].col, format!("{prefix}Can't create DNS resolution for server '{}'", tokens[1].text)));
        }
    }
    let mut init_addr = default_server.and_then(|d| d.init_addr).unwrap_or_default();
    let mut resolvers = default_server.and_then(|d| d.resolvers.clone());
    let mut resolve = default_server.map(|d| d.resolve.clone()).unwrap_or_default();
    let mut check = default_server.is_some_and(|d| d.check);
    let mut inter = default_server.and_then(|d| d.inter);
    let mut fastinter = default_server.and_then(|d| d.fastinter);
    let mut downinter = default_server.and_then(|d| d.downinter);
    let mut fall = default_server.and_then(|d| d.fall);
    let mut rise = default_server.and_then(|d| d.rise);
    let mut send_proxy = default_server.is_some_and(|d| d.send_proxy);
    let mut send_proxy_v2 = default_server.is_some_and(|d| d.send_proxy_v2);
    // `srv_settings_cpy` copies `default-server`'s TLVs first; the server's own
    // `set-proxy-v2-tlv-fmt` entries are appended, so the inherited ones are sent first.
    let mut ppv2_tlvs = default_server.map(|d| d.ppv2_tlvs.clone()).unwrap_or_default();
    let mut maxconn = default_server.and_then(|d| d.maxconn);
    let mut pool_max_conn = default_server.and_then(|d| d.pool_max_conn).unwrap_or(-1);
    let mut max_reuse = default_server.and_then(|d| d.max_reuse).unwrap_or(-1);
    let mut pool_low_conn = default_server.and_then(|d| d.pool_low_conn).unwrap_or(0);
    let mut pool_purge_delay = default_server.and_then(|d| d.pool_purge_delay).unwrap_or(5000);
    let mut check_port = default_server.and_then(|d| d.check_port);
    let mut check_addr = default_server.and_then(|d| d.check_addr);
    let mut observe = default_server.map(|d| d.observe).unwrap_or_default();
    let mut error_limit = default_server.and_then(|d| d.error_limit).unwrap_or(10);
    let mut on_error = default_server.map(|d| d.on_error).unwrap_or_default();
    let mut check_proto = default_server.and_then(|d| d.check_proto);
    let mut proto_h2 = default_server.is_some_and(|d| d.proto_h2);
    let mut weight = default_server.and_then(|d| d.weight);
    let mut backup = default_server.is_some_and(|d| d.backup);
    let mut tfo = default_server.is_some_and(|d| d.tfo);
    let mut cookie = default_server.and_then(|d| d.cookie.clone());
    let mut proxy_v2_unique_id = default_server.is_some_and(|d| d.proxy_v2_unique_id);
    let mut ssl = default_server.map(|d| d.ssl.clone()).unwrap_or_default();
    let mut disabled = default_server.is_some_and(|d| d.disabled);
    let mut track = default_server.and_then(|d| d.track.clone());
    let mut puid = 0u32;
    let index = u32::try_from(servers.len()).unwrap_or(u32::MAX);
    // `srv_check_health` of a server nothing checks: the last `rise` given (`srv_settings_cpy`
    // copies the one of `default-server`, `srv_parse_check_rise` sets it again), 0 when there
    // is none, and for a server `disabled` after it.
    let mut health = if disabled { 0 } else { default_server.and_then(|d| d.rise).unwrap_or(0) };

    // Every keyword HAProxy knows is either implemented here or listed, with what Alcyon
    // does about it, in `server_keywords.rs`. A keyword's argument is consumed with it.
    let mut i = 3;
    while i < tokens.len() {
        if let Some(last) = parse_server_ssl_keyword(&mut ssl, tokens, i, who)? {
            i = last + 1;
            continue;
        }
        match tokens[i].text.as_str() {
            "check" => check = true,
            "no-check" => check = false,
            "inter" => {
                inter = Some(parse_server_delay(server_kw_arg(tokens, i, who, "expects a delay as argument.")?, "inter", who)?);
                i += 1;
            }
            "fastinter" => {
                fastinter = Some(parse_server_delay(server_kw_arg(tokens, i, who, "expects a delay as argument.")?, "fastinter", who)?);
                i += 1;
            }
            "downinter" => {
                downinter = Some(parse_server_delay(server_kw_arg(tokens, i, who, "expects a delay as argument.")?, "downinter", who)?);
                i += 1;
            }
            "fall" => {
                fall = Some(parse_check_count(server_kw_arg(tokens, i, who, "expects an integer argument.")?, "fall")?);
                i += 1;
            }
            "rise" => {
                let value = parse_check_count(server_kw_arg(tokens, i, who, "expects an integer argument.")?, "rise")?;
                rise = Some(value);
                health = value;
                i += 1;
            }
            "send-proxy" => send_proxy = true,
            "no-send-proxy" => send_proxy = false,
            "send-proxy-v2" => send_proxy_v2 = true,
            "no-send-proxy-v2" => send_proxy_v2 = false,
            t if t.starts_with("set-proxy-v2-tlv-fmt") => {
                // `srv_parse_set_proxy_v2_tlv_fmt`: the id is in the keyword's
                // parentheses, the log format the following token when there is one.
                let (id, fmt, consumed) = parse_ppv2_tlv_fmt(tokens, i, who)?;
                ppv2_tlvs.push(ProxyV2Tlv { id, fmt });
                if consumed {
                    i += 1;
                }
            }
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
            "pool-max-conn" => {
                pool_max_conn = parse_pool_max_conn(tokens, i, who)?;
                i += 1;
            }
            "max-reuse" => {
                max_reuse = parse_max_reuse(tokens, i, who)?;
                i += 1;
            }
            "pool-low-conn" => {
                pool_low_conn = parse_pool_low_conn(tokens, i, who)?;
                i += 1;
            }
            "pool-purge-delay" => {
                pool_purge_delay = parse_pool_purge_delay(tokens, i, who)?;
                i += 1;
            }
            "port" => {
                check_port = Some(parse_u16(server_kw_arg(tokens, i, who, "expects a port number as argument.")?, "port")?);
                i += 1;
            }
            "addr" => {
                check_addr = Some(parse_check_addr(server_kw_arg(tokens, i, who, "expects <ipv4|ipv6> as argument.")?, who)?);
                i += 1;
            }
            "observe" => {
                observe = parse_observe(server_kw_arg(tokens, i, who, "expects <mode> as argument.")?, who)?;
                i += 1;
            }
            "error-limit" => {
                error_limit = parse_error_limit(server_kw_arg(tokens, i, who, "expects an integer argument.")?, who)?;
                i += 1;
            }
            "on-error" => {
                on_error = parse_on_error(
                    server_kw_arg(tokens, i, who, "expects one of 'fastinter', 'fail-check', 'sudden-death' or 'mark-down' as argument.")?,
                    who,
                )?;
                i += 1;
            }
            "check-proto" => {
                check_proto = Some(parse_server_proto(tokens, i, who)?);
                i += 1;
            }
            "proto" => {
                proto_h2 = parse_server_proto(tokens, i, who)? == "h2";
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
            "id" => {
                // `srv_parse_id`: `atol`, then 1 to `u32::MAX`; a name is 0.
                let arg = server_kw_arg(tokens, i, who, "expects an integer argument")?;
                let digits: String = arg.text.chars().take_while(char::is_ascii_digit).collect();
                let value = digits.parse::<u64>().unwrap_or(0);
                let Some(id) = u32::try_from(value).ok().filter(|&v| v >= 1) else {
                    return Err(ConfigError::new(
                        arg.line,
                        arg.col,
                        format!("'server {}' : 'id' : custom id has to be between 1 and 4294967295.", tokens[1].text),
                    ));
                };
                if let Some(other) = extras.puid.iter().find(|e| e.1 == id).and_then(|e| servers.get(e.0 as usize)) {
                    return Err(ConfigError::new(
                        arg.line,
                        arg.col,
                        format!("'server {}' : 'id' : custom id {id} already used by 'server {}'", tokens[1].text, other.id),
                    ));
                }
                puid = id;
                i += 1;
            }
            "tfo" => tfo = true,
            "no-tfo" => tfo = false,
            "backup" => backup = true,
            "no-backup" => backup = false,
            "disabled" => {
                disabled = true;
                health = 0;
            }
            "enabled" => {
                disabled = false;
                health = rise.unwrap_or(0);
            }
            "track" => {
                track = Some(server_kw_arg(tokens, i, who, "expects [<proxy>/]<server> as argument.")?.text.as_str().into());
                i += 1;
            }
            "init-addr" => {
                init_addr = parse_init_addr(tokens, i, who)?;
                i += 1;
            }
            "resolve-prefer" | "resolve-net" | "resolve-opts" => {
                // `resolve-opts` alone is accepted and changes nothing.
                if parse_resolve_keyword(&mut resolve, tokens, i, who)? {
                    i += 1;
                }
            }
            "resolvers" => {
                resolvers = Some(server_kw_arg(tokens, i, who, "expects <resolvers_id> as argument.")?.text.as_str().into());
                i += 1;
            }
            // What these turn on, Alcyon never does: they leave the server as Alcyon runs it.
            "stick" | "no-agent-check" | "no-check-send-proxy" | "no-check-reuse-pool"
            | "no-send-proxy-v2-ssl" | "no-send-proxy-v2-ssl-cn" => {}
            _ => i = unimplemented_server_keyword(tokens, i, who)?,
        }
        i += 1;
    }
    if let Some(prefix) = validate_server_ssl(&ssl, check_port, kw, who)? {
        // Whether this is an error waits for the global `ssl-server-verify` (`apply_ssl_server_verify`).
        extras.no_ca.push(crate::ast::NoCa {
            line: kw.line,
            col: kw.col,
            prefix,
            explicit: ssl.verify == Some(SslVerify::Required),
        });
    }

    // Kept apart from the server: a backend of 60,000 of them must stay small.
    if health != 0 {
        extras.init_health.push((index, health));
    }
    if puid != 0 {
        extras.puid.push((index, puid));
    }
    if !ppv2_tlvs.is_empty() {
        extras.ppv2_tlvs.push((index, ppv2_tlvs));
    }
    if track.is_some() {
        extras.track_line.push((index, u32::try_from(kw.line).unwrap_or(u32::MAX)));
    }
    if let Some(sec) = &resolvers {
        extras.resolvers_refs.push((index, u32::try_from(kw.line).unwrap_or(u32::MAX), sec.clone()));
    }
    if let Some(name) = fqdn {
        extras.names.push(crate::ast::ServerName {
            index,
            line: u32::try_from(kw.line).unwrap_or(u32::MAX),
            fqdn: name.into_boxed_str(),
            init_addr,
            unresolved: false,
            resolvers,
            resolve,
            last_addr: None,
            fqdn_changed: false,
            template: None,
        });
    }
    extras.name_lines.insert(tokens[1].text.as_str().into(), u32::try_from(kw.line).unwrap_or(u32::MAX));
    servers.push(Server {
        check_port,
        check_proto,
        proto_h2,
        // Boxed, and absent when no TLS keyword touched it, so a plaintext server is 8
        // bytes (`Server` embeds no TLS state): the memory-bound tests stay where they were.
        ssl: (ssl != ServerSsl::default()).then(|| Box::new(ssl)),
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
        pool: {
            let pool = crate::ast::server::ServerPool {
                max_conn: pool_max_conn,
                low_conn: pool_low_conn,
                purge_delay: pool_purge_delay,
                fastinter_ms: fastinter.map_or(0, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
                downinter_ms: downinter.map_or(0, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
                max_reuse,
                check_addr,
                observe,
                error_limit,
                on_error,
            };
            (pool != crate::ast::server::ServerPool::default()).then(|| Box::new(pool))
        },
        backup,
        tfo,
        cookie: cookie.map(String::into_boxed_str),
        disabled,
        track,
    });
    Ok(())
}

fn parse_check_addr(tok: &Token, who: Option<&str>) -> Result<std::net::IpAddr, ConfigError> {
    tok.text.parse::<std::net::IpAddr>().map_err(|_| {
        let prefix = server_keywords::server_prefix(who);
        ConfigError::new(
            tok.line,
            tok.col,
            format!("{prefix}'addr' : invalid address '{}'.", tok.text),
        )
    })
}

fn parse_observe(tok: &Token, who: Option<&str>) -> Result<ObserveMode, ConfigError> {
    match tok.text.as_str() {
        "none" => Ok(ObserveMode::None),
        "layer4" => Ok(ObserveMode::Layer4),
        "layer7" => Ok(ObserveMode::Layer7),
        other => {
            let prefix = server_keywords::server_prefix(who);
            Err(ConfigError::new(
                tok.line,
                tok.col,
                format!("{prefix}'observe' expects one of 'none', 'layer4', 'layer7' but got '{other}'"),
            ))
        }
    }
}

fn parse_error_limit(tok: &Token, who: Option<&str>) -> Result<u32, ConfigError> {
    let n = atoi(&tok.text);
    if n <= 0 || n > i64::from(u32::MAX) {
        let prefix = server_keywords::server_prefix(who);
        return Err(ConfigError::new(
            tok.line,
            tok.col,
            format!("{prefix}'error-limit' has to be > 0."),
        ));
    }
    Ok(u32::try_from(n).unwrap_or(10))
}

fn parse_on_error(tok: &Token, who: Option<&str>) -> Result<OnErrorMode, ConfigError> {
    match tok.text.as_str() {
        "fastinter" => Ok(OnErrorMode::FastInter),
        "fail-check" => Ok(OnErrorMode::FailCheck),
        "sudden-death" => Ok(OnErrorMode::SuddenDeath),
        "mark-down" => Ok(OnErrorMode::MarkDown),
        other => {
            let prefix = server_keywords::server_prefix(who);
            Err(ConfigError::new(
                tok.line,
                tok.col,
                format!("{prefix}'on-error' expects one of 'fastinter', 'fail-check', 'sudden-death' or 'mark-down' but got '{other}'"),
            ))
        }
    }
}

/// `atoi`: the leading `[-]digits` of `s`, 0 when there are none.
fn atoi(s: &str) -> i64 {
    let (neg, digits) = s.strip_prefix('-').map_or((false, s), |d| (true, d));
    let n = digits.bytes().take_while(u8::is_ascii_digit).take(12).fold(0i64, |a, b| a * 10 + i64::from(b - b'0'));
    if neg { -n } else { n }
}

/// `server-template <prefix> <num | lo-hi> <addr>[:<port>] [from <origin>] [params*]`
/// (`_srv_parse_init` with `SRV_PARSE_TEMPLATE`): one `server <prefix><n> <addr> params*` per
/// number, so each slot is a server of its own that shares the name (and, with `resolvers`, the
/// resolution) with its siblings.
///
/// `from none` ignores `default-server`. `from be:<backend>` and `from srv:<server>` copy the
/// settings of another backend's default server or of a server, which Alcyon does not keep: refused.
pub(crate) fn parse_server_template(
    servers: &mut Vec<Server>,
    extras: &mut ServerExtras,
    default_server: Option<&DefaultServerConfig>,
    proxy: &str,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 4 || tokens[3].text.is_empty() {
        return Err(ConfigError::new(kw.line, kw.col, "'server-template' expects <prefix> <nb | range> <addr>[:<port>] as arguments."));
    }
    let prefix = &tokens[1].text;
    let range = &tokens[2];
    let (low, high) = match range.text.split_once('-') {
        Some((lo, hi)) => (atoi(lo), atoi(hi)),
        None => (1, atoi(&range.text)),
    };
    // A leading `-` makes the low bound negative (`atoi` of the whole argument).
    let low = if range.text.starts_with('-') { atoi(&range.text) } else { low };
    if low < 0 || high < low {
        return Err(ConfigError::new(range.line, range.col, format!("Wrong server-template number or range arg '{}'.", range.text)));
    }
    let who = format!("'server-template {proxy}/{prefix}' : ");
    let mut rest = 4;
    let mut default_server = default_server;
    if tokens.get(4).is_some_and(|t| t.text == "from") {
        let from = tokens.get(5).filter(|t| !t.text.is_empty());
        let Some(from) = from else {
            return Err(ConfigError::new(tokens[4].line, tokens[4].col, format!("{who}from: missing value.")));
        };
        if from.text == "none" {
            default_server = None;
        } else if from.text.starts_with("be:") || from.text.starts_with("srv:") {
            return Err(ConfigError::new(
                from.line,
                from.col,
                format!("{who}'from {}' is not supported: Alcyon settings come from default-server or 'from none' only.", from.text),
            ));
        } else {
            return Err(ConfigError::new(from.line, from.col, format!("{who}invalid '{}' value for 'from' keyword.", from.text)));
        }
        rest = 6;
    }
    let mut line: Vec<Token> = Vec::with_capacity(tokens.len());
    for n in low..=high {
        let id = format!("{prefix}{n}");
        if let Some(first) = extras.name_lines.get(id.as_str()) {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("{who}another server named '{id}' was already defined at line {first}, please use a distinct name."),
            ));
        }
        line.clear();
        line.push(Token { text: "server".to_string(), ..kw.clone() });
        line.push(Token { text: id, ..tokens[1].clone() });
        line.push(tokens[3].clone());
        line.extend_from_slice(&tokens[rest.min(tokens.len())..]);
        let before = servers.len();
        parse_server(servers, extras, default_server, proxy, &line, kw)?;
        if n == low && extras.names.last().is_some_and(|e| e.index as usize == before) {
            if let Some(e) = extras.names.last_mut() {
                e.template = Some(prefix.as_str().into());
            }
        }
    }
    Ok(())
}

/// `init-addr <method>[,...]` (`srv_parse_init_addr`). A missing argument is an empty
/// list, as in `HAProxy`: the default methods then apply.
fn parse_init_addr(tokens: &[Token], i: usize, who: Option<&str>) -> Result<crate::ast::InitAddr, ConfigError> {
    use crate::ast::InitAddrMethod as M;
    let prefix = server_keywords::server_prefix(who);
    let tok = &tokens[i];
    let fail = |msg: String| ConfigError::new(tok.line, tok.col, format!("{prefix}'init-addr' : {msg}"));
    let mut out = crate::ast::InitAddr::default();
    let list = tokens.get(i + 1).map_or("", |t| t.text.as_str());
    for p in list.split(',').filter(|p| !p.is_empty()) {
        let m = match p {
            "libc" => M::Libc,
            "none" => M::None,
            "last" => M::Last,
            _ => match p.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    if out.ip.is_some() {
                        return Err(fail(format!("initial address already specified, cannot add '{p}'..")));
                    }
                    out.ip = Some(ip);
                    M::Ip
                }
                Err(_) => {
                    return Err(fail(format!("unknown init-addr method '{p}', supported methods are 'libc', 'last', 'none'..")));
                }
            },
        };
        if !out.push(m) {
            return Err(fail(format!("too many init-addr methods when trying to add '{p}'.")));
        }
    }
    Ok(out)
}

/// `resolve-prefer`, `resolve-net` and `resolve-opts` into `opts`, checked as `HAProxy` checks
/// them (`srv_parse_resolve_*`). They act with a server's `resolvers` (T484,
/// `resolvers::pick`). Returns whether the keyword took its argument.
fn parse_resolve_keyword(opts: &mut crate::ast::ResolveOpts, tokens: &[Token], i: usize, who: Option<&str>) -> Result<bool, ConfigError> {
    let prefix = server_keywords::server_prefix(who);
    let tok = &tokens[i];
    let kw = tok.text.as_str();
    let fail = |msg: String| ConfigError::new(tok.line, tok.col, format!("{prefix}'{kw}' {msg}"));
    let a = tokens.get(i + 1).map_or("", |t| t.text.as_str());
    match kw {
        "resolve-prefer" => {
            if a != "ipv4" && a != "ipv6" {
                return Err(fail("expects either ipv4 or ipv6 as argument..".to_string()));
            }
            opts.prefer_ipv4 = a == "ipv4";
        }
        "resolve-net" => {
            if a.is_empty() {
                return Err(fail("expects a list of networks..".to_string()));
            }
            opts.nets.clear();
            for (n, net) in a.split(',').filter(|p| !p.is_empty()).enumerate() {
                if n >= 5 {
                    return Err(fail("exceed 5 networks..".to_string()));
                }
                opts.nets.push(parse_network(net).ok_or_else(|| fail(format!("invalid network '{net}'..")))?);
            }
        }
        _ => {
            for p in a.split(',').filter(|p| !p.is_empty()) {
                match p {
                    "allow-dup-ip" => opts.allow_dup_ip = true,
                    "prevent-dup-ip" => opts.allow_dup_ip = false,
                    "ignore-weight" => opts.ignore_weight = true,
                    _ => {
                        return Err(fail(format!(
                            ": unknown resolve-opts option '{p}', supported methods are 'allow-dup-ip', 'ignore-weight', and 'prevent-dup-ip'.."
                        )))
                    }
                }
            }
        }
    }
    Ok(!a.is_empty())
}

/// `str2net` (an IPv4 address, a `/bits` or dotted mask optional) or `str62net` (an IPv6
/// address, `/0` to `/128` optional), as (address, prefix length).
fn parse_network(net: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr, mask) = match net.rsplit_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (net, None),
    };
    if let Ok(a) = addr.parse::<std::net::Ipv4Addr>() {
        let bits = match mask {
            None => 32,
            Some(m) => match m.parse::<u8>() {
                Ok(b) if b <= 32 => b,
                Ok(_) => return None,
                // A dotted mask: its leading ones.
                Err(_) => u8::try_from(u32::from(m.parse::<std::net::Ipv4Addr>().ok()?).leading_ones()).ok()?,
            },
        };
        return Some((a.into(), bits));
    }
    let a = addr.parse::<std::net::Ipv6Addr>().ok()?;
    let bits = match mask {
        None => 128,
        Some(m) => m.parse::<u8>().ok().filter(|b| *b <= 128)?,
    };
    Some((a.into(), bits))
}

/// The TLS keywords of a server line (`src/cfgparse-ssl.c`). `Ok(Some(last))` when
/// `tokens[i]` is one, with the index of its last argument; `Ok(None)` when it is not.
///
/// What rustls cannot do is refused rather than approximated: it speaks TLS 1.2 and 1.3
/// only, so a line that pins an older version would describe a server Alcyon can never
/// reach. `no-sslv3`, `no-tlsv10` and `no-tlsv11` are accepted because what they ask for
/// is already the case.
#[allow(clippy::too_many_lines)]
fn parse_server_ssl_keyword(
    ssl: &mut ServerSsl,
    tokens: &[Token],
    i: usize,
    who: Option<&str>,
) -> Result<Option<usize>, ConfigError> {
    let kw = &tokens[i];
    let prefix = server_prefix(who);
    let arg = |what: &str| server_kw_arg(tokens, i, who, what);
    let list = |t: &Token| t.text.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect::<Vec<_>>();
    let rustls_only = |what: &str| {
        Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("{prefix}'{}' is not supported: rustls speaks TLS 1.2 and 1.3 only, so {what}.", kw.text),
        ))
    };
    // HAProxy skips these on a default-server line with an alert; the configuration is valid.
    if who.is_none() && matches!(kw.text.as_str(), "no-sslv3" | "no-tlsv10" | "no-tlsv11" | "no-tlsv12" | "no-tlsv13") {
        super::warn::push_alert(kw.line, crate::ast::global::WarnStyle::At, &format!("'{}' option is not accepted in default-server sections", kw.text));
        return Ok(Some(i));
    }
    let last = match kw.text.as_str() {
        "ssl" => {
            ssl.ssl = true;
            i
        }
        "no-ssl" => {
            ssl.ssl = false;
            i
        }
        "verify" => {
            let v = arg(": missing parameter.")?;
            ssl.verify = Some(match v.text.as_str() {
                "none" => SslVerify::None,
                "required" => SslVerify::Required,
                other => {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        format!("{prefix}'verify' : unknown verify method '{other}', only 'none' and 'required' are supported."),
                    ))
                }
            });
            i + 1
        }
        "ca-file" => {
            ssl.ca_file = Some(arg(": missing CAfile path.")?.text.clone());
            i + 1
        }
        "crl-file" => {
            ssl.crl_file = Some(arg(": missing CRLfile path.")?.text.clone());
            i + 1
        }
        "crt" => {
            ssl.crt = Some(arg(": missing certificate file path.")?.text.clone());
            i + 1
        }
        "sni" => {
            ssl.sni = Some(arg(": missing sni expression.")?.text.clone());
            i + 1
        }
        "sni-auto" => {
            ssl.no_sni_auto = false;
            i
        }
        "no-sni-auto" => {
            ssl.no_sni_auto = true;
            i
        }
        "verifyhost" => {
            ssl.verifyhost = Some(arg(": missing hostname to verify against.")?.text.clone());
            i + 1
        }
        "alpn" | "check-alpn" => {
            let v = list(arg(": missing the comma-delimited ALPN protocol suite.")?);
            // A TCP server cannot be offered HTTP/3, which runs over QUIC: Alcyon has no QUIC
            // connections to servers, and offered over TLS it would speak HTTP/1.1 under
            // it (T535). `HAProxy` takes it for a `quic4@` server only.
            if v.iter().any(|p| p == "h3") {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    format!("{prefix}'{}' : 'h3' is not supported: HTTP/3 to a server runs over QUIC, which Alcyon does not connect to servers with.", kw.text),
                ));
            }
            if kw.text == "alpn" {
                ssl.alpn = v;
            } else {
                ssl.check_alpn = v;
            }
            i + 1
        }
        "check-sni" => {
            ssl.check_sni = Some(arg(": missing SNI.")?.text.clone());
            i + 1
        }
        "check-sni-auto" => {
            ssl.no_check_sni_auto = false;
            i
        }
        "no-check-sni-auto" => {
            ssl.no_check_sni_auto = true;
            i
        }
        "check-ssl" => {
            ssl.check_ssl = Some(true);
            i
        }
        "no-check-ssl" => {
            ssl.check_ssl = Some(false);
            i
        }
        "ssl-min-ver" => {
            ssl.min_ver = Some(parse_tls_version(arg(": missing the ssl/tls version.")?, who)?);
            i + 1
        }
        "ssl-max-ver" => {
            ssl.max_ver = Some(parse_tls_version(arg(": missing the ssl/tls version.")?, who)?);
            i + 1
        }
        "force-tlsv12" => {
            ssl.min_ver = Some(TlsVersion::Tls12);
            ssl.max_ver = Some(TlsVersion::Tls12);
            i
        }
        "force-tlsv13" => {
            ssl.min_ver = Some(TlsVersion::Tls13);
            ssl.max_ver = Some(TlsVersion::Tls13);
            i
        }
        "force-sslv3" | "force-tlsv10" | "force-tlsv11" => {
            return rustls_only("a server that only speaks that version cannot be reached");
        }
        "no-tlsv12" => {
            ssl.min_ver = Some(TlsVersion::Tls13);
            i
        }
        "no-tlsv13" => {
            ssl.max_ver = Some(TlsVersion::Tls12);
            i
        }
        // rustls never offers these: what the keyword asks for is already the case.
        "no-sslv3" | "no-tlsv10" | "no-tlsv11" => i,
        "ssl-reuse" => {
            ssl.no_reuse = false;
            i
        }
        "no-ssl-reuse" => {
            ssl.no_reuse = true;
            i
        }
        _ => return Ok(None),
    };
    Ok(Some(last))
}

/// `ssl-min-ver` / `ssl-max-ver`: `HAProxy` knows `SSLv3` and `TLSv1.0` to `TLSv1.3`
/// ("'TLSv1.4' : unknown ssl/tls version."); rustls speaks the last two.
fn parse_tls_version(t: &Token, who: Option<&str>) -> Result<TlsVersion, ConfigError> {
    let prefix = server_prefix(who);
    match t.text.as_str() {
        "TLSv1.2" => Ok(TlsVersion::Tls12),
        "TLSv1.3" => Ok(TlsVersion::Tls13),
        "SSLv3" | "TLSv1.0" | "TLSv1.1" => Err(ConfigError::new(
            t.line,
            t.col,
            format!(
                "{prefix}'{}' is not supported: rustls speaks TLS 1.2 and 1.3 only, so a server that needs it cannot be reached.",
                t.text
            ),
        )),
        other => Err(ConfigError::new(t.line, t.col, format!("{prefix}'{other}' : unknown ssl/tls version."))),
    }
}

/// What `HAProxy` checks once a server line is complete (`ssl_sock_prepare_srv_ctx`):
/// a TLS server, or a TLS check, verifies the certificate unless told not to, and that
/// needs trust anchors. The alert is `HAProxy`'s, and whether it is raised depends on the
/// global `ssl-server-verify`, which may come later in the file: `Ok(Some(start))` is a
/// line that needs a CA it has not got, with the start of the alert for
/// `apply_ssl_server_verify` to finish.
fn validate_server_ssl(ssl: &ServerSsl, check_port: Option<u16>, kw: &Token, who: Option<&str>) -> Result<Option<String>, ConfigError> {
    let prefix = server_prefix(who);
    let mut no_ca = None;
    if (ssl.ssl || ssl.check_uses_tls(check_port)) && ssl.verify != Some(SslVerify::None) && ssl.ca_file.is_none() {
        let turned_on = if ssl.ssl { "ssl" } else { "check-ssl" };
        no_ca = Some(format!("{prefix}'{turned_on}' : "));
    }
    if let (Some(min), Some(max)) = (ssl.min_ver, ssl.max_ver) {
        if min > max {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("{prefix}no TLS version is left between 'ssl-min-ver' and 'ssl-max-ver'."),
            ));
        }
    }
    Ok(no_ca)
}

/// `proto <mux>` and `check-proto <mux>`: the protocol spoken to the server, HTTP/1.1 or,
/// since T540, HTTP/2 (`h2`: h2c over cleartext, one stream at a time as `HAProxy` under
/// `http-reuse safe`; for `check-proto h2`, an HTTP check's request goes as an h2 stream). `HAProxy` refuses a protocol it has no mux for ("'proto' :  unknown
/// MUX protocol 'h3'.").
fn parse_server_proto(tokens: &[Token], i: usize, server: Option<&str>) -> Result<&'static str, ConfigError> {
    let kw = &tokens[i];
    let value = &server_kw_arg(tokens, i, server, ": missing value.")?.text;
    let prefix = server_prefix(server);
    match value.as_str() {
        // The one protocol Alcyon speaks to servers; a `&'static str` so `Server` stays the
        // size it was before `ssl` joined it (60,000 of them are measured).
        "h1" => Ok("h1"),
        "h2" => Ok("h2"),
        "fcgi" | "spop" | "quic" | "qmux" | "none" => {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("{prefix}'{}' : '{value}' is not supported: Alcyon speaks only HTTP/1.1 and HTTP/2 to servers.", kw.text),
            ));
        }
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("{prefix}'{}' :  unknown MUX protocol '{other}'.", kw.text),
        )),
    }
}

/// `pool-max-conn <max>` (`srv_parse_pool_max_conn`): `atoi`, so text that is not a number
/// reads as 0, and anything below -1 is refused.
fn parse_pool_max_conn(tokens: &[Token], i: usize, who: Option<&str>) -> Result<i32, ConfigError> {
    let arg = server_kw_arg(tokens, i, who, "expects <value> as argument.")?;
    let t = arg.text.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = (n * 10 + i64::from(b - b'0')).min(i64::from(i32::MAX) + 1);
    }
    let n = if neg { -n } else { n };
    if n < -1 {
        let prefix = server_keywords::server_prefix(who);
        return Err(ConfigError::new(tokens[i].line, tokens[i].col, format!("{prefix}'pool-max-conn' must be >= -1")));
    }
    Ok(n.min(i64::from(i32::MAX)) as i32)
}

/// `max-reuse <count>` (`srv_parse_max_reuse`): `atoi`, so text that is not a number reads as
/// 0 (no reuse) and any negative number is no limit.
fn parse_max_reuse(tokens: &[Token], i: usize, who: Option<&str>) -> Result<i32, ConfigError> {
    let arg = server_kw_arg(tokens, i, who, "expects <value> as argument.")?;
    let t = arg.text.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = (n * 10 + i64::from(b - b'0')).min(i64::from(i32::MAX));
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(if neg { -n } else { n } as i32)
}

/// `pool-low-conn <max>` (`srv_parse_pool_low_conn`): `atoi` into an unsigned count, so text
/// that is not a number reads as 0 and a negative number wraps.
fn parse_pool_low_conn(tokens: &[Token], i: usize, who: Option<&str>) -> Result<u32, ConfigError> {
    let arg = server_kw_arg(tokens, i, who, "expects <value> as argument.")?;
    let t = arg.text.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = (n * 10 + i64::from(b - b'0')).min(i64::from(i32::MAX));
    }
    let n = if neg { -n } else { n };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(n as i32 as u32)
}

/// `pool-purge-delay <delay>` (`srv_parse_pool_purge_delay`): a time in milliseconds by
/// default, with `HAProxy`'s messages.
fn parse_pool_purge_delay(tokens: &[Token], i: usize, who: Option<&str>) -> Result<u32, ConfigError> {
    let arg = server_kw_arg(tokens, i, who, "expects <value> as argument.")?;
    let prefix = server_keywords::server_prefix(who);
    super::rules_http::parse_time_ms(&arg.text).map_err(|e| {
        let msg = if e.starts_with("unexpected character") {
            format!("{prefix}{} in argument to <pool-purge-delay>.", e.trim_end_matches('.'))
        } else {
            format!(
                "{prefix}timer overflow in argument '{}' to 'pool-purge-delay' (maximum value is 2147483647 ms or ~24.8 days)",
                arg.text
            )
        };
        ConfigError::new(tokens[i].line, tokens[i].col, msg)
    })
}

pub(crate) fn parse_default_server(
    def: &mut Option<DefaultServerConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let mut cfg = def.take().unwrap_or_default();
    let mut i = 1;
    while i < tokens.len() {
        if let Some(last) = parse_server_ssl_keyword(&mut cfg.ssl, tokens, i, None)? {
            i = last + 1;
            continue;
        }
        match tokens[i].text.as_str() {
            "check" => cfg.check = true,
            "no-check" => cfg.check = false,
            "inter" => {
                cfg.inter = Some(parse_server_delay(server_kw_arg(tokens, i, None, "expects a delay as argument.")?, "inter", None)?);
                i += 1;
            }
            "fastinter" => {
                cfg.fastinter = Some(parse_server_delay(server_kw_arg(tokens, i, None, "expects a delay as argument.")?, "fastinter", None)?);
                i += 1;
            }
            "downinter" => {
                cfg.downinter = Some(parse_server_delay(server_kw_arg(tokens, i, None, "expects a delay as argument.")?, "downinter", None)?);
                i += 1;
            }
            "fall" => {
                cfg.fall = Some(parse_check_count(server_kw_arg(tokens, i, None, "expects an integer argument.")?, "fall")?);
                i += 1;
            }
            "rise" => {
                cfg.rise = Some(parse_check_count(server_kw_arg(tokens, i, None, "expects an integer argument.")?, "rise")?);
                i += 1;
            }
            "send-proxy" => cfg.send_proxy = true,
            "no-send-proxy" => cfg.send_proxy = false,
            "send-proxy-v2" => cfg.send_proxy_v2 = true,
            "no-send-proxy-v2" => cfg.send_proxy_v2 = false,
            t if t.starts_with("set-proxy-v2-tlv-fmt") => {
                let (id, fmt, consumed) = parse_ppv2_tlv_fmt(tokens, i, None)?;
                cfg.ppv2_tlvs.push(ProxyV2Tlv { id, fmt });
                if consumed {
                    i += 1;
                }
            }
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
            "pool-max-conn" => {
                cfg.pool_max_conn = Some(parse_pool_max_conn(tokens, i, None)?);
                i += 1;
            }
            "max-reuse" => {
                cfg.max_reuse = Some(parse_max_reuse(tokens, i, None)?);
                i += 1;
            }
            "pool-low-conn" => {
                cfg.pool_low_conn = Some(parse_pool_low_conn(tokens, i, None)?);
                i += 1;
            }
            "pool-purge-delay" => {
                cfg.pool_purge_delay = Some(parse_pool_purge_delay(tokens, i, None)?);
                i += 1;
            }
            "port" => {
                cfg.check_port = Some(parse_u16(server_kw_arg(tokens, i, None, "expects a port number as argument.")?, "port")?);
                i += 1;
            }
            "addr" => {
                cfg.check_addr = Some(parse_check_addr(server_kw_arg(tokens, i, None, "expects <ipv4|ipv6> as argument.")?, None)?);
                i += 1;
            }
            "observe" => {
                cfg.observe = parse_observe(server_kw_arg(tokens, i, None, "expects <mode> as argument.")?, None)?;
                i += 1;
            }
            "error-limit" => {
                cfg.error_limit = Some(parse_error_limit(server_kw_arg(tokens, i, None, "expects an integer argument.")?, None)?);
                i += 1;
            }
            "on-error" => {
                cfg.on_error = parse_on_error(
                    server_kw_arg(tokens, i, None, "expects one of 'fastinter', 'fail-check', 'sudden-death' or 'mark-down' as argument.")?,
                    None,
                )?;
                i += 1;
            }
            "check-proto" => {
                cfg.check_proto = Some(parse_server_proto(tokens, i, None)?);
                i += 1;
            }
            "proto" => {
                cfg.proto_h2 = parse_server_proto(tokens, i, None)? == "h2";
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
            "tfo" => cfg.tfo = true,
            "no-tfo" => cfg.tfo = false,
            "backup" => cfg.backup = true,
            "no-backup" => cfg.backup = false,
            "disabled" => cfg.disabled = true,
            "enabled" => cfg.disabled = false,
            "track" => {
                cfg.track = Some(server_kw_arg(tokens, i, None, "expects [<proxy>/]<server> as argument.")?.text.as_str().into());
                i += 1;
            }
            "init-addr" => {
                cfg.init_addr = Some(parse_init_addr(tokens, i, None)?);
                i += 1;
            }
            "resolve-prefer" | "resolve-net" | "resolve-opts" => {
                if parse_resolve_keyword(&mut cfg.resolve, tokens, i, None)? {
                    i += 1;
                }
            }
            "resolvers" => {
                cfg.resolvers = Some(server_kw_arg(tokens, i, None, "expects <resolvers_id> as argument.")?.text.as_str().into());
                i += 1;
            }
            "stick" | "no-agent-check" | "no-check-send-proxy" | "no-check-reuse-pool"
            | "no-send-proxy-v2-ssl" | "no-send-proxy-v2-ssl-cn" => {}
            _ => i = unimplemented_server_keyword(tokens, i, None)?,
        }
        i += 1;
    }
    *def = Some(cfg);
    Ok(())
}

pub(crate) fn parse_balance(
    balance: &mut BalanceAlgorithm,
    uri: &mut UriHash,
    tokens: &[Token],
    _kw: &Token,
) -> Result<(), ConfigError> {
    // HAProxy clears the algorithm's arguments on every `balance` line.
    *uri = UriHash::default();
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        // Bare `balance` selects `BE_LB_ALGO_RND` without setting `arg_opt1` (`backend_parse_balance`),
        // so `get_server_rnd` performs 1 draw.
        *balance = BalanceAlgorithm::Random(1);
        return Ok(());
    }
    *balance = match tokens[1].text.as_str() {
        "roundrobin" => BalanceAlgorithm::RoundRobin,
        "source" => BalanceAlgorithm::Source,
        "uri" => {
            *uri = parse_balance_uri(tokens)?;
            BalanceAlgorithm::Uri
        }
        "leastconn" => BalanceAlgorithm::Leastconn,
        "static-rr" => BalanceAlgorithm::StaticRr,
        "first" => BalanceAlgorithm::First,
        other if other.starts_with("random") => BalanceAlgorithm::Random(parse_random_draws(&tokens[1])?),
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

/// Parses `random` / `random(<draws>)` as `backend_parse_balance` (`src/backend.c`) does:
/// `random` or `random()` defaults to 2 draws; otherwise `strtol(beg, &end, 0)` into an `int`.
fn parse_random_draws(tok: &Token) -> Result<u32, ConfigError> {
    let rest = &tok.text["random".len()..];
    let Some(beg) = rest.strip_prefix('(').filter(|b| !b.starts_with(')')) else {
        return Ok(2);
    };
    let (draws, end) = c_strtol0(beg);
    let tail = &beg[end..];
    match tail.chars().next() {
        None => {
            return Err(ConfigError::new(
                tok.line,
                tok.col,
                "balance random : missing closing parenthesis.",
            ));
        }
        Some(ch) if ch != ')' => {
            return Err(ConfigError::new(
                tok.line,
                tok.col,
                format!("balance random : unexpected character '{ch}' after argument."),
            ));
        }
        Some(_) => {}
    }
    #[allow(clippy::cast_possible_truncation)]
    let draws_i32 = draws as i32;
    if draws_i32 < 1 {
        return Err(ConfigError::new(
            tok.line,
            tok.col,
            "balance random : number of draws must be at least 1.",
        ));
    }
    Ok(draws_i32.cast_unsigned())
}

/// C's `strtol(s, &end, 0)`: optional blanks and sign, `0x` hex, leading-`0` octal or decimal,
/// returning `(value, end_byte_offset)` (`end == 0` when no digits were read).
fn c_strtol0(s: &str) -> (i64, usize) {
    let b = s.as_bytes();
    let mut j = b
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
        .unwrap_or(b.len());
    let neg = match b.get(j) {
        Some(b'-') => {
            j += 1;
            true
        }
        Some(b'+') => {
            j += 1;
            false
        }
        _ => false,
    };
    let (radix, digits_at) = if b.get(j) == Some(&b'0')
        && matches!(b.get(j + 1), Some(b'x' | b'X'))
        && b.get(j + 2).is_some_and(u8::is_ascii_hexdigit)
    {
        (16, j + 2)
    } else if b.get(j) == Some(&b'0') {
        (8, j)
    } else {
        (10, j)
    };
    let mut k = digits_at;
    while b.get(k).is_some_and(|c| char::from(*c).is_digit(radix)) {
        k += 1;
    }
    if k == digits_at {
        return (0, 0);
    }
    let digits = &s[digits_at..k];
    let val = if neg {
        u64::from_str_radix(digits, radix)
            .ok()
            .and_then(|u| i64::try_from(u).ok().map(i64::wrapping_neg))
            .unwrap_or(i64::MIN)
    } else {
        i64::from_str_radix(digits, radix).unwrap_or(i64::MAX)
    };
    (val, k)
}

/// The options after `balance uri`, read and refused as `backend_parse_balance` does
/// (`src/backend.c`): `whole`, `path-only`, `len <n>` and `depth <n>` in any order, a
/// repeated one keeping its last value, anything else an error. The other algorithms take
/// no option and `HAProxy` does not look at what follows them, so neither does Alcyon.
fn parse_balance_uri(tokens: &[Token]) -> Result<UriHash, ConfigError> {
    let mut opts = UriHash::default();
    let mut i = 2;
    while let Some(tok) = tokens.get(i).filter(|t| !t.text.is_empty()) {
        let name = tok.text.as_str();
        match name {
            "len" | "depth" => {
                let arg = tokens.get(i + 1).map_or("", |t| t.text.as_str());
                let n = c_atoi(arg);
                if n <= 0 {
                    return Err(ConfigError::new(
                        tok.line,
                        tok.col,
                        format!("balance uri : '{name}' expects a positive integer (got '{arg}')."),
                    ));
                }
                if name == "len" {
                    opts.len = n.unsigned_abs();
                } else {
                    opts.depth_end = n.wrapping_add(1);
                }
                i += 2;
            }
            "whole" => {
                opts.whole = true;
                i += 1;
            }
            "path-only" => {
                opts.path_only = true;
                i += 1;
            }
            other => {
                return Err(ConfigError::new(
                    tok.line,
                    tok.col,
                    format!("balance uri only accepts parameters 'len', 'depth', 'path-only', and 'whole' (got '{other}')."),
                ));
            }
        }
    }
    Ok(opts)
}

/// C's `atoi` as glibc runs it, which is how `HAProxy` reads these numbers: blanks, a sign,
/// then digits up to the first other byte (`3x` is 3, `x` is 0), the `long` cut to an
/// `int` (2^31 is negative, 2^32 + 1 is 1).
fn c_atoi(text: &str) -> i32 {
    let t = text.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut v: i64 = 0;
    for d in digits.bytes().take_while(u8::is_ascii_digit) {
        v = v.saturating_mul(10).saturating_add(i64::from(d - b'0'));
    }
    // Truncation is the point: `(int) strtol(..)`.
    #[allow(clippy::cast_possible_truncation)]
    let n = if neg { v.saturating_neg() } else { v } as i32;
    n
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
                "'hash-preserve-affinity maxqueue' is not implemented: Alcyon has no per-server \
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
/// in the header that Alcyon does not build, so they are refused rather than left out of it.
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
                    format!("'proxy-v2-options' : '{opt}' is not implemented in Alcyon"),
                ));
            }
            _ => {
                return Err(ConfigError::new(kw.line, kw.col, format!("'{opt}' : proxy v2 option not implemented")));
            }
        }
    }
    Ok(unique_id)
}

/// `set-proxy-v2-tlv-fmt(<id>) [<fmt>]` on the line of `server` (`None` for
/// `default-server`), at `tokens[i]`. Returns the TLV id, the log format (the following
/// token's text when there is one, else empty) and whether that token was consumed.
/// `srv_parse_set_proxy_v2_tlv_fmt` reads the id from the keyword itself and the format
/// from `args[*cur_arg + 1]`, unconditionally.
fn parse_ppv2_tlv_fmt(
    tokens: &[Token],
    i: usize,
    who: Option<&str>,
) -> Result<(u8, Box<str>, bool), ConfigError> {
    let tok = &tokens[i];
    let token = tok.text.as_str();
    let id = match token.strip_prefix("set-proxy-v2-tlv-fmt(") {
        Some(inner) => parse_ppv2_tlv_id(inner, token, who, tok.line, tok.col)?,
        None => 0, // `set-proxy-v2-tlv-fmt` with no parentheses: `*cmd` is not `'('`, id stays 0.
    };
    let (fmt, consumed) = match tokens.get(i + 1).filter(|t| !t.text.is_empty()) {
        Some(next) => (next.text.clone().into_boxed_str(), true),
        None => (Box::<str>::default(), false),
    };
    Ok((id, fmt, consumed))
}

/// The `<id>` of `set-proxy-v2-tlv-fmt(<id>)`, with C's `strtoul(, 0)` semantics
/// (`srv_parse_set_proxy_v2_tlv_fmt`): an optional sign, then `0x` hex (only when a hex
/// digit follows), `0b` binary (only when a `0`/`1` follows), a leading `0` octal (the `0`
/// itself is the first digit), or decimal. `inner` is the token text after the `(`, so it
/// ends with the closing `)` the scan must stop at. Measured on 3.5-dev11: `08`, `0x`, `0b`
/// and `1e1` all stop mid-number ("expects ..."), `abc` and `()` convert nothing
/// ("could not convert ..."), `0b100` is 4, `-1` is the maximum unsigned and trips the
/// 255 limit.
fn parse_ppv2_tlv_id(inner: &str, token: &str, who: Option<&str>, line: usize, col: usize) -> Result<u8, ConfigError> {
    let reject = |reason: &str| {
        ConfigError::new(line, col, format!("{}'{}' : {reason}", server_keywords::server_prefix(who), token))
    };
    let mut s = inner;
    let neg = match s.as_bytes().first() {
        Some(b'-') => {
            s = &s[1..];
            true
        }
        Some(b'+') => {
            s = &s[1..];
            false
        }
        _ => false,
    };
    let (base, digits) = if s.starts_with("0x") || s.starts_with("0X") {
        let after = &s[2..];
        if after.bytes().next().is_some_and(|c| (c as char).to_digit(16).is_some()) {
            (16, after)
        } else {
            (8, s) // a `0x` with no hex digit is an octal `0` followed by junk.
        }
    } else if s.starts_with("0b") || s.starts_with("0B") {
        let after = &s[2..];
        if after.bytes().next().is_some_and(|c| matches!(c, b'0' | b'1')) {
            (2, after)
        } else {
            (8, s)
        }
    } else if s.starts_with('0') {
        (8, s)
    } else {
        (10, s)
    };
    let mut n = 0usize;
    for c in digits.bytes() {
        if (c as char).to_digit(base).is_some() {
            n += 1;
        } else {
            break;
        }
    }
    if n == 0 {
        return Err(reject("could not convert TLV ID"));
    }
    // `*error` must be the closing parenthesis.
    if digits[n..].as_bytes().first() != Some(&b')') {
        return Err(reject("expects set-proxy-v2-tlv(<TLV ID>)"));
    }
    // The value, C's `ERANGE` included; the sign is applied afterwards, as unsigned.
    let magnitude = u64::from_str_radix(&digits[..n], base).map_err(|_| reject("could not convert TLV ID"))?;
    let value = if neg { magnitude.wrapping_neg() } else { magnitude };
    if value > 0xFF {
        return Err(reject("the maximum allowed TLV ID is 255"));
    }
    Ok(value as u8)
}

/// `fall`/`rise` are `int`s in HAProxy: one past `i32::MAX` reads negative and is refused
/// ("'rise' has to be > 0"; measured on 3.5-dev8: 2147483647 accepted, 2147483648 refused).
fn parse_check_count(token: &Token, keyword: &str) -> Result<u32, ConfigError> {
    let v = parse_u32(token, keyword)?;
    if v == 0 || v > i32::MAX as u32 {
        return Err(ConfigError::new(token.line, token.col, format!("'{keyword}' has to be > 0.")));
    }
    Ok(v)
}
