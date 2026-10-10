// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `ring` and `log-forward` sections (`cfg_parse_ring` in `src/sink.c`,
//! `cfg_parse_log_forward` in `src/log.c`).
//!
//! Every keyword read here reaches the runtime in `ibex-rt`'s `ring.rs` (the buffers, their
//! forwarders and `show events`) and `logfwd.rs` (the listeners and the relaying); one
//! `HAProxy` has and Ibex does not is refused rather than read and dropped.

use super::*;
use crate::ast::{LogForwardBind, LogForwardHost, RingFormat, RingServer, RingServerAddr};

/// The sinks `HAProxy` always has: a ring cannot take their names.
const BUILTIN_SINKS: &[&str] = &["stdout", "stderr", "buf0", "dpapi"];

/// `invalid_char`: a name is letters, digits and `_ - . :`.
fn invalid_char(name: &str) -> Option<char> {
    name.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')))
}

fn err(tok: &Token, msg: impl Into<String>) -> ConfigError {
    ConfigError::new(tok.line, tok.col, msg)
}

pub(crate) fn parse_ring_header(tokens: &[Token], kw: &Token, rings: &[RingSection]) -> Result<RingSection, ConfigError> {
    let Some(name) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
        return Err(err(kw, "missing ring name."));
    };
    if let Some(c) = invalid_char(&name.text) {
        return Err(err(name, format!("invalid ring name '{}' (character '{c}' is not permitted).", name.text)));
    }
    if rings.iter().any(|r| r.name == name.text) || BUILTIN_SINKS.contains(&name.text.as_str()) {
        return Err(err(name, format!("sink named '{}' already exists.", name.text)));
    }
    Ok(RingSection {
        name: name.text.clone(),
        description: None,
        format: RingFormat::Raw,
        maxlen: None,
        size: 16384,
        timeout_connect: Duration::from_millis(5000),
        timeout_server: Duration::from_millis(5000),
        servers: Vec::new(),
    })
}

pub(crate) fn parse_ring_directive(ring: &mut RingSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    let arg = tokens.get(1).filter(|t| !t.text.is_empty());
    match kw.text.as_str() {
        "description" => {
            let Some(a) = arg else {
                return Err(err(kw, "missing ring description text."));
            };
            ring.description = Some(a.text.clone());
        }
        "format" => {
            let Some(a) = arg else {
                return Err(err(kw, "unable to set format ''."));
            };
            ring.format = RingFormat::from_name(&a.text).ok_or_else(|| err(a, format!("unknown format '{}'.", a.text)))?;
        }
        "maxlen" => {
            let n = arg.and_then(|a| a.text.parse::<usize>().ok()).filter(|n| *n > 0);
            let Some(n) = n else {
                return Err(err(kw, format!("invalid size '{}' for new sink buffer.", arg.map_or("", |a| a.text.as_str()))));
            };
            ring.maxlen = Some(n);
        }
        "size" => {
            let n = arg.and_then(|a| parse_size(a).ok()).filter(|n| *n > 0);
            let Some(n) = n else {
                return Err(err(kw, format!("invalid size '{}' for new sink buffer.", arg.map_or("", |a| a.text.as_str()))));
            };
            ring.size = n;
        }
        "timeout" => {
            let which = arg.map(|a| a.text.as_str());
            if matches!(which, Some("connect" | "server")) {
                let Some(t) = tokens.get(2).filter(|t| !t.text.is_empty()) else {
                    return Err(err(kw, format!("'timeout {}' expects <time> as argument.", which.unwrap_or(""))));
                };
                let w = which.unwrap_or_default();
                let d = parse_timer(t, "timeout", |a| {
                    format!("timer overflow in argument <{a}> to <timeout {w}>, maximum value is 2147483647 ms (~24.8 days).")
                })?;
                if which == Some("connect") {
                    ring.timeout_connect = d;
                } else {
                    ring.timeout_server = d;
                }
            }
            // Any other `timeout` is read and ignored by `HAProxy` itself.
        }
        "server" => ring.servers.push(parse_ring_server(tokens, kw)?),
        "backing-file" => return Err(err(kw, "'backing-file' is not implemented: a ring lives in memory only")),
        other => return Err(err(kw, format!("unknown statement '{other}'."))),
    }
    Ok(())
}

/// `server <name> <addr> [ssl] [verify none] [log-proto octet-count|legacy]`.
fn parse_ring_server(tokens: &[Token], kw: &Token) -> Result<RingServer, ConfigError> {
    let (Some(name), Some(addr)) = (
        tokens.get(1).filter(|t| !t.text.is_empty()),
        tokens.get(2).filter(|t| !t.text.is_empty()),
    ) else {
        return Err(err(kw, "'server' expects <name> and <addr>[:<port>] as arguments."));
    };
    let target = if let Some(path) = addr.text.strip_prefix("unix@") {
        RingServerAddr::Unix(path.to_string())
    } else if addr.text.starts_with('/') {
        RingServerAddr::Unix(addr.text.clone())
    } else {
        let text = ["tcp@", "tcp4@", "tcp6@", "ipv4@", "ipv6@", "ip@"]
            .iter()
            .find_map(|p| addr.text.strip_prefix(p))
            .unwrap_or(&addr.text);
        let (sa, quic) = parse_socket_addr(&Token { text: text.to_string(), ..addr.clone() }, None)?;
        if quic {
            return Err(err(addr, "QUIC is not supported for a ring server"));
        }
        RingServerAddr::Tcp(sa)
    };
    let mut server = RingServer { name: name.text.clone(), addr: target, ssl: false, octet_count: false };
    let mut i = 3;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "ssl" => server.ssl = true,
            "verify" => {
                let v = tokens.get(i + 1).map(|t| t.text.as_str());
                if v != Some("none") {
                    return Err(err(&tokens[i], "'verify' on a ring server is not implemented: only 'verify none' is"));
                }
                i += 1;
            }
            "log-proto" => {
                match tokens.get(i + 1).map(|t| t.text.as_str()) {
                    Some("octet-count") => server.octet_count = true,
                    Some("legacy") => server.octet_count = false,
                    _ => return Err(err(&tokens[i], "'log-proto' expects 'legacy' or 'octet-count'")),
                }
                i += 1;
            }
            other => {
                return Err(err(&tokens[i], format!("'server' parameter '{other}' is not implemented in a ring section")));
            }
        }
        i += 1;
    }
    Ok(server)
}

pub(crate) fn parse_log_forward_header(
    tokens: &[Token],
    kw: &Token,
    log_forwards: &[LogForwardSection],
) -> Result<LogForwardSection, ConfigError> {
    let Some(name) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
        return Err(err(kw, "missing name for log-forward section."));
    };
    if let Some(c) = invalid_char(&name.text) {
        return Err(err(name, format!("character '{c}' is not permitted in 'log-forward' name '{}'.", name.text)));
    }
    if log_forwards.iter().any(|l| l.name == name.text) {
        return Err(err(
            name,
            format!("log-forward section '{}' has the same name as another log-forward section.", name.text),
        ));
    }
    Ok(LogForwardSection {
        name: name.text.clone(),
        binds: Vec::new(),
        dgram_binds: Vec::new(),
        logs: Vec::new(),
        maxconn: 10,
        timeout_client: None,
        log_global: false,
        assume_ntf: false,
        dont_parse: false,
        host: LogForwardHost::Fill,
    })
}

pub(crate) fn parse_log_forward_directive(
    lf: &mut LogForwardSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "bind" => {
            let Some(addr) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(err(kw, "<bind> expects <addr:port> as argument."));
            };
            let unix = addr.text.strip_prefix("unix@").or_else(|| addr.text.starts_with('/').then_some(addr.text.as_str()));
            if let Some(path) = unix {
                let mut mode = None;
                let mut i = 2;
                while i < tokens.len() {
                    if tokens[i].text == "mode" {
                        let m = tokens.get(i + 1).and_then(|t| u32::from_str_radix(&t.text, 8).ok());
                        mode = Some(m.ok_or_else(|| err(&tokens[i], "'mode' expects an octal file mode"))?);
                        i += 2;
                    } else {
                        return Err(err(&tokens[i], format!("'bind' parameter '{}' is not implemented on a UNIX socket", tokens[i].text)));
                    }
                }
                lf.binds.push(LogForwardBind::Unix { path: path.to_string(), mode });
            } else {
                let bind = super::proxy::parse_bind(tokens, kw, "log-forward")?;
                if bind.quic {
                    return Err(err(addr, "QUIC is not supported in a log-forward section"));
                }
                lf.binds.push(LogForwardBind::Tcp(bind));
            }
        }
        "dgram-bind" => {
            let Some(addr) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(err(kw, "<dgram-bind> expects <addr:port> as argument."));
            };
            if let Some(extra) = tokens.get(2) {
                return Err(err(extra, format!("'dgram-bind' parameter '{}' is not implemented", extra.text)));
            }
            let (sa, quic) = parse_socket_addr(addr, None)?;
            if quic {
                return Err(err(addr, "QUIC is not supported in a log-forward section"));
            }
            lf.dgram_binds.push(sa);
        }
        "log" => {
            if parse_log(&mut lf.logs, tokens, kw)? {
                lf.log_global = true;
            }
        }
        "maxconn" => {
            let Some(a) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                return Err(err(kw, "'maxconn' expects an integer argument."));
            };
            lf.maxconn = a.text.parse().unwrap_or(0);
        }
        "backlog" => return Err(err(kw, "'backlog' is not implemented in a log-forward section")),
        "timeout" => {
            if tokens.get(1).map(|t| t.text.as_str()) == Some("client") {
                let Some(t) = tokens.get(2).filter(|t| !t.text.is_empty()) else {
                    return Err(err(kw, "'timeout client' expects <time> as argument."));
                };
                lf.timeout_client = Some(parse_timer(t, "timeout client", |a| {
                    format!("timeout : timer overflow in argument '{a}' to 'timeout client' {TIMER_LIMIT}")
                })?);
            } else {
                return Err(err(kw, "'timeout' other than 'client' is not implemented in a log-forward section"));
            }
        }
        "option" => match tokens.get(1).map(|t| t.text.as_str()) {
            Some("assume-rfc6587-ntf") => lf.assume_ntf = true,
            Some("dont-parse-log") => lf.dont_parse = true,
            Some("host") => {
                lf.host = match tokens.get(2).map(|t| t.text.as_str()) {
                    Some("replace") => LogForwardHost::Replace,
                    Some("fill") => LogForwardHost::Fill,
                    Some("keep") => LogForwardHost::Keep,
                    Some("append") => LogForwardHost::Append,
                    _ => return Err(err(kw, "'option host' expects one of 'replace', 'fill', 'keep' or 'append'")),
                };
            }
            other => {
                return Err(err(
                    kw,
                    format!("unknown option '{}' in log-forward section", other.unwrap_or("")),
                ));
            }
        },
        other => return Err(err(kw, format!("unknown keyword '{other}' in log-forward section."))),
    }
    Ok(())
}
