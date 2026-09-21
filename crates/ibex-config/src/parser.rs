// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy 1.0 configuration parser, ported to Rust.
// Derived from HAProxy 1.0.2 (haproxy.c) by Willy Tarreau <willy@meta-x.org>.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::ast::{Config, HeaderExp, ListenSection, LogConfig, LogFacility, LogLevel, Mode, Server};
use crate::error::ConfigError;
use crate::lexer::{lex, Token};

/// Parses `HAProxy` 1.0 configuration text into a typed `Config` AST.
///
/// # Errors
///
/// Returns a `ConfigError` with line and column information if the configuration
/// contains syntax errors, invalid values, or structural inconsistencies.
pub fn parse_str(input: &str) -> Result<Config, ConfigError> {
    let lines = lex(input);
    if lines.is_empty() {
        return Err(ConfigError::new(
            1,
            1,
            "no <listen> line. Nothing to do !",
        ));
    }

    let mut listens = Vec::new();
    let mut cur_proxy: Option<ListenSection> = None;

    for line in &lines {
        let tokens = &line.tokens;
        if tokens.is_empty() {
            continue;
        }

        let kw = &tokens[0];
        if kw.text == "listen" {
            if let Some(prev) = cur_proxy.take() {
                listens.push(prev);
            }
            cur_proxy = Some(parse_listen_header(tokens, kw)?);
        } else {
            let proxy = get_current_proxy_mut(&mut cur_proxy, kw)?;
            parse_directive(proxy, tokens, kw)?;
        }
    }

    if let Some(last) = cur_proxy.take() {
        listens.push(last);
    }

    if listens.is_empty() {
        return Err(ConfigError::new(
            1,
            1,
            "no <listen> line. Nothing to do !",
        ));
    }

    validate_config(&listens)?;

    Ok(Config { listens })
}

fn parse_listen_header(tokens: &[Token], kw: &Token) -> Result<ListenSection, ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<listen> expects <id> and <addr:port> as arguments.",
        ));
    }

    let id = tokens[1].text.clone();
    let addr = parse_socket_addr(&tokens[2], None)?;

    Ok(ListenSection {
        name: id,
        addr,
        mode: Mode::Tcp,
        disabled: false,
        cookie: None,
        contimeout: None,
        clitimeout: None,
        srvtimeout: None,
        retries: 3,
        redisp: false,
        maxconn: 2000,
        grace: None,
        dispatch: None,
        servers: Vec::new(),
        logs: Vec::new(),
        cliexp: Vec::new(),
        srvexp: Vec::new(),
    })
}

fn parse_directive(
    proxy: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "mode" => parse_mode(proxy, tokens, kw),
        "disabled" => {
            proxy.disabled = true;
            Ok(())
        }
        "cookie" => parse_cookie(proxy, tokens, kw),
        "contimeout" => parse_contimeout(proxy, tokens, kw),
        "clitimeout" => parse_clitimeout(proxy, tokens, kw),
        "srvtimeout" => parse_srvtimeout(proxy, tokens, kw),
        "retries" => parse_retries(proxy, tokens, kw),
        "redisp" => {
            proxy.redisp = true;
            Ok(())
        }
        "maxconn" => parse_maxconn(proxy, tokens, kw),
        "grace" => parse_grace(proxy, tokens, kw),
        "dispatch" => parse_dispatch(proxy, tokens, kw),
        "server" => parse_server(proxy, tokens, kw),
        "log" => parse_log(proxy, tokens, kw),
        "cliexp" => parse_cliexp(proxy, tokens, kw),
        "srvexp" => parse_srvexp(proxy, tokens, kw),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword <{other}>"),
        )),
    }
}

fn parse_mode(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "unknown proxy mode <>.",
        ));
    }
    let mode_token = &tokens[1];
    match mode_token.text.as_str() {
        "http" => proxy.mode = Mode::Http,
        "tcp" => proxy.mode = Mode::Tcp,
        "health" => proxy.mode = Mode::Health,
        other => {
            return Err(ConfigError::new(
                mode_token.line,
                mode_token.col,
                format!("unknown proxy mode <{other}>."),
            ));
        }
    }
    Ok(())
}

fn parse_cookie(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<cookie> expects <cookie_name> as argument.",
        ));
    }
    if proxy.cookie.is_none() {
        proxy.cookie = Some(tokens[1].text.clone());
    }
    Ok(())
}

fn parse_contimeout(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<contimeout> expects an integer <time_in_ms> as argument.",
        ));
    }
    let dur = parse_timeout(&tokens[1], "contimeout")?;
    if proxy.contimeout.is_none() {
        proxy.contimeout = Some(dur);
    }
    Ok(())
}

fn parse_clitimeout(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<clitimeout> expects an integer <time_in_ms> as argument.",
        ));
    }
    let dur = parse_timeout(&tokens[1], "clitimeout")?;
    if proxy.clitimeout.is_none() {
        proxy.clitimeout = Some(dur);
    }
    Ok(())
}

fn parse_srvtimeout(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<srvtimeout> expects an integer <time_in_ms> as argument.",
        ));
    }
    let dur = parse_timeout(&tokens[1], "srvtimeout")?;
    if proxy.srvtimeout.is_none() {
        proxy.srvtimeout = Some(dur);
    }
    Ok(())
}

fn parse_retries(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<retries> expects an integer argument (dispatch counts for one).",
        ));
    }
    let retries = parse_u32(&tokens[1], "retries")?;
    proxy.retries = retries;
    Ok(())
}

fn parse_maxconn(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<maxconn> expects an integer argument.",
        ));
    }
    let maxconn = parse_u32(&tokens[1], "maxconn")?;
    proxy.maxconn = maxconn;
    Ok(())
}

fn parse_grace(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<grace> expects a time in milliseconds.",
        ));
    }
    let grace = parse_timeout(&tokens[1], "grace")?;
    proxy.grace = Some(grace);
    Ok(())
}

fn parse_dispatch(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<dispatch> expects <addr:port> as argument.",
        ));
    }
    let addr = parse_socket_addr(&tokens[1], None)?;
    proxy.dispatch = Some(addr);
    Ok(())
}

fn parse_server(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<server> expects <name> and <addr:port> as arguments.",
        ));
    }
    let addr = parse_socket_addr(&tokens[2], None)?;
    proxy.servers.push(Server {
        id: tokens[1].text.clone(),
        addr,
    });
    Ok(())
}

fn parse_log(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<log> expects <address> and <facility> as arguments.",
        ));
    }
    if proxy.logs.len() >= 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "too many syslog servers",
        ));
    }
    let addr = parse_socket_addr(&tokens[1], Some(514))?;
    let facility = parse_facility(&tokens[2])?;
    let level = if tokens.len() >= 4 && !tokens[3].text.is_empty() {
        Some(parse_level(&tokens[3])?)
    } else {
        None
    };
    proxy.logs.push(LogConfig {
        addr,
        facility,
        level,
    });
    Ok(())
}

fn parse_cliexp(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<cliexp> expects <search> and <replace> as arguments.",
        ));
    }
    validate_regex(&tokens[1])?;
    if proxy.cliexp.len() < 10 {
        proxy.cliexp.push(HeaderExp {
            regex: tokens[1].text.clone(),
            replacement: tokens[2].text.clone(),
        });
    }
    Ok(())
}

fn parse_srvexp(proxy: &mut ListenSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<srvexp> expects <search> and <replace> as arguments.",
        ));
    }
    validate_regex(&tokens[1])?;
    if proxy.srvexp.len() < 10 {
        proxy.srvexp.push(HeaderExp {
            regex: tokens[1].text.clone(),
            replacement: tokens[2].text.clone(),
        });
    }
    Ok(())
}

fn validate_config(listens: &[ListenSection]) -> Result<(), ConfigError> {
    for proxy in listens {
        if proxy.mode == Mode::Http && proxy.cookie.is_some() && proxy.servers.is_empty() {
            return Err(ConfigError::new(
                1,
                1,
                format!("HTTP proxy {} has a cookie but no server list !", proxy.name),
            ));
        }
    }
    Ok(())
}

fn get_current_proxy_mut<'a>(
    cur: &'a mut Option<ListenSection>,
    kw: &Token,
) -> Result<&'a mut ListenSection, ConfigError> {
    cur.as_mut().ok_or_else(|| {
        ConfigError::new(
            kw.line,
            kw.col,
            "<listen> expected.",
        )
    })
}

fn parse_socket_addr(
    token: &Token,
    default_port: Option<u16>,
) -> Result<SocketAddr, ConfigError> {
    let s = &token.text;
    if let Some(colon_pos) = s.rfind(':') {
        let (host_part, port_part_with_colon) = s.split_at(colon_pos);
        let port_part = &port_part_with_colon[1..];
        if port_part.is_empty() {
            return Err(ConfigError::new(
                token.line,
                token.col + colon_pos,
                format!("missing port in address '{s}'"),
            ));
        }
        let port: u16 = port_part.parse().map_err(|_| {
            ConfigError::new(
                token.line,
                token.col + colon_pos + 1,
                format!("invalid port '{port_part}' (must be 0..=65535)"),
            )
        })?;
        let ip = parse_ip(host_part, token.line, token.col)?;
        Ok(SocketAddr::new(ip, port))
    } else if let Some(dp) = default_port {
        let ip = parse_ip(s, token.line, token.col)?;
        Ok(SocketAddr::new(ip, dp))
    } else {
        Err(ConfigError::new(
            token.line,
            token.col,
            format!("expects <addr:port> as argument, found '{s}'"),
        ))
    }
}

fn parse_ip(s: &str, line: usize, col: usize) -> Result<IpAddr, ConfigError> {
    if s.is_empty() || s == "*" {
        Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    } else {
        s.parse::<IpAddr>().map_err(|_| {
            ConfigError::new(line, col, format!("invalid IP address '{s}'"))
        })
    }
}

fn parse_u32(token: &Token, field: &str) -> Result<u32, ConfigError> {
    token.text.parse::<u32>().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("'{field}' expects an integer, found \"{}\"", token.text),
        )
    })
}

fn parse_timeout(token: &Token, field: &str) -> Result<Duration, ConfigError> {
    let ms = parse_u32(token, field)?;
    Ok(Duration::from_millis(u64::from(ms)))
}

fn parse_facility(token: &Token) -> Result<LogFacility, ConfigError> {
    match token.text.as_str() {
        "kern" => Ok(LogFacility::Kern),
        "user" => Ok(LogFacility::User),
        "mail" => Ok(LogFacility::Mail),
        "daemon" => Ok(LogFacility::Daemon),
        "auth" => Ok(LogFacility::Auth),
        "syslog" => Ok(LogFacility::Syslog),
        "lpr" => Ok(LogFacility::Lpr),
        "news" => Ok(LogFacility::News),
        "uucp" => Ok(LogFacility::Uucp),
        "cron" => Ok(LogFacility::Cron),
        "auth2" => Ok(LogFacility::Auth2),
        "ftp" => Ok(LogFacility::Ftp),
        "ntp" => Ok(LogFacility::Ntp),
        "audit" => Ok(LogFacility::Audit),
        "alert" => Ok(LogFacility::Alert),
        "cron2" => Ok(LogFacility::Cron2),
        "local0" => Ok(LogFacility::Local0),
        "local1" => Ok(LogFacility::Local1),
        "local2" => Ok(LogFacility::Local2),
        "local3" => Ok(LogFacility::Local3),
        "local4" => Ok(LogFacility::Local4),
        "local5" => Ok(LogFacility::Local5),
        "local6" => Ok(LogFacility::Local6),
        "local7" => Ok(LogFacility::Local7),
        other => Err(ConfigError::new(
            token.line,
            token.col,
            format!("unknown log facility <{other}>"),
        )),
    }
}

fn parse_level(token: &Token) -> Result<LogLevel, ConfigError> {
    match token.text.as_str() {
        "emerg" => Ok(LogLevel::Emerg),
        "alert" => Ok(LogLevel::Alert),
        "crit" => Ok(LogLevel::Crit),
        "err" => Ok(LogLevel::Err),
        "warning" => Ok(LogLevel::Warning),
        "notice" => Ok(LogLevel::Notice),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        other => Err(ConfigError::new(
            token.line,
            token.col,
            format!("unknown log level <{other}>"),
        )),
    }
}

fn validate_regex(token: &Token) -> Result<(), ConfigError> {
    regex::Regex::new(&token.text).map_err(|e| {
        ConfigError::new(
            token.line,
            token.col,
            format!("bad regular expression <{}>: {e}", token.text),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_cfg() {
        let sample = r"
listen proxy1 0.0.0.0:3128
	mode	http
        cookie SERVERID
	dispatch 192.168.12.1:80
 	server srv1 192.168.12.2:8080
 	server srv2 192.168.12.3:8080
	contimeout	3000
	clitimeout	150000
	srvtimeout	150000
	maxconn 60000
	redisp
	retries	3
	grace 3000

listen proxy2 0.0.0.0:3129
	mode	http
	dispatch 127.0.0.1:80
	contimeout	3000
	clitimeout	150000
	srvtimeout	150000
	maxconn 60000
	retries	3
	grace 3000

listen health 0.0.0.0:3130
	mode	health
	clitimeout	1500
	srvtimeout	1500
	maxconn 4
	grace 0
";
        let config = parse_str(sample).unwrap();
        assert_eq!(config.listens.len(), 3);
        assert_eq!(config.listens[0].name, "proxy1");
        assert_eq!(config.listens[0].mode, Mode::Http);
        assert_eq!(config.listens[0].cookie.as_deref(), Some("SERVERID"));
        assert_eq!(config.listens[0].servers.len(), 2);
        assert_eq!(config.listens[0].retries, 3);
        assert!(config.listens[0].redisp);
        assert_eq!(config.listens[0].maxconn, 60000);
        assert_eq!(config.listens[0].contimeout, Some(Duration::from_millis(3000)));

        assert_eq!(config.listens[1].name, "proxy2");
        assert_eq!(config.listens[1].mode, Mode::Http);

        assert_eq!(config.listens[2].name, "health");
        assert_eq!(config.listens[2].mode, Mode::Health);
        assert_eq!(config.listens[2].maxconn, 4);
    }

    #[test]
    fn test_parse_http_cookie_without_servers_error() {
        let sample = "listen proxy1 0.0.0.0:3128\nmode http\ncookie SERVERID\n";
        let err = parse_str(sample).unwrap_err();
        assert!(err.message.contains("has a cookie but no server list"));
    }

    #[test]
    fn test_parse_server_before_listen() {
        let sample = "server s1 127.0.0.1:8080\n";
        let err = parse_str(sample).unwrap_err();
        assert!(err.message.contains("<listen> expected"));
    }
}
