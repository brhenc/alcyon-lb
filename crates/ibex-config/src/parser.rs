// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy configuration parser, ported to Rust.
// Derived from HAProxy 1.0 - 3.5 by Willy Tarreau <willy@meta-x.org>.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::ast::{
    AclCondition, AclRule, AclTerm, BackendSection, BalanceAlgorithm, BindConfig, Config,
    DefaultServerConfig, DefaultsSection, FrontendSection, GlobalSection, HeaderExp,
    HttpAfterResAction, HttpAfterResRule, HttpReqAction, HttpReqRule, HttpResAction, HttpResRule,
    ListenSection, LogConfig, LogFacility, LogLevel, Mode, Server, StatsConfig, StickRule,
    StickRuleType, StickTableConfigAst, TcpReqConnAction, TcpReqConnRule, TimeoutConfig,
    UseBackendRule,
};
use crate::error::ConfigError;
use crate::lexer::{lex, Token};

enum CurrentSection {
    Global(GlobalSection),
    Defaults(DefaultsSection),
    Listen(ListenSection),
    Frontend(FrontendSection),
    Backend(BackendSection),
}

/// Parses `HAProxy` configuration text into a typed `Config` AST.
///
/// # Errors
///
/// Returns a `ConfigError` with line and column information if the configuration
/// contains syntax errors, invalid values, or structural inconsistencies.
#[allow(clippy::too_many_lines)]
pub fn parse_str(input: &str) -> Result<Config, ConfigError> {
    let lines = lex(input);
    if lines.is_empty() {
        return Err(ConfigError::new(1, 1, "no <listen> line. Nothing to do !"));
    }

    let mut global: Option<GlobalSection> = None;
    let mut defaults: Option<DefaultsSection> = None;
    let mut listens = Vec::new();
    let mut frontends = Vec::new();
    let mut backends = Vec::new();
    let mut cur_section: Option<CurrentSection> = None;

    for line in &lines {
        let tokens = &line.tokens;
        if tokens.is_empty() {
            continue;
        }

        let kw = &tokens[0];
        match kw.text.as_str() {
            "global" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Global(GlobalSection::default()));
            }
            "defaults" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Defaults(DefaultsSection::default()));
            }
            "listen" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Listen(parse_listen_header(
                    tokens,
                    kw,
                    defaults.as_ref(),
                )?));
            }
            "frontend" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Frontend(parse_frontend_header(
                    tokens,
                    kw,
                    defaults.as_ref(),
                )?));
            }
            "backend" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Backend(parse_backend_header(
                    tokens,
                    kw,
                    defaults.as_ref(),
                )?));
            }
            _ => {
                let section = cur_section
                    .as_mut()
                    .ok_or_else(|| ConfigError::new(kw.line, kw.col, "<listen> expected."))?;
                parse_section_directive(section, tokens, kw)?;
            }
        }
    }

    flush_current_section(
        &mut cur_section,
        &mut global,
        &mut defaults,
        &mut listens,
        &mut frontends,
        &mut backends,
    );

    if global.is_none()
        && defaults.is_none()
        && listens.is_empty()
        && frontends.is_empty()
        && backends.is_empty()
    {
        return Err(ConfigError::new(1, 1, "no <listen> line. Nothing to do !"));
    }

    validate_config(&listens, &frontends, &backends)?;

    Ok(Config {
        global,
        defaults,
        listens,
        frontends,
        backends,
    })
}

fn flush_current_section(
    cur: &mut Option<CurrentSection>,
    global: &mut Option<GlobalSection>,
    defaults: &mut Option<DefaultsSection>,
    listens: &mut Vec<ListenSection>,
    frontends: &mut Vec<FrontendSection>,
    backends: &mut Vec<BackendSection>,
) {
    if let Some(sec) = cur.take() {
        match sec {
            CurrentSection::Global(g) => *global = Some(g),
            CurrentSection::Defaults(d) => *defaults = Some(d),
            CurrentSection::Listen(l) => listens.push(l),
            CurrentSection::Frontend(f) => frontends.push(f),
            CurrentSection::Backend(b) => backends.push(b),
        }
    }
}

fn parse_listen_header(
    tokens: &[Token],
    kw: &Token,
    defaults: Option<&DefaultsSection>,
) -> Result<ListenSection, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<listen> expects <id> as argument.",
        ));
    }

    let id = tokens[1].text.clone();
    let addr = if tokens.len() >= 3 && !tokens[2].text.is_empty() {
        parse_socket_addr(&tokens[2], None)?
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let mut accept_proxy = false;
    let mut accept_proxy_v2 = false;

    if let Some(extra_tokens) = tokens.get(3..) {
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
        name: id,
        addr,
        mode,
        disabled: false,
        cookie: None,
        contimeout: timeouts.connect,
        clitimeout: timeouts.client,
        srvtimeout: timeouts.server,
        timeouts,
        retries: 3,
        redisp: false,
        maxconn: 2000,
        grace: None,
        dispatch: None,
        default_server: None,
        servers: Vec::new(),
        logs: Vec::new(),
        cliexp: Vec::new(),
        srvexp: Vec::new(),
        acls: Vec::new(),
        use_backends: Vec::new(),
        default_backend: None,
        balance: BalanceAlgorithm::RoundRobin,
        stick_table: None,
        stick_rules: Vec::new(),
        accept_proxy,
        accept_proxy_v2,
        stats: StatsConfig::default(),
    })
}

fn parse_frontend_header(
    tokens: &[Token],
    kw: &Token,
    defaults: Option<&DefaultsSection>,
) -> Result<FrontendSection, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<frontend> expects <id> as argument.",
        ));
    }

    let id = tokens[1].text.clone();
    let bind = if tokens.len() >= 3 && !tokens[2].text.is_empty() {
        Some(parse_socket_addr(&tokens[2], None)?)
    } else {
        None
    };
    let mut accept_proxy = false;
    let mut accept_proxy_v2 = false;
    let mut binds = Vec::new();

    if let Some(b_addr) = bind {
        if let Some(extra_tokens) = tokens.get(3..) {
            for tok in extra_tokens {
                if tok.text == "accept-proxy" {
                    accept_proxy = true;
                } else if tok.text == "accept-proxy-v2" {
                    accept_proxy = true;
                    accept_proxy_v2 = true;
                }
            }
        }
        binds.push(BindConfig {
            addr: b_addr,
            ssl: false,
            crt: None,
            alpn: Vec::new(),
            accept_proxy,
            accept_proxy_v2,
        });
    }

    let mode = defaults.and_then(|d| d.mode).unwrap_or(Mode::Tcp);
    let timeouts = defaults.map_or_else(TimeoutConfig::default, |d| d.timeouts);

    Ok(FrontendSection {
        name: id,
        bind,
        binds,
        mode,
        disabled: false,
        clitimeout: timeouts.client,
        timeouts,
        maxconn: 2000,
        default_backend: None,
        use_backends: Vec::new(),
        acls: Vec::new(),
        cliexp: Vec::new(),
        logs: Vec::new(),
        stick_table: None,
        stick_rules: Vec::new(),
        tcp_req_conn_rules: Vec::new(),
        http_req_rules: Vec::new(),
        http_after_res_rules: Vec::new(),
        accept_proxy,
        accept_proxy_v2,
        stats: StatsConfig::default(),
    })
}

fn parse_backend_header(
    tokens: &[Token],
    kw: &Token,
    defaults: Option<&DefaultsSection>,
) -> Result<BackendSection, ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<backend> expects <id> as argument.",
        ));
    }

    let id = tokens[1].text.clone();
    let mode = defaults.and_then(|d| d.mode).unwrap_or(Mode::Tcp);
    let timeouts = defaults.map_or_else(TimeoutConfig::default, |d| d.timeouts);

    Ok(BackendSection {
        name: id,
        mode,
        disabled: false,
        balance: BalanceAlgorithm::RoundRobin,
        cookie: None,
        contimeout: timeouts.connect,
        srvtimeout: timeouts.server,
        timeouts,
        retries: 3,
        redisp: false,
        dispatch: None,
        default_server: None,
        servers: Vec::new(),
        srvexp: Vec::new(),
        acls: Vec::new(),
        stick_table: None,
        stick_rules: Vec::new(),
        http_req_rules: Vec::new(),
        http_res_rules: Vec::new(),
        http_after_res_rules: Vec::new(),
        stats: StatsConfig::default(),
    })
}

fn parse_section_directive(
    section: &mut CurrentSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match section {
        CurrentSection::Global(g) => parse_global_directive(g, tokens, kw),
        CurrentSection::Defaults(d) => parse_defaults_directive(d, tokens, kw),
        CurrentSection::Listen(l) => parse_listen_directive(l, tokens, kw),
        CurrentSection::Frontend(f) => parse_frontend_directive(f, tokens, kw),
        CurrentSection::Backend(b) => parse_backend_directive(b, tokens, kw),
    }
}

fn parse_global_directive(
    global: &mut GlobalSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "nbthread" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<nbthread> expects an integer.",
                ));
            }
            global.nbthread = Some(parse_u32(&tokens[1], "nbthread")?);
            Ok(())
        }
        "stats" => {
            if tokens.len() >= 3 && tokens[1].text == "socket" {
                global.stats_socket = Some(tokens[2].text.clone());
                let mut i = 3;
                while i < tokens.len() {
                    match tokens[i].text.as_str() {
                        "mode" if i + 1 < tokens.len() => {
                            i += 1;
                            let mode_val = u32::from_str_radix(&tokens[i].text, 8)
                                .or_else(|_| tokens[i].text.parse::<u32>())
                                .map_err(|_| {
                                    ConfigError::new(
                                        tokens[i].line,
                                        tokens[i].col,
                                        format!("invalid socket mode <{}>", tokens[i].text),
                                    )
                                })?;
                            global.stats_socket_mode = Some(mode_val);
                        }
                        "level" if i + 1 < tokens.len() => {
                            i += 1;
                            global.stats_socket_level = Some(tokens[i].text.clone());
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_defaults_directive(
    defaults: &mut DefaultsSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "mode" => {
            let mut mode = defaults.mode.unwrap_or(Mode::Tcp);
            parse_mode(&mut mode, tokens, kw)?;
            defaults.mode = Some(mode);
            Ok(())
        }
        "timeout" => parse_timeout_directive(&mut defaults.timeouts, tokens, kw),
        "log" => {
            if tokens.len() >= 2 && tokens[1].text == "global" {
                defaults.log_global = true;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn parse_listen_directive(
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
        "contimeout" => parse_contimeout(&mut proxy.contimeout, tokens, kw),
        "clitimeout" => parse_clitimeout(&mut proxy.clitimeout, tokens, kw),
        "srvtimeout" => parse_srvtimeout(&mut proxy.srvtimeout, tokens, kw),
        "timeout" => {
            parse_generic_timeout(
                &mut proxy.contimeout,
                &mut proxy.clitimeout,
                &mut proxy.srvtimeout,
                tokens,
                kw,
            )?;
            parse_timeout_directive(&mut proxy.timeouts, tokens, kw)
        }
        "retries" => parse_retries(&mut proxy.retries, tokens, kw),
        "redisp" => {
            proxy.redisp = true;
            Ok(())
        }
        "maxconn" => parse_maxconn(&mut proxy.maxconn, tokens, kw),
        "grace" => parse_grace(&mut proxy.grace, tokens, kw),
        "dispatch" => parse_dispatch(&mut proxy.dispatch, tokens, kw),
        "default-server" => parse_default_server(&mut proxy.default_server, tokens, kw),
        "server" => parse_server(
            &mut proxy.servers,
            proxy.default_server.as_ref(),
            tokens,
            kw,
        ),
        "log" => parse_log(&mut proxy.logs, tokens, kw),
        "cliexp" => parse_cliexp(&mut proxy.cliexp, tokens, kw),
        "srvexp" => parse_srvexp(&mut proxy.srvexp, tokens, kw),
        "balance" => parse_balance(&mut proxy.balance, tokens, kw),
        "acl" => parse_acl(&mut proxy.acls, tokens, kw),
        "use_backend" => parse_use_backend(&mut proxy.use_backends, tokens, kw),
        "default_backend" => parse_default_backend(&mut proxy.default_backend, tokens, kw),
        "bind" => {
            if tokens.len() < 2 || tokens[1].text.is_empty() {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<bind> expects <addr:port> as argument.",
                ));
            }
            proxy.addr = parse_socket_addr(&tokens[1], None)?;
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
        "stats" => parse_stats_directive(&mut proxy.stats, tokens, kw),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword <{other}>"),
        )),
    }
}

fn parse_frontend_directive(
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
        "tcp-request" => parse_tcp_req_conn_rule(&mut fe.tcp_req_conn_rules, tokens, kw),
        "http-request" => parse_http_req_rule(&mut fe.http_req_rules, tokens, kw),
        "http-after-response" => {
            parse_http_after_res_rule(&mut fe.http_after_res_rules, tokens, kw)
        }
        "mode" => parse_mode(&mut fe.mode, tokens, kw),
        "disabled" => {
            fe.disabled = true;
            Ok(())
        }
        "clitimeout" => parse_clitimeout(&mut fe.clitimeout, tokens, kw),
        "timeout" => {
            let mut dummy1 = None;
            let mut dummy2 = None;
            parse_generic_timeout(&mut dummy1, &mut fe.clitimeout, &mut dummy2, tokens, kw)?;
            parse_timeout_directive(&mut fe.timeouts, tokens, kw)
        }
        "maxconn" => parse_maxconn(&mut fe.maxconn, tokens, kw),
        "log" => parse_log(&mut fe.logs, tokens, kw),
        "cliexp" => parse_cliexp(&mut fe.cliexp, tokens, kw),
        "acl" => parse_acl(&mut fe.acls, tokens, kw),
        "use_backend" => parse_use_backend(&mut fe.use_backends, tokens, kw),
        "default_backend" => parse_default_backend(&mut fe.default_backend, tokens, kw),
        "stick-table" => parse_stick_table(&mut fe.stick_table, tokens, kw),
        "stick" => parse_stick_rule(&mut fe.stick_rules, tokens, kw),
        "track-sc0" | "track-sc1" | "track-sc2" => {
            parse_track_rule(&mut fe.stick_rules, tokens, kw)
        }
        "stats" => parse_stats_directive(&mut fe.stats, tokens, kw),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword <{other}>"),
        )),
    }
}

fn parse_frontend_bind(
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
    let addr = parse_socket_addr(&tokens[1], None)?;
    let mut ssl = false;
    let mut crt = None;
    let mut alpn = Vec::new();
    let mut accept_proxy = false;
    let mut accept_proxy_v2 = false;

    let mut i = 2;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "ssl" => ssl = true,
            "crt" if i + 1 < tokens.len() => {
                i += 1;
                crt = Some(tokens[i].text.clone());
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

    fe.binds.push(BindConfig {
        addr,
        ssl,
        crt,
        alpn,
        accept_proxy,
        accept_proxy_v2,
    });
    Ok(())
}

fn parse_backend_directive(
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
        "cookie" => parse_cookie(&mut be.cookie, tokens, kw),
        "contimeout" => parse_contimeout(&mut be.contimeout, tokens, kw),
        "srvtimeout" => parse_srvtimeout(&mut be.srvtimeout, tokens, kw),
        "timeout" => {
            let mut dummy = None;
            parse_generic_timeout(
                &mut be.contimeout,
                &mut dummy,
                &mut be.srvtimeout,
                tokens,
                kw,
            )?;
            parse_timeout_directive(&mut be.timeouts, tokens, kw)
        }
        "retries" => parse_retries(&mut be.retries, tokens, kw),
        "redisp" => {
            be.redisp = true;
            Ok(())
        }
        "dispatch" => parse_dispatch(&mut be.dispatch, tokens, kw),
        "default-server" => parse_default_server(&mut be.default_server, tokens, kw),
        "server" => parse_server(&mut be.servers, be.default_server.as_ref(), tokens, kw),
        "http-request" => parse_http_req_rule(&mut be.http_req_rules, tokens, kw),
        "http-response" => parse_http_res_rule(&mut be.http_res_rules, tokens, kw),
        "http-after-response" => {
            parse_http_after_res_rule(&mut be.http_after_res_rules, tokens, kw)
        }
        "srvexp" => parse_srvexp(&mut be.srvexp, tokens, kw),
        "acl" => parse_acl(&mut be.acls, tokens, kw),
        "stick-table" => parse_stick_table(&mut be.stick_table, tokens, kw),
        "stick" => parse_stick_rule(&mut be.stick_rules, tokens, kw),
        "track-sc0" | "track-sc1" | "track-sc2" => {
            parse_track_rule(&mut be.stick_rules, tokens, kw)
        }
        "stats" => parse_stats_directive(&mut be.stats, tokens, kw),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword <{other}>"),
        )),
    }
}

fn parse_default_server(
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
            _ => {}
        }
        i += 1;
    }
    *def = Some(cfg);
    Ok(())
}

fn parse_stats_directive(
    stats: &mut StatsConfig,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        stats.enable = true;
        return Ok(());
    }
    match tokens[1].text.as_str() {
        "uri" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<stats uri> expects <path>.",
                ));
            }
            stats.enable = true;
            stats.uri = Some(tokens[2].text.clone());
            Ok(())
        }
        "refresh" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<stats refresh> expects <interval>.",
                ));
            }
            stats.refresh = Some(parse_timeout(&tokens[2], "stats refresh")?);
            Ok(())
        }
        "admin" => {
            stats.admin = true;
            if tokens.len() >= 4 && (tokens[2].text == "if" || tokens[2].text == "unless") {
                let cond = parse_acl_condition_from_tokens(&tokens[2..])?;
                stats.admin_cond = cond;
            }
            Ok(())
        }
        "show-legends" => {
            stats.show_legends = true;
            Ok(())
        }
        "show-desc" => {
            if tokens.len() >= 3 {
                stats.show_desc = Some(
                    tokens[2..]
                        .iter()
                        .map(|t| t.text.as_str())
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
            Ok(())
        }
        "show-node" => {
            if tokens.len() >= 3 {
                stats.show_node = Some(tokens[2].text.clone());
            }
            Ok(())
        }
        _ => {
            stats.enable = true;
            Ok(())
        }
    }
}

fn parse_mode(mode: &mut Mode, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(kw.line, kw.col, "unknown proxy mode <>."));
    }
    let mode_token = &tokens[1];
    match mode_token.text.as_str() {
        "http" => *mode = Mode::Http,
        "tcp" => *mode = Mode::Tcp,
        "health" => *mode = Mode::Health,
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

fn parse_cookie(
    cookie: &mut Option<String>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<cookie> expects <cookie_name> as argument.",
        ));
    }
    if cookie.is_none() {
        *cookie = Some(tokens[1].text.clone());
    }
    Ok(())
}

fn parse_contimeout(
    contimeout: &mut Option<Duration>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<contimeout> expects an integer <time_in_ms> as argument.",
        ));
    }
    let dur = parse_timeout(&tokens[1], "contimeout")?;
    if contimeout.is_none() {
        *contimeout = Some(dur);
    }
    Ok(())
}

fn parse_clitimeout(
    clitimeout: &mut Option<Duration>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<clitimeout> expects an integer <time_in_ms> as argument.",
        ));
    }
    let dur = parse_timeout(&tokens[1], "clitimeout")?;
    if clitimeout.is_none() {
        *clitimeout = Some(dur);
    }
    Ok(())
}

fn parse_srvtimeout(
    srvtimeout: &mut Option<Duration>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<srvtimeout> expects an integer <time_in_ms> as argument.",
        ));
    }
    let dur = parse_timeout(&tokens[1], "srvtimeout")?;
    if srvtimeout.is_none() {
        *srvtimeout = Some(dur);
    }
    Ok(())
}

fn parse_generic_timeout(
    contimeout: &mut Option<Duration>,
    clitimeout: &mut Option<Duration>,
    srvtimeout: &mut Option<Duration>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<timeout> expects <target> and <time_in_ms> as arguments.",
        ));
    }
    let target = &tokens[1].text;
    let dur = parse_timeout(&tokens[2], "timeout")?;
    match target.as_str() {
        "connect" if contimeout.is_none() => {
            *contimeout = Some(dur);
        }
        "client" if clitimeout.is_none() => {
            *clitimeout = Some(dur);
        }
        "server" if srvtimeout.is_none() => {
            *srvtimeout = Some(dur);
        }
        _ => {}
    }
    Ok(())
}

fn parse_timeout_directive(
    timeouts: &mut TimeoutConfig,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<timeout> expects <target> and <time_in_ms> as arguments.",
        ));
    }
    let target = &tokens[1].text;
    let dur = parse_timeout(&tokens[2], "timeout")?;
    match target.as_str() {
        "connect" => timeouts.connect = Some(dur),
        "client" => timeouts.client = Some(dur),
        "server" => timeouts.server = Some(dur),
        "http-request" => timeouts.http_request = Some(dur),
        "http-keep-alive" => timeouts.http_keep_alive = Some(dur),
        "check" => timeouts.check = Some(dur),
        "queue" => timeouts.queue = Some(dur),
        _ => {}
    }
    Ok(())
}

fn parse_retries(retries: &mut u32, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<retries> expects an integer argument (dispatch counts for one).",
        ));
    }
    let r = parse_u32(&tokens[1], "retries")?;
    *retries = r;
    Ok(())
}

fn parse_maxconn(maxconn: &mut u32, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<maxconn> expects an integer argument.",
        ));
    }
    let m = parse_u32(&tokens[1], "maxconn")?;
    *maxconn = m;
    Ok(())
}

fn parse_balance(
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

fn parse_grace(
    grace: &mut Option<Duration>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<grace> expects a time in milliseconds.",
        ));
    }
    let g = parse_timeout(&tokens[1], "grace")?;
    *grace = Some(g);
    Ok(())
}

fn parse_dispatch(
    dispatch: &mut Option<SocketAddr>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<dispatch> expects <addr:port> as argument.",
        ));
    }
    let addr = parse_socket_addr(&tokens[1], None)?;
    *dispatch = Some(addr);
    Ok(())
}

fn parse_server(
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
    let addr = parse_socket_addr(&tokens[2], None)?;
    let mut check = default_server.is_some_and(|d| d.check);
    let mut inter = default_server.and_then(|d| d.inter);
    let mut fall = default_server.and_then(|d| d.fall);
    let mut rise = default_server.and_then(|d| d.rise);
    let mut send_proxy = default_server.is_some_and(|d| d.send_proxy);
    let mut send_proxy_v2 = default_server.is_some_and(|d| d.send_proxy_v2);
    let mut maxconn = default_server.and_then(|d| d.maxconn);
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
            "backup" => backup = true,
            _ => {}
        }
        i += 1;
    }

    servers.push(Server {
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

fn parse_log(logs: &mut Vec<LogConfig>, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<log> expects <address> and <facility> as arguments.",
        ));
    }
    if logs.len() >= 2 {
        return Err(ConfigError::new(kw.line, kw.col, "too many syslog servers"));
    }
    let addr = parse_socket_addr(&tokens[1], Some(514))?;
    let facility = parse_facility(&tokens[2])?;
    let level = if tokens.len() >= 4 && !tokens[3].text.is_empty() {
        Some(parse_level(&tokens[3])?)
    } else {
        None
    };
    logs.push(LogConfig {
        addr,
        facility,
        level,
    });
    Ok(())
}

fn parse_cliexp(
    cliexp: &mut Vec<HeaderExp>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<cliexp> expects <search> and <replace> as arguments.",
        ));
    }
    validate_regex(&tokens[1])?;
    if cliexp.len() < 10 {
        cliexp.push(HeaderExp {
            regex: tokens[1].text.clone(),
            replacement: tokens[2].text.clone(),
        });
    }
    Ok(())
}

fn parse_srvexp(
    srvexp: &mut Vec<HeaderExp>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<srvexp> expects <search> and <replace> as arguments.",
        ));
    }
    validate_regex(&tokens[1])?;
    if srvexp.len() < 10 {
        srvexp.push(HeaderExp {
            regex: tokens[1].text.clone(),
            replacement: tokens[2].text.clone(),
        });
    }
    Ok(())
}

fn parse_acl(acls: &mut Vec<AclRule>, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<acl> expects <name> and <expression> as arguments.",
        ));
    }
    let name = tokens[1].text.clone();
    let expr_tokens: Vec<&str> = tokens[2..].iter().map(|t| t.text.as_str()).collect();
    let expr = expr_tokens.join(" ");
    acls.push(AclRule { name, expr });
    Ok(())
}

fn parse_acl_condition_from_tokens(tokens: &[Token]) -> Result<Option<AclCondition>, ConfigError> {
    if tokens.is_empty() {
        return Ok(None);
    }
    let is_if = match tokens[0].text.as_str() {
        "if" => true,
        "unless" => false,
        other => {
            return Err(ConfigError::new(
                tokens[0].line,
                tokens[0].col,
                format!("expected 'if' or 'unless', got <{other}>"),
            ));
        }
    };

    let mut terms = Vec::new();
    let mut i = 1;
    while i < tokens.len() {
        let tok = &tokens[i];
        if tok.text == "{" {
            let mut brace_tokens = Vec::new();
            brace_tokens.push("{");
            i += 1;
            while i < tokens.len() && tokens[i].text != "}" {
                brace_tokens.push(tokens[i].text.as_str());
                i += 1;
            }
            if i < tokens.len() && tokens[i].text == "}" {
                brace_tokens.push("}");
                i += 1;
            }
            terms.push(AclTerm {
                negated: false,
                name: brace_tokens.join(" "),
            });
        } else if tok.text.starts_with('{') {
            if tok.text.ends_with('}') {
                terms.push(AclTerm {
                    negated: false,
                    name: tok.text.clone(),
                });
                i += 1;
            } else {
                let mut brace_tokens = Vec::new();
                brace_tokens.push(tok.text.as_str());
                i += 1;
                while i < tokens.len() && !tokens[i].text.ends_with('}') {
                    brace_tokens.push(tokens[i].text.as_str());
                    i += 1;
                }
                if i < tokens.len() {
                    brace_tokens.push(tokens[i].text.as_str());
                    i += 1;
                }
                terms.push(AclTerm {
                    negated: false,
                    name: brace_tokens.join(" "),
                });
            }
        } else if let Some(stripped) = tok.text.strip_prefix('!') {
            terms.push(AclTerm {
                negated: true,
                name: stripped.to_string(),
            });
            i += 1;
        } else {
            terms.push(AclTerm {
                negated: false,
                name: tok.text.clone(),
            });
            i += 1;
        }
    }

    Ok(Some(AclCondition { is_if, terms }))
}

fn parse_use_backend(
    rules: &mut Vec<UseBackendRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<use_backend> expects <backend_name> as argument.",
        ));
    }
    let backend = tokens[1].text.clone();
    let cond = if tokens.len() >= 3 {
        parse_acl_condition_from_tokens(&tokens[2..])?
    } else {
        None
    };

    rules.push(UseBackendRule { backend, cond });
    Ok(())
}

fn parse_default_backend(
    def: &mut Option<String>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<default_backend> expects <backend_name> as argument.",
        ));
    }
    *def = Some(tokens[1].text.clone());
    Ok(())
}

fn parse_tcp_req_conn_rule(
    rules: &mut Vec<TcpReqConnRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text != "connection" {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<tcp-request> expects 'connection <action>'",
        ));
    }
    let act_tok = &tokens[2];
    match act_tok.text.as_str() {
        "track-sc0" | "track-sc1" | "track-sc2" => {
            if tokens.len() < 4 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<tcp-request connection track-sc*> expects sample expression.",
                ));
            }
            let expr = tokens[3].text.clone();
            let mut table = None;
            let mut cond_start = None;
            let mut i = 4;
            while i < tokens.len() {
                if tokens[i].text == "table" && i + 1 < tokens.len() {
                    table = Some(tokens[i + 1].text.clone());
                    i += 2;
                } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                    cond_start = Some(i);
                    break;
                } else {
                    i += 1;
                }
            }
            let cond = if let Some(idx) = cond_start {
                parse_acl_condition_from_tokens(&tokens[idx..])?
            } else {
                None
            };
            let action = match act_tok.text.as_str() {
                "track-sc1" => TcpReqConnAction::TrackSc1 { expr, table },
                "track-sc2" => TcpReqConnAction::TrackSc2 { expr, table },
                _ => TcpReqConnAction::TrackSc0 { expr, table },
            };
            rules.push(TcpReqConnRule { action, cond });
        }
        "silent-drop" => {
            let cond = if tokens.len() > 3 {
                parse_acl_condition_from_tokens(&tokens[3..])?
            } else {
                None
            };
            rules.push(TcpReqConnRule {
                action: TcpReqConnAction::SilentDrop,
                cond,
            });
        }
        "reject" => {
            let cond = if tokens.len() > 3 {
                parse_acl_condition_from_tokens(&tokens[3..])?
            } else {
                None
            };
            rules.push(TcpReqConnRule {
                action: TcpReqConnAction::Reject,
                cond,
            });
        }
        "accept" => {
            let cond = if tokens.len() > 3 {
                parse_acl_condition_from_tokens(&tokens[3..])?
            } else {
                None
            };
            rules.push(TcpReqConnRule {
                action: TcpReqConnAction::Accept,
                cond,
            });
        }
        other => {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("unknown tcp-request connection action <{other}>"),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn parse_http_req_rule(
    rules: &mut Vec<HttpReqRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-request> expects an action as argument.",
        ));
    }

    let act_token = &tokens[1];
    match act_token.text.as_str() {
        "track-sc0" | "track-sc1" | "track-sc2" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-request track-sc*> expects sample expression.",
                ));
            }
            let expr = tokens[2].text.clone();
            let mut table = None;
            let mut cond_start = None;
            let mut i = 3;
            while i < tokens.len() {
                if tokens[i].text == "table" && i + 1 < tokens.len() {
                    table = Some(tokens[i + 1].text.clone());
                    i += 2;
                } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                    cond_start = Some(i);
                    break;
                } else {
                    i += 1;
                }
            }
            let cond = if let Some(idx) = cond_start {
                parse_acl_condition_from_tokens(&tokens[idx..])?
            } else {
                None
            };
            let action = match act_token.text.as_str() {
                "track-sc1" => HttpReqAction::TrackSc1 { expr, table },
                "track-sc2" => HttpReqAction::TrackSc2 { expr, table },
                _ => HttpReqAction::TrackSc0 { expr, table },
            };
            rules.push(HttpReqRule { action, cond });
        }
        "return" => {
            let mut status = 200u16;
            let mut content_type = None;
            let mut lf_string = None;
            let mut cond_start = None;
            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].text.as_str() {
                    "status" if i + 1 < tokens.len() => {
                        status = parse_u16(&tokens[i + 1], "status")?;
                        i += 2;
                    }
                    "content-type" if i + 1 < tokens.len() => {
                        content_type = Some(tokens[i + 1].text.clone());
                        i += 2;
                    }
                    "lf-string" | "string" | "file" | "lf-file" if i + 1 < tokens.len() => {
                        lf_string = Some(tokens[i + 1].text.clone());
                        i += 2;
                    }
                    "if" | "unless" => {
                        cond_start = Some(i);
                        break;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            let cond = if let Some(idx) = cond_start {
                parse_acl_condition_from_tokens(&tokens[idx..])?
            } else {
                None
            };
            rules.push(HttpReqRule {
                action: HttpReqAction::Return {
                    status,
                    content_type,
                    lf_string,
                },
                cond,
            });
        }
        "deny" => {
            let mut deny_status = None;
            let mut cond_start = None;
            let mut i = 2;
            while i < tokens.len() {
                match tokens[i].text.as_str() {
                    "deny_status" if i + 1 < tokens.len() => {
                        deny_status = Some(parse_u16(&tokens[i + 1], "deny_status")?);
                        i += 2;
                    }
                    "if" | "unless" => {
                        cond_start = Some(i);
                        break;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            let cond = if let Some(idx) = cond_start {
                parse_acl_condition_from_tokens(&tokens[idx..])?
            } else {
                None
            };
            rules.push(HttpReqRule {
                action: HttpReqAction::Deny { deny_status },
                cond,
            });
        }
        "allow" => {
            let cond = if tokens.len() > 2 {
                parse_acl_condition_from_tokens(&tokens[2..])?
            } else {
                None
            };
            rules.push(HttpReqRule {
                action: HttpReqAction::Allow,
                cond,
            });
        }
        "set-header" | "add-header" => {
            if tokens.len() < 4 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-request set-header|add-header> expects <name> and <fmt>.",
                ));
            }
            let name = tokens[2].text.clone();
            let fmt = tokens[3].text.clone();
            let cond = if tokens.len() > 4 {
                parse_acl_condition_from_tokens(&tokens[4..])?
            } else {
                None
            };
            let action = if act_token.text == "set-header" {
                HttpReqAction::SetHeader { name, fmt }
            } else {
                HttpReqAction::AddHeader { name, fmt }
            };
            rules.push(HttpReqRule { action, cond });
        }
        "del-header" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-request del-header> expects <name>.",
                ));
            }
            let name = tokens[2].text.clone();
            let cond = if tokens.len() > 3 {
                parse_acl_condition_from_tokens(&tokens[3..])?
            } else {
                None
            };
            rules.push(HttpReqRule {
                action: HttpReqAction::DelHeader { name },
                cond,
            });
        }
        "replace-header" => {
            if tokens.len() < 5 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-request replace-header> expects <name>, <regex>, <replace>.",
                ));
            }
            let name = tokens[2].text.clone();
            let regex = tokens[3].text.clone();
            let repl = tokens[4].text.clone();
            let cond = if tokens.len() > 5 {
                parse_acl_condition_from_tokens(&tokens[5..])?
            } else {
                None
            };
            rules.push(HttpReqRule {
                action: HttpReqAction::ReplaceHeader { name, regex, repl },
                cond,
            });
        }
        other => {
            return Err(ConfigError::new(
                act_token.line,
                act_token.col,
                format!("unknown http-request action <{other}>"),
            ));
        }
    }
    Ok(())
}

fn parse_http_res_rule(
    rules: &mut Vec<HttpResRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-response> expects an action as argument.",
        ));
    }
    let act_token = &tokens[1];
    match act_token.text.as_str() {
        "set-header" | "add-header" => {
            if tokens.len() < 4 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-response set-header|add-header> expects <name> and <fmt>.",
                ));
            }
            let name = tokens[2].text.clone();
            let fmt = tokens[3].text.clone();
            let cond = if tokens.len() > 4 {
                parse_acl_condition_from_tokens(&tokens[4..])?
            } else {
                None
            };
            let action = if act_token.text == "set-header" {
                HttpResAction::SetHeader { name, fmt }
            } else {
                HttpResAction::AddHeader { name, fmt }
            };
            rules.push(HttpResRule { action, cond });
        }
        "del-header" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-response del-header> expects <name>.",
                ));
            }
            let name = tokens[2].text.clone();
            let cond = if tokens.len() > 3 {
                parse_acl_condition_from_tokens(&tokens[3..])?
            } else {
                None
            };
            rules.push(HttpResRule {
                action: HttpResAction::DelHeader { name },
                cond,
            });
        }
        "set-status" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-response set-status> expects <status>.",
                ));
            }
            let status = parse_u16(&tokens[2], "set-status")?;
            let cond = if tokens.len() > 3 {
                parse_acl_condition_from_tokens(&tokens[3..])?
            } else {
                None
            };
            rules.push(HttpResRule {
                action: HttpResAction::SetStatus { status },
                cond,
            });
        }
        other => {
            return Err(ConfigError::new(
                act_token.line,
                act_token.col,
                format!("unknown http-response action <{other}>"),
            ));
        }
    }
    Ok(())
}

fn parse_http_after_res_rule(
    rules: &mut Vec<HttpAfterResRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<http-after-response> expects an action as argument.",
        ));
    }
    let act_token = &tokens[1];
    match act_token.text.as_str() {
        "set-header" | "add-header" => {
            if tokens.len() < 4 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-after-response set-header|add-header> expects <name> and <fmt>.",
                ));
            }
            let name = tokens[2].text.clone();
            let fmt = tokens[3].text.clone();
            let cond = if tokens.len() > 4 {
                parse_acl_condition_from_tokens(&tokens[4..])?
            } else {
                None
            };
            let action = if act_token.text == "set-header" {
                HttpAfterResAction::SetHeader { name, fmt }
            } else {
                HttpAfterResAction::AddHeader { name, fmt }
            };
            rules.push(HttpAfterResRule { action, cond });
        }
        "del-header" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<http-after-response del-header> expects <name>.",
                ));
            }
            let name = tokens[2].text.clone();
            let cond = if tokens.len() > 3 {
                parse_acl_condition_from_tokens(&tokens[3..])?
            } else {
                None
            };
            rules.push(HttpAfterResRule {
                action: HttpAfterResAction::DelHeader { name },
                cond,
            });
        }
        other => {
            return Err(ConfigError::new(
                act_token.line,
                act_token.col,
                format!("unknown http-after-response action <{other}>"),
            ));
        }
    }
    Ok(())
}

fn parse_stick_table(
    table: &mut Option<StickTableConfigAst>,
    tokens: &[Token],
    _kw: &Token,
) -> Result<(), ConfigError> {
    let mut key_type = "ip".to_string();
    let mut size = 100_000usize;
    let mut expire = Duration::from_secs(300);
    let mut store_fields = Vec::new();

    let mut i = 1;
    while i < tokens.len() {
        match tokens[i].text.as_str() {
            "type" => {
                i += 1;
                if i < tokens.len() {
                    key_type.clone_from(&tokens[i].text);
                }
            }
            "size" => {
                i += 1;
                if i < tokens.len() {
                    size = parse_size(&tokens[i])?;
                }
            }
            "expire" => {
                i += 1;
                if i < tokens.len() {
                    expire = parse_timeout(&tokens[i], "expire")?;
                }
            }
            "store" => {
                i += 1;
                if i < tokens.len() {
                    let fields: Vec<String> = tokens[i]
                        .text
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    store_fields.extend(fields);
                }
            }
            _ => {}
        }
        i += 1;
    }

    *table = Some(StickTableConfigAst {
        key_type,
        size,
        expire,
        store_fields,
    });
    Ok(())
}

fn parse_size(token: &Token) -> Result<usize, ConfigError> {
    let s = token.text.to_lowercase();
    let (num_str, multiplier) = if let Some(stripped) = s.strip_suffix('k') {
        (stripped, 1024)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('g') {
        (stripped, 1024 * 1024 * 1024)
    } else {
        (s.as_str(), 1)
    };

    let base: usize = num_str.parse().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("invalid size <{}>", token.text),
        )
    })?;

    Ok(base.saturating_mul(multiplier))
}

fn parse_stick_rule(
    rules: &mut Vec<StickRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 || tokens[1].text.is_empty() || tokens[2].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<stick> expects <action> and <sample> as arguments.",
        ));
    }
    let rule_type = match tokens[1].text.as_str() {
        "on" => StickRuleType::StickOn,
        "match" => StickRuleType::StickMatch,
        "store-request" => StickRuleType::StickStoreRequest,
        "store-response" => StickRuleType::StickStoreResponse,
        other => {
            return Err(ConfigError::new(
                tokens[1].line,
                tokens[1].col,
                format!("unknown stick action <{other}>"),
            ));
        }
    };
    let expr_tokens: Vec<&str> = tokens[2..].iter().map(|t| t.text.as_str()).collect();
    let expr = expr_tokens.join(" ");
    rules.push(StickRule { rule_type, expr });
    Ok(())
}

fn parse_track_rule(
    rules: &mut Vec<StickRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("<{}> expects <sample> as argument.", kw.text),
        ));
    }
    let rule_type = match kw.text.as_str() {
        "track-sc1" => StickRuleType::TrackSc1,
        "track-sc2" => StickRuleType::TrackSc2,
        _ => StickRuleType::TrackSc0,
    };
    let expr_tokens: Vec<&str> = tokens[1..].iter().map(|t| t.text.as_str()).collect();
    let expr = expr_tokens.join(" ");
    rules.push(StickRule { rule_type, expr });
    Ok(())
}

fn validate_config(
    listens: &[ListenSection],
    _frontends: &[FrontendSection],
    backends: &[BackendSection],
) -> Result<(), ConfigError> {
    for proxy in listens {
        if proxy.mode == Mode::Http && proxy.cookie.is_some() && proxy.servers.is_empty() {
            return Err(ConfigError::new(
                1,
                1,
                format!(
                    "HTTP proxy {} has a cookie but no server list !",
                    proxy.name
                ),
            ));
        }
    }
    for proxy in backends {
        if proxy.mode == Mode::Http && proxy.cookie.is_some() && proxy.servers.is_empty() {
            return Err(ConfigError::new(
                1,
                1,
                format!(
                    "HTTP backend {} has a cookie but no server list !",
                    proxy.name
                ),
            ));
        }
    }
    Ok(())
}

fn parse_socket_addr(token: &Token, default_port: Option<u16>) -> Result<SocketAddr, ConfigError> {
    let s = &token.text;
    if s.starts_with('[') {
        if let Some(bracket_end) = s.find(']') {
            let ip_str = &s[1..bracket_end];
            let rest = &s[bracket_end + 1..];
            let port = if let Some(stripped) = rest.strip_prefix(':') {
                stripped.parse::<u16>().map_err(|_| {
                    ConfigError::new(
                        token.line,
                        token.col + bracket_end + 1,
                        format!("invalid port '{stripped}' (must be 0..=65535)"),
                    )
                })?
            } else if let Some(port) = default_port {
                port
            } else {
                return Err(ConfigError::new(
                    token.line,
                    token.col,
                    format!("missing port in address '{s}'"),
                ));
            };
            let ip = parse_ip(ip_str, token.line, token.col)?;
            return Ok(SocketAddr::new(ip, port));
        }
    }

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
    } else if let Some(port) = default_port {
        let ip = parse_ip(s, token.line, token.col)?;
        Ok(SocketAddr::new(ip, port))
    } else {
        Err(ConfigError::new(
            token.line,
            token.col,
            format!("missing port in address '{s}'"),
        ))
    }
}

fn parse_ip(s: &str, line: usize, col: usize) -> Result<IpAddr, ConfigError> {
    let s = s.trim();
    if s.is_empty() || s == "*" || s == "0" {
        return Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    s.parse::<IpAddr>()
        .map_err(|_| ConfigError::new(line, col, format!("invalid IP address '{s}'")))
}

fn parse_timeout(token: &Token, keyword: &str) -> Result<Duration, ConfigError> {
    let s = &token.text;
    let (num_str, factor) = if let Some(stripped) = s.strip_suffix("ms") {
        (stripped, 1u64)
    } else if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1000u64)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60_000u64)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3_600_000u64)
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 86_400_000u64)
    } else {
        (s.as_str(), 1u64)
    };

    let ms: u64 = num_str.parse().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects an integer <time_in_ms> as argument."),
        )
    })?;

    Ok(Duration::from_millis(ms.saturating_mul(factor)))
}

fn parse_u32(token: &Token, keyword: &str) -> Result<u32, ConfigError> {
    token.text.parse::<u32>().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects an integer argument."),
        )
    })
}

fn parse_u16(token: &Token, keyword: &str) -> Result<u16, ConfigError> {
    token.text.parse::<u16>().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects a 16-bit integer argument."),
        )
    })
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
        assert_eq!(
            config.listens[0].contimeout,
            Some(Duration::from_millis(3000))
        );

        assert_eq!(config.listens[1].name, "proxy2");
        assert_eq!(config.listens[1].mode, Mode::Http);

        assert_eq!(config.listens[2].name, "health");
        assert_eq!(config.listens[2].mode, Mode::Health);
        assert_eq!(config.listens[2].maxconn, 4);
    }

    #[test]
    fn test_parse_frontend_backend_content_switching() {
        let sample = r"
frontend web
    bind 0.0.0.0:80
    mode http
    clitimeout 10000
    acl is_static path_beg /static
    acl is_api path_beg /api
    use_backend static_be if is_static
    use_backend api_be if is_api !is_static
    default_backend app_be

backend static_be
    mode http
    server s1 127.0.0.1:8081

backend api_be
    mode http
    server s2 127.0.0.1:8082

backend app_be
    mode http
    balance roundrobin
    server app1 127.0.0.1:8083
    server app2 127.0.0.1:8084
";
        let config = parse_str(sample).unwrap();
        assert_eq!(config.frontends.len(), 1);
        assert_eq!(config.backends.len(), 3);

        let fe = &config.frontends[0];
        assert_eq!(fe.name, "web");
        assert_eq!(fe.mode, Mode::Http);
        assert_eq!(fe.acls.len(), 2);
        assert_eq!(fe.acls[0].name, "is_static");
        assert_eq!(fe.acls[0].expr, "path_beg /static");
        assert_eq!(fe.use_backends.len(), 2);
        assert_eq!(fe.use_backends[0].backend, "static_be");
        assert_eq!(fe.default_backend.as_deref(), Some("app_be"));

        let be_app = &config.backends[2];
        assert_eq!(be_app.name, "app_be");
        assert_eq!(be_app.balance, BalanceAlgorithm::RoundRobin);
        assert_eq!(be_app.servers.len(), 2);
    }

    #[test]
    fn test_parse_stick_table_and_rules() {
        let sample = r"
frontend fe_rate
    bind 0.0.0.0:8080
    stick-table type ip size 100k expire 30s store conn_rate(10s),conn_cur
    stick on src
    track-sc0 src
";
        let config = parse_str(sample).unwrap();
        assert_eq!(config.frontends.len(), 1);
        let fe = &config.frontends[0];
        let st = fe.stick_table.as_ref().unwrap();
        assert_eq!(st.key_type, "ip");
        assert_eq!(st.size, 100 * 1024);
        assert_eq!(st.expire, Duration::from_secs(30));
        assert_eq!(st.store_fields, vec!["conn_rate(10s)", "conn_cur"]);
        assert_eq!(fe.stick_rules.len(), 2);
        assert_eq!(fe.stick_rules[0].rule_type, StickRuleType::StickOn);
        assert_eq!(fe.stick_rules[0].expr, "src");
        assert_eq!(fe.stick_rules[1].rule_type, StickRuleType::TrackSc0);
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

    #[test]
    fn test_parse_proxy_protocol_options() {
        let sample = r"
frontend fe_in
    bind 0.0.0.0:80 accept-proxy
    mode http
    default_backend be_out

frontend fe_v2
    bind 0.0.0.0:81 accept-proxy-v2
    mode tcp
    default_backend be_out

listen li_proxy 0.0.0.0:82 accept-proxy
    mode tcp
    server s_v1 127.0.0.1:8081 send-proxy
    server s_v2 127.0.0.1:8082 send-proxy-v2

backend be_out
    mode http
    server s1 127.0.0.1:8083 send-proxy
    server s2 127.0.0.1:8084 send-proxy-v2
";
        let config = parse_str(sample).unwrap();
        assert_eq!(config.frontends.len(), 2);
        assert!(config.frontends[0].accept_proxy);
        assert!(!config.frontends[0].accept_proxy_v2);

        assert!(config.frontends[1].accept_proxy);
        assert!(config.frontends[1].accept_proxy_v2);

        assert_eq!(config.listens.len(), 1);
        assert!(config.listens[0].accept_proxy);
        assert!(config.listens[0].servers[0].send_proxy);
        assert!(!config.listens[0].servers[0].send_proxy_v2);
        assert!(!config.listens[0].servers[1].send_proxy);
        assert!(config.listens[0].servers[1].send_proxy_v2);

        assert_eq!(config.backends.len(), 1);
        assert!(config.backends[0].servers[0].send_proxy);
        assert!(!config.backends[0].servers[0].send_proxy_v2);
        assert!(!config.backends[0].servers[1].send_proxy);
        assert!(config.backends[0].servers[1].send_proxy_v2);
    }

    #[test]
    fn test_parse_canonical_haproxy_35() {
        let sample = include_str!("../../../examples/canonical_haproxy_35.cfg");
        let config = parse_str(sample).expect("Failed to parse canonical HAProxy 3.5 config");

        // Verify Global
        let global = config.global.expect("global section missing");
        assert_eq!(global.nbthread, Some(4));
        assert_eq!(global.stats_socket.as_deref(), Some("/tmp/ibex.sock"));
        assert_eq!(global.stats_socket_mode, Some(0o660));
        assert_eq!(global.stats_socket_level.as_deref(), Some("admin"));

        // Verify Defaults
        let defaults = config.defaults.expect("defaults section missing");
        assert_eq!(defaults.mode, Some(Mode::Http));
        assert_eq!(defaults.timeouts.connect, Some(Duration::from_secs(5)));
        assert_eq!(defaults.timeouts.client, Some(Duration::from_secs(30)));
        assert_eq!(defaults.timeouts.server, Some(Duration::from_secs(30)));
        assert_eq!(
            defaults.timeouts.http_request,
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            defaults.timeouts.http_keep_alive,
            Some(Duration::from_secs(60))
        );
        assert!(defaults.log_global);

        // Verify Stick Table Backend
        let st_be = config
            .backends
            .iter()
            .find(|b| b.name == "st_rate_limit")
            .expect("st_rate_limit missing");
        let st = st_be.stick_table.as_ref().expect("stick-table missing");
        assert_eq!(st.key_type, "ipv6");
        assert_eq!(st.size, 1024 * 1024);
        assert_eq!(st.expire, Duration::from_secs(600));
        assert_eq!(
            st.store_fields,
            vec![
                "conn_cnt",
                "conn_rate(10s)",
                "http_req_cnt",
                "http_req_rate(10s)",
                "http_err_rate(10s)"
            ]
        );

        // Verify Frontend
        let fe = config
            .frontends
            .iter()
            .find(|f| f.name == "fe_main")
            .expect("fe_main missing");
        assert_eq!(fe.binds.len(), 2);
        assert_eq!(fe.binds[0].addr, "0.0.0.0:8443".parse().unwrap());
        assert!(fe.binds[0].ssl);
        assert_eq!(fe.binds[0].crt.as_deref(), Some("/etc/ibex/certs/"));
        assert_eq!(fe.binds[0].alpn, vec!["h2", "http/1.1"]);
        assert!(fe.binds[0].accept_proxy);

        assert_eq!(fe.binds[1].addr, "[::]:8443".parse().unwrap());
        assert!(fe.binds[1].ssl);
        assert_eq!(fe.binds[1].crt.as_deref(), Some("/etc/ibex/certs/"));
        assert!(fe.binds[1].accept_proxy);

        // Verify Frontend TCP & HTTP Rules
        assert_eq!(fe.tcp_req_conn_rules.len(), 2);
        assert_eq!(fe.http_req_rules.len(), 5);
        assert_eq!(fe.use_backends.len(), 2);
        assert_eq!(fe.default_backend.as_deref(), Some("be_default"));

        // Verify be_default
        let be_def = config
            .backends
            .iter()
            .find(|b| b.name == "be_default")
            .expect("be_default missing");
        assert_eq!(be_def.servers.len(), 3);
        assert_eq!(be_def.servers[0].id, "app-01");
        assert!(be_def.servers[0].check);
        assert_eq!(be_def.servers[0].inter, Some(Duration::from_secs(2)));
        assert_eq!(be_def.servers[0].fall, Some(3));
        assert_eq!(be_def.servers[0].rise, Some(2));
        assert!(be_def.servers[0].send_proxy_v2);
        assert_eq!(be_def.servers[0].weight, Some(100));
        assert_eq!(be_def.servers[0].maxconn, Some(1000));
        assert!(!be_def.servers[0].backup);

        assert_eq!(be_def.servers[2].id, "app-backup");
        assert!(be_def.servers[2].backup);

        assert_eq!(be_def.http_res_rules.len(), 1);
        assert_eq!(be_def.http_after_res_rules.len(), 1);
    }
}
