// SPDX-License-Identifier: GPL-2.0-or-later
//
// HAProxy configuration parser, ported to Rust.
// Derived from HAProxy 1.0 - 3.5 by Willy Tarreau <willy@meta-x.org>.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::ast::{
    clear_resolved_checks, register_resolved_check, register_resolved_check_for_addr, AclCondition,
    AclRule, AclTerm, BackendSection, BalanceAlgorithm, BindConfig, Config, DefaultServerConfig,
    DefaultsSection, FrontendSection, GlobalSection, GlobalSetVar, HttpAfterResAction,
    HttpAfterResRule, HttpCheckAction, HttpCheckExpectPattern, HttpChkConfig, HttpReqAction,
    HttpReqRule, HttpResAction, HttpResRule, HttpReuse, ListenSection, LogConfig, LogFacility,
    LogLevel, LogTarget, MatchType, Mode, ResolvedCheckConfig, ResolvedHttpCheck,
    ResolvedHttpExpectPattern, ResolvedHttpExpectRule, ResolvedTcpExpectPattern, ResolvedTcpStep,
    Server, StatsConfig, StickRule, StickRuleType, StickTableConfigAst, TcpCheckAction,
    TcpCheckExpectPattern, TcpReqConnAction, TcpReqConnRule, TcpReqContentAction,
    TcpReqContentRule, TcpReqSessionAction, TcpReqSessionRule, TimeoutConfig, UseBackendRule,
};
use crate::error::ConfigError;
use crate::lexer::{lex, Token};

/// `HAProxy` keywords in `global` section that are deliberately inert or accepted
/// because their absence changes nothing observable in Ibex's runtime model.
/// Each entry documents why ignoring the keyword preserves compatibility and correctness.
const IGNORED_GLOBAL_KEYWORDS: &[(&str, &str)] = &[
    (
        "expose-experimental-directives",
        "Directive enabling experimental features in HAProxy; inert in Ibex where supported features are parsed directly",
    ),
    (
        "insecure-fork-wanted",
        "Directive allowing daemon fork under systemd; inert in Ibex single-process runtime",
    ),
    (
        "tune.idle-pool.shared",
        "Connection idle pool sharing across threads; inert in Ibex single-process runtime",
    ),
    (
        "tune.ssl.capture-buffer-size",
        "SSL capture buffer size tuning; inert in Ibex Rustls-based TLS subsystem",
    ),
    (
        "tune.ssl.default-dh-param",
        "SSL DH parameter size; inert in Ibex Rustls-based TLS subsystem",
    ),
    (
        "ssl-server-verify",
        "SSL server certificate verification mode default",
    ),
    (
        "crt-base",
        "SSL certificate directory path prefix",
    ),
];

/// `HAProxy` keywords in `defaults` section that are deliberately inert or accepted.
const IGNORED_DEFAULTS_KEYWORDS: &[(&str, &str)] = &[
    (
        "resolvers",
        "Default resolvers directive; inert when dynamic DNS resolution is inactive",
    ),
];

/// `HAProxy` keywords in `resolvers` section that are deliberately inert.
const IGNORED_RESOLVERS_KEYWORDS: &[(&str, &str)] = &[
    ("nameserver", "DNS nameserver definition"),
    ("timeout", "DNS resolver timeout"),
    ("resolve_retries", "DNS resolver retry count"),
    ("hold", "DNS cache hold timers"),
    ("accepted_payload_size", "DNS UDP payload size"),
    ("parse-resolv-conf", "System resolv.conf parser flag"),
];

enum CurrentSection {
    Global(GlobalSection),
    Defaults(DefaultsSection),
    Listen(ListenSection),
    Frontend(FrontendSection),
    Backend(BackendSection),
    Resolvers,
}

/// Parses `HAProxy` configuration text into a typed `Config` AST.
///
/// # Errors
///
/// Returns a `ConfigError` with line and column information if the configuration
/// contains syntax errors, invalid values, or structural inconsistencies.
#[allow(clippy::too_many_lines)]
pub fn parse_str(input: &str) -> Result<Config, ConfigError> {
    // An empty config is valid: HAProxy 3.5 accepts it and exits 0 under `-c`.
    let lines = lex(input);

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
                if tokens.len() >= 2 && !tokens[1].text.is_empty() {
                    return Err(ConfigError::new(tokens[1].line, tokens[1].col, "named defaults sections are not implemented".to_string()));
                }
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
            "resolvers" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Resolvers);
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

    // HAProxy 3.5 accepts a config with no proxy sections -- including a completely
    // empty file -- and exits 0 under `-c`. Verified directly against the oracle for
    // both an empty file and a `global`-only config. Rejecting it makes Ibex refuse
    // configurations the reference accepts, which is the wrong direction for a
    // compatibility target: `-c` is used in CI and deployment gates, so a spurious
    // failure there blocks a rollout that HAProxy would have allowed.
    //
    // The old "no <listen> line. Nothing to do !" error is HAProxy 1.x wording that
    // modern HAProxy no longer emits.

    let maxrewrite = global.as_ref().and_then(|g| g.maxrewrite);
    for l in &mut listens {
        l.stats.maxrewrite = maxrewrite;
    }
    for f in &mut frontends {
        f.stats.maxrewrite = maxrewrite;
    }
    for b in &mut backends {
        b.stats.maxrewrite = maxrewrite;
    }

    validate_config(global.as_ref(), &listens, &frontends, &backends)?;

    let config = Config {
        global,
        defaults,
        listens,
        frontends,
        backends,
    };
    register_checks_from_config(&config);

    Ok(config)
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
            CurrentSection::Resolvers => {}
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

    // Modern HAProxy requires a `bind` line and rejects an inline listening address on
    // the section header. Verified against 3.5-dev7, which answers:
    //   "please use the 'bind' keyword for listening addresses."
    //
    // Accepting the 1.0 form here would make Ibex take configs that the oracle refuses,
    // which is the wrong direction for a compatibility target: a config that works on
    // Ibex and fails on HAProxy is a migration trap.
    if tokens.len() >= 3 && !tokens[2].text.is_empty() {
        if tokens[2].text == "from" {
            return Err(ConfigError::new(tokens[2].line, tokens[2].col, "named defaults sections are not implemented".to_string()));
        }
        return Err(ConfigError::new(
            tokens[2].line,
            tokens[2].col,
            "please use the 'bind' keyword for listening addresses",
        ));
    }
    let addr = SocketAddr::from(([0, 0, 0, 0], 0));
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
        httpchk: defaults.and_then(|d| d.httpchk.clone()),
        http_checks: defaults.map_or_else(Vec::new, |d| d.http_checks.clone()),
        tcp_checks: defaults.map_or_else(Vec::new, |d| d.tcp_checks.clone()),
        tcp_check: defaults.is_some_and(|d| d.tcp_check),
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
        log_global: false,
        log_health_checks: false,
        cliexp: Vec::new(),
        srvexp: Vec::new(),
        acls: Vec::new(),
        use_backends: Vec::new(),
        default_backend: None,
        balance: BalanceAlgorithm::RoundRobin,
        stick_table: None,
        stick_rules: Vec::new(),
        tcp_req_inspect_delay: defaults.and_then(|d| d.tcp_req_inspect_delay),
        tcp_req_conn_rules: Vec::new(),
        tcp_req_session_rules: Vec::new(),
        tcp_req_content_rules: Vec::new(),
        http_req_rules: Vec::new(),
        http_res_rules: Vec::new(),
        http_after_res_rules: Vec::new(),
        accept_proxy,
        accept_proxy_v2,
        http_reuse: defaults.and_then(|d| d.http_reuse),
        forwardfor: None,
        originalto: None,
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
        if tokens[2].text == "from" {
            return Err(ConfigError::new(tokens[2].line, tokens[2].col, "named defaults sections are not implemented".to_string()));
        }
        return Err(ConfigError::new(tokens[2].line, tokens[2].col, "please use the 'bind' keyword for listening addresses".to_string()));
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
            crt: Vec::new(),
            alpn: Vec::new(),
            proto: None,
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
        log_global: false,
        log_health_checks: false,
        stick_table: None,
        stick_rules: Vec::new(),
        tcp_req_inspect_delay: defaults.and_then(|d| d.tcp_req_inspect_delay),
        tcp_req_conn_rules: Vec::new(),
        tcp_req_session_rules: Vec::new(),
        tcp_req_content_rules: Vec::new(),
        http_req_rules: Vec::new(),
        http_res_rules: Vec::new(),
        http_after_res_rules: Vec::new(),
        accept_proxy,
        accept_proxy_v2,
        forwardfor: None,
        originalto: None,
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
    if tokens.len() >= 3 && !tokens[2].text.is_empty() {
        if tokens[2].text == "from" {
            return Err(ConfigError::new(tokens[2].line, tokens[2].col, "named defaults sections are not implemented".to_string()));
        }
        return Err(ConfigError::new(tokens[2].line, tokens[2].col, "unexpected extra argument in backend header".to_string()));
    }
    let mode = defaults.and_then(|d| d.mode).unwrap_or(Mode::Tcp);
    let timeouts = defaults.map_or_else(TimeoutConfig::default, |d| d.timeouts);

    Ok(BackendSection {
        httpchk: defaults.and_then(|d| d.httpchk.clone()),
        http_checks: defaults.map_or_else(Vec::new, |d| d.http_checks.clone()),
        tcp_checks: defaults.map_or_else(Vec::new, |d| d.tcp_checks.clone()),
        tcp_check: defaults.is_some_and(|d| d.tcp_check),
        name: id,
        logs: Vec::new(),
        log_global: false,
        log_health_checks: false,
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
        tcp_req_inspect_delay: defaults.and_then(|d| d.tcp_req_inspect_delay),
        tcp_req_content_rules: Vec::new(),
        http_req_rules: Vec::new(),
        http_res_rules: Vec::new(),
        http_after_res_rules: Vec::new(),
        http_reuse: defaults.and_then(|d| d.http_reuse),
        forwardfor: None,
        originalto: None,
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
        CurrentSection::Resolvers => parse_resolvers_directive(tokens, kw),
    }
}

fn parse_resolvers_directive(tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    let _ = tokens;
    match kw.text.as_str() {
        other if IGNORED_RESOLVERS_KEYWORDS.iter().any(|(k, _)| *k == other) => Ok(()),
        other => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{other}' in 'resolvers' section"),
        )),
    }
}

#[allow(clippy::too_many_lines)]
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
        "log" => {
            // `log global` is meaningless here -- this *is* global -- and HAProxy
            // rejects it, so parse_log's inherit form is treated as an error.
            if parse_log(&mut global.logs, tokens, kw)? {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'log global' is not valid in the global section",
                ));
            }
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
        "tune.maxrewrite" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.maxrewrite' expects an integer argument."));
            }
            let raw_val = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.maxrewrite' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            global.maxrewrite = Some(raw_val);
            Ok(())
        }
        "tune.bufsize" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.bufsize' expects an integer argument."));
            }
            let raw_size = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            if raw_size == 0 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, "'tune.bufsize' expects a positive integer argument."));
            }
            if raw_size >= 268_435_456 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize' must be less than 268435456 bytes (256 MB), got {raw_size}")));
            }
            let rounded = (raw_size + 15) & !15;
            global.bufsize = Some(rounded);
            Ok(())
        }
        "tune.bufsize.small" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.bufsize.small' expects an integer argument."));
            }
            let raw_size = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.small' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            if raw_size == 0 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, "'tune.bufsize.small' expects a positive integer argument."));
            }
            if raw_size >= 268_435_456 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.small' must be less than 268435456 bytes (256 MB), got {raw_size}")));
            }
            let rounded = (raw_size + 15) & !15;
            global.bufsize_small = Some(rounded);
            Ok(())
        }
        "tune.bufsize.large" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(kw.line, kw.col, "'tune.bufsize.large' expects an integer argument."));
            }
            let raw_size = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.large' expects an integer argument, got '{}'", tokens[1].text))
            })?;
            if raw_size == 0 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, "'tune.bufsize.large' expects a positive integer argument."));
            }
            if raw_size >= 268_435_456 {
                return Err(ConfigError::new(tokens[1].line, tokens[1].col, format!("'tune.bufsize.large' must be less than 268435456 bytes (256 MB), got {raw_size}")));
            }
            let rounded = (raw_size + 15) & !15;
            global.bufsize_large = Some(rounded);
            Ok(())
        }
        "tune.h2.fe.max-total-streams" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'tune.h2.fe.max-total-streams' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!(
                        "'tune.h2.fe.max-total-streams' expects an integer argument, got '{}'",
                        tokens[1].text
                    ),
                )
            })?;
            global.h2_max_total_streams = Some(val);
            Ok(())
        }
        "tune.h2.fe.glitches-threshold" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'tune.h2.fe.glitches-threshold' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<usize>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!(
                        "'tune.h2.fe.glitches-threshold' expects an integer argument, got '{}'",
                        tokens[1].text
                    ),
                )
            })?;
            global.h2_glitches_threshold = Some(val);
            Ok(())
        }
        "tune.glitches.kill.cpu-usage" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                "'tune.glitches.kill.cpu-usage' is not supported (no CPU measurement subsystem in tree)",
            ))
        }
        "tune.h2.fe.max-rst-at-once" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                "'tune.h2.fe.max-rst-at-once' is not supported (resets-burst deprioritization is not implemented)",
            ))
        }
        "thread-groups" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'thread-groups' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<u32>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!(
                        "'thread-groups' expects an integer argument, got '{}'",
                        tokens[1].text
                    ),
                )
            })?;
            if val == 0 {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    "'thread-groups' value must be between 1 and 32 (was 0)",
                ));
            }
            if val > 1 {
                return Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("'thread-groups' > 1 is not supported (got {val})"),
                ));
            }
            // val == 1: accepted as inert default (Ibex single thread group runtime model)
            Ok(())
        }
        "external-check" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                "'external-check' is not supported (external health checks are not implemented)",
            ))
        }
        "lua-load" | "lua-load-per-thread" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported (embedded Lua runtime is not implemented)", kw.text),
            ))
        }
        "httpclient.resolvers.disabled" | "httpclient.resolvers.prefer" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported (HTTP client resolvers are not implemented)", kw.text),
            ))
        }
        "maxconn" => {
            if tokens.len() < 2 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'maxconn' expects an integer argument.",
                ));
            }
            let val = tokens[1].text.parse::<u32>().map_err(|_| {
                ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("'maxconn' expects an integer argument, got '{}'", tokens[1].text),
                )
            })?;
            global.maxconn = Some(val);
            Ok(())
        }
        "daemon" => {
            global.daemon = true;
            Ok(())
        }
        "master-worker" => {
            global.master_worker = true;
            Ok(())
        }
        "user" => {
            if tokens.len() >= 2 {
                global.user = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "group" => {
            if tokens.len() >= 2 {
                global.group = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "chroot" => {
            if tokens.len() >= 2 {
                global.chroot = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "pidfile" => {
            if tokens.len() >= 2 {
                global.pidfile = Some(tokens[1].text.clone());
            }
            Ok(())
        }
        "hard-stop-after" => {
            if tokens.len() >= 2 {
                global.hard_stop_after = Some(parse_timeout(&tokens[1], "hard-stop-after")?);
            }
            Ok(())
        }
        "maxsslconn" => {
            if tokens.len() >= 2 {
                global.maxsslconn = tokens[1].text.parse::<u32>().ok();
            }
            Ok(())
        }
        "ssl-default-bind-ciphers" => {
            if tokens.len() >= 2 {
                global.ssl_default_bind_ciphers = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "ssl-default-bind-options" => {
            if tokens.len() >= 2 {
                global.ssl_default_bind_options = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "ssl-default-server-ciphers" => {
            if tokens.len() >= 2 {
                global.ssl_default_server_ciphers = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "ssl-default-server-options" => {
            if tokens.len() >= 2 {
                global.ssl_default_server_options = Some(tokens[1..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" "));
            }
            Ok(())
        }
        "set-var" => {
            if tokens.len() >= 3 {
                let var_name = tokens[1].text.clone();
                let expr = tokens[2..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
                global.set_vars.push(GlobalSetVar {
                    name: var_name,
                    expr,
                    is_fmt: false,
                });
            }
            Ok(())
        }
        "set-var-fmt" => {
            if tokens.len() >= 3 {
                let var_name = tokens[1].text.clone();
                let expr = tokens[2..].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
                global.set_vars.push(GlobalSetVar {
                    name: var_name,
                    expr,
                    is_fmt: true,
                });
            }
            Ok(())
        }
        other if IGNORED_GLOBAL_KEYWORDS.iter().any(|(k, _)| *k == other) => Ok(()),
        _ => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{}' in 'global' section", kw.text),
        )),
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
        "retries" => {
            let mut r = defaults.retries.unwrap_or(0);
            parse_retries(&mut r, tokens, kw)?;
            defaults.retries = Some(r);
            Ok(())
        }
        "redisp" => {
            defaults.redisp = true;
            Ok(())
        }
        "maxconn" => {
            let mut mc = defaults.maxconn.unwrap_or(0);
            parse_maxconn(&mut mc, tokens, kw)?;
            defaults.maxconn = Some(mc);
            Ok(())
        }
        "balance" => {
            let mut b = defaults.balance.unwrap_or(BalanceAlgorithm::RoundRobin);
            parse_balance(&mut b, tokens, kw)?;
            defaults.balance = Some(b);
            Ok(())
        }
        "cookie" => {
            let mut c = defaults.cookie.clone();
            parse_cookie(&mut c, tokens, kw)?;
            defaults.cookie = c;
            Ok(())
        }
        "default-server" => parse_default_server(&mut defaults.default_server, tokens, kw),
        "stats" => parse_stats_directive(&mut defaults.stats, tokens, kw),
        "errorfile" => {
            // errorfile <status> <file> in defaults
            Ok(())
        }
        "tcp-request" => {
            if tokens.len() >= 3 && tokens[1].text == "inspect-delay" {
                defaults.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
                Ok(())
            } else {
                Err(ConfigError::new(
                    tokens[1].line,
                    tokens[1].col,
                    format!("tcp-request subcommand '{}' is not supported in defaults", tokens[1].text),
                ))
            }
        }
        "log" => {
            defaults.log_global |= parse_log(&mut defaults.logs, tokens, kw)?;
            Ok(())
        }
        "option" => parse_option_defaults(defaults, tokens, kw),
        "no" => parse_no_directive(tokens, kw),
        "declare" => parse_declare(tokens, kw),
        "contimeout" => parse_contimeout(kw),
        "clitimeout" => parse_clitimeout(kw),
        "srvtimeout" => parse_srvtimeout(kw),
        "dispatch" => parse_dispatch(kw),
        "http-reuse" => parse_http_reuse(&mut defaults.http_reuse, tokens, kw),
        "cliexp" => parse_cliexp(kw),
        "srvexp" => parse_srvexp(kw),
        "tcp-response" | "http-request" | "http-response" | "http-after-request" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("directive '{}' is not supported in defaults", kw.text),
            ))
        }
        "http-check" => {
            parse_http_check_directive(&mut defaults.http_checks, tokens, kw)?;
            Ok(())
        }
        "tcp-check" => {
            parse_tcp_check_directive(&mut defaults.tcp_checks, tokens, kw)?;
            Ok(())
        }
        "log-format" | "log-format-sd" => {
            Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("'{}' is not supported", kw.text),
            ))
        }
        other if IGNORED_DEFAULTS_KEYWORDS.iter().any(|(k, _)| *k == other) => Ok(()),
        _ => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown keyword '{}' in 'defaults' section", kw.text),
        )),
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
        "log" => {
            proxy.log_global |= parse_log(&mut proxy.logs, tokens, kw)?;
            Ok(())
        }
        "cliexp" => parse_cliexp(kw),
        "srvexp" => parse_srvexp(kw),
        "balance" => parse_balance(&mut proxy.balance, tokens, kw),
        "http-reuse" => parse_http_reuse(&mut proxy.http_reuse, tokens, kw),
        "acl" => parse_acl(&mut proxy.acls, tokens, kw),
        "use_backend" => parse_use_backend(&mut proxy.use_backends, tokens, kw),
        "default_backend" => parse_default_backend(&mut proxy.default_backend, tokens, kw),
        "option" => parse_option_listen(proxy, tokens, kw),
        "no" => parse_no_directive(tokens, kw),
        "declare" => parse_declare(tokens, kw),
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
        "tcp-check" => {
            parse_tcp_check_directive(&mut proxy.tcp_checks, tokens, kw)?;
            Ok(())
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
        "log" => {
            fe.log_global |= parse_log(&mut fe.logs, tokens, kw)?;
            Ok(())
        }
        "acl" => parse_acl(&mut fe.acls, tokens, kw),
        "use_backend" => parse_use_backend(&mut fe.use_backends, tokens, kw),
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

    fe.binds.push(BindConfig {
        addr,
        ssl,
        crt,
        alpn,
        proto,
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
        "http-reuse" => parse_http_reuse(&mut be.http_reuse, tokens, kw),
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
        "log" => {
            be.log_global |= parse_log(&mut be.logs, tokens, kw)?;
            Ok(())
        }
        "http-check" => {
            parse_http_check_directive(&mut be.http_checks, tokens, kw)?;
            Ok(())
        }
        "tcp-check" => {
            parse_tcp_check_directive(&mut be.tcp_checks, tokens, kw)?;
            Ok(())
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

#[allow(clippy::unnecessary_wraps)]
/// Options whose silent absence changes what the daemon *checks*, not merely what it logs.
///
/// `option httpchk GET /health` parsed into nothing and `ibex -c` reported the config valid.
/// The server then got a bare TCP connect, so a backend accepting connections and answering
/// 500 to everything was reported UP. A health check that silently degrades is how an outage
/// is masked rather than caught, which is worse than one that never started.
///
/// This is deliberately a named list rather than a blanket refusal of unknown options.
/// Making the `global` section strictly reject unknown keywords took the reg-test board from
/// 7 passing to 1 in one commit, because `thread-groups` appears in nearly every HAProxy
/// reg-test. Refuse what is dangerous to ignore; keep ignoring what is merely unimplemented.
const CHECK_OPTIONS_THAT_MUST_NOT_BE_IGNORED: &[&str] = &[
    "ssl-hello-chk",
    "smtpchk",
    "mysql-check",
    "pgsql-check",
    "redis-check",
    "ldap-check",
    "spop-check",
];

fn refuse_if_check_option(name: &str, kw: &Token) -> Result<(), ConfigError> {
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

fn parse_option_listen(
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
            other => {
                refuse_if_check_option(other, kw)?;
                eprintln!("[ibex] warning: ignored option '{other}'");
            }
        }
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn parse_option_frontend(
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
fn parse_option_backend(
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
            other => {
                refuse_if_check_option(other, kw)?;
                eprintln!("[ibex] warning: ignored option '{other}'");
            }
        }
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn parse_option_defaults(
    defaults: &mut DefaultsSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        match tokens[1].text.as_str() {
            "log-health-checks" => {
                defaults.log_health_checks = true;
            }
            "httpchk" => {
                parse_httpchk_option(&mut defaults.httpchk, tokens, kw)?;
            }
            "tcp-check" => {
                defaults.tcp_check = true;
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
fn parse_no_directive(tokens: &[Token], _kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        eprintln!("[ibex] warning: ignored 'no {}'", tokens[1].text);
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn parse_declare(tokens: &[Token], _kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        eprintln!("[ibex] warning: ignored declare directive '{}'", tokens[1].text);
    }
    Ok(())
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

fn unescape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    'r' => {
                        out.push('\r');
                        chars.next();
                    }
                    'n' => {
                        out.push('\n');
                        chars.next();
                    }
                    't' => {
                        out.push('\t');
                        chars.next();
                    }
                    '0' => {
                        out.push('\0');
                        chars.next();
                    }
                    '\\' => {
                        out.push('\\');
                        chars.next();
                    }
                    ' ' => {
                        out.push(' ');
                        chars.next();
                    }
                    _ => {
                        out.push(c);
                    }
                }
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_hex_binary(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim().replace(' ', "");
    if clean.len() % 2 != 0 {
        return Err(format!("odd hex string length: {}", clean.len()));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for i in (0..clean.len()).step_by(2) {
        let byte = u8::from_str_radix(&clean[i..i + 2], 16)
            .map_err(|e| format!("invalid hex byte '{}': {}", &clean[i..i + 2], e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn parse_match_type(s: &str) -> MatchType {
    match s.to_ascii_lowercase().as_str() {
        "beg" => MatchType::Beg,
        "end" => MatchType::End,
        "sub" => MatchType::Sub,
        "reg" => MatchType::Reg,
        _ => MatchType::Str,
    }
}

#[allow(clippy::unnecessary_wraps)]
fn parse_httpchk_option(
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
fn parse_http_check_directive(
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
fn parse_tcp_check_directive(
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

fn build_resolved_http_check(
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
                method: m,
                uri: u,
                version: v,
                headers: h,
                body: b,
            } => {
                if let Some(m) = m {
                    method = m.clone();
                }
                if let Some(u) = u {
                    uri = u.clone();
                }
                if let Some(v) = v {
                    version = v.clone();
                }
                for (name, val) in h {
                    if name.eq_ignore_ascii_case("host") {
                        host = Some(val.clone());
                    }
                    headers.push((name.clone(), val.clone()));
                }
                if let Some(b) = b {
                    body = Some(b.clone());
                }
            }
            HttpCheckAction::Expect { pattern, negate } => {
                let resolved_pat = match pattern {
                    HttpCheckExpectPattern::Status(codes) => {
                        ResolvedHttpExpectPattern::Status(codes.clone())
                    }
                    HttpCheckExpectPattern::StatusRange(low, high) => {
                        ResolvedHttpExpectPattern::StatusRange(*low, *high)
                    }
                    HttpCheckExpectPattern::String(s) => {
                        ResolvedHttpExpectPattern::String(s.clone())
                    }
                    HttpCheckExpectPattern::RStatus(s) => {
                        ResolvedHttpExpectPattern::RStatus(s.clone())
                    }
                    HttpCheckExpectPattern::RString(s) => {
                        ResolvedHttpExpectPattern::RString(s.clone())
                    }
                    HttpCheckExpectPattern::Hdr {
                        name,
                        match_type,
                        value,
                        value_match_type,
                    } => ResolvedHttpExpectPattern::Hdr {
                        name: name.clone(),
                        match_type: *match_type,
                        value: value.clone(),
                        value_match_type: *value_match_type,
                    },
                    HttpCheckExpectPattern::Fhdr {
                        name,
                        match_type,
                        value,
                        value_match_type,
                    } => ResolvedHttpExpectPattern::Fhdr {
                        name: name.clone(),
                        match_type: *match_type,
                        value: value.clone(),
                        value_match_type: *value_match_type,
                    },
                };
                expect_rules.push(ResolvedHttpExpectRule {
                    pattern: resolved_pat,
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

fn build_resolved_tcp_steps(
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
                let pat = match pattern {
                    TcpCheckExpectPattern::String(s) => {
                        ResolvedTcpExpectPattern::String(s.clone())
                    }
                    TcpCheckExpectPattern::Binary(b) => {
                        ResolvedTcpExpectPattern::Binary(b.clone())
                    }
                    TcpCheckExpectPattern::RString(r) => {
                        ResolvedTcpExpectPattern::RString(r.clone())
                    }
                };
                steps.push(ResolvedTcpStep::Expect {
                    pattern: pat,
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

fn register_checks_from_config(config: &Config) {
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

fn register_section_checks(
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

fn parse_contimeout(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'contimeout' was removed in HAProxy 2.1; use 'timeout connect' instead",
    ))
}

fn parse_clitimeout(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'clitimeout' was removed in HAProxy 2.1; use 'timeout client' instead",
    ))
}

fn parse_srvtimeout(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'srvtimeout' was removed in HAProxy 2.1; use 'timeout server' instead",
    ))
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
        "tunnel" => timeouts.tunnel = Some(dur),
        "tarpit" => timeouts.tarpit = Some(dur),
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

fn parse_http_reuse(
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

fn parse_dispatch(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'dispatch' was removed in HAProxy 3.5; use 'server' or 'default_backend' instead",
    ))
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

/// Parses a `log` directive into `logs`, returning true for the `log global` form.
///
/// `log global` inherits whatever the `global` section declared, and is how essentially
/// every real `HAProxy` configuration turns logging on for a proxy. It used to fall into
/// the argument check below and be rejected as "expects <address> and <facility>", so a
/// canonical config did not load at all.
/// Parses a `log` directive into `logs`, returning true for the `log global` form.
///
/// The grammar, from `src/log.c`:
///
/// ```text
/// log <target> [len <n>] [format <fmt>] <facility> [<level>]
/// log global
/// ```
///
/// `log global` inherits whatever the `global` section declared, and is how essentially
/// every real `HAProxy` configuration turns logging on for a proxy.
fn parse_log(
    logs: &mut Vec<LogConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<bool, ConfigError> {
    if tokens.len() >= 2 && tokens[1].text == "global" {
        return Ok(true);
    }
    if tokens.len() < 3 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<log> expects <address> and <facility> as arguments.",
        ));
    }
    if logs.len() >= 2 {
        return Err(ConfigError::new(kw.line, kw.col, "too many syslog servers"));
    }

    let target = parse_log_target(&tokens[1])?;

    // `len` and `format` sit between the target and the facility, in that order, and
    // both are optional -- so the facility is wherever those stop, not a fixed index.
    let mut i = 2;
    let mut max_len = 1024usize;
    let mut format = None;
    while i + 1 < tokens.len() {
        match tokens[i].text.as_str() {
            "len" => {
                let n: usize = tokens[i + 1].text.parse().map_err(|_| {
                    ConfigError::new(
                        tokens[i + 1].line,
                        tokens[i + 1].col,
                        format!("invalid log length '{}'", tokens[i + 1].text),
                    )
                })?;
                if !(80..=65535).contains(&n) {
                    return Err(ConfigError::new(
                        tokens[i + 1].line,
                        tokens[i + 1].col,
                        format!("invalid log length '{n}', must be between 80 and 65535"),
                    ));
                }
                max_len = n;
                i += 2;
            }
            "format" => {
                format = Some(tokens[i + 1].text.clone());
                i += 2;
            }
            _ => break,
        }
    }

    let Some(fac_tok) = tokens.get(i) else {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<log> expects <address> and <facility> as arguments.",
        ));
    };
    let facility = parse_facility(fac_tok)?;
    let level = match tokens.get(i + 1) {
        Some(t) if !t.text.is_empty() => Some(parse_level(t)?),
        _ => None,
    };

    logs.push(LogConfig {
        target,
        facility,
        level,
        max_len,
        format,
    });
    Ok(false)
}

/// Resolves a `log` target: an address, a file descriptor, or a unix socket.
///
/// `stdout` and `stderr` are aliases for `fd@1` and `fd@2` (`src/log.c`), which is how a
/// containerised or systemd-managed proxy logs without a syslog daemon anywhere.
fn parse_log_target(tok: &Token) -> Result<LogTarget, ConfigError> {
    let t = tok.text.as_str();
    match t {
        "stdout" => return Ok(LogTarget::Fd(1)),
        "stderr" => return Ok(LogTarget::Fd(2)),
        _ => {}
    }
    if let Some(n) = t.strip_prefix("fd@") {
        let fd: i32 = n.parse().map_err(|_| {
            ConfigError::new(tok.line, tok.col, format!("invalid file descriptor '{n}'"))
        })?;
        if fd < 0 {
            return Err(ConfigError::new(
                tok.line,
                tok.col,
                format!("invalid file descriptor '{fd}'"),
            ));
        }
        return Ok(LogTarget::Fd(fd));
    }
    if let Some(path) = t.strip_prefix("unix@") {
        return Ok(LogTarget::Unix(path.to_string()));
    }
    // A bare absolute path is a unix socket, as it is for `bind`.
    if t.starts_with('/') {
        return Ok(LogTarget::Unix(t.to_string()));
    }
    Ok(LogTarget::Udp(parse_socket_addr(tok, Some(514))?))
}

fn parse_cliexp(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'cliexp' was removed in HAProxy 2.0; use 'http-request replace-path' or 'http-request replace-header' instead",
    ))
}

fn parse_srvexp(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'srvexp' was removed in HAProxy 2.0; use 'http-response replace-header' instead",
    ))
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

fn parse_track_sc_args(
    tokens: &[Token],
    start: usize,
) -> Result<(String, Option<String>, Option<usize>), ConfigError> {
    if tokens.len() <= start {
        return Err(ConfigError::new(
            tokens.get(start - 1).map_or(0, |t| t.line),
            tokens.get(start - 1).map_or(0, |t| t.col),
            "track-sc* expects sample expression",
        ));
    }
    let expr = tokens[start].text.clone();
    let mut table = None;
    let mut cond_start = None;
    let mut i = start + 1;
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
    Ok((expr, table, cond_start))
}

fn parse_rule_condition(
    tokens: &[Token],
    start: usize,
) -> Result<(Option<usize>, Option<AclCondition>), ConfigError> {
    let cond_idx = find_cond_idx(tokens, start);
    let cond = match cond_idx {
        Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
        None => None,
    };
    Ok((cond_idx, cond))
}

fn join_tokens_until(tokens: &[Token], start: usize, cond_idx: Option<usize>) -> String {
    let limit = cond_idx.unwrap_or(tokens.len());
    tokens[start..limit]
        .iter()
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_sc_counter_action(
    act_str: &str,
    prefix: &str,
    act_tok: &Token,
) -> Result<Option<u8>, ConfigError> {
    if act_str == prefix {
        return Ok(Some(0));
    }
    if let Some(rest) = act_str.strip_prefix(prefix) {
        if !rest.starts_with('(') {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("invalid stick table track ID. Expects {prefix}(<Track ID>)"),
            ));
        }
        if !rest.ends_with(')') {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("missing closing parenthesis in <{act_str}>"),
            ));
        }
        let inner = &rest[1..rest.len() - 1];
        let val = inner.parse::<u8>().map_err(|_| {
            ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("invalid stick counter index in <{act_str}>"),
            )
        })?;
        if val > 2 {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                format!("stick counter index must be 0, 1, or 2 in <{act_str}>"),
            ));
        }
        return Ok(Some(val));
    }
    Ok(None)
}


fn parse_tcp_req_connection(
    rules: &mut Vec<TcpReqConnRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<tcp-request connection> expects <action>",
        ));
    }
    let act_tok = &tokens[2];
    match act_tok.text.as_str() {
        "track-sc0" | "track-sc1" | "track-sc2" => {
            let (expr, table, cond_start) = parse_track_sc_args(tokens, 3)?;
            let cond = match cond_start {
                Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
                None => None,
            };
            let action = match act_tok.text.as_str() {
                "track-sc1" => TcpReqConnAction::TrackSc1 { expr, table },
                "track-sc2" => TcpReqConnAction::TrackSc2 { expr, table },
                _ => TcpReqConnAction::TrackSc0 { expr, table },
            };
            rules.push(TcpReqConnRule { action, cond });
        }
        "silent-drop" => {
            let (_, cond) = parse_rule_condition(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SilentDrop, cond });
        }
        "reject" => {
            let (_, cond) = parse_rule_condition(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::Reject, cond });
        }
        "accept" => {
            let (_, cond) = parse_rule_condition(tokens, 3)?;
            rules.push(TcpReqConnRule { action: TcpReqConnAction::Accept, cond });
        }
        "set-src" => {
            let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
            let expr = join_tokens_until(tokens, 3, cond_idx);
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SetSrc { expr }, cond });
        }
        "set-dst" => {
            let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
            let expr = join_tokens_until(tokens, 3, cond_idx);
            rules.push(TcpReqConnRule { action: TcpReqConnAction::SetDst { expr }, cond });
        }
        "do-log" => {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                "action do-log is not supported in this build",
            ));
        }
        other => {
            if other.starts_with("lua.") {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    format!("lua actions require Lua support, which this build does not have: <{other}>"),
                ));
            }
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
fn parse_tcp_req_session(
    rules: &mut Vec<TcpReqSessionRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<tcp-request session> expects <action>",
        ));
    }
    let act_tok = &tokens[2];
    let act_str = &act_tok.text;
    if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let is_fmt = act_str.starts_with("set-var-fmt(");
        let var_name = act_str
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
        let action = if is_fmt {
            TcpReqSessionAction::SetVarFmt { var_name, fmt: expr }
        } else {
            TcpReqSessionAction::SetVar { var_name, expr }
        };
        rules.push(TcpReqSessionRule { action, cond });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_str
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::UnsetVar { var_name }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScIncGpc0 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScIncGpc1 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_tok)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 4)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
        if expr.is_empty() {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                "<tcp-request session sc-set-gpt0> expects value or expression",
            ));
        }
        rules.push(TcpReqSessionRule { action: TcpReqSessionAction::ScSetGpt0 { sc, expr }, cond });
    } else {
        match act_str.as_str() {
            "track-sc0" | "track-sc1" | "track-sc2" => {
                let (expr, table, cond_start) = parse_track_sc_args(tokens, 3)?;
                let cond = match cond_start {
                    Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
                    None => None,
                };
                let action = match act_str.as_str() {
                    "track-sc1" => TcpReqSessionAction::TrackSc1 { expr, table },
                    "track-sc2" => TcpReqSessionAction::TrackSc2 { expr, table },
                    _ => TcpReqSessionAction::TrackSc0 { expr, table },
                };
                rules.push(TcpReqSessionRule { action, cond });
            }
            "silent-drop" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SilentDrop, cond });
            }
            "reject" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::Reject, cond });
            }
            "accept" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::Accept, cond });
            }
            "set-src" => {
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetSrc { expr }, cond });
            }
            "set-dst" => {
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqSessionRule { action: TcpReqSessionAction::SetDst { expr }, cond });
            }
            "attach-srv" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action attach-srv is not supported in this build",
                ));
            }
            "do-log" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action do-log is not supported in this build",
                ));
            }
            other => {
                if other.starts_with("lua.") {
                    return Err(ConfigError::new(
                        act_tok.line,
                        act_tok.col,
                        format!("lua actions require Lua support, which this build does not have: <{other}>"),
                    ));
                }
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    format!("unknown tcp-request session action <{other}>"),
                ));
            }
        }
    }
    Ok(())
}

fn parse_tcp_content_var(
    tokens: &[Token],
    act_str: &str,
) -> Result<Option<TcpReqContentRule>, ConfigError> {
    if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let is_fmt = act_str.starts_with("set-var-fmt(");
        let var_name = act_str
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
        let action = if is_fmt {
            TcpReqContentAction::SetVarFmt { var_name, fmt: expr }
        } else {
            TcpReqContentAction::SetVar { var_name, expr }
        };
        Ok(Some(TcpReqContentRule { action, cond }))
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_str
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        Ok(Some(TcpReqContentRule {
            action: TcpReqContentAction::UnsetVar { var_name },
            cond,
        }))
    } else {
        Ok(None)
    }
}

fn parse_tcp_content_switch_mode(
    tokens: &[Token],
) -> Result<TcpReqContentRule, ConfigError> {
    let mut proto = None;
    let (cond_idx, cond) = parse_rule_condition(tokens, 4)?;
    let limit = cond_idx.unwrap_or(tokens.len());
    let mut i = 4;
    while i < limit {
        if tokens[i].text == "proto" && i + 1 < limit {
            proto = Some(tokens[i + 1].text.clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(TcpReqContentRule {
        action: TcpReqContentAction::SwitchModeHttp { proto },
        cond,
    })
}

#[allow(clippy::too_many_lines)]
fn parse_tcp_req_content(
    rules: &mut Vec<TcpReqContentRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 3 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "<tcp-request content> expects <action>",
        ));
    }
    let act_tok = &tokens[2];
    let act_str = &act_tok.text;
    if let Some(rule) = parse_tcp_content_var(tokens, act_str)? {
        rules.push(rule);
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScIncGpc0 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_tok)? {
        let (_, cond) = parse_rule_condition(tokens, 3)?;
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScIncGpc1 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_tok)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 4)?;
        let expr = join_tokens_until(tokens, 3, cond_idx);
        if expr.is_empty() {
            return Err(ConfigError::new(
                act_tok.line,
                act_tok.col,
                "<tcp-request content sc-set-gpt0> expects value or expression",
            ));
        }
        rules.push(TcpReqContentRule { action: TcpReqContentAction::ScSetGpt0 { sc, expr }, cond });
    } else if act_str.starts_with("lua.") {
        return Err(ConfigError::new(
            act_tok.line,
            act_tok.col,
            format!("lua actions require Lua support, which this build does not have: <{act_str}>"),
        ));
    } else {
        match act_str.as_str() {
            "track-sc0" | "track-sc1" | "track-sc2" => {
                let (expr, table, cond_start) = parse_track_sc_args(tokens, 3)?;
                let cond = match cond_start {
                    Some(idx) => parse_acl_condition_from_tokens(&tokens[idx..])?,
                    None => None,
                };
                let action = match act_str.as_str() {
                    "track-sc1" => TcpReqContentAction::TrackSc1 { expr, table },
                    "track-sc2" => TcpReqContentAction::TrackSc2 { expr, table },
                    _ => TcpReqContentAction::TrackSc0 { expr, table },
                };
                rules.push(TcpReqContentRule { action, cond });
            }
            "silent-drop" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SilentDrop, cond });
            }
            "reject" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::Reject, cond });
            }
            "accept" => {
                let (_, cond) = parse_rule_condition(tokens, 3)?;
                rules.push(TcpReqContentRule { action: TcpReqContentAction::Accept, cond });
            }
            "set-src" => {
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetSrc { expr }, cond });
            }
            "set-dst" => {
                let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
                let expr = join_tokens_until(tokens, 3, cond_idx);
                rules.push(TcpReqContentRule { action: TcpReqContentAction::SetDst { expr }, cond });
            }
            "switch-mode" => {
                rules.push(parse_tcp_content_switch_mode(tokens)?);
            }
            "use-service" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action use-service is not supported in this build",
                ));
            }
            "do-log" => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    "action do-log is not supported in this build",
                ));
            }
            other => {
                return Err(ConfigError::new(
                    act_tok.line,
                    act_tok.col,
                    format!("unknown tcp-request content action <{other}>"),
                ));
            }
        }
    }
    Ok(())
}

fn parse_listen_tcp_request(
    listen: &mut ListenSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "missing argument for 'tcp-request'",
        ));
    }
    match tokens[1].text.as_str() {
        "inspect-delay" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<tcp-request inspect-delay> expects delay timeout",
                ));
            }
            listen.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
            Ok(())
        }
        "connection" => parse_tcp_req_connection(&mut listen.tcp_req_conn_rules, tokens, kw),
        "session" => parse_tcp_req_session(&mut listen.tcp_req_session_rules, tokens, kw),
        "content" => parse_tcp_req_content(&mut listen.tcp_req_content_rules, tokens, kw),
        other => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("unknown tcp-request subcommand <{other}>, expects 'inspect-delay', 'connection', 'session', or 'content'"),
        )),
    }
}

fn parse_frontend_tcp_request(
    fe: &mut FrontendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "missing argument for 'tcp-request'",
        ));
    }
    match tokens[1].text.as_str() {
        "inspect-delay" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<tcp-request inspect-delay> expects delay timeout",
                ));
            }
            fe.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
            Ok(())
        }
        "connection" => parse_tcp_req_connection(&mut fe.tcp_req_conn_rules, tokens, kw),
        "session" => parse_tcp_req_session(&mut fe.tcp_req_session_rules, tokens, kw),
        "content" => parse_tcp_req_content(&mut fe.tcp_req_content_rules, tokens, kw),
        other => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("unknown tcp-request subcommand <{other}>, expects 'inspect-delay', 'connection', 'session', or 'content'"),
        )),
    }
}

fn parse_backend_tcp_request(
    be: &mut BackendSection,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "missing argument for 'tcp-request'",
        ));
    }
    match tokens[1].text.as_str() {
        "inspect-delay" => {
            if tokens.len() < 3 {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "<tcp-request inspect-delay> expects delay timeout",
                ));
            }
            be.tcp_req_inspect_delay = Some(parse_timeout(&tokens[2], "tcp-request inspect-delay")?);
            Ok(())
        }
        "content" => parse_tcp_req_content(&mut be.tcp_req_content_rules, tokens, kw),
        "connection" | "session" => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("'tcp-request {}' is not allowed in a backend", tokens[1].text),
        )),
        other => Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            format!("unknown tcp-request subcommand <{other}>, expects 'inspect-delay' or 'content'"),
        )),
    }
}

fn find_cond_idx(tokens: &[Token], start: usize) -> Option<usize> {
    for (idx, tok) in tokens.iter().enumerate().skip(start) {
        if tok.text == "if" || tok.text == "unless" {
            return Some(idx);
        }
    }
    None
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
    let act_str = act_token.text.as_str();

    if act_str == "track-sc0" || act_str == "track-sc1" || act_str == "track-sc2" {
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
        let action = match act_str {
            "track-sc1" => HttpReqAction::TrackSc1 { expr, table },
            "track-sc2" => HttpReqAction::TrackSc2 { expr, table },
            _ => HttpReqAction::TrackSc0 { expr, table },
        };
        rules.push(HttpReqRule { action, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc0", act_token)? {
        let (_, cond) = parse_rule_condition(tokens, 2)?;
        rules.push(HttpReqRule { action: HttpReqAction::ScIncGpc0 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-inc-gpc1", act_token)? {
        let (_, cond) = parse_rule_condition(tokens, 2)?;
        rules.push(HttpReqRule { action: HttpReqAction::ScIncGpc1 { sc }, cond });
    } else if let Some(sc) = parse_sc_counter_action(act_str, "sc-set-gpt0", act_token)? {
        let (cond_idx, cond) = parse_rule_condition(tokens, 3)?;
        let expr = join_tokens_until(tokens, 2, cond_idx);
        if expr.is_empty() {
            return Err(ConfigError::new(
                act_token.line,
                act_token.col,
                "<http-request sc-set-gpt0> expects value or expression",
            ));
        }
        rules.push(HttpReqRule { action: HttpReqAction::ScSetGpt0 { sc, expr }, cond });
    } else if act_str == "return" {
        let mut status = 200u16;
        let mut content_type = None;
        let mut lf_string = None;
        let mut custom_headers = Vec::new();
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            match tokens[i].text.as_str() {
                "status" if i + 1 < limit => {
                    status = parse_u16(&tokens[i + 1], "status")?;
                    i += 2;
                }
                "content-type" if i + 1 < limit => {
                    content_type = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "lf-string" | "string" if i + 1 < limit => {
                    lf_string = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "file" | "lf-file" if i + 1 < limit => {
                    let path = &tokens[i + 1].text;
                    if let Ok(c) = std::fs::read_to_string(path) {
                        lf_string = Some(c);
                    } else {
                        lf_string = Some(String::new());
                    }
                    i += 2;
                }
                "hdr" if i + 2 < limit => {
                    custom_headers.push((tokens[i + 1].text.clone(), tokens[i + 2].text.clone()));
                    i += 3;
                }
                "errorfile" if i + 2 < limit => {
                    i += 3;
                }
                "errorfiles" if i + 1 < limit => {
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let final_lf_string = if custom_headers.is_empty() {
            lf_string
        } else {
            let mut enc = String::new();
            for (k, v) in custom_headers {
                let _ = writeln!(enc, "\0HDR:{k}:{v}");
            }
            if let Some(s) = lf_string {
                let _ = write!(enc, "\0BODY:{s}");
            }
            Some(enc)
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Return {
                status,
                content_type,
                lf_string: final_lf_string,
            },
            cond,
        });
    } else if act_str == "deny" {
        let mut deny_status = None;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            if (tokens[i].text == "status" || tokens[i].text == "deny_status") && i + 1 < limit {
                deny_status = Some(parse_u16(&tokens[i + 1], "deny_status")?);
                i += 2;
            } else {
                i += 1;
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Deny { deny_status },
            cond,
        });
    } else if act_str == "allow" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Allow,
            cond,
        });
    } else if act_str == "set-header" || act_str == "add-header" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-header|add-header> expects <name> and <fmt>.",
            ));
        }
        let name = tokens[2].text.clone();
        let fmt = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if act_str == "set-header" {
            HttpReqAction::SetHeader { name, fmt }
        } else {
            HttpReqAction::AddHeader { name, fmt }
        };
        rules.push(HttpReqRule { action, cond });
    } else if act_str == "del-header" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request del-header> expects <name>.",
            ));
        }
        let name = tokens[2].text.clone();
        let mut method = None;
        let mut i = 3;
        while i < tokens.len() {
            if tokens[i].text == "-m" && i + 1 < tokens.len() {
                method = Some(tokens[i + 1].text.clone());
                i += 2;
            } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                break;
            } else {
                i += 1;
            }
        }
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let encoded_name = match method.as_deref() {
            Some("str") | None => name,
            Some(m) => format!("\0m:{m}:{name}"),
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::DelHeader { name: encoded_name },
            cond,
        });
    } else if act_str == "replace-header" {
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
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplaceHeader { name, regex, repl },
            cond,
        });
    } else if act_str == "replace-value" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-value> expects <name>, <regex>, <replace>.",
            ));
        }
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplaceValue { name, regex, repl },
            cond,
        });
    } else if act_str == "set-path" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-path> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetPath { fmt },
            cond,
        });
    } else if act_str == "replace-path" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-path> expects <regex> and <replace>.",
            ));
        }
        let regex = tokens[2].text.clone();
        let repl = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplacePath { regex, repl },
            cond,
        });
    } else if act_str == "set-pathq" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-pathq> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetPathq { fmt },
            cond,
        });
    } else if act_str == "replace-pathq" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request replace-pathq> expects <regex> and <replace>.",
            ));
        }
        let regex = tokens[2].text.clone();
        let repl = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::ReplacePathq { regex, repl },
            cond,
        });
    } else if act_str == "set-query" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-query> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetQuery { fmt },
            cond,
        });
    } else if act_str == "set-uri" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-uri> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetUri { fmt },
            cond,
        });
    } else if act_str == "set-method" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-method> expects <fmt>.",
            ));
        }
        let fmt = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetMethod { fmt },
            cond,
        });
    } else if act_str == "set-src" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetSrc { expr },
            cond,
        });
    } else if act_str == "set-dst" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetDst { expr },
            cond,
        });
    } else if act_str == "redirect" {
        let mut location = None;
        let mut scheme = None;
        let mut prefix = None;
        let mut code = None;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            match tokens[i].text.as_str() {
                "location" if i + 1 < limit => {
                    location = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "scheme" if i + 1 < limit => {
                    scheme = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "prefix" if i + 1 < limit => {
                    prefix = Some(tokens[i + 1].text.clone());
                    i += 2;
                }
                "code" if i + 1 < limit => {
                    code = Some(parse_u16(&tokens[i + 1], "code")?);
                    i += 2;
                }
                _ => {
                    i += 1;
                }
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Redirect {
                location,
                scheme,
                prefix,
                code,
            },
            cond,
        });
    } else if act_str == "strict-mode" {
        let on = tokens.get(2).is_none_or(|t| t.text == "on");
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::StrictMode { on },
            cond,
        });
    } else if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let is_fmt = act_str.starts_with("set-var-fmt(");
        let var_name = act_token
            .text
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if is_fmt {
            HttpReqAction::SetVarFmt {
                var_name,
                fmt: expr,
            }
        } else {
            HttpReqAction::SetVar { var_name, expr }
        };
        rules.push(HttpReqRule { action, cond });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_token
            .text
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::UnsetVar { var_name },
            cond,
        });
    } else if act_str == "normalize-uri" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request normalize-uri> expects a normalizer.",
            ));
        }
        let normalizer = tokens[2].text.clone();
        let mut full = false;
        let mut strict = false;
        let cond_idx = find_cond_idx(tokens, 3);
        let limit = cond_idx.unwrap_or(tokens.len());
        for tok in &tokens[3..limit] {
            if tok.text == "full" {
                full = true;
            } else if tok.text == "strict" {
                strict = true;
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::NormalizeUri {
                normalizer,
                full,
                strict,
            },
            cond,
        });
    } else if act_str == "set-timeout" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-request set-timeout> expects <type> and <value>.",
            ));
        }
        let timeout_type = tokens[2].text.clone();
        let cond_idx = find_cond_idx(tokens, 3);
        let limit = cond_idx.unwrap_or(tokens.len());
        let timeout_val = tokens[3..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::SetTimeout {
                timeout_type,
                timeout_val,
            },
            cond,
        });
    } else if act_str == "auth" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Auth,
            cond,
        });
    } else if act_str == "capture" {
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = if limit > 2 { tokens[2].text.clone() } else { String::new() };
        let mut len = None;
        let mut id = None;
        let mut i = 3;
        while i < limit {
            if tokens[i].text == "len" && i + 1 < limit {
                len = Some(tokens[i + 1].text.parse::<usize>().unwrap_or(64));
                i += 2;
            } else if tokens[i].text == "id" && i + 1 < limit {
                id = Some(tokens[i + 1].text.parse::<usize>().unwrap_or(0));
                i += 2;
            } else {
                i += 1;
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpReqRule {
            action: HttpReqAction::Capture { expr, len, id },
            cond,
        });
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-request action <{act_str}>"),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
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
    let act_str = act_token.text.as_str();

    if act_str == "set-header" || act_str == "add-header" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response set-header|add-header> expects <name> and <fmt>.",
            ));
        }
        let name = tokens[2].text.clone();
        let fmt = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if act_str == "set-header" {
            HttpResAction::SetHeader { name, fmt }
        } else {
            HttpResAction::AddHeader { name, fmt }
        };
        rules.push(HttpResRule { action, cond });
    } else if act_str == "del-header" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response del-header> expects <name>.",
            ));
        }
        let name = tokens[2].text.clone();
        let mut method = None;
        let mut i = 3;
        while i < tokens.len() {
            if tokens[i].text == "-m" && i + 1 < tokens.len() {
                method = Some(tokens[i + 1].text.clone());
                i += 2;
            } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                break;
            } else {
                i += 1;
            }
        }
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let encoded_name = match method.as_deref() {
            Some("str") | None => name,
            Some(m) => format!("\0m:{m}:{name}"),
        };
        rules.push(HttpResRule {
            action: HttpResAction::DelHeader { name: encoded_name },
            cond,
        });
    } else if act_str == "set-status" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response set-status> expects <status>.",
            ));
        }
        let status = parse_u16(&tokens[2], "set-status")?;
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetStatus { status },
            cond,
        });
    } else if act_str == "replace-header" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response replace-header> expects <name>, <regex>, <replace>.",
            ));
        }
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: format!("\0replace-header:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
        });
    } else if act_str == "replace-value" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-response replace-value> expects <name>, <regex>, <replace>.",
            ));
        }
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: format!("\0replace-value:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
        });
    } else if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let var_name = act_token
            .text
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: format!("\0set-var:{var_name}"),
                fmt: expr,
            },
            cond,
        });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_token
            .text
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::DelHeader {
                name: format!("\0unset-var:{var_name}"),
            },
            cond,
        });
    } else if act_str == "strict-mode" {
        let on = tokens.get(2).is_none_or(|t| t.text == "on");
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0strict-mode".to_string(),
                fmt: if on { "on".into() } else { "off".into() },
            },
            cond,
        });
    } else if act_str == "allow" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0allow".to_string(),
                fmt: String::new(),
            },
            cond,
        });
    } else if act_str == "deny" {
        let mut status = None;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            if (tokens[i].text == "status" || tokens[i].text == "deny_status") && i + 1 < limit {
                status = Some(parse_u16(&tokens[i + 1], "status")?);
                i += 2;
            } else {
                i += 1;
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpResRule {
            action: HttpResAction::SetHeader {
                name: "\0deny".to_string(),
                fmt: status.map_or_else(String::new, |s| s.to_string()),
            },
            cond,
        });
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-response action <{act_str}>"),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
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
    let act_str = act_token.text.as_str();

    if act_str == "set-header" || act_str == "add-header" {
        if tokens.len() < 4 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response set-header|add-header> expects <name> and <fmt>.",
            ));
        }
        let name = tokens[2].text.clone();
        let fmt = tokens[3].text.clone();
        let cond_idx = find_cond_idx(tokens, 4);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let action = if act_str == "set-header" {
            HttpAfterResAction::SetHeader { name, fmt }
        } else {
            HttpAfterResAction::AddHeader { name, fmt }
        };
        rules.push(HttpAfterResRule { action, cond });
    } else if act_str == "del-header" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response del-header> expects <name>.",
            ));
        }
        let name = tokens[2].text.clone();
        let mut method = None;
        let mut i = 3;
        while i < tokens.len() {
            if tokens[i].text == "-m" && i + 1 < tokens.len() {
                method = Some(tokens[i + 1].text.clone());
                i += 2;
            } else if tokens[i].text == "if" || tokens[i].text == "unless" {
                break;
            } else {
                i += 1;
            }
        }
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        let encoded_name = match method.as_deref() {
            Some("str") | None => name,
            Some(m) => format!("\0m:{m}:{name}"),
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::DelHeader { name: encoded_name },
            cond,
        });
    } else if act_str == "set-status" {
        if tokens.len() < 3 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response set-status> expects <status>.",
            ));
        }
        let status = parse_u16(&tokens[2], "set-status")?;
        let cond_idx = find_cond_idx(tokens, 3);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0set-status".to_string(),
                fmt: status.to_string(),
            },
            cond,
        });
    } else if act_str == "replace-header" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response replace-header> expects <name>, <regex>, <replace>.",
            ));
        }
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: format!("\0replace-header:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
        });
    } else if act_str == "replace-value" {
        if tokens.len() < 5 {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                "<http-after-response replace-value> expects <name>, <regex>, <replace>.",
            ));
        }
        let name = tokens[2].text.clone();
        let regex = tokens[3].text.clone();
        let repl = tokens[4].text.clone();
        let cond_idx = find_cond_idx(tokens, 5);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: format!("\0replace-value:{name}"),
                fmt: format!("{regex}\t{repl}"),
            },
            cond,
        });
    } else if act_str.starts_with("set-var(") || act_str.starts_with("set-var-fmt(") {
        let var_name = act_token
            .text
            .trim_start_matches("set-var(")
            .trim_start_matches("set-var-fmt(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let expr = tokens[2..limit].iter().map(|t| t.text.as_str()).collect::<Vec<_>>().join(" ");
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: format!("\0set-var:{var_name}"),
                fmt: expr,
            },
            cond,
        });
    } else if act_str.starts_with("unset-var(") {
        let var_name = act_token
            .text
            .trim_start_matches("unset-var(")
            .trim_end_matches(')')
            .to_string();
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::DelHeader {
                name: format!("\0unset-var:{var_name}"),
            },
            cond,
        });
    } else if act_str == "strict-mode" {
        let on = tokens.get(2).is_none_or(|t| t.text == "on");
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0strict-mode".to_string(),
                fmt: if on { "on".into() } else { "off".into() },
            },
            cond,
        });
    } else if act_str == "allow" {
        let cond_idx = find_cond_idx(tokens, 2);
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0allow".to_string(),
                fmt: String::new(),
            },
            cond,
        });
    } else if act_str == "deny" {
        let mut status = None;
        let cond_idx = find_cond_idx(tokens, 2);
        let limit = cond_idx.unwrap_or(tokens.len());
        let mut i = 2;
        while i < limit {
            if (tokens[i].text == "status" || tokens[i].text == "deny_status") && i + 1 < limit {
                status = Some(parse_u16(&tokens[i + 1], "status")?);
                i += 2;
            } else {
                i += 1;
            }
        }
        let cond = if let Some(idx) = cond_idx {
            parse_acl_condition_from_tokens(&tokens[idx..])?
        } else {
            None
        };
        rules.push(HttpAfterResRule {
            action: HttpAfterResAction::SetHeader {
                name: "\0deny".to_string(),
                fmt: status.map_or_else(String::new, |s| s.to_string()),
            },
            cond,
        });
    } else {
        return Err(ConfigError::new(
            act_token.line,
            act_token.col,
            format!("unknown http-after-response action <{act_str}>"),
        ));
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
    global: Option<&GlobalSection>,
    listens: &[ListenSection],
    frontends: &[FrontendSection],
    backends: &[BackendSection],
) -> Result<(), ConfigError> {
    let bufsize = global.and_then(|g| g.bufsize).unwrap_or(16384);
    let mut h2_configured = false;
    for l in listens {
        if l.tcp_req_content_rules.iter().any(|r| {
            matches!(
                &r.action,
                TcpReqContentAction::SwitchModeHttp { proto: Some(p) } if p == "h2"
            )
        }) {
            h2_configured = true;
        }
    }
    for f in frontends {
        for b in &f.binds {
            if b.alpn.iter().any(|a| a == "h2") || b.proto.as_deref() == Some("h2") {
                h2_configured = true;
                break;
            }
        }
        if f.tcp_req_content_rules.iter().any(|r| {
            matches!(
                &r.action,
                TcpReqContentAction::SwitchModeHttp { proto: Some(p) } if p == "h2"
            )
        }) {
            h2_configured = true;
        }
    }
    if h2_configured && bufsize < 16384 {
        return Err(ConfigError::new(
            1,
            1,
            format!("'tune.bufsize' must be at least 16384 bytes when HTTP/2 is configured (got {bufsize})"),
        ));
    }

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
    let mut s = token.text.as_str();

    if let Some(stripped) = s.strip_prefix("stream+") {
        s = stripped;
    }

    let unsupported_prefixes = [
        "quic+", "dgram+", "quic4+", "quic6+",
        "fd@", "unix@", "uxdg@", "uxst@", "abns@", "abnsz@", "ip@", "ipv4@",
        "ipv6@", "tcp4@", "mptcp4@", "udp4@", "tcp6@", "mptcp6@", "udp6@",
        "tcp@", "mptcp@", "udp@", "quic4@", "quic6@", "sockpair@", "rhttp@",
    ];
    for prefix in unsupported_prefixes {
        if s.starts_with(prefix) {
            return Err(ConfigError::new(
                token.line,
                token.col,
                format!("address prefix '{prefix}' is not implemented"),
            ));
        }
    }


    if s.starts_with('/') {
        return Err(ConfigError::new(
            token.line,
            token.col,
            "address prefix 'unix@' is not implemented".to_string(),
        ));
    }

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

fn parse_usize(token: &Token, keyword: &str) -> Result<usize, ConfigError> {
    token.text.parse::<usize>().map_err(|_| {
        ConfigError::new(
            token.line,
            token.col,
            format!("<{keyword}> expects a positive integer argument."),
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

#[allow(dead_code)]
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
listen proxy1
	bind 0.0.0.0:3128
	mode	http
	cookie SERVERID
 	server srv1 192.168.12.2:8080
 	server srv2 192.168.12.3:8080
	timeout connect	3000
	timeout client	150000
	timeout server	150000
	maxconn 60000
	redisp
	retries	3
	grace 3000

listen proxy2
	bind 0.0.0.0:3129
	mode	http
	timeout connect	3000
	timeout client	150000
	timeout server	150000
	maxconn 60000
	retries	3
	grace 3000

listen health
	bind 0.0.0.0:3130
	mode	health
	timeout client	1500
	timeout server	1500
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
            config.listens[0].timeouts.connect,
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
    timeout client 10000
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
    fn test_rejected_directives() {
        let dispatch_err = parse_str("listen p\n dispatch 127.0.0.1:80\n").unwrap_err();
        assert_eq!(
            dispatch_err.message,
            "'dispatch' was removed in HAProxy 3.5; use 'server' or 'default_backend' instead"
        );

        let cliexp_err = parse_str("frontend f\n cliexp ^x y\n").unwrap_err();
        assert_eq!(
            cliexp_err.message,
            "'cliexp' was removed in HAProxy 2.0; use 'http-request replace-path' or 'http-request replace-header' instead"
        );

        let srvexp_err = parse_str("backend b\n srvexp ^x y\n").unwrap_err();
        assert_eq!(
            srvexp_err.message,
            "'srvexp' was removed in HAProxy 2.0; use 'http-response replace-header' instead"
        );

        let contimeout_err = parse_str("defaults\n contimeout 5000\n").unwrap_err();
        assert_eq!(
            contimeout_err.message,
            "'contimeout' was removed in HAProxy 2.1; use 'timeout connect' instead"
        );

        let clitimeout_err = parse_str("frontend f\n clitimeout 5000\n").unwrap_err();
        assert_eq!(
            clitimeout_err.message,
            "'clitimeout' was removed in HAProxy 2.1; use 'timeout client' instead"
        );

        let srvtimeout_err = parse_str("backend b\n srvtimeout 5000\n").unwrap_err();
        assert_eq!(
            srvtimeout_err.message,
            "'srvtimeout' was removed in HAProxy 2.1; use 'timeout server' instead"
        );
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
        let sample = "listen proxy1\n    bind 0.0.0.0:3128\nmode http\ncookie SERVERID\n";
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

listen li_proxy
    bind 0.0.0.0:82 accept-proxy
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
        assert_eq!(fe.binds[0].crt, vec!["/etc/ibex/certs/".to_string()]);
        assert_eq!(fe.binds[0].alpn, vec!["h2", "http/1.1"]);
        assert!(fe.binds[0].accept_proxy);

        assert_eq!(fe.binds[1].addr, "[::]:8443".parse().unwrap());
        assert!(fe.binds[1].ssl);
        assert_eq!(fe.binds[1].crt, vec!["/etc/ibex/certs/".to_string()]);
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
