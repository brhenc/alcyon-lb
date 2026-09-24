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
    LogLevel, LogTarget, MatchType, Mode, MysqlCheckVersion, ProtoCheckConfig, ResolvedCheckConfig,
    ResolvedHttpCheck, ResolvedHttpExpectPattern, ResolvedHttpExpectRule, ResolvedTcpStep,
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

pub(crate) enum CurrentSection {
    Global(GlobalSection),
    Defaults(DefaultsSection),
    Listen(ListenSection),
    Frontend(FrontendSection),
    Backend(BackendSection),
    Resolvers,
}

pub(crate) mod global;
pub(crate) use global::*;
pub(crate) mod defaults;
pub(crate) use defaults::*;
pub(crate) mod proxy;
pub(crate) use proxy::*;
pub(crate) mod checks;
pub(crate) use checks::*;
pub(crate) mod server;
pub(crate) use server::*;
pub(crate) mod rules_tcp;
pub(crate) use rules_tcp::*;
pub(crate) mod rules_http;
pub(crate) use rules_http::*;
pub(crate) mod stick;
pub(crate) use stick::*;
pub(crate) mod logging;
pub(crate) use logging::*;
pub(crate) mod acl;
pub(crate) use acl::*;
pub(crate) mod address;
pub(crate) use address::*;
pub(crate) mod stats;
pub(crate) use stats::*;
pub(crate) mod scalars;
pub(crate) use scalars::*;

/// Parses `HAProxy` configuration text into a typed `Config` AST.
///
/// # Errors
///
/// Returns a `ConfigError` with line and column information if the configuration
/// contains syntax errors, invalid values, or structural inconsistencies.
#[allow(clippy::too_many_lines)]
pub fn parse_str(input: &str) -> Result<Config, ConfigError> {
    // An empty config is valid: HAProxy 3.5 accepts it and exits 0 under `-c`.
    //
    // `.if` / `.elif` / `.else` / `.endif` are resolved here, before section parsing, the
    // way HAProxy does it. 269 of the 312 reg-tests use them; without this call the
    // preprocessor module existed, was unit-tested, and was reached by nothing, so `.if`
    // still failed with "unknown keyword" and the harness went on stripping the blocks
    // itself.
    let lines = crate::preproc::preprocess(lex(input))?;

    let mut global: Option<GlobalSection> = None;
    let mut defaults: Option<DefaultsSection> = None;
    let mut named_defaults: std::collections::HashMap<String, DefaultsSection> = std::collections::HashMap::new();
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
                    &mut named_defaults,
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
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                let def = if tokens.len() >= 2 && !tokens[1].text.is_empty() {
                    if tokens[1].text == "from" {
                        if tokens.len() < 3 || tokens[2].text.is_empty() {
                            return Err(ConfigError::new(tokens[1].line, tokens[1].col, "'from' expects a defaults section name".to_string()));
                        }
                        let parent = &tokens[2].text;
                        let parent_def = named_defaults.get(parent).ok_or_else(|| {
                            ConfigError::new(tokens[2].line, tokens[2].col, format!("defaults section '{parent}' not found for defaults 'unnamed'."))
                        })?;
                        let mut d = parent_def.clone();
                        d.name = None;
                        d
                    } else {
                        let name = tokens[1].text.clone();
                        if tokens.len() >= 4 && tokens[2].text == "from" {
                            let parent = &tokens[3].text;
                            let parent_def = named_defaults.get(parent).ok_or_else(|| {
                                ConfigError::new(tokens[3].line, tokens[3].col, format!("defaults section '{parent}' not found for defaults '{name}'."))
                            })?;
                            let mut d = parent_def.clone();
                            d.name = Some(name);
                            d
                        } else if tokens.len() >= 3 && tokens[2].text == "from" {
                            return Err(ConfigError::new(tokens[2].line, tokens[2].col, "'from' expects a defaults section name".to_string()));
                        } else {
                            DefaultsSection {
                                name: Some(name),
                                ..DefaultsSection::default()
                            }
                        }
                    }
                } else {
                    DefaultsSection::default()
                };
                cur_section = Some(CurrentSection::Defaults(def));
            }
            "listen" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Listen(parse_listen_header(
                    tokens,
                    kw,
                    &named_defaults,
                    defaults.as_ref(),
                )?));
            }
            "frontend" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Frontend(parse_frontend_header(
                    tokens,
                    kw,
                    &named_defaults,
                    defaults.as_ref(),
                )?));
            }
            "backend" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                );
                cur_section = Some(CurrentSection::Backend(parse_backend_header(
                    tokens,
                    kw,
                    &named_defaults,
                    defaults.as_ref(),
                )?));
            }
            "resolvers" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
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
        &mut named_defaults,
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

pub(crate) fn flush_current_section(
    cur: &mut Option<CurrentSection>,
    global: &mut Option<GlobalSection>,
    defaults: &mut Option<DefaultsSection>,
    named_defaults: &mut std::collections::HashMap<String, DefaultsSection>,
    listens: &mut Vec<ListenSection>,
    frontends: &mut Vec<FrontendSection>,
    backends: &mut Vec<BackendSection>,
) {
    if let Some(sec) = cur.take() {
        match sec {
            CurrentSection::Global(g) => *global = Some(g),
            CurrentSection::Defaults(d) => {
                if let Some(ref name) = d.name {
                    named_defaults.insert(name.clone(), d.clone());
                }
                *defaults = Some(d);
            }
            CurrentSection::Listen(l) => listens.push(l),
            CurrentSection::Frontend(f) => frontends.push(f),
            CurrentSection::Backend(b) => backends.push(b),
            CurrentSection::Resolvers => {}
        }
    }
}




pub(crate) fn parse_section_directive(
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

pub(crate) fn parse_resolvers_directive(tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
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
/// 7 passing to 1 in one commit, because `thread-groups` appears in nearly every `HAProxy`
/// reg-test. Refuse what is dangerous to ignore; keep ignoring what is merely unimplemented.
const CHECK_OPTIONS_THAT_MUST_NOT_BE_IGNORED: &[&str] = &[
    "spop-check",
];






#[allow(clippy::unnecessary_wraps)]
pub(crate) fn parse_no_directive(tokens: &[Token], _kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        eprintln!("[ibex] warning: ignored 'no {}'", tokens[1].text);
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn parse_declare(tokens: &[Token], _kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() >= 2 {
        eprintln!("[ibex] warning: ignored declare directive '{}'", tokens[1].text);
    }
    Ok(())
}













pub(crate) fn parse_mode(mode: &mut Mode, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
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

pub(crate) fn parse_cookie(
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

pub(crate) fn parse_contimeout(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'contimeout' was removed in HAProxy 2.1; use 'timeout connect' instead",
    ))
}

pub(crate) fn parse_clitimeout(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'clitimeout' was removed in HAProxy 2.1; use 'timeout client' instead",
    ))
}

pub(crate) fn parse_srvtimeout(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'srvtimeout' was removed in HAProxy 2.1; use 'timeout server' instead",
    ))
}

pub(crate) fn parse_timeout_directive(
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

pub(crate) fn parse_retries(retries: &mut u32, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
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

pub(crate) fn parse_maxconn(maxconn: &mut u32, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
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



pub(crate) fn parse_grace(
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

pub(crate) fn parse_dispatch(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'dispatch' was removed in HAProxy 3.5; use 'server' or 'default_backend' instead",
    ))
}




pub(crate) fn parse_cliexp(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'cliexp' was removed in HAProxy 2.0; use 'http-request replace-path' or 'http-request replace-header' instead",
    ))
}

pub(crate) fn parse_srvexp(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "'srvexp' was removed in HAProxy 2.0; use 'http-response replace-header' instead",
    ))
}



pub(crate) fn parse_use_backend(
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

pub(crate) fn parse_default_backend(
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






















pub(crate) fn validate_config(
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
        let sample = include_str!("../../../../examples/canonical_haproxy_35.cfg");
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
