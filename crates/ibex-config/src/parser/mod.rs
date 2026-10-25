// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.
//
// HAProxy configuration parser, ported to Rust.
// Derived from HAProxy 1.0 - 3.5 by Willy Tarreau <willy@meta-x.org>.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::ast::{LogForwardSection, RingSection, ProxyKind, ServerExtras,
    clear_http_errors_sections, clear_resolved_checks, clear_userlists, http_errors_section, http_errors_section_code,
    register_userlist, take_userlists, Userlist, UserlistUser,
    register_http_errors_section, register_resolved_check, register_resolved_check_for_addr,
    AclCondition, AclRule, AclTerm, BackendSection, BalanceAlgorithm, BindConfig, Config, CookieConfig,
    DefaultServerConfig, DefaultsSection, ErrorPageSource, FrontendSection, GlobalSection,
    GlobalSetVar, HashPreserveAffinity, HashType, HttpAfterResAction, HttpAfterResRule, HttpCheckAction, HttpCheckExpectPattern,
    HttpChkConfig, HttpReqAction, HttpReqRule, HttpResAction, HttpResRule, HttpReuse, RedirectCookie, RedirectKind, RedirectRule, RetriesValue,
    HeaderCapture, ListenSection, LogConfig, LogFacility, LogFormatSpec, LogLevel, LogTarget, MatchType, Mode,
    MysqlCheckVersion, ProtoCheckConfig, ResolvedCheckConfig, ResolvedHttpCheck,
    HdrPattern, ResolvedHttpExpectRule, ResolvedHttpRule, ResolvedTcpStep, SampleRef, SectionKind, Server, ServerSsl,
    SslVerify, StatsConfig, TlsVersion,
    StickRule, StickRuleType, StickTableConfigAst, TcpCheckAction, TcpCheckExpectPattern,
    TcpReqConnAction, TcpReqConnRule, TcpReqContentAction, TcpReqContentRule, TcpResAction, TcpResContentRule,
    TcpReqSessionAction, TcpReqSessionRule, TimeoutConfig, UseBackendRule, UseServerRule,
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
        "tune.ssl.default-dh-param",
        "SSL DH parameter size; inert in Ibex Rustls-based TLS subsystem",
    ),
];

pub(crate) enum CurrentSection {
    Global(GlobalSection),
    Defaults(DefaultsSection),
    Listen(ListenSection),
    Frontend(FrontendSection),
    Backend(BackendSection),
    /// `userlist <name>`.
    Userlist(Userlist),
    /// `http-errors <name>`: a named, independent set of `errorfile` entries referenced by
    /// proxies via `errorfiles <name> [<code>...]`.
    HttpErrors(String, std::collections::HashMap<u16, Vec<u8>>),
    /// `ring <name>`.
    Ring(RingSection),
    /// `log-forward <name>`.
    LogForward(LogForwardSection),
}

impl CurrentSection {
    /// The kind, the name and the `id` of a proxy section that has given one.
    fn explicit_id(&self) -> Option<(&'static str, &str, u32)> {
        match self {
            Self::Listen(l) => l.id.map(|id| ("listen", l.name.as_str(), id)),
            Self::Frontend(f) => f.id.map(|id| ("frontend", f.name.as_str(), id)),
            Self::Backend(b) => b.id.map(|id| ("backend", b.name.as_str(), id)),
            _ => None,
        }
    }
}

pub(crate) mod global;
pub(crate) use global::*;
pub(crate) mod defaults;
pub(crate) use defaults::*;
pub(crate) mod proxy;
pub(crate) use proxy::*;
pub(crate) mod proxy_options;
pub(crate) use proxy_options::*;
pub(crate) mod checks;
pub(crate) use checks::*;
pub(crate) mod server;
pub(crate) use server::*;
pub(crate) mod ring;
pub(crate) mod bind_keywords;
pub(crate) mod tls_versions;
pub(crate) mod server_keywords;
pub(crate) use server_keywords::*;
pub(crate) mod rules_tcp;
pub(crate) use rules_tcp::*;
pub(crate) mod rules_http;
pub(crate) use rules_http::*;
pub(crate) mod stick;
pub(crate) mod userlist;
pub(crate) use userlist::*;
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
pub(crate) mod error_pages;
pub(crate) mod sample_refs;
pub(crate) mod scope;
pub(crate) mod acl_scope;
pub(crate) mod warn;
pub(crate) mod server_state;
pub(crate) mod refs;
pub use sample_refs::log_format_exprs;
pub(crate) use error_pages::*;

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
    let lexed = lex(input);
    if let Some((line, (col, msg))) = lexed.iter().find_map(|l| Some((l.line_number, l.error.clone()?))) {
        return Err(ConfigError::new(line, col, msg));
    }
    let (lines, directive_messages) = crate::preproc::preprocess_with_messages(lexed)?;
    let env_ops = crate::env::take_ops();

    // `http-errors` sections are resolved eagerly into a process-wide registry as they are
    // parsed (see `crate::ast::rules_http`), the same way `crate::ast::checks` resolves
    // checks. Clear it first so a previous `parse_str` call in the same process -- tests
    // parse many configs -- cannot leak a section into this one.
    clear_http_errors_sections();
    clear_userlists();
    warn::reset();
    acl_scope::begin();
    struct EndScope;
    impl Drop for EndScope {
        fn drop(&mut self) {
            acl_scope::end();
        }
    }
    let _end_scope = EndScope;

    let mut global: Option<GlobalSection> = None;
    let mut proxy_warnings: Vec<crate::ast::global::LoadWarning> = Vec::new();
    let mut defaults: Option<DefaultsSection> = None;
    let mut named_defaults: std::collections::HashMap<String, DefaultsSection> = std::collections::HashMap::new();
    let mut listens = Vec::new();
    let mut frontends = Vec::new();
    let mut backends = Vec::new();
    let mut rings: Vec<RingSection> = Vec::new();
    let mut log_forwards: Vec<LogForwardSection> = Vec::new();
    let mut cur_section: Option<CurrentSection> = None;
    let mut sample_refs = Vec::new();
    // The proxy sections in the order written, and the explicit `id` of each, for the
    // numbering of the others (`Config::proxy_ids`) and for refusing a reused one.
    let mut proxy_order: Vec<(ProxyKind, usize)> = Vec::new();
    let mut explicit_ids: Vec<(u32, &'static str, String, usize)> = Vec::new();
    // Where each named defaults section starts, and what kind of section first inherited
    // from it, for [`check_inheritance`].
    let mut defaults_lines: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut defaults_users: std::collections::HashMap<String, Inheritor> = std::collections::HashMap::new();
    // The unnamed `defaults` sections, for [`AnonDefaults`].
    let mut anon_defaults: Vec<AnonDefaults> = Vec::new();

    for line in &lines {
        let tokens = &line.tokens;
        if tokens.is_empty() {
            continue;
        }

        scope::check(tokens)?;
        acl_scope::enter_line(tokens);
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
                    &mut rings,
                    &mut log_forwards,
                );
                // HAProxy reads every `global` section into the same struct: a later one
                // adds to the earlier ones, it does not replace them.
                cur_section = Some(CurrentSection::Global(global.take().unwrap_or_default()));
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
                    &mut rings,
                    &mut log_forwards,
                );
                check_inheritance(Inheritor::Defaults, tokens, &named_defaults, &defaults_lines, &mut defaults_users)?;
                if tokens.len() >= 2 && !tokens[1].text.is_empty() && tokens[1].text != "from" {
                    defaults_lines.insert(tokens[1].text.clone(), kw.line);
                } else {
                    anon_defaults.push(AnonDefaults { line: kw.line, httpchk: false, backend_user: false });
                }
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
                    &mut rings,
                    &mut log_forwards,
                );
                check_inheritance(Inheritor::Listen, tokens, &named_defaults, &defaults_lines, &mut defaults_users)?;
                proxy_order.push((ProxyKind::Listen, listens.len()));
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
                    &mut rings,
                    &mut log_forwards,
                );
                check_inheritance(Inheritor::Frontend, tokens, &named_defaults, &defaults_lines, &mut defaults_users)?;
                proxy_order.push((ProxyKind::Frontend, frontends.len()));
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
                    &mut rings,
                    &mut log_forwards,
                );
                check_inheritance(Inheritor::Backend, tokens, &named_defaults, &defaults_lines, &mut defaults_users)?;
                if !tokens.iter().any(|t| t.text == "from") {
                    if let Some(d) = anon_defaults.last_mut() {
                        d.backend_user = true;
                    }
                }
                proxy_order.push((ProxyKind::Backend, backends.len()));
                cur_section = Some(CurrentSection::Backend(parse_backend_header(
                    tokens,
                    kw,
                    &named_defaults,
                    defaults.as_ref(),
                )?));
            }
            "ring" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                    &mut rings,
                    &mut log_forwards,
                );
                cur_section = Some(CurrentSection::Ring(ring::parse_ring_header(tokens, kw, &rings)?));
            }
            "log-forward" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                    &mut rings,
                    &mut log_forwards,
                );
                cur_section = Some(CurrentSection::LogForward(ring::parse_log_forward_header(tokens, kw, &log_forwards)?));
            }
            "resolvers" => {
                return Err(ConfigError::new(
                    kw.line,
                    kw.col,
                    "'resolvers' sections are not supported: Ibex does no DNS resolution at run time (out of M1 scope)",
                ));
            }
            "userlist" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                    &mut rings,
                    &mut log_forwards,
                );
                let Some(name) = tokens.get(1).filter(|t| !t.text.is_empty()) else {
                    return Err(ConfigError::new(kw.line, kw.col, "'userlist' expects <name> as arguments."));
                };
                cur_section = Some(CurrentSection::Userlist(Userlist { name: name.text.clone(), line: kw.line, ..Userlist::default() }));
            }
            "http-errors" => {
                flush_current_section(
                    &mut cur_section,
                    &mut global,
                    &mut defaults,
                    &mut named_defaults,
                    &mut listens,
                    &mut frontends,
                    &mut backends,
                    &mut rings,
                    &mut log_forwards,
                );
                if tokens.len() < 2 || tokens[1].text.is_empty() {
                    return Err(ConfigError::new(
                        kw.line,
                        kw.col,
                        "<http-errors> expects a section name",
                    ));
                }
                cur_section = Some(CurrentSection::HttpErrors(
                    tokens[1].text.clone(),
                    std::collections::HashMap::new(),
                ));
            }
            _ => {
                let section = cur_section
                    .as_mut()
                    .ok_or_else(|| ConfigError::new(kw.line, kw.col, "<listen> expected."))?;
                sample_refs::collect(section, tokens, &mut sample_refs);
                if matches!(section, CurrentSection::Defaults(d) if d.name.is_none())
                    && kw.text == "option"
                    && tokens.get(1).is_some_and(|t| t.text == "httpchk")
                {
                    if let Some(d) = anon_defaults.last_mut() {
                        d.httpchk = true;
                    }
                }
                // `stats show-desc` with no text and no `global description` yet: a warning,
                // and nothing is set (src/cfgparse-listen.c).
                if kw.text == "stats"
                    && tokens.len() == 2
                    && tokens[1].text == "show-desc"
                    && matches!(section, CurrentSection::Defaults(_) | CurrentSection::Listen(_) | CurrentSection::Frontend(_) | CurrentSection::Backend(_))
                    && !global.as_ref().is_some_and(|g| g.description.is_some())
                {
                    proxy_warnings.push(crate::ast::global::LoadWarning {
                        line: kw.line,
                        alert: false,
                        text: "'show-desc' requires a parameter or 'desc' to be set in the global section.".into(),
                        style: crate::ast::global::WarnStyle::Tight,
                    });
                    continue;
                }
                match &*section {
                    CurrentSection::Listen(l) => warn::set_proxy(&l.name),
                    CurrentSection::Frontend(f) => warn::set_proxy(&f.name),
                    CurrentSection::Backend(b) => warn::set_proxy(&b.name),
                    _ => warn::set_proxy(""),
                }
                parse_section_directive(section, tokens, kw)?;
                if kw.text == "id" {
                    for (kind, name, id) in section.explicit_id() {
                        if let Some((_, okind, oname, oline)) = explicit_ids.iter().find(|e| e.0 == id) {
                            return Err(ConfigError::new(
                                kw.line,
                                kw.col,
                                format!("{kind} {name} reuses same custom id as {okind} {oname} (declared at line {oline})."),
                            ));
                        }
                        explicit_ids.push((id, kind, name.to_string(), kw.line));
                    }
                }
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
        &mut rings,
        &mut log_forwards,
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

    // `HAProxy` resolves the arguments of an unnamed `defaults`' `http-check` rules only in
    // the backends that inherit them (`proxy_ref_defaults`): a section with no backend
    // after it, or without `option httpchk`, never resolves them.
    sample_refs.retain(|r| {
        if r.section != SectionKind::Defaults || r.proxy.is_some() || r.directive != "http-check" {
            return true;
        }
        let owner = anon_defaults.iter().rev().find(|d| d.line <= r.line);
        owner.is_some_and(|d| d.httpchk && d.backend_user)
    });

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

    if let Some(g) = global.as_ref() {
        apply_ssl_bases(g, &mut listens, &mut frontends, &mut backends);
    }
    apply_ssl_server_verify(global.as_ref().and_then(|g| g.ssl_server_verify), &mut listens, &mut backends)?;
    if let Some(g) = global.as_ref() {
        apply_ssl_default_versions(g, &mut listens, &mut frontends, &mut backends)?;
    }

    stick::allocate_server_id(&mut listens, &mut frontends, &mut backends);
    validate_config(global.as_ref(), &listens, &frontends, &backends)?;
    stats::finish_stats_auth(&mut listens, &mut frontends, &mut backends)?;
    let mut userlists = take_userlists();
    for list in &mut userlists {
        list.resolve().map_err(|(line, msg)| ConfigError::new(line, 1, msg))?;
    }

    let config = Config {
        global,
        defaults,
        listens,
        frontends,
        backends,
        rings,
        log_forwards,
        sample_refs,
        userlists,
        proxy_order,
        directive_messages,
        env_ops,
        proxy_warnings: {
            proxy_warnings.extend(warn::take());
            proxy_warnings.sort_by_key(|w| w.line);
            proxy_warnings
        },
    };
    register_checks_from_config(&config);

    Ok(config)
}

/// `path` under `base` when it is relative (`ssl_sock_load_cert_file`, `ssl_store_load_locations_file`
/// join them with a `/`); an absolute path is kept.
fn under_base(base: Option<&str>, path: &mut String) {
    if let Some(base) = base.filter(|_| !path.starts_with('/')) {
        *path = format!("{base}/{path}");
    }
}

fn rebase_server_ssl(ssl: &mut ServerSsl, crt_base: Option<&str>, ca_base: Option<&str>) {
    if let Some(p) = ssl.crt.as_mut() {
        under_base(crt_base, p);
    }
    // `@system-ca` is not a path.
    if let Some(p) = ssl.ca_file.as_mut().filter(|p| !p.starts_with('@')) {
        under_base(ca_base, p);
    }
    if let Some(p) = ssl.crl_file.as_mut() {
        under_base(ca_base, p);
    }
}

/// Global `crt-base` / `ca-base`: HAProxy applies them when it loads the files, after the
/// whole configuration is read, so the keyword may follow the sections that use it. Ibex
/// loads from the paths the AST carries, so they are rewritten here.
fn apply_ssl_bases(
    global: &GlobalSection,
    listens: &mut [ListenSection],
    frontends: &mut [FrontendSection],
    backends: &mut [BackendSection],
) {
    let (crt_base, ca_base) = (global.crt_base.as_deref(), global.ca_base.as_deref());
    if crt_base.is_none() && ca_base.is_none() {
        return;
    }
    let binds = listens.iter_mut().flat_map(|l| l.binds.iter_mut()).chain(frontends.iter_mut().flat_map(|f| f.binds.iter_mut()));
    for bind in binds {
        for crt in &mut bind.crt {
            under_base(crt_base, crt);
        }
    }
    let mut servers: Vec<&mut Server> = Vec::new();
    servers.extend(listens.iter_mut().flat_map(|l| l.servers.iter_mut()));
    servers.extend(backends.iter_mut().flat_map(|b| b.servers.iter_mut()));
    for srv in servers {
        if let Some(ssl) = srv.ssl.as_mut() {
            rebase_server_ssl(ssl, crt_base, ca_base);
        }
    }
    let defaults = listens.iter_mut().filter_map(|l| l.default_server.as_mut()).chain(backends.iter_mut().filter_map(|b| b.default_server.as_mut()));
    for ds in defaults {
        rebase_server_ssl(&mut ds.ssl, crt_base, ca_base);
    }
}

/// Global `ssl-server-verify`: what a `server` line's `verify` is when it does not say
/// (`ssl_sock_prepare_srv_ctx`). `none` turns verification off for those, and it is also
/// what decides whether a TLS server with no CA file is refused: only one that verifies is.
/// Done once the whole file is read, because the keyword may come after the servers.
///
/// # Errors
/// The first TLS server that verifies without a CA file, in `HAProxy`'s words.
fn apply_ssl_server_verify(
    default: Option<SslVerify>,
    listens: &mut [ListenSection],
    backends: &mut [BackendSection],
) -> Result<(), ConfigError> {
    let none = default == Some(SslVerify::None);
    let mut sections: Vec<(&mut Vec<Server>, &ServerExtras)> = Vec::new();
    for l in listens.iter_mut() {
        sections.push((&mut l.servers, &l.server_extras));
    }
    for b in backends.iter_mut() {
        sections.push((&mut b.servers, &b.server_extras));
    }
    for (servers, extras) in sections {
        for e in &extras.no_ca {
            if e.explicit && none {
                return Err(ConfigError::new(e.line, e.col, format!("{}verify is enabled but no CA file specified.", e.prefix)));
            }
            if !none {
                return Err(ConfigError::new(
                    e.line,
                    e.col,
                    format!(
                        "{}verify is enabled by default but no CA file specified. If you're running on a LAN where you're certain to trust \
                         the server's certificate, please set an explicit 'verify none' statement on the 'server' line, or use \
                         'ssl-server-verify none' in the global section to disable server-side verifications by default.",
                        e.prefix
                    ),
                ));
            }
        }
        if none {
            for ssl in servers.iter_mut().filter_map(|s| s.ssl.as_mut()).filter(|s| s.verify.is_none()) {
                ssl.verify = Some(SslVerify::None);
            }
        }
    }
    Ok(())
}

/// Global `ssl-default-bind-options` / `ssl-default-server-options`: the TLS version bounds
/// a `bind` or a `server` line that names none gets, one bound at a time (a line's own
/// `ssl-min-ver` wins, the default's `ssl-max-ver` still applies). Done once the whole file
/// is read, because the keyword may come after the lines.
///
/// # Errors
/// A `bind` whose bounds, once the defaults are in, leave no version: `HAProxy`'s alert.
fn apply_ssl_default_versions(
    global: &GlobalSection,
    listens: &mut [ListenSection],
    frontends: &mut [FrontendSection],
    backends: &mut [BackendSection],
) -> Result<(), ConfigError> {
    let default = global.ssl_default_bind_versions;
    let binds = listens.iter_mut().flat_map(|l| l.binds.iter_mut()).chain(frontends.iter_mut().flat_map(|f| f.binds.iter_mut()));
    for bind in binds.filter(|b| b.ssl) {
        let range = crate::ast::TlsRange { min: bind.min_ver, max: bind.max_ver }.or(default);
        if range.is_empty() {
            return Err(ConfigError::new(1, 1, format!("all SSL/TLS versions are disabled for bind '{}'.", bind.addr)));
        }
        bind.min_ver = range.min;
        bind.max_ver = range.max;
    }
    let default = global.ssl_default_server_versions;
    let servers = listens.iter_mut().flat_map(|l| l.servers.iter_mut()).chain(backends.iter_mut().flat_map(|b| b.servers.iter_mut()));
    for ssl in servers.filter_map(|s| s.ssl.as_mut()) {
        let range = crate::ast::TlsRange { min: ssl.min_ver, max: ssl.max_ver }.or(default);
        ssl.min_ver = range.min;
        ssl.max_ver = range.max;
    }
    Ok(())
}

/// An unnamed `defaults` section, and what its `http-check` rules need to be resolved.
struct AnonDefaults {
    /// The line of its header.
    line: usize,
    /// It has `option httpchk`: only then do its `http-check` rules reach the backends.
    httpchk: bool,
    /// A `backend` (not a `listen`, whose capabilities are not a backend's alone) without `from` follows it, before the next `defaults`.
    backend_user: bool,
}

/// A kind of section that can inherit from a named `defaults` section.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Inheritor {
    Defaults,
    Listen,
    Frontend,
    Backend,
}

/// What `proxy_ref_defaults` (`src/proxy.c`) refuses when a section is initialised from a
/// named `defaults` section (`<section> ... from <name>`) that defines TCP/HTTP rules:
///
/// * another `defaults` section, or a `listen`, cannot inherit them;
/// * one section kind only can: a frontend and a backend (or listen) cannot both use it;
/// * a backend cannot inherit `tcp-request connection` or `session` rules, and a frontend
///   cannot inherit `tcp-response content` rules.
///
/// Ibex copies the defaults into each section, so a rule would otherwise run in a section
/// where `HAProxy` has none of them. `HAProxy` words the location as `file:line`; Ibex's
/// errors carry no file, so only the line is given.
fn check_inheritance(
    kind: Inheritor,
    tokens: &[Token],
    named: &std::collections::HashMap<String, DefaultsSection>,
    lines: &std::collections::HashMap<String, usize>,
    users: &mut std::collections::HashMap<String, Inheritor>,
) -> Result<(), ConfigError> {
    let Some(at) = tokens.iter().skip(1).position(|t| t.text == "from") else { return Ok(()) };
    let Some(name_tok) = tokens.get(at + 2) else { return Ok(()) };
    let Some(def) = named.get(&name_tok.text) else { return Ok(()) };
    let l4_l5 = !def.tcp_req_conn_rules.is_empty() || !def.tcp_req_session_rules.is_empty();
    let inspect_res = !def.tcp_res_content_rules.is_empty();
    let defines_rules = l4_l5
        || inspect_res
        || !def.http_req_rules.is_empty()
        || !def.http_res_rules.is_empty()
        || !def.http_after_res_rules.is_empty()
        || !def.tcp_req_content_rules.is_empty();
    if !defines_rules {
        return Ok(());
    }
    let (line, col) = (tokens[0].line, tokens[0].col);
    let def_at = lines.get(&name_tok.text).copied().unwrap_or(0);
    let err = |msg: String| Err(ConfigError::new(line, col, msg));
    match kind {
        Inheritor::Defaults => {
            return err(format!("a defaults section cannot inherit from a defaults section defining TCP/HTTP rules (defaults section at line {def_at})"));
        }
        Inheritor::Listen => {
            return err("a listen section cannot inherit from a defaults section defining TCP/HTTP rules".to_string());
        }
        Inheritor::Frontend | Inheritor::Backend => {
            if users.get(&name_tok.text).is_some_and(|first| *first != kind) {
                return err(format!("frontends and backends cannot inherit from the same defaults section if it defines TCP/HTTP rules (defaults section at line {def_at})"));
            }
            if kind == Inheritor::Backend && l4_l5 {
                return err(format!("a backend section cannot inherit from a defaults section defining 'tcp-request connection' or 'tcp-request session' rules (defaults section at line {def_at})"));
            }
            if kind == Inheritor::Frontend && inspect_res {
                return err(format!("a frontend section cannot inherit from a defaults section defining 'tcp-response content' rules (defaults section at line {def_at})"));
            }
        }
    }
    users.entry(name_tok.text.clone()).or_insert(kind);
    Ok(())
}

pub(crate) fn flush_current_section(
    cur: &mut Option<CurrentSection>,
    global: &mut Option<GlobalSection>,
    defaults: &mut Option<DefaultsSection>,
    named_defaults: &mut std::collections::HashMap<String, DefaultsSection>,
    listens: &mut Vec<ListenSection>,
    frontends: &mut Vec<FrontendSection>,
    backends: &mut Vec<BackendSection>,
    rings: &mut Vec<RingSection>,
    log_forwards: &mut Vec<LogForwardSection>,
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
            CurrentSection::Userlist(u) => register_userlist(u),
            CurrentSection::HttpErrors(name, table) => register_http_errors_section(name, table),
            CurrentSection::Ring(r) => rings.push(r),
            CurrentSection::LogForward(l) => log_forwards.push(l),
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
        CurrentSection::Userlist(u) => parse_userlist_directive(u, tokens, kw),
        CurrentSection::Ring(r) => ring::parse_ring_directive(r, tokens, kw),
        CurrentSection::LogForward(l) => ring::parse_log_forward_directive(l, tokens, kw),
        CurrentSection::HttpErrors(_, table) => match kw.text.as_str() {
            "errorfile" => parse_errorfile_directive(table, tokens, kw),
            other => Err(ConfigError::new(
                kw.line,
                kw.col,
                format!("unknown keyword '{other}' in 'http-errors' section, expects 'errorfile'"),
            )),
        },
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
///
/// `external-check` was ignored the same way until T94.
const CHECK_OPTIONS_THAT_MUST_NOT_BE_IGNORED: &[&str] = &[
    "spop-check",
    "external-check",
];

/// Options, other than checks, whose silent absence changes what reaches the server or the
/// client, or which server is used. The same policy as the list above: by name, with the
/// reason; an option `HAProxy` knows and that is not here is accepted with a warning
/// (`parser/proxy_options.rs`). An option `HAProxy` does not know is refused, as `HAProxy`
/// refuses it.
///
/// None of these appears in a reg-test that passed before T94.
const OPTIONS_THAT_MUST_NOT_BE_IGNORED: &[(&str, &str)] = &[
    ("disable-h2-upgrade", "Ibex would still accept HTTP/2 on this HTTP/1 listener"),
    (
        "allbackups",
        "Ibex sends traffic to the first available backup server only, not to all of them",
    ),
];






pub(crate) fn parse_no_directive(_tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    // `no option` and `no log` are handled by the callers; HAProxy (`cfgparse-listen.c`)
    // refuses every other `no <keyword>`, and a bare `no`, with this one message.
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "negation/default currently supported only for options, log, busy-polling, set-dumpable, strict-limits, insecure-fork-wanted and numa-cpu-mapping.".to_string(),
    ))
}

/// Where a `declare` line is, for the sections `HAProxy` refuses it in.
#[derive(Clone, Copy)]
pub(crate) enum DeclareIn {
    Defaults,
    Backend,
}

/// `declare` in a section that cannot have one: `HAProxy` refuses it in a `backend`
/// ("'declare' only available in frontend or listen section") and in `defaults`
/// ("'declare' not available in default section"), whatever follows it.
pub(crate) fn refuse_declare(section: DeclareIn, kw: &Token) -> Result<(), ConfigError> {
    let msg = match section {
        DeclareIn::Defaults => "'declare' not available in default section",
        DeclareIn::Backend => "'declare' only available in frontend or listen section",
    };
    Err(ConfigError::new(kw.line, kw.col, msg.to_string()))
}

/// A `declare` in a frontend or a listen that is not `declare capture` (that one has its own
/// parser, `parse_declare_capture`): `HAProxy` supports `capture` only.
pub(crate) fn parse_declare(tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    match tokens.get(1).map(|t| t.text.as_str()) {
        None | Some("") => Err(ConfigError::new(
            kw.line,
            kw.col,
            "'declare' needs a second keyword that specify the type of declaration ('capture')".to_string(),
        )),
        Some(other) => Err(ConfigError::new(
            kw.line,
            kw.col,
            format!("unknown declaration type '{other}' (supports 'capture')"),
        )),
    }
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

/// `cookie <name> [options]`, as `cfg_parse_listen` reads it: every option HAProxy has,
/// checked as HAProxy checks them, and the line replaces any earlier one whole (the
/// defaults' included). `dynamic` is refused: Ibex has no `dynamic-cookie-key`.
pub(crate) fn parse_cookie(
    cookie: &mut Option<CookieConfig>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    let fail = |msg: String| Err(ConfigError::new(kw.line, kw.col, msg));
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return fail("'cookie' expects <cookie_name> as argument.".to_string());
    }
    let mut ck = CookieConfig { name: tokens[1].text.clone(), ..CookieConfig::default() };
    let mut i = 2;
    while let Some(opt) = tokens.get(i) {
        let arg = tokens.get(i + 1).map(|t| t.text.as_str()).filter(|a| !a.is_empty());
        match opt.text.as_str() {
            "rewrite" => ck.rewrite = true,
            "indirect" => ck.indirect = true,
            "insert" => ck.insert = true,
            "nocache" => ck.nocache = true,
            "postonly" => ck.postonly = true,
            "preserve" => ck.preserve = true,
            "prefix" => ck.prefix = true,
            "httponly" => ck.httponly = true,
            "secure" => ck.secure = true,
            "domain" => {
                let Some(d) = arg else {
                    return fail("'domain' expects <domain> as argument.".to_string());
                };
                if !d.contains('.') {
                    warn::push(
                        kw.line,
                        crate::ast::global::WarnStyle::Tight,
                        &format!("domain '{d}' contains no embedded dot, this configuration may not work properly (see RFC6265#5.2.3)."),
                    );
                }
                if let Some(c) = d.chars().find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '.' | '_' | '-')) {
                    return fail(format!("character '{c}' is not permitted in domain name '{d}'."));
                }
                ck.domain = Some(match ck.domain.take() {
                    None => d.to_string(),
                    Some(prev) => format!("{prev}; domain={d}"),
                });
                i += 1;
            }
            kw_name @ ("maxidle" | "maxlife") => {
                let Some(v) = arg else {
                    let what = if kw_name == "maxidle" { "idletime" } else { "lifetime" };
                    return fail(format!("'{kw_name}' expects <{what}> in seconds as argument."));
                };
                let secs = match parse_time_secs(v) {
                    Ok(s) => s,
                    Err(TimeErr::Over) => {
                        return fail(format!(
                            "timer overflow in argument <{v}> to <{kw_name}>, maximum value is 2147483647 s (~68 years)."
                        ))
                    }
                    Err(TimeErr::Char(c)) => {
                        return fail(format!("unexpected character '{c}' in argument to <{kw_name}>."))
                    }
                };
                if kw_name == "maxidle" {
                    ck.maxidle = secs;
                } else {
                    ck.maxlife = secs;
                }
                i += 1;
            }
            "dynamic" => {
                return fail(
                    "'cookie ... dynamic' is not implemented: Ibex has no 'dynamic-cookie-key', and a server without a 'cookie' value would get no cookie.".to_string(),
                )
            }
            "attr" => {
                let Some(v) = arg else {
                    return fail("'attr' expects <value> as argument.".to_string());
                };
                if let Some(b) = v.bytes().find(|b| b.is_ascii_control() || *b == b';') {
                    return fail(format!("character '%x{b:02X}' is not permitted in attribute value."));
                }
                ck.attrs = Some(match ck.attrs.take() {
                    None => v.to_string(),
                    Some(prev) => format!("{prev}; {v}"),
                });
                i += 1;
            }
            _ => {
                return fail(
                    "'cookie' supports 'rewrite', 'insert', 'prefix', 'indirect', 'nocache', 'postonly', 'domain', 'maxidle', 'dynamic', 'maxlife' and 'attr' options.".to_string(),
                )
            }
        }
        i += 1;
    }
    if ck.rewrite && ck.indirect {
        return fail("cookie 'rewrite' and 'indirect' modes are incompatible.".to_string());
    }
    if u8::from(ck.rewrite) + u8::from(ck.insert) + u8::from(ck.prefix) > 1 {
        return fail("cookie 'rewrite', 'insert' and 'prefix' modes are incompatible.".to_string());
    }
    if ck.preserve && !ck.insert && !ck.indirect {
        return fail("cookie 'preserve' requires at least 'insert' or 'indirect'.".to_string());
    }
    *cookie = Some(ck);
    Ok(())
}

enum TimeErr {
    Over,
    Char(char),
}

/// A time in seconds as `parse_time_err(.., TIME_UNIT_S)` reads it: digits, then `us`,
/// `ms`, `s`, `m`, `h` or `d` (none: seconds), rounded up to a whole second.
fn parse_time_secs(text: &str) -> Result<u32, TimeErr> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return Err(TimeErr::Char(text.chars().next().unwrap_or('\0')));
    }
    let value: u128 = text[..digits].parse().unwrap_or(u128::MAX);
    let unit = &text[digits..];
    // (multiplier, divisor) from the unit to seconds.
    let (mul, div): (u128, u128) = if unit.is_empty() || unit.starts_with('s') {
        (1, 1)
    } else if unit.starts_with("us") {
        (1, 1_000_000)
    } else if unit.starts_with("ms") {
        (1, 1000)
    } else if unit.starts_with('m') {
        (60, 1)
    } else if unit.starts_with('h') {
        (3600, 1)
    } else if unit.starts_with('d') {
        (86400, 1)
    } else {
        return Err(TimeErr::Char(unit.chars().next().unwrap_or('\0')));
    };
    let secs = value.saturating_mul(mul).saturating_add(div - 1) / div;
    u32::try_from(secs).ok().filter(|s| *s < 0x8000_0000).ok_or(TimeErr::Over)
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
    // `proxy_parse_timeout` (src/proxy.c), measured on 3.5-dev8: the word first, then the
    // value. `handshake` is in HAProxy's list and refused by it all the same.
    let target = tokens.get(1).map_or("", |t| t.text.as_str());
    let slot = match target {
        "connect" => &mut timeouts.connect,
        "client" => &mut timeouts.client,
        "server" => &mut timeouts.server,
        "http-request" => &mut timeouts.http_request,
        "http-keep-alive" => &mut timeouts.http_keep_alive,
        "check" => &mut timeouts.check,
        "queue" => &mut timeouts.queue,
        "tunnel" => &mut timeouts.tunnel,
        "tarpit" => &mut timeouts.tarpit,
        // HAProxy's, which Ibex has no use for: refused rather than dropped (T240).
        "client-fin" | "server-fin" | "client-hs" => &mut None,
        _ => {
            return Err(ConfigError::new(
                kw.line,
                kw.col,
                format!(
                    "'timeout' supports 'client', 'server', 'connect', 'check', 'queue', 'handshake', 'http-keep-alive', \
                     'http-request', 'tunnel', 'tarpit', 'client-fin' and 'server-fin' (got '{target}')"
                ),
            ));
        }
    };
    let Some(value) = tokens.get(2).filter(|t| !t.text.is_empty()) else {
        return Err(ConfigError::new(kw.line, kw.col, format!("'timeout {target}' expects an integer value (in milliseconds)")));
    };
    let dur = parse_timer(value, "timeout", |a| format!("timer overflow in argument '{a}' to 'timeout {target}' {TIMER_LIMIT}"))
        .map_err(|e| {
            if e.message.starts_with("timer overflow") {
                return e;
            }
            let rest = value.text.trim_start_matches(|c: char| c.is_ascii_digit());
            let unit = ["ms", "s", "m", "h", "d"].into_iter().find(|u| rest.starts_with(u)).map_or(0, str::len);
            let bad = rest[unit..].chars().next().unwrap_or_default();
            ConfigError::new(value.line, value.col, format!("unexpected character '{bad}' in 'timeout {target}'"))
        })?;
    if let Some(extra) = tokens.get(3) {
        return Err(ConfigError::new(
            extra.line,
            extra.col,
            format!("'timeout {target}' : unexpected extra argument '{}' after value '{}'.", extra.text, value.text),
        ));
    }
    if matches!(target, "client-fin" | "server-fin" | "client-hs") {
        return Err(ConfigError::new(kw.line, kw.col, format!("'timeout {target}' is not implemented in Ibex")));
    }
    *slot = Some(dur);
    Ok(())
}

/// `option redispatch [<interval>]` (`cfgparse-listen.c`): the interval is read with
/// `atol`, so a non-numeric one is 0, and 0 clears the option. Without one the default is
/// -1, a redispatch on the last retry.
pub(crate) fn set_redispatch(on: &mut bool, after: &mut i32, tokens: &[Token]) {
    *after = -1;
    *on = true;
    if let Some(arg) = tokens.get(2) {
        *after = atol(&arg.text);
        if *after == 0 {
            *on = false;
        }
    }
}

/// C `atol`: leading blanks, an optional sign, then digits; anything after is ignored and
/// no digit is 0. Out-of-range values saturate.
fn atol(s: &str) -> i32 {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = (n * 10 + i64::from(b - b'0')).min(i64::from(i32::MAX));
    }
    i32::try_from(if neg { -n } else { n }).unwrap_or(0)
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

/// `retry-on <keyword>...`, replacing what was set before (`proxy_parse_retry_on`).
pub(crate) fn parse_retry_on(retry_on: &mut u32, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    use crate::ast::{RE_CONN_FAILED, RE_DISCONNECTED, RE_EARLY_ERROR, RE_JUNK_RESPONSE, RE_STATUSES, RE_TIMEOUT};
    let words: Vec<&str> = tokens.iter().skip(1).map(|t| t.text.as_str()).take_while(|w| !w.is_empty()).collect();
    if words.is_empty() {
        return Err(ConfigError::new(kw.line, kw.col, "'retry-on' needs at least one keyword to specify when to retry"));
    }
    let mut bits = 0;
    for (i, w) in words.iter().enumerate() {
        bits |= match *w {
            "conn-failure" => RE_CONN_FAILED,
            "empty-response" => RE_DISCONNECTED,
            "response-timeout" => RE_TIMEOUT,
            "0rtt-rejected" => RE_EARLY_ERROR,
            "junk-response" => RE_JUNK_RESPONSE,
            "all-retryable-errors" => {
                RE_CONN_FAILED | RE_DISCONNECTED | RE_TIMEOUT | RE_EARLY_ERROR | RE_JUNK_RESPONSE
                    | RE_STATUSES.iter().filter(|(s, _)| matches!(s, 500 | 502 | 503 | 504)).fold(0, |a, (_, b)| a | b)
            }
            "none" => {
                if i != 0 || words.len() > 1 {
                    return Err(ConfigError::new(kw.line, kw.col, "'retry-on' 'none' keyword only usable alone"));
                }
                0
            }
            other => match other.parse::<u16>().ok().and_then(|n| RE_STATUSES.iter().find(|(s, _)| *s == n)) {
                Some((_, b)) => *b,
                None => return Err(ConfigError::new(kw.line, kw.col, format!("'retry-on': unknown keyword '{other}'"))),
            },
        };
    }
    *retry_on = bits;
    Ok(())
}

/// `backlog <n>` of a proxy (HAProxy `cfg_parse_listen`: `"backlog"` -> `curproxy->backlog`).
pub(crate) fn parse_backlog(backlog: &mut u32, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(kw.line, kw.col, "'backlog' expects an integer argument."));
    }
    *backlog = parse_u32(&tokens[1], "backlog")?;
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



/// `grace`, removed from HAProxy in 2.5: refused in every proxy section with its text.
pub(crate) fn parse_grace(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(kw.line, kw.col, "the 'grace' keyword is not supported any more since HAProxy version 2.5."))
}

pub(crate) fn parse_redisp(kw: &Token) -> Result<(), ConfigError> {
    Err(ConfigError::new(
        kw.line,
        kw.col,
        "keyword 'redisp' directive is not supported anymore since HAProxy 2.1. Use 'option redispatch'.",
    ))
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
    // HAProxy builds the name from a log-format string when it holds `%`; Ibex looks the
    // written text up as a name, never finds it and sends the request to the default
    // backend, as if the rule had not matched.
    if tokens[1].text.contains('%') {
        return Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            "'use_backend' with a log-format backend name is not implemented by Ibex; \
             the rule would never match",
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

/// `use-server <server> if|unless <cond>` (`src/cfgparse-listen.c`). The condition is
/// required. A name that is a log-format expression chooses the server per request, which
/// Ibex does not do, so it is refused rather than read as a literal name.
pub(crate) fn parse_use_server(
    rules: &mut Vec<UseServerRule>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if tokens.len() < 2 || tokens[1].text.is_empty() {
        return Err(ConfigError::new(kw.line, kw.col, "'use-server' expects a server name."));
    }
    if !matches!(tokens.get(2).map(|t| t.text.as_str()), Some("if" | "unless")) {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "'use-server' requires either 'if' or 'unless' followed by a condition.",
        ));
    }
    if tokens[1].text.contains("%[") || tokens[1].text.contains('%') {
        return Err(ConfigError::new(
            tokens[1].line,
            tokens[1].col,
            "'use-server' with a log-format server name is not implemented by Ibex; \
             the rule would pick no server",
        ));
    }
    // The check above leaves a condition to parse, so this never yields `None`.
    let server = tokens[1].text.clone();
    rules.extend(parse_acl_condition_from_tokens(&tokens[2..])?.map(|cond| UseServerRule { server, cond }));
    Ok(())
}

/// `force-be-switch if|unless <cond>`, in a frontend or a listen section.
pub(crate) fn parse_force_be_switch(
    rules: &mut Vec<AclCondition>,
    tokens: &[Token],
    kw: &Token,
) -> Result<(), ConfigError> {
    if !matches!(tokens.get(1).map(|t| t.text.as_str()), Some("if" | "unless")) {
        return Err(ConfigError::new(
            kw.line,
            kw.col,
            "'force-be-switch' requires either 'if' or 'unless' followed by a condition.",
        ));
    }
    // The check above leaves a condition to parse, so this never yields `None`.
    rules.extend(parse_acl_condition_from_tokens(&tokens[1..])?);
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






















/// Where `track [<proxy>/]<server>` of a server of `px` points: the proxy name is what
/// precedes the last `/`, and a bare name is a server of the same proxy.
#[must_use]
pub fn tracked_target<'a>(px: &'a str, spec: &'a str) -> (&'a str, &'a str) {
    spec.rsplit_once('/').unwrap_or((px, spec))
}

/// `track` is resolved when the configuration loads, the servers taken in the order they
/// are declared, as `srv_apply_track` does (`src/server.c`): the target must exist, must
/// have a check or itself track something (a later server's `track` counts), and the chain
/// it starts must not lead back to the server.
fn validate_tracking(listens: &[ListenSection], backends: &[BackendSection]) -> Result<(), ConfigError> {
    // Most configurations track nothing, and the bookkeeping below allocates per backend.
    let tracks = |servers: &[Server]| servers.iter().any(|s| s.track.is_some());
    if !listens.iter().any(|l| tracks(&l.servers)) && !backends.iter().any(|b| tracks(&b.servers)) {
        return Ok(());
    }
    let all: Vec<(&str, &[Server])> = listens
        .iter()
        .map(|l| (l.name.as_str(), l.servers.as_slice()))
        .chain(backends.iter().map(|b| (b.name.as_str(), b.servers.as_slice())))
        .collect();
    let extras: Vec<&ServerExtras> = listens.iter().map(|l| &l.server_extras).chain(backends.iter().map(|b| &b.server_extras)).collect();
    let find = |px: &str, sv: &str| -> Option<(usize, usize)> {
        let p = all.iter().position(|(n, _)| *n == px)?;
        Some((p, all[p].1.iter().position(|s| s.id == sv)?))
    };
    // The links applied so far.
    let mut link: Vec<Vec<Option<(usize, usize)>>> = all.iter().map(|(_, s)| vec![None; s.len()]).collect();
    for (p, (px, servers)) in all.iter().enumerate() {
        for (s, server) in servers.iter().enumerate() {
            let Some(spec) = &server.track else { continue };
            // HAProxy prints these after the parse, with the `server` line's place and no frame.
            let at = extras[p].track_line.iter().find(|e| e.0 as usize == s).map_or(0, |e| e.1 as usize);
            let err = |msg: String| ConfigError::alerts(vec![(at, format!("{{at}} : 'server {px}/{}' : {msg}", server.id))]);
            if server.check {
                return Err(err("unable to enable checks and tracking at the same time!".to_string()));
            }
            let (tpx, tsv) = tracked_target(px, spec);
            if !all.iter().any(|(n, _)| *n == tpx) {
                return Err(err(format!("unable to find required proxy '{tpx}' for tracking.")));
            }
            let Some(t) = find(tpx, tsv) else {
                return Err(err(format!("unable to find required server '{tsv}' for tracking.")));
            };
            let target = &all[t.0].1[t.1];
            if !target.check && target.track.is_none() {
                return Err(err(format!("unable to use {tpx}/{tsv} for tracking as it does not have any check nor agent enabled.")));
            }
            let mut at = Some(t);
            while let Some(x) = at {
                if x == (p, s) {
                    return Err(err(format!("unable to track {tpx}/{tsv} as it belongs to a tracking chain looping back to {px}/{}.", server.id)));
                }
                at = link[x.0][x.1];
            }
            link[p][s] = Some(t);
        }
    }
    Ok(())
}

pub(crate) fn validate_config(
    global: Option<&GlobalSection>,
    listens: &[ListenSection],
    frontends: &[FrontendSection],
    backends: &[BackendSection],
) -> Result<(), ConfigError> {
    let bufsize = global.and_then(|g| g.bufsize).unwrap_or(16384);
    if bufsize < 16384 {
        // `src/proxy.c`: an HTTP proxy (frontend or listen) whose `bind` offers `h2` by ALPN
        // needs a buffer a whole HTTP/2 frame fits in; one alert per such bind, naming it.
        let proxies = listens.iter().map(|l| (&l.name, l.mode, &l.binds)).chain(frontends.iter().map(|f| (&f.name, f.mode, &f.binds)));
        let mut alerts = Vec::new();
        for (name, mode, binds) in proxies {
            if mode != Mode::Http {
                continue;
            }
            for b in binds.iter().filter(|b| b.alpn.iter().any(|a| a == "h2")) {
                alerts.push((
                    b.line,
                    format!("HTTP frontend '{name}' enables HTTP/2 via ALPN at {{at}}, so global.tune.bufsize must be at least 16384 bytes ({bufsize} now)."),
                ));
            }
        }
        if !alerts.is_empty() {
            return Err(ConfigError::alerts(alerts));
        }
        // Ibex's own refusal, where `HAProxy` loads the configuration: cleartext HTTP/2
        // (`proto h2`, `switch-mode http proto h2`) with a buffer a frame does not fit in.
        // `HAProxy` then fails every HTTP/2 request on that bind (T223); Ibex does not start
        // a listener that cannot serve.
        let switch_h2 = |rules: &[TcpReqContentRule]| {
            rules.iter().any(|r| matches!(&r.action, TcpReqContentAction::SwitchModeHttp { proto: Some(p) } if p == "h2"))
        };
        let cleartext = listens.iter().any(|l| l.binds.iter().any(|b| b.proto.as_deref() == Some("h2")) || switch_h2(&l.tcp_req_content_rules))
            || frontends.iter().any(|f| f.binds.iter().any(|b| b.proto.as_deref() == Some("h2")) || switch_h2(&f.tcp_req_content_rules));
        if cleartext {
            return Err(ConfigError::new(
                1,
                1,
                format!("'tune.bufsize' must be at least 16384 bytes when HTTP/2 is configured (got {bufsize})"),
            ));
        }
    }

    // `use-server` names are resolved when the configuration loads (`check_config_validity`).
    for l in listens {
        for r in &l.use_servers {
            if !l.servers.iter().any(|s| s.id == r.server) {
                return Err(ConfigError::alerts(vec![(0, format!(
                    "proxy '{}' : unable to find server '{}' referenced in a 'use-server' rule.", l.name, r.server))]));
            }
        }
    }
    for b in backends {
        for r in &b.use_servers {
            if !b.servers.iter().any(|s| s.id == r.server) {
                return Err(ConfigError::alerts(vec![(0, format!(
                    "backend '{}' : unable to find server '{}' referenced in a 'use-server' rule.", b.name, r.server))]));
            }
        }
    }
    validate_tracking(listens, backends)?;
    stick::validate_stick_rules(listens, frontends, backends)?;
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
    fn only_a_proxy_section_gives_an_explicit_id() {
        let mut be = BackendSection { name: "b".into(), ..Default::default() };
        assert!(CurrentSection::Backend(be.clone()).explicit_id().is_none());
        be.id = Some(4);
        assert_eq!(CurrentSection::Backend(be).explicit_id(), Some(("backend", "b", 4)));
    }

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
	option redispatch
	retries	3

listen proxy2
	bind 0.0.0.0:3129
	mode	http
	timeout connect	3000
	timeout client	150000
	timeout server	150000
	maxconn 60000
	retries	3

listen health
	bind 0.0.0.0:3130
	mode	health
	timeout client	1500
	timeout server	1500
	maxconn 4
";
        let config = parse_str(sample).unwrap();
        assert_eq!(config.listens.len(), 3);
        assert_eq!(config.listens[0].name, "proxy1");
        assert_eq!(config.listens[0].mode, Mode::Http);
        assert_eq!(config.listens[0].cookie.as_ref().map(|c| c.name.as_str()), Some("SERVERID"));
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
    fn test_balance_first_and_random() {
        let sample = "
backend b1
    balance first
    server s1 127.0.0.1:8001

backend b2
    balance random
    server s1 127.0.0.1:8001

backend b3
    balance random(5)
    server s1 127.0.0.1:8001
";
        let config = parse_str(sample).unwrap();
        assert_eq!(config.backends[0].balance, BalanceAlgorithm::First);
        // Bare `random` draws 2, matching HAProxy's default (`arg_opt1 = 2` in
        // `backend_parse_balance` before the optional `(N)` is applied).
        assert_eq!(config.backends[1].balance, BalanceAlgorithm::Random(2));
        assert_eq!(config.backends[2].balance, BalanceAlgorithm::Random(5));

        let bad_draws = parse_str("backend b\n balance random(0)\n server s1 127.0.0.1:8001\n").unwrap_err();
        assert_eq!(bad_draws.message, "random : number of draws must be at least 1.");

        let no_paren = parse_str("backend b\n balance random(5\n server s1 127.0.0.1:8001\n").unwrap_err();
        assert_eq!(no_paren.message, "random : missing closing parenthesis.");
    }

    #[test]
    fn test_hash_type_and_hash_preserve_affinity() {
        let sample = "
backend b1
    balance uri
    hash-type consistent
    hash-preserve-affinity maxconn
    server s1 127.0.0.1:8001

backend b2
    balance uri
    hash-type map-based
    server s1 127.0.0.1:8001
";
        let config = parse_str(sample).unwrap();
        assert_eq!(config.backends[0].hash_type, Some(HashType::Consistent));
        assert_eq!(
            config.backends[0].hash_preserve_affinity,
            Some(HashPreserveAffinity::MaxConn)
        );
        assert_eq!(config.backends[1].hash_type, Some(HashType::MapBased));
        assert_eq!(config.backends[1].hash_preserve_affinity, None);

        let always = parse_str("backend b\n hash-preserve-affinity always\n server s1 127.0.0.1:8001\n").unwrap();
        assert_eq!(always.backends[0].hash_preserve_affinity, Some(HashPreserveAffinity::Always));

        // Ibex has no per-server request queue, so it cannot hold a request at a saturated
        // server until that server's own queue fills -- AGENTS.md #5: an unimplemented
        // action must not parse as if it worked.
        let maxqueue_err = parse_str("backend b\n hash-preserve-affinity maxqueue\n server s1 127.0.0.1:8001\n").unwrap_err();
        assert!(
            maxqueue_err.message.contains("not implemented"),
            "hash-preserve-affinity maxqueue must be refused, not silently accepted: {}",
            maxqueue_err.message
        );

        let bad_hash_type = parse_str("backend b\n hash-type bogus\n server s1 127.0.0.1:8001\n").unwrap_err();
        assert_eq!(bad_hash_type.message, "'hash-type' only supports 'consistent' and 'map-based'.");
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
        // `stick on` in a frontend is ignored, as `HAProxy` does; `track-sc0` is kept.
        assert_eq!(fe.stick_rules.len(), 1);
        assert_eq!(fe.stick_rules[0].rule_type, StickRuleType::TrackSc0);
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

    #[test]
    fn stats_socket_expose_fd_listeners_is_parsed_and_other_values_are_refused() {
        let cfg = parse_str("global\n  stats socket /tmp/s.sock level admin expose-fd listeners\n")
            .expect("parse");
        assert!(cfg.global.expect("global").stats_socket_expose_fd);

        let plain = parse_str("global\n  stats socket /tmp/s.sock level admin\n").expect("parse");
        assert!(!plain.global.expect("global").stats_socket_expose_fd);

        let err = parse_str("global\n  stats socket /tmp/s.sock expose-fd everything\n")
            .expect_err("only 'listeners' exists");
        assert!(err.message.contains("expose-fd"), "{}", err.message);
    }
}

/// The conditions after the name in `set-var(<name>[,<cond>...])` and `set-var-fmt(...)`
/// (`vars_parse_cond_param`, src/vars.c): `ifexists`, `ifnotexists`, `ifempty`,
/// `ifnotempty`, `ifset`, `ifnotset`, `ifgt` and `iflt` are honoured when the action runs
/// (`ifgt`/`iflt` compare two `sint`). Any other word is HAProxy's
/// "unknown condition".
pub(crate) fn check_set_var_conds(tok: &Token, spec: &str) -> Result<(), ConfigError> {
    for cond in spec.split(',').skip(1).filter(|c| !c.is_empty()) {
        match cond {
            "ifexists" | "ifnotexists" | "ifempty" | "ifnotempty" | "ifset" | "ifnotset" | "ifgt" | "iflt" => {}
            _ => {
                return Err(ConfigError::new(tok.line, tok.col, format!("unknown condition \"{cond}\".")));
            }
        }
    }
    Ok(())
}
