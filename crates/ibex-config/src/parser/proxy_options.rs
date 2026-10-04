// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The proxy `option`s `HAProxy` knows, where it accepts them, and what Ibex does with
//! the ones it does not implement.
//!
//! The list is `cfg_opts`, `cfg_opts2` and `cfg_opts3` in `src/proxy.c` and the options
//! `cfg_parse_listen` (`src/cfgparse-listen.c`) parses by name, `HAProxy` 3.5-dev8. What
//! Ibex refuses is the two named lists in `parser/mod.rs`; everything else it does not
//! implement is accepted with a warning.

use super::{refuse_if_check_option, ConfigError, Token, OPTIONS_THAT_MUST_NOT_BE_IGNORED};

/// The section an `option` line is in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptSection {
    Defaults,
    Frontend,
    Backend,
    Listen,
}

impl OptSection {
    const fn has_frontend(self) -> bool {
        !matches!(self, Self::Backend)
    }
    const fn has_backend(self) -> bool {
        !matches!(self, Self::Frontend)
    }
}

/// Which side of a proxy an option acts on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cap {
    Fe,
    Be,
    Both,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// From the `cfg_opts` tables. In a section without the capability it needs, 3.5-dev8
    /// warns "'x' ignored because frontend 'f' has no backend capability" and then
    /// fails on "unknown option 'x'": the line is fatal.
    Table,
    /// Parsed by name, and `no option x` is accepted. Without the capability: a warning.
    Negatable,
    /// Parsed by name, after the check that refuses `no option x` ("negation/default is
    /// not supported for option 'x'"). Without the capability: a warning.
    Plain,
    /// Removed from `HAProxy`; the message it prints.
    Removed(&'static str),
}

struct OptSpec {
    name: &'static str,
    cap: Cap,
    kind: Kind,
}

macro_rules! opt {
    ($name:expr, $cap:expr, $kind:expr $(,)?) => {
        OptSpec { name: $name, cap: $cap, kind: $kind }
    };
}

const HAPROXY_OPTIONS: &[OptSpec] = &[
    opt!("abortonclose", Cap::Both, Kind::Table),
    opt!("allbackups", Cap::Be, Kind::Table),
    opt!("checkcache", Cap::Be, Kind::Table),
    opt!("clitcpka", Cap::Fe, Kind::Table),
    opt!("contstats", Cap::Fe, Kind::Table),
    opt!("dontlognull", Cap::Fe, Kind::Table),
    opt!("http-buffer-request", Cap::Both, Kind::Table),
    opt!("http-drop-request-trailers", Cap::Be, Kind::Table),
    opt!("http-drop-response-trailers", Cap::Fe, Kind::Table),
    opt!("http-ignore-probes", Cap::Fe, Kind::Table),
    opt!("idle-close-on-response", Cap::Fe, Kind::Table),
    opt!("prefer-last-server", Cap::Be, Kind::Table),
    opt!("logasap", Cap::Fe, Kind::Table),
    opt!("nolinger", Cap::Both, Kind::Table),
    opt!("persist", Cap::Be, Kind::Table),
    opt!("srvtcpka", Cap::Be, Kind::Table),
    opt!("splice-request", Cap::Both, Kind::Table),
    opt!("splice-response", Cap::Both, Kind::Table),
    opt!("splice-auto", Cap::Both, Kind::Table),
    opt!("accept-unsafe-violations-in-http-request", Cap::Fe, Kind::Table),
    opt!("accept-unsafe-violations-in-http-response", Cap::Be, Kind::Table),
    opt!("dontlog-normal", Cap::Fe, Kind::Table),
    opt!("log-separate-errors", Cap::Fe, Kind::Table),
    opt!("log-health-checks", Cap::Be, Kind::Table),
    opt!("socket-stats", Cap::Fe, Kind::Table),
    opt!("tcp-smart-accept", Cap::Fe, Kind::Table),
    opt!("tcp-smart-connect", Cap::Be, Kind::Table),
    opt!("independent-streams", Cap::Both, Kind::Table),
    opt!("http-use-proxy-header", Cap::Fe, Kind::Table),
    opt!("http-pretend-keepalive", Cap::Be, Kind::Table),
    opt!("http-no-delay", Cap::Both, Kind::Table),
    opt!("h1-case-adjust-bogus-client", Cap::Fe, Kind::Table),
    opt!("h1-case-adjust-bogus-server", Cap::Be, Kind::Table),
    opt!("disable-h2-upgrade", Cap::Fe, Kind::Table),
    opt!("assume-rfc6587-ntf", Cap::Fe, Kind::Table),
    opt!("dont-parse-log", Cap::Fe, Kind::Table),
    opt!("transparent", Cap::Both, Kind::Removed("support for option 'transparent' was removed in version 3.5.")),
    opt!(
        "forceclose",
        Cap::Both,
        Kind::Removed(
            "option 'forceclose' is not supported any more since HAProxy 2.0, please just remove it, \
             or use 'option httpclose' if absolutely needed.",
        ),
    ),
    opt!(
        "http-tunnel",
        Cap::Both,
        Kind::Removed("option 'http-tunnel' is not supported any more since HAProxy 2.1, please just remove it, it shouldn't be needed."),
    ),
    opt!(
        "http_proxy",
        Cap::Both,
        Kind::Removed("option 'http_proxy' is not supported any more since HAProxy 2.5."),
    ),
    opt!("httpclose", Cap::Both, Kind::Negatable),
    opt!("http-server-close", Cap::Both, Kind::Negatable),
    opt!("http-keep-alive", Cap::Both, Kind::Negatable),
    opt!("forwarded", Cap::Be, Kind::Negatable),
    opt!("redispatch", Cap::Be, Kind::Negatable),
    opt!("use-small-buffers", Cap::Be, Kind::Negatable),
    opt!("httplog", Cap::Both, Kind::Plain),
    opt!("tcplog", Cap::Both, Kind::Plain),
    opt!("httpslog", Cap::Both, Kind::Plain),
    opt!("tcpka", Cap::Both, Kind::Plain),
    opt!("httpchk", Cap::Be, Kind::Plain),
    opt!("ssl-hello-chk", Cap::Be, Kind::Plain),
    opt!("smtpchk", Cap::Be, Kind::Plain),
    opt!("pgsql-check", Cap::Be, Kind::Plain),
    opt!("redis-check", Cap::Be, Kind::Plain),
    opt!("mysql-check", Cap::Be, Kind::Plain),
    opt!("ldap-check", Cap::Be, Kind::Plain),
    opt!("spop-check", Cap::Be, Kind::Plain),
    opt!("tcp-check", Cap::Be, Kind::Plain),
    opt!("external-check", Cap::Be, Kind::Plain),
    opt!("forwardfor", Cap::Both, Kind::Plain),
    opt!("originalto", Cap::Both, Kind::Plain),
    opt!("http-restrict-req-hdr-names", Cap::Both, Kind::Plain),
    opt!("accept-invalid-http-request", Cap::Fe, Kind::Plain),
    opt!("accept-invalid-http-response", Cap::Be, Kind::Plain),
];

/// The options the section parsers implement. Every other option `HAProxy` knows is
/// refused by name (the lists in `parser/mod.rs`) or accepted with a warning.
const IMPLEMENTED: &[&str] = &[
    // The log format: handled by `parse_log_option` before the table is consulted (T53).
    "httplog",
    "tcplog",
    "forwardfor",
    "originalto",
    "redispatch",
    // Waits for the request body ahead of the rules (T119).
    "http-buffer-request",
    "log-health-checks",
    "httpchk",
    "tcp-check",
    "ssl-hello-chk",
    "smtpchk",
    "pgsql-check",
    "redis-check",
    "mysql-check",
    "ldap-check",
    // Read by the HTTP/1 request parser (T101).
    "accept-unsafe-violations-in-http-request",
];

fn find(name: &str) -> Option<&'static OptSpec> {
    HAPROXY_OPTIONS.iter().find(|o| o.name == name)
}

fn applies(spec: &OptSpec, section: OptSection) -> bool {
    match spec.cap {
        Cap::Fe => section.has_frontend(),
        Cap::Be => section.has_backend(),
        Cap::Both => true,
    }
}

fn err(kw: &Token, msg: String) -> ConfigError {
    ConfigError::new(kw.line, kw.col, msg)
}

/// Only a frontend lacks a backend, and only a backend lacks a frontend.
fn missing_capability(spec: &OptSpec) -> String {
    let (section, lacks) = if matches!(spec.cap, Cap::Be) { ("frontend", "backend") } else { ("backend", "frontend") };
    format!("'{}' ignored because {section} has no {lacks} capability", spec.name)
}

/// Decides an `option` line. `Ok(true)`: the caller implements the option and applies it.
/// `Ok(false)`: nothing to apply (ignored here, with a warning). `Err`: refused.
pub(crate) fn check_option(section: OptSection, tokens: &[Token], kw: &Token) -> Result<bool, ConfigError> {
    let Some(name) = tokens.get(1).map(|t| t.text.as_str()).filter(|n| !n.is_empty()) else {
        return Err(err(kw, "'option' expects an option name.".to_string()));
    };
    let Some(spec) = find(name) else {
        return Err(err(kw, format!("unknown option '{name}'.")));
    };
    if let Kind::Removed(msg) = spec.kind {
        return Err(err(kw, msg.to_string()));
    }
    // HAProxy refuses `option external-check` in a frontend too, after parsing, when the
    // `global` section does not enable external checks; Ibex has neither.
    if name == "external-check" {
        refuse_if_check_option(name, kw)?;
    }
    if !applies(spec, section) {
        let why = missing_capability(spec);
        if spec.kind == Kind::Table {
            return Err(err(kw, format!("{why}: unknown option '{name}'.")));
        }
        eprintln!("[ibex] warning: {why}.");
        return Ok(false);
    }
    if IMPLEMENTED.contains(&name) {
        return Ok(true);
    }
    refuse_if_check_option(name, kw)?;
    if name == "http-restrict-req-hdr-names" {
        return http_restrict_req_hdr_names(tokens, kw).map(|()| false);
    }
    if let Some((_, why)) = OPTIONS_THAT_MUST_NOT_BE_IGNORED.iter().find(|(o, _)| *o == name) {
        return Err(err(kw, format!("'option {name}' is not supported: {why}.")));
    }
    eprintln!("[ibex] warning: 'option {name}' is not implemented and is ignored.");
    Ok(false)
}

/// `preserve` is what Ibex does; `reject` and `delete` change what reaches the server.
fn http_restrict_req_hdr_names(tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    const NAME: &str = "http-restrict-req-hdr-names";
    match tokens.get(2).map(|t| t.text.as_str()) {
        Some("preserve") => Ok(()),
        Some(v @ ("reject" | "delete")) => Err(err(
            kw,
            format!(
                "'option {NAME} {v}' is not supported: Ibex forwards header names with characters \
                 other than letters, digits and '-', and the server would receive them."
            ),
        )),
        None | Some("") => Err(err(
            kw,
            format!("missing parameter. option '{NAME}' expects 'preserve', 'reject' or 'delete' option."),
        )),
        Some(other) => Err(err(
            kw,
            format!("invalid parameter '{other}'. option '{NAME}' expects 'preserve', 'reject' or 'delete' option."),
        )),
    }
}

/// `no option <name>`. Returns the name when the caller implements the option and must
/// turn it off; `None` when there is nothing to undo.
pub(crate) fn check_no_option<'t>(section: OptSection, tokens: &'t [Token], kw: &Token) -> Result<Option<&'t str>, ConfigError> {
    let Some(name) = tokens.get(2).map(|t| t.text.as_str()).filter(|n| !n.is_empty()) else {
        return Err(err(kw, "'option' expects an option name.".to_string()));
    };
    let spec = find(name).ok_or_else(|| err(kw, format!("negation/default is not supported for option '{name}'.")))?;
    match spec.kind {
        Kind::Removed(msg) => return Err(err(kw, msg.to_string())),
        Kind::Plain => return Err(err(kw, format!("negation/default is not supported for option '{name}'."))),
        Kind::Table if !applies(spec, section) => {
            return Err(err(kw, format!("{}: unknown option '{name}'.", missing_capability(spec))));
        }
        Kind::Table | Kind::Negatable => {}
    }
    if !applies(spec, section) {
        eprintln!("[ibex] warning: {}.", missing_capability(spec));
        return Ok(None);
    }
    if IMPLEMENTED.contains(&name) {
        return Ok(Some(name));
    }
    // Ibex does none of what these options turn on: turning it off changes nothing.
    Ok(None)
}

/// `option forwardfor [except <net>] [header <name>] [if-none]` and
/// `option originalto [except <net>] [header <name>]`. Returns the `except` network, or
/// an empty string for none, and whether `if-none` was given.
///
/// Ibex always writes the client (destination) address to `X-Forwarded-For`
/// (`X-Original-To`). With another header name, the server would read a header only the
/// client wrote: refused rather than run differently.
pub(crate) fn parse_forward_option(tokens: &[Token], kw: &Token) -> Result<(String, bool), ConfigError> {
    let name = tokens[1].text.as_str();
    let allowed = if name == "forwardfor" { "'except', 'header' and 'if-none'" } else { "'except' and 'header'" };
    let mut except = String::new();
    let mut if_none = false;
    let mut i = 2;
    while let Some(arg) = tokens.get(i).map(|t| t.text.as_str()) {
        match arg {
            "except" => {
                let net = tokens.get(i + 1).map(|t| t.text.as_str()).filter(|n| !n.is_empty()).ok_or_else(|| {
                    err(kw, format!("'option {name} except' expects <address>[/mask] as argument."))
                })?;
                except = net.to_string();
                i += 2;
            }
            "header" => {
                return Err(err(
                    kw,
                    format!(
                        "'option {name} header' is not supported: Ibex sends the address in its standard \
                         header only, and the server would read a header the client wrote."
                    ),
                ));
            }
            "if-none" if name == "forwardfor" => {
                if_none = true;
                i += 1;
            }
            _ => return Err(err(kw, format!("'option {name}' only supports optional values: {allowed}."))),
        }
    }
    Ok((except, if_none))
}
