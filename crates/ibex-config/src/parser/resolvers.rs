// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2000-2026 Willy Tarreau and HAProxy contributors. See LICENSE.

//! The `resolvers` section (`cfg_parse_resolvers`, `src/resolvers.c`), with `HAProxy`'s
//! messages (measured on 3.5-dev8-885761-29, `docs/design/dns-2026-10-25.md` appendix A).
//!
//! Where it goes: `Config::resolvers`, which nothing reads until a server may name a
//! section (T484); that keyword is refused until then. What Ibex cannot do yet is refused
//! here: `parse-resolv-conf` (T489) and the `tcp@` / `udp@` nameservers (T488).

use super::{address, server_keywords, ConfigError, Duration, IpAddr, SocketAddr, Token};
use crate::ast::{Nameserver, ResolversSection};

/// `invalid_char`: a name is letters, digits and `_ - . :`.
fn invalid_char(name: &str) -> Option<char> {
    name.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')))
}

fn err(tok: &Token, msg: impl Into<String>) -> ConfigError {
    ConfigError::new(tok.line, tok.col, msg)
}

/// The text of `tokens[i]`, empty when there is none (`*args[i]` in C).
fn arg(tokens: &[Token], i: usize) -> &str {
    tokens.get(i).map_or("", |t| t.text.as_str())
}

pub(crate) fn parse_resolvers_header(tokens: &[Token], kw: &Token, done: &[ResolversSection]) -> Result<ResolversSection, ConfigError> {
    let name = arg(tokens, 1);
    if name.is_empty() {
        return Err(err(kw, "missing name for resolvers section."));
    }
    if let Some(c) = invalid_char(name) {
        return Err(err(kw, format!("character '{c}' is not permitted in 'resolvers' name '{name}'.")));
    }
    if let Some(other) = done.iter().find(|r| r.name == name) {
        return Err(err(kw, format!("resolvers '{name}' has same name as another resolvers (declared at line {}).", other.line)));
    }
    Ok(ResolversSection::new(name.to_string(), kw.line))
}

pub(crate) fn parse_resolvers_directive(r: &mut ResolversSection, tokens: &[Token], kw: &Token) -> Result<(), ConfigError> {
    match kw.text.as_str() {
        "nameserver" => {
            let ns = parse_nameserver(r, tokens, kw)?;
            r.nameservers.push(ns);
        }
        "parse-resolv-conf" => {
            return Err(err(kw, "'parse-resolv-conf' is not supported: Ibex does not read /etc/resolv.conf yet (T489); list the nameservers"));
        }
        "hold" => {
            let (event, time) = (arg(tokens, 1), arg(tokens, 2));
            if time.is_empty() {
                return Err(err(
                    kw,
                    "'hold' expects an <event> and a <time> as arguments.\n<event> can be either 'valid', 'nx', 'refused', 'timeout', or 'other'",
                ));
            }
            let d = parse_resolver_time(kw, time, || format!("<{event}> to <hold>"), "<hold>")?;
            let slot = match event {
                "nx" => &mut r.hold.nx,
                "other" => &mut r.hold.other,
                "refused" => &mut r.hold.refused,
                "timeout" => &mut r.hold.timeout,
                "valid" => &mut r.hold.valid,
                "obsolete" => &mut r.hold.obsolete,
                _ => {
                    return Err(err(
                        kw,
                        format!("'hold' unknown <event>: '{event}', expects either 'nx', 'timeout', 'valid', 'obsolete' or 'other'."),
                    ))
                }
            };
            *slot = d;
            warn_if_small(kw, &format!("hold {event}"), time);
        }
        "accepted_payload_size" => {
            let a = arg(tokens, 1);
            if a.is_empty() {
                return Err(err(kw, "'accepted_payload_size' expects <nb> as argument."));
            }
            // `atoi`, then DNS_HEADER_SIZE..=DNS_MAX_MSG_SIZE.
            let n = server_keywords::atol(a);
            let Some(n) = u16::try_from(n).ok().filter(|n| *n >= 12) else {
                return Err(err(kw, format!("'accepted_payload_size' must be between 12 and 65535 inclusive (was {a}).")));
            };
            r.accepted_payload_size = n;
        }
        "resolution_pool_size" => {
            return Err(err(kw, "'resolution_pool_size' directive is not supported anymore (it never appeared in a stable release)."));
        }
        "resolve_retries" => {
            let a = arg(tokens, 1);
            if a.is_empty() {
                return Err(err(kw, "'resolve_retries' expects <nb> as argument."));
            }
            // `atoi`: what is not a number is 0, as in `HAProxy`.
            #[allow(clippy::cast_possible_truncation)]
            {
                r.resolve_retries = server_keywords::atol(a).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
            }
        }
        "timeout" => {
            let which = arg(tokens, 1);
            if which.is_empty() {
                return Err(err(kw, "'timeout' expects 'retry' or 'resolve' and <time> as arguments."));
            }
            if which != "retry" && which != "resolve" {
                return Err(err(kw, format!("'timeout' expects 'retry' or 'resolve' and <time> as arguments got '{which}'.")));
            }
            let time = arg(tokens, 2);
            if time.is_empty() {
                return Err(err(kw, format!("'timeout {which}' expects <time> as argument.")));
            }
            let d = parse_resolver_time(kw, time, || format!("<{time}> to <timeout {which}>"), &format!("<timeout {which}>"))?;
            if which == "retry" {
                r.timeout_retry = d;
            } else {
                r.timeout_resolve = d;
            }
            warn_if_small(kw, &format!("timeout {which}"), time);
        }
        other => return Err(err(kw, format!("unknown keyword '{other}' in 'resolvers' section"))),
    }
    Ok(())
}

/// `parse_time_err(.., TIME_UNIT_MS)` with the section's messages: `overflow_at` names
/// what overflowed (`<nx> to <hold>`), `kw_at` the keyword (`<hold>`).
fn parse_resolver_time(kw: &Token, time: &str, overflow_at: impl FnOnce() -> String, kw_at: &str) -> Result<Duration, ConfigError> {
    match super::rules_http::parse_time_ms(time) {
        Ok(ms) => Ok(Duration::from_millis(u64::from(ms))),
        Err(e) if e.starts_with("unexpected character") => {
            Err(err(kw, format!("{} in argument to {kw_at}.", e.trim_end_matches('.'))))
        }
        Err(_) => Err(err(
            kw,
            format!("timer overflow in argument {}, maximum value is 2147483647 ms (~24.8 days).", overflow_at()),
        )),
    }
}

/// `warn_if_lower(args[2], 100)`: a number with no unit below 100 is probably not meant in
/// milliseconds. `HAProxy` prints it as an alert that does not stop the load.
fn warn_if_small(kw: &Token, what: &str, time: &str) {
    if let Ok(n) = time.parse::<u32>() {
        if n > 0 && n < 100 {
            super::warn::push_alert(
                kw.line,
                crate::ast::global::WarnStyle::Spaced,
                &format!("'{what} {n}' looks suspiciously small for a value in milliseconds. Please use an explicit unit ('{n}ms') if that was the intent."),
            );
        }
    }
}

fn parse_nameserver(r: &ResolversSection, tokens: &[Token], kw: &Token) -> Result<Nameserver, ConfigError> {
    let (name, text) = (arg(tokens, 1), arg(tokens, 2));
    if text.is_empty() {
        return Err(err(kw, "'nameserver' expects <name> and <addr>[:<port>] as arguments."));
    }
    if let Some(c) = invalid_char(name) {
        return Err(err(kw, format!("character '{c}' is not permitted in server name '{name}'.")));
    }
    if let Some(other) = r.nameservers.iter().find(|n| n.name == name) {
        return Err(err(kw, format!("nameserver '{name}' has same name as another nameserver (declared at line {}).", other.line)));
    }
    let fail = |msg: String| err(kw, format!("'nameserver {name}' : {msg}"));
    for prefix in ["tcp@", "udp@"] {
        if text.starts_with(prefix) {
            return Err(fail(format!("address prefix '{prefix}' is not supported yet: nameservers are queried over UDP with no TCP fallback until T488")));
        }
    }
    if let Some(at) = text.find('@') {
        return Err(fail(format!("address prefix '{}' is not implemented", &text[..=at])));
    }
    // `str2sa_range(.., PA_O_RESOLVE | PA_O_PORT_MAND)`: the port is after the last colon,
    // or after the brackets of an IPv6 address.
    let (host, port) = match text.strip_prefix('[').and_then(|rest| rest.split_once(']')) {
        Some((h, p)) => (h, p.strip_prefix(':')),
        None => match text.rfind(':') {
            Some(i) => (&text[..i], Some(&text[i + 1..])),
            None => (text, None),
        },
    };
    let Some(port) = port.filter(|p| !p.is_empty()) else {
        return Err(fail(format!("missing port specification in '{text}'")));
    };
    if port.starts_with('+') || port.starts_with('-') {
        return Err(fail(format!("port offset not permitted here in '{text}'")));
    }
    if port.contains('-') {
        return Err(fail(format!("port range not permitted here in '{text}'")));
    }
    if let Some(c) = port.chars().find(|c| !c.is_ascii_digit()) {
        return Err(fail(format!("invalid character '{c}' in port number '{port}' in '{text}'")));
    }
    let Some(port) = port.parse::<u16>().ok().filter(|p| *p != 0) else {
        return Err(fail(format!("invalid port '{port}'")));
    };
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => address::libc_resolve(host).ok_or_else(|| fail(format!("invalid address: '{host}' in '{text}'")))?,
    };
    Ok(Nameserver { name: name.to_string(), addr: SocketAddr::new(ip, port), line: kw.line })
}

/// `cfg_post_check_resolvers`: a section without a nameserver draws a warning.
pub(crate) fn check_resolvers(sections: &[ResolversSection]) {
    for r in sections.iter().filter(|r| r.nameservers.is_empty()) {
        super::warn::push(
            r.line,
            crate::ast::global::WarnStyle::Bare,
            &format!("resolvers '{}' {{at}} has no nameservers configured!", r.name),
        );
    }
}
